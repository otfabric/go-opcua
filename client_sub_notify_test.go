// SPDX-License-Identifier: MIT

package opcua

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newNotifyTestClient(t *testing.T) *Client {
	t.Helper()
	c, err := NewClient("opc.tcp://example.com:4840")
	require.NoError(t, err)
	return c
}

func newNotifyTestSub(id uint32) (*Subscription, <-chan *PublishNotificationData) {
	ch := make(chan *PublishNotificationData, 8)
	sub := &Subscription{
		SubscriptionID:            id,
		RevisedPublishingInterval: time.Second,
		RevisedMaxKeepAliveCount:  10,
		Notifs:                    ch,
		items:                     make(map[uint32]*monitoredItem),
		params:                    &SubscriptionParameters{},
	}
	return sub, ch
}

func TestRegisterSubscriptionNeedsSubMuxLock(t *testing.T) {
	c := newNotifyTestClient(t)
	c.subMux.Lock()
	defer c.subMux.Unlock()

	sub0, _ := newNotifyTestSub(0)
	require.ErrorIs(t, c.registerSubscriptionNeedsSubMuxLock(sub0), ua.StatusBadSubscriptionIDInvalid)

	sub, _ := newNotifyTestSub(7)
	require.NoError(t, c.registerSubscriptionNeedsSubMuxLock(sub))
	dup, _ := newNotifyTestSub(7)
	err := c.registerSubscriptionNeedsSubMuxLock(dup)
	require.Error(t, err)
	assert.ErrorIs(t, err, errors.ErrInvalidSubscriptionID)
}

func TestRepublishSubscription_UnknownID(t *testing.T) {
	c := newNotifyTestClient(t)
	_, err := c.republishSubscription(context.Background(), 404, nil)
	require.ErrorIs(t, err, errors.ErrInvalidSubscriptionID)
}

func TestRecreateSubscription_UnknownID(t *testing.T) {
	c := newNotifyTestClient(t)
	err := c.recreateSubscription(context.Background(), 404)
	require.ErrorIs(t, err, ua.StatusBadSubscriptionIDInvalid)
}

func TestUpdatePublishTimeout_UsesMinSubTimeout(t *testing.T) {
	c := newNotifyTestClient(t)
	c.cfg.sechan.RequestTimeout = 100 * time.Millisecond

	slow, _ := newNotifyTestSub(1)
	slow.RevisedPublishingInterval = time.Second
	slow.RevisedMaxKeepAliveCount = 30
	slow.c = c

	fast, _ := newNotifyTestSub(2)
	fast.RevisedPublishingInterval = 200 * time.Millisecond
	fast.RevisedMaxKeepAliveCount = 2
	fast.c = c

	c.subMux.Lock()
	c.subs[1] = slow
	c.subs[2] = fast
	c.updatePublishTimeoutNeedsSubMuxLock()
	c.subMux.Unlock()

	assert.Equal(t, fast.publishTimeout(), c.publishTimeout())
}

func TestNotifySubscription_NilAndInvalid(t *testing.T) {
	c := newNotifyTestClient(t)
	sub, ch := newNotifyTestSub(11)

	c.notifySubscription(context.Background(), sub, nil)
	msg := <-ch
	require.ErrorIs(t, msg.Error, errors.ErrEmptyResponse)

	c.notifySubscription(context.Background(), sub, &ua.NotificationMessage{
		NotificationData: []*ua.ExtensionObject{nil},
	})
	msg = <-ch
	require.ErrorIs(t, msg.Error, errors.ErrEmptyResponse)

	c.notifySubscription(context.Background(), sub, &ua.NotificationMessage{
		NotificationData: []*ua.ExtensionObject{
			{Value: "not-a-notification"},
		},
	})
	msg = <-ch
	require.ErrorIs(t, msg.Error, errors.ErrInvalidResponseType)
}

func TestNotifySubscription_DataChange(t *testing.T) {
	c := newNotifyTestClient(t)
	sub, ch := newNotifyTestSub(12)
	dcn := &ua.DataChangeNotification{}

	c.notifySubscription(context.Background(), sub, &ua.NotificationMessage{
		NotificationData: []*ua.ExtensionObject{{Value: dcn}},
	})
	msg := <-ch
	require.NoError(t, msg.Error)
	assert.Equal(t, dcn, msg.Value)
	assert.Equal(t, uint32(12), msg.SubscriptionID)
}

func TestNotifySubscriptionOfError_KnownAndUnknown(t *testing.T) {
	c := newNotifyTestClient(t)
	sub, ch := newNotifyTestSub(3)
	c.subMux.Lock()
	c.subs[3] = sub
	c.subMux.Unlock()

	c.notifySubscriptionOfError(context.Background(), 999, assert.AnError)
	c.notifySubscriptionOfError(context.Background(), 3, assert.AnError)
	select {
	case msg := <-ch:
		require.ErrorIs(t, msg.Error, assert.AnError)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for error notification")
	}
}

func TestNotifyAllSubscriptionsOfError(t *testing.T) {
	c := newNotifyTestClient(t)
	a, ach := newNotifyTestSub(1)
	b, bch := newNotifyTestSub(2)
	c.subMux.Lock()
	c.subs[1] = a
	c.subs[2] = b
	c.subMux.Unlock()

	c.notifyAllSubscriptionsOfError(context.Background(), assert.AnError)
	for _, ch := range []<-chan *PublishNotificationData{ach, bch} {
		select {
		case msg := <-ch:
			require.ErrorIs(t, msg.Error, assert.AnError)
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for error notification")
		}
	}
}

func TestHandleAcksNeedsSubMuxLock(t *testing.T) {
	c := newNotifyTestClient(t)
	c.cfg.logger = slog.Default()
	ackOK := &ua.SubscriptionAcknowledgement{SubscriptionID: 1, SequenceNumber: 1}
	ackRetry := &ua.SubscriptionAcknowledgement{SubscriptionID: 1, SequenceNumber: 2}
	ackBadSub := &ua.SubscriptionAcknowledgement{SubscriptionID: 9, SequenceNumber: 3}
	ackUnknownSeq := &ua.SubscriptionAcknowledgement{SubscriptionID: 1, SequenceNumber: 4}

	c.subMux.Lock()
	c.pendingAcks = []*ua.SubscriptionAcknowledgement{ackOK, ackRetry, ackBadSub, ackUnknownSeq}
	c.handleAcksNeedsSubMuxLock([]ua.StatusCode{
		ua.StatusOK,
		ua.StatusBadTimeout,
		ua.StatusBadSubscriptionIDInvalid,
		ua.StatusBadSequenceNumberUnknown,
	})
	require.Len(t, c.pendingAcks, 1)
	assert.Equal(t, ackRetry, c.pendingAcks[0])

	c.pendingAcks = []*ua.SubscriptionAcknowledgement{ackOK}
	c.handleAcksNeedsSubMuxLock(nil)
	assert.Empty(t, c.pendingAcks)
	c.subMux.Unlock()
}

func TestHandleNotificationNeedsSubMuxLock(t *testing.T) {
	c := newNotifyTestClient(t)
	sub, _ := newNotifyTestSub(5)
	sub.nextSeq = 10

	c.subMux.Lock()
	c.handleNotificationNeedsSubMuxLock(sub, &ua.PublishResponse{
		SubscriptionID: 5,
		NotificationMessage: &ua.NotificationMessage{
			SequenceNumber:   10,
			NotificationData: nil,
		},
	})
	assert.Equal(t, uint32(10), sub.nextSeq)
	assert.Empty(t, c.pendingAcks)

	c.handleNotificationNeedsSubMuxLock(sub, &ua.PublishResponse{
		SubscriptionID: 5,
		NotificationMessage: &ua.NotificationMessage{
			SequenceNumber: 10,
			NotificationData: []*ua.ExtensionObject{
				{Value: &ua.DataChangeNotification{}},
			},
		},
	})
	assert.Equal(t, uint32(10), sub.lastSeq)
	assert.Equal(t, uint32(11), sub.nextSeq)
	require.Len(t, c.pendingAcks, 1)
	assert.Equal(t, uint32(5), c.pendingAcks[0].SubscriptionID)
	assert.Equal(t, uint32(10), c.pendingAcks[0].SequenceNumber)
	c.subMux.Unlock()
}

func TestResumeSubscriptions_Signals(t *testing.T) {
	c := newNotifyTestClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.resumeSubscriptions(ctx)

	ctx = context.Background()
	c.resumeSubscriptions(ctx)
	select {
	case <-c.resumech:
	default:
		t.Fatal("expected resume signal")
	}
}
