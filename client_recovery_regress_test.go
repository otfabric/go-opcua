// SPDX-License-Identifier: MIT

package opcua

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression tests for the reconnect and publish-loop fixes that came out of
// the chaos suite (see package chaos). They exercise the bookkeeping without
// a server; the end-to-end behaviour is covered there.

// A publish attempt that fails after the connection monitor has already
// repaired the connection and resumed publishing must not pause the loop
// again: nobody would resume it and all subscriptions would stay silent.
// (Pause and resume used to be unordered signals on two channels.)
func TestPublishLoop_StalePauseDoesNotOverrideResume(t *testing.T) {
	c := newNotifyTestClient(t)

	// a client starts paused: there is nothing to publish for
	paused, _ := c.publishState()
	require.True(t, paused)

	c.setPublishPaused(false)
	paused, gen := c.publishState()
	require.False(t, paused)

	// the attempt that started in generation gen fails: pause
	c.pausePublishIfGen(gen)
	paused, _ = c.publishState()
	require.True(t, paused, "a failed publish attempt pauses the loop")

	// the monitor resumes; then a second, older attempt reports its failure
	c.setPublishPaused(false)
	c.pausePublishIfGen(gen)
	paused, _ = c.publishState()
	assert.False(t, paused, "a failure from before the resume must not pause the loop again")
}

// While a recovery is in progress the loop is held, also when Subscribe
// resumes publishing, and a PublishResponse that arrives in that time is left
// to the republish step instead of being delivered out of order.
func TestPublishLoop_HeldDuringRecovery(t *testing.T) {
	c := newNotifyTestClient(t)
	ctx := context.Background()

	sub, ch := newNotifyTestSub(7)
	sub.nextSeq = 3
	c.subMux.Lock()
	c.subs[7] = sub
	c.subMux.Unlock()

	c.setPublishRecovering(true)
	c.setPublishPaused(false) // e.g. a Subscribe call during the recovery
	held, _ := c.publishState()
	require.True(t, held, "publishing must be held during a recovery")

	res := &ua.PublishResponse{
		SubscriptionID: 7,
		Results:        []ua.StatusCode{},
		NotificationMessage: &ua.NotificationMessage{
			SequenceNumber:   3,
			NotificationData: []*ua.ExtensionObject{ua.NewExtensionObject(&ua.DataChangeNotification{})},
		},
	}
	c.deliverPublishResponse(ctx, res)
	select {
	case n := <-ch:
		t.Fatalf("a response that arrived during the recovery was delivered: %+v", n)
	default:
	}
	assert.Equal(t, uint32(3), sub.nextSeq, "the sequence number must not advance: republish fetches the message")

	c.setPublishRecovering(false)
	held, _ = c.publishState()
	require.False(t, held)

	c.deliverPublishResponse(ctx, res)
	select {
	case n := <-ch:
		require.NoError(t, n.Error)
	case <-time.After(10 * time.Second):
		t.Fatal("the response was not delivered after the recovery")
	}
	assert.Equal(t, uint32(4), sub.nextSeq)
}

// A subscription whose recreation fails must stay registered, keep the list
// of items it monitors, and be marked for another attempt. It used to be
// dropped from the client for good, without a word to its consumer.
func TestRecreateSubscription_FailureKeepsSubscription(t *testing.T) {
	c := newNotifyTestClient(t) // not connected: every request fails
	ctx := context.Background()

	sub, _ := newNotifyTestSub(5)
	sub.c = c
	sub.items[11] = &monitoredItem{
		req: NewMonitoredItemCreateRequestWithDefaults(ua.NewNumericNodeID(0, 2258), ua.AttributeIDValue, 1),
		ts:  ua.TimestampsToReturnBoth,
	}
	c.subMux.Lock()
	c.subs[5] = sub
	c.subMux.Unlock()

	err := c.recreateSubscription(ctx, 5)
	require.Error(t, err)

	assert.Equal(t, []uint32{5}, c.SubscriptionIDs(), "the subscription must stay registered")
	intact, broken := c.partitionSubscriptions()
	assert.Empty(t, intact)
	assert.Equal(t, []uint32{5}, broken, "the subscription must be marked for recreation")
	sub.itemsMu.Lock()
	assert.Len(t, sub.items, 1, "the monitored items must be kept for the next attempt")
	sub.itemsMu.Unlock()
}

// Cancel removes the subscription by identity. A reconnect that recreates it
// gives it a new id; cancelling "the old id" used to leave the subscription
// registered under the new one.
func TestCancel_AfterRecreateForgetsCurrentID(t *testing.T) {
	c := newNotifyTestClient(t)

	sub, _ := newNotifyTestSub(7)
	sub.c = c
	sub.cancelled = make(chan struct{})
	c.subMux.Lock()
	c.subs[7] = sub
	c.subMux.Unlock()

	// what recreateCreate does once the server assigned a new id
	c.subMux.Lock()
	delete(c.subs, 7)
	sub.setID(9)
	c.subs[9] = sub
	c.subMux.Unlock()

	_ = sub.Cancel(context.Background()) // not connected: the server request fails
	assert.Empty(t, c.SubscriptionIDs(), "the recreated subscription must be forgotten")

	// a notification for a cancelled subscription is dropped, not blocked on
	done := make(chan struct{})
	go func() {
		blocked := &Subscription{Notifs: make(chan *PublishNotificationData), cancelled: sub.cancelled}
		blocked.notify(context.Background(), &PublishNotificationData{})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("notify blocks on a cancelled subscription")
	}
}

// A failed Connect must not leave the client in the Connecting state.
func TestConnect_DialFailureEndsClosed(t *testing.T) {
	var states []ConnState
	c, err := NewClient("opc.tcp://127.0.0.1:1", // nothing listens on port 1
		DialTimeout(5*time.Second),
		WithConnStateHandler(func(s ConnState) { states = append(states, s) }),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.Error(t, c.Connect(ctx))

	assert.Equal(t, Closed, c.State())
	assert.Equal(t, []ConnState{Connecting, Closed}, states)
}

// Connect on a client that was already closed must not come up.
func TestConnect_AfterCloseFails(t *testing.T) {
	c, err := NewClient("opc.tcp://127.0.0.1:1", DialTimeout(5*time.Second))
	require.NoError(t, err)
	require.NoError(t, c.Close(context.Background()))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.Error(t, c.Connect(ctx))
	assert.Equal(t, Closed, c.State())
	assert.Nil(t, c.SecureChannel())
}
