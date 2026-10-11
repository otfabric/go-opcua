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

// TestMarkSilentSubscriptions covers the rule by which the client recognizes
// a subscription that the server no longer serves in the client's session
// although the connection and the other subscriptions are fine (deleted
// behind the client's back, or left behind in another session). Nothing else
// reports that: the client used to stay Connected with a subscription that
// never delivered again (chaos TestChaosMonkeyNetworkFaults, STUCK).
func TestMarkSilentSubscriptions(t *testing.T) {
	c := newNotifyTestClient(t)
	// keep-alive every 10 s: silent after 30 s
	slow, _ := newNotifyTestSub(1)
	// keep-alive every 100 ms: silent after the floor of 5 s
	fast, _ := newNotifyTestSub(2)
	fast.RevisedPublishingInterval, fast.RevisedMaxKeepAliveCount = 20*time.Millisecond, 5
	other, _ := newNotifyTestSub(3)
	c.subMux.Lock()
	for _, s := range []*Subscription{slow, fast, other} {
		s.c = c
		require.NoError(t, c.registerSubscriptionNeedsSubMuxLock(s))
	}
	c.subMux.Unlock()

	broken := func() []uint32 {
		_, ids := c.partitionSubscriptions()
		return ids
	}
	start := time.Now()
	at := func(d time.Duration) int64 { return start.Add(d).UnixNano() }
	set := func(response time.Duration, seen map[*Subscription]time.Duration) {
		c.lastPublishResponse.Store(at(response))
		for s, d := range seen {
			s.lastActivity.Store(at(d))
		}
	}

	// Everybody was served a moment ago.
	set(time.Second, map[*Subscription]time.Duration{slow: time.Second, fast: time.Second, other: time.Second})
	assert.Zero(t, c.markSilentSubscriptions())

	// Nothing has arrived for anybody for a minute (paused publish loop,
	// blocked consumer, slow connection): nobody is singled out, however
	// much time has passed on the clock.
	assert.Zero(t, c.markSilentSubscriptions())
	assert.Empty(t, broken())

	// Responses keep arriving for one subscription. After 4 s the others
	// are within their limits.
	set(5*time.Second, map[*Subscription]time.Duration{other: 5 * time.Second})
	assert.Zero(t, c.markSilentSubscriptions())

	// After 6 s the fast one has missed 50 keep-alives: it is marked. The
	// slow one, whose keep-alive is not even due, is not.
	set(7*time.Second, map[*Subscription]time.Duration{other: 7 * time.Second})
	assert.Equal(t, 1, c.markSilentSubscriptions())
	assert.Equal(t, []uint32{2}, broken())
	// A marked subscription is not counted twice.
	assert.Zero(t, c.markSilentSubscriptions())

	// The slow one follows after three of its keep-alive intervals.
	set(30*time.Second, map[*Subscription]time.Duration{other: 30 * time.Second})
	assert.Zero(t, c.markSilentSubscriptions())
	set(32*time.Second, map[*Subscription]time.Duration{other: 32 * time.Second})
	assert.Equal(t, 1, c.markSilentSubscriptions())
	assert.ElementsMatch(t, []uint32{1, 2}, broken())

	// A subscription that was registered without a time stamp starts
	// counting when it is first looked at.
	late, _ := newNotifyTestSub(4)
	late.c = c
	c.subMux.Lock()
	c.subs[4] = late
	c.subMux.Unlock()
	assert.Zero(t, c.markSilentSubscriptions())
	assert.NotZero(t, late.lastActivity.Load())

	// When publishing starts again after a recovery everybody starts anew.
	c.touchSubscriptions()
	c.subMux.Lock()
	slow.needsRecreate, fast.needsRecreate = false, false
	c.subMux.Unlock()
	assert.Zero(t, c.markSilentSubscriptions())

	// A Publish response counts for its subscription and for the client,
	// also when it is for a subscription the client does not know.
	before := c.lastPublishResponse.Load()
	time.Sleep(2 * time.Millisecond)
	c.deliverPublishResponse(context.Background(), &ua.PublishResponse{
		SubscriptionID:      3,
		Results:             []ua.StatusCode{},
		NotificationMessage: &ua.NotificationMessage{SequenceNumber: 1},
	})
	assert.Greater(t, c.lastPublishResponse.Load(), before)
	assert.Equal(t, c.lastPublishResponse.Load(), other.lastActivity.Load())
	seen := other.lastActivity.Load()
	time.Sleep(2 * time.Millisecond)
	c.deliverPublishResponse(context.Background(), &ua.PublishResponse{
		SubscriptionID:      99,
		Results:             []ua.StatusCode{},
		NotificationMessage: &ua.NotificationMessage{SequenceNumber: 1},
	})
	assert.Greater(t, c.lastPublishResponse.Load(), seen)
	assert.Equal(t, seen, other.lastActivity.Load())
}

// TestPublish_StaleSessionError: an error that says "this session is gone"
// for a Publish request sent in a session the client has left since must not
// pause the publish loop of the session the client has now.
func TestPublish_StaleSessionError(t *testing.T) {
	assert.True(t, staleSessionError(ua.StatusBadSessionClosed))
	assert.True(t, staleSessionError(ua.StatusBadSessionIDInvalid))
	assert.True(t, staleSessionError(ua.StatusBadSessionNotActivated))
	assert.False(t, staleSessionError(ua.StatusBadNoSubscription))
	assert.False(t, staleSessionError(ua.StatusBadTimeout))
}

// TestDeliverPublishResponse_DropsARepeatedMessage: the notification message
// a subscription delivered last is not delivered a second time.
//
// Regression (chaos/secure TestSecureChaosMonkey without the race detector:
// "REORDERED: delivered 525 after 531"): a recovery republished a message
// while the Publish response carrying the same message, sent before the
// recovery, was waiting for its turn; when the recovery had ended by then,
// the consumer got the message twice, the second time after newer values.
func TestDeliverPublishResponse_DropsARepeatedMessage(t *testing.T) {
	c := newNotifyTestClient(t)
	sub, ch := newNotifyTestSub(7)
	sub.c = c
	sub.nextSeq = 1
	c.subMux.Lock()
	require.NoError(t, c.registerSubscriptionNeedsSubMuxLock(sub))
	c.subMux.Unlock()

	data := func(seq uint32) *ua.PublishResponse {
		return &ua.PublishResponse{
			SubscriptionID: 7,
			Results:        []ua.StatusCode{},
			NotificationMessage: &ua.NotificationMessage{
				SequenceNumber:   seq,
				NotificationData: []*ua.ExtensionObject{ua.NewExtensionObject(&ua.DataChangeNotification{})},
			},
		}
	}
	received := func() int {
		n := 0
		for {
			select {
			case <-ch:
				n++
			case <-time.After(50 * time.Millisecond):
				return n
			}
		}
	}
	ctx := context.Background()

	c.deliverPublishResponse(ctx, data(1))
	c.deliverPublishResponse(ctx, data(2))
	assert.Equal(t, 2, received())

	// message 2 again: dropped, but acknowledged so that the server lets go
	// of it
	c.subMux.Lock()
	c.pendingAcks = nil
	c.subMux.Unlock()
	c.deliverPublishResponse(ctx, data(2))
	assert.Zero(t, received(), "a repeated message is not delivered again")
	c.subMux.RLock()
	require.Len(t, c.pendingAcks, 1)
	assert.Equal(t, uint32(2), c.pendingAcks[0].SequenceNumber)
	c.subMux.RUnlock()

	// the next one is delivered as usual
	c.deliverPublishResponse(ctx, data(3))
	assert.Equal(t, 1, received())

	// A keep-alive (no data) with the sequence number of the last message
	// is not a repetition.
	keepAlive := data(3)
	keepAlive.NotificationMessage.NotificationData = nil
	c.deliverPublishResponse(ctx, keepAlive)
	c.deliverPublishResponse(ctx, data(4))
	assert.GreaterOrEqual(t, received(), 1)
}
