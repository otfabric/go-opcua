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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	c, err := NewClient("opc.tcp://127.0.0.1:1", DialTimeout(5*time.Second))
	require.NoError(t, err)
	require.NoError(t, c.Close(context.Background()))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.Error(t, c.Connect(ctx))
	assert.Equal(t, Closed, c.State())
	assert.Nil(t, c.SecureChannel())
}

// A StatusChangeNotification with a bad status means the server has closed
// the subscription. The client used to hand it to the consumer and carry on
// as if nothing had happened.
func TestSubscriptionEnded(t *testing.T) {
	t.Parallel()
	msg := func(v any) *ua.NotificationMessage {
		return &ua.NotificationMessage{NotificationData: []*ua.ExtensionObject{ua.NewExtensionObject(v)}}
	}

	assert.True(t, subscriptionEnded(msg(&ua.StatusChangeNotification{Status: ua.StatusBadTimeout})))
	assert.True(t, subscriptionEnded(msg(&ua.StatusChangeNotification{Status: ua.StatusBadSubscriptionIDInvalid})))

	// the subscription lives on in another session
	assert.False(t, subscriptionEnded(msg(&ua.StatusChangeNotification{Status: ua.StatusGoodSubscriptionTransferred})))
	assert.False(t, subscriptionEnded(msg(&ua.DataChangeNotification{})))
	assert.False(t, subscriptionEnded(&ua.NotificationMessage{}))
	assert.False(t, subscriptionEnded(&ua.NotificationMessage{NotificationData: []*ua.ExtensionObject{nil}}))
	assert.False(t, subscriptionEnded(nil))
}

func TestDeliverPublishResponse_StatusChangeSchedulesRecreation(t *testing.T) {
	t.Parallel()
	statusChange := func(subID uint32) *ua.PublishResponse {
		return &ua.PublishResponse{
			SubscriptionID: subID,
			Results:        []ua.StatusCode{},
			NotificationMessage: &ua.NotificationMessage{
				SequenceNumber: 1,
				NotificationData: []*ua.ExtensionObject{
					ua.NewExtensionObject(&ua.StatusChangeNotification{Status: ua.StatusBadTimeout}),
				},
			},
		}
	}
	setup := func(t *testing.T, opts ...Option) (*Client, <-chan *PublishNotificationData) {
		c, err := NewClient("opc.tcp://example.com:4840", opts...)
		require.NoError(t, err)
		ended, ch := newNotifyTestSub(7)
		sibling, _ := newNotifyTestSub(8)
		c.subMux.Lock()
		c.subs[7], c.subs[8] = ended, sibling
		c.subMux.Unlock()
		c.setPublishPaused(false)
		return c, ch
	}

	t.Run("auto reconnect", func(t *testing.T) {
		c, ch := setup(t)
		c.deliverPublishResponse(context.Background(), statusChange(7))

		// the consumer still sees the notification
		select {
		case n := <-ch:
			_, ok := n.Value.(*ua.StatusChangeNotification)
			require.True(t, ok, "got %T", n.Value)
		default:
			t.Fatal("the StatusChangeNotification was not delivered to the consumer")
		}
		// only the ended subscription is marked, and the monitor is woken
		intact, broken := c.partitionSubscriptions()
		assert.Equal(t, []uint32{8}, intact)
		assert.Equal(t, []uint32{7}, broken)
		select {
		case <-c.subRecoverCh:
		default:
			t.Fatal("the connection monitor was not asked to recreate the subscription")
		}
	})

	t.Run("without auto reconnect nothing is recreated", func(t *testing.T) {
		c, ch := setup(t, AutoReconnect(false))
		c.deliverPublishResponse(context.Background(), statusChange(7))
		require.Len(t, ch, 1)
		_, broken := c.partitionSubscriptions()
		assert.Empty(t, broken)
		assert.Empty(t, c.subRecoverCh)
	})
}

func TestMarkSubscriptionsBroken(t *testing.T) {
	t.Parallel()
	c := newNotifyTestClient(t)
	assert.Zero(t, c.markSubscriptionsBroken())

	a, _ := newNotifyTestSub(1)
	b, _ := newNotifyTestSub(2)
	c.subMux.Lock()
	c.subs[1], c.subs[2] = a, b
	c.subMux.Unlock()

	assert.Equal(t, 2, c.markSubscriptionsBroken())
	intact, broken := c.partitionSubscriptions()
	assert.Empty(t, intact)
	assert.ElementsMatch(t, []uint32{1, 2}, broken)
}

// ActivateSession closes the session it replaces while that session is
// still the active one. A fault of a request in it (a Publish answered
// with Bad_SessionIdInvalid by the closing session) is one of a session
// the client has left: it must not set off a reconnect. Found by an
// intermittent TestClientCovActivateSessionRecreatesSubscriptions failure
// (Disconnected, Reconnecting after a session switch).
func TestLeftSession_SessionBeingReplaced(t *testing.T) {
	t.Parallel()
	c := newNotifyTestClient(t)
	prev := &Session{resp: &ua.CreateSessionResponse{AuthenticationToken: ua.NewNumericNodeID(0, 1)}}
	next := &Session{resp: &ua.CreateSessionResponse{AuthenticationToken: ua.NewNumericNodeID(0, 2)}}
	c.setSession(prev)
	require.False(t, c.leftSession(prev.resp.AuthenticationToken))

	c.leaving.Store(prev) // being closed, still active
	require.True(t, c.leftSession(prev.resp.AuthenticationToken))

	c.setSession(next)
	require.True(t, c.leftSession(prev.resp.AuthenticationToken))
	require.False(t, c.leftSession(next.resp.AuthenticationToken))

	// A session that is set again is no longer being left.
	c.setSession(prev)
	require.Nil(t, c.leaving.Load())
	require.False(t, c.leftSession(prev.resp.AuthenticationToken))
}

// Good_SubscriptionTransferred for a subscription that left the session the
// client uses: another session took it, so the client forgets it (it would
// otherwise recreate it on the next Bad_NoSubscription and duplicate it).
// From another session the client moved it away itself: it stays, and its
// sequence numbers are untouched.
//
// Regression (TestDiagnostics_Transfer on CI): the client whose subscription
// another client had taken recreated it.
func TestPublish_SubscriptionTransferred(t *testing.T) {
	t.Parallel()
	transferred := func(id, seq uint32) *ua.PublishResponse {
		eo := ua.NewExtensionObject(&ua.StatusChangeNotification{Status: ua.StatusGoodSubscriptionTransferred})
		return &ua.PublishResponse{
			SubscriptionID:      id,
			Results:             []ua.StatusCode{},
			NotificationMessage: &ua.NotificationMessage{SequenceNumber: seq, NotificationData: []*ua.ExtensionObject{eo}},
		}
	}
	in, elsewhere := &Session{}, &Session{}
	setup := func(t *testing.T) (*Client, *Subscription, <-chan *PublishNotificationData) {
		c := newNotifyTestClient(t)
		sub, ch := newNotifyTestSub(7)
		sub.session.Store(in)
		sub.lastSeq, sub.nextSeq = 4, 5
		c.subMux.Lock()
		c.subs[7] = sub
		c.subMux.Unlock()
		c.setPublishPaused(false)
		return c, sub, ch
	}

	t.Run("taken by another session", func(t *testing.T) {
		c, _, ch := setup(t)
		require.Zero(t, c.deliverPublishResponseOf(context.Background(), transferred(7, 5), in))
		require.Len(t, ch, 1, "the consumer sees the notification")
		n := <-ch
		sc, ok := n.Value.(*ua.StatusChangeNotification)
		require.True(t, ok, "got %T", n.Value)
		require.Equal(t, ua.StatusGoodSubscriptionTransferred, sc.Status)
		assert.Empty(t, c.SubscriptionIDs(), "the subscription is forgotten")
		assert.Empty(t, c.subRecoverCh, "nothing is recreated")
		assert.Empty(t, c.pendingAcks)
		paused, _ := c.publishState()
		assert.True(t, paused, "nothing is left to publish for")
	})

	t.Run("moved away by the client", func(t *testing.T) {
		c, sub, ch := setup(t)
		require.Zero(t, c.deliverPublishResponseOf(context.Background(), transferred(7, 5), elsewhere))
		assert.Empty(t, ch)
		assert.Equal(t, []uint32{7}, c.SubscriptionIDs())
		assert.Equal(t, uint32(4), sub.lastSeq)
		assert.Equal(t, uint32(5), sub.nextSeq)
		assert.Empty(t, c.pendingAcks)
	})
}

// Bad_NoSubscription for a Publish request sent in a session the client has
// left: the reconnect logic transferred the subscriptions to the new session,
// and the server answers the Publish requests still waiting in the old one
// with Bad_NoSubscription. That says nothing about the subscriptions, which
// live on in the new session: they must not be marked for recreation.
//
// Regression (Race, TestClientCovMonitorTriggers/session_invalid/republished:
// no recovery event "republished"): the transferred subscription was marked
// broken and recreated right after its transfer. When the mark was still
// pending at the next reconnect, that reconnect recreated the subscription
// instead of transferring and republishing it.
func TestPublish_NoSubscriptionOfLeftSession(t *testing.T) {
	c, err := NewClient("opc.tcp://example.com:4840", AutoReconnect(true))
	require.NoError(t, err)
	sub, _ := newNotifyTestSub(7)
	sub.c = c
	c.subMux.Lock()
	require.NoError(t, c.registerSubscriptionNeedsSubMuxLock(sub))
	c.subMux.Unlock()
	prev := &Session{resp: &ua.CreateSessionResponse{AuthenticationToken: ua.NewNumericNodeID(0, 1)}}
	next := &Session{resp: &ua.CreateSessionResponse{AuthenticationToken: ua.NewNumericNodeID(0, 2)}}

	broken := func() bool {
		c.subMux.RLock()
		defer c.subMux.RUnlock()
		return sub.needsRecreate
	}

	// sent in prev, answered after the reconnect replaced it with next
	c.setSession(prev)
	withPublishHook(t, func(context.Context, *Client) (*ua.PublishResponse, error) {
		c.setSession(next)
		return nil, ua.StatusBadNoSubscription
	})
	require.NoError(t, c.publish(context.Background()), "the publish loop carries on in the new session")
	assert.False(t, broken(), "the subscription is not marked for recreation")
	select {
	case <-c.subRecoverCh:
		t.Fatal("subscription recovery requested")
	default:
	}

	// in the session the client still uses, the subscriptions are gone
	withPublishHook(t, func(context.Context, *Client) (*ua.PublishResponse, error) {
		return nil, ua.StatusBadNoSubscription
	})
	require.ErrorIs(t, c.publish(context.Background()), ua.StatusBadNoSubscription)
	assert.True(t, broken())
}
