// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil/cleanup"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// timedPubReq is a queued Publish request with TimeoutHint hint (ms) that
// arrived age ago.
func timedPubReq(id, hint uint32, age time.Duration) PubReq {
	return PubReq{
		Req:      &ua.PublishRequest{RequestHeader: &ua.RequestHeader{RequestHandle: 1000 + id, TimeoutHint: hint}},
		ID:       id,
		received: time.Now().Add(-age),
	}
}

// TestTakePublishRequest_TimeoutHint: "The Server shall check the
// timeoutHint parameter of a Publish request before processing a Publish
// response. If the request timed out, a Bad_Timeout Service result is sent
// and another Publish request is used", and "The value of 0 indicates no
// timeout" (Part 4 §7.32).
func TestTakePublishRequest_TimeoutHint(t *testing.T) {
	srv := newTestServer()
	faults := recordFaults(srv)
	sess := &session{PublishRequests: make(chan PubReq, 8)}
	sess.PublishRequests <- timedPubReq(1, 10, time.Hour)                                                            // timed out
	sess.PublishRequests <- timedPubReq(2, 0, time.Hour)                                                             // no timeout
	sess.PublishRequests <- timedPubReq(3, 10, time.Hour)                                                            // timed out
	sess.PublishRequests <- timedPubReq(4, 3_600_000, time.Minute)                                                   // within its hint
	sess.PublishRequests <- PubReq{Req: &ua.PublishRequest{RequestHeader: &ua.RequestHeader{TimeoutHint: 1}}, ID: 5} // queued without a time

	pr, ok := srv.takePublishRequest(sess)
	require.True(t, ok)
	require.Equal(t, uint32(2), pr.ID)
	require.Equal(t, []uint32{1}, faults.faulted())
	require.Equal(t, ua.StatusBadTimeout, faults.status[1])
	require.Equal(t, uint32(1001), faults.handle[1], "the fault carries the handle of the request it answers")

	pr, ok = srv.takePublishRequest(sess)
	require.True(t, ok)
	require.Equal(t, uint32(4), pr.ID, "the timed-out request before it is answered")
	require.Equal(t, []uint32{1, 3}, faults.faulted())

	pr, ok = srv.takePublishRequest(sess)
	require.True(t, ok)
	require.Equal(t, uint32(5), pr.ID)

	_, ok = srv.takePublishRequest(sess)
	require.False(t, ok, "the queue is empty")

	require.False(t, srv.publishTimedOut(PubReq{received: time.Now().Add(-time.Hour)}), "a request without a header")
	require.Equal(t, []uint32{1, 3}, faults.faulted())
}

// TestPublish_TimedOutRequestNotUsed: a subscription with a notification
// to send skips a queued Publish request whose TimeoutHint has elapsed,
// answers it with Bad_Timeout and uses the next one (Part 4 §7.32).
func TestPublish_TimedOutRequestNotUsed(t *testing.T) {
	srv, err := New(EndPoint("localhost", 0),
		InsecureNoSecurity(),
		EnableAuthMode(ua.UserTokenTypeAnonymous))
	require.NoError(t, err)
	faults := recordFaults(srv)
	ns := NewNodeNameSpace(srv, "timeout")
	n := ns.AddNewVariableStringNode("v", int32(0))
	require.NoError(t, srv.Start(context.Background()))
	cleanup.Register(t, func() { _ = srv.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := opcua.NewClient(srv.Endpoints()[0].EndpointURL, opcua.InsecureNoSecurity(),
		opcua.AutoReconnect(false), opcua.RequestTimeout(30*time.Second))
	require.NoError(t, err)
	require.NoError(t, c.Connect(ctx))
	cleanup.Register(t, func() { _ = c.Close(context.Background()) })

	sub, notes, err := c.NewSubscription().Interval(20 * time.Millisecond).MaxKeepAliveCount(10000).
		LifetimeCount(30000).Monitor(n.ID()).Start(ctx)
	require.NoError(t, err)
	cleanup.Register(t, func() { _ = sub.Cancel(context.Background()) })
	await := func(want int32) {
		t.Helper()
		deadline := time.After(10 * time.Second)
		for {
			select {
			case msg := <-notes:
				require.NoError(t, msg.Error)
				if dcn, ok := msg.Value.(*ua.DataChangeNotification); ok {
					for _, it := range dcn.MonitoredItems {
						if it.Value.Value.Value() == want {
							return
						}
					}
				}
			case <-deadline:
				t.Fatalf("no notification with value %d", want)
			}
		}
	}
	await(0)

	srv.sb.mu.Lock()
	var sess *session
	for _, s := range srv.sb.s {
		sess = s
	}
	srv.sb.mu.Unlock()
	require.NotNil(t, sess)

	// Put a request that timed out in front of the client's next one.
	require.Eventually(t, func() bool { return len(sess.PublishRequests) > 0 }, 10*time.Second, time.Millisecond)
	var live []PubReq
	for len(sess.PublishRequests) > 0 {
		live = append(live, <-sess.PublishRequests)
	}
	stale := timedPubReq(1<<30, 1, time.Hour)
	stale.Channel = scNone()
	sess.PublishRequests <- stale
	for _, pr := range live {
		sess.PublishRequests <- pr
	}

	require.Equal(t, ua.StatusOK, ns.SetAttribute(n.ID(), ua.AttributeIDValue, &ua.DataValue{
		EncodingMask: ua.DataValueValue,
		Value:        ua.MustVariant(int32(7)),
	}))
	srv.ChangeNotification(n.ID())
	await(7)
	faults.mu.Lock()
	defer faults.mu.Unlock()
	require.Equal(t, ua.StatusBadTimeout, faults.status[1<<30])
}
