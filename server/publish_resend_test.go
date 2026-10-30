// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// A notification message whose Publish response cannot be sent (the
// connection of its Publish request is gone) goes out with the next Publish
// request of the session.
//
// Regression (found with conformance TestTransportWSS_Reconnect under load):
// a client's Publish request read just before its connection dropped was
// queued after the channel had closed. The next data change was sent to that
// request and lost; the client, reconnected on a new channel, learned of it
// only from the sequence number of a later message, a keep-alive many
// publishing intervals away.
func TestPublish_ResendsMessageOfDeadRequest(t *testing.T) {
	srv, err := New(EndPoint("localhost", 0),
		InsecureNoSecurity(),
		EnableAuthMode(ua.UserTokenTypeAnonymous))
	require.NoError(t, err)
	ns := NewNodeNameSpace(srv, "resend")
	n := ns.AddNewVariableStringNode("v", int32(0))
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := opcua.NewClient(srv.Endpoints()[0].EndpointURL, opcua.InsecureNoSecurity(),
		opcua.AutoReconnect(false), opcua.RequestTimeout(30*time.Second))
	require.NoError(t, err)
	require.NoError(t, c.Connect(ctx))
	t.Cleanup(func() { _ = c.Close(context.Background()) })

	// Keep-alives are far off: only a resent message reaches the client in
	// time.
	sub, notes, err := c.NewSubscription().Interval(20 * time.Millisecond).MaxKeepAliveCount(10000).
		LifetimeCount(30000).Monitor(n.ID()).Start(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(context.Background()) })
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

	// The client's next Publish request is queued. Put a request of a closed
	// channel in front of it.
	require.Eventually(t, func() bool { return len(sess.PublishRequests) > 0 }, 10*time.Second, time.Millisecond)
	var live []PubReq
	for len(sess.PublishRequests) > 0 {
		live = append(live, <-sess.PublishRequests)
	}
	sess.PublishRequests <- PubReq{Req: &ua.PublishRequest{RequestHeader: reqHeader()}, ID: 1 << 30, Channel: scNone()}
	for _, pr := range live {
		sess.PublishRequests <- pr
	}

	require.Equal(t, ua.StatusOK, ns.SetAttribute(n.ID(), ua.AttributeIDValue, &ua.DataValue{
		EncodingMask: ua.DataValueValue,
		Value:        ua.MustVariant(int32(7)),
	}))
	srv.ChangeNotification(n.ID())
	await(7)
}
