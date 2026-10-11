// SPDX-License-Identifier: MIT

package conformance

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// startServerOn starts a server with the fixture on a fixed port, so a second
// instance can later take the place of the first one. The returned stop
// function is idempotent.
//
// Tests using it are deliberately not parallel: they need "their" port to stay
// free between the two instances, which only holds while no other test is
// starting servers.
func startServerOn(t *testing.T, port int) (*testutil.Fixture, func()) {
	t.Helper()
	var srv *server.Server
	// The previous instance may need a moment to release the port.
	eventually(t, func() bool {
		s, err := server.New(
			server.EndPoint("localhost", port),
			server.EnableSecurity("None", ua.MessageSecurityModeNone),
			server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		)
		if err != nil {
			return false
		}
		if err := s.Start(context.Background()); err != nil {
			_ = s.Close()
			return false
		}
		srv = s
		return true
	}, "server start")
	f := testutil.AddFixture(t, srv)
	var once sync.Once
	stop := func() { once.Do(func() { _ = srv.Close() }) }
	t.Cleanup(stop)
	return f, stop
}

// stateRecorder collects connection states in order.
type stateRecorder struct {
	mu     sync.Mutex
	states []opcua.ConnState
}

func (r *stateRecorder) record(s opcua.ConnState) {
	r.mu.Lock()
	r.states = append(r.states, s)
	r.mu.Unlock()
}

func (r *stateRecorder) seen(s opcua.ConnState) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, x := range r.states {
		if x == s {
			return true
		}
	}
	return false
}

// seenAfter reports whether state b was recorded after the first a.
func (r *stateRecorder) seenAfter(a, b opcua.ConnState) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	foundA := false
	for _, x := range r.states {
		if x == a {
			foundA = true
		} else if foundA && x == b {
			return true
		}
	}
	return false
}

// TestRecovery_ServerRestart verifies automatic reconnect across a full server
// restart: the connection state transitions, the recovery handler, and that
// subscriptions and their monitored items are recreated and deliver again
// through the original notification channel.
func TestRecovery_ServerRestart(t *testing.T) {
	port := freeCustomPort(t)
	url := fmt.Sprintf("opc.tcp://localhost:%d", port)
	f, stop := startServerOn(t, port)
	ctx := context.Background()

	states := &stateRecorder{}
	var evMu sync.Mutex
	var events []opcua.SubscriptionRecoveryEvent
	c := newClient(t, url,
		opcua.AutoReconnect(true),
		opcua.ReconnectInterval(50*time.Millisecond),
		opcua.WithConnStateHandler(states.record),
		opcua.WithSubscriptionRecoveryHandler(func(ev opcua.SubscriptionRecoveryEvent) {
			evMu.Lock()
			events = append(events, ev)
			evMu.Unlock()
		}),
	)
	oldSession := c.Session().SessionID().String()

	// Two subscriptions; the second also carries an item that failed to create.
	ch1 := make(chan *opcua.PublishNotificationData, 256)
	sub1, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: fastInterval}, ch1)
	require.NoError(t, err)
	_, err = sub1.Monitor(ctx, ua.TimestampsToReturnBoth,
		opcua.NewMonitoredItemCreateRequestWithDefaults(f.Int32, ua.AttributeIDValue, 1),
		opcua.NewMonitoredItemCreateRequestWithDefaults(f.Double, ua.AttributeIDValue, 2),
	)
	require.NoError(t, err)

	ch2 := make(chan *opcua.PublishNotificationData, 256)
	sub2, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: fastInterval}, ch2)
	require.NoError(t, err)
	mon, err := sub2.Monitor(ctx, ua.TimestampsToReturnNeither,
		opcua.NewMonitoredItemCreateRequestWithDefaults(f.String, ua.AttributeIDValue, 3),
		opcua.NewMonitoredItemCreateRequestWithDefaults(ua.NewStringNodeID(f.NSIndex, "DoesNotExist"), ua.AttributeIDValue, 4),
	)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadNodeIDUnknown, mon.Results[1].StatusCode)

	awaitValue(t, ch1, 1, int32(42))
	awaitValue(t, ch1, 2, 3.14159)
	awaitValue(t, ch2, 3, "hello")

	// Take the server away.
	stop()
	eventually(t, func() bool { return states.seen(opcua.Disconnected) }, "client notices the lost connection")
	eventually(t, func() bool { return states.seen(opcua.Reconnecting) }, "client starts reconnecting")
	_, err = c.ReadValue(ctx, f.Int32)
	require.Error(t, err, "requests fail while the server is gone")

	// A brand-new server instance on the same address: no session, no
	// subscriptions, fixture values back at their defaults.
	f2, _ := startServerOn(t, port)
	eventually(t, func() bool { return states.seenAfter(opcua.Reconnecting, opcua.Connected) }, "client reconnects")
	eventually(t, func() bool { return c.State() == opcua.Connected }, "state Connected")

	// A new session was created.
	eventually(t, func() bool { return c.Session() != nil }, "session")
	require.NotEqual(t, oldSession, c.Session().SessionID().String())

	// Both subscriptions were recreated and reported to the recovery handler.
	eventually(t, func() bool {
		evMu.Lock()
		defer evMu.Unlock()
		return len(events) >= 2
	}, "recovery events for both subscriptions")
	evMu.Lock()
	for _, ev := range events {
		require.Equal(t, opcua.SubscriptionRecoveryRecreated, ev.Outcome)
		require.NotEmpty(t, ev.Detail)
		require.Empty(t, ev.AvailableSequenceNumbers)
	}
	evMu.Unlock()
	require.Len(t, c.SubscriptionIDs(), 2)

	// The recreated items deliver the new server's values on the original
	// channels, with their original client handles...
	awaitValue(t, ch1, 1, int32(42))
	awaitValue(t, ch1, 2, 3.14159)
	awaitValue(t, ch2, 3, "hello")

	// ...and keep reporting changes.
	writeInt32(t, c, f2.Int32, 2024)
	awaitValue(t, ch1, 1, int32(2024))
	st, err := c.WriteNodeValue(ctx, f2.String, "after restart")
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, st)
	awaitValue(t, ch2, 3, "after restart")

	// The subscription handles are usable for further calls.
	res, err := sub1.SetPublishingMode(ctx, true)
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, res.Results)
	require.NoError(t, sub1.Cancel(ctx))
	require.NoError(t, sub2.Cancel(ctx))
	require.Empty(t, c.SubscriptionIDs())
}

// TestRecovery_AutoReconnectDisabled verifies a client without automatic
// reconnect reports the loss and stays down.
func TestRecovery_AutoReconnectDisabled(t *testing.T) {
	port := freeCustomPort(t)
	url := fmt.Sprintf("opc.tcp://localhost:%d", port)
	f, stop := startServerOn(t, port)
	ctx := context.Background()

	states := &stateRecorder{}
	c := newClient(t, url, opcua.AutoReconnect(false), opcua.WithConnStateHandler(states.record))
	ch := make(chan *opcua.PublishNotificationData, 64)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: fastInterval}, ch)
	require.NoError(t, err)
	_, err = sub.Monitor(ctx, ua.TimestampsToReturnNeither, opcua.NewMonitoredItemCreateRequestWithDefaults(f.Int32, ua.AttributeIDValue, 1))
	require.NoError(t, err)
	awaitValue(t, ch, 1, int32(42))

	stop()
	eventually(t, func() bool { return states.seen(opcua.Disconnected) }, "client notices the lost connection")
	eventually(t, func() bool { return c.State() == opcua.Closed }, "client ends up Closed")

	// Even with the server back, the client does not reconnect on its own.
	startServerOn(t, port)
	time.Sleep(300 * time.Millisecond)
	require.False(t, states.seen(opcua.Reconnecting))
	require.Equal(t, opcua.Closed, c.State())
	_, err = c.ReadValue(ctx, f.Int32)
	require.Error(t, err)

	// A fresh client connects fine.
	c2 := newClient(t, url)
	dv, err := c2.ReadValue(ctx, f.Int32)
	require.NoError(t, err)
	require.Equal(t, int32(42), dv.Value.Value())
}
