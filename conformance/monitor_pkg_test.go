// SPDX-License-Identifier: MIT

package conformance

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/monitor"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// awaitMonitorMsg waits for a monitor message for node carrying want.
func awaitMonitorMsg(t *testing.T, ch <-chan *monitor.DataChangeMessage, node *ua.NodeID, want any) *monitor.DataChangeMessage {
	t.Helper()
	deadline := time.After(waitTimeout)
	for {
		select {
		case msg := <-ch:
			require.NoError(t, msg.Error)
			if msg.NodeID.String() == node.String() && msg.Value.Value() == want {
				return msg
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %s to report %v", node, want)
			return nil
		}
	}
}

// expectNoMonitorMsg asserts no message for node arrives within d.
func expectNoMonitorMsg(t *testing.T, ch <-chan *monitor.DataChangeMessage, node *ua.NodeID, d time.Duration) {
	t.Helper()
	timer := time.After(d)
	for {
		select {
		case msg := <-ch:
			if msg.Error == nil && msg.NodeID.String() == node.String() {
				t.Fatalf("unexpected message for %s: %v", node, msg.Value.Value())
			}
		case <-timer:
			return
		}
	}
}

// TestMonitor_ChannelSubscription drives the monitor package's channel-based
// subscription through its whole API.
func TestMonitor_ChannelSubscription(t *testing.T) {
	c, f, ctx := setup(t)
	m, err := monitor.NewNodeMonitor(c)
	require.NoError(t, err)

	ch := make(chan *monitor.DataChangeMessage, 256)
	sub, err := m.ChanSubscribe(ctx, &opcua.SubscriptionParameters{Interval: fastInterval}, ch, f.Int32.String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Unsubscribe(ctx) }) // also stops the pump goroutine
	require.NotZero(t, sub.SubscriptionID())
	require.Contains(t, c.SubscriptionIDs(), sub.SubscriptionID())
	require.Equal(t, 1, sub.Subscribed())

	// Messages are tagged with the node they belong to and carry timestamps.
	msg := awaitMonitorMsg(t, ch, f.Int32, int32(42))
	require.False(t, msg.ServerTimestamp.IsZero())

	// AddNodes / AddNodeIDs / AddMonitorItems.
	require.NoError(t, sub.AddNodes(ctx, f.Double.String()))
	require.NoError(t, sub.AddNodeIDs(ctx, f.String))
	items, err := sub.AddMonitorItems(ctx, monitor.Request{
		NodeID:               f.Uint32,
		MonitoringMode:       ua.MonitoringModeReporting,
		MonitoringParameters: &ua.MonitoringParameters{QueueSize: 5, DiscardOldest: true},
	})
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.NotZero(t, items[0].ID())
	require.Equal(t, f.Uint32.String(), items[0].NodeID().String())
	require.Equal(t, 4, sub.Subscribed())
	awaitMonitorMsg(t, ch, f.Double, 3.14159)
	awaitMonitorMsg(t, ch, f.String, "hello")
	awaitMonitorMsg(t, ch, f.Uint32, uint32(4242))

	// A bad node id string is rejected before anything is sent.
	require.Error(t, sub.AddNodes(ctx, "this is not a node id"))
	require.Equal(t, 4, sub.Subscribed())

	// Disabling one node silences it; the others keep reporting.
	require.NoError(t, sub.SetMonitoringModeForNodes(ctx, ua.MonitoringModeDisabled, f.Int32.String()))
	writeInt32(t, c, f.Int32, 1)
	st, err := c.WriteNodeValue(ctx, f.Double, 1.25)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, st)
	awaitMonitorMsg(t, ch, f.Double, 1.25)
	expectNoMonitorMsg(t, ch, f.Int32, 150*time.Millisecond)

	require.NoError(t, sub.SetMonitoringModeForNodeIDs(ctx, ua.MonitoringModeReporting, f.Int32))
	writeInt32(t, c, f.Int32, 2)
	awaitMonitorMsg(t, ch, f.Int32, int32(2))

	require.NoError(t, sub.SetMonitoringMode(ctx, ua.MonitoringModeDisabled, items...))
	st, err = c.WriteNodeValue(ctx, f.Uint32, uint32(7))
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, st)
	writeInt32(t, c, f.Int32, 3)
	awaitMonitorMsg(t, ch, f.Int32, int32(3))
	expectNoMonitorMsg(t, ch, f.Uint32, 150*time.Millisecond)
	require.NoError(t, sub.SetMonitoringMode(ctx, ua.MonitoringModeReporting, items...))

	// ModifyMonitorItems is accepted for a monitored node and keeps delivery
	// mapped to the right node.
	require.NoError(t, sub.ModifyMonitorItems(ctx, monitor.Request{
		NodeID:               f.Int32,
		MonitoringParameters: &ua.MonitoringParameters{QueueSize: 3, DiscardOldest: true},
	}))
	writeInt32(t, c, f.Int32, 4)
	awaitMonitorMsg(t, ch, f.Int32, int32(4))

	// Modify the subscription itself.
	require.NoError(t, sub.Modify(ctx, &opcua.SubscriptionParameters{Interval: 30 * time.Millisecond}))
	writeInt32(t, c, f.Int32, 5)
	awaitMonitorMsg(t, ch, f.Int32, int32(5))

	// Remove nodes three ways.
	require.NoError(t, sub.RemoveNodes(ctx, f.Double.String()))
	require.NoError(t, sub.RemoveNodeIDs(ctx, f.String))
	require.NoError(t, sub.RemoveMonitorItems(ctx, items...))
	require.Equal(t, 1, sub.Subscribed())
	require.Error(t, sub.RemoveMonitorItems(ctx, items...), "removing twice must fail")
	st, err = c.WriteNodeValue(ctx, f.Double, 9.5)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, st)
	writeInt32(t, c, f.Int32, 6)
	awaitMonitorMsg(t, ch, f.Int32, int32(6))
	expectNoMonitorMsg(t, ch, f.Double, 150*time.Millisecond)

	require.GreaterOrEqual(t, sub.Delivered(), uint64(9))
	require.Zero(t, sub.Dropped())

	id := sub.SubscriptionID()
	require.NoError(t, sub.Unsubscribe(ctx))
	require.NotContains(t, c.SubscriptionIDs(), id)
}

// TestMonitor_CallbackSubscription covers the callback flavour, the error
// handler and the slow-consumer accounting.
func TestMonitor_CallbackSubscription(t *testing.T) {
	c, f, ctx := setup(t)
	m, err := monitor.NewNodeMonitor(c)
	require.NoError(t, err)

	var mu sync.Mutex
	got := map[string][]any{}
	var subSeen *monitor.Subscription
	sub, err := m.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: fastInterval},
		func(s *monitor.Subscription, msg *monitor.DataChangeMessage) {
			mu.Lock()
			defer mu.Unlock()
			subSeen = s
			if msg.Error == nil {
				got[msg.NodeID.String()] = append(got[msg.NodeID.String()], msg.Value.Value())
			}
		},
		f.Int32.String(), f.String.String(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Unsubscribe(ctx) })
	defer func() { _ = sub.Unsubscribe(ctx) }()
	require.Equal(t, 2, sub.Subscribed())

	last := func(n *ua.NodeID) any {
		mu.Lock()
		defer mu.Unlock()
		vs := got[n.String()]
		if len(vs) == 0 {
			return nil
		}
		return vs[len(vs)-1]
	}
	eventually(t, func() bool { return last(f.Int32) == int32(42) && last(f.String) == "hello" }, "initial values via callback")

	for i := int32(1); i <= 5; i++ {
		writeInt32(t, c, f.Int32, i)
		eventually(t, func() bool { return last(f.Int32) == i }, "callback sees each write")
	}
	mu.Lock()
	require.Same(t, sub, subSeen, "the callback receives its subscription")
	require.Equal(t, []any{int32(42), int32(1), int32(2), int32(3), int32(4), int32(5)}, got[f.Int32.String()], "in order, nothing lost")
	mu.Unlock()
	// Counted after the callback returned.
	eventually(t, func() bool { return sub.Delivered() >= 7 }, "deliveries counted")
}

// TestMonitor_SlowConsumerIsReported verifies messages that cannot be handed
// to a full channel are counted as dropped and reported to the error handler.
func TestMonitor_SlowConsumerIsReported(t *testing.T) {
	c, f, ctx := setup(t)
	m, err := monitor.NewNodeMonitor(c)
	require.NoError(t, err)

	errs := make(chan error, 64)
	m.SetErrorHandler(func(cl *opcua.Client, s *monitor.Subscription, err error) {
		if cl == c && s != nil {
			select {
			case errs <- err:
			default:
			}
		}
	})

	// Nobody reads from this unbuffered channel.
	stuck := make(chan *monitor.DataChangeMessage)
	sub, err := m.ChanSubscribe(ctx, &opcua.SubscriptionParameters{Interval: fastInterval}, stuck, f.Int32.String())
	require.NoError(t, err)
	defer func() { _ = sub.Unsubscribe(ctx) }()

	select {
	case err := <-errs:
		require.ErrorIs(t, err, monitor.ErrSlowConsumer)
	case <-time.After(waitTimeout):
		t.Fatal("slow consumer was not reported")
	}
	eventually(t, func() bool { return sub.Dropped() >= 1 }, "dropped counter")
	require.Zero(t, sub.Delivered())
}

// TestSubscription_Stats verifies Subscription.Stats picks the entry for its
// own subscription out of the server's SubscriptionDiagnosticsArray. The
// in-process server does not maintain these diagnostics itself, so the test
// publishes an array through the standard node.
func TestSubscription_Stats(t *testing.T) {
	var diag []*ua.ExtensionObject
	var mu sync.Mutex
	c, _, _, _ := setupWith(t, func(srv *server.Server, _ *testutil.Fixture) {
		node := server.NewVariableNode(ua.NewNumericNodeID(0, id.ServerServerDiagnosticsSubscriptionDiagnosticsArray),
			"SubscriptionDiagnosticsArray", func() *ua.DataValue {
				mu.Lock()
				defer mu.Unlock()
				return server.DataValueFromValue(diag)
			})
		ns0, err := srv.Namespace(0)
		require.NoError(t, err)
		ns0.AddNode(node)
	})
	ctx := context.Background()

	a, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: time.Hour}, make(chan *opcua.PublishNotificationData, 4))
	require.NoError(t, err)
	b, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: time.Hour}, make(chan *opcua.PublishNotificationData, 4))
	require.NoError(t, err)

	mu.Lock()
	diag = []*ua.ExtensionObject{
		ua.NewExtensionObject(&ua.SubscriptionDiagnosticsDataType{
			SessionID: c.Session().SessionID(), SubscriptionID: a.SubscriptionID, Priority: 1,
			PublishingInterval: 3_600_000, MaxKeepAliveCount: 3000, PublishRequestCount: 11, MonitoredItemCount: 3,
		}),
		ua.NewExtensionObject(&ua.SubscriptionDiagnosticsDataType{
			SessionID: c.Session().SessionID(), SubscriptionID: b.SubscriptionID, Priority: 2,
			PublishingInterval: 3_600_000, MaxKeepAliveCount: 3000, PublishRequestCount: 22, MonitoredItemCount: 7,
		}),
	}
	mu.Unlock()

	sa, err := a.Stats(ctx)
	require.NoError(t, err)
	require.Equal(t, a.SubscriptionID, sa.SubscriptionID)
	require.Equal(t, uint32(11), sa.PublishRequestCount)
	require.Equal(t, uint32(3), sa.MonitoredItemCount)
	require.Equal(t, c.Session().SessionID().String(), sa.SessionID.String())

	sb, err := b.Stats(ctx)
	require.NoError(t, err)
	require.Equal(t, b.SubscriptionID, sb.SubscriptionID)
	require.Equal(t, uint32(22), sb.PublishRequestCount)
	require.Equal(t, uint8(2), sb.Priority)

	// A subscription missing from the array is reported as not found.
	mu.Lock()
	diag = diag[:1]
	mu.Unlock()
	_, err = b.Stats(ctx)
	require.Error(t, err)
	_, err = a.Stats(ctx)
	require.NoError(t, err)

	// The monitor package forwards to the same call.
	m, err := monitor.NewNodeMonitor(c)
	require.NoError(t, err)
	msub, err := m.ChanSubscribe(ctx, &opcua.SubscriptionParameters{Interval: time.Hour}, make(chan *monitor.DataChangeMessage, 4))
	require.NoError(t, err)
	t.Cleanup(func() { _ = msub.Unsubscribe(ctx) })
	mu.Lock()
	diag = append(diag, ua.NewExtensionObject(&ua.SubscriptionDiagnosticsDataType{SubscriptionID: msub.SubscriptionID(), NotificationsCount: 99}))
	mu.Unlock()
	ms, err := msub.Stats(ctx)
	require.NoError(t, err)
	require.Equal(t, uint32(99), ms.NotificationsCount)
}

// TestSubscription_BuilderOptions verifies every SubscriptionBuilder option
// takes effect.
func TestSubscription_BuilderOptions(t *testing.T) {
	c, f, ctx := setup(t)

	t.Run("ParametersAndChannel", func(t *testing.T) {
		own := make(chan *opcua.PublishNotificationData, 64)
		sub, ch, err := c.NewSubscription().
			Interval(40*time.Millisecond).
			LifetimeCount(90).
			MaxKeepAliveCount(30).
			MaxNotificationsPerPublish(1).
			Priority(7).
			Timestamps(ua.TimestampsToReturnServer).
			SamplingInterval(40*time.Millisecond).
			NotifyChannel(own).
			Monitor(f.Int16, f.Int32, f.Int64).
			Start(ctx)
		require.NoError(t, err)
		defer func() { _ = sub.Cancel(ctx) }()
		require.Equal(t, (chan *opcua.PublishNotificationData)(own), ch, "Start returns the supplied channel")
		require.Equal(t, 40*time.Millisecond, sub.RevisedPublishingInterval)
		require.Equal(t, uint32(90), sub.RevisedLifetimeCount)
		require.Equal(t, uint32(30), sub.RevisedMaxKeepAliveCount)

		// MaxNotificationsPerPublish(1): three initial values arrive in three
		// separate notifications, one sample each, for handles 0..2 (in the
		// order the server happened to sample them) and with only the server
		// timestamp.
		var handlesSeen []uint32
		for len(handlesSeen) < 3 {
			samples := nextDataChanges(t, own)
			require.Len(t, samples, 1, "at most one notification per publish")
			handlesSeen = append(handlesSeen, samples[0].Handle)
			require.False(t, samples[0].DV.ServerTimestamp.IsZero())
			require.True(t, samples[0].DV.SourceTimestamp.IsZero())
		}
		require.ElementsMatch(t, []uint32{0, 1, 2}, handlesSeen)
	})

	t.Run("MonitorItemsWithCustomRequests", func(t *testing.T) {
		req := opcua.NewMonitoredItemCreateRequestWithDefaults(f.Double, ua.AttributeIDValue, 4711)
		req.RequestedParameters.QueueSize = 1
		sub, ch, err := c.NewSubscription().Interval(fastInterval).MonitorItems(req).Start(ctx)
		require.NoError(t, err)
		defer func() { _ = sub.Cancel(ctx) }()
		require.Equal(t, 256, cap(ch), "default notification channel is buffered")
		awaitValue(t, ch, 4711, 3.14159)
	})

	t.Run("NoItems", func(t *testing.T) {
		sub, ch, err := c.NewSubscription().Start(ctx)
		require.NoError(t, err)
		require.NotNil(t, ch)
		require.Equal(t, opcua.DefaultSubscriptionInterval, sub.RevisedPublishingInterval)
		require.NoError(t, sub.Cancel(ctx))
	})

	t.Run("StartFailsWhenNotConnected", func(t *testing.T) {
		offline, err := opcua.NewClient("opc.tcp://localhost:1")
		require.NoError(t, err)
		_, _, err = offline.NewSubscription().Monitor(f.Int32).Start(ctx)
		require.ErrorIs(t, err, ua.StatusBadServerNotConnected)
	})
}
