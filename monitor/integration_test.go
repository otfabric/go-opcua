// SPDX-License-Identifier: MIT

package monitor_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/monitor"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestNodeMonitor_ChanSubscribeDataChange(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	f := testutil.AddFixture(t, srv)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	m, err := monitor.NewNodeMonitor(c)
	require.NoError(t, err)

	ch := make(chan *monitor.DataChangeMessage, 4)
	sub, err := m.ChanSubscribe(ctx, &opcua.SubscriptionParameters{
		Interval: 100 * time.Millisecond,
	}, ch)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Unsubscribe(ctx) })

	_, err = sub.AddMonitorItems(ctx, monitor.Request{NodeID: f.Int32})
	require.NoError(t, err)

	deadline := time.After(5 * time.Second)
	for {
		select {
		case msg := <-ch:
			if msg.Error == nil && msg.NodeID.String() == f.Int32.String() {
				return
			}
		case <-deadline:
			t.Fatal("timed out waiting for data change")
		}
	}
}

func TestNodeMonitor_ModifyAndUnsubscribe(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	f := testutil.AddFixture(t, srv)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	m, err := monitor.NewNodeMonitor(c)
	require.NoError(t, err)

	ch := make(chan *monitor.DataChangeMessage, 4)
	sub, err := m.ChanSubscribe(ctx, &opcua.SubscriptionParameters{
		Interval: 100 * time.Millisecond,
	}, ch)
	require.NoError(t, err)

	items, err := sub.AddMonitorItems(ctx, monitor.Request{NodeID: f.Double})
	require.NoError(t, err)
	require.Len(t, items, 1)

	require.NoError(t, sub.ModifyMonitorItems(ctx, monitor.Request{
		NodeID: f.Double,
		MonitoringParameters: &ua.MonitoringParameters{
			SamplingInterval: 200,
		},
	}))
	require.Equal(t, 1, sub.Subscribed())

	require.NoError(t, sub.RemoveMonitorItems(ctx, items[0]))
	require.Equal(t, 0, sub.Subscribed())

	require.NoError(t, sub.Unsubscribe(ctx))
}

func TestNodeMonitor_PartialBatchItemError(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	f := testutil.AddFixture(t, srv)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	m, err := monitor.NewNodeMonitor(c)
	require.NoError(t, err)

	ch := make(chan *monitor.DataChangeMessage, 4)
	sub, err := m.ChanSubscribe(ctx, &opcua.SubscriptionParameters{
		Interval: 100 * time.Millisecond,
	}, ch)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Unsubscribe(ctx) })

	items, err := sub.AddMonitorItems(ctx,
		monitor.Request{NodeID: f.Int32},
		monitor.Request{NodeID: ua.NewStringNodeID(f.NSIndex, "missing")},
	)
	require.Len(t, items, 1)
	require.Error(t, err)

	var itemErr *monitor.ItemError
	require.True(t, errors.As(err, &itemErr))
	require.Equal(t, ua.StatusBadNodeIDUnknown, itemErr.StatusCode)
}

func TestNodeMonitor_CallbackSubscribe(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	f := testutil.AddFixture(t, srv)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	m, err := monitor.NewNodeMonitor(c)
	require.NoError(t, err)

	got := make(chan struct{}, 1)
	sub, err := m.Subscribe(ctx, &opcua.SubscriptionParameters{
		Interval: 100 * time.Millisecond,
	}, func(_ *monitor.Subscription, msg *monitor.DataChangeMessage) {
		if msg.Error == nil && msg.NodeID.String() == f.Int32.String() {
			select {
			case got <- struct{}{}:
			default:
			}
		}
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Unsubscribe(ctx) })

	_, err = sub.AddMonitorItems(ctx, monitor.Request{NodeID: f.Int32})
	require.NoError(t, err)

	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for callback notification")
	}
}

func TestNodeMonitor_SetMonitoringModeAndStats(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	f := testutil.AddFixture(t, srv)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	m, err := monitor.NewNodeMonitor(c)
	require.NoError(t, err)

	ch := make(chan *monitor.DataChangeMessage, 4)
	sub, err := m.ChanSubscribe(ctx, &opcua.SubscriptionParameters{
		Interval: 100 * time.Millisecond,
	}, ch)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Unsubscribe(ctx) })

	items, err := sub.AddMonitorItems(ctx, monitor.Request{NodeID: f.Int32})
	require.NoError(t, err)
	require.Len(t, items, 1)

	require.NoError(t, sub.SetMonitoringMode(ctx, ua.MonitoringModeDisabled, items[0]))
	require.NoError(t, sub.SetMonitoringMode(ctx, ua.MonitoringModeReporting, items[0]))

	_, err = sub.Stats(ctx)
	require.Error(t, err)
	require.NotZero(t, sub.SubscriptionID())
}

func TestNodeMonitor_StringNodeHelpers(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	f := testutil.AddFixture(t, srv)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	m, err := monitor.NewNodeMonitor(c)
	require.NoError(t, err)

	ch := make(chan *monitor.DataChangeMessage, 4)
	sub, err := m.ChanSubscribe(ctx, &opcua.SubscriptionParameters{
		Interval: 100 * time.Millisecond,
	}, ch)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Unsubscribe(ctx) })

	require.NoError(t, sub.AddNodes(ctx, f.Double.String()))
	require.Equal(t, 1, sub.Subscribed())

	require.NoError(t, sub.SetMonitoringModeForNodes(ctx, ua.MonitoringModeDisabled, f.Double.String()))
	require.NoError(t, sub.SetMonitoringModeForNodes(ctx, ua.MonitoringModeReporting, f.Double.String()))

	require.NoError(t, sub.Modify(ctx, &opcua.SubscriptionParameters{
		Interval: 200 * time.Millisecond,
	}))
	require.NoError(t, sub.RemoveNodes(ctx, f.Double.String()))
	require.Equal(t, 0, sub.Subscribed())
}

func TestNodeMonitor_AddRemoveNodesByID(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	f := testutil.AddFixture(t, srv)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	m, err := monitor.NewNodeMonitor(c)
	require.NoError(t, err)

	ch := make(chan *monitor.DataChangeMessage, 4)
	sub, err := m.ChanSubscribe(ctx, &opcua.SubscriptionParameters{
		Interval: 100 * time.Millisecond,
	}, ch)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Unsubscribe(ctx) })

	require.NoError(t, sub.AddNodeIDs(ctx, f.Double))
	require.Equal(t, 1, sub.Subscribed())
	require.NoError(t, sub.RemoveNodeIDs(ctx, f.Double))
	require.Equal(t, 0, sub.Subscribed())
}
