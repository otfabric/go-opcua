// SPDX-License-Identifier: MIT

package opcua_test

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// The id Monitor returns must keep denoting the same item after the
// subscription is recreated on the server, although the server then knows the
// items by new ids. Before, an id obtained before a reconnect could address a
// different item afterwards: Unmonitor removed the wrong one.
func TestMonitoredItemIDsSurviveRecreation(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	ns := server.NewNodeNameSpace(srv, "StableIDs")
	nodes := make([]*ua.NodeID, 4)
	for i := range nodes {
		n := ns.AddNewVariableStringNode(string(rune('A'+i)), int32(0))
		nodes[i] = n.ID()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c := testutil.NewTestClient(t, url)

	notifyCh := make(chan *opcua.PublishNotificationData, 256)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 50 * time.Millisecond}, notifyCh)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(context.Background()) })

	// Create the items one by one and delete the first, so the ids the server
	// hands out after a recreation (1..3 again) cannot line up with the ids
	// the caller holds (2..4).
	ids := make([]uint32, len(nodes))
	for i, n := range nodes {
		res, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth,
			opcua.NewMonitoredItemCreateRequestWithDefaults(n, ua.AttributeIDValue, uint32(100+i)))
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, res.Results[0].StatusCode)
		ids[i] = res.Results[0].MonitoredItemID
	}
	del, err := sub.Unmonitor(ctx, ids[0])
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, del.Results[0])

	require.NoError(t, c.TestingRecreateSubscription(ctx, sub.SubscriptionID))

	// The ids still held by the caller address their own items: remove B (the
	// item with client handle 101) by its original id.
	del, err = sub.Unmonitor(ctx, ids[1])
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, del.Results[0])

	// A new item must not be handed an id the caller already holds.
	extra, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth,
		opcua.NewMonitoredItemCreateRequestWithDefaults(nodes[0], ua.AttributeIDValue, 200))
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, extra.Results[0].StatusCode)
	for _, id := range ids[2:] {
		require.NotEqual(t, id, extra.Results[0].MonitoredItemID, "new item reuses an id the caller holds")
	}

	// Modify C and switch D to sampling through their original ids; both
	// must be accepted, and neither may touch the other items.
	mod, err := sub.ModifyMonitoredItems(ctx, ua.TimestampsToReturnBoth, &ua.MonitoredItemModifyRequest{
		MonitoredItemID:     ids[2],
		RequestedParameters: &ua.MonitoringParameters{ClientHandle: 302, QueueSize: 5, DiscardOldest: true},
	})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, mod.Results[0].StatusCode)
	mode, err := sub.SetMonitoringMode(ctx, ua.MonitoringModeSampling, ids[3])
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, mode.Results[0])

	// Write a fresh value to every node and collect which client handles
	// report: A through the new item (200), C under its modified handle
	// (302); B was removed and D only samples.
	for i, n := range nodes {
		st, err := c.WriteValue(ctx, n, &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int32(1000 + i))})
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, st)
	}
	got := map[uint32]int32{}
	deadline := time.After(20 * time.Second)
	for len(got) < 2 {
		select {
		case msg := <-notifyCh:
			require.NoError(t, msg.Error)
			dcn, ok := msg.Value.(*ua.DataChangeNotification)
			if !ok {
				continue
			}
			for _, mi := range dcn.MonitoredItems {
				if v, ok := mi.Value.Value.Value().(int32); ok && v >= 1000 {
					got[mi.ClientHandle] = v
				}
			}
		case <-deadline:
			t.Fatalf("notifications after recreation: %v, want handles 200 and 302", got)
		}
	}
	// Give a wrongly surviving item (B, handle 101) or a wrongly reporting
	// one (D, handle 103) a chance to show up.
	settle := time.After(500 * time.Millisecond)
drain:
	for {
		select {
		case msg := <-notifyCh:
			if dcn, ok := msg.Value.(*ua.DataChangeNotification); ok {
				for _, mi := range dcn.MonitoredItems {
					if v, ok := mi.Value.Value.Value().(int32); ok && v >= 1000 {
						got[mi.ClientHandle] = v
					}
				}
			}
		case <-settle:
			break drain
		}
	}
	require.Equal(t, map[uint32]int32{200: 1000, 302: 1002}, got)

	// An id that denotes nothing is still reported by the server.
	del, err = sub.Unmonitor(ctx, 987654)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadMonitoredItemIDInvalid, del.Results[0])
}
