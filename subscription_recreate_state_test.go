// SPDX-License-Identifier: MIT

package opcua_test

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// A recreated subscription keeps the publishing mode the caller set: one
// that was disabled with SetPublishingMode comes back disabled (Part 4
// §5.14.2.2, publishingEnabled), through Subscription.SetPublishingMode and
// Client.SetPublishingMode alike.
//
// Regression: the recreation always sent PublishingEnabled TRUE.
func TestRecreateSubscription_KeepsPublishingMode(t *testing.T) {
	t.Parallel()
	srv, url := testutil.NewTestServer(t)
	ns := testutil.AddTestNodes(t, srv)
	c := testutil.NewTestClient(t, url)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	notify := make(chan *opcua.PublishNotificationData, 64)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 50 * time.Millisecond}, notify)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(context.Background()) })
	_, err = sub.Monitor(ctx, ua.TimestampsToReturnBoth,
		opcua.NewMonitoredItemCreateRequestWithDefaults(ua.NewStringNodeID(ns.ID(), "IntVar"), ua.AttributeIDValue, 1))
	require.NoError(t, err)

	publishing := func() bool {
		t.Helper()
		st, err := sub.Stats(ctx)
		require.NoError(t, err)
		return st.PublishingEnabled
	}

	res, err := sub.SetPublishingMode(ctx, false)
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, res.Results)
	require.NoError(t, c.TestingRecreateSubscription(ctx, sub.SubscriptionID))
	require.False(t, publishing(), "the recreated subscription must stay disabled")

	res, err = c.SetPublishingMode(ctx, true, sub.SubscriptionID, sub.SubscriptionID+1000)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, res.Results[0])
	require.NoError(t, c.TestingRecreateSubscription(ctx, sub.SubscriptionID))
	require.True(t, publishing(), "the recreated subscription must be enabled again")
}

// A recreated subscription gets its triggering links back, with the new
// server ids of its items (Part 4 §5.13.5): an item to report in sampling
// mode is reported when its triggering item reports.
//
// Regression: the links were not recreated, so the item to report never
// reported again.
func TestRecreateSubscription_RestoresTriggeringLinks(t *testing.T) {
	t.Parallel()
	srv, url := testutil.NewTestServer(t)
	ns := testutil.AddTestNodes(t, srv)
	c := testutil.NewTestClient(t, url)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	trigNode := ua.NewStringNodeID(ns.ID(), "IntVar")
	reportNode := ua.NewStringNodeID(ns.ID(), "FloatVar")
	const trigHandle, reportHandle = 1, 2

	notify := make(chan *opcua.PublishNotificationData, 64)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 50 * time.Millisecond}, notify)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(context.Background()) })

	reportReq := opcua.NewMonitoredItemCreateRequestWithDefaults(reportNode, ua.AttributeIDValue, reportHandle)
	reportReq.MonitoringMode = ua.MonitoringModeSampling
	res, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth,
		opcua.NewMonitoredItemCreateRequestWithDefaults(trigNode, ua.AttributeIDValue, trigHandle), reportReq)
	require.NoError(t, err)
	trigID, reportID := res.Results[0].MonitoredItemID, res.Results[1].MonitoredItemID
	trig, err := sub.SetTriggering(ctx, trigID, []uint32{reportID}, nil)
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, trig.AddResults)

	require.NoError(t, c.TestingRecreateSubscription(ctx, sub.SubscriptionID))

	write := func(n *ua.NodeID, v any) {
		t.Helper()
		wr, err := c.Write(ctx, &ua.WriteRequest{NodesToWrite: []*ua.WriteValue{{
			NodeID: n, AttributeID: ua.AttributeIDValue,
			Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)},
		}}})
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, wr.Results[0])
	}
	write(reportNode, float64(7.5))
	write(trigNode, int32(77))

	deadline := time.After(20 * time.Second)
	for {
		select {
		case msg := <-notify:
			if msg == nil || msg.Error != nil {
				continue
			}
			if dcn, ok := msg.Value.(*ua.DataChangeNotification); ok {
				for _, it := range dcn.MonitoredItems {
					if it.ClientHandle == reportHandle && it.Value.Value.Value() == float64(7.5) {
						return
					}
				}
			}
		case <-deadline:
			t.Fatal("the item to report was not reported with its triggering item after the recreation")
		}
	}
}

// restoreTriggering reports the links the server does not create, and
// keeps them for the next recreation.
func TestRestoreTriggering_ServerRefuses(t *testing.T) {
	t.Parallel()
	srv, url := testutil.NewTestServer(t)
	ns := testutil.AddTestNodes(t, srv)
	c := testutil.NewTestClient(t, url)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 50 * time.Millisecond}, make(chan *opcua.PublishNotificationData, 64))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(context.Background()) })
	res, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth,
		opcua.NewMonitoredItemCreateRequestWithDefaults(ua.NewStringNodeID(ns.ID(), "IntVar"), ua.AttributeIDValue, 1),
		opcua.NewMonitoredItemCreateRequestWithDefaults(ua.NewStringNodeID(ns.ID(), "FloatVar"), ua.AttributeIDValue, 2))
	require.NoError(t, err)
	trigID, reportID := res.Results[0].MonitoredItemID, res.Results[1].MonitoredItemID
	_, err = sub.SetTriggering(ctx, trigID, []uint32{reportID}, nil)
	require.NoError(t, err)

	// The server re-links what it has.
	require.NoError(t, sub.TestingRestoreTriggering(ctx))

	// An item to report the server does not know.
	sub.TestingSetItemServerID(reportID, 0x7fff0000)
	err = sub.TestingRestoreTriggering(ctx)
	require.ErrorIs(t, err, ua.StatusBadMonitoredItemIDInvalid)
	require.Contains(t, err.Error(), "item to report")

	// A triggering item the server does not know fails the request.
	sub.TestingSetItemServerID(trigID, 0x7fff0001)
	err = sub.TestingRestoreTriggering(ctx)
	require.ErrorIs(t, err, ua.StatusBadMonitoredItemIDInvalid)
	require.NotContains(t, err.Error(), "item to report")
}

// A SetTriggering request that removes and adds the same link keeps it:
// "The list of linksToRemove is processed before the linksToAdd" (Part 4
// §5.13.5.2, Table 72). The item to report in sampling mode is reported
// with its triggering item afterwards.
//
// Regression: the go-opcua server processed the additions first and
// removed the link again.
func TestSetTriggering_RemoveAndAddKeepsLink(t *testing.T) {
	t.Parallel()
	srv, url := testutil.NewTestServer(t)
	ns := testutil.AddTestNodes(t, srv)
	c := testutil.NewTestClient(t, url)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	trigNode := ua.NewStringNodeID(ns.ID(), "IntVar")
	reportNode := ua.NewStringNodeID(ns.ID(), "FloatVar")
	const trigHandle, reportHandle = 1, 2

	notify := make(chan *opcua.PublishNotificationData, 64)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 50 * time.Millisecond}, notify)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(context.Background()) })

	reportReq := opcua.NewMonitoredItemCreateRequestWithDefaults(reportNode, ua.AttributeIDValue, reportHandle)
	reportReq.MonitoringMode = ua.MonitoringModeSampling
	res, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth,
		opcua.NewMonitoredItemCreateRequestWithDefaults(trigNode, ua.AttributeIDValue, trigHandle), reportReq)
	require.NoError(t, err)
	trigID, reportID := res.Results[0].MonitoredItemID, res.Results[1].MonitoredItemID
	_, err = sub.SetTriggering(ctx, trigID, []uint32{reportID}, nil)
	require.NoError(t, err)
	trig, err := sub.SetTriggering(ctx, trigID, []uint32{reportID}, []uint32{reportID})
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, trig.RemoveResults)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, trig.AddResults)

	write := func(n *ua.NodeID, v any) {
		t.Helper()
		wr, err := c.Write(ctx, &ua.WriteRequest{NodesToWrite: []*ua.WriteValue{{
			NodeID: n, AttributeID: ua.AttributeIDValue,
			Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)},
		}}})
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, wr.Results[0])
	}
	write(reportNode, float64(8.5))
	write(trigNode, int32(78))

	deadline := time.After(20 * time.Second)
	for {
		select {
		case msg := <-notify:
			if msg == nil || msg.Error != nil {
				continue
			}
			if dcn, ok := msg.Value.(*ua.DataChangeNotification); ok {
				for _, it := range dcn.MonitoredItems {
					if it.ClientHandle == reportHandle && it.Value.Value.Value() == float64(8.5) {
						return
					}
				}
			}
		case <-deadline:
			t.Fatal("the item to report was not reported: the link was removed")
		}
	}
}
