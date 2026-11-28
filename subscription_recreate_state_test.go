// SPDX-License-Identifier: MIT

package opcua_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/cleanup"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
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
	cleanup.Register(t, func() { _ = sub.Cancel(context.Background()) })
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
	cleanup.Register(t, func() { _ = sub.Cancel(context.Background()) })

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
	cleanup.Register(t, func() { _ = sub.Cancel(context.Background()) })
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

// Unmonitor drops the links of the items it deletes: "When a MonitoredItem
// is deleted, its triggered item links are also deleted" (Part 4
// §5.13.6.1), and so is a link to a deleted item to report (§5.13.1.6), so
// a recreation does not send them.
func TestUnmonitor_DropsTriggeringLinks(t *testing.T) {
	t.Parallel()
	srv, url := testutil.NewTestServer(t)
	ns := testutil.AddTestNodes(t, srv)
	c := testutil.NewTestClient(t, url)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 50 * time.Millisecond}, make(chan *opcua.PublishNotificationData, 64))
	require.NoError(t, err)
	cleanup.Register(t, func() { _ = sub.Cancel(context.Background()) })
	var reqs []*ua.MonitoredItemCreateRequest
	for i, name := range []string{"IntVar", "FloatVar", "StringVar", "IntVar"} {
		reqs = append(reqs, opcua.NewMonitoredItemCreateRequestWithDefaults(ua.NewStringNodeID(ns.ID(), name), ua.AttributeIDValue, uint32(i+1)))
	}
	res, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, reqs...)
	require.NoError(t, err)
	var ids []uint32
	for _, r := range res.Results {
		require.Equal(t, ua.StatusOK, r.StatusCode)
		ids = append(ids, r.MonitoredItemID)
	}
	a, b, d, e := ids[0], ids[1], ids[2], ids[3]
	for _, l := range []struct {
		trigger uint32
		reports []uint32
	}{{a, []uint32{b, d}}, {e, []uint32{d}}} {
		_, err := sub.SetTriggering(ctx, l.trigger, l.reports, nil)
		require.NoError(t, err)
	}
	require.Equal(t, map[uint32][]uint32{a: {b, d}, e: {d}}, sub.TestingTriggers())

	// An item to report: the links to it go, and a triggering item left
	// without links is forgotten.
	_, err = sub.Unmonitor(ctx, d)
	require.NoError(t, err)
	require.Equal(t, map[uint32][]uint32{a: {b}}, sub.TestingTriggers())

	// A triggering item: its links go with it.
	_, err = sub.Unmonitor(ctx, a)
	require.NoError(t, err)
	require.Empty(t, sub.TestingTriggers())
}

// restoreTriggering reports a link the response of the server has no
// result for as not created (Bad_UnknownResponse): the addResults have
// "the size and order" of linksToAdd (Part 4 §5.13.5.2).
func TestRestoreTriggering_MissingResult(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	_, url := newScriptedServer(t, map[uint16]server.Handler{
		id.SetTriggeringRequestEncodingDefaultBinary: func(_ context.Context, _ *uasc.SecureChannel, r ua.Request, _ uint32) (ua.Response, error) {
			req := r.(*ua.SetTriggeringRequest)
			res := &ua.SetTriggeringResponse{ResponseHeader: &ua.ResponseHeader{RequestHandle: req.RequestHeader.RequestHandle, ServiceResult: ua.StatusOK}}
			if calls.Add(1) == 1 {
				res.AddResults = make([]ua.StatusCode, len(req.LinksToAdd)) // all Good
			}
			return res, nil
		},
	})
	c := connectCovClient(t, url)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 50 * time.Millisecond}, make(chan *opcua.PublishNotificationData, 64))
	require.NoError(t, err)
	cleanup.Register(t, func() { _ = sub.Cancel(context.Background()) })
	res, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth,
		opcua.NewMonitoredItemCreateRequestWithDefaults(ua.NewNumericNodeID(0, id.ServerServerStatusCurrentTime), ua.AttributeIDValue, 1),
		opcua.NewMonitoredItemCreateRequestWithDefaults(ua.NewNumericNodeID(0, id.ServerServerStatusState), ua.AttributeIDValue, 2))
	require.NoError(t, err)
	trigID, reportID := res.Results[0].MonitoredItemID, res.Results[1].MonitoredItemID
	_, err = sub.SetTriggering(ctx, trigID, []uint32{reportID}, nil)
	require.NoError(t, err)

	err = sub.TestingRestoreTriggering(ctx)
	require.ErrorIs(t, err, ua.StatusBadUnknownResponse)
	require.Contains(t, err.Error(), "item to report")
}

// A SetPublishingMode the server refuses for the subscription changes
// nothing the recreation uses. The client does not reconnect: its
// subscription recovery would recreate the deleted subscription itself
// (Bad_NoSubscription of the publish loop) while the test does.
func TestSetPublishingMode_RefusedKeepsMode(t *testing.T) {
	t.Parallel()
	srv, url := testutil.NewTestServer(t)
	testutil.AddTestNodes(t, srv)
	c := connectCovClient(t, url, opcua.AutoReconnect(false))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 50 * time.Millisecond}, make(chan *opcua.PublishNotificationData, 64))
	require.NoError(t, err)
	require.NoError(t, sub.TestingRecreateDelete(ctx)) // the server no longer has it
	res, err := sub.SetPublishingMode(ctx, false)
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusBadSubscriptionIDInvalid}, res.Results)
	require.NoError(t, sub.TestingRecreateCreate(ctx))
	cleanup.Register(t, func() { _ = sub.Cancel(context.Background()) })
	st, err := sub.Stats(ctx)
	require.NoError(t, err)
	require.True(t, st.PublishingEnabled, "the refused request did not disable publishing")
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
	cleanup.Register(t, func() { _ = sub.Cancel(context.Background()) })

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
