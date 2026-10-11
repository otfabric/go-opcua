// SPDX-License-Identifier: MIT

package conformance

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// refill disables publishing, performs the writes, re-enables publishing and
// returns the samples of the next data Publish. Writes are processed
// synchronously by the server, so the item queues are in a known state.
func (r *rawSub) refill(node *ua.NodeID, vals ...int32) []dataChange {
	r.t.Helper()
	r.setPublishing(false)
	for _, v := range vals {
		writeInt32(r.t, r.c, node, v)
	}
	r.setPublishing(true)
	return r.nextData()
}

// nextData returns the samples of the next Publish response carrying data,
// skipping keep-alives.
func (r *rawSub) nextData() []dataChange {
	r.t.Helper()
	var p *ua.PublishResponse
	eventually(r.t, func() bool { p = publish(r.t, r.c); return !isKeepAlive(p) }, "a data notification")
	return dataOf(r.t, p)
}

// TestMonitoredItem_CreateResults covers the per-item and service-level
// results of CreateMonitoredItems.
func TestMonitoredItem_CreateResults(t *testing.T) {
	c, f, url := rawSetup(t)
	sub := newRawSub(t, c, rawSubParams{interval: 50})

	t.Run("MixedBatch", func(t *testing.T) {
		res := sub.createItems(ua.TimestampsToReturnBoth,
			itemSpec{node: f.Int32, handle: 1, queue: 0},
			itemSpec{node: ua.NewStringNodeID(f.NSIndex, "DoesNotExist"), handle: 2, queue: 1},
			itemSpec{node: f.Double, handle: 3, queue: 5},
			itemSpec{node: ua.NewNumericNodeID(99, 1), handle: 4, queue: 1},
			itemSpec{node: f.String, handle: 5, queue: 100_000},
			// An event item needs an EventFilter.
			itemSpec{node: f.EventObject, attr: ua.AttributeIDEventNotifier, handle: 6, queue: 1},
		)
		want := []struct {
			status ua.StatusCode
			queue  uint32
		}{
			{ua.StatusOK, 1}, // 0 is revised up to 1
			{ua.StatusBadNodeIDUnknown, 0},
			{ua.StatusOK, 5}, // kept
			{ua.StatusBadNodeIDUnknown, 0},
			{ua.StatusOK, 100}, // capped at the server maximum
			{ua.StatusBadEventFilterInvalid, 0},
		}
		ids := map[uint32]bool{}
		for i, w := range want {
			require.Equal(t, w.status, res[i].StatusCode, "item %d", i)
			require.Equal(t, w.queue, res[i].RevisedQueueSize, "item %d", i)
			if w.status == ua.StatusOK {
				require.NotZero(t, res[i].MonitoredItemID)
				require.False(t, ids[res[i].MonitoredItemID], "duplicate monitored item id")
				ids[res[i].MonitoredItemID] = true
				require.Equal(t, sub.interval, res[i].RevisedSamplingInterval)
			} else {
				require.Zero(t, res[i].MonitoredItemID)
			}
		}
	})

	t.Run("InvalidTimestampsToReturn", func(t *testing.T) {
		_, err := sendRaw[ua.CreateMonitoredItemsResponse](t, c, &ua.CreateMonitoredItemsRequest{
			SubscriptionID:     sub.id,
			TimestampsToReturn: ua.TimestampsToReturn(17),
			ItemsToCreate:      []*ua.MonitoredItemCreateRequest{itemSpec{node: f.Int32, handle: 1}.request()},
		})
		require.ErrorIs(t, err, ua.StatusBadTimestampsToReturnInvalid)
	})

	t.Run("UnknownSubscription", func(t *testing.T) {
		_, err := sendRaw[ua.CreateMonitoredItemsResponse](t, c, &ua.CreateMonitoredItemsRequest{
			SubscriptionID:     sub.id + 1000,
			TimestampsToReturn: ua.TimestampsToReturnBoth,
			ItemsToCreate:      []*ua.MonitoredItemCreateRequest{itemSpec{node: f.Int32, handle: 1}.request()},
		})
		require.ErrorIs(t, err, ua.StatusBadSubscriptionIDInvalid)
	})

	t.Run("ForeignSubscription", func(t *testing.T) {
		_, err := sendRaw[ua.CreateMonitoredItemsResponse](t, newClient(t, url), &ua.CreateMonitoredItemsRequest{
			SubscriptionID:     sub.id,
			TimestampsToReturn: ua.TimestampsToReturnBoth,
			ItemsToCreate:      []*ua.MonitoredItemCreateRequest{itemSpec{node: f.Int32, handle: 1}.request()},
		})
		require.ErrorIs(t, err, ua.StatusBadSubscriptionIDInvalid)
	})

	t.Run("HighLevelPartialFailure", func(t *testing.T) {
		// The client API surfaces per-item failures in the response.
		hsub, err := c.Subscribe(context.Background(), &opcua.SubscriptionParameters{Interval: time.Hour}, make(chan *opcua.PublishNotificationData, 4))
		require.NoError(t, err)
		resp, err := hsub.Monitor(context.Background(), ua.TimestampsToReturnBoth,
			opcua.NewMonitoredItemCreateRequestWithDefaults(f.Int32, 0, 1),
			opcua.NewMonitoredItemCreateRequestWithDefaults(ua.NewStringNodeID(f.NSIndex, "Nope"), ua.AttributeIDValue, 2),
		)
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, resp.Results[0].StatusCode)
		require.Equal(t, uint32(10), resp.Results[0].RevisedQueueSize, "default request asks for a queue of 10")
		require.Equal(t, ua.StatusBadNodeIDUnknown, resp.Results[1].StatusCode)
	})
}

// TestMonitoredItem_QueueDeliversInOrder verifies a queue large enough for all
// samples delivers every one of them, oldest first, without the overflow bit.
func TestMonitoredItem_QueueDeliversInOrder(t *testing.T) {
	c, f, _ := rawSetup(t)
	sub := newRawSub(t, c, rawSubParams{})
	sub.mustCreateItems(ua.TimestampsToReturnNeither, itemSpec{node: f.Int32, handle: 3, queue: 10, discard: true})
	sub.primeItem(int32(42))

	samples := sub.refill(f.Int32, 1, 2, 3, 4, 5)
	require.Equal(t, []any{int32(1), int32(2), int32(3), int32(4), int32(5)}, values(samples))
	for _, s := range samples {
		require.Equal(t, uint32(3), s.handle)
		require.False(t, s.dv.Status.HasOverflow())
		require.Equal(t, ua.StatusOK, s.dv.Status)
	}
}

// TestMonitoredItem_QueueOverflow verifies the DiscardOldest policy and the
// Overflow info bit when more samples arrive than the queue can hold.
func TestMonitoredItem_QueueOverflow(t *testing.T) {
	_, f, url := rawSetup(t)

	t.Run("DiscardOldest", func(t *testing.T) {
		// One session per subtest: a Publish request is answered by any
		// subscription of the session.
		sub := newRawSub(t, newClient(t, url), rawSubParams{})
		sub.mustCreateItems(ua.TimestampsToReturnNeither, itemSpec{node: f.Int32, handle: 1, queue: 3, discard: true})
		sub.nextData() // initial value

		samples := sub.refill(f.Int32, 1, 2, 3, 4, 5)
		// The newest three survive; the oldest survivor carries the overflow bit.
		require.Equal(t, []any{int32(3), int32(4), int32(5)}, values(samples))
		require.True(t, samples[0].dv.Status.HasOverflow())
		require.Equal(t, ua.StatusOK.WithOverflow(), samples[0].dv.Status)
		require.False(t, samples[1].dv.Status.HasOverflow())
		require.False(t, samples[2].dv.Status.HasOverflow())
	})

	t.Run("DiscardNewest", func(t *testing.T) {
		// One session per subtest: a Publish request is answered by any
		// subscription of the session.
		sub := newRawSub(t, newClient(t, url), rawSubParams{})
		sub.mustCreateItems(ua.TimestampsToReturnNeither, itemSpec{node: f.Int32, handle: 1, queue: 3, discard: false})
		sub.nextData()

		samples := sub.refill(f.Int32, 1, 2, 3, 4, 5)
		// The oldest two survive; the last slot is overwritten by the newest
		// sample, which carries the overflow bit.
		require.Equal(t, []any{int32(1), int32(2), int32(5)}, values(samples))
		require.False(t, samples[0].dv.Status.HasOverflow())
		require.False(t, samples[1].dv.Status.HasOverflow())
		require.True(t, samples[2].dv.Status.HasOverflow())
	})

	t.Run("QueueSizeOneKeepsLatest", func(t *testing.T) {
		// One session per subtest: a Publish request is answered by any
		// subscription of the session.
		sub := newRawSub(t, newClient(t, url), rawSubParams{})
		sub.mustCreateItems(ua.TimestampsToReturnNeither, itemSpec{node: f.Int32, handle: 1, queue: 1, discard: true})
		sub.nextData()

		samples := sub.refill(f.Int32, 1, 2, 3)
		require.Equal(t, []any{int32(3)}, values(samples))
		require.False(t, samples[0].dv.Status.HasOverflow(), "a queue of one never reports overflow")
	})

	t.Run("NoOverflowAfterDrain", func(t *testing.T) {
		// One session per subtest: a Publish request is answered by any
		// subscription of the session.
		sub := newRawSub(t, newClient(t, url), rawSubParams{})
		sub.mustCreateItems(ua.TimestampsToReturnNeither, itemSpec{node: f.Int32, handle: 1, queue: 2, discard: true})
		sub.nextData()
		require.True(t, sub.refill(f.Int32, 1, 2, 3)[0].dv.Status.HasOverflow())
		// The next batch fits again and must be clean.
		samples := sub.refill(f.Int32, 10, 11)
		require.Equal(t, []any{int32(10), int32(11)}, values(samples))
		require.False(t, samples[0].dv.Status.HasOverflow())
		require.False(t, samples[1].dv.Status.HasOverflow())
	})
}

// TestMonitoredItem_MonitoringModes verifies Disabled (no sampling), Sampling
// (queue but do not report) and Reporting, and the transitions between them.
func TestMonitoredItem_MonitoringModes(t *testing.T) {
	c, f, url := rawSetup(t)
	sub := newRawSub(t, c, rawSubParams{keepAlive: 1})

	onlyKeepAlives := func(msg string) {
		t.Helper()
		for i := 0; i < 3; i++ {
			p := publish(t, c)
			require.True(t, isKeepAlive(p), "%s: got %v", msg, values(dataOf(t, p)))
		}
	}

	ids := sub.mustCreateItems(ua.TimestampsToReturnNeither,
		itemSpec{node: f.Int32, handle: 1, queue: 5, discard: true, modeSet: true, mode: ua.MonitoringModeDisabled})
	id := ids[0]

	// Disabled: neither the initial value nor later changes are sampled.
	writeInt32(t, c, f.Int32, 1)
	onlyKeepAlives("disabled item")

	// Sampling: changes are queued but not reported.
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, sub.setMode(ua.MonitoringModeSampling, id))
	writeInt32(t, c, f.Int32, 2)
	writeInt32(t, c, f.Int32, 3)
	onlyKeepAlives("sampling item")

	// Reporting: the samples queued while Sampling are delivered. The value
	// written while Disabled (1) was never sampled.
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, sub.setMode(ua.MonitoringModeReporting, id))
	require.Equal(t, []any{int32(2), int32(3)}, values(sub.nextData()))

	// Back to Disabled: queued samples are dropped.
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, sub.setMode(ua.MonitoringModeSampling, id))
	writeInt32(t, c, f.Int32, 4)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, sub.setMode(ua.MonitoringModeDisabled, id))
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, sub.setMode(ua.MonitoringModeReporting, id))
	onlyKeepAlives("queue must have been cleared by Disabled")

	writeInt32(t, c, f.Int32, 5)
	require.Equal(t, []any{int32(5)}, values(sub.nextData()))

	// Result codes for unknown and foreign items.
	foreign := newClient(t, url)
	require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusBadMonitoredItemIDInvalid},
		sub.setMode(ua.MonitoringModeReporting, id, id+1000))
	res := mustSendRaw[ua.SetMonitoringModeResponse](t, foreign, &ua.SetMonitoringModeRequest{
		SubscriptionID: sub.id, MonitoringMode: ua.MonitoringModeDisabled, MonitoredItemIDs: []uint32{id},
	})
	require.Equal(t, []ua.StatusCode{ua.StatusBadSessionIDInvalid}, res.Results)
	// The foreign request must not have disabled the item.
	writeInt32(t, c, f.Int32, 6)
	require.Equal(t, []any{int32(6)}, values(sub.nextData()))
}

// TestMonitoredItem_Modify verifies ModifyMonitoredItems changes the client
// handle, queue size, discard policy and timestamps of a live item.
func TestMonitoredItem_Modify(t *testing.T) {
	c, f, url := rawSetup(t)
	sub := newRawSub(t, c, rawSubParams{})
	id := sub.mustCreateItems(ua.TimestampsToReturnNeither, itemSpec{node: f.Int32, handle: 1, queue: 1, discard: true})[0]
	first := sub.nextData()
	require.Equal(t, uint32(1), first[0].handle)
	require.True(t, first[0].dv.ServerTimestamp.IsZero())

	modify := func(cl *opcua.Client, ts ua.TimestampsToReturn, items ...*ua.MonitoredItemModifyRequest) []*ua.MonitoredItemModifyResult {
		t.Helper()
		res := mustSendRaw[ua.ModifyMonitoredItemsResponse](t, cl, &ua.ModifyMonitoredItemsRequest{
			SubscriptionID: sub.id, TimestampsToReturn: ts, ItemsToModify: items,
		})
		require.Len(t, res.Results, len(items))
		return res.Results
	}
	params := func(handle, queue uint32, discard bool) *ua.MonitoringParameters {
		return &ua.MonitoringParameters{ClientHandle: handle, SamplingInterval: 250, QueueSize: queue, DiscardOldest: discard}
	}

	// Grow the queue, change handle and timestamps.
	res := modify(c, ua.TimestampsToReturnServer, &ua.MonitoredItemModifyRequest{MonitoredItemID: id, RequestedParameters: params(50, 3, true)})
	require.Equal(t, ua.StatusOK, res[0].StatusCode)
	require.Equal(t, uint32(3), res[0].RevisedQueueSize)
	require.Equal(t, float64(250), res[0].RevisedSamplingInterval)

	samples := sub.refill(f.Int32, 1, 2, 3, 4, 5)
	require.Equal(t, []any{int32(3), int32(4), int32(5)}, values(samples))
	require.True(t, samples[0].dv.Status.HasOverflow())
	for _, s := range samples {
		require.Equal(t, uint32(50), s.handle, "notifications must carry the modified client handle")
		require.False(t, s.dv.ServerTimestamp.IsZero(), "server timestamp requested by the modify")
		require.True(t, s.dv.SourceTimestamp.IsZero())
	}

	// Switch the discard policy.
	res = modify(c, ua.TimestampsToReturnNeither, &ua.MonitoredItemModifyRequest{MonitoredItemID: id, RequestedParameters: params(50, 3, false)})
	require.Equal(t, ua.StatusOK, res[0].StatusCode)
	samples = sub.refill(f.Int32, 1, 2, 3, 4, 5)
	require.Equal(t, []any{int32(1), int32(2), int32(5)}, values(samples))
	require.True(t, samples[2].dv.Status.HasOverflow())
	require.True(t, samples[0].dv.ServerTimestamp.IsZero())

	// Shrinking the queue while it holds samples keeps the newest ones.
	sub.setPublishing(false)
	for _, v := range []int32{6, 7, 8} {
		writeInt32(t, c, f.Int32, v)
	}
	res = modify(c, ua.TimestampsToReturnNeither, &ua.MonitoredItemModifyRequest{MonitoredItemID: id, RequestedParameters: params(50, 2, true)})
	require.Equal(t, uint32(2), res[0].RevisedQueueSize)
	sub.setPublishing(true)
	require.Equal(t, []any{int32(7), int32(8)}, values(sub.nextData()))

	// Queue size revision and per-item errors.
	res = modify(c, ua.TimestampsToReturnNeither,
		&ua.MonitoredItemModifyRequest{MonitoredItemID: id, RequestedParameters: params(50, 0, true)},
		&ua.MonitoredItemModifyRequest{MonitoredItemID: id, RequestedParameters: params(50, 5000, true)},
		&ua.MonitoredItemModifyRequest{MonitoredItemID: id + 1000, RequestedParameters: params(50, 1, true)},
	)
	require.Equal(t, uint32(1), res[0].RevisedQueueSize)
	require.Equal(t, uint32(100), res[1].RevisedQueueSize)
	require.Equal(t, ua.StatusBadMonitoredItemIDInvalid, res[2].StatusCode)

	res = modify(newClient(t, url), ua.TimestampsToReturnNeither,
		&ua.MonitoredItemModifyRequest{MonitoredItemID: id, RequestedParameters: params(99, 1, true)})
	require.Equal(t, ua.StatusBadSessionIDInvalid, res[0].StatusCode)
	// The foreign modify must not have changed the handle.
	writeInt32(t, c, f.Int32, 9)
	require.Equal(t, []uint32{50}, handles(sub.nextData()))
}

// TestMonitoredItem_DeleteAndTriggeringStatuses covers DeleteMonitoredItems and
// the SetTriggering result codes.
func TestMonitoredItem_DeleteAndTriggeringStatuses(t *testing.T) {
	c, f, url := rawSetup(t)
	foreign := newClient(t, url)
	sub := newRawSub(t, c, rawSubParams{keepAlive: 1})
	ids := sub.mustCreateItems(ua.TimestampsToReturnNeither,
		itemSpec{node: f.Int32, handle: 1, queue: 1, discard: true},
		itemSpec{node: f.Double, handle: 2, queue: 1, discard: true},
		itemSpec{node: f.String, handle: 3, queue: 1, discard: true},
	)
	trig, a, b := ids[0], ids[1], ids[2]

	t.Run("SetTriggering", func(t *testing.T) {
		res := mustSendRaw[ua.SetTriggeringResponse](t, c, &ua.SetTriggeringRequest{
			SubscriptionID:   sub.id,
			TriggeringItemID: trig,
			LinksToAdd:       []uint32{a, b + 1000, b},
			LinksToRemove:    []uint32{a, a + 1000},
		})
		require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusBadMonitoredItemIDInvalid, ua.StatusOK}, res.AddResults)
		require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusBadMonitoredItemIDInvalid}, res.RemoveResults)

		_, err := sendRaw[ua.SetTriggeringResponse](t, c, &ua.SetTriggeringRequest{
			SubscriptionID: sub.id, TriggeringItemID: trig + 1000, LinksToAdd: []uint32{a},
		})
		require.ErrorIs(t, err, ua.StatusBadMonitoredItemIDInvalid)

		_, err = sendRaw[ua.SetTriggeringResponse](t, foreign, &ua.SetTriggeringRequest{
			SubscriptionID: sub.id, TriggeringItemID: trig, LinksToAdd: []uint32{a},
		})
		require.ErrorIs(t, err, ua.StatusBadSessionIDInvalid)
	})

	t.Run("Delete", func(t *testing.T) {
		// Drain initial values first.
		seen := map[uint32]bool{}
		eventually(t, func() bool {
			for _, s := range dataOf(t, publish(t, c)) {
				seen[s.handle] = true
			}
			return len(seen) == 3
		}, "initial values of all three items")

		res := mustSendRaw[ua.DeleteMonitoredItemsResponse](t, foreign, &ua.DeleteMonitoredItemsRequest{
			SubscriptionID: sub.id, MonitoredItemIDs: []uint32{a},
		})
		require.Equal(t, []ua.StatusCode{ua.StatusBadSessionIDInvalid}, res.Results)

		res = mustSendRaw[ua.DeleteMonitoredItemsResponse](t, c, &ua.DeleteMonitoredItemsRequest{
			SubscriptionID: sub.id, MonitoredItemIDs: []uint32{a, a + 1000},
		})
		require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusBadMonitoredItemIDInvalid}, res.Results)
		eventually(t, func() bool {
			return sub.setMode(ua.MonitoringModeReporting, a)[0] == ua.StatusBadMonitoredItemIDInvalid
		}, "item deleted")

		// The deleted item (Double) no longer reports; its siblings still do.
		st, err := c.WriteNodeValue(context.Background(), f.Double, 2.5)
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, st)
		for i := 0; i < 3; i++ {
			require.True(t, isKeepAlive(publish(t, c)), "deleted item must not report")
		}
		writeInt32(t, c, f.Int32, 8)
		require.Equal(t, []uint32{1}, handles(sub.nextData()))
	})
}

// TestMonitoredItem_TimestampsToReturn verifies which timestamps notifications
// carry for each TimestampsToReturn setting.
func TestMonitoredItem_TimestampsToReturn(t *testing.T) {
	_, f, url := rawSetup(t)
	before := time.Now().Add(-time.Minute)

	for _, tc := range []struct {
		ts             ua.TimestampsToReturn
		source, server bool
	}{
		{ua.TimestampsToReturnSource, true, false},
		{ua.TimestampsToReturnServer, false, true},
		{ua.TimestampsToReturnBoth, true, true},
		{ua.TimestampsToReturnNeither, false, false},
	} {
		t.Run(tc.ts.String(), func(t *testing.T) {
			sub := newRawSub(t, newClient(t, url), rawSubParams{})
			// f.Double is never written in this test, so the sample is the
			// fixture's initial value with its source timestamp.
			sub.mustCreateItems(tc.ts, itemSpec{node: f.Double, handle: 1, queue: 1, discard: true})
			dv := sub.nextData()[0].dv
			require.Equal(t, 3.14159, dv.Value.Value())
			require.Equal(t, tc.source, !dv.SourceTimestamp.IsZero(), "source timestamp")
			require.Equal(t, tc.server, !dv.ServerTimestamp.IsZero(), "server timestamp")
			if tc.source {
				require.True(t, dv.SourceTimestamp.After(before))
			}
			if tc.server {
				require.True(t, dv.ServerTimestamp.After(before))
			}
		})
	}
}

// TestMonitoredItem_NonValueAttribute verifies an item can monitor an attribute
// other than Value and is notified when that attribute is written.
func TestMonitoredItem_NonValueAttribute(t *testing.T) {
	c, f, _ := rawSetup(t)
	ctx := context.Background()
	sub := newRawSub(t, c, rawSubParams{})
	sub.mustCreateItems(ua.TimestampsToReturnNeither,
		itemSpec{node: f.Int32, attr: ua.AttributeIDDisplayName, handle: 11, queue: 1, discard: true})

	first := sub.nextData()
	require.Equal(t, uint32(11), first[0].handle)
	lt, ok := first[0].dv.Value.Value().(*ua.LocalizedText)
	require.True(t, ok, "got %T", first[0].dv.Value.Value())
	require.Equal(t, "Int32", lt.Text)

	st, err := c.WriteAttribute(ctx, f.Int32, ua.AttributeIDDisplayName, &ua.DataValue{
		EncodingMask: ua.DataValueValue,
		Value:        ua.MustVariant(ua.NewLocalizedText("Renamed")),
	})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, st)

	next := sub.nextData()
	require.Equal(t, uint32(11), next[0].handle)
	require.Equal(t, "Renamed", next[0].dv.Value.Value().(*ua.LocalizedText).Text)
}

// TestMonitoredItem_ManyItemsOneSubscription creates a large number of items
// in a single subscription and verifies every one reports its own value.
func TestMonitoredItem_ManyItemsOneSubscription(t *testing.T) {
	const n = 400
	c, f, _, _ := setupWith(t, func(_ *server.Server, f *testutil.Fixture) {
		for i := 0; i < n; i++ {
			node := f.NS.AddNewVariableStringNode(fmt.Sprintf("Bulk%03d", i), int32(i))
			f.NS.Objects().AddRef(node, server.RefTypeIDHasComponent, true)
		}
	})
	ctx := context.Background()

	ch := make(chan *opcua.PublishNotificationData, 2*n)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: fastInterval}, ch)
	require.NoError(t, err)

	reqs := make([]*ua.MonitoredItemCreateRequest, n)
	for i := range reqs {
		reqs[i] = opcua.NewMonitoredItemCreateRequestWithDefaults(
			ua.NewStringNodeID(f.NSIndex, fmt.Sprintf("Bulk%03d", i)), ua.AttributeIDValue, uint32(1000+i))
	}
	resp, err := sub.Monitor(ctx, ua.TimestampsToReturnNeither, reqs...)
	require.NoError(t, err)
	require.Len(t, resp.Results, n)
	itemIDs := make([]uint32, n)
	for i, r := range resp.Results {
		require.Equal(t, ua.StatusOK, r.StatusCode)
		itemIDs[i] = r.MonitoredItemID
	}

	// Every handle reports exactly its node's value.
	got := map[uint32]int32{}
	for len(got) < n {
		for _, s := range nextDataChanges(t, ch) {
			v := s.dv.Value.Value().(int32)
			require.Equal(t, int32(s.handle-1000), v, "handle %d reported a foreign value", s.handle)
			got[s.handle] = v
		}
	}

	// A single change is reported for exactly one item.
	writeInt32(t, c, ua.NewStringNodeID(f.NSIndex, "Bulk123"), -5)
	samples := nextDataChanges(t, ch)
	require.Len(t, samples, 1)
	require.Equal(t, uint32(1123), samples[0].handle)
	require.Equal(t, int32(-5), samples[0].dv.Value.Value())

	// Remove them all in one call.
	del, err := sub.Unmonitor(ctx, itemIDs...)
	require.NoError(t, err)
	require.Len(t, del.Results, n)
	for _, st := range del.Results {
		require.Equal(t, ua.StatusOK, st)
	}
	eventually(t, func() bool {
		r := mustSendRaw[ua.SetMonitoringModeResponse](t, c, &ua.SetMonitoringModeRequest{
			SubscriptionID: sub.SubscriptionID, MonitoringMode: ua.MonitoringModeReporting,
			MonitoredItemIDs: []uint32{itemIDs[0], itemIDs[n-1]},
		})
		return r.Results[0] == ua.StatusBadMonitoredItemIDInvalid && r.Results[1] == ua.StatusBadMonitoredItemIDInvalid
	}, "items deleted")
	writeInt32(t, c, ua.NewStringNodeID(f.NSIndex, "Bulk123"), -6)
	expectNoDataChange(t, ch, 1123, 150*time.Millisecond)
	require.NoError(t, sub.Cancel(ctx))
}

// TestSubscription_HighLevelItemLifecycle drives the Subscription methods of
// the client API and asserts their effect on what is delivered.
func TestSubscription_HighLevelItemLifecycle(t *testing.T) {
	c, f, _ := rawSetup(t)
	ctx := context.Background()

	ch := make(chan *opcua.PublishNotificationData, 256)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: fastInterval}, ch)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	mon, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth,
		opcua.NewMonitoredItemCreateRequestWithDefaults(f.Int32, ua.AttributeIDValue, 1),
		opcua.NewMonitoredItemCreateRequestWithDefaults(f.Double, ua.AttributeIDValue, 2),
	)
	require.NoError(t, err)
	intItem, dblItem := mon.Results[0].MonitoredItemID, mon.Results[1].MonitoredItemID
	awaitValue(t, ch, 1, int32(42))
	dv := awaitValue(t, ch, 2, 3.14159)
	require.False(t, dv.ServerTimestamp.IsZero())

	// ModifyMonitoredItems: a new client handle shows up on later samples.
	mod, err := sub.ModifyMonitoredItems(ctx, ua.TimestampsToReturnNeither, &ua.MonitoredItemModifyRequest{
		MonitoredItemID:     intItem,
		RequestedParameters: &ua.MonitoringParameters{ClientHandle: 77, QueueSize: 4, DiscardOldest: true},
	})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, mod.Results[0].StatusCode)
	require.Equal(t, uint32(4), mod.Results[0].RevisedQueueSize)
	writeInt32(t, c, f.Int32, 100)
	dv = awaitValue(t, ch, 77, int32(100))
	require.True(t, dv.ServerTimestamp.IsZero(), "timestamps were switched off by the modify")

	// SetMonitoringMode(Disabled) silences one item only.
	sm, err := sub.SetMonitoringMode(ctx, ua.MonitoringModeDisabled, intItem)
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, sm.Results)
	writeInt32(t, c, f.Int32, 101)
	st, err := c.WriteNodeValue(ctx, f.Double, 1.5)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, st)
	awaitValue(t, ch, 2, 1.5)
	expectNoDataChange(t, ch, 77, 150*time.Millisecond)

	sm, err = sub.SetMonitoringMode(ctx, ua.MonitoringModeReporting, intItem)
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, sm.Results)
	writeInt32(t, c, f.Int32, 102)
	awaitValue(t, ch, 77, int32(102))

	// SetPublishingMode(false) silences the whole subscription...
	pm, err := sub.SetPublishingMode(ctx, false)
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, pm.Results)
	writeInt32(t, c, f.Int32, 103)
	expectNoDataChange(t, ch, 77, 150*time.Millisecond)
	// ...and the change is delivered once publishing is enabled again.
	pm, err = c.SetPublishingMode(ctx, true, sub.SubscriptionID)
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, pm.Results)
	awaitValue(t, ch, 77, int32(103))

	// SetTriggering result codes through the client API.
	tr, err := sub.SetTriggering(ctx, intItem, []uint32{dblItem}, []uint32{dblItem + 1000})
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, tr.AddResults)
	require.Equal(t, []ua.StatusCode{ua.StatusBadMonitoredItemIDInvalid}, tr.RemoveResults)

	// Unmonitor stops delivery for that item.
	un, err := sub.Unmonitor(ctx, intItem)
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, un.Results)
	eventually(t, func() bool {
		r := mustSendRaw[ua.SetMonitoringModeResponse](t, c, &ua.SetMonitoringModeRequest{
			SubscriptionID: sub.SubscriptionID, MonitoringMode: ua.MonitoringModeReporting, MonitoredItemIDs: []uint32{intItem},
		})
		return r.Results[0] == ua.StatusBadMonitoredItemIDInvalid
	}, "item removed")
	// The client no longer tracks the item and refuses to address it.
	_, err = sub.SetMonitoringMode(ctx, ua.MonitoringModeReporting, intItem)
	require.ErrorContains(t, err, "unknown monitored item id")
	_, err = sub.ModifyMonitoredItems(ctx, ua.TimestampsToReturnNeither, &ua.MonitoredItemModifyRequest{
		MonitoredItemID: intItem, RequestedParameters: &ua.MonitoringParameters{ClientHandle: 1},
	})
	require.ErrorContains(t, err, "unknown monitored item id")
	writeInt32(t, c, f.Int32, 104)
	expectNoDataChange(t, ch, 77, 150*time.Millisecond)

	// Cancel removes the subscription from client and server.
	id := sub.SubscriptionID
	require.NoError(t, sub.Cancel(ctx))
	require.NotContains(t, c.SubscriptionIDs(), id)
	eventually(t, func() bool {
		r, err := c.SetPublishingMode(ctx, true, id)
		return err == nil && r.Results[0] == ua.StatusBadSubscriptionIDInvalid
	}, "subscription deleted on the server")
}
