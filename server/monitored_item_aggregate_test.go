// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server/aggregate"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

var aggT0 = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func aggID(n uint32) *ua.NodeID { return ua.NewNumericNodeID(0, n) }

func TestReviseProcessingInterval(t *testing.T) {
	for _, bad := range []float64{0, -1, math.NaN(), math.Inf(1), math.Inf(-1)} {
		require.Equal(t, 500.0, reviseProcessingInterval(bad, 0, 500), "the publishing interval for %v", bad)
	}
	require.Equal(t, minAggregateProcessingMS, reviseProcessingInterval(0, 0, 10), "at least the minimum")
	require.Equal(t, minAggregateProcessingMS, reviseProcessingInterval(1, 0, 500))
	require.Equal(t, 1000.0, reviseProcessingInterval(300, 500, 500), "at least twice the sampling interval (Part 4 Table 147)")
	require.Equal(t, 2500.0, reviseProcessingInterval(2500, 1000, 500))
	require.Equal(t, maxAggregateProcessingMS, reviseProcessingInterval(1e15, 0, 500))
}

func TestReviseAggregateStart(t *testing.T) {
	pi := time.Second
	now := aggT0.Add(2500 * time.Millisecond)
	require.Equal(t, aggT0.Add(3*time.Second), reviseAggregateStart(aggT0, pi, now), "the next boundary of the startTime")
	require.Equal(t, aggT0, reviseAggregateStart(aggT0, pi, aggT0), "a startTime of now is kept")
	require.Equal(t, now.Add(time.Hour), reviseAggregateStart(now.Add(time.Hour), pi, now), "a future startTime is kept")
	require.Equal(t, aggT0.Add(2*time.Second), reviseAggregateStart(aggT0, pi, aggT0.Add(2*time.Second)), "on a boundary")
	odd := aggT0.Add(1234567 * time.Nanosecond)
	require.Equal(t, aggT0.Add(time.Millisecond), reviseAggregateStart(time.Time{}, pi, odd), "no startTime: now")
	old := now.AddDate(-300, 0, 0)
	require.Equal(t, now.Truncate(time.Millisecond), reviseAggregateStart(old, pi, now), "too far back for a Duration")
}

func TestAggregateFilterOf(t *testing.T) {
	f := ua.AggregateFilter{AggregateType: aggID(id.AggregateFunctionAverage)}
	require.Nil(t, aggregateFilterOf(nil))
	require.Nil(t, aggregateFilterOf(ua.NewExtensionObject(&ua.DataChangeFilter{})))
	require.Equal(t, &f, aggregateFilterOf(ua.NewExtensionObject(&f)))
	require.Equal(t, &f, aggregateFilterOf(&ua.ExtensionObject{Value: f}))
}

func TestNewAggregateItem(t *testing.T) {
	value := &ua.ReadValueID{NodeID: ua.NewStringNodeID(1, "x"), AttributeID: ua.AttributeIDValue}
	f := &ua.AggregateFilter{StartTime: aggT0, AggregateType: aggID(id.AggregateFunctionAverage), ProcessingInterval: 1000}
	now := aggT0.Add(1500 * time.Millisecond)
	cases := []struct {
		name string
		rv   *ua.ReadValueID
		f    ua.AggregateFilter
		cfg  aggregate.Config
		ts   ua.TimestampsToReturn
		want ua.StatusCode
	}{
		{"DisplayName", &ua.ReadValueID{NodeID: value.NodeID, AttributeID: ua.AttributeIDDisplayName}, *f, aggregate.DefaultConfig(), ua.TimestampsToReturnSource, ua.StatusBadFilterNotAllowed},
		{"AnnotationCount", value, ua.AggregateFilter{AggregateType: aggID(id.AggregateFunctionAnnotationCount)}, aggregate.DefaultConfig(), ua.TimestampsToReturnSource, ua.StatusBadAggregateNotSupported},
		{"no Aggregate", value, ua.AggregateFilter{}, aggregate.DefaultConfig(), ua.TimestampsToReturnSource, ua.StatusBadAggregateNotSupported},
		{"invalid override", value, ua.AggregateFilter{AggregateType: f.AggregateType, AggregateConfiguration: &ua.AggregateConfiguration{PercentDataBad: 10, PercentDataGood: 10}}, aggregate.DefaultConfig(), ua.TimestampsToReturnSource, ua.StatusBadMonitoredItemFilterInvalid},
		{"invalid Variable configuration", value, *f, aggregate.Config{}, ua.TimestampsToReturnSource, ua.StatusBadMonitoredItemFilterInvalid},
		{"Server timestamps", value, *f, aggregate.DefaultConfig(), ua.TimestampsToReturnServer, ua.StatusBadTimestampsToReturnInvalid},
		{"Neither", value, *f, aggregate.DefaultConfig(), ua.TimestampsToReturnNeither, ua.StatusBadTimestampsToReturnInvalid},
		{"Source", value, *f, aggregate.DefaultConfig(), ua.TimestampsToReturnSource, ua.StatusOK},
		{"Both", value, *f, aggregate.DefaultConfig(), ua.TimestampsToReturnBoth, ua.StatusOK},
	}
	for _, tc := range cases {
		a, st := newAggregateItem(tc.rv, &tc.f, tc.cfg, tc.ts, 0, 500, now)
		require.Equal(t, tc.want, st, tc.name)
		if st != ua.StatusOK {
			require.Nil(t, a, tc.name)
			continue
		}
		require.Equal(t, time.Second, a.pi, tc.name)
		require.Equal(t, aggT0.Add(2*time.Second), a.start, tc.name)
		require.Equal(t, a.start, a.next, tc.name)
		res, ok := a.filterResult().Value.(*ua.AggregateFilterResult)
		require.True(t, ok)
		require.Equal(t, &ua.AggregateFilterResult{
			RevisedStartTime:              aggT0.Add(2 * time.Second),
			RevisedProcessingInterval:     1000,
			RevisedAggregateConfiguration: aggregate.DefaultConfig().AggregateConfiguration(),
		}, res, tc.name)
	}

	// The override is the configuration the item uses and returns.
	o := *f
	o.AggregateConfiguration = &ua.AggregateConfiguration{PercentDataBad: 50, PercentDataGood: 50, UseSlopedExtrapolation: true}
	a, st := newAggregateItem(value, &o, aggregate.Config{TreatUncertainAsBad: true, PercentDataBad: 100, PercentDataGood: 100, Stepped: true}, ua.TimestampsToReturnBoth, 0, 500, now)
	require.Equal(t, ua.StatusOK, st)
	require.Equal(t, aggregate.Config{PercentDataBad: 50, PercentDataGood: 50, UseSlopedExtrapolation: true, Stepped: true}, a.cfg)
}

func TestAggregateItemRecord(t *testing.T) {
	a := &aggregateItem{}
	now := aggT0.Add(time.Hour)
	a.record(nil, now)
	require.Empty(t, a.raw)

	// The timestamp of a raw value: source, else server, else the sample.
	a.record(&ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(1.0)}, now)
	a.record(&ua.DataValue{EncodingMask: ua.DataValueValue | ua.DataValueServerTimestamp, Value: ua.MustVariant(2.0), ServerTimestamp: aggT0}, now)
	a.record(&ua.DataValue{EncodingMask: ua.DataValueValue | ua.DataValueSourceTimestamp, Value: ua.MustVariant(3.0), SourceTimestamp: aggT0.Add(time.Second)}, now)
	require.Len(t, a.raw, 3)
	require.Equal(t, now, a.raw[0].SourceTimestamp)
	require.Equal(t, aggT0, a.raw[1].SourceTimestamp)
	require.NotZero(t, a.raw[1].EncodingMask&ua.DataValueSourceTimestamp)

	// The same sample again is no new raw value; a new timestamp is.
	a.record(&ua.DataValue{EncodingMask: ua.DataValueValue | ua.DataValueSourceTimestamp, Value: ua.MustVariant(3.0), SourceTimestamp: aggT0.Add(time.Second)}, now)
	require.Len(t, a.raw, 3)
	a.record(&ua.DataValue{EncodingMask: ua.DataValueValue | ua.DataValueSourceTimestamp, Value: ua.MustVariant(3.0), SourceTimestamp: aggT0.Add(2 * time.Second)}, now)
	require.Len(t, a.raw, 4)

	// The oldest go beyond the bound.
	b := &aggregateItem{}
	for i := range maxAggregateRaw + 3 {
		b.record(&ua.DataValue{EncodingMask: ua.DataValueValue | ua.DataValueSourceTimestamp, Value: ua.MustVariant(float64(i)), SourceTimestamp: aggT0.Add(time.Duration(i) * time.Millisecond)}, now)
	}
	require.Len(t, b.raw, maxAggregateRaw)
	require.Equal(t, aggT0.Add(3*time.Millisecond), b.raw[0].SourceTimestamp)
}

func TestAggregateItemPrune(t *testing.T) {
	dv := func(ms int, st ua.StatusCode) *ua.DataValue {
		return &ua.DataValue{EncodingMask: ua.DataValueValue | ua.DataValueSourceTimestamp | ua.DataValueStatusCode, Value: ua.MustVariant(float64(ms)), Status: st, SourceTimestamp: aggT0.Add(time.Duration(ms) * time.Millisecond)}
	}
	a := &aggregateItem{next: aggT0.Add(time.Second)}
	// Out of order, with Bad values between the Good ones before next.
	a.raw = []*ua.DataValue{dv(1500, ua.StatusOK), dv(100, ua.StatusOK), dv(200, ua.StatusOK), dv(300, ua.StatusOK), dv(400, ua.StatusBad), dv(500, ua.StatusOK), dv(600, ua.StatusBad), dv(1000, ua.StatusOK)}
	a.prune()
	var got []int64
	for _, v := range a.raw {
		got = append(got, v.SourceTimestamp.Sub(aggT0).Milliseconds())
	}
	require.Equal(t, []int64{300, 400, 500, 600, 1000, 1500}, got)

	// Fewer than two Good values before next: all are kept.
	b := &aggregateItem{next: aggT0.Add(time.Second), raw: []*ua.DataValue{dv(100, ua.StatusBad), dv(200, ua.StatusOK)}}
	b.prune()
	require.Len(t, b.raw, 2)
	empty := &aggregateItem{next: aggT0}
	empty.prune()
	require.Empty(t, empty.raw)
}

// aggregateFixture is a sampler fixture whose item on rw_float64 has an
// AggregateFilter with its intervals at aggT0, and a Historian that records
// the same values, to compare with a HistoryRead.
type aggregateFixture struct {
	*samplerFixture
	node *ua.NodeID
	item *MonitoredItem
	hist *Historian
}

func newAggregateFixture(t *testing.T, fn uint32, pi time.Duration, ts ua.TimestampsToReturn) *aggregateFixture {
	t.Helper()
	f := &aggregateFixture{samplerFixture: newSamplerFixture(t), hist: NewHistorian()}
	f.node = f.samplerFixture.node("rw_float64")
	f.hist.EnableNode(f.node, 1000)
	f.item = f.add(1, f.node, func(mi *MonitoredItem) {
		mi.queueSize = 100
		mi.timestampsToReturn = ts
		mi.agg = &aggregateItem{fn: aggID(fn), cfg: aggregate.DefaultConfig(), pi: pi, piMS: float64(pi) / float64(time.Millisecond), start: aggT0, next: aggT0}
	})
	f.svc.aggItems.Add(1)
	return f
}

// write gives the node a value with a source timestamp ms after aggT0.
func (f *aggregateFixture) write(ms int, v float64, st ua.StatusCode) {
	f.t.Helper()
	dv := &ua.DataValue{
		EncodingMask:    ua.DataValueValue | ua.DataValueStatusCode | ua.DataValueSourceTimestamp,
		Value:           ua.MustVariant(v),
		Status:          st,
		SourceTimestamp: aggT0.Add(time.Duration(ms) * time.Millisecond),
	}
	require.Equal(f.t, ua.StatusOK, f.ns.SetAttribute(f.node, ua.AttributeIDValue, dv))
	cp := *dv
	f.hist.RecordValue(f.node, &cp)
}

// values returns and removes the queued values of the item.
func (f *aggregateFixture) values() []*ua.DataValue {
	f.svc.Mu.Lock()
	defer f.svc.Mu.Unlock()
	out := make([]*ua.DataValue, 0, len(f.item.queue))
	for _, n := range f.item.queue {
		out = append(out, n.Value)
	}
	f.item.queue = f.item.queue[:0]
	return out
}

// TestAggregateFilter_SameAsHistoryRead: the values of an aggregate item
// are those of a HistoryRead over the same raw values and intervals (Part
// 13 §4.3.2), with the ServerTimestamp the end of the interval (Part 4
// §7.22.4), for Aggregates of every kind.
func TestAggregateFilter_SameAsHistoryRead(t *testing.T) {
	writes := []struct {
		ms int
		v  float64
		st ua.StatusCode
	}{
		{-700, 1, ua.StatusOK}, {200, 4, ua.StatusOK}, {900, 2, ua.StatusUncertain},
		{1300, 8, ua.StatusOK}, {1800, 5, ua.StatusBad}, {2600, 3, ua.StatusOK}, {4100, 6, ua.StatusOK},
	}
	for _, fn := range []uint32{
		id.AggregateFunctionAverage, id.AggregateFunctionTimeAverage, id.AggregateFunctionInterpolative,
		id.AggregateFunctionMinimum, id.AggregateFunctionMaximumActualTime, id.AggregateFunctionCount,
		id.AggregateFunctionDurationGood, id.AggregateFunctionWorstQuality, id.AggregateFunctionEnd,
		id.AggregateFunctionTotal, id.AggregateFunctionStandardDeviationSample,
	} {
		t.Run(aggregate.Name(aggID(fn)), func(t *testing.T) {
			f := newAggregateFixture(t, fn, time.Second, ua.TimestampsToReturnBoth)
			for _, w := range writes {
				f.write(w.ms, w.v, w.st)
			}
			// Nothing has completed before the end of the first interval.
			f.svc.calculateAggregates(f.sub.ID, aggT0.Add(999*time.Millisecond))
			require.Empty(t, f.values())
			// Two calculations: data is carried over to the next one.
			f.svc.calculateAggregates(f.sub.ID, aggT0.Add(2500*time.Millisecond))
			got := f.values()
			f.svc.calculateAggregates(f.sub.ID, aggT0.Add(4*time.Second))
			got = append(got, f.values()...)
			require.Len(t, got, 4)

			want, err := f.hist.ReadProcessed(f.node, aggT0, aggT0.Add(4*time.Second), 1000, aggID(fn), nil)
			require.NoError(t, err)
			require.Equal(t, ua.StatusOK, want.StatusCode)
			hd := want.HistoryData.Value.(*ua.HistoryData)
			require.Len(t, hd.DataValues, 4)
			for i, dv := range got {
				end := aggT0.Add(time.Duration(i+1) * time.Second)
				require.Equal(t, end, dv.ServerTimestamp, "interval %d", i)
				require.NotZero(t, dv.EncodingMask&ua.DataValueServerTimestamp)
				w := *hd.DataValues[i]
				require.Equal(t, w.Status, dv.Status, "interval %d", i)
				require.Equal(t, w.SourceTimestamp, dv.SourceTimestamp, "interval %d", i)
				require.Equal(t, w.Value, dv.Value, "interval %d", i)
			}
		})
	}
}

func TestAggregateFilter_SourceTimestamps(t *testing.T) {
	f := newAggregateFixture(t, id.AggregateFunctionCount, time.Second, ua.TimestampsToReturnSource)
	f.write(100, 1, ua.StatusOK)
	f.svc.calculateAggregates(f.sub.ID, aggT0.Add(time.Second))
	got := f.values()
	require.Len(t, got, 1)
	require.Equal(t, aggT0, got[0].SourceTimestamp)
	require.True(t, got[0].ServerTimestamp.IsZero())
	require.Zero(t, got[0].EncodingMask&ua.DataValueServerTimestamp)
	require.Equal(t, int32(1), got[0].Value.Value())
}

// TestAggregateFilter_NotCalculated: an Aggregate that cannot be applied to
// the values reports its status for every interval; a disabled item and a
// subscription without aggregate items calculate nothing.
func TestAggregateFilter_NotCalculated(t *testing.T) {
	f := newAggregateFixture(t, id.AggregateFunctionAverage, time.Second, ua.TimestampsToReturnBoth)
	f.svc.Mu.Lock()
	f.item.agg.record(&ua.DataValue{
		EncodingMask: ua.DataValueValue | ua.DataValueSourceTimestamp, Value: ua.MustVariant([]float64{1, 2}), SourceTimestamp: aggT0.Add(time.Millisecond),
	}, aggT0)
	f.svc.Mu.Unlock()
	f.svc.calculateAggregates(f.sub.ID, aggT0.Add(2*time.Second))
	got := f.values()
	require.Len(t, got, 2)
	for i, dv := range got {
		require.Equal(t, ua.StatusBadNotSupported, dv.Status)
		require.Nil(t, dv.Value)
		require.Equal(t, aggT0.Add(time.Duration(i)*time.Second), dv.SourceTimestamp)
		require.Equal(t, aggT0.Add(time.Duration(i+1)*time.Second), dv.ServerTimestamp)
	}

	f.item.Mode = ua.MonitoringModeDisabled
	f.svc.calculateAggregates(f.sub.ID, aggT0.Add(10*time.Second))
	require.Empty(t, f.values())
	require.Equal(t, aggT0.Add(2*time.Second), f.item.agg.next)

	f.svc.aggItems.Add(-1)
	f.item.Mode = ua.MonitoringModeReporting
	f.svc.calculateAggregates(f.sub.ID, aggT0.Add(10*time.Second))
	require.Empty(t, f.values(), "no aggregate item is counted")
	f.svc.aggItems.Add(1)

	// A clock before the intervals start calculates nothing.
	f.item.agg.next = aggT0.Add(time.Hour)
	f.svc.calculateAggregates(f.sub.ID, aggT0)
	require.Empty(t, f.values())
}

// TestAggregateFilter_SkipsUnreachableIntervals: intervals beyond
// aggregate.MaxIntervals are skipped, not calculated.
func TestAggregateFilter_SkipsUnreachableIntervals(t *testing.T) {
	f := newAggregateFixture(t, id.AggregateFunctionCount, time.Millisecond, ua.TimestampsToReturnSource)
	f.item.queueSize = 1
	now := aggT0.Add((aggregate.MaxIntervals + 5) * time.Millisecond)
	f.svc.calculateAggregates(f.sub.ID, now)
	require.Equal(t, now, f.item.agg.next)
	got := f.values()
	require.Len(t, got, 1)
	require.Equal(t, now.Add(-time.Millisecond), got[0].SourceTimestamp, "the last interval")
}

// aggregateServiceFixture drives the MonitoredItem services with requests.
type aggregateServiceFixture struct {
	t   *testing.T
	svc *MonitoredItemService
	sub *Subscription
	hdr *ua.RequestHeader
	ns  *NodeNameSpace
}

func newAggregateServiceFixture(t *testing.T) *aggregateServiceFixture {
	t.Helper()
	srv := newTestServer()
	ns, _ := addTestNamespace(srv)
	sess := srv.sb.NewSession()
	sub := NewSubscription()
	sub.srv = srv.SubscriptionService
	sub.Session = sess
	sub.ID = 1
	sub.running = true
	sub.RevisedPublishingInterval = 250
	srv.SubscriptionService.Mu.Lock()
	srv.SubscriptionService.Subs[sub.ID] = sub
	srv.SubscriptionService.Mu.Unlock()
	return &aggregateServiceFixture{
		t: t, svc: srv.MonitoredItemService, sub: sub, ns: ns,
		hdr: &ua.RequestHeader{RequestHandle: 1, AuthenticationToken: sess.AuthTokenID},
	}
}

func (f *aggregateServiceFixture) create(ts ua.TimestampsToReturn, filters ...*ua.ExtensionObject) []*ua.MonitoredItemCreateResult {
	f.t.Helper()
	items := make([]*ua.MonitoredItemCreateRequest, len(filters))
	for i, flt := range filters {
		items[i] = &ua.MonitoredItemCreateRequest{
			ItemToMonitor:       &ua.ReadValueID{NodeID: ua.NewStringNodeID(f.ns.ID(), "rw_float64"), AttributeID: ua.AttributeIDValue},
			MonitoringMode:      ua.MonitoringModeReporting,
			RequestedParameters: &ua.MonitoringParameters{ClientHandle: uint32(i + 1), QueueSize: 10, Filter: flt},
		}
	}
	resp, err := f.svc.CreateMonitoredItems(context.Background(), nil, &ua.CreateMonitoredItemsRequest{
		RequestHeader: f.hdr, SubscriptionID: f.sub.ID, TimestampsToReturn: ts, ItemsToCreate: items,
	}, 1)
	require.NoError(f.t, err)
	return resp.(*ua.CreateMonitoredItemsResponse).Results
}

func (f *aggregateServiceFixture) modify(ts ua.TimestampsToReturn, itemID uint32, params *ua.MonitoringParameters) *ua.MonitoredItemModifyResult {
	f.t.Helper()
	resp, err := f.svc.ModifyMonitoredItems(context.Background(), nil, &ua.ModifyMonitoredItemsRequest{
		RequestHeader: f.hdr, SubscriptionID: f.sub.ID, TimestampsToReturn: ts,
		ItemsToModify: []*ua.MonitoredItemModifyRequest{{MonitoredItemID: itemID, RequestedParameters: params}},
	}, 1)
	require.NoError(f.t, err)
	return resp.(*ua.ModifyMonitoredItemsResponse).Results[0]
}

func (f *aggregateServiceFixture) setMode(mode ua.MonitoringMode, itemID uint32) {
	f.t.Helper()
	_, err := f.svc.SetMonitoringMode(context.Background(), nil, &ua.SetMonitoringModeRequest{
		RequestHeader: f.hdr, SubscriptionID: f.sub.ID, MonitoringMode: mode, MonitoredItemIDs: []uint32{itemID},
	}, 1)
	require.NoError(f.t, err)
}

func (f *aggregateServiceFixture) item(itemID uint32) *MonitoredItem {
	f.svc.Mu.Lock()
	defer f.svc.Mu.Unlock()
	return f.svc.Items[itemID]
}

func aggFilter(fn uint32, piMS float64, start time.Time) *ua.ExtensionObject {
	return ua.NewExtensionObject(&ua.AggregateFilter{StartTime: start, AggregateType: aggID(fn), ProcessingInterval: piMS})
}

// TestAggregateFilter_Services: CreateMonitoredItems and
// ModifyMonitoredItems with an AggregateFilter, their revised values, and
// the switch to and from a DataChangeFilter; SetMonitoringMode and
// DeleteMonitoredItems keep the count of aggregate items.
func TestAggregateFilter_Services(t *testing.T) {
	f := newAggregateServiceFixture(t)
	before := time.Now()
	res := f.create(ua.TimestampsToReturnBoth,
		aggFilter(id.AggregateFunctionAverage, 0, time.Time{}),
		aggFilter(id.AggregateFunctionAnnotationCount, 1000, time.Time{}),
		ua.NewExtensionObject(&ua.DataChangeFilter{Trigger: ua.DataChangeTriggerStatusValue}),
	)
	require.Equal(t, ua.StatusOK, res[0].StatusCode)
	afr, ok := res[0].FilterResult.Value.(*ua.AggregateFilterResult)
	require.True(t, ok)
	require.Equal(t, 250.0, afr.RevisedProcessingInterval, "the publishing interval for 0 (Part 13 §5.4.3.1)")
	require.False(t, afr.RevisedStartTime.Before(before.Truncate(time.Millisecond)))
	require.Equal(t, aggregate.DefaultConfig().AggregateConfiguration(), afr.RevisedAggregateConfiguration)
	require.Equal(t, ua.StatusBadAggregateNotSupported, res[1].StatusCode)
	require.Equal(t, ua.StatusOK, res[2].StatusCode)
	require.Nil(t, res[2].FilterResult.Value)
	require.Equal(t, int64(1), f.svc.aggItems.Load())

	agg := f.item(res[0].MonitoredItemID)
	require.NotNil(t, agg.agg)
	require.Empty(t, agg.queue, "an aggregate item reports no initial value")
	require.Len(t, agg.agg.raw, 1, "it keeps it as its first raw value")
	require.Len(t, f.item(res[2].MonitoredItemID).queue, 1)

	// Source and Both only (Part 13 §5.4.3.1).
	for _, ts := range []ua.TimestampsToReturn{ua.TimestampsToReturnServer, ua.TimestampsToReturnNeither} {
		res := f.create(ts, aggFilter(id.AggregateFunctionAverage, 1000, time.Time{}))
		require.Equal(t, ua.StatusBadTimestampsToReturnInvalid, res[0].StatusCode)
	}

	// Modify: a new Aggregate keeps the raw values; a rejected one keeps
	// the item as it was.
	id0 := res[0].MonitoredItemID
	start := time.Now().Add(time.Hour).Truncate(time.Second)
	mr := f.modify(ua.TimestampsToReturnSource, id0, &ua.MonitoringParameters{ClientHandle: 1, SamplingInterval: 400, QueueSize: 5, Filter: aggFilter(id.AggregateFunctionMaximum, 500, start)})
	require.Equal(t, ua.StatusOK, mr.StatusCode)
	afr = mr.FilterResult.Value.(*ua.AggregateFilterResult)
	require.Equal(t, 800.0, afr.RevisedProcessingInterval, "twice the sampling interval")
	require.Equal(t, start, afr.RevisedStartTime)
	mi := f.item(id0)
	require.Equal(t, aggID(id.AggregateFunctionMaximum), mi.agg.fn)
	require.Len(t, mi.agg.raw, 1)
	require.Equal(t, ua.TimestampsToReturnSource, mi.timestampsToReturn)
	mr = f.modify(ua.TimestampsToReturnSource, id0, &ua.MonitoringParameters{ClientHandle: 1, Filter: aggFilter(id.AggregateFunctionAnnotationCount, 500, start)})
	require.Equal(t, ua.StatusBadAggregateNotSupported, mr.StatusCode)
	require.Equal(t, aggID(id.AggregateFunctionMaximum), f.item(id0).agg.fn)
	mr = f.modify(ua.TimestampsToReturnServer, id0, &ua.MonitoringParameters{ClientHandle: 1, Filter: aggFilter(id.AggregateFunctionMaximum, 500, start)})
	require.Equal(t, ua.StatusBadTimestampsToReturnInvalid, mr.StatusCode)
	mr = f.modify(ua.TimestampsToReturnServer, id0, nil)
	require.Equal(t, ua.StatusBadTimestampsToReturnInvalid, mr.StatusCode, "an aggregate item keeps Source or Both")
	require.Equal(t, ua.TimestampsToReturnSource, f.item(id0).timestampsToReturn)

	// Disabled: no raw values; enabled again: the intervals restart at the
	// next boundary with the current value.
	f.setMode(ua.MonitoringModeDisabled, id0)
	require.Nil(t, f.item(id0).agg.raw)
	f.setMode(ua.MonitoringModeSampling, id0)
	mi = f.item(id0)
	require.Len(t, mi.agg.raw, 1)
	require.Equal(t, start, mi.agg.next)

	// To a DataChangeFilter: it reports the current value, as a new item.
	mr = f.modify(ua.TimestampsToReturnBoth, id0, &ua.MonitoringParameters{ClientHandle: 1, QueueSize: 5})
	require.Equal(t, ua.StatusOK, mr.StatusCode)
	require.Nil(t, mr.FilterResult.Value)
	mi = f.item(id0)
	require.Nil(t, mi.agg)
	require.Len(t, mi.queue, 1)
	require.Equal(t, int64(0), f.svc.aggItems.Load())

	// From a DataChangeFilter to an AggregateFilter: the current value is
	// the first raw value.
	id2 := res[2].MonitoredItemID
	mr = f.modify(ua.TimestampsToReturnBoth, id2, &ua.MonitoringParameters{ClientHandle: 3, QueueSize: 5, Filter: aggFilter(id.AggregateFunctionCount, 1000, time.Time{})})
	require.Equal(t, ua.StatusOK, mr.StatusCode)
	require.Len(t, f.item(id2).agg.raw, 1)
	require.Equal(t, int64(1), f.svc.aggItems.Load())
	// A plain modify of a plain item changes nothing of the kind.
	require.Equal(t, ua.StatusOK, f.modify(ua.TimestampsToReturnBoth, id0, &ua.MonitoringParameters{ClientHandle: 1, QueueSize: 5}).StatusCode)
	require.Equal(t, int64(1), f.svc.aggItems.Load())

	f.svc.DeleteMonitoredItem(id2)
	require.Equal(t, int64(0), f.svc.aggItems.Load())
}

// TestAggregateFilter_ProviderConfig: the configuration of the Variable
// comes from the history provider (Part 13 §4.3.1).
func TestAggregateFilter_ProviderConfig(t *testing.T) {
	f := newAggregateServiceFixture(t)
	h := NewHistorian()
	node := ua.NewStringNodeID(f.ns.ID(), "rw_float64")
	cfg := aggregate.Config{PercentDataBad: 60, PercentDataGood: 40, UseSlopedExtrapolation: true}
	h.SetAggregateConfig(node, cfg)
	f.svc.SubService.srv.SetHistorian(h)
	res := f.create(ua.TimestampsToReturnSource, aggFilter(id.AggregateFunctionAverage, 1000, time.Time{}))
	require.Equal(t, ua.StatusOK, res[0].StatusCode)
	require.Equal(t, cfg.AggregateConfiguration(), res[0].FilterResult.Value.(*ua.AggregateFilterResult).RevisedAggregateConfiguration)
	mr := f.modify(ua.TimestampsToReturnSource, res[0].MonitoredItemID, &ua.MonitoringParameters{ClientHandle: 1, Filter: aggFilter(id.AggregateFunctionCount, 1000, time.Time{})})
	require.Equal(t, cfg.AggregateConfiguration(), mr.FilterResult.Value.(*ua.AggregateFilterResult).RevisedAggregateConfiguration)
}

// TestSetMonitoringMode_WakeWithoutRoom: an item that goes to Reporting
// with queued samples wakes Publish, also when the wake-up channel is full.
func TestSetMonitoringMode_WakeWithoutRoom(t *testing.T) {
	f := newAggregateServiceFixture(t)
	res := f.create(ua.TimestampsToReturnBoth, nil)
	require.Equal(t, ua.StatusOK, res[0].StatusCode)
	f.setMode(ua.MonitoringModeSampling, res[0].MonitoredItemID)
	f.sub.NotifyChannel = make(chan *ua.MonitoredItemNotification) // nobody reads it
	f.setMode(ua.MonitoringModeReporting, res[0].MonitoredItemID)
	require.Len(t, f.item(res[0].MonitoredItemID).queue, 1, "the queued sample stays for Publish")
}
