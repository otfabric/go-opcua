// SPDX-License-Identifier: MIT

package conformance

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/monitor"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// These tests cover what the server does between "the node changed" and "a
// notification is queued": the DataChangeFilter (Part 4 §7.22.2, Part 8
// §7.2), the sampling interval (Part 4 §5.13.1.2) and the item's IndexRange.
//
// They are deterministic without sleeping. Values are changed while
// publishing is disabled; the server samples a change synchronously, so when
// publishing is enabled again the item queues hold exactly the samples that
// passed the filters. A sentinel item, changed last, tells the test that the
// Publish response it is looking at is the one carrying that batch - also
// when the filters under test let nothing through.

const sentinelHandle = uint32(9999)

// filterRig is a raw subscription with a sentinel item.
type filterRig struct {
	t        *testing.T
	c        *opcua.Client
	f        *testutil.Fixture
	sub      *rawSub
	sentinel float64
}

func newFilterRig(t *testing.T) *filterRig {
	t.Helper()
	c, f, _ := rawSetup(t)
	r := &filterRig{t: t, c: c, f: f, sub: newRawSub(t, c, rawSubParams{})}
	r.sub.mustCreateItems(ua.TimestampsToReturnBoth,
		itemSpec{node: f.HistoryVar, handle: sentinelHandle, queue: 1, discard: true})
	return r
}

// set changes a node's value on the server, which samples its monitored
// items before returning.
func (r *filterRig) set(node *ua.NodeID, dv *ua.DataValue) {
	r.t.Helper()
	require.Equal(r.t, ua.StatusOK, r.f.NS.SetAttribute(node, ua.AttributeIDValue, dv))
}

// setValue is set for a plain Good value.
func (r *filterRig) setValue(node *ua.NodeID, v any) {
	r.t.Helper()
	r.set(node, server.DataValueFromValue(v))
}

// observe runs change with publishing disabled and returns the samples that
// were queued by it (and before it), per client handle, in queue order.
func (r *filterRig) observe(change func()) map[uint32][]dataChange {
	r.t.Helper()
	r.sub.setPublishing(false)
	if change != nil {
		change()
	}
	r.sentinel++
	r.setValue(r.f.HistoryVar, r.sentinel)
	r.sub.setPublishing(true)

	out := map[uint32][]dataChange{}
	for done := false; !done; {
		for _, s := range r.sub.nextData() {
			if s.Handle == sentinelHandle {
				done = done || s.DV.Value.Value() == r.sentinel
				continue
			}
			out[s.Handle] = append(out[s.Handle], s)
		}
	}
	return out
}

// dvAt builds a DataValue with explicit status and source timestamp.
func dvAt(v any, status ua.StatusCode, ts time.Time) *ua.DataValue {
	return &ua.DataValue{
		EncodingMask:    ua.DataValueValue | ua.DataValueStatusCode | ua.DataValueSourceTimestamp,
		Value:           ua.MustVariant(v),
		Status:          status,
		SourceTimestamp: ts,
	}
}

// obs is a (value, status) pair of a sample.
type obs struct {
	v  any
	st ua.StatusCode
}

func obsOf(samples []dataChange) []obs {
	out := make([]obs, len(samples))
	for i, s := range samples {
		out[i].st = s.DV.Status
		if s.DV.Value != nil {
			out[i].v = s.DV.Value.Value()
		}
	}
	return out
}

func good(vals ...any) []obs {
	out := make([]obs, len(vals))
	for i, v := range vals {
		out[i] = obs{v: v, st: ua.StatusOK}
	}
	return out
}

func isNullFilterResult(eo *ua.ExtensionObject) bool {
	return eo == nil || eo.Value == nil
}

var (
	ts0 = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	ts1 = ts0.Add(time.Second)
	ts2 = ts0.Add(2 * time.Second)
)

var uncertain = ua.StatusUncertainLastUsableValue

// TestDataChange_Triggers verifies the three DataChangeTrigger values and the
// default (no filter) without a deadband: each step changes exactly one of
// status, value and source timestamp, or nothing at all.
func TestDataChange_Triggers(t *testing.T) {
	r := newFilterRig(t)
	node := r.f.Double
	r.set(node, dvAt(1.0, ua.StatusOK, ts0))

	const hStatus, hStatusValue, hTimestamp, hDefault = 1, 2, 3, 4
	res := r.sub.createItems(ua.TimestampsToReturnBoth,
		itemSpec{node: node, handle: hStatus, queue: 20, filter: opcua.NewDataChangeFilter(ua.DataChangeTriggerStatus, ua.DeadbandTypeNone, 0)},
		itemSpec{node: node, handle: hStatusValue, queue: 20, filter: opcua.NewDataChangeFilter(ua.DataChangeTriggerStatusValue, ua.DeadbandTypeNone, 0)},
		// A deadband value is ignored when the type is None.
		itemSpec{node: node, handle: hTimestamp, queue: 20, filter: opcua.NewDataChangeFilter(ua.DataChangeTriggerStatusValueTimestamp, ua.DeadbandTypeNone, 1000)},
		itemSpec{node: node, handle: hDefault, queue: 20},
	)
	for i, cr := range res {
		require.Equal(t, ua.StatusOK, cr.StatusCode, "item %d", i)
		require.True(t, isNullFilterResult(cr.FilterResult), "a DataChangeFilter has no result structure")
	}

	// Every item reports its current value first, whatever the trigger.
	initial := r.observe(nil)
	for _, h := range []uint32{hStatus, hStatusValue, hTimestamp, hDefault} {
		require.Equal(t, good(1.0), obsOf(initial[h]), "initial value of handle %d", h)
	}

	got := r.observe(func() {
		r.set(node, dvAt(1.0, ua.StatusOK, ts1)) // timestamp only
		r.set(node, dvAt(2.0, ua.StatusOK, ts1)) // value only
		r.set(node, dvAt(2.0, uncertain, ts1))   // status only
		r.set(node, dvAt(2.0, uncertain, ts1))   // nothing
		r.set(node, dvAt(2.0, ua.StatusOK, ts1)) // status only
		r.set(node, dvAt(3.0, ua.StatusOK, ts2)) // value and timestamp
	})

	statusValue := []obs{{2.0, ua.StatusOK}, {2.0, uncertain}, {2.0, ua.StatusOK}, {3.0, ua.StatusOK}}
	require.Equal(t, []obs{{2.0, uncertain}, {2.0, ua.StatusOK}}, obsOf(got[hStatus]), "Status trigger")
	require.Equal(t, statusValue, obsOf(got[hStatusValue]), "StatusValue trigger")
	require.Equal(t, statusValue, obsOf(got[hDefault]), "no filter behaves as StatusValue")
	require.Equal(t, append([]obs{{1.0, ua.StatusOK}}, statusValue...), obsOf(got[hTimestamp]), "StatusValueTimestamp trigger")
	require.True(t, got[hTimestamp][0].DV.SourceTimestamp.Equal(ts1), "the timestamp-only change carries the new timestamp")
}

// TestDataChange_AbsoluteDeadbandPerTrigger verifies an absolute deadband
// combined with each trigger: only a change of more than the deadband against
// the last reported value counts, a status change bypasses the deadband, and
// StatusValueTimestamp with a deadband behaves like StatusValue.
func TestDataChange_AbsoluteDeadbandPerTrigger(t *testing.T) {
	r := newFilterRig(t)
	node := r.f.Double
	r.set(node, dvAt(10.0, ua.StatusOK, ts0))

	const hStatus, hStatusValue, hTimestamp = 1, 2, 3
	r.sub.mustCreateItems(ua.TimestampsToReturnBoth,
		itemSpec{node: node, handle: hStatus, queue: 20, filter: opcua.NewDataChangeFilter(ua.DataChangeTriggerStatus, ua.DeadbandTypeAbsolute, 5)},
		itemSpec{node: node, handle: hStatusValue, queue: 20, filter: opcua.NewDataChangeFilter(ua.DataChangeTriggerStatusValue, ua.DeadbandTypeAbsolute, 5)},
		itemSpec{node: node, handle: hTimestamp, queue: 20, filter: opcua.NewDataChangeFilter(ua.DataChangeTriggerStatusValueTimestamp, ua.DeadbandTypeAbsolute, 5)},
	)
	r.observe(nil)

	got := r.observe(func() {
		r.set(node, dvAt(12.0, ua.StatusOK, ts0)) // within the deadband
		r.set(node, dvAt(15.0, ua.StatusOK, ts0)) // exactly the deadband: not exceeded
		r.set(node, dvAt(15.5, ua.StatusOK, ts0)) // exceeded -> new reference 15.5
		r.set(node, dvAt(11.0, ua.StatusOK, ts0)) // 4.5 from 15.5
		r.set(node, dvAt(10.4, ua.StatusOK, ts0)) // 5.1 from 15.5 -> new reference 10.4
		r.set(node, dvAt(10.4, ua.StatusOK, ts1)) // timestamp only
		r.set(node, dvAt(10.5, uncertain, ts1))   // status change ignores the deadband
		r.set(node, dvAt(10.5, ua.StatusOK, ts1)) // and back
	})

	value := []obs{{15.5, ua.StatusOK}, {10.4, ua.StatusOK}, {10.5, uncertain}, {10.5, ua.StatusOK}}
	require.Equal(t, []obs{{10.5, uncertain}, {10.5, ua.StatusOK}}, obsOf(got[hStatus]), "Status trigger never looks at the value")
	require.Equal(t, value, obsOf(got[hStatusValue]), "StatusValue + deadband")
	require.Equal(t, value, obsOf(got[hTimestamp]), "StatusValueTimestamp + deadband behaves as StatusValue")
}

// TestDataChange_AbsoluteDeadbandNumericTypes applies a deadband of 1 to a
// variable of every Number type: a step of 1 stays inside it, a step of 2
// leaves it.
func TestDataChange_AbsoluteDeadbandNumericTypes(t *testing.T) {
	r := newFilterRig(t)
	f := r.f
	cases := []struct {
		node           *ua.NodeID
		base, one, two any
	}{
		{node: f.SByte, base: int8(-7), one: int8(-6), two: int8(-5)},
		{node: f.Byte, base: byte(200), one: byte(199), two: byte(198)},
		{node: f.Int16, base: int16(-1234), one: int16(-1233), two: int16(-1232)},
		{node: f.Uint16, base: uint16(4321), one: uint16(4322), two: uint16(4323)},
		{node: f.Int32, base: int32(42), one: int32(41), two: int32(40)},
		{node: f.Uint32, base: uint32(4242), one: uint32(4243), two: uint32(4244)},
		// Values a float64 cannot tell apart: the comparison has to be exact.
		{node: f.Int64, base: int64(1) << 62, one: int64(1)<<62 + 1, two: int64(1)<<62 + 2},
		{node: f.Uint64, base: uint64(1) << 63, one: uint64(1)<<63 - 1, two: uint64(1)<<63 - 2},
		{node: f.Float, base: float32(3.5), one: float32(4.5), two: float32(5.75)},
		{node: f.Double, base: float64(8), one: float64(7), two: float64(5.5)},
	}
	specs := make([]itemSpec, len(cases))
	for i, tc := range cases {
		r.setValue(tc.node, tc.base)
		specs[i] = itemSpec{
			node: tc.node, handle: uint32(i + 1), queue: 20,
			filter: opcua.NewDataChangeFilter(ua.DataChangeTriggerStatusValue, ua.DeadbandTypeAbsolute, 1),
		}
	}
	r.sub.mustCreateItems(ua.TimestampsToReturnNeither, specs...)
	initial := r.observe(nil)

	got := r.observe(func() {
		for _, tc := range cases {
			r.setValue(tc.node, tc.one)  // |1| is not more than 1
			r.setValue(tc.node, tc.two)  // 2 away from the reference
			r.setValue(tc.node, tc.two)  // unchanged
			r.setValue(tc.node, tc.base) // 2 away from the new reference
			r.setValue(tc.node, tc.one)  // 1 away
		}
	})
	for i, tc := range cases {
		h := uint32(i + 1)
		require.Equal(t, good(tc.base), obsOf(initial[h]), "%s initial", tc.node)
		require.Equal(t, good(tc.two, tc.base), obsOf(got[h]), "%s", tc.node)
	}
}

// TestDataChange_ZeroDeadbandAndNaN verifies the edges of value comparison: a
// deadband of 0 reports every change but not a rewrite of the same value, and
// NaN is reported once when the value becomes NaN (Part 4 §7.10).
func TestDataChange_ZeroDeadbandAndNaN(t *testing.T) {
	r := newFilterRig(t)
	r.sub.mustCreateItems(ua.TimestampsToReturnNeither,
		itemSpec{node: r.f.Int32, handle: 1, queue: 20, filter: opcua.NewDataChangeFilter(ua.DataChangeTriggerStatusValue, ua.DeadbandTypeAbsolute, 0)},
		itemSpec{node: r.f.Double, handle: 2, queue: 20},
		itemSpec{node: r.f.String, handle: 3, queue: 20},
	)
	r.observe(nil)

	got := r.observe(func() {
		r.setValue(r.f.Int32, int32(42)) // same value as before
		r.setValue(r.f.Int32, int32(43))
		r.setValue(r.f.Int32, int32(43))
		r.setValue(r.f.Int32, int32(42))

		r.setValue(r.f.Double, math.NaN())
		r.setValue(r.f.Double, math.NaN())
		r.setValue(r.f.Double, 1.5)
		r.setValue(r.f.Double, math.Inf(1))
		r.setValue(r.f.Double, math.Inf(1))

		r.setValue(r.f.String, "hello") // same value as before
		r.setValue(r.f.String, "world")
	})
	require.Equal(t, good(int32(43), int32(42)), obsOf(got[1]))
	require.Len(t, got[2], 3)
	require.True(t, math.IsNaN(got[2][0].DV.Value.Value().(float64)))
	require.Equal(t, 1.5, got[2][1].DV.Value.Value())
	require.True(t, math.IsInf(got[2][2].DV.Value.Value().(float64), 1))
	require.Equal(t, good("world"), obsOf(got[3]))
}

// TestDataChange_AbsoluteDeadbandArrays verifies the array rule of Part 4
// §7.22.2: the whole array is reported when any element exceeds the deadband
// or when the size or the dimensions of the array change.
func TestDataChange_AbsoluteDeadbandArrays(t *testing.T) {
	r := newFilterRig(t)
	f := r.f
	const hDouble, hInt, hMatrix = 1, 2, 3
	r.sub.mustCreateItems(ua.TimestampsToReturnNeither,
		itemSpec{node: f.DoubleArray, handle: hDouble, queue: 20, filter: opcua.NewDataChangeFilter(ua.DataChangeTriggerStatusValue, ua.DeadbandTypeAbsolute, 1)},
		itemSpec{node: f.Int32Array, handle: hInt, queue: 20, filter: opcua.NewDataChangeFilter(ua.DataChangeTriggerStatusValue, ua.DeadbandTypeAbsolute, 2)},
		itemSpec{node: f.Matrix, handle: hMatrix, queue: 20, filter: opcua.NewDataChangeFilter(ua.DataChangeTriggerStatusValue, ua.DeadbandTypeAbsolute, 1)},
	)
	initial := r.observe(nil)
	require.Equal(t, good([]float64{0.5, 1.5, 2.5, 3.5}), obsOf(initial[hDouble]))
	require.Equal(t, good([]int32{1, 2, 3, 4, 5}), obsOf(initial[hInt]))
	require.Len(t, initial[hMatrix], 1)

	got := r.observe(func() {
		r.setValue(f.DoubleArray, []float64{0.6, 1.6, 2.6, 3.6}) // every element within 1
		r.setValue(f.DoubleArray, []float64{0.5, 1.5, 2.5, 4.6}) // one element exceeds
		r.setValue(f.DoubleArray, []float64{0.5, 1.5, 2.5, 4.6}) // unchanged
		r.setValue(f.DoubleArray, []float64{0.5, 1.5, 2.5})      // size changed
		r.setValue(f.DoubleArray, []float64{0.4, 1.4, 2.4})      // within 1

		r.setValue(f.Int32Array, []int32{3, 4, 5, 6, 7}) // every element exactly 2 away
		r.setValue(f.Int32Array, []int32{1, 2, 3, 4, 8}) // last element 3 away

		r.setValue(f.Matrix, [][]int32{{2, 3, 4}, {5, 6, 7}}) // every element 1 away
		r.setValue(f.Matrix, [][]int32{{1, 2, 3}, {4, 5, 8}}) // one element 2 away
	})
	require.Equal(t, good([]float64{0.5, 1.5, 2.5, 4.6}, []float64{0.5, 1.5, 2.5}), obsOf(got[hDouble]))
	require.Equal(t, good([]int32{1, 2, 3, 4, 8}), obsOf(got[hInt]))
	require.Len(t, got[hMatrix], 1, "matrix: only the change that exceeds the deadband")
}

// TestDataChange_PercentDeadband verifies the PercentDeadband of Part 8 §7.2:
// the deadband is a percentage of the EURange of the AnalogItem.
func TestDataChange_PercentDeadband(t *testing.T) {
	r := newFilterRig(t)
	f := r.f
	const hTen, hZero, hFull, hArray, hStatus = 1, 2, 3, 4, 5
	pct := func(trigger ua.DataChangeTrigger, v float64) *ua.ExtensionObject {
		return opcua.NewDataChangeFilter(trigger, ua.DeadbandTypePercent, v)
	}
	res := r.sub.createItems(ua.TimestampsToReturnNeither,
		// Analog has EURange [0, 200]: 10 % is 20.
		itemSpec{node: f.Analog, handle: hTen, queue: 20, filter: pct(ua.DataChangeTriggerStatusValue, 10)},
		itemSpec{node: f.Analog, handle: hZero, queue: 20, filter: pct(ua.DataChangeTriggerStatusValueTimestamp, 0)},
		itemSpec{node: f.Analog, handle: hFull, queue: 20, filter: pct(ua.DataChangeTriggerStatusValue, 100)},
		// AnalogArray has EURange [0, 100]: 5 % is 5.
		itemSpec{node: f.AnalogArray, handle: hArray, queue: 20, filter: pct(ua.DataChangeTriggerStatusValue, 5)},
		itemSpec{node: f.Analog, handle: hStatus, queue: 20, filter: pct(ua.DataChangeTriggerStatus, 10)},
	)
	for i, cr := range res {
		require.Equal(t, ua.StatusOK, cr.StatusCode, "item %d", i)
		require.True(t, isNullFilterResult(cr.FilterResult))
	}
	initial := r.observe(nil)
	require.Equal(t, good(100.0), obsOf(initial[hTen]))
	require.Equal(t, good([]float64{10, 20, 30}), obsOf(initial[hArray]))

	got := r.observe(func() {
		r.setValue(f.Analog, 115.0) // 15 from 100
		r.setValue(f.Analog, 120.0) // exactly 20: not exceeded
		r.setValue(f.Analog, 121.0) // 21 -> new reference
		r.setValue(f.Analog, 101.0) // 20 from 121
		r.setValue(f.Analog, 100.5) // 20.5 from 121

		r.setValue(f.AnalogArray, []float64{10, 20, 35}) // exactly 5
		r.setValue(f.AnalogArray, []float64{10, 20, 36}) // 6
	})
	require.Equal(t, good(121.0, 100.5), obsOf(got[hTen]), "10 %% of [0,200]")
	require.Equal(t, good(115.0, 120.0, 121.0, 101.0, 100.5), obsOf(got[hZero]), "0 %% reports every change")
	require.Empty(t, got[hFull], "100 %% of the range is never exceeded inside the range")
	require.Equal(t, good([]float64{10, 20, 36}), obsOf(got[hArray]))
	require.Empty(t, got[hStatus], "Status trigger: the value does not matter")
}

// TestDataChange_FilterErrors verifies the operation results of
// CreateMonitoredItems for filters that cannot be applied, and that a rejected
// item neither exists nor affects the other items of the request.
func TestDataChange_FilterErrors(t *testing.T) {
	r := newFilterRig(t)
	f := r.f
	dc := opcua.NewDataChangeFilter
	raw := func(trigger ua.DataChangeTrigger, deadbandType uint32, v float64) *ua.ExtensionObject {
		return ua.NewExtensionObject(&ua.DataChangeFilter{Trigger: trigger, DeadbandType: deadbandType, DeadbandValue: v})
	}
	cases := []struct {
		name   string
		spec   itemSpec
		status ua.StatusCode
	}{
		{"valid absolute", itemSpec{node: f.Double, filter: dc(ua.DataChangeTriggerStatusValue, ua.DeadbandTypeAbsolute, 1)}, ua.StatusOK},
		{"percent without EURange", itemSpec{node: f.Double, filter: dc(ua.DataChangeTriggerStatusValue, ua.DeadbandTypePercent, 10)}, ua.StatusBadMonitoredItemFilterUnsupported},
		{"percent above 100", itemSpec{node: f.Analog, filter: dc(ua.DataChangeTriggerStatusValue, ua.DeadbandTypePercent, 100.5)}, ua.StatusBadDeadbandFilterInvalid},
		{"percent negative", itemSpec{node: f.Analog, filter: dc(ua.DataChangeTriggerStatusValue, ua.DeadbandTypePercent, -1)}, ua.StatusBadDeadbandFilterInvalid},
		{"absolute negative", itemSpec{node: f.Double, filter: dc(ua.DataChangeTriggerStatusValue, ua.DeadbandTypeAbsolute, -0.5)}, ua.StatusBadDeadbandFilterInvalid},
		{"absolute NaN", itemSpec{node: f.Double, filter: dc(ua.DataChangeTriggerStatusValue, ua.DeadbandTypeAbsolute, math.NaN())}, ua.StatusBadDeadbandFilterInvalid},
		{"deadband on String", itemSpec{node: f.String, filter: dc(ua.DataChangeTriggerStatusValue, ua.DeadbandTypeAbsolute, 1)}, ua.StatusBadFilterNotAllowed},
		{"deadband on Boolean", itemSpec{node: f.Bool, filter: dc(ua.DataChangeTriggerStatusValue, ua.DeadbandTypeAbsolute, 1)}, ua.StatusBadFilterNotAllowed},
		{"deadband on ByteString", itemSpec{node: f.ByteString, filter: dc(ua.DataChangeTriggerStatusValue, ua.DeadbandTypePercent, 1)}, ua.StatusBadFilterNotAllowed},
		{"deadband on String array", itemSpec{node: f.StringArray, filter: dc(ua.DataChangeTriggerStatus, ua.DeadbandTypeAbsolute, 1)}, ua.StatusBadFilterNotAllowed},
		{"trigger only on String", itemSpec{node: f.String, filter: dc(ua.DataChangeTriggerStatusValueTimestamp, ua.DeadbandTypeNone, 0)}, ua.StatusOK},
		{"filter on DisplayName", itemSpec{node: f.Double, attr: ua.AttributeIDDisplayName, filter: dc(ua.DataChangeTriggerStatusValue, ua.DeadbandTypeNone, 0)}, ua.StatusBadFilterNotAllowed},
		{"deadband on DataType attribute", itemSpec{node: f.Double, attr: ua.AttributeIDDataType, filter: dc(ua.DataChangeTriggerStatusValue, ua.DeadbandTypeAbsolute, 1)}, ua.StatusBadFilterNotAllowed},
		{"invalid trigger", itemSpec{node: f.Double, filter: raw(ua.DataChangeTrigger(7), 0, 0)}, ua.StatusBadMonitoredItemFilterInvalid},
		{"invalid deadband type", itemSpec{node: f.Double, filter: raw(ua.DataChangeTriggerStatusValue, 9, 1)}, ua.StatusBadMonitoredItemFilterInvalid},
		{"EventFilter on Value", itemSpec{node: f.Double, filter: eventFilter([]string{"Message"})}, ua.StatusBadFilterNotAllowed},
		{"AggregateFilter", itemSpec{node: f.Double, filter: ua.NewExtensionObject(&ua.AggregateFilter{
			StartTime: ts0, AggregateType: ua.NewNumericNodeID(0, 2342), ProcessingInterval: 1000,
			AggregateConfiguration: &ua.AggregateConfiguration{},
		})}, ua.StatusBadMonitoredItemFilterUnsupported},
		{"not a filter", itemSpec{node: f.Double, filter: ua.NewExtensionObject(&ua.Range{Low: 1, High: 2})}, ua.StatusBadMonitoredItemFilterInvalid},
		{"no filter on DisplayName", itemSpec{node: f.Double, attr: ua.AttributeIDDisplayName}, ua.StatusOK},
	}
	specs := make([]itemSpec, len(cases))
	for i, tc := range cases {
		specs[i] = tc.spec
		specs[i].handle = uint32(i + 1)
		specs[i].queue = 5
	}
	res := r.sub.createItems(ua.TimestampsToReturnNeither, specs...)
	for i, tc := range cases {
		require.Equal(t, tc.status, res[i].StatusCode, tc.name)
		require.True(t, isNullFilterResult(res[i].FilterResult), tc.name)
		if tc.status == ua.StatusOK {
			require.NotZero(t, res[i].MonitoredItemID, tc.name)
		} else {
			require.Zero(t, res[i].MonitoredItemID, tc.name)
		}
	}

	// Only the accepted items exist: they, and nothing else, report an
	// initial value.
	initial := r.observe(nil)
	for i, tc := range cases {
		h := uint32(i + 1)
		if tc.status == ua.StatusOK {
			require.Len(t, initial[h], 1, tc.name)
		} else {
			require.Empty(t, initial[h], tc.name)
		}
	}
}

// TestDataChange_ModifyFilter verifies ModifyMonitoredItems: a new filter
// applies to the following samples with the last reported value as reference,
// a rejected filter leaves the item untouched, and no filter restores the
// default.
func TestDataChange_ModifyFilter(t *testing.T) {
	r := newFilterRig(t)
	node := r.f.Double
	r.setValue(node, 10.0)
	ids := r.sub.mustCreateItems(ua.TimestampsToReturnNeither,
		itemSpec{node: node, handle: 1, queue: 20},
		itemSpec{node: r.f.String, handle: 2, queue: 20},
	)
	r.observe(nil)

	modify := func(itemID uint32, filter *ua.ExtensionObject) *ua.MonitoredItemModifyResult {
		t.Helper()
		handle := uint32(1)
		if itemID == ids[1] {
			handle = 2
		}
		res := mustSendRaw[ua.ModifyMonitoredItemsResponse](t, r.c, &ua.ModifyMonitoredItemsRequest{
			SubscriptionID: r.sub.id, TimestampsToReturn: ua.TimestampsToReturnNeither,
			ItemsToModify: []*ua.MonitoredItemModifyRequest{{
				MonitoredItemID:     itemID,
				RequestedParameters: &ua.MonitoringParameters{ClientHandle: handle, QueueSize: 20, DiscardOldest: true, Filter: filter},
			}},
		})
		require.Len(t, res.Results, 1)
		require.True(t, isNullFilterResult(res.Results[0].FilterResult))
		return res.Results[0]
	}
	step := func(vals ...float64) []obs {
		t.Helper()
		return obsOf(r.observe(func() {
			for _, v := range vals {
				r.setValue(node, v)
			}
		})[1])
	}

	// No filter yet: every change.
	require.Equal(t, good(11.0, 12.0), step(11, 12))

	// Absolute deadband 5; the reference is the last reported value, 12.
	require.Equal(t, ua.StatusOK, modify(ids[0], opcua.NewDataChangeFilter(ua.DataChangeTriggerStatusValue, ua.DeadbandTypeAbsolute, 5)).StatusCode)
	require.Equal(t, good(17.5), step(14, 17, 17.5, 13))

	// Rejected filters leave the deadband in force.
	require.Equal(t, ua.StatusBadMonitoredItemFilterUnsupported,
		modify(ids[0], opcua.NewDataChangeFilter(ua.DataChangeTriggerStatusValue, ua.DeadbandTypePercent, 10)).StatusCode)
	require.Equal(t, ua.StatusBadDeadbandFilterInvalid,
		modify(ids[0], opcua.NewDataChangeFilter(ua.DataChangeTriggerStatusValue, ua.DeadbandTypeAbsolute, -1)).StatusCode)
	require.Equal(t, ua.StatusBadFilterNotAllowed,
		modify(ids[1], opcua.NewDataChangeFilter(ua.DataChangeTriggerStatusValue, ua.DeadbandTypeAbsolute, 1)).StatusCode)
	require.Equal(t, good(23.0), step(20, 22, 23))

	// Status trigger: no value change is reported.
	require.Equal(t, ua.StatusOK, modify(ids[0], opcua.NewDataChangeFilter(ua.DataChangeTriggerStatus, ua.DeadbandTypeNone, 0)).StatusCode)
	require.Empty(t, step(100, 200))

	// No filter: back to every change.
	require.Equal(t, ua.StatusOK, modify(ids[0], nil).StatusCode)
	require.Equal(t, good(201.0, 202.0), step(201, 202))
}

// TestDataChange_SamplingIntervalRevision verifies how the requested sampling
// interval is revised by CreateMonitoredItems and ModifyMonitoredItems.
func TestDataChange_SamplingIntervalRevision(t *testing.T) {
	c, f, _ := rawSetup(t)
	sub := newRawSub(t, c, rawSubParams{interval: 50})
	cases := []struct {
		name            string
		requested, want float64
	}{
		{"zero is exception based", 0, 0},
		{"negative is the publishing interval", -1, sub.interval},
		{"below the minimum", 0.25, 1},
		{"kept", 250, 250},
		{"above the maximum", 1e12, 3_600_000},
	}
	specs := make([]itemSpec, len(cases))
	for i, tc := range cases {
		specs[i] = itemSpec{node: f.Int32, handle: uint32(i + 1), queue: 1, sampling: tc.requested}
	}
	res := sub.createItems(ua.TimestampsToReturnNeither, specs...)
	for i, tc := range cases {
		require.Equal(t, ua.StatusOK, res[i].StatusCode, tc.name)
		require.Equal(t, tc.want, res[i].RevisedSamplingInterval, "create: %s", tc.name)
	}

	// The same policy applies to ModifyMonitoredItems.
	itemID := res[0].MonitoredItemID
	for _, tc := range cases {
		mod := mustSendRaw[ua.ModifyMonitoredItemsResponse](t, c, &ua.ModifyMonitoredItemsRequest{
			SubscriptionID: sub.id, TimestampsToReturn: ua.TimestampsToReturnNeither,
			ItemsToModify: []*ua.MonitoredItemModifyRequest{{
				MonitoredItemID:     itemID,
				RequestedParameters: &ua.MonitoringParameters{ClientHandle: 1, QueueSize: 1, SamplingInterval: tc.requested},
			}},
		})
		require.Equal(t, ua.StatusOK, mod.Results[0].StatusCode, tc.name)
		require.Equal(t, tc.want, mod.Results[0].RevisedSamplingInterval, "modify: %s", tc.name)
	}

	// Events are not sampled: their interval is 0 whatever was asked for.
	ev := sub.createItems(ua.TimestampsToReturnNeither, itemSpec{
		node: f.EventObject, attr: ua.AttributeIDEventNotifier, handle: 50, queue: 5,
		filter: eventFilter([]string{"Message"}), sampling: 500,
	})
	require.Equal(t, ua.StatusOK, ev[0].StatusCode)
	require.Zero(t, ev[0].RevisedSamplingInterval)
}

// TestDataChange_SamplingIntervalThrottles verifies that a value changing
// faster than the sampling interval produces at most one sample per interval,
// and that the latest value is not lost. An item with sampling interval 0 on
// the same node sees every change.
func TestDataChange_SamplingIntervalThrottles(t *testing.T) {
	c, f, _ := rawSetup(t)
	sub := newRawSub(t, c, rawSubParams{})
	const (
		interval = 400 * time.Millisecond
		writes   = 30
		hSlow    = 1
		hFast    = 2
	)
	start := time.Now()
	res := sub.createItems(ua.TimestampsToReturnNeither,
		itemSpec{node: f.Int32, handle: hSlow, queue: 100, discard: true, sampling: float64(interval / time.Millisecond)},
		itemSpec{node: f.Int32, handle: hFast, queue: 100, discard: true},
	)
	require.Equal(t, float64(interval/time.Millisecond), res[0].RevisedSamplingInterval)
	require.Zero(t, res[1].RevisedSamplingInterval)

	for i := 1; i <= writes; i++ {
		writeInt32(t, c, f.Int32, int32(1000+i))
	}
	last := int32(1000 + writes)

	// Collect until the throttled item has delivered the final value.
	var slow, fast []any
	for len(slow) == 0 || slow[len(slow)-1] != any(last) {
		for _, s := range sub.nextData() {
			if s.Handle == hSlow {
				slow = append(slow, s.DV.Value.Value())
			} else {
				fast = append(fast, s.DV.Value.Value())
			}
		}
	}
	elapsed := time.Since(start)

	// Samples are at least one interval apart, so their number is bounded by
	// the time that passed - however slow this machine is.
	maxSamples := int(elapsed/interval) + 2
	require.LessOrEqual(t, len(slow), maxSamples, "throttled item: %v in %s", slow, elapsed)
	require.GreaterOrEqual(t, len(slow), 2, "the initial value and the latest value")
	require.Equal(t, int32(42), slow[0], "initial value")
	for i := 1; i < len(slow); i++ {
		require.Greater(t, slow[i].(int32), slow[i-1].(int32), "samples are in order")
	}

	// The exception-based item got the initial value and every single write.
	require.Len(t, fast, writes+1)
	require.Equal(t, int32(42), fast[0])
	for i := 1; i <= writes; i++ {
		require.Equal(t, int32(1000+i), fast[i])
	}
}

// TestDataChange_ModifySamplingIntervalReleasesPostponedSample verifies that a
// change held back by a long sampling interval is delivered when the interval
// is shortened, instead of waiting out the old one.
func TestDataChange_ModifySamplingIntervalReleasesPostponedSample(t *testing.T) {
	c, f, _ := rawSetup(t)
	sub := newRawSub(t, c, rawSubParams{})
	const hour = 3_600_000.0
	res := sub.createItems(ua.TimestampsToReturnNeither,
		itemSpec{node: f.Int32, handle: 1, queue: 10, discard: true, sampling: hour})
	require.Equal(t, hour, res[0].RevisedSamplingInterval)
	sub.primeItem(int32(42))

	// Inside the hour: postponed. An unthrottled item created afterwards
	// reports the new value, which shows the write has been processed.
	writeInt32(t, c, f.Int32, 43)
	sub.mustCreateItems(ua.TimestampsToReturnNeither, itemSpec{node: f.Int32, handle: 2, queue: 10, discard: true})
	samples := sub.nextData()
	require.Equal(t, []uint32{2}, handles(samples), "the throttled item must not have reported yet")
	require.Equal(t, []any{int32(43)}, values(samples))

	mod := mustSendRaw[ua.ModifyMonitoredItemsResponse](t, c, &ua.ModifyMonitoredItemsRequest{
		SubscriptionID: sub.id, TimestampsToReturn: ua.TimestampsToReturnNeither,
		ItemsToModify: []*ua.MonitoredItemModifyRequest{{
			MonitoredItemID:     res[0].MonitoredItemID,
			RequestedParameters: &ua.MonitoringParameters{ClientHandle: 1, QueueSize: 10, DiscardOldest: true, SamplingInterval: 1},
		}},
	})
	require.Equal(t, ua.StatusOK, mod.Results[0].StatusCode)
	require.Equal(t, 1.0, mod.Results[0].RevisedSamplingInterval)

	samples = sub.nextData()
	require.Equal(t, []uint32{1}, handles(samples))
	require.Equal(t, []any{int32(43)}, values(samples))
}

// TestDataChange_IndexRange verifies monitoring a part of an array: only the
// selected range is reported and a change outside it does not trigger.
func TestDataChange_IndexRange(t *testing.T) {
	r := newFilterRig(t)
	f := r.f
	const hRange, hBytes, hMatrix, hDeadband, hBeyond, hWhole = 1, 2, 3, 4, 5, 6
	res := r.sub.createItems(ua.TimestampsToReturnNeither,
		itemSpec{node: f.Int32Array, handle: hRange, queue: 20, index: "1:2"},
		itemSpec{node: f.ByteArray, handle: hBytes, queue: 20, index: "2:4"},
		itemSpec{node: f.Matrix, handle: hMatrix, queue: 20, index: "1,0:1"},
		itemSpec{node: f.DoubleArray, handle: hDeadband, queue: 20, index: "0:1",
			filter: opcua.NewDataChangeFilter(ua.DataChangeTriggerStatusValue, ua.DeadbandTypeAbsolute, 1)},
		// Nothing there yet; the array may grow into the range.
		itemSpec{node: f.Int32Array, handle: hBeyond, queue: 20, index: "6:7"},
		itemSpec{node: f.Int32Array, handle: hWhole, queue: 20},
		// Malformed ranges are rejected.
		itemSpec{node: f.Int32Array, handle: 7, queue: 20, index: "2:1"},
		itemSpec{node: f.Int32Array, handle: 8, queue: 20, index: "abc"},
	)
	for i := 0; i < 6; i++ {
		require.Equal(t, ua.StatusOK, res[i].StatusCode, "item %d", i)
	}
	require.Equal(t, ua.StatusBadIndexRangeInvalid, res[6].StatusCode)
	require.Equal(t, ua.StatusBadIndexRangeInvalid, res[7].StatusCode)

	initial := r.observe(nil)
	require.Equal(t, good([]int32{2, 3}), obsOf(initial[hRange]))
	require.Equal(t, good([]byte{2, 3, 4}), obsOf(initial[hBytes]))
	require.Len(t, initial[hMatrix], 1)
	require.Equal(t, good([]float64{0.5, 1.5}), obsOf(initial[hDeadband]))
	require.Equal(t, []obs{{nil, ua.StatusBadIndexRangeNoData}}, obsOf(initial[hBeyond]))
	require.Equal(t, good([]int32{1, 2, 3, 4, 5}), obsOf(initial[hWhole]))

	got := r.observe(func() {
		r.setValue(f.Int32Array, []int32{9, 2, 3, 9, 9}) // outside 1:2
		r.setValue(f.Int32Array, []int32{9, 7, 3, 9, 9}) // inside
		r.setValue(f.Int32Array, []int32{9, 7, 3, 0, 0}) // outside

		r.setValue(f.ByteArray, []byte{9, 9, 2, 3, 4, 9, 9, 9, 9, 9}) // outside 2:4
		r.setValue(f.ByteArray, []byte{9, 9, 2, 3, 5, 9, 9, 9, 9, 9}) // inside

		r.setValue(f.Matrix, [][]int32{{7, 8, 9}, {4, 5, 0}}) // outside row 1, columns 0:1
		r.setValue(f.Matrix, [][]int32{{7, 8, 9}, {4, 6, 0}}) // inside

		r.setValue(f.DoubleArray, []float64{1.0, 2.0, 99, 99}) // outside, or within the deadband
		r.setValue(f.DoubleArray, []float64{1.0, 2.6, 99, 99}) // element 1 exceeds
	})
	require.Equal(t, good([]int32{7, 3}), obsOf(got[hRange]))
	require.Len(t, got[hWhole], 3, "the unrestricted item sees every change")
	require.Equal(t, good([]byte{2, 3, 5}), obsOf(got[hBytes]))
	require.Len(t, got[hMatrix], 1)
	require.Equal(t, good([]float64{1.0, 2.6}), obsOf(got[hDeadband]))
	require.Empty(t, got[hBeyond], "still no data in 6:7, and that was reported already")

	// The array grows into the range, then shrinks out of it again.
	got = r.observe(func() {
		r.setValue(f.Int32Array, []int32{9, 7, 3, 0, 0, 0, 60, 70})
		r.setValue(f.Int32Array, []int32{9, 7, 3})
	})
	require.Equal(t, []obs{{[]int32{60, 70}, ua.StatusOK}, {nil, ua.StatusBadIndexRangeNoData}}, obsOf(got[hBeyond]))
	require.Empty(t, got[hRange], "1:2 did not change")
}

// TestDataChange_NewItemDoesNotRenotifySiblings is the regression test for a
// bug where creating a monitored item sampled every item on the same node, so
// existing items reported their unchanged value again.
func TestDataChange_NewItemDoesNotRenotifySiblings(t *testing.T) {
	r := newFilterRig(t)
	node := r.f.Int32
	r.sub.mustCreateItems(ua.TimestampsToReturnNeither, itemSpec{node: node, handle: 1, queue: 20})
	require.Equal(t, good(int32(42)), obsOf(r.observe(nil)[1]))

	// More items on the same node, in this and in another subscription.
	other := newRawSub(t, r.c, rawSubParams{})
	got := r.observe(func() {
		r.sub.mustCreateItems(ua.TimestampsToReturnNeither,
			itemSpec{node: node, handle: 2, queue: 20},
			itemSpec{node: node, handle: 3, queue: 20, filter: opcua.NewDataChangeFilter(ua.DataChangeTriggerStatus, ua.DeadbandTypeNone, 0)},
		)
		other.mustCreateItems(ua.TimestampsToReturnNeither, itemSpec{node: node, handle: 4, queue: 20})
	})
	require.Empty(t, got[1], "the existing item has nothing new to report")
	require.Equal(t, good(int32(42)), obsOf(got[2]), "a new item reports its initial value once")
	require.Equal(t, good(int32(42)), obsOf(got[3]))

	// A real change still reaches every item whose filter lets it through.
	got = r.observe(func() { r.setValue(node, int32(43)) })
	require.Equal(t, good(int32(43)), obsOf(got[1]))
	require.Equal(t, good(int32(43)), obsOf(got[2]))
	require.Empty(t, got[3])
}

// TestDataChange_EventItemsAndOtherAttributes verifies that items which are
// not about the Value attribute are unaffected: an event item never receives
// a data change, and a non-Value attribute is monitored with the default
// trigger.
func TestDataChange_EventItemsAndOtherAttributes(t *testing.T) {
	r := newFilterRig(t)
	f := r.f
	const hEvent, hName = 1, 2
	r.sub.mustCreateItems(ua.TimestampsToReturnNeither,
		itemSpec{node: f.EventObject, attr: ua.AttributeIDEventNotifier, handle: hEvent, queue: 5, filter: eventFilter([]string{"Message"})},
		itemSpec{node: f.Double, attr: ua.AttributeIDDisplayName, handle: hName, queue: 5},
	)
	initial := r.observe(nil)
	require.Empty(t, initial[hEvent], "an event item has no initial value")
	require.Len(t, initial[hName], 1)

	got := r.observe(func() {
		f.Srv.ChangeNotification(f.EventObject)
		// The value changes, the DisplayName does not.
		r.setValue(f.Double, 99.5)
		require.Equal(t, ua.StatusOK, f.NS.SetAttribute(f.Double, ua.AttributeIDDisplayName,
			server.DataValueFromValue(ua.NewLocalizedText("renamed"))))
	})
	require.Empty(t, got[hEvent], "data changes are not delivered to event items")
	require.Len(t, got[hName], 1, "only the DisplayName change")
	require.Equal(t, "renamed", got[hName][0].DV.Value.Value().(*ua.LocalizedText).Text)
}

// TestDataChange_BuilderAndHelper drives the client-side helpers:
// SubscriptionBuilder.DataChangeFilter, opcua.NewDataChangeFilter with a
// hand-built request, and the monitor package.
func TestDataChange_BuilderAndHelper(t *testing.T) {
	c, f, ctx := setup(t)

	t.Run("Builder", func(t *testing.T) {
		sub, ch, err := c.NewSubscription().
			Interval(fastInterval).
			Monitor(f.Int32). // added before the filter: unfiltered
			DataChangeFilter(ua.DataChangeTriggerStatusValue, ua.DeadbandTypeAbsolute, 5).
			Monitor(f.Double).
			Start(ctx)
		require.NoError(t, err)
		defer func() { _ = sub.Cancel(ctx) }()
		awaitValue(t, ch, 0, int32(42))
		awaitValue(t, ch, 1, 3.14159)

		// 6.0 stays within the deadband; 50.0 does not. The unfiltered item
		// is written last, so everything before it has been sampled when its
		// value arrives.
		writeDouble(t, c, f.Double, 6.0)
		writeDouble(t, c, f.Double, 50.0)
		writeInt32(t, c, f.Int32, 43)
		awaitValue(t, ch, 0, int32(43))
		require.Equal(t, []any{50.0}, pendingValues(ch, 1))
	})

	t.Run("RequestWithHelper", func(t *testing.T) {
		req := opcua.NewMonitoredItemCreateRequestWithDefaults(f.Analog, ua.AttributeIDValue, 7)
		req.RequestedParameters.Filter = opcua.NewDataChangeFilter(ua.DataChangeTriggerStatusValue, ua.DeadbandTypePercent, 10)
		bad := opcua.NewMonitoredItemCreateRequestWithDefaults(f.String, ua.AttributeIDValue, 8)
		bad.RequestedParameters.Filter = opcua.NewDataChangeFilter(ua.DataChangeTriggerStatusValue, ua.DeadbandTypeAbsolute, 1)

		sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: fastInterval}, make(chan *opcua.PublishNotificationData, 16))
		require.NoError(t, err)
		defer func() { _ = sub.Cancel(ctx) }()
		res, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, req, bad)
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, res.Results[0].StatusCode)
		require.Equal(t, ua.StatusBadFilterNotAllowed, res.Results[1].StatusCode)
	})

	t.Run("MonitorPackage", func(t *testing.T) {
		m, err := monitor.NewNodeMonitor(c)
		require.NoError(t, err)
		ch := make(chan *monitor.DataChangeMessage, 32)
		sub, err := m.ChanSubscribe(ctx, &opcua.SubscriptionParameters{Interval: fastInterval}, ch)
		require.NoError(t, err)
		defer func() { _ = sub.Unsubscribe(ctx) }()

		// The unfiltered item comes second: a Publish response lists the
		// samples item by item, so its value is the last message of a batch.
		_, err = sub.AddMonitorItems(ctx,
			monitor.Request{NodeID: f.Float, MonitoringMode: ua.MonitoringModeReporting, MonitoringParameters: &ua.MonitoringParameters{
				QueueSize: 10, DiscardOldest: true,
				Filter: opcua.NewDataChangeFilter(ua.DataChangeTriggerStatusValue, ua.DeadbandTypeAbsolute, 2),
			}},
			monitor.Request{NodeID: f.Uint32, MonitoringMode: ua.MonitoringModeReporting},
		)
		require.NoError(t, err)

		st, err := c.WriteNodeValue(ctx, f.Float, float32(4.5)) // 1 away from 3.5
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, st)
		st, err = c.WriteNodeValue(ctx, f.Float, float32(9.5))
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, st)
		st, err = c.WriteNodeValue(ctx, f.Uint32, uint32(1))
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, st)

		// Messages arrive in order: initial 3.5, then 9.5, never 4.5.
		var floats []any
		deadline := time.After(waitTimeout)
		for done := false; !done; {
			select {
			case msg := <-ch:
				require.NoError(t, msg.Error)
				switch msg.NodeID.String() {
				case f.Float.String():
					floats = append(floats, msg.Value.Value())
				case f.Uint32.String():
					done = msg.Value.Value() == uint32(1)
				}
			case <-deadline:
				t.Fatal("timed out waiting for the monitor messages")
			}
		}
		require.Equal(t, []any{float32(3.5), float32(9.5)}, floats)
	})
}

// writeDouble writes a float64 to a node and requires StatusOK.
func writeDouble(t *testing.T, c *opcua.Client, id *ua.NodeID, v float64) {
	t.Helper()
	st, err := c.WriteNodeValue(context.Background(), id, v)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, st)
}
