// SPDX-License-Identifier: MIT

package server

import (
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server/aggregate"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestHistorian_UpdateDataSemantics(t *testing.T) {
	h := NewHistorian()
	nodeID := ua.NewStringNodeID(2, "Hist.Update")
	h.EnableNode(nodeID, 100)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h.RecordValue(nodeID, &ua.DataValue{
		EncodingMask:    ua.DataValueValue | ua.DataValueSourceTimestamp,
		Value:           ua.MustVariant(float64(1)),
		SourceTimestamp: base,
	})

	existing := &ua.DataValue{
		EncodingMask:    ua.DataValueValue | ua.DataValueSourceTimestamp,
		Value:           ua.MustVariant(float64(9)),
		SourceTimestamp: base,
	}
	missing := &ua.DataValue{
		EncodingMask:    ua.DataValueValue | ua.DataValueSourceTimestamp,
		Value:           ua.MustVariant(float64(2)),
		SourceTimestamp: base.Add(time.Second),
	}

	ins := h.UpdateData(nodeID, ua.PerformUpdateTypeInsert, []*ua.DataValue{existing, missing})
	if ins.OperationResults[0] != ua.StatusBadEntryExists {
		t.Fatalf("insert existing: %v", ins.OperationResults[0])
	}
	if ins.OperationResults[1] != ua.StatusOK {
		t.Fatalf("insert missing: %v", ins.OperationResults[1])
	}

	rep := h.UpdateData(nodeID, ua.PerformUpdateTypeReplace, []*ua.DataValue{existing, {
		EncodingMask:    ua.DataValueValue | ua.DataValueSourceTimestamp,
		Value:           ua.MustVariant(float64(3)),
		SourceTimestamp: base.Add(2 * time.Second),
	}})
	if rep.OperationResults[0] != ua.StatusOK {
		t.Fatalf("replace existing: %v", rep.OperationResults[0])
	}
	if rep.OperationResults[1] != ua.StatusBadNoEntryExists {
		t.Fatalf("replace missing: %v", rep.OperationResults[1])
	}

	upd := h.UpdateData(nodeID, ua.PerformUpdateTypeUpdate, []*ua.DataValue{existing, {
		EncodingMask:    ua.DataValueValue | ua.DataValueSourceTimestamp,
		Value:           ua.MustVariant(float64(4)),
		SourceTimestamp: base.Add(3 * time.Second),
	}})
	if upd.OperationResults[0] != ua.StatusOK || upd.OperationResults[1] != ua.StatusOK {
		t.Fatalf("update results: %v", upd.OperationResults)
	}
}

func TestHistorian_ReadAtTimeAndProcessed(t *testing.T) {
	h := NewHistorian()
	nodeID := ua.NewStringNodeID(2, "Hist.Agg")
	h.EnableNode(nodeID, 100)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		h.RecordValue(nodeID, &ua.DataValue{
			EncodingMask:    ua.DataValueValue | ua.DataValueSourceTimestamp,
			Value:           ua.MustVariant(float64(i)),
			SourceTimestamp: base.Add(time.Duration(i) * time.Second),
		})
	}

	at, err := h.ReadAtTime(nodeID, []time.Time{base.Add(1500 * time.Millisecond)}, false)
	if err != nil {
		t.Fatal(err)
	}
	hd := at.HistoryData.Value.(*ua.HistoryData)
	if v := hd.DataValues[0].Value.Value().(float64); v != 1 {
		t.Fatalf("nearest previous=%v, want 1", v)
	}

	agg := ua.NewNumericNodeID(0, id.AggregateFunctionAverage)
	proc, err := h.ReadProcessed(nodeID, base, base.Add(4*time.Second), 2000, agg, nil)
	if err != nil {
		t.Fatal(err)
	}
	phd := proc.HistoryData.Value.(*ua.HistoryData)
	if len(phd.DataValues) != 2 {
		t.Fatalf("intervals=%d, want 2", len(phd.DataValues))
	}
}

func TestHistorian_DeleteAtTime(t *testing.T) {
	h := NewHistorian()
	nodeID := ua.NewStringNodeID(2, "Hist.Del")
	h.EnableNode(nodeID, 100)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h.RecordValue(nodeID, &ua.DataValue{
		EncodingMask: ua.DataValueValue | ua.DataValueSourceTimestamp, Value: ua.MustVariant(float64(1)), SourceTimestamp: base,
	})
	res := h.DeleteAtTime(nodeID, []time.Time{base, base.Add(time.Second)})
	if res.OperationResults[0] != ua.StatusOK {
		t.Fatalf("delete existing: %v", res.OperationResults[0])
	}
	if res.OperationResults[1] != ua.StatusBadNoEntryExists {
		t.Fatalf("delete missing: %v", res.OperationResults[1])
	}
}

func TestHistorian_DeleteRawModified(t *testing.T) {
	h := NewHistorian()
	nodeID := ua.NewStringNodeID(2, "Hist.DelRaw")
	h.EnableNode(nodeID, 100)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		h.RecordValue(nodeID, &ua.DataValue{
			EncodingMask:    ua.DataValueValue | ua.DataValueSourceTimestamp,
			Value:           ua.MustVariant(float64(i)),
			SourceTimestamp: base.Add(time.Duration(i) * time.Second),
		})
	}

	if st := h.DeleteRawModified(nodeID, true, base, base.Add(10*time.Second)).StatusCode; st != ua.StatusBadHistoryOperationUnsupported {
		t.Fatalf("modified-only delete: %v", st)
	}
	if st := h.DeleteRawModified(ua.NewStringNodeID(2, "missing"), false, base, base.Add(time.Second)).StatusCode; st != ua.StatusBadHistoryOperationUnsupported {
		t.Fatalf("unknown node: %v", st)
	}

	res := h.DeleteRawModified(nodeID, false, base.Add(time.Second), base.Add(3*time.Second))
	if res.StatusCode != ua.StatusOK {
		t.Fatalf("delete range: %v", res.StatusCode)
	}
	raw, err := h.ReadRaw(nodeID, time.Time{}, time.Time{}, 0, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	hd := raw.HistoryData.Value.(*ua.HistoryData)
	// Samples at t=0, t=3 and t=4 remain (deleted [1s, 3s)).
	if len(hd.DataValues) != 3 {
		t.Fatalf("remaining=%d, want 3", len(hd.DataValues))
	}
}

// TestHistorian_DeleteRawModifiedRange: the range of a raw delete (Part 11
// §6.9.5.1) is that of a raw read: the end time is excluded, startTime =
// endTime deletes the value at startTime, and a range without a sample is
// Bad_NoData (§6.9.5.2). A delete removes exactly what a read of the same
// range returns. "Both startTime and endTime shall be defined. The
// startTime shall be less than the endTime": a range without one of them,
// or reversed, is Bad_HistoryOperationInvalid and deletes nothing, for a
// modified delete too.
func TestHistorian_DeleteRawModifiedRange(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	at := func(i int) time.Time { return base.Add(time.Duration(i) * time.Second) }
	nodeID := ua.NewStringNodeID(2, "Hist.DelRange")
	fresh := func(t *testing.T) *Historian {
		t.Helper()
		h := NewHistorian()
		h.EnableNode(nodeID, 100)
		for i := 0; i < 5; i++ {
			h.RecordValue(nodeID, &ua.DataValue{
				EncodingMask: ua.DataValueValue | ua.DataValueSourceTimestamp,
				Value:        ua.MustVariant(float64(i)), SourceTimestamp: at(i),
			})
		}
		return h
	}
	values := func(t *testing.T, h *Historian, start, end time.Time) []float64 {
		t.Helper()
		raw, err := h.ReadRaw(nodeID, start, end, 0, false, nil)
		require.NoError(t, err)
		var out []float64
		for _, dv := range raw.HistoryData.Value.(*ua.HistoryData).DataValues {
			out = append(out, dv.Value.Value().(float64))
		}
		return out
	}
	all := []float64{0, 1, 2, 3, 4}
	epoch := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC) // the 0 of the binary encoding
	for _, tc := range []struct {
		name       string
		start, end time.Time
		status     ua.StatusCode
		left       []float64
	}{
		{"end excluded", at(1), at(3), ua.StatusOK, []float64{0, 3, 4}},
		{"start equals end", at(2), at(2), ua.StatusOK, []float64{0, 1, 3, 4}},
		{"start equals end without sample", at(2).Add(time.Millisecond), at(2).Add(time.Millisecond), ua.StatusBadNoData, []float64{0, 1, 2, 3, 4}},
		{"reverse", at(3), at(1), ua.StatusBadHistoryOperationInvalid, all},
		{"no start time", time.Time{}, at(2), ua.StatusBadHistoryOperationInvalid, all},
		{"no end time", at(3), time.Time{}, ua.StatusBadHistoryOperationInvalid, all},
		{"neither time", time.Time{}, time.Time{}, ua.StatusBadHistoryOperationInvalid, all},
		{"start time at the epoch", epoch, at(2), ua.StatusBadHistoryOperationInvalid, all},
		{"end time before the epoch", at(0), epoch.Add(-time.Hour), ua.StatusBadHistoryOperationInvalid, all},
		{"only the end time in range", at(4), at(4).Add(time.Hour), ua.StatusOK, []float64{0, 1, 2, 3}},
		{"nothing in range", at(10), at(20), ua.StatusBadNoData, []float64{0, 1, 2, 3, 4}},
		{"range ending at the first sample", at(-5), at(0), ua.StatusBadNoData, []float64{0, 1, 2, 3, 4}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := fresh(t)
			if tc.status == ua.StatusOK && !tc.start.Equal(tc.end) {
				// What a read of the range returns is what the delete removes.
				read := values(t, h, tc.start, tc.end)
				require.NotEmpty(t, read)
				defer func() {
					for _, v := range read {
						require.NotContains(t, values(t, h, time.Time{}, time.Time{}), v)
					}
				}()
			}
			require.Equal(t, tc.status, h.DeleteRawModified(nodeID, false, tc.start, tc.end).StatusCode)
			require.Equal(t, tc.left, values(t, h, time.Time{}, time.Time{}))
			if tc.status == ua.StatusBadHistoryOperationInvalid {
				// A modified delete checks the range first as well.
				require.Equal(t, tc.status, h.DeleteRawModified(nodeID, true, tc.start, tc.end).StatusCode)
			}
		})
	}
}

func TestHistorian_ReadModified(t *testing.T) {
	h := NewHistorian()
	nodeID := ua.NewStringNodeID(2, "Hist.Mod")
	h.EnableNode(nodeID, 100)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h.RecordValue(nodeID, &ua.DataValue{
		EncodingMask: ua.DataValueValue | ua.DataValueSourceTimestamp, Value: ua.MustVariant(float64(1)), SourceTimestamp: base,
	})
	_ = h.UpdateData(nodeID, ua.PerformUpdateTypeInsert, []*ua.DataValue{{
		EncodingMask: ua.DataValueValue | ua.DataValueSourceTimestamp, Value: ua.MustVariant(float64(2)), SourceTimestamp: base.Add(time.Second),
	}})
	_ = h.UpdateData(nodeID, ua.PerformUpdateTypeReplace, []*ua.DataValue{{
		EncodingMask: ua.DataValueValue | ua.DataValueSourceTimestamp, Value: ua.MustVariant(float64(9)), SourceTimestamp: base,
	}})

	if st, _ := h.ReadModified(nodeID, time.Time{}, time.Time{}, 0, []byte("cp")); st.StatusCode != ua.StatusBadContinuationPointInvalid {
		t.Fatalf("bad CP: %v", st.StatusCode)
	}
	if st, _ := h.ReadModified(ua.NewStringNodeID(2, "x"), time.Time{}, time.Time{}, 0, nil); st.StatusCode != ua.StatusBadHistoryOperationUnsupported {
		t.Fatalf("unknown node: %v", st.StatusCode)
	}

	res, err := h.ReadModified(nodeID, base, base.Add(2*time.Second), 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	md := res.HistoryData.Value.(*ua.HistoryModifiedData)
	if len(md.DataValues) != 1 || len(md.ModificationInfos) != 1 {
		t.Fatalf("values=%d infos=%d", len(md.DataValues), len(md.ModificationInfos))
	}
}

func TestHistorian_ReadProcessed_MinMaxCount(t *testing.T) {
	h := NewHistorian()
	nodeID := ua.NewStringNodeID(2, "Hist.MinMax")
	h.EnableNode(nodeID, 100)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i, v := range []any{float32(1), int32(5), int64(3), uint32(9), float64(2)} {
		h.RecordValue(nodeID, &ua.DataValue{
			EncodingMask:    ua.DataValueValue | ua.DataValueSourceTimestamp,
			Value:           ua.MustVariant(v),
			SourceTimestamp: base.Add(time.Duration(i) * time.Second),
		})
	}

	// One interval [base, base+5s) over the five values, which ends after
	// the last of them: Partial (Part 13 §5.3.3.2). Minimum is the raw value
	// at the start of the interval, "Good, Raw" (Table 58); Maximum and
	// Count are Calculated; each keeps the type of its source value.
	end := base.Add(5 * time.Second)
	partial := ua.StatusCodeInfoTypeDataValue | ua.StatusCodeHistorianPartial
	for _, tc := range []struct {
		agg    uint32
		value  any
		status ua.StatusCode
	}{
		{id.AggregateFunctionMinimum, float32(1), partial},
		{id.AggregateFunctionMaximum, uint32(9), partial | ua.StatusCodeHistorianCalculated},
		{id.AggregateFunctionCount, int32(5), partial | ua.StatusCodeHistorianCalculated},
	} {
		res, err := h.ReadProcessed(nodeID, base, end, 5000, ua.NewNumericNodeID(0, tc.agg), nil)
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, res.StatusCode, id.Name(tc.agg))
		hd := res.HistoryData.Value.(*ua.HistoryData)
		require.Len(t, hd.DataValues, 1, id.Name(tc.agg))
		require.Equal(t, tc.value, hd.DataValues[0].Value.Value(), id.Name(tc.agg))
		require.Equal(t, tc.status, hd.DataValues[0].Status, id.Name(tc.agg))
		require.Equal(t, base, hd.DataValues[0].SourceTimestamp, id.Name(tc.agg))
	}

	read := func(start, end time.Time, pi float64, agg uint32, ac *ua.AggregateConfiguration) ua.StatusCode {
		res, err := h.ReadProcessed(nodeID, start, end, pi, ua.NewNumericNodeID(0, agg), ac)
		require.NoError(t, err)
		return res.StatusCode
	}
	require.Equal(t, ua.StatusBadAggregateNotSupported, read(base, end, 1000, 99999, nil))
	require.Equal(t, ua.StatusBadAggregateNotSupported, read(base, end, 1000, 99998, nil))
	// Part 11 §6.5.4.2: startTime equal to endTime is Bad_InvalidArgument,
	// an endTime before the startTime reads backwards.
	require.Equal(t, ua.StatusBadInvalidArgument, read(base, base, 1000, id.AggregateFunctionCount, nil))
	require.Equal(t, ua.StatusOK, read(end, base, 1000, id.AggregateFunctionCount, nil))
	require.Equal(t, ua.StatusBadInvalidArgument, read(base, end, -1, id.AggregateFunctionCount, nil))
	require.Equal(t, ua.StatusBadInvalidArgument, read(base, end, math.NaN(), id.AggregateFunctionCount, nil))
	require.Equal(t, ua.StatusOK, read(base, end, math.Inf(1), id.AggregateFunctionCount, nil))
	// Part 13 §4.2.1.2: PercentDataGood < 100 - PercentDataBad.
	require.Equal(t, ua.StatusBadAggregateInvalidInputs, read(base, end, 1000, id.AggregateFunctionCount, &ua.AggregateConfiguration{PercentDataBad: 10, PercentDataGood: 10}))

	res, err := h.ReadProcessed(ua.NewStringNodeID(2, "nope"), base, end, 1000, ua.NewNumericNodeID(0, id.AggregateFunctionCount), nil)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadHistoryOperationUnsupported, res.StatusCode)
}

// TestHistorian_AggregateConfig: the configuration of a node is the default
// one until it is set, and a read overrides it with its own.
func TestHistorian_AggregateConfig(t *testing.T) {
	h := NewHistorian()
	nodeID := ua.NewStringNodeID(2, "Hist.Cfg")
	h.EnableNode(nodeID, 100)
	require.Equal(t, aggregate.DefaultConfig(), h.AggregateConfig(nodeID))
	cfg := aggregate.Config{PercentDataBad: 50, PercentDataGood: 100, Stepped: true}
	h.SetAggregateConfig(nodeID, cfg)
	require.Equal(t, cfg, h.AggregateConfig(nodeID))
	require.Equal(t, aggregate.Functions(), h.AggregateFunctions())

	// A Good value and a Bad one: with PercentDataBad 50 the interval is
	// Bad, with the default 100 it is Uncertain.
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h.RecordValue(nodeID, &ua.DataValue{EncodingMask: ua.DataValueValue | ua.DataValueSourceTimestamp, Value: ua.MustVariant(1.0), SourceTimestamp: base})
	h.RecordValue(nodeID, &ua.DataValue{EncodingMask: ua.DataValueStatusCode | ua.DataValueSourceTimestamp, Status: ua.StatusBad, SourceTimestamp: base.Add(time.Second)})
	h.RecordValue(nodeID, &ua.DataValue{EncodingMask: ua.DataValueValue | ua.DataValueSourceTimestamp, Value: ua.MustVariant(2.0), SourceTimestamp: base.Add(3 * time.Second)})
	status := func(ac *ua.AggregateConfiguration) ua.StatusCode {
		res, err := h.ReadProcessed(nodeID, base, base.Add(2*time.Second), 0, ua.NewNumericNodeID(0, id.AggregateFunctionAverage), ac)
		require.NoError(t, err)
		return res.HistoryData.Value.(*ua.HistoryData).DataValues[0].Status &^ ua.StatusCodeHistorianBits &^ ua.StatusCodeInfoTypeDataValue
	}
	require.Equal(t, ua.StatusBad, status(nil))
	require.Equal(t, ua.StatusUncertainDataSubNormal, status(aggregate.DefaultConfig().AggregateConfiguration()))
}

func TestHistoryCPRegistry_SessionBound(t *testing.T) {
	released := 0
	reg := newHistoryCPRegistry(func([]byte) { released++ })
	outer := reg.bind("session-a", []byte("inner-1"))
	if _, st := reg.resolve("session-b", outer); st != ua.StatusBadContinuationPointInvalid {
		t.Fatalf("cross-session status=%v", st)
	}
	// Original binding still present after failed resolve.
	inner, st := reg.resolve("session-a", outer)
	if st != ua.StatusOK || string(inner) != "inner-1" {
		t.Fatalf("same-session resolve: st=%v inner=%q", st, inner)
	}
	reg.releaseSession("session-a")
	_ = released
}

// TestHistoryCPRegistry_ConcurrentSessionClose races bind/resolve/releaseSession.
// Must remain race-clean under go test -race.
func TestHistoryCPRegistry_ConcurrentSessionClose(t *testing.T) {
	var released atomic.Int64
	reg := newHistoryCPRegistry(func([]byte) { released.Add(1) })

	const n = 64
	var wg sync.WaitGroup
	wg.Add(n * 3)
	for i := 0; i < n; i++ {
		session := fmt.Sprintf("session-%d", i%4)
		go func() {
			defer wg.Done()
			outer := reg.bind(session, []byte("inner"))
			_, _ = reg.resolve(session, outer)
		}()
		go func() {
			defer wg.Done()
			reg.releaseSession(session)
		}()
		go func() {
			defer wg.Done()
			_ = reg.release(session, reg.bind(session, []byte("drop")))
		}()
	}
	wg.Wait()
	reg.releaseSession("session-0")
	reg.releaseSession("session-1")
	reg.releaseSession("session-2")
	reg.releaseSession("session-3")
}
