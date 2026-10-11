// SPDX-License-Identifier: MIT

package conformance

import (
	"context"
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// histBase is the timestamp of history sample 0; sample i is at histBase+i s.
var histBase = time.Date(2024, 1, 2, 3, 0, 0, 0, time.UTC)

func histAt(i int) time.Time { return histBase.Add(time.Duration(i) * time.Second) }

func histSample(i int, v float64) *ua.DataValue {
	return &ua.DataValue{
		EncodingMask:    ua.DataValueValue | ua.DataValueSourceTimestamp | ua.DataValueServerTimestamp,
		Value:           ua.MustVariant(v),
		SourceTimestamp: histAt(i),
		ServerTimestamp: histAt(i),
	}
}

// historySetup starts a server whose HistoryVar holds samples 0..n-1 (value i
// at histAt(i)) in the built-in historian.
func historySetup(t *testing.T, n int) (*opcua.Client, *testutil.Fixture, *server.Historian, string) {
	t.Helper()
	h := server.NewHistorian()
	c, f, _, url := setupWith(t, func(srv *server.Server, f *testutil.Fixture) {
		h.EnableNode(f.HistoryVar, 0)
		for i := 0; i < n; i++ {
			h.RecordValue(f.HistoryVar, histSample(i, float64(i)))
		}
		srv.SetHistorian(h)
	})
	return c, f, h, url
}

// rawHistory performs a raw (not modified) HistoryRead for one node and
// returns its result.
func rawHistory(t *testing.T, c *opcua.Client, node *ua.NodeID, start, end time.Time, max uint32, cp []byte) *ua.HistoryReadResult {
	t.Helper()
	resp, err := c.HistoryReadRawModified(context.Background(),
		[]*ua.HistoryReadValueID{{NodeID: node, ContinuationPoint: cp}},
		&ua.ReadRawModifiedDetails{StartTime: start, EndTime: end, NumValuesPerNode: max})
	require.NoError(t, err)
	require.Len(t, resp.Results, 1)
	return resp.Results[0]
}

// histValues extracts the float values of a HistoryData result.
func histValues(t *testing.T, r *ua.HistoryReadResult) []float64 {
	t.Helper()
	require.Equal(t, ua.StatusOK, r.StatusCode)
	require.NotNil(t, r.HistoryData)
	hd, ok := r.HistoryData.Value.(*ua.HistoryData)
	require.True(t, ok, "expected *ua.HistoryData, got %T", r.HistoryData.Value)
	return floats(hd.DataValues)
}

func floats(dvs []*ua.DataValue) []float64 {
	out := make([]float64, len(dvs))
	for i, dv := range dvs {
		out[i] = dv.Value.Value().(float64)
	}
	return out
}

func seq(from, to int) []float64 {
	var out []float64
	if from <= to {
		for i := from; i <= to; i++ {
			out = append(out, float64(i))
		}
	} else {
		for i := from; i >= to; i-- {
			out = append(out, float64(i))
		}
	}
	return out
}

func TestHistory_ReadRawRanges(t *testing.T) {
	c, f, _, _ := historySetup(t, 10)
	ctx := context.Background()

	t.Run("FullRangeWithTimestamps", func(t *testing.T) {
		dvs, err := c.ReadHistory(ctx, f.HistoryVar, histAt(0), histAt(100), 0)
		require.NoError(t, err)
		require.Equal(t, seq(0, 9), floats(dvs))
		for i, dv := range dvs {
			require.True(t, histAt(i).Equal(dv.SourceTimestamp), "sample %d source timestamp", i)
			require.True(t, histAt(i).Equal(dv.ServerTimestamp), "sample %d server timestamp", i)
		}
	})

	t.Run("StartInclusiveEndExclusive", func(t *testing.T) {
		dvs, err := c.ReadHistory(ctx, f.HistoryVar, histAt(2), histAt(5), 0)
		require.NoError(t, err)
		require.Equal(t, seq(2, 4), floats(dvs))
	})

	t.Run("BetweenSamples", func(t *testing.T) {
		dvs, err := c.ReadHistory(ctx, f.HistoryVar, histAt(2).Add(time.Millisecond), histAt(5).Add(time.Millisecond), 0)
		require.NoError(t, err)
		require.Equal(t, seq(3, 5), floats(dvs))
	})

	t.Run("EmptyRange", func(t *testing.T) {
		dvs, err := c.ReadHistory(ctx, f.HistoryVar, histAt(50), histAt(60), 0)
		require.NoError(t, err)
		require.Empty(t, dvs)
	})

	t.Run("ReverseOrder", func(t *testing.T) {
		// start > end: newest first, start inclusive, end exclusive.
		dvs, err := c.ReadHistory(ctx, f.HistoryVar, histAt(7), histAt(3), 0)
		require.NoError(t, err)
		require.Equal(t, seq(7, 4), floats(dvs))
	})

	t.Run("MaxValuesTruncates", func(t *testing.T) {
		dvs, err := c.ReadHistory(ctx, f.HistoryVar, histAt(0), histAt(100), 4)
		require.NoError(t, err)
		require.Equal(t, seq(0, 3), floats(dvs))
	})

	t.Run("ReverseWithMaxValuesReturnsNewest", func(t *testing.T) {
		dvs, err := c.ReadHistory(ctx, f.HistoryVar, histAt(9), histAt(0), 3)
		require.NoError(t, err)
		require.Equal(t, seq(9, 7), floats(dvs))
	})

	t.Run("NodeWithoutHistory", func(t *testing.T) {
		_, err := c.ReadHistory(ctx, f.NoHistoryVar, histAt(0), histAt(100), 0)
		require.ErrorIs(t, err, ua.StatusBadHistoryOperationUnsupported)
	})

	t.Run("MixedNodesPerNodeStatus", func(t *testing.T) {
		resp, err := c.HistoryReadRawModified(ctx,
			[]*ua.HistoryReadValueID{{NodeID: f.NoHistoryVar}, {NodeID: f.HistoryVar}, {NodeID: ua.NewStringNodeID(f.NSIndex, "Nope")}},
			&ua.ReadRawModifiedDetails{StartTime: histAt(8), EndTime: histAt(100)})
		require.NoError(t, err)
		require.Len(t, resp.Results, 3)
		require.Equal(t, ua.StatusBadHistoryOperationUnsupported, resp.Results[0].StatusCode)
		require.Equal(t, seq(8, 9), histValues(t, resp.Results[1]))
		require.Equal(t, ua.StatusBadHistoryOperationUnsupported, resp.Results[2].StatusCode)
	})
}

// TestHistory_ContinuationPoints covers paging, one-shot semantics, release,
// reuse after release and session binding of history continuation points.
func TestHistory_ContinuationPoints(t *testing.T) {
	c, f, _, url := historySetup(t, 10)
	ctx := context.Background()
	all := func() (time.Time, time.Time) { return histAt(0), histAt(100) }

	t.Run("PagesThroughAllData", func(t *testing.T) {
		start, end := all()
		var got []float64
		var cp []byte
		pages := 0
		for {
			r := rawHistory(t, c, f.HistoryVar, start, end, 4, cp)
			got = append(got, histValues(t, r)...)
			pages++
			cp = r.ContinuationPoint
			if len(cp) == 0 {
				break
			}
			require.Less(t, pages, 10, "continuation never terminated")
		}
		require.Equal(t, seq(0, 9), got)
		require.Equal(t, 3, pages, "4 + 4 + 2 values")
	})

	t.Run("ReversePaging", func(t *testing.T) {
		var got []float64
		var cp []byte
		for {
			r := rawHistory(t, c, f.HistoryVar, histAt(9), histAt(0).Add(-time.Second), 4, cp)
			got = append(got, histValues(t, r)...)
			cp = r.ContinuationPoint
			if len(cp) == 0 {
				break
			}
			require.LessOrEqual(t, len(got), 10)
		}
		require.Equal(t, seq(9, 0), got)
	})

	t.Run("ExactFitLeavesNoContinuationPoint", func(t *testing.T) {
		start, end := all()
		r := rawHistory(t, c, f.HistoryVar, start, end, 10, nil)
		require.Equal(t, seq(0, 9), histValues(t, r))
		require.Empty(t, r.ContinuationPoint)
	})

	t.Run("OneShot", func(t *testing.T) {
		start, end := all()
		first := rawHistory(t, c, f.HistoryVar, start, end, 4, nil)
		require.NotEmpty(t, first.ContinuationPoint)
		second := rawHistory(t, c, f.HistoryVar, start, end, 4, first.ContinuationPoint)
		require.Equal(t, seq(4, 7), histValues(t, second))
		require.NotEmpty(t, second.ContinuationPoint)
		require.NotEqual(t, first.ContinuationPoint, second.ContinuationPoint)

		// A consumed continuation point cannot be replayed.
		replay := rawHistory(t, c, f.HistoryVar, start, end, 4, first.ContinuationPoint)
		require.Equal(t, ua.StatusBadContinuationPointInvalid, replay.StatusCode)
		// The live one still works.
		third := rawHistory(t, c, f.HistoryVar, start, end, 4, second.ContinuationPoint)
		require.Equal(t, seq(8, 9), histValues(t, third))
		require.Empty(t, third.ContinuationPoint)
	})

	t.Run("ReleaseThenReuse", func(t *testing.T) {
		start, end := all()
		first := rawHistory(t, c, f.HistoryVar, start, end, 4, nil)
		require.NotEmpty(t, first.ContinuationPoint)

		rel := mustSendRaw[ua.HistoryReadResponse](t, c, &ua.HistoryReadRequest{
			HistoryReadDetails:        ua.NewExtensionObject(&ua.ReadRawModifiedDetails{StartTime: start, EndTime: end}),
			TimestampsToReturn:        ua.TimestampsToReturnBoth,
			ReleaseContinuationPoints: true,
			NodesToRead:               []*ua.HistoryReadValueID{{NodeID: f.HistoryVar, ContinuationPoint: first.ContinuationPoint}},
		})
		require.Len(t, rel.Results, 1)
		require.Equal(t, ua.StatusOK, rel.Results[0].StatusCode)
		require.Nil(t, rel.Results[0].HistoryData.Value, "a release returns no data")
		require.Empty(t, rel.Results[0].ContinuationPoint)

		reuse := rawHistory(t, c, f.HistoryVar, start, end, 4, first.ContinuationPoint)
		require.Equal(t, ua.StatusBadContinuationPointInvalid, reuse.StatusCode)

		// A fresh read is unaffected.
		require.Equal(t, seq(0, 3), histValues(t, rawHistory(t, c, f.HistoryVar, start, end, 4, nil)))
	})

	t.Run("BoundToSession", func(t *testing.T) {
		start, end := all()
		first := rawHistory(t, c, f.HistoryVar, start, end, 4, nil)
		require.NotEmpty(t, first.ContinuationPoint)

		intruder := newClient(t, url)
		stolen := rawHistory(t, intruder, f.HistoryVar, start, end, 4, first.ContinuationPoint)
		require.Equal(t, ua.StatusBadContinuationPointInvalid, stolen.StatusCode)

		// The failed attempt did not consume the owner's continuation point.
		mine := rawHistory(t, c, f.HistoryVar, start, end, 4, first.ContinuationPoint)
		require.Equal(t, seq(4, 7), histValues(t, mine))
	})

	t.Run("Garbage", func(t *testing.T) {
		start, end := all()
		r := rawHistory(t, c, f.HistoryVar, start, end, 4, []byte("not-a-continuation-point"))
		require.Equal(t, ua.StatusBadContinuationPointInvalid, r.StatusCode)
	})

	t.Run("ReadHistoryAllIterator", func(t *testing.T) {
		var got []float64
		for dv, err := range c.ReadHistoryAll(ctx, f.HistoryVar, histAt(1), histAt(100)) {
			require.NoError(t, err)
			got = append(got, dv.Value.Value().(float64))
		}
		require.Equal(t, seq(1, 9), got)

		// Early termination by the caller.
		got = nil
		for dv, err := range c.ReadHistoryAll(ctx, f.HistoryVar, histAt(0), histAt(100)) {
			require.NoError(t, err)
			got = append(got, dv.Value.Value().(float64))
			if len(got) == 3 {
				break
			}
		}
		require.Equal(t, seq(0, 2), got)
	})
}

func TestHistory_ReadAtTime(t *testing.T) {
	c, f, _, _ := historySetup(t, 10)
	ctx := context.Background()

	times := []time.Time{
		histAt(3),                             // exact
		histAt(5).Add(400 * time.Millisecond), // between samples: nearest previous
		histAt(-10),                           // before the first sample
		histAt(1000),                          // after the last sample
	}
	resp, err := c.HistoryReadAtTime(ctx,
		[]*ua.HistoryReadValueID{{NodeID: f.HistoryVar}, {NodeID: f.NoHistoryVar}},
		&ua.ReadAtTimeDetails{ReqTimes: times})
	require.NoError(t, err)
	require.Len(t, resp.Results, 2)
	require.Equal(t, ua.StatusBadHistoryOperationUnsupported, resp.Results[1].StatusCode)

	require.Equal(t, ua.StatusOK, resp.Results[0].StatusCode)
	dvs := resp.Results[0].HistoryData.Value.(*ua.HistoryData).DataValues
	require.Len(t, dvs, len(times))

	require.Equal(t, float64(3), dvs[0].Value.Value())
	require.True(t, histAt(3).Equal(dvs[0].SourceTimestamp))

	require.Equal(t, float64(5), dvs[1].Value.Value())
	require.True(t, histAt(5).Equal(dvs[1].SourceTimestamp))

	require.Equal(t, ua.StatusBadNoData, dvs[2].Status)
	require.True(t, times[2].Equal(dvs[2].SourceTimestamp), "a missing value echoes the requested time")

	require.Equal(t, float64(9), dvs[3].Value.Value())
}

func TestHistory_ReadProcessed(t *testing.T) {
	c, f, _, _ := historySetup(t, 10)
	ctx := context.Background()

	read := func(agg uint32, start, end time.Time, intervalMS float64) *ua.HistoryReadResult {
		t.Helper()
		resp, err := c.HistoryReadProcessed(ctx,
			[]*ua.HistoryReadValueID{{NodeID: f.HistoryVar}},
			&ua.ReadProcessedDetails{
				StartTime:              start,
				EndTime:                end,
				ProcessingInterval:     intervalMS,
				AggregateType:          []*ua.NodeID{ua.NewNumericNodeID(0, agg)},
				AggregateConfiguration: &ua.AggregateConfiguration{},
			})
		require.NoError(t, err)
		require.Len(t, resp.Results, 1)
		return resp.Results[0]
	}

	// Three 5s intervals over samples 0..9: [0..4], [5..9], and an empty one.
	for _, tc := range []struct {
		name string
		agg  uint32
		want []any
	}{
		{"Average", id.AggregateFunctionAverage, []any{float64(2), float64(7)}},
		{"Minimum", id.AggregateFunctionMinimum, []any{float64(0), float64(5)}},
		{"Maximum", id.AggregateFunctionMaximum, []any{float64(4), float64(9)}},
		{"Count", id.AggregateFunctionCount, []any{uint32(5), uint32(5)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := read(tc.agg, histAt(0), histAt(15), 5000)
			require.Equal(t, ua.StatusOK, r.StatusCode)
			dvs := r.HistoryData.Value.(*ua.HistoryData).DataValues
			require.Len(t, dvs, 3)
			for i, want := range tc.want {
				require.Equal(t, ua.StatusOK, dvs[i].Status)
				require.Equal(t, want, dvs[i].Value.Value(), "interval %d", i)
				require.True(t, histAt(5*i).Equal(dvs[i].SourceTimestamp), "interval %d starts at its lower bound", i)
			}
			require.Equal(t, ua.StatusBadNoData, dvs[2].Status, "interval without samples")
			require.True(t, histAt(10).Equal(dvs[2].SourceTimestamp))
		})
	}

	t.Run("PartialLastInterval", func(t *testing.T) {
		// 4s intervals over [0s, 10s): [0..3], [4..7], [8..9].
		r := read(id.AggregateFunctionCount, histAt(0), histAt(10), 4000)
		dvs := r.HistoryData.Value.(*ua.HistoryData).DataValues
		require.Len(t, dvs, 3)
		require.Equal(t, []any{uint32(4), uint32(4), uint32(2)},
			[]any{dvs[0].Value.Value(), dvs[1].Value.Value(), dvs[2].Value.Value()})
	})

	t.Run("InvalidArguments", func(t *testing.T) {
		require.Equal(t, ua.StatusBadHistoryOperationInvalid,
			read(id.AggregateFunctionAverage, histAt(5), histAt(5), 1000).StatusCode, "empty time range")
		require.Equal(t, ua.StatusBadHistoryOperationInvalid,
			read(id.AggregateFunctionAverage, histAt(5), histAt(2), 1000).StatusCode, "end before start")
		require.Equal(t, ua.StatusBadHistoryOperationInvalid,
			read(id.AggregateFunctionAverage, histAt(0), histAt(10), 0).StatusCode, "zero processing interval")
		require.Equal(t, ua.StatusBadHistoryOperationUnsupported,
			read(id.AggregateFunctionTotal, histAt(0), histAt(10), 1000).StatusCode, "unsupported aggregate")
	})
}

func TestHistory_UpdateData(t *testing.T) {
	c, f, _, _ := historySetup(t, 5)
	ctx := context.Background()

	update := func(node *ua.NodeID, perform ua.PerformUpdateType, values ...*ua.DataValue) *ua.HistoryUpdateResult {
		t.Helper()
		resp, err := c.HistoryUpdateData(ctx, &ua.UpdateDataDetails{
			NodeID:               node,
			PerformInsertReplace: perform,
			UpdateValues:         values,
		})
		require.NoError(t, err)
		require.Len(t, resp.Results, 1)
		return resp.Results[0]
	}
	current := func() []float64 {
		t.Helper()
		dvs, err := c.ReadHistory(ctx, f.HistoryVar, histAt(-100), histAt(100), 0)
		require.NoError(t, err)
		// Results must always be ordered by source timestamp.
		for i := 1; i < len(dvs); i++ {
			require.True(t, dvs[i-1].SourceTimestamp.Before(dvs[i].SourceTimestamp), "history out of order at %d", i)
		}
		return floats(dvs)
	}
	// A sample between the seconds of the pre-recorded ones.
	mid := func(i int, v float64) *ua.DataValue {
		dv := histSample(i, v)
		dv.SourceTimestamp = histAt(i).Add(500 * time.Millisecond)
		return dv
	}

	t.Run("Insert", func(t *testing.T) {
		r := update(f.HistoryVar, ua.PerformUpdateTypeInsert, mid(1, 1.5), histSample(2, 222), histSample(7, 7))
		require.Equal(t, ua.StatusOK, r.StatusCode)
		require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusBadEntryExists, ua.StatusOK}, r.OperationResults)
		require.Equal(t, []float64{0, 1, 1.5, 2, 3, 4, 7}, current(), "existing entry untouched, new ones sorted in")
	})

	t.Run("Replace", func(t *testing.T) {
		r := update(f.HistoryVar, ua.PerformUpdateTypeReplace, histSample(2, 20), histSample(40, 40))
		require.Equal(t, ua.StatusOK, r.StatusCode)
		require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusBadNoEntryExists}, r.OperationResults)
		require.Equal(t, []float64{0, 1, 1.5, 20, 3, 4, 7}, current())
	})

	t.Run("Update", func(t *testing.T) {
		r := update(f.HistoryVar, ua.PerformUpdateTypeUpdate, histSample(3, 30), histSample(5, 50))
		require.Equal(t, ua.StatusOK, r.StatusCode)
		require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusOK}, r.OperationResults)
		require.Equal(t, []float64{0, 1, 1.5, 20, 30, 4, 50, 7}, current())
	})

	t.Run("InvalidValues", func(t *testing.T) {
		// A historical value needs a source timestamp to be placed in time.
		noTimestamp := &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(1.0)}
		r := update(f.HistoryVar, ua.PerformUpdateTypeInsert, noTimestamp, histSample(6, 6), noTimestamp)
		require.Equal(t, []ua.StatusCode{ua.StatusBadInvalidArgument, ua.StatusOK, ua.StatusBadInvalidArgument}, r.OperationResults)
		del, err := c.HistoryDeleteAtTime(ctx, &ua.DeleteAtTimeDetails{NodeID: f.HistoryVar, ReqTimes: []time.Time{histAt(6)}})
		require.NoError(t, err)
		require.Equal(t, []ua.StatusCode{ua.StatusOK}, del.Results[0].OperationResults)

		r = update(f.HistoryVar, ua.PerformUpdateTypeRemove, histSample(0, 0))
		require.Equal(t, []ua.StatusCode{ua.StatusBadHistoryOperationInvalid}, r.OperationResults)
		require.Equal(t, []float64{0, 1, 1.5, 20, 30, 4, 50, 7}, current(), "rejected updates must not change history")
	})

	t.Run("NodeWithoutHistory", func(t *testing.T) {
		r := update(f.NoHistoryVar, ua.PerformUpdateTypeInsert, histSample(0, 1))
		require.Equal(t, ua.StatusBadHistoryOperationUnsupported, r.StatusCode)
	})

	t.Run("ReadModified", func(t *testing.T) {
		// The modification log lists every successful change above, in order.
		resp, err := c.HistoryReadRawModified(ctx,
			[]*ua.HistoryReadValueID{{NodeID: f.HistoryVar}},
			&ua.ReadRawModifiedDetails{IsReadModified: true, StartTime: histAt(-100), EndTime: histAt(100)})
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, resp.Results[0].StatusCode)
		md, ok := resp.Results[0].HistoryData.Value.(*ua.HistoryModifiedData)
		require.True(t, ok, "expected *ua.HistoryModifiedData, got %T", resp.Results[0].HistoryData.Value)

		require.Equal(t, []float64{1.5, 7, 20, 30, 50, 6}, floats(md.DataValues))
		wantTypes := []ua.HistoryUpdateType{
			ua.HistoryUpdateTypeInsert, ua.HistoryUpdateTypeInsert,
			ua.HistoryUpdateTypeReplace,
			ua.HistoryUpdateTypeReplace, ua.HistoryUpdateTypeInsert,
			ua.HistoryUpdateTypeInsert,
		}
		require.Len(t, md.ModificationInfos, len(wantTypes))
		for i, mi := range md.ModificationInfos {
			require.Equal(t, wantTypes[i], mi.UpdateType, "modification %d", i)
			require.WithinDuration(t, time.Now(), mi.ModificationTime, time.Minute)
		}

		// Time range and count limit apply to the modified values.
		resp, err = c.HistoryReadRawModified(ctx,
			[]*ua.HistoryReadValueID{{NodeID: f.HistoryVar}},
			&ua.ReadRawModifiedDetails{IsReadModified: true, StartTime: histAt(2), EndTime: histAt(100), NumValuesPerNode: 2})
		require.NoError(t, err)
		md = resp.Results[0].HistoryData.Value.(*ua.HistoryModifiedData)
		require.Equal(t, []float64{7, 20}, floats(md.DataValues))

		// Modified reads on a node without history are refused.
		resp, err = c.HistoryReadRawModified(ctx,
			[]*ua.HistoryReadValueID{{NodeID: f.NoHistoryVar}},
			&ua.ReadRawModifiedDetails{IsReadModified: true})
		require.NoError(t, err)
		require.Equal(t, ua.StatusBadHistoryOperationUnsupported, resp.Results[0].StatusCode)
	})

	t.Run("MultipleDetailsInOneRequest", func(t *testing.T) {
		resp, err := c.HistoryUpdateData(ctx,
			&ua.UpdateDataDetails{NodeID: f.HistoryVar, PerformInsertReplace: ua.PerformUpdateTypeInsert, UpdateValues: []*ua.DataValue{histSample(8, 8)}},
			&ua.UpdateDataDetails{NodeID: f.NoHistoryVar, PerformInsertReplace: ua.PerformUpdateTypeInsert, UpdateValues: []*ua.DataValue{histSample(8, 8)}},
			&ua.UpdateDataDetails{NodeID: f.HistoryVar, PerformInsertReplace: ua.PerformUpdateTypeInsert, UpdateValues: []*ua.DataValue{histSample(8, 8)}},
		)
		require.NoError(t, err)
		require.Len(t, resp.Results, 3)
		require.Equal(t, []ua.StatusCode{ua.StatusOK}, resp.Results[0].OperationResults)
		require.Equal(t, ua.StatusBadHistoryOperationUnsupported, resp.Results[1].StatusCode)
		require.Equal(t, []ua.StatusCode{ua.StatusBadEntryExists}, resp.Results[2].OperationResults)
	})
}

func TestHistory_Delete(t *testing.T) {
	c, f, _, _ := historySetup(t, 10)
	ctx := context.Background()
	current := func() []float64 {
		t.Helper()
		dvs, err := c.ReadHistory(ctx, f.HistoryVar, histAt(-100), histAt(100), 0)
		require.NoError(t, err)
		return floats(dvs)
	}

	t.Run("AtTime", func(t *testing.T) {
		resp, err := c.HistoryDeleteAtTime(ctx, &ua.DeleteAtTimeDetails{
			NodeID:   f.HistoryVar,
			ReqTimes: []time.Time{histAt(3), histAt(3).Add(time.Millisecond), histAt(8), histAt(3)},
		})
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, resp.Results[0].StatusCode)
		require.Equal(t, []ua.StatusCode{
			ua.StatusOK, ua.StatusBadNoEntryExists, ua.StatusOK, ua.StatusBadNoEntryExists,
		}, resp.Results[0].OperationResults)
		require.Equal(t, []float64{0, 1, 2, 4, 5, 6, 7, 9}, current())
	})

	t.Run("RawRangeInclusiveWindow", func(t *testing.T) {
		// The built-in historian deletes the inclusive window [start, end]
		// (see server.Historian.DeleteRawModified).
		resp, err := c.HistoryDeleteRawModified(ctx, &ua.DeleteRawModifiedDetails{
			NodeID: f.HistoryVar, StartTime: histAt(4), EndTime: histAt(6),
		})
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, resp.Results[0].StatusCode)
		require.Equal(t, []float64{0, 1, 2, 7, 9}, current())
	})

	t.Run("RawRangeReversedBounds", func(t *testing.T) {
		resp, err := c.HistoryDeleteRawModified(ctx, &ua.DeleteRawModifiedDetails{
			NodeID: f.HistoryVar, StartTime: histAt(2), EndTime: histAt(1),
		})
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, resp.Results[0].StatusCode)
		require.Equal(t, []float64{0, 7, 9}, current())
	})

	t.Run("RawRangeMatchingNothing", func(t *testing.T) {
		resp, err := c.HistoryDeleteRawModified(ctx, &ua.DeleteRawModifiedDetails{
			NodeID: f.HistoryVar, StartTime: histAt(50), EndTime: histAt(60),
		})
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, resp.Results[0].StatusCode)
		require.Equal(t, []float64{0, 7, 9}, current())
	})

	t.Run("DeleteModifiedUnsupported", func(t *testing.T) {
		resp, err := c.HistoryDeleteRawModified(ctx, &ua.DeleteRawModifiedDetails{
			NodeID: f.HistoryVar, IsDeleteModified: true, StartTime: histAt(0), EndTime: histAt(100),
		})
		require.NoError(t, err)
		require.Equal(t, ua.StatusBadHistoryOperationUnsupported, resp.Results[0].StatusCode)
		require.Equal(t, []float64{0, 7, 9}, current(), "nothing may be deleted")
	})

	t.Run("NodeWithoutHistory", func(t *testing.T) {
		resp, err := c.HistoryDeleteRawModified(ctx, &ua.DeleteRawModifiedDetails{
			NodeID: f.NoHistoryVar, StartTime: histAt(0), EndTime: histAt(100),
		})
		require.NoError(t, err)
		require.Equal(t, ua.StatusBadHistoryOperationUnsupported, resp.Results[0].StatusCode)

		resp, err = c.HistoryDeleteAtTime(ctx, &ua.DeleteAtTimeDetails{NodeID: f.NoHistoryVar, ReqTimes: []time.Time{histAt(0)}})
		require.NoError(t, err)
		require.Equal(t, ua.StatusBadHistoryOperationUnsupported, resp.Results[0].StatusCode)
	})

	t.Run("RawWholeRange", func(t *testing.T) {
		resp, err := c.HistoryDeleteRawModified(ctx, &ua.DeleteRawModifiedDetails{
			NodeID: f.HistoryVar, StartTime: histAt(-100), EndTime: histAt(100),
		})
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, resp.Results[0].StatusCode)
		require.Empty(t, current())
	})
}

// TestHistory_SampleCapacity verifies the historian keeps only the newest
// samples once a node's capacity is reached.
func TestHistory_SampleCapacity(t *testing.T) {
	h := server.NewHistorian()
	c, f, _, _ := setupWith(t, func(srv *server.Server, f *testutil.Fixture) {
		h.EnableNode(f.HistoryVar, 4)
		srv.SetHistorian(h)
	})
	for i := 0; i < 9; i++ {
		h.RecordValue(f.HistoryVar, histSample(i, float64(i)))
	}
	dvs, err := c.ReadHistory(context.Background(), f.HistoryVar, histAt(0), histAt(100), 0)
	require.NoError(t, err)
	require.Equal(t, seq(5, 8), floats(dvs))

	// Values recorded while the client is connected become visible at once.
	h.RecordValue(f.HistoryVar, histSample(9, 9))
	dvs, err = c.ReadHistory(context.Background(), f.HistoryVar, histAt(0), histAt(100), 0)
	require.NoError(t, err)
	require.Equal(t, seq(6, 9), floats(dvs))
}

// pagingProvider is a minimal custom server.HistoryProvider that serves values
// 0..total-1 in fixed pages regardless of the requested count and supports
// none of the optional history capabilities.
type pagingProvider struct {
	total, page int

	mu       sync.Mutex
	released [][]byte
	reads    int
}

func (p *pagingProvider) ReadRaw(nodeID *ua.NodeID, start, end time.Time, numValues uint32, bounds bool, cp []byte) (*ua.HistoryReadResult, error) {
	p.mu.Lock()
	p.reads++
	p.mu.Unlock()
	if nodeID.StringID() != "HistoryVar" {
		return &ua.HistoryReadResult{StatusCode: ua.StatusBadNodeIDUnknown}, nil
	}
	from := 0
	if len(cp) > 0 {
		if len(cp) != 4 {
			return &ua.HistoryReadResult{StatusCode: ua.StatusBadContinuationPointInvalid}, nil
		}
		from = int(binary.LittleEndian.Uint32(cp))
	}
	to := from + p.page
	if to > p.total {
		to = p.total
	}
	var dvs []*ua.DataValue
	for i := from; i < to; i++ {
		dvs = append(dvs, histSample(i, float64(i)))
	}
	res := &ua.HistoryReadResult{StatusCode: ua.StatusOK, HistoryData: ua.NewExtensionObject(&ua.HistoryData{DataValues: dvs})}
	if to < p.total {
		res.ContinuationPoint = binary.LittleEndian.AppendUint32(nil, uint32(to))
	}
	return res, nil
}

func (p *pagingProvider) ReleaseContinuation(cp []byte) {
	p.mu.Lock()
	p.released = append(p.released, append([]byte(nil), cp...))
	p.mu.Unlock()
}

// TestHistory_CustomProvider plugs a user-supplied HistoryProvider into the
// server and verifies continuation points are mapped, hidden and released, and
// that capabilities the provider lacks are reported as unsupported.
func TestHistory_CustomProvider(t *testing.T) {
	p := &pagingProvider{total: 11, page: 4}
	c, f, _, _ := setupWith(t, func(srv *server.Server, _ *testutil.Fixture) { srv.SetHistorian(p) })
	ctx := context.Background()

	t.Run("ReadHistoryAllFollowsContinuationPoints", func(t *testing.T) {
		var got []float64
		for dv, err := range c.ReadHistoryAll(ctx, f.HistoryVar, histAt(0), histAt(100)) {
			require.NoError(t, err)
			got = append(got, dv.Value.Value().(float64))
		}
		require.Equal(t, seq(0, 10), got)
	})

	t.Run("ContinuationPointIsOpaque", func(t *testing.T) {
		r := rawHistory(t, c, f.HistoryVar, histAt(0), histAt(100), 0, nil)
		require.Equal(t, seq(0, 3), histValues(t, r))
		require.Len(t, r.ContinuationPoint, 16, "clients get a server-issued token, not the provider's")
		// The provider's own token is not accepted from clients.
		forged := rawHistory(t, c, f.HistoryVar, histAt(0), histAt(100), 0, binary.LittleEndian.AppendUint32(nil, 8))
		require.Equal(t, ua.StatusBadContinuationPointInvalid, forged.StatusCode)

		next := rawHistory(t, c, f.HistoryVar, histAt(0), histAt(100), 0, r.ContinuationPoint)
		require.Equal(t, seq(4, 7), histValues(t, next))

		// Releasing reaches the provider with its own token (offset 8).
		rel := mustSendRaw[ua.HistoryReadResponse](t, c, &ua.HistoryReadRequest{
			HistoryReadDetails:        ua.NewExtensionObject(&ua.ReadRawModifiedDetails{}),
			TimestampsToReturn:        ua.TimestampsToReturnBoth,
			ReleaseContinuationPoints: true,
			NodesToRead:               []*ua.HistoryReadValueID{{NodeID: f.HistoryVar, ContinuationPoint: next.ContinuationPoint}},
		})
		require.Equal(t, ua.StatusOK, rel.Results[0].StatusCode)
		p.mu.Lock()
		released := append([][]byte(nil), p.released...)
		p.mu.Unlock()
		require.Contains(t, released, binary.LittleEndian.AppendUint32(nil, 8))
	})

	t.Run("ProviderStatusIsForwarded", func(t *testing.T) {
		r := rawHistory(t, c, f.NoHistoryVar, histAt(0), histAt(100), 0, nil)
		require.Equal(t, ua.StatusBadNodeIDUnknown, r.StatusCode)
	})

	t.Run("MissingCapabilitiesUnsupported", func(t *testing.T) {
		nodes := []*ua.HistoryReadValueID{{NodeID: f.HistoryVar}}
		unsupported := ua.StatusBadHistoryOperationUnsupported

		at, err := c.HistoryReadAtTime(ctx, nodes, &ua.ReadAtTimeDetails{ReqTimes: []time.Time{histAt(1)}})
		require.NoError(t, err)
		require.Equal(t, unsupported, at.Results[0].StatusCode)

		pr, err := c.HistoryReadProcessed(ctx, nodes, &ua.ReadProcessedDetails{
			StartTime: histAt(0), EndTime: histAt(10), ProcessingInterval: 1000,
			AggregateType:          []*ua.NodeID{ua.NewNumericNodeID(0, id.AggregateFunctionAverage)},
			AggregateConfiguration: &ua.AggregateConfiguration{},
		})
		require.NoError(t, err)
		require.Equal(t, unsupported, pr.Results[0].StatusCode)

		mod, err := c.HistoryReadRawModified(ctx, nodes, &ua.ReadRawModifiedDetails{IsReadModified: true})
		require.NoError(t, err)
		require.Equal(t, unsupported, mod.Results[0].StatusCode)

		up, err := c.HistoryUpdateData(ctx, &ua.UpdateDataDetails{
			NodeID: f.HistoryVar, PerformInsertReplace: ua.PerformUpdateTypeInsert, UpdateValues: []*ua.DataValue{histSample(50, 1)},
		})
		require.NoError(t, err)
		require.Equal(t, unsupported, up.Results[0].StatusCode)

		del, err := c.HistoryDeleteRawModified(ctx, &ua.DeleteRawModifiedDetails{NodeID: f.HistoryVar, StartTime: histAt(0), EndTime: histAt(1)})
		require.NoError(t, err)
		require.Equal(t, unsupported, del.Results[0].StatusCode)

		delAt, err := c.HistoryDeleteAtTime(ctx, &ua.DeleteAtTimeDetails{NodeID: f.HistoryVar, ReqTimes: []time.Time{histAt(0)}})
		require.NoError(t, err)
		require.Equal(t, unsupported, delAt.Results[0].StatusCode)
	})
}
