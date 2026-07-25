// SPDX-License-Identifier: MIT

package server

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
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

	// Reverse range (start > end) still deletes the inclusive window.
	res := h.DeleteRawModified(nodeID, false, base.Add(3*time.Second), base.Add(time.Second))
	if res.StatusCode != ua.StatusOK {
		t.Fatalf("delete range: %v", res.StatusCode)
	}
	raw, err := h.ReadRaw(nodeID, time.Time{}, time.Time{}, 0, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	hd := raw.HistoryData.Value.(*ua.HistoryData)
	// Samples at t=0 and t=4 remain (deleted inclusive [1s, 3s]).
	if len(hd.DataValues) != 2 {
		t.Fatalf("remaining=%d, want 2", len(hd.DataValues))
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

	end := base.Add(5 * time.Second)
	for _, agg := range []uint32{id.AggregateFunctionMinimum, id.AggregateFunctionMaximum, id.AggregateFunctionCount} {
		res, err := h.ReadProcessed(nodeID, base, end, 5000, ua.NewNumericNodeID(0, agg), nil)
		if err != nil {
			t.Fatalf("agg %d: %v", agg, err)
		}
		if res.StatusCode != ua.StatusOK {
			t.Fatalf("agg %d status=%v", agg, res.StatusCode)
		}
		hd := res.HistoryData.Value.(*ua.HistoryData)
		if len(hd.DataValues) == 0 || hd.DataValues[0].Status != ua.StatusOK {
			t.Fatalf("agg %d empty/bad result", agg)
		}
	}

	if st, _ := h.ReadProcessed(nodeID, base, end, 1000, ua.NewNumericNodeID(0, 99999), nil); st.StatusCode != ua.StatusBadHistoryOperationUnsupported {
		t.Fatalf("unsupported agg: %v", st.StatusCode)
	}
	if st, _ := h.ReadProcessed(nodeID, end, base, 1000, ua.NewNumericNodeID(0, id.AggregateFunctionCount), nil); st.StatusCode != ua.StatusBadHistoryOperationInvalid {
		t.Fatalf("invalid window: %v", st.StatusCode)
	}
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
			reg.release(reg.bind(session, []byte("drop")))
		}()
	}
	wg.Wait()
	reg.releaseSession("session-0")
	reg.releaseSession("session-1")
	reg.releaseSession("session-2")
	reg.releaseSession("session-3")
}
