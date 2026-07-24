// SPDX-License-Identifier: MIT

package server

import (
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
