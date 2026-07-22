// SPDX-License-Identifier: MIT

package server

import (
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
)

func TestHistorian_EnableAndRecord(t *testing.T) {
	h := NewHistorian()
	nodeID := ua.NewStringNodeID(2, "Test.Temp")

	h.EnableNode(nodeID, 10)
	if !h.IsEnabled(nodeID) {
		t.Fatal("node should be enabled")
	}
	if h.IsEnabled(ua.NewStringNodeID(2, "Other")) {
		t.Fatal("other node should not be enabled")
	}

	// Record samples.
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 15; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		dv := &ua.DataValue{
			EncodingMask:    ua.DataValueValue | ua.DataValueSourceTimestamp,
			Value:           ua.MustVariant(float64(i)),
			SourceTimestamp: ts,
		}
		h.RecordValue(nodeID, dv)
	}

	// Max 10 → oldest 5 should be evicted.
	result, err := h.ReadRaw(nodeID, base, base.Add(20*time.Second), 0, false, nil)
	if err != nil {
		t.Fatalf("ReadRaw: %v", err)
	}
	if result.StatusCode != ua.StatusOK {
		t.Fatalf("status=%v", result.StatusCode)
	}
	hd := result.HistoryData.Value.(*ua.HistoryData)
	if len(hd.DataValues) != 10 {
		t.Fatalf("values=%d, want 10 (max capacity)", len(hd.DataValues))
	}
	// First remaining should be sample 5.
	if v := hd.DataValues[0].Value.Value().(float64); v != 5.0 {
		t.Errorf("first value=%v, want 5.0", v)
	}
}

func TestHistorian_ReadRawTimeRange(t *testing.T) {
	h := NewHistorian()
	nodeID := ua.NewStringNodeID(2, "Test.Sensor")
	h.EnableNode(nodeID, 100)

	base := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 20; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		dv := &ua.DataValue{
			EncodingMask:    ua.DataValueValue | ua.DataValueSourceTimestamp,
			Value:           ua.MustVariant(float64(i)),
			SourceTimestamp: ts,
		}
		h.RecordValue(nodeID, dv)
	}

	// Read [5s, 10s) → samples 5,6,7,8,9.
	start := base.Add(5 * time.Second)
	end := base.Add(10 * time.Second)
	result, err := h.ReadRaw(nodeID, start, end, 0, false, nil)
	if err != nil {
		t.Fatalf("ReadRaw: %v", err)
	}
	hd := result.HistoryData.Value.(*ua.HistoryData)
	if len(hd.DataValues) != 5 {
		t.Fatalf("values=%d, want 5", len(hd.DataValues))
	}
	if v := hd.DataValues[0].Value.Value().(float64); v != 5.0 {
		t.Errorf("first=%v, want 5.0", v)
	}
	if v := hd.DataValues[4].Value.Value().(float64); v != 9.0 {
		t.Errorf("last=%v, want 9.0", v)
	}
}

func TestHistorian_ContinuationPoint(t *testing.T) {
	h := NewHistorian()
	nodeID := ua.NewStringNodeID(2, "Test.Paged")
	h.EnableNode(nodeID, 100)

	base := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		dv := &ua.DataValue{
			EncodingMask:    ua.DataValueValue | ua.DataValueSourceTimestamp,
			Value:           ua.MustVariant(float64(i)),
			SourceTimestamp: ts,
		}
		h.RecordValue(nodeID, dv)
	}

	// Read 3 at a time.
	var all []*ua.DataValue
	var cp []byte
	for {
		result, err := h.ReadRaw(nodeID, base, base.Add(20*time.Second), 3, false, cp)
		if err != nil {
			t.Fatalf("ReadRaw: %v", err)
		}
		if result.StatusCode != ua.StatusOK {
			t.Fatalf("status=%v", result.StatusCode)
		}
		hd := result.HistoryData.Value.(*ua.HistoryData)
		all = append(all, hd.DataValues...)
		cp = result.ContinuationPoint
		if len(cp) == 0 {
			break
		}
		if len(all) > 20 {
			t.Fatal("infinite loop")
		}
	}
	if len(all) != 10 {
		t.Fatalf("total=%d, want 10", len(all))
	}
}

func TestHistorian_InvalidContinuationPoint(t *testing.T) {
	h := NewHistorian()
	nodeID := ua.NewStringNodeID(2, "Test.X")
	h.EnableNode(nodeID, 100)

	result, err := h.ReadRaw(nodeID, time.Time{}, time.Time{}, 0, false, []byte("bogus"))
	if err != nil {
		t.Fatalf("ReadRaw: %v", err)
	}
	if result.StatusCode != ua.StatusBadContinuationPointInvalid {
		t.Fatalf("status=%v, want BadContinuationPointInvalid", result.StatusCode)
	}
}

func TestHistorian_NonEnabledNode(t *testing.T) {
	h := NewHistorian()
	nodeID := ua.NewStringNodeID(2, "NotEnabled")

	result, err := h.ReadRaw(nodeID, time.Time{}, time.Time{}, 0, false, nil)
	if err != nil {
		t.Fatalf("ReadRaw: %v", err)
	}
	if result.StatusCode != ua.StatusBadHistoryOperationUnsupported {
		t.Fatalf("status=%v, want BadHistoryOperationUnsupported", result.StatusCode)
	}
}

func TestHistorian_RecordOnNonEnabled(t *testing.T) {
	h := NewHistorian()
	nodeID := ua.NewStringNodeID(2, "Ghost")

	// Should be no-op, not panic.
	h.RecordValue(nodeID, &ua.DataValue{
		EncodingMask: ua.DataValueValue,
		Value:        ua.MustVariant(float64(1.0)),
	})
}

func TestHistorian_ReleaseContinuation(t *testing.T) {
	h := NewHistorian()
	nodeID := ua.NewStringNodeID(2, "Test.Release")
	h.EnableNode(nodeID, 100)

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		h.RecordValue(nodeID, &ua.DataValue{
			EncodingMask:    ua.DataValueValue | ua.DataValueSourceTimestamp,
			Value:           ua.MustVariant(float64(i)),
			SourceTimestamp: ts,
		})
	}

	// Get a continuation point.
	result, _ := h.ReadRaw(nodeID, base, base.Add(20*time.Second), 3, false, nil)
	cp := result.ContinuationPoint
	if len(cp) == 0 {
		t.Fatal("expected continuation point")
	}

	// Release it.
	h.ReleaseContinuation(cp)

	// Using released CP should fail.
	result2, _ := h.ReadRaw(nodeID, base, base.Add(20*time.Second), 0, false, cp)
	if result2.StatusCode != ua.StatusBadContinuationPointInvalid {
		t.Fatalf("status=%v after release", result2.StatusCode)
	}
}
