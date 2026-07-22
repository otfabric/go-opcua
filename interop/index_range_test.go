//go:build interop

// SPDX-License-Identifier: MIT

// Go↔Go IndexRange / NumericRange edge companions.
// COVERAGE.md: attribute / read.index-range

package interop

import (
	"testing"

	"github.com/otfabric/go-opcua/ua"
)

// TestGoServer_MatrixIndexRangeRead verifies multidimensional NumericRange Read
// on Array.Matrix2D.
func TestGoServer_MatrixIndexRangeRead(t *testing.T) {
	endpoint := startGoServer(t)
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx := shortTestCtx(t)
	nodeID := ua.NewStringNodeID(nsIdx, "Array.Matrix2D")

	cases := []struct {
		name   string
		range_ string
		check  func(t *testing.T, dv *ua.DataValue)
	}{
		{"Cell", "0,0", func(t *testing.T, dv *ua.DataValue) {
			if dv.Status != ua.StatusOK {
				t.Fatalf("status %v", dv.Status)
			}
			switch v := dv.Value.Value().(type) {
			case float64:
				if v != 1.1 {
					t.Errorf("got %v, want 1.1", v)
				}
			case [][]float64:
				if len(v) != 1 || len(v[0]) != 1 || v[0][0] != 1.1 {
					t.Errorf("got %v, want [[1.1]]", v)
				}
			default:
				t.Fatalf("unexpected type %T", v)
			}
		}},
		{"Rect", "0:1,0:1", func(t *testing.T, dv *ua.DataValue) {
			if dv.Status != ua.StatusOK {
				t.Fatalf("status %v", dv.Status)
			}
			got, ok := dv.Value.Value().([][]float64)
			if !ok {
				t.Fatalf("type %T", dv.Value.Value())
			}
			want := [][]float64{{1.1, 2.2}, {3.3, 4.4}}
			if len(got) != 2 || len(got[0]) != 2 || got[0][0] != want[0][0] || got[1][1] != want[1][1] {
				t.Errorf("got %v, want %v", got, want)
			}
		}},
		{"Row", "1,0:1", func(t *testing.T, dv *ua.DataValue) {
			if dv.Status != ua.StatusOK {
				t.Fatalf("status %v", dv.Status)
			}
			got, ok := dv.Value.Value().([][]float64)
			if !ok {
				// may be 1D row
				if row, ok := dv.Value.Value().([]float64); ok {
					if len(row) != 2 || row[0] != 3.3 || row[1] != 4.4 {
						t.Errorf("got %v", row)
					}
					return
				}
				t.Fatalf("type %T", dv.Value.Value())
			}
			if len(got) != 1 || len(got[0]) != 2 || got[0][0] != 3.3 {
				t.Errorf("got %v", got)
			}
		}},
		{"TooManyDims", "0:1,0:1,0", func(t *testing.T, dv *ua.DataValue) {
			if dv.Status != ua.StatusBadIndexRangeInvalid {
				t.Errorf("got %v, want BadIndexRangeInvalid", dv.Status)
			}
		}},
		{"OneDimOnMatrix", "0:1", func(t *testing.T, dv *ua.DataValue) {
			if dv.Status != ua.StatusBadIndexRangeInvalid {
				t.Errorf("got %v, want BadIndexRangeInvalid", dv.Status)
			}
		}},
		{"OutOfRange", "10:11,0:1", func(t *testing.T, dv *ua.DataValue) {
			if dv.Status != ua.StatusBadIndexRangeNoData {
				t.Errorf("got %v, want BadIndexRangeNoData", dv.Status)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := c.Read(ctx, &ua.ReadRequest{
				TimestampsToReturn: ua.TimestampsToReturnNeither,
				NodesToRead: []*ua.ReadValueID{{
					NodeID: nodeID, AttributeID: ua.AttributeIDValue, IndexRange: tc.range_,
				}},
			})
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			tc.check(t, resp.Results[0])
		})
	}
}

// TestGoServer_MatrixIndexRangeWrite verifies matrix IndexRange Write and
// atomic failure.

// TestGoServer_MatrixIndexRangeWrite verifies matrix IndexRange Write and
// atomic failure.
func TestGoServer_MatrixIndexRangeWrite(t *testing.T) {
	endpoint := startGoServer(t)
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx := shortTestCtx(t)
	nodeID := ua.NewStringNodeID(nsIdx, "Array.Matrix2D")

	readFull := func() [][]float64 {
		resp, err := c.Read(ctx, &ua.ReadRequest{
			TimestampsToReturn: ua.TimestampsToReturnNeither,
			NodesToRead:        []*ua.ReadValueID{{NodeID: nodeID, AttributeID: ua.AttributeIDValue}},
		})
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		got, ok := resp.Results[0].Value.Value().([][]float64)
		if !ok {
			t.Fatalf("type %T", resp.Results[0].Value.Value())
		}
		return got
	}

	t.Run("RectReplace", func(t *testing.T) {
		before := readFull()
		w, err := c.Write(ctx, &ua.WriteRequest{
			NodesToWrite: []*ua.WriteValue{{
				NodeID: nodeID, AttributeID: ua.AttributeIDValue, IndexRange: "0:1,0:1",
				Value: &ua.DataValue{
					EncodingMask: ua.DataValueValue,
					Value:        ua.MustVariant([][]float64{{9.1, 9.2}, {9.3, 9.4}}),
				},
			}},
		})
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		if w.Results[0] != ua.StatusOK {
			t.Fatalf("Write status: %v", w.Results[0])
		}
		after := readFull()
		if after[0][0] != 9.1 || after[1][1] != 9.4 {
			t.Errorf("after write: %v", after)
		}
		if after[2][0] != before[2][0] {
			t.Errorf("unrelated cell changed: %v vs %v", after[2], before[2])
		}
	})

	t.Run("ShapeMismatchAtomic", func(t *testing.T) {
		before := readFull()
		w, err := c.Write(ctx, &ua.WriteRequest{
			NodesToWrite: []*ua.WriteValue{{
				NodeID: nodeID, AttributeID: ua.AttributeIDValue, IndexRange: "0:1,0:1",
				Value: &ua.DataValue{
					EncodingMask: ua.DataValueValue,
					Value:        ua.MustVariant([][]float64{{1.0}}), // wrong shape
				},
			}},
		})
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		if w.Results[0] != ua.StatusBadIndexRangeDataMismatch {
			t.Errorf("got %v, want BadIndexRangeDataMismatch", w.Results[0])
		}
		after := readFull()
		if after[0][0] != before[0][0] || after[1][1] != before[1][1] {
			t.Errorf("matrix mutated on failed write: before=%v after=%v", before, after)
		}
	})
}

// TestGoServer_IndexRangeHardening covers 1D
// IndexRange atomicity, partial overlap, ByteString, and bad-read timestamps.

// TestGoServer_IndexRangeHardening covers 1D
// IndexRange atomicity, partial overlap, ByteString, and bad-read timestamps.
func TestGoServer_IndexRangeHardening(t *testing.T) {
	endpoint := startGoServer(t)
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx := shortTestCtx(t)

	t.Run("FailedWriteAtomic", func(t *testing.T) {
		nodeID := ua.NewStringNodeID(nsIdx, "Array.Int32")
		before, err := c.Read(ctx, &ua.ReadRequest{
			TimestampsToReturn: ua.TimestampsToReturnNeither,
			NodesToRead:        []*ua.ReadValueID{{NodeID: nodeID, AttributeID: ua.AttributeIDValue}},
		})
		if err != nil {
			t.Fatal(err)
		}
		want := before.Results[0].Value.Value().([]int32)
		w, err := c.Write(ctx, &ua.WriteRequest{
			NodesToWrite: []*ua.WriteValue{{
				NodeID: nodeID, AttributeID: ua.AttributeIDValue, IndexRange: "0:1",
				Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant([]int32{1})},
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if w.Results[0] != ua.StatusBadIndexRangeDataMismatch {
			t.Fatalf("got %v", w.Results[0])
		}
		after, err := c.Read(ctx, &ua.ReadRequest{
			TimestampsToReturn: ua.TimestampsToReturnNeither,
			NodesToRead:        []*ua.ReadValueID{{NodeID: nodeID, AttributeID: ua.AttributeIDValue}},
		})
		if err != nil {
			t.Fatal(err)
		}
		got := after.Results[0].Value.Value().([]int32)
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("array mutated: before=%v after=%v", want, got)
			}
		}
	})

	t.Run("PartialOverlap", func(t *testing.T) {
		nodeID := ua.NewStringNodeID(nsIdx, "Array.Int32")
		// Read clips.
		r, err := c.Read(ctx, &ua.ReadRequest{
			TimestampsToReturn: ua.TimestampsToReturnNeither,
			NodesToRead: []*ua.ReadValueID{{
				NodeID: nodeID, AttributeID: ua.AttributeIDValue, IndexRange: "4:100",
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if r.Results[0].Status != ua.StatusOK {
			t.Fatalf("Read clip status %v", r.Results[0].Status)
		}
		got := r.Results[0].Value.Value().([]int32)
		if len(got) != 2 { // indices 4,5 of 6-element array
			t.Errorf("Read clip len=%d want 2: %v", len(got), got)
		}
		// Write rejects.
		w, err := c.Write(ctx, &ua.WriteRequest{
			NodesToWrite: []*ua.WriteValue{{
				NodeID: nodeID, AttributeID: ua.AttributeIDValue, IndexRange: "4:100",
				Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant([]int32{1, 2})},
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if w.Results[0] != ua.StatusBadIndexRangeNoData {
			t.Errorf("Write partial: got %v, want BadIndexRangeNoData", w.Results[0])
		}
	})

	t.Run("ByteStringIndexRange", func(t *testing.T) {
		nodeID := ua.NewStringNodeID(nsIdx, "Scalar.ByteString")
		r, err := c.Read(ctx, &ua.ReadRequest{
			TimestampsToReturn: ua.TimestampsToReturnNeither,
			NodesToRead: []*ua.ReadValueID{{
				NodeID: nodeID, AttributeID: ua.AttributeIDValue, IndexRange: "0:4",
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if r.Results[0].Status != ua.StatusOK {
			t.Fatalf("ByteString IndexRange status %v", r.Results[0].Status)
		}
		bs, ok := r.Results[0].Value.Value().([]byte)
		if !ok {
			t.Fatalf("type %T", r.Results[0].Value.Value())
		}
		if string(bs) != "opcua" {
			t.Errorf("got %q, want opcua", bs)
		}
	})

	t.Run("BadReadNoFabricatedTimestamps", func(t *testing.T) {
		nodeID := ua.NewStringNodeID(nsIdx, "Scalar.Int32")
		r, err := c.Read(ctx, &ua.ReadRequest{
			TimestampsToReturn: ua.TimestampsToReturnNeither,
			NodesToRead: []*ua.ReadValueID{{
				NodeID: nodeID, AttributeID: ua.AttributeIDValue, IndexRange: "0:1",
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		dv := r.Results[0]
		if dv.Status != ua.StatusBadIndexRangeInvalid {
			t.Fatalf("status %v", dv.Status)
		}
		if dv.EncodingMask&ua.DataValueSourceTimestamp != 0 || dv.EncodingMask&ua.DataValueServerTimestamp != 0 {
			t.Errorf("fabricated timestamps on error: mask=%#x", dv.EncodingMask)
		}
	})
}

// TestGoServer_BrowseResultMaskBits verifies each ResultMask field bit and a
// combined mask.
