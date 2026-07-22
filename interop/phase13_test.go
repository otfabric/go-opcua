//go:build interop

// SPDX-License-Identifier: MIT

package interop

import (
	"context"
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// collectDataChange waits for a DataChangeNotification whose MonitoredItems
// length is at least minItems.
func collectDataChange(t *testing.T, notifyCh <-chan *opcua.PublishNotificationData, minItems int, timeout time.Duration) *ua.DataChangeNotification {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case msg, ok := <-notifyCh:
			if !ok {
				t.Fatal("notify channel closed")
			}
			if msg.Error != nil {
				t.Fatalf("notification error: %v", msg.Error)
			}
			dcn, ok := msg.Value.(*ua.DataChangeNotification)
			if !ok || dcn == nil {
				continue
			}
			if len(dcn.MonitoredItems) >= minItems {
				return dcn
			}
		case <-deadline:
			t.Fatalf("timeout waiting for DataChange with >=%d items", minItems)
		}
	}
}

// collectHandleValues waits until a single DataChangeNotification carries at
// least minCount samples for the given ClientHandle.
func collectHandleValues(t *testing.T, notifyCh <-chan *opcua.PublishNotificationData, handle uint32, minCount int, timeout time.Duration) (*ua.DataChangeNotification, []int32) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case msg, ok := <-notifyCh:
			if !ok {
				t.Fatal("notify channel closed")
			}
			if msg.Error != nil {
				t.Fatalf("notification error: %v", msg.Error)
			}
			dcn, ok := msg.Value.(*ua.DataChangeNotification)
			if !ok || dcn == nil {
				continue
			}
			got := int32sFromDCN(dcn, handle)
			if len(got) >= minCount {
				return dcn, got
			}
		case <-deadline:
			t.Fatalf("timeout waiting for handle %d with >=%d values", handle, minCount)
		}
	}
}

func writeInt32(t *testing.T, c *opcua.Client, ctx context.Context, nodeID *ua.NodeID, v int32) {
	t.Helper()
	resp, err := c.Write(ctx, &ua.WriteRequest{
		NodesToWrite: []*ua.WriteValue{{
			NodeID: nodeID, AttributeID: ua.AttributeIDValue,
			Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)},
		}},
	})
	if err != nil {
		t.Fatalf("Write(%d): %v", v, err)
	}
	if len(resp.Results) == 0 || resp.Results[0] != ua.StatusOK {
		t.Fatalf("Write(%d) status: %v", v, resp.Results)
	}
}

func int32sFromDCN(dcn *ua.DataChangeNotification, handle uint32) []int32 {
	var out []int32
	for _, mi := range dcn.MonitoredItems {
		if mi.ClientHandle != handle {
			continue
		}
		if mi.Value == nil || mi.Value.Value == nil {
			continue
		}
		switch v := mi.Value.Value.Value().(type) {
		case int32:
			out = append(out, v)
		case int64:
			out = append(out, int32(v))
		}
	}
	return out
}

// drainInitial consumes the initial DataChange after CreateMonitoredItems.
func drainInitial(t *testing.T, notifyCh <-chan *opcua.PublishNotificationData) {
	t.Helper()
	_ = collectDataChange(t, notifyCh, 1, 10*time.Second)
}

func phase13Ctx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// TestGoServer_QueueExactWindow verifies Part 4 monitored-item queue windows
// with explicit writes 1..5 (Phase 13 workstream A).
func TestGoServer_QueueExactWindow(t *testing.T) {
	endpoint := startGoServer(t)

	cases := []struct {
		name          string
		queueSize     uint32
		discardOldest bool
		want          []int32
		wantOverflow  bool
	}{
		{"QueueSize1", 1, true, []int32{5}, false},
		{"DiscardOldestTrue", 3, true, []int32{3, 4, 5}, true},
		{"DiscardOldestFalse", 3, false, []int32{1, 2, 5}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Fresh client per case avoids publish-request contention across
			// rapid subscribe/cancel cycles on one session.
			c := dialClient(t, endpoint)
			_, nsIdx := findNS(t, c)
			ctx := phase13Ctx(t)
			nodeID := ua.NewStringNodeID(nsIdx, "Access.ReadWrite")

			req := opcua.NewMonitoredItemCreateRequestWithDefaults(nodeID, ua.AttributeIDValue, 7)
			req.RequestedParameters.QueueSize = tc.queueSize
			req.RequestedParameters.DiscardOldest = tc.discardOldest
			req.RequestedParameters.SamplingInterval = 0

			// Long interval: after the initial publish, all writes enqueue
			// before the next Publish (Part 4 exact-window driver).
			const pubInterval = 5 * time.Second
			notifyCh := make(chan *opcua.PublishNotificationData, 64)
			sub, _, err := c.NewSubscription().
				Interval(pubInterval).
				NotifyChannel(notifyCh).
				Timestamps(ua.TimestampsToReturnNeither).
				MonitorItems(req).
				Start(ctx)
			if err != nil {
				t.Fatalf("Subscribe: %v", err)
			}
			defer sub.Cancel(ctx) //nolint:errcheck

			drainInitial(t, notifyCh)
			// Right after a publish, the next tick is a full interval away.
			for _, v := range []int32{1, 2, 3, 4, 5} {
				writeInt32(t, c, ctx, nodeID, v)
			}

			dcn, got := collectHandleValues(t, notifyCh, 7, len(tc.want), pubInterval+3*time.Second)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
			if tc.wantOverflow {
				found := false
				for _, mi := range dcn.MonitoredItems {
					if mi.ClientHandle == 7 && mi.Value != nil && mi.Value.Status.HasOverflow() {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected Overflow InfoBit on at least one queued value")
				}
			}
		})
	}
}

// TestGoServer_QueueItemIsolation verifies overflow on one monitored item does
// not affect another (Phase 13 workstream B).
func TestGoServer_QueueItemIsolation(t *testing.T) {
	endpoint := startGoServer(t)
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx := phase13Ctx(t)
	nodeA := ua.NewStringNodeID(nsIdx, "Access.ReadWrite")
	nodeB := ua.NewStringNodeID(nsIdx, "Scalar.Int32")

	reqA := opcua.NewMonitoredItemCreateRequestWithDefaults(nodeA, ua.AttributeIDValue, 11)
	reqA.RequestedParameters.QueueSize = 3
	reqA.RequestedParameters.DiscardOldest = true
	reqA.RequestedParameters.SamplingInterval = 0

	reqB := opcua.NewMonitoredItemCreateRequestWithDefaults(nodeB, ua.AttributeIDValue, 22)
	reqB.RequestedParameters.QueueSize = 1
	reqB.RequestedParameters.DiscardOldest = true
	reqB.RequestedParameters.SamplingInterval = 0

	notifyCh := make(chan *opcua.PublishNotificationData, 64)
	sub, _, err := c.NewSubscription().
		Interval(2 * time.Second).
		NotifyChannel(notifyCh).
		Timestamps(ua.TimestampsToReturnNeither).
		MonitorItems(reqA, reqB).
		Start(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Cancel(ctx) //nolint:errcheck

	// Drain initials (may arrive as one or two publishes).
	deadline := time.After(6 * time.Second)
drainLoop:
	for {
		select {
		case msg := <-notifyCh:
			if msg.Error != nil {
				t.Fatalf("initial: %v", msg.Error)
			}
		case <-deadline:
			break drainLoop
		case <-time.After(500 * time.Millisecond):
			break drainLoop
		}
	}

	for _, v := range []int32{1, 2, 3, 4, 5} {
		writeInt32(t, c, ctx, nodeA, v)
	}
	writeInt32(t, c, ctx, nodeB, 42)

	// Collect until we see both handles.
	var gotA, gotB []int32
	deadline = time.After(8 * time.Second)
	for len(gotA) < 3 || len(gotB) < 1 {
		select {
		case msg := <-notifyCh:
			if msg.Error != nil {
				t.Fatalf("notif: %v", msg.Error)
			}
			dcn, ok := msg.Value.(*ua.DataChangeNotification)
			if !ok {
				continue
			}
			gotA = append(gotA, int32sFromDCN(dcn, 11)...)
			gotB = append(gotB, int32sFromDCN(dcn, 22)...)
		case <-deadline:
			t.Fatalf("timeout: A=%v B=%v", gotA, gotB)
		}
	}
	if len(gotA) != 3 || gotA[0] != 3 || gotA[1] != 4 || gotA[2] != 5 {
		t.Errorf("item A window: got %v, want [3 4 5]", gotA)
	}
	if len(gotB) != 1 || gotB[0] != 42 {
		t.Errorf("item B: got %v, want [42]", gotB)
	}
}

// TestGoServer_SubscribeTimestampsToReturn verifies DataChange EncodingMask
// honors TimestampsToReturn (Phase 13 workstream C).
func TestGoServer_SubscribeTimestampsToReturn(t *testing.T) {
	endpoint := startGoServer(t)

	cases := []struct {
		name       string
		ts         ua.TimestampsToReturn
		wantSrc    bool
		wantServer bool
		writeVal   int32
	}{
		{"Neither", ua.TimestampsToReturnNeither, false, false, 101},
		{"Source", ua.TimestampsToReturnSource, false, false, 102}, // no source stored on node → absent
		{"Server", ua.TimestampsToReturnServer, false, true, 103},
		{"Both", ua.TimestampsToReturnBoth, false, true, 104},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := dialClient(t, endpoint)
			_, nsIdx := findNS(t, c)
			ctx := phase13Ctx(t)
			nodeID := ua.NewStringNodeID(nsIdx, "Access.ReadWrite")

			req := opcua.NewMonitoredItemCreateRequestWithDefaults(nodeID, ua.AttributeIDValue, 1)
			req.RequestedParameters.QueueSize = 1
			notifyCh := make(chan *opcua.PublishNotificationData, 16)
			sub, _, err := c.NewSubscription().
				Interval(500 * time.Millisecond).
				NotifyChannel(notifyCh).
				Timestamps(tc.ts).
				MonitorItems(req).
				Start(ctx)
			if err != nil {
				t.Fatalf("Subscribe: %v", err)
			}
			defer sub.Cancel(ctx) //nolint:errcheck

			dcn := collectDataChange(t, notifyCh, 1, 5*time.Second)
			dv := dcn.MonitoredItems[0].Value
			hasSrc := dv.EncodingMask&ua.DataValueSourceTimestamp != 0
			hasSrv := dv.EncodingMask&ua.DataValueServerTimestamp != 0
			if hasSrc != tc.wantSrc {
				t.Errorf("source timestamp present=%v, want %v (mask=%#x)", hasSrc, tc.wantSrc, dv.EncodingMask)
			}
			if hasSrv != tc.wantServer {
				t.Errorf("server timestamp present=%v, want %v (mask=%#x)", hasSrv, tc.wantServer, dv.EncodingMask)
			}

			writeInt32(t, c, ctx, nodeID, tc.writeVal)
			dcn2 := collectDataChange(t, notifyCh, 1, 5*time.Second)
			dv2 := dcn2.MonitoredItems[0].Value
			hasSrv2 := dv2.EncodingMask&ua.DataValueServerTimestamp != 0
			if hasSrv2 != tc.wantServer {
				t.Errorf("subsequent server timestamp present=%v, want %v", hasSrv2, tc.wantServer)
			}
		})
	}
}

// TestGoServer_MatrixIndexRangeRead verifies multidimensional NumericRange Read
// on Array.Matrix2D (Phase 13 workstream D).
func TestGoServer_MatrixIndexRangeRead(t *testing.T) {
	endpoint := startGoServer(t)
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx := phase13Ctx(t)
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
// atomic failure (Phase 13 workstream E).
func TestGoServer_MatrixIndexRangeWrite(t *testing.T) {
	endpoint := startGoServer(t)
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx := phase13Ctx(t)
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

// TestGoServer_IndexRangeHardening covers Phase 13 workstream F items for 1D
// IndexRange atomicity, partial overlap, ByteString, and bad-read timestamps.
func TestGoServer_IndexRangeHardening(t *testing.T) {
	endpoint := startGoServer(t)
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx := phase13Ctx(t)

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
// combined mask (Phase 13 workstream F).
func TestGoServer_BrowseResultMaskBits(t *testing.T) {
	endpoint := startGoServer(t)
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx := phase13Ctx(t)
	objectsID := ua.NewNumericNodeID(nsIdx, id.ObjectsFolder)

	browse := func(mask ua.BrowseResultMask) []*ua.ReferenceDescription {
		resp, err := c.Browse(ctx, &ua.BrowseRequest{
			NodesToBrowse: []*ua.BrowseDescription{{
				NodeID: objectsID, BrowseDirection: ua.BrowseDirectionForward,
				ReferenceTypeID: ua.NewNumericNodeID(0, id.HierarchicalReferences),
				IncludeSubtypes: true, ResultMask: uint32(mask),
			}},
		})
		if err != nil {
			t.Fatalf("Browse: %v", err)
		}
		return resp.Results[0].References
	}

	t.Run("BrowseNameOnly", func(t *testing.T) {
		refs := browse(ua.BrowseResultMaskBrowseName)
		if len(refs) == 0 {
			t.Fatal("no refs")
		}
		r := refs[0]
		if r.BrowseName == nil || r.BrowseName.Name == "" {
			t.Error("BrowseName missing")
		}
		if r.DisplayName != nil && r.DisplayName.Text != "" {
			t.Error("DisplayName should be cleared")
		}
		if r.NodeClass != 0 {
			t.Error("NodeClass should be zero")
		}
	})

	t.Run("NodeClassOnly", func(t *testing.T) {
		refs := browse(ua.BrowseResultMaskNodeClass)
		if len(refs) == 0 {
			t.Fatal("no refs")
		}
		if refs[0].NodeClass == 0 {
			t.Error("NodeClass missing")
		}
		if refs[0].BrowseName != nil && refs[0].BrowseName.Name != "" {
			t.Error("BrowseName should be cleared")
		}
	})

	t.Run("CombinedBrowseNameNodeClass", func(t *testing.T) {
		refs := browse(ua.BrowseResultMaskBrowseName | ua.BrowseResultMaskNodeClass)
		if len(refs) == 0 {
			t.Fatal("no refs")
		}
		r := refs[0]
		if r.BrowseName == nil || r.BrowseName.Name == "" {
			t.Error("BrowseName missing")
		}
		if r.NodeClass == 0 {
			t.Error("NodeClass missing")
		}
		if r.DisplayName != nil && r.DisplayName.Text != "" {
			t.Error("DisplayName should be cleared")
		}
	})
}
