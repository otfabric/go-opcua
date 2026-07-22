//go:build interop

// SPDX-License-Identifier: MIT

package interop

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
)

// startGoServerWithHistory starts a Go server with a historizing node and pre-recorded samples.
func startGoServerWithHistory(t *testing.T) (string, *server.Server, *server.Historian) {
	t.Helper()

	port := freePort(t)

	s, err := server.New(
		server.ListenOn(fmt.Sprintf("0.0.0.0:%d", port)),
		server.EndPoint("host.docker.internal", port),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
	)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	ns := server.NewNodeNameSpace(s, interopNamespaceURI)
	s.AddNamespace(ns)
	objs := ns.Objects()
	nsIdx := ns.ID()

	// Historized node.
	histNodeID := ua.NewStringNodeID(nsIdx, "History.Temperature")
	histNode := server.NewNode(
		histNodeID,
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:       server.DataValueFromValue(uint32(ua.NodeClassVariable)),
			ua.AttributeIDBrowseName:      server.DataValueFromValue(attrs.BrowseName("History.Temperature")),
			ua.AttributeIDDisplayName:     server.DataValueFromValue(attrs.DisplayName("Temperature (Historical)", "en")),
			ua.AttributeIDAccessLevel:     server.DataValueFromValue(uint8(ua.AccessLevelTypeCurrentRead | ua.AccessLevelTypeHistoryRead)),
			ua.AttributeIDUserAccessLevel: server.DataValueFromValue(uint8(ua.AccessLevelTypeCurrentRead | ua.AccessLevelTypeHistoryRead)),
			ua.AttributeIDValueRank:       server.DataValueFromValue(int32(-1)),
			ua.AttributeIDHistorizing:     server.DataValueFromValue(true),
		},
		nil,
		func() *ua.DataValue {
			return &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(float64(22.5))}
		},
	)
	ns.AddNode(histNode)
	objs.AddRef(histNode, server.RefTypeIDHasComponent, true)

	// Non-historized node.
	addVar := func(name string, val interface{}) {
		n := ns.AddNewVariableStringNode(name, val)
		objs.AddRef(n, server.RefTypeIDHasComponent, true)
	}
	addVar("Access.ReadWrite", int32(42))

	// Set up historian.
	hist := server.NewHistorian()
	hist.EnableNode(histNodeID, 500)
	s.SetHistorian(hist)

	// Pre-record 20 samples at 1-second intervals.
	baseTime := time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 20; i++ {
		ts := baseTime.Add(time.Duration(i) * time.Second)
		dv := &ua.DataValue{
			EncodingMask:    ua.DataValueValue | ua.DataValueSourceTimestamp | ua.DataValueServerTimestamp,
			Value:           ua.MustVariant(float64(20.0) + float64(i)*0.5),
			SourceTimestamp: ts,
			ServerTimestamp: ts,
		}
		hist.RecordValue(histNodeID, dv)
	}

	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("server.Start: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	return fmt.Sprintf("opc.tcp://localhost:%d", port), s, hist
}

// TestGoServer_HistoryReadRaw verifies basic HistoryRead with ReadRawModifiedDetails (Phase 17).
func TestGoServer_HistoryReadRaw(t *testing.T) {
	endpoint, _, _ := startGoServerWithHistory(t)
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	histNodeID := ua.NewStringNodeID(nsIdx, "History.Temperature")
	startTime := time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)
	endTime := time.Date(2026, 7, 24, 10, 0, 10, 0, time.UTC) // first 10 seconds → 10 samples

	details := &ua.ReadRawModifiedDetails{
		IsReadModified:   false,
		StartTime:        startTime,
		EndTime:          endTime,
		NumValuesPerNode: 0, // unlimited
		ReturnBounds:     false,
	}

	var resp *ua.HistoryReadResponse
	err := c.Send(ctx, &ua.HistoryReadRequest{
		HistoryReadDetails:        ua.NewExtensionObject(details),
		TimestampsToReturn:        ua.TimestampsToReturnBoth,
		ReleaseContinuationPoints: false,
		NodesToRead: []*ua.HistoryReadValueID{{
			NodeID: histNodeID,
		}},
	}, func(r ua.Response) error {
		resp = r.(*ua.HistoryReadResponse)
		return nil
	})
	if err != nil {
		t.Fatalf("HistoryRead: %v", err)
	}

	if len(resp.Results) != 1 {
		t.Fatalf("results len=%d", len(resp.Results))
	}
	result := resp.Results[0]
	if result.StatusCode != ua.StatusOK {
		t.Fatalf("result status=%v", result.StatusCode)
	}

	if result.HistoryData == nil || result.HistoryData.Value == nil {
		t.Fatal("no HistoryData in result")
	}
	hd, ok := result.HistoryData.Value.(*ua.HistoryData)
	if !ok {
		t.Fatalf("HistoryData type=%T", result.HistoryData.Value)
	}
	if len(hd.DataValues) < 10 {
		t.Fatalf("expected >=10 samples, got %d", len(hd.DataValues))
	}

	// Verify first sample value.
	first := hd.DataValues[0]
	if v, ok := first.Value.Value().(float64); !ok || v != 20.0 {
		t.Errorf("first value=%v, want 20.0", first.Value.Value())
	}
}

// TestGoServer_HistoryReadWithContinuation verifies continuation point pagination (Phase 17).
func TestGoServer_HistoryReadWithContinuation(t *testing.T) {
	endpoint, _, _ := startGoServerWithHistory(t)
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	histNodeID := ua.NewStringNodeID(nsIdx, "History.Temperature")
	startTime := time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)
	endTime := time.Date(2026, 7, 24, 10, 0, 20, 0, time.UTC) // all 20 samples

	details := &ua.ReadRawModifiedDetails{
		IsReadModified:   false,
		StartTime:        startTime,
		EndTime:          endTime,
		NumValuesPerNode: 5, // request only 5 at a time
		ReturnBounds:     false,
	}

	var allValues []*ua.DataValue
	var continuationPoint []byte

	for {
		var resp *ua.HistoryReadResponse
		err := c.Send(ctx, &ua.HistoryReadRequest{
			HistoryReadDetails:        ua.NewExtensionObject(details),
			TimestampsToReturn:        ua.TimestampsToReturnBoth,
			ReleaseContinuationPoints: false,
			NodesToRead: []*ua.HistoryReadValueID{{
				NodeID:            histNodeID,
				ContinuationPoint: continuationPoint,
			}},
		}, func(r ua.Response) error {
			resp = r.(*ua.HistoryReadResponse)
			return nil
		})
		if err != nil {
			t.Fatalf("HistoryRead: %v", err)
		}

		result := resp.Results[0]
		if result.StatusCode != ua.StatusOK {
			t.Fatalf("result status=%v on iteration", result.StatusCode)
		}

		if result.HistoryData != nil && result.HistoryData.Value != nil {
			if hd, ok := result.HistoryData.Value.(*ua.HistoryData); ok {
				allValues = append(allValues, hd.DataValues...)
			}
		}

		continuationPoint = result.ContinuationPoint
		if len(continuationPoint) == 0 {
			break
		}
		if len(allValues) > 50 {
			t.Fatal("too many iterations, possible infinite loop")
		}
	}

	if len(allValues) < 20 {
		t.Fatalf("expected 20 samples via continuation, got %d", len(allValues))
	}
	t.Logf("collected %d historical values via continuation points", len(allValues))
}

// TestGoServer_HistoryReadModifiedRejected verifies IsReadModified=true is rejected (Phase 17).
func TestGoServer_HistoryReadModifiedRejected(t *testing.T) {
	endpoint, _, _ := startGoServerWithHistory(t)
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	histNodeID := ua.NewStringNodeID(nsIdx, "History.Temperature")

	details := &ua.ReadRawModifiedDetails{
		IsReadModified:   true,
		StartTime:        time.Now().Add(-1 * time.Hour),
		EndTime:          time.Now(),
		NumValuesPerNode: 10,
	}

	var resp *ua.HistoryReadResponse
	err := c.Send(ctx, &ua.HistoryReadRequest{
		HistoryReadDetails:        ua.NewExtensionObject(details),
		TimestampsToReturn:        ua.TimestampsToReturnBoth,
		ReleaseContinuationPoints: false,
		NodesToRead: []*ua.HistoryReadValueID{{
			NodeID: histNodeID,
		}},
	}, func(r ua.Response) error {
		resp = r.(*ua.HistoryReadResponse)
		return nil
	})
	if err != nil {
		t.Fatalf("HistoryRead: %v", err)
	}

	if resp.Results[0].StatusCode != ua.StatusBadHistoryOperationInvalid {
		t.Fatalf("status=%v, want BadHistoryOperationInvalid", resp.Results[0].StatusCode)
	}
}

// TestGoServer_HistoryReadNonHistorizedNode verifies that reading history from a
// non-historized node returns BadHistoryOperationUnsupported (Phase 17).
func TestGoServer_HistoryReadNonHistorizedNode(t *testing.T) {
	endpoint, _, _ := startGoServerWithHistory(t)
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Access.ReadWrite is not historized.
	nodeID := ua.NewStringNodeID(nsIdx, "Access.ReadWrite")

	details := &ua.ReadRawModifiedDetails{
		IsReadModified:   false,
		StartTime:        time.Now().Add(-1 * time.Hour),
		EndTime:          time.Now(),
		NumValuesPerNode: 10,
	}

	var resp *ua.HistoryReadResponse
	err := c.Send(ctx, &ua.HistoryReadRequest{
		HistoryReadDetails:        ua.NewExtensionObject(details),
		TimestampsToReturn:        ua.TimestampsToReturnBoth,
		ReleaseContinuationPoints: false,
		NodesToRead: []*ua.HistoryReadValueID{{
			NodeID: nodeID,
		}},
	}, func(r ua.Response) error {
		resp = r.(*ua.HistoryReadResponse)
		return nil
	})
	if err != nil {
		t.Fatalf("HistoryRead: %v", err)
	}

	if resp.Results[0].StatusCode != ua.StatusBadHistoryOperationUnsupported {
		t.Fatalf("status=%v, want BadHistoryOperationUnsupported", resp.Results[0].StatusCode)
	}
}

// TestGoServer_HistoryRecordAndRead verifies recording new samples and immediately reading them back (Phase 17).
func TestGoServer_HistoryRecordAndRead(t *testing.T) {
	endpoint, _, hist := startGoServerWithHistory(t)
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	histNodeID := ua.NewStringNodeID(nsIdx, "History.Temperature")

	// Record additional samples after the pre-loaded ones.
	newBase := time.Date(2026, 7, 24, 11, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		ts := newBase.Add(time.Duration(i) * time.Second)
		dv := &ua.DataValue{
			EncodingMask:    ua.DataValueValue | ua.DataValueSourceTimestamp,
			Value:           ua.MustVariant(float64(100.0) + float64(i)),
			SourceTimestamp: ts,
		}
		hist.RecordValue(histNodeID, dv)
	}

	// Read only the new samples.
	details := &ua.ReadRawModifiedDetails{
		IsReadModified:   false,
		StartTime:        newBase,
		EndTime:          newBase.Add(10 * time.Second),
		NumValuesPerNode: 0,
	}

	var resp *ua.HistoryReadResponse
	err := c.Send(ctx, &ua.HistoryReadRequest{
		HistoryReadDetails:        ua.NewExtensionObject(details),
		TimestampsToReturn:        ua.TimestampsToReturnSource,
		ReleaseContinuationPoints: false,
		NodesToRead: []*ua.HistoryReadValueID{{
			NodeID: histNodeID,
		}},
	}, func(r ua.Response) error {
		resp = r.(*ua.HistoryReadResponse)
		return nil
	})
	if err != nil {
		t.Fatalf("HistoryRead: %v", err)
	}

	result := resp.Results[0]
	if result.StatusCode != ua.StatusOK {
		t.Fatalf("status=%v", result.StatusCode)
	}

	hd, ok := result.HistoryData.Value.(*ua.HistoryData)
	if !ok || hd == nil {
		t.Fatal("no HistoryData")
	}
	if len(hd.DataValues) != 5 {
		t.Fatalf("expected 5 new samples, got %d", len(hd.DataValues))
	}
	// Verify first new value.
	if v, ok := hd.DataValues[0].Value.Value().(float64); !ok || v != 100.0 {
		t.Errorf("first new value=%v, want 100.0", hd.DataValues[0].Value.Value())
	}
}
