//go:build interop

// SPDX-License-Identifier: MIT

// Peer HistoryRead raw tests (C→O / C→M) against gate-compliant reference historians.
// COVERAGE.md: history / history.read.raw

package interop

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
)

func assertPeerHistoryRaw(t *testing.T, endpoint string) {
	t.Helper()
	c := dialClient(t, endpoint)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, nsIdx := findNS(t, c)
	node := ua.NewStringNodeID(nsIdx, "History.Temperature")

	resp, err := c.HistoryReadRawModified(ctx, []*ua.HistoryReadValueID{{NodeID: node}}, &ua.ReadRawModifiedDetails{
		IsReadModified:   false,
		StartTime:        time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC),
		EndTime:          time.Date(2026, 7, 24, 10, 0, 20, 0, time.UTC),
		NumValuesPerNode: 5,
	})
	if err != nil {
		t.Fatalf("HistoryReadRawModified: %v", err)
	}
	if resp.ResponseHeader != nil && resp.ResponseHeader.ServiceResult != ua.StatusOK {
		t.Fatalf("serviceResult=%v", resp.ResponseHeader.ServiceResult)
	}
	if len(resp.Results) == 0 {
		t.Fatal("empty HistoryRead results")
	}
	if resp.Results[0].StatusCode != ua.StatusOK {
		t.Fatalf("item status=%v", resp.Results[0].StatusCode)
	}
	if resp.Results[0].HistoryData == nil || resp.Results[0].HistoryData.Value == nil {
		t.Fatalf("expected HistoryData, got %#v", resp.Results[0].HistoryData)
	}
	hd, ok := resp.Results[0].HistoryData.Value.(*ua.HistoryData)
	if !ok || hd == nil || len(hd.DataValues) == 0 {
		t.Fatalf("expected HistoryData values, got %#v", resp.Results[0].HistoryData)
	}
	t.Logf("history raw values=%d first=%v", len(hd.DataValues), hd.DataValues[0].Value)
}

func TestMiloServer_HistoryReadRaw(t *testing.T) {
	t.Run("coverage/history.read.raw/go-client-to-milo-server", func(t *testing.T) {
		h := startMiloServer(t)
		requirePeerNode(t, h.endpoint, "History.Temperature")
		assertPeerHistoryRaw(t, h.endpoint)
	})
}

func TestOpen62541Server_HistoryReadRaw(t *testing.T) {
	t.Run("coverage/history.read.raw/go-client-to-open62541-server", func(t *testing.T) {
		h := startOpen62541Server(t)
		requirePeerNode(t, h.endpoint, "History.Temperature")
		assertPeerHistoryRaw(t, h.endpoint)
	})
}
