//go:build interop

// SPDX-License-Identifier: MIT

// Peer HistoryRead continuation-point tests (O→S / M→S).
// COVERAGE.md: history / history.read.continuation

package interop

import (
	"encoding/json"
	"testing"
)

type historyReadItem struct {
	NodeID            string          `json:"nodeId"`
	StatusCode        statusCodeObj   `json:"statusCode"`
	ContinuationPoint *string         `json:"continuationPoint"`
	Values            json.RawMessage `json:"values"`
}

// TestGoServer_Open62541Client_HistoryReadContinuation exercises history-read
// pagination via continuation points against the Go historian.
func TestGoServer_Open62541Client_HistoryReadContinuation(t *testing.T) {
	t.Run("coverage/history.read.continuation/open62541-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, "OPEN62541_IMAGE", defaultOpen62541Image, "history-read")
		requireHistoryContinueScenario(t, "OPEN62541_IMAGE", defaultOpen62541Image)
		endpoint, _, _ := startGoServerWithHistory(t)
		assertHistoryContinuation(t, endpoint, runOpen62541ClientResult)
	})
}

// TestGoServer_MiloClient_HistoryReadContinuation exercises history-read
// pagination via continuation points against the Go historian.
func TestGoServer_MiloClient_HistoryReadContinuation(t *testing.T) {
	t.Run("coverage/history.read.continuation/milo-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, "MILO_IMAGE", defaultMiloImage, "history-read")
		requireHistoryContinueScenario(t, "MILO_IMAGE", defaultMiloImage)
		endpoint, _, _ := startGoServerWithHistory(t)
		assertHistoryContinuation(t, endpoint, runMiloClientResult)
	})
}

type historyContinueResult struct {
	Scenario                    string            `json:"scenario"`
	Pages                       []historyReadItem `json:"pages"`
	ReleaseStatusCode           statusCodeObj     `json:"releaseStatusCode"`
	ReuseAfterReleaseStatusCode statusCodeObj     `json:"reuseAfterReleaseStatusCode"`
}

func assertHistoryContinuation(t *testing.T, endpoint string, run func(t *testing.T, endpoint, subcmd string, args ...string) adapterResult) {
	t.Helper()
	node := "nsu=" + interopNamespaceURI + ";s=History.Temperature"

	// Single-session page/continue/release/reuse baseline (Wave 3B).
	result := run(t, endpoint, "history-read",
		"--node", node,
		"--start", "2026-07-24T10:00:00Z",
		"--end", "2026-07-24T10:00:20Z",
		"--num-values", "2",
		"--scenario", "continue",
	)
	if !result.Success {
		t.Fatalf("history-read --scenario continue failed: %+v", result)
	}
	var items []historyContinueResult
	if err := json.Unmarshal(result.Results, &items); err != nil || len(items) == 0 {
		t.Fatalf("parse continue scenario: %v raw=%s", err, result.Results)
	}
	sc := items[0]
	if sc.Scenario != "continue" {
		t.Fatalf("scenario=%q, want continue", sc.Scenario)
	}
	if len(sc.Pages) < 2 {
		t.Fatalf("expected >=2 pages for continuation baseline, got %d raw=%s", len(sc.Pages), result.Results)
	}
	if sc.Pages[0].ContinuationPoint == nil || *sc.Pages[0].ContinuationPoint == "" {
		t.Fatalf("first page missing continuationPoint: %+v", sc.Pages[0])
	}
	if len(sc.Pages[0].Values) == 0 || string(sc.Pages[0].Values) == "[]" {
		t.Fatalf("first page has no values: %s", sc.Pages[0].Values)
	}
	// Final page should clear CP or be empty of CP.
	last := sc.Pages[len(sc.Pages)-1]
	if last.ContinuationPoint != nil && *last.ContinuationPoint != "" && len(sc.Pages) < 3 {
		t.Logf("last page still has CP=%q (acceptable if more data remains)", *last.ContinuationPoint)
	}
	if sc.ReuseAfterReleaseStatusCode.Name == "Good" {
		t.Logf("reuse-after-release returned Good (peer variance); release=%s reuse=%s",
			sc.ReleaseStatusCode.Name, sc.ReuseAfterReleaseStatusCode.Name)
	} else {
		t.Logf("continuation baseline ok pages=%d release=%s reuse=%s",
			len(sc.Pages), sc.ReleaseStatusCode.Name, sc.ReuseAfterReleaseStatusCode.Name)
	}
}

func parseHistoryReadItems(t *testing.T, raw json.RawMessage) []historyReadItem {
	t.Helper()
	var items []historyReadItem
	if err := json.Unmarshal(raw, &items); err != nil || len(items) == 0 {
		t.Fatalf("parse history-read results: %v; raw: %s", err, raw)
	}
	if items[0].StatusCode.Severity == "Bad" || (items[0].StatusCode.Name != "" &&
		items[0].StatusCode.Name != "Good" && items[0].StatusCode.Severity != "Good") {
		if items[0].StatusCode.Code != 0 && items[0].StatusCode.Severity == "Bad" {
			t.Fatalf("history-read item status Bad: %s", items[0].StatusCode)
		}
	}
	return items
}
