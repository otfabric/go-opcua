//go:build interop

// SPDX-License-Identifier: MIT

// Peer HistoryRead raw tests (O→S / M→S).
// COVERAGE.md: history / history.read.raw

package interop

import "testing"

func TestGoServer_Open62541Client_HistoryReadRaw(t *testing.T) {
	t.Run("coverage/history.raw/open62541-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, "OPEN62541_IMAGE", defaultOpen62541Image, "history-read")
		endpoint, _, _ := startGoServerWithHistory(t)
		node := "nsu=" + interopNamespaceURI + ";s=History.Temperature"
		result := runOpen62541ClientResult(t, endpoint, "history-read",
			"--node", node,
			"--start", "2026-07-24T10:00:00Z",
			"--end", "2026-07-24T10:00:20Z",
			"--num-values", "5",
		)
		if !result.Success {
			t.Fatalf("history-read failed: %+v", result)
		}
	})
}

func TestGoServer_MiloClient_HistoryReadRaw(t *testing.T) {
	t.Run("coverage/history.raw/milo-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, "MILO_IMAGE", defaultMiloImage, "history-read")
		endpoint, _, _ := startGoServerWithHistory(t)
		node := "nsu=" + interopNamespaceURI + ";s=History.Temperature"
		result := runMiloClientResult(t, endpoint, "history-read",
			"--node", node,
			"--start", "2026-07-24T10:00:00Z",
			"--end", "2026-07-24T10:00:20Z",
			"--num-values", "5",
		)
		if !result.Success {
			t.Fatalf("history-read failed: %+v", result)
		}
	})
}
