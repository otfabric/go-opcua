//go:build interop

// SPDX-License-Identifier: MIT

// Server diagnostics of the go-opcua server, read by the peer clients
// (peer client → go-opcua server) and by the go-opcua client in process.
package interop

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testhook"
	"github.com/otfabric/go-opcua/ua"
)

// diagnosticsReadNodes are the scalar diagnostics variables a peer client
// reads: EnabledFlag, CurrentSessionCount and CumulatedSessionCount of
// Server.ServerDiagnostics.ServerDiagnosticsSummary.
var diagnosticsReadNodes = []uint32{
	id.ServerServerDiagnosticsEnabledFlag,
	id.ServerServerDiagnosticsServerDiagnosticsSummaryCurrentSessionCount,
	id.ServerServerDiagnosticsServerDiagnosticsSummaryCumulatedSessionCount,
}

// diagnosticsReadResult is one result of the adapter read command.
type diagnosticsReadResult struct {
	NodeID     string          `json:"nodeId"`
	StatusCode statusCodeObj   `json:"statusCode"`
	DataType   string          `json:"dataType"`
	Value      json.RawMessage `json:"value"`
}

// diagnosticsUint parses an unsigned integer value of the adapter output,
// which some adapters quote.
func diagnosticsUint(raw json.RawMessage) (uint64, error) {
	return strconv.ParseUint(strings.Trim(strings.TrimSpace(string(raw)), `"`), 10, 32)
}

// assertGoServerDiagnosticsFromPeer has the peer client read the server
// diagnostics of a go-opcua server: EnabledFlag is true and the summary
// counts the peer's own session. The server then holds a diagnostics object
// for every session it keeps, and the peer's session is in its cumulated
// count.
func assertGoServerDiagnosticsFromPeer(t *testing.T, imageEnv, defaultImage string, run func(*testing.T, string, string, ...string) adapterResult) {
	t.Helper()
	requireAdapterOp(t, imageEnv, defaultImage, "read")
	endpoint, srv := startGoServerWithOptions(t)
	args := []string{}
	for _, n := range diagnosticsReadNodes {
		args = append(args, "--node", fmt.Sprintf("i=%d", n))
	}
	result := run(t, endpoint, "read", args...)
	if !result.Success {
		t.Fatalf("read diagnostics: serviceResult=%s error=%s", result.ServiceResult, result.Error)
	}
	var items []diagnosticsReadResult
	if err := json.Unmarshal(result.Results, &items); err != nil || len(items) != len(diagnosticsReadNodes) {
		t.Fatalf("read diagnostics: %d results (%v): %s", len(items), err, result.Results)
	}
	for i, it := range items {
		if !statusCodeIs(it.StatusCode, ua.StatusOK) {
			t.Fatalf("read %s (i=%d): %s", it.NodeID, diagnosticsReadNodes[i], it.StatusCode)
		}
	}
	if v := strings.TrimSpace(string(items[0].Value)); v != "true" {
		t.Errorf("EnabledFlag = %s, want true", v)
	}
	current, err := diagnosticsUint(items[1].Value)
	if err != nil {
		t.Fatalf("CurrentSessionCount %s: %v", items[1].Value, err)
	}
	cumulated, err := diagnosticsUint(items[2].Value)
	if err != nil {
		t.Fatalf("CumulatedSessionCount %s: %v", items[2].Value, err)
	}
	if current < 1 || cumulated < current {
		t.Errorf("the peer read %d current / %d cumulated sessions with its own session open", current, cumulated)
	}
	t.Logf("peer read EnabledFlag=%s CurrentSessionCount=%d CumulatedSessionCount=%d", items[0].Value, current, cumulated)

	sum := srv.ServerDiagnosticsSummary()
	if sum.CumulatedSessionCount < uint32(cumulated) {
		t.Errorf("server CumulatedSessionCount %d < %d the peer read", sum.CumulatedSessionCount, cumulated)
	}
	// Whether the peer closed its session or left it to time out, every
	// session the server keeps has its diagnostics object and no other.
	deadline := time.Now().Add(10 * time.Second)
	for {
		res := testhook.ServerResourcesOf(srv)
		if res.DiagnosticsSessionObjects == res.Sessions {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d sessions but %d diagnostics objects", res.Sessions, res.DiagnosticsSessionObjects)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestGoServer_Open62541Client_Diagnostics(t *testing.T) {
	t.Run("coverage/diagnostics.server-summary/open62541-client-to-go-server", func(t *testing.T) {
		assertGoServerDiagnosticsFromPeer(t, "OPEN62541_IMAGE", defaultOpen62541Image, runOpen62541ClientResult)
	})
}

func TestGoServer_MiloClient_Diagnostics(t *testing.T) {
	t.Run("coverage/diagnostics.server-summary/milo-client-to-go-server", func(t *testing.T) {
		assertGoServerDiagnosticsFromPeer(t, "MILO_IMAGE", defaultMiloImage, runMiloClientResult)
	})
}

// TestGoServer_GoClient_Diagnostics runs the assertions the go-opcua client
// makes against the peer servers (assertPeerServerDiagnostics,
// assertPeerReturnDiagnostics) against the go-opcua server, in process: no
// Docker. The go-opcua server must pass every one of them without a skip.
func TestGoServer_GoClient_Diagnostics(t *testing.T) {
	endpoint := startGoServer(t)
	for name, f := range map[string]func(*testing.T, string){
		"server-summary":     assertPeerServerDiagnostics,
		"return-diagnostics": assertPeerReturnDiagnostics,
	} {
		t.Run(name, func(t *testing.T) {
			done := false
			defer func() {
				if !done && t.Skipped() {
					t.Errorf("the go-opcua server skipped %s", name)
				}
			}()
			f(t, endpoint)
			done = true
		})
	}
}
