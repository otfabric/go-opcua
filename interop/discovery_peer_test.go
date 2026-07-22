//go:build interop

// SPDX-License-Identifier: MIT

// Peer FindServers discovery tests (C→O / C→M / O→S / M→S).
// COVERAGE.md: discovery / discovery.find-servers

package interop

import (
	"encoding/json"
	"testing"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
)

// TestOpen62541Server_FindServers verifies FindServers against an open62541
// peer returns at least one ApplicationDescription with a non-empty
// ApplicationURI or ProductURI.
func TestOpen62541Server_FindServers(t *testing.T) {
	t.Run("coverage/discovery.find-servers/go-client-to-open62541-server", func(t *testing.T) {
		h := startOpen62541Server(t)
		ctx := shortTestCtx(t)
		servers, err := opcua.FindServers(ctx, h.endpoint)
		if err != nil {
			t.Fatalf("FindServers: %v", err)
		}
		assertFindServersResult(t, servers)
	})
}

// TestMiloServer_FindServers verifies FindServers against a Milo peer returns
// at least one ApplicationDescription with a non-empty ApplicationURI or ProductURI.
func TestMiloServer_FindServers(t *testing.T) {
	t.Run("coverage/discovery.find-servers/go-client-to-milo-server", func(t *testing.T) {
		h := startMiloServer(t)
		ctx := shortTestCtx(t)
		servers, err := opcua.FindServers(ctx, h.endpoint)
		if err != nil {
			t.Fatalf("FindServers: %v", err)
		}
		assertFindServersResult(t, servers)
	})
}

func assertFindServersResult(t *testing.T, servers []*ua.ApplicationDescription) {
	t.Helper()
	if len(servers) == 0 {
		t.Fatal("FindServers returned no ApplicationDescription")
	}
	for i, s := range servers {
		if s == nil {
			continue
		}
		if s.ApplicationURI != "" || s.ProductURI != "" {
			t.Logf("FindServers[%d]: ApplicationURI=%q ProductURI=%q", i, s.ApplicationURI, s.ProductURI)
			return
		}
	}
	t.Fatalf("FindServers: no ApplicationDescription with non-empty ApplicationURI or ProductURI; got %d entries", len(servers))
}

// TestGoServer_Open62541Client_FindServers runs the open62541 adapter
// find-servers command against an in-process go-opcua server.
func TestGoServer_Open62541Client_FindServers(t *testing.T) {
	t.Run("coverage/discovery.find-servers/open62541-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, "OPEN62541_IMAGE", defaultOpen62541Image, "find-servers")
		endpoint := startGoServer(t)
		result := runOpen62541Client(t, endpoint, "find-servers")
		assertAdapterFindServers(t, result)
	})
}

// TestGoServer_MiloClient_FindServers runs the Milo adapter find-servers
// command against an in-process go-opcua server.
func TestGoServer_MiloClient_FindServers(t *testing.T) {
	t.Run("coverage/discovery.find-servers/milo-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, "MILO_IMAGE", defaultMiloImage, "find-servers")
		endpoint := startGoServer(t)
		result := runMiloClient(t, endpoint, "find-servers")
		assertAdapterFindServers(t, result)
	})
}

func assertAdapterFindServers(t *testing.T, result adapterResult) {
	t.Helper()
	if result.Operation != "find-servers" {
		t.Errorf("operation: got %q, want %q", result.Operation, "find-servers")
	}
	if !result.Success {
		t.Fatalf("find-servers failed: serviceResult=%s error=%v", result.ServiceResult, result.Error)
	}
	if len(result.Results) == 0 || string(result.Results) == "null" || string(result.Results) == "[]" {
		t.Fatal("find-servers: expected non-empty results array")
	}
	var apps []struct {
		ApplicationURI  string   `json:"applicationUri"`
		ProductURI      string   `json:"productUri"`
		DiscoveryURLs   []string `json:"discoveryUrls"`
		ApplicationName struct {
			Locale string `json:"locale"`
			Text   string `json:"text"`
		} `json:"applicationName"`
	}
	if err := json.Unmarshal(result.Results, &apps); err != nil {
		t.Fatalf("unmarshal find-servers results: %v\nraw: %s", err, result.Results)
	}
	for i, app := range apps {
		if app.ApplicationURI != "" || app.ProductURI != "" {
			t.Logf("find-servers[%d]: applicationUri=%q productUri=%q discoveryUrls=%v name=%q",
				i, app.ApplicationURI, app.ProductURI, app.DiscoveryURLs, app.ApplicationName.Text)
			return
		}
	}
	t.Fatalf("find-servers: no ApplicationDescription with non-empty applicationUri or productUri; got %d entries: %s",
		len(apps), result.Results)
}
