//go:build interop

// SPDX-License-Identifier: MIT

// Peer TranslateBrowsePathsToNodeIDs tests (C→O / C→M / O→S / M→S).
// COVERAGE.md: views / translate.browse-path

package interop

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/otfabric/go-opcua/id"
)

// TestOpen62541Server_TranslateBrowsePath resolves Objects→Server via
// NodeFromPath against an open62541 peer.
func TestOpen62541Server_TranslateBrowsePath(t *testing.T) {
	t.Run("coverage/translate.browse-path/go-client-to-open62541-server", func(t *testing.T) {
		h := startOpen62541Server(t)
		c := dialClient(t, h.endpoint)
		ctx := shortTestCtx(t)
		node, err := c.NodeFromPath(ctx, "Server")
		if err != nil {
			t.Fatalf("NodeFromPath(Server): %v", err)
		}
		if node == nil || node.ID == nil {
			t.Fatal("NodeFromPath(Server): nil NodeID")
		}
		t.Logf("TranslateBrowsePath Server → %s", node.ID)
	})
}

// TestMiloServer_TranslateBrowsePath resolves Objects→Server via NodeFromPath
// against a Milo peer.
func TestMiloServer_TranslateBrowsePath(t *testing.T) {
	t.Run("coverage/translate.browse-path/go-client-to-milo-server", func(t *testing.T) {
		h := startMiloServer(t)
		c := dialClient(t, h.endpoint)
		ctx := shortTestCtx(t)
		node, err := c.NodeFromPath(ctx, "Server")
		if err != nil {
			t.Fatalf("NodeFromPath(Server): %v", err)
		}
		if node == nil || node.ID == nil {
			t.Fatal("NodeFromPath(Server): nil NodeID")
		}
		t.Logf("TranslateBrowsePath Server → %s", node.ID)
	})
}

// TestGoServer_Open62541Client_TranslateBrowsePath runs the open62541 adapter
// translate command against an in-process go-opcua server (Objects → Server).
func TestGoServer_Open62541Client_TranslateBrowsePath(t *testing.T) {
	t.Run("coverage/translate.browse-path/open62541-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, "OPEN62541_IMAGE", defaultOpen62541Image, "translate")
		endpoint := startGoServer(t)
		result := runOpen62541Client(t, endpoint, "translate",
			"--starting-node", "i=85",
			"--path", "Server",
		)
		assertAdapterTranslateServer(t, result)
	})
}

// TestGoServer_MiloClient_TranslateBrowsePath runs the Milo adapter translate
// command against an in-process go-opcua server (Objects → Server).
func TestGoServer_MiloClient_TranslateBrowsePath(t *testing.T) {
	t.Run("coverage/translate.browse-path/milo-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, "MILO_IMAGE", defaultMiloImage, "translate")
		endpoint := startGoServer(t)
		result := runMiloClient(t, endpoint, "translate",
			"--starting-node", "i=85",
			"--path", "Server",
		)
		assertAdapterTranslateServer(t, result)
	})
}

func assertAdapterTranslateServer(t *testing.T, result adapterResult) {
	t.Helper()
	if result.Operation != "translate" {
		t.Errorf("operation: got %q, want %q", result.Operation, "translate")
	}
	if !result.Success {
		t.Fatalf("translate failed: serviceResult=%s error=%v results=%s",
			result.ServiceResult, result.Error, result.Results)
	}
	var items []struct {
		StatusCode struct {
			Name string `json:"name"`
		} `json:"statusCode"`
		Targets []string `json:"targets"`
	}
	if err := json.Unmarshal(result.Results, &items); err != nil {
		t.Fatalf("unmarshal translate results: %v\nraw: %s", err, result.Results)
	}
	if len(items) == 0 {
		t.Fatal("translate: expected at least one result item")
	}
	if items[0].StatusCode.Name != "Good" {
		t.Fatalf("translate path statusCode: got %q, want Good", items[0].StatusCode.Name)
	}
	want := "i=" + strconv.FormatUint(uint64(id.Server), 10)
	found := false
	for _, target := range items[0].Targets {
		if target == want || strings.HasSuffix(target, ";i="+strconv.FormatUint(uint64(id.Server), 10)) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("translate: expected target %s, got %v", want, items[0].Targets)
	}
	t.Logf("translate Server → %v", items[0].Targets)
}
