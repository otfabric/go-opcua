//go:build interop

// SPDX-License-Identifier: MIT

// Peer method argument validation tests (C→O / C→M).
// COVERAGE.md: methods / method.validation

package interop

import (
	"context"
	"strings"
	"testing"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
)

// TestOpen62541Server_MethodValidation calls Methods.Add with too few args and
// expects BadArgumentsMissing (or equivalent Bad status).
func TestOpen62541Server_MethodValidation(t *testing.T) {
	t.Run("coverage/method.validation/go-client-to-open62541-server", func(t *testing.T) {
		h := startOpen62541Server(t)
		c := dialClient(t, h.endpoint)
		ctx, nsIdx := findNS(t, c)
		assertMethodTooFewArgs(t, c, ctx, nsIdx)
	})
}

// TestMiloServer_MethodValidation calls Methods.Add with too few args and
// expects BadArgumentsMissing (or equivalent Bad status).
func TestMiloServer_MethodValidation(t *testing.T) {
	t.Run("coverage/method.validation/go-client-to-milo-server", func(t *testing.T) {
		h := startMiloServer(t)
		c := dialClient(t, h.endpoint)
		ctx, nsIdx := findNS(t, c)
		assertMethodTooFewArgs(t, c, ctx, nsIdx)
	})
}

func assertMethodTooFewArgs(t *testing.T, c *opcua.Client, ctx context.Context, nsIdx uint16) {
	t.Helper()
	objectID := ua.NewStringNodeID(nsIdx, "Methods")
	methodID := ua.NewStringNodeID(nsIdx, "Methods.Add")

	result, err := c.CallMethod(ctx, objectID, methodID) // zero input args
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "ArgumentsMissing") || strings.Contains(msg, "BadTooFewArguments") {
			return
		}
		t.Fatalf("CallMethod too-few-args: unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("CallMethod too-few-args: nil result")
	}
	sc := result.StatusCode
	if sc == ua.StatusBadArgumentsMissing {
		return
	}
	name := sc.Error()
	if strings.Contains(name, "ArgumentsMissing") || strings.Contains(name, "TooFewArguments") {
		return
	}
	// Severity bit 31 set ⇒ Bad (IEC 62541-4 StatusCode encoding).
	if sc != ua.StatusOK && uint32(sc)&0x80000000 != 0 {
		t.Logf("CallMethod too-few-args: got Bad status %v (accepted as validation failure)", sc)
		return
	}
	t.Fatalf("CallMethod too-few-args: status=%v, want BadArgumentsMissing (or Bad)", sc)
}
