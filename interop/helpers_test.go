//go:build interop

// SPDX-License-Identifier: MIT

// Shared helpers for Go↔Go and peer capability companions.
// Not ledger evidence by itself — used by tests that map to COVERAGE.md rows.

package interop

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/server"
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

func shortTestCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// requireCapabilities reports whether missing adapter ops must fail the test.
// Set OPCUA_INTEROP_REQUIRE_CAPABILITIES=1 for release verification runs against
// pinned images so skips cannot greenwash missing client operations.
func requireCapabilities() bool {
	v := strings.TrimSpace(os.Getenv("OPCUA_INTEROP_REQUIRE_CAPABILITIES"))
	return v == "1" || strings.EqualFold(v, "true")
}

// requireAdapterOp skips (or fails when REQUIRE_CAPABILITIES=1) when the pinned
// adapter image lacks a client operation.
func requireAdapterOp(t *testing.T, imageEnv, defaultImage, op string) {
	t.Helper()
	image := getEnvOr(imageEnv, defaultImage)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", image, "print-capabilities")
	raw, err := cmd.Output()
	if err != nil {
		if requireCapabilities() {
			t.Fatalf("print-capabilities failed for %s: %v", image, err)
		}
		t.Skipf("print-capabilities failed for %s: %v", image, err)
	}
	var caps struct {
		ClientOperations []string `json:"clientOperations"`
		Adapter          struct {
			Version string `json:"version"`
		} `json:"adapter"`
	}
	if err := json.Unmarshal(raw, &caps); err != nil {
		lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
		if len(lines) == 0 || json.Unmarshal([]byte(lines[len(lines)-1]), &caps) != nil {
			if requireCapabilities() {
				t.Fatalf("cannot parse capabilities from %s: %v\nraw: %s", image, err, raw)
			}
			t.Skipf("cannot parse capabilities from %s: %v\nraw: %s", image, err, raw)
		}
	}
	for _, o := range caps.ClientOperations {
		if o == op {
			return
		}
	}
	msg := "adapter " + image + " (version " + caps.Adapter.Version +
		") lacks client op " + op + "; need opcua-interop v0.5.0 client ops"
	if requireCapabilities() {
		t.Fatal(msg)
	}
	t.Skipf("%s", msg)
}

// findNSFromServer returns the interop namespace URI and index from a running Go server.
func findNSFromServer(t *testing.T, srv *server.Server) (string, uint16) {
	t.Helper()
	for i := 0; i < 16; i++ {
		ns, err := srv.Namespace(i)
		if err != nil {
			continue
		}
		if ns.Name() == interopNamespaceURI {
			return interopNamespaceURI, uint16(i)
		}
	}
	t.Fatalf("interop namespace %q not found", interopNamespaceURI)
	return "", 0
}
