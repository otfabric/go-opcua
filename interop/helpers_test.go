//go:build interop

// SPDX-License-Identifier: MIT

// Shared helpers for Go↔Go and peer capability companions.
// Not ledger evidence by itself — used by tests that map to COVERAGE.md rows.

package interop

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
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

// requirePeerNode skips (or fails when REQUIRE_CAPABILITIES=1) when the peer
// address space lacks a fixture node required for the capability under test.
func requirePeerNode(t *testing.T, endpoint, browseName string) {
	t.Helper()
	c := dialClient(t, endpoint)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, nsIdx := findNS(t, c)
	nodeID := ua.NewStringNodeID(nsIdx, browseName)
	_, err := c.ReadValue(ctx, nodeID)
	if err == nil {
		return
	}
	msg := "peer missing fixture node " + browseName + ": " + err.Error()
	if requireCapabilities() {
		t.Fatal(msg)
	}
	t.Skipf("%s", msg)
}

// requireHistoryContinueScenario skips (or fails when REQUIRE_CAPABILITIES=1)
// when history-read does not advertise the single-session continue scenario.
func requireHistoryContinueScenario(t *testing.T, imageEnv, defaultImage string) {
	t.Helper()
	image := getEnvOr(imageEnv, defaultImage)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Missing required flags → adapters emit usage that includes [--scenario continue]
	// once Wave 3B is present (published v0.6.0 pins).
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", image, "client", "history-read")
	raw, _ := cmd.CombinedOutput()
	out := string(raw)
	if strings.Contains(out, "--scenario continue") || strings.Contains(out, "scenario continue") {
		return
	}
	msg := "adapter " + image + " lacks history-read --scenario continue"
	if requireCapabilities() {
		t.Fatal(msg + "\n" + out)
	}
	t.Skipf("%s", msg)
}

// adapterCaps is the part of an adapter's print-capabilities output the suite
// gates on (opcua-interop client contract §13).
type adapterCaps struct {
	Adapter struct {
		Version string `json:"version"`
	} `json:"adapter"`
	ClientOperations []string `json:"clientOperations"`
	ClientFeatures   []string `json:"clientFeatures"`
	ServerFeatures   []string `json:"serverFeatures"`
	SecurityProfiles []struct {
		Policy string `json:"policy"`
		Mode   string `json:"mode"`
	} `json:"securityProfiles"`
}

var (
	adapterCapsMu    sync.Mutex
	adapterCapsCache = map[string]*adapterCaps{}
)

// capabilityUnavailable skips the test, or fails it when
// OPCUA_INTEROP_REQUIRE_CAPABILITIES=1: a release verification run (CI) must
// not turn green because the image under test predates a feature the suite
// has evidence rows for.
func capabilityUnavailable(t *testing.T, format string, args ...any) {
	t.Helper()
	msg := fmt.Sprintf(format, args...)
	if requireCapabilities() {
		t.Fatal(msg)
	}
	t.Skip(msg)
}

// imageCapabilities returns the print-capabilities output of the adapter
// image selected by imageEnv (cached per image).
func imageCapabilities(t *testing.T, imageEnv, defaultImage string) (*adapterCaps, string) {
	t.Helper()
	image := getEnvOr(imageEnv, defaultImage)
	adapterCapsMu.Lock()
	defer adapterCapsMu.Unlock()
	if c, ok := adapterCapsCache[image]; ok {
		return c, image
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	raw, err := exec.CommandContext(ctx, "docker", "run", "--rm", image, "print-capabilities").Output()
	if err != nil {
		capabilityUnavailable(t, "print-capabilities failed for %s: %v", image, err)
	}
	caps := &adapterCaps{}
	if err := json.Unmarshal(raw, caps); err != nil {
		lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
		if len(lines) == 0 || json.Unmarshal([]byte(lines[len(lines)-1]), caps) != nil {
			capabilityUnavailable(t, "cannot parse capabilities from %s: %v\nraw: %s", image, err, raw)
		}
	}
	adapterCapsCache[image] = caps
	return caps, image
}

// requirePinnedVersion fails a capability-gated test when the image in use is
// the default pin (no OPEN62541_IMAGE / MILO_IMAGE override) and that pin is
// not the opcua-interop release the suite and the ledger are written against.
// Skipping would let `make interop` pass against a stale pin while
// coverage.json claims evidence for the newer release.
func requirePinnedVersion(t *testing.T, imageEnv string, caps *adapterCaps, image string) {
	t.Helper()
	if os.Getenv(imageEnv) != "" || "v"+caps.Adapter.Version == interopVersion {
		return
	}
	t.Fatalf("the default image %s is opcua-interop v%s, but this suite and interop/coverage.json are written against %s: "+
		"re-pin the default images (harness_test.go, .github/workflows/interop.yml) or set %s to a %s image",
		image, caps.Adapter.Version, interopVersion, imageEnv, interopVersion)
}

// requireAdapterOp skips (or fails when REQUIRE_CAPABILITIES=1) when the
// adapter image lacks a client operation.
func requireAdapterOp(t *testing.T, imageEnv, defaultImage, op string) {
	t.Helper()
	caps, image := imageCapabilities(t, imageEnv, defaultImage)
	requirePinnedVersion(t, imageEnv, caps, image)
	if slices.Contains(caps.ClientOperations, op) {
		return
	}
	capabilityUnavailable(t, "adapter %s (version %s) lacks client op %s; need opcua-interop %s",
		image, caps.Adapter.Version, op, interopVersion)
}

// requireAdapterFeature skips (or fails when REQUIRE_CAPABILITIES=1) when the
// adapter image does not advertise feature in the given print-capabilities
// list ("serverFeatures" or "clientFeatures"). Once the feature is
// advertised, everything that goes wrong in the test fails it.
func requireAdapterFeature(t *testing.T, imageEnv, defaultImage, list, feature string) {
	t.Helper()
	caps, image := imageCapabilities(t, imageEnv, defaultImage)
	requirePinnedVersion(t, imageEnv, caps, image)
	var have []string
	switch list {
	case "clientFeatures":
		have = caps.ClientFeatures
	case "serverFeatures":
		have = caps.ServerFeatures
	default:
		t.Fatalf("requireAdapterFeature: unknown capability list %q", list)
	}
	if slices.Contains(have, feature) {
		return
	}
	capabilityUnavailable(t, "adapter %s (version %s) does not advertise %s %q (has %v); need opcua-interop %s",
		image, caps.Adapter.Version, list, feature, have, interopVersion)
}

// requireAdapterClientFeature gates on a clientFeatures entry.
func requireAdapterClientFeature(t *testing.T, imageEnv, defaultImage, feature string) {
	t.Helper()
	requireAdapterFeature(t, imageEnv, defaultImage, "clientFeatures", feature)
}

// requireServerFeature gates on serverFeatures entries.
func requireServerFeature(t *testing.T, imageEnv, defaultImage string, features ...string) {
	t.Helper()
	for _, f := range features {
		requireAdapterFeature(t, imageEnv, defaultImage, "serverFeatures", f)
	}
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
