//go:build interop

// SPDX-License-Identifier: MIT

// This commit against opcua-interop-otfabric, the image of an earlier go-opcua
// release (own/go-opcua of otfabric/opcua-interop), in both roles.
//
//	OPCUA_INTEROP_OTFABRIC_IMAGE   the image; these tests skip when it is unset
//
//	OPCUA_INTEROP_OTFABRIC_IMAGE=ghcr.io/otfabric/opcua-interop-otfabric:latest \
//	    go test -tags=interop -run Otfabric ./interop/
//
// The e2e tests run both sides from one commit; these find a change on the wire
// that breaks an earlier release. A pass is not independent verification, so
// there are no ledger rows: see INTEROP.md. They cover what the image declares,
// and a test of an operation the image no longer declares fails.

package interop

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
)

const otfabricEnv = "OPCUA_INTEROP_OTFABRIC_IMAGE"

// otfabricSecurity are the secured profiles the image declares and the test PKI
// supports.
var otfabricSecurity = []struct{ policy, mode string }{
	{"Basic256Sha256", "Sign"},
	{"Basic256Sha256", "SignAndEncrypt"},
	{"Aes128_Sha256_RsaOaep", "SignAndEncrypt"},
	{"Aes256_Sha256_RsaPss", "SignAndEncrypt"},
}

// requireOtfabric skips without the variable, also with
// OPCUA_INTEROP_REQUIRE_CAPABILITIES=1: this is no peer of a release.
func requireOtfabric(t *testing.T) {
	t.Helper()
	if os.Getenv(otfabricEnv) == "" {
		t.Skip(otfabricEnv + " is not set")
	}
}

func startOtfabricServer(t *testing.T) *serverHandle {
	t.Helper()
	requireOtfabric(t)
	return startAdapterServer(t, otfabricEnv, "")
}

func runOtfabricClient(t *testing.T, endpoint, subcmd string, args ...string) adapterResult {
	t.Helper()
	requireOtfabric(t)
	result := runAdapterClient(t, otfabricEnv, "", endpoint, subcmd, args...)
	if !result.Success {
		t.Fatalf("%s failed: %s error=%s", subcmd, result.ServiceResult, result.Error)
	}
	return result
}

// TestOtfabric_Capabilities checks that the image declares the core these tests
// cover, and that it says it is not independent.
func TestOtfabric_Capabilities(t *testing.T) {
	requireOtfabric(t)
	image := os.Getenv(otfabricEnv)
	raw, err := printCapabilities(image)
	if err != nil {
		t.Fatalf("print-capabilities: %v", err)
	}
	var caps struct {
		ClientOperations []string `json:"clientOperations"`
		Upstream         struct {
			Name              string `json:"name"`
			Version           string `json:"version"`
			Revision          string `json:"revision"`
			IndependentEngine *bool  `json:"independentEngine"`
		} `json:"upstream"`
	}
	if err := json.Unmarshal(raw, &caps); err != nil {
		t.Fatalf("parse capabilities: %v; raw: %s", err, raw)
	}
	for _, op := range []string{"endpoints", "read", "write", "browse", "call", "subscribe"} {
		if !slices.Contains(caps.ClientOperations, op) {
			t.Errorf("clientOperations %v lacks %s", caps.ClientOperations, op)
		}
	}
	if caps.Upstream.IndependentEngine == nil || *caps.Upstream.IndependentEngine {
		t.Errorf("upstream.independentEngine: want false, raw: %s", raw)
	}
	t.Logf("image %s has %s %s at %s", image, caps.Upstream.Name, caps.Upstream.Version, caps.Upstream.Revision)
}

// ---------------------------------------------------------------------------
// this commit's client → the image's server
// ---------------------------------------------------------------------------

func TestOtfabricServer_Endpoints(t *testing.T) {
	h := startOtfabricServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), clientTimeout)
	defer cancel()
	eps, err := opcua.GetEndpoints(ctx, h.endpoint)
	if err != nil {
		t.Fatalf("GetEndpoints: %v", err)
	}
	if len(eps) == 0 {
		t.Fatal("no endpoints")
	}
}

func TestOtfabricServer_Browse(t *testing.T) {
	h := startOtfabricServer(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)
	refs, err := c.Node(ua.NewStringNodeID(nsIdx, "Methods")).References(ctx,
		33, // HierarchicalReferences
		ua.BrowseDirectionForward,
		ua.NodeClassAll,
		true,
	)
	if err != nil {
		t.Fatalf("Browse Methods: %v", err)
	}
	var names []string
	for _, r := range refs {
		names = append(names, r.BrowseName.Name)
	}
	if !slices.Contains(names, "Methods.Add") {
		t.Errorf("Methods has %v, want Methods.Add", names)
	}
}

func TestOtfabricServer_Read(t *testing.T) {
	h := startOtfabricServer(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)
	for _, tc := range []struct {
		node string
		want any
	}{
		{"Scalar.Boolean", true},
		{"Scalar.SByte", int8(-100)},
		{"Scalar.Byte", uint8(200)},
		{"Scalar.Int16", int16(-12345)},
		{"Scalar.UInt16", uint16(54321)},
		{"Scalar.Int32", int32(-123456789)},
		{"Scalar.UInt32", uint32(3234567890)},
		{"Scalar.Int64", int64(-1234567890123456789)},
		{"Scalar.UInt64", uint64(12345678901234567890)},
		{"Scalar.Float", float32(12.5)},
		{"Scalar.Double", float64(-12345.6789)},
	} {
		t.Run(tc.node, func(t *testing.T) {
			v, err := c.Node(ua.NewStringNodeID(nsIdx, tc.node)).Value(ctx)
			if err != nil {
				t.Fatalf("Value: %v", err)
			}
			if v.Value() != tc.want {
				t.Errorf("got %T %v, want %T %v", v.Value(), v.Value(), tc.want, tc.want)
			}
		})
	}
	t.Run("Array.Int32", func(t *testing.T) {
		v, err := c.Node(ua.NewStringNodeID(nsIdx, "Array.Int32")).Value(ctx)
		if err != nil {
			t.Fatalf("Value: %v", err)
		}
		want := []int32{0, 1, -1, 2147483647, -2147483648, -123456789}
		if got, ok := v.Value().([]int32); !ok || !slices.Equal(got, want) {
			t.Errorf("got %T %v, want %v", v.Value(), v.Value(), want)
		}
	})
}

func TestOtfabricServer_WriteAndReadBack(t *testing.T) {
	h := startOtfabricServer(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)
	nodeID := ua.NewStringNodeID(nsIdx, "Access.ReadWrite")
	const want int32 = 8888
	sc, err := c.WriteNodeValue(ctx, nodeID, want)
	if err != nil {
		t.Fatalf("WriteNodeValue: %v", err)
	}
	if sc != ua.StatusGood {
		t.Fatalf("WriteNodeValue status: %v", sc)
	}
	v, err := c.Node(nodeID).Value(ctx)
	if err != nil {
		t.Fatalf("Value after write: %v", err)
	}
	if got := v.Value(); got != want {
		t.Errorf("read-back: got %T %v, want %d", got, got, want)
	}
}

func TestOtfabricServer_CallMethod(t *testing.T) {
	h := startOtfabricServer(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)
	result, err := c.CallMethod(ctx,
		ua.NewStringNodeID(nsIdx, "Methods"),
		ua.NewStringNodeID(nsIdx, "Methods.Add"),
		int32(3), int32(4),
	)
	if err != nil {
		t.Fatalf("CallMethod: %v", err)
	}
	if result.StatusCode != ua.StatusOK {
		t.Fatalf("CallMethod status: %v", result.StatusCode)
	}
	if len(result.OutputArguments) != 1 || result.OutputArguments[0].Value() != int32(7) {
		t.Errorf("Methods.Add(3,4): got %v, want 7", result.OutputArguments)
	}
}

func TestOtfabricServer_Subscribe(t *testing.T) {
	h := startOtfabricServer(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)
	sub, notifyCh, err := c.NewSubscription().
		Interval(300 * time.Millisecond).
		Monitor(ua.NewStringNodeID(nsIdx, "Dynamic.Counter")).
		Start(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Cancel(ctx) //nolint:errcheck

	got := 0
	deadline := time.After(15 * time.Second)
	for got < 3 {
		select {
		case msg, ok := <-notifyCh:
			if !ok {
				t.Fatal("notification channel closed")
			}
			if msg.Error != nil {
				t.Fatalf("notification error: %v", msg.Error)
			}
			if dcn, ok := msg.Value.(*ua.DataChangeNotification); ok {
				got += len(dcn.MonitoredItems)
			}
		case <-deadline:
			t.Fatalf("got %d notifications, want 3", got)
		}
	}
}

func TestOtfabricServer_Username(t *testing.T) {
	h := startOtfabricServer(t)
	c, err := dialUsernameClient(t, h.endpoint, "test-user", "test-password")
	if err != nil {
		t.Fatalf("valid credentials: %v", err)
	}
	ctx, nsIdx := findNS(t, c)
	if _, err := c.Node(ua.NewStringNodeID(nsIdx, "Scalar.Int32")).Value(ctx); err != nil {
		t.Fatalf("Value: %v", err)
	}

	_, err = dialUsernameClient(t, h.endpoint, "test-user", "wrong-password")
	if err == nil {
		t.Fatal("the server accepted a wrong password")
	}
	if !isIdentityRejectedError(err) {
		t.Fatalf("rejected for an unexpected reason: %v", err)
	}
}

func TestOtfabricServer_Secure(t *testing.T) {
	requireOtfabric(t)
	h := startSecureAdapterServer(t, otfabricEnv, "", "go-server")
	for _, s := range otfabricSecurity {
		t.Run(s.policy+"_"+s.mode, func(t *testing.T) {
			c := dialSecureClient(t, h.endpoint, s.policy, s.mode)
			ctx, nsIdx := findNS(t, c)
			v, err := c.Node(ua.NewStringNodeID(nsIdx, "Scalar.Int32")).Value(ctx)
			if err != nil {
				t.Fatalf("Value: %v", err)
			}
			if got := v.Value(); got != int32(-123456789) {
				t.Errorf("Scalar.Int32: got %T %v", got, got)
			}
		})
	}
	t.Run("Username", func(t *testing.T) {
		c, err := connectSecureClient(t, h.endpoint, "Basic256Sha256", "SignAndEncrypt", ua.UserTokenTypeUserName,
			opcua.AuthUsername("test-user", "test-password"))
		if err != nil {
			t.Fatalf("Connect: %v", err)
		}
		ctx, nsIdx := findNS(t, c)
		if _, err := c.Node(ua.NewStringNodeID(nsIdx, "Scalar.Int32")).Value(ctx); err != nil {
			t.Fatalf("Value: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// the image's client → this commit's server
// ---------------------------------------------------------------------------

func TestOtfabricClient_Endpoints(t *testing.T) {
	requireOtfabric(t)
	result := runOtfabricClient(t, startGoServer(t), "endpoints")
	if len(result.Results) == 0 || string(result.Results) == "[]" {
		t.Errorf("no endpoints: %s", result.Results)
	}
}

func TestOtfabricClient_Browse(t *testing.T) {
	requireOtfabric(t)
	result := runOtfabricClient(t, startGoServer(t), "browse", "--node", "nsu="+interopNamespaceURI+";i=85")
	if names := parseBrowseNames(t, result.Results); !names["Scalar.Int32"] {
		t.Errorf("Scalar.Int32 not in %v", names)
	}
}

func TestOtfabricClient_Read(t *testing.T) {
	requireOtfabric(t)
	endpoint := startGoServer(t)
	for _, tc := range []struct{ node, want string }{
		{"Scalar.Boolean", `true`},
		{"Scalar.Int32", `-123456789`},
		{"Scalar.Int64", `"-1234567890123456789"`},
		{"Scalar.Double", `-12345.6789`},
		{"Array.Int32", `[0,1,-1,2147483647,-2147483648,-123456789]`},
	} {
		t.Run(tc.node, func(t *testing.T) {
			result := runOtfabricClient(t, endpoint, "read", "--node", "nsu="+interopNamespaceURI+";s="+tc.node)
			var items []struct {
				Value json.RawMessage `json:"value"`
			}
			if err := json.Unmarshal(result.Results, &items); err != nil || len(items) != 1 {
				t.Fatalf("parse results: %v; raw: %s", err, result.Results)
			}
			if got := string(items[0].Value); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestOtfabricClient_Write(t *testing.T) {
	requireOtfabric(t)
	endpoint := startGoServer(t)
	node := "nsu=" + interopNamespaceURI + ";s=Access.ReadWrite"
	runOtfabricClient(t, endpoint, "write", "--node", node, "--type", "Int32", "--value", "6666")
	result := runOtfabricClient(t, endpoint, "read", "--node", node)
	var items []struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(result.Results, &items); err != nil || len(items) != 1 {
		t.Fatalf("parse results: %v; raw: %s", err, result.Results)
	}
	if string(items[0].Value) != "6666" {
		t.Errorf("read-back: got %s, want 6666", items[0].Value)
	}
}

func TestOtfabricClient_CallMethod(t *testing.T) {
	requireOtfabric(t)
	result := runOtfabricClient(t, startGoServer(t), "call",
		"--object", "nsu="+interopNamespaceURI+";s=Methods",
		"--method", "nsu="+interopNamespaceURI+";s=Methods.Add",
		"--input", "Int32:3",
		"--input", "Int32:4",
	)
	if !strings.Contains(string(result.Results), `7`) {
		t.Errorf("Methods.Add(3,4): %s", result.Results)
	}
}

func TestOtfabricClient_Subscribe(t *testing.T) {
	requireOtfabric(t)
	result := runOtfabricClient(t, startGoServer(t), "subscribe",
		"--node", "nsu="+interopNamespaceURI+";s=Dynamic.Counter",
		"--notifications", "3",
		"--publishing-interval-ms", "200",
		"--sampling-interval-ms", "100",
		"--timeout-ms", "15000",
	)
	var items []struct {
		Notifications []struct {
			Value json.RawMessage `json:"value"`
		} `json:"notifications"`
	}
	if err := json.Unmarshal(result.Results, &items); err != nil || len(items) != 1 {
		t.Fatalf("parse results: %v; raw: %s", err, result.Results)
	}
	if len(items[0].Notifications) < 3 {
		t.Fatalf("got %d notifications, want 3: %s", len(items[0].Notifications), result.Results)
	}
	prev := int64(-1 << 63)
	for _, n := range items[0].Notifications {
		v, err := strconv.ParseInt(strings.Trim(string(n.Value), `"`), 10, 64)
		if err != nil {
			t.Fatalf("Dynamic.Counter value %s: %v", n.Value, err)
		}
		if v < prev {
			t.Errorf("Dynamic.Counter went back: %d after %d", v, prev)
		}
		prev = v
	}
}

func TestOtfabricClient_Secure(t *testing.T) {
	requireOtfabric(t)
	endpoint := startSecureGoServer(t)
	node := "nsu=" + interopNamespaceURI + ";s=Scalar.Int32"
	for _, s := range otfabricSecurity {
		t.Run(s.policy+"_"+s.mode, func(t *testing.T) {
			result := runSecureAdapterClient(t, otfabricEnv, "", "consumer", endpoint, "read", s.policy, s.mode, "--node", node)
			if !result.Success {
				t.Fatalf("read failed: %s error=%s", result.ServiceResult, result.Error)
			}
		})
	}
	t.Run("Username", func(t *testing.T) {
		result := runSecureAdapterClient(t, otfabricEnv, "", "consumer", endpoint, "read", "Basic256Sha256", "SignAndEncrypt",
			"--node", node, "--username", "test-user", "--password", "test-password")
		if !result.Success {
			t.Fatalf("read failed: %s error=%s", result.ServiceResult, result.Error)
		}
	})
	t.Run("WrongPassword", func(t *testing.T) {
		result := runSecureAdapterClientResult(t, otfabricEnv, "", "consumer", endpoint, "read", "Basic256Sha256", "SignAndEncrypt",
			"--node", node, "--username", "test-user", "--password", "wrong-password")
		if result.Success {
			t.Fatal("the server accepted a wrong password")
		}
	})
}
