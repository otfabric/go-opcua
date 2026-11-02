//go:build interop

// SPDX-License-Identifier: MIT

// The capabilities opcua-interop-otfabric gained after its core subset, in both
// roles. Each test is gated by what the image declares, so an older image skips it
// and says why. See otfabric_self_test.go: a pass is not independent verification.

package interop

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/otfabric/go-opcua/uapolicy"
)

// otfabricCaps is what the image declares.
type otfabricCaps struct {
	ClientOperations []string `json:"clientOperations"`
	ClientFeatures   []string `json:"clientFeatures"`
	ServerFeatures   []string `json:"serverFeatures"`
	Stack            struct {
		Version string `json:"version"`
	} `json:"stack"`
}

func readOtfabricCaps(t *testing.T) otfabricCaps {
	t.Helper()
	requireOtfabric(t)
	raw, err := printCapabilities(os.Getenv(otfabricEnv))
	if err != nil {
		t.Fatalf("print-capabilities: %v", err)
	}
	var caps otfabricCaps
	if err := json.Unmarshal(raw, &caps); err != nil {
		t.Fatalf("parse capabilities: %v; raw: %s", err, raw)
	}
	return caps
}

// requireOtfabricClient skips unless the image declares these client operations or
// features.
func requireOtfabricClient(t *testing.T, names ...string) {
	t.Helper()
	caps := readOtfabricCaps(t)
	for _, name := range names {
		if !slices.Contains(caps.ClientOperations, name) && !slices.Contains(caps.ClientFeatures, name) {
			t.Skipf("the image %s does not declare the client capability %s", caps.Stack.Version, name)
		}
	}
}

// requireOtfabricServer skips unless the image declares these server features.
func requireOtfabricServer(t *testing.T, names ...string) {
	t.Helper()
	caps := readOtfabricCaps(t)
	for _, name := range names {
		if !slices.Contains(caps.ServerFeatures, name) {
			t.Skipf("the image %s does not declare the server feature %s", caps.Stack.Version, name)
		}
	}
}

// otfabricPKIArgs mount the test PKI of the image.
func otfabricPKIArgs(t *testing.T) []string {
	t.Helper()
	return []string{"-v", pkiDir(t) + ":/pki:ro"}
}

// runOtfabricPKIClient runs the image's client with the test PKI at /pki. The result
// comes back also when the command failed.
func runOtfabricPKIClient(t *testing.T, endpoint, subcmd string, args ...string) adapterResult {
	t.Helper()
	dockerEndpoint := strings.ReplaceAll(endpoint, "localhost", "host.docker.internal")
	cmd := append([]string{"run", "--rm", "--add-host=host.docker.internal:host-gateway"}, otfabricPKIArgs(t)...)
	cmd = append(cmd, os.Getenv(otfabricEnv), "client", subcmd, "--endpoint", dockerEndpoint)
	cmd = append(cmd, args...)
	raw, runErr := runClientContainer(t, cmd)
	result, err := parseAdapterOutput(raw)
	if err != nil {
		t.Fatalf("parse adapter client output: %v (run: %v)\nraw: %s", err, runErr, raw)
	}
	return result
}

// startOtfabricSecureServer is the image's server with RSA and ECC endpoints.
func startOtfabricSecureServer(t *testing.T, dockerArgs []string, serverArgs ...string) *serverHandle {
	t.Helper()
	h, _ := startAdapterServerWith(t, otfabricEnv, "", append(otfabricPKIArgs(t), dockerArgs...), append([]string{
		"--certificate", "/pki/go-server/cert.crt", "--private-key", "/pki/go-server/cert.key",
		"--pki-dir", "/pki/go-server/pki", "--ecc-dir", "/pki/go-server",
	}, serverArgs...))
	return h
}

// ---------------------------------------------------------------------------
// history
// ---------------------------------------------------------------------------

func TestOtfabricServer_HistoryRaw(t *testing.T) {
	requireOtfabricServer(t, "history-events")
	h := startOtfabricServer(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)
	values, err := c.ReadHistory(ctx, ua.NewStringNodeID(nsIdx, "History.Temperature"), histEventsBase, histEventsBase.Add(time.Minute), 0)
	if err != nil {
		t.Fatalf("ReadHistory: %v", err)
	}
	if len(values) != 5 {
		t.Fatalf("%d samples, want 5", len(values))
	}
	if got := values[4].Value.Value(); got != float64(24) {
		t.Errorf("last sample: %T %v, want 24", got, got)
	}
}

func TestOtfabricServer_HistoryEvents(t *testing.T) {
	requireOtfabricServer(t, "history-events", "history-events-update")
	h := startOtfabricServer(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)
	notifier := ua.NewStringNodeID(nsIdx, histEventsName)
	filter := &ua.EventFilter{SelectClauses: []*ua.SimpleAttributeOperand{{
		TypeDefinitionID: ua.NewNumericNodeID(0, id.BaseEventType),
		BrowsePath:       []*ua.QualifiedName{{Name: "EventId"}},
		AttributeID:      ua.AttributeIDValue,
	}}, WhereClause: &ua.ContentFilter{}}
	read := func() []string {
		t.Helper()
		events, err := c.ReadEventHistory(ctx, notifier, histEventsBase, histEventsBase.Add(time.Minute), filter, 0)
		if err != nil {
			t.Fatalf("ReadEventHistory: %v", err)
		}
		ids := make([]string, len(events))
		for i, ev := range events {
			b, _ := ev.EventFields[0].Value().([]byte)
			ids[i] = string(b)
		}
		return ids
	}
	seed := []string{"hist-evt-0", "hist-evt-1", "hist-evt-2", "hist-evt-3", "hist-evt-4"}
	if got := read(); !slices.Equal(got, seed) {
		t.Fatalf("events %v, want %v", got, seed)
	}
	resp, err := c.HistoryDeleteEvents(ctx, &ua.DeleteEventDetails{NodeID: notifier, EventIDs: [][]byte{[]byte("hist-evt-1")}})
	if err != nil {
		t.Fatalf("HistoryDeleteEvents: %v", err)
	}
	if resp.Results[0].OperationResults[0] != ua.StatusOK {
		t.Fatalf("delete: %v", resp.Results[0].OperationResults)
	}
	if got := read(); slices.Contains(got, "hist-evt-1") {
		t.Fatalf("hist-evt-1 is still there: %v", got)
	}
	res, err := c.Call(ctx, &ua.CallMethodRequest{ObjectID: notifier, MethodID: ua.NewStringNodeID(nsIdx, "History.ResetEvents")})
	if err != nil || res.StatusCode != ua.StatusOK {
		t.Fatalf("ResetEvents: %v %v", err, res)
	}
	if got := read(); !slices.Equal(got, seed) {
		t.Fatalf("after the reset: %v", got)
	}
}

func TestOtfabricClient_HistoryRaw(t *testing.T) {
	requireOtfabricClient(t, "history-read")
	endpoint, _, _ := startGoServerWithHistory(t)
	result := runOtfabricClient(t, endpoint, "history-read",
		"--node", "nsu="+interopNamespaceURI+";s=History.Temperature",
		"--start", "2026-07-24T10:00:00Z", "--end", "2026-07-24T10:00:04Z")
	var items []struct {
		Values []struct {
			Value float64 `json:"value"`
		} `json:"values"`
	}
	if err := json.Unmarshal(result.Results, &items); err != nil || len(items) != 1 {
		t.Fatalf("results: %v: %s", err, result.Results)
	}
	if len(items[0].Values) < 2 || items[0].Values[0].Value != 20 || items[0].Values[1].Value != 20.5 {
		t.Errorf("values: %+v", items[0].Values)
	}
}

func TestOtfabricClient_HistoryEvents(t *testing.T) {
	requireOtfabricClient(t, "history-read-events", "history-update-events")
	g := startGoServerWithEventHistory(t)
	span := []string{"--node", histEventsNode, "--start", "2026-07-24T10:00:00Z", "--end", "2026-07-24T10:01:00Z"}
	count := func() int {
		t.Helper()
		result := runOtfabricClient(t, g.endpoint, "history-read-events", span...)
		var items []struct {
			Events []json.RawMessage `json:"events"`
		}
		if err := json.Unmarshal(result.Results, &items); err != nil || len(items) != 1 {
			t.Fatalf("results: %v: %s", err, result.Results)
		}
		return len(items[0].Events)
	}
	if n := count(); n != 5 {
		t.Fatalf("%d events, want 5", n)
	}
	runOtfabricClient(t, g.endpoint, "history-update-events", "--node", histEventsNode, "--perform", "delete",
		"--event-id", base64.StdEncoding.EncodeToString([]byte("hist-evt-1")))
	if n := count(); n != 4 {
		t.Fatalf("%d events after the delete, want 4", n)
	}
}

// ---------------------------------------------------------------------------
// alarms and events
// ---------------------------------------------------------------------------

func TestOtfabricServer_Alarms(t *testing.T) {
	requireOtfabricServer(t, "alarms")
	s := newPeerAlarmSession(t, startOtfabricServer(t).endpoint)
	t.Run("Refresh", s.assertRefresh)
	t.Run("Actions", s.assertActions)
}

func TestOtfabricClient_Alarms(t *testing.T) {
	requireOtfabricClient(t, "alarms")
	r := runPeerAlarms(t, func(t *testing.T, endpoint, subcmd string, args ...string) adapterResult {
		t.Helper()
		return runOtfabricClient(t, endpoint, subcmd, args...)
	})
	t.Run("Refresh", r.assertRefresh)
	t.Run("Actions", r.assertActions)
}

func TestOtfabricServer_Events(t *testing.T) {
	requireOtfabricClient(t, "event-subscribe")
	h := startOtfabricServer(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)
	notify := make(chan *opcua.PublishNotificationData, 16)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 200 * time.Millisecond}, notify)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	filter := &ua.EventFilter{SelectClauses: []*ua.SimpleAttributeOperand{{
		TypeDefinitionID: ua.NewNumericNodeID(0, id.BaseEventType),
		BrowsePath:       []*ua.QualifiedName{{Name: "Severity"}},
		AttributeID:      ua.AttributeIDValue,
	}}, WhereClause: &ua.ContentFilter{}}
	resp, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, &ua.MonitoredItemCreateRequest{
		ItemToMonitor:       &ua.ReadValueID{NodeID: ua.NewStringNodeID(nsIdx, "Events.Source"), AttributeID: ua.AttributeIDEventNotifier},
		MonitoringMode:      ua.MonitoringModeReporting,
		RequestedParameters: &ua.MonitoringParameters{ClientHandle: 1, QueueSize: 10, DiscardOldest: true, Filter: ua.NewExtensionObject(filter)},
	})
	if err != nil || resp.Results[0].StatusCode != ua.StatusOK {
		t.Fatalf("Monitor: %v %+v", err, resp)
	}
	deadline := time.After(15 * time.Second)
	for {
		select {
		case msg := <-notify:
			list, ok := msg.Value.(*ua.EventNotificationList)
			if !ok || len(list.Events) == 0 {
				continue
			}
			if got := list.Events[0].EventFields[0].Value(); got != uint16(500) {
				t.Fatalf("Severity: %T %v, want 500", got, got)
			}
			return
		case <-deadline:
			t.Fatal("no event in 15 s")
		}
	}
}

func TestOtfabricClient_Events(t *testing.T) {
	requireOtfabricClient(t, "event-subscribe")
	endpoint, srv := startGoServerWithEvents(t)
	result := runPeerEventSubscribe(t, endpoint, srv, func(t *testing.T, endpoint, subcmd string, args ...string) adapterResult {
		t.Helper()
		return runOtfabricClient(t, endpoint, subcmd, args...)
	})
	assertPeerEventPayload(t, parseEventSubscribeItem(t, result))
}

// ---------------------------------------------------------------------------
// ECC and X.509 user tokens
// ---------------------------------------------------------------------------

func TestOtfabricServer_ECC(t *testing.T) {
	requireOtfabricServer(t, "ecc-security")
	h := startOtfabricSecureServer(t, nil)
	for _, p := range eccProfiles {
		for _, m := range p.modes() {
			t.Run(p.policy+"_"+m.mode, func(t *testing.T) {
				c := dialECCClient(t, h.endpoint, p, m.mode)
				ctx, nsIdx := findNS(t, c)
				v, err := c.Node(ua.NewStringNodeID(nsIdx, "Scalar.Int32")).Value(ctx)
				if err != nil {
					t.Fatalf("Value: %v", err)
				}
				if got := v.Value(); got != int32(-123456789) {
					t.Errorf("Scalar.Int32: %T %v", got, got)
				}
			})
		}
	}
}

func TestOtfabricClient_ECC(t *testing.T) {
	requireOtfabricClient(t, "ecc-security")
	endpoint, _ := startECCGoServer(t)
	for _, p := range eccProfiles {
		for _, m := range p.modes() {
			t.Run(p.policy+"_"+m.mode, func(t *testing.T) {
				result := runOtfabricPKIClient(t, endpoint, "read", "--node", "nsu="+interopNamespaceURI+";s=Scalar.Int32",
					"--security-policy", p.policy, "--security-mode", m.mode,
					"--certificate", "/pki/consumer/"+p.curve+"/cert.crt", "--private-key", "/pki/consumer/"+p.curve+"/cert.key",
					"--trust-list", "/pki/ca/ca.crt")
				if !result.Success {
					t.Fatalf("read: %s error=%s", result.ServiceResult, result.Error)
				}
			})
		}
	}
}

// consumerUserIdentity is the consumer identity of the PKI as a user certificate.
func consumerUserIdentity(t *testing.T) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	certPEM := mustReadFile(t, filepath.Join(pkiDir(t), "consumer", "cert.crt"))
	key, err := uapolicy.ParsePrivateKey(mustReadFile(t, filepath.Join(pkiDir(t), "consumer", "cert.key")))
	if err != nil {
		t.Fatalf("consumer key: %v", err)
	}
	return pemCertDER(t, certPEM), key.(*rsa.PrivateKey)
}

func TestOtfabricServer_X509User(t *testing.T) {
	requireOtfabricServer(t, "x509-user-token")
	h := startOtfabricSecureServer(t, nil)
	cert, key := consumerUserIdentity(t)
	c, err := connectSecureClient(t, h.endpoint, "Basic256Sha256", "SignAndEncrypt", ua.UserTokenTypeCertificate,
		opcua.AuthCertificate(cert), opcua.AuthPrivateKey(key))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	ctx, nsIdx := findNS(t, c)
	if _, err := c.Node(ua.NewStringNodeID(nsIdx, "Scalar.Int32")).Value(ctx); err != nil {
		t.Fatalf("Value: %v", err)
	}

	// A user certificate that does not chain to the trust store is refused.
	untrustedPEM := mustReadFile(t, filepath.Join(pkiDir(t), "untrusted", "cert.crt"))
	untrustedKey, err := uapolicy.ParsePrivateKey(mustReadFile(t, filepath.Join(pkiDir(t), "untrusted", "cert.key")))
	if err != nil {
		t.Fatalf("untrusted key: %v", err)
	}
	if _, err := connectSecureClient(t, h.endpoint, "Basic256Sha256", "SignAndEncrypt", ua.UserTokenTypeCertificate,
		opcua.AuthCertificate(pemCertDER(t, untrustedPEM)), opcua.AuthPrivateKey(untrustedKey.(*rsa.PrivateKey))); err == nil {
		t.Fatal("the server accepted an untrusted user certificate")
	}
}

func TestOtfabricClient_X509User(t *testing.T) {
	requireOtfabricClient(t, "x509-user-token")
	want, _ := consumerUserIdentity(t)
	var got []byte
	endpoint, _ := startGoServerWithOptions(t,
		server.Certificate(loadGoServerCert(t)), server.PrivateKey(loadGoServerKey(t)),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeCertificate),
		server.WithX509UserValidator(func(cert []byte) error { got = cert; return nil }),
	)
	result := runOtfabricPKIClient(t, endpoint, "read", "--node", "nsu="+interopNamespaceURI+";s=Scalar.Int32",
		"--security-policy", "Basic256Sha256", "--security-mode", "SignAndEncrypt",
		"--certificate", "/pki/consumer/cert.crt", "--private-key", "/pki/consumer/cert.key", "--trust-list", "/pki/ca/ca.crt",
		"--user-certificate", "/pki/consumer/cert.crt", "--user-private-key", "/pki/consumer/cert.key")
	if !result.Success {
		t.Fatalf("read: %s error=%s", result.ServiceResult, result.Error)
	}
	if !slices.Equal(got, want) {
		t.Errorf("the server saw a user certificate of %d bytes, want the consumer's %d", len(got), len(want))
	}
}

// ---------------------------------------------------------------------------
// reverse connect
// ---------------------------------------------------------------------------

func TestOtfabricServer_Reverse(t *testing.T) {
	requireOtfabricServer(t, "reverse-connect")
	l, err := uacp.ListenReverse(context.Background(), "0.0.0.0:0", &uacp.ReverseListenerConfig{})
	if err != nil {
		t.Fatalf("ListenReverse: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	startAdapterReverseServer(t, otfabricEnv, "", l.Addr().(*net.TCPAddr).Port)
	ctx, cancel := context.WithTimeout(context.Background(), 2*reverseDialTimeout)
	defer cancel()
	c, err := opcua.NewClient("", opcua.InsecureNoSecurity(), opcua.SecurityModeString("None"), opcua.AuthAnonymous(),
		opcua.DialTimeout(reverseDialTimeout), opcua.AutoReconnect(false), opcua.ReverseConnectListener(l))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("Connect over a reverse connection: %v", err)
	}
	defer func() { _ = c.Close(ctx) }()
	nsIdx, err := c.FindNamespace(ctx, interopNamespaceURI)
	if err != nil {
		t.Fatalf("FindNamespace: %v", err)
	}
	v, err := c.Node(ua.NewStringNodeID(nsIdx, "Scalar.Int32")).Value(ctx)
	if err != nil {
		t.Fatalf("Value: %v", err)
	}
	if got := v.Value(); got != int32(-123456789) {
		t.Errorf("Scalar.Int32: %T %v", got, got)
	}
}

func TestOtfabricClient_Reverse(t *testing.T) {
	requireOtfabricClient(t, "reverse-listen")
	endpoint, hostPort, _, counter := reverseGoServer(t)
	result := runAdapterReverseClient(t, otfabricEnv, "", endpoint, hostPort, "read", "--node", "nsu="+interopNamespaceURI+";s=Scalar.Int32")
	if !result.Success {
		t.Fatalf("read: %s error=%s", result.ServiceResult, result.Error)
	}
	requireOnlyReverseConnections(t, counter)
}

// ---------------------------------------------------------------------------
// opc.https and opc.wss
// ---------------------------------------------------------------------------

func TestOtfabricServer_Transports(t *testing.T) {
	requireOtfabricServer(t, "transport-https", "transport-wss")
	httpsPort, wssPort := freePort(t), freePort(t)
	startOtfabricSecureServer(t, []string{"-p", fmt.Sprintf("%d:4843", httpsPort), "-p", fmt.Sprintf("%d:4844", wssPort)},
		"--https-port", "4843", "--wss-port", "4844", "--advertised-host", "localhost")
	for _, url := range []string{
		fmt.Sprintf("opc.https://localhost:%d%s", httpsPort, endpointPath),
		fmt.Sprintf("opc.wss://localhost:%d%s", wssPort, endpointPath),
	} {
		t.Run(strings.SplitN(url, ":", 2)[0], func(t *testing.T) {
			exerciseTransport(t, dialTransportClient(t, url, true))
		})
	}
}

func TestOtfabricClient_Transports(t *testing.T) {
	requireOtfabricClient(t, "transport-https", "transport-wss")
	h := startGoTransportServer(t)
	node := "nsu=" + interopNamespaceURI + ";s=Scalar.Int32"
	for _, url := range []string{h.https, h.wss} {
		t.Run(strings.SplitN(url, ":", 2)[0], func(t *testing.T) {
			result := runOtfabricPKIClient(t, url, "read", "--node", node, "--trust-list", "/pki/ca/ca.crt")
			if !result.Success {
				t.Fatalf("read: %s error=%s", result.ServiceResult, result.Error)
			}
			if bad := runOtfabricPKIClient(t, url, "read", "--node", node, "--trust-list", "/pki/untrusted/cert.crt"); bad.Success {
				t.Fatal("a TLS certificate outside --trust-list was accepted")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// codec
// ---------------------------------------------------------------------------

// TestOtfabricClient_Codec decodes the image's documents with this commit, and the
// other way round: a changed encoding on either side shows.
func TestOtfabricClient_Codec(t *testing.T) {
	requireOtfabricClient(t, "codec", "codec-json", "codec-xml")
	image := os.Getenv(otfabricEnv)
	for _, format := range []string{"json", "xml"} {
		t.Run(format, func(t *testing.T) {
			raw, err := runClientContainer(t, []string{"run", "--rm", image, "client", "codec", "encode", "--format", format, "--type", "String", "--value", "interop"})
			if err != nil {
				t.Fatalf("encode: %v: %s", err, raw)
			}
			result, err := parseAdapterOutput(raw)
			if err != nil {
				t.Fatalf("parse: %v: %s", err, raw)
			}
			var items []struct {
				Encoded struct {
					Variant string `json:"variant"`
				} `json:"encoded"`
				Binary struct {
					Variant string `json:"variant"`
				} `json:"binary"`
			}
			if err := json.Unmarshal(result.Results, &items); err != nil || len(items) != 1 {
				t.Fatalf("results: %v: %s", err, result.Results)
			}
			var v ua.Variant
			if format == "json" {
				err = ua.DecodeJSON([]byte(items[0].Encoded.Variant), &v)
			} else {
				err = ua.DecodeXML([]byte(items[0].Encoded.Variant), &v)
			}
			if err != nil {
				t.Fatalf("decode %s: %v", items[0].Encoded.Variant, err)
			}
			if got := v.Value(); got != "interop" {
				t.Errorf("value: %T %v", got, got)
			}
			b, err := v.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if got := base64.StdEncoding.EncodeToString(b); got != items[0].Binary.Variant {
				t.Errorf("binary %s, the image has %s", got, items[0].Binary.Variant)
			}
		})
	}
}
