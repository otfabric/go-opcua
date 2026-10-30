//go:build interop

// SPDX-License-Identifier: MIT

// Extended peer evidence beyond the baseline surface.
// COVERAGE.md: security / security.channel.renewal,
// history / history.read.continuation (C→),
// view / view.register-nodes,
// node-management / nodemgmt.add-nodes, nodemgmt.delete-nodes,
// subscriptions / subscription.modify, monitoreditem.modify,
// monitoreditem.monitoring-mode

package interop

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
)

// renewalLifetime is the requested SecureChannel lifetime for renewal tests.
// Clients renew at 75% of the revised lifetime, so a run of several lifetimes
// crosses multiple SecurityToken renewals and the expiry of the first token.
const renewalLifetime = 6 * time.Second

// ---------------------------------------------------------------------------
// SecureChannel renewal — Go client → peer server (C→O / C→M)
// ---------------------------------------------------------------------------

// dialSecureClientWith is dialSecureClient with extra client options appended.
func dialSecureClientWith(t *testing.T, endpoint, policy, mode string, extra ...opcua.Option) *opcua.Client {
	t.Helper()

	pki := pkiDir(t)
	ca := loadCACert(t, filepath.Join(pki, "ca", "ca.crt"))

	discoverCtx, discoverCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer discoverCancel()
	eps, err := opcua.GetEndpoints(discoverCtx, endpoint)
	if err != nil {
		t.Fatalf("GetEndpoints(%q): %v", endpoint, err)
	}

	wantPolicy := ua.FormatSecurityPolicyURI(policy)
	wantMode := ua.MessageSecurityModeFromString(mode)
	var chosen *ua.EndpointDescription
	for _, ep := range eps {
		if ep.SecurityPolicyURI == wantPolicy && ep.SecurityMode == wantMode {
			chosen = ep
			break
		}
	}
	if chosen == nil {
		t.Fatalf("server did not advertise %s/%s endpoint (got %d endpoints)", policy, mode, len(eps))
	}
	chosen.EndpointURL = endpoint

	opts := []opcua.Option{
		opcua.SecurityFromEndpoint(chosen, ua.UserTokenTypeAnonymous),
		opcua.CertificateFile(filepath.Join(pki, "consumer", "cert.crt")),
		opcua.PrivateKeyFile(filepath.Join(pki, "consumer", "cert.key")),
		opcua.TrustedCertificates(ca),
		opcua.AuthAnonymous(),
	}
	opts = append(opts, extra...)
	c, err := opcua.NewClient(endpoint, append([]opcua.Option{opcua.InsecureNoSecurity()}, opts...)...)
	if err != nil {
		t.Fatalf("NewClient (secure): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("Connect secure (%q %s/%s): %v", endpoint, policy, mode, err)
	}
	t.Cleanup(func() {
		ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel2()
		_ = c.Close(ctx2)
	})
	return c
}

// counterValue converts a Dynamic.Counter sample (integer type differs per
// stack) to int64.
func counterValue(t *testing.T, v *ua.Variant) int64 {
	t.Helper()
	if v == nil {
		t.Fatal("nil counter variant")
	}
	switch n := v.Value().(type) {
	case int32:
		return int64(n)
	case uint32:
		return int64(n)
	case int64:
		return n
	case uint64:
		return int64(n)
	default:
		t.Fatalf("unexpected Dynamic.Counter type %T", v.Value())
		return 0
	}
}

// awaitCounterAdvance blocks until the subscription delivers a counter value
// strictly greater than last and returns it.
func awaitCounterAdvance(t *testing.T, notifyCh <-chan *opcua.PublishNotificationData, last int64, timeout time.Duration, phase string) int64 {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case msg, ok := <-notifyCh:
			if !ok {
				t.Fatalf("%s: notify channel closed", phase)
			}
			if msg.Error != nil {
				t.Fatalf("%s: notification error: %v", phase, msg.Error)
			}
			dcn, ok := msg.Value.(*ua.DataChangeNotification)
			if !ok || dcn == nil {
				continue
			}
			for _, mi := range dcn.MonitoredItems {
				if mi == nil || mi.Value == nil || mi.Value.Value == nil {
					continue
				}
				v := counterValue(t, mi.Value.Value)
				if v < last {
					t.Fatalf("%s: counter went backwards: %d after %d", phase, v, last)
				}
				if v > last {
					return v
				}
			}
		case <-deadline:
			t.Fatalf("%s: no counter advance past %d within %s", phase, last, timeout)
		}
	}
}

// assertClientChannelRenewal proves that a session with a live subscription
// survives SecurityToken renewals on an encrypted channel: explicit renewals
// must be accepted by the peer, the subscription must keep delivering on each
// new token, and the session must still be usable once the original token
// (lifetime + 25% grace) has expired.
func assertClientChannelRenewal(t *testing.T, endpoint string) {
	t.Helper()
	c := dialSecureClientWith(t, endpoint, "Basic256Sha256", "SignAndEncrypt",
		opcua.Lifetime(renewalLifetime))
	_, nsIdx := findNS(t, c)
	counter := ua.NewStringNodeID(nsIdx, "Dynamic.Counter")

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	sub, notifyCh, err := c.NewSubscription().
		Interval(250 * time.Millisecond).
		Monitor(counter).
		Start(ctx)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer func() { _ = sub.Cancel(ctx) }()

	start := time.Now()
	last := awaitCounterAdvance(t, notifyCh, -1, 15*time.Second, "before renewal")

	const renewals = 3
	for i := 1; i <= renewals; i++ {
		if err := c.SecureChannel().Renew(ctx); err != nil {
			t.Fatalf("renewal %d rejected: %v", i, err)
		}
		phase := fmt.Sprintf("after renewal %d", i)
		// Two advances so at least one sample was produced after the renewal.
		last = awaitCounterAdvance(t, notifyCh, last, 15*time.Second, phase)
		last = awaitCounterAdvance(t, notifyCh, last, 15*time.Second, phase)
		if _, err := c.ReadValue(ctx, counter); err != nil {
			t.Fatalf("%s: read: %v", phase, err)
		}
	}

	// Outlive the original token (lifetime + 25% grace) and one further
	// automatic renewal cycle, with data still flowing.
	for time.Since(start) < 2*renewalLifetime+renewalLifetime/2 {
		last = awaitCounterAdvance(t, notifyCh, last, 15*time.Second, "past original token expiry")
	}
	dv, err := c.ReadValue(ctx, counter)
	if err != nil {
		t.Fatalf("read after token expiry: %v", err)
	}
	if dv.Status != ua.StatusOK {
		t.Fatalf("read after token expiry: status %v", dv.Status)
	}
	t.Logf("channel renewed %d× explicitly over %s; counter reached %d", renewals, time.Since(start).Round(time.Millisecond), last)
}

func TestOpen62541Server_SecureChannelRenewal(t *testing.T) {
	t.Run("coverage/security.channel.renewal/go-client-to-open62541-server", func(t *testing.T) {
		h := startOpen62541SecureServer(t)
		assertClientChannelRenewal(t, h.endpoint)
	})
}

func TestMiloServer_SecureChannelRenewal(t *testing.T) {
	t.Run("coverage/security.channel.renewal/go-client-to-milo-server", func(t *testing.T) {
		h := startMiloSecureServer(t)
		assertClientChannelRenewal(t, h.endpoint)
	})
}

// ---------------------------------------------------------------------------
// SecureChannel renewal — peer client → Go server (O→S / M→S)
// ---------------------------------------------------------------------------

// openChannelCounter derives the number of SecurityToken renewals the Go
// server handled from its structured log: every OpenSecureChannel request
// beyond the first one on each registered channel is a renewal.
type openChannelCounter struct {
	slog.Handler
	n *atomic.Int64
}

const (
	openChannelLogMsg = "handling OpenSecureChannelRequest"
	newChannelLogMsg  = "registered new channel"
)

func (h openChannelCounter) Enabled(context.Context, slog.Level) bool { return true }

func (h openChannelCounter) Handle(_ context.Context, r slog.Record) error {
	switch r.Message {
	case openChannelLogMsg:
		h.n.Add(1)
	case newChannelLogMsg:
		h.n.Add(-1)
	}
	if os.Getenv("INTEROP_DEBUG_LOG") != "" {
		var b strings.Builder
		r.Attrs(func(a slog.Attr) bool { fmt.Fprintf(&b, " %s=%v", a.Key, a.Value); return true })
		fmt.Fprintf(os.Stderr, "%s [go-server %s] %s%s\n", time.Now().Format("15:04:05.000"), r.Level, r.Message, b.String())
	}
	return nil
}

func (h openChannelCounter) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h openChannelCounter) WithGroup(string) slog.Handler      { return h }

// startRenewalGoServer starts a secure Go server exposing Dynamic.Counter
// (Int64, +1 every 250 ms) and returns its endpoint plus the running count of
// SecurityToken renewals it handled.
func startRenewalGoServer(t *testing.T) (string, *atomic.Int64) {
	t.Helper()

	renewals := new(atomic.Int64)
	s, err := server.New(
		server.ListenOn("0.0.0.0:0"),
		server.EndPoint("host.docker.internal", 0),
		server.Certificate(loadGoServerCert(t)),
		server.PrivateKey(loadGoServerKey(t)),
		server.InsecureNoSecurity(),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.SetLogger(slog.New(openChannelCounter{n: renewals})),
	)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	ns := server.NewNodeNameSpace(s, interopNamespaceURI)
	s.AddNamespace(ns)
	nsIdx := ns.ID()

	var ctr atomic.Int64
	counterID := ua.NewStringNodeID(nsIdx, "Dynamic.Counter")
	counterNode := server.NewNode(
		counterID,
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:       server.DataValueFromValue(uint32(ua.NodeClassVariable)),
			ua.AttributeIDBrowseName:      server.DataValueFromValue(attrs.BrowseName("Dynamic.Counter")),
			ua.AttributeIDDisplayName:     server.DataValueFromValue(attrs.DisplayName("Counter", "en")),
			ua.AttributeIDAccessLevel:     server.DataValueFromValue(uint8(ua.AccessLevelTypeCurrentRead)),
			ua.AttributeIDUserAccessLevel: server.DataValueFromValue(uint8(ua.AccessLevelTypeCurrentRead)),
			ua.AttributeIDValueRank:       server.DataValueFromValue(int32(-1)),
		},
		nil,
		func() *ua.DataValue {
			return &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(ctr.Load())}
		},
	)
	ns.AddNode(counterNode)
	ns.Objects().AddRef(counterNode, server.RefTypeIDHasComponent, true)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = s.Close()
	})
	if err := s.Start(ctx); err != nil {
		t.Fatalf("server.Start: %v", err)
	}
	port := s.Port()
	if port == 0 {
		t.Fatal("bound port is 0")
	}

	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				ctr.Add(1)
				s.ChangeNotification(counterID)
			case <-ctx.Done():
				return
			}
		}
	}()

	addr := fmt.Sprintf("localhost:%d", port)
	deadline := time.Now().Add(serverReadyTimeout)
	for time.Now().Before(deadline) {
		if conn, err := net.Dial("tcp", addr); err == nil {
			_ = conn.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Sprintf("opc.tcp://localhost:%d%s", port, endpointPath), renewals
}

type renewalSubscribeResult struct {
	MonitoredItemStatusCode statusCodeObj `json:"monitoredItemStatusCode"`
	Notifications           []struct {
		Value      json.Number   `json:"value"`
		StatusCode statusCodeObj `json:"statusCode"`
	} `json:"notifications"`
}

// assertPeerChannelRenewal runs an adapter subscribe that spans several
// requested SecureChannel lifetimes over SignAndEncrypt. The command only
// completes if the Go server accepts each renewal and keeps publishing on the
// renewed token.
func assertPeerChannelRenewal(t *testing.T, imageEnv, defaultImage, clientPKI string) {
	t.Helper()
	endpoint, renewals := startRenewalGoServer(t)

	// 500 ms publishing over a 250 ms counter: ~2 notifications/s, so 32
	// notifications span ~16 s (≥ 3 renewals at 75% of the 6 s lifetime).
	const want = 32
	started := time.Now()
	result := runSecureAdapterClientResult(t, imageEnv, defaultImage, clientPKI, endpoint,
		"subscribe", "Basic256Sha256", "SignAndEncrypt",
		"--node", "nsu="+interopNamespaceURI+";s=Dynamic.Counter",
		"--publishing-interval-ms", "500",
		"--sampling-interval-ms", "250",
		"--notifications", fmt.Sprint(want),
		"--timeout-ms", "60000",
		"--request-timeout", "20",
		"--channel-lifetime-ms", fmt.Sprint(renewalLifetime.Milliseconds()),
	)
	elapsed := time.Since(started)
	if !result.Success {
		t.Fatalf("subscribe across renewals failed after %s: serviceResult=%s error=%+v",
			elapsed, result.ServiceResult, result.Error)
	}

	var items []renewalSubscribeResult
	if err := json.Unmarshal(result.Results, &items); err != nil || len(items) != 1 {
		t.Fatalf("unexpected subscribe results (%v): %s", err, result.Results)
	}
	got := items[0].Notifications
	if len(got) != want {
		t.Fatalf("notifications=%d, want %d", len(got), want)
	}
	prev := int64(-1)
	for i, n := range got {
		v, err := n.Value.Int64()
		if err != nil {
			t.Fatalf("notification %d: value %q: %v", i, n.Value, err)
		}
		if v <= prev {
			t.Fatalf("notification %d: counter %d not after %d (lost or reordered across renewal)", i, v, prev)
		}
		prev = v
	}

	renewed := renewals.Load()
	if renewed < 2 {
		t.Fatalf("Go server handled %d SecurityToken renewals in %s; want ≥ 2", renewed, elapsed)
	}
	t.Logf("%d notifications over %s across %d channel renewals", len(got), elapsed.Round(time.Millisecond), renewed)
}

func TestGoServer_Open62541Client_SecureChannelRenewal(t *testing.T) {
	t.Run("coverage/security.channel.renewal/open62541-to-go-server", func(t *testing.T) {
		assertPeerChannelRenewal(t, "OPEN62541_IMAGE", defaultOpen62541Image, "open62541-client")
	})
}

func TestGoServer_MiloClient_SecureChannelRenewal(t *testing.T) {
	t.Run("coverage/security.channel.renewal/milo-to-go-server", func(t *testing.T) {
		assertPeerChannelRenewal(t, "MILO_IMAGE", defaultMiloImage, "milo-client")
	})
}

// ---------------------------------------------------------------------------
// HistoryRead continuation points — Go client → peer server (C→O / C→M)
// ---------------------------------------------------------------------------

func historyReadPage(t *testing.T, ctx context.Context, c *opcua.Client, node *ua.NodeID, cp []byte, release bool) *ua.HistoryReadResult {
	t.Helper()
	req := &ua.HistoryReadRequest{
		TimestampsToReturn:        ua.TimestampsToReturnBoth,
		ReleaseContinuationPoints: release,
		NodesToRead:               []*ua.HistoryReadValueID{{NodeID: node, ContinuationPoint: cp}},
		HistoryReadDetails: &ua.ExtensionObject{
			TypeID:       ua.NewFourByteExpandedNodeID(0, id.ReadRawModifiedDetailsEncodingDefaultBinary),
			EncodingMask: ua.ExtensionObjectBinary,
			// EndTime is one second past the last sample (10:00:20): Part 11
			// leaves the end time out of the interval and UA-.NETStandard does
			// so, open62541 and Milo include it; either way all five are inside.
			Value: &ua.ReadRawModifiedDetails{
				StartTime:        time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC),
				EndTime:          time.Date(2026, 7, 24, 10, 0, 21, 0, time.UTC),
				NumValuesPerNode: 2,
			},
		},
	}
	var resp *ua.HistoryReadResponse
	err := c.Send(ctx, req, func(r ua.Response) error {
		hr, ok := r.(*ua.HistoryReadResponse)
		if !ok {
			return fmt.Errorf("unexpected response %T", r)
		}
		resp = hr
		return nil
	})
	if err != nil {
		t.Fatalf("HistoryRead (cp=%x release=%v): %v", cp, release, err)
	}
	if len(resp.Results) != 1 {
		t.Fatalf("HistoryRead results=%d, want 1", len(resp.Results))
	}
	return resp.Results[0]
}

func historyDoubles(t *testing.T, res *ua.HistoryReadResult) []float64 {
	t.Helper()
	if res.HistoryData == nil || res.HistoryData.Value == nil {
		// No HistoryData, or a null ExtensionObject (e.g. on release).
		return nil
	}
	hd, ok := res.HistoryData.Value.(*ua.HistoryData)
	if !ok || hd == nil {
		t.Fatalf("expected *ua.HistoryData, got %T", res.HistoryData.Value)
	}
	out := make([]float64, 0, len(hd.DataValues))
	for _, dv := range hd.DataValues {
		f, ok := dv.Value.Value().(float64)
		if !ok {
			t.Fatalf("history value type %T, want float64", dv.Value.Value())
		}
		out = append(out, f)
	}
	return out
}

// assertPeerHistoryContinuation pages the five fixed History.Temperature
// samples two at a time through peer-issued continuation points. When the peer
// honours ReleaseContinuationPoints it also proves a released continuation
// point is rejected on reuse.
func assertPeerHistoryContinuation(t *testing.T, endpoint string, peerReleases bool) {
	t.Helper()
	c := dialClient(t, endpoint)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, nsIdx := findNS(t, c)
	node := ua.NewStringNodeID(nsIdx, "History.Temperature")

	var all []float64
	var cp []byte
	pages := 0
	for {
		res := historyReadPage(t, ctx, c, node, cp, false)
		if res.StatusCode != ua.StatusOK {
			t.Fatalf("page %d status=%v", pages+1, res.StatusCode)
		}
		vals := historyDoubles(t, res)
		if len(vals) == 0 || len(vals) > 2 {
			t.Fatalf("page %d carried %d values, want 1..2", pages+1, len(vals))
		}
		all = append(all, vals...)
		pages++
		cp = res.ContinuationPoint
		if len(cp) == 0 {
			break
		}
		if pages > 5 {
			t.Fatalf("continuation did not terminate after %d pages", pages)
		}
	}
	if pages != 3 {
		t.Fatalf("pages=%d, want 3 (2+2+1)", pages)
	}
	want := []float64{20, 21, 22, 23, 24}
	if len(all) != len(want) {
		t.Fatalf("values=%v, want %v", all, want)
	}
	for i := range want {
		if all[i] != want[i] {
			t.Fatalf("values=%v, want %v", all, want)
		}
	}

	// Release a fresh continuation point, then reuse it.
	first := historyReadPage(t, ctx, c, node, nil, false)
	if first.StatusCode != ua.StatusOK || len(first.ContinuationPoint) == 0 {
		t.Fatalf("first page status=%v cp=%x, want Good with continuation point", first.StatusCode, first.ContinuationPoint)
	}
	rel := historyReadPage(t, ctx, c, node, first.ContinuationPoint, true)
	if rel.StatusCode != ua.StatusOK {
		t.Fatalf("release status=%v, want Good", rel.StatusCode)
	}
	if !peerReleases {
		// The request was accepted; the peer SDK does not surface the flag to
		// its history backend, so invalidation cannot be observed.
		return
	}
	if n := len(historyDoubles(t, rel)); n != 0 {
		t.Fatalf("release returned %d values, want none", n)
	}
	reuse := historyReadPage(t, ctx, c, node, first.ContinuationPoint, false)
	if reuse.StatusCode != ua.StatusBadContinuationPointInvalid {
		t.Fatalf("reuse after release status=%v, want BadContinuationPointInvalid", reuse.StatusCode)
	}
}

func TestOpen62541Server_HistoryReadContinuation(t *testing.T) {
	t.Run("coverage/history.read.continuation/go-client-to-open62541-server", func(t *testing.T) {
		h := startOpen62541Server(t)
		requirePeerNode(t, h.endpoint, "History.Temperature")
		assertPeerHistoryContinuation(t, h.endpoint, true)
	})
}

func TestMiloServer_HistoryReadContinuation(t *testing.T) {
	t.Run("coverage/history.read.continuation/go-client-to-milo-server", func(t *testing.T) {
		h := startMiloServer(t)
		requirePeerNode(t, h.endpoint, "History.Temperature")
		// Milo's AddressSpace.historyRead is not told about
		// ReleaseContinuationPoints, so only paging is asserted.
		assertPeerHistoryContinuation(t, h.endpoint, false)
	})
}

// ---------------------------------------------------------------------------
// RegisterNodes / UnregisterNodes
// ---------------------------------------------------------------------------

func assertClientRegisterNodes(t *testing.T, endpoint string) {
	t.Helper()
	c := dialClient(t, endpoint)
	ctx, nsIdx := findNS(t, c)
	nodes := []*ua.NodeID{
		ua.NewStringNodeID(nsIdx, "Scalar.Int32"),
		ua.NewStringNodeID(nsIdx, "Scalar.String"),
	}

	reg, err := c.RegisterNodes(ctx, &ua.RegisterNodesRequest{NodesToRegister: nodes})
	if err != nil {
		t.Fatalf("RegisterNodes: %v", err)
	}
	if len(reg.RegisteredNodeIDs) != len(nodes) {
		t.Fatalf("registered=%d, want %d", len(reg.RegisteredNodeIDs), len(nodes))
	}
	for i, r := range reg.RegisteredNodeIDs {
		if r == nil {
			t.Fatalf("registered id %d is nil", i)
		}
	}

	// The aliases must address the same nodes.
	dvs, err := c.ReadValues(ctx, reg.RegisteredNodeIDs...)
	if err != nil {
		t.Fatalf("read via registered ids: %v", err)
	}
	if len(dvs) != 2 || dvs[0].Status != ua.StatusOK || dvs[1].Status != ua.StatusOK {
		t.Fatalf("read via registered ids: %+v", dvs)
	}
	if got := dvs[0].Value.Value(); got != int32(-123456789) {
		t.Fatalf("Scalar.Int32 via alias = %v (%T), want -123456789", got, got)
	}
	if _, ok := dvs[1].Value.Value().(string); !ok {
		t.Fatalf("Scalar.String via alias has type %T", dvs[1].Value.Value())
	}

	unreg, err := c.UnregisterNodes(ctx, &ua.UnregisterNodesRequest{NodesToUnregister: reg.RegisteredNodeIDs})
	if err != nil {
		t.Fatalf("UnregisterNodes: %v", err)
	}
	if unreg.ResponseHeader == nil || unreg.ResponseHeader.ServiceResult != ua.StatusOK {
		t.Fatalf("UnregisterNodes header: %+v", unreg.ResponseHeader)
	}
}

func TestOpen62541Server_RegisterNodes(t *testing.T) {
	t.Run("coverage/view.register-nodes/go-client-to-open62541-server", func(t *testing.T) {
		h := startOpen62541Server(t)
		assertClientRegisterNodes(t, h.endpoint)
	})
}

func TestMiloServer_RegisterNodes(t *testing.T) {
	t.Run("coverage/view.register-nodes/go-client-to-milo-server", func(t *testing.T) {
		h := startMiloServer(t)
		assertClientRegisterNodes(t, h.endpoint)
	})
}

type registerNodesResult struct {
	NodeID               string          `json:"nodeId"`
	RegisteredNodeID     string          `json:"registeredNodeId"`
	StatusCode           statusCodeObj   `json:"statusCode"`
	Value                json.RawMessage `json:"value"`
	UnregisterStatusCode statusCodeObj   `json:"unregisterStatusCode"`
}

func assertPeerRegisterNodes(t *testing.T, imageEnv, defaultImage string, run func(*testing.T, string, string, ...string) adapterResult) {
	t.Helper()
	requireAdapterOp(t, imageEnv, defaultImage, "register-nodes")
	endpoint := startGoServer(t)
	result := run(t, endpoint, "register-nodes",
		"--node", "nsu="+interopNamespaceURI+";s=Scalar.Int32",
		"--node", "nsu="+interopNamespaceURI+";s=Scalar.Boolean",
	)
	if !result.Success {
		t.Fatalf("register-nodes failed: serviceResult=%s error=%+v", result.ServiceResult, result.Error)
	}
	var items []registerNodesResult
	if err := json.Unmarshal(result.Results, &items); err != nil || len(items) != 2 {
		t.Fatalf("unexpected results (%v): %s", err, result.Results)
	}
	for i, it := range items {
		if it.RegisteredNodeID == "" {
			t.Errorf("item %d: empty registeredNodeId", i)
		}
		if !statusCodeIs(it.StatusCode, ua.StatusOK) || !statusCodeIs(it.UnregisterStatusCode, ua.StatusOK) {
			t.Errorf("item %d: read=%s unregister=%s", i, it.StatusCode, it.UnregisterStatusCode)
		}
	}
	if string(items[0].Value) != "-123456789" {
		t.Errorf("Scalar.Int32 via alias = %s, want -123456789", items[0].Value)
	}
	if string(items[1].Value) != "true" {
		t.Errorf("Scalar.Boolean via alias = %s, want true", items[1].Value)
	}
}

func TestGoServer_Open62541Client_RegisterNodes(t *testing.T) {
	t.Run("coverage/view.register-nodes/open62541-to-go-server", func(t *testing.T) {
		assertPeerRegisterNodes(t, "OPEN62541_IMAGE", defaultOpen62541Image, runOpen62541ClientResult)
	})
}

func TestGoServer_MiloClient_RegisterNodes(t *testing.T) {
	t.Run("coverage/view.register-nodes/milo-to-go-server", func(t *testing.T) {
		assertPeerRegisterNodes(t, "MILO_IMAGE", defaultMiloImage, runMiloClientResult)
	})
}

// ---------------------------------------------------------------------------
// NodeManagement — AddNodes / DeleteNodes
// ---------------------------------------------------------------------------

func addVariableRequest(nsIdx uint16, parent, newID *ua.NodeID, value int32) *ua.AddNodesRequest {
	mask := ua.NodeAttributesMaskAccessLevel | ua.NodeAttributesMaskDataType |
		ua.NodeAttributesMaskDisplayName | ua.NodeAttributesMaskUserAccessLevel |
		ua.NodeAttributesMaskValueRank | ua.NodeAttributesMaskValue
	return &ua.AddNodesRequest{
		NodesToAdd: []*ua.AddNodesItem{{
			ParentNodeID:       ua.NewExpandedNodeID(parent, "", 0),
			ReferenceTypeID:    ua.NewNumericNodeID(0, id.HasComponent),
			RequestedNewNodeID: ua.NewExpandedNodeID(newID, "", 0),
			BrowseName:         &ua.QualifiedName{NamespaceIndex: nsIdx, Name: "InteropAdded"},
			NodeClass:          ua.NodeClassVariable,
			NodeAttributes: &ua.ExtensionObject{
				TypeID:       ua.NewFourByteExpandedNodeID(0, id.VariableAttributesEncodingDefaultBinary),
				EncodingMask: ua.ExtensionObjectBinary,
				Value: &ua.VariableAttributes{
					SpecifiedAttributes: uint32(mask),
					DisplayName:         ua.NewLocalizedTextWithLocale("InteropAdded", "en"),
					Description:         &ua.LocalizedText{},
					Value:               ua.MustVariant(value),
					DataType:            ua.NewNumericNodeID(0, id.Int32),
					ValueRank:           -1,
					AccessLevel:         uint8(ua.AccessLevelTypeCurrentRead | ua.AccessLevelTypeCurrentWrite),
					UserAccessLevel:     uint8(ua.AccessLevelTypeCurrentRead | ua.AccessLevelTypeCurrentWrite),
				},
			},
			TypeDefinition: ua.NewNumericExpandedNodeID(0, id.BaseDataVariableType),
		}},
	}
}

// assertClientNodeManagement adds an Int32 Variable to the peer address space,
// reads the value the peer stored from VariableAttributes, deletes the node,
// and proves it is gone.
func assertClientNodeManagement(t *testing.T, endpoint string, deleteOnly bool) {
	t.Helper()
	c := dialClient(t, endpoint)
	ctx, nsIdx := findNS(t, c)
	parent := ua.NewStringNodeID(nsIdx, "Compatibility")
	newID := ua.NewStringNodeID(nsIdx, "Interop.GoAdded")

	add, err := c.AddNodes(ctx, addVariableRequest(nsIdx, parent, newID, 4242))
	if err != nil {
		t.Fatalf("AddNodes: %v", err)
	}
	if len(add.Results) != 1 || add.Results[0].StatusCode != ua.StatusOK {
		t.Fatalf("AddNodes result: %+v", add.Results)
	}
	added := add.Results[0].AddedNodeID
	if added == nil || added.String() != newID.String() {
		t.Fatalf("addedNodeId=%v, want %v", added, newID)
	}

	if !deleteOnly {
		dv, err := c.ReadValue(ctx, added)
		if err != nil {
			t.Fatalf("read added node: %v", err)
		}
		if dv.Status != ua.StatusOK || dv.Value == nil || dv.Value.Value() != int32(4242) {
			t.Fatalf("added node value=%v status=%v, want 4242 Good", dv.Value, dv.Status)
		}
		refs, err := c.BrowseAll(ctx, parent)
		if err != nil {
			t.Fatalf("browse parent: %v", err)
		}
		found := false
		for _, r := range refs {
			if r.BrowseName != nil && r.BrowseName.Name == "InteropAdded" {
				found = true
			}
		}
		if !found {
			t.Fatalf("added node not reachable from parent (%d refs)", len(refs))
		}
	}

	del, err := c.DeleteNodes(ctx, &ua.DeleteNodesRequest{
		NodesToDelete: []*ua.DeleteNodesItem{{NodeID: added, DeleteTargetReferences: true}},
	})
	if err != nil {
		t.Fatalf("DeleteNodes: %v", err)
	}
	if len(del.Results) != 1 || del.Results[0] != ua.StatusOK {
		t.Fatalf("DeleteNodes result: %v", del.Results)
	}
	gone, err := c.ReadValue(ctx, added)
	if err != nil {
		t.Fatalf("read after delete: %v", err)
	}
	if gone.Status != ua.StatusBadNodeIDUnknown {
		t.Fatalf("read after delete status=%v, want BadNodeIdUnknown", gone.Status)
	}

	// Deleting again must report the node as unknown.
	again, err := c.DeleteNodes(ctx, &ua.DeleteNodesRequest{
		NodesToDelete: []*ua.DeleteNodesItem{{NodeID: added, DeleteTargetReferences: true}},
	})
	if err != nil {
		t.Fatalf("second DeleteNodes: %v", err)
	}
	if len(again.Results) != 1 || again.Results[0] != ua.StatusBadNodeIDUnknown {
		t.Fatalf("second DeleteNodes result: %v, want BadNodeIdUnknown", again.Results)
	}
}

func TestOpen62541Server_AddNodes(t *testing.T) {
	t.Run("coverage/nodemgmt.add-nodes/go-client-to-open62541-server", func(t *testing.T) {
		h := startOpen62541Server(t)
		assertClientNodeManagement(t, h.endpoint, false)
	})
}

func TestOpen62541Server_DeleteNodes(t *testing.T) {
	t.Run("coverage/nodemgmt.delete-nodes/go-client-to-open62541-server", func(t *testing.T) {
		h := startOpen62541Server(t)
		assertClientNodeManagement(t, h.endpoint, true)
	})
}

// TestMiloServer_NodeManagementUnsupported pins the reason the C→M
// node-management rows are `unsupported`: the Milo reference server does not
// implement the NodeManagement service set.
func TestMiloServer_NodeManagementUnsupported(t *testing.T) {
	h := startMiloServer(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)
	parent := ua.NewStringNodeID(nsIdx, "Compatibility")
	newID := ua.NewStringNodeID(nsIdx, "Interop.GoAdded")

	add, err := c.AddNodes(ctx, addVariableRequest(nsIdx, parent, newID, 1))
	if err == nil && len(add.Results) == 1 && add.Results[0].StatusCode == ua.StatusOK {
		t.Fatal("Milo accepted AddNodes: promote nodemgmt.add-nodes C→M from unsupported to a verified test")
	}
	if err != nil {
		t.Logf("Milo AddNodes rejected as expected: %v", err)
		return
	}
	for _, r := range add.Results {
		t.Logf("Milo AddNodes rejected as expected: item status %v", r.StatusCode)
	}
}

type nodeManagementResult struct {
	RequestedNodeID           string          `json:"requestedNodeId"`
	AddStatusCode             statusCodeObj   `json:"addStatusCode"`
	AddedNodeID               string          `json:"addedNodeId"`
	ReadStatusCode            statusCodeObj   `json:"readStatusCode"`
	Value                     json.RawMessage `json:"value"`
	DeleteStatusCode          statusCodeObj   `json:"deleteStatusCode"`
	ReadAfterDeleteStatusCode statusCodeObj   `json:"readAfterDeleteStatusCode"`
}

func runPeerNodeManagement(t *testing.T, imageEnv, defaultImage string, run func(*testing.T, string, string, ...string) adapterResult) nodeManagementResult {
	t.Helper()
	requireAdapterOp(t, imageEnv, defaultImage, "node-management")
	endpoint := startGoServer(t)
	result := run(t, endpoint, "node-management",
		"--parent", "i=85",
		"--node", "nsu="+interopNamespaceURI+";s=Interop.PeerAdded",
		"--browse-name", "PeerAdded",
		"--value", "4242",
	)
	var items []nodeManagementResult
	if err := json.Unmarshal(result.Results, &items); err != nil || len(items) != 1 {
		t.Fatalf("unexpected node-management results (%v) serviceResult=%s error=%+v: %s",
			err, result.ServiceResult, result.Error, result.Results)
	}
	if !result.Success {
		t.Fatalf("node-management failed: serviceResult=%s item=%+v", result.ServiceResult, items[0])
	}
	return items[0]
}

func assertPeerAddNodes(t *testing.T, imageEnv, defaultImage string, run func(*testing.T, string, string, ...string) adapterResult) {
	t.Helper()
	it := runPeerNodeManagement(t, imageEnv, defaultImage, run)
	if !statusCodeIs(it.AddStatusCode, ua.StatusOK) {
		t.Fatalf("addStatusCode=%s", it.AddStatusCode)
	}
	if it.AddedNodeID == "" || it.AddedNodeID != it.RequestedNodeID {
		t.Fatalf("addedNodeId=%q, want requested %q", it.AddedNodeID, it.RequestedNodeID)
	}
	if !statusCodeIs(it.ReadStatusCode, ua.StatusOK) || string(it.Value) != "4242" {
		t.Fatalf("read-back status=%s value=%s, want Good 4242", it.ReadStatusCode, it.Value)
	}
}

func assertPeerDeleteNodes(t *testing.T, imageEnv, defaultImage string, run func(*testing.T, string, string, ...string) adapterResult) {
	t.Helper()
	it := runPeerNodeManagement(t, imageEnv, defaultImage, run)
	if !statusCodeIs(it.DeleteStatusCode, ua.StatusOK) {
		t.Fatalf("deleteStatusCode=%s", it.DeleteStatusCode)
	}
	if !statusCodeIs(it.ReadAfterDeleteStatusCode, ua.StatusBadNodeIDUnknown) {
		t.Fatalf("readAfterDelete=%s, want BadNodeIdUnknown", it.ReadAfterDeleteStatusCode)
	}
}

func TestGoServer_Open62541Client_AddNodes(t *testing.T) {
	t.Run("coverage/nodemgmt.add-nodes/open62541-to-go-server", func(t *testing.T) {
		assertPeerAddNodes(t, "OPEN62541_IMAGE", defaultOpen62541Image, runOpen62541ClientResult)
	})
}

func TestGoServer_MiloClient_AddNodes(t *testing.T) {
	t.Run("coverage/nodemgmt.add-nodes/milo-to-go-server", func(t *testing.T) {
		assertPeerAddNodes(t, "MILO_IMAGE", defaultMiloImage, runMiloClientResult)
	})
}

func TestGoServer_Open62541Client_DeleteNodes(t *testing.T) {
	t.Run("coverage/nodemgmt.delete-nodes/open62541-to-go-server", func(t *testing.T) {
		assertPeerDeleteNodes(t, "OPEN62541_IMAGE", defaultOpen62541Image, runOpen62541ClientResult)
	})
}

func TestGoServer_MiloClient_DeleteNodes(t *testing.T) {
	t.Run("coverage/nodemgmt.delete-nodes/milo-to-go-server", func(t *testing.T) {
		assertPeerDeleteNodes(t, "MILO_IMAGE", defaultMiloImage, runMiloClientResult)
	})
}

// ---------------------------------------------------------------------------
// Subscription / MonitoredItem modify services — Go client → peer server
// ---------------------------------------------------------------------------

func startCounterSubscription(t *testing.T, endpoint string) (context.Context, *opcua.Client, *opcua.Subscription, chan *opcua.PublishNotificationData, uint32) {
	t.Helper()
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	sub, notifyCh, err := c.NewSubscription().Interval(250 * time.Millisecond).Start(ctx)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Cancel(context.Background()) })

	mon, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth,
		opcua.NewMonitoredItemCreateRequestWithDefaults(ua.NewStringNodeID(nsIdx, "Dynamic.Counter"), ua.AttributeIDValue, 7))
	if err != nil {
		t.Fatalf("monitor: %v", err)
	}
	if len(mon.Results) != 1 || mon.Results[0].StatusCode != ua.StatusOK {
		t.Fatalf("monitor result: %+v", mon.Results)
	}
	awaitCounterAdvance(t, notifyCh, -1, 15*time.Second, "initial")
	return ctx, c, sub, notifyCh, mon.Results[0].MonitoredItemID
}

// quietFor reports whether no data change arrives for the given window.
func quietFor(notifyCh <-chan *opcua.PublishNotificationData, window time.Duration) (bool, int) {
	deadline := time.After(window)
	n := 0
	for {
		select {
		case msg := <-notifyCh:
			if msg == nil || msg.Error != nil {
				continue
			}
			if dcn, ok := msg.Value.(*ua.DataChangeNotification); ok && dcn != nil {
				n += len(dcn.MonitoredItems)
			}
		case <-deadline:
			return n == 0, n
		}
	}
}

func assertClientModifySubscription(t *testing.T, endpoint string) {
	t.Helper()
	ctx, _, sub, notifyCh, _ := startCounterSubscription(t, endpoint)

	resp, err := sub.ModifySubscription(ctx, opcua.SubscriptionParameters{
		Interval:          1 * time.Second,
		LifetimeCount:     60,
		MaxKeepAliveCount: 5,
	})
	if err != nil {
		t.Fatalf("ModifySubscription: %v", err)
	}
	if resp.ResponseHeader == nil || resp.ResponseHeader.ServiceResult != ua.StatusOK {
		t.Fatalf("ModifySubscription header: %+v", resp.ResponseHeader)
	}
	if resp.RevisedPublishingInterval != 1000 {
		t.Fatalf("revisedPublishingInterval=%v, want 1000", resp.RevisedPublishingInterval)
	}
	if resp.RevisedMaxKeepAliveCount != 5 {
		t.Fatalf("revisedMaxKeepAliveCount=%d, want 5", resp.RevisedMaxKeepAliveCount)
	}
	if resp.RevisedLifetimeCount < 3*resp.RevisedMaxKeepAliveCount {
		t.Fatalf("revisedLifetimeCount=%d < 3×keepAlive(%d)", resp.RevisedLifetimeCount, resp.RevisedMaxKeepAliveCount)
	}
	// The modified subscription keeps delivering.
	v := awaitCounterAdvance(t, notifyCh, -1, 15*time.Second, "after modify")
	awaitCounterAdvance(t, notifyCh, v, 15*time.Second, "after modify")

	// Disabling publishing silences it; re-enabling resumes delivery.
	pm, err := sub.SetPublishingMode(ctx, false)
	if err != nil || len(pm.Results) != 1 || pm.Results[0] != ua.StatusOK {
		t.Fatalf("SetPublishingMode(false): %v %+v", err, pm)
	}
	quietFor(notifyCh, 1500*time.Millisecond) // drain anything already in flight
	if quiet, n := quietFor(notifyCh, 3*time.Second); !quiet {
		t.Fatalf("received %d data changes while publishing was disabled", n)
	}
	pm, err = sub.SetPublishingMode(ctx, true)
	if err != nil || len(pm.Results) != 1 || pm.Results[0] != ua.StatusOK {
		t.Fatalf("SetPublishingMode(true): %v %+v", err, pm)
	}
	awaitCounterAdvance(t, notifyCh, v, 15*time.Second, "after re-enable")
}

func assertClientModifyMonitoredItems(t *testing.T, endpoint string) {
	t.Helper()
	ctx, _, sub, notifyCh, itemID := startCounterSubscription(t, endpoint)

	resp, err := sub.ModifyMonitoredItems(ctx, ua.TimestampsToReturnBoth, &ua.MonitoredItemModifyRequest{
		MonitoredItemID: itemID,
		RequestedParameters: &ua.MonitoringParameters{
			ClientHandle:     99,
			SamplingInterval: 500,
			QueueSize:        4,
			DiscardOldest:    true,
		},
	})
	if err != nil {
		t.Fatalf("ModifyMonitoredItems: %v", err)
	}
	if len(resp.Results) != 1 || resp.Results[0].StatusCode != ua.StatusOK {
		t.Fatalf("ModifyMonitoredItems result: %+v", resp.Results)
	}
	if resp.Results[0].RevisedQueueSize != 4 {
		t.Fatalf("revisedQueueSize=%d, want 4", resp.Results[0].RevisedQueueSize)
	}
	if resp.Results[0].RevisedSamplingInterval <= 0 {
		t.Fatalf("revisedSamplingInterval=%v", resp.Results[0].RevisedSamplingInterval)
	}

	// Notifications must now carry the new ClientHandle.
	deadline := time.After(20 * time.Second)
	for {
		select {
		case msg := <-notifyCh:
			if msg == nil || msg.Error != nil {
				continue
			}
			dcn, ok := msg.Value.(*ua.DataChangeNotification)
			if !ok || dcn == nil {
				continue
			}
			for _, mi := range dcn.MonitoredItems {
				if mi.ClientHandle == 99 {
					goto modified
				}
			}
		case <-deadline:
			t.Fatal("no notification with the modified ClientHandle within 20s")
		}
	}
modified:
}

func assertClientSetMonitoringMode(t *testing.T, endpoint string) {
	t.Helper()
	ctx, _, sub, notifyCh, itemID := startCounterSubscription(t, endpoint)

	for _, mode := range []ua.MonitoringMode{ua.MonitoringModeDisabled, ua.MonitoringModeSampling} {
		resp, err := sub.SetMonitoringMode(ctx, mode, itemID)
		if err != nil || len(resp.Results) != 1 || resp.Results[0] != ua.StatusOK {
			t.Fatalf("SetMonitoringMode(%v): %v %+v", mode, err, resp)
		}
		quietFor(notifyCh, 1500*time.Millisecond) // drain anything already in flight
		if quiet, n := quietFor(notifyCh, 3*time.Second); !quiet {
			t.Fatalf("received %d data changes in mode %v", n, mode)
		}
	}

	resp, err := sub.SetMonitoringMode(ctx, ua.MonitoringModeReporting, itemID)
	if err != nil || len(resp.Results) != 1 || resp.Results[0] != ua.StatusOK {
		t.Fatalf("SetMonitoringMode(Reporting): %v %+v", err, resp)
	}
	v := awaitCounterAdvance(t, notifyCh, -1, 15*time.Second, "after Reporting")
	awaitCounterAdvance(t, notifyCh, v, 15*time.Second, "after Reporting")
}

func TestOpen62541Server_ModifySubscription(t *testing.T) {
	t.Run("coverage/subscription.modify/go-client-to-open62541-server", func(t *testing.T) {
		assertClientModifySubscription(t, startOpen62541Server(t).endpoint)
	})
}

func TestMiloServer_ModifySubscription(t *testing.T) {
	t.Run("coverage/subscription.modify/go-client-to-milo-server", func(t *testing.T) {
		assertClientModifySubscription(t, startMiloServer(t).endpoint)
	})
}

func TestOpen62541Server_ModifyMonitoredItems(t *testing.T) {
	t.Run("coverage/monitoreditem.modify/go-client-to-open62541-server", func(t *testing.T) {
		assertClientModifyMonitoredItems(t, startOpen62541Server(t).endpoint)
	})
}

func TestMiloServer_ModifyMonitoredItems(t *testing.T) {
	t.Run("coverage/monitoreditem.modify/go-client-to-milo-server", func(t *testing.T) {
		assertClientModifyMonitoredItems(t, startMiloServer(t).endpoint)
	})
}

func TestOpen62541Server_SetMonitoringMode(t *testing.T) {
	t.Run("coverage/monitoreditem.monitoring-mode/go-client-to-open62541-server", func(t *testing.T) {
		assertClientSetMonitoringMode(t, startOpen62541Server(t).endpoint)
	})
}

func TestMiloServer_SetMonitoringMode(t *testing.T) {
	t.Run("coverage/monitoreditem.monitoring-mode/go-client-to-milo-server", func(t *testing.T) {
		assertClientSetMonitoringMode(t, startMiloServer(t).endpoint)
	})
}

// ---------------------------------------------------------------------------
// EventFilter WhereClause comparison operators — Go client → peer server
// ---------------------------------------------------------------------------

// whereProbe is one WhereClause over the peer BaseEvent (Severity 500,
// emitted every ~2 s) together with whether it must let the event through.
type whereProbe struct {
	name  string
	where *ua.ContentFilterElement
	match bool
}

func severityWhereProbes() []whereProbe {
	sev := func() *ua.FieldOperand { return ua.Field("Severity") }
	return []whereProbe{
		{"Equals(500)", sev().Equals(uint16(500)), true},
		{"Equals(499)", sev().Equals(uint16(499)), false},
		{"GreaterThan(499)", sev().GreaterThan(uint16(499)), true},
		{"GreaterThan(500)", sev().GreaterThan(uint16(500)), false},
		{"LessThan(501)", sev().LessThan(uint16(501)), true},
		{"LessThan(500)", sev().LessThan(uint16(500)), false},
		{"GreaterThanOrEqual(500)", sev().GreaterThanOrEqual(uint16(500)), true},
		{"GreaterThanOrEqual(501)", sev().GreaterThanOrEqual(uint16(501)), false},
		{"LessThanOrEqual(500)", sev().LessThanOrEqual(uint16(500)), true},
		{"LessThanOrEqual(499)", sev().LessThanOrEqual(uint16(499)), false},
	}
}

// assertPeerEventWhereClause installs one event monitored item per probe on a
// single subscription and observes several emission periods: every matching
// filter must deliver the event and every non-matching filter must stay
// silent. A peer that ignores the WhereClause fails the negative probes.
func assertPeerEventWhereClause(t *testing.T, endpoint string) {
	t.Helper()
	c := dialClient(t, endpoint)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, nsIdx := findNS(t, c)
	source := ua.NewStringNodeID(nsIdx, "Events.Source")

	notifyCh := make(chan *opcua.PublishNotificationData, 256)
	sub, _, err := c.NewSubscription().
		Interval(200 * time.Millisecond).
		NotifyChannel(notifyCh).
		Start(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Cancel(context.Background()) })

	probes := severityWhereProbes()
	reqs := make([]*ua.MonitoredItemCreateRequest, len(probes))
	for i, p := range probes {
		filter := ua.NewEventFilter().Select("EventId", "Severity").Where(p.where).Build()
		reqs[i] = &ua.MonitoredItemCreateRequest{
			ItemToMonitor:  &ua.ReadValueID{NodeID: source, AttributeID: ua.AttributeIDEventNotifier},
			MonitoringMode: ua.MonitoringModeReporting,
			RequestedParameters: &ua.MonitoringParameters{
				ClientHandle:  uint32(100 + i),
				Filter:        ua.NewExtensionObject(filter),
				QueueSize:     10,
				DiscardOldest: true,
			},
		}
	}
	monResp, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, reqs...)
	if err != nil {
		t.Fatalf("Monitor: %v", err)
	}
	if len(monResp.Results) != len(probes) {
		t.Fatalf("monitor results=%d, want %d", len(monResp.Results), len(probes))
	}
	for i, r := range monResp.Results {
		if r.StatusCode != ua.StatusOK {
			t.Fatalf("%s: CreateMonitoredItems status=%v", probes[i].name, r.StatusCode)
		}
	}

	// Four emission periods: enough for every matching filter to fire more
	// than once and for a leaking non-matching filter to show up.
	got := make([]int, len(probes))
	window := time.After(9 * time.Second)
collect:
	for {
		select {
		case msg, ok := <-notifyCh:
			if !ok {
				t.Fatal("notify channel closed")
			}
			if msg.Error != nil {
				t.Fatalf("notification error: %v", msg.Error)
			}
			enl, ok := msg.Value.(*ua.EventNotificationList)
			if !ok || enl == nil {
				continue
			}
			for _, ev := range enl.Events {
				idx := int(ev.ClientHandle) - 100
				if idx < 0 || idx >= len(probes) {
					t.Fatalf("event for unknown client handle %d", ev.ClientHandle)
				}
				if len(ev.EventFields) != 2 {
					t.Fatalf("%s: %d event fields, want 2", probes[idx].name, len(ev.EventFields))
				}
				if sev, ok := ev.EventFields[1].Value().(uint16); !ok || sev != 500 {
					t.Fatalf("%s: Severity=%v, want 500", probes[idx].name, ev.EventFields[1].Value())
				}
				got[idx]++
			}
		case <-window:
			break collect
		}
	}

	for i, p := range probes {
		switch {
		case p.match && got[i] == 0:
			t.Errorf("%s: no event delivered although the filter matches", p.name)
		case !p.match && got[i] != 0:
			t.Errorf("%s: %d events delivered although the filter does not match", p.name, got[i])
		}
	}
	t.Logf("events per probe: %v", got)
}

func TestOpen62541Server_EventFilterWhereClause(t *testing.T) {
	t.Run("coverage/event.filter.where-clause/go-client-to-open62541-server", func(t *testing.T) {
		h := startOpen62541Server(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		assertPeerEventWhereClause(t, h.endpoint)
	})
}

func TestMiloServer_EventFilterWhereClause(t *testing.T) {
	t.Run("coverage/event.filter.where-clause/go-client-to-milo-server", func(t *testing.T) {
		h := startMiloServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		assertPeerEventWhereClause(t, h.endpoint)
	})
}

// ---------------------------------------------------------------------------
// Publishing / monitoring mode lifecycle — peer client → Go server
// ---------------------------------------------------------------------------

type publishingModeResult struct {
	SubscriptionID uint32  `json:"subscriptionId"`
	Overflow       bool    `json:"overflow"`
	Values         []int32 `json:"values"`
}

// assertPeerPublishingMode runs the adapter scenario that disables publishing,
// writes 1..5 into a queue of 3, re-enables publishing and collects what the Go
// server kept: exactly the newest three values, with the overflow bit set.
//
// The expectation holds when every write is sampled. Since opcua-interop
// v0.7.0 the adapters create the monitored item with SamplingInterval 0
// (report every change), so the five back-to-back writes are five samples
// whatever the server's sampling rate; before that they asked for 100 ms, and
// a server that honours the sampling interval (go-opcua since v1.6.0)
// coalesced the burst.
func assertPeerPublishingMode(t *testing.T, run func(*testing.T, string, string, ...string) adapterResult) {
	t.Helper()
	endpoint := startGoServer(t)
	result := run(t, endpoint, "subscription-lifecycle",
		"--node", "nsu="+interopNamespaceURI+";s=Access.ReadWrite",
		"--scenario", "publishing-mode",
		"--timeout-ms", "20000",
	)
	var items []publishingModeResult
	if err := json.Unmarshal(result.Results, &items); err != nil || len(items) != 1 {
		t.Fatalf("publishing-mode: success=%v serviceResult=%s error=%+v; parse results (%v): %s",
			result.Success, result.ServiceResult, result.Error, err, result.Results)
	}
	if !result.Success {
		t.Fatalf("publishing-mode failed: serviceResult=%s error=%+v raw=%s", result.ServiceResult, result.Error, result.Results)
	}
	got := items[0].Values
	if len(got) < 3 || got[len(got)-3] != 3 || got[len(got)-2] != 4 || got[len(got)-1] != 5 {
		t.Fatalf("values=%v, want the window [3 4 5] (newest 3 of 5 writes)", got)
	}
	if !items[0].Overflow {
		t.Errorf("overflow bit not reported although 5 writes went into a queue of 3")
	}
}

type monitoringModeResult struct {
	ModeSteps []struct {
		Mode              string `json:"mode"`
		NotificationCount int    `json:"notificationCount"`
	} `json:"modeSteps"`
}

// assertPeerMonitoringMode runs the adapter scenario that steps a monitored
// item through Disabled → Sampling → Reporting on the Go server: only
// Reporting may produce notifications.
func assertPeerMonitoringMode(t *testing.T, run func(*testing.T, string, string, ...string) adapterResult) {
	t.Helper()
	endpoint := startGoServer(t)
	result := run(t, endpoint, "subscription-lifecycle",
		"--node", "nsu="+interopNamespaceURI+";s=Access.ReadWrite",
		"--scenario", "monitoring-mode",
		"--timeout-ms", "20000",
	)
	if !result.Success {
		t.Fatalf("monitoring-mode failed: serviceResult=%s error=%+v raw=%s", result.ServiceResult, result.Error, result.Results)
	}
	var items []monitoringModeResult
	if err := json.Unmarshal(result.Results, &items); err != nil || len(items) != 1 {
		t.Fatalf("parse monitoring-mode results (%v): %s", err, result.Results)
	}
	counts := map[string]int{}
	for _, s := range items[0].ModeSteps {
		counts[s.Mode] = s.NotificationCount
	}
	if len(counts) != 3 {
		t.Fatalf("modeSteps=%+v, want Disabled, Sampling and Reporting", items[0].ModeSteps)
	}
	if counts["Disabled"] != 0 {
		t.Errorf("Disabled delivered %d notifications, want 0", counts["Disabled"])
	}
	if counts["Sampling"] != 0 {
		t.Errorf("Sampling delivered %d notifications, want 0", counts["Sampling"])
	}
	if counts["Reporting"] < 1 {
		t.Errorf("Reporting delivered %d notifications, want ≥ 1", counts["Reporting"])
	}
}

func TestGoServer_Open62541Client_SubscriptionLifecycle_PublishingMode(t *testing.T) {
	t.Run("coverage/subscription.publishing-mode/open62541-to-go-server", func(t *testing.T) {
		assertPeerPublishingMode(t, runOpen62541ClientResult)
	})
}

func TestGoServer_MiloClient_SubscriptionLifecycle_PublishingMode(t *testing.T) {
	t.Run("coverage/subscription.publishing-mode/milo-to-go-server", func(t *testing.T) {
		assertPeerPublishingMode(t, runMiloClientResult)
	})
}

func TestGoServer_Open62541Client_SubscriptionLifecycle_MonitoringMode(t *testing.T) {
	t.Run("coverage/monitoreditem.monitoring-mode/open62541-to-go-server", func(t *testing.T) {
		assertPeerMonitoringMode(t, runOpen62541ClientResult)
	})
}

func TestGoServer_MiloClient_SubscriptionLifecycle_MonitoringMode(t *testing.T) {
	t.Run("coverage/monitoreditem.monitoring-mode/milo-to-go-server", func(t *testing.T) {
		assertPeerMonitoringMode(t, runMiloClientResult)
	})
}

// ---------------------------------------------------------------------------
// Event severity filter, non-matching — peer client → Go server
// ---------------------------------------------------------------------------

// assertPeerEventSeverityRejects is the negative half of the severity
// threshold evidence: the Go server emits Severity 500 events throughout, and
// a peer filter of Severity ≥ 600 must see none of them.
func assertPeerEventSeverityRejects(t *testing.T, run func(*testing.T, string, string, ...string) adapterResult) {
	t.Helper()
	endpoint, srv := startGoServerWithEvents(t)
	_, nsIdx := findNSFromServer(t, srv)
	pulsePeerEvents(t, srv, ua.NewStringNodeID(nsIdx, "Events.Source"))

	result := run(t, endpoint, "event-subscribe",
		"--node", "nsu="+interopNamespaceURI+";s=Events.Source",
		"--events", "1",
		"--timeout-ms", "8000",
		"--min-severity", "600",
	)
	if result.Success {
		t.Fatalf("event-subscribe succeeded: the Go server delivered a Severity 500 event through a ≥ 600 filter: %s", result.Results)
	}
	var items []eventSubscribeItem
	if err := json.Unmarshal(result.Results, &items); err != nil || len(items) != 1 {
		t.Fatalf("parse event-subscribe results (%v) serviceResult=%s error=%+v: %s", err, result.ServiceResult, result.Error, result.Results)
	}
	if !statusCodeIs(items[0].MonitoredItem, ua.StatusOK) {
		t.Fatalf("monitored item status=%s: the filter was rejected instead of evaluated", items[0].MonitoredItem)
	}
	if n := len(items[0].Events); n != 0 {
		t.Fatalf("%d events passed a Severity ≥ 600 filter", n)
	}
}

func TestGoServer_Open62541Client_EventFilterSeverityRejects(t *testing.T) {
	requireAdapterOp(t, "OPEN62541_IMAGE", defaultOpen62541Image, "event-subscribe")
	assertPeerEventSeverityRejects(t, runOpen62541ClientResult)
}

func TestGoServer_MiloClient_EventFilterSeverityRejects(t *testing.T) {
	requireAdapterOp(t, "MILO_IMAGE", defaultMiloImage, "event-subscribe")
	assertPeerEventSeverityRejects(t, runMiloClientResult)
}

// ---------------------------------------------------------------------------
// Event queue overflow — Go client → peer server
// ---------------------------------------------------------------------------

// assertPeerEventQueueOverflow lets several peer events (one every ~2 s) pile
// up in a queue of two behind a 9 s publishing interval. The peer must report
// the loss with an EventQueueOverflowEventType event ahead of the two events it
// kept (Part 4 §5.12.1.5), and the client must decode that mixed batch.
func assertPeerEventQueueOverflow(t *testing.T, endpoint string) {
	t.Helper()
	c := dialClient(t, endpoint)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, nsIdx := findNS(t, c)

	notifyCh := make(chan *opcua.PublishNotificationData, 64)
	sub, _, err := c.NewSubscription().
		Interval(9 * time.Second).
		NotifyChannel(notifyCh).
		Start(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Cancel(context.Background()) })

	const queueSize = 2
	filter := ua.NewEventFilter().Select("EventType", "Severity").Build()
	resp, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, &ua.MonitoredItemCreateRequest{
		ItemToMonitor:  &ua.ReadValueID{NodeID: ua.NewStringNodeID(nsIdx, "Events.Source"), AttributeID: ua.AttributeIDEventNotifier},
		MonitoringMode: ua.MonitoringModeReporting,
		RequestedParameters: &ua.MonitoringParameters{
			ClientHandle:  1,
			Filter:        ua.NewExtensionObject(filter),
			QueueSize:     queueSize,
			DiscardOldest: true,
		},
	})
	if err != nil {
		t.Fatalf("Monitor: %v", err)
	}
	if len(resp.Results) != 1 || resp.Results[0].StatusCode != ua.StatusOK {
		t.Fatalf("monitor result: %+v", resp.Results)
	}
	if resp.Results[0].RevisedQueueSize != queueSize {
		t.Fatalf("revisedQueueSize=%d, want %d", resp.Results[0].RevisedQueueSize, queueSize)
	}

	overflowType := ua.NewNumericNodeID(0, id.EventQueueOverflowEventType)
	deadline := time.After(30 * time.Second)
	for {
		select {
		case msg, ok := <-notifyCh:
			if !ok {
				t.Fatal("notify channel closed")
			}
			if msg.Error != nil {
				t.Fatalf("notification error: %v", msg.Error)
			}
			enl, ok := msg.Value.(*ua.EventNotificationList)
			if !ok || enl == nil || len(enl.Events) == 0 {
				continue
			}
			if len(enl.Events) != queueSize+1 {
				t.Fatalf("batch of %d events, want overflow event + %d queued", len(enl.Events), queueSize)
			}
			for i, ev := range enl.Events {
				if len(ev.EventFields) != 2 {
					t.Fatalf("event %d: %d fields, want 2", i, len(ev.EventFields))
				}
				typ, ok := ev.EventFields[0].Value().(*ua.NodeID)
				if !ok {
					t.Fatalf("event %d: EventType is %T", i, ev.EventFields[0].Value())
				}
				isOverflow := typ.String() == overflowType.String()
				if i == 0 && !isOverflow {
					t.Fatalf("first event type=%v, want EventQueueOverflowEventType (%v)", typ, overflowType)
				}
				if i > 0 {
					if isOverflow {
						t.Fatalf("event %d is a second overflow event", i)
					}
					if sev, ok := ev.EventFields[1].Value().(uint16); !ok || sev != 500 {
						t.Fatalf("event %d: Severity=%v, want 500", i, ev.EventFields[1].Value())
					}
				}
			}
			return
		case <-deadline:
			t.Fatal("no event batch within 30s")
		}
	}
}

func TestOpen62541Server_EventQueueOverflow(t *testing.T) {
	t.Run("coverage/event.queue-overflow/go-client-to-open62541-server", func(t *testing.T) {
		h := startOpen62541Server(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		assertPeerEventQueueOverflow(t, h.endpoint)
	})
}

func TestMiloServer_EventQueueOverflow(t *testing.T) {
	t.Run("coverage/event.queue-overflow/go-client-to-milo-server", func(t *testing.T) {
		h := startMiloServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		assertPeerEventQueueOverflow(t, h.endpoint)
	})
}
