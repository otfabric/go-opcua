//go:build interop

// SPDX-License-Identifier: MIT

// Reverse connect (Part 6 §7.1.3) peer evidence.
// COVERAGE.md: transport / transport.reverse-connect.client (Go client
// listening ← peer server dialling), transport.reverse-connect.server (Go
// server dialling → peer client listening).
//
// The adapter images advertise the two halves in print-capabilities as
// serverFeatures: ["reverse-connect"] (server flag --reverse-connect <url>)
// and clientFeatures: ["reverse-listen"] (client flag --reverse-listen <port>).
// A test is skipped when the image under test does not advertise its half.
//
// Milo 1.1.8 implements neither half (its transport knows no ReverseHello
// message), so there are no Milo tests.

package interop

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
)

const (
	// reverseDialTimeout bounds how long a Go client waits for a peer server
	// to connect. open62541 retries a reverse connection every 15 seconds
	// unless configured otherwise, so it must cover a few of those intervals.
	reverseDialTimeout = 90 * time.Second

	// adapterReverseListenPort is the port an adapter client listens on
	// inside its container; it is published on a free host port.
	adapterReverseListenPort = 4841
)

// startAdapterReverseServer starts an adapter container in server mode that
// opens reverse connections to the consumer's listener on the given host
// port. Unlike startAdapterServer it publishes no port: the only way to
// reach the server is the connection it opens itself.
func startAdapterReverseServer(t *testing.T, imageEnvVar, defaultImage string, clientPort int) {
	t.Helper()
	requireOptionalPeer(t, imageEnvVar, defaultImage)

	image := getEnvOr(imageEnvVar, defaultImage)
	containerName := dockerContainerName(t)
	fixtureDir := getEnvOr("OPCUA_INTEROP_FIXTURE_DIR", defaultFixtureDir)
	if !strings.HasPrefix(fixtureDir, "/") {
		cwd, err := os.Getwd()
		if err != nil {
			t.Fatalf("getwd: %v", err)
		}
		fixtureDir = cwd + "/" + fixtureDir
	}

	cmdCtx, cmdCancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(cmdCtx, "docker", "run", "--rm",
		"--name", containerName,
		"--add-host=host.docker.internal:host-gateway",
		"-v", fixtureDir+":/fixtures:ro",
		image,
		"server",
		"--fixture", "/fixtures/baseline.json",
		"--reverse-connect", fmt.Sprintf("opc.tcp://host.docker.internal:%d", clientPort),
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		cmdCancel()
		t.Fatalf("start adapter reverse server (%s): %v", image, err)
	}
	stop := func() {
		dockerStop(containerName)
		cmdCancel()
		_ = cmd.Wait()
	}
	t.Cleanup(stop)

	startCtx, startCancel := context.WithTimeout(context.Background(), serverReadyTimeout)
	defer startCancel()
	for exec.CommandContext(startCtx, "docker", "exec",
		containerName, "test", "-f", "/run/opcua-interop/ready").Run() != nil {
		select {
		case <-startCtx.Done():
			t.Fatalf("timed out waiting for adapter server (container: %s)", containerName)
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// runAdapterReverseClient runs an adapter container in client mode that does
// not connect to the server but listens for its reverse connection. The
// adapter's listen port is published on hostPort, which is where the server
// has to connect to. endpoint is the endpoint URL the server announces.
func runAdapterReverseClient(t *testing.T, imageEnvVar, defaultImage, endpoint string, hostPort int, subcmd string, args ...string) adapterResult {
	t.Helper()
	return runAdapterReverseClientWith(t, imageEnvVar, defaultImage, endpoint, hostPort, nil, subcmd, args...)
}

// runAdapterReverseClientWith is runAdapterReverseClient with extra
// `docker run` arguments (certificate mounts).
func runAdapterReverseClientWith(t *testing.T, imageEnvVar, defaultImage, endpoint string, hostPort int, dockerArgs []string, subcmd string, args ...string) adapterResult {
	t.Helper()
	requireOptionalPeer(t, imageEnvVar, defaultImage)

	image := getEnvOr(imageEnvVar, defaultImage)
	containerName := dockerContainerName(t) + "-" + subcmd
	dockerEndpoint := strings.ReplaceAll(endpoint, "localhost", "host.docker.internal")

	cmdArgs := []string{"run", "--rm",
		"--name", containerName,
		"-p", fmt.Sprintf("%d:%d", hostPort, adapterReverseListenPort),
		"--add-host=host.docker.internal:host-gateway",
	}
	cmdArgs = append(cmdArgs, dockerArgs...)
	cmdArgs = append(cmdArgs, image,
		"client", subcmd, "--endpoint", dockerEndpoint,
		"--reverse-listen", strconv.Itoa(adapterReverseListenPort),
	)
	cmdArgs = append(cmdArgs, args...)

	ctx, cancel := context.WithTimeout(context.Background(), reverseDialTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", cmdArgs...)
	cmd.Stderr = os.Stderr
	t.Cleanup(func() { dockerStop(containerName) })

	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("adapter reverse client %q (%s): %v\noutput: %s", subcmd, image, err, raw)
	}
	result, err := parseAdapterOutput(raw)
	if err != nil {
		t.Fatalf("parse adapter client output: %v\nraw: %s", err, raw)
	}
	return result
}

// connectionCounter is a log handler that counts how the connections of a Go
// server came about: accepted from a client or opened by the server.
type connectionCounter struct {
	accepted atomic.Int64
	reverse  atomic.Int64
}

func (c *connectionCounter) Enabled(context.Context, slog.Level) bool { return true }
func (c *connectionCounter) WithAttrs([]slog.Attr) slog.Handler       { return c }
func (c *connectionCounter) WithGroup(string) slog.Handler            { return c }
func (c *connectionCounter) Handle(_ context.Context, r slog.Record) error {
	switch r.Message {
	case "registered connection":
		c.accepted.Add(1)
	case "registered reverse connection":
		c.reverse.Add(1)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Go client listening ← open62541 server dialling
// ---------------------------------------------------------------------------

// TestOpen62541Server_ReverseConnect verifies the client half of reverse
// connect against open62541: the peer server connects to the Go client's
// listener and announces itself, and the client reads, subscribes and runs
// discovery over the connections the server opened.
func TestOpen62541Server_ReverseConnect(t *testing.T) {
	requireAdapterFeature(t, "OPEN62541_IMAGE", defaultOpen62541Image, "serverFeatures", "reverse-connect")

	// Record what the server announces.
	var mu sync.Mutex
	var hellos []uacp.ReverseHello
	l, err := uacp.ListenReverse(context.Background(), "0.0.0.0:0", &uacp.ReverseListenerConfig{
		Filter: func(rhe *uacp.ReverseHello) error {
			mu.Lock()
			hellos = append(hellos, *rhe)
			mu.Unlock()
			return nil
		},
	})
	if err != nil {
		t.Fatalf("ListenReverse: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	startAdapterReverseServer(t, "OPEN62541_IMAGE", defaultOpen62541Image, l.Addr().(*net.TCPAddr).Port)

	ctx, cancel := context.WithTimeout(context.Background(), 2*reverseDialTimeout)
	defer cancel()

	// The client has no endpoint URL of its own: the server is not reachable
	// from here, so the one it announces is used.
	base := []opcua.Option{
		opcua.SecurityModeString("None"),
		opcua.AuthAnonymous(),
		opcua.DialTimeout(reverseDialTimeout),
		opcua.AutoReconnect(false),
	}
	c, err := opcua.NewClient("", append(base, opcua.ReverseConnectListener(l))...)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("Connect over reverse connection: %v", err)
	}
	t.Cleanup(func() {
		ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel2()
		_ = c.Close(ctx2)
	})

	// The server announced itself under the ApplicationUri it reports in
	// its endpoint descriptions, with the URL of the endpoint in use.
	mu.Lock()
	if len(hellos) == 0 {
		mu.Unlock()
		t.Fatal("no ReverseHello recorded")
	}
	rhe := hellos[len(hellos)-1]
	mu.Unlock()
	t.Logf("ReverseHello: ServerUri=%q EndpointUrl=%q", rhe.ServerURI, rhe.EndpointURL)
	eps := c.Session().ServerEndpoints()
	if len(eps) == 0 {
		t.Fatal("no server endpoints in the session")
	}
	appURI := eps[0].Server.ApplicationURI
	if rhe.ServerURI == "" || rhe.ServerURI != appURI {
		t.Errorf("ReverseHello ServerUri = %q, want the server's ApplicationUri %q", rhe.ServerURI, appURI)
	}
	if !strings.HasPrefix(rhe.EndpointURL, "opc.tcp://") {
		t.Errorf("ReverseHello EndpointUrl = %q, want an opc.tcp URL", rhe.EndpointURL)
	}

	// Read.
	_, nsIdx := findNS(t, c)
	dv, err := c.ReadValue(ctx, ua.NewStringNodeID(nsIdx, "Scalar.Int32"))
	if err != nil {
		t.Fatalf("Read Scalar.Int32: %v", err)
	}
	if got, ok := dv.Value.Value().(int32); !ok || got != -123456789 {
		t.Errorf("Scalar.Int32 = %v, want -123456789", dv.Value.Value())
	}

	// Subscription: publish responses arrive on the reverse connection.
	sub, notifyCh, err := c.NewSubscription().
		Interval(200 * time.Millisecond).
		Monitor(ua.NewStringNodeID(nsIdx, "Dynamic.Counter")).
		Start(ctx)
	if err != nil {
		t.Fatalf("Subscribe Dynamic.Counter: %v", err)
	}
	last := awaitCounterAdvance(t, notifyCh, -1, 30*time.Second, "first sample")
	for i := range 3 {
		last = awaitCounterAdvance(t, notifyCh, last, 30*time.Second, fmt.Sprintf("advance %d", i+1))
	}
	if err := sub.Cancel(ctx); err != nil {
		t.Errorf("cancel subscription: %v", err)
	}
	if err := c.Close(ctx); err != nil {
		t.Errorf("close: %v", err)
	}

	// The server connects again after the connection was closed; discovery
	// runs over the new connection, this time insisting on the ServerUri.
	discovered, err := opcua.GetEndpoints(ctx, "",
		append(base, opcua.ReverseConnectListener(l, opcua.ReverseServerURI(appURI)))...)
	if err != nil {
		t.Fatalf("GetEndpoints over a second reverse connection: %v", err)
	}
	if len(discovered) == 0 {
		t.Fatal("GetEndpoints returned no endpoints")
	}
	for _, ep := range discovered {
		if ep.Server.ApplicationURI != appURI {
			t.Errorf("endpoint %s: ApplicationUri %q, want %q", ep.EndpointURL, ep.Server.ApplicationURI, appURI)
		}
	}
	mu.Lock()
	n := len(hellos)
	mu.Unlock()
	if n < 2 {
		t.Errorf("server announced itself %d time(s), want one per connection", n)
	}
}

// ---------------------------------------------------------------------------
// Go server dialling → open62541 client listening
// ---------------------------------------------------------------------------

// reverseGoServer starts the Go fixture server with a reverse connect target
// on a free host port and returns the endpoint URL, that port, the target and
// the connection counter of the server.
func reverseGoServer(t *testing.T, extra ...server.Option) (string, int, *server.ReverseConnect, *connectionCounter) {
	t.Helper()
	counter := &connectionCounter{}
	hostPort := freePort(t)
	endpoint, srv := startGoServerWithOptions(t, append(extra,
		server.WithSlogLogger(slog.New(counter)),
		// The adapter's listen port is published by Docker, which accepts
		// (and then drops) connections before the adapter listens: retry
		// quickly instead of backing off for long.
		server.WithReverseConnect(fmt.Sprintf("opc.tcp://127.0.0.1:%d", hostPort),
			server.ReverseConnectRetryInterval(200*time.Millisecond, time.Second)),
	)...)
	rcs := srv.ReverseConnects()
	if len(rcs) != 1 {
		t.Fatalf("server has %d reverse connect targets, want 1", len(rcs))
	}
	return endpoint, hostPort, rcs[0], counter
}

// requireOnlyReverseConnections asserts that the peer used a connection the
// Go server opened, and none that the server accepted.
func requireOnlyReverseConnections(t *testing.T, counter *connectionCounter) {
	t.Helper()
	if n := counter.reverse.Load(); n == 0 {
		t.Error("the server registered no reverse connection")
	}
	if n := counter.accepted.Load(); n != 0 {
		t.Errorf("the peer opened %d connection(s) to the server itself", n)
	}
}

// TestGoServer_Open62541Client_ReverseConnect_Read verifies the server half of
// reverse connect against open62541: the Go server connects to the listening
// peer client, which then reads over that connection.
func TestGoServer_Open62541Client_ReverseConnect_Read(t *testing.T) {
	requireAdapterFeature(t, "OPEN62541_IMAGE", defaultOpen62541Image, "clientFeatures", "reverse-listen")
	endpoint, hostPort, rc, counter := reverseGoServer(t)

	result := runAdapterReverseClient(t, "OPEN62541_IMAGE", defaultOpen62541Image, endpoint, hostPort, "read",
		"--node", "nsu="+interopNamespaceURI+";s=Scalar.Int32",
	)
	if result.Operation != "read" {
		t.Errorf("operation: got %q, want %q", result.Operation, "read")
	}
	if !result.Success {
		t.Fatalf("read over reverse connection failed: serviceResult=%s error=%s (target: %s, %v)",
			result.ServiceResult, result.Error, rc.State(), rc.Err())
	}
	var items []struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(result.Results, &items); err != nil || len(items) == 0 {
		t.Fatalf("parse read results: %v; raw: %s", err, result.Results)
	}
	if !strings.Contains(string(items[0].Value), "-123456789") {
		t.Errorf("Scalar.Int32 = %s, want -123456789", items[0].Value)
	}
	requireOnlyReverseConnections(t, counter)
}

// TestGoServer_Open62541Client_ReverseConnect_Subscribe verifies that a
// subscription of the listening peer client delivers over the connection the
// Go server opened.
func TestGoServer_Open62541Client_ReverseConnect_Subscribe(t *testing.T) {
	requireAdapterFeature(t, "OPEN62541_IMAGE", defaultOpen62541Image, "clientFeatures", "reverse-listen")
	endpoint, hostPort, rc, counter := reverseGoServer(t)

	result := runAdapterReverseClient(t, "OPEN62541_IMAGE", defaultOpen62541Image, endpoint, hostPort, "subscribe",
		"--node", "nsu="+interopNamespaceURI+";s=Dynamic.Counter",
		"--notifications", "3",
		"--publishing-interval-ms", "300",
		"--sampling-interval-ms", "100",
		"--timeout-ms", "30000",
	)
	if result.Operation != "subscribe" {
		t.Errorf("operation: got %q, want %q", result.Operation, "subscribe")
	}
	if !result.Success {
		t.Fatalf("subscribe over reverse connection failed: serviceResult=%s error=%s (target: %s, %v)",
			result.ServiceResult, result.Error, rc.State(), rc.Err())
	}
	var items []struct {
		Notifications json.RawMessage `json:"notifications"`
	}
	if err := json.Unmarshal(result.Results, &items); err != nil || len(items) == 0 {
		t.Fatalf("parse subscribe results: %v; raw: %s", err, result.Results)
	}
	vals := parseNotificationValues(t, items[0].Notifications)
	if len(vals) < 3 {
		t.Errorf("expected at least 3 notifications, got %d: %v", len(vals), vals)
	}
	for i := 1; i < len(vals); i++ {
		if vals[i] < vals[i-1] {
			t.Errorf("counter went backwards: %v", vals)
			break
		}
	}
	requireOnlyReverseConnections(t, counter)
}

// ---------------------------------------------------------------------------
// Secured reverse connect
// ---------------------------------------------------------------------------

// reverseSecureCase is one security profile a reverse connection is secured
// with: an RSA policy and the two ECC policies go-opcua implements.
type reverseSecureCase struct {
	policy, mode string
	curve        string // "" for RSA: <identity>/cert.*; else <identity>/<curve>/cert.*
}

var reverseSecureCases = []reverseSecureCase{
	{policy: "Basic256Sha256", mode: "SignAndEncrypt"},
	{policy: "ECC_nistP256", mode: "SignAndEncrypt", curve: "ecc-nistp256"},
	{policy: "ECC_nistP384", mode: "Sign", curve: "ecc-nistp384"},
}

// identityFile returns the certificate or key of an identity of the test PKI
// for the case.
func (rc reverseSecureCase) identityFile(t *testing.T, identity, file string) string {
	t.Helper()
	path := filepath.Join(pkiDir(t), identity, rc.curve, file)
	if _, err := os.Stat(path); err != nil {
		capabilityUnavailable(t, "test PKI has no %s: %v (run certs/generate.sh)", path, err)
	}
	return path
}

func (rc reverseSecureCase) require(t *testing.T) {
	t.Helper()
	if rc.curve != "" {
		requireECCProfile(t, rc.policy, rc.mode)
	}
}

// TestOpen62541Server_ReverseConnect_Secure: the open62541 server dials the
// listening Go client, which opens a secured channel (RSA and ECC) on the
// connection the server opened: discovery over one reverse connection, the
// secured session over the next.
func TestOpen62541Server_ReverseConnect_Secure(t *testing.T) {
	requireAdapterFeature(t, "OPEN62541_IMAGE", defaultOpen62541Image, "serverFeatures", "reverse-connect")
	requireAdapterFeature(t, "OPEN62541_IMAGE", defaultOpen62541Image, "serverFeatures", "ecc-security")

	l, err := uacp.ListenReverse(context.Background(), "0.0.0.0:0", nil)
	if err != nil {
		t.Fatalf("ListenReverse: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	// One server with the RSA and the ECC endpoints; it is only reached
	// through the connections it opens (every 300 ms while there is none).
	startOpen62541ECCServerWith(t,
		"--reverse-connect", fmt.Sprintf("opc.tcp://host.docker.internal:%d", l.Addr().(*net.TCPAddr).Port),
		"--reverse-connect-interval-ms", "300")

	ctx, cancel := context.WithTimeout(context.Background(), 2*reverseDialTimeout)
	defer cancel()
	base := []opcua.Option{
		opcua.DialTimeout(reverseDialTimeout),
		opcua.AutoReconnect(false),
		opcua.ReverseConnectListener(l),
	}
	ca := loadCACert(t, filepath.Join(pkiDir(t), "ca", "ca.crt"))

	for _, rc := range reverseSecureCases {
		t.Run("coverage/transport.reverse-connect.secure/go-client-to-open62541-server/"+rc.policy, func(t *testing.T) {
			rc.require(t)
			// The endpoint list, read over a reverse connection of its own.
			eps, err := opcua.GetEndpoints(ctx, "", append([]opcua.Option{opcua.SecurityModeString("None"), opcua.AuthAnonymous()}, base...)...)
			if err != nil {
				t.Fatalf("GetEndpoints over a reverse connection: %v", err)
			}
			var ep *ua.EndpointDescription
			for _, e := range eps {
				if e.SecurityPolicyURI == ua.FormatSecurityPolicyURI(rc.policy) && e.SecurityMode == ua.MessageSecurityModeFromString(rc.mode) {
					ep = e
				}
			}
			if ep == nil {
				t.Fatalf("the server does not offer %s/%s over the reverse connection (%d endpoints)", rc.policy, rc.mode, len(eps))
			}

			c, err := opcua.NewClient("", append([]opcua.Option{
				opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous),
				opcua.CertificateFile(rc.identityFile(t, "consumer", "cert.crt")),
				opcua.PrivateKeyFile(rc.identityFile(t, "consumer", "cert.key")),
				opcua.TrustedCertificates(ca),
				opcua.AuthAnonymous(),
			}, base...)...)
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			if err := c.Connect(ctx); err != nil {
				t.Fatalf("Connect %s/%s over a reverse connection: %v", rc.policy, rc.mode, err)
			}
			defer func() {
				ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel2()
				_ = c.Close(ctx2)
			}()
			if got := c.SecurityPolicy(); got != ua.FormatSecurityPolicyURI(rc.policy) {
				t.Fatalf("connected with %s, want %s", got, rc.policy)
			}
			if got := c.SecurityMode(); got != ua.MessageSecurityModeFromString(rc.mode) {
				t.Fatalf("connected with %s, want %s", got, rc.mode)
			}

			_, nsIdx := findNS(t, c)
			dv, err := c.ReadValue(ctx, ua.NewStringNodeID(nsIdx, "Scalar.Int32"))
			if err != nil {
				t.Fatalf("Read Scalar.Int32: %v", err)
			}
			if got, ok := dv.Value.Value().(int32); !ok || got != -123456789 {
				t.Errorf("Scalar.Int32 = %v, want -123456789", dv.Value.Value())
			}
			sub, notifyCh, err := c.NewSubscription().
				Interval(200 * time.Millisecond).
				Monitor(ua.NewStringNodeID(nsIdx, "Dynamic.Counter")).
				Start(ctx)
			if err != nil {
				t.Fatalf("Subscribe Dynamic.Counter: %v", err)
			}
			last := awaitCounterAdvance(t, notifyCh, -1, 30*time.Second, "first sample")
			awaitCounterAdvance(t, notifyCh, last, 30*time.Second, "second sample")
			if err := sub.Cancel(ctx); err != nil {
				t.Errorf("cancel subscription: %v", err)
			}
		})
	}
}

// TestGoServer_Open62541Client_ReverseConnect_Secure: the Go server dials the
// listening open62541 client, which opens a secured channel (RSA and ECC)
// over the connections the server opened. open62541 reads the endpoints on
// the first reverse connection and opens the secured channel on the next one,
// so the Go server has to come back after the first one was closed.
func TestGoServer_Open62541Client_ReverseConnect_Secure(t *testing.T) {
	requireAdapterFeature(t, "OPEN62541_IMAGE", defaultOpen62541Image, "clientFeatures", "reverse-listen")
	requireAdapterFeature(t, "OPEN62541_IMAGE", defaultOpen62541Image, "clientFeatures", "ecc-security")

	for _, rc := range reverseSecureCases {
		t.Run("coverage/transport.reverse-connect.secure/open62541-client-to-go-server/"+rc.policy, func(t *testing.T) {
			rc.require(t)
			opts := append([]server.Option{
				server.Certificate(loadGoServerCert(t)),
				server.PrivateKey(loadGoServerKey(t)),
				server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
			}, goServerECCOptions(t)...)
			endpoint, hostPort, target, counter := reverseGoServer(t, opts...)

			mounts := []string{
				"-v", rc.identityFile(t, "open62541-client", "cert.crt") + ":/certs/cert.crt:ro",
				"-v", rc.identityFile(t, "open62541-client", "cert.key") + ":/certs/cert.key:ro",
				"-v", filepath.Join(pkiDir(t), "ca", "ca.crt") + ":/certs/ca.crt:ro",
			}
			result := runAdapterReverseClientWith(t, "OPEN62541_IMAGE", defaultOpen62541Image, endpoint, hostPort, mounts, "subscribe",
				"--security-policy", rc.policy, "--security-mode", rc.mode,
				"--certificate", "/certs/cert.crt", "--private-key", "/certs/cert.key", "--trust-list", "/certs/ca.crt",
				"--node", "nsu="+interopNamespaceURI+";s=Dynamic.Counter",
				"--notifications", "3",
				"--publishing-interval-ms", "300",
				"--sampling-interval-ms", "100",
				"--timeout-ms", "30000",
			)
			if !result.Success {
				t.Fatalf("subscribe over a secured reverse connection failed: serviceResult=%s error=%s (target: %s, %v)",
					result.ServiceResult, result.Error, target.State(), target.Err())
			}
			var items []struct {
				Notifications json.RawMessage `json:"notifications"`
			}
			if err := json.Unmarshal(result.Results, &items); err != nil || len(items) == 0 {
				t.Fatalf("parse subscribe results: %v; raw: %s", err, result.Results)
			}
			if vals := parseNotificationValues(t, items[0].Notifications); len(vals) < 3 {
				t.Errorf("expected at least 3 notifications, got %d: %v", len(vals), vals)
			}
			requireOnlyReverseConnections(t, counter)
			if n := counter.reverse.Load(); n < 2 {
				t.Errorf("the server opened %d reverse connection(s); a secured open62541 client needs one for discovery and one for the session", n)
			}
		})
	}
}
