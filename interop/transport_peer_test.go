//go:build interop

// SPDX-License-Identifier: MIT

// Tests in this file cover the opc.https (Part 6 §7.4, https-uabinary) and
// opc.wss (Part 6 §7.5, wss-uasc-uabinary) transports against the
// UA-.NETStandard adapter, in both directions:
//
//	go-client-to-dotnet-server   go-opcua dials the adapter's opc.https / opc.wss listeners
//	dotnet-client-to-go-server   the adapter client dials go-opcua's opc.https / opc.wss listeners
//
// The TLS certificates are those of the test PKI: the dotnet-server identity
// (SAN localhost) serves TLS for the adapter, the go-server identity (SAN
// host.docker.internal) for go-opcua; both are issued by the test CA.
//
// open62541 1.5.9 has no WebSocket or HTTPS transport (the libwebsockets
// provider UA_ENABLE_LWS exists on master only); its rows are unsupported.

package interop

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// Container ports of the adapter's opc.https and opc.wss listeners.
const (
	dotnetHTTPSPort = 4843
	dotnetWSSPort   = 4844
)

// transportServerHandle is an adapter server with opc.tcp, opc.https and
// opc.wss endpoints, as dialed from the host.
type transportServerHandle struct {
	tcp, https, wss string
}

// testCAPool returns the test CA as a certificate pool.
func testCAPool(t *testing.T) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(loadCACert(t, filepath.Join(pkiDir(t), "ca", "ca.crt")))
	return pool
}

// startDotnetTransportServer starts the dotnet adapter with its certificate
// and the opc.https and opc.wss listeners.
func startDotnetTransportServer(t *testing.T) *transportServerHandle {
	t.Helper()
	requireDotnetImage(t)
	requireServerFeature(t, dotnetEnv, defaultDotnetImage, "transport-https", "transport-wss")

	pki := pkiDir(t)
	certFile := filepath.Join(pki, "dotnet-server", "cert.crt")
	keyFile := filepath.Join(pki, "dotnet-server", "cert.key")
	adapterPKI := filepath.Join(pki, "dotnet-server", "pki")
	for _, f := range []string{certFile, keyFile, adapterPKI} {
		if _, err := os.Stat(f); err != nil {
			capabilityUnavailable(t, "test PKI file missing (%s): %v — run certs/generate.sh first", f, err)
		}
	}
	runtimePKI := filepath.Join(containerScratchDir(t), "pki")
	if err := copyDir(adapterPKI, runtimePKI); err != nil {
		t.Fatalf("copy PKI: %v", err)
	}
	if err := shareWithContainers(runtimePKI); err != nil {
		t.Fatalf("share PKI with the container: %v", err)
	}

	image := getEnvOr(dotnetEnv, defaultDotnetImage)
	containerName := dockerContainerName(t)
	fixtureDir := getEnvOr("OPCUA_INTEROP_FIXTURE_DIR", defaultFixtureDir)
	if !filepath.IsAbs(fixtureDir) {
		cwd, err := os.Getwd()
		if err != nil {
			t.Fatalf("getwd: %v", err)
		}
		fixtureDir = filepath.Join(cwd, fixtureDir)
	}

	for range publishAttempts {
		tcpPort, httpsPort, wssPort := freePort(t), freePort(t), freePort(t)
		cmdCtx, cmdCancel := context.WithCancel(context.Background())
		cmd := exec.CommandContext(cmdCtx, "docker", "run", "--rm",
			"--name", containerName,
			"-p", fmt.Sprintf("%d:4840", tcpPort),
			"-p", fmt.Sprintf("%d:%d", httpsPort, dotnetHTTPSPort),
			"-p", fmt.Sprintf("%d:%d", wssPort, dotnetWSSPort),
			"-v", fixtureDir+":/fixtures:ro",
			"-v", certFile+":/certs/cert.crt:ro",
			"-v", keyFile+":/certs/cert.key:ro",
			"-v", runtimePKI+":/certs/pki",
			image,
			"server",
			"--fixture", "/fixtures/baseline.json",
			"--certificate", "/certs/cert.crt",
			"--private-key", "/certs/cert.key",
			"--pki-dir", "/certs/pki",
			"--https-port", fmt.Sprint(dotnetHTTPSPort),
			"--wss-port", fmt.Sprint(dotnetWSSPort),
		)
		run, err := startDockerRun(cmd, nil)
		if err != nil {
			cmdCancel()
			t.Fatalf("start dotnet transport server (%s): %v", image, err)
		}
		stop := func() {
			dockerReleaseMount(containerName, "/certs/pki")
			dockerStop(containerName)
			cmdCancel()
			run.wait()
		}
		startCtx, startCancel := context.WithTimeout(context.Background(), serverReadyTimeout)
		err = waitDockerReady(startCtx, run, containerName)
		startCancel()
		if run.portTaken() {
			cmdCancel()
			dockerRemove(containerName)
			continue
		}
		if err != nil {
			stop()
			t.Fatalf("waiting for dotnet transport server (container: %s): %v", containerName, err)
		}
		t.Cleanup(stop)
		return &transportServerHandle{
			tcp:   fmt.Sprintf("opc.tcp://localhost:%d%s", tcpPort, endpointPath),
			https: fmt.Sprintf("opc.https://localhost:%d%s", httpsPort, endpointPath),
			wss:   fmt.Sprintf("opc.wss://localhost:%d%s", wssPort, endpointPath),
		}
	}
	t.Fatalf("no host ports Docker could publish the dotnet transport server on in %d attempts", publishAttempts)
	return nil
}

// dialTransportClient connects a go-opcua client over url with security
// None, trusting the test CA for TLS. Over HTTPS the adapter requires a user
// name (UA-.NETStandard filters Anonymous out of HTTPS endpoints without
// mutual TLS).
func dialTransportClient(t *testing.T, url string, user bool) *opcua.Client {
	t.Helper()
	tlsCfg := &tls.Config{RootCAs: testCAPool(t), MinVersion: tls.VersionTLS12}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	eps, err := opcua.GetEndpoints(ctx, url, opcua.TLSConfig(tlsCfg))
	if err != nil {
		t.Fatalf("GetEndpoints(%s): %v", url, err)
	}
	ep, err := opcua.SelectEndpointForTransport(eps, ua.TransportProfileForURL(url), ua.SecurityPolicyURINone, ua.MessageSecurityModeNone, nil)
	if err != nil {
		t.Fatalf("%s: no None endpoint of transport %s in %d endpoints: %v", url, ua.TransportProfileForURL(url), len(eps), err)
	}
	ep.EndpointURL = url
	opts := []opcua.Option{opcua.TLSConfig(tlsCfg), opcua.DialTimeout(dialTimeout), opcua.RequestTimeout(10 * time.Second)}
	if user {
		opts = append(opts, opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeUserName), opcua.AuthUsername("test-user", "test-password"))
	} else {
		opts = append(opts, opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous), opcua.AuthAnonymous())
	}
	c, err := opcua.NewClient(url, opts...)
	if err != nil {
		t.Fatalf("NewClient(%s): %v", url, err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel2()
	if err := c.Connect(ctx2); err != nil {
		t.Fatalf("Connect(%s): %v", url, err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = c.Close(ctx)
	})
	return c
}

// exerciseTransport reads, writes, browses and subscribes over c.
func exerciseTransport(t *testing.T, c *opcua.Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ns, err := c.FindNamespace(ctx, interopNamespaceURI)
	if err != nil {
		t.Fatalf("FindNamespace: %v", err)
	}
	int32ID := ua.NewStringNodeID(ns, "Scalar.Int32")
	writeInt32(t, c, ctx, int32ID, 4711)
	v, err := c.ReadValue(ctx, int32ID)
	if err != nil {
		t.Fatalf("Read Scalar.Int32: %v", err)
	}
	if got, _ := v.Value.Value().(int32); got != 4711 {
		t.Errorf("Scalar.Int32 = %v, want 4711", v.Value.Value())
	}

	refs, err := c.Node(ua.NewNumericNodeID(0, id.ObjectsFolder)).References(ctx,
		id.HierarchicalReferences, ua.BrowseDirectionForward, ua.NodeClassAll, true)
	if err != nil {
		t.Fatalf("Browse Objects: %v", err)
	}
	if len(refs) == 0 {
		t.Error("Browse Objects: no references")
	}

	sub, ch, err := c.NewSubscription().Interval(100 * time.Millisecond).
		Monitor(ua.NewStringNodeID(ns, "Dynamic.Counter")).Start(ctx)
	if err != nil {
		t.Fatalf("subscribe Dynamic.Counter: %v", err)
	}
	defer func() { _ = sub.Cancel(context.Background()) }()
	// Two notifications: the initial value and a change.
	collectDataChange(t, ch, 1, 20*time.Second)
	collectDataChange(t, ch, 1, 20*time.Second)
}

// requireTransportProfiles checks that GetEndpoints over url describes the
// endpoints of every transport with its profile.
func requireTransportProfiles(t *testing.T, url string) {
	t.Helper()
	tlsCfg := &tls.Config{RootCAs: testCAPool(t), MinVersion: tls.VersionTLS12}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	eps, err := opcua.GetEndpoints(ctx, url, opcua.TLSConfig(tlsCfg))
	if err != nil {
		t.Fatalf("GetEndpoints(%s): %v", url, err)
	}
	profiles := map[string]bool{}
	for _, ep := range eps {
		profiles[ep.TransportProfileURI] = true
	}
	for _, want := range []string{ua.TransportProfileUATCP, ua.TransportProfileWSS, ua.TransportProfileHTTPS} {
		if !profiles[want] {
			t.Errorf("GetEndpoints(%s): no endpoint with %s (got %v)", url, want, setKeys(profiles))
		}
	}
}

// TestDotnetServer_Transport_WSS: go-opcua client → dotnet server over opc.wss.
func TestDotnetServer_Transport_WSS(t *testing.T) {
	h := startDotnetTransportServer(t)
	requireTransportProfiles(t, h.wss)
	exerciseTransport(t, dialTransportClient(t, h.wss, false))
}

// TestDotnetServer_Transport_HTTPS: go-opcua client → dotnet server over
// opc.https; Publish is a long-polled POST.
func TestDotnetServer_Transport_HTTPS(t *testing.T) {
	h := startDotnetTransportServer(t)
	requireTransportProfiles(t, h.https)
	exerciseTransport(t, dialTransportClient(t, h.https, true))
}

// startGoTransportServer starts the interop go-opcua server with opc.https
// and opc.wss endpoints next to opc.tcp; TLS uses the go-server identity of
// the test PKI. It returns the endpoint URLs as dialed from the host.
func startGoTransportServer(t *testing.T) *transportServerHandle {
	t.Helper()
	pki := pkiDir(t)
	cert, err := tls.LoadX509KeyPair(filepath.Join(pki, "go-server", "cert.crt"), filepath.Join(pki, "go-server", "cert.key"))
	if err != nil {
		capabilityUnavailable(t, "go-server TLS identity: %v", err)
	}
	_, s := startGoServerWithOptions(t,
		server.WebSocketEndPoint("host.docker.internal", 0),
		server.ListenWebSocketOn("0.0.0.0:0"),
		server.HTTPSEndPoint("host.docker.internal", 0),
		server.ListenHTTPSOn("0.0.0.0:0"),
		server.TLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
	)
	port := func(a interface{ String() string }) string {
		return a.String()[strings.LastIndex(a.String(), ":")+1:]
	}
	return &transportServerHandle{
		tcp:   fmt.Sprintf("opc.tcp://localhost:%d%s", s.Port(), endpointPath),
		https: fmt.Sprintf("opc.https://localhost:%s%s", port(s.HTTPSAddr()), endpointPath),
		wss:   fmt.Sprintf("opc.wss://localhost:%s%s", port(s.WebSocketAddr()), endpointPath),
	}
}

// runDotnetTransportClient runs the dotnet adapter client over endpoint,
// trusting the test CA (which issued go-opcua's TLS certificate).
func runDotnetTransportClient(t *testing.T, endpoint, subcmd string, args ...string) adapterResult {
	t.Helper()
	requireDotnetImage(t)
	requireAdapterClientFeature(t, dotnetEnv, defaultDotnetImage, "transport-"+strings.TrimPrefix(strings.SplitN(endpoint, "://", 2)[0], "opc."))
	caCert := filepath.Join(pkiDir(t), "ca", "ca.crt")
	image := getEnvOr(dotnetEnv, defaultDotnetImage)
	cmdArgs := []string{"run", "--rm",
		"--add-host=host.docker.internal:host-gateway",
		"-v", caCert + ":/certs/ca.crt:ro",
		image,
		"client", subcmd,
		"--endpoint", strings.ReplaceAll(endpoint, "localhost", "host.docker.internal"),
		"--trust-list", "/certs/ca.crt",
	}
	raw, err := runClientContainer(t, append(cmdArgs, args...))
	result, perr := parseAdapterOutput(raw)
	if perr != nil {
		t.Fatalf("dotnet client %s %s: %v (%v)\nraw: %s", subcmd, endpoint, perr, err, raw)
	}
	if !result.Success {
		t.Fatalf("dotnet client %s %s failed: %s %s", subcmd, endpoint, result.ServiceResult, result.Error)
	}
	return result
}

// dotnetClientOverTransport reads, browses and subscribes from the dotnet
// client over endpoint.
func dotnetClientOverTransport(t *testing.T, endpoint string) {
	t.Helper()
	r := runDotnetTransportClient(t, endpoint, "read", "--node", "nsu="+interopNamespaceURI+";s=Scalar.Int32")
	var items []struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(r.Results, &items); err != nil || len(items) != 1 {
		t.Fatalf("read results: %v: %s", err, r.Results)
	}
	if !strings.Contains(string(items[0].Value), "-123456789") {
		t.Errorf("read Scalar.Int32 = %s, want -123456789", items[0].Value)
	}

	r = runDotnetTransportClient(t, endpoint, "browse", "--node", "nsu="+interopNamespaceURI+";i=85")
	if names := parseBrowseNames(t, r.Results); !names["Scalar.Int32"] {
		t.Errorf("browse: Scalar.Int32 missing (got %v)", setKeys(names))
	}

	r = runDotnetTransportClient(t, endpoint, "subscribe",
		"--node", "nsu="+interopNamespaceURI+";s=Dynamic.Counter",
		"--notifications", "3",
		"--publishing-interval-ms", "200",
		"--sampling-interval-ms", "100",
		"--timeout-ms", "15000",
	)
	var subs []struct {
		Notifications json.RawMessage `json:"notifications"`
	}
	if err := json.Unmarshal(r.Results, &subs); err != nil || len(subs) == 0 {
		t.Fatalf("subscribe results: %v: %s", err, r.Results)
	}
	if vals := dotnetParseNotificationValues(t, subs[0].Notifications); len(vals) < 3 {
		t.Errorf("subscribe: %d notifications, want 3", len(vals))
	}
}

// TestGoServer_DotnetClient_Transport_WSS: dotnet client → go-opcua server over opc.wss.
func TestGoServer_DotnetClient_Transport_WSS(t *testing.T) {
	h := startGoTransportServer(t)
	dotnetClientOverTransport(t, h.wss)
}

// TestGoServer_DotnetClient_Transport_HTTPS: dotnet client → go-opcua server over opc.https.
func TestGoServer_DotnetClient_Transport_HTTPS(t *testing.T) {
	h := startGoTransportServer(t)
	dotnetClientOverTransport(t, h.https)
}
