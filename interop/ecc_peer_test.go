//go:build interop

// SPDX-License-Identifier: MIT

// ECC security policies against open62541 (OpenSSL build), both directions.
// COVERAGE.md: security / security.ecc-*
//
// Eclipse Milo implements no ECC security policy, so there is no Milo
// direction here.
//
// These tests need an opcua-interop open62541 adapter that is built with
// OpenSSL and offers ECC endpoints, and a test PKI with ECC certificates
// (<identity>/ecc-<curve>/cert.crt and cert.key next to the RSA files). Both
// are checked up front: a test skips with the reason when they are missing
// and fails instead when OPCUA_INTEROP_REQUIRE_CAPABILITIES=1 is set, so a
// release verification run cannot pass without the evidence.

package interop

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	opcuaerrors "github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

// eccProfile is one ECC security policy under test.
type eccProfile struct {
	policy string // short name, as used by the adapter and the fixture
	curve  string // directory of its certificates: <identity>/<curve>/
	ledger string // capability prefix in coverage.json

	// aead marks the policies of OPC UA 1.05.07 with authenticated
	// encryption. The adapter offers them in SignAndEncrypt mode only.
	aead bool
}

var eccProfiles = []eccProfile{
	{policy: "ECC_nistP256", curve: "ecc-nistp256", ledger: "security.ecc-nistp256"},
	{policy: "ECC_nistP384", curve: "ecc-nistp384", ledger: "security.ecc-nistp384"},
	{policy: "ECC_nistP256_AesGcm", curve: "ecc-nistp256", ledger: "security.ecc-nistp256-aesgcm", aead: true},
	{policy: "ECC_nistP256_ChaChaPoly", curve: "ecc-nistp256", ledger: "security.ecc-nistp256-chachapoly", aead: true},
	{policy: "ECC_curve25519", curve: "ecc-curve25519", ledger: "security.ecc-curve25519", aead: true},
}

// eccMode is a message security mode with its name in the ledger.
type eccMode struct {
	mode   string
	ledger string
}

// modes returns the message security modes the profile is tested in.
func (p eccProfile) modes() []eccMode {
	if p.aead {
		return []eccMode{{"SignAndEncrypt", "sign-encrypt"}}
	}
	return eccModes
}

// renewals returns how many SecurityToken renewals a renewal test of the
// profile has to see.
func (p eccProfile) renewals() int {
	if p.aead {
		return 5
	}
	return 3
}

var eccModes = []eccMode{
	{"Sign", "sign"},
	{"SignAndEncrypt", "sign-encrypt"},
}

// requireECCProfile makes sure the open62541 adapter image advertises the
// security profile in its capabilities.
func requireECCProfile(t *testing.T, policy, mode string) {
	t.Helper()
	caps, image := imageCapabilities(t, "OPEN62541_IMAGE", defaultOpen62541Image)
	requirePinnedVersion(t, "OPEN62541_IMAGE", caps, image)
	for _, p := range caps.SecurityProfiles {
		if p.Policy == policy && p.Mode == mode {
			return
		}
	}
	capabilityUnavailable(t, "adapter %s does not advertise security profile %s/%s (needs opcua-interop %s: an OpenSSL build with ECC endpoints)", image, policy, mode, interopVersion)
}

// eccPKIFile returns the path of an ECC certificate or key in the test PKI.
func eccPKIFile(t *testing.T, identity, curve, file string) string {
	t.Helper()
	path := filepath.Join(pkiDir(t), identity, curve, file)
	if _, err := os.Stat(path); err != nil {
		capabilityUnavailable(t, "test PKI has no ECC file %s: %v (run certs/generate.sh --add-ecc)", path, err)
	}
	return path
}

// interopFixtureDir returns the absolute path of the directory with the
// baseline fixture. Since opcua-interop v0.7.0 the fixture names the ECC
// security profiles itself: the adapter server offers every profile of the
// fixture it has a certificate for.
func interopFixtureDir(t *testing.T) string {
	t.Helper()
	dir := getEnvOr("OPCUA_INTEROP_FIXTURE_DIR", defaultFixtureDir)
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("fixture dir %s: %v", dir, err)
	}
	return abs
}

// startOpen62541ECCServer starts the open62541 adapter with its RSA
// certificate and the ECC certificates of the test PKI, so it offers the RSA
// and the ECC endpoints side by side.
func startOpen62541ECCServer(t *testing.T) *serverHandle {
	t.Helper()
	return startOpen62541ECCServerWith(t)
}

// startOpen62541ECCServerWith is startOpen62541ECCServer with extra adapter
// server arguments (e.g. --reverse-connect).
func startOpen62541ECCServerWith(t *testing.T, serverArgs ...string) *serverHandle {
	t.Helper()

	pki := pkiDir(t)
	identity := filepath.Join(pki, "open62541-server")
	certFile := filepath.Join(identity, "cert.crt")
	keyFile := filepath.Join(identity, "cert.key")
	for _, f := range []string{certFile, keyFile, filepath.Join(identity, "pki")} {
		if _, err := os.Stat(f); err != nil {
			capabilityUnavailable(t, "test PKI file missing (%s): %v — run certs/generate.sh first", f, err)
		}
	}
	for _, p := range eccProfiles {
		eccPKIFile(t, "open62541-server", p.curve, "cert.crt")
		eccPKIFile(t, "open62541-server", p.curve, "cert.key")
	}

	// The adapter may write rejected certificates; give it a copy.
	runtimePKI := filepath.Join(containerScratchDir(t), "pki")
	if err := copyDir(filepath.Join(identity, "pki"), runtimePKI); err != nil {
		t.Fatalf("copy PKI to temp dir: %v", err)
	}
	if err := shareWithContainers(runtimePKI); err != nil {
		t.Fatalf("share PKI with the container: %v", err)
	}

	port := freePort(t)
	image := getEnvOr("OPEN62541_IMAGE", defaultOpen62541Image)
	containerName := dockerContainerName(t)
	cmdCtx, cmdCancel := context.WithCancel(context.Background())

	cmd := exec.CommandContext(cmdCtx, "docker", append([]string{"run", "--rm",
		"--name", containerName,
		"--add-host=host.docker.internal:host-gateway",
		"-p", fmt.Sprintf("%d:4840", port),
		"-v", interopFixtureDir(t) + ":/fixtures:ro",
		"-v", certFile + ":/certs/cert.crt:ro",
		"-v", keyFile + ":/certs/cert.key:ro",
		"-v", runtimePKI + ":/certs/pki",
		"-v", identity + ":/certs/ecc:ro",
		image,
		"server",
		"--fixture", "/fixtures/baseline.json",
		"--certificate", "/certs/cert.crt",
		"--private-key", "/certs/cert.key",
		"--pki-dir", "/certs/pki",
		"--ecc-dir", "/certs/ecc",
	}, serverArgs...)...)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		cmdCancel()
		t.Fatalf("start ECC adapter server (%s): %v", image, err)
	}
	stop := func() {
		dockerReleaseMount(containerName, "/certs/pki")
		dockerStop(containerName)
		cmdCancel()
		_ = cmd.Wait()
	}

	startCtx, startCancel := context.WithTimeout(context.Background(), serverReadyTimeout)
	defer startCancel()
	for exec.CommandContext(startCtx, "docker", "exec", containerName, "test", "-f", "/run/opcua-interop/ready").Run() != nil {
		select {
		case <-startCtx.Done():
			stop()
			t.Fatalf("timed out waiting for ECC adapter server (container: %s)", containerName)
		default:
			time.Sleep(500 * time.Millisecond)
		}
	}

	t.Cleanup(stop)
	return &serverHandle{
		endpoint: fmt.Sprintf("opc.tcp://localhost:%d%s", port, endpointPath),
		stopFn:   stop,
	}
}

// eccEndpoint returns the endpoint the server advertises for the profile.
func eccEndpoint(t *testing.T, endpoint, policy, mode string) *ua.EndpointDescription {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	eps, err := opcua.GetEndpoints(ctx, endpoint)
	if err != nil {
		t.Fatalf("GetEndpoints(%q): %v", endpoint, err)
	}
	wantPolicy := ua.FormatSecurityPolicyURI(policy)
	wantMode := ua.MessageSecurityModeFromString(mode)
	var have []string
	for _, ep := range eps {
		if ep.SecurityPolicyURI == wantPolicy && ep.SecurityMode == wantMode {
			// Keep the certificate and security parameters the server
			// advertises, but connect to the port mapped on this host.
			ep.EndpointURL = endpoint
			return ep
		}
		have = append(have, strings.TrimPrefix(ep.SecurityPolicyURI, ua.SecurityPolicyURIPrefix)+"/"+ep.SecurityMode.String())
	}
	t.Fatalf("server did not advertise %s/%s (advertised: %v)", policy, mode, have)
	return nil
}

// newECCClient builds a go-opcua client for the ECC endpoint with the
// consumer's ECC certificate of the given curve. It is not connected yet.
func newECCClient(t *testing.T, endpoint string, p eccProfile, mode string, auth ua.UserTokenType, extra ...opcua.Option) *opcua.Client {
	t.Helper()
	ep := eccEndpoint(t, endpoint, p.policy, mode)
	if err := uapolicy.CheckCertificate(ep.SecurityPolicyURI, ep.ServerCertificate); err != nil {
		t.Fatalf("the %s endpoint advertises a certificate that does not fit the policy: %v", p.policy, err)
	}
	opts := []opcua.Option{
		opcua.SecurityFromEndpoint(ep, auth),
		opcua.CertificateFile(eccPKIFile(t, "consumer", p.curve, "cert.crt")),
		opcua.PrivateKeyFile(eccPKIFile(t, "consumer", p.curve, "cert.key")),
		opcua.TrustedCertificates(loadCACert(t, filepath.Join(pkiDir(t), "ca", "ca.crt"))),
	}
	c, err := opcua.NewClient(endpoint, append(opts, extra...)...)
	if err != nil {
		t.Fatalf("NewClient (%s/%s): %v", p.policy, mode, err)
	}
	return c
}

// dialECCClient connects a go-opcua client over the ECC endpoint.
func dialECCClient(t *testing.T, endpoint string, p eccProfile, mode string, extra ...opcua.Option) *opcua.Client {
	t.Helper()
	c := newECCClient(t, endpoint, p, mode, ua.UserTokenTypeAnonymous, append([]opcua.Option{opcua.AuthAnonymous()}, extra...)...)
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("Connect (%s/%s): %v", p.policy, mode, err)
	}
	t.Cleanup(func() {
		ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel2()
		c.Close(ctx2) //nolint:errcheck
	})
	if got := c.SecurityPolicy(); got != ua.FormatSecurityPolicyURI(p.policy) {
		t.Fatalf("connected with %s, want %s", got, p.policy)
	}
	return c
}

// ---------------------------------------------------------------------------
// Go client → open62541 server
// ---------------------------------------------------------------------------

// TestOpen62541Server_ECC_Read opens a SecureChannel with every ECC policy
// and mode and reads a fixture value over it.
func TestOpen62541Server_ECC_Read(t *testing.T) {
	for _, p := range eccProfiles {
		for _, m := range p.modes() {
			t.Run("coverage/"+p.ledger+"."+m.ledger+"/go-client-to-open62541-server", func(t *testing.T) {
				requireECCProfile(t, p.policy, m.mode)
				h := startOpen62541ECCServer(t)
				c := dialECCClient(t, h.endpoint, p, m.mode)
				ctx, nsIdx := findNS(t, c)
				v, err := c.Node(ua.NewStringNodeID(nsIdx, "Scalar.Int32")).Value(ctx)
				if err != nil {
					t.Fatalf("Value(Scalar.Int32): %v", err)
				}
				if got, ok := v.Value().(int32); !ok || got != -123456789 {
					t.Fatalf("Scalar.Int32 = %v (%T), want -123456789", v.Value(), v.Value())
				}
			})
		}
	}
}

// TestOpen62541Server_ECC_Subscription runs a subscription over an encrypted
// ECC channel.
func TestOpen62541Server_ECC_Subscription(t *testing.T) {
	for _, p := range eccProfiles {
		t.Run("coverage/"+p.ledger+".subscription/go-client-to-open62541-server", func(t *testing.T) {
			requireECCProfile(t, p.policy, "SignAndEncrypt")
			h := startOpen62541ECCServer(t)
			c := dialECCClient(t, h.endpoint, p, "SignAndEncrypt")
			_, nsIdx := findNS(t, c)

			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			sub, notifyCh, err := c.NewSubscription().
				Interval(250 * time.Millisecond).
				Monitor(ua.NewStringNodeID(nsIdx, "Dynamic.Counter")).
				Start(ctx)
			if err != nil {
				t.Fatalf("subscribe: %v", err)
			}
			defer sub.Cancel(ctx) //nolint:errcheck

			last := awaitCounterAdvance(t, notifyCh, -1, 15*time.Second, "first sample")
			for i := 0; i < 4; i++ {
				last = awaitCounterAdvance(t, notifyCh, last, 15*time.Second, "following samples")
			}
		})
	}
}

// TestOpen62541Server_ECC_Username authenticates with a user name and
// password over ECC. The password travels in an EccEncryptedSecret that the
// peer has to verify and decrypt with the ephemeral key it handed out.
func TestOpen62541Server_ECC_Username(t *testing.T) {
	connect := func(t *testing.T, endpoint string, p eccProfile, password string) (*opcua.Client, error) {
		c := newECCClient(t, endpoint, p, "SignAndEncrypt", ua.UserTokenTypeUserName, opcua.AuthUsername("test-user", password))
		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		defer cancel()
		err := c.Connect(ctx)
		t.Cleanup(func() {
			ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel2()
			c.Close(ctx2) //nolint:errcheck
		})
		return c, err
	}

	for _, p := range eccProfiles {
		t.Run("coverage/"+p.ledger+".username.valid/go-client-to-open62541-server", func(t *testing.T) {
			requireECCProfile(t, p.policy, "SignAndEncrypt")
			h := startOpen62541ECCServer(t)
			c, err := connect(t, h.endpoint, p, "test-password")
			if err != nil {
				t.Fatalf("valid credentials rejected over %s: %v", p.policy, err)
			}
			ctx, nsIdx := findNS(t, c)
			if _, err := c.Node(ua.NewStringNodeID(nsIdx, "Scalar.Int32")).Value(ctx); err != nil {
				t.Fatalf("read as test-user: %v", err)
			}
		})

		t.Run("coverage/"+p.ledger+".username.invalid/go-client-to-open62541-server", func(t *testing.T) {
			requireECCProfile(t, p.policy, "SignAndEncrypt")
			h := startOpen62541ECCServer(t)
			_, err := connect(t, h.endpoint, p, "wrong-password")
			if err == nil {
				t.Fatal("wrong password accepted")
			}
			if !isIdentityRejectedError(err) {
				t.Fatalf("expected an identity rejection, got: %v", err)
			}
		})
	}
}

// TestOpen62541Server_ECC_Renewal keeps a subscription running across
// SecurityToken renewals. Every renewal is a new ephemeral key agreement.
func TestOpen62541Server_ECC_Renewal(t *testing.T) {
	for _, p := range eccProfiles {
		t.Run("coverage/"+p.ledger+".renewal/go-client-to-open62541-server", func(t *testing.T) {
			requireECCProfile(t, p.policy, "SignAndEncrypt")
			h := startOpen62541ECCServer(t)
			c := dialECCClient(t, h.endpoint, p, "SignAndEncrypt", opcua.Lifetime(renewalLifetime))
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
			defer sub.Cancel(ctx) //nolint:errcheck

			start := time.Now()
			last := awaitCounterAdvance(t, notifyCh, -1, 15*time.Second, "before renewal")

			for i := 1; i <= p.renewals(); i++ {
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

			// Outlive the original token (lifetime + 25% grace) and one more
			// automatic renewal, with data still flowing.
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
		})
	}
}

// TestOpen62541Server_ECC_Write writes a value over the policies with
// authenticated encryption and reads it back.
func TestOpen62541Server_ECC_Write(t *testing.T) {
	for _, p := range eccProfiles {
		if !p.aead {
			continue
		}
		t.Run("coverage/"+p.ledger+".write/go-client-to-open62541-server", func(t *testing.T) {
			requireECCProfile(t, p.policy, "SignAndEncrypt")
			h := startOpen62541ECCServer(t)
			c := dialECCClient(t, h.endpoint, p, "SignAndEncrypt")
			ctx, nsIdx := findNS(t, c)
			node := ua.NewStringNodeID(nsIdx, "Access.ReadWrite")
			const want = int32(271828)
			st, err := c.WriteNodeValue(ctx, node, want)
			if err != nil || st != ua.StatusOK {
				t.Fatalf("write over %s: status %v, error %v", p.policy, st, err)
			}
			v, err := c.Node(node).Value(ctx)
			if err != nil {
				t.Fatalf("read back: %v", err)
			}
			if got, ok := v.Value().(int32); !ok || got != want {
				t.Fatalf("Access.ReadWrite = %v (%T), want %d", v.Value(), v.Value(), want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// open62541 client → Go server
// ---------------------------------------------------------------------------

// TestGoServer_Open62541Client_ECC_Write has the open62541 client write a
// value over the policies with authenticated encryption and read it back.
func TestGoServer_Open62541Client_ECC_Write(t *testing.T) {
	for _, p := range eccProfiles {
		if !p.aead {
			continue
		}
		t.Run("coverage/"+p.ledger+".write/open62541-client-to-go-server", func(t *testing.T) {
			requireECCProfile(t, p.policy, "SignAndEncrypt")
			endpoint, _ := startECCGoServer(t)
			node := "nsu=" + interopNamespaceURI + ";s=Access.ReadWrite"
			result := runECCAdapterClient(t, endpoint, p, "SignAndEncrypt", "write",
				"--node", node, "--type", "Int32", "--value", "271828")
			if !result.Success {
				t.Fatalf("write over %s failed: serviceResult=%s error=%s", p.policy, result.ServiceResult, result.Error)
			}
			result = runECCAdapterClient(t, endpoint, p, "SignAndEncrypt", "read", "--node", node)
			if !result.Success || !strings.Contains(string(result.Results), "271828") {
				t.Fatalf("read back over %s: success=%v results=%s", p.policy, result.Success, result.Results)
			}
		})
	}
}

// startECCGoServer starts a go-opcua server with an RSA and two ECC
// application instance certificates. It offers the ECC policies next to an
// RSA one, has the fixture's user, and exposes Scalar.Int32 and a
// Dynamic.Counter that advances every 250 ms. The returned counter is the
// number of SecurityToken renewals the server handled.
func startECCGoServer(t *testing.T) (string, *atomic.Int64) {
	t.Helper()

	renewals := new(atomic.Int64)
	opts := []server.Option{
		// Bind port 0; advertise host.docker.internal for the adapter.
		server.ListenOn("0.0.0.0:0"),
		server.EndPoint("host.docker.internal", 0),
		server.Certificate(loadGoServerCert(t)),
		server.PrivateKey(loadGoServerKey(t)),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.WithUsernameValidator(func(username, password string) error {
			if pw, ok := goServerUsers[username]; ok && pw == password {
				return nil
			}
			return ua.StatusBadUserAccessDenied
		}),
		server.SetLogger(slog.New(openChannelCounter{n: renewals})),
	}
	opts = append(opts, goServerECCOptions(t)...)

	s, err := server.New(opts...)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	ns := server.NewNodeNameSpace(s, interopNamespaceURI)
	s.AddNamespace(ns)
	objs := ns.Objects()
	objs.AddRef(ns.AddNewVariableStringNode("Scalar.Int32", int32(42)), server.RefTypeIDHasComponent, true)
	objs.AddRef(ns.AddNewVariableStringNode("Access.ReadWrite", int32(42)), server.RefTypeIDHasComponent, true)

	var ctr atomic.Int64
	counterID := ua.NewStringNodeID(ns.ID(), "Dynamic.Counter")
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
	objs.AddRef(counterNode, server.RefTypeIDHasComponent, true)

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

// goServerECCOptions returns the server options that give a go-opcua server
// the go-server ECC application instance certificates of the test PKI and
// the ECC endpoints of eccProfiles, next to whatever else it offers.
func goServerECCOptions(t *testing.T) []server.Option {
	t.Helper()
	var opts []server.Option
	identities := map[string]bool{} // one certificate per curve
	for _, p := range eccProfiles {
		if !identities[p.curve] {
			identities[p.curve] = true
			certPEM, err := os.ReadFile(eccPKIFile(t, "go-server", p.curve, "cert.crt"))
			if err != nil {
				t.Fatal(err)
			}
			keyPEM, err := os.ReadFile(eccPKIFile(t, "go-server", p.curve, "cert.key"))
			if err != nil {
				t.Fatal(err)
			}
			key, err := uapolicy.ParsePrivateKey(keyPEM)
			if err != nil {
				t.Fatalf("go-server %s key: %v", p.curve, err)
			}
			opts = append(opts, server.ApplicationIdentity(pemCertDER(t, certPEM), key))
		}
		for _, m := range p.modes() {
			opts = append(opts, server.EnableSecurity(p.policy, ua.MessageSecurityModeFromString(m.mode)))
		}
	}
	return opts
}

// pemCertDER returns the DER bytes of a PEM (or already DER) certificate.
func pemCertDER(t *testing.T, raw []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(raw)
	if block == nil {
		return raw
	}
	if block.Type != "CERTIFICATE" {
		t.Fatalf("PEM block %q is not a certificate", block.Type)
	}
	return block.Bytes
}

// runECCAdapterClient runs the open62541 adapter client with its ECC
// certificate of the profile's curve against the Go server.
func runECCAdapterClient(t *testing.T, endpoint string, p eccProfile, mode, subcmd string, args ...string) adapterResult {
	t.Helper()
	eccPKIFile(t, "open62541-client", p.curve, "cert.crt")
	eccPKIFile(t, "open62541-client", p.curve, "cert.key")
	return runSecureAdapterClientResult(t, "OPEN62541_IMAGE", defaultOpen62541Image,
		filepath.Join("open62541-client", p.curve), endpoint, subcmd, p.policy, mode, args...)
}

// TestGoServer_Open62541Client_ECC_Read has the open62541 client open a
// SecureChannel with every ECC policy and mode and read a value.
func TestGoServer_Open62541Client_ECC_Read(t *testing.T) {
	for _, p := range eccProfiles {
		for _, m := range p.modes() {
			t.Run("coverage/"+p.ledger+"."+m.ledger+"/open62541-client-to-go-server", func(t *testing.T) {
				requireECCProfile(t, p.policy, m.mode)
				endpoint, _ := startECCGoServer(t)
				result := runECCAdapterClient(t, endpoint, p, m.mode, "read",
					"--node", "nsu="+interopNamespaceURI+";s=Scalar.Int32")
				if !result.Success {
					t.Fatalf("read over %s/%s failed: serviceResult=%s error=%s", p.policy, m.mode, result.ServiceResult, result.Error)
				}
				if !strings.Contains(string(result.Results), "42") {
					t.Fatalf("read result does not carry the value 42: %s", result.Results)
				}
			})
		}
	}
}

// TestGoServer_Open62541Client_ECC_Username has the open62541 client
// authenticate with user name and password over ECC: the Go server decrypts
// the EccEncryptedSecret the peer created.
func TestGoServer_Open62541Client_ECC_Username(t *testing.T) {
	for _, p := range eccProfiles {
		t.Run("coverage/"+p.ledger+".username.valid/open62541-client-to-go-server", func(t *testing.T) {
			requireECCProfile(t, p.policy, "SignAndEncrypt")
			endpoint, _ := startECCGoServer(t)
			result := runECCAdapterClient(t, endpoint, p, "SignAndEncrypt", "read",
				"--username", "test-user",
				"--password", "test-password",
				"--node", "nsu="+interopNamespaceURI+";s=Scalar.Int32")
			if !result.Success {
				t.Fatalf("valid credentials rejected over %s: %s error=%s", p.policy, result.ServiceResult, result.Error)
			}
		})

		t.Run("coverage/"+p.ledger+".username.invalid/open62541-client-to-go-server", func(t *testing.T) {
			requireECCProfile(t, p.policy, "SignAndEncrypt")
			endpoint, _ := startECCGoServer(t)
			result := runECCAdapterClient(t, endpoint, p, "SignAndEncrypt", "read",
				"--username", "test-user",
				"--password", "wrong-password",
				"--node", "nsu="+interopNamespaceURI+";s=Scalar.Int32")
			if result.Operation == "" {
				t.Fatal("the adapter produced no result: the rejection cannot be told from a crash")
			}
			if result.Success {
				t.Fatal("wrong password accepted")
			}
			if !isIdentityRejectedServiceResult(result.ServiceResult.Name) {
				t.Fatalf("expected an identity rejection, got: %s", result.ServiceResult)
			}
		})
	}
}

// eccPeerSubscribe runs an adapter subscription on Dynamic.Counter over an
// encrypted ECC channel and returns the counter values it was notified of.
func eccPeerSubscribe(t *testing.T, endpoint string, p eccProfile, want int, extra ...string) []int64 {
	t.Helper()
	args := append([]string{
		"--node", "nsu=" + interopNamespaceURI + ";s=Dynamic.Counter",
		"--publishing-interval-ms", "500",
		"--sampling-interval-ms", "250",
		"--notifications", fmt.Sprint(want),
		"--timeout-ms", "60000",
		"--request-timeout", "20",
	}, extra...)
	result := runECCAdapterClient(t, endpoint, p, "SignAndEncrypt", "subscribe", args...)
	if !result.Success {
		t.Fatalf("subscribe over %s failed: serviceResult=%s error=%s", p.policy, result.ServiceResult, result.Error)
	}
	var items []renewalSubscribeResult
	if err := json.Unmarshal(result.Results, &items); err != nil || len(items) != 1 {
		t.Fatalf("unexpected subscribe results (%v): %s", err, result.Results)
	}
	got := items[0].Notifications
	if len(got) != want {
		t.Fatalf("notifications=%d, want %d", len(got), want)
	}
	values := make([]int64, len(got))
	prev := int64(-1)
	for i, n := range got {
		v, err := n.Value.Int64()
		if err != nil {
			t.Fatalf("notification %d: value %q: %v", i, n.Value, err)
		}
		if v <= prev {
			t.Fatalf("notification %d: counter %d not after %d (lost or reordered)", i, v, prev)
		}
		values[i], prev = v, v
	}
	return values
}

// TestGoServer_Open62541Client_ECC_Subscription has the open62541 client
// subscribe to a changing value over an encrypted ECC channel.
func TestGoServer_Open62541Client_ECC_Subscription(t *testing.T) {
	for _, p := range eccProfiles {
		t.Run("coverage/"+p.ledger+".subscription/open62541-client-to-go-server", func(t *testing.T) {
			requireECCProfile(t, p.policy, "SignAndEncrypt")
			endpoint, _ := startECCGoServer(t)
			eccPeerSubscribe(t, endpoint, p, 6)
		})
	}
}

// TestGoServer_Open62541Client_ECC_Renewal runs an adapter subscription that
// spans several SecureChannel lifetimes over an encrypted ECC channel. It
// only completes if the Go server accepts every renewal (a new ephemeral key
// agreement each time) and keeps publishing afterwards.
func TestGoServer_Open62541Client_ECC_Renewal(t *testing.T) {
	for _, p := range eccProfiles {
		t.Run("coverage/"+p.ledger+".renewal/open62541-client-to-go-server", func(t *testing.T) {
			requireECCProfile(t, p.policy, "SignAndEncrypt")
			endpoint, renewals := startECCGoServer(t)

			// 500 ms publishing over a 250 ms counter: about 2 notifications
			// a second, so 32 of them span about 16 s: at least 3 renewals at
			// 75% of the 6 s lifetime.
			notifications, lifetime, want := 32, renewalLifetime, int64(2)
			if p.aead {
				// Five renewals: 44 notifications span about 22 s, and a 5 s
				// lifetime is renewed every 3.75 s.
				notifications, lifetime, want = 44, 5*time.Second, int64(p.renewals())
			}
			started := time.Now()
			eccPeerSubscribe(t, endpoint, p, notifications, "--channel-lifetime-ms", fmt.Sprint(lifetime.Milliseconds()))
			if renewed := renewals.Load(); renewed < want {
				t.Fatalf("Go server handled %d SecurityToken renewals in %s; want at least %d", renewed, time.Since(started), want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ECC policies go-opcua does not implement
// ---------------------------------------------------------------------------

// eccUnimplemented are the ECC policies open62541 1.5.9 offers and go-opcua
// does not implement, with the directory of the certificate they use.
var eccUnimplemented = []eccProfile{
	{policy: "ECC_brainpoolP256r1", curve: "ecc-brainpoolp256r1"},
	{policy: "ECC_brainpoolP384r1", curve: "ecc-brainpoolp384r1"},
	{policy: "ECC_curve448", curve: "ecc-curve448"},
}

// uncleanFailure bounds how long a refusal may take: it is decided locally
// or at the first message, nothing waits for a timeout.
const uncleanFailure = 8 * time.Second

// TestOpen62541Server_ECC_UnimplementedPolicies: the open62541 server offers
// three ECC policies go-opcua does not implement. The go-opcua client must read
// its endpoint list, never select such an endpoint on its own, and refuse it
// at once with ErrUnsupportedSecurityPolicy when it is told to use it; the
// implemented policies stay usable next to them.
func TestOpen62541Server_ECC_UnimplementedPolicies(t *testing.T) {
	t.Run("coverage/security.ecc.unimplemented-policy/go-client-to-open62541-server", func(t *testing.T) {
		for _, p := range eccUnimplemented {
			requireECCProfile(t, p.policy, "SignAndEncrypt")
			eccPKIFile(t, "open62541-server", p.curve, "cert.crt")
		}
		h := startOpen62541ECCServer(t)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		eps, err := opcua.GetEndpoints(ctx, h.endpoint)
		if err != nil {
			t.Fatalf("GetEndpoints: %v", err)
		}
		p256 := eccProfiles[0]
		certDER := pemCertDER(t, mustReadFile(t, eccPKIFile(t, "consumer", p256.curve, "cert.crt")))
		ca := loadCACert(t, filepath.Join(pkiDir(t), "ca", "ca.crt"))

		for _, p := range eccUnimplemented {
			uri := ua.FormatSecurityPolicyURI(p.policy)
			var ep *ua.EndpointDescription
			for _, e := range eps {
				if e.SecurityPolicyURI == uri {
					ep = e
				}
			}
			if ep == nil {
				t.Errorf("%s: the server does not offer the policy, nothing is proven", p.policy)
				continue
			}
			// Not selectable.
			if got, err := opcua.SelectEndpoint(eps, p.policy, ua.MessageSecurityModeInvalid, certDER); !errors.Is(err, opcuaerrors.ErrNoMatchingEndpoint) {
				t.Errorf("%s: SelectEndpoint = %v, %v; want ErrNoMatchingEndpoint", p.policy, got, err)
			}
			// Refused at once when forced.
			start := time.Now()
			ep.EndpointURL = h.endpoint
			c, err := opcua.NewClient(h.endpoint,
				opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous),
				opcua.Certificate(certDER),
				opcua.PrivateKeyFile(eccPKIFile(t, "consumer", p256.curve, "cert.key")),
				opcua.TrustedCertificates(ca),
				opcua.AuthAnonymous(),
				opcua.AutoReconnect(false),
			)
			if err == nil {
				cctx, ccancel := context.WithTimeout(ctx, uncleanFailure)
				err = c.Connect(cctx)
				ccancel()
				if err == nil {
					_ = c.Close(ctx)
				}
			}
			elapsed := time.Since(start)
			t.Logf("%s: %v (%s)", p.policy, err, elapsed.Round(time.Millisecond))
			if !errors.Is(err, opcuaerrors.ErrUnsupportedSecurityPolicy) {
				t.Errorf("%s: got %v, want ErrUnsupportedSecurityPolicy", p.policy, err)
			}
			if elapsed > uncleanFailure/2 {
				t.Errorf("%s: the refusal took %s", p.policy, elapsed)
			}
		}

		// Left to itself the client takes the best endpoint it implements,
		// and the server still serves it.
		best, err := opcua.SelectEndpoint(eps, "", ua.MessageSecurityModeInvalid, certDER)
		if err != nil {
			t.Fatalf("SelectEndpoint: %v", err)
		}
		// open62541 gives its ECC endpoints one security level, so the
		// ranking of go-opcua decides between the policies a P-256
		// certificate can be used with: ECC_nistP256_ChaChaPoly.
		t.Logf("SelectEndpoint with a P-256 certificate: %s (level %d)", best.SecurityPolicyURI, best.SecurityLevel)
		for _, e := range eps {
			if uapolicy.IsSupported(e.SecurityPolicyURI) && uapolicy.CheckCertificate(e.SecurityPolicyURI, certDER) == nil && e.SecurityLevel > best.SecurityLevel {
				t.Errorf("SelectEndpoint chose %s (level %d) over %s (level %d)", best.SecurityPolicyURI, best.SecurityLevel, e.SecurityPolicyURI, e.SecurityLevel)
			}
		}
		if best.SecurityPolicyURI != ua.SecurityPolicyURIECCNistP256ChaChaPoly {
			t.Errorf("SelectEndpoint with a P-256 certificate chose %s", best.SecurityPolicyURI)
		}
		c := dialECCClient(t, h.endpoint, p256, "SignAndEncrypt")
		rctx, nsIdx := findNS(t, c)
		if _, err := c.Node(ua.NewStringNodeID(nsIdx, "Scalar.Int32")).Value(rctx); err != nil {
			t.Fatalf("read over %s after the refusals: %v", p256.policy, err)
		}
	})
}

// TestGoServer_Open62541Client_ECC_UnimplementedPolicies: the open62541
// client asks the go-opcua server for an ECC policy go-opcua does not
// implement. The server does not offer such an endpoint, so the client must
// find none to select (client contract §9: exit 3, error category
// "transport") instead of hanging, and the server keeps serving.
func TestGoServer_Open62541Client_ECC_UnimplementedPolicies(t *testing.T) {
	t.Run("coverage/security.ecc.unimplemented-policy/open62541-client-to-go-server", func(t *testing.T) {
		for _, p := range eccUnimplemented {
			requireECCProfile(t, p.policy, "SignAndEncrypt")
		}
		endpoint, _ := startECCGoServer(t)

		// The server does not advertise what it does not implement.
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		eps, err := opcua.GetEndpoints(ctx, endpoint)
		if err != nil {
			t.Fatalf("GetEndpoints: %v", err)
		}
		for _, ep := range eps {
			for _, p := range eccUnimplemented {
				if ep.SecurityPolicyURI == ua.FormatSecurityPolicyURI(p.policy) {
					t.Errorf("the go-opcua server advertises %s", p.policy)
				}
			}
		}

		for _, p := range eccUnimplemented {
			start := time.Now()
			result := runECCAdapterClient(t, endpoint, p, "SignAndEncrypt", "read",
				"--node", "nsu="+interopNamespaceURI+";s=Scalar.Int32")
			elapsed := time.Since(start)
			t.Logf("%s: success=%v serviceResult=%s error=%s (%s)", p.policy, result.Success, result.ServiceResult, result.Error, elapsed.Round(time.Millisecond))
			if result.Operation == "" {
				t.Errorf("%s: the adapter produced no result: the refusal cannot be told from a crash or a hang", p.policy)
				continue
			}
			if result.Success {
				t.Errorf("%s: the read succeeded over a policy go-opcua does not implement", p.policy)
			}
			var e struct {
				Category string `json:"category"`
			}
			if err := json.Unmarshal(result.Error, &e); err != nil || e.Category != "transport" {
				t.Errorf("%s: error %s, want category \"transport\" (no matching endpoint)", p.policy, result.Error)
			}
			if elapsed > uncleanFailure {
				t.Errorf("%s: the refusal took %s", p.policy, elapsed)
			}
		}

		// The implemented policy still works on the same server.
		result := runECCAdapterClient(t, endpoint, eccProfiles[0], "SignAndEncrypt", "read",
			"--node", "nsu="+interopNamespaceURI+";s=Scalar.Int32")
		if !result.Success {
			t.Fatalf("read over %s after the refusals: %s error=%s", eccProfiles[0].policy, result.ServiceResult, result.Error)
		}
	})
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
