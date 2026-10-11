// SPDX-License-Identifier: MIT

package conformance

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/stretchr/testify/require"
)

// waitTimeout is the generous upper bound used when polling for an
// asynchronous effect (a notification, a state change). Tests return as soon as
// the condition holds; the bound only matters on a heavily loaded machine.
const waitTimeout = 20 * time.Second

// fastInterval is the publishing interval used by subscription tests.
const fastInterval = 20 * time.Millisecond

// eventually polls cond until it returns true or waitTimeout elapses.
func eventually(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("condition not met within %s: %s", waitTimeout, msg)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// parallelTests remembers which tests were already marked parallel, since
// t.Parallel may be called only once per test.
var parallelTests sync.Map

// parallel marks t as a parallel test (once). Every test that brings up its
// own server on an OS-assigned port calls it: each server start is costly
// under the race detector, so running such tests concurrently is what keeps
// the suite's wall time down. Tests that need a fixed port stay serial.
func parallel(t *testing.T) {
	t.Helper()
	if _, done := parallelTests.LoadOrStore(t, true); !done {
		t.Parallel()
	}
}

// newServer starts a server on an OS-assigned loopback port, with a None
// endpoint and anonymous access plus the given options, and returns it with
// its endpoint URL. Letting the OS pick the port (instead of probing for a
// free one first) rules out two concurrently starting servers ending up with
// the same port. The server is closed on test cleanup.
func newServer(t *testing.T, opts ...server.Option) (*server.Server, string) {
	t.Helper()
	parallel(t)
	all := append([]server.Option{
		server.EndPoint("localhost", 0),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
	}, opts...)
	srv, err := server.New(all...)
	require.NoError(t, err)
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })
	require.NotZero(t, srv.Port())
	return srv, fmt.Sprintf("opc.tcp://localhost:%d", srv.Port())
}

// setupWith is like setup but lets the caller add server options and tweak the
// server (e.g. attach a historian or more nodes) before the client connects.
func setupWith(t *testing.T, prepare func(srv *server.Server, f *testutil.Fixture), opts ...server.Option) (*opcua.Client, *testutil.Fixture, *server.Server, string) {
	t.Helper()
	srv, url := newServer(t, opts...)
	f := testutil.AddFixture(t, srv)
	if prepare != nil {
		prepare(srv, f)
	}
	c := testutil.NewTestClient(t, url)
	return c, f, srv, url
}

// newClient builds and connects an additional client against url. The client
// is closed on test cleanup.
func newClient(t *testing.T, url string, opts ...opcua.Option) *opcua.Client {
	t.Helper()
	c, err := dialClient(t, url, opts...)
	require.NoError(t, err)
	return c
}

// dialClient builds a client with generous timeouts and connects it, returning
// the connect error so negative tests can assert on it.
func dialClient(t *testing.T, url string, opts ...opcua.Option) (*opcua.Client, error) {
	t.Helper()
	all := append([]opcua.Option{
		opcua.SecurityMode(ua.MessageSecurityModeNone),
		opcua.DialTimeout(30 * time.Second),
		opcua.RequestTimeout(30 * time.Second),
		// The client treats certain service faults (BadSessionIdInvalid,
		// BadSubscriptionIdInvalid, BadNoSubscription) as a sign that its
		// session or subscriptions are gone and, with automatic reconnect
		// enabled, replaces the session in the background. Many tests provoke
		// exactly these faults on purpose and then keep using the session,
		// so recovery is off unless a test asks for it.
		opcua.AutoReconnect(false),
	}, opts...)
	c, err := opcua.NewClient(url, all...)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		_ = c.Close(context.Background())
		return nil, err
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c, nil
}

// ackDialer returns a Dialer option that advertises the given UACP limits in
// the client's HELLO.
func ackDialer(ack *uacp.Acknowledge) opcua.Option {
	return opcua.Dialer(&uacp.Dialer{Dialer: &net.Dialer{}, ClientACK: ack})
}

// --- notification helpers ---------------------------------------------------

// dataChange is one flattened data-change sample.
type dataChange struct {
	handle uint32
	dv     *ua.DataValue
}

// nextDataChanges blocks until the next publish that carries at least one
// data-change sample and returns its samples in wire order.
func nextDataChanges(t *testing.T, ch <-chan *opcua.PublishNotificationData) []dataChange {
	t.Helper()
	deadline := time.After(waitTimeout)
	for {
		select {
		case msg := <-ch:
			require.NoError(t, msg.Error)
			dcn, ok := msg.Value.(*ua.DataChangeNotification)
			if !ok || len(dcn.MonitoredItems) == 0 {
				continue
			}
			out := make([]dataChange, len(dcn.MonitoredItems))
			for i, it := range dcn.MonitoredItems {
				out[i] = dataChange{handle: it.ClientHandle, dv: it.Value}
			}
			return out
		case <-deadline:
			t.Fatal("timed out waiting for a data-change notification")
			return nil
		}
	}
}

// sampleBuffer remembers data-change samples that were read from a notify
// channel but not yet claimed by an assertion, so awaiting one handle never
// discards samples of another that arrived in the same or an earlier publish.
type sampleBuffer struct {
	mu      sync.Mutex
	pending []dataChange
}

var sampleBuffers sync.Map // (<-chan *opcua.PublishNotificationData) -> *sampleBuffer

func bufferFor(ch <-chan *opcua.PublishNotificationData) *sampleBuffer {
	b, _ := sampleBuffers.LoadOrStore(ch, &sampleBuffer{})
	return b.(*sampleBuffer)
}

// take removes and returns the first pending sample for handle matching want.
// Older samples of the same handle are discarded with it.
func (b *sampleBuffer) take(handle uint32, want any) *ua.DataValue {
	for i, s := range b.pending {
		if s.handle != handle || s.dv == nil || s.dv.Value == nil || s.dv.Value.Value() != want {
			continue
		}
		kept := b.pending[:0:0]
		for j, o := range b.pending {
			if j == i || (j < i && o.handle == handle) {
				continue
			}
			kept = append(kept, o)
		}
		b.pending = kept
		return s.dv
	}
	return nil
}

// awaitValue waits until a sample for handle with the given value has been
// received on ch and returns it. Samples for other handles are kept for later
// calls.
func awaitValue(t *testing.T, ch <-chan *opcua.PublishNotificationData, handle uint32, want any) *ua.DataValue {
	t.Helper()
	b := bufferFor(ch)
	b.mu.Lock()
	defer b.mu.Unlock()
	deadline := time.After(waitTimeout)
	for {
		if dv := b.take(handle, want); dv != nil {
			return dv
		}
		select {
		case msg := <-ch:
			require.NoError(t, msg.Error)
			if dcn, ok := msg.Value.(*ua.DataChangeNotification); ok {
				for _, it := range dcn.MonitoredItems {
					b.pending = append(b.pending, dataChange{handle: it.ClientHandle, dv: it.Value})
				}
			}
		case <-deadline:
			t.Fatalf("timed out waiting for handle %d to report %v", handle, want)
			return nil
		}
	}
}

// expectNoDataChange asserts that no data-change sample for handle is pending
// or arrives within the quiet window d.
func expectNoDataChange(t *testing.T, ch <-chan *opcua.PublishNotificationData, handle uint32, d time.Duration) {
	t.Helper()
	b := bufferFor(ch)
	b.mu.Lock()
	defer b.mu.Unlock()
	check := func() {
		for _, s := range b.pending {
			if s.handle == handle {
				t.Fatalf("unexpected data change for handle %d: %v", handle, s.dv.Value.Value())
			}
		}
	}
	check()
	timer := time.After(d)
	for {
		select {
		case msg := <-ch:
			if msg.Error != nil {
				continue
			}
			if dcn, ok := msg.Value.(*ua.DataChangeNotification); ok {
				for _, it := range dcn.MonitoredItems {
					b.pending = append(b.pending, dataChange{handle: it.ClientHandle, dv: it.Value})
				}
			}
			check()
		case <-timer:
			return
		}
	}
}

// nextEvents blocks until the next publish carrying events and returns them.
func nextEvents(t *testing.T, ch <-chan *opcua.PublishNotificationData) []*ua.EventFieldList {
	t.Helper()
	deadline := time.After(waitTimeout)
	for {
		select {
		case msg := <-ch:
			require.NoError(t, msg.Error)
			enl, ok := msg.Value.(*ua.EventNotificationList)
			if !ok || len(enl.Events) == 0 {
				continue
			}
			return enl.Events
		case <-deadline:
			t.Fatal("timed out waiting for an event notification")
			return nil
		}
	}
}

// writeInt32 writes an int32 to a node and requires StatusOK.
func writeInt32(t *testing.T, c *opcua.Client, id *ua.NodeID, v int32) {
	t.Helper()
	st, err := c.WriteNodeValue(context.Background(), id, v)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, st)
}

// --- PKI helpers ------------------------------------------------------------

// testPKI is a small in-memory PKI shared by all security tests. RSA key
// generation is expensive (more so under the race detector), so it is built
// once per test binary.
type testPKI struct {
	// Self-signed application instance certificates.
	serverCert []byte
	serverKey  *rsa.PrivateKey
	clientCert []byte
	clientKey  *rsa.PrivateKey

	// A CA plus a client certificate issued by it, for trust-list tests.
	caCert         []byte
	issuedCert     []byte
	issuedKey      *rsa.PrivateKey
	userCert       []byte // self-signed X.509 user identity certificate
	userKey        *rsa.PrivateKey
	strangerCert   []byte // a second self-signed cert nobody trusts
	strangerKey    *rsa.PrivateKey
	serverCertX509 *x509.Certificate
}

const (
	serverAppURI = "urn:otfabric:conformance:server"
	clientAppURI = "urn:otfabric:conformance:client"
)

var (
	pkiOnce sync.Once
	pkiVal  *testPKI
	pkiErr  error
)

func pki(t *testing.T) *testPKI {
	t.Helper()
	pkiOnce.Do(func() { pkiVal, pkiErr = buildPKI() })
	require.NoError(t, pkiErr)
	return pkiVal
}

func buildPKI() (*testPKI, error) {
	p := &testPKI{}
	var err error
	if p.serverCert, p.serverKey, err = selfSigned("conformance server", serverAppURI); err != nil {
		return nil, err
	}
	if p.clientCert, p.clientKey, err = selfSigned("conformance client", clientAppURI); err != nil {
		return nil, err
	}
	if p.userCert, p.userKey, err = selfSigned("conformance user", "urn:otfabric:conformance:user"); err != nil {
		return nil, err
	}
	if p.strangerCert, p.strangerKey, err = selfSigned("conformance stranger", "urn:otfabric:conformance:stranger"); err != nil {
		return nil, err
	}
	if p.serverCertX509, err = x509.ParseCertificate(p.serverCert); err != nil {
		return nil, err
	}

	// CA and a leaf issued by it.
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	caTmpl := certTemplate("conformance CA", "")
	caTmpl.IsCA = true
	caTmpl.KeyUsage |= x509.KeyUsageCertSign
	if p.caCert, err = x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey); err != nil {
		return nil, err
	}
	caX509, err := x509.ParseCertificate(p.caCert)
	if err != nil {
		return nil, err
	}
	if p.issuedKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		return nil, err
	}
	leaf := certTemplate("conformance issued client", clientAppURI)
	if p.issuedCert, err = x509.CreateCertificate(rand.Reader, leaf, caX509, &p.issuedKey.PublicKey, caKey); err != nil {
		return nil, err
	}
	return p, nil
}

func certTemplate(cn, appURI string) *x509.Certificate {
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"otfabric conformance"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment |
			x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	if appURI != "" {
		if u, err := url.Parse(appURI); err == nil {
			tmpl.URIs = []*url.URL{u}
		}
	}
	return tmpl
}

func selfSigned(cn, appURI string) ([]byte, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	tmpl := certTemplate(cn, appURI)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	return der, key, nil
}

// endpointFor returns the endpoint advertised by the server for the given
// policy (short name or URI) and mode.
func endpointFor(t *testing.T, url, policyURI string, mode ua.MessageSecurityMode) *ua.EndpointDescription {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	eps, err := opcua.GetEndpoints(ctx, url, opcua.DialTimeout(30*time.Second), opcua.RequestTimeout(30*time.Second))
	require.NoError(t, err)
	for _, ep := range eps {
		if ep.SecurityPolicyURI == policyURI && ep.SecurityMode == mode {
			return ep
		}
	}
	t.Fatalf("server does not advertise %s / %s", policyURI, mode)
	return nil
}
