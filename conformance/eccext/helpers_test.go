// SPDX-License-Identifier: MIT

package eccext

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// waitTimeout is the generous upper bound used when polling for an
// asynchronous effect (a notification, a state change). Tests return as soon as
// the condition holds; the bound only matters on a heavily loaded machine.
const waitTimeout = 20 * time.Second

// fastInterval is the publishing interval used by subscription tests.
const fastInterval = 20 * time.Millisecond

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
// once per test binary. The certificates come from internal/testutil/testpki,
// which the chaos suites share.
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

	// ecc holds the certificates for the ECC security policies.
	ecc *eccPKI
}

const ()

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
	src, err := testpki.Get()
	if err != nil {
		return nil, err
	}
	return &testPKI{
		serverCert:     src.ServerCert,
		serverKey:      src.ServerKey,
		clientCert:     src.ClientCert,
		clientKey:      src.ClientKey,
		caCert:         src.CACert,
		issuedCert:     src.IssuedCert,
		issuedKey:      src.IssuedKey,
		userCert:       src.UserCert,
		userKey:        src.UserKey,
		strangerCert:   src.StrangerCert,
		strangerKey:    src.StrangerKey,
		serverCertX509: src.ServerCertX509,
		ecc:            adaptECC(src.ECC),
	}, nil
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
