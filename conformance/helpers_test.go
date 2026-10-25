// SPDX-License-Identifier: MIT

package conformance

import (
	"crypto/rsa"
	"crypto/x509"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil/conformkit"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/stretchr/testify/require"
)

// The generic helpers are shared with the other conformance packages, see
// conformkit.
const (
	waitTimeout  = conformkit.WaitTimeout
	fastInterval = conformkit.FastInterval
)

var (
	eventually         = conformkit.Eventually
	parallel           = conformkit.Parallel
	newServer          = conformkit.NewServer
	setupWith          = conformkit.SetupWith
	newClient          = conformkit.NewClient
	dialClient         = conformkit.DialClient
	awaitValue         = conformkit.AwaitValue
	expectNoDataChange = conformkit.ExpectNoDataChange
	nextEvents         = conformkit.NextEvents
	writeInt32         = conformkit.WriteInt32
	endpointFor        = conformkit.EndpointFor
	pendingValues      = conformkit.PendingValues
)

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

const (
	serverAppURI = testpki.ServerAppURI
	clientAppURI = testpki.ClientAppURI
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
