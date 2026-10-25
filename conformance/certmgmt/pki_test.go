// SPDX-License-Identifier: MIT

package certmgmt

import (
	"crypto/rsa"
	"sync"
	"testing"

	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/stretchr/testify/require"
)

// testPKI holds the RSA certificates of internal/testutil/testpki that the
// certificate management tests use. RSA key generation is expensive (more so
// under the race detector), so it is built once per test binary.
type testPKI struct {
	// Self-signed application instance certificates.
	serverCert []byte
	serverKey  *rsa.PrivateKey
	clientCert []byte
	clientKey  *rsa.PrivateKey

	// A CA plus a client certificate issued by it.
	caCert     []byte
	issuedCert []byte
	issuedKey  *rsa.PrivateKey
	userCert   []byte // self-signed X.509 user identity certificate
	userKey    *rsa.PrivateKey
}

var (
	pkiOnce sync.Once
	pkiVal  *testPKI
	pkiErr  error
)

func pki(t *testing.T) *testPKI {
	t.Helper()
	pkiOnce.Do(func() {
		src, err := testpki.Get()
		if err != nil {
			pkiErr = err
			return
		}
		pkiVal = &testPKI{
			serverCert: src.ServerCert,
			serverKey:  src.ServerKey,
			clientCert: src.ClientCert,
			clientKey:  src.ClientKey,
			caCert:     src.CACert,
			issuedCert: src.IssuedCert,
			issuedKey:  src.IssuedKey,
			userCert:   src.UserCert,
			userKey:    src.UserKey,
		}
	})
	require.NoError(t, pkiErr)
	return pkiVal
}
