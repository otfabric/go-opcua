// SPDX-License-Identifier: MIT

package security

import (
	"sync"
	"testing"

	"github.com/otfabric/go-opcua/internal/testutil/conformkit"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
)

// testPKI is the PKI of conformkit (the RSA certificates of
// internal/testutil/testpki) plus the ECC certificates in the shape the ECC
// tests use.
type testPKI struct {
	*testpki.PKI

	// ecc holds the certificates for the ECC security policies.
	ecc *eccPKI
}

var (
	pkiOnce sync.Once
	pkiVal  *testPKI
)

func pki(t *testing.T) *testPKI {
	t.Helper()
	p := conformkit.PKI(t)
	pkiOnce.Do(func() { pkiVal = &testPKI{PKI: p, ecc: adaptECC(p.ECC)} })
	return pkiVal
}
