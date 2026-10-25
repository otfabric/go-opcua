// SPDX-License-Identifier: MIT

package uapolicy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/stretchr/testify/require"
)

// rsaTestPolicies returns the policies that the RSA based tests of this
// package apply to: everything but the ECC policies, which take other keys
// and derive their symmetric keys differently.
func rsaTestPolicies() []string {
	var uris []string
	for _, uri := range SupportedPolicies() {
		if !IsECC(uri) {
			uris = append(uris, uri)
		}
	}
	return uris
}

func eccTestPolicies() []string {
	var uris []string
	for _, uri := range SupportedPolicies() {
		if IsECC(uri) {
			uris = append(uris, uri)
		}
	}
	return uris
}

// eccTestKey returns a new application instance key of a type the ECC policy
// accepts, and the size of the signatures it makes.
func eccTestKey(t *testing.T, uri string) (crypto.Signer, int) {
	t.Helper()
	p, ok := eccPolicies[uri]
	require.True(t, ok, uri)
	switch suite := p.signature.(type) {
	case ecdsaSuite:
		return newECDSAKey(t, suite.curves[0]), ecdsaSignatureSize(suite.curves[0])
	case ed25519Suite:
		_, key, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		return key, ed25519.SignatureSize
	case ed448Suite:
		return newEd448Key(t), ed448.SignatureSize
	}
	t.Fatalf("no test key for %s", uri)
	return nil, 0
}

// aeadTestPolicies returns the ECC policies with authenticated encryption.
func aeadTestPolicies() []string {
	var uris []string
	for _, uri := range eccTestPolicies() {
		if IsAEAD(uri) {
			uris = append(uris, uri)
		}
	}
	return uris
}

func newECDSAKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	return key
}

func newEd448Key(t *testing.T) ed448.PrivateKey {
	t.Helper()
	_, key, err := ed448.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return key
}

// selfSignedCert returns a DER encoded self-signed certificate for key.
func selfSignedCert(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "uapolicy test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	return der
}
