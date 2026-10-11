// SPDX-License-Identifier: MIT

package uapolicy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
)

func TestParsePrivateKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	p256 := newECDSAKey(t, elliptic.P256())
	p384 := newECDSAKey(t, elliptic.P384())
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pkcs8 := func(key any) []byte {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		require.NoError(t, err)
		return der
	}
	sec1 := func(key *ecdsa.PrivateKey) []byte {
		der, err := x509.MarshalECPrivateKey(key)
		require.NoError(t, err)
		return der
	}
	pemOf := func(typ string, der []byte) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
	}
	type equaler interface{ Equal(crypto.PrivateKey) bool }

	for name, tt := range map[string]struct {
		data []byte
		want equaler
	}{
		"rsa pkcs1 pem":     {pemOf("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey)), rsaKey},
		"rsa pkcs1 der":     {x509.MarshalPKCS1PrivateKey(rsaKey), rsaKey},
		"rsa pkcs8 pem":     {pemOf("PRIVATE KEY", pkcs8(rsaKey)), rsaKey},
		"rsa pkcs8 der":     {pkcs8(rsaKey), rsaKey},
		"p256 pkcs8 pem":    {pemOf("PRIVATE KEY", pkcs8(p256)), p256},
		"p256 pkcs8 der":    {pkcs8(p256), p256},
		"p256 sec1 pem":     {pemOf("EC PRIVATE KEY", sec1(p256)), p256},
		"p256 sec1 der":     {sec1(p256), p256},
		"p384 pkcs8 pem":    {pemOf("PRIVATE KEY", pkcs8(p384)), p384},
		"p384 sec1 pem":     {pemOf("EC PRIVATE KEY", sec1(p384)), p384},
		"p384 sec1 der":     {sec1(p384), p384},
		"ed25519 pkcs8 pem": {pemOf("PRIVATE KEY", pkcs8(edKey)), edKey},
		"ed25519 pkcs8 der": {pkcs8(edKey), edKey},
	} {
		got, err := ParsePrivateKey(tt.data)
		require.NoError(t, err, name)
		require.True(t, tt.want.Equal(got), name)
	}

	for name, data := range map[string][]byte{
		"empty":               nil,
		"garbage":             []byte("not a key"),
		"certificate pem":     pemOf("CERTIFICATE", selfSignedCert(t, p256)),
		"encrypted pem type":  pemOf("ENCRYPTED PRIVATE KEY", pkcs8(p256)),
		"bad pkcs1 pem":       pemOf("RSA PRIVATE KEY", sec1(p256)),
		"bad sec1 pem":        pemOf("EC PRIVATE KEY", pkcs8(rsaKey)),
		"bad pkcs8 pem":       pemOf("PRIVATE KEY", sec1(p256)),
		"truncated pkcs8 der": pkcs8(p256)[:20],
	} {
		_, err := ParsePrivateKey(data)
		require.ErrorIs(t, err, errors.ErrInvalidPrivateKey, name)
	}
}

func TestCertificatePublicKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	p256 := newECDSAKey(t, elliptic.P256())
	p384 := newECDSAKey(t, elliptic.P384())
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	for _, key := range []crypto.Signer{rsaKey, p256, p384, edKey} {
		cert := selfSignedCert(t, key)
		got, err := CertificatePublicKey(cert)
		require.NoError(t, err)
		require.True(t, got.(interface{ Equal(crypto.PublicKey) bool }).Equal(key.Public()))
		require.True(t, KeyMatchesCertificate(key, cert))

		// The thumbprint is the SHA-1 of the DER encoding for every key type.
		require.Len(t, Thumbprint(cert), 20)
	}

	// The leaf of a chain is the application instance certificate.
	chain := append(selfSignedCert(t, p256), selfSignedCert(t, rsaKey)...)
	got, err := CertificatePublicKey(chain)
	require.NoError(t, err)
	require.True(t, p256.PublicKey.Equal(got))

	_, err = CertificatePublicKey([]byte("not a certificate"))
	require.Error(t, err)

	// The RSA accessor keeps refusing other keys.
	_, err = PublicKey(selfSignedCert(t, p256))
	require.Error(t, err)

	require.False(t, KeyMatchesCertificate(p384, selfSignedCert(t, p256)))
	require.False(t, KeyMatchesCertificate(rsaKey, selfSignedCert(t, p256)))
	require.False(t, KeyMatchesCertificate(nil, selfSignedCert(t, p256)))
	require.False(t, KeyMatchesCertificate(p256, []byte("junk")))
	var nilKey *ecdsa.PrivateKey
	require.False(t, KeyMatchesCertificate(nilKey, selfSignedCert(t, p256)))
}

func TestCheckCertificate(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	certs := map[string][]byte{
		"rsa":     selfSignedCert(t, rsaKey),
		"p256":    selfSignedCert(t, newECDSAKey(t, elliptic.P256())),
		"p384":    selfSignedCert(t, newECDSAKey(t, elliptic.P384())),
		"p521":    selfSignedCert(t, newECDSAKey(t, elliptic.P521())),
		"ed25519": selfSignedCert(t, edKey),
	}

	accepted := map[string][]string{
		ua.SecurityPolicyURINone:               {"rsa", "p256", "p384", "p521", "ed25519"},
		ua.SecurityPolicyURIBasic256Sha256:     {"rsa"},
		ua.SecurityPolicyURIAes256Sha256RsaPss: {"rsa"},
		ua.SecurityPolicyURIECCNistP256:        {"p256", "p384"},
		ua.SecurityPolicyURIECCNistP384:        {"p384"},
	}
	for uri, ok := range accepted {
		for name, cert := range certs {
			err := CheckCertificate(uri, cert)
			want := false
			for _, n := range ok {
				want = want || n == name
			}
			if want {
				require.NoError(t, err, "%s with %s", name, uri)
			} else {
				require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig, "%s with %s", name, uri)
			}
		}
	}

	require.ErrorIs(t, CheckCertificate("http://opcfoundation.org/UA/SecurityPolicy#Nope", certs["rsa"]), errors.ErrUnsupportedSecurityPolicy)
	require.Error(t, CheckCertificate(ua.SecurityPolicyURIECCNistP256, []byte("junk")))
}
