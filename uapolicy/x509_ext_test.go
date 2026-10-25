// SPDX-License-Identifier: MIT

package uapolicy

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/brainpool"
	"github.com/cloudflare/circl/sign/ed448"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
)

// extKeys returns a new key of every type CreateCertificate handles.
func extKeys(t *testing.T) map[string]crypto.Signer {
	t.Helper()
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return map[string]crypto.Signer{
		"p256":    newECDSAKey(t, elliptic.P256()),
		"p384":    newECDSAKey(t, elliptic.P384()),
		"p521":    newECDSAKey(t, elliptic.P521()),
		"ed25519": ed,
		"bp256":   newECDSAKey(t, brainpool.P256r1()),
		"bp384":   newECDSAKey(t, brainpool.P384r1()),
		"ed448":   newEd448Key(t),
	}
}

func certTemplate(cn string) *x509.Certificate {
	u, _ := url.Parse("urn:uapolicy:" + cn)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"uapolicy"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		URIs:                  []*url.URL{u},
	}
}

func caTemplate(cn string) *x509.Certificate {
	tmpl := certTemplate(cn)
	tmpl.IsCA = true
	tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	tmpl.URIs = nil
	return tmpl
}

type testCert struct {
	der  []byte
	cert *x509.Certificate
	key  crypto.Signer
}

func newTestCert(t *testing.T, tmpl *x509.Certificate, key crypto.Signer, issuer *testCert) *testCert {
	t.Helper()
	parent, signer := tmpl, key
	if issuer != nil {
		parent, signer = issuer.cert, issuer.key
	}
	der, err := CreateCertificate(rand.Reader, tmpl, parent, key.Public(), signer)
	require.NoError(t, err)
	cert, err := ParseCertificate(der)
	require.NoError(t, err)
	return &testCert{der: der, cert: cert, key: key}
}

func TestCreateParseCertificate(t *testing.T) {
	keys := extKeys(t)
	for name, key := range keys {
		t.Run(name, func(t *testing.T) {
			c := newTestCert(t, certTemplate(name), key, nil)
			require.Equal(t, c.der, c.cert.Raw)
			require.True(t, keysEqual(c.cert.PublicKey, key.Public()))
			require.Equal(t, "urn:uapolicy:"+name, c.cert.URIs[0].String())
			require.Equal(t, name, c.cert.Subject.CommonName)
			require.Equal(t, []string{"localhost"}, c.cert.DNSNames)
			require.Equal(t, x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment, c.cert.KeyUsage)

			// The raw fields are those of the certificate itself.
			parts, err := splitCertificate(c.der)
			require.NoError(t, err)
			require.Equal(t, parts.tbs, c.cert.RawTBSCertificate)
			require.Equal(t, parts.spki, c.cert.RawSubjectPublicKeyInfo)

			// A self-signed certificate verifies against itself.
			require.NoError(t, checkCertificateSignature(c.cert, c.cert))
			require.NoError(t, VerifyCertificate([]*x509.Certificate{c.cert}, poolOf(c.cert), []*x509.Certificate{c.cert}))

			pub, err := CertificatePublicKey(c.der)
			require.NoError(t, err)
			require.True(t, keysEqual(pub, key.Public()))
			require.True(t, KeyMatchesCertificate(key, c.der))
			for other, k := range keys {
				if other != name {
					require.False(t, KeyMatchesCertificate(k, c.der), other)
				}
			}

			// Thumbprint and chains work the same.
			other := newTestCert(t, certTemplate(name+" 2"), key, nil)
			chain := append(bytes.Clone(c.der), other.der...)
			certs, err := ParseCertificates(chain)
			require.NoError(t, err)
			require.Len(t, certs, 2)
			require.Equal(t, Thumbprint(c.der), Thumbprint(chain))
		})
	}
}

func poolOf(certs ...*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool
}

// TestCertificateChains issues certificates between every pair of key
// families and verifies the chains, with an intermediate CA as well.
func TestCertificateChains(t *testing.T) {
	keys := extKeys(t)
	for caName, caKey := range keys {
		ca := newTestCert(t, caTemplate("ca "+caName), caKey, nil)
		for leafName := range keys {
			t.Run(caName+"/"+leafName, func(t *testing.T) {
				leafKey := extKeys(t)[leafName]
				leaf := newTestCert(t, certTemplate("leaf "+leafName), leafKey, ca)
				require.Equal(t, ca.cert.SubjectKeyId, leaf.cert.AuthorityKeyId)
				require.NoError(t, checkCertificateSignature(leaf.cert, ca.cert))
				require.NoError(t, VerifyCertificate([]*x509.Certificate{leaf.cert}, poolOf(ca.cert), []*x509.Certificate{ca.cert}))

				// Not trusted without the CA.
				stranger := newTestCert(t, caTemplate("ca "+caName), caKey, nil)
				_ = stranger
				other := newTestCert(t, caTemplate("other ca"), keys["p256"], nil)
				require.Error(t, VerifyCertificate([]*x509.Certificate{leaf.cert}, poolOf(other.cert), []*x509.Certificate{other.cert}))
			})
		}
		t.Run(caName+"/intermediate", func(t *testing.T) {
			inter := newTestCert(t, caTemplate("intermediate under "+caName), keys["ed448"], ca)
			leaf := newTestCert(t, certTemplate("leaf"), keys["bp256"], inter)
			chain := []*x509.Certificate{leaf.cert, inter.cert}
			require.NoError(t, VerifyCertificate(chain, poolOf(ca.cert), []*x509.Certificate{ca.cert}))
			// The intermediate is not a trust anchor.
			require.Error(t, VerifyCertificate([]*x509.Certificate{leaf.cert}, poolOf(ca.cert), []*x509.Certificate{ca.cert}))
		})
	}
}

// TestVerifyEd448Chain covers the rules of the chain builder for Ed448
// signatures.
func TestVerifyEd448Chain(t *testing.T) {
	key := newEd448Key(t)
	ca := newTestCert(t, caTemplate("ed448 ca"), key, nil)
	leafKey := newEd448Key(t)
	leaf := newTestCert(t, certTemplate("ed448 leaf"), leafKey, ca)
	verify := func(chain []*x509.Certificate, anchors ...*x509.Certificate) error {
		return VerifyCertificate(chain, poolOf(anchors...), anchors)
	}
	require.NoError(t, verify([]*x509.Certificate{leaf.cert}, ca.cert))
	// A leaf that is itself trusted.
	require.NoError(t, verify([]*x509.Certificate{leaf.cert}, leaf.cert))
	require.ErrorIs(t, verify([]*x509.Certificate{leaf.cert}), errors.ErrInvalidCertificate)
	require.ErrorIs(t, VerifyCertificate(nil, nil, nil), errors.ErrInvalidCertificate)

	t.Run("tampered signature", func(t *testing.T) {
		bad := *leaf.cert
		bad.Signature = bytes.Clone(bad.Signature)
		bad.Signature[5] ^= 1
		require.ErrorIs(t, verify([]*x509.Certificate{&bad}, ca.cert), errors.ErrInvalidCertificate)
	})
	t.Run("expired", func(t *testing.T) {
		tmpl := certTemplate("expired")
		tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
		old := newTestCert(t, tmpl, newEd448Key(t), ca)
		require.ErrorIs(t, verify([]*x509.Certificate{old.cert}, ca.cert), errors.ErrInvalidCertificate)
		require.ErrorIs(t, verify([]*x509.Certificate{old.cert}, old.cert), errors.ErrInvalidCertificate)

		tmpl = caTemplate("expired ca")
		tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
		oldCA := newTestCert(t, tmpl, key, nil)
		l := newTestCert(t, certTemplate("leaf of expired ca"), newEd448Key(t), oldCA)
		require.ErrorIs(t, verify([]*x509.Certificate{l.cert}, oldCA.cert), errors.ErrInvalidCertificate)
	})
	t.Run("issuer not a CA", func(t *testing.T) {
		tmpl := caTemplate("not a ca")
		tmpl.IsCA = false
		notCA := newTestCert(t, tmpl, key, nil)
		l := newTestCert(t, certTemplate("leaf of not a ca"), newEd448Key(t), notCA)
		require.ErrorIs(t, verify([]*x509.Certificate{l.cert}, notCA.cert), errors.ErrInvalidCertificate)
	})
	t.Run("issuer may not sign certificates", func(t *testing.T) {
		tmpl := caTemplate("no certsign")
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		noSign := newTestCert(t, tmpl, key, nil)
		l := newTestCert(t, certTemplate("leaf of no certsign"), newEd448Key(t), noSign)
		require.ErrorIs(t, verify([]*x509.Certificate{l.cert}, noSign.cert), errors.ErrInvalidCertificate)
	})
	t.Run("path length", func(t *testing.T) {
		tmpl := caTemplate("pathlen 0")
		tmpl.MaxPathLenZero = true
		root := newTestCert(t, tmpl, key, nil)
		interKey := newEd448Key(t)
		inter := newTestCert(t, caTemplate("intermediate"), interKey, root)
		l := newTestCert(t, certTemplate("too deep"), newEd448Key(t), inter)
		require.ErrorIs(t, verify([]*x509.Certificate{l.cert, inter.cert}, root.cert), errors.ErrInvalidCertificate)
		// Directly below the root is fine.
		l2 := newTestCert(t, certTemplate("not too deep"), newEd448Key(t), root)
		require.NoError(t, verify([]*x509.Certificate{l2.cert}, root.cert))
	})
	t.Run("name constraints", func(t *testing.T) {
		tmpl := caTemplate("constrained")
		tmpl.PermittedDNSDomains = []string{"example.com"}
		constrained := newTestCert(t, tmpl, key, nil)
		l := newTestCert(t, certTemplate("leaf of constrained"), newEd448Key(t), constrained)
		require.ErrorIs(t, verify([]*x509.Certificate{l.cert}, constrained.cert), errors.ErrInvalidCertificate)
	})
	t.Run("unknown critical extension", func(t *testing.T) {
		tmpl := certTemplate("critical")
		tmpl.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
		l := newTestCert(t, tmpl, newEd448Key(t), ca)
		require.ErrorIs(t, verify([]*x509.Certificate{l.cert}, ca.cert), errors.ErrInvalidCertificate)
	})
	t.Run("key identifiers", func(t *testing.T) {
		// A CA with the same name but another key: the AuthorityKeyId of
		// the leaf does not match.
		twin := newTestCert(t, caTemplate("ed448 ca"), newEd448Key(t), nil)
		require.ErrorIs(t, verify([]*x509.Certificate{leaf.cert}, twin.cert), errors.ErrInvalidCertificate)
		// Both: the right one is found.
		require.NoError(t, verify([]*x509.Certificate{leaf.cert}, twin.cert, ca.cert))
	})
	t.Run("issuer key of another type", func(t *testing.T) {
		// Same name and key identifier, but a P-256 key cannot have made
		// an Ed448 signature.
		p256 := newECDSAKey(t, elliptic.P256())
		tmpl := caTemplate("ed448 ca")
		tmpl.SubjectKeyId = ca.cert.SubjectKeyId
		impostor := newTestCert(t, tmpl, p256, nil)
		require.ErrorIs(t, verify([]*x509.Certificate{leaf.cert}, impostor.cert), errors.ErrInvalidCertificate)
	})
	t.Run("too long", func(t *testing.T) {
		chain := []*x509.Certificate{}
		issuer := ca
		var certs []*testCert
		for i := range maxChainLength + 1 {
			c := newTestCert(t, caTemplate("level "+string(rune('a'+i))), newEd448Key(t), issuer)
			certs = append(certs, c)
			issuer = c
		}
		l := newTestCert(t, certTemplate("deep leaf"), newEd448Key(t), issuer)
		chain = append(chain, l.cert)
		for i := len(certs) - 1; i >= 0; i-- {
			chain = append(chain, certs[i].cert)
		}
		require.ErrorIs(t, verify(chain, ca.cert), errors.ErrInvalidCertificate)
		// A short one through the same builder works.
		require.NoError(t, verify([]*x509.Certificate{certs[1].cert, certs[0].cert}, ca.cert))
	})
}

// TestBrainpoolChain_Stdlib checks that a Brainpool chain takes the path of
// crypto/x509, which verifies the signatures of the custom curve.
func TestBrainpoolChain_Stdlib(t *testing.T) {
	ca := newTestCert(t, caTemplate("bp ca"), newECDSAKey(t, brainpool.P384r1()), nil)
	leaf := newTestCert(t, certTemplate("bp leaf"), newECDSAKey(t, brainpool.P256r1()), ca)
	require.False(t, hasEd448Signature(leaf.cert))
	require.Equal(t, x509.ECDSAWithSHA384, leaf.cert.SignatureAlgorithm)
	require.Equal(t, x509.ECDSA, leaf.cert.PublicKeyAlgorithm)
	_, err := leaf.cert.Verify(x509.VerifyOptions{Roots: poolOf(ca.cert), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	require.NoError(t, err)
	require.NoError(t, VerifyCertificate([]*x509.Certificate{leaf.cert}, poolOf(ca.cert), nil))
	require.Error(t, VerifyCertificate([]*x509.Certificate{leaf.cert}, nil, nil), "no roots: not the system roots")
}

func readPEM(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "openssl", name))
	require.NoError(t, err)
	return data
}

// TestOpenSSLFixtures parses certificates and keys made by OpenSSL 3.5
// (testdata/openssl): the encodings of open62541 and other OpenSSL based
// stacks.
func TestOpenSSLFixtures(t *testing.T) {
	for _, tt := range []struct {
		name  string
		uri   string
		keys  []string
		curve string
	}{
		{"brainpoolP256r1", ua.SecurityPolicyURIECCBrainpoolP256r1, []string{"brainpoolP256r1-sec1.pem", "brainpoolP256r1-pkcs8.pem"}, "brainpoolP256r1"},
		{"brainpoolP384r1", ua.SecurityPolicyURIECCBrainpoolP384r1, []string{"brainpoolP384r1-sec1.pem", "brainpoolP384r1-pkcs8.pem"}, "brainpoolP384r1"},
		{"ed448", ua.SecurityPolicyURIECCCurve448, []string{"ed448-pkcs8.pem"}, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			block, _ := pem.Decode(readPEM(t, tt.name+"-cert.pem"))
			require.NotNil(t, block)
			cert, err := ParseCertificate(block.Bytes)
			require.NoError(t, err)
			require.Equal(t, "urn:openssl:"+tt.name, cert.URIs[0].String())
			require.NoError(t, CheckCertificate(tt.uri, block.Bytes))
			// Self-signed CA: verifies against itself on either path.
			require.NoError(t, VerifyCertificate([]*x509.Certificate{cert}, poolOf(cert), []*x509.Certificate{cert}))
			require.NoError(t, checkCertificateSignature(cert, cert))
			if tt.curve != "" {
				require.Equal(t, tt.curve, cert.PublicKey.(*ecdsa.PublicKey).Params().Name)
			} else {
				require.True(t, hasEd448Signature(cert))
			}

			for _, name := range tt.keys {
				data := readPEM(t, name)
				key, err := ParsePrivateKey(data)
				require.NoError(t, err, name)
				require.True(t, KeyMatchesCertificate(key, block.Bytes), name)
				b, _ := pem.Decode(data)
				key, err = ParsePrivateKey(b.Bytes) // DER
				require.NoError(t, err, name)
				require.True(t, KeyMatchesCertificate(key, block.Bytes), name)

				// The key signs for the policy, the certificate verifies.
				local, err := AsymmetricKeys(tt.uri, key, cert.PublicKey)
				require.NoError(t, err)
				sig, err := local.Signature([]byte("openssl"))
				require.NoError(t, err)
				require.NoError(t, local.VerifySignature([]byte("openssl"), sig))

				// Marshal and parse again.
				der, err := MarshalPrivateKey(key)
				require.NoError(t, err)
				again, err := ParsePrivateKey(der)
				require.NoError(t, err)
				require.True(t, keysEqual(again.Public(), key.Public()))
			}
		})
	}
}

func TestExtendedPrivateKeys(t *testing.T) {
	for name, key := range extKeys(t) {
		t.Run(name, func(t *testing.T) {
			der, err := MarshalPrivateKey(key)
			require.NoError(t, err)
			for _, data := range [][]byte{der, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})} {
				got, err := ParsePrivateKey(data)
				require.NoError(t, err)
				require.True(t, keysEqual(got.Public(), key.Public()))
				eq, ok := got.(interface{ Equal(crypto.PrivateKey) bool })
				require.True(t, ok)
				require.True(t, eq.Equal(key))
			}
		})
	}
	_, err := MarshalPrivateKey(ed448.PrivateKey("short"))
	require.ErrorIs(t, err, errors.ErrInvalidPrivateKey)
	_, err = MarshalPrivateKey(opaqueSigner{newECDSAKey(t, elliptic.P256())})
	require.ErrorIs(t, err, errors.ErrInvalidPrivateKey)
}

// TestExtendedPrivateKeys_Malformed feeds broken encodings of Brainpool and
// Ed448 keys to ParsePrivateKey.
func TestExtendedPrivateKeys_Malformed(t *testing.T) {
	bp := newECDSAKey(t, brainpool.P256r1())
	n := 32
	d := bp.D.FillBytes(make([]byte, n)) //nolint:staticcheck // SA1019: Bytes does not support custom curves.
	pub := marshalECPoint(&bp.PublicKey)
	curveOID, _ := asn1.Marshal(oidBrainpoolP256r1)
	otherOID, _ := asn1.Marshal(oidBrainpoolP384r1)
	k1OID, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 132, 0, 10}) // secp256k1

	sec1 := func(version int64, d []byte, params []byte, pub []byte) []byte {
		var b cryptobyte.Builder
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1Int64(version)
			b.AddASN1OctetString(d)
			if params != nil {
				b.AddASN1(tagECParameters, func(b *cryptobyte.Builder) { b.AddBytes(params) })
			}
			if pub != nil {
				b.AddASN1(tagECPublicKey, func(b *cryptobyte.Builder) { addBitString(b, pub) })
			}
		})
		return b.BytesOrPanic()
	}
	pemOf := func(typ string, der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}) }

	// The good ones first.
	for name, der := range map[string][]byte{
		"params":            sec1(1, d, curveOID, nil),
		"params and public": sec1(1, d, curveOID, pub),
		"short d":           sec1(1, d[1:], curveOID, nil), // valid if d has a leading zero; else another key
	} {
		key, err := ParsePrivateKey(pemOf("EC PRIVATE KEY", der))
		if name == "short d" {
			if err == nil {
				require.NotNil(t, key)
			}
			continue
		}
		require.NoError(t, err, name)
		require.True(t, keysEqual(key.Public(), &bp.PublicKey), name)
	}

	order := brainpool.P256r1().Params().N
	for name, der := range map[string][]byte{
		"no params":      sec1(1, d, nil, nil),
		"unknown curve":  sec1(1, d, k1OID, nil),
		"version 2":      sec1(2, d, curveOID, nil),
		"zero d":         sec1(1, make([]byte, n), curveOID, nil),
		"d = N":          sec1(1, order.Bytes(), curveOID, nil),
		"d too long":     sec1(1, append([]byte{1}, d...), curveOID, nil),
		"wrong public":   sec1(1, d, curveOID, marshalECPoint(&newECDSAKey(t, brainpool.P256r1()).PublicKey)),
		"garbage public": sec1(1, d, curveOID, []byte{4, 1, 2}),
		"trailing":       append(sec1(1, d, curveOID, nil), 0),
	} {
		_, err := ParsePrivateKey(pemOf("EC PRIVATE KEY", der))
		require.ErrorIs(t, err, errors.ErrInvalidPrivateKey, name)
		_, err = ParsePrivateKey(der)
		require.ErrorIs(t, err, errors.ErrInvalidPrivateKey, name)
	}

	// PKCS #8 wrappers.
	type algID struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}
	type pkcs8 struct {
		Version    int
		Algorithm  algID
		PrivateKey []byte
		Attributes asn1.RawValue  `asn1:"optional,tag:0"`
		PublicKey  asn1.BitString `asn1:"optional,tag:1"`
	}
	wrap := func(v pkcs8) []byte {
		der, err := asn1.Marshal(v)
		require.NoError(t, err)
		return der
	}
	ecAlg := func(params []byte) algID {
		return algID{Algorithm: oidPublicKeyECDSA, Parameters: asn1.RawValue{FullBytes: params}}
	}
	edKey := newEd448Key(t)
	seed, _ := asn1.Marshal(edKey.Seed())
	edPub := []byte(edKey.Public().(ed448.PublicKey))

	good := map[string][]byte{
		"brainpool, no params inside": wrap(pkcs8{Algorithm: ecAlg(curveOID), PrivateKey: sec1(1, d, nil, pub)}),
		"brainpool, params inside":    wrap(pkcs8{Algorithm: ecAlg(curveOID), PrivateKey: sec1(1, d, curveOID, nil)}),
		"ed448 v2 with public key":    wrap(pkcs8{Version: 1, Algorithm: algID{Algorithm: oidEd448}, PrivateKey: seed, PublicKey: asn1.BitString{Bytes: edPub, BitLength: 8 * len(edPub)}}),
		"ed448 with attributes":       wrap(pkcs8{Algorithm: algID{Algorithm: oidEd448}, PrivateKey: seed, Attributes: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: []byte{}}}),
	}
	for name, der := range good {
		_, err := ParsePrivateKey(pemOf("PRIVATE KEY", der))
		require.NoError(t, err, name)
	}
	bad := map[string][]byte{
		"brainpool, other params inside": wrap(pkcs8{Algorithm: ecAlg(curveOID), PrivateKey: sec1(1, d, otherOID, nil)}),
		"brainpool, bad inner":           wrap(pkcs8{Algorithm: ecAlg(curveOID), PrivateKey: []byte{1, 2, 3}}),
		"version 2":                      wrap(pkcs8{Version: 2, Algorithm: algID{Algorithm: oidEd448}, PrivateKey: seed}),
		"ed448 params":                   wrap(pkcs8{Algorithm: algID{Algorithm: oidEd448, Parameters: asn1.NullRawValue}, PrivateKey: seed}),
		"ed448 short seed":               wrap(pkcs8{Algorithm: algID{Algorithm: oidEd448}, PrivateKey: seed[:len(seed)-1]}),
		"ed448 raw seed":                 wrap(pkcs8{Algorithm: algID{Algorithm: oidEd448}, PrivateKey: edKey.Seed()}),
		"ed448 wrong public key":         wrap(pkcs8{Version: 1, Algorithm: algID{Algorithm: oidEd448}, PrivateKey: seed, PublicKey: asn1.BitString{Bytes: make([]byte, 57), BitLength: 8 * 57}}),
		"unknown algorithm":              wrap(pkcs8{Algorithm: algID{Algorithm: asn1.ObjectIdentifier{1, 2, 3}}, PrivateKey: seed}),
		"trailing":                       append(wrap(pkcs8{Algorithm: algID{Algorithm: oidEd448}, PrivateKey: seed}), 0),
	}
	for name, der := range bad {
		_, err := ParsePrivateKey(pemOf("PRIVATE KEY", der))
		require.ErrorIs(t, err, errors.ErrInvalidPrivateKey, name)
	}
}

// TestParseCertificate_Malformed swaps parts of certificates for broken ones.
func TestParseCertificate_Malformed(t *testing.T) {
	keys := extKeys(t)
	bp := newTestCert(t, certTemplate("bp"), keys["bp256"], nil)
	ed := newTestCert(t, certTemplate("ed"), keys["ed448"], nil)

	withSPKI := func(c *testCert, spki []byte) []byte {
		parts, err := splitCertificate(c.der)
		require.NoError(t, err)
		parts.spki = spki
		parts.tbs, err = parts.joinTBS()
		require.NoError(t, err)
		der, err := parts.join()
		require.NoError(t, err)
		return der
	}
	spki := func(alg, key []byte) []byte {
		bits, err := asn1.Marshal(asn1.BitString{Bytes: key, BitLength: 8 * len(key)})
		require.NoError(t, err)
		v, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: append(bytes.Clone(alg), bits...)})
		require.NoError(t, err)
		return v
	}
	alg := func(oids ...asn1.ObjectIdentifier) []byte {
		var body []byte
		for _, o := range oids {
			b, err := asn1.Marshal(o)
			require.NoError(t, err)
			body = append(body, b...)
		}
		v, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
		require.NoError(t, err)
		return v
	}
	point := marshalECPoint(&keys["bp256"].(*ecdsa.PrivateKey).PublicKey)
	offCurve := bytes.Clone(point)
	offCurve[len(offCurve)-1] ^= 1
	compressed := append([]byte{2}, point[1:33]...)

	for name, der := range map[string][]byte{
		"brainpool off curve":   withSPKI(bp, spki(alg(oidPublicKeyECDSA, oidBrainpoolP256r1), offCurve)),
		"brainpool compressed":  withSPKI(bp, spki(alg(oidPublicKeyECDSA, oidBrainpoolP256r1), compressed)),
		"brainpool other curve": withSPKI(bp, spki(alg(oidPublicKeyECDSA, oidBrainpoolP384r1), point)),
		"ed448 short key":       withSPKI(ed, spki(alg(oidEd448), make([]byte, 56))),
		"ed448 params":          withSPKI(ed, spki(alg(oidEd448, oidEd448), make([]byte, 57))),
		"truncated":             bp.der[:len(bp.der)-1],
		"trailing":              append(bytes.Clone(ed.der), 0),
		"garbage":               []byte("not a certificate"),
	} {
		_, err := ParseCertificate(der)
		require.Error(t, err, name)
		_, err = ParseCertificates(der)
		require.Error(t, err, name)
		_, err = CertificatePublicKey(der)
		require.Error(t, err, name)
	}

	// An unknown key algorithm stays as crypto/x509 leaves it.
	unknown := withSPKI(ed, spki(alg(asn1.ObjectIdentifier{1, 2, 3, 4}), make([]byte, 10)))
	cert, err := ParseCertificate(unknown)
	require.NoError(t, err)
	require.Nil(t, cert.PublicKey)
	_, err = CertificatePublicKey(unknown)
	require.ErrorIs(t, err, errors.ErrInvalidCertificate)

	// A NIST key with a curve crypto/x509 does not know is still its error.
	_, err = ParseCertificate(withSPKI(ed, spki(alg(oidPublicKeyECDSA, asn1.ObjectIdentifier{1, 3, 132, 0, 10}), point)))
	require.ErrorContains(t, err, "unsupported elliptic curve")
}

func TestCreateCertificate_Errors(t *testing.T) {
	keys := extKeys(t)
	tmpl := certTemplate("x")
	_, err := CreateCertificate(rand.Reader, tmpl, tmpl, keys["bp256"].Public(), nil)
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)

	withAlgo := certTemplate("algo")
	withAlgo.SignatureAlgorithm = x509.ECDSAWithSHA256
	_, err = CreateCertificate(rand.Reader, withAlgo, withAlgo, keys["bp256"].Public(), keys["bp256"])
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)

	ca := newTestCert(t, caTemplate("ca"), keys["ed448"], nil)
	_, err = CreateCertificate(rand.Reader, tmpl, ca.cert, keys["bp256"].Public(), keys["bp384"])
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig, "the issuer key does not belong to the parent")

	_, err = CreateCertificate(rand.Reader, tmpl, tmpl, ed448.PublicKey("short"), keys["ed448"])
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)

	// A signer that lies about its signatures.
	_, err = CreateCertificate(rand.Reader, tmpl, tmpl, keys["ed448"].Public(), brokenSigner{opaqueSigner{keys["ed448"]}, make([]byte, 114)})
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	_, err = CreateCertificate(rand.Reader, tmpl, tmpl, keys["ed448"].Public(), failingSigner{keys["ed448"]})
	require.Error(t, err)

	// Issuer keys CreateCertificate cannot sign with.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := CreateCertificate(rand.Reader, tmpl, tmpl, keys["ed448"].Public(), rsaKey)
	require.NoError(t, err, "RSA signs with PKCS #1 v1.5 and SHA-256")
	c, err := ParseCertificate(der)
	require.NoError(t, err)
	require.Equal(t, x509.SHA256WithRSA, c.SignatureAlgorithm)
	require.NoError(t, checkCertificateSignature(c, &x509.Certificate{PublicKey: &rsaKey.PublicKey}))

	_, err = signerFor(&ecdsa.PublicKey{})
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	_, err = signerFor(newECDSAKey(t, elliptic.P224()).Public())
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
}
