// SPDX-License-Identifier: MIT

package uapolicy

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/errors"
)

// revokedSerial is the serial number the CRLs of the tests revoke; its
// encoding occurs once in a CRL.
var revokedSerial = big.NewInt(0x5eedc0ffee)

func crlCATemplate(cn string) *x509.Certificate {
	tmpl := caTemplate(cn)
	tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	return tmpl
}

func crlTemplate() *x509.RevocationList {
	now := time.Now()
	return &x509.RevocationList{
		Number:     big.NewInt(7),
		ThisUpdate: now.Add(-time.Minute),
		NextUpdate: now.Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: revokedSerial, RevocationTime: now.Add(-time.Hour), ReasonCode: 1},
		},
	}
}

func newTestCRL(t *testing.T, ca *testCert) []byte {
	t.Helper()
	der, err := CreateRevocationList(rand.Reader, crlTemplate(), ca.cert, ca.key)
	require.NoError(t, err)
	return der
}

func TestCreateRevocationList(t *testing.T) {
	keys := extKeys(t)
	for name, key := range keys {
		t.Run(name, func(t *testing.T) {
			ca := newTestCert(t, crlCATemplate("crl-ca-"+name), key, nil)
			der := newTestCRL(t, ca)
			crl, err := ParseRevocationList(der)
			require.NoError(t, err)
			require.NoError(t, CheckRevocationListSignature(crl, ca.cert))
			require.Equal(t, ca.cert.RawSubject, crl.RawIssuer)
			require.Equal(t, ca.cert.SubjectKeyId, crl.AuthorityKeyId)
			require.Equal(t, int64(7), crl.Number.Int64())
			require.Len(t, crl.RevokedCertificateEntries, 1)
			require.Equal(t, revokedSerial, crl.RevokedCertificateEntries[0].SerialNumber)
			require.Equal(t, 1, crl.RevokedCertificateEntries[0].ReasonCode)

			// A changed TBSCertList or signature does not verify.
			serial := revokedSerial.Bytes()
			i := bytes.Index(der, serial)
			require.Positive(t, i)
			tampered := bytes.Clone(der)
			tampered[i] ^= 1
			changed, err := ParseRevocationList(tampered)
			require.NoError(t, err)
			require.Error(t, CheckRevocationListSignature(changed, ca.cert))
			tampered = bytes.Clone(der)
			tampered[len(tampered)-2] ^= 1
			changed, err = ParseRevocationList(tampered)
			require.NoError(t, err)
			require.Error(t, CheckRevocationListSignature(changed, ca.cert))

			// Trailing data.
			_, err = ParseRevocationList(append(bytes.Clone(der), 0))
			require.ErrorIs(t, err, errors.ErrInvalidCertificate)

			// Another issuer: name, key identifier, key.
			other := "ed448"
			if name == other {
				other = "bp256"
			}
			o := newTestCert(t, crlCATemplate("crl-ca-"+other), keys[other], nil)
			require.ErrorIs(t, CheckRevocationListSignature(crl, o.cert), errors.ErrInvalidCertificate)
			sameName := newTestCert(t, crlCATemplate("crl-ca-"+name), keys[other], nil)
			require.ErrorIs(t, CheckRevocationListSignature(crl, sameName.cert), errors.ErrInvalidCertificate)
			noKeyID := *sameName.cert
			noKeyID.SubjectKeyId = nil
			require.ErrorIs(t, CheckRevocationListSignature(crl, &noKeyID), errors.ErrInvalidCertificate)

			// The issuer is no CA, or may not sign CRLs.
			notCA := *ca.cert
			notCA.IsCA = false
			require.ErrorIs(t, CheckRevocationListSignature(crl, &notCA), errors.ErrInvalidCertificate)
			noBasicConstraints := *ca.cert
			noBasicConstraints.BasicConstraintsValid = false
			require.ErrorIs(t, CheckRevocationListSignature(crl, &noBasicConstraints), errors.ErrInvalidCertificate)
			noCRLSign := *ca.cert
			noCRLSign.KeyUsage = x509.KeyUsageCertSign
			require.ErrorIs(t, CheckRevocationListSignature(crl, &noCRLSign), errors.ErrInvalidCertificate)

			// A version 3 CA with an IsCA false is rejected as such: made
			// for real, not by changing the parsed certificate.
			tmpl := crlCATemplate("crl-leaf-" + name)
			tmpl.IsCA = false
			tmpl.SubjectKeyId = []byte{1, 2, 3, 4}
			leaf := newTestCert(t, tmpl, key, nil)
			leafCRL, err := CreateRevocationList(rand.Reader, crlTemplate(), leaf.cert, key)
			require.NoError(t, err)
			parsed, err := ParseRevocationList(leafCRL)
			require.NoError(t, err)
			require.ErrorIs(t, CheckRevocationListSignature(parsed, leaf.cert), errors.ErrInvalidCertificate)
		})
	}
}

// TestCreateRevocationList_OpenSSL checks that OpenSSL verifies the CRLs.
func TestCreateRevocationList_OpenSSL(t *testing.T) {
	openssl := opensslCLI(t)
	for name, key := range extKeys(t) {
		t.Run(name, func(t *testing.T) {
			ca := newTestCert(t, crlCATemplate("crl-ca-"+name), key, nil)
			der := newTestCRL(t, ca)
			dir := t.TempDir()
			crlFile, caFile := filepath.Join(dir, "crl.pem"), filepath.Join(dir, "ca.pem")
			require.NoError(t, os.WriteFile(crlFile, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), 0o600))
			require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.der}), 0o600))
			out, err := exec.Command(openssl, "crl", "-in", crlFile, "-CAfile", caFile, "-noout").CombinedOutput() //nolint:gosec // test
			require.NoError(t, err, string(out))
			require.Contains(t, string(out), "verify OK")
		})
	}
}

// TestRevocationList_OpenSSLFixtures verifies the CRLs of
// testdata/pkix/generate.sh.
func TestRevocationList_OpenSSLFixtures(t *testing.T) {
	for _, name := range []string{"brainpoolP256r1", "brainpoolP384r1", "ed448"} {
		t.Run(name, func(t *testing.T) {
			ca, err := ParseCertificate(readPKIX(t, name+"-ca.pem"))
			require.NoError(t, err)
			crl, err := ParseRevocationList(readPKIX(t, name+"-crl.pem"))
			require.NoError(t, err)
			require.NoError(t, CheckRevocationListSignature(crl, ca))
			require.Len(t, crl.RevokedCertificateEntries, 1)
			require.Equal(t, int64(0x1001), crl.RevokedCertificateEntries[0].SerialNumber.Int64())
			require.Equal(t, 1, crl.RevokedCertificateEntries[0].ReasonCode)

			// The CRL of another fixture CA does not verify.
			other := "ed448"
			if name == "ed448" {
				other = "brainpoolP256r1"
			}
			otherCA, err := ParseCertificate(readPKIX(t, other+"-ca.pem"))
			require.NoError(t, err)
			require.Error(t, CheckRevocationListSignature(crl, otherCA))
			// Same name, other key.
			swapped := *ca
			swapped.PublicKey = otherCA.PublicKey
			swapped.SubjectKeyId = nil
			require.Error(t, CheckRevocationListSignature(crl, &swapped))
		})
	}
}

func TestRevocationList_Errors(t *testing.T) {
	keys := extKeys(t)
	ca := newTestCert(t, crlCATemplate("crl-ca"), keys["ed448"], nil)
	_, err := CreateRevocationList(rand.Reader, crlTemplate(), ca.cert, nil)
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	_, err = CreateRevocationList(rand.Reader, nil, ca.cert, ca.key)
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	_, err = CreateRevocationList(rand.Reader, crlTemplate(), nil, ca.key)
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	tmpl := crlTemplate()
	tmpl.SignatureAlgorithm = x509.PureEd25519
	_, err = CreateRevocationList(rand.Reader, tmpl, ca.cert, ca.key)
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	_, err = CreateRevocationList(rand.Reader, crlTemplate(), ca.cert, keys["bp256"])
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	_, err = CreateRevocationList(failingReader{}, crlTemplate(), ca.cert, ca.key)
	require.Error(t, err)
	_, err = CreateRevocationList(rand.Reader, crlTemplate(), ca.cert, wrongSigner{ca.key})
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	noKey := *ca.cert
	noKey.PublicKey = nil
	noKey.SubjectKeyId = nil // x509.CreateRevocationList needs it
	_, err = CreateRevocationList(rand.Reader, crlTemplate(), &noKey, ca.key)
	require.Error(t, err)
	_, err = CreateRevocationList(rand.Reader, crlTemplate(), ca.cert, failingSigner{ca.key})
	require.Error(t, err)

	require.Error(t, CheckRevocationListSignature(nil, ca.cert))
	crl, err := ParseRevocationList(newTestCRL(t, ca))
	require.NoError(t, err)
	require.Error(t, CheckRevocationListSignature(crl, nil))

	// An Ed448 CRL with parameters in the algorithm identifier, with an
	// unknown algorithm, or with a broken Raw.
	parts, err := splitSigned(crl.Raw)
	require.NoError(t, err)
	bad := *crl
	parts.algorithm = mustAlgorithmIdentifier(oidEd448, true)
	bad.Raw, err = parts.join()
	require.NoError(t, err)
	require.Error(t, CheckRevocationListSignature(&bad, ca.cert))
	parts.algorithm = mustAlgorithmIdentifier(oidSHA256WithRSA, false)
	bad.Raw, err = parts.join()
	require.NoError(t, err)
	require.Error(t, CheckRevocationListSignature(&bad, ca.cert))
	bad.Raw = nil
	require.Error(t, CheckRevocationListSignature(&bad, ca.cert))

	_, err = ParseRevocationList([]byte{0x30, 0x00})
	require.ErrorIs(t, err, errors.ErrInvalidCertificate)
	_, err = ParseRevocationList(nil)
	require.ErrorIs(t, err, errors.ErrInvalidCertificate)

	// The standard library path.
	p256 := newTestCert(t, crlCATemplate("crl-p256"), keys["p256"], nil)
	_, err = CreateRevocationList(rand.Reader, crlTemplate(), p256.cert, keys["p256"])
	require.NoError(t, err)
}

// FuzzParseRevocationList checks that ParseRevocationList and
// CheckRevocationListSignature never panic.
func FuzzParseRevocationList(f *testing.F) {
	var cas []*x509.Certificate
	for _, name := range []string{"brainpoolP256r1", "brainpoolP384r1", "ed448"} {
		f.Add(readPKIX(f, name+"-crl.pem"))
		ca, err := ParseCertificate(readPKIX(f, name+"-ca.pem"))
		if err != nil {
			f.Fatal(err)
		}
		cas = append(cas, ca)
	}
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01})
	f.Fuzz(func(t *testing.T, der []byte) {
		crl, err := ParseRevocationList(der)
		if err != nil {
			return
		}
		for _, ca := range cas {
			_ = CheckRevocationListSignature(crl, ca)
		}
	})
}
