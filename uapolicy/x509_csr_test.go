// SPDX-License-Identifier: MIT

package uapolicy

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/ProtonMail/go-crypto/brainpool"
	"github.com/cloudflare/circl/sign/ed448"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/errors"
)

func readPKIX(t testing.TB, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "pkix", name))
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block, name)
	return block.Bytes
}

// csrKeys returns a key of every type CreateCertificateRequest handles.
func csrKeys(t *testing.T) map[string]crypto.Signer {
	t.Helper()
	keys := extKeys(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keys["rsa"] = rsaKey
	return keys
}

func csrTemplate(cn string) *x509.CertificateRequest {
	u, _ := url.Parse("urn:csr:" + cn)
	return &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn, Organization: []string{"uapolicy"}},
		DNSNames: []string{"localhost"},
		URIs:     []*url.URL{u},
	}
}

func TestCreateCertificateRequest(t *testing.T) {
	for name, key := range csrKeys(t) {
		t.Run(name, func(t *testing.T) {
			der, err := CreateCertificateRequest(rand.Reader, csrTemplate(name), key)
			require.NoError(t, err)
			csr, err := ParseCertificateRequest(der)
			require.NoError(t, err)
			require.True(t, keysEqual(csr.PublicKey, key.Public()))
			require.Equal(t, name, csr.Subject.CommonName)
			require.Equal(t, []string{"localhost"}, csr.DNSNames)
			require.Equal(t, "urn:csr:"+name, csr.URIs[0].String())
			require.NoError(t, CheckCertificateRequestSignature(csr))

			spki, _, err := marshalPublicKey(key.Public())
			require.NoError(t, err)
			require.Equal(t, spki, csr.RawSubjectPublicKeyInfo)
			parts, err := splitSigned(der)
			require.NoError(t, err)
			require.Equal(t, parts.tbs, csr.RawTBSCertificateRequest)
			require.Equal(t, der, csr.Raw)

			// A changed signature or request does not verify.
			bad := *csr
			bad.Signature = bytes.Clone(csr.Signature)
			bad.Signature[len(bad.Signature)/2] ^= 1
			require.Error(t, CheckCertificateRequestSignature(&bad))
			tampered := bytes.Clone(der)
			i := bytes.Index(tampered, []byte("localhost"))
			require.Positive(t, i)
			tampered[i] = 'L'
			changed, err := ParseCertificateRequest(tampered)
			require.NoError(t, err)
			require.Error(t, CheckCertificateRequestSignature(changed))

			// A trailing byte is an error.
			_, err = ParseCertificateRequest(append(bytes.Clone(der), 0))
			require.ErrorIs(t, err, errors.ErrInvalidCertificate)
		})
	}
}

// TestCreateCertificateRequest_OpenSSL checks that OpenSSL verifies the
// requests.
func TestCreateCertificateRequest_OpenSSL(t *testing.T) {
	openssl := opensslCLI(t)
	for name, key := range csrKeys(t) {
		t.Run(name, func(t *testing.T) {
			der, err := CreateCertificateRequest(rand.Reader, csrTemplate(name), key)
			require.NoError(t, err)
			file := filepath.Join(t.TempDir(), "req.pem")
			require.NoError(t, os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), 0o600))
			out, err := exec.Command(openssl, "req", "-verify", "-noout", "-in", file).CombinedOutput() //nolint:gosec // test
			require.NoError(t, err, string(out))
			require.Contains(t, string(out), "verify OK")
		})
	}
}

// TestParseCertificateRequest_OpenSSL parses the requests of
// testdata/pkix/generate.sh.
func TestParseCertificateRequest_OpenSSL(t *testing.T) {
	for _, tt := range []struct {
		name  string
		curve elliptic.Curve
	}{
		{"brainpoolP256r1", brainpool.P256r1()},
		{"brainpoolP384r1", brainpool.P384r1()},
		{"ed448", nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			der := readPKIX(t, tt.name+"-csr.pem")
			csr, err := ParseCertificateRequest(der)
			require.NoError(t, err)
			require.NoError(t, CheckCertificateRequestSignature(csr))
			require.Equal(t, "csr-"+tt.name, csr.Subject.CommonName)
			require.Equal(t, "urn:csr:"+tt.name, csr.URIs[0].String())
			require.Equal(t, []string{"localhost"}, csr.DNSNames)
			if tt.curve != nil {
				require.Equal(t, tt.curve, csr.PublicKey.(*ecdsa.PublicKey).Curve)
				require.Equal(t, x509.ECDSA, csr.PublicKeyAlgorithm)
			} else {
				require.IsType(t, ed448.PublicKey{}, csr.PublicKey)
				require.Equal(t, x509.UnknownSignatureAlgorithm, csr.SignatureAlgorithm)
			}
		})
	}
}

func TestCertificateRequest_Errors(t *testing.T) {
	keys := extKeys(t)
	_, err := CreateCertificateRequest(rand.Reader, csrTemplate("x"), nil)
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	_, err = CreateCertificateRequest(rand.Reader, csrTemplate("x"), (*ecdsa.PrivateKey)(nil))
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	_, err = CreateCertificateRequest(rand.Reader, nil, keys["ed448"])
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	tmpl := csrTemplate("x")
	tmpl.SignatureAlgorithm = x509.ECDSAWithSHA256
	_, err = CreateCertificateRequest(rand.Reader, tmpl, keys["bp256"])
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	_, err = CreateCertificateRequest(failingReader{}, csrTemplate("x"), keys["bp256"])
	require.Error(t, err)
	_, err = CreateCertificateRequest(rand.Reader, csrTemplate("x"), wrongSigner{keys["bp256"]})
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)

	require.Error(t, CheckCertificateRequestSignature(nil))

	// Malformed requests.
	_, err = ParseCertificateRequest([]byte{0x30, 0x00})
	require.ErrorIs(t, err, errors.ErrInvalidCertificate)

	// A Brainpool point that is not on the curve, an Ed448 key of the wrong
	// size.
	for _, name := range []string{"brainpoolP256r1", "ed448"} {
		der := readPKIX(t, name+"-csr.pem")
		csr, err := ParseCertificateRequest(der)
		require.NoError(t, err)
		bits := csr.RawSubjectPublicKeyInfo[len(csr.RawSubjectPublicKeyInfo)-4:]
		i := bytes.Index(der, bits)
		require.Positive(t, i)
		bad := bytes.Clone(der)
		bad[i] ^= 0xff
		_, err = ParseCertificateRequest(bad)
		if name == "ed448" {
			// Any 57 bytes are an Ed448 key: the signature fails.
			require.NoError(t, err)
			csr, _ := ParseCertificateRequest(bad)
			require.Error(t, CheckCertificateRequestSignature(csr))
		} else {
			require.ErrorIs(t, err, errors.ErrInvalidCertificate)
		}
	}

	// An Ed448 request with a key of another type or parameters in the
	// algorithm identifier.
	csr, err := ParseCertificateRequest(readPKIX(t, "ed448-csr.pem"))
	require.NoError(t, err)
	bad := *csr
	bad.PublicKey = keys["ed25519"].Public()
	require.Error(t, CheckCertificateRequestSignature(&bad))
	parts, err := splitSigned(csr.Raw)
	require.NoError(t, err)
	parts.algorithm = mustAlgorithmIdentifier(oidEd448, true)
	raw, err := parts.join()
	require.NoError(t, err)
	bad = *csr
	bad.Raw = raw
	require.Error(t, CheckCertificateRequestSignature(&bad))
	parts.algorithm = mustAlgorithmIdentifier(oidSHA256WithRSA, true)
	bad.Raw, err = parts.join()
	require.NoError(t, err)
	require.Error(t, CheckCertificateRequestSignature(&bad))
	bad.Raw = []byte{0x30, 0x00}
	require.Error(t, CheckCertificateRequestSignature(&bad))
}

// failingReader fails every read.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.ErrInvalidState }

// wrongSigner signs another message than it is given.
type wrongSigner struct{ crypto.Signer }

func (w wrongSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	other := bytes.Clone(digest)
	other[0] ^= 1
	return w.Signer.Sign(rand, other, opts)
}

func TestSplitSigned_Malformed(t *testing.T) {
	for _, der := range [][]byte{
		nil,
		{0x30, 0x00},
		{0x30, 0x02, 0x30, 0x00},
		{0x30, 0x04, 0x30, 0x00, 0x30, 0x00},
		{0x30, 0x09, 0x30, 0x00, 0x30, 0x00, 0x03, 0x01, 0x00, 0x05, 0x00},
	} {
		_, err := splitSigned(der)
		require.ErrorIs(t, err, errors.ErrInvalidCertificate)
	}
	for _, der := range [][]byte{
		nil,
		{0x30, 0x00},
		{0x30, 0x05, 0x02, 0x01, 0x00, 0x30, 0x00},
	} {
		_, err := splitRequestInfo(der)
		require.ErrorIs(t, err, errors.ErrInvalidCertificate)
	}
	require.Nil(t, (&signedParts{algorithm: []byte{0x30, 0x00}}).signatureOID())
}

// FuzzParseCertificateRequest checks that ParseCertificateRequest and
// CheckCertificateRequestSignature never panic.
func FuzzParseCertificateRequest(f *testing.F) {
	files, err := filepath.Glob(filepath.Join("testdata", "pkix", "*-csr.pem"))
	if err != nil {
		f.Fatal(err)
	}
	for _, name := range files {
		data, err := os.ReadFile(name)
		if err != nil {
			f.Fatal(err)
		}
		block, _ := pem.Decode(data)
		f.Add(block.Bytes)
	}
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x00})
	f.Fuzz(func(t *testing.T, der []byte) {
		csr, err := ParseCertificateRequest(der)
		if err != nil {
			return
		}
		_ = CheckCertificateRequestSignature(csr)
		if isExtendedKey(csr.PublicKey) {
			spki, _, err := marshalPublicKey(csr.PublicKey)
			if err != nil || !bytes.Equal(spki, csr.RawSubjectPublicKeyInfo) {
				t.Fatalf("parsed key is not the request key: %v", err)
			}
		}
	})
}
