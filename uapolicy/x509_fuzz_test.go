// SPDX-License-Identifier: MIT

package uapolicy

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/otfabric/go-opcua/ua"
)

// fuzzSeeds returns the DER blocks of the OpenSSL fixtures with the given
// PEM type.
func fuzzSeeds(f *testing.F, typ string) [][]byte {
	f.Helper()
	files, err := filepath.Glob(filepath.Join("testdata", "openssl", "*.pem"))
	if err != nil {
		f.Fatal(err)
	}
	var seeds [][]byte
	for _, name := range files {
		data, err := os.ReadFile(name)
		if err != nil {
			f.Fatal(err)
		}
		if b, _ := pem.Decode(data); b != nil && (b.Type == typ || typ == "") {
			seeds = append(seeds, b.Bytes)
		}
	}
	return seeds
}

// FuzzParseCertificate checks that ParseCertificates never panics, and that
// a Brainpool or Ed448 key it accepts is the key of the certificate: encoded
// again, it is the SubjectPublicKeyInfo of the certificate.
func FuzzParseCertificate(f *testing.F) {
	for _, s := range fuzzSeeds(f, "CERTIFICATE") {
		f.Add(s)
	}
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x00})
	f.Fuzz(func(t *testing.T, der []byte) {
		certs, err := ParseCertificates(der)
		if err != nil {
			return
		}
		for _, c := range certs {
			if isExtendedKey(c.PublicKey) {
				spki, _, err := marshalPublicKey(c.PublicKey)
				if err != nil {
					t.Fatalf("cannot encode the parsed key: %v", err)
				}
				if !bytes.Equal(spki, c.RawSubjectPublicKeyInfo) {
					t.Fatalf("parsed key %x is not the certificate key %x", spki, c.RawSubjectPublicKeyInfo)
				}
			}
			_ = VerifyCertificate([]*x509.Certificate{c}, x509.NewCertPool(), []*x509.Certificate{c})
			_ = checkCertificateSignature(c, c)
		}
		_, _ = CertificatePublicKey(der)
	})
}

// FuzzParsePrivateKey checks that ParsePrivateKey never panics and that a key
// it accepts survives MarshalPrivateKey.
func FuzzParsePrivateKey(f *testing.F) {
	for _, s := range fuzzSeeds(f, "") {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		key, err := ParsePrivateKey(data)
		if err != nil {
			return
		}
		if !isExtendedKey(key.Public()) {
			return
		}
		der, err := MarshalPrivateKey(key)
		if err != nil {
			t.Fatalf("cannot encode the parsed key: %v", err)
		}
		again, err := ParsePrivateKey(der)
		if err != nil || !keysEqual(again.Public(), key.Public()) {
			t.Fatalf("encoded key does not parse to the same key: %v", err)
		}
	})
}

// FuzzExtendedSharedSecret feeds arbitrary peer nonces to the key agreements
// of the Brainpool and Curve448 policies.
func FuzzExtendedSharedSecret(f *testing.F) {
	uris := []string{ua.SecurityPolicyURIECCBrainpoolP256r1, ua.SecurityPolicyURIECCBrainpoolP384r1, ua.SecurityPolicyURIECCCurve448}
	keys := make([]*EphemeralKey, len(uris))
	for i, uri := range uris {
		k, err := NewEphemeralKey(uri)
		if err != nil {
			f.Fatal(err)
		}
		keys[i] = k
		f.Add(uint8(i), k.PublicKey())
	}
	random := make([]byte, 96)
	_, _ = rand.Read(random)
	f.Add(uint8(0), random[:64])
	f.Fuzz(func(t *testing.T, which uint8, nonce []byte) {
		k := keys[int(which)%len(keys)]
		secret, err := k.key.sharedSecret(nonce)
		if err == nil && len(secret) == 0 {
			t.Fatal("empty shared secret")
		}
	})
}
