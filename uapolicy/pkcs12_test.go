// SPDX-License-Identifier: MIT

package uapolicy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/otfabric/go-opcua/errors"
)

const pfxTestPassword = "opcua"

func readPFX(t testing.TB, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "pkcs12", name))
	require.NoError(t, err)
	return data
}

// opensslCLI returns the openssl command, or skips the test.
func opensslCLI(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not in PATH")
	}
	return path
}

func keyKind(key crypto.Signer) string {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return "rsa"
	case *ecdsa.PrivateKey:
		return k.Params().Name
	case ed25519.PrivateKey:
		return "ed25519"
	case ed448.PrivateKey:
		return "ed448"
	}
	return "?"
}

// TestParsePFX_OpenSSL decodes the PKCS #12 files of OpenSSL 4
// (testdata/pkcs12/generate.sh).
func TestParsePFX_OpenSSL(t *testing.T) {
	for _, tt := range []struct {
		file     string
		password string
		kind     string
		certs    int
		// unprotected: neither MAC nor encryption, any password works.
		unprotected bool
	}{
		{"rsa-default.p12", pfxTestPassword, "rsa", 1, false},
		{"p256-default.p12", pfxTestPassword, "P-256", 1, false},
		{"brainpoolP256r1-default.p12", pfxTestPassword, "brainpoolP256r1", 1, false},
		{"brainpoolP384r1-default.p12", pfxTestPassword, "brainpoolP384r1", 1, false},
		{"ed25519-default.p12", pfxTestPassword, "ed25519", 1, false},
		{"ed448-default.p12", pfxTestPassword, "ed448", 1, false},
		{"rsa-legacy.p12", pfxTestPassword, "rsa", 1, false},
		{"brainpoolP256r1-legacy.p12", pfxTestPassword, "brainpoolP256r1", 1, false},
		{"p256-2des-rc2-128.p12", pfxTestPassword, "P-256", 1, false},
		{"ed448-3des-sha384.p12", pfxTestPassword, "ed448", 1, false},
		{"ed25519-sha224.p12", pfxTestPassword, "ed25519", 1, false},
		{"p256-pbes2-des3-aes128.p12", pfxTestPassword, "P-256", 1, false},
		{"bp384-pbes2-aes192.p12", pfxTestPassword, "brainpoolP384r1", 1, false},
		{"rsa-pbmac1.p12", pfxTestPassword, "rsa", 1, false},
		{"ed448-pbmac1-sha512.p12", pfxTestPassword, "ed448", 1, false},
		{"p256-noenc.p12", pfxTestPassword, "P-256", 1, false},
		{"ed25519-nomac.p12", pfxTestPassword, "ed25519", 1, false},
		{"p256-noenc-nomac.p12", "", "P-256", 1, true},
		{"rsa-emptypass.p12", "", "rsa", 1, false},
		{"bp256-emptypass-legacy.p12", "", "brainpoolP256r1", 1, false},
		{"rsa-chain.p12", pfxTestPassword, "rsa", 2, false},
		// Java keytool: the JDK 17 default and the JDK 8 legacy format.
		{"keytool-rsa.p12", "opcuaopcua", "rsa", 1, false},
		{"keytool-p256-legacy.p12", "opcuaopcua", "P-256", 1, false},
	} {
		t.Run(tt.file, func(t *testing.T) {
			data := readPFX(t, tt.file)
			key, certs, err := ParsePFX(data, tt.password)
			require.NoError(t, err)
			require.Equal(t, tt.kind, keyKind(key))
			require.Len(t, certs, tt.certs)
			require.True(t, KeyMatchesCertificate(key, certs[0].Raw))
			for _, c := range certs[1:] {
				require.False(t, KeyMatchesCertificate(key, c.Raw))
			}

			_, _, err = ParsePFX(data, "wrong")
			if tt.unprotected {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, ErrPFXPassword)
				require.ErrorIs(t, err, errors.ErrInvalidPrivateKey)
			}
		})
	}
}

func TestEncodePFX(t *testing.T) {
	keys := extKeys(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keys["rsa"] = rsaKey
	ca := newTestCert(t, caTemplate("pfx-ca"), newECDSAKey(t, elliptic.P384()), nil)
	for name, key := range keys {
		t.Run(name, func(t *testing.T) {
			leaf := newTestCert(t, certTemplate("pfx-"+name), key, ca)
			for _, password := range []string{pfxTestPassword, "", "pässwörd 🔑"} {
				// The CA first: ParsePFX puts the leaf first.
				data, err := EncodePFX(key, [][]byte{ca.der, leaf.der}, password)
				require.NoError(t, err)
				got, certs, err := ParsePFX(data, password)
				require.NoError(t, err)
				require.True(t, keysEqual(got.Public(), key.Public()))
				require.Len(t, certs, 2)
				require.Equal(t, leaf.der, certs[0].Raw)
				require.Equal(t, ca.der, certs[1].Raw)

				_, _, err = ParsePFX(data, password+"x")
				require.ErrorIs(t, err, ErrPFXPassword)
			}

			// Without certificates.
			data, err := EncodePFX(key, nil, pfxTestPassword)
			require.NoError(t, err)
			got, certs, err := ParsePFX(data, pfxTestPassword)
			require.NoError(t, err)
			require.True(t, keysEqual(got.Public(), key.Public()))
			require.Empty(t, certs)
		})
	}
}

// TestEncodePFX_OpenSSL checks that OpenSSL reads what EncodePFX writes.
func TestEncodePFX_OpenSSL(t *testing.T) {
	openssl := opensslCLI(t)
	keys := extKeys(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keys["rsa"] = rsaKey
	for name, key := range keys {
		t.Run(name, func(t *testing.T) {
			leaf := newTestCert(t, certTemplate("pfx-"+name), key, nil)
			for _, password := range []string{pfxTestPassword, ""} {
				data, err := EncodePFX(key, [][]byte{leaf.der}, password)
				require.NoError(t, err)
				file := filepath.Join(t.TempDir(), "out.p12")
				require.NoError(t, os.WriteFile(file, data, 0o600))
				out, err := exec.Command(openssl, "pkcs12", "-in", file, "-passin", "pass:"+password, "-nodes").CombinedOutput() //nolint:gosec // test
				require.NoError(t, err, string(out))
				require.Contains(t, string(out), "-----BEGIN PRIVATE KEY-----")
				require.Contains(t, string(out), "-----BEGIN CERTIFICATE-----")
				require.Contains(t, string(out), "localKeyID")
			}
		})
	}
}

func TestEncodePFX_Errors(t *testing.T) {
	key := newECDSAKey(t, elliptic.P256())
	other := newTestCert(t, certTemplate("other"), newEd448Key(t), nil)
	_, err := EncodePFX(nil, nil, "x")
	require.ErrorIs(t, err, errors.ErrInvalidPrivateKey)
	_, err = EncodePFX((*ecdsa.PrivateKey)(nil), nil, "x")
	require.ErrorIs(t, err, errors.ErrInvalidPrivateKey)
	_, err = EncodePFX(key, [][]byte{other.der}, "x")
	require.ErrorIs(t, err, errors.ErrInvalidPrivateKey)
	_, err = EncodePFX(key, [][]byte{{0x30, 0x00}}, "x")
	require.Error(t, err)
	_, err = EncodePFX(key, nil, strings.Repeat("x", maxPFXPassword+1))
	require.ErrorIs(t, err, errors.ErrInvalidPrivateKey)
	_, _, err = ParsePFX(readPFX(t, "rsa-default.p12"), strings.Repeat("x", maxPFXPassword+1))
	require.ErrorIs(t, err, errors.ErrInvalidPrivateKey)
}

// TestPBES2Schemes encrypts with every PRF and cipher and decrypts again.
func TestPBES2Schemes(t *testing.T) {
	plain := []byte("PKCS #12 test plaintext of some length")
	for _, prf := range pfxHashes {
		for _, c := range pbes2Ciphers {
			algo, ciphertext, err := encryptPBES2(rand.Reader, []byte("pw"), plain, &prf, &c, 3)
			require.NoError(t, err)
			work := 100
			d := &pfxDecoder{password: pfxPassword{utf8: []byte("pw")}, work: &work}
			got, err := d.decrypt(algorithmContents(t, algo), ciphertext)
			require.NoError(t, err, "%s %s", prf.hmac, c.oid)
			require.Equal(t, plain, got)
			require.Equal(t, 97, work)

			d = &pfxDecoder{password: pfxPassword{utf8: []byte("wrong")}, work: &work}
			got, err = d.decrypt(algorithmContents(t, algo), ciphertext)
			if err == nil { // valid padding by chance
				require.NotEqual(t, plain, got)
			} else {
				require.ErrorIs(t, err, ErrPFXPassword)
			}
		}
	}
}

// algorithmContents returns the contents of a DER AlgorithmIdentifier.
func algorithmContents(t *testing.T, der []byte) cryptobyte.String {
	t.Helper()
	in := cryptobyte.String(der)
	var algo cryptobyte.String
	require.True(t, in.ReadASN1(&algo, cbasn1.SEQUENCE))
	return algo
}

// TestPKCS12KDF checks the PKCS #12 KDF against OpenSSL 4:
//
//	openssl kdf -keylen 24 -kdfopt digest:SHA1 -kdfopt hexpass:0073006d006500670000 \
//		-kdfopt hexsalt:0a58cf64530d823f -kdfopt id:1 -kdfopt iter:1 PKCS12KDF
//
// and so on with the parameters of each case.
func TestPKCS12KDF(t *testing.T) {
	salt, _ := hex.DecodeString("0a58cf64530d823f")
	sha512 := &pfxHashes[4]
	for _, tt := range []struct {
		h          *pfxHash
		id         byte
		iterations int
		want       string
	}{
		{pfxSHA1, 1, 1, "8aaae6297b6cb04642ab5b077851284eb7128f1a2a7fbca3"},
		{pfxSHA1, 2, 1, "79993dfe048d3b76"},
		{sha512, 3, 1000, "03d741f5949e0f87720daa7f1e6c8e77deefae1c0e1c8293007301" +
			"95c2f2f3ca276408f5841e6c2529fbd0c8a2bdb325b391"},
		{pfxSHA1, 1, 1000, "65a0185313e1be626a62223edc56a602e45d07570bd6c4473ed445ecb448cfe709046958" +
			"06c29d709dd015fc4d2234080cbfa8e6c9f0158c782e0edd95339d4acaf6b54f3ffa12ecad7a581344c27c2447a81f52dfbf158b083d241bddfb16be5e11f79a"},
	} {
		want, _ := hex.DecodeString(tt.want)
		require.Equal(t, tt.want, hex.EncodeToString(pkcs12KDF(tt.h, bmpString("smeg"), salt, tt.id, tt.iterations, len(want))))
	}
}

func TestRC2(t *testing.T) {
	// RFC 2268 §5.
	for _, tt := range []struct {
		key, plain, cipher string
		t1                 int
	}{
		{"0000000000000000", "0000000000000000", "ebb773f993278eff", 63},
		{"ffffffffffffffff", "ffffffffffffffff", "278b27e42e2f0d49", 64},
		{"3000000000000000", "1000000000000001", "30649edf9be7d2c2", 64},
		{"88", "0000000000000000", "61a8a244adacccf0", 64},
		{"88bca90e90875a", "0000000000000000", "6ccf4308974c267f", 64},
		{"88bca90e90875a7f0f79c384627bafb2", "0000000000000000", "1a807d272bbe5db1", 64},
		{"88bca90e90875a7f0f79c384627bafb2", "0000000000000000", "2269552ab0f85ca6", 128},
		{"88bca90e90875a7f0f79c384627bafb216f80a6f85920584c42fceb0be255daf1e", "0000000000000000", "5b78d3a43dfff1f1", 129},
	} {
		key, _ := hex.DecodeString(tt.key)
		c, _ := hex.DecodeString(tt.cipher)
		k, err := newRC2Key(key, tt.t1)
		require.NoError(t, err)
		out := make([]byte, 8)
		k.decryptBlock(out, c)
		require.Equal(t, tt.plain, hex.EncodeToString(out), tt.key)
	}
	for _, bad := range []struct {
		n, t1 int
	}{{0, 64}, {129, 64}, {8, 0}, {8, 1025}} {
		_, err := newRC2Key(make([]byte, bad.n), bad.t1)
		require.Error(t, err)
	}
}

func TestUnpad(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want string
		ok   bool
	}{
		{"4142434445460202", "414243444546", true},
		{"4142434445464701", "41424344454647", true},
		{"0808080808080808", "", true},
		{"4142434445464700", "", false},
		{"4142434445464709", "", false},
		{"4142434445460303", "", false},
		{"4142434445040404", "", false},
	} {
		in, _ := hex.DecodeString(tt.in)
		got, err := unpad(in, 8)
		if tt.ok {
			require.NoError(t, err, tt.in)
			require.Equal(t, tt.want, hex.EncodeToString(got))
		} else {
			require.ErrorIs(t, err, ErrPFXPassword, tt.in)
		}
	}
}

// pfxBuilder makes PKCS #12 files for the error paths.
type pfxBuilder struct {
	password string
	contents [][]byte // ContentInfos
	mac      func(b *cryptobyte.Builder, authSafe []byte)
	version  int64
}

func (p *pfxBuilder) bytes(t *testing.T) []byte {
	t.Helper()
	var as cryptobyte.Builder
	as.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for _, c := range p.contents {
			b.AddBytes(c)
		}
	})
	authSafe := as.BytesOrPanic()
	version := p.version
	if version == 0 {
		version = 3
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(version)
		addDataContentInfo(b, authSafe)
		switch {
		case p.mac != nil:
			p.mac(b, authSafe)
		default:
			addPKCS12MAC(b, authSafe, p.password, pfxSHA256, 1)
		}
	})
	return b.BytesOrPanic()
}

func addPKCS12MAC(b *cryptobyte.Builder, authSafe []byte, password string, h *pfxHash, iterations int64) {
	salt := []byte("saltsalt")
	pw := pfxPasswords(password)
	key := pkcs12KDF(h, pw[len(pw)-1].bmp, salt, 3, int(iterations), h.new().Size())
	mac := hmacSum(h, key, authSafe)
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddBytes(mustAlgorithmIdentifier(h.digest, false))
			b.AddASN1OctetString(mac)
		})
		b.AddASN1OctetString(salt)
		if iterations != 1 {
			b.AddASN1Int64(iterations)
		}
	})
}

func hmacSum(h *pfxHash, key, data []byte) []byte {
	m := hmac.New(h.new, key)
	m.Write(data)
	return m.Sum(nil)
}

// dataContent returns a data ContentInfo with the SafeBags.
func dataContent(bags ...[]byte) []byte {
	var b cryptobyte.Builder
	addDataContentInfo(&b, safeContents(bags...))
	return b.BytesOrPanic()
}

func safeContents(bags ...[]byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for _, bag := range bags {
			b.AddBytes(bag)
		}
	})
	return b.BytesOrPanic()
}

func safeBag(oid asn1.ObjectIdentifier, value []byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oid)
		b.AddASN1(tagExplicit0, func(b *cryptobyte.Builder) {
			b.AddBytes(value)
		})
	})
	return b.BytesOrPanic()
}

func certBagValue(oid asn1.ObjectIdentifier, der []byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oid)
		b.AddASN1(tagExplicit0, func(b *cryptobyte.Builder) {
			b.AddASN1OctetString(der)
		})
	})
	return b.BytesOrPanic()
}

// encryptedContent returns an encryptedData ContentInfo; constructed
// encodes the encrypted content as a constructed [0] of OCTET STRINGs.
func encryptedContent(algo, ciphertext []byte, constructed bool) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oidPKCS7EncryptedData)
		b.AddASN1(tagExplicit0, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1Int64(0)
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1ObjectIdentifier(oidPKCS7Data)
					b.AddBytes(algo)
					if constructed {
						b.AddASN1(tagExplicit0, func(b *cryptobyte.Builder) {
							half := len(ciphertext) / 2
							b.AddASN1OctetString(ciphertext[:half])
							b.AddASN1OctetString(ciphertext[half:])
						})
					} else {
						b.AddASN1(tagImplicit0, func(b *cryptobyte.Builder) {
							b.AddBytes(ciphertext)
						})
					}
				})
			})
		})
	})
	return b.BytesOrPanic()
}

func TestParsePFX_Structures(t *testing.T) {
	key := newEd448Key(t)
	cert := newTestCert(t, certTemplate("pfx"), key, nil)
	other := newTestCert(t, certTemplate("other"), newECDSAKey(t, elliptic.P256()), nil)
	pkcs8, err := MarshalPrivateKey(key)
	require.NoError(t, err)
	keyBag := safeBag(oidKeyBag, pkcs8)
	certBag := safeBag(oidCertBag, certBagValue(oidCertTypeX509, cert.der))
	otherBag := safeBag(oidCertBag, certBagValue(oidCertTypeX509, other.der))
	sdsiBag := safeBag(oidCertBag, certBagValue(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 2}, []byte("sdsi")))
	crlBag := safeBag(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 4}, []byte{0x30, 0x00})
	nested := func(bags ...[]byte) []byte { return safeBag(oidSafeContentsBag, safeContents(bags...)) }

	encrypt := func(plain []byte, password string) ([]byte, []byte) {
		algo, ciphertext, err := encryptPBES2(rand.Reader, []byte(password), plain, pfxSHA256, pbes2AES256, 1)
		require.NoError(t, err)
		return algo, ciphertext
	}
	shroudedOf := func(plain []byte, password string) []byte {
		algo, ciphertext := encrypt(plain, password)
		var b cryptobyte.Builder
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddBytes(algo)
			b.AddASN1OctetString(ciphertext)
		})
		return safeBag(oidShroudedKeyBag, b.BytesOrPanic())
	}
	shrouded := func(password string) []byte { return shroudedOf(pkcs8, password) }

	ok := func(t *testing.T, p *pfxBuilder, wantCerts int) {
		t.Helper()
		got, certs, err := ParsePFX(p.bytes(t), p.password)
		require.NoError(t, err)
		require.True(t, keysEqual(got.Public(), key.Public()))
		require.Len(t, certs, wantCerts)
		if wantCerts > 0 {
			require.Equal(t, cert.der, certs[0].Raw)
		}
	}
	fails := func(t *testing.T, p *pfxBuilder, target error) {
		t.Helper()
		_, _, err := ParsePFX(p.bytes(t), p.password)
		require.ErrorIs(t, err, target)
	}

	t.Run("plain bags", func(t *testing.T) {
		ok(t, &pfxBuilder{password: "p", contents: [][]byte{dataContent(otherBag, sdsiBag, crlBag, certBag, keyBag)}}, 2)
	})
	t.Run("nested", func(t *testing.T) {
		ok(t, &pfxBuilder{password: "p", contents: [][]byte{dataContent(nested(nested(keyBag), certBag))}}, 1)
		deep := keyBag
		for range maxPFXDepth + 1 {
			deep = nested(deep)
		}
		fails(t, &pfxBuilder{password: "p", contents: [][]byte{dataContent(deep)}}, errors.ErrInvalidPrivateKey)
	})
	t.Run("constructed encrypted content", func(t *testing.T) {
		algo, ciphertext := encrypt(safeContents(certBag), "p")
		ok(t, &pfxBuilder{password: "p", contents: [][]byte{encryptedContent(algo, ciphertext, true), dataContent(shrouded("p"))}}, 1)
		ok(t, &pfxBuilder{password: "p", contents: [][]byte{encryptedContent(algo, ciphertext, false), dataContent(shrouded("p"))}}, 1)
	})
	t.Run("other MAC hashes and iterations", func(t *testing.T) {
		for i := range pfxHashes {
			h := &pfxHashes[i]
			ok(t, &pfxBuilder{password: "p", contents: [][]byte{dataContent(keyBag)}, mac: func(b *cryptobyte.Builder, as []byte) {
				addPKCS12MAC(b, as, "p", h, 3)
			}}, 0)
		}
	})
	t.Run("no key", func(t *testing.T) {
		fails(t, &pfxBuilder{password: "p", contents: [][]byte{dataContent(certBag)}}, errors.ErrInvalidPrivateKey)
	})
	t.Run("two keys", func(t *testing.T) {
		fails(t, &pfxBuilder{password: "p", contents: [][]byte{dataContent(keyBag, keyBag)}}, errors.ErrInvalidPrivateKey)
	})
	t.Run("too many bags", func(t *testing.T) {
		bags := [][]byte{keyBag}
		for range maxPFXBags {
			bags = append(bags, crlBag)
		}
		fails(t, &pfxBuilder{password: "p", contents: [][]byte{dataContent(bags...)}}, errors.ErrInvalidPrivateKey)
		var contents [][]byte
		for range maxPFXBags + 1 {
			contents = append(contents, dataContent())
		}
		fails(t, &pfxBuilder{password: "p", contents: contents}, errors.ErrInvalidPrivateKey)
	})
	t.Run("bad key", func(t *testing.T) {
		bad := safeBag(oidKeyBag, []byte{0x30, 0x03, 0x02, 0x01, 0x05})
		fails(t, &pfxBuilder{password: "p", contents: [][]byte{dataContent(bad)}}, errors.ErrInvalidPrivateKey)
	})
	t.Run("bad certificate", func(t *testing.T) {
		bad := safeBag(oidCertBag, certBagValue(oidCertTypeX509, []byte{0x30, 0x00}))
		fails(t, &pfxBuilder{password: "p", contents: [][]byte{dataContent(keyBag, bad)}}, errors.ErrInvalidCertificate)
	})
	t.Run("wrong decryption password, right MAC", func(t *testing.T) {
		// The -twopass case: the MAC verifies, decryption does not.
		fails(t, &pfxBuilder{password: "p", contents: [][]byte{dataContent(shrouded("other"))}}, ErrPFXPassword)
		// A wrong password gives valid padding about 1 in 256 times; the
		// result does not parse. Encrypting bytes that are not a key gives
		// that case every time: it is a wrong password too, MAC or not.
		garbage := shroudedOf([]byte("not a PrivateKeyInfo"), "p")
		fails(t, &pfxBuilder{password: "p", contents: [][]byte{dataContent(garbage)}}, ErrPFXPassword)
		fails(t, &pfxBuilder{password: "p", contents: [][]byte{dataContent(garbage)}}, errors.ErrInvalidPrivateKey)
	})
	t.Run("version", func(t *testing.T) {
		fails(t, &pfxBuilder{password: "p", version: 2, contents: [][]byte{dataContent(keyBag)}}, errors.ErrInvalidPrivateKey)
	})
	t.Run("iteration limits", func(t *testing.T) {
		fails(t, &pfxBuilder{password: "p", contents: [][]byte{dataContent(keyBag)}, mac: func(b *cryptobyte.Builder, as []byte) {
			addPKCS12MAC(b, as, "p", pfxSHA1, 0)
		}}, errors.ErrInvalidPrivateKey)
		defer func(i, w int) { pfxMaxIterations, pfxMaxWork = i, w }(pfxMaxIterations, pfxMaxWork)
		pfxMaxIterations, pfxMaxWork = 10, 15
		fails(t, &pfxBuilder{password: "p", contents: [][]byte{dataContent(keyBag)}, mac: func(b *cryptobyte.Builder, as []byte) {
			addPKCS12MAC(b, as, "p", pfxSHA1, 11)
		}}, errors.ErrInvalidPrivateKey)
		// The work limit: the MAC takes 10, the PBES2 key 10 more.
		algo, ciphertext, err := encryptPBES2(rand.Reader, []byte("p"), safeContents(keyBag), pfxSHA256, pbes2AES256, 10)
		require.NoError(t, err)
		fails(t, &pfxBuilder{password: "p", contents: [][]byte{encryptedContent(algo, ciphertext, false)}, mac: func(b *cryptobyte.Builder, as []byte) {
			addPKCS12MAC(b, as, "p", pfxSHA1, 10)
		}}, errors.ErrInvalidPrivateKey)
	})
	t.Run("size", func(t *testing.T) {
		_, _, err := ParsePFX(make([]byte, maxPFXSize+1), "")
		require.ErrorIs(t, err, errors.ErrInvalidPrivateKey)
	})
}

// TestParsePFX_Malformed feeds structurally broken files to ParsePFX.
func TestParsePFX_Malformed(t *testing.T) {
	seq := func(parts ...[]byte) []byte {
		var b cryptobyte.Builder
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			for _, p := range parts {
				b.AddBytes(p)
			}
		})
		return b.BytesOrPanic()
	}
	tagged := func(tag cbasn1.Tag, parts ...[]byte) []byte {
		var b cryptobyte.Builder
		b.AddASN1(tag, func(b *cryptobyte.Builder) {
			for _, p := range parts {
				b.AddBytes(p)
			}
		})
		return b.BytesOrPanic()
	}
	oid := func(o asn1.ObjectIdentifier) []byte {
		var b cryptobyte.Builder
		b.AddASN1ObjectIdentifier(o)
		return b.BytesOrPanic()
	}
	octets := func(data []byte) []byte { return tagged(cbasn1.OCTET_STRING, data) }
	integer := func(v int64) []byte {
		var b cryptobyte.Builder
		b.AddASN1Int64(v)
		return b.BytesOrPanic()
	}
	null := []byte{0x05, 0x00}
	pfxOf := func(authSafe []byte, rest ...[]byte) []byte {
		return seq(append([][]byte{integer(3), seq(oid(oidPKCS7Data), tagged(tagExplicit0, octets(authSafe)))}, rest...)...)
	}
	macData := func(algo []byte, extra ...[]byte) []byte {
		return seq(append([][]byte{seq(algo, octets(make([]byte, 32))), octets([]byte("salt"))}, extra...)...)
	}
	sha256Algo := mustAlgorithmIdentifier(pfxSHA256.digest, true)
	pbkdf2Params := func(extra ...[]byte) []byte {
		return seq(oid(oidPBKDF2), seq(append([][]byte{octets([]byte("salt")), integer(1)}, extra...)...))
	}
	pbmac1 := func(kdf, scheme []byte) []byte {
		return seq(oid(oidPBMAC1), seq(kdf, scheme))
	}
	hmac256 := mustAlgorithmIdentifier(pfxSHA256.hmac, true)
	contentOf := func(ci []byte) []byte { return pfxOf(seq(ci)) }
	encData := func(version int64, ctype asn1.ObjectIdentifier, algo []byte, content ...[]byte) []byte {
		return contentOf(seq(oid(oidPKCS7EncryptedData), tagged(tagExplicit0, seq(integer(version), seq(append([][]byte{oid(ctype), algo}, content...)...)))))
	}
	enc := func(algo []byte) []byte {
		return encData(0, oidPKCS7Data, algo, tagged(tagImplicit0, make([]byte, 16)))
	}
	pbes2 := func(kdf, scheme []byte) []byte { return seq(oid(oidPBES2), seq(kdf, scheme)) }
	aesScheme := seq(oid(oidAES256CBC), octets(make([]byte, 16)))
	pkcs12PBE := func(o asn1.ObjectIdentifier, params []byte) []byte { return seq(oid(o), params) }
	bags := func(bag []byte) []byte {
		return contentOf(seq(oid(oidPKCS7Data), tagged(tagExplicit0, octets(seq(bag)))))
	}

	for name, data := range map[string][]byte{
		"empty":                    nil,
		"not a sequence":           {0x02, 0x01, 0x03},
		"trailing data":            append(pfxOf(seq()), 0),
		"no authSafe":              seq(integer(3)),
		"signedData authSafe":      seq(integer(3), seq(oid(oidPKCS7EncryptedData), tagged(tagExplicit0, octets(nil)))),
		"authSafe not octets":      seq(integer(3), seq(oid(oidPKCS7Data), tagged(tagExplicit0, integer(1)))),
		"trailing after MacData":   pfxOf(seq(), macData(sha256Algo), integer(1)),
		"MacData broken":           pfxOf(seq(), seq(integer(1))),
		"MacData bad iterations":   pfxOf(seq(), macData(sha256Algo, integer(1), integer(2))),
		"MAC unknown hash":         pfxOf(seq(), macData(mustAlgorithmIdentifier(asn1.ObjectIdentifier{1, 2, 3}, false))),
		"MAC bad params":           pfxOf(seq(), macData(seq(oid(pfxSHA256.digest), integer(1)))),
		"MAC huge salt":            pfxOf(seq(), seq(seq(sha256Algo, octets(nil)), octets(make([]byte, maxPFXSalt+1)))),
		"PBMAC1 broken":            pfxOf(seq(), macData(seq(oid(oidPBMAC1), integer(1)))),
		"PBMAC1 not PBKDF2":        pfxOf(seq(), macData(pbmac1(seq(oid(oidPBES2)), hmac256))),
		"PBMAC1 unknown HMAC":      pfxOf(seq(), macData(pbmac1(pbkdf2Params(integer(32)), seq(oid(asn1.ObjectIdentifier{1, 2, 3}))))),
		"PBMAC1 no key length":     pfxOf(seq(), macData(pbmac1(pbkdf2Params(), hmac256))),
		"PBMAC1 bad key length":    pfxOf(seq(), macData(pbmac1(pbkdf2Params(integer(0)), hmac256))),
		"PBKDF2 broken":            pfxOf(seq(), macData(pbmac1(seq(oid(oidPBKDF2), integer(1)), hmac256))),
		"PBKDF2 bad PRF":           pfxOf(seq(), macData(pbmac1(pbkdf2Params(integer(32), seq(integer(1))), hmac256))),
		"PBKDF2 unknown PRF":       pfxOf(seq(), macData(pbmac1(pbkdf2Params(integer(32), seq(oid(asn1.ObjectIdentifier{1, 2, 3}))), hmac256))),
		"PBKDF2 trailing":          pfxOf(seq(), macData(pbmac1(pbkdf2Params(integer(32), hmac256, null), hmac256))),
		"PBKDF2 huge salt":         pfxOf(seq(), macData(pbmac1(seq(oid(oidPBKDF2), seq(octets(make([]byte, maxPFXSalt+1)), integer(1), integer(32))), hmac256))),
		"authSafe not a sequence":  pfxOf(nil),
		"ContentInfo broken":       pfxOf(seq(seq(oid(oidPKCS7Data)))),
		"unknown content type":     contentOf(seq(oid(asn1.ObjectIdentifier{1, 2, 3}), tagged(tagExplicit0, null))),
		"data not octets":          contentOf(seq(oid(oidPKCS7Data), tagged(tagExplicit0, null))),
		"SafeContents broken":      contentOf(seq(oid(oidPKCS7Data), tagged(tagExplicit0, octets(null)))),
		"SafeBag broken":           bags(seq(oid(oidKeyBag))),
		"keyBag broken":            bags(seq(oid(oidKeyBag), tagged(tagExplicit0, null))),
		"shrouded broken":          bags(seq(oid(oidShroudedKeyBag), tagged(tagExplicit0, null))),
		"certBag broken":           bags(seq(oid(oidCertBag), tagged(tagExplicit0, null))),
		"certBag value broken":     bags(seq(oid(oidCertBag), tagged(tagExplicit0, seq(oid(oidCertTypeX509), tagged(tagExplicit0, null))))),
		"EncryptedData broken":     contentOf(seq(oid(oidPKCS7EncryptedData), tagged(tagExplicit0, null))),
		"EncryptedData version":    encData(1, oidPKCS7Data, aesScheme, tagged(tagImplicit0, make([]byte, 16))),
		"EncryptedData type":       encData(0, oidPKCS7EncryptedData, aesScheme, tagged(tagImplicit0, make([]byte, 16))),
		"EncryptedData no content": encData(0, oidPKCS7Data, aesScheme),
		"EncryptedData trailing":   encData(0, oidPKCS7Data, aesScheme, tagged(tagImplicit0, make([]byte, 16)), null),
		"constructed broken":       encData(0, oidPKCS7Data, aesScheme, tagged(tagExplicit0, null)),
		"constructed truncated":    encData(0, oidPKCS7Data, aesScheme, []byte{0xa0, 0x05, 0x04, 0x01}),
		"implicit truncated":       encData(0, oidPKCS7Data, aesScheme, []byte{0x80, 0x05, 0x00}),
		"algorithm no OID":         enc(seq(null)),
		"unknown encryption":       enc(seq(oid(asn1.ObjectIdentifier{1, 2, 3}))),
		"PBES2 broken":             enc(seq(oid(oidPBES2), null)),
		"PBES2 not PBKDF2":         enc(pbes2(seq(oid(oidPBMAC1)), aesScheme)),
		"PBES2 unknown cipher":     enc(pbes2(pbkdf2Params(), seq(oid(asn1.ObjectIdentifier{1, 2, 3})))),
		"PBES2 no IV":              enc(pbes2(pbkdf2Params(), seq(oid(oidAES256CBC)))),
		"PBES2 IV size":            enc(pbes2(pbkdf2Params(), seq(oid(oidAES256CBC), octets(make([]byte, 8))))),
		"PBES2 key length":         enc(pbes2(pbkdf2Params(integer(16)), aesScheme)),
		"PBES2 bad KDF":            enc(pbes2(seq(oid(oidPBKDF2), null), aesScheme)),
		"PBES2 bad block size":     encData(0, oidPKCS7Data, pbes2(pbkdf2Params(), aesScheme), tagged(tagImplicit0, make([]byte, 15))),
		"PBES2 empty ciphertext":   encData(0, oidPKCS7Data, pbes2(pbkdf2Params(), aesScheme), tagged(tagImplicit0, nil)),
		"PBE broken params":        enc(pkcs12PBE(oidPBEWithSHAAnd3KeyTripleDESCBC, null)),
		"PBE huge salt":            enc(pkcs12PBE(oidPBEWithSHAAnd3KeyTripleDESCBC, seq(octets(make([]byte, maxPFXSalt+1)), integer(1)))),
		"PBE zero iterations":      enc(pkcs12PBE(oidPBEWithSHAAnd3KeyTripleDESCBC, seq(octets([]byte("salt")), integer(0)))),
		"PBE RC2 bad block size":   encData(0, oidPKCS7Data, pkcs12PBE(oidPBEWithSHAAnd40BitRC2CBC, seq(octets([]byte("salt")), integer(1))), tagged(tagImplicit0, make([]byte, 7))),
		"PBE 3DES bad block size":  encData(0, oidPKCS7Data, pkcs12PBE(oidPBEWithSHAAnd2KeyTripleDESCBC, seq(octets([]byte("salt")), integer(1))), tagged(tagImplicit0, make([]byte, 7))),
		"PBE RC2-128 garbage":      encData(0, oidPKCS7Data, pkcs12PBE(oidPBEWithSHAAnd128BitRC2CBC, seq(octets([]byte("salt")), integer(1))), tagged(tagImplicit0, make([]byte, 16))),
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := ParsePFX(data, "p")
			require.ErrorIs(t, err, errors.ErrInvalidPrivateKey)
		})
	}
}

// TestParsePFX_Truncated parses every prefix of a fixture: none may panic or
// succeed.
func TestParsePFX_Truncated(t *testing.T) {
	data := readPFX(t, "brainpoolP256r1-legacy.p12")
	for n := range len(data) {
		_, _, err := ParsePFX(data[:n], pfxTestPassword)
		require.Error(t, err)
	}
}

// FuzzParsePFX checks that ParsePFX never panics and stays fast: the
// iteration limits are lowered so that the fixtures still decode.
func FuzzParsePFX(f *testing.F) {
	files, err := filepath.Glob(filepath.Join("testdata", "pkcs12", "*.p12"))
	if err != nil {
		f.Fatal(err)
	}
	for _, name := range files {
		data, err := os.ReadFile(name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data, pfxTestPassword)
	}
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x03}, "")
	defer func(i, w int) { pfxMaxIterations, pfxMaxWork = i, w }(pfxMaxIterations, pfxMaxWork)
	pfxMaxIterations, pfxMaxWork = 2048, 8192
	f.Fuzz(func(t *testing.T, data []byte, password string) {
		key, certs, err := ParsePFX(data, password)
		if err != nil {
			return
		}
		if key == nil {
			t.Fatal("no key without error")
		}
		for _, c := range certs {
			if c == nil {
				t.Fatal("nil certificate")
			}
		}
	})
}
