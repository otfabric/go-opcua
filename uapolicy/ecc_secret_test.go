// SPDX-License-Identifier: MIT

package uapolicy

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
)

// secretFixture is a sender (a client with an application instance key) and
// a receiver (a server with an ephemeral key) of an EccEncryptedSecret.
type secretFixture struct {
	uri      string
	key      crypto.Signer
	sigLen   int
	cert     []byte
	receiver *EphemeralKey
	nonce    []byte
}

func newSecretFixture(t *testing.T, uri string) *secretFixture {
	t.Helper()
	key, sigLen := eccTestKey(t, uri)
	receiver, err := NewEphemeralKey(uri)
	require.NoError(t, err)
	nonce := make([]byte, 32)
	_, err = rand.Read(nonce)
	require.NoError(t, err)
	return &secretFixture{uri: uri, key: key, sigLen: sigLen, cert: selfSignedCert(t, key), receiver: receiver, nonce: nonce}
}

func (f *secretFixture) encrypt(t *testing.T, secret []byte) []byte {
	t.Helper()
	data, err := EncryptSecret(f.uri, f.key, f.cert, f.receiver.PublicKey(), f.nonce, secret, time.Unix(1700000000, 0).UTC())
	require.NoError(t, err)
	return data
}

// signer returns the callback a receiver uses when it trusts the fixture's
// certificate.
func (f *secretFixture) signer() func([]byte) (crypto.PublicKey, error) {
	return func([]byte) (crypto.PublicKey, error) { return f.key.Public(), nil }
}

// ecdsaKey returns the key of a fixture for a policy with ECDSA keys.
func (f *secretFixture) ecdsaKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, ok := f.key.(*ecdsa.PrivateKey)
	require.True(t, ok)
	return key
}

func TestEncryptedSecret_RoundTrip(t *testing.T) {
	for _, uri := range eccTestPolicies() {
		t.Run(uri, func(t *testing.T) {
			f := newSecretFixture(t, uri)
			sigLen := f.sigLen
			overhead := eccPolicies[uri].symmetric.secretOverhead()

			for _, n := range []int{0, 1, 5, 6, 7, 15, 16, 17, 31, 32, 33, 100, 4096} {
				secret := bytes.Repeat([]byte{byte(n), 0xa5}, n)[:n]
				data := f.encrypt(t, secret)

				var gotCert []byte
				got, err := f.receiver.DecryptSecret(data, func(cert []byte) (crypto.PublicKey, error) {
					gotCert = cert
					return f.key.Public(), nil
				})
				require.NoError(t, err, "length %d", n)
				require.Equal(t, secret, got.Secret)
				require.Equal(t, f.nonce, got.Nonce)
				require.Equal(t, f.cert, got.Certificate)
				require.Equal(t, f.cert, gotCert)
				require.True(t, got.SigningTime.Equal(time.Unix(1700000000, 0)))

				// The Length field counts what follows it.
				require.Equal(t, []byte{0x01, 0x00, 0x8a, 0x44}, data[:4], "TypeId i=17546 as four byte NodeId")
				require.Equal(t, byte(1), data[4], "EncodingMask")
				require.Equal(t, uint32(len(data)-9), binary.LittleEndian.Uint32(data[5:]))

				// The encrypted part is a whole number of cipher blocks, and
				// a short secret is padded up to a full block of its own so
				// its length does not show.
				_, payload := splitSecret(t, data, sigLen)
				// Authenticated encryption appends its tag to the payload.
				payload = payload[:len(payload)-overhead]
				require.Zero(t, len(payload)%16)
				plainLen := 4 + len(f.nonce) + 4 + n + 2
				require.GreaterOrEqual(t, len(payload), plainLen)
				require.Less(t, len(payload)-plainLen, 32)
				if n < 16 {
					require.GreaterOrEqual(t, len(payload)-plainLen+n, 16)
				}
			}
		})
	}
}

// splitSecret returns the header (up to and including the key data) and the
// encrypted payload of an EccEncryptedSecret.
func splitSecret(t *testing.T, data []byte, sigLen int) (header, payload []byte) {
	t.Helper()
	buf := ua.NewBuffer(data[9:])
	_ = buf.ReadString()
	_ = buf.ReadBytes()
	_ = buf.ReadTime()
	keyData := int(buf.ReadUint16())
	require.NoError(t, buf.Error())
	end := 9 + buf.Pos() + keyData
	return data[:end], data[end : len(data)-sigLen]
}

func TestEncryptedSecret_Layout(t *testing.T) {
	// Decrypt the payload by hand, with the keys of the specification, to pin
	// down the wire format rather than only the round trip.
	f := newSecretFixture(t, ua.SecurityPolicyURIECCNistP256)
	p := eccPolicies[f.uri]
	secret := []byte("s3cret")
	data := f.encrypt(t, secret)

	buf := ua.NewBuffer(data[9:])
	require.Equal(t, f.uri, buf.ReadString())
	require.Equal(t, f.cert, buf.ReadBytes())
	require.True(t, buf.ReadTime().Equal(time.Unix(1700000000, 0)))
	keyDataLength := int(buf.ReadUint16())
	start := buf.Pos()
	sender := buf.ReadBytes()
	receiver := buf.ReadBytes()
	require.NoError(t, buf.Error())
	require.Equal(t, keyDataLength, buf.Pos()-start, "KeyDataLength covers both public keys with their length prefixes")
	require.Len(t, sender, 64)
	require.Equal(t, f.receiver.PublicKey(), receiver)

	// Salt = L | "opcua-secret" | SenderPublicKey | ReceiverPublicKey
	shared, err := f.receiver.key.sharedSecret(sender)
	require.NoError(t, err)
	okm, err := p.deriveKeys(shared, "opcua-secret", sender, receiver, 16+16)
	require.NoError(t, err)

	payload := data[9+buf.Pos() : len(data)-64]
	block, err := aes.NewCipher(okm[:16])
	require.NoError(t, err)
	plain := make([]byte, len(payload))
	cipher.NewCBCDecrypter(block, okm[16:]).CryptBlocks(plain, payload)

	body := ua.NewBuffer(plain)
	require.Equal(t, f.nonce, body.ReadBytes())
	require.Equal(t, secret, body.ReadBytes())
	require.NoError(t, body.Error())
	padding := plain[body.Pos() : len(plain)-2]
	size := binary.LittleEndian.Uint16(plain[len(plain)-2:])
	require.Equal(t, int(size), len(padding))
	require.Equal(t, bytes.Repeat([]byte{byte(size)}, len(padding)), padding)
	// 4+32+4+6+2 = 48 is a block multiple, but the secret is shorter than a
	// block: one block of padding is added.
	require.Equal(t, 16, len(padding))

	// The signature covers everything before it.
	v := &ECDSA{Hash: crypto.SHA256, PublicKey: &f.ecdsaKey(t).PublicKey}
	require.NoError(t, v.Verify(data[:len(data)-64], data[len(data)-64:]))
}

func TestEncryptedSecret_Tamper(t *testing.T) {
	for _, uri := range eccTestPolicies() {
		t.Run(uri, func(t *testing.T) {
			f := newSecretFixture(t, uri)
			data := f.encrypt(t, []byte("correct horse battery staple"))
			probe := tamperPositions(uri, len(data))

			// Flipping any single bit anywhere invalidates the secret.
			for i := range data {
				if !probe(i) {
					continue
				}
				bad := append([]byte{}, data...)
				bad[i] ^= 0x20
				_, err := f.receiver.DecryptSecret(bad, f.signer())
				require.Error(t, err, "byte %d of %d", i, len(data))
			}

			// Truncation and trailing data, at every length.
			for n := 0; n < len(data); n++ {
				if !probe(n) {
					continue
				}
				_, err := f.receiver.DecryptSecret(data[:n], f.signer())
				require.Error(t, err, "truncated to %d", n)
			}
			_, err := f.receiver.DecryptSecret(append(append([]byte{}, data...), 0), f.signer())
			require.Error(t, err)
		})
	}
}

// tamperPositions reports which byte positions of an n-byte secret
// TestEncryptedSecret_Tamper probes. Each probe is a full decryption with a
// signature check and a key agreement. The layout of the secret is the same
// for every policy, so the P-256 and Curve25519 policies probe every byte,
// and the policies with expensive curves (math/big for Brainpool, and P-384
// and Ed448 under the race detector) probe the header, the tail with the
// signature and every 16th byte between them.
func tamperPositions(uri string, n int) func(int) bool {
	switch uri {
	case ua.SecurityPolicyURIECCNistP256, ua.SecurityPolicyURIECCNistP256AesGcm,
		ua.SecurityPolicyURIECCNistP256ChaChaPoly, ua.SecurityPolicyURIECCCurve25519:
		return func(int) bool { return true }
	}
	return func(i int) bool { return i < 64 || i >= n-32 || i%16 == 0 }
}

func TestEncryptedSecret_Rejections(t *testing.T) {
	f := newSecretFixture(t, ua.SecurityPolicyURIECCNistP256)
	data := f.encrypt(t, []byte("password"))

	t.Run("signed by someone else", func(t *testing.T) {
		other := newECDSAKey(t, elliptic.P256())
		_, err := f.receiver.DecryptSecret(data, func([]byte) (crypto.PublicKey, error) { return &other.PublicKey, nil })
		require.ErrorIs(t, err, errors.ErrSignatureValidationFailed)
	})

	t.Run("certificate rejected", func(t *testing.T) {
		_, err := f.receiver.DecryptSecret(data, func([]byte) (crypto.PublicKey, error) {
			return nil, errors.ErrInvalidCertificate
		})
		require.ErrorIs(t, err, errors.ErrInvalidCertificate)
	})

	t.Run("no verification key", func(t *testing.T) {
		_, err := f.receiver.DecryptSecret(data, nil)
		require.Error(t, err)
		_, err = f.receiver.DecryptSecret(data, func([]byte) (crypto.PublicKey, error) { return nil, nil })
		require.Error(t, err)
		var nilKey *ecdsa.PublicKey
		_, err = f.receiver.DecryptSecret(data, func([]byte) (crypto.PublicKey, error) { return nilKey, nil })
		require.Error(t, err)
	})

	t.Run("signer key of the wrong type", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		_, err = f.receiver.DecryptSecret(data, func([]byte) (crypto.PublicKey, error) { return &rsaKey.PublicKey, nil })
		require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	})

	t.Run("made for another ephemeral key", func(t *testing.T) {
		// Replay against a later key of the same server: the signature is
		// valid, but the secret names the key it was made for.
		other, err := NewEphemeralKey(f.uri)
		require.NoError(t, err)
		_, err = other.DecryptSecret(data, f.signer())
		require.ErrorIs(t, err, errors.ErrInvalidCiphertext)
	})

	t.Run("other policy", func(t *testing.T) {
		g := newSecretFixture(t, ua.SecurityPolicyURIECCNistP384)
		_, err := g.receiver.DecryptSecret(data, f.signer())
		require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	})

	t.Run("not an EccEncryptedSecret", func(t *testing.T) {
		for _, bad := range [][]byte{
			nil,
			{},
			[]byte("plain text password"),
			append([]byte{0x01, 0x00, 0x8a, 0x45}, data[4:]...), // other TypeId
			append([]byte{0x01, 0x01, 0x8a, 0x44}, data[4:]...), // other namespace
			append(append([]byte{}, data[:4]...), append([]byte{0}, data[5:]...)...),
		} {
			_, err := f.receiver.DecryptSecret(bad, f.signer())
			require.ErrorIs(t, err, errors.ErrInvalidCiphertext)
		}
	})
}

func TestEncryptSecret_Errors(t *testing.T) {
	f := newSecretFixture(t, ua.SecurityPolicyURIECCNistP256)
	now := time.Now()

	_, err := EncryptSecret(ua.SecurityPolicyURIBasic256Sha256, f.key, f.cert, f.receiver.PublicKey(), f.nonce, nil, now)
	require.ErrorIs(t, err, errors.ErrUnsupportedSecurityPolicy)

	_, err = EncryptSecret(f.uri, nil, f.cert, f.receiver.PublicKey(), f.nonce, nil, now)
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	var nilKey *ecdsa.PrivateKey
	_, err = EncryptSecret(f.uri, nilKey, f.cert, f.receiver.PublicKey(), f.nonce, nil, now)
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	_, err = EncryptSecret(f.uri, rsaKey, f.cert, f.receiver.PublicKey(), f.nonce, nil, now)
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)

	// The receiver's key is validated before anything is encrypted for it.
	for _, bad := range [][]byte{nil, make([]byte, 64), bytes.Repeat([]byte{1}, 64), f.receiver.PublicKey()[:63]} {
		_, err = EncryptSecret(f.uri, f.key, f.cert, bad, f.nonce, []byte("pw"), now)
		require.Error(t, err)
	}

	// Two secrets for the same key and content differ: each has its own
	// ephemeral sender key.
	a := f.encrypt(t, []byte("pw"))
	b := f.encrypt(t, []byte("pw"))
	require.NotEqual(t, a, b)
}

func FuzzDecryptSecret(f *testing.F) {
	uri := ua.SecurityPolicyURIECCNistP256
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	receiver, err := NewEphemeralKey(uri)
	if err != nil {
		f.Fatal(err)
	}
	valid, err := EncryptSecret(uri, key, []byte("cert"), receiver.PublicKey(), []byte("nonce"), []byte("secret"), time.Unix(0, 0))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add(valid[:40])
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic, whatever the input.
		secret, err := receiver.DecryptSecret(data, func([]byte) (crypto.PublicKey, error) { return &key.PublicKey, nil })
		if err == nil && !bytes.Equal(data, valid) {
			t.Fatalf("accepted a forged secret: %x -> %q", data, secret.Secret)
		}
	})
}
