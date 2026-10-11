// SPDX-License-Identifier: MIT

package uapolicy

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
)

// RFC 7748 §6.1: X25519 test vector. a and b are the private keys of Alice
// and Bob, pa and pb their public keys and k the shared secret.
const (
	rfc7748a  = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	rfc7748pa = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
	rfc7748b  = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
	rfc7748pb = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
	rfc7748k  = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
)

// Keys of the AEAD policies, computed with an independent implementation of
// HKDF-SHA256 (Python, hmac and hashlib of the standard library only) from
// the RFC 5903 exchange (nistP256 policies: client = initiator) and the RFC
// 7748 exchange (ECC_curve25519: client = Alice):
//
//	Salt = UInt16LE(L) | label | first | second ; OKM = HKDF-SHA256(secret, Salt, Salt, L)
//
// L is the sum of the key lengths: 16+12 for ECC_nistP256_AesGcm, 32+12 for
// ECC_nistP256_ChaChaPoly and 32+32+12 for ECC_curve25519.
const (
	katAesGcmClientKeys = "a3ab0e137e491c6d58b5c5eac080c464" + "14ea91eca5bf34860d828745"
	katAesGcmServerKeys = "965cacf6c4639a4bf75b0ea6e2184a52" + "4248c82ee560fa8d17fc3004"
	katAesGcmSecretKeys = "10a153760b8ea1fa8657050086cb546f" + "1b6353405414b49939681dd4"

	katChaChaClientKeys = "57cdb42c6a1eb1aa7c280e2875f0a8c58d456ac2fff784e6c44d921bbd2fde75" + "816e17b687d2941c356040c3"
	katChaChaServerKeys = "fbc4e04c20c7ab2668c850f7f5d2dd0b0c7200ae4447ee043b2ce61b8ccd5f03" + "387658bd16ff4b041bdce463"
	katChaChaSecretKeys = "9c81c298eb16ec11f1cd7ab5eb708740623042897c9f8e38d4291123873ee090" + "c7e382c11bc6a658f00a2cb7"

	katCurve25519ClientKeys = "1f9c9a8afab09a11a55e6e9698ccfc530dfe2b5e2e606d44dc7f6325fffd9eb9" + // signing key
		"34225ce7af53cfa83dcaef877cbd3cf86bd7c40483c501618bea6d78f27bc1f8" + // encrypting key
		"220104e958849ede9eb27c14" // initialization vector
	katCurve25519ServerKeys = "7a82e36f7540a2a6ea7970fe5b46e42bd88ba9c2bff7f2badccbea119d25c5d8" +
		"cbbc6812d05ebb927bf3f173c573487c68bcc9ef25e2964859cde8b133075bab" +
		"817ad05f8deed346e0014ac9"
	katCurve25519SecretKeys = "cb74f513b689616300cde9403c735b86ee26d7c5d08928e54ef48e32ca3210c0" + "32360f6ba8ddc899a54c2723"

	// Renewal of an ECC_nistP256_AesGcm channel whose previous IKM is the
	// bytes 00 01 .. 1f: IKM = previous XOR girx, and the client keys derived
	// from it with the same nonces.
	katAesGcmChainedIKM        = "d6850d6846f3eba8d9381cebed286b2f3ffe9c8dda68d814993d7ecb57895cc1"
	katAesGcmChainedClientKeys = "e3de7480cd85800cb919d7ef483af89a" + "844da9b1c50d4c0c1a5710f7"
)

// aeadKAT describes the fixed key exchange of an AEAD policy.
type aeadKAT struct {
	uri                      string
	client, server           string // private keys
	clientPublic             string
	serverPublic             string
	secret                   string // shared secret
	clientKeys, serverKeys   string
	secretKeys               string
	signKey, encKey          int
	newAEAD                  func([]byte) (cipher.AEAD, error)
	enhancements             bool
	nonceLength, sigLen      int
	certificateKeyIsEd25519  bool
	encryptionAlgorithmLabel string
}

var aeadKATs = []aeadKAT{
	{
		uri: ua.SecurityPolicyURIECCNistP256AesGcm, client: rfc5903i, server: rfc5903r,
		clientPublic: rfc5903gi, serverPublic: rfc5903gr, secret: rfc5903girx,
		clientKeys: katAesGcmClientKeys, serverKeys: katAesGcmServerKeys, secretKeys: katAesGcmSecretKeys,
		encKey: 16, newAEAD: aes128GCM, enhancements: true, nonceLength: 64, sigLen: 64,
		encryptionAlgorithmLabel: "http://opcfoundation.org/UA/security/aes128-gcm",
	},
	{
		uri: ua.SecurityPolicyURIECCNistP256ChaChaPoly, client: rfc5903i, server: rfc5903r,
		clientPublic: rfc5903gi, serverPublic: rfc5903gr, secret: rfc5903girx,
		clientKeys: katChaChaClientKeys, serverKeys: katChaChaServerKeys, secretKeys: katChaChaSecretKeys,
		encKey: 32, newAEAD: chacha20poly1305.New, enhancements: true, nonceLength: 64, sigLen: 64,
		encryptionAlgorithmLabel: "http://opcfoundation.org/UA/security/chacha20-poly1305",
	},
	{
		uri: ua.SecurityPolicyURIECCCurve25519, client: rfc7748a, server: rfc7748b,
		clientPublic: rfc7748pa, serverPublic: rfc7748pb, secret: rfc7748k,
		clientKeys: katCurve25519ClientKeys, serverKeys: katCurve25519ServerKeys, secretKeys: katCurve25519SecretKeys,
		signKey: 32, encKey: 32, newAEAD: chacha20poly1305.New, nonceLength: 32, sigLen: 64,
		certificateKeyIsEd25519:  true,
		encryptionAlgorithmLabel: "http://opcfoundation.org/UA/security/chacha20-poly1305",
	},
}

// fixedEphemeralKeyFor returns the ephemeral key of an ECC policy with the
// given private key.
func fixedEphemeralKeyFor(t *testing.T, uri, private string) *EphemeralKey {
	t.Helper()
	p := eccPolicies[uri]
	var k eccEphemeralPrivateKey
	switch p.agreement.(type) {
	case x25519Agreement:
		key, err := ecdh.X25519().NewPrivateKey(unhex(t, private))
		require.NoError(t, err)
		k = x25519EphemeralKey{key: key}
	default:
		key, err := ecdh.P256().NewPrivateKey(unhex(t, private))
		require.NoError(t, err)
		k = nistEphemeralKey{key: key}
	}
	return &EphemeralKey{policy: p, key: k, public: k.publicKey()}
}

// fixedExchange returns the two symmetric algorithms of the fixed exchange.
func (k aeadKAT) fixedExchange(t *testing.T, chain []byte) (client, server *EncryptionAlgorithm, next []byte) {
	t.Helper()
	p := eccPolicies[k.uri]
	ck, sk := fixedEphemeralKeyFor(t, k.uri, k.client), fixedEphemeralKeyFor(t, k.uri, k.server)
	client, next, err := p.symmetricKeys(ck, sk.PublicKey(), RoleClient, chain)
	require.NoError(t, err)
	server, next2, err := p.symmetricKeys(sk, ck.PublicKey(), RoleServer, chain)
	require.NoError(t, err)
	require.Equal(t, next, next2)
	return client, server, next
}

// RFC 8439 §2.8.2: AEAD_CHACHA20_POLY1305 test vector, through the cipher
// constructor the policies use.
func TestChaCha20Poly1305_RFC8439(t *testing.T) {
	key := unhex(t, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	nonce := unhex(t, "070000004041424344454647")
	aad := unhex(t, "50515253c0c1c2c3c4c5c6c7")
	plain := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	want := unhex(t, "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"+
		"3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"+
		"92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"+
		"3ff4def08e4b7a9de576d26586cec64b6116"+
		"1ae10b594f09e26a7e902ecbd0600691")

	suite := eccPolicies[ua.SecurityPolicyURIECCNistP256ChaChaPoly].symmetric
	sealed, err := suite.sealSecret(key, nonce, aad, plain)
	require.NoError(t, err)
	require.Equal(t, want, sealed)

	c, err := suite.(aeadSuite).newCipher(key)
	require.NoError(t, err)
	got, err := c.Open(nil, nonce, sealed, aad)
	require.NoError(t, err)
	require.Equal(t, plain, got)
}

// The GCM specification (McGrew, Viega), test cases 2 and 4: AES-128.
func TestAES128GCM_KnownAnswer(t *testing.T) {
	for name, tt := range map[string]struct{ key, iv, aad, plain, want string }{
		"test case 2": {
			key:   "00000000000000000000000000000000",
			iv:    "000000000000000000000000",
			plain: "00000000000000000000000000000000",
			want:  "0388dace60b6a392f328c2b971b2fe78" + "ab6e47d42cec13bdf53a67b21257bddf",
		},
		"test case 4": {
			key: "feffe9928665731c6d6a8f9467308308",
			iv:  "cafebabefacedbaddecaf888",
			aad: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
			plain: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72" +
				"1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
			want: "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e" +
				"21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091" +
				"5bc94fbc3221a5db94fae95ae7121a47",
		},
	} {
		c, err := aes128GCM(unhex(t, tt.key))
		require.NoError(t, err, name)
		require.Equal(t, unhex(t, tt.want), c.Seal(nil, unhex(t, tt.iv), unhex(t, tt.plain), unhex(t, tt.aad)), name)
	}

	// Only AES-128: a longer key is a mistake in the policy table.
	_, err := aes128GCM(make([]byte, 32))
	require.Error(t, err)
	_, err = aeadSuite{cipher: aes128GCM}.newCipher(make([]byte, 24))
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
}

func TestX25519_RFC7748(t *testing.T) {
	uri := ua.SecurityPolicyURIECCCurve25519
	a := fixedEphemeralKeyFor(t, uri, rfc7748a)
	b := fixedEphemeralKeyFor(t, uri, rfc7748b)
	require.Equal(t, unhex(t, rfc7748pa), a.PublicKey())
	require.Equal(t, unhex(t, rfc7748pb), b.PublicKey())

	k1, err := a.key.sharedSecret(b.PublicKey())
	require.NoError(t, err)
	k2, err := b.key.sharedSecret(a.PublicKey())
	require.NoError(t, err)
	require.Equal(t, unhex(t, rfc7748k), k1)
	require.Equal(t, k1, k2)

	fresh, err := NewEphemeralKey(uri)
	require.NoError(t, err)
	require.Len(t, fresh.PublicKey(), 32)
}

// RFC 8032 §7.1, tests 1 and 2.
func TestEdDSA_RFC8032(t *testing.T) {
	for name, tt := range map[string]struct{ seed, public, msg, sig string }{
		"test 1": {
			seed:   "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
			public: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
			sig: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
				"5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
		},
		"test 2": {
			seed:   "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
			public: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
			msg:    "72",
			sig: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
				"085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
		},
	} {
		key := ed25519.NewKeyFromSeed(unhex(t, tt.seed))
		public := ed25519.PublicKey(unhex(t, tt.public))
		require.Equal(t, public, key.Public(), name)
		msg, want := unhex(t, tt.msg), unhex(t, tt.sig)

		// Ed25519 is deterministic: the signature is the one of the RFC,
		// also when the key is behind an opaque crypto.Signer.
		for _, signer := range []crypto.Signer{key, opaqueSigner{key}} {
			local, err := AsymmetricKeys(ua.SecurityPolicyURIECCCurve25519, signer, nil)
			require.NoError(t, err, name)
			sig, err := local.Signature(msg)
			require.NoError(t, err, name)
			require.Equal(t, want, sig, name)
			require.Equal(t, 64, local.SignatureLength())
		}

		remote, err := AsymmetricKeys(ua.SecurityPolicyURIECCCurve25519, nil, public)
		require.NoError(t, err, name)
		require.Equal(t, 64, remote.RemoteSignatureLength())
		require.NoError(t, remote.VerifySignature(msg, want), name)
		require.ErrorIs(t, remote.VerifySignature(append(msg, 0), want), errors.ErrSignatureValidationFailed, name)
		for i := range want {
			bad := append([]byte{}, want...)
			bad[i] ^= 0x04
			require.Error(t, remote.VerifySignature(msg, bad), "%s: byte %d", name, i)
		}
		require.Error(t, remote.VerifySignature(msg, want[:63]), name)
		require.Error(t, remote.VerifySignature(msg, append(want, 0)), name)
	}
}

func TestEdDSA_Errors(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	p256 := newECDSAKey(t, elliptic.P256())
	msg := []byte("msg")

	_, err = (&EdDSA{}).Signature(msg)
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	_, err = (&EdDSA{PrivateKey: p256}).Signature(msg)
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	require.ErrorIs(t, (&EdDSA{}).Verify(msg, make([]byte, 64)), errors.ErrSignatureValidationFailed)

	// A signer that returns something else than a 64 byte signature.
	_, err = (&EdDSA{PrivateKey: brokenSigner{opaqueSigner{key}, []byte("short")}}).Signature(msg)
	require.Error(t, err)
	_, err = (&EdDSA{PrivateKey: failingSigner{key}}).Signature(msg)
	require.Error(t, err)
}

type failingSigner struct{ crypto.Signer }

func (failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.ErrInvalidState
}

// TestAEADPolicyParameters pins the properties of the AEAD policies: key
// types, nonce and key lengths, ranking.
func TestAEADPolicyParameters(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keys := map[string]crypto.Signer{
		"rsa":     rsaKey,
		"p256":    newECDSAKey(t, elliptic.P256()),
		"p384":    newECDSAKey(t, elliptic.P384()),
		"p521":    newECDSAKey(t, elliptic.P521()),
		"ed25519": edKey,
	}

	require.Len(t, aeadTestPolicies(), len(aeadKATs))
	for _, k := range aeadKATs {
		t.Run(k.uri, func(t *testing.T) {
			require.True(t, IsSupported(k.uri))
			require.True(t, IsECC(k.uri))
			require.True(t, IsAEAD(k.uri))
			require.Equal(t, k.enhancements, SecureChannelEnhancements(k.uri))
			require.False(t, LegacySequenceNumbers(k.uri))

			p := eccPolicies[k.uri]
			require.Equal(t, k.nonceLength, p.agreement.publicKeyLength())
			require.Equal(t, k.signKey, p.symmetric.signingKeyLength())
			require.Equal(t, k.encKey, p.symmetric.encryptingKeyLength())
			require.Equal(t, 12, p.symmetric.ivLength())
			require.Equal(t, 16, p.symmetric.secretOverhead())
			require.Equal(t, crypto.SHA256, p.hash)

			kx, err := NewKeyExchange(k.uri, RoleClient)
			require.NoError(t, err)
			require.Len(t, kx.Nonce(), k.nonceLength)

			// Which certificate keys the policy accepts.
			for name, key := range keys {
				want := name == "p256" || name == "p384"
				if k.certificateKeyIsEd25519 {
					want = name == "ed25519"
				}
				cert := selfSignedCert(t, key)
				if want {
					require.NoError(t, CheckCertificate(k.uri, cert), name)
					require.NoError(t, CheckPublicKey(k.uri, key.Public()), name)
					local, err := AsymmetricKeys(k.uri, key, key.Public())
					require.NoError(t, err, name)
					require.True(t, local.SignOnly())
					require.Empty(t, local.SignatureURI(), "SignatureData.Algorithm is empty for the ECC policies")
					sig, err := local.Signature([]byte("x"))
					require.NoError(t, err, name)
					require.NoError(t, local.VerifySignature([]byte("x"), sig), name)
					continue
				}
				require.ErrorIs(t, CheckCertificate(k.uri, cert), errors.ErrInvalidSecurityConfig, name)
				_, err := AsymmetricKeys(k.uri, key, nil)
				require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig, name)
				_, err = AsymmetricKeys(k.uri, nil, key.Public())
				require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig, name)
			}

			// Above every policy without authenticated encryption, Sign
			// below SignAndEncrypt.
			sign, enc := SecurityLevel(k.uri, ua.MessageSecurityModeSign), SecurityLevel(k.uri, ua.MessageSecurityModeSignAndEncrypt)
			require.Less(t, sign, enc)
			require.Zero(t, SecurityLevel(k.uri, ua.MessageSecurityModeNone))
			for _, other := range SupportedPolicies() {
				if !IsAEAD(other) {
					require.Greater(t, sign, SecurityLevel(other, ua.MessageSecurityModeSignAndEncrypt), other)
				}
			}
		})
	}

	// An Ed25519 key is of no use with the other policies.
	for _, uri := range SupportedPolicies() {
		if uri == ua.SecurityPolicyURINone || uri == ua.SecurityPolicyURIECCCurve25519 {
			continue
		}
		require.Error(t, CheckPublicKey(uri, edKey.Public()), uri)
	}
	// The levels are distinct, so that an endpoint selection is never a tie.
	seen := map[uint8]string{}
	for _, uri := range SupportedPolicies() {
		for _, mode := range []ua.MessageSecurityMode{ua.MessageSecurityModeSign, ua.MessageSecurityModeSignAndEncrypt} {
			if uri == ua.SecurityPolicyURINone {
				continue
			}
			level := SecurityLevel(uri, mode)
			require.Empty(t, seen[level], "%s/%s shares level %d", uri, mode, level)
			seen[level] = uri
		}
	}
}

// TestAEADKeyDerivation_KnownAnswer checks the layout of the derived key
// material against the independently computed vectors.
func TestAEADKeyDerivation_KnownAnswer(t *testing.T) {
	for _, k := range aeadKATs {
		t.Run(k.uri, func(t *testing.T) {
			p := eccPolicies[k.uri]
			secret := unhex(t, k.secret)
			client, server := unhex(t, k.clientPublic), unhex(t, k.serverPublic)

			ck, err := p.channelKeys(secret, eccLabelClient, client, server)
			require.NoError(t, err)
			want := unhex(t, k.clientKeys)
			require.Len(t, want, k.signKey+k.encKey+12)
			require.Equal(t, want[:k.signKey], ck.signing, "signing key: offset 0")
			require.Equal(t, want[k.signKey:k.signKey+k.encKey], ck.encryption, "encrypting key: follows the signing key")
			require.Equal(t, want[k.signKey+k.encKey:], ck.iv, "IV: 12 bytes, follows the encrypting key")

			sk, err := p.channelKeys(secret, eccLabelServer, server, client)
			require.NoError(t, err)
			want = unhex(t, k.serverKeys)
			require.Equal(t, want[:k.signKey], sk.signing)
			require.Equal(t, want[k.signKey:k.signKey+k.encKey], sk.encryption)
			require.Equal(t, want[k.signKey+k.encKey:], sk.iv)

			// The key and IV of an EccEncryptedSecret: no signing key.
			okm, err := p.deriveKeys(secret, eccLabelSecret, client, server, k.encKey+12)
			require.NoError(t, err)
			require.Equal(t, unhex(t, k.secretKeys), okm)
		})
	}
}

const (
	testTokenID = uint32(0x0a0b0c0d)
	testLastSeq = uint32(0x01020304)
)

// testChunk returns a symmetric chunk without its tag: the 16 byte header
// (with the final MessageSize) followed by a sequence header and a body.
func testChunk(body []byte) []byte {
	chunk := []byte("MSGF")
	chunk = binary.LittleEndian.AppendUint32(chunk, uint32(16+8+len(body)+aeadTagSize))
	chunk = binary.LittleEndian.AppendUint32(chunk, 7)           // SecureChannelId
	chunk = binary.LittleEndian.AppendUint32(chunk, testTokenID) // TokenId
	chunk = binary.LittleEndian.AppendUint32(chunk, testLastSeq+1)
	chunk = binary.LittleEndian.AppendUint32(chunk, 99) // RequestId
	return append(chunk, body...)
}

// TestAEADChunk_KnownAnswer seals a chunk with the keys of the fixed exchange
// and compares it with the cipher applied by hand: which key, which nonce,
// what is authenticated and what is encrypted.
func TestAEADChunk_KnownAnswer(t *testing.T) {
	body := []byte("the body of a service message")
	for _, k := range aeadKATs {
		t.Run(k.uri, func(t *testing.T) {
			keys := unhex(t, k.clientKeys)
			signKey, encKey, iv := keys[:k.signKey], keys[k.signKey:k.signKey+k.encKey], keys[k.signKey+k.encKey:]

			// IV XOR (TokenId | LastSequenceNumber), little endian, on the
			// first eight bytes; the last four are the IV's.
			nonce := append([]byte{}, iv...)
			for i, m := range []byte{0x0d, 0x0c, 0x0b, 0x0a, 0x04, 0x03, 0x02, 0x01} {
				nonce[i] ^= m
			}
			require.Equal(t, nonce, chunkNonce(iv, testTokenID, testLastSeq))
			require.Equal(t, iv[8:], nonce[8:])
			require.Equal(t, iv, chunkNonce(iv, 0, 0))

			chunk := testChunk(body)

			t.Run("SignAndEncrypt", func(t *testing.T) {
				calgo, salgo, _ := k.fixedExchange(t, nil)
				require.True(t, calgo.AEAD())
				require.Equal(t, 16, calgo.SignatureLength())
				require.Equal(t, 16, calgo.RemoteSignatureLength())
				require.Equal(t, 1, calgo.BlockSize())
				require.Equal(t, 1, calgo.PlaintextBlockSize())
				require.Equal(t, k.encryptionAlgorithmLabel, calgo.EncryptionURI())

				sealed, err := calgo.SealChunk(chunk, 16, testTokenID, testLastSeq, true)
				require.NoError(t, err)

				c, err := k.newAEAD(encKey)
				require.NoError(t, err)
				want := append(append([]byte{}, chunk[:16]...), c.Seal(nil, nonce, chunk[16:], chunk[:16])...)
				require.Equal(t, want, sealed, "header in the clear and authenticated, the rest encrypted, tag last")
				require.Len(t, sealed, len(chunk)+16)
				require.Equal(t, uint32(len(sealed)), binary.LittleEndian.Uint32(sealed[4:]), "MessageSize counts the tag")
				require.False(t, bytes.Contains(sealed, body))

				opened, err := salgo.OpenChunk(sealed, 16, testTokenID, testLastSeq, true)
				require.NoError(t, err)
				require.Equal(t, chunk, opened)
			})

			t.Run("Sign", func(t *testing.T) {
				calgo, salgo, _ := k.fixedExchange(t, nil)
				sealed, err := calgo.SealChunk(chunk, 16, testTokenID, testLastSeq, false)
				require.NoError(t, err)

				// The tag of an empty plaintext with the whole chunk as
				// additional data. ECC_curve25519 has a key of its own for
				// it; the others use the encrypting key.
				key := encKey
				if k.signKey > 0 {
					key = signKey
				}
				c, err := k.newAEAD(key)
				require.NoError(t, err)
				want := append(append([]byte{}, chunk...), c.Seal(nil, nonce, nil, chunk)...)
				require.Equal(t, want, sealed)
				require.True(t, bytes.Contains(sealed, body), "nothing is encrypted")

				opened, err := salgo.OpenChunk(sealed, 16, testTokenID, testLastSeq, false)
				require.NoError(t, err)
				require.Equal(t, chunk, opened)
			})

			t.Run("Server", func(t *testing.T) {
				// The other direction uses the server keys.
				calgo, salgo, _ := k.fixedExchange(t, nil)
				sealed, err := salgo.SealChunk(chunk, 16, testTokenID, testLastSeq, true)
				require.NoError(t, err)
				keys := unhex(t, k.serverKeys)
				c, err := k.newAEAD(keys[k.signKey : k.signKey+k.encKey])
				require.NoError(t, err)
				want := c.Seal(nil, chunkNonce(keys[k.signKey+k.encKey:], testTokenID, testLastSeq), chunk[16:], chunk[:16])
				require.Equal(t, want, sealed[16:])
				_, err = calgo.OpenChunk(sealed, 16, testTokenID, testLastSeq, true)
				require.NoError(t, err)
				// A peer cannot be fed its own messages.
				_, err = salgo.OpenChunk(sealed, 16, testTokenID, testLastSeq, true)
				require.ErrorIs(t, err, errors.ErrInvalidCiphertext)
			})
		})
	}
}

// TestAEADChunk_Rejections modifies a sealed chunk in every possible place
// and presents it with every wrong parameter.
func TestAEADChunk_Rejections(t *testing.T) {
	body := bytes.Repeat([]byte("0123456789"), 5)
	for _, uri := range aeadTestPolicies() {
		for _, encrypt := range []bool{true, false} {
			name := uri + "/Sign"
			if encrypt {
				name = uri + "/SignAndEncrypt"
			}
			t.Run(name, func(t *testing.T) {
				client, err := NewKeyExchange(uri, RoleClient)
				require.NoError(t, err)
				server, err := NewKeyExchange(uri, RoleServer)
				require.NoError(t, err)
				calgo, err := client.Symmetric(server.Nonce())
				require.NoError(t, err)
				salgo, err := server.Symmetric(client.Nonce())
				require.NoError(t, err)

				chunk := testChunk(body)
				sealed, err := calgo.SealChunk(chunk, 16, testTokenID, testLastSeq, encrypt)
				require.NoError(t, err)
				open := func(b []byte) error {
					_, err := salgo.OpenChunk(b, 16, testTokenID, testLastSeq, encrypt)
					return err
				}
				require.NoError(t, open(sealed))

				// Every bit of every field is authenticated: message type,
				// chunk type, size, channel id, token id, sequence header,
				// body, tag.
				for i := range sealed {
					for _, bit := range []byte{0x01, 0x80} {
						bad := append([]byte{}, sealed...)
						bad[i] ^= bit
						require.ErrorIs(t, open(bad), errors.ErrInvalidCiphertext, "byte %d", i)
					}
				}
				// Truncated and extended at every length.
				for n := 0; n < len(sealed); n++ {
					require.ErrorIs(t, open(sealed[:n]), errors.ErrInvalidCiphertext, "truncated to %d", n)
				}
				require.ErrorIs(t, open(append(append([]byte{}, sealed...), 0)), errors.ErrInvalidCiphertext)

				// The nonce: another token, another position in the stream
				// (a replayed or reordered chunk).
				for _, tt := range []struct{ token, last uint32 }{
					{testTokenID + 1, testLastSeq},
					{testTokenID, testLastSeq + 1},
					{testTokenID, testLastSeq - 1},
					{testLastSeq, testTokenID},
					{0, 0},
				} {
					_, err := salgo.OpenChunk(sealed, 16, tt.token, tt.last, encrypt)
					require.ErrorIs(t, err, errors.ErrInvalidCiphertext)
				}
				// The other security mode, and another header boundary.
				_, err = salgo.OpenChunk(sealed, 16, testTokenID, testLastSeq, !encrypt)
				require.ErrorIs(t, err, errors.ErrInvalidCiphertext)
				if encrypt {
					_, err = salgo.OpenChunk(sealed, 12, testTokenID, testLastSeq, encrypt)
					require.ErrorIs(t, err, errors.ErrInvalidCiphertext)
				}
				_, err = salgo.OpenChunk(sealed, -1, testTokenID, testLastSeq, encrypt)
				require.ErrorIs(t, err, errors.ErrInvalidCiphertext)
				_, err = salgo.OpenChunk(sealed, len(sealed), testTokenID, testLastSeq, encrypt)
				require.ErrorIs(t, err, errors.ErrInvalidCiphertext)

				// Keys of another exchange.
				other, err := NewKeyExchange(uri, RoleServer)
				require.NoError(t, err)
				oalgo, err := other.Symmetric(client.Nonce())
				require.NoError(t, err)
				_, err = oalgo.OpenChunk(sealed, 16, testTokenID, testLastSeq, encrypt)
				require.ErrorIs(t, err, errors.ErrInvalidCiphertext)

				// Bad arguments to SealChunk.
				_, err = calgo.SealChunk(chunk, len(chunk)+1, testTokenID, testLastSeq+1, encrypt)
				require.ErrorIs(t, err, errors.ErrInvalidPlaintext)
				_, err = calgo.SealChunk(chunk, -1, testTokenID, testLastSeq+1, encrypt)
				require.ErrorIs(t, err, errors.ErrInvalidPlaintext)
			})
		}
	}

	// Not an AEAD algorithm.
	kx, err := NewKeyExchange(ua.SecurityPolicyURIECCNistP256, RoleClient)
	require.NoError(t, err)
	peer, err := NewKeyExchange(ua.SecurityPolicyURIECCNistP256, RoleServer)
	require.NoError(t, err)
	algo, err := kx.Symmetric(peer.Nonce())
	require.NoError(t, err)
	_, err = algo.SealChunk(testChunk(nil), 16, 1, 1, true)
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	_, err = algo.OpenChunk(make([]byte, 64), 16, 1, 1, true)
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	var nilAlgo *EncryptionAlgorithm
	require.False(t, nilAlgo.AEAD())
}

// TestAEADChunk_NonceNeverReused: SealChunk refuses a LastSequenceNumber that
// may have been used with the key before.
func TestAEADChunk_NonceNeverReused(t *testing.T) {
	uri := ua.SecurityPolicyURIECCNistP256AesGcm
	newAlgo := func(t *testing.T) *EncryptionAlgorithm {
		client, err := NewKeyExchange(uri, RoleClient)
		require.NoError(t, err)
		server, err := NewKeyExchange(uri, RoleServer)
		require.NoError(t, err)
		algo, err := client.Symmetric(server.Nonce())
		require.NoError(t, err)
		return algo
	}
	chunk := testChunk([]byte("x"))
	seal := func(algo *EncryptionAlgorithm, last uint32) error {
		_, err := algo.SealChunk(chunk, 16, 1, last, true)
		return err
	}

	t.Run("repeated and earlier numbers", func(t *testing.T) {
		algo := newAlgo(t)
		require.NoError(t, seal(algo, 100))
		require.NoError(t, seal(algo, 101))
		require.ErrorIs(t, seal(algo, 101), errors.ErrInvalidState, "the same number")
		require.ErrorIs(t, seal(algo, 100), errors.ErrInvalidState, "an earlier number")
		// A gap is fine (an OpenSecureChannel message in between), and the
		// numbers before it stay refused.
		require.NoError(t, seal(algo, 105))
		require.ErrorIs(t, seal(algo, 103), errors.ErrInvalidState)
		require.NoError(t, seal(algo, 106))
	})

	t.Run("wrap of the sequence numbers", func(t *testing.T) {
		// The numbers wrap from UInt32.MaxValue to 0 while the token lives:
		// still all different.
		algo := newAlgo(t)
		for _, last := range []uint32{0xfffffffe, 0xffffffff, 0, 1, 2} {
			require.NoError(t, seal(algo, last), "%#x", last)
		}
		require.ErrorIs(t, seal(algo, 0xffffffff), errors.ErrInvalidState)
		require.ErrorIs(t, seal(algo, 0xfffffffe), errors.ErrInvalidState)
		require.ErrorIs(t, seal(algo, 1), errors.ErrInvalidState)
	})

	t.Run("2^32 chunks", func(t *testing.T) {
		// The last number before the first one would come round again ends
		// the use of the key.
		algo := newAlgo(t)
		require.NoError(t, seal(algo, 5))
		require.NoError(t, seal(algo, 4), "the 2^32th number")
		for _, last := range []uint32{5, 6, 4, 0, 0xffffffff} {
			require.ErrorIs(t, seal(algo, last), errors.ErrInvalidState, "%#x", last)
		}
	})

	t.Run("all nonces differ", func(t *testing.T) {
		keys := unhex(t, katAesGcmClientKeys)
		seen := map[string]bool{}
		for token := uint32(1); token <= 3; token++ {
			for last := uint32(0xfffffffd); last != 3; last++ {
				n := string(chunkNonce(keys[16:], token, last))
				require.False(t, seen[n])
				seen[n] = true
			}
		}
	})
}

// TestKeyExchange_Chained covers the key chaining of the policies with
// SecureChannelEnhancements.
func TestKeyExchange_Chained(t *testing.T) {
	chunk := testChunk([]byte("renewed"))
	exchange := func(t *testing.T, uri string, clientChain, serverChain []byte) (c, s *EncryptionAlgorithm, cn, sn []byte) {
		client, err := NewKeyExchange(uri, RoleClient)
		require.NoError(t, err)
		server, err := NewKeyExchange(uri, RoleServer)
		require.NoError(t, err)
		c, cn, err = client.SymmetricChained(server.Nonce(), clientChain)
		require.NoError(t, err)
		s, sn, err = server.SymmetricChained(client.Nonce(), serverChain)
		require.NoError(t, err)
		return
	}
	interoperate := func(c, s *EncryptionAlgorithm) error {
		sealed, err := c.SealChunk(chunk, 16, 2, 9, true)
		if err != nil {
			return err
		}
		_, err = s.OpenChunk(sealed, 16, 2, 9, true)
		return err
	}

	t.Run("known answer", func(t *testing.T) {
		k := aeadKATs[0]
		_, _, first := k.fixedExchange(t, nil)
		require.Equal(t, unhex(t, k.secret), first, "the first exchange starts the chain with the shared secret")

		previous := make([]byte, 32)
		for i := range previous {
			previous[i] = byte(i)
		}
		calgo, salgo, next := k.fixedExchange(t, previous)
		require.Equal(t, unhex(t, katAesGcmChainedIKM), next, "IKM = previous XOR shared secret")

		keys := unhex(t, katAesGcmChainedClientKeys)
		sealed, err := calgo.SealChunk(chunk, 16, testTokenID, testLastSeq, true)
		require.NoError(t, err)
		c, err := aes128GCM(keys[:16])
		require.NoError(t, err)
		require.Equal(t, c.Seal(nil, chunkNonce(keys[16:], testTokenID, testLastSeq), chunk[16:], chunk[:16]), sealed[16:])
		_, err = salgo.OpenChunk(sealed, 16, testTokenID, testLastSeq, true)
		require.NoError(t, err)

		// The same nonces without the chain give other keys.
		plain, _, _ := k.fixedExchange(t, nil)
		other, err := plain.SealChunk(chunk, 16, testTokenID, testLastSeq, true)
		require.NoError(t, err)
		require.NotEqual(t, sealed, other)
	})

	for _, uri := range []string{ua.SecurityPolicyURIECCNistP256AesGcm, ua.SecurityPolicyURIECCNistP256ChaChaPoly} {
		t.Run(uri, func(t *testing.T) {
			c, s, cn, sn := exchange(t, uri, nil, nil)
			require.NoError(t, interoperate(c, s))
			require.Len(t, cn, 32)
			require.Equal(t, cn, sn)

			// Five renewals in step.
			for i := 0; i < 5; i++ {
				prev := cn
				c, s, cn, sn = exchange(t, uri, cn, sn)
				require.NoError(t, interoperate(c, s), "renewal %d", i+1)
				require.Equal(t, cn, sn)
				require.NotEqual(t, prev, cn)
			}

			// A side that does not have the history of the channel (it took
			// part in this exchange only) ends up with other keys.
			c, s, _, _ = exchange(t, uri, cn, nil)
			require.ErrorIs(t, interoperate(c, s), errors.ErrInvalidCiphertext)
			c, s, _, _ = exchange(t, uri, nil, sn)
			require.ErrorIs(t, interoperate(c, s), errors.ErrInvalidCiphertext)
			stale := append([]byte{}, cn...)
			stale[0] ^= 1
			c, s, _, _ = exchange(t, uri, cn, stale)
			require.ErrorIs(t, interoperate(c, s), errors.ErrInvalidCiphertext)

			// A chain value of the wrong length is refused.
			client, err := NewKeyExchange(uri, RoleClient)
			require.NoError(t, err)
			server, err := NewKeyExchange(uri, RoleServer)
			require.NoError(t, err)
			for _, bad := range [][]byte{{}, make([]byte, 31), make([]byte, 33)} {
				_, _, err = client.SymmetricChained(server.Nonce(), bad)
				require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
			}
		})
	}

	t.Run("policies without chaining", func(t *testing.T) {
		for _, uri := range SupportedPolicies() {
			if SecureChannelEnhancements(uri) {
				continue
			}
			client, err := NewKeyExchange(uri, RoleClient)
			require.NoError(t, err)
			server, err := NewKeyExchange(uri, RoleServer)
			require.NoError(t, err)
			// The chain is ignored, whatever it is.
			_, next, err := client.SymmetricChained(server.Nonce(), []byte("ignored"))
			require.NoError(t, err, uri)
			require.Nil(t, next, uri)
		}
		// Every exchange of ECC_curve25519 stands alone.
		uri := ua.SecurityPolicyURIECCCurve25519
		c, s, cn, sn := exchange(t, uri, []byte("a"), []byte("b"))
		require.NoError(t, interoperate(c, s))
		require.Nil(t, cn)
		require.Nil(t, sn)
	})
}

func TestCertificateHash(t *testing.T) {
	key := newECDSAKey(t, elliptic.P256())
	cert := selfSignedCert(t, key)
	other := selfSignedCert(t, newECDSAKey(t, elliptic.P256()))
	want := sha256.Sum256(cert)

	for _, uri := range []string{ua.SecurityPolicyURIECCNistP256AesGcm, ua.SecurityPolicyURIECCNistP256ChaChaPoly} {
		h, err := CertificateHash(uri, cert)
		require.NoError(t, err)
		require.Equal(t, want[:], h, "SHA-256 of the DER certificate")

		// Of a chain, the leaf.
		h, err = CertificateHash(uri, append(append([]byte{}, cert...), other...))
		require.NoError(t, err)
		require.Equal(t, want[:], h)

		// No certificate, no hash.
		h, err = CertificateHash(uri, nil)
		require.NoError(t, err)
		require.Empty(t, h)

		_, err = CertificateHash(uri, []byte("not a certificate"))
		require.ErrorIs(t, err, errors.ErrInvalidCertificate)
	}
	for _, uri := range []string{ua.SecurityPolicyURIECCCurve25519, ua.SecurityPolicyURIECCNistP256, ua.SecurityPolicyURIBasic256Sha256, "nope"} {
		_, err := CertificateHash(uri, cert)
		require.ErrorIs(t, err, errors.ErrUnsupportedSecurityPolicy, uri)
	}
}

// TestEncryptedSecret_AEADLayout opens the EccEncryptedSecret of the AEAD
// policies by hand to pin down its construction.
func TestEncryptedSecret_AEADLayout(t *testing.T) {
	for _, k := range aeadKATs {
		t.Run(k.uri, func(t *testing.T) {
			f := newSecretFixture(t, k.uri)
			p := eccPolicies[k.uri]
			secret := []byte("s3cret")
			data := f.encrypt(t, secret)

			header, sealed := splitSecret(t, data, k.sigLen)
			buf := ua.NewBuffer(header[9:])
			require.Equal(t, k.uri, buf.ReadString())
			require.Equal(t, f.cert, buf.ReadBytes())
			require.True(t, buf.ReadTime().Equal(time.Unix(1700000000, 0)))
			_ = buf.ReadUint16()
			sender := buf.ReadBytes()
			receiver := buf.ReadBytes()
			require.NoError(t, buf.Error())
			require.Len(t, sender, k.nonceLength)
			require.Equal(t, f.receiver.PublicKey(), receiver)
			require.Equal(t, uint32(len(data)-9), binary.LittleEndian.Uint32(data[5:]), "Length counts the tag and the signature")

			// EncryptingKey | IV = HKDF(shared, L | "opcua-secret" | sender | receiver)
			shared, err := f.receiver.key.sharedSecret(sender)
			require.NoError(t, err)
			okm, err := p.deriveKeys(shared, "opcua-secret", sender, receiver, k.encKey+12)
			require.NoError(t, err)

			// The IV is used as derived, the header is the additional
			// authenticated data, the tag follows the ciphertext.
			c, err := k.newAEAD(okm[:k.encKey])
			require.NoError(t, err)
			plain, err := c.Open(nil, okm[k.encKey:], sealed, header)
			require.NoError(t, err)
			require.Zero(t, len(plain)%16)
			require.Len(t, sealed, len(plain)+16)

			body := ua.NewBuffer(plain)
			require.Equal(t, f.nonce, body.ReadBytes())
			require.Equal(t, secret, body.ReadBytes())
			require.NoError(t, body.Error())
			padding := plain[body.Pos() : len(plain)-2]
			size := binary.LittleEndian.Uint16(plain[len(plain)-2:])
			require.Equal(t, int(size), len(padding))
			require.Equal(t, bytes.Repeat([]byte{byte(size)}, len(padding)), padding)
			require.Equal(t, 16, len(padding), "48 bytes are a multiple of 16, a short secret gets 16 more")

			// The signature covers everything before it, tag included.
			signed, sig := data[:len(data)-k.sigLen], data[len(data)-k.sigLen:]
			verifier, _, err := p.signature.verifier(f.key.Public())
			require.NoError(t, err)
			require.NoError(t, verifier.Verify(signed, sig))

			// A valid signature does not make a modified payload acceptable:
			// re-sign a secret with one ciphertext bit changed.
			forged := append([]byte{}, signed...)
			forged[len(header)] ^= 1
			signer, _, err := p.signature.signer(f.key)
			require.NoError(t, err)
			newSig, err := signer.Signature(forged)
			require.NoError(t, err)
			_, err = f.receiver.DecryptSecret(append(forged, newSig...), f.signer())
			require.ErrorIs(t, err, errors.ErrInvalidCiphertext)

			// Nor a payload of the wrong size.
			for _, n := range []int{len(header), len(header) + 16, len(signed) - 1} {
				short := append([]byte{}, signed[:n]...)
				binary.LittleEndian.PutUint32(short[5:], uint32(n-9+k.sigLen))
				newSig, err = signer.Signature(short)
				require.NoError(t, err)
				_, err = f.receiver.DecryptSecret(append(short, newSig...), f.signer())
				require.ErrorIs(t, err, errors.ErrInvalidCiphertext, "payload of %d bytes", n-len(header))
			}
		})
	}
}

// The symmetric suite of the HMAC + AES-CBC policies, used directly.
func TestCBCHMACSuite_Secret(t *testing.T) {
	s := eccPolicies[ua.SecurityPolicyURIECCNistP256].symmetric
	key, iv := make([]byte, 16), make([]byte, 16)
	plain := bytes.Repeat([]byte{7}, 32)
	sealed, err := s.sealSecret(key, iv, []byte("header"), plain)
	require.NoError(t, err)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	want := make([]byte, 32)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(want, plain)
	require.Equal(t, want, sealed)
	require.Zero(t, s.secretOverhead())

	got, err := s.openSecret(key, iv, nil, sealed)
	require.NoError(t, err)
	require.Equal(t, plain, got)
	for _, bad := range [][]byte{nil, sealed[:31], sealed[:17]} {
		_, err = s.openSecret(key, iv, nil, bad)
		require.ErrorIs(t, err, errors.ErrInvalidCiphertext)
	}
}

func TestAEADSuite_Errors(t *testing.T) {
	s := eccPolicies[ua.SecurityPolicyURIECCNistP256AesGcm].symmetric.(aeadSuite)
	key, iv := make([]byte, 16), make([]byte, 12)

	_, err := s.sealSecret(key[:15], iv, nil, make([]byte, 16))
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	_, err = s.sealSecret(key, iv[:11], nil, make([]byte, 16))
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	sealed, err := s.sealSecret(key, iv, nil, make([]byte, 16))
	require.NoError(t, err)
	_, err = s.openSecret(key[:15], iv, nil, sealed)
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	_, err = s.openSecret(key, iv[:11], nil, sealed)
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)

	// Derived keys of the wrong shape.
	good := &derivedKeys{encryption: key, iv: iv}
	for _, bad := range []*derivedKeys{
		{encryption: key, iv: iv[:11]},
		{encryption: key[:15], iv: iv},
	} {
		_, err = s.channel(bad, good)
		require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
		_, err = s.channel(good, bad)
		require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	}
	withSignKey := eccPolicies[ua.SecurityPolicyURIECCCurve25519].symmetric.(aeadSuite)
	good = &derivedKeys{signing: make([]byte, 32), encryption: make([]byte, 32), iv: iv}
	bad := &derivedKeys{signing: make([]byte, 31), encryption: make([]byte, 32), iv: iv}
	_, err = withSignKey.channel(bad, good)
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	_, err = withSignKey.channel(good, bad)
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)

	// A cipher with other parameters than the chunk layout assumes.
	odd := aeadSuite{cipher: func(k []byte) (cipher.AEAD, error) {
		block, err := aes.NewCipher(k)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCMWithTagSize(block, 12)
	}}
	_, err = odd.newCipher(key)
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)

	// The stand-ins for the separate algorithms refuse to work.
	for _, err := range []error{
		func() error { _, err := aeadOnly{}.Encrypt(nil); return err }(),
		func() error { _, err := aeadOnly{}.Decrypt(nil); return err }(),
		func() error { _, err := aeadOnly{}.Signature(nil); return err }(),
		aeadOnly{}.Verify(nil, nil),
	} {
		require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	}

	// An X25519 key cannot be combined with a key of another length.
	x, err := NewEphemeralKey(ua.SecurityPolicyURIECCCurve25519)
	require.NoError(t, err)
	_, err = x.key.sharedSecret(make([]byte, 31))
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	var _ = ecdsa.PublicKey{}
}

// FuzzOpenChunk feeds arbitrary data to the AEAD chunk decoder: it must not
// panic and must accept nothing but the chunks the peer sealed.
func FuzzOpenChunk(f *testing.F) {
	type pair struct {
		algo  *EncryptionAlgorithm
		valid [2][]byte // sealed in Sign and in SignAndEncrypt mode
	}
	var pairs []pair
	chunk := testChunk([]byte("fuzz me"))
	for _, uri := range aeadTestPolicies() {
		client, err := NewKeyExchange(uri, RoleClient)
		if err != nil {
			f.Fatal(err)
		}
		server, err := NewKeyExchange(uri, RoleServer)
		if err != nil {
			f.Fatal(err)
		}
		p := pair{}
		if p.algo, err = server.Symmetric(client.Nonce()); err != nil {
			f.Fatal(err)
		}
		for i, encrypt := range []bool{false, true} {
			// A sender of its own per mode: one key seals a number once.
			calgo, err := client.Symmetric(server.Nonce())
			if err != nil {
				f.Fatal(err)
			}
			if p.valid[i], err = calgo.SealChunk(chunk, 16, testTokenID, testLastSeq, encrypt); err != nil {
				f.Fatal(err)
			}
			f.Add(p.valid[i], 16, testTokenID, testLastSeq, encrypt)
			f.Add(p.valid[i][:20], 16, testTokenID, testLastSeq, encrypt)
		}
		pairs = append(pairs, p)
	}
	f.Add([]byte{}, 0, uint32(0), uint32(0), true)
	f.Add(make([]byte, 16), 16, uint32(0), uint32(0), false)

	f.Fuzz(func(t *testing.T, data []byte, headerLength int, tokenID, last uint32, encrypted bool) {
		for _, p := range pairs {
			out, err := p.algo.OpenChunk(data, headerLength, tokenID, last, encrypted)
			if err != nil {
				continue
			}
			i := 0
			if encrypted {
				i = 1
			}
			// In Sign mode the header boundary does not matter: the whole
			// chunk is authenticated.
			headerOK := headerLength == 16 || !encrypted
			if !bytes.Equal(data, p.valid[i]) || tokenID != testTokenID || last != testLastSeq || !headerOK {
				t.Fatalf("accepted a forged chunk: %x (header %d, token %d, last %d, encrypted %v) -> %x",
					data, headerLength, tokenID, last, encrypted, out)
			}
		}
	})
}
