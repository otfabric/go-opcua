// SPDX-License-Identifier: MIT

package uapolicy

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// RFC 5903 §8.1: 256-bit random ECP group. i and r are the private keys of
// the initiator and the responder, gi and gr their public keys and girx the
// x-coordinate of the shared point.
const (
	rfc5903i    = "C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433"
	rfc5903gi   = "DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C3772581180" + "5271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3"
	rfc5903r    = "C6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53"
	rfc5903gr   = "D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63" + "56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB"
	rfc5903girx = "D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE"
)

// Keys derived from the RFC 5903 exchange with the OPC UA key derivation
// (Part 6 §6.8.1), computed with an independent implementation of HKDF:
//
//	Salt = UInt16LE(L) | label | first | second ; OKM = HKDF-SHA256(girx, Salt, Salt, L)
const (
	katP256ClientKeys = "23b545c7a761640b1ace16a0f2cbb1ae4bdb51cc6d86ab0c09c64f46401aefd9" + // signing key
		"8a93ce768b55d6bb42134178614a9c53" + // encrypting key
		"92130709ecd64be92a27fa73b1e136f3" // initialization vector
	katP256ServerKeys = "227ace9032ca8194f924158ba731a9c6ecf065b5243fb36568ed8eb952c6ed3d" +
		"3ad5a7411a89f268e5ae259145976dcc" +
		"fa6d52ff46aaebd76e5763ae6d13ee9a"
	// EncryptingKey | InitializationVector of an EccEncryptedSecret with
	// gi as SenderPublicKey and gr as ReceiverPublicKey.
	katP256SecretKeys = "55cd445b094cf682d0d98ef53a9a9d6a" + "915c6ce561b03d1f8b8f1aa873028421"
)

// fixedEphemeralKey returns the ephemeral key with the given P-256 private
// key.
func fixedEphemeralKey(t *testing.T, private string) *EphemeralKey {
	t.Helper()
	p := eccPolicies[ua.SecurityPolicyURIECCNistP256]
	key, err := ecdh.P256().NewPrivateKey(unhex(t, private))
	require.NoError(t, err)
	k := nistEphemeralKey{key: key}
	return &EphemeralKey{policy: p, key: k, public: k.publicKey()}
}

func TestHKDF_RFC5869(t *testing.T) {
	// RFC 5869 A.1: the primitive the key derivation is built on.
	okm, err := hkdf.Key(sha256.New,
		unhex(t, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
		unhex(t, "000102030405060708090a0b0c"),
		string(unhex(t, "f0f1f2f3f4f5f6f7f8f9")), 42)
	require.NoError(t, err)
	require.Equal(t, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", hex.EncodeToString(okm))
}

func TestECDH_RFC5903(t *testing.T) {
	i := fixedEphemeralKey(t, rfc5903i)
	r := fixedEphemeralKey(t, rfc5903r)

	// The public key encoding is x || y without the SEC 1 format byte.
	require.Equal(t, unhex(t, rfc5903gi), i.PublicKey())
	require.Equal(t, unhex(t, rfc5903gr), r.PublicKey())
	require.Len(t, i.PublicKey(), 64)

	// Both sides compute the x-coordinate of the shared point.
	si, err := i.key.sharedSecret(r.PublicKey())
	require.NoError(t, err)
	sr, err := r.key.sharedSecret(i.PublicKey())
	require.NoError(t, err)
	require.Equal(t, unhex(t, rfc5903girx), si)
	require.Equal(t, si, sr)
}

func TestECCKeyDerivation_KnownAnswer(t *testing.T) {
	p := eccPolicies[ua.SecurityPolicyURIECCNistP256]
	secret := unhex(t, rfc5903girx)
	client, server := unhex(t, rfc5903gi), unhex(t, rfc5903gr)

	ck, err := p.channelKeys(secret, eccLabelClient, client, server)
	require.NoError(t, err)
	want := unhex(t, katP256ClientKeys)
	require.Equal(t, want[:32], ck.signing, "ClientSigningKey: offset 0, DerivedSignatureKeyLength")
	require.Equal(t, want[32:48], ck.encryption, "ClientEncryptingKey: follows the signing key")
	require.Equal(t, want[48:], ck.iv, "ClientInitializationVector: follows the encrypting key")

	sk, err := p.channelKeys(secret, eccLabelServer, server, client)
	require.NoError(t, err)
	want = unhex(t, katP256ServerKeys)
	require.Equal(t, want[:32], sk.signing)
	require.Equal(t, want[32:48], sk.encryption)
	require.Equal(t, want[48:], sk.iv)

	// The label and the order of the nonces are part of the salt.
	other, err := p.channelKeys(secret, eccLabelClient, server, client)
	require.NoError(t, err)
	require.NotEqual(t, ck.signing, other.signing)

	okm, err := p.deriveKeys(secret, eccLabelSecret, client, server, 32)
	require.NoError(t, err)
	require.Equal(t, unhex(t, katP256SecretKeys), okm)
}

func TestECCSymmetric_KnownAnswer(t *testing.T) {
	p := eccPolicies[ua.SecurityPolicyURIECCNistP256]
	client := fixedEphemeralKey(t, rfc5903i)
	server := fixedEphemeralKey(t, rfc5903r)

	calgo, chain, err := p.symmetricKeys(client, server.PublicKey(), RoleClient, nil)
	require.NoError(t, err)
	require.Nil(t, chain, "no key chaining without SecureChannelEnhancements")
	salgo, _, err := p.symmetricKeys(server, client.PublicKey(), RoleServer, nil)
	require.NoError(t, err)
	require.False(t, calgo.AEAD())

	ck, sk := unhex(t, katP256ClientKeys), unhex(t, katP256ServerKeys)
	msg := []byte("0123456789abcdef0123456789abcdef") // two AES blocks

	// The client signs with the ClientSigningKey ...
	sig, err := calgo.Signature(msg)
	require.NoError(t, err)
	mac := hmac.New(sha256.New, ck[:32])
	mac.Write(msg)
	require.Equal(t, mac.Sum(nil), sig)
	require.NoError(t, salgo.VerifySignature(msg, sig))

	// ... and encrypts with the ClientEncryptingKey and ClientInitializationVector.
	enc, err := calgo.Encrypt(msg)
	require.NoError(t, err)
	block, err := aes.NewCipher(ck[32:48])
	require.NoError(t, err)
	want := make([]byte, len(msg))
	cipher.NewCBCEncrypter(block, ck[48:]).CryptBlocks(want, msg)
	require.Equal(t, want, enc)
	dec, err := salgo.Decrypt(enc)
	require.NoError(t, err)
	require.Equal(t, msg, dec)

	// The server uses the server keys.
	sig, err = salgo.Signature(msg)
	require.NoError(t, err)
	mac = hmac.New(sha256.New, sk[:32])
	mac.Write(msg)
	require.Equal(t, mac.Sum(nil), sig)
	require.NoError(t, calgo.VerifySignature(msg, sig))
	enc, err = salgo.Encrypt(msg)
	require.NoError(t, err)
	dec, err = calgo.Decrypt(enc)
	require.NoError(t, err)
	require.Equal(t, msg, dec)

	// A side cannot read its own messages: the directions have separate keys.
	require.Error(t, calgo.VerifySignature(msg, mustSign(t, calgo, msg)))

	require.Equal(t, 32, calgo.SignatureLength())
	require.Equal(t, 32, calgo.RemoteSignatureLength())
	require.Equal(t, 16, calgo.BlockSize())
	require.Equal(t, 16, calgo.PlaintextBlockSize())
	require.False(t, calgo.SignOnly())
	require.Equal(t, "http://www.w3.org/2001/04/xmlenc#aes128-cbc", calgo.EncryptionURI())
}

func mustSign(t *testing.T, a *EncryptionAlgorithm, msg []byte) []byte {
	t.Helper()
	sig, err := a.Signature(msg)
	require.NoError(t, err)
	return sig
}

func TestECCPolicyParameters(t *testing.T) {
	tests := []struct {
		uri                   string
		nonce, sigKey, encKey int
		hash                  crypto.Hash
	}{
		{uri: ua.SecurityPolicyURIECCNistP256, nonce: 64, sigKey: 32, encKey: 16, hash: crypto.SHA256},
		{uri: ua.SecurityPolicyURIECCNistP384, nonce: 96, sigKey: 48, encKey: 32, hash: crypto.SHA384},
		{uri: ua.SecurityPolicyURIECCBrainpoolP256r1, nonce: 64, sigKey: 32, encKey: 16, hash: crypto.SHA256},
		{uri: ua.SecurityPolicyURIECCBrainpoolP384r1, nonce: 96, sigKey: 48, encKey: 32, hash: crypto.SHA384},
	}
	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			require.True(t, IsECC(tt.uri))
			require.False(t, LegacySequenceNumbers(tt.uri))
			p := eccPolicies[tt.uri]
			require.Equal(t, tt.nonce, p.agreement.publicKeyLength())
			require.Equal(t, tt.sigKey, p.symmetric.signingKeyLength())
			require.Equal(t, tt.encKey, p.symmetric.encryptingKeyLength())
			require.Equal(t, 16, p.symmetric.ivLength())
			require.Equal(t, tt.hash, p.hash)
			require.False(t, IsAEAD(tt.uri))
			require.False(t, SecureChannelEnhancements(tt.uri))

			kx, err := NewKeyExchange(tt.uri, RoleClient)
			require.NoError(t, err)
			require.Len(t, kx.Nonce(), tt.nonce)

			// Sign and SignAndEncrypt rank above every RSA policy.
			for _, mode := range []ua.MessageSecurityMode{ua.MessageSecurityModeSign, ua.MessageSecurityModeSignAndEncrypt} {
				for _, rsaURI := range rsaTestPolicies() {
					require.Greater(t, SecurityLevel(tt.uri, mode), SecurityLevel(rsaURI, ua.MessageSecurityModeSignAndEncrypt), rsaURI)
				}
			}
			require.Zero(t, SecurityLevel(tt.uri, ua.MessageSecurityModeNone))
		})
	}
	require.Greater(t,
		SecurityLevel(ua.SecurityPolicyURIECCNistP384, ua.MessageSecurityModeSign),
		SecurityLevel(ua.SecurityPolicyURIECCNistP256, ua.MessageSecurityModeSignAndEncrypt))

	for _, uri := range rsaTestPolicies() {
		require.False(t, IsECC(uri), uri)
		require.True(t, LegacySequenceNumbers(uri), uri)
	}
	require.False(t, IsECC("http://opcfoundation.org/UA/SecurityPolicy#ECC_brainpoolP512r1"))
}

func TestKeyExchange_AllPolicies(t *testing.T) {
	for _, uri := range SupportedPolicies() {
		t.Run(uri, func(t *testing.T) {
			client, err := NewKeyExchange(uri, RoleClient)
			require.NoError(t, err)
			server, err := NewKeyExchange(uri, RoleServer)
			require.NoError(t, err)

			calgo, err := client.Symmetric(server.Nonce())
			require.NoError(t, err)
			salgo, err := server.Symmetric(client.Nonce())
			require.NoError(t, err)

			if uri == ua.SecurityPolicyURINone {
				return
			}
			if calgo.AEAD() {
				// Authenticated encryption has no separate signature and
				// encryption; see ecc_aead_test.go.
				_, err := calgo.Signature([]byte("x"))
				require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
				require.True(t, salgo.AEAD())
				return
			}

			msg := bytes.Repeat([]byte{0x5a}, 4*calgo.BlockSize())
			for _, pair := range [][2]*EncryptionAlgorithm{{calgo, salgo}, {salgo, calgo}} {
				from, to := pair[0], pair[1]
				sig, err := from.Signature(msg)
				require.NoError(t, err)
				require.Len(t, sig, from.SignatureLength())
				require.NoError(t, to.VerifySignature(msg, sig))

				sig[0] ^= 1
				require.ErrorIs(t, to.VerifySignature(msg, sig), errors.ErrSignatureValidationFailed)

				enc, err := from.Encrypt(msg)
				require.NoError(t, err)
				require.NotEqual(t, msg, enc)
				dec, err := to.Decrypt(enc)
				require.NoError(t, err)
				require.Equal(t, msg, dec)
			}

			// Every negotiation has its own nonce (and, for ECC, its own
			// ephemeral key): a renewal never reuses key material.
			again, err := NewKeyExchange(uri, RoleClient)
			require.NoError(t, err)
			require.NotEqual(t, client.Nonce(), again.Nonce())
		})
	}

	_, err := NewKeyExchange("http://opcfoundation.org/UA/SecurityPolicy#Nope", RoleClient)
	require.ErrorIs(t, err, errors.ErrUnsupportedSecurityPolicy)
}

func TestKeyExchange_ECC_InvalidPeerKey(t *testing.T) {
	for _, uri := range eccTestPolicies() {
		t.Run(uri, func(t *testing.T) {
			kx, err := NewKeyExchange(uri, RoleServer)
			require.NoError(t, err)
			n := len(kx.Nonce())

			// A key of the other key length is one of another curve.
			other := ua.SecurityPolicyURIECCNistP256
			if n == 64 {
				other = ua.SecurityPolicyURIECCNistP384
			}
			wrongCurve, err := NewKeyExchange(other, RoleClient)
			require.NoError(t, err)

			bad := map[string][]byte{
				"nil":       nil,
				"empty":     {},
				"too short": kx.Nonce()[:n-1],
				"too long":  append(append([]byte{}, kx.Nonce()...), 0),
				// NIST curves: the point at infinity has no affine encoding.
				// Curve25519: a point of small order, the shared secret
				// would be all zero whatever the private key.
				"zero":          make([]byte, n),
				"other curve":   wrongCurve.Nonce(),
				"sec1 encoding": append([]byte{4}, kx.Nonce()...),
			}
			switch uri {
			case ua.SecurityPolicyURIECCCurve25519:
				// Every 32 byte string is an X25519 public key; the ones to
				// refuse are the points of small order (RFC 7748 §6.1).
				bad["order 1"] = append([]byte{1}, make([]byte, 31)...)
				bad["order 8"] = unhex(t, "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")
			case ua.SecurityPolicyURIECCCurve448:
				// The same for X448 (RFC 7748 §6.2): u = 1 and u = p - 1,
				// and the non-canonical u = p and p + 1, which reduce to
				// 0 and 1. Little-endian, p = 2^448 - 2^224 - 1.
				bad["u=1"] = append([]byte{1}, make([]byte, 55)...)
				p := bytes.Repeat([]byte{0xff}, 56)
				p[28] = 0xfe
				bad["u=p"] = p
				pMinus1 := bytes.Clone(p)
				pMinus1[0] = 0xfe
				bad["u=p-1"] = pMinus1
				pPlus1 := append(make([]byte, 28), bytes.Repeat([]byte{0xff}, 28)...)
				bad["u=p+1"] = pPlus1
			default:
				bad["not on curve"] = bytes.Repeat([]byte{0x01}, n)
			}
			for name, nonce := range bad {
				_, err := kx.Symmetric(nonce)
				require.Error(t, err, name)
			}

			// The same exchange still works with a valid key.
			peer, err := NewKeyExchange(uri, RoleClient)
			require.NoError(t, err)
			_, err = kx.Symmetric(peer.Nonce())
			require.NoError(t, err)
		})
	}
}

func TestSymmetric_RejectsECC(t *testing.T) {
	for _, uri := range eccTestPolicies() {
		_, err := Symmetric(uri, make([]byte, 64), make([]byte, 64))
		require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig, uri)
	}
}

func TestEphemeralKey(t *testing.T) {
	_, err := NewEphemeralKey(ua.SecurityPolicyURIBasic256Sha256)
	require.ErrorIs(t, err, errors.ErrUnsupportedSecurityPolicy)

	k, err := NewEphemeralKey(ua.SecurityPolicyURIECCNistP384)
	require.NoError(t, err)
	require.Equal(t, ua.SecurityPolicyURIECCNistP384, k.PolicyURI())
	require.Len(t, k.PublicKey(), 96)

	// The returned slice is a copy.
	pub := k.PublicKey()
	pub[0] ^= 0xff
	require.NotEqual(t, pub, k.PublicKey())

	// A key of one policy cannot be used with another.
	p256 := eccPolicies[ua.SecurityPolicyURIECCNistP256]
	_, _, err = p256.symmetricKeys(k, make([]byte, 64), RoleClient, nil)
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	_, _, err = p256.symmetricKeys(nil, make([]byte, 64), RoleClient, nil)
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
}

// RFC 6979 A.2.5: ECDSA, P-256, SHA-256, message "sample".
func TestECDSA_RFC6979_Verify(t *testing.T) {
	// The public key as an uncompressed point: 0x04 || X || Y.
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), unhex(t, "04"+
		"60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"+
		"7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"))
	require.NoError(t, err)

	// The OPC UA encoding: r || s, 32 bytes each.
	sig := unhex(t, "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"+
		"F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8")

	v := &ECDSA{Hash: crypto.SHA256, PublicKey: pub}
	require.NoError(t, v.Verify([]byte("sample"), sig))
	require.ErrorIs(t, v.Verify([]byte("Sample"), sig), errors.ErrSignatureValidationFailed)

	for i := range sig {
		bad := append([]byte{}, sig...)
		bad[i] ^= 0x01
		require.ErrorIs(t, v.Verify([]byte("sample"), bad), errors.ErrSignatureValidationFailed, "byte %d", i)
	}

	// Lengths other than exactly r || s are rejected, including the ASN.1
	// DER encoding used elsewhere.
	require.Error(t, v.Verify([]byte("sample"), sig[:63]))
	require.Error(t, v.Verify([]byte("sample"), append(sig, 0)))
	require.Error(t, v.Verify([]byte("sample"), nil))
	// r = s = 0 must not verify.
	require.Error(t, v.Verify([]byte("sample"), make([]byte, 64)))
	// No key, no verification.
	require.Error(t, (&ECDSA{Hash: crypto.SHA256}).Verify([]byte("sample"), sig))
}

// opaqueSigner hides the concrete key type, like a key in an HSM.
type opaqueSigner struct{ key crypto.Signer }

func (s opaqueSigner) Public() crypto.PublicKey { return s.key.Public() }
func (s opaqueSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(r, digest, opts)
}

// brokenSigner returns something that is not an ECDSA signature.
type brokenSigner struct {
	opaqueSigner
	out []byte
}

func (s brokenSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return s.out, nil
}

func TestECCAsymmetric(t *testing.T) {
	p256 := newECDSAKey(t, elliptic.P256())
	p384 := newECDSAKey(t, elliptic.P384())
	p521 := newECDSAKey(t, elliptic.P521())
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	msg := []byte("OpenSecureChannel")

	t.Run("sign and verify", func(t *testing.T) {
		for _, tt := range []struct {
			uri  string
			key  *ecdsa.PrivateKey
			size int
		}{
			{ua.SecurityPolicyURIECCNistP256, p256, 64},
			{ua.SecurityPolicyURIECCNistP256, p384, 96}, // a P-384 certificate is permitted
			{ua.SecurityPolicyURIECCNistP384, p384, 96},
		} {
			for _, signer := range []crypto.Signer{tt.key, opaqueSigner{tt.key}} {
				local, err := AsymmetricKeys(tt.uri, signer, nil)
				require.NoError(t, err)
				remote, err := AsymmetricKeys(tt.uri, nil, &tt.key.PublicKey)
				require.NoError(t, err)

				require.True(t, local.SignOnly())
				require.Equal(t, tt.size, local.SignatureLength())
				require.Equal(t, tt.size, remote.RemoteSignatureLength())
				require.Equal(t, 1, local.BlockSize())
				require.Equal(t, 1, local.PlaintextBlockSize())
				require.Empty(t, local.SignatureURI())
				require.Empty(t, local.EncryptionURI())

				sig, err := local.Signature(msg)
				require.NoError(t, err)
				require.Len(t, sig, tt.size)
				require.NoError(t, remote.VerifySignature(msg, sig))
				require.Error(t, remote.VerifySignature(append(msg, 0), sig))

				// Nothing is encrypted.
				enc, err := local.Encrypt(msg)
				require.NoError(t, err)
				require.Equal(t, msg, enc)
				dec, err := remote.Decrypt(msg)
				require.NoError(t, err)
				require.Equal(t, msg, dec)
			}
		}
	})

	t.Run("hash follows the policy", func(t *testing.T) {
		// ECC_nistP256 signs with SHA-256 even when the key is on P-384.
		local, err := AsymmetricKeys(ua.SecurityPolicyURIECCNistP256, p384, nil)
		require.NoError(t, err)
		sig, err := local.Signature(msg)
		require.NoError(t, err)
		other, err := AsymmetricKeys(ua.SecurityPolicyURIECCNistP384, nil, &p384.PublicKey)
		require.NoError(t, err)
		require.Error(t, other.VerifySignature(msg, sig))
	})

	t.Run("wrong key type", func(t *testing.T) {
		for name, tt := range map[string]struct {
			uri    string
			local  crypto.PrivateKey
			remote crypto.PublicKey
		}{
			"rsa local on ecc":       {ua.SecurityPolicyURIECCNistP256, rsaKey, nil},
			"rsa remote on ecc":      {ua.SecurityPolicyURIECCNistP256, nil, &rsaKey.PublicKey},
			"p256 local on p384":     {ua.SecurityPolicyURIECCNistP384, p256, nil},
			"p256 remote on p384":    {ua.SecurityPolicyURIECCNistP384, nil, &p256.PublicKey},
			"p521 local":             {ua.SecurityPolicyURIECCNistP256, p521, nil},
			"p521 remote":            {ua.SecurityPolicyURIECCNistP384, nil, &p521.PublicKey},
			"ecc local on rsa":       {ua.SecurityPolicyURIBasic256Sha256, p256, nil},
			"ecc remote on rsa":      {ua.SecurityPolicyURIAes256Sha256RsaPss, nil, &p256.PublicKey},
			"not a signer":           {ua.SecurityPolicyURIECCNistP256, []byte("key"), nil},
			"public key by value":    {ua.SecurityPolicyURIECCNistP256, nil, p256.PublicKey},
			"curveless public key":   {ua.SecurityPolicyURIECCNistP256, nil, &ecdsa.PublicKey{}},
			"opaque rsa on ecc":      {ua.SecurityPolicyURIECCNistP256, opaqueSigner{rsaKey}, nil},
			"opaque rsa signer, rsa": {ua.SecurityPolicyURIBasic256Sha256, opaqueSigner{rsaKey}, nil},
		} {
			_, err := AsymmetricKeys(tt.uri, tt.local, tt.remote)
			require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig, name)
		}
		_, err := AsymmetricKeys("http://opcfoundation.org/UA/SecurityPolicy#Nope", p256, nil)
		require.ErrorIs(t, err, errors.ErrUnsupportedSecurityPolicy)
	})

	t.Run("nil keys", func(t *testing.T) {
		var nilRSA *rsa.PrivateKey
		var nilECDSA *ecdsa.PrivateKey
		var nilPub *ecdsa.PublicKey
		for _, uri := range eccTestPolicies() {
			for _, local := range []crypto.PrivateKey{nil, nilRSA, nilECDSA} {
				algo, err := AsymmetricKeys(uri, local, nilPub)
				require.NoError(t, err)
				// Without keys the algorithm neither signs nor accepts anything.
				_, err = algo.Signature(msg)
				require.Error(t, err)
				require.Error(t, algo.VerifySignature(msg, make([]byte, 64)))
				require.Zero(t, algo.SignatureLength())
				require.Zero(t, algo.RemoteSignatureLength())
				require.True(t, algo.SignOnly())
			}
		}
		// The RSA entry point still takes nil keys.
		algo, err := Asymmetric(ua.SecurityPolicyURIBasic256Sha256, nil, nil)
		require.NoError(t, err)
		require.False(t, algo.SignOnly())
		algo, err = Asymmetric(ua.SecurityPolicyURIBasic256Sha256, rsaKey, &rsaKey.PublicKey)
		require.NoError(t, err)
		require.Equal(t, 256, algo.SignatureLength())
	})

	t.Run("misbehaving signer", func(t *testing.T) {
		for name, out := range map[string][]byte{
			"garbage":  []byte("not asn.1"),
			"empty":    {},
			"zero r":   {0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01},
			"negative": {0x30, 0x06, 0x02, 0x01, 0x81, 0x02, 0x01, 0x01},
			"trailing": {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00},
		} {
			algo, err := AsymmetricKeys(ua.SecurityPolicyURIECCNistP256, brokenSigner{opaqueSigner{p256}, out}, nil)
			require.NoError(t, err)
			_, err = algo.Signature(msg)
			require.Error(t, err, name)
		}
		// r and s larger than the field.
		huge := append([]byte{0x30, 0x46, 0x02, 0x21}, bytes.Repeat([]byte{0x7f}, 33)...)
		huge = append(huge, append([]byte{0x02, 0x21}, bytes.Repeat([]byte{0x7f}, 33)...)...)
		algo, err := AsymmetricKeys(ua.SecurityPolicyURIECCNistP256, brokenSigner{opaqueSigner{p256}, huge}, nil)
		require.NoError(t, err)
		_, err = algo.Signature(msg)
		require.Error(t, err)

		// A signer that is not an ECDSA key at all.
		_, err = (&ECDSA{Hash: crypto.SHA256, PrivateKey: rsaKey}).Signature(msg)
		require.Error(t, err)
	})
}
