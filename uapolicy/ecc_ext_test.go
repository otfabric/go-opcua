// SPDX-License-Identifier: MIT

package uapolicy

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/brainpool"
	"github.com/cloudflare/circl/sign/ed448"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
)

// RFC 7027 Appendix A: ECDH on brainpoolP256r1 and brainpoolP384r1. dA and
// dB are the private keys, qA and qB the public keys (x || y), z the
// x-coordinate of the shared point. Checked against OpenSSL 3.5.
//
// The keys of the policies are computed from them with an independent
// implementation of HKDF (Python, hmac and hashlib of the standard library
// only), client = A:
//
//	Salt = UInt16LE(L) | label | first | second ; OKM = HKDF(secret, Salt, Salt, L)
//
// with SHA-256 and L = 32+16+16 for ECC_brainpoolP256r1, SHA-384 and
// L = 48+32+16 for ECC_brainpoolP384r1.
var brainpoolKATs = []struct {
	uri                    string
	curve                  elliptic.Curve
	dA, qA, dB, qB, z      string
	clientKeys, serverKeys string
	secretKeys             string
}{
	{
		uri:   ua.SecurityPolicyURIECCBrainpoolP256r1,
		curve: brainpool.P256r1(),
		dA:    "81DB1EE100150FF2EA338D708271BE38300CB54241D79950F77B063039804F1D",
		qA: "44106E913F92BC02A1705D9953A8414DB95E1AAA49E81D9E85F929A8E3100BE5" +
			"8AB4846F11CACCB73CE49CBDD120F5A900A69FD32C272223F789EF10EB089BDC",
		dB: "55E40BC41E37E3E2AD25C3C6654511FFA8474A91A0032087593852D3E7D76BD3",
		qB: "8D2D688C6CF93E1160AD04CC4429117DC2C41825E1E9FCA0ADDD34E6F1B39F7B" +
			"990C57520812BE512641E47034832106BC7D3E8DD0E4C7F1136D7006547CEC6A",
		z:          "89AFC39D41D3B327814B80940B042590F96556EC91E6AE7939BCE31F3A18BF2B",
		clientKeys: "b8b7d159e7be9194d8c89cbfea402a4d61bec02c91a2047c62f8bf312b2b343d" + "d6d64de8d38e09055c8ce68b87fa18fe" + "ce93678a65f8e9439ad2ee60fddadcb6",
		serverKeys: "2c7c726e0a60f56c5d7ad74cdc1625237b66ed7b448ab7081cc28ae13d83e7aa" + "c938937ba0ac8dcc37a35237aaf0cfdc" + "6f4205855b6e48869f8e02c4f76a3f47",
		secretKeys: "b26ecadeb6d1524361ea1aee89e12663" + "8c49f21f6983343f9e840f2ac7ead7f6",
	},
	{
		uri:   ua.SecurityPolicyURIECCBrainpoolP384r1,
		curve: brainpool.P384r1(),
		dA:    "1E20F5E048A5886F1F157C74E91BDE2B98C8B52D58E5003D57053FC4B0BD65D6F15EB5D1EE1610DF870795143627D042",
		qA: "68B665DD91C195800650CDD363C625F4E742E8134667B767B1B476793588F885AB698C852D4A6E77A252D6380FCAF068" +
			"55BC91A39C9EC01DEE36017B7D673A931236D2F1F5C83942D049E3FA20607493E0D038FF2FD30C2AB67D15C85F7FAA59",
		dB: "032640BC6003C59260F7250C3DB58CE647F98E1260ACCE4ACDA3DD869F74E01F8BA5E0324309DB6A9831497ABAC96670",
		qB: "4D44326F269A597A5B58BBA565DA5556ED7FD9A8A9EB76C25F46DB69D19DC8CE6AD18E404B15738B2086DF37E71D1EB4" +
			"62D692136DE56CBE93BF5FA3188EF58BC8A3A0EC6C1E151A21038A42E9185329B5B275903D192F8D4E1F32FE9CC78C48",
		z: "0BD9D3A7EA0B3D519D09D8E48D0785FB744A6B355E6304BC51C229FBBCE239BBADF6403715C35D4FB2A5444F575D4F42",
		clientKeys: "d8b085f735ff0aca46564f3ca14d93c0a7eaac1225e312927687ecbb97801a171d70a1c71d677e4d20a1723ac0dd28d5" +
			"7028bf6db721a6f13dde7e9ab13e9db3f99b1a84499ad429f8b9b777f7471d7e" + "185079f54a44688c69d450ccbc8846c1",
		serverKeys: "c93fe8bf00dab4fa9546475d40e6222fe57c733399f72bbf4009e18310cc8b488eca281809b739a5dd3dc9056cc621e9" +
			"7d7cfee388eb0e9ca00de70818fa86034ca1637f40497c72c49eb055633c80a0" + "a07413f2a63600d54b53e7cc2961aa38",
		secretKeys: "1bd2417282309fcc634c61e2b1a74d9a0d5bd6c1d7224bc82b8a2964a3303c19" + "06a375e14e2c8f8a16f74f8a0e19dbea",
	},
}

// brainpoolKey returns the private key d (hex) on the curve.
func brainpoolKey(t *testing.T, curve elliptic.Curve, d string) *ecdsa.PrivateKey {
	t.Helper()
	n := (curve.Params().BitSize + 7) / 8
	key, err := parseBrainpoolECPrivateKey(sec1Brainpool(t, curve, unhex(t, d), n), curve)
	require.NoError(t, err)
	return key
}

// sec1Brainpool encodes a SEC 1 ECPrivateKey without the optional fields.
func sec1Brainpool(t *testing.T, _ elliptic.Curve, d []byte, n int) []byte {
	t.Helper()
	padded := make([]byte, n)
	copy(padded[n-len(d):], d)
	return append([]byte{0x30, byte(5 + n), 0x02, 0x01, 0x01, 0x04, byte(n)}, padded...)
}

func TestBrainpoolECDH_RFC7027(t *testing.T) {
	for _, k := range brainpoolKATs {
		t.Run(k.uri, func(t *testing.T) {
			a := brainpoolEphemeralKey{key: brainpoolKey(t, k.curve, k.dA)}
			b := brainpoolEphemeralKey{key: brainpoolKey(t, k.curve, k.dB)}
			require.Equal(t, unhex(t, k.qA), a.publicKey(), "public key: x || y")
			require.Equal(t, unhex(t, k.qB), b.publicKey())

			za, err := a.sharedSecret(unhex(t, k.qB))
			require.NoError(t, err)
			zb, err := b.sharedSecret(unhex(t, k.qA))
			require.NoError(t, err)
			require.Equal(t, unhex(t, k.z), za, "the shared secret is the x-coordinate")
			require.Equal(t, za, zb)
		})
	}
}

func TestBrainpoolKeyDerivation_KnownAnswer(t *testing.T) {
	for _, k := range brainpoolKATs {
		t.Run(k.uri, func(t *testing.T) {
			p := eccPolicies[k.uri]
			secret, client, server := unhex(t, k.z), unhex(t, k.qA), unhex(t, k.qB)
			sig, enc := p.symmetric.signingKeyLength(), p.symmetric.encryptingKeyLength()

			ck, err := p.channelKeys(secret, eccLabelClient, client, server)
			require.NoError(t, err)
			want := unhex(t, k.clientKeys)
			require.Len(t, want, sig+enc+16)
			require.Equal(t, want[:sig], ck.signing)
			require.Equal(t, want[sig:sig+enc], ck.encryption)
			require.Equal(t, want[sig+enc:], ck.iv)

			sk, err := p.channelKeys(secret, eccLabelServer, server, client)
			require.NoError(t, err)
			require.Equal(t, unhex(t, k.serverKeys), append(append(append([]byte{}, sk.signing...), sk.encryption...), sk.iv...))

			okm, err := p.deriveKeys(secret, eccLabelSecret, client, server, enc+16)
			require.NoError(t, err)
			require.Equal(t, unhex(t, k.secretKeys), okm)

			// The whole exchange: both sides agree on the keys.
			a := &EphemeralKey{policy: p, key: brainpoolEphemeralKey{key: brainpoolKey(t, k.curve, k.dA)}, public: client}
			b := &EphemeralKey{policy: p, key: brainpoolEphemeralKey{key: brainpoolKey(t, k.curve, k.dB)}, public: server}
			calgo, _, err := p.symmetricKeys(a, server, RoleClient, nil)
			require.NoError(t, err)
			salgo, _, err := p.symmetricKeys(b, client, RoleServer, nil)
			require.NoError(t, err)
			msg := bytes.Repeat([]byte("brainpool"), 16)[:128]
			enc1, err := calgo.Encrypt(msg)
			require.NoError(t, err)
			dec, err := salgo.Decrypt(enc1)
			require.NoError(t, err)
			require.Equal(t, msg, dec)
		})
	}
}

func TestBrainpoolECDH_InvalidPeerKey(t *testing.T) {
	for _, k := range brainpoolKATs {
		t.Run(k.uri, func(t *testing.T) {
			a := brainpoolEphemeralKey{key: brainpoolKey(t, k.curve, k.dA)}
			qB := unhex(t, k.qB)
			n := len(qB) / 2
			p := k.curve.Params().P

			off := bytes.Clone(qB)
			off[len(off)-1] ^= 1
			bad := map[string][]byte{
				"short":        qB[:len(qB)-1],
				"long":         append(bytes.Clone(qB), 0),
				"zero":         make([]byte, len(qB)),
				"not on curve": off,
			}
			// A coordinate outside the field that reduces to the one of a
			// valid point: x + P and y + P, where they fit.
			x := new(big.Int).Add(new(big.Int).SetBytes(qB[:n]), p)
			if x.BitLen() <= 8*n {
				bad["x + P"] = append(x.FillBytes(make([]byte, n)), qB[n:]...)
			}
			y := new(big.Int).Add(new(big.Int).SetBytes(qB[n:]), p)
			if y.BitLen() <= 8*n {
				bad["y + P"] = append(bytes.Clone(qB[:n]), y.FillBytes(make([]byte, n))...)
			}
			for name, nonce := range bad {
				_, err := a.sharedSecret(nonce)
				require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig, name)
			}
			// A NIST point of the same size is not on the Brainpool curve.
			nist, err := NewEphemeralKey(map[int]string{32: ua.SecurityPolicyURIECCNistP256, 48: ua.SecurityPolicyURIECCNistP384}[n])
			require.NoError(t, err)
			_, err = a.sharedSecret(nist.PublicKey())
			require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
		})
	}
}

func TestBrainpoolECDSA(t *testing.T) {
	for _, tt := range []struct {
		uri   string
		curve elliptic.Curve
		hash  crypto.Hash
		size  int
	}{
		{ua.SecurityPolicyURIECCBrainpoolP256r1, brainpool.P256r1(), crypto.SHA256, 64},
		{ua.SecurityPolicyURIECCBrainpoolP256r1, brainpool.P384r1(), crypto.SHA256, 96}, // a P384r1 certificate is permitted
		{ua.SecurityPolicyURIECCBrainpoolP384r1, brainpool.P384r1(), crypto.SHA384, 96},
	} {
		t.Run(tt.uri+"/"+tt.curve.Params().Name, func(t *testing.T) {
			key := newECDSAKey(t, tt.curve)
			algo, err := AsymmetricKeys(tt.uri, key, &key.PublicKey)
			require.NoError(t, err)
			require.Equal(t, tt.size, algo.SignatureLength())
			require.Equal(t, tt.size, algo.RemoteSignatureLength())
			msg := []byte("OpenSecureChannel")
			sig, err := algo.Signature(msg)
			require.NoError(t, err)
			require.Len(t, sig, tt.size)
			require.NoError(t, algo.VerifySignature(msg, sig))

			// r || s: the signature verifies as ASN.1 with crypto/ecdsa.
			h := tt.hash.New()
			h.Write(msg)
			r, s := new(big.Int).SetBytes(sig[:tt.size/2]), new(big.Int).SetBytes(sig[tt.size/2:])
			require.True(t, ecdsa.Verify(&key.PublicKey, h.Sum(nil), r, s))

			sig[3] ^= 0x10
			require.ErrorIs(t, algo.VerifySignature(msg, sig), errors.ErrSignatureValidationFailed)
		})
	}

	// A NIST key is not a Brainpool key and the other way round.
	p256 := newECDSAKey(t, elliptic.P256())
	_, err := AsymmetricKeys(ua.SecurityPolicyURIECCBrainpoolP256r1, p256, nil)
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	bp256 := newECDSAKey(t, brainpool.P256r1())
	_, err = AsymmetricKeys(ua.SecurityPolicyURIECCNistP256, nil, &bp256.PublicKey)
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	_, err = AsymmetricKeys(ua.SecurityPolicyURIECCBrainpoolP384r1, bp256, nil)
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	require.Contains(t, describeKey(&bp256.PublicKey), "brainpoolP256r1")
}

// RFC 8032 §7.4, "1 octet": an Ed448 key, the message 03 and its signature.
// The signature was checked against OpenSSL 3.5.
const (
	rfc8032Ed448Secret = "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e"
	rfc8032Ed448Public = "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480"
	rfc8032Ed448Sig    = "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00"
)

func TestEd448_RFC8032(t *testing.T) {
	key := ed448.NewKeyFromSeed(unhex(t, rfc8032Ed448Secret))
	require.Equal(t, unhex(t, rfc8032Ed448Public), []byte(key.Public().(ed448.PublicKey)))

	local, err := AsymmetricKeys(ua.SecurityPolicyURIECCCurve448, key, nil)
	require.NoError(t, err)
	require.Equal(t, 114, local.SignatureLength())
	sig, err := local.Signature([]byte{0x03})
	require.NoError(t, err)
	require.Equal(t, unhex(t, rfc8032Ed448Sig), sig, "pure Ed448, empty context, deterministic")

	remote, err := AsymmetricKeys(ua.SecurityPolicyURIECCCurve448, nil, key.Public())
	require.NoError(t, err)
	require.NoError(t, remote.VerifySignature([]byte{0x03}, sig))
	require.ErrorIs(t, remote.VerifySignature([]byte{0x04}, sig), errors.ErrSignatureValidationFailed)
	require.ErrorIs(t, remote.VerifySignature([]byte{0x03}, sig[1:]), errors.ErrSignatureValidationFailed)
	// Ed448ph or a context make other signatures.
	ph := ed448.SignPh(key, []byte{0x03}, "")
	require.ErrorIs(t, remote.VerifySignature([]byte{0x03}, ph), errors.ErrSignatureValidationFailed)
	withCtx := ed448.Sign(key, []byte{0x03}, "opcua")
	require.ErrorIs(t, remote.VerifySignature([]byte{0x03}, withCtx), errors.ErrSignatureValidationFailed)
}

func TestEd448_Errors(t *testing.T) {
	_, err := (&Ed448{}).Signature([]byte("x"))
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	_, err = (&Ed448{PrivateKey: newECDSAKey(t, elliptic.P256())}).Signature([]byte("x"))
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	key := newEd448Key(t)
	_, err = (&Ed448{PrivateKey: brokenSigner{opaqueSigner{key}, []byte("short")}}).Signature([]byte("x"))
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	_, err = (&Ed448{PrivateKey: failingSigner{key}}).Signature([]byte("x"))
	require.ErrorIs(t, err, errors.ErrInvalidState)
	require.ErrorIs(t, (&Ed448{PublicKey: ed448.PublicKey("short")}).Verify([]byte("x"), make([]byte, 114)), errors.ErrSignatureValidationFailed)

	for name, k := range map[string]crypto.PrivateKey{
		"not a signer": []byte("key"),
		"ecdsa":        newECDSAKey(t, elliptic.P256()),
	} {
		_, err := AsymmetricKeys(ua.SecurityPolicyURIECCCurve448, k, nil)
		require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig, name)
	}
	for name, k := range map[string]crypto.PublicKey{
		"short":   ed448.PublicKey("short"),
		"ed25519": newECDSAKey(t, elliptic.P256()).Public(),
	} {
		_, err := AsymmetricKeys(ua.SecurityPolicyURIECCCurve448, nil, k)
		require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig, name)
	}
	require.Equal(t, "an Ed448 key", describeKey(key.Public()))
}

func TestX448_RFC7748(t *testing.T) {
	uri := ua.SecurityPolicyURIECCCurve448
	a := fixedEphemeralKeyFor(t, uri, rfc7748x448a)
	b := fixedEphemeralKeyFor(t, uri, rfc7748x448b)
	require.Equal(t, unhex(t, rfc7748x448pa), a.PublicKey())
	require.Equal(t, unhex(t, rfc7748x448pb), b.PublicKey())
	ka, err := a.key.sharedSecret(b.PublicKey())
	require.NoError(t, err)
	kb, err := b.key.sharedSecret(a.PublicKey())
	require.NoError(t, err)
	require.Equal(t, unhex(t, rfc7748x448k), ka)
	require.Equal(t, ka, kb)

	_, err = newX448Key(strings.NewReader("too short"))
	require.Error(t, err)
}

// TestExtendedPolicies_KeyExchange runs a complete exchange for every new
// policy with random keys, renewals included.
func TestExtendedPolicies_KeyExchange(t *testing.T) {
	for _, uri := range []string{ua.SecurityPolicyURIECCBrainpoolP256r1, ua.SecurityPolicyURIECCBrainpoolP384r1, ua.SecurityPolicyURIECCCurve448} {
		t.Run(uri, func(t *testing.T) {
			require.True(t, IsECC(uri))
			require.False(t, SecureChannelEnhancements(uri))
			require.Equal(t, uri == ua.SecurityPolicyURIECCCurve448, IsAEAD(uri))
			for range 3 {
				c, err := NewKeyExchange(uri, RoleClient)
				require.NoError(t, err)
				s, err := NewKeyExchange(uri, RoleServer)
				require.NoError(t, err)
				calgo, err := c.Symmetric(s.Nonce())
				require.NoError(t, err)
				salgo, err := s.Symmetric(c.Nonce())
				require.NoError(t, err)
				require.Equal(t, calgo.AEAD(), salgo.AEAD())
			}
		})
	}
}
