// SPDX-License-Identifier: MIT

package security

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// TestOpen62541DecryptionVector checks the policy against the encrypted
// NetworkMessage of open62541 v1.5.9 tests/pubsub/check_pubsub_decryption.c
// (MSG_HEADER, MSG_PAYLOAD_ENC, MSG_PAYLOAD_DEC, MSG_SIG, MSG_SIG_INVALID):
// all keys zero, PubSub-Aes128-CTR, token id 1, MessageNonce
// b02d012e01000000 (four random bytes and the little endian sequence 1).
// The signature covers the header and the encrypted payload.
func TestOpen62541DecryptionVector(t *testing.T) {
	const (
		header      = "f111ba08016400014df4030100000008b02d012e01000000"
		encrypted   = "1c26767c41d1b02e506daece57546ce9c958279e1b6be3e28c0f775648"
		decrypted   = "e1101054c2949f3ad701b4205f69841e5f6901000d7657c2949F3ad701"
		signature   = "31eb5d01b947a70cee7f82d4c77924811b06e7e1c93d1e7f03dd2125fc48fc5a"
		badSig      = "5e08a9ff14b83ea2247792eeffc757c85ac99c0ffa79e4fbe5629783dc77b403"
		nonceHex    = "b02d012e01000000"
		tokenID     = 1
		keyMaterial = 32 + 16 + 4
	)
	p := Aes128CTR()
	k, err := p.SplitKey(tokenID, make([]byte, keyMaterial))
	require.NoError(t, err)

	nonce := unhex(t, nonceHex)
	require.Equal(t, nonce, unhex(t, header)[len(header)/2-8:], "nonce is the end of the security header")

	signed := append(unhex(t, header), unhex(t, encrypted)...)
	require.NoError(t, p.Verify(k, signed, unhex(t, signature)))
	require.ErrorIs(t, p.Verify(k, signed, unhex(t, badSig)), ErrSignature)
	sig, err := p.Sign(k, signed)
	require.NoError(t, err)
	require.Equal(t, unhex(t, signature), sig)

	data := unhex(t, encrypted)
	require.NoError(t, p.Decrypt(k, nonce, data))
	require.Equal(t, unhex(t, decrypted), data)
	require.NoError(t, p.Encrypt(k, nonce, data))
	require.Equal(t, unhex(t, encrypted), data)
}

// TestCounterBlockLayout checks the AES-CTR counter block against a
// reference built by hand: KeyNonce | MessageNonce | 00000001, incremented
// per block (open62541 encrypt_pubsub_aes128ctr).
func TestCounterBlockLayout(t *testing.T) {
	for _, p := range []Policy{Aes128CTR(), Aes256CTR()} {
		t.Run(p.URI(), func(t *testing.T) {
			key := make([]byte, p.KeyLength())
			for i := range key {
				key[i] = byte(i + 1)
			}
			k, err := p.SplitKey(7, key)
			require.NoError(t, err)
			nonce := []byte{9, 8, 7, 6, 5, 4, 3, 2}

			plain := make([]byte, 3*aes.BlockSize+5)
			got := bytes.Clone(plain)
			require.NoError(t, p.Encrypt(k, nonce, got))

			block, err := aes.NewCipher(k.EncryptingKey)
			require.NoError(t, err)
			want := make([]byte, 0, len(plain))
			for ctr := byte(1); len(want) < len(plain); ctr++ {
				cb := append(append(bytes.Clone(k.KeyNonce), nonce...), 0, 0, 0, ctr)
				ks := make([]byte, aes.BlockSize)
				block.Encrypt(ks, cb)
				want = append(want, ks...)
			}
			require.Equal(t, want[:len(plain)], got)
		})
	}
}

// TestSplitKeyOrder checks SigningKey | EncryptingKey | KeyNonce, the order
// of open62541 splitCurrentKeyMaterial, and the key lengths.
func TestSplitKeyOrder(t *testing.T) {
	cases := []struct {
		p                       Policy
		uri                     string
		total, sign, enc, nonce int
	}{
		{Aes128CTR(), PolicyURIAes128CTR, 52, 32, 16, 4},
		{Aes256CTR(), PolicyURIAes256CTR, 68, 32, 32, 4},
	}
	for _, c := range cases {
		t.Run(c.uri, func(t *testing.T) {
			p, err := PolicyByURI(c.uri)
			require.NoError(t, err)
			require.Same(t, c.p, p)
			require.Equal(t, c.uri, p.URI())
			require.Equal(t, c.total, p.KeyLength())
			require.Equal(t, c.sign, p.SigningKeyLength())
			require.Equal(t, c.enc, p.EncryptingKeyLength())
			require.Equal(t, c.nonce, p.KeyNonceLength())
			require.Equal(t, 8, p.MessageNonceLength())
			require.Equal(t, 32, p.SignatureLength())
			require.Equal(t, c.uri, p.(interface{ String() string }).String())

			key := make([]byte, c.total)
			for i := range key {
				key[i] = byte(i)
			}
			k, err := p.SplitKey(42, key)
			require.NoError(t, err)
			require.Equal(t, uint32(42), k.TokenID)
			require.Equal(t, key[:c.sign], k.SigningKey)
			require.Equal(t, key[c.sign:c.sign+c.enc], k.EncryptingKey)
			require.Equal(t, key[c.sign+c.enc:], k.KeyNonce)
			require.Equal(t, key, k.raw())
			key[0] = 0xFF
			require.Equal(t, byte(0), k.SigningKey[0], "SplitKey copies")

			_, err = p.SplitKey(1, key[:c.total-1])
			require.ErrorIs(t, err, ErrInvalidKey)
			require.Equal(t, ua.StatusBadSecurityChecksFailed, StatusCode(err))
		})
	}
	_, err := PolicyByURI("http://opcfoundation.org/UA/SecurityPolicy#None")
	require.ErrorIs(t, err, ErrUnknownPolicy)
	require.Equal(t, ua.StatusBadSecurityPolicyRejected, StatusCode(err))
}

func TestRoundTripAndTamper(t *testing.T) {
	for _, p := range []Policy{Aes128CTR(), Aes256CTR()} {
		t.Run(p.URI(), func(t *testing.T) {
			raw, err := GenerateKey(p, nil)
			require.NoError(t, err)
			require.Len(t, raw, p.KeyLength())
			k, err := p.SplitKey(3, raw)
			require.NoError(t, err)

			nonce, err := p.NewMessageNonce(0x01020304)
			require.NoError(t, err)
			require.Len(t, nonce, 8)
			require.Equal(t, []byte{4, 3, 2, 1}, nonce[4:], "sequence is little endian")

			msg := []byte("PubSub network message payload bytes")
			data := bytes.Clone(msg)
			require.NoError(t, p.Encrypt(k, nonce, data))
			require.NotEqual(t, msg, data)
			require.Len(t, data, len(msg))
			sig, err := p.Sign(k, data)
			require.NoError(t, err)
			require.NoError(t, p.Verify(k, data, sig))

			tampered := bytes.Clone(data)
			tampered[3] ^= 1
			require.ErrorIs(t, p.Verify(k, tampered, sig), ErrSignature)
			require.ErrorIs(t, p.Verify(k, data, sig[:31]), ErrSignature)
			require.Equal(t, ua.StatusBadSecurityChecksFailed, StatusCode(p.Verify(k, data, nil)))

			require.NoError(t, p.Decrypt(k, nonce, data))
			require.Equal(t, msg, data)

			// Wrong nonce or key gives garbage, not the plaintext.
			other := bytes.Clone(data)
			require.NoError(t, p.Encrypt(k, nonce, other))
			nonce[0] ^= 1
			require.NoError(t, p.Decrypt(k, nonce, other))
			require.NotEqual(t, msg, other)
		})
	}
}

func TestPolicyErrors(t *testing.T) {
	p := Aes128CTR()
	k, err := p.SplitKey(1, make([]byte, p.KeyLength()))
	require.NoError(t, err)

	require.ErrorIs(t, p.Encrypt(k, []byte{1, 2, 3}, nil), ErrInvalidNonce)
	_, err = p.Sign(nil, nil)
	require.ErrorIs(t, err, ErrNoKeys)
	require.ErrorIs(t, p.Verify(nil, nil, nil), ErrNoKeys)
	require.ErrorIs(t, p.Encrypt(nil, make([]byte, 8), nil), ErrNoKeys)

	// Keys of the other policy are rejected.
	k256, err := Aes256CTR().SplitKey(1, make([]byte, 68))
	require.NoError(t, err)
	require.ErrorIs(t, p.Encrypt(k256, make([]byte, 8), nil), ErrInvalidKey)
	_, err = p.Sign(k256, nil)
	require.ErrorIs(t, err, ErrInvalidKey)

	failing := errReader{}
	_, err = GenerateKey(p, failing)
	require.Error(t, err)
	old := nonceReader
	nonceReader = failing
	t.Cleanup(func() { nonceReader = old })
	_, err = p.NewMessageNonce(1)
	require.Error(t, err)
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }
