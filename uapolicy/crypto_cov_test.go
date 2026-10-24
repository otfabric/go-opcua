// SPDX-License-Identifier: MIT

package uapolicy

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"testing"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// TestAES_KnownAnswer checks CBC against the NIST SP 800-38A vectors
// (F.2.1 AES-128, F.2.5 AES-256, first block) in both directions.
func TestAES_KnownAnswer(t *testing.T) {
	iv := "000102030405060708090a0b0c0d0e0f"
	pt := "6bc1bee22e409f96e93d7e117393172a"
	for _, tc := range []struct {
		name, key, ct string
		bits          int
	}{
		{"AES-128", "2b7e151628aed2a6abf7158809cf4f3c", "7649abac8119b246cee98e9b12e9197d", 128},
		{"AES-256", "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "f58c4c04d6e5f1ba779eabfb5f7bfbd6", 256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &AES{KeyLength: tc.bits, IV: unhex(t, iv), Secret: unhex(t, tc.key)}
			ct, err := a.Encrypt(unhex(t, pt))
			require.NoError(t, err)
			require.Equal(t, tc.ct, hex.EncodeToString(ct))

			got, err := a.Decrypt(ct)
			require.NoError(t, err)
			require.Equal(t, pt, hex.EncodeToString(got))
		})
	}
}

func TestAES_RejectsPartialBlocks(t *testing.T) {
	a := &AES{KeyLength: 128, IV: make([]byte, aes.BlockSize), Secret: make([]byte, 16)}

	_, err := a.Encrypt(make([]byte, aes.BlockSize-1))
	require.ErrorIs(t, err, errors.ErrInvalidPlaintext)
	_, err = a.Encrypt(make([]byte, aes.BlockSize+1))
	require.ErrorIs(t, err, errors.ErrInvalidPlaintext)

	_, err = a.Decrypt(nil)
	require.ErrorIs(t, err, errors.ErrInvalidCiphertext, "shorter than one block")
	_, err = a.Decrypt(make([]byte, aes.BlockSize-1))
	require.ErrorIs(t, err, errors.ErrInvalidCiphertext, "shorter than one block")
	_, err = a.Decrypt(make([]byte, aes.BlockSize+1))
	require.ErrorIs(t, err, errors.ErrInvalidCiphertext, "not whole blocks")
}

// TestAES_KeyAndIVSizes: a key that does not match KeyLength, or an IV that
// is not one block, is an error in both directions instead of a silently
// zero-padded key (Encrypt used to pad, Decrypt did not, so the two did not
// agree) or a panic in crypto/cipher.
func TestAES_KeyAndIVSizes(t *testing.T) {
	iv := make([]byte, aes.BlockSize)
	block := make([]byte, aes.BlockSize)
	for _, tc := range []struct {
		name string
		a    *AES
	}{
		{"short key", &AES{KeyLength: 128, IV: iv, Secret: make([]byte, 10)}},
		{"long key", &AES{KeyLength: 128, IV: iv, Secret: make([]byte, 32)}},
		{"key length bits mismatch", &AES{KeyLength: 256, IV: iv, Secret: make([]byte, 16)}},
		{"short IV", &AES{KeyLength: 128, IV: iv[:8], Secret: make([]byte, 16)}},
		{"long IV", &AES{KeyLength: 128, IV: make([]byte, 32), Secret: make([]byte, 16)}},
		{"no IV", &AES{KeyLength: 128, Secret: make([]byte, 16)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NotPanics(t, func() {
				_, err := tc.a.Encrypt(block)
				require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
				_, err = tc.a.Decrypt(block)
				require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
			})
		})
	}

	// A key length that matches but is no AES key size is reported by
	// crypto/aes.
	a := &AES{KeyLength: 40, IV: iv, Secret: make([]byte, 5)}
	var kse aes.KeySizeError
	_, err := a.Encrypt(block)
	require.ErrorAs(t, err, &kse)
	_, err = a.Decrypt(block)
	require.ErrorAs(t, err, &kse)
}

// TestHMAC_KnownAnswer uses RFC 4231 test case 2.
func TestHMAC_KnownAnswer(t *testing.T) {
	h := &HMAC{Hash: crypto.SHA256, Secret: []byte("Jefe")}
	msg := []byte("what do ya want for nothing?")
	want := "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"

	sig, err := h.Signature(msg)
	require.NoError(t, err)
	require.Equal(t, want, hex.EncodeToString(sig))
	require.NoError(t, h.Verify(msg, sig))

	tampered := bytes.Clone(sig)
	tampered[0] ^= 1
	require.ErrorIs(t, h.Verify(msg, tampered), errors.ErrSignatureValidationFailed)
	require.ErrorIs(t, h.Verify(msg, sig[:len(sig)-1]), errors.ErrSignatureValidationFailed)
	require.ErrorIs(t, h.Verify(append(bytes.Clone(msg), '!'), sig), errors.ErrSignatureValidationFailed)
	require.ErrorIs(t, h.Verify(msg, nil), errors.ErrSignatureValidationFailed)

	other := &HMAC{Hash: crypto.SHA256, Secret: []byte("jefe")}
	require.ErrorIs(t, other.Verify(msg, sig), errors.ErrSignatureValidationFailed, "a different secret")
}

func TestRSAPSS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	msg := []byte("the quick brown fox")

	for _, hash := range []crypto.Hash{crypto.SHA1, crypto.SHA256} {
		t.Run(hash.String(), func(t *testing.T) {
			s := &RSAPSS{Hash: hash, PrivateKey: key, PublicKey: &key.PublicKey}
			sig, err := s.Signature(msg)
			require.NoError(t, err)
			require.Len(t, sig, key.Size())
			require.NoError(t, s.Verify(msg, sig))

			// The salt is random: a second signature differs but verifies.
			sig2, err := s.Signature(msg)
			require.NoError(t, err)
			require.NotEqual(t, sig, sig2)
			require.NoError(t, s.Verify(msg, sig2))

			require.ErrorIs(t, s.Verify([]byte("the quick brown fax"), sig), rsa.ErrVerification)
			tampered := bytes.Clone(sig)
			tampered[len(tampered)-1] ^= 1
			require.ErrorIs(t, s.Verify(msg, tampered), rsa.ErrVerification)

			wrongKey := &RSAPSS{Hash: hash, PublicKey: &other.PublicKey}
			require.ErrorIs(t, wrongKey.Verify(msg, sig), rsa.ErrVerification)
		})
	}

	t.Run("missing keys", func(t *testing.T) {
		_, err := (&RSAPSS{Hash: crypto.SHA256, PublicKey: &key.PublicKey}).Signature(msg)
		require.ErrorIs(t, err, ua.StatusBadSecurityChecksFailed)
		err = (&RSAPSS{Hash: crypto.SHA256, PrivateKey: key}).Verify(msg, make([]byte, key.Size()))
		require.ErrorIs(t, err, ua.StatusBadSecurityChecksFailed)
	})
}
