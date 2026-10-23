// SPDX-License-Identifier: MIT

package uadp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/otfabric/go-opcua/pubsub/security"
)

// testPolicy is PubSub-Aes128-CTR as open62541 implements it
// (plugins/crypto/mbedtls/securitypolicy_pubsub_aes128ctr.c): HMAC-SHA256
// signatures, AES-128 in CTR mode with the counter block
// KeyNonce(4) | MessageNonce(8) | 00 00 00 01, and a MessageNonce of four
// random bytes followed by the UInt32 sequence number (writergroup.c). The
// random part is fixed so that tests are reproducible.
type testPolicy struct {
	nonceRandom [4]byte
}

func (testPolicy) URI() string              { return security.PolicyURIAes128CTR }
func (testPolicy) KeyLength() int           { return 32 + 16 + 4 }
func (testPolicy) SigningKeyLength() int    { return 32 }
func (testPolicy) EncryptingKeyLength() int { return 16 }
func (testPolicy) KeyNonceLength() int      { return 4 }
func (testPolicy) MessageNonceLength() int  { return 8 }
func (testPolicy) SignatureLength() int     { return sha256.Size }

func (p testPolicy) SplitKey(tokenID uint32, key []byte) (*security.Keys, error) {
	if len(key) != p.KeyLength() {
		return nil, errors.New("bad key length")
	}
	return &security.Keys{TokenID: tokenID, SigningKey: key[:32], EncryptingKey: key[32:48], KeyNonce: key[48:]}, nil
}

func (p testPolicy) NewMessageNonce(sequence uint32) ([]byte, error) {
	n := make([]byte, 8)
	copy(n, p.nonceRandom[:])
	binary.LittleEndian.PutUint32(n[4:], sequence)
	return n, nil
}

func (testPolicy) Sign(k *security.Keys, data []byte) ([]byte, error) {
	m := hmac.New(sha256.New, k.SigningKey)
	m.Write(data)
	return m.Sum(nil), nil
}

func (p testPolicy) Verify(k *security.Keys, data, signature []byte) error {
	sig, _ := p.Sign(k, data)
	if !hmac.Equal(sig, signature) {
		return errors.New("signature mismatch")
	}
	return nil
}

func (testPolicy) Encrypt(k *security.Keys, nonce, data []byte) error {
	block, err := aes.NewCipher(k.EncryptingKey)
	if err != nil {
		return err
	}
	if len(nonce) != 8 || len(k.KeyNonce) != 4 {
		return errors.New("bad nonce")
	}
	iv := make([]byte, aes.BlockSize)
	copy(iv, k.KeyNonce)
	copy(iv[4:], nonce)
	iv[15] = 1 // the block counter starts at 1 (Part 14)
	cipher.NewCTR(block, iv).XORKeyStream(data, data)
	return nil
}

func (p testPolicy) Decrypt(k *security.Keys, nonce, data []byte) error {
	return p.Encrypt(k, nonce, data)
}

// testKeys is a KeySource with one set of keys.
type testKeys struct {
	policy security.Policy
	keys   *security.Keys
	err    error // returned by CurrentKeys
}

func (s *testKeys) Policy() security.Policy { return s.policy }

func (s *testKeys) CurrentKeys() (*security.Keys, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.keys, nil
}

func (s *testKeys) KeysForToken(id uint32) (*security.Keys, error) {
	if s.keys == nil || id != s.keys.TokenID {
		return nil, security.ErrNoKeys
	}
	return s.keys, nil
}

// zeroKeys are the keys of open62541's check_pubsub_decryption.c: all zero,
// token 1.
func zeroKeys(p security.Policy) *testKeys {
	return &testKeys{policy: p, keys: &security.Keys{
		TokenID:       1,
		SigningKey:    make([]byte, 32),
		EncryptingKey: make([]byte, 16),
		KeyNonce:      make([]byte, 4),
	}}
}
