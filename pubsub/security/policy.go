// SPDX-License-Identifier: MIT

package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Lengths of the PubSub-Aes128-CTR and PubSub-Aes256-CTR security policies
// (Part 14 §7.2.2.2.6, Part 7 profiles; open62541
// plugins/crypto/mbedtls/securitypolicy_pubsub_aes{128,256}ctr.c).
const (
	// SigningKeyLength is the length of the HMAC-SHA256 signing key of
	// both policies.
	SigningKeyLength = 32
	// KeyNonceLength is the length of the KeyNonce, the first four bytes
	// of the AES-CTR counter block.
	KeyNonceLength = 4
	// MessageNonceLength is the length of the MessageNonce of the
	// security header: four random bytes followed by a sequence number.
	MessageNonceLength = 8
	// SignatureLength is the length of an HMAC-SHA256 signature.
	SignatureLength = sha256.Size
)

// Errors of the policies.
var (
	// ErrUnknownPolicy is returned by PolicyByURI for an unsupported
	// SecurityPolicyUri.
	ErrUnknownPolicy = errors.New("pubsub/security: unknown security policy")
	// ErrInvalidKey is returned for key material of the wrong length.
	ErrInvalidKey = errors.New("pubsub/security: invalid key length")
	// ErrInvalidNonce is returned for a MessageNonce of the wrong length.
	ErrInvalidNonce = errors.New("pubsub/security: invalid message nonce length")
	// ErrSignature is returned by Verify when the signature does not
	// match (Bad_SecurityChecksFailed).
	ErrSignature = errors.New("pubsub/security: signature verification failed")
)

// ctrPolicy implements PubSub-Aes128-CTR and PubSub-Aes256-CTR: HMAC-SHA256
// signatures and AES in counter mode with the RFC 3686 counter block
// KeyNonce(4) | MessageNonce(8) | BlockCounter(4, big endian, starting at 1).
type ctrPolicy struct {
	uri       string
	encKeyLen int
}

var (
	aes128CTR = &ctrPolicy{uri: PolicyURIAes128CTR, encKeyLen: 16}
	aes256CTR = &ctrPolicy{uri: PolicyURIAes256CTR, encKeyLen: 32}
)

// Aes128CTR returns the PubSub-Aes128-CTR policy: a 32 byte signing key, a
// 16 byte AES-128 key and a 4 byte key nonce (52 byte SKS keys).
func Aes128CTR() Policy { return aes128CTR }

// Aes256CTR returns the PubSub-Aes256-CTR policy: a 32 byte signing key, a
// 32 byte AES-256 key and a 4 byte key nonce (68 byte SKS keys).
func Aes256CTR() Policy { return aes256CTR }

// PolicyByURI returns the policy with the given SecurityPolicyUri.
func PolicyByURI(uri string) (Policy, error) {
	switch uri {
	case PolicyURIAes128CTR:
		return aes128CTR, nil
	case PolicyURIAes256CTR:
		return aes256CTR, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrUnknownPolicy, uri)
}

func (p *ctrPolicy) URI() string              { return p.uri }
func (p *ctrPolicy) SigningKeyLength() int    { return SigningKeyLength }
func (p *ctrPolicy) EncryptingKeyLength() int { return p.encKeyLen }
func (p *ctrPolicy) KeyNonceLength() int      { return KeyNonceLength }
func (p *ctrPolicy) MessageNonceLength() int  { return MessageNonceLength }
func (p *ctrPolicy) SignatureLength() int     { return SignatureLength }
func (p *ctrPolicy) KeyLength() int           { return SigningKeyLength + p.encKeyLen + KeyNonceLength }
func (p *ctrPolicy) String() string           { return p.uri }
func (p *ctrPolicy) checkKeys(k *Keys) error  { return checkKeys(p, k) }

// nonceReader is the randomness of message nonces; tests replace it.
var nonceReader io.Reader = rand.Reader

func orRand(r io.Reader) io.Reader {
	if r == nil {
		return rand.Reader
	}
	return r
}

// SplitKey splits a key of an SKS in the order of Part 14 §8.3.2 (and
// open62541 ua_pubsub_keystorage.c splitCurrentKeyMaterial): SigningKey,
// EncryptingKey, KeyNonce.
func (p *ctrPolicy) SplitKey(tokenID uint32, key []byte) (*Keys, error) {
	if len(key) != p.KeyLength() {
		return nil, fmt.Errorf("%w: got %d bytes, want %d for %s", ErrInvalidKey, len(key), p.KeyLength(), p.uri)
	}
	b := append([]byte(nil), key...)
	enc := SigningKeyLength + p.encKeyLen
	return &Keys{
		TokenID:       tokenID,
		SigningKey:    b[:SigningKeyLength:SigningKeyLength],
		EncryptingKey: b[SigningKeyLength:enc:enc],
		KeyNonce:      b[enc:],
	}, nil
}

// NewMessageNonce returns four random bytes followed by sequence encoded as
// a little endian UInt32, the MessageNonce open62541 builds
// (ua_pubsub_writergroup.c: random(4) | UInt32 nonceSequenceNumber).
func (p *ctrPolicy) NewMessageNonce(sequence uint32) ([]byte, error) {
	n := make([]byte, MessageNonceLength)
	if _, err := io.ReadFull(nonceReader, n[:4]); err != nil {
		return nil, fmt.Errorf("pubsub/security: message nonce: %w", err)
	}
	binary.LittleEndian.PutUint32(n[4:], sequence)
	return n, nil
}

// Sign returns HMAC-SHA256(SigningKey, data).
func (p *ctrPolicy) Sign(k *Keys, data []byte) ([]byte, error) {
	if err := p.checkKeys(k); err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, k.SigningKey)
	m.Write(data)
	return m.Sum(nil), nil
}

// Verify checks an HMAC-SHA256 signature in constant time.
func (p *ctrPolicy) Verify(k *Keys, data, signature []byte) error {
	want, err := p.Sign(k, data)
	if err != nil {
		return err
	}
	if len(signature) != SignatureLength || !hmac.Equal(want, signature) {
		return ErrSignature
	}
	return nil
}

// Encrypt encrypts data in place with AES-CTR. The initial counter block is
// KeyNonce | MessageNonce | 0x00000001; the whole block is incremented as a
// big endian integer per AES block (RFC 3686, open62541
// encrypt_pubsub_aes128ctr).
func (p *ctrPolicy) Encrypt(k *Keys, messageNonce, data []byte) error {
	if err := p.checkKeys(k); err != nil {
		return err
	}
	if len(messageNonce) != MessageNonceLength {
		return fmt.Errorf("%w: got %d bytes, want %d", ErrInvalidNonce, len(messageNonce), MessageNonceLength)
	}
	block, err := aes.NewCipher(k.EncryptingKey)
	if err != nil {
		return fmt.Errorf("pubsub/security: %w", err)
	}
	var iv [aes.BlockSize]byte
	copy(iv[:KeyNonceLength], k.KeyNonce)
	copy(iv[KeyNonceLength:KeyNonceLength+MessageNonceLength], messageNonce)
	iv[aes.BlockSize-1] = 1
	cipher.NewCTR(block, iv[:]).XORKeyStream(data, data)
	return nil
}

// Decrypt is Encrypt: CTR mode is its own inverse.
func (p *ctrPolicy) Decrypt(k *Keys, messageNonce, data []byte) error {
	return p.Encrypt(k, messageNonce, data)
}

// GenerateKey returns a fresh random key of the policy's KeyLength, as an
// SKS hands it out.
func GenerateKey(p Policy, r io.Reader) ([]byte, error) {
	return randomBytes(orRand(r), p.KeyLength())
}

func randomBytes(r io.Reader, n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, fmt.Errorf("pubsub/security: random: %w", err)
	}
	return b, nil
}

func checkKeys(p Policy, k *Keys) error {
	if k == nil {
		return ErrNoKeys
	}
	if len(k.SigningKey) != p.SigningKeyLength() || len(k.EncryptingKey) != p.EncryptingKeyLength() || len(k.KeyNonce) != p.KeyNonceLength() {
		return fmt.Errorf("%w for %s", ErrInvalidKey, p.URI())
	}
	return nil
}
