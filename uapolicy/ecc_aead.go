// SPDX-License-Identifier: MIT

package uapolicy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/otfabric/go-opcua/errors"
)

// Authenticated encryption for the ECC security policies of OPC UA 1.05.07:
// ECC_nistP256_AesGcm, ECC_nistP256_ChaChaPoly and ECC_curve25519.
//
// A symmetric MessageChunk of these policies has no padding and no HMAC
// (Part 6 §6.7.2):
//
//	MessageHeader | SecureChannelId | TokenId     12 + 4 bytes, in the clear
//	SequenceHeader | Body                         encrypted in SignAndEncrypt mode
//	Tag                                           16 bytes
//
// In SignAndEncrypt mode the 16 header bytes are the additional authenticated
// data and everything after them is encrypted. In Sign mode nothing is
// encrypted: the whole chunk is additional authenticated data of an empty
// plaintext, and the tag is all the cipher produces.
//
// # Nonce
//
// Every chunk is sealed with its own nonce (Part 6 §6.8.1): the derived
// InitializationVector with its first eight bytes XORed with
//
//	TokenId | LastSequenceNumber          both UInt32, little endian
//
// LastSequenceNumber is the sequence number of the chunk sent before this one
// in the same direction, whatever its type and SecurityToken: for the first
// chunk after an OpenSecureChannel message it is the number of that message.
// A receiver knows it without decrypting anything, which matters because the
// sequence number of the chunk itself is encrypted.
//
// An AEAD nonce must never repeat under a key. Here that holds because:
//
//   - Each direction of each SecurityToken has its own key and IV (the HKDF
//     salts differ in label and nonce order), so the two peers never share a
//     key, and a renewal changes key, IV and TokenId together.
//   - Under one key the TokenId is constant, so a nonce can only repeat if a
//     LastSequenceNumber does. Sequence numbers of the ECC policies increase
//     by one per chunk and wrap from UInt32.MaxValue to 0, so that takes 2^32
//     chunks under one SecurityToken. chunkAEAD refuses to get there: it seals
//     with strictly increasing distances from the first number it saw and
//     fails once the distance would wrap. A channel that busy has to renew its
//     token first, which the token lifetime forces long before (2^32 chunks
//     in an hour is more than a million chunks per second).
//   - A wrap of the sequence numbers that falls within the life of a token is
//     harmless: the numbers used under the key are still all different.
//
// The secret of a user identity token is sealed with the unmasked IV: its key
// comes from a fresh ephemeral key pair and seals exactly one message.

const (
	aeadNonceSize = 12
	aeadTagSize   = 16

	// aeadMaxChunks is how many chunks may be sealed with one key.
	aeadMaxChunks = 1 << 32
)

// aes128GCM returns AES-128 in Galois/Counter Mode with the standard 12 byte
// nonce and 16 byte tag.
func aes128GCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 16 {
		return nil, aes.KeySizeError(len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// aeadSuite is the symmetric suite of the ECC policies with authenticated
// encryption.
type aeadSuite struct {
	cipher    func(key []byte) (cipher.AEAD, error)
	keyLength int

	// signKeyLength is the length of a separate key for the tags of Sign-only
	// channels. Zero means there is none and the encrypting key makes them.
	signKeyLength int

	uri string
}

func (s aeadSuite) signingKeyLength() int    { return s.signKeyLength }
func (s aeadSuite) encryptingKeyLength() int { return s.keyLength }
func (s aeadSuite) ivLength() int            { return aeadNonceSize }

func (s aeadSuite) newCipher(key []byte) (cipher.AEAD, error) {
	c, err := s.cipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errors.ErrInvalidSecurityConfig, err)
	}
	if c.NonceSize() != aeadNonceSize || c.Overhead() != aeadTagSize {
		return nil, fmt.Errorf("%w: unexpected AEAD parameters", errors.ErrInvalidSecurityConfig)
	}
	return c, nil
}

func (s aeadSuite) channel(local, remote *derivedKeys) (*EncryptionAlgorithm, error) {
	if len(local.iv) != aeadNonceSize || len(remote.iv) != aeadNonceSize {
		return nil, fmt.Errorf("%w: unexpected IV length", errors.ErrInvalidSecurityConfig)
	}
	c := &chunkAEAD{
		localIV:  append([]byte(nil), local.iv...),
		remoteIV: append([]byte(nil), remote.iv...),
	}
	var err error
	if c.seal, err = s.newCipher(local.encryption); err != nil {
		return nil, err
	}
	if c.open, err = s.newCipher(remote.encryption); err != nil {
		return nil, err
	}
	c.sealSign, c.openSign = c.seal, c.open
	if s.signKeyLength > 0 {
		if c.sealSign, err = s.newCipher(local.signing); err != nil {
			return nil, err
		}
		if c.openSign, err = s.newCipher(remote.signing); err != nil {
			return nil, err
		}
	}
	return &EncryptionAlgorithm{
		// No blocks and no padding: a chunk grows by the tag only.
		blockSize:           NoneBlockSize,
		plainttextBlockSize: NoneBlockSize - NoneMinPadding,
		// The chunk code must use SealChunk and OpenChunk. Anything else
		// fails closed.
		encrypt:               aeadOnly{},
		decrypt:               aeadOnly{},
		signature:             aeadOnly{},
		verifySignature:       aeadOnly{},
		signatureLength:       aeadTagSize,
		remoteSignatureLength: aeadTagSize,
		encryptionURI:         s.uri,
		signatureURI:          s.uri,
		aead:                  c,
	}, nil
}

// sealSecret encrypts the payload of an EccEncryptedSecret. The header of the
// secret is the additional authenticated data; the tag follows the
// ciphertext.
func (s aeadSuite) sealSecret(key, iv, header, payload []byte) ([]byte, error) {
	c, err := s.newCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != aeadNonceSize {
		return nil, fmt.Errorf("%w: unexpected IV length", errors.ErrInvalidSecurityConfig)
	}
	return c.Seal(nil, iv, payload, header), nil
}

func (s aeadSuite) openSecret(key, iv, header, sealed []byte) ([]byte, error) {
	// The payload is padded to a multiple of 16 bytes, like the one of the
	// policies with a block cipher.
	if len(sealed) <= aeadTagSize || (len(sealed)-aeadTagSize)%AESBlockSize != 0 {
		return nil, fmt.Errorf("%w: encrypted secret: payload has an invalid length", errors.ErrInvalidCiphertext)
	}
	c, err := s.newCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != aeadNonceSize {
		return nil, fmt.Errorf("%w: unexpected IV length", errors.ErrInvalidSecurityConfig)
	}
	plain, err := c.Open(nil, iv, sealed, header)
	if err != nil {
		return nil, fmt.Errorf("%w: encrypted secret: authentication failed", errors.ErrInvalidCiphertext)
	}
	return plain, nil
}

func (s aeadSuite) secretOverhead() int { return aeadTagSize }

// aeadOnly stands in for the separate encryption and signature algorithms an
// AEAD suite does not have.
type aeadOnly struct{}

var errAEADOnly = fmt.Errorf("%w: the security policy uses authenticated encryption", errors.ErrInvalidSecurityConfig)

func (aeadOnly) Encrypt([]byte) ([]byte, error)   { return nil, errAEADOnly }
func (aeadOnly) Decrypt([]byte) ([]byte, error)   { return nil, errAEADOnly }
func (aeadOnly) Signature([]byte) ([]byte, error) { return nil, errAEADOnly }
func (aeadOnly) Verify([]byte, []byte) error      { return errAEADOnly }

// chunkAEAD seals and opens the symmetric MessageChunks of one SecurityToken.
type chunkAEAD struct {
	// seal and open encrypt; sealSign and openSign make the tags of Sign-only
	// channels (the same ciphers unless the policy derives a signing key).
	seal, open         cipher.AEAD
	sealSign, openSign cipher.AEAD
	localIV, remoteIV  []byte

	// Nonce bookkeeping of the sending side, see the package comment.
	mu       sync.Mutex
	started  bool
	first    uint32 // LastSequenceNumber of the first chunk sealed
	distance uint64 // of the next acceptable LastSequenceNumber from first
}

// chunkNonce masks the IV with the TokenId and the LastSequenceNumber.
func chunkNonce(iv []byte, tokenID, lastSequenceNumber uint32) []byte {
	nonce := make([]byte, aeadNonceSize)
	copy(nonce, iv)
	var mask [8]byte
	binary.LittleEndian.PutUint32(mask[0:], tokenID)
	binary.LittleEndian.PutUint32(mask[4:], lastSequenceNumber)
	for i, m := range mask {
		nonce[i] ^= m
	}
	return nonce
}

// reserve admits lastSequenceNumber for sealing if it cannot have been used
// with the key before.
func (c *chunkAEAD) reserve(lastSequenceNumber uint32) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.started {
		c.started = true
		c.first = lastSequenceNumber
	}
	// The distance from the first number, counted in the direction the
	// sequence numbers run, wraps with them.
	d := uint64(lastSequenceNumber - c.first)
	if d < c.distance || c.distance >= aeadMaxChunks {
		return fmt.Errorf("%w: sequence number would reuse a nonce of the SecurityToken", errors.ErrInvalidState)
	}
	c.distance = d + 1
	return nil
}

// AEAD reports whether the algorithm is an authenticated encryption
// algorithm. Its chunks are secured with SealChunk and OpenChunk; Encrypt,
// Decrypt, Signature and VerifySignature fail.
func (e *EncryptionAlgorithm) AEAD() bool {
	return e != nil && e.aead != nil
}

// SealChunk secures a symmetric MessageChunk of a policy with authenticated
// encryption.
//
// chunk holds the complete chunk without its tag; its MessageSize field must
// already count the tag (SignatureLength bytes), because the header is
// authenticated as it is sent. headerLength is the size of the part that
// stays readable: the message header and the symmetric security header.
// tokenID and lastSequenceNumber make the nonce: the TokenId of the chunk and
// the sequence number of the chunk sent before it. With encrypt the data
// after the header is encrypted (SignAndEncrypt), otherwise the chunk is only
// authenticated (Sign).
//
// The result is a new slice: the header, the (encrypted) data and the tag.
// SealChunk fails rather than use a nonce twice.
func (e *EncryptionAlgorithm) SealChunk(chunk []byte, headerLength int, tokenID, lastSequenceNumber uint32, encrypt bool) ([]byte, error) {
	c := e.aead
	if c == nil {
		return nil, fmt.Errorf("%w: not an AEAD algorithm", errors.ErrInvalidSecurityConfig)
	}
	if headerLength < 0 || headerLength > len(chunk) {
		return nil, errors.ErrInvalidPlaintext
	}
	if err := c.reserve(lastSequenceNumber); err != nil {
		return nil, err
	}
	nonce := chunkNonce(c.localIV, tokenID, lastSequenceNumber)
	out := make([]byte, 0, len(chunk)+aeadTagSize)
	if !encrypt {
		out = append(out, chunk...)
		return c.sealSign.Seal(out, nonce, nil, chunk), nil
	}
	out = append(out, chunk[:headerLength]...)
	return c.seal.Seal(out, nonce, chunk[headerLength:], chunk[:headerLength]), nil
}

// OpenChunk verifies and, if encrypted, decrypts a chunk made by the peer's
// SealChunk. It returns the chunk without its tag: the header followed by the
// plain data. The tag is compared in constant time; a chunk that was modified,
// truncated, replayed or secured with other keys yields ErrInvalidCiphertext
// and no data.
func (e *EncryptionAlgorithm) OpenChunk(chunk []byte, headerLength int, tokenID, lastSequenceNumber uint32, encrypted bool) ([]byte, error) {
	c := e.aead
	if c == nil {
		return nil, fmt.Errorf("%w: not an AEAD algorithm", errors.ErrInvalidSecurityConfig)
	}
	if headerLength < 0 || len(chunk) < headerLength+aeadTagSize {
		return nil, errors.ErrInvalidCiphertext
	}
	nonce := chunkNonce(c.remoteIV, tokenID, lastSequenceNumber)
	if !encrypted {
		signed, tag := chunk[:len(chunk)-aeadTagSize], chunk[len(chunk)-aeadTagSize:]
		if _, err := c.openSign.Open(nil, nonce, tag, signed); err != nil {
			return nil, errors.ErrInvalidCiphertext
		}
		return append([]byte(nil), signed...), nil
	}
	out := make([]byte, 0, len(chunk)-aeadTagSize)
	out = append(out, chunk[:headerLength]...)
	out, err := c.open.Open(out, nonce, chunk[headerLength:], chunk[:headerLength])
	if err != nil {
		return nil, errors.ErrInvalidCiphertext
	}
	return out, nil
}

// x25519Agreement is the key agreement of ECC_curve25519 (RFC 7748).
type x25519Agreement struct{}

func (x25519Agreement) publicKeyLength() int { return 32 }

func (x25519Agreement) generate() (eccEphemeralPrivateKey, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return x25519EphemeralKey{key: key}, nil
}

type x25519EphemeralKey struct {
	key *ecdh.PrivateKey
}

// publicKey returns the 32 byte u-coordinate, the encoding of RFC 7748.
func (k x25519EphemeralKey) publicKey() []byte {
	return k.key.PublicKey().Bytes()
}

func (k x25519EphemeralKey) sharedSecret(remote []byte) ([]byte, error) {
	// NewPublicKey checks the length. ECDH fails if the result is the
	// all-zero value, which is what the points of small order produce: a peer
	// cannot force a shared secret it knows without knowing a private key.
	pub, err := ecdh.X25519().NewPublicKey(remote)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid ephemeral public key", errors.ErrInvalidSecurityConfig)
	}
	secret, err := k.key.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid ephemeral public key", errors.ErrInvalidSecurityConfig)
	}
	return secret, nil
}
