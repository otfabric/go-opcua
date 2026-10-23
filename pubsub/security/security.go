// SPDX-License-Identifier: MIT

// Package security implements the message security of OPC UA PubSub
// (Part 14 §5.4.3, §7.2.2.2.6): the symmetric security policies
// PubSub-Aes128-CTR and PubSub-Aes256-CTR, the keys of SecurityGroups and
// their rotation, and the Security Key Service (SKS) that distributes them
// (GetSecurityKeys, Part 14 §8.3.2).
package security

import "errors"

// Security policy URIs.
const (
	PolicyURIAes128CTR = "http://opcfoundation.org/UA/SecurityPolicy#PubSub-Aes128-CTR"
	PolicyURIAes256CTR = "http://opcfoundation.org/UA/SecurityPolicy#PubSub-Aes256-CTR"
)

// ErrNoKeys is returned when no key is available for a security token.
var ErrNoKeys = errors.New("pubsub/security: no keys for this security token")

// Keys is one generation of the symmetric keys of a SecurityGroup: the
// signing key, the encrypting key and the key nonce derived from one key of
// the SKS (Part 14 §8.3.2), identified by its security token id.
type Keys struct {
	TokenID       uint32
	SigningKey    []byte
	EncryptingKey []byte
	KeyNonce      []byte
}

// Policy is a PubSub security policy: symmetric signing and encryption of
// NetworkMessages with Keys.
type Policy interface {
	// URI is the SecurityPolicyUri.
	URI() string
	// KeyLength is the length of a key as distributed by an SKS:
	// SigningKeyLength + EncryptingKeyLength + KeyNonceLength.
	KeyLength() int
	SigningKeyLength() int
	EncryptingKeyLength() int
	KeyNonceLength() int
	// MessageNonceLength is the length of the MessageNonce of the security
	// header.
	MessageNonceLength() int
	// SignatureLength is the length of the message signature.
	SignatureLength() int

	// SplitKey splits a key from an SKS into signing key, encrypting key
	// and key nonce.
	SplitKey(tokenID uint32, key []byte) (*Keys, error)
	// NewMessageNonce returns a fresh MessageNonce; sequence is the
	// sender's message counter that keeps nonces unique per key.
	NewMessageNonce(sequence uint32) ([]byte, error)

	Sign(k *Keys, data []byte) ([]byte, error)
	Verify(k *Keys, data, signature []byte) error
	// Encrypt and Decrypt transform data in place (AES-CTR keeps the
	// length) with the keys and the MessageNonce of the message.
	Encrypt(k *Keys, messageNonce, data []byte) error
	Decrypt(k *Keys, messageNonce, data []byte) error
}

// KeySource supplies the keys of one SecurityGroup to the message codecs.
type KeySource interface {
	// Policy is the security policy of the SecurityGroup.
	Policy() Policy
	// CurrentKeys are the keys to secure outgoing messages with.
	CurrentKeys() (*Keys, error)
	// KeysForToken returns the keys of a received message's token; it
	// returns ErrNoKeys if the token is unknown or expired.
	KeysForToken(tokenID uint32) (*Keys, error)
}
