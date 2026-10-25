// SPDX-License-Identifier: MIT

package uapolicy

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	"github.com/ProtonMail/go-crypto/brainpool"
	"github.com/cloudflare/circl/sign/ed448"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
)

// ECC security policies (OPC UA 1.05, Part 6 §6.8 and Part 7).
//
// An ECC policy differs from an RSA policy in three ways:
//
//   - Asymmetric messages (OpenSecureChannel) are signed but not encrypted:
//     elliptic curve keys cannot encrypt.
//   - The nonces exchanged in OpenSecureChannel are ephemeral public keys.
//     Both sides run a Diffie-Hellman key agreement and feed the shared
//     secret to HKDF to derive the symmetric keys. Every (re)negotiation uses
//     fresh ephemeral keys, which gives the channel forward secrecy.
//   - Secrets in user identity tokens are protected with an EccEncryptedSecret
//     (see ecc_secret.go) instead of asymmetric encryption.
//
// A policy is one eccPolicy value built from three primitives: a signature
// suite for the application instance keys, a key agreement for the ephemeral
// keys and a symmetric suite. Adding a policy means adding a table entry in
// eccPolicies; adding a curve the Go standard library does not provide means
// implementing eccSignatureSuite and eccKeyAgreement for it.
//
// The symmetric suite is either HMAC plus AES-CBC (ECC_nistP256, ECC_nistP384,
// ECC_brainpoolP256r1, ECC_brainpoolP384r1) or an AEAD cipher (the policies of OPC UA 1.05.07, see ecc_aead.go).

// eccSignatureSuite creates the asymmetric signature algorithm of an ECC
// policy for a pair of application instance keys.
type eccSignatureSuite interface {
	// signer returns the algorithm that signs with key and the size of the
	// signatures it creates.
	signer(key crypto.PrivateKey) (interface{ Signature([]byte) ([]byte, error) }, int, error)
	// verifier returns the algorithm that verifies signatures made with key
	// and the size of those signatures.
	verifier(key crypto.PublicKey) (interface{ Verify([]byte, []byte) error }, int, error)
	// describe names the keys the suite accepts, for error messages.
	describe() string
}

// eccEphemeralPrivateKey is the private half of an ephemeral key pair.
type eccEphemeralPrivateKey interface {
	// publicKey returns the public key in the OPC UA encoding of the curve
	// (Part 6 §6.8.1): x || y, both zero padded, for NIST curves.
	publicKey() []byte
	// sharedSecret runs the key agreement with the remote public key, which
	// it validates. The result is the IKM of the key derivation.
	sharedSecret(remotePublicKey []byte) ([]byte, error)
}

// eccKeyAgreement creates ephemeral keys.
type eccKeyAgreement interface {
	generate() (eccEphemeralPrivateKey, error)
	// publicKeyLength is the SecureChannelNonceLength of the policy.
	publicKeyLength() int
}

// eccPolicy holds the parameters of one ECC security policy.
type eccPolicy struct {
	uri       string
	signature eccSignatureSuite
	agreement eccKeyAgreement

	// hash is used by the key derivation (HKDF).
	hash crypto.Hash

	// symmetric secures the messages of an open channel and the secrets of
	// user identity tokens with the derived keys.
	symmetric eccSymmetricSuite

	// enhancements is the SecureChannelEnhancements property of OPC UA
	// 1.05.07: the first OpenSecureChannel exchange yields a
	// ChannelThumbprint, renewals chain their key material to the previous
	// keys and the session signatures are bound to the channel.
	enhancements bool
}

// eccSymmetricSuite is the symmetric half of an ECC policy.
type eccSymmetricSuite interface {
	// Lengths in bytes of the keys one side of a channel sends with. They
	// are derived in this order: signing key, encrypting key, IV.
	signingKeyLength() int
	encryptingKeyLength() int
	ivLength() int

	// channel returns the algorithm that secures the messages of a
	// SecurityToken: sent with the local keys, received with the remote ones.
	channel(local, remote *derivedKeys) (*EncryptionAlgorithm, error)

	// sealSecret encrypts the padded payload of an EccEncryptedSecret and
	// openSecret reverses it. header is everything that precedes the payload;
	// an authenticated suite binds the ciphertext to it.
	sealSecret(key, iv, header, payload []byte) ([]byte, error)
	openSecret(key, iv, header, sealed []byte) ([]byte, error)
	// secretOverhead is by how many bytes sealSecret extends the payload.
	secretOverhead() int
}

var eccPolicies = map[string]*eccPolicy{
	ua.SecurityPolicyURIECCNistP256: {
		uri: ua.SecurityPolicyURIECCNistP256,
		// CertificateKeyAlgorithm: nistP256; nistP384 may be used as well.
		signature: ecdsaSuite{hash: crypto.SHA256, curves: []elliptic.Curve{elliptic.P256(), elliptic.P384()}},
		agreement: nistAgreement{curve: ecdh.P256()},
		hash:      crypto.SHA256,
		symmetric: cbcHMACSuite{
			hash:          crypto.SHA256,
			keyLength:     16, // AES128-CBC
			signatureURI:  "http://www.w3.org/2000/09/xmldsig#hmac-sha256",
			encryptionURI: "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
		},
	},
	ua.SecurityPolicyURIECCNistP384: {
		uri:       ua.SecurityPolicyURIECCNistP384,
		signature: ecdsaSuite{hash: crypto.SHA384, curves: []elliptic.Curve{elliptic.P384()}},
		agreement: nistAgreement{curve: ecdh.P384()},
		hash:      crypto.SHA384,
		symmetric: cbcHMACSuite{
			hash:          crypto.SHA384,
			keyLength:     32, // AES256-CBC
			signatureURI:  "http://www.w3.org/2000/09/xmldsig#hmac-sha384",
			encryptionURI: "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
		},
	},

	// The policies of OPC UA 1.05.07 with authenticated encryption.
	ua.SecurityPolicyURIECCNistP256AesGcm: {
		uri:          ua.SecurityPolicyURIECCNistP256AesGcm,
		signature:    ecdsaSuite{hash: crypto.SHA256, curves: []elliptic.Curve{elliptic.P256(), elliptic.P384()}},
		agreement:    nistAgreement{curve: ecdh.P256()},
		hash:         crypto.SHA256,
		symmetric:    aeadSuite{cipher: aes128GCM, keyLength: 16, uri: "http://opcfoundation.org/UA/security/aes128-gcm"},
		enhancements: true,
	},
	ua.SecurityPolicyURIECCNistP256ChaChaPoly: {
		uri:          ua.SecurityPolicyURIECCNistP256ChaChaPoly,
		signature:    ecdsaSuite{hash: crypto.SHA256, curves: []elliptic.Curve{elliptic.P256(), elliptic.P384()}},
		agreement:    nistAgreement{curve: ecdh.P256()},
		hash:         crypto.SHA256,
		symmetric:    aeadSuite{cipher: chacha20poly1305.New, keyLength: chacha20poly1305.KeySize, uri: "http://opcfoundation.org/UA/security/chacha20-poly1305"},
		enhancements: true,
	},
	ua.SecurityPolicyURIECCCurve25519: {
		uri:       ua.SecurityPolicyURIECCCurve25519,
		signature: ed25519Suite{},
		agreement: x25519Agreement{},
		hash:      crypto.SHA256,
		// open62541 v1.5.9 derives a separate key for the tags of Sign-only
		// channels of this policy, and does not apply the
		// SecureChannelEnhancements to it. See docs/security.md.
		symmetric: aeadSuite{cipher: chacha20poly1305.New, keyLength: chacha20poly1305.KeySize, signKeyLength: chacha20poly1305.KeySize, uri: "http://opcfoundation.org/UA/security/chacha20-poly1305"},
	},

	// The Brainpool policies mirror ECC_nistP256 and ECC_nistP384 with the
	// curves of RFC 5639: the same hashes, key derivation, nonce layout
	// (x || y) and symmetric suites.
	ua.SecurityPolicyURIECCBrainpoolP256r1: {
		uri: ua.SecurityPolicyURIECCBrainpoolP256r1,
		// CertificateKeyAlgorithm: brainpoolP256r1; brainpoolP384r1 may be
		// used as well, as nistP384 with ECC_nistP256.
		signature: ecdsaSuite{hash: crypto.SHA256, curves: []elliptic.Curve{brainpool.P256r1(), brainpool.P384r1()}},
		agreement: brainpoolAgreement{curve: brainpool.P256r1()},
		hash:      crypto.SHA256,
		symmetric: cbcHMACSuite{
			hash:          crypto.SHA256,
			keyLength:     16, // AES128-CBC
			signatureURI:  "http://www.w3.org/2000/09/xmldsig#hmac-sha256",
			encryptionURI: "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
		},
	},
	ua.SecurityPolicyURIECCBrainpoolP384r1: {
		uri:       ua.SecurityPolicyURIECCBrainpoolP384r1,
		signature: ecdsaSuite{hash: crypto.SHA384, curves: []elliptic.Curve{brainpool.P384r1()}},
		agreement: brainpoolAgreement{curve: brainpool.P384r1()},
		hash:      crypto.SHA384,
		symmetric: cbcHMACSuite{
			hash:          crypto.SHA384,
			keyLength:     32, // AES256-CBC
			signatureURI:  "http://www.w3.org/2000/09/xmldsig#hmac-sha384",
			encryptionURI: "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
		},
	},
	// ECC_curve448 is ECC_curve25519 with Ed448 and X448: 56 byte nonces,
	// 114 byte signatures. Key derivation with HKDF-SHA256 and the symmetric
	// suite (ChaCha20-Poly1305 with a separate key for the tags of Sign-only
	// channels, no SecureChannelEnhancements) are those of ECC_curve25519 in
	// open62541 v1.5.9, the reference implementation.
	ua.SecurityPolicyURIECCCurve448: {
		uri:       ua.SecurityPolicyURIECCCurve448,
		signature: ed448Suite{},
		agreement: x448Agreement{},
		hash:      crypto.SHA256,
		symmetric: aeadSuite{cipher: chacha20poly1305.New, keyLength: chacha20poly1305.KeySize, signKeyLength: chacha20poly1305.KeySize, uri: "http://opcfoundation.org/UA/security/chacha20-poly1305"},
	},
}

// IsECC reports whether uri names a supported ECC security policy.
func IsECC(uri string) bool {
	_, ok := eccPolicies[uri]
	return ok
}

// IsAEAD reports whether uri names a supported security policy that secures
// its messages with authenticated encryption (AES-GCM or ChaCha20-Poly1305).
func IsAEAD(uri string) bool {
	p, ok := eccPolicies[uri]
	if !ok {
		return false
	}
	_, aead := p.symmetric.(aeadSuite)
	return aead
}

// SecureChannelEnhancements reports whether SecureChannels of the security
// policy use the enhancements of OPC UA 1.05.07 (Part 6 §6.7.5 and §6.8.1,
// Part 4 §6.1.8):
//
//   - the signature of the first OpenSecureChannel response also covers the
//     signature of the request and becomes the ChannelThumbprint;
//   - a renewal derives its keys from the new shared secret combined with the
//     key material of all earlier exchanges;
//   - the signatures of CreateSession and ActivateSession cover the
//     ChannelThumbprint, which binds a Session to its SecureChannel.
func SecureChannelEnhancements(uri string) bool {
	p, ok := eccPolicies[uri]
	return ok && p.enhancements
}

// LegacySequenceNumbers reports whether SecureChannels of the security policy
// use the original sequence number rules of Part 6 §6.7.2.4: start anywhere
// below 1024 and wrap before UInt32.MaxValue-1024. ECC policies do not: their
// sequence numbers start at 0 and wrap to 0 after UInt32.MaxValue.
func LegacySequenceNumbers(uri string) bool {
	return !IsECC(uri)
}

// ecdsaSuite is ECDSA with application keys on one of the given curves.
type ecdsaSuite struct {
	hash   crypto.Hash
	curves []elliptic.Curve
}

func (s ecdsaSuite) describe() string {
	names := ""
	for i, c := range s.curves {
		if i > 0 {
			names += " or "
		}
		names += c.Params().Name
	}
	return "an ECDSA " + names + " key"
}

func (s ecdsaSuite) allowed(pub *ecdsa.PublicKey) bool {
	if pub == nil || pub.Curve == nil {
		return false
	}
	for _, c := range s.curves {
		if c == pub.Curve {
			return true
		}
	}
	return false
}

func (s ecdsaSuite) signer(key crypto.PrivateKey) (interface{ Signature([]byte) ([]byte, error) }, int, error) {
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, 0, fmt.Errorf("%w: need %s, got %T", errors.ErrInvalidSecurityConfig, s.describe(), key)
	}
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok || !s.allowed(pub) {
		return nil, 0, fmt.Errorf("%w: need %s, got %s", errors.ErrInvalidSecurityConfig, s.describe(), describeKey(signer.Public()))
	}
	return &ECDSA{Hash: s.hash, PrivateKey: signer}, ecdsaSignatureSize(pub.Curve), nil
}

func (s ecdsaSuite) verifier(key crypto.PublicKey) (interface{ Verify([]byte, []byte) error }, int, error) {
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok || !s.allowed(pub) {
		return nil, 0, fmt.Errorf("%w: need %s, got %s", errors.ErrInvalidSecurityConfig, s.describe(), describeKey(key))
	}
	return &ECDSA{Hash: s.hash, PublicKey: pub}, ecdsaSignatureSize(pub.Curve), nil
}

// describeKey names a public key for error messages.
func describeKey(key crypto.PublicKey) string {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		if k != nil && k.Curve != nil {
			return "an ECDSA " + k.Curve.Params().Name + " key"
		}
	case *rsa.PublicKey:
		return "an RSA key"
	case ed25519.PublicKey:
		return "an Ed25519 key"
	case ed448.PublicKey:
		return "an Ed448 key"
	}
	return fmt.Sprintf("a key of type %T", key)
}

// nistAgreement is ECDH on a NIST curve (RFC 8422).
type nistAgreement struct {
	curve ecdh.Curve
}

func (a nistAgreement) publicKeyLength() int {
	switch a.curve {
	case ecdh.P256():
		return 64
	case ecdh.P384():
		return 96
	default:
		return 0
	}
}

func (a nistAgreement) generate() (eccEphemeralPrivateKey, error) {
	key, err := a.curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return nistEphemeralKey{key: key}, nil
}

type nistEphemeralKey struct {
	key *ecdh.PrivateKey
}

// publicKey returns x || y. The standard library produces the uncompressed
// SEC 1 encoding 0x04 || x || y; OPC UA omits the format byte.
func (k nistEphemeralKey) publicKey() []byte {
	return k.key.PublicKey().Bytes()[1:]
}

func (k nistEphemeralKey) sharedSecret(remote []byte) ([]byte, error) {
	point := make([]byte, 0, 1+len(remote))
	point = append(point, 0x04)
	point = append(point, remote...)
	// NewPublicKey checks the length, that the coordinates are in range and
	// that the point is on the curve (and not the point at infinity).
	pub, err := k.key.Curve().NewPublicKey(point)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid ephemeral public key", errors.ErrInvalidSecurityConfig)
	}
	// The x-coordinate as a zero padded big-endian octet string.
	return k.key.ECDH(pub)
}

// EphemeralKey is a single-use key pair for the key agreement of an ECC
// security policy.
type EphemeralKey struct {
	policy *eccPolicy
	key    eccEphemeralPrivateKey
	public []byte
}

// NewEphemeralKey generates an ephemeral key pair for the ECC security policy.
func NewEphemeralKey(uri string) (*EphemeralKey, error) {
	p, ok := eccPolicies[uri]
	if !ok {
		return nil, fmt.Errorf("%w: %s is not an ECC policy", errors.ErrUnsupportedSecurityPolicy, uri)
	}
	key, err := p.agreement.generate()
	if err != nil {
		return nil, err
	}
	return &EphemeralKey{policy: p, key: key, public: key.publicKey()}, nil
}

// PolicyURI returns the security policy the key was generated for.
func (k *EphemeralKey) PolicyURI() string {
	return k.policy.uri
}

// PublicKey returns the public key in the encoding OPC UA puts on the wire:
// the SecureChannel nonce and the EphemeralKeyType.PublicKey.
func (k *EphemeralKey) PublicKey() []byte {
	return append([]byte(nil), k.public...)
}

// deriveKeys runs the key derivation of Part 6 §6.8.1:
//
//	Salt = L | UTF8(label) | first | second
//	OKM  = HKDF(IKM = shared secret, Salt, Info = Salt, L)
//
// L is the number of bytes to derive, encoded as a little-endian UInt16.
func (p *eccPolicy) deriveKeys(secret []byte, label string, first, second []byte, length int) ([]byte, error) {
	salt := make([]byte, 2, 2+len(label)+len(first)+len(second))
	binary.LittleEndian.PutUint16(salt, uint16(length))
	salt = append(salt, label...)
	salt = append(salt, first...)
	salt = append(salt, second...)
	return hkdf.Key(p.hash.New, secret, salt, string(salt), length)
}

const (
	eccLabelClient = "opcua-client"
	eccLabelServer = "opcua-server"
	eccLabelSecret = "opcua-secret"
)

// channelKeys derives the keys one side of a SecureChannel sends with.
// nonce is the ephemeral public key of that side, peerNonce the other one.
func (p *eccPolicy) channelKeys(secret []byte, label string, nonce, peerNonce []byte) (*derivedKeys, error) {
	// L always covers all three keys, also on a Sign-only channel that uses
	// the signing key alone. That is what open62541 v1.5.9 does and what
	// interoperates with it. OPC UA 1.05.07 (Part 6 §6.8.1) sets the
	// encrypting key and IV lengths to zero in L for Sign-only channels of
	// policies without authenticated encryption; since L is part of the salt,
	// a peer following that rule ends up with other signing keys in Sign
	// mode. SignAndEncrypt is the same under both readings.
	//
	// The policies with authenticated encryption have no signing key: the
	// tag is made with the encrypting key. (ECC_curve25519 is the exception,
	// see its table entry.)
	sig, enc, iv := p.symmetric.signingKeyLength(), p.symmetric.encryptingKeyLength(), p.symmetric.ivLength()
	okm, err := p.deriveKeys(secret, label, nonce, peerNonce, sig+enc+iv)
	if err != nil {
		return nil, err
	}
	return &derivedKeys{
		signing:    okm[:sig],
		encryption: okm[sig : sig+enc],
		iv:         okm[sig+enc:],
	}, nil
}

// symmetricKeys derives the symmetric algorithm of a SecureChannel from the
// local ephemeral key and the peer's ephemeral public key.
//
// previousIKM is the input keying material the current keys of the channel
// were derived from, or nil for the first OpenSecureChannel exchange. A policy
// with SecureChannelEnhancements combines it with the new shared secret (Part
// 6 §6.8.1): IKM = previousIKM XOR shared secret. The keys of a renewed token
// therefore depend on every exchange since the channel was opened, so that
// someone who joins the conversation later cannot take it over. The IKM used
// is returned and has to be passed to the next renewal; it is nil for policies
// that do not chain.
func (p *eccPolicy) symmetricKeys(local *EphemeralKey, remoteNonce []byte, role Role, previousIKM []byte) (*EncryptionAlgorithm, []byte, error) {
	if local == nil || local.policy != p {
		return nil, nil, fmt.Errorf("%w: ephemeral key does not belong to %s", errors.ErrInvalidSecurityConfig, p.uri)
	}
	secret, err := local.key.sharedSecret(remoteNonce)
	if err != nil {
		return nil, nil, err
	}
	defer clear(secret)

	ikm := secret
	if p.enhancements {
		ikm = append([]byte(nil), secret...)
		if previousIKM != nil {
			if len(previousIKM) != len(secret) {
				return nil, nil, fmt.Errorf("%w: key material of the previous SecurityToken has the wrong length", errors.ErrInvalidSecurityConfig)
			}
			subtle.XORBytes(ikm, secret, previousIKM)
		}
	}

	clientNonce, serverNonce := local.public, remoteNonce
	if role == RoleServer {
		clientNonce, serverNonce = remoteNonce, local.public
	}
	clientKeys, err := p.channelKeys(ikm, eccLabelClient, clientNonce, serverNonce)
	if err != nil {
		return nil, nil, err
	}
	serverKeys, err := p.channelKeys(ikm, eccLabelServer, serverNonce, clientNonce)
	if err != nil {
		return nil, nil, err
	}

	// Messages are secured with the sender's keys.
	localKeys, remoteKeys := clientKeys, serverKeys
	if role == RoleServer {
		localKeys, remoteKeys = serverKeys, clientKeys
	}
	algo, err := p.symmetric.channel(localKeys, remoteKeys)
	if err != nil {
		return nil, nil, err
	}
	if !p.enhancements {
		return algo, nil, nil
	}
	return algo, ikm, nil
}

// cbcHMACSuite is the symmetric suite of ECC_nistP256 and ECC_nistP384:
// HMAC-SHA2 signatures and AES-CBC encryption.
type cbcHMACSuite struct {
	hash          crypto.Hash
	keyLength     int // of the AES key
	signatureURI  string
	encryptionURI string
}

func (s cbcHMACSuite) signingKeyLength() int    { return s.hash.Size() }
func (s cbcHMACSuite) encryptingKeyLength() int { return s.keyLength }
func (s cbcHMACSuite) ivLength() int            { return AESBlockSize }

func (s cbcHMACSuite) channel(local, remote *derivedKeys) (*EncryptionAlgorithm, error) {
	bits := s.keyLength * 8
	return &EncryptionAlgorithm{
		blockSize:             AESBlockSize,
		plainttextBlockSize:   AESBlockSize - AESMinPadding,
		encrypt:               &AES{KeyLength: bits, IV: local.iv, Secret: local.encryption},
		decrypt:               &AES{KeyLength: bits, IV: remote.iv, Secret: remote.encryption},
		signature:             &HMAC{Hash: s.hash, Secret: local.signing},
		verifySignature:       &HMAC{Hash: s.hash, Secret: remote.signing},
		signatureLength:       s.hash.Size(),
		remoteSignatureLength: s.hash.Size(),
		encryptionURI:         s.encryptionURI,
		signatureURI:          s.signatureURI,
	}, nil
}

func (s cbcHMACSuite) sealSecret(key, iv, _, payload []byte) ([]byte, error) {
	return (&AES{KeyLength: s.keyLength * 8, IV: iv, Secret: key}).Encrypt(payload)
}

func (s cbcHMACSuite) secretOverhead() int { return 0 }

func (s cbcHMACSuite) openSecret(key, iv, _, sealed []byte) ([]byte, error) {
	if len(sealed) == 0 || len(sealed)%AESBlockSize != 0 {
		return nil, fmt.Errorf("%w: encrypted secret: payload is not a multiple of the block size", errors.ErrInvalidCiphertext)
	}
	return (&AES{KeyLength: s.keyLength * 8, IV: iv, Secret: key}).Decrypt(sealed)
}

// asymmetric returns the asymmetric algorithm of the policy. It signs with
// localKey and verifies with remoteKey; either may be nil if that direction
// is not needed. There is no asymmetric encryption.
func (p *eccPolicy) asymmetric(localKey crypto.PrivateKey, remoteKey crypto.PublicKey) (*EncryptionAlgorithm, error) {
	algo := &EncryptionAlgorithm{
		// Nothing is encrypted: a block is one byte and there is no padding.
		blockSize:           NoneBlockSize,
		plainttextBlockSize: NoneBlockSize - NoneMinPadding,
		encrypt:             &None{},
		decrypt:             &None{},
		signature:           &ECDSA{}, // refuses to sign
		verifySignature:     &ECDSA{}, // refuses every signature
		nonceLength:         p.agreement.publicKeyLength(),
		signOnly:            true,
		// The SignatureData.Algorithm of the ECC policies is null: the
		// algorithm follows from the SecurityPolicy.
		signatureURI:  "",
		encryptionURI: "",
	}
	if localKey != nil {
		signer, size, err := p.signature.signer(localKey)
		if err != nil {
			return nil, fmt.Errorf("local key for %s: %w", p.uri, err)
		}
		algo.signature = signer
		algo.signatureLength = size
	}
	if remoteKey != nil {
		verifier, size, err := p.signature.verifier(remoteKey)
		if err != nil {
			return nil, fmt.Errorf("remote key for %s: %w", p.uri, err)
		}
		algo.verifySignature = verifier
		algo.remoteSignatureLength = size
	}
	return algo, nil
}
