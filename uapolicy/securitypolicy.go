// SPDX-License-Identifier: MIT

// Package uapolicy implements the encryption, decryption, signing,
// and signature verifying algorithms for Security Policy profiles as
// defined in Part 7 of the OPC-UA specifications (version 1.04, and the ECC
// policies of version 1.05)
package uapolicy

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"reflect"
	"sort"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
)

// SupportedPolicies returns all supported Security Policies
// (and therefore, valid inputs to Asymmetric(...) and Symmetric(...)).
func SupportedPolicies() []string {
	var uris []string
	for k := range policies {
		uris = append(uris, k)
	}
	sort.Strings(uris)
	return uris
}

// IsSupported reports whether the security policy with the given URI is
// implemented.
func IsSupported(uri string) bool {
	_, ok := policies[uri]
	return ok
}

// Asymmetric returns the asymmetric encryption algorithm for the given security policy.
//
// It takes RSA keys and is kept for compatibility; AsymmetricKeys accepts the
// keys of every supported policy, including the ECC ones.
func Asymmetric(uri string, localKey *rsa.PrivateKey, remoteKey *rsa.PublicKey) (*EncryptionAlgorithm, error) {
	var (
		local  crypto.PrivateKey
		remote crypto.PublicKey
	)
	if localKey != nil {
		local = localKey
	}
	if remoteKey != nil {
		remote = remoteKey
	}
	return AsymmetricKeys(uri, local, remote)
}

// AsymmetricKeys returns the asymmetric algorithm for the given security
// policy: the algorithm that secures OpenSecureChannel messages and creates
// and verifies the signatures of CreateSession and ActivateSession.
//
// localKey is the private key of the local application instance (or user)
// certificate and remoteKey the public key of the peer's certificate. Either
// may be nil when only the other direction is needed. The key types must match
// the policy: RSA policies need an *rsa.PrivateKey and an *rsa.PublicKey, the
// ECC policies a crypto.Signer with an *ecdsa.PublicKey on a curve the policy
// permits and an *ecdsa.PublicKey, ECC_curve25519 a crypto.Signer with an
// ed25519.PublicKey and an ed25519.PublicKey, and ECC_curve448 the same with
// ed448.PublicKey (github.com/cloudflare/circl/sign/ed448).
func AsymmetricKeys(uri string, localKey crypto.PrivateKey, remoteKey crypto.PublicKey) (*EncryptionAlgorithm, error) {
	p, ok := policies[uri]
	if !ok {
		return nil, fmt.Errorf("%w: %s", errors.ErrUnsupportedSecurityPolicy, uri)
	}
	if isNilKey(localKey) {
		localKey = nil
	}
	if isNilKey(remoteKey) {
		remoteKey = nil
	}
	return p.asymmetric(localKey, remoteKey)
}

// isNilKey reports whether key is nil or a typed nil pointer, which callers
// holding an unset *rsa.PrivateKey field pass without noticing.
func isNilKey(key any) bool {
	if key == nil {
		return true
	}
	v := reflect.ValueOf(key)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Slice, reflect.Map:
		return v.IsNil()
	default:
		return false
	}
}

// Symmetric returns the symmetric encryption algorithm for the given security policy.
//
// The keys are derived from the two nonces, which is how the RSA policies
// work. The ECC policies derive them from a key agreement instead: use a
// KeyExchange, which handles both families.
func Symmetric(uri string, localNonce, remoteNonce []byte) (*EncryptionAlgorithm, error) {
	p, ok := policies[uri]
	if !ok {
		return nil, fmt.Errorf("%w: %s", errors.ErrUnsupportedSecurityPolicy, uri)
	}
	if p.ecc != nil {
		return nil, fmt.Errorf("%w: %s derives its keys from a key agreement, use a KeyExchange", errors.ErrInvalidSecurityConfig, uri)
	}

	if uri != ua.SecurityPolicyURINone && (localNonce == nil || remoteNonce == nil) {
		return nil, fmt.Errorf("%w: both nonces required", errors.ErrInvalidSecurityConfig)
	}

	return p.symmetric(localNonce, remoteNonce)
}

// Role is the side of a SecureChannel an application is on.
type Role int

const (
	// RoleClient is the side that sends the OpenSecureChannel request.
	RoleClient Role = iota
	// RoleServer is the side that answers it.
	RoleServer
)

// KeyExchange is one side of the key negotiation of an OpenSecureChannel
// exchange. It creates the nonce the side sends and, once the peer's nonce is
// known, the symmetric algorithm that secures the messages of the new
// SecurityToken.
//
// For the RSA policies the nonce is random data and the keys are derived from
// both nonces with P_SHA. For the ECC policies the nonce is an ephemeral
// public key and the keys are derived with HKDF from the Diffie-Hellman
// shared secret (Part 6 §6.8.1).
//
// A KeyExchange is used for exactly one OpenSecureChannel exchange: opening a
// channel and every renewal create a new one, and with it new ephemeral keys.
type KeyExchange struct {
	uri       string
	policy    policy
	role      Role
	nonce     []byte
	ephemeral *EphemeralKey
}

// NewKeyExchange starts the key negotiation for the security policy.
func NewKeyExchange(uri string, role Role) (*KeyExchange, error) {
	p, ok := policies[uri]
	if !ok {
		return nil, fmt.Errorf("%w: %s", errors.ErrUnsupportedSecurityPolicy, uri)
	}
	k := &KeyExchange{uri: uri, policy: p, role: role}

	if p.ecc != nil {
		eph, err := NewEphemeralKey(uri)
		if err != nil {
			return nil, err
		}
		k.ephemeral = eph
		k.nonce = eph.PublicKey()
		return k, nil
	}

	// The nonce length is a property of the asymmetric algorithm.
	asym, err := p.asymmetric(nil, nil)
	if err != nil {
		return nil, err
	}
	if k.nonce, err = asym.MakeNonce(); err != nil {
		return nil, err
	}
	return k, nil
}

// Nonce returns the nonce to send to the peer: the ClientNonce of the
// OpenSecureChannel request or the ServerNonce of the response.
func (k *KeyExchange) Nonce() []byte {
	return k.nonce
}

// Symmetric completes the negotiation with the nonce received from the peer
// and returns the symmetric algorithm for the new SecurityToken.
//
// For an ECC policy the peer's nonce is validated as a public key on the
// curve of the policy; an invalid key fails the negotiation.
//
// It is SymmetricChained for the first exchange of a channel. A renewal of a
// channel whose policy has SecureChannelEnhancements needs SymmetricChained.
func (k *KeyExchange) Symmetric(remoteNonce []byte) (*EncryptionAlgorithm, error) {
	algo, _, err := k.SymmetricChained(remoteNonce, nil)
	return algo, err
}

// SymmetricChained completes the negotiation like Symmetric and links the new
// keys to the previous ones of the channel.
//
// chain is the value the previous exchange on the same SecureChannel returned,
// or nil for the exchange that opens the channel. The result is the value for
// the next renewal. For the security policies with SecureChannelEnhancements
// it is key material: the keys of a renewed SecurityToken are derived from the
// new shared secret combined with that of every earlier exchange (Part 6
// §6.8.1), so both sides must pass the values in step. The value is secret; it
// must not be logged. For every other policy chain is ignored and the result
// is nil.
func (k *KeyExchange) SymmetricChained(remoteNonce, chain []byte) (algo *EncryptionAlgorithm, next []byte, err error) {
	if k.policy.ecc != nil {
		return k.policy.ecc.symmetricKeys(k.ephemeral, remoteNonce, k.role, chain)
	}
	if k.uri != ua.SecurityPolicyURINone && (k.nonce == nil || remoteNonce == nil) {
		return nil, nil, fmt.Errorf("%w: both nonces required", errors.ErrInvalidSecurityConfig)
	}
	algo, err = k.policy.symmetric(k.nonce, remoteNonce)
	return algo, nil, err
}

// EncryptionAlgorithm wraps the functions used to return the various
// methods required to implement the symmetric and asymmetric algorithms
// Function variables were used instead of an interface to make better use
// of policies which implement the same algorithms in different combinations
//
// EncryptionAlgorithm should always be instantiated through calls to
// SecurityPolicy.Symmetric() and SecurityPolicy.Asymmetric() to ensure
// correct behavior.
//
// The zero value of this struct will use SecurityPolicy#None although
// using in this manner is discouraged for readability.
type EncryptionAlgorithm struct {
	blockSize             int
	plainttextBlockSize   int
	decrypt               interface{ Decrypt([]byte) ([]byte, error) }
	encrypt               interface{ Encrypt([]byte) ([]byte, error) }
	signature             interface{ Signature([]byte) ([]byte, error) }
	verifySignature       interface{ Verify([]byte, []byte) error }
	nonceLength           int
	signatureLength       int
	remoteSignatureLength int
	encryptionURI         string
	signatureURI          string

	// signOnly is set for asymmetric algorithms that cannot encrypt (ECC).
	signOnly bool

	// aead is set for symmetric algorithms with authenticated encryption.
	// See ecc_aead.go.
	aead *chunkAEAD
}

// SignOnly reports whether the algorithm signs but never encrypts, whatever
// the MessageSecurityMode. That is the case for the asymmetric algorithm of
// the ECC policies: their OpenSecureChannel messages are signed, not
// encrypted and not padded.
func (e *EncryptionAlgorithm) SignOnly() bool {
	return e.signOnly
}

// BlockSize returns the underlying encryption algorithm's blocksize.
// Used to calculate the padding required to make the cleartext an
// even multiple of the blocksize.
func (e *EncryptionAlgorithm) BlockSize() int {
	return e.blockSize
}

// PlaintextBlockSize returns the size of the plaintext blocksize that
// can be fed into the encryption algorithm.
// Used to calculate the amount of padding to add to the
// unencrypted message.
func (e *EncryptionAlgorithm) PlaintextBlockSize() int {
	return e.plainttextBlockSize
}

// Encrypt encrypts the input cleartext based on the algorithms and keys passed in.
func (e *EncryptionAlgorithm) Encrypt(cleartext []byte) (ciphertext []byte, err error) {
	if e.encrypt == nil {
		e.encrypt = &None{}
	}

	return e.encrypt.Encrypt(cleartext)
}

// Decrypt decrypts the input ciphertext based on the algorithms and keys passed in.
func (e *EncryptionAlgorithm) Decrypt(ciphertext []byte) (cleartext []byte, err error) {
	if e.decrypt == nil {
		e.decrypt = &None{}
	}

	return e.decrypt.Decrypt(ciphertext)
}

// Signature returns the cryptographic signature of message.
func (e *EncryptionAlgorithm) Signature(message []byte) (signature []byte, err error) {
	if e.signature == nil {
		e.signature = &None{}
	}

	return e.signature.Signature(message)
}

// VerifySignature validates that 'signature' is the correct cryptographic signature
// of 'message' or returns an error.
// A return value of nil means the signature is valid.
func (e *EncryptionAlgorithm) VerifySignature(message, signature []byte) error {
	if e.verifySignature == nil {
		e.verifySignature = &None{}
	}

	return e.verifySignature.Verify(message, signature)
}

// SignatureLength returns the length in bytes for outgoing signatures.
func (e *EncryptionAlgorithm) SignatureLength() int {
	return e.signatureLength
}

// RemoteSignatureLength returns the length in bytes for incoming signatures.
func (e *EncryptionAlgorithm) RemoteSignatureLength() int {
	return e.remoteSignatureLength
}

// NonceLength returns the recommended nonce length in bytes for the security policy
// Only applicable for the Asymmetric security algorithm.  Symmetric algorithms should
// report NonceLength as zero.
func (e *EncryptionAlgorithm) NonceLength() int {
	return e.nonceLength
}

func (e *EncryptionAlgorithm) MakeNonce() ([]byte, error) {
	b := make([]byte, e.NonceLength())
	// note: we use `rand.Reader` instead of `rand.Read(...)` to ensure that we don't accidentally switch to using
	// math/rand (which has a default, fixed seed). Only crypto/rand exposes a global `io.Reader` var.
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// EncryptionURI returns the URI for the encryption algorithm as defined
// by the OPC-UA profiles in Part 7.
func (e *EncryptionAlgorithm) EncryptionURI() string {
	return e.encryptionURI
}

// SignatureURI returns the URI for the signature algorithm as defined
// by the OPC-UA profiles in Part 7.
func (e *EncryptionAlgorithm) SignatureURI() string {
	return e.signatureURI
}

var policies = map[string]policy{
	ua.SecurityPolicyURINone:                {asymmetric: rsaAsymmetric(newNoneAsymmetric), symmetric: newNoneSymmetric},
	ua.SecurityPolicyURIBasic128Rsa15:       {asymmetric: rsaAsymmetric(newBasic128Rsa15Asymmetric), symmetric: newBasic128Rsa15Symmetric},
	ua.SecurityPolicyURIBasic256:            {asymmetric: rsaAsymmetric(newBasic256Asymmetric), symmetric: newBasic256Symmetric},
	ua.SecurityPolicyURIBasic256Sha256:      {asymmetric: rsaAsymmetric(newBasic256Rsa256Asymmetric), symmetric: newBasic256Rsa256Symmetric},
	ua.SecurityPolicyURIAes128Sha256RsaOaep: {asymmetric: rsaAsymmetric(newAes128Sha256RsaOaepAsymmetric), symmetric: newAes128Sha256RsaOaepSymmetric},
	ua.SecurityPolicyURIAes256Sha256RsaPss:  {asymmetric: rsaAsymmetric(newAes256Sha256RsaPssAsymmetric), symmetric: newAes256Sha256RsaPssSymmetric},
}

func init() {
	for uri, p := range eccPolicies {
		policies[uri] = policy{asymmetric: p.asymmetric, ecc: p}
	}
}

// policy is one security policy: the constructors of its algorithms.
type policy struct {
	// asymmetric creates the asymmetric algorithm for a pair of application
	// instance keys. Either key may be nil.
	asymmetric func(localKey crypto.PrivateKey, remoteKey crypto.PublicKey) (*EncryptionAlgorithm, error)

	// symmetric derives the symmetric algorithm from the two nonces of an
	// OpenSecureChannel exchange. It is nil for the ECC policies.
	symmetric func(localNonce []byte, remoteNonce []byte) (*EncryptionAlgorithm, error)

	// ecc is set for the ECC policies, which derive the symmetric algorithm
	// from an ephemeral key agreement.
	ecc *eccPolicy
}

// rsaAsymmetric adapts the constructor of an RSA policy, which needs the
// concrete RSA key types, to the key-type independent signature of the policy
// table.
func rsaAsymmetric(f func(*rsa.PrivateKey, *rsa.PublicKey) (*EncryptionAlgorithm, error)) func(crypto.PrivateKey, crypto.PublicKey) (*EncryptionAlgorithm, error) {
	return func(localKey crypto.PrivateKey, remoteKey crypto.PublicKey) (*EncryptionAlgorithm, error) {
		var (
			local  *rsa.PrivateKey
			remote *rsa.PublicKey
			ok     bool
		)
		if localKey != nil {
			if local, ok = localKey.(*rsa.PrivateKey); !ok {
				return nil, fmt.Errorf("%w: local key: need an RSA key, got %s", errors.ErrInvalidSecurityConfig, describePrivateKey(localKey))
			}
		}
		if remoteKey != nil {
			if remote, ok = remoteKey.(*rsa.PublicKey); !ok {
				return nil, fmt.Errorf("%w: remote key: need an RSA key, got %s", errors.ErrInvalidSecurityConfig, describeKey(remoteKey))
			}
		}
		return f(local, remote)
	}
}

func describePrivateKey(key crypto.PrivateKey) string {
	if s, ok := key.(crypto.Signer); ok {
		return describeKey(s.Public())
	}
	return fmt.Sprintf("%T", key)
}

// SecurityLevel returns the recommended security level for endpoints
// It is a ranking of security quality, higher is better.
var securityLevels = map[string][4]uint8{
	// Array indicies are : {Invalid, None, Sign, SignAndEncrypt}
	ua.SecurityPolicyURINone:                {00, 01, 00, 00},
	ua.SecurityPolicyURIBasic128Rsa15:       {00, 00, 12, 13},
	ua.SecurityPolicyURIBasic256:            {00, 00, 22, 23},
	ua.SecurityPolicyURIBasic256Sha256:      {00, 00, 32, 33},
	ua.SecurityPolicyURIAes128Sha256RsaOaep: {00, 00, 42, 43},
	ua.SecurityPolicyURIAes256Sha256RsaPss:  {00, 00, 52, 53},
	// The ECC policies rank above the RSA ones: every SecurityToken is
	// negotiated with fresh ephemeral keys (forward secrecy), which no RSA
	// policy offers.
	ua.SecurityPolicyURIECCNistP256: {00, 00, 62, 63},
	ua.SecurityPolicyURIECCNistP384: {00, 00, 72, 73},
	// The policies of OPC UA 1.05.07 rank above those: authenticated
	// encryption instead of HMAC plus AES-CBC, and, for the nistP256 ones,
	// keys and session signatures that are bound to the channel. The numbers
	// continue the scheme (a decade per policy, Sign below SignAndEncrypt);
	// within the group the order is by what the policy adds: AES-GCM, then
	// ChaCha20-Poly1305 (a 256 bit key, constant time without hardware
	// support), then Curve25519 with Ed25519 certificates.
	ua.SecurityPolicyURIECCNistP256AesGcm:     {00, 00, 82, 83},
	ua.SecurityPolicyURIECCNistP256ChaChaPoly: {00, 00, 92, 93},
	ua.SecurityPolicyURIECCCurve25519:         {00, 00, 102, 103},
	// The Brainpool policies rank just below their NIST counterparts: the
	// same strength, but an implementation that is not constant time (see
	// docs/security.md). ECC_curve448 ranks above ECC_curve25519: the same
	// construction with a 224 bit instead of a 128 bit security level.
	ua.SecurityPolicyURIECCBrainpoolP256r1: {00, 00, 60, 61},
	ua.SecurityPolicyURIECCBrainpoolP384r1: {00, 00, 70, 71},
	ua.SecurityPolicyURIECCCurve448:        {00, 00, 112, 113},
}

func SecurityLevel(policy string, mode ua.MessageSecurityMode) uint8 {
	return securityLevels[policy][mode]
}
