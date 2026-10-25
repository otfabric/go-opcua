// SPDX-License-Identifier: MIT

package uapolicy

import (
	"crypto"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/cloudflare/circl/dh/x448"
	"github.com/cloudflare/circl/sign/ed448"

	"github.com/otfabric/go-opcua/errors"
)

// The primitives of ECC_curve448: Ed448 signatures (RFC 8032) and X448 key
// agreement (RFC 7748), both from github.com/cloudflare/circl.

// Ed448 implements the asymmetric signature algorithm of the ECC_curve448
// security policy: pure Ed448 (RFC 8032 §5.2) with an empty context. The
// message is signed as it is, and a signature is the 114 bytes of the RFC.
//
// PrivateKey is a crypto.Signer so the application instance key may live in
// an HSM or a key agent; only its public key has to be an ed448.PublicKey.
type Ed448 struct {
	PublicKey  ed448.PublicKey
	PrivateKey crypto.Signer
}

// Signature returns the Ed448 signature of msg.
func (s *Ed448) Signature(msg []byte) ([]byte, error) {
	if s.PrivateKey == nil {
		return nil, fmt.Errorf("%w: no private key to sign with", errors.ErrInvalidSecurityConfig)
	}
	if _, ok := s.PrivateKey.Public().(ed448.PublicKey); !ok {
		return nil, fmt.Errorf("%w: private key is not an Ed448 key", errors.ErrInvalidSecurityConfig)
	}
	// crypto.Hash(0) selects pure Ed448 with an empty context.
	sig, err := s.PrivateKey.Sign(rand.Reader, msg, crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	if len(sig) != ed448.SignatureSize {
		return nil, fmt.Errorf("%w: signer returned a malformed Ed448 signature", errors.ErrInvalidSecurityConfig)
	}
	return sig, nil
}

// Verify checks the Ed448 signature of msg.
func (s *Ed448) Verify(msg, signature []byte) error {
	if len(s.PublicKey) != ed448.PublicKeySize || len(signature) != ed448.SignatureSize {
		return errors.ErrSignatureValidationFailed
	}
	if !ed448.Verify(s.PublicKey, msg, signature, "") {
		return errors.ErrSignatureValidationFailed
	}
	return nil
}

// ed448Suite is EdDSA with Ed448 application keys.
type ed448Suite struct{}

func (ed448Suite) describe() string { return "an Ed448 key" }

func (s ed448Suite) signer(key crypto.PrivateKey) (interface{ Signature([]byte) ([]byte, error) }, int, error) {
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, 0, fmt.Errorf("%w: need %s, got %T", errors.ErrInvalidSecurityConfig, s.describe(), key)
	}
	pub, ok := signer.Public().(ed448.PublicKey)
	if !ok || len(pub) != ed448.PublicKeySize {
		return nil, 0, fmt.Errorf("%w: need %s, got %s", errors.ErrInvalidSecurityConfig, s.describe(), describeKey(signer.Public()))
	}
	return &Ed448{PrivateKey: signer}, ed448.SignatureSize, nil
}

func (s ed448Suite) verifier(key crypto.PublicKey) (interface{ Verify([]byte, []byte) error }, int, error) {
	pub, ok := key.(ed448.PublicKey)
	if !ok || len(pub) != ed448.PublicKeySize {
		return nil, 0, fmt.Errorf("%w: need %s, got %s", errors.ErrInvalidSecurityConfig, s.describe(), describeKey(key))
	}
	return &Ed448{PublicKey: pub}, ed448.SignatureSize, nil
}

// x448Agreement is the key agreement of ECC_curve448 (RFC 7748).
type x448Agreement struct{}

func (x448Agreement) publicKeyLength() int { return x448.Size }

func (x448Agreement) generate() (eccEphemeralPrivateKey, error) {
	return newX448Key(rand.Reader)
}

func newX448Key(r io.Reader) (*x448EphemeralKey, error) {
	var k x448EphemeralKey
	if _, err := io.ReadFull(r, k.secret[:]); err != nil {
		return nil, err
	}
	// KeyGen clamps the secret (RFC 7748 §5).
	x448.KeyGen(&k.public, &k.secret)
	return &k, nil
}

type x448EphemeralKey struct {
	secret, public x448.Key
}

// publicKey returns the 56 byte u-coordinate, the encoding of RFC 7748.
func (k *x448EphemeralKey) publicKey() []byte {
	return append([]byte(nil), k.public[:]...)
}

func (k *x448EphemeralKey) sharedSecret(remote []byte) ([]byte, error) {
	if len(remote) != x448.Size {
		return nil, fmt.Errorf("%w: invalid ephemeral public key", errors.ErrInvalidSecurityConfig)
	}
	var pub, shared, zero x448.Key
	copy(pub[:], remote)
	// Shared fails for the points of small order, which give the all-zero
	// value (RFC 7748 §6.2): a peer cannot force a shared secret it knows
	// without knowing a private key. The result is checked as well.
	if !x448.Shared(&shared, &k.secret, &pub) || subtle.ConstantTimeCompare(shared[:], zero[:]) == 1 {
		return nil, fmt.Errorf("%w: invalid ephemeral public key", errors.ErrInvalidSecurityConfig)
	}
	return shared[:], nil
}
