// SPDX-License-Identifier: MIT

package uapolicy

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/otfabric/go-opcua/errors"
)

// EdDSA implements the asymmetric signature algorithm of the ECC_curve25519
// security policy: pure Ed25519 (RFC 8032). The message is signed as it is,
// without hashing it first, and a signature is the 64 bytes of the RFC.
//
// PrivateKey is a crypto.Signer so the application instance key may live in
// an HSM or a key agent; only its public key has to be an ed25519.PublicKey.
type EdDSA struct {
	PublicKey  ed25519.PublicKey
	PrivateKey crypto.Signer
}

// Signature returns the Ed25519 signature of msg.
func (s *EdDSA) Signature(msg []byte) ([]byte, error) {
	if s.PrivateKey == nil {
		return nil, fmt.Errorf("%w: no private key to sign with", errors.ErrInvalidSecurityConfig)
	}
	if _, ok := s.PrivateKey.Public().(ed25519.PublicKey); !ok {
		return nil, fmt.Errorf("%w: private key is not an Ed25519 key", errors.ErrInvalidSecurityConfig)
	}
	// crypto.Hash(0) selects pure Ed25519: the signer gets the message, not
	// a digest of it.
	sig, err := s.PrivateKey.Sign(rand.Reader, msg, crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: signer returned a malformed Ed25519 signature", errors.ErrInvalidSecurityConfig)
	}
	return sig, nil
}

// Verify checks the Ed25519 signature of msg.
func (s *EdDSA) Verify(msg, signature []byte) error {
	if len(s.PublicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return errors.ErrSignatureValidationFailed
	}
	if !ed25519.Verify(s.PublicKey, msg, signature) {
		return errors.ErrSignatureValidationFailed
	}
	return nil
}

// ed25519Suite is EdDSA with Ed25519 application keys.
type ed25519Suite struct{}

func (ed25519Suite) describe() string { return "an Ed25519 key" }

func (s ed25519Suite) signer(key crypto.PrivateKey) (interface{ Signature([]byte) ([]byte, error) }, int, error) {
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, 0, fmt.Errorf("%w: need %s, got %T", errors.ErrInvalidSecurityConfig, s.describe(), key)
	}
	pub, ok := signer.Public().(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return nil, 0, fmt.Errorf("%w: need %s, got %s", errors.ErrInvalidSecurityConfig, s.describe(), describeKey(signer.Public()))
	}
	return &EdDSA{PrivateKey: signer}, ed25519.SignatureSize, nil
}

func (s ed25519Suite) verifier(key crypto.PublicKey) (interface{ Verify([]byte, []byte) error }, int, error) {
	pub, ok := key.(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return nil, 0, fmt.Errorf("%w: need %s, got %s", errors.ErrInvalidSecurityConfig, s.describe(), describeKey(key))
	}
	return &EdDSA{PublicKey: pub}, ed25519.SignatureSize, nil
}
