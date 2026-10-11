// SPDX-License-Identifier: MIT

package uapolicy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/otfabric/go-opcua/errors"
)

// ECDSA implements the AsymmetricSignatureAlgorithm_ECDSA-SHA2-* algorithms
// of the ECC security policies.
//
// OPC UA does not use the ASN.1 DER signature encoding of X.509 and TLS. A
// signature is the concatenation r || s, each value a big-endian integer
// zero-padded to the size of the curve's field (Part 6 §6.8.1, Part 7): 64
// bytes for P-256 and 96 bytes for P-384.
//
// PrivateKey is a crypto.Signer so the application instance key may live in
// an HSM or a key agent; only its public key has to be an *ecdsa.PublicKey.
type ECDSA struct {
	Hash       crypto.Hash
	PublicKey  *ecdsa.PublicKey
	PrivateKey crypto.Signer
}

// ecdsaSignatureSize returns the size in bytes of an OPC UA encoded signature
// made with a key on the given curve.
func ecdsaSignatureSize(curve elliptic.Curve) int {
	return 2 * ((curve.Params().BitSize + 7) / 8)
}

type ecdsaASN1Signature struct {
	R, S *big.Int
}

// Signature returns the r || s encoded signature of msg.
func (s *ECDSA) Signature(msg []byte) ([]byte, error) {
	if s.PrivateKey == nil {
		return nil, fmt.Errorf("%w: no private key to sign with", errors.ErrInvalidSecurityConfig)
	}
	pub, ok := s.PrivateKey.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: private key is not an ECDSA key", errors.ErrInvalidSecurityConfig)
	}

	h := s.Hash.New()
	h.Write(msg)
	der, err := s.PrivateKey.Sign(rand.Reader, h.Sum(nil), s.Hash)
	if err != nil {
		return nil, err
	}

	// crypto.Signer returns the ASN.1 DER encoding for ECDSA keys.
	var sig ecdsaASN1Signature
	if rest, err := asn1.Unmarshal(der, &sig); err != nil || len(rest) != 0 || sig.R == nil || sig.S == nil {
		return nil, fmt.Errorf("%w: signer returned a malformed ECDSA signature", errors.ErrInvalidSecurityConfig)
	}

	n := ecdsaSignatureSize(pub.Curve) / 2
	if sig.R.Sign() <= 0 || sig.S.Sign() <= 0 || sig.R.BitLen() > 8*n || sig.S.BitLen() > 8*n {
		return nil, fmt.Errorf("%w: signer returned an out of range ECDSA signature", errors.ErrInvalidSecurityConfig)
	}
	out := make([]byte, 2*n)
	sig.R.FillBytes(out[:n])
	sig.S.FillBytes(out[n:])
	return out, nil
}

// Verify checks the r || s encoded signature of msg.
func (s *ECDSA) Verify(msg, signature []byte) error {
	if s.PublicKey == nil {
		return errors.ErrSignatureValidationFailed
	}
	n := ecdsaSignatureSize(s.PublicKey.Curve) / 2
	if len(signature) != 2*n {
		return errors.ErrSignatureValidationFailed
	}
	r := new(big.Int).SetBytes(signature[:n])
	sv := new(big.Int).SetBytes(signature[n:])

	h := s.Hash.New()
	h.Write(msg)
	// ecdsa.Verify rejects r or s outside [1, N-1].
	if !ecdsa.Verify(s.PublicKey, h.Sum(nil), r, sv) {
		return errors.ErrSignatureValidationFailed
	}
	return nil
}
