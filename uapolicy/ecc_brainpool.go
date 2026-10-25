// SPDX-License-Identifier: MIT

package uapolicy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/otfabric/go-opcua/errors"
)

// brainpoolAgreement is ECDH (RFC 8422) on a Brainpool curve (RFC 5639), the
// key agreement of ECC_brainpoolP256r1 and ECC_brainpoolP384r1.
//
// crypto/ecdh has no Brainpool curves. The curve arithmetic is the generic
// one of crypto/elliptic on the curves of
// github.com/ProtonMail/go-crypto/brainpool, which is not constant time; see
// docs/security.md. Every ephemeral key is used for a single key agreement.
type brainpoolAgreement struct {
	curve elliptic.Curve
}

// publicKeyLength is the size of x || y.
func (a brainpoolAgreement) publicKeyLength() int {
	return 2 * ((a.curve.Params().BitSize + 7) / 8)
}

func (a brainpoolAgreement) generate() (eccEphemeralPrivateKey, error) {
	key, err := ecdsa.GenerateKey(a.curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	return brainpoolEphemeralKey{key: key}, nil
}

type brainpoolEphemeralKey struct {
	key *ecdsa.PrivateKey
}

// publicKey returns x || y, both zero padded, as for the NIST curves.
func (k brainpoolEphemeralKey) publicKey() []byte {
	return marshalECPoint(&k.key.PublicKey)[1:]
}

func (k brainpoolEphemeralKey) sharedSecret(remote []byte) ([]byte, error) {
	curve := k.key.Curve
	point := make([]byte, 0, 1+len(remote))
	point = append(point, 0x04)
	point = append(point, remote...)
	// parseECPoint checks the length, that the coordinates are in range and
	// that the point is on the curve. The cofactor of the Brainpool curves is
	// 1: there are no points of small order to force a known secret with.
	pub, err := parseECPoint(curve, point)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid ephemeral public key", errors.ErrInvalidSecurityConfig)
	}
	n := (curve.Params().BitSize + 7) / 8
	//nolint:staticcheck // SA1019: crypto/ecdh has no Brainpool curves.
	x, y := curve.ScalarMult(pub.X, pub.Y, k.key.D.FillBytes(make([]byte, n)))
	if x.Sign() == 0 && y.Sign() == 0 {
		return nil, fmt.Errorf("%w: invalid ephemeral public key", errors.ErrInvalidSecurityConfig)
	}
	// The x-coordinate as a zero padded big-endian octet string.
	return x.FillBytes(make([]byte, n)), nil
}
