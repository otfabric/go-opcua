// SPDX-License-Identifier: MIT

package uapolicy

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	stderrors "errors"
	"fmt"
	"math/big"

	"github.com/cloudflare/circl/sign/ed448"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/otfabric/go-opcua/errors"
)

// Private keys crypto/x509 does not parse: ECDSA keys on the Brainpool curves
// (SEC 1 ECPrivateKey, RFC 5915, alone or in PKCS #8) and Ed448 keys (PKCS #8,
// RFC 8410 §7).

var (
	tagECParameters = cbasn1.Tag(0).Constructed().ContextSpecific()
	tagECPublicKey  = cbasn1.Tag(1).Constructed().ContextSpecific()
	// The attributes and publicKey of a OneAsymmetricKey (RFC 5958) are
	// IMPLICIT.
	tagPKCS8Attributes = cbasn1.Tag(0).Constructed().ContextSpecific()
	tagPKCS8PublicKey  = cbasn1.Tag(1).ContextSpecific()
)

// parseExtendedPKCS8 parses a PKCS #8 key on a Brainpool curve or an Ed448
// key. It returns errNotExtended for any other algorithm.
func parseExtendedPKCS8(der []byte) (crypto.Signer, error) {
	var (
		in               = cryptobyte.String(der)
		info, algo, priv cryptobyte.String
		version          int
		oid              asn1.ObjectIdentifier
	)
	if !in.ReadASN1(&info, cbasn1.SEQUENCE) || !in.Empty() ||
		!info.ReadASN1Integer(&version) ||
		!info.ReadASN1(&algo, cbasn1.SEQUENCE) ||
		!algo.ReadASN1ObjectIdentifier(&oid) ||
		!info.ReadASN1(&priv, cbasn1.OCTET_STRING) {
		return nil, errNotExtended
	}
	if version != 0 && version != 1 {
		return nil, fmt.Errorf("%w: unsupported PKCS #8 version %d", errors.ErrInvalidPrivateKey, version)
	}
	// Attributes are ignored; a public key is checked against the private key.
	if !info.SkipOptionalASN1(tagPKCS8Attributes) {
		return nil, fmt.Errorf("%w: malformed PKCS #8 attributes", errors.ErrInvalidPrivateKey)
	}
	var public []byte
	if info.PeekASN1Tag(tagPKCS8PublicKey) {
		var bits cryptobyte.String
		var unused uint8
		if !info.ReadASN1(&bits, tagPKCS8PublicKey) || !bits.ReadUint8(&unused) || unused != 0 {
			return nil, fmt.Errorf("%w: malformed PKCS #8 public key", errors.ErrInvalidPrivateKey)
		}
		public = bits
	}
	if !info.Empty() {
		return nil, fmt.Errorf("%w: trailing data in PKCS #8 key", errors.ErrInvalidPrivateKey)
	}

	switch {
	case oid.Equal(oidPublicKeyECDSA):
		var curveOID asn1.ObjectIdentifier
		if !algo.ReadASN1ObjectIdentifier(&curveOID) || !algo.Empty() {
			return nil, errNotExtended
		}
		curve := brainpoolCurve(curveOID)
		if curve == nil {
			return nil, errNotExtended
		}
		return parseBrainpoolECPrivateKey(priv, curve)
	case oid.Equal(oidEd448):
		var seed cryptobyte.String
		if !algo.Empty() || !priv.ReadASN1(&seed, cbasn1.OCTET_STRING) || !priv.Empty() || len(seed) != ed448.SeedSize {
			return nil, fmt.Errorf("%w: malformed Ed448 key", errors.ErrInvalidPrivateKey)
		}
		key := ed448.NewKeyFromSeed(seed)
		if public != nil && !bytes.Equal(public, key.Public().(ed448.PublicKey)) {
			return nil, fmt.Errorf("%w: Ed448 public key does not match the private key", errors.ErrInvalidPrivateKey)
		}
		return key, nil
	}
	return nil, errNotExtended
}

// parseBrainpoolECPrivateKey parses a SEC 1 ECPrivateKey on a Brainpool
// curve. curve is the curve of the enclosing PKCS #8 structure, or nil if the
// key has to name it. It returns errNotExtended for keys on other curves.
func parseBrainpoolECPrivateKey(der []byte, curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	var (
		in       = cryptobyte.String(der)
		key, raw cryptobyte.String
		version  int
	)
	if !in.ReadASN1(&key, cbasn1.SEQUENCE) || !in.Empty() ||
		!key.ReadASN1Integer(&version) || version != 1 ||
		!key.ReadASN1(&raw, cbasn1.OCTET_STRING) {
		return nil, errNotExtended
	}
	if key.PeekASN1Tag(tagECParameters) {
		var params cryptobyte.String
		var oid asn1.ObjectIdentifier
		if !key.ReadASN1(&params, tagECParameters) || !params.ReadASN1ObjectIdentifier(&oid) || !params.Empty() {
			return nil, errNotExtended
		}
		named := brainpoolCurve(oid)
		if named == nil {
			return nil, errNotExtended
		}
		if curve != nil && curve != named {
			return nil, fmt.Errorf("%w: EC parameters name another curve than the PKCS #8 algorithm", errors.ErrInvalidPrivateKey)
		}
		curve = named
	}
	if curve == nil {
		return nil, errNotExtended
	}
	var public []byte
	if key.PeekASN1Tag(tagECPublicKey) {
		var wrapper cryptobyte.String
		var bits asn1.BitString
		if !key.ReadASN1(&wrapper, tagECPublicKey) || !wrapper.ReadASN1BitString(&bits) || !wrapper.Empty() || bits.BitLength%8 != 0 {
			return nil, fmt.Errorf("%w: malformed EC public key", errors.ErrInvalidPrivateKey)
		}
		public = bits.Bytes
	}
	if !key.Empty() {
		return nil, fmt.Errorf("%w: trailing data in EC private key", errors.ErrInvalidPrivateKey)
	}

	params := curve.Params()
	n := (params.N.BitLen() + 7) / 8
	if len(raw) > n {
		return nil, fmt.Errorf("%w: %s private key is too long", errors.ErrInvalidPrivateKey, params.Name)
	}
	d := new(big.Int).SetBytes(raw)
	if d.Sign() <= 0 || d.Cmp(params.N) >= 0 {
		return nil, fmt.Errorf("%w: %s private key is out of range", errors.ErrInvalidPrivateKey, params.Name)
	}
	priv := &ecdsa.PrivateKey{D: d}                                     //nolint:staticcheck // SA1019: see parseECPoint.
	priv.Curve = curve                                                  //nolint:staticcheck // SA1019: see parseECPoint.
	priv.X, priv.Y = curve.ScalarBaseMult(d.FillBytes(make([]byte, n))) //nolint:staticcheck // SA1019: see parseECPoint.
	if public != nil {
		pub, err := parseECPoint(curve, public)
		if err != nil || !pub.Equal(&priv.PublicKey) {
			return nil, fmt.Errorf("%w: EC public key does not match the private key", errors.ErrInvalidPrivateKey)
		}
	}
	return priv, nil
}

// MarshalPrivateKey returns the PKCS #8 encoding of an application instance
// or user key: everything x509.MarshalPKCS8PrivateKey encodes and the keys
// ParsePrivateKey adds, ECDSA keys on the Brainpool curves and Ed448 keys.
func MarshalPrivateKey(key crypto.Signer) ([]byte, error) {
	var b cryptobyte.Builder
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		oid, ok := brainpoolOID(k.Curve)
		if !ok {
			break
		}
		n := (k.Params().N.BitLen() + 7) / 8
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1Int64(0)
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(oidPublicKeyECDSA)
				b.AddASN1ObjectIdentifier(oid)
			})
			b.AddASN1(cbasn1.OCTET_STRING, func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1Int64(1)
					b.AddASN1OctetString(k.D.FillBytes(make([]byte, n))) //nolint:staticcheck // SA1019: see parseECPoint.
					b.AddASN1(tagECPublicKey, func(b *cryptobyte.Builder) {
						addBitString(b, marshalECPoint(&k.PublicKey))
					})
				})
			})
		})
		return b.Bytes()
	case ed448.PrivateKey:
		if len(k) != ed448.PrivateKeySize {
			return nil, fmt.Errorf("%w: malformed Ed448 key", errors.ErrInvalidPrivateKey)
		}
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1Int64(0)
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(oidEd448)
			})
			b.AddASN1(cbasn1.OCTET_STRING, func(b *cryptobyte.Builder) {
				b.AddASN1OctetString(k.Seed())
			})
		})
		return b.Bytes()
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errors.ErrInvalidPrivateKey, err)
	}
	return der, nil
}

// extendedKeyError returns err unless it is errNotExtended, in which case it
// returns fallback: the error of the standard library parser.
func extendedKeyError(err, fallback error) error {
	if stderrors.Is(err, errNotExtended) {
		return fallback
	}
	return err
}
