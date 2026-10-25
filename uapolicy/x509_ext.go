// SPDX-License-Identifier: MIT

package uapolicy

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	stderrors "errors"
	"fmt"
	"io"
	"math/big"

	"github.com/ProtonMail/go-crypto/brainpool"
	"github.com/cloudflare/circl/sign/ed448"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/otfabric/go-opcua/errors"
)

// Certificates with keys the standard library does not support.
//
// crypto/x509 knows RSA, ECDSA on the NIST curves and Ed25519. The
// ECC_brainpoolP256r1 and ECC_brainpoolP384r1 policies need ECDSA keys on the
// Brainpool curves of RFC 5639 (RFC 5480 SubjectPublicKeyInfo with a
// brainpool namedCurve, RFC 5639 §4.1), ECC_curve448 Ed448 keys and
// signatures (RFC 8410). x509.ParseCertificate rejects a certificate with a
// Brainpool key ("unsupported elliptic curve"), leaves the key of an Ed448
// certificate unparsed and cannot verify an Ed448 signature, and
// x509.CreateCertificate creates neither.
//
// The functions here close that gap with as little ASN.1 of their own as
// possible. The standard library still does all the parsing and encoding of
// names, validity, extensions and everything else: only the
// SubjectPublicKeyInfo and the signature algorithm are handled here.
//
//   - ParseCertificate swaps the SubjectPublicKeyInfo of a Brainpool
//     certificate for one with an algorithm crypto/x509 does not know before
//     it hands the certificate to x509.ParseCertificate, and puts the original
//     back into the result. An Ed448 key is parsed from the
//     RawSubjectPublicKeyInfo crypto/x509 leaves alone.
//   - CreateCertificate lets x509.CreateCertificate build the
//     TBSCertificate with a throwaway key and signs it again after the
//     SubjectPublicKeyInfo and signature algorithm were replaced by the real
//     ones.
//   - VerifyCertificate verifies chains with (*x509.Certificate).Verify,
//     which handles Brainpool keys (crypto/ecdsa verifies signatures of custom
//     curves), and with a small chain builder of its own only if a
//     certificate of the chain carries an Ed448 signature.

var (
	oidPublicKeyECDSA  = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidBrainpoolP256r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 7}
	oidBrainpoolP384r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 11}
	oidEd448           = asn1.ObjectIdentifier{1, 3, 101, 113}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidEd25519         = asn1.ObjectIdentifier{1, 3, 101, 112}
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
)

// errNotExtended reports that a key or certificate is not one of the types
// this file adds: the caller keeps the error of the standard library.
var errNotExtended = stderrors.New("uapolicy: not a Brainpool or Ed448 key")

// brainpoolCurve returns the Brainpool curve with the given OID, or nil.
func brainpoolCurve(oid asn1.ObjectIdentifier) elliptic.Curve {
	switch {
	case oid.Equal(oidBrainpoolP256r1):
		return brainpool.P256r1()
	case oid.Equal(oidBrainpoolP384r1):
		return brainpool.P384r1()
	}
	return nil
}

// brainpoolOID returns the OID of a Brainpool curve; ok is false for any other
// curve.
func brainpoolOID(c elliptic.Curve) (oid asn1.ObjectIdentifier, ok bool) {
	switch c {
	case brainpool.P256r1():
		return oidBrainpoolP256r1, true
	case brainpool.P384r1():
		return oidBrainpoolP384r1, true
	}
	return nil, false
}

// isExtendedKey reports whether pub is a key crypto/x509 cannot encode: an
// ECDSA key on a Brainpool curve or an Ed448 key.
func isExtendedKey(pub crypto.PublicKey) bool {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		_, ok := brainpoolOID(k.Curve)
		return ok
	case ed448.PublicKey:
		return true
	}
	return false
}

// parseECPoint parses an uncompressed SEC 1 point (0x04 || x || y) on a
// Brainpool curve. It rejects coordinates outside the field and points that
// are not on the curve; the point at infinity has no uncompressed encoding.
// The Brainpool curves have cofactor 1, so every point on the curve is in
// the prime order group.
func parseECPoint(curve elliptic.Curve, data []byte) (*ecdsa.PublicKey, error) {
	n := (curve.Params().BitSize + 7) / 8
	if len(data) != 1+2*n || data[0] != 4 {
		return nil, fmt.Errorf("%w: not an uncompressed %s point", errors.ErrInvalidCertificate, curve.Params().Name)
	}
	x := new(big.Int).SetBytes(data[1 : 1+n])
	y := new(big.Int).SetBytes(data[1+n:])
	p := curve.Params().P
	// IsOnCurve of the Brainpool curves reduces the coordinates modulo P
	// first, so the range is checked here.
	if x.Cmp(p) >= 0 || y.Cmp(p) >= 0 || !curve.IsOnCurve(x, y) { //nolint:staticcheck // SA1019: crypto/ecdh has no Brainpool curves.
		return nil, fmt.Errorf("%w: point is not on %s", errors.ErrInvalidCertificate, curve.Params().Name)
	}
	//nolint:staticcheck // SA1019: crypto/ecdsa has no other way to hold a key on a custom curve.
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// marshalECPoint returns the uncompressed SEC 1 encoding of pub.
func marshalECPoint(pub *ecdsa.PublicKey) []byte {
	n := (pub.Params().BitSize + 7) / 8
	out := make([]byte, 1+2*n)
	out[0] = 4
	pub.X.FillBytes(out[1 : 1+n]) //nolint:staticcheck // SA1019: see parseECPoint.
	pub.Y.FillBytes(out[1+n:])    //nolint:staticcheck // SA1019: see parseECPoint.
	return out
}

// parseExtendedPublicKey parses a SubjectPublicKeyInfo with a Brainpool or
// an Ed448 key. It returns errNotExtended for any other algorithm.
func parseExtendedPublicKey(spki []byte) (crypto.PublicKey, error) {
	var (
		in, info, algo cryptobyte.String = spki, nil, nil
		oid            asn1.ObjectIdentifier
		bits           asn1.BitString
	)
	if !in.ReadASN1(&info, cbasn1.SEQUENCE) || !in.Empty() ||
		!info.ReadASN1(&algo, cbasn1.SEQUENCE) ||
		!algo.ReadASN1ObjectIdentifier(&oid) ||
		!info.ReadASN1BitString(&bits) || !info.Empty() {
		return nil, fmt.Errorf("%w: malformed SubjectPublicKeyInfo", errors.ErrInvalidCertificate)
	}
	switch {
	case oid.Equal(oidPublicKeyECDSA):
		var curveOID asn1.ObjectIdentifier
		if !algo.ReadASN1ObjectIdentifier(&curveOID) {
			return nil, errNotExtended
		}
		curve := brainpoolCurve(curveOID)
		if curve == nil {
			return nil, errNotExtended
		}
		if !algo.Empty() || bits.BitLength%8 != 0 {
			return nil, fmt.Errorf("%w: malformed %s key", errors.ErrInvalidCertificate, curve.Params().Name)
		}
		return parseECPoint(curve, bits.Bytes)
	case oid.Equal(oidEd448):
		// RFC 8410 §3: the parameters are absent.
		if !algo.Empty() || bits.BitLength != 8*ed448.PublicKeySize {
			return nil, fmt.Errorf("%w: malformed Ed448 key", errors.ErrInvalidCertificate)
		}
		return ed448.PublicKey(bytes.Clone(bits.Bytes)), nil
	}
	return nil, errNotExtended
}

// marshalPublicKey returns the DER encoded SubjectPublicKeyInfo of pub and
// the contents of its subjectPublicKey BIT STRING.
func marshalPublicKey(pub crypto.PublicKey) (spki, keyBits []byte, err error) {
	var b cryptobyte.Builder
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		oid, ok := brainpoolOID(k.Curve)
		if !ok {
			break
		}
		keyBits = marshalECPoint(k)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(oidPublicKeyECDSA)
				b.AddASN1ObjectIdentifier(oid)
			})
			addBitString(b, keyBits)
		})
		spki, err = b.Bytes()
		return spki, keyBits, err
	case ed448.PublicKey:
		if len(k) != ed448.PublicKeySize {
			return nil, nil, fmt.Errorf("%w: malformed Ed448 key", errors.ErrInvalidSecurityConfig)
		}
		keyBits = bytes.Clone(k)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(oidEd448)
			})
			addBitString(b, keyBits)
		})
		spki, err = b.Bytes()
		return spki, keyBits, err
	}
	spki, err = x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	in := cryptobyte.String(spki)
	var info cryptobyte.String
	var bits asn1.BitString
	if !in.ReadASN1(&info, cbasn1.SEQUENCE) || !info.SkipASN1(cbasn1.SEQUENCE) || !info.ReadASN1BitString(&bits) {
		return nil, nil, fmt.Errorf("%w: cannot encode the public key", errors.ErrInvalidSecurityConfig)
	}
	return spki, bits.Bytes, nil
}

func addBitString(b *cryptobyte.Builder, data []byte) {
	b.AddASN1(cbasn1.BIT_STRING, func(b *cryptobyte.Builder) {
		b.AddUint8(0) // no unused bits
		b.AddBytes(data)
	})
}

// certificateParts are the elements of a DER encoded certificate (RFC 5280
// §4.1), each with its tag and length.
type certificateParts struct {
	tbs       []byte // the TBSCertificate
	head      []byte // version and serialNumber
	signature []byte // the signature AlgorithmIdentifier inside the TBSCertificate
	names     []byte // issuer, validity and subject
	spki      []byte // subjectPublicKeyInfo
	tail      []byte // issuerUniqueID, subjectUniqueID and extensions
	algorithm []byte // the signatureAlgorithm after the TBSCertificate
	value     []byte // the signatureValue BIT STRING
}

func splitCertificate(der []byte) (*certificateParts, error) {
	var (
		p                cryptobyte.String
		in               = cryptobyte.String(der)
		cert, tbs, field cryptobyte.String
		parts            certificateParts
	)
	if !in.ReadASN1(&cert, cbasn1.SEQUENCE) || !in.Empty() {
		return nil, fmt.Errorf("%w: malformed certificate", errors.ErrInvalidCertificate)
	}
	rest := cert
	if !rest.ReadASN1Element(&p, cbasn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: malformed TBSCertificate", errors.ErrInvalidCertificate)
	}
	parts.tbs = p
	tbs = p
	if !tbs.ReadASN1(&field, cbasn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: malformed TBSCertificate", errors.ErrInvalidCertificate)
	}
	tbs = field
	start := len(tbs)
	// version [0] EXPLICIT (optional) and serialNumber.
	if tbs.PeekASN1Tag(cbasn1.Tag(0).Constructed().ContextSpecific()) {
		if !tbs.SkipASN1(cbasn1.Tag(0).Constructed().ContextSpecific()) {
			return nil, fmt.Errorf("%w: malformed version", errors.ErrInvalidCertificate)
		}
	}
	if !tbs.SkipASN1(cbasn1.INTEGER) {
		return nil, fmt.Errorf("%w: malformed serial number", errors.ErrInvalidCertificate)
	}
	parts.head = field[:start-len(tbs)]
	if !tbs.ReadASN1Element(&p, cbasn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: malformed signature algorithm", errors.ErrInvalidCertificate)
	}
	parts.signature = p
	names := tbs
	for range 3 { // issuer, validity, subject
		if !tbs.SkipASN1(cbasn1.SEQUENCE) {
			return nil, fmt.Errorf("%w: malformed name or validity", errors.ErrInvalidCertificate)
		}
	}
	parts.names = names[:len(names)-len(tbs)]
	if !tbs.ReadASN1Element(&p, cbasn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: malformed SubjectPublicKeyInfo", errors.ErrInvalidCertificate)
	}
	parts.spki = p
	parts.tail = tbs

	if !rest.ReadASN1Element(&p, cbasn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: malformed signature algorithm", errors.ErrInvalidCertificate)
	}
	parts.algorithm = p
	if !rest.ReadASN1Element(&p, cbasn1.BIT_STRING) || !rest.Empty() {
		return nil, fmt.Errorf("%w: malformed signature", errors.ErrInvalidCertificate)
	}
	parts.value = p
	return &parts, nil
}

// join encodes the certificate of the parts.
func (c *certificateParts) join() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(c.tbs)
		b.AddBytes(c.algorithm)
		b.AddBytes(c.value)
	})
	return b.Bytes()
}

// joinTBS encodes the TBSCertificate of the parts.
func (c *certificateParts) joinTBS() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(c.head)
		b.AddBytes(c.signature)
		b.AddBytes(c.names)
		b.AddBytes(c.spki)
		b.AddBytes(c.tail)
	})
	return b.Bytes()
}

// ParseCertificate parses a single DER encoded certificate like
// x509.ParseCertificate. It also accepts certificates with an ECDSA key on
// brainpoolP256r1 or brainpoolP384r1 (PublicKey is an *ecdsa.PublicKey on
// the curve of github.com/ProtonMail/go-crypto/brainpool, PublicKeyAlgorithm
// x509.ECDSA) and with an Ed448 key (PublicKey is an ed448.PublicKey of
// github.com/cloudflare/circl/sign/ed448; PublicKeyAlgorithm and, for an
// Ed448 signature, SignatureAlgorithm stay unknown to crypto/x509).
func ParseCertificate(der []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		bp, bpErr := parseBrainpoolCertificate(der)
		if bpErr == nil {
			return bp, nil
		}
		if stderrors.Is(bpErr, errNotExtended) {
			return nil, err
		}
		return nil, bpErr
	}
	if err := completeCertificate(cert); err != nil {
		return nil, err
	}
	return cert, nil
}

// ParseCertificates parses one or more concatenated DER encoded certificates
// like x509.ParseCertificates, with the key types of ParseCertificate.
func ParseCertificates(der []byte) ([]*x509.Certificate, error) {
	if certs, err := x509.ParseCertificates(der); err == nil {
		for _, c := range certs {
			if err := completeCertificate(c); err != nil {
				return nil, err
			}
		}
		return certs, nil
	}
	var certs []*x509.Certificate
	in := cryptobyte.String(der)
	for !in.Empty() {
		var elem cryptobyte.String
		if !in.ReadASN1Element(&elem, cbasn1.SEQUENCE) {
			return nil, fmt.Errorf("%w: malformed certificate", errors.ErrInvalidCertificate)
		}
		cert, err := ParseCertificate(elem)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// completeCertificate fills in the Ed448 key crypto/x509 leaves unparsed.
func completeCertificate(cert *x509.Certificate) error {
	if cert.PublicKeyAlgorithm != x509.UnknownPublicKeyAlgorithm {
		return nil
	}
	key, err := parseExtendedPublicKey(cert.RawSubjectPublicKeyInfo)
	switch {
	case err == nil:
		cert.PublicKey = key
	case !stderrors.Is(err, errNotExtended):
		return err
	}
	return nil
}

// parseBrainpoolCertificate parses a certificate with a Brainpool key, which
// x509.ParseCertificate rejects. The key's algorithm is replaced by the OID
// of the curve, which crypto/x509 does not know and therefore does not try to
// parse; the original key is put back into the result. The certificate is
// not changed in any other way.
func parseBrainpoolCertificate(der []byte) (*x509.Certificate, error) {
	parts, err := splitCertificate(der)
	if err != nil {
		return nil, errNotExtended // keep the error of x509.ParseCertificate
	}
	key, err := parseExtendedPublicKey(parts.spki)
	if err != nil {
		return nil, err
	}
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, errNotExtended
	}
	oid, _ := brainpoolOID(pub.Curve)

	original := *parts
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oid)
		})
		addBitString(b, marshalECPoint(pub))
	})
	if parts.spki, err = b.Bytes(); err != nil {
		return nil, err
	}
	if parts.tbs, err = parts.joinTBS(); err != nil {
		return nil, err
	}
	patched, err := parts.join()
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(patched)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errors.ErrInvalidCertificate, err)
	}
	cert.Raw = bytes.Clone(der)
	cert.RawTBSCertificate = bytes.Clone(original.tbs)
	cert.RawSubjectPublicKeyInfo = bytes.Clone(original.spki)
	cert.PublicKeyAlgorithm = x509.ECDSA
	cert.PublicKey = pub
	return cert, nil
}

// certificateSignatureOID returns the OID of the signatureAlgorithm of a
// certificate.
func certificateSignatureOID(cert *x509.Certificate) asn1.ObjectIdentifier {
	parts, err := splitCertificate(cert.Raw)
	if err != nil {
		return nil
	}
	in := cryptobyte.String(parts.algorithm)
	var algo cryptobyte.String
	var oid asn1.ObjectIdentifier
	if !in.ReadASN1(&algo, cbasn1.SEQUENCE) || !algo.ReadASN1ObjectIdentifier(&oid) {
		return nil
	}
	return oid
}

// hasEd448Signature reports whether the certificate is signed with Ed448.
func hasEd448Signature(cert *x509.Certificate) bool {
	return cert.SignatureAlgorithm == x509.UnknownSignatureAlgorithm && certificateSignatureOID(cert).Equal(oidEd448)
}

// checkCertificateSignature verifies that parent signed cert.
func checkCertificateSignature(cert, parent *x509.Certificate) error {
	if hasEd448Signature(cert) {
		pub, ok := parent.PublicKey.(ed448.PublicKey)
		if !ok {
			return fmt.Errorf("%w: an Ed448 signature needs an Ed448 issuer key", errors.ErrInvalidCertificate)
		}
		parts, err := splitCertificate(cert.Raw)
		if err != nil {
			return err
		}
		// RFC 8410 §3: the parameters are absent. (x509.ParseCertificate has
		// checked that both signature algorithm fields are the same.)
		if !bytes.Equal(parts.algorithm, mustAlgorithmIdentifier(oidEd448, false)) {
			return fmt.Errorf("%w: malformed Ed448 signature algorithm", errors.ErrInvalidCertificate)
		}
		if len(cert.Signature) != ed448.SignatureSize || !ed448.Verify(pub, cert.RawTBSCertificate, cert.Signature, "") {
			return fmt.Errorf("%w: Ed448 signature of %q is invalid", errors.ErrInvalidCertificate, cert.Subject.String())
		}
		return nil
	}
	return parent.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
}

// mustAlgorithmIdentifier encodes an AlgorithmIdentifier with absent or NULL
// parameters.
func mustAlgorithmIdentifier(oid asn1.ObjectIdentifier, null bool) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oid)
		if null {
			b.AddASN1NULL()
		}
	})
	return b.BytesOrPanic()
}

// certificateSigner is how CreateCertificate signs with a key: the
// AlgorithmIdentifier and the hash; hash 0 signs the message itself (EdDSA).
type certificateSigner struct {
	algorithm []byte
	hash      crypto.Hash
}

func signerFor(pub crypto.PublicKey) (*certificateSigner, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve == nil {
			break
		}
		switch k.Params().BitSize {
		case 256:
			return &certificateSigner{mustAlgorithmIdentifier(oidECDSAWithSHA256, false), crypto.SHA256}, nil
		case 384:
			return &certificateSigner{mustAlgorithmIdentifier(oidECDSAWithSHA384, false), crypto.SHA384}, nil
		case 521:
			return &certificateSigner{mustAlgorithmIdentifier(oidECDSAWithSHA512, false), crypto.SHA512}, nil
		}
	case ed448.PublicKey:
		return &certificateSigner{mustAlgorithmIdentifier(oidEd448, false), 0}, nil
	case ed25519.PublicKey:
		return &certificateSigner{mustAlgorithmIdentifier(oidEd25519, false), 0}, nil
	case *rsa.PublicKey:
		return &certificateSigner{mustAlgorithmIdentifier(oidSHA256WithRSA, true), crypto.SHA256}, nil
	}
	return nil, fmt.Errorf("%w: cannot sign a certificate with %s", errors.ErrInvalidSecurityConfig, describeKey(pub))
}

func (s *certificateSigner) sign(rand io.Reader, key crypto.Signer, msg []byte) ([]byte, error) {
	if s.hash == 0 {
		return key.Sign(rand, msg, crypto.Hash(0))
	}
	h := s.hash.New()
	h.Write(msg)
	return key.Sign(rand, h.Sum(nil), s.hash)
}

// CreateCertificate creates a certificate like x509.CreateCertificate, with
// the key types of ParseCertificate for the subject key pub and the issuer
// key priv in addition to those crypto/x509 supports.
//
// If neither key is a Brainpool or Ed448 key, it is x509.CreateCertificate.
// Otherwise the certificate is signed with ECDSA and SHA-256, SHA-384 or
// SHA-512 by the size of the issuer's curve, with PKCS #1 v1.5 and SHA-256
// for an RSA issuer, or with pure EdDSA; template.SignatureAlgorithm must be
// unset. A missing SubjectKeyId of a CA is derived from pub as
// x509.CreateCertificate does (RFC 7093 §2 method 1).
func CreateCertificate(rand io.Reader, template, parent *x509.Certificate, pub crypto.PublicKey, priv crypto.Signer) ([]byte, error) {
	if priv == nil || isNilKey(priv) {
		return nil, fmt.Errorf("%w: no issuer key", errors.ErrInvalidSecurityConfig)
	}
	if !isExtendedKey(pub) && !isExtendedKey(priv.Public()) {
		return x509.CreateCertificate(rand, template, parent, pub, priv)
	}
	if template.SignatureAlgorithm != x509.UnknownSignatureAlgorithm {
		return nil, fmt.Errorf("%w: the signature algorithm of a Brainpool or Ed448 certificate follows from the issuer key", errors.ErrInvalidSecurityConfig)
	}
	if parent.PublicKey != nil && !keysEqual(parent.PublicKey, priv.Public()) {
		return nil, fmt.Errorf("%w: the issuer key does not belong to the parent certificate", errors.ErrInvalidSecurityConfig)
	}
	signer, err := signerFor(priv.Public())
	if err != nil {
		return nil, err
	}
	spki, keyBits, err := marshalPublicKey(pub)
	if err != nil {
		return nil, err
	}

	// x509.CreateCertificate builds the TBSCertificate with a throwaway key
	// as subject and issuer key. Everything it encodes but the
	// SubjectPublicKeyInfo and the signature algorithm is kept.
	_, placeholder, err := ed25519.GenerateKey(rand)
	if err != nil {
		return nil, err
	}
	tmpl := *template
	tmpl.PublicKey = nil
	if len(tmpl.SubjectKeyId) == 0 && tmpl.IsCA {
		sum := sha256.Sum256(keyBits)
		tmpl.SubjectKeyId = sum[:20]
	}
	issuer := &tmpl
	if parent != template {
		p := *parent
		p.PublicKey = nil // the issuer key was checked above
		issuer = &p
	}
	der, err := x509.CreateCertificate(rand, &tmpl, issuer, placeholder.Public(), placeholder)
	if err != nil {
		return nil, err
	}
	parts, err := splitCertificate(der)
	if err != nil {
		return nil, err
	}
	parts.signature = signer.algorithm
	parts.spki = spki
	if parts.tbs, err = parts.joinTBS(); err != nil {
		return nil, err
	}
	sig, err := signer.sign(rand, priv, parts.tbs)
	if err != nil {
		return nil, err
	}
	parts.algorithm = signer.algorithm
	var b cryptobyte.Builder
	addBitString(&b, sig)
	if parts.value, err = b.Bytes(); err != nil {
		return nil, err
	}
	out, err := parts.join()
	if err != nil {
		return nil, err
	}

	// Like x509.CreateCertificate, check that the signer made a valid
	// signature.
	cert, err := ParseCertificate(out)
	if err != nil {
		return nil, err
	}
	if err := checkCertificateSignature(cert, &x509.Certificate{PublicKey: priv.Public()}); err != nil {
		return nil, fmt.Errorf("%w: signature over the certificate is invalid: %w", errors.ErrInvalidSecurityConfig, err)
	}
	return out, nil
}

func keysEqual(a, b crypto.PublicKey) bool {
	eq, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && eq.Equal(b)
}
