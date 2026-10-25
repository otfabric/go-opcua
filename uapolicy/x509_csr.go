// SPDX-License-Identifier: MIT

package uapolicy

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/asn1"
	stderrors "errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/ed448"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/otfabric/go-opcua/errors"
)

// Certificate signing requests (PKCS #10, RFC 2986) with Brainpool and Ed448
// keys, which crypto/x509 neither creates nor parses (Part 12 §7.10.8
// CreateSigningRequest of a Push Management server with a Brainpool or
// Curve448 certificate type). The same approach as for certificates (see
// x509_ext.go): the standard library encodes and parses everything but the
// SubjectPublicKeyInfo and the signature algorithm.

// signedParts are the elements of a DER encoded SIGNED{} structure (X.509
// SIGNED macro: a certificate, a CRL or a certification request), each with
// its tag and length.
type signedParts struct {
	tbs       []byte // the signed data: TBSCertList, CertificationRequestInfo
	algorithm []byte // the signatureAlgorithm AlgorithmIdentifier
	value     []byte // the signature BIT STRING
}

// splitSigned splits a SIGNED{} structure; trailing data is an error.
func splitSigned(der []byte) (*signedParts, error) {
	var (
		in    = cryptobyte.String(der)
		outer cryptobyte.String
		p     signedParts
		elem  cryptobyte.String
	)
	if !in.ReadASN1(&outer, cbasn1.SEQUENCE) || !in.Empty() {
		return nil, fmt.Errorf("%w: malformed signed structure", errors.ErrInvalidCertificate)
	}
	if !outer.ReadASN1Element(&elem, cbasn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: malformed signed data", errors.ErrInvalidCertificate)
	}
	p.tbs = elem
	if !outer.ReadASN1Element(&elem, cbasn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: malformed signature algorithm", errors.ErrInvalidCertificate)
	}
	p.algorithm = elem
	if !outer.ReadASN1Element(&elem, cbasn1.BIT_STRING) || !outer.Empty() {
		return nil, fmt.Errorf("%w: malformed signature", errors.ErrInvalidCertificate)
	}
	p.value = elem
	return &p, nil
}

// join encodes the SIGNED{} structure of the parts.
func (p *signedParts) join() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(p.tbs)
		b.AddBytes(p.algorithm)
		b.AddBytes(p.value)
	})
	return b.Bytes()
}

// signatureOID returns the OID of the signatureAlgorithm, or nil.
func (p *signedParts) signatureOID() asn1.ObjectIdentifier {
	in := cryptobyte.String(p.algorithm)
	var algo cryptobyte.String
	var oid asn1.ObjectIdentifier
	if !in.ReadASN1(&algo, cbasn1.SEQUENCE) || !algo.ReadASN1ObjectIdentifier(&oid) {
		return nil
	}
	return oid
}

// resign signs parts.tbs with priv and sets the signature algorithm and value.
func (p *signedParts) resign(rand io.Reader, signer *certificateSigner, priv crypto.Signer) error {
	sig, err := signer.sign(rand, priv, p.tbs)
	if err != nil {
		return err
	}
	p.algorithm = signer.algorithm
	var b cryptobyte.Builder
	addBitString(&b, sig)
	p.value, err = b.Bytes()
	return err
}

// verifyEd448 verifies the Ed448 signature of a SIGNED{} structure: the
// algorithm identifier is exactly id-Ed448 without parameters (RFC 8410 §3),
// the signature has the size of an Ed448 signature.
func verifyEd448(pub crypto.PublicKey, algorithm, tbs, sig []byte, what string) error {
	key, ok := pub.(ed448.PublicKey)
	if !ok || len(key) != ed448.PublicKeySize {
		return fmt.Errorf("%w: an Ed448 signature needs an Ed448 key", errors.ErrInvalidCertificate)
	}
	if !bytes.Equal(algorithm, mustAlgorithmIdentifier(oidEd448, false)) {
		return fmt.Errorf("%w: malformed Ed448 signature algorithm", errors.ErrInvalidCertificate)
	}
	if len(sig) != ed448.SignatureSize || !ed448.Verify(key, tbs, sig, "") {
		return fmt.Errorf("%w: Ed448 signature of the %s is invalid", errors.ErrInvalidCertificate, what)
	}
	return nil
}

// requestInfoParts are the elements of a CertificationRequestInfo (RFC 2986
// §4.1).
type requestInfoParts struct {
	head []byte // version and subject
	spki []byte // subjectPKInfo
	tail []byte // attributes
}

func splitRequestInfo(der []byte) (*requestInfoParts, error) {
	var (
		in   = cryptobyte.String(der)
		info cryptobyte.String
		elem cryptobyte.String
	)
	if !in.ReadASN1(&info, cbasn1.SEQUENCE) || !in.Empty() {
		return nil, fmt.Errorf("%w: malformed CertificationRequestInfo", errors.ErrInvalidCertificate)
	}
	start := info
	if !info.SkipASN1(cbasn1.INTEGER) || !info.SkipASN1(cbasn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: malformed CertificationRequestInfo", errors.ErrInvalidCertificate)
	}
	head := start[:len(start)-len(info)]
	if !info.ReadASN1Element(&elem, cbasn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: malformed SubjectPublicKeyInfo", errors.ErrInvalidCertificate)
	}
	return &requestInfoParts{head: head, spki: elem, tail: info}, nil
}

func (r *requestInfoParts) join() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(r.head)
		b.AddBytes(r.spki)
		b.AddBytes(r.tail)
	})
	return b.Bytes()
}

// CreateCertificateRequest creates a PKCS #10 certificate signing request
// like x509.CreateCertificateRequest, also for an ECDSA key on
// brainpoolP256r1 or brainpoolP384r1 and for an Ed448 key.
//
// For any other key it is x509.CreateCertificateRequest. A Brainpool request
// is signed with ECDSA and SHA-256 or SHA-384 by the size of the curve, an
// Ed448 request with pure Ed448; template.SignatureAlgorithm must be unset.
// The signature is verified before the request is returned.
func CreateCertificateRequest(rand io.Reader, template *x509.CertificateRequest, priv crypto.Signer) ([]byte, error) {
	if priv == nil || isNilKey(priv) {
		return nil, fmt.Errorf("%w: no key for the certificate request", errors.ErrInvalidSecurityConfig)
	}
	if template == nil {
		return nil, fmt.Errorf("%w: no certificate request template", errors.ErrInvalidSecurityConfig)
	}
	if !isExtendedKey(priv.Public()) {
		return x509.CreateCertificateRequest(rand, template, priv)
	}
	if template.SignatureAlgorithm != x509.UnknownSignatureAlgorithm {
		return nil, fmt.Errorf("%w: the signature algorithm of a Brainpool or Ed448 request follows from the key", errors.ErrInvalidSecurityConfig)
	}
	signer, err := signerFor(priv.Public())
	if err != nil {
		return nil, err
	}
	spki, _, err := marshalPublicKey(priv.Public())
	if err != nil {
		return nil, err
	}

	// x509.CreateCertificateRequest encodes subject and attributes with a
	// throwaway key; key and signature are replaced.
	_, placeholder, err := ed25519.GenerateKey(rand)
	if err != nil {
		return nil, err
	}
	tmpl := *template
	der, err := x509.CreateCertificateRequest(rand, &tmpl, placeholder)
	if err != nil {
		return nil, err
	}
	parts, err := splitSigned(der)
	if err != nil {
		return nil, err
	}
	info, err := splitRequestInfo(parts.tbs)
	if err != nil {
		return nil, err
	}
	info.spki = spki
	if parts.tbs, err = info.join(); err != nil {
		return nil, err
	}
	if err := parts.resign(rand, signer, priv); err != nil {
		return nil, err
	}
	out, err := parts.join()
	if err != nil {
		return nil, err
	}

	csr, err := ParseCertificateRequest(out)
	if err != nil {
		return nil, err
	}
	if err := CheckCertificateRequestSignature(csr); err != nil {
		return nil, fmt.Errorf("%w: signature over the certificate request is invalid: %w", errors.ErrInvalidSecurityConfig, err)
	}
	return out, nil
}

// ParseCertificateRequest parses a single DER encoded PKCS #10 certificate
// signing request like x509.ParseCertificateRequest, with the key types of
// ParseCertificate: PublicKey is an *ecdsa.PublicKey on a Brainpool curve
// (PublicKeyAlgorithm x509.ECDSA) or an ed448.PublicKey (PublicKeyAlgorithm
// and, for an Ed448 signature, SignatureAlgorithm unknown to crypto/x509).
// Trailing data is an error. The signature is not verified: see
// CheckCertificateRequestSignature.
func ParseCertificateRequest(der []byte) (*x509.CertificateRequest, error) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		bp, bpErr := parseBrainpoolCertificateRequest(der)
		if bpErr == nil {
			return bp, nil
		}
		if stderrors.Is(bpErr, errNotExtended) {
			return nil, fmt.Errorf("%w: %w", errors.ErrInvalidCertificate, err)
		}
		return nil, bpErr
	}
	if csr.PublicKeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
		key, err := parseExtendedPublicKey(csr.RawSubjectPublicKeyInfo)
		switch {
		case err == nil:
			csr.PublicKey = key
		case !stderrors.Is(err, errNotExtended):
			return nil, err
		}
	}
	return csr, nil
}

// parseBrainpoolCertificateRequest parses a request with a Brainpool key,
// which x509.ParseCertificateRequest rejects, as parseBrainpoolCertificate
// does for a certificate.
func parseBrainpoolCertificateRequest(der []byte) (*x509.CertificateRequest, error) {
	parts, err := splitSigned(der)
	if err != nil {
		return nil, errNotExtended // keep the error of x509.ParseCertificateRequest
	}
	info, err := splitRequestInfo(parts.tbs)
	if err != nil {
		return nil, errNotExtended
	}
	key, err := parseExtendedPublicKey(info.spki)
	if err != nil {
		return nil, err
	}
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, errNotExtended
	}
	originalTBS, originalSPKI := parts.tbs, info.spki
	if info.spki, err = placeholderSPKI(pub); err != nil {
		return nil, err
	}
	if parts.tbs, err = info.join(); err != nil {
		return nil, err
	}
	patched, err := parts.join()
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(patched)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errors.ErrInvalidCertificate, err)
	}
	csr.Raw = bytes.Clone(der)
	csr.RawTBSCertificateRequest = bytes.Clone(originalTBS)
	csr.RawSubjectPublicKeyInfo = bytes.Clone(originalSPKI)
	csr.PublicKeyAlgorithm = x509.ECDSA
	csr.PublicKey = pub
	return csr, nil
}

// placeholderSPKI returns a SubjectPublicKeyInfo for a Brainpool key whose
// algorithm is the OID of the curve: crypto/x509 does not know it and leaves
// the key alone.
func placeholderSPKI(pub *ecdsa.PublicKey) ([]byte, error) {
	oid, _ := brainpoolOID(pub.Curve)
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oid)
		})
		addBitString(b, marshalECPoint(pub))
	})
	return b.Bytes()
}

// CheckCertificateRequestSignature verifies the self-signature of a
// certificate signing request parsed with ParseCertificateRequest, with the
// key types of crypto/x509 and Brainpool and Ed448 keys.
func CheckCertificateRequestSignature(csr *x509.CertificateRequest) error {
	if csr == nil {
		return fmt.Errorf("%w: no certificate request", errors.ErrInvalidCertificate)
	}
	if csr.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		parts, err := splitSigned(csr.Raw)
		if err != nil {
			return err
		}
		if !parts.signatureOID().Equal(oidEd448) {
			return fmt.Errorf("%w: unsupported signature algorithm of the certificate request", errors.ErrInvalidCertificate)
		}
		return verifyEd448(csr.PublicKey, parts.algorithm, parts.tbs, csr.Signature, "certificate request")
	}
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("%w: %w", errors.ErrInvalidCertificate, err)
	}
	return nil
}
