// SPDX-License-Identifier: MIT

package uapolicy

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"fmt"
	"io"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/otfabric/go-opcua/errors"
)

// Certificate revocation lists (RFC 5280 §5) issued by CAs with Brainpool or
// Ed448 keys. x509.ParseRevocationList parses them (an Ed448 signature
// algorithm is unknown to it), but (*x509.RevocationList).CheckSignatureFrom
// refuses an Ed448 issuer and x509.CreateRevocationList signs with neither
// key type.

// ParseRevocationList parses a DER encoded CRL like x509.ParseRevocationList,
// which accepts CRLs signed with ECDSA on the Brainpool curves and with Ed448
// (SignatureAlgorithm unknown to crypto/x509). Unlike the standard library it
// rejects trailing data. The signature is not verified: see
// CheckRevocationListSignature.
func ParseRevocationList(der []byte) (*x509.RevocationList, error) {
	in := cryptobyte.String(der)
	if !in.SkipASN1(cbasn1.SEQUENCE) || !in.Empty() {
		return nil, fmt.Errorf("%w: malformed CRL or trailing data", errors.ErrInvalidCertificate)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errors.ErrInvalidCertificate, err)
	}
	return crl, nil
}

// CheckRevocationListSignature verifies that issuer issued and signed the
// CRL, like (*x509.RevocationList).CheckSignatureFrom with the key types of
// ParseCertificate: the issuer name of the CRL is the subject of issuer, the
// authority key identifier of the CRL, if present, is the subject key
// identifier of issuer, if present; a version 3 issuer is a CA (basic
// constraints), and its key usage, if present, includes cRLSign (RFC 5280
// §6.3.3).
//
// An Ed448 signature has an algorithm identifier of exactly id-Ed448 without
// parameters (RFC 8410 §3) and is verified over the TBSCertList.
func CheckRevocationListSignature(crl *x509.RevocationList, issuer *x509.Certificate) error {
	if crl == nil || issuer == nil {
		return fmt.Errorf("%w: no CRL or no issuer", errors.ErrInvalidCertificate)
	}
	name := issuer.Subject.String()
	if !bytes.Equal(crl.RawIssuer, issuer.RawSubject) {
		return fmt.Errorf("%w: CRL is not issued by %q", errors.ErrInvalidCertificate, name)
	}
	if len(crl.AuthorityKeyId) > 0 && len(issuer.SubjectKeyId) > 0 && !bytes.Equal(crl.AuthorityKeyId, issuer.SubjectKeyId) {
		return fmt.Errorf("%w: CRL authority key identifier is not the key of %q", errors.ErrInvalidCertificate, name)
	}
	if issuer.Version == 3 && !issuer.BasicConstraintsValid || issuer.BasicConstraintsValid && !issuer.IsCA {
		return fmt.Errorf("%w: CRL issuer %q is not a CA", errors.ErrInvalidCertificate, name)
	}
	if issuer.KeyUsage != 0 && issuer.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return fmt.Errorf("%w: CRL issuer %q may not sign CRLs", errors.ErrInvalidCertificate, name)
	}
	return checkRevocationListKey(crl, issuer.PublicKey)
}

// checkRevocationListKey verifies the signature of a CRL with pub.
func checkRevocationListKey(crl *x509.RevocationList, pub crypto.PublicKey) error {
	if crl.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		parts, err := splitSigned(crl.Raw)
		if err != nil {
			return err
		}
		if !parts.signatureOID().Equal(oidEd448) {
			return fmt.Errorf("%w: unsupported signature algorithm of the CRL", errors.ErrInvalidCertificate)
		}
		// x509.ParseRevocationList checked that the signature field of the
		// TBSCertList is the same.
		return verifyEd448(pub, parts.algorithm, parts.tbs, crl.Signature, "CRL")
	}
	// (*x509.Certificate).CheckSignature only looks at the key: it verifies
	// ECDSA signatures on the Brainpool curves, too.
	if err := (&x509.Certificate{PublicKey: pub}).CheckSignature(crl.SignatureAlgorithm, crl.RawTBSRevocationList, crl.Signature); err != nil {
		return fmt.Errorf("%w: CRL signature: %w", errors.ErrInvalidCertificate, err)
	}
	return nil
}

// CreateRevocationList creates a CRL like x509.CreateRevocationList, also for
// an issuer with an ECDSA key on brainpoolP256r1 or brainpoolP384r1 or with
// an Ed448 key.
//
// For any other key it is x509.CreateRevocationList. A Brainpool CRL is signed
// with ECDSA and SHA-256 or SHA-384 by the size of the curve, an Ed448 CRL
// with pure Ed448; template.SignatureAlgorithm must be unset. The issuer
// needs the cRLSign key usage and a subject key identifier, and a public key
// in issuer, if set, must be the key of priv. The signature is verified
// before the CRL is returned.
func CreateRevocationList(rand io.Reader, template *x509.RevocationList, issuer *x509.Certificate, priv crypto.Signer) ([]byte, error) {
	if priv == nil || isNilKey(priv) {
		return nil, fmt.Errorf("%w: no CRL issuer key", errors.ErrInvalidSecurityConfig)
	}
	if template == nil || issuer == nil {
		return nil, fmt.Errorf("%w: no CRL template or issuer", errors.ErrInvalidSecurityConfig)
	}
	if !isExtendedKey(priv.Public()) {
		return x509.CreateRevocationList(rand, template, issuer, priv)
	}
	if template.SignatureAlgorithm != x509.UnknownSignatureAlgorithm {
		return nil, fmt.Errorf("%w: the signature algorithm of a Brainpool or Ed448 CRL follows from the issuer key", errors.ErrInvalidSecurityConfig)
	}
	if issuer.PublicKey != nil && !keysEqual(issuer.PublicKey, priv.Public()) {
		return nil, fmt.Errorf("%w: the CRL issuer key does not belong to the issuer certificate", errors.ErrInvalidSecurityConfig)
	}
	signer, err := signerFor(priv.Public())
	if err != nil {
		return nil, err
	}

	// x509.CreateRevocationList encodes the TBSCertList with a throwaway key;
	// the signature algorithm and the signature are replaced.
	_, placeholder, err := ed25519.GenerateKey(rand)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateRevocationList(rand, template, issuer, placeholder)
	if err != nil {
		return nil, err
	}
	parts, err := splitSigned(der)
	if err != nil {
		return nil, err
	}
	// TBSCertList: version (always present: crypto/x509 writes v2),
	// signature, and the rest.
	var (
		in        = cryptobyte.String(parts.tbs)
		tbs, head cryptobyte.String
	)
	if !in.ReadASN1(&tbs, cbasn1.SEQUENCE) || !tbs.ReadASN1Element(&head, cbasn1.INTEGER) || !tbs.SkipASN1(cbasn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: malformed TBSCertList", errors.ErrInvalidSecurityConfig)
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(head)
		b.AddBytes(signer.algorithm)
		b.AddBytes(tbs)
	})
	if parts.tbs, err = b.Bytes(); err != nil {
		return nil, err
	}
	if err := parts.resign(rand, signer, priv); err != nil {
		return nil, err
	}
	out, err := parts.join()
	if err != nil {
		return nil, err
	}

	crl, err := ParseRevocationList(out)
	if err != nil {
		return nil, err
	}
	if err := checkRevocationListKey(crl, priv.Public()); err != nil {
		return nil, fmt.Errorf("%w: signature over the CRL is invalid: %w", errors.ErrInvalidSecurityConfig, err)
	}
	return out, nil
}
