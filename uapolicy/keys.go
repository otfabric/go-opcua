// SPDX-License-Identifier: MIT

package uapolicy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
)

// CertificatePublicKey returns the public key of the leaf of a DER-encoded
// certificate (or certificate chain), whatever its type: *rsa.PublicKey,
// *ecdsa.PublicKey or ed25519.PublicKey.
//
// The standard library validates an elliptic curve key while it parses the
// certificate: a point that is not on the named curve is rejected.
func CertificatePublicKey(c []byte) (crypto.PublicKey, error) {
	leaf, err := leafCertificate(c)
	if err != nil {
		return nil, err
	}
	switch key := leaf.PublicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		return key, nil
	default:
		return nil, fmt.Errorf("%w: unsupported public key type %T", errors.ErrInvalidCertificate, leaf.PublicKey)
	}
}

// CheckCertificate reports whether the application instance certificate can
// be used with the security policy: an RSA policy needs an RSA key, an ECC
// policy a key on one of the curves the policy permits: an ECDSA key on
// nistP256 or nistP384 for ECC_nistP256, ECC_nistP256_AesGcm and
// ECC_nistP256_ChaChaPoly, on nistP384 for ECC_nistP384, and an Ed25519 key
// for ECC_curve25519. Every certificate is acceptable for the None policy,
// which does not use it.
//
// It checks the key type only. Trust and validity are the business of the
// certificate validators.
func CheckCertificate(uri string, c []byte) error {
	key, err := CertificatePublicKey(c)
	if err != nil {
		return err
	}
	return CheckPublicKey(uri, key)
}

// CheckPublicKey reports whether a public key can be used as an application
// instance key with the security policy. See CheckCertificate.
func CheckPublicKey(uri string, key crypto.PublicKey) error {
	p, ok := policies[uri]
	if !ok {
		return fmt.Errorf("%w: %s", errors.ErrUnsupportedSecurityPolicy, uri)
	}
	if uri == ua.SecurityPolicyURINone {
		return nil
	}
	_, err := p.asymmetric(nil, key)
	return err
}

// CertificateHash returns the hash that stands for a certificate in the
// channel bound signatures of a security policy with SecureChannelEnhancements
// (Part 4 §6.1.8): the SHA-256 hash of the DER encoding of the leaf of the
// certificate (or certificate chain). A missing certificate has an empty hash.
func CertificateHash(uri string, c []byte) ([]byte, error) {
	p, ok := eccPolicies[uri]
	if !ok || !p.enhancements {
		return nil, fmt.Errorf("%w: %s has no channel bound signatures", errors.ErrUnsupportedSecurityPolicy, uri)
	}
	if len(c) == 0 {
		return nil, nil
	}
	leaf, err := leafCertificate(c)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errors.ErrInvalidCertificate, err)
	}
	h := p.hash.New()
	h.Write(leaf.Raw)
	return h.Sum(nil), nil
}

// ParsePrivateKey parses the private key of an application instance or user
// certificate. The data is either PEM or DER encoded; the supported formats
// are PKCS #8 ("PRIVATE KEY": RSA, ECDSA and Ed25519), PKCS #1 ("RSA PRIVATE
// KEY") and SEC 1 ("EC PRIVATE KEY").
//
// The returned key is an *rsa.PrivateKey, an *ecdsa.PrivateKey or an
// ed25519.PrivateKey.
func ParsePrivateKey(data []byte) (crypto.Signer, error) {
	if block, _ := pem.Decode(data); block != nil {
		switch block.Type {
		case "RSA PRIVATE KEY":
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("%w: %w", errors.ErrInvalidPrivateKey, err)
			}
			return key, nil
		case "EC PRIVATE KEY":
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("%w: %w", errors.ErrInvalidPrivateKey, err)
			}
			return key, nil
		case "PRIVATE KEY":
			return parsePKCS8(block.Bytes)
		default:
			return nil, fmt.Errorf("%w: unsupported PEM block type %q", errors.ErrInvalidPrivateKey, block.Type)
		}
	}

	// Raw DER: the three formats are distinct ASN.1 structures, so at most
	// one of them parses.
	if key, err := x509.ParsePKCS1PrivateKey(data); err == nil {
		return key, nil
	}
	if key, err := parsePKCS8(data); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(data); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("%w: not a PKCS #1, PKCS #8 or SEC 1 private key", errors.ErrInvalidPrivateKey)
}

func parsePKCS8(der []byte) (crypto.Signer, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errors.ErrInvalidPrivateKey, err)
	}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return k, nil
	case *ecdsa.PrivateKey:
		return k, nil
	case ed25519.PrivateKey:
		return k, nil
	default:
		return nil, fmt.Errorf("%w: unsupported PKCS #8 key type %T", errors.ErrInvalidPrivateKey, key)
	}
}

// KeyMatchesCertificate reports whether key is the private key of the leaf of
// the DER-encoded certificate.
func KeyMatchesCertificate(key crypto.Signer, c []byte) bool {
	if isNilKey(key) {
		return false
	}
	pub, err := CertificatePublicKey(c)
	if err != nil {
		return false
	}
	type equaler interface{ Equal(crypto.PublicKey) bool }
	eq, ok := pub.(equaler)
	return ok && eq.Equal(key.Public())
}
