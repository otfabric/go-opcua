// SPDX-License-Identifier: MIT

package uapolicy

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"errors"
)

// leafCertificate parses a DER blob that may contain a certificate chain (a leaf
// certificate followed by one or more intermediate certificates, as presented by
// some servers such as Siemens WinCC Unified Runtime) and returns the leaf
// certificate. A blob containing a single certificate is returned as that
// certificate. x509.ParseCertificate rejects trailing data, so a chain must be
// parsed with x509.ParseCertificates.
func leafCertificate(c []byte) (*x509.Certificate, error) {
	certs, err := x509.ParseCertificates(c)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, errors.New("uapolicy: no certificate found in DER blob")
	}
	// The leaf (application instance) certificate is always first in an OPC UA
	// SenderCertificate / ServerCertificate chain.
	return certs[0], nil
}

// Thumbprint returns the SHA-1 thumbprint of the leaf certificate in a
// DER-encoded certificate (or certificate chain). The thumbprint identifies the
// application instance certificate whose private key the peer holds, so it must
// be computed over the leaf only — not the whole chain. If the blob cannot be
// parsed as a certificate, it falls back to hashing the raw bytes to preserve
// the previous behavior.
func Thumbprint(c []byte) []byte {
	der := c
	if leaf, err := leafCertificate(c); err == nil {
		der = leaf.Raw
	}
	thumbprint := sha1.Sum(der)
	return thumbprint[:]
}

// PublicKey returns the RSA PublicKey from the leaf of a DER-encoded certificate
// (or certificate chain).
func PublicKey(c []byte) (*rsa.PublicKey, error) {
	leaf, err := leafCertificate(c)
	if err != nil {
		return nil, err
	}
	key, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("uapolicy: certificate does not contain an RSA public key")
	}
	return key, nil
}
