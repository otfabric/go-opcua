// SPDX-License-Identifier: MIT

package uapolicy

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/otfabric/go-opcua/errors"
)

// maxChainLength bounds the chains verifyEd448Chain builds: leaf,
// intermediates and trust anchor.
const maxChainLength = 8

var oidExtensionNameConstraints = asn1.ObjectIdentifier{2, 5, 29, 30}

// VerifyCertificate verifies a certificate chain as an OPC UA application
// does (Part 4 §6.1.3): certs[0] is the certificate to verify, the others are
// candidate intermediates. Certificates are parsed with ParseCertificate.
//
// roots are the trust anchors for (*x509.Certificate).Verify, which verifies
// every chain without Ed448 signatures, those with Brainpool keys included.
// crypto/x509 cannot verify an Ed448 signature: a chain in which a
// certificate is signed with Ed448 is verified against anchors instead,
// which should hold the same certificates as roots (system roots aside, which
// never carry Ed448 keys), with these rules of RFC 5280 §6.1: every
// certificate is valid at the current time and has no unknown critical
// extension; every issuer is a CA (basicConstraints) whose key usage, if
// present, includes keyCertSign and whose path length constraint holds; names
// chain issuer to subject and key identifiers match where both are present.
// A CA with name constraints is not accepted on that path. A certificate that
// is itself a trust anchor is trusted.
//
// Any extended key usage is accepted.
func VerifyCertificate(certs []*x509.Certificate, roots *x509.CertPool, anchors []*x509.Certificate) error {
	if len(certs) == 0 || certs[0] == nil {
		return fmt.Errorf("%w: no certificate", errors.ErrInvalidCertificate)
	}
	ed448Signed := false
	for _, c := range certs {
		if hasEd448Signature(c) {
			ed448Signed = true
		}
	}
	if ed448Signed {
		return verifyEd448Chain(certs[0], certs[1:], anchors, time.Now())
	}
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	if roots == nil {
		roots = x509.NewCertPool() // never the system roots by accident
	}
	_, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}

func verifyEd448Chain(leaf *x509.Certificate, intermediates, anchors []*x509.Certificate, now time.Time) error {
	if err := checkCertificateValidity(leaf, now); err != nil {
		return err
	}
	for _, a := range anchors {
		if a != nil && a.Equal(leaf) {
			return nil
		}
	}
	return buildEd448Chain([]*x509.Certificate{leaf}, intermediates, anchors, now)
}

// buildEd448Chain extends chain, which runs from the leaf to the certificate
// whose issuer is searched, to a trust anchor.
func buildEd448Chain(chain, intermediates, anchors []*x509.Certificate, now time.Time) error {
	c := chain[len(chain)-1]
	err := fmt.Errorf("%w: certificate %q is signed by an unknown authority", errors.ErrInvalidCertificate, c.Subject.String())
	if len(chain) >= maxChainLength {
		return fmt.Errorf("%w: certificate chain is too long", errors.ErrInvalidCertificate)
	}
	for _, a := range anchors {
		if a == nil {
			continue
		}
		e := checkIssuer(chain, a, now)
		if e == nil {
			return nil
		}
		if e != errNotIssuer {
			err = e
		}
	}
	for _, ic := range intermediates {
		if ic == nil || inChain(chain, ic) {
			continue
		}
		e := checkIssuer(chain, ic, now)
		if e == nil {
			e = buildEd448Chain(append(chain[:len(chain):len(chain)], ic), intermediates, anchors, now)
			if e == nil {
				return nil
			}
		}
		if e != errNotIssuer {
			err = e
		}
	}
	return err
}

func inChain(chain []*x509.Certificate, c *x509.Certificate) bool {
	for _, x := range chain {
		if x.Equal(c) {
			return true
		}
	}
	return false
}

// errNotIssuer reports a candidate whose names or key identifiers do not fit.
var errNotIssuer = fmt.Errorf("%w: not the issuer", errors.ErrInvalidCertificate)

// checkIssuer reports whether parent issued the last certificate of chain
// and may do so.
func checkIssuer(chain []*x509.Certificate, parent *x509.Certificate, now time.Time) error {
	c := chain[len(chain)-1]
	if !bytes.Equal(c.RawIssuer, parent.RawSubject) {
		return errNotIssuer
	}
	if len(c.AuthorityKeyId) > 0 && len(parent.SubjectKeyId) > 0 && !bytes.Equal(c.AuthorityKeyId, parent.SubjectKeyId) {
		return errNotIssuer
	}
	if err := checkCertificateValidity(parent, now); err != nil {
		return err
	}
	name := parent.Subject.String()
	if !parent.BasicConstraintsValid || !parent.IsCA {
		return fmt.Errorf("%w: issuer %q is not a CA", errors.ErrInvalidCertificate, name)
	}
	if parent.KeyUsage != 0 && parent.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("%w: issuer %q may not sign certificates", errors.ErrInvalidCertificate, name)
	}
	// The intermediates below parent: the chain without its leaf.
	if parent.MaxPathLen >= 0 && len(chain)-1 > parent.MaxPathLen {
		return fmt.Errorf("%w: path length constraint of %q exceeded", errors.ErrInvalidCertificate, name)
	}
	for _, ext := range parent.Extensions {
		if ext.Id.Equal(oidExtensionNameConstraints) {
			return fmt.Errorf("%w: name constraints of %q are not supported for Ed448 chains", errors.ErrInvalidCertificate, name)
		}
	}
	return checkCertificateSignature(c, parent)
}

func checkCertificateValidity(c *x509.Certificate, now time.Time) error {
	if now.Before(c.NotBefore) || now.After(c.NotAfter) {
		return fmt.Errorf("%w: certificate %q is not valid at %s", errors.ErrInvalidCertificate, c.Subject.String(), now.Format(time.RFC3339))
	}
	if len(c.UnhandledCriticalExtensions) > 0 {
		return fmt.Errorf("%w: certificate %q has an unknown critical extension", errors.ErrInvalidCertificate, c.Subject.String())
	}
	return nil
}
