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
	b := &ed448Builder{
		intermediates: dedupCertificates(intermediates),
		anchors:       anchors,
		now:           now,
		sigs:          make(map[sigEdge]error),
	}
	return b.build([]*x509.Certificate{leaf})
}

// Bounds of the work verifyEd448Chain does for one certificate. Like
// crypto/x509, which stops after 100 signature checks, they keep a set of
// certificates that issue each other from turning the search for a path
// into a combinatorial one.
const (
	// maxChainSignatureChecks bounds the signatures verified.
	maxChainSignatureChecks = 100
	// maxChainCandidates bounds the issuer candidates looked at.
	maxChainCandidates = 10000
)

// errChainWork reports a search for a chain that went over its bounds.
var errChainWork = fmt.Errorf("%w: too many candidate certificates to build a chain", errors.ErrInvalidCertificate)

// ed448Builder searches a path from a leaf to a trust anchor.
type ed448Builder struct {
	intermediates []*x509.Certificate
	anchors       []*x509.Certificate
	now           time.Time

	// sigs holds the outcome of every signature check: a signature is
	// verified once per certificate and issuer key, however many paths
	// or certificates with that key lead to it.
	sigs       map[sigEdge]error
	sigChecks  int
	candidates int
}

// sigEdge is a certificate and the public key of an issuer.
type sigEdge struct {
	cert string // raw certificate
	key  string // raw SubjectPublicKeyInfo of the issuer
}

// dedupCertificates returns certs without nil entries and duplicates.
func dedupCertificates(certs []*x509.Certificate) []*x509.Certificate {
	out := make([]*x509.Certificate, 0, len(certs))
	seen := make(map[string]struct{}, len(certs))
	for _, c := range certs {
		if c == nil {
			continue
		}
		if _, ok := seen[string(c.Raw)]; ok {
			continue
		}
		seen[string(c.Raw)] = struct{}{}
		out = append(out, c)
	}
	return out
}

// build extends chain, which runs from the leaf to the certificate whose
// issuer is searched, to a trust anchor.
func (b *ed448Builder) build(chain []*x509.Certificate) error {
	c := chain[len(chain)-1]
	err := fmt.Errorf("%w: certificate %q is signed by an unknown authority", errors.ErrInvalidCertificate, c.Subject.String())
	if len(chain) >= maxChainLength {
		return fmt.Errorf("%w: certificate chain is too long", errors.ErrInvalidCertificate)
	}
	for _, a := range b.anchors {
		if a == nil {
			continue
		}
		e := b.checkIssuer(chain, a)
		if e == nil {
			return nil
		}
		if e == errChainWork {
			return e
		}
		if e != errNotIssuer {
			err = e
		}
	}
	for _, ic := range b.intermediates {
		if inChain(chain, ic) {
			continue
		}
		e := b.checkIssuer(chain, ic)
		if e == nil {
			e = b.build(append(chain[:len(chain):len(chain)], ic))
			if e == nil {
				return nil
			}
		}
		if e == errChainWork {
			return e
		}
		if e != errNotIssuer {
			err = e
		}
	}
	return err
}

// checkIssuer is the package's checkIssuer within the bounds of the
// builder, with the signature checks remembered.
func (b *ed448Builder) checkIssuer(chain []*x509.Certificate, parent *x509.Certificate) error {
	c := chain[len(chain)-1]
	if !bytes.Equal(c.RawIssuer, parent.RawSubject) {
		return errNotIssuer
	}
	b.candidates++
	if b.candidates > maxChainCandidates {
		return errChainWork
	}
	return checkIssuer(chain, parent, b.now, func(c, parent *x509.Certificate) error {
		edge := sigEdge{cert: string(c.Raw), key: string(parent.RawSubjectPublicKeyInfo)}
		if err, ok := b.sigs[edge]; ok {
			return err
		}
		b.sigChecks++
		if b.sigChecks > maxChainSignatureChecks {
			return errChainWork
		}
		err := checkCertificateSignature(c, parent)
		b.sigs[edge] = err
		return err
	})
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
// and may do so; checkSig verifies the signature.
func checkIssuer(chain []*x509.Certificate, parent *x509.Certificate, now time.Time, checkSig func(c, parent *x509.Certificate) error) error {
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
	return checkSig(c, parent)
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
