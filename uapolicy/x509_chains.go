// SPDX-License-Identifier: MIT

package uapolicy

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/otfabric/go-opcua/errors"
)

// maxChains bounds the number of chains VerifyCertificateChains returns for
// a chain with Ed448 signatures.
const maxChains = 16

// VerifyCertificateChains verifies certs like VerifyCertificate and returns
// the verified chains, each running from certs[0] to a trust anchor. Every
// certificate in a chain is linked to the next one by a verified signature,
// so a check that has to follow the certification path, such as the
// revocation of the issuers (Part 4 §6.1.3), can use them.
func VerifyCertificateChains(certs []*x509.Certificate, roots *x509.CertPool, anchors []*x509.Certificate) ([][]*x509.Certificate, error) {
	if len(certs) == 0 || certs[0] == nil {
		return nil, fmt.Errorf("%w: no certificate", errors.ErrInvalidCertificate)
	}
	for _, c := range certs {
		if hasEd448Signature(c) {
			return ed448Chains(certs[0], certs[1:], anchors, time.Now())
		}
	}
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	if roots == nil {
		roots = x509.NewCertPool() // never the system roots by accident
	}
	return certs[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
}

// ed448Chains returns the chains verifyEd448Chain accepts.
func ed448Chains(leaf *x509.Certificate, intermediates, anchors []*x509.Certificate, now time.Time) ([][]*x509.Certificate, error) {
	if err := checkCertificateValidity(leaf, now); err != nil {
		return nil, err
	}
	for _, a := range anchors {
		if a != nil && a.Equal(leaf) {
			return [][]*x509.Certificate{{leaf}}, nil
		}
	}
	b := &ed448Builder{
		intermediates: dedupCertificates(intermediates),
		anchors:       anchors,
		now:           now,
		sigs:          make(map[sigEdge]error),
	}
	var chains [][]*x509.Certificate
	err := b.collect([]*x509.Certificate{leaf}, &chains)
	if len(chains) > 0 {
		return chains, nil
	}
	return nil, err
}

// collect extends chain to every trust anchor it reaches, as build does,
// within the same bounds, and adds the complete chains to out.
func (b *ed448Builder) collect(chain []*x509.Certificate, out *[][]*x509.Certificate) error {
	c := chain[len(chain)-1]
	err := fmt.Errorf("%w: certificate %q is signed by an unknown authority", errors.ErrInvalidCertificate, c.Subject.String())
	if len(chain) >= maxChainLength {
		return fmt.Errorf("%w: certificate chain is too long", errors.ErrInvalidCertificate)
	}
	for _, a := range b.anchors {
		if a == nil || len(*out) >= maxChains {
			continue
		}
		e := b.checkIssuer(chain, a)
		if e == nil {
			*out = append(*out, append(chain[:len(chain):len(chain)], a))
			continue
		}
		if e == errChainWork {
			return e
		}
		if e != errNotIssuer {
			err = e
		}
	}
	for _, ic := range b.intermediates {
		if inChain(chain, ic) || len(*out) >= maxChains {
			continue
		}
		e := b.checkIssuer(chain, ic)
		if e == nil {
			e = b.collect(append(chain[:len(chain):len(chain)], ic), out)
		}
		if e == errChainWork {
			return e
		}
		if e != nil && e != errNotIssuer {
			err = e
		}
	}
	if len(*out) > 0 {
		return nil
	}
	return err
}
