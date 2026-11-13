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
	var chains [][]*x509.Certificate
	err := collectEd448Chains([]*x509.Certificate{leaf}, intermediates, anchors, now, &chains)
	if len(chains) > 0 {
		return chains, nil
	}
	return nil, err
}

// collectEd448Chains extends chain to every trust anchor it reaches, as
// buildEd448Chain does, and adds the complete chains to out.
func collectEd448Chains(chain, intermediates, anchors []*x509.Certificate, now time.Time, out *[][]*x509.Certificate) error {
	c := chain[len(chain)-1]
	err := fmt.Errorf("%w: certificate %q is signed by an unknown authority", errors.ErrInvalidCertificate, c.Subject.String())
	if len(chain) >= maxChainLength {
		return fmt.Errorf("%w: certificate chain is too long", errors.ErrInvalidCertificate)
	}
	for _, a := range anchors {
		if a == nil || len(*out) >= maxChains {
			continue
		}
		e := checkIssuer(chain, a, now)
		if e == nil {
			*out = append(*out, append(chain[:len(chain):len(chain)], a))
			continue
		}
		if e != errNotIssuer {
			err = e
		}
	}
	for _, ic := range intermediates {
		if ic == nil || inChain(chain, ic) || len(*out) >= maxChains {
			continue
		}
		e := checkIssuer(chain, ic, now)
		if e == nil {
			e = collectEd448Chains(append(chain[:len(chain):len(chain)], ic), intermediates, anchors, now, out)
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
