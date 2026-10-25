// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"crypto/x509"
	stderrors "errors"
	"slices"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

const (
	// defaultMaxTrustListSize is the MaxTrustListSize of a server that does
	// not set one: the most bytes the encoded TrustListDataType may have.
	defaultMaxTrustListSize = 1 << 20
	// maxTrustListEntries bounds each of the four lists of a trust list.
	maxTrustListEntries = 1024
	// maxIssuerDepth bounds the issuer chains walked for revocation.
	maxIssuerDepth = 8
)

// trustList is an immutable snapshot of the trust list of a certificate
// group (Part 12 §7.8.2): the certificates and CRLs with
// what client certificate validation needs of them. A validation loads one
// snapshot and uses only it, so an update never leaves a channel checked
// against half a trust list.
type trustList struct {
	data *ua.TrustListDataType // SpecifiedLists is TrustListMasksAll
	size int                   // encoded size of data

	trusted []*x509.Certificate
	issuers []*x509.Certificate
	roots   *x509.CertPool // the trusted certificates

	// revoked holds the serial numbers revoked by a CRL whose issuer is a
	// certificate of the lists, by the RawSubject of that issuer.
	revoked map[string]map[string]bool
}

// emptyTrustListData returns a trust list without certificates and CRLs.
func emptyTrustListData() *ua.TrustListDataType {
	return &ua.TrustListDataType{SpecifiedLists: uint32(ua.TrustListMasksAll)}
}

// cloneTrustListData returns a copy of d whose lists can be changed.
func cloneTrustListData(d *ua.TrustListDataType) *ua.TrustListDataType {
	return &ua.TrustListDataType{
		SpecifiedLists:      uint32(ua.TrustListMasksAll),
		TrustedCertificates: slices.Clone(d.TrustedCertificates),
		TrustedCrls:         slices.Clone(d.TrustedCrls),
		IssuerCertificates:  slices.Clone(d.IssuerCertificates),
		IssuerCrls:          slices.Clone(d.IssuerCrls),
	}
}

// mergeTrustList returns base with the lists that upd specifies replaced by
// those of upd (Part 12 §7.8.2.4: CloseAndUpdate changes only the lists
// named by SpecifiedLists).
func mergeTrustList(base, upd *ua.TrustListDataType) *ua.TrustListDataType {
	out := cloneTrustListData(base)
	m := ua.TrustListMasks(upd.SpecifiedLists)
	if m&ua.TrustListMasksTrustedCertificates != 0 {
		out.TrustedCertificates = slices.Clone(upd.TrustedCertificates)
	}
	if m&ua.TrustListMasksTrustedCrls != 0 {
		out.TrustedCrls = slices.Clone(upd.TrustedCrls)
	}
	if m&ua.TrustListMasksIssuerCertificates != 0 {
		out.IssuerCertificates = slices.Clone(upd.IssuerCertificates)
	}
	if m&ua.TrustListMasksIssuerCrls != 0 {
		out.IssuerCrls = slices.Clone(upd.IssuerCrls)
	}
	return out
}

// maskTrustList returns the lists of d that masks selects, as OpenWithMasks
// reads them.
func maskTrustList(d *ua.TrustListDataType, masks ua.TrustListMasks) *ua.TrustListDataType {
	masks &= ua.TrustListMasksAll
	out := &ua.TrustListDataType{SpecifiedLists: uint32(masks)}
	if masks&ua.TrustListMasksTrustedCertificates != 0 {
		out.TrustedCertificates = d.TrustedCertificates
	}
	if masks&ua.TrustListMasksTrustedCrls != 0 {
		out.TrustedCrls = d.TrustedCrls
	}
	if masks&ua.TrustListMasksIssuerCertificates != 0 {
		out.IssuerCertificates = d.IssuerCertificates
	}
	if masks&ua.TrustListMasksIssuerCrls != 0 {
		out.IssuerCrls = d.IssuerCrls
	}
	return out
}

// dedupe drops the repeated entries of a list.
func dedupe(xs [][]byte) [][]byte {
	out := make([][]byte, 0, len(xs))
	seen := make(map[string]bool, len(xs))
	for _, x := range xs {
		if !seen[string(x)] {
			seen[string(x)] = true
			out = append(out, x)
		}
	}
	return out
}

// newTrustList validates a complete trust list and builds its snapshot.
// Every certificate must be a single DER certificate and every CRL a DER
// CRL; the encoded list may have at most maxSize bytes (0: no limit).
//
// It returns Bad_CertificateInvalid for an entry that does not parse and
// Bad_EncodingLimitsExceeded for a list that is too large.
func newTrustList(d *ua.TrustListDataType, maxSize uint32) (*trustList, ua.StatusCode) {
	if d == nil {
		d = emptyTrustListData()
	}
	for _, l := range [][][]byte{d.TrustedCertificates, d.TrustedCrls, d.IssuerCertificates, d.IssuerCrls} {
		if len(l) > maxTrustListEntries {
			return nil, ua.StatusBadEncodingLimitsExceeded
		}
	}
	d = &ua.TrustListDataType{
		SpecifiedLists:      uint32(ua.TrustListMasksAll),
		TrustedCertificates: dedupe(d.TrustedCertificates),
		TrustedCrls:         dedupe(d.TrustedCrls),
		IssuerCertificates:  dedupe(d.IssuerCertificates),
		IssuerCrls:          dedupe(d.IssuerCrls),
	}
	b, err := ua.Encode(d)
	if err != nil {
		return nil, ua.StatusBadEncodingError
	}
	if maxSize > 0 && len(b) > int(maxSize) {
		return nil, ua.StatusBadEncodingLimitsExceeded
	}
	tl := &trustList{data: d, size: len(b), roots: x509.NewCertPool(), revoked: map[string]map[string]bool{}}
	parse := func(ders [][]byte) ([]*x509.Certificate, bool) {
		out := make([]*x509.Certificate, 0, len(ders))
		for _, der := range ders {
			c, err := uapolicy.ParseCertificate(der)
			if err != nil || !bytes.Equal(c.Raw, der) {
				return nil, false // not one DER certificate
			}
			out = append(out, c)
		}
		return out, true
	}
	var ok bool
	if tl.trusted, ok = parse(d.TrustedCertificates); !ok {
		return nil, ua.StatusBadCertificateInvalid
	}
	if tl.issuers, ok = parse(d.IssuerCertificates); !ok {
		return nil, ua.StatusBadCertificateInvalid
	}
	for _, c := range tl.trusted {
		tl.roots.AddCert(c)
	}
	cas := append(slices.Clone(tl.trusted), tl.issuers...)
	for _, der := range append(slices.Clone(d.TrustedCrls), d.IssuerCrls...) {
		crl, err := uapolicy.ParseRevocationList(der)
		if err != nil {
			return nil, ua.StatusBadCertificateInvalid
		}
		// A CRL counts only with the signature of a CA of the lists (RSA,
		// ECDSA on the NIST and Brainpool curves, Ed25519 or Ed448). One
		// whose issuer is missing is kept in the list but not used.
		for _, ca := range cas {
			if !bytes.Equal(ca.RawSubject, crl.RawIssuer) || uapolicy.CheckRevocationListSignature(crl, ca) != nil {
				continue
			}
			set := tl.revoked[string(crl.RawIssuer)]
			if set == nil {
				set = map[string]bool{}
				tl.revoked[string(crl.RawIssuer)] = set
			}
			for _, e := range crl.RevokedCertificateEntries {
				if e.SerialNumber != nil {
					set[e.SerialNumber.String()] = true
				}
			}
			break
		}
	}
	return tl, ua.StatusOK
}

// isRevoked reports whether a CRL of the list revokes c.
func (tl *trustList) isRevoked(c *x509.Certificate) bool {
	set := tl.revoked[string(c.RawIssuer)]
	return set != nil && c.SerialNumber != nil && set[c.SerialNumber.String()]
}

// errUntrusted and errRevoked tell how a validation failed.
var (
	errUntrusted     = stderrors.New("certificate untrusted")
	errRevoked       = stderrors.New("certificate revoked")
	errIssuerRevoked = stderrors.New("issuer certificate revoked")
)

// verify validates a client certificate (chain) as Part 4 §6.1.3 does with
// the trust list: certs[0] must chain, through the certificates presented
// after it and the issuer certificates, to a trusted certificate, or be
// trusted itself; neither it nor an issuer on its chain may be revoked by a
// CRL of the list.
func (tl *trustList) verify(certs []*x509.Certificate) error {
	chain := append(slices.Clone(certs), tl.issuers...)
	if err := uapolicy.VerifyCertificate(chain, tl.roots, tl.trusted); err != nil {
		return errUntrusted
	}
	// Walk up the issuers by name; the chain itself was verified above.
	candidates := append(slices.Clone(certs[1:]), tl.issuers...)
	candidates = append(candidates, tl.trusted...)
	cur := certs[0]
	for depth := 0; depth < maxIssuerDepth; depth++ {
		if tl.isRevoked(cur) {
			if depth == 0 {
				return errRevoked
			}
			return errIssuerRevoked
		}
		if bytes.Equal(cur.RawIssuer, cur.RawSubject) {
			break
		}
		var parent *x509.Certificate
		for _, c := range candidates {
			if bytes.Equal(c.RawSubject, cur.RawIssuer) && !c.Equal(cur) {
				parent = c
				break
			}
		}
		if parent == nil {
			break
		}
		cur = parent
	}
	return nil
}

// crlIssuer returns the RawIssuer of a DER CRL, nil if it does not parse.
func crlIssuer(der []byte) []byte {
	crl, err := uapolicy.ParseRevocationList(der)
	if err != nil {
		return nil
	}
	return crl.RawIssuer
}
