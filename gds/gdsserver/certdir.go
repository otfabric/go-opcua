// SPDX-License-Identifier: MIT

package gdsserver

import (
	"bytes"
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

// clockSkew is how far before the issuance the validity of an issued
// certificate starts.
const clockSkew = time.Hour

// maxDomainNames bounds the DomainNames of StartNewKeyPairRequest.
const maxDomainNames = 32

// certType returns the certificate type of a group a request asks for:
// the first type of the group for a null NodeId. A group that issues no
// certificates (the DefaultUserTokenGroup) has none.
func (g *GDS) certType(gr *group, n *ua.NodeID) (*certType, ua.StatusCode) {
	if len(gr.types) == 0 {
		return nil, ua.StatusBadInvalidArgument
	}
	if isNull(n) {
		return certTypes[gr.types[0]], ua.StatusOK
	}
	if n.Namespace() != 0 || !slices.Contains(gr.types, n.IntID()) {
		return nil, ua.StatusBadInvalidArgument
	}
	return certTypes[n.IntID()], ua.StatusOK
}

// target returns the group and the certificate type a certificate request
// names, and notes them for its audit event.
func (g *GDS) target(c *caller, groupID, typeID *ua.NodeID) (*group, *certType, ua.StatusCode) {
	gr := g.groupOf(groupID)
	if gr == nil {
		return nil, nil, ua.StatusBadInvalidArgument
	}
	c.auditGroup = g.node(gr.node)
	ct, sc := g.certType(gr, typeID)
	if sc != ua.StatusOK {
		return nil, nil, sc
	}
	c.auditType = ua.NewNumericNodeID(0, ct.id)
	return gr, ct, ua.StatusOK
}

// pruneRequestsLocked drops the requests older than RequestLifetime.
func (g *GDS) pruneRequestsLocked(ctx context.Context) {
	limit := g.now().Add(-g.cfg.RequestLifetime)
	for id, r := range g.reqs {
		if g.issuing[id] || !r.Created.Before(limit) {
			continue
		}
		if err := g.store.DeleteRequest(ctx, id); err != nil {
			g.log.Warn("gds: deleting an expired request failed", "error", err)
			continue
		}
		delete(g.reqs, id)
	}
}

// addRequestLocked stores a new request of the application.
func (g *GDS) addRequestLocked(ctx context.Context, req *Request) ([]*ua.Variant, ua.StatusCode) {
	g.pruneRequestsLocked(ctx)
	n := 0
	for _, r := range g.reqs {
		if r.ApplicationID == req.ApplicationID {
			n++
		}
	}
	if n >= g.cfg.MaxRequests {
		return nil, ua.StatusBadTooManyOperations
	}
	req.ID = uuid.NewString()
	req.Created = g.now()
	if g.cfg.AutoApprove {
		req.State = RequestApproved
	}
	if err := g.store.PutRequest(ctx, req); err != nil {
		g.log.Warn("gds: storing the request failed", "error", err)
		return nil, ua.StatusBadInternalError
	}
	g.reqs[req.ID] = req
	g.log.Info("gds: certificate request", "application_id", req.ApplicationID, "request_id", req.ID, "state", req.State)
	return []*ua.Variant{ua.MustVariant(g.guidNode(req.ID))}, ua.StatusOK
}

// parseCSR parses a PKCS #10 request, with the keys of every certificate
// type (Brainpool and Ed448 included), and checks its signature.
func parseCSR(der []byte) (*x509.CertificateRequest, error) {
	csr, err := uapolicy.ParseCertificateRequest(der)
	if err != nil {
		return nil, err
	}
	if err := uapolicy.CheckCertificateRequestSignature(csr); err != nil {
		return nil, err
	}
	return csr, nil
}

// startSigningRequest is StartSigningRequest (Part 12 §7.9.4): the
// CertificateAuthorityAdmin role or the application itself, over an
// encrypted channel. The request must have a key of the certificate type
// and carry the ApplicationUri of the application (an HTTPS certificate
// request may have no URI).
func (g *GDS) startSigningRequest(ctx context.Context, c *caller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	if sc := c.channelCheck(true); sc != ua.StatusOK {
		return nil, sc
	}
	appID, ok1 := argNodeID(args, 0)
	group, ok2 := argNodeID(args, 1)
	typ, ok3 := argNodeID(args, 2)
	der, ok4 := argBytes(args, 3)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return nil, ua.StatusBadTypeMismatch
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	gr, ct, sc := g.target(c, group, typ)
	if sc != ua.StatusOK {
		return nil, sc
	}
	app, sc := g.authorizeAppLocked(c, g.guidOf(appID), g.isCAAdmin(c))
	if sc != ua.StatusOK {
		return nil, sc
	}
	csr, err := parseCSR(der)
	if err != nil {
		return nil, ua.StatusBadInvalidArgument
	}
	if !ct.accepts(csr.PublicKey) || g.cas[ct.issuerFor(csr.PublicKey)] == nil {
		return nil, ua.StatusBadInvalidArgument
	}
	uris := make([]string, len(csr.URIs))
	for i, u := range csr.URIs {
		uris[i] = u.String()
	}
	if !slices.Contains(uris, app.Record.ApplicationURI) && (gr.key != GroupHTTPS || len(uris) > 0) {
		return nil, ua.StatusBadCertificateURIInvalid
	}
	return g.addRequestLocked(ctx, &Request{
		ApplicationID:      app.ID,
		CertificateType:    ct.id,
		CertificateGroup:   gr.key,
		CertificateRequest: slices.Clone(der),
	})
}

// startNewKeyPairRequest is StartNewKeyPairRequest (Part 12 §7.9.5): the
// CertificateAuthorityAdmin role or the application itself, over an
// encrypted channel. The application itself may only ask for the host
// names of its discovery URLs. The private key format is PEM (PKCS #8,
// encrypted with the password if one is given) or PFX (PKCS #12 with the
// certificate and its issuer, protected with the password).
func (g *GDS) startNewKeyPairRequest(ctx context.Context, c *caller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	if sc := c.channelCheck(true); sc != ua.StatusOK {
		return nil, sc
	}
	appID, ok1 := argNodeID(args, 0)
	group, ok2 := argNodeID(args, 1)
	typ, ok3 := argNodeID(args, 2)
	subject, ok4 := argValue[string](args, 3)
	domains, ok5 := argStrings(args, 4)
	format, ok6 := argValue[string](args, 5)
	password, ok7 := argValue[string](args, 6)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 || !ok7 {
		return nil, ua.StatusBadTypeMismatch
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	gr, ct, sc := g.target(c, group, typ)
	if sc != ua.StatusOK {
		return nil, sc
	}
	admin := g.isCAAdmin(c)
	app, sc := g.authorizeAppLocked(c, g.guidOf(appID), admin)
	if sc != ua.StatusOK {
		return nil, sc
	}
	switch {
	case format == "" || strings.EqualFold(format, gds.PrivateKeyFormatPEM):
		format = gds.PrivateKeyFormatPEM
	case strings.EqualFold(format, gds.PrivateKeyFormatPFX):
		format = gds.PrivateKeyFormatPFX
	default:
		return nil, ua.StatusBadInvalidArgument
	}
	if !validString(subject) || !validString(password) {
		return nil, ua.StatusBadInvalidArgument
	}
	if subject != "" {
		if _, err := parseSubjectName(subject); err != nil {
			return nil, ua.StatusBadInvalidArgument
		}
	}
	if len(domains) > maxDomainNames {
		return nil, ua.StatusBadInvalidArgument
	}
	dns, ips := hostsOf(app.Record.DiscoveryURLs)
	for _, d := range domains {
		if d == "" || len(d) > 253 || strings.ContainsAny(d, " /\\*") {
			return nil, ua.StatusBadInvalidArgument
		}
		if !admin && !slices.ContainsFunc(dns, func(h string) bool { return strings.EqualFold(h, d) }) &&
			!slices.ContainsFunc(ips, func(ip net.IP) bool { return ip.Equal(net.ParseIP(d)) }) {
			return nil, ua.StatusBadUserAccessDenied
		}
	}
	return g.addRequestLocked(ctx, &Request{
		ApplicationID:      app.ID,
		CertificateType:    ct.id,
		CertificateGroup:   gr.key,
		SubjectName:        subject,
		DomainNames:        slices.Clone(domains),
		PrivateKeyFormat:   format,
		PrivateKeyPassword: password,
	})
}

// finishRequest is FinishRequest (Part 12 §7.9.6): the
// CertificateAuthorityAdmin role or the application itself, over an
// encrypted channel. It issues the certificate of an approved request and
// removes the request: Bad_NothingToDo while the request waits for
// approval, Bad_RequestNotAllowed when it was rejected and
// Bad_InvalidArgument for an unknown or completed request.
func (g *GDS) finishRequest(ctx context.Context, c *caller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	if sc := c.channelCheck(true); sc != ua.StatusOK {
		return nil, sc
	}
	appID, ok1 := argNodeID(args, 0)
	reqID, ok2 := argNodeID(args, 1)
	if !ok1 || !ok2 {
		return nil, ua.StatusBadTypeMismatch
	}
	rid := g.guidOf(reqID)

	g.mu.Lock()
	app, sc := g.authorizeAppLocked(c, g.guidOf(appID), g.isCAAdmin(c))
	if sc != ua.StatusOK {
		g.mu.Unlock()
		return nil, sc
	}
	g.pruneRequestsLocked(ctx)
	req := g.reqs[rid]
	if req != nil && req.ApplicationID == app.ID {
		c.auditGroup = g.node(g.groupByKey(req.CertificateGroup).node)
		c.auditType = ua.NewNumericNodeID(0, req.CertificateType)
	}
	switch {
	case req == nil || req.ApplicationID != app.ID:
		sc = ua.StatusBadInvalidArgument
	case req.State == RequestPending || g.issuing[rid]:
		sc = ua.StatusBadNothingToDo
	case req.State == RequestRejected:
		sc = ua.StatusBadRequestNotAllowed
	}
	if sc != ua.StatusOK {
		g.mu.Unlock()
		return nil, sc
	}
	req = cloneRequest(req)
	rec := cloneRecord(app.Record)
	g.issuing[rid] = true
	g.mu.Unlock()

	// Key generation and signing happen without the lock (g.cas does not
	// change after Attach, nor do the certificate and key of a CA).
	certDER, keyPEM, issuer, sc := g.issue(rec, req)

	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.issuing, rid)
	if sc != ua.StatusOK {
		return nil, sc
	}
	app = g.apps[app.ID]
	if app == nil || g.reqs[rid] == nil {
		// Unregistered or expired meanwhile.
		return nil, ua.StatusBadInvalidArgument
	}
	app = cloneApplication(app)
	app.Certificates = append(app.Certificates, &IssuedCertificate{CertificateType: req.CertificateType, Certificate: certDER,
		CertificateGroup: req.CertificateGroup})
	if sc := g.putApplicationLocked(ctx, app, nil); sc != ua.StatusOK {
		return nil, sc
	}
	if err := g.store.DeleteRequest(ctx, rid); err != nil {
		g.log.Warn("gds: deleting the completed request failed", "error", err)
		return nil, ua.StatusBadInternalError
	}
	delete(g.reqs, rid)
	g.log.Info("gds: certificate issued", "application_uri", app.Record.ApplicationURI, "request_id", rid)
	return []*ua.Variant{
		ua.MustVariant(certDER),
		ua.MustVariant(keyPEM),
		ua.MustVariant([][]byte{slices.Clone(issuer.cert.Raw)}),
	}, ua.StatusOK
}

// newKey makes the key of a new key pair request: of the certificate type,
// for an HTTPS certificate RSA, or ECDSA on P-256 or P-384 when the GDS has
// no RSA CA.
func (g *GDS) newKey(ct *certType) (crypto.Signer, error) {
	if ct.issuer == "" && g.cas["RSA"] == nil {
		if g.cas["NistP256"] != nil {
			return genECDSA(elliptic.P256())(0)
		}
		return genECDSA(elliptic.P384())(0)
	}
	return ct.generate(g.cfg.RSAKeySize)
}

// issue makes the certificate (and for a new key pair request the private
// key, encoded) of an approved request, and returns the CA that signed it.
func (g *GDS) issue(rec *gds.ApplicationRecord, req *Request) (certDER, keyData []byte, issuer *ca, sc ua.StatusCode) {
	ct := certTypes[req.CertificateType]
	now := g.now()
	l := &leaf{uri: rec.ApplicationURI, notBefore: now.Add(-clockSkew), notAfter: now.Add(g.cfg.CertificateLifetime)}
	l.dns, l.ips = hostsOf(rec.DiscoveryURLs)
	name := ""
	if len(rec.ApplicationNames) > 0 && rec.ApplicationNames[0] != nil {
		name = rec.ApplicationNames[0].Text
	}
	var key crypto.Signer
	if len(req.CertificateRequest) > 0 {
		csr, err := parseCSR(req.CertificateRequest)
		if err != nil {
			return nil, nil, nil, ua.StatusBadInvalidArgument
		}
		l.pub = csr.PublicKey
		l.subject = csr.Subject
	} else {
		var err error
		if key, err = g.newKey(ct); err != nil {
			g.log.Warn("gds: key generation failed", "error", err)
			return nil, nil, nil, ua.StatusBadInternalError
		}
		l.pub = key.Public()
		l.subject, _ = parseSubjectName(req.SubjectName)
		if len(req.DomainNames) > 0 {
			l.dns, l.ips = nil, nil
			for _, d := range req.DomainNames {
				if ip := net.ParseIP(d); ip != nil {
					l.ips = append(l.ips, ip)
				} else {
					l.dns = append(l.dns, d)
				}
			}
		}
	}
	if len(l.subject.Names) == 0 && l.subject.CommonName == "" && len(l.subject.Organization) == 0 {
		l.subject = pkix.Name{CommonName: name}
	}
	issuer = g.cas[ct.issuerFor(l.pub)]
	if issuer == nil {
		// The CA of an HTTPS key the GDS does not have (checked by
		// StartSigningRequest).
		return nil, nil, nil, ua.StatusBadInvalidArgument
	}
	certDER, err := issuer.issue(l)
	if err != nil {
		g.log.Warn("gds: signing the certificate failed", "error", err)
		return nil, nil, nil, ua.StatusBadInternalError
	}
	if key != nil {
		if req.PrivateKeyFormat == gds.PrivateKeyFormatPFX {
			keyData, err = uapolicy.EncodePFX(key, [][]byte{certDER, issuer.cert.Raw}, req.PrivateKeyPassword)
		} else {
			keyData, err = gds.EncodePrivateKey(gds.PrivateKeyFormatPEM, key, req.PrivateKeyPassword)
		}
		if err != nil {
			g.log.Warn("gds: encoding the private key failed", "error", err)
			return nil, nil, nil, ua.StatusBadInternalError
		}
	}
	return certDER, keyData, issuer, ua.StatusOK
}

// revokeLocked revokes an issued certificate: its CA lists it in a new CRL.
func (g *GDS) revokeLocked(ctx context.Context, ic *IssuedCertificate) ua.StatusCode {
	cert, err := uapolicy.ParseCertificate(ic.Certificate)
	if err != nil {
		return ua.StatusBadCertificateInvalid
	}
	for _, name := range g.caNamesLocked() {
		c := g.cas[name]
		if !c.issues(cert) {
			continue
		}
		if c.isRevoked(cert) {
			return ua.StatusOK
		}
		oldRec, oldCRL := c.rec, c.crl
		c.rec = cloneIssuer(oldRec)
		c.rec.Revoked = append(c.rec.Revoked, &RevokedCertificate{SerialNumber: cert.SerialNumber.Bytes(), RevokedAt: g.now().UTC()})
		if err := c.makeCRL(g.now(), g.cfg.CRLLifetime); err != nil {
			c.rec, c.crl = oldRec, oldCRL
			g.log.Warn("gds: signing the CRL failed", "error", err)
			return ua.StatusBadInternalError
		}
		if err := g.store.PutIssuer(ctx, c.rec); err != nil {
			c.rec, c.crl = oldRec, oldCRL
			g.log.Warn("gds: storing the CRL failed", "error", err)
			return ua.StatusBadInternalError
		}
		c.revoked[serialKey(cert.SerialNumber)] = true
		g.trustChanged()
		return ua.StatusOK
	}
	// A CA the GDS no longer has: nothing to revoke with.
	return ua.StatusOK
}

// revokeCertificate is RevokeCertificate (Part 12 §7.9.9): the
// CertificateAuthorityAdmin role. The certificate must be one the GDS
// issued to the application.
func (g *GDS) revokeCertificate(ctx context.Context, c *caller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	if sc := c.channelCheck(false); sc != ua.StatusOK {
		return nil, sc
	}
	appID, ok1 := argNodeID(args, 0)
	der, ok2 := argBytes(args, 1)
	if !ok1 || !ok2 {
		return nil, ua.StatusBadTypeMismatch
	}
	if !g.isCAAdmin(c) {
		return nil, ua.StatusBadUserAccessDenied
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	app, sc := g.authorizeAppLocked(c, g.guidOf(appID), true)
	if sc != ua.StatusOK {
		return nil, sc
	}
	i := slices.IndexFunc(app.Certificates, func(ic *IssuedCertificate) bool { return bytes.Equal(ic.Certificate, der) })
	if i < 0 {
		return nil, ua.StatusBadInvalidArgument
	}
	if app.Certificates[i].Revoked {
		return nil, ua.StatusOK
	}
	if sc := g.revokeLocked(ctx, app.Certificates[i]); sc != ua.StatusOK {
		return nil, sc
	}
	app = cloneApplication(app)
	app.Certificates[i].Revoked = true
	if sc := g.putApplicationLocked(ctx, app, nil); sc != ua.StatusOK {
		return nil, sc
	}
	g.log.Info("gds: certificate revoked", "application_uri", app.Record.ApplicationURI)
	return nil, ua.StatusOK
}

// getCertificateGroups is GetCertificateGroups (Part 12 §7.9.10): the
// groups of the application (see groupsOf).
func (g *GDS) getCertificateGroups(_ context.Context, c *caller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	appID, ok := argNodeID(args, 0)
	if !ok {
		return nil, ua.StatusBadTypeMismatch
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	app, sc := g.authorizeAppLocked(c, g.guidOf(appID), g.isCAAdmin(c))
	if sc != ua.StatusOK {
		return nil, sc
	}
	var ids []*ua.NodeID
	for _, gr := range g.groupsOf(app) {
		ids = append(ids, g.node(gr.node))
	}
	return []*ua.Variant{ua.MustVariant(ids)}, ua.StatusOK
}

// validIssuedLocked returns the certificates of a group of the application
// that are not revoked.
func (g *GDS) validIssuedLocked(app *Application, gr *group) []*IssuedCertificate {
	var out []*IssuedCertificate
	for _, ic := range app.Certificates {
		if ic.Revoked || ic.CertificateGroup != gr.key {
			continue
		}
		cert, err := uapolicy.ParseCertificate(ic.Certificate)
		if err != nil {
			continue
		}
		if slices.ContainsFunc(g.caNamesLocked(), func(n string) bool { return g.cas[n].issues(cert) && !g.cas[n].isRevoked(cert) }) {
			out = append(out, ic)
		}
	}
	return out
}

// getCertificates is GetCertificates (Part 12 §7.9.11): the certificates
// of the group the GDS issued to the application and did not revoke.
func (g *GDS) getCertificates(_ context.Context, c *caller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	appID, ok1 := argNodeID(args, 0)
	group, ok2 := argNodeID(args, 1)
	if !ok1 || !ok2 {
		return nil, ua.StatusBadTypeMismatch
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	app, sc := g.authorizeAppLocked(c, g.guidOf(appID), g.isCAAdmin(c))
	if sc != ua.StatusOK {
		return nil, sc
	}
	gr := g.groupOf(group)
	if gr == nil {
		return nil, ua.StatusBadInvalidArgument
	}
	types := []*ua.NodeID{}
	certs := [][]byte{}
	for _, ic := range g.validIssuedLocked(app, gr) {
		types = append(types, ua.NewNumericNodeID(0, ic.CertificateType))
		certs = append(certs, slices.Clone(ic.Certificate))
	}
	return []*ua.Variant{ua.MustVariant(types), ua.MustVariant(certs)}, ua.StatusOK
}

// getTrustList is GetTrustList (Part 12 §7.9.12): the TrustList object of
// the group.
func (g *GDS) getTrustList(_ context.Context, c *caller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	appID, ok1 := argNodeID(args, 0)
	group, ok2 := argNodeID(args, 1)
	if !ok1 || !ok2 {
		return nil, ua.StatusBadTypeMismatch
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, sc := g.authorizeAppLocked(c, g.guidOf(appID), g.isCAAdmin(c)); sc != ua.StatusOK {
		return nil, sc
	}
	gr := g.groupOf(group)
	if gr == nil {
		return nil, ua.StatusBadInvalidArgument
	}
	return []*ua.Variant{ua.MustVariant(g.node(gr.trustNode))}, ua.StatusOK
}

// getCertificateStatus is GetCertificateStatus (Part 12 §7.9.13): true
// when the application should ask for a new certificate of the type (of
// any type of the group for a null type): it has none, or the one it has
// passed two thirds of its validity or is of a CA the GDS no longer uses.
func (g *GDS) getCertificateStatus(_ context.Context, c *caller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	appID, ok1 := argNodeID(args, 0)
	group, ok2 := argNodeID(args, 1)
	typ, ok3 := argNodeID(args, 2)
	if !ok1 || !ok2 || !ok3 {
		return nil, ua.StatusBadTypeMismatch
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	app, sc := g.authorizeAppLocked(c, g.guidOf(appID), g.isCAAdmin(c))
	if sc != ua.StatusOK {
		return nil, sc
	}
	gr := g.groupOf(group)
	if gr == nil {
		return nil, ua.StatusBadInvalidArgument
	}
	types := gr.types
	if !isNull(typ) {
		ct, sc := g.certType(gr, typ)
		if sc != ua.StatusOK {
			return nil, sc
		}
		types = []uint32{ct.id}
	}
	valid := g.validIssuedLocked(app, gr)
	now := g.now()
	update := false
	for _, t := range types {
		fresh := false
		for _, ic := range valid {
			if ic.CertificateType != t {
				continue
			}
			cert, _ := uapolicy.ParseCertificate(ic.Certificate)
			renewAt := cert.NotBefore.Add(cert.NotAfter.Sub(cert.NotBefore) * 2 / 3)
			if ca := g.cas[certTypes[t].issuerFor(cert.PublicKey)]; now.Before(renewAt) && ca != nil && ca.issues(cert) {
				fresh = true
			}
		}
		if !fresh {
			update = true
		}
	}
	return []*ua.Variant{ua.MustVariant(update)}, ua.StatusOK
}

// checkRevocationStatus is CheckRevocationStatus (Part 12 §7.9.14): any
// client over a signed channel. The status is that of the certificate with
// the CAs of the GDS; ValidityTime is when the answer has to be checked
// again (the NextUpdate of the CRL).
func (g *GDS) checkRevocationStatus(_ context.Context, c *caller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	if sc := c.channelCheck(false); sc != ua.StatusOK {
		return nil, sc
	}
	der, ok := argBytes(args, 0)
	if !ok {
		return nil, ua.StatusBadTypeMismatch
	}
	out := func(sc ua.StatusCode, t time.Time) []*ua.Variant {
		return []*ua.Variant{ua.MustVariant(sc), ua.MustVariant(t)}
	}
	cert, err := uapolicy.ParseCertificate(der)
	if err != nil {
		return out(ua.StatusBadCertificateInvalid, time.Time{}), ua.StatusOK
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.refreshCRLsLocked()
	for _, name := range g.caNamesLocked() {
		ca := g.cas[name]
		if !ca.issues(cert) {
			continue
		}
		next := time.Time{}
		if ca.crl != nil {
			next = ca.crl.NextUpdate.UTC()
		}
		switch now := g.now(); {
		case ca.isRevoked(cert):
			return out(ua.StatusBadCertificateRevoked, next), ua.StatusOK
		case now.Before(cert.NotBefore) || now.After(cert.NotAfter):
			return out(ua.StatusBadCertificateTimeInvalid, next), ua.StatusOK
		}
		return out(ua.StatusOK, next), ua.StatusOK
	}
	return out(ua.StatusBadCertificateUntrusted, time.Time{}), ua.StatusOK
}

// PendingRequest is a certificate request that waits for approval.
type PendingRequest struct {
	// ID is the GUID of the RequestId.
	ID string
	// ApplicationURI is the URI of the application that made it.
	ApplicationURI   string
	CertificateGroup *ua.NodeID
	CertificateType  *ua.NodeID
	State            RequestState
	Created          time.Time
	// NewKeyPair tells a StartNewKeyPairRequest from a
	// StartSigningRequest.
	NewKeyPair bool
}

// Requests returns the open certificate requests, oldest first.
func (g *GDS) Requests() []*PendingRequest {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]*PendingRequest, 0, len(g.reqs))
	for _, r := range g.reqs {
		p := &PendingRequest{
			ID:               r.ID,
			CertificateGroup: g.node(g.groupByKey(r.CertificateGroup).node),
			CertificateType:  ua.NewNumericNodeID(0, r.CertificateType),
			State:            r.State,
			Created:          r.Created,
			NewKeyPair:       len(r.CertificateRequest) == 0,
		}
		if a := g.apps[r.ApplicationID]; a != nil {
			p.ApplicationURI = a.Record.ApplicationURI
		}
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b *PendingRequest) int {
		if c := a.Created.Compare(b.Created); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out
}

// ErrClosed is the error of ApproveRequest after Close.
var ErrClosed = errors.New("gdsserver: the GDS is closed")

// ErrUnknownRequest is the error of ApproveRequest for a request the GDS
// does not have.
var ErrUnknownRequest = errors.New("gdsserver: unknown certificate request")

// ApproveRequest approves (approve true) or rejects a pending certificate
// request by its ID (the GUID of the RequestId). The CertificateAuthority
// of an application decides with it when Config.AutoApprove is not set.
func (g *GDS) ApproveRequest(ctx context.Context, requestID string, approve bool) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return ErrClosed
	}
	r := g.reqs[strings.ToLower(requestID)]
	if r == nil {
		return ErrUnknownRequest
	}
	if r.State != RequestPending {
		return fmt.Errorf("gdsserver: request %s is %s", r.ID, r.State)
	}
	r = cloneRequest(r)
	r.State = RequestRejected
	if approve {
		r.State = RequestApproved
	}
	if err := g.store.PutRequest(ctx, r); err != nil {
		return err
	}
	g.reqs[r.ID] = r
	return nil
}

// RequestID returns the GUID of a RequestId or ApplicationId NodeId of
// the GDS, "" for any other NodeId.
func (g *GDS) RequestID(n *ua.NodeID) string { return g.guidOf(n) }
