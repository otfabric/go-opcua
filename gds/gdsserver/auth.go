// SPDX-License-Identifier: MIT

package gdsserver

import (
	"bytes"
	"context"
	"crypto/x509"
	"slices"

	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

// caller is the session that calls a method of the GDS.
type caller struct {
	mc *server.MethodCaller
	// cert is the application instance certificate of the channel, nil
	// on a channel without security.
	cert *x509.Certificate
}

// identify returns the caller of a method: a session is required.
func (g *GDS) identify(ctx context.Context) (*caller, ua.StatusCode) {
	mc, ok := server.MethodCallerFromContext(ctx)
	if !ok || mc.SessionID == nil {
		return nil, ua.StatusBadUserAccessDenied
	}
	c := &caller{mc: mc}
	if len(mc.ClientCertificate) > 0 {
		if certs, err := uapolicy.ParseCertificates(mc.ClientCertificate); err == nil && len(certs) > 0 {
			c.cert = certs[0]
		}
	}
	return c, ua.StatusOK
}

// hasRole reports whether the session has the role.
func (c *caller) hasRole(role *ua.NodeID) bool {
	return slices.ContainsFunc(c.mc.Roles, func(r *ua.NodeID) bool { return r.Equal(role) })
}

// signed reports a channel that signs (Sign or SignAndEncrypt);
// encrypted one that also encrypts.
func (c *caller) signed() bool {
	return c.mc.SecurityMode == ua.MessageSecurityModeSign || c.mc.SecurityMode == ua.MessageSecurityModeSignAndEncrypt
}

func (c *caller) encrypted() bool { return c.mc.SecurityMode == ua.MessageSecurityModeSignAndEncrypt }

// channelCheck returns Bad_SecurityModeInsufficient for a channel that does
// not sign, or does not encrypt when encrypt is set.
func (c *caller) channelCheck(encrypt bool) ua.StatusCode {
	if encrypt && !c.encrypted() || !c.signed() {
		return ua.StatusBadSecurityModeInsufficient
	}
	return ua.StatusOK
}

// isDiscoveryAdmin, isCAAdmin report the roles of Part 12 §6.2 and §7.2.
func (g *GDS) isDiscoveryAdmin(c *caller) bool { return c.hasRole(g.DiscoveryAdminRole()) }
func (g *GDS) isCAAdmin(c *caller) bool        { return c.hasRole(g.CertificateAuthorityAdminRole()) }

// selfLocked reports whether the caller is the application app (the
// ApplicationSelfAdmin privilege of Part 12 §6.2): its channel
// certificate carries the application URI of the record and is a
// certificate the GDS issued to the application and did not revoke, or one
// that Config.SelfAdmin accepts.
func (g *GDS) selfLocked(c *caller, app *Application) bool {
	if c.cert == nil || app == nil || !c.signed() {
		return false
	}
	if !slices.Contains(certURIs(c.cert), app.Record.ApplicationURI) {
		return false
	}
	if g.issuedLocked(app, c.cert) {
		return true
	}
	if f := g.cfg.SelfAdmin; f != nil {
		return f(cloneRecord(app.Record), c.cert)
	}
	return false
}

// issuedLocked reports whether cert is a certificate the GDS issued to the
// application and did not revoke, of a CA that still signs and did not
// revoke it.
func (g *GDS) issuedLocked(app *Application, cert *x509.Certificate) bool {
	for _, ic := range app.Certificates {
		if ic.Revoked || !bytes.Equal(ic.Certificate, cert.Raw) {
			continue
		}
		for _, ca := range g.cas {
			if ca.issues(cert) && !ca.isRevoked(cert) {
				return true
			}
		}
	}
	return false
}

// authorizeApp checks that the caller may act for the application with
// the ID: with the role, or as the application itself. It returns the
// application, nil and Bad_NotFound if there is none, or the status the
// call fails with. An unknown application is reported only to callers
// with the role.
func (g *GDS) authorizeAppLocked(c *caller, appID string, admin bool) (*Application, ua.StatusCode) {
	app := g.apps[appID]
	if admin {
		if app == nil {
			return nil, ua.StatusBadNotFound
		}
		return app, ua.StatusOK
	}
	if app == nil || !g.selfLocked(c, app) {
		return nil, ua.StatusBadUserAccessDenied
	}
	return app, ua.StatusOK
}

// authorizeTrustList is the Authorize of the TrustList object: reading
// needs the CertificateAuthorityAdmin or SecurityAdmin role or a registered
// application with a certificate of the GDS; changing it the
// CertificateAuthorityAdmin role. The channel must sign; changes need an
// encrypted one.
func (g *GDS) authorizeTrustList(_ context.Context, mc *server.MethodCaller, _ string, write bool) ua.StatusCode {
	c := &caller{mc: mc}
	if sc := c.channelCheck(write); sc != ua.StatusOK {
		return sc
	}
	if g.isCAAdmin(c) {
		return ua.StatusOK
	}
	if write {
		return ua.StatusBadUserAccessDenied
	}
	if c.hasRole(ua.RoleSecurityAdmin.NodeID()) {
		return ua.StatusOK
	}
	if certs, err := uapolicy.ParseCertificates(mc.ClientCertificate); err == nil && len(certs) > 0 {
		c.cert = certs[0]
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, u := range certURIs(c.cert) {
		if app := g.apps[g.byURI[u]]; app != nil && g.selfLocked(c, app) {
			return ua.StatusOK
		}
	}
	return ua.StatusBadUserAccessDenied
}

func certURIs(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}
	out := make([]string, 0, len(cert.URIs))
	for _, u := range cert.URIs {
		out = append(out, u.String())
	}
	return out
}
