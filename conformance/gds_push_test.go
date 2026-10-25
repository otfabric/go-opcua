// SPDX-License-Identifier: MIT

package conformance

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// Push certificate management (Part 12 §7): the ServerConfiguration object
// over the wire, driven by package gds. The keys are those of the shared PKI;
// no test here generates one.

const (
	pushAdmin     = "secadmin"
	pushAdminPass = "secadmin-pw"
)

func pushServer(t *testing.T, pm server.PushManagement) string {
	t.Helper()
	p := pki(t)
	if pm.TrustList == nil {
		pm.TrustList = &ua.TrustListDataType{TrustedCertificates: [][]byte{p.clientCert}}
	}
	_, url := newServer(t,
		server.Certificate(p.serverCert),
		server.PrivateKey(p.serverKey),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSign),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.WithUsernameValidator(func(user, pass string) error {
			if user == pushAdmin && pass == pushAdminPass {
				return nil
			}
			return ua.StatusBadUserAccessDenied
		}),
		server.WithRoleMapper(func(tok ua.IdentityToken) []*ua.NodeID {
			if _, ok := tok.(*ua.UserNameIdentityToken); ok {
				return []*ua.NodeID{ua.RoleAuthenticatedUser.NodeID(), ua.RoleSecurityAdmin.NodeID()}
			}
			return server.DefaultRoleMapper(tok)
		}),
		server.WithPushManagement(pm),
	)
	return url
}

// pushDial connects over Basic256Sha256 with the application certificate,
// as the admin or, with admin false, anonymously.
func pushDial(t *testing.T, url string, mode ua.MessageSecurityMode, cert []byte, key *rsa.PrivateKey, admin bool) (*opcua.Client, error) {
	t.Helper()
	tok := ua.UserTokenTypeAnonymous
	if admin {
		tok = ua.UserTokenTypeUserName
	}
	opts := []opcua.Option{
		opcua.SecurityFromEndpoint(endpointFor(t, url, ua.SecurityPolicyURIBasic256Sha256, mode), tok),
		opcua.Certificate(cert),
		opcua.PrivateKey(key),
		opcua.InsecureSkipVerify(),
	}
	if admin {
		opts = append(opts, opcua.AuthUsername(pushAdmin, pushAdminPass))
	}
	return dialClient(t, url, opts...)
}

func pushAdminClient(t *testing.T, url string) (*opcua.Client, *gds.Client) {
	t.Helper()
	p := pki(t)
	c, err := pushDial(t, url, ua.MessageSecurityModeSignAndEncrypt, p.clientCert, p.clientKey, true)
	require.NoError(t, err)
	return c, gds.New(c)
}

// TestGDSPush_AddressSpace: the ServerConfiguration object is a component
// of the Server object with the DefaultApplicationGroup, its TrustList and
// the methods of Part 12 §7.10.3.
func TestGDSPush_AddressSpace(t *testing.T) {
	url := pushServer(t, server.PushManagement{})
	c, g := pushAdminClient(t, url)
	ctx := context.Background()

	names := func(nid uint32, ref uint32) map[string]bool {
		t.Helper()
		refs, err := c.Node(ua.NewNumericNodeID(0, nid)).References(ctx, ref, ua.BrowseDirectionForward, ua.NodeClassAll, true)
		require.NoError(t, err)
		out := map[string]bool{}
		for _, r := range refs {
			out[r.BrowseName.Name] = true
		}
		return out
	}
	require.True(t, names(id.Server, id.HasComponent)["ServerConfiguration"])
	sc := names(id.ServerConfiguration, id.HasComponent)
	for _, m := range []string{"UpdateCertificate", "CreateSigningRequest", "CreateSelfSignedCertificate", "GetCertificates", "GetRejectedList",
		"ApplyChanges", "CancelChanges", "ResetToServerDefaults", "CertificateGroups", "TransactionDiagnostics"} {
		require.True(t, sc[m], m)
	}
	groups := names(id.ServerConfigurationCertificateGroups, id.HasComponent)
	require.Equal(t, map[string]bool{"DefaultApplicationGroup": true, "DefaultHttpsGroup": true, "DefaultUserTokenGroup": true}, groups)
	tl := names(id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustList, id.HasComponent)
	for _, m := range []string{"Open", "OpenWithMasks", "Read", "Write", "Close", "CloseAndUpdate", "AddCertificate", "RemoveCertificate"} {
		require.True(t, tl[m], m)
	}

	props, err := g.Properties(ctx)
	require.NoError(t, err)
	require.Equal(t, []string{"PEM", "PFX"}, props.SupportedPrivateKeyFormats)
	require.NotZero(t, props.MaxTrustListSize)
	require.Len(t, props.CertificateTypes, 1)
	require.True(t, props.CertificateTypes[0].Equal(gds.RsaSha256ApplicationCertificateType))

	// The TrustList properties follow the file.
	before, err := c.ReadValue(ctx, ua.NewNumericNodeID(0, id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListSize))
	require.NoError(t, err)
	require.NoError(t, g.AddCertificate(ctx, pki(t).caCert, true))
	require.NoError(t, g.ApplyChanges(ctx))
	after, err := c.ReadValue(ctx, ua.NewNumericNodeID(0, id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListSize))
	require.NoError(t, err)
	require.Greater(t, after.Value.Value().(uint64), before.Value.Value().(uint64))
}

// TestGDSPush_Authorization: Part 12 §7.2 — the methods need the
// SecurityAdmin role and an encrypted channel.
func TestGDSPush_Authorization(t *testing.T) {
	p := pki(t)
	url := pushServer(t, server.PushManagement{})
	ctx := context.Background()

	anon, err := pushDial(t, url, ua.MessageSecurityModeSignAndEncrypt, p.clientCert, p.clientKey, false)
	require.NoError(t, err)
	_, err = gds.New(anon).ReadTrustList(ctx, ua.TrustListMasksAll)
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
	require.ErrorIs(t, gds.New(anon).ApplyChanges(ctx), ua.StatusBadUserAccessDenied)

	signed, err := pushDial(t, url, ua.MessageSecurityModeSign, p.clientCert, p.clientKey, true)
	require.NoError(t, err)
	_, err = gds.New(signed).GetRejectedList(ctx)
	require.ErrorIs(t, err, ua.StatusBadSecurityModeInsufficient)
	_, err = gds.New(signed).CreateSigningRequest(ctx, &gds.SigningRequest{CertificateType: gds.RsaSha256ApplicationCertificateType})
	require.Error(t, err)

	// The method arguments are checked against their declaration.
	_, g := pushAdminClient(t, url)
	res, err := anon.Call(ctx, &ua.CallMethodRequest{
		ObjectID: gds.ServerConfiguration,
		MethodID: ua.NewNumericNodeID(0, id.ServerConfigurationUpdateCertificate),
	})
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadArgumentsMissing, res.StatusCode)
	_, err = g.UpdateCertificate(ctx, &gds.CertificateUpdate{CertificateType: gds.RsaSha256ApplicationCertificateType, Certificate: []byte{1}})
	require.ErrorIs(t, err, ua.StatusBadCertificateInvalid)
}

// TestGDSPush_TrustList: the trust list decides which client certificates
// new channels accept, after ApplyChanges; the rejected certificates are
// reported.
func TestGDSPush_TrustList(t *testing.T) {
	p := pki(t)
	url := pushServer(t, server.PushManagement{})
	_, g := pushAdminClient(t, url)
	ctx := context.Background()

	_, err := pushDial(t, url, ua.MessageSecurityModeSignAndEncrypt, p.issuedCert, p.issuedKey, false)
	require.ErrorIs(t, err, ua.StatusBadCertificateUntrusted)
	rejected, err := g.GetRejectedList(ctx)
	require.NoError(t, err)
	require.Contains(t, rejected, p.issuedCert)

	tl, err := g.ReadTrustList(ctx, ua.TrustListMasksAll)
	require.NoError(t, err)
	tl.TrustedCertificates = append(tl.TrustedCertificates, p.caCert)
	required, err := g.WriteTrustList(ctx, tl)
	require.NoError(t, err)
	require.True(t, required)
	_, err = pushDial(t, url, ua.MessageSecurityModeSignAndEncrypt, p.issuedCert, p.issuedKey, false)
	require.ErrorIs(t, err, ua.StatusBadCertificateUntrusted, "applied before ApplyChanges")
	require.NoError(t, g.ApplyChanges(ctx))
	c, err := pushDial(t, url, ua.MessageSecurityModeSignAndEncrypt, p.issuedCert, p.issuedKey, false)
	require.NoError(t, err)
	_, err = c.ReadValue(ctx, ua.NewNumericNodeID(0, id.ServerServerStatusState))
	require.NoError(t, err)

	// Remove the CA again; the channel that is open stays.
	require.NoError(t, g.RemoveCertificate(ctx, gds.Thumbprint(p.caCert), true))
	require.NoError(t, g.ApplyChanges(ctx))
	_, err = pushDial(t, url, ua.MessageSecurityModeSignAndEncrypt, p.issuedCert, p.issuedKey, false)
	require.ErrorIs(t, err, ua.StatusBadCertificateUntrusted)
	_, err = c.ReadValue(ctx, ua.NewNumericNodeID(0, id.ServerServerStatusState))
	require.NoError(t, err)
}

// TestGDSPush_SigningRequest: CreateSigningRequest for the existing key, a
// CA signs it, UpdateCertificate with ApplyChanges installs it and new
// channels present it.
func TestGDSPush_SigningRequest(t *testing.T) {
	p := pki(t)
	src, err := testpki.Get()
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(src.CACert)
	require.NoError(t, err)
	url := pushServer(t, server.PushManagement{})
	_, g := pushAdminClient(t, url)
	ctx := context.Background()

	csr, err := g.CreateSigningRequest(ctx, &gds.SigningRequest{CertificateType: gds.RsaSha256ApplicationCertificateType})
	require.NoError(t, err)
	cert, err := testpki.IssueFromCSR(csr, ca, src.CAKey)
	require.NoError(t, err)
	required, err := g.UpdateCertificate(ctx, &gds.CertificateUpdate{
		CertificateType:    gds.RsaSha256ApplicationCertificateType,
		Certificate:        cert,
		IssuerCertificates: [][]byte{src.CACert},
	})
	require.NoError(t, err)
	require.True(t, required)
	require.NoError(t, g.ApplyChanges(ctx))

	ep := endpointFor(t, url, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)
	require.Equal(t, cert, ep.ServerCertificate)
	// A client that trusts the CA validates the new certificate.
	c, err := dialClient(t, url,
		opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous),
		opcua.Certificate(p.clientCert),
		opcua.PrivateKey(p.clientKey),
		opcua.TrustedCertificates(ca),
	)
	require.NoError(t, err)
	require.Equal(t, cert, c.SecureChannel().RemoteCertificate())
	_, err = g.GetRejectedList(ctx) // the admin channel still uses the old certificate
	require.NoError(t, err)
}
