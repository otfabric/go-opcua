// SPDX-License-Identifier: MIT

package conformance

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/gds/gdsid"
	"github.com/otfabric/go-opcua/gds/gdsserver"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// The pull model of Part 12 (§6 and §7.9): a Global Discovery Server of
// package gdsserver over the wire, driven by gds.PullClient. The RSA CA of
// the GDS is the CA of the shared PKI, so no test here generates an RSA
// key.

const (
	gdsAdmin     = "gdsadmin"
	gdsAdminPass = "gdsadmin-pw"
)

func gdsPullServer(t *testing.T, cfg gdsserver.Config) (*gdsserver.GDS, string) {
	t.Helper()
	src, err := testpki.Get()
	require.NoError(t, err)
	caKey, err := x509.MarshalPKCS8PrivateKey(src.CAKey)
	require.NoError(t, err)
	cfg.Issuers = []*gdsserver.Issuer{{Name: "RSA", Certificate: src.CACert, PrivateKey: caKey}}
	cfg.CertificateTypes = []*ua.NodeID{gds.RsaSha256ApplicationCertificateType, gds.EccNistP256ApplicationCertificateType}
	cfg.Logger = slog.New(slog.DiscardHandler)
	p := pki(t)
	parallel(t)
	var g atomic.Pointer[gdsserver.GDS]
	srv, err := server.New(
		server.EndPoint("localhost", 0),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.Certificate(p.serverCert),
		server.PrivateKey(p.serverKey),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSign),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.WithUsernameValidator(func(user, pass string) error {
			if user == gdsAdmin && pass == gdsAdminPass {
				return nil
			}
			return ua.StatusBadUserAccessDenied
		}),
		server.WithRoleMapper(func(tok ua.IdentityToken) []*ua.NodeID {
			if _, ok := tok.(*ua.UserNameIdentityToken); ok {
				return []*ua.NodeID{ua.RoleAuthenticatedUser.NodeID(), g.Load().DiscoveryAdminRole(), g.Load().CertificateAuthorityAdminRole()}
			}
			return server.DefaultRoleMapper(tok)
		}),
	)
	require.NoError(t, err)
	gd, err := gdsserver.Attach(srv, cfg)
	require.NoError(t, err)
	g.Store(gd)
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() {
		gd.Close()
		_ = srv.Close()
	})
	url := fmt.Sprintf("opc.tcp://localhost:%d", srv.Port())
	return gd, url
}

func gdsPullClient(t *testing.T, url string, admin bool) (*opcua.Client, *gds.PullClient) {
	t.Helper()
	p := pki(t)
	tok := ua.UserTokenTypeAnonymous
	if admin {
		tok = ua.UserTokenTypeUserName
	}
	opts := []opcua.Option{
		opcua.SecurityFromEndpoint(endpointFor(t, url, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt), tok),
		opcua.Certificate(p.clientCert),
		opcua.PrivateKey(p.clientKey),
		opcua.InsecureSkipVerify(),
	}
	if admin {
		opts = append(opts, opcua.AuthUsername(gdsAdmin, gdsAdminPass))
	}
	c, err := dialClient(t, url, opts...)
	require.NoError(t, err)
	return c, gds.NewPullClient(c)
}

// TestGDSPull_AddressSpace: the Directory object of Part 12 §6.6.2 with
// the methods of the CertificateDirectoryType and the
// DefaultApplicationGroup with its TrustList.
func TestGDSPull_AddressSpace(t *testing.T) {
	g, url := gdsPullServer(t, gdsserver.Config{})
	c, _ := gdsPullClient(t, url, false)
	ctx := context.Background()
	ns := g.Namespace()

	nsIdx, err := c.FindNamespace(ctx, gdsid.NamespaceURI)
	require.NoError(t, err)
	require.Equal(t, ns, nsIdx)

	refs, err := c.Node(ua.NewNumericNodeID(0, id.ObjectsFolder)).References(ctx, id.Organizes, ua.BrowseDirectionForward, ua.NodeClassObject, true)
	require.NoError(t, err)
	var dir *ua.ReferenceDescription
	for _, r := range refs {
		if r.NodeID.NodeID.Equal(ua.NewNumericNodeID(ns, gdsid.Directory)) {
			dir = r
		}
	}
	require.NotNil(t, dir, "Directory under Objects")
	require.Equal(t, &ua.QualifiedName{NamespaceIndex: ns, Name: "Directory"}, dir.BrowseName)
	require.True(t, dir.TypeDefinition.NodeID.Equal(ua.NewNumericNodeID(ns, gdsid.CertificateDirectoryType)))

	methods, err := c.Node(ua.NewNumericNodeID(ns, gdsid.Directory)).References(ctx, id.HasComponent, ua.BrowseDirectionForward, ua.NodeClassMethod, true)
	require.NoError(t, err)
	names := map[string]uint16{}
	for _, m := range methods {
		names[m.BrowseName.Name] = m.BrowseName.NamespaceIndex
	}
	for _, m := range []string{"FindApplications", "RegisterApplication", "UpdateApplication", "UnregisterApplication",
		"GetApplication", "QueryApplications", "QueryServers", "StartSigningRequest", "StartNewKeyPairRequest",
		"FinishRequest", "RevokeCertificate", "GetCertificateGroups", "GetCertificates", "GetTrustList",
		"GetCertificateStatus", "CheckRevocationStatus"} {
		require.Equal(t, ns, names[m], m)
	}

	groups, err := c.Node(ua.NewNumericNodeID(ns, gdsid.DirectoryCertificateGroups)).References(ctx, id.HierarchicalReferences, ua.BrowseDirectionForward, ua.NodeClassObject, true)
	require.NoError(t, err)
	require.Len(t, groups, 1)
	require.Equal(t, "DefaultApplicationGroup", groups[0].BrowseName.Name)

	// The TrustList methods keep their browse names of namespace 0.
	tl, err := c.Node(ua.NewNumericNodeID(ns, gdsid.DirectoryCertificateGroupsDefaultApplicationGroupTrustList)).References(ctx, id.HasComponent, ua.BrowseDirectionForward, ua.NodeClassMethod, true)
	require.NoError(t, err)
	tlNames := map[string]bool{}
	for _, m := range tl {
		require.Zero(t, m.BrowseName.NamespaceIndex, m.BrowseName.Name)
		tlNames[m.BrowseName.Name] = true
	}
	for _, m := range []string{"Open", "OpenWithMasks", "Read", "Close", "CloseAndUpdate", "AddCertificate", "RemoveCertificate"} {
		require.True(t, tlNames[m], m)
	}

	types, err := c.ReadValue(ctx, ua.NewNumericNodeID(ns, gdsid.DirectoryCertificateGroupsDefaultApplicationGroupCertificateTypes))
	require.NoError(t, err)
	require.Equal(t, []*ua.NodeID{gds.RsaSha256ApplicationCertificateType, gds.EccNistP256ApplicationCertificateType}, types.Value.Value())

	// The methods declare their arguments (Part 3 §5.7.1).
	args, err := c.ReadValue(ctx, ua.NewNumericNodeID(ns, gdsid.DirectoryRegisterApplicationInputArguments))
	require.NoError(t, err)
	require.Len(t, args.Value.Value(), 1)
}

// TestGDSPull_Lifecycle: register, request, approve, finish, use and
// revoke a certificate.
func TestGDSPull_Lifecycle(t *testing.T) {
	g, url := gdsPullServer(t, gdsserver.Config{})
	_, admin := gdsPullClient(t, url, true)
	ctx := context.Background()

	rec := &gds.ApplicationRecord{
		ApplicationURI:   "urn:otfabric:conformance:gds-app",
		ApplicationType:  ua.ApplicationTypeServer,
		ApplicationNames: []*ua.LocalizedText{ua.NewLocalizedText("GDS app")},
		ProductURI:       "urn:otfabric:conformance",
		DiscoveryURLs:    []string{"opc.tcp://localhost:4841"},
	}
	appID, err := admin.RegisterApplication(ctx, rec)
	require.NoError(t, err)

	reqID, err := admin.StartNewKeyPairRequest(ctx, appID, &gds.NewKeyPairRequest{CertificateType: gds.EccNistP256ApplicationCertificateType})
	require.NoError(t, err)
	_, err = admin.FinishRequest(ctx, appID, reqID)
	require.ErrorIs(t, err, ua.StatusBadNothingToDo, "waiting for approval")
	require.NoError(t, g.ApproveRequest(ctx, g.RequestID(reqID), true))
	res, err := admin.FinishRequest(ctx, appID, reqID)
	require.NoError(t, err)
	key, err := gds.DecodePrivateKey(gds.PrivateKeyFormatPEM, res.PrivateKey, "")
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(res.Certificate)
	require.NoError(t, err)
	require.Equal(t, rec.ApplicationURI, cert.URIs[0].String())
	require.Equal(t, []string{"localhost"}, cert.DNSNames)

	tl, err := admin.ReadTrustList(ctx, appID, nil)
	require.NoError(t, err)
	require.Len(t, tl.TrustedCertificates, 2)
	require.Len(t, tl.TrustedCrls, 2)

	status, _, err := admin.CheckRevocationStatus(ctx, res.Certificate)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, status)
	require.NoError(t, admin.RevokeCertificate(ctx, appID, res.Certificate))
	status, _, err = admin.CheckRevocationStatus(ctx, res.Certificate)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadCertificateRevoked, status)
	require.NotNil(t, key)

	// The directory is open for queries; the rest needs a role.
	_, anon := gdsPullClient(t, url, false)
	found, err := anon.QueryServers(ctx, nil)
	require.NoError(t, err)
	require.Len(t, found.Servers, 1)
	_, err = anon.RegisterApplication(ctx, rec)
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
	_, err = anon.StartNewKeyPairRequest(ctx, appID, nil)
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
	require.ErrorIs(t, anon.RevokeCertificate(ctx, appID, res.Certificate), ua.StatusBadUserAccessDenied)
}
