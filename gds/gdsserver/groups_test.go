// SPDX-License-Identifier: MIT

package gdsserver

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/gds/gdsid"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

var httpsType = ua.NewNumericNodeID(0, id.HTTPSCertificateType)

// TestGroups_HTTPS: the DefaultHttpsGroup of a server issues TLS
// certificates from a request (with or without the ApplicationUri) and
// with a key the GDS generates; GetCertificates, GetTrustList and
// GetCertificateStatus answer per group.
func TestGroups_HTTPS(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{AutoApprove: true})
	ctx := ctxT(t)
	uri := "urn:otfabric:test:https"
	appID, err := e.admin().RegisterApplication(ctx, record(uri, "opc.tcp://host.example:4840"))
	require.NoError(t, err)
	ca := e.caAdmin()
	httpsGroup := e.gds.DefaultHTTPSGroup()

	groups, err := ca.GetCertificateGroups(ctx, appID)
	require.NoError(t, err)
	require.Len(t, groups, 3)
	require.True(t, groups[0].Equal(e.gds.DefaultApplicationGroup()))
	require.True(t, groups[1].Equal(httpsGroup))
	require.True(t, groups[2].Equal(e.gds.DefaultUserTokenGroup()))

	update, err := ca.GetCertificateStatus(ctx, appID, httpsGroup, nil)
	require.NoError(t, err)
	require.True(t, update, "no HTTPS certificate yet")

	// A request without the ApplicationUri.
	key := newKey(t, testpki.CurveP256)
	der, err := uapolicy.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "host.example"}, DNSNames: []string{"host.example"}}, key)
	require.NoError(t, err)
	reqID, err := ca.StartSigningRequest(ctx, appID, httpsGroup, httpsType, der)
	require.NoError(t, err)
	res, err := ca.FinishRequest(ctx, appID, reqID)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(res.Certificate)
	require.NoError(t, err)
	require.True(t, uapolicy.KeyMatchesCertificate(key, res.Certificate))
	require.Contains(t, cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	require.Equal(t, []string{"host.example"}, cert.DNSNames)

	// The application group still needs one; the HTTPS group does not.
	update, err = ca.GetCertificateStatus(ctx, appID, httpsGroup, httpsType)
	require.NoError(t, err)
	require.False(t, update)
	update, err = ca.GetCertificateStatus(ctx, appID, nil, nil)
	require.NoError(t, err)
	require.True(t, update)
	types, certs, err := ca.GetCertificates(ctx, appID, httpsGroup)
	require.NoError(t, err)
	require.Len(t, certs, 1)
	require.True(t, types[0].Equal(httpsType))
	require.Equal(t, res.Certificate, certs[0])
	_, certs, err = ca.GetCertificates(ctx, appID, nil)
	require.NoError(t, err)
	require.Empty(t, certs)

	// A key the GDS generates, ECDSA as the GDS has no RSA CA.
	reqID, err = ca.StartNewKeyPairRequest(ctx, appID, &gds.NewKeyPairRequest{CertificateGroup: httpsGroup})
	require.NoError(t, err)
	res, err = ca.FinishRequest(ctx, appID, reqID)
	require.NoError(t, err)
	k, err := gds.DecodePrivateKey(gds.PrivateKeyFormatPEM, res.PrivateKey, "")
	require.NoError(t, err)
	require.True(t, uapolicy.KeyMatchesCertificate(k, res.Certificate))

	// The trust list of the group is a node of its own.
	tlNode, err := ca.GetTrustList(ctx, appID, httpsGroup)
	require.NoError(t, err)
	require.True(t, tlNode.Equal(e.gds.node(gdsid.DirectoryCertificateGroupsDefaultHTTPSGroupTrustList)))
	tl, err := ca.ReadTrustList(ctx, appID, httpsGroup)
	require.NoError(t, err)
	require.Equal(t, e.gds.IssuerCertificates(), tl.TrustedCertificates)
	require.Equal(t, e.gds.GroupTrustList(httpsGroup).TrustedCertificates, tl.TrustedCertificates)
	require.Nil(t, e.gds.GroupTrustList(ua.NewNumericNodeID(e.gds.Namespace(), 9999)))

	// A request with another URI, an application certificate type and a
	// key the group has no CA for are refused.
	_, err = ca.StartSigningRequest(ctx, appID, httpsGroup, httpsType, csrFor(t, key, "urn:other"))
	require.ErrorIs(t, err, ua.StatusBadCertificateURIInvalid)
	_, err = ca.StartSigningRequest(ctx, appID, httpsGroup, p256Type, csrFor(t, key, uri))
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
	_, err = ca.StartSigningRequest(ctx, appID, httpsGroup, httpsType, csrFor(t, newKey(t, testpki.CurveBrainpoolP256r1), uri))
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)

	// The HTTPS revocation is in the CRL of the group.
	require.NoError(t, ca.RevokeCertificate(ctx, appID, certs0(t, ca, appID, httpsGroup)))
	status, _, err := ca.CheckRevocationStatus(ctx, res.Certificate)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadCertificateRevoked, status)
}

// certs0 returns the first certificate of an application in a group.
func certs0(t *testing.T, p *gds.PullClient, appID, group *ua.NodeID) []byte {
	t.Helper()
	_, certs, err := p.GetCertificates(ctxT(t), appID, group)
	require.NoError(t, err)
	require.NotEmpty(t, certs)
	return certs[len(certs)-1]
}

// TestGroups_Client: a client has the DefaultApplicationGroup only; the
// DefaultUserTokenGroup issues nothing and its trust list holds what a
// CertificateAuthorityAdmin adds.
func TestGroups_ClientAndUserToken(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{SelfAdmin: selfAdminAll, AutoApprove: true})
	ctx := ctxT(t)
	appID := e.registerClient()
	self := e.anonymous()
	groups, err := self.GetCertificateGroups(ctx, appID)
	require.NoError(t, err)
	require.Len(t, groups, 1)

	userGroup := e.gds.DefaultUserTokenGroup()
	_, err = self.StartNewKeyPairRequest(ctx, appID, &gds.NewKeyPairRequest{CertificateGroup: userGroup})
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
	tl, err := self.ReadTrustList(ctx, appID, userGroup)
	require.NoError(t, err)
	require.Empty(t, tl.TrustedCertificates)

	push := gds.New(e.dial(dialOpts{user: userCAAdmin}))
	push.TrustList = e.gds.node(gdsid.DirectoryCertificateGroupsDefaultUserTokenGroupTrustList)
	userCA := pkiOf(t).ECC.CAs[testpki.CurveP384].Cert
	require.NoError(t, push.AddCertificate(ctx, userCA, true))
	tl, err = self.ReadTrustList(ctx, appID, userGroup)
	require.NoError(t, err)
	require.Equal(t, [][]byte{userCA}, tl.TrustedCertificates)
	require.NotContains(t, e.gds.TrustList().TrustedCertificates, userCA, "the application group's trust list is apart")

	// It survives a restart.
	e.restart()
	require.Equal(t, [][]byte{userCA}, e.gds.GroupTrustList(userGroup).TrustedCertificates)
}

// TestGroups_HTTPSWithoutCA: a GDS without an RSA or NIST CA has no HTTPS
// certificate type.
func TestGroups_HTTPSWithoutCA(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{CertificateTypes: []*ua.NodeID{gds.EccBrainpoolP256r1ApplicationCertificateType}})
	ctx := ctxT(t)
	appID, err := e.admin().RegisterApplication(ctx, record("urn:otfabric:test:bp"))
	require.NoError(t, err)
	ca := e.caAdmin()
	groups, err := ca.GetCertificateGroups(ctx, appID)
	require.NoError(t, err)
	require.Len(t, groups, 2, "the application and user token groups")
	_, err = ca.StartNewKeyPairRequest(ctx, appID, &gds.NewKeyPairRequest{CertificateGroup: e.gds.DefaultHTTPSGroup()})
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
}

// TestPFX: StartNewKeyPairRequest with the PFX format returns a PKCS #12
// with the key, the certificate and its issuer.
func TestPFX(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{SelfAdmin: selfAdminAll, AutoApprove: true})
	ctx := ctxT(t)
	appID := e.registerClient()
	self := e.anonymous()
	for _, format := range []string{gds.PrivateKeyFormatPFX, "pfx"} {
		reqID, err := self.StartNewKeyPairRequest(ctx, appID, &gds.NewKeyPairRequest{PrivateKeyFormat: format, PrivateKeyPassword: "secret"})
		require.NoError(t, err)
		res, err := self.FinishRequest(ctx, appID, reqID)
		require.NoError(t, err)
		key, certs, err := uapolicy.ParsePFX(res.PrivateKey, "secret")
		require.NoError(t, err)
		require.True(t, uapolicy.KeyMatchesCertificate(key, res.Certificate))
		require.Len(t, certs, 2)
		require.Equal(t, res.Certificate, certs[0].Raw)
		require.Equal(t, res.IssuerCertificates[0], certs[1].Raw)
		_, err = gds.DecodePrivateKey(gds.PrivateKeyFormatPFX, res.PrivateKey, "wrong")
		require.Error(t, err)
	}

	// Enroll with PFX.
	en, err := self.Enroll(ctx, &gds.EnrollRequest{ApplicationID: appID, PrivateKeyFormat: gds.PrivateKeyFormatPFX, PrivateKeyPassword: "pw"})
	require.NoError(t, err)
	require.True(t, uapolicy.KeyMatchesCertificate(en.PrivateKey, en.Certificate))
}

// TestRolePermissions: the methods of the Directory carry the
// RolePermissions of the GDS NodeSet, which the GDS honours besides its
// own checks.
func TestRolePermissions(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{})
	perms := e.gds.rolePermissions(e.gds.node(gdsid.DirectoryRevokeCertificate))
	require.NotEmpty(t, perms)
	caAdmin := &caller{mc: &server.MethodCaller{Roles: []*ua.NodeID{ua.RoleAuthenticatedUser.NodeID(), e.gds.CertificateAuthorityAdminRole()}}}
	anon := &caller{mc: &server.MethodCaller{}}
	user := &caller{mc: &server.MethodCaller{Roles: []*ua.NodeID{ua.RoleAuthenticatedUser.NodeID()}}}
	require.True(t, caAdmin.permits(perms))
	require.False(t, anon.permits(perms))
	require.False(t, user.permits(perms))
	require.True(t, user.permits(nil))
	require.Nil(t, e.gds.rolePermissions(ua.NewNumericNodeID(e.gds.Namespace(), 999999)))
	require.Nil(t, e.gds.rolePermissions(e.gds.node(gdsid.Directory)))

	reg := e.gds.rolePermissions(e.gds.node(gdsid.DirectoryRegisterApplication))
	require.True(t, (&caller{mc: &server.MethodCaller{Roles: []*ua.NodeID{e.gds.DiscoveryAdminRole()}}}).permits(reg))
	require.False(t, caAdmin.permits(reg), "RegisterApplication is for the DiscoveryAdmin")

	// Over the wire: the CertificateAuthorityAdmin may not register.
	_, err := e.caAdmin().RegisterApplication(ctxT(t), record("urn:otfabric:test:rp"))
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
}
