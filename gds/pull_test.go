// SPDX-License-Identifier: MIT

package gds_test

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/gds/gdsid"
	"github.com/otfabric/go-opcua/gds/gdsserver"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

// gdsServer starts a GDS whose RSA CA is the CA of the PKI. The admin user
// has the DiscoveryAdmin and CertificateAuthorityAdmin roles.
func gdsServer(t *testing.T, cfg gdsserver.Config) (*gdsserver.GDS, string) {
	t.Helper()
	p := pki(t)
	key, err := x509.MarshalPKCS8PrivateKey(p.CAKey)
	require.NoError(t, err)
	if cfg.CertificateTypes == nil {
		cfg.CertificateTypes = []*ua.NodeID{gds.EccNistP256ApplicationCertificateType, gds.RsaSha256ApplicationCertificateType}
	}
	cfg.Issuers = append(cfg.Issuers, &gdsserver.Issuer{Name: "RSA", Certificate: p.CACert, PrivateKey: key})
	cfg.Logger = slog.New(slog.DiscardHandler)
	var g atomic.Pointer[gdsserver.GDS]
	srv, err := server.New(
		server.EndPoint("localhost", 0),
		server.Certificate(p.ServerCert),
		server.PrivateKey(p.ServerKey),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.WithUsernameValidator(users),
		server.WithRoleMapper(func(tok ua.IdentityToken) []*ua.NodeID {
			if u, ok := tok.(*ua.UserNameIdentityToken); ok && u.UserName == adminUser {
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
	t.Cleanup(func() { _ = srv.Close() })
	return gd, fmt.Sprintf("opc.tcp://localhost:%d", srv.Port())
}

func pullClient(t *testing.T, url, user, pass string) *gds.PullClient {
	t.Helper()
	p := pki(t)
	c, err := dial(t, url, ua.MessageSecurityModeSignAndEncrypt, identity{p.ClientCert, p.ClientKey}, user, pass)
	require.NoError(t, err)
	return gds.NewPullClient(c)
}

func ctxOf(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func serverRecord(uri string) *gds.ApplicationRecord {
	return &gds.ApplicationRecord{
		ApplicationURI:   uri,
		ApplicationType:  ua.ApplicationTypeServer,
		ApplicationNames: []*ua.LocalizedText{ua.NewLocalizedText("Server " + uri)},
		ProductURI:       "urn:otfabric:test",
		DiscoveryURLs:    []string{"opc.tcp://localhost:4840"},
	}
}

// TestPull_EnrollAndApply: a server and a client obtain their certificates
// from the GDS and use them: the client connects to the server, both trust
// the CA of the GDS.
func TestPull_EnrollAndApply(t *testing.T) {
	t.Parallel()
	_, url := gdsServer(t, gdsserver.Config{AutoApprove: true})
	ctx := ctxOf(t)
	admin := pullClient(t, url, adminUser, adminPass)

	srvEnroll, err := admin.Enroll(ctx, &gds.EnrollRequest{
		Record:          serverRecord("urn:otfabric:test:enrolled-server"),
		CertificateType: gds.EccNistP256ApplicationCertificateType,
		SubjectName:     "CN=Enrolled Server/O=otfabric",
		PollInterval:    time.Millisecond,
	})
	require.NoError(t, err)
	require.NotNil(t, srvEnroll.ApplicationID)
	require.Len(t, srvEnroll.IssuerCertificates, 1)
	require.NotEmpty(t, srvEnroll.TrustList.TrustedCrls)

	key, err := testpki.NewKey(testpki.CurveP256)
	require.NoError(t, err)
	cliRec := serverRecord("urn:otfabric:test:enrolled-client")
	cliRec.ApplicationType = ua.ApplicationTypeClient
	cliRec.DiscoveryURLs = nil
	cliEnroll, err := admin.Enroll(ctx, &gds.EnrollRequest{
		Record:          cliRec,
		CertificateType: gds.EccNistP256ApplicationCertificateType,
		Key:             key,
		SubjectName:     "CN=Enrolled Client",
	})
	require.NoError(t, err)
	require.Equal(t, key, cliEnroll.PrivateKey)

	// Enrolling again finds the registered application.
	again, err := admin.Enroll(ctx, &gds.EnrollRequest{Record: cliRec, CertificateType: gds.EccNistP256ApplicationCertificateType, Key: key})
	require.NoError(t, err)
	require.True(t, again.ApplicationID.Equal(cliEnroll.ApplicationID))
	// With the ApplicationId only.
	_, err = admin.Enroll(ctx, &gds.EnrollRequest{ApplicationID: cliEnroll.ApplicationID, CertificateType: gds.EccNistP256ApplicationCertificateType, Key: key})
	require.NoError(t, err)
	_, err = admin.Enroll(ctx, &gds.EnrollRequest{})
	require.Error(t, err)

	// The enrolled server.
	srv, err := server.New(append(srvEnroll.ServerOptions(),
		server.EndPoint("localhost", 0),
		server.EnableSecurity(ua.SecurityPolicyURIECCNistP256, ua.MessageSecurityModeSignAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
	)...)
	require.NoError(t, err)
	require.NoError(t, srv.Start(ctx))
	t.Cleanup(func() { _ = srv.Close() })
	surl := fmt.Sprintf("opc.tcp://localhost:%d", srv.Port())

	eps, err := opcua.GetEndpoints(ctx, surl)
	require.NoError(t, err)
	var ep *ua.EndpointDescription
	for _, e := range eps {
		if e.SecurityPolicyURI == ua.SecurityPolicyURIECCNistP256 {
			ep = e
		}
	}
	require.NotNil(t, ep)
	connect := func(e *gds.Enrollment) error {
		opts, err := e.ClientOptions()
		require.NoError(t, err)
		c, err := opcua.NewClient(surl, append([]opcua.Option{opcua.InsecureNoSecurity()}, append(opts, opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous), opcua.AutoReconnect(false))...)...)
		require.NoError(t, err)
		defer func() { _ = c.Close(context.Background()) }()
		return c.Connect(ctx)
	}
	require.NoError(t, connect(cliEnroll))

	// A client the GDS did not issue a certificate to is refused.
	stranger := pki(t).ECC.Stranger
	err = connect(&gds.Enrollment{Certificate: stranger.Cert, PrivateKey: stranger.Key, TrustList: cliEnroll.TrustList})
	require.Error(t, err)

	// ServerOptions without a trust list and ClientOptions with a bad one.
	require.Len(t, (&gds.Enrollment{Certificate: stranger.Cert, PrivateKey: stranger.Key}).ServerOptions(), 2)
	_, err = (&gds.Enrollment{TrustList: &ua.TrustListDataType{TrustedCertificates: [][]byte{[]byte("junk")}}}).ClientOptions()
	require.Error(t, err)
	opts, err := (&gds.Enrollment{Certificate: stranger.Cert, PrivateKey: stranger.Key}).ClientOptions()
	require.NoError(t, err)
	require.Len(t, opts, 3)
}

// TestPull_Methods drives every method of the Directory.
func TestPull_Methods(t *testing.T) {
	t.Parallel()
	g, url := gdsServer(t, gdsserver.Config{})
	ctx := ctxOf(t)
	admin := pullClient(t, url, adminUser, adminPass)

	ns, err := admin.Namespace(ctx)
	require.NoError(t, err)
	require.Equal(t, g.Namespace(), ns)
	group, err := admin.DefaultApplicationGroup(ctx)
	require.NoError(t, err)
	require.True(t, group.Equal(g.DefaultApplicationGroup()))

	rec := serverRecord("urn:otfabric:test:methods")
	appID, err := admin.RegisterApplication(ctx, rec)
	require.NoError(t, err)
	got, err := admin.GetApplication(ctx, appID)
	require.NoError(t, err)
	require.Equal(t, rec.ApplicationURI, got.ApplicationURI)
	got.ServerCapabilities = []string{"DA"}
	require.NoError(t, admin.UpdateApplication(ctx, got))
	found, err := admin.FindApplications(ctx, rec.ApplicationURI)
	require.NoError(t, err)
	require.Equal(t, []string{"DA"}, found[0].ServerCapabilities)

	apps, err := admin.QueryApplications(ctx, nil)
	require.NoError(t, err)
	require.Len(t, apps.Applications, 1)
	servers, err := admin.QueryServers(ctx, &gds.ServerQuery{ServerCapabilities: []string{"DA"}})
	require.NoError(t, err)
	require.Len(t, servers.Servers, 1)
	require.Equal(t, "opc.tcp://localhost:4840", servers.Servers[0].DiscoveryURL)

	// A pending request: polling ends with the context, or with the
	// approval.
	reqID, err := admin.StartNewKeyPairRequest(ctx, appID, &gds.NewKeyPairRequest{CertificateType: gds.RsaSha256ApplicationCertificateType, PrivateKeyPassword: "pw"})
	require.NoError(t, err)
	short, cancel := context.WithCancel(ctx)
	cancel()
	_, err = admin.WaitForCertificate(short, appID, reqID, time.Millisecond)
	require.Error(t, err)
	done := make(chan error, 1)
	var res *gds.IssuedCertificate
	go func() {
		var err error
		res, err = admin.WaitForCertificate(ctx, appID, reqID, time.Millisecond)
		done <- err
	}()
	require.NoError(t, g.ApproveRequest(ctx, g.RequestID(reqID), true))
	require.NoError(t, <-done)
	k, err := gds.DecodePrivateKey(gds.PrivateKeyFormatPEM, res.PrivateKey, "pw")
	require.NoError(t, err)
	require.True(t, uapolicy.KeyMatchesCertificate(k, res.Certificate))

	// CSR with the RSA key of the PKI.
	csr, err := gds.NewCertificateRequest(pki(t).ServerKey, rec.ApplicationURI, "", []string{"localhost", "127.0.0.1", ""})
	require.NoError(t, err)
	reqID, err = admin.StartSigningRequest(ctx, appID, nil, gds.RsaSha256ApplicationCertificateType, csr)
	require.NoError(t, err)
	_, err = admin.FinishRequest(ctx, appID, reqID)
	require.ErrorIs(t, err, ua.StatusBadNothingToDo)
	var gdsErr *gds.Error
	require.ErrorAs(t, err, &gdsErr)
	require.Equal(t, "FinishRequest", gdsErr.Method)

	groups, err := admin.GetCertificateGroups(ctx, appID)
	require.NoError(t, err)
	require.Len(t, groups, 3, "a server: the application, HTTPS and user token groups")
	types, certs, err := admin.GetCertificates(ctx, appID, nil)
	require.NoError(t, err)
	require.Len(t, types, 1)
	require.Equal(t, res.Certificate, certs[0])
	update, err := admin.GetCertificateStatus(ctx, appID, nil, gds.RsaSha256ApplicationCertificateType)
	require.NoError(t, err)
	require.False(t, update)
	tlID, err := admin.GetTrustList(ctx, appID, nil)
	require.NoError(t, err)
	require.Equal(t, uint32(gdsid.DirectoryCertificateGroupsDefaultApplicationGroupTrustList), tlID.IntID())
	tl, err := admin.ReadTrustList(ctx, appID, nil)
	require.NoError(t, err)
	require.Len(t, tl.TrustedCertificates, 2)

	require.NoError(t, admin.RevokeCertificate(ctx, appID, res.Certificate))
	status, _, err := admin.CheckRevocationStatus(ctx, res.Certificate)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadCertificateRevoked, status)
	require.NoError(t, admin.UnregisterApplication(ctx, appID))
	_, err = admin.GetApplication(ctx, appID)
	require.ErrorIs(t, err, ua.StatusBadNotFound)

	_, err = admin.RegisterApplication(ctx, &gds.ApplicationRecord{})
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
}

// TestPull_NoGDS: a server without the GDS namespace.
func TestPull_NoGDS(t *testing.T) {
	t.Parallel()
	_, url := newServer(t, server.PushManagement{})
	p := pki(t)
	c, err := dial(t, url, ua.MessageSecurityModeSignAndEncrypt, identity{p.ClientCert, p.ClientKey}, "", "")
	require.NoError(t, err)
	pc := gds.NewPullClient(c)
	ctx := ctxOf(t)
	_, err = pc.Namespace(ctx)
	require.Error(t, err)
	calls := []func() error{
		func() error { _, err := pc.RegisterApplication(ctx, serverRecord("urn:x")); return err },
		func() error { return pc.UpdateApplication(ctx, serverRecord("urn:x")) },
		func() error { return pc.UnregisterApplication(ctx, nil) },
		func() error { _, err := pc.FindApplications(ctx, "urn:x"); return err },
		func() error { _, err := pc.GetApplication(ctx, nil); return err },
		func() error { _, err := pc.QueryApplications(ctx, nil); return err },
		func() error { _, err := pc.QueryServers(ctx, nil); return err },
		func() error { _, err := pc.StartSigningRequest(ctx, nil, nil, nil, nil); return err },
		func() error { _, err := pc.StartNewKeyPairRequest(ctx, nil, nil); return err },
		func() error { _, err := pc.FinishRequest(ctx, nil, nil); return err },
		func() error { return pc.RevokeCertificate(ctx, nil, nil) },
		func() error { _, err := pc.GetCertificateGroups(ctx, nil); return err },
		func() error { _, _, err := pc.GetCertificates(ctx, nil, nil); return err },
		func() error { _, err := pc.GetTrustList(ctx, nil, nil); return err },
		func() error { _, err := pc.ReadTrustList(ctx, nil, nil); return err },
		func() error { _, err := pc.GetCertificateStatus(ctx, nil, nil, nil); return err },
		func() error { _, _, err := pc.CheckRevocationStatus(ctx, nil); return err },
		func() error {
			_, err := pc.Enroll(ctx, &gds.EnrollRequest{Record: serverRecord("urn:x")})
			return err
		},
	}
	for i, f := range calls {
		require.Error(t, f(), i)
	}
}

type pullHandler = func(args []*ua.Variant) ([]*ua.Variant, ua.StatusCode)

// fakeGDS serves the Directory methods with handlers that answer what a
// misbehaving GDS could.
func fakeGDS(t *testing.T, hs map[uint32]pullHandler) *gds.PullClient {
	t.Helper()
	p := pki(t)
	srv, err := server.New(
		server.EndPoint("localhost", 0),
		server.Certificate(p.ServerCert),
		server.PrivateKey(p.ServerKey),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
	)
	require.NoError(t, err)
	// The real information model, with the methods replaced.
	g, err := gdsserver.Attach(srv, gdsserver.Config{CertificateTypes: []*ua.NodeID{gds.EccNistP256ApplicationCertificateType}, Logger: slog.New(slog.DiscardHandler)})
	require.NoError(t, err)
	for m, h := range hs {
		srv.RegisterMethod(ua.NewNumericNodeID(g.Namespace(), gdsid.Directory), ua.NewNumericNodeID(g.Namespace(), m),
			func(_ context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
				return h(args)
			})
	}
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })
	c, err := dial(t, fmt.Sprintf("opc.tcp://localhost:%d", srv.Port()), ua.MessageSecurityModeSignAndEncrypt, identity{p.ClientCert, p.ClientKey}, "", "")
	require.NoError(t, err)
	return gds.NewPullClient(c)
}

func outs(vs ...any) pullHandler {
	return func([]*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		res := make([]*ua.Variant, len(vs))
		for i, v := range vs {
			res[i] = ua.MustVariant(v)
		}
		return res, ua.StatusOK
	}
}

func TestPull_MisbehavingGDS(t *testing.T) {
	t.Parallel()
	ctx := ctxOf(t)
	wrongRecord := ua.NewExtensionObject(&ua.Range{})
	pc := fakeGDS(t, map[uint32]pullHandler{
		gdsid.DirectoryRegisterApplication:    outs("x"),
		gdsid.DirectoryFindApplications:       outs([]*ua.ExtensionObject{wrongRecord}),
		gdsid.DirectoryGetApplication:         outs(int32(1)),
		gdsid.DirectoryQueryApplications:      outs("x", uint32(0), []*ua.ExtensionObject{}),
		gdsid.DirectoryQueryServers:           outs(time.Now(), []*ua.ExtensionObject{wrongRecord}),
		gdsid.DirectoryStartSigningRequest:    outs(uint32(1)),
		gdsid.DirectoryStartNewKeyPairRequest: outs(uint32(1)),
		gdsid.DirectoryFinishRequest:          outs([]byte{}, []byte{}, [][]byte{}),
		gdsid.DirectoryGetCertificateGroups:   outs("x"),
		gdsid.DirectoryGetCertificates:        outs("x", "y"),
		gdsid.DirectoryGetTrustList:           outs("x"),
		gdsid.DirectoryGetCertificateStatus:   outs("x"),
		gdsid.DirectoryCheckRevocationStatus:  outs("x", "y"),
		gdsid.DirectoryUnregisterApplication:  outs(),
	})
	_, err := pc.RegisterApplication(ctx, serverRecord("urn:x"))
	require.Error(t, err)
	_, err = pc.FindApplications(ctx, "urn:x")
	require.Error(t, err)
	_, err = pc.GetApplication(ctx, nil)
	require.Error(t, err)
	_, err = pc.QueryApplications(ctx, nil)
	require.Error(t, err)
	_, err = pc.QueryServers(ctx, nil)
	require.Error(t, err)
	_, err = pc.StartSigningRequest(ctx, nil, nil, nil, nil)
	require.Error(t, err)
	_, err = pc.StartNewKeyPairRequest(ctx, nil, nil)
	require.Error(t, err)
	_, err = pc.FinishRequest(ctx, nil, nil)
	require.Error(t, err)
	_, err = pc.GetCertificateGroups(ctx, nil)
	require.Error(t, err)
	_, _, err = pc.GetCertificates(ctx, nil, nil)
	require.Error(t, err)
	_, err = pc.GetTrustList(ctx, nil, nil)
	require.Error(t, err)
	_, err = pc.GetCertificateStatus(ctx, nil, nil, nil)
	require.Error(t, err)
	_, _, err = pc.CheckRevocationStatus(ctx, nil)
	require.Error(t, err)
	require.NoError(t, pc.UnregisterApplication(ctx, nil))
	_, err = pc.Enroll(ctx, &gds.EnrollRequest{ApplicationID: ua.NewNumericNodeID(0, 1), Key: pki(t).ClientKey})
	require.Error(t, err)

	// Too few outputs.
	pc = fakeGDS(t, map[uint32]pullHandler{
		gdsid.DirectoryFindApplications:      outs(),
		gdsid.DirectoryQueryApplications:     outs(time.Now(), "x", []*ua.ExtensionObject{}),
		gdsid.DirectoryQueryServers:          outs("x", []*ua.ExtensionObject{}),
		gdsid.DirectoryGetApplication:        outs([]*ua.ExtensionObject{}),
		gdsid.DirectoryFinishRequest:         outs([]byte{1}, "x", [][]byte{}),
		gdsid.DirectoryGetCertificates:       outs([]*ua.NodeID{}, "y"),
		gdsid.DirectoryCheckRevocationStatus: outs(ua.StatusOK, "y"),
	})
	_, err = pc.FindApplications(ctx, "urn:x")
	require.Error(t, err)
	_, err = pc.QueryApplications(ctx, nil)
	require.Error(t, err)
	_, err = pc.QueryServers(ctx, nil)
	require.Error(t, err)
	_, err = pc.GetApplication(ctx, nil)
	require.Error(t, err)
	_, err = pc.FinishRequest(ctx, nil, nil)
	require.Error(t, err)
	_, _, err = pc.GetCertificates(ctx, nil, nil)
	require.Error(t, err)
	_, _, err = pc.CheckRevocationStatus(ctx, nil)
	require.Error(t, err)

	pc = fakeGDS(t, map[uint32]pullHandler{
		gdsid.DirectoryFinishRequest: outs([]byte{1}, []byte{}, "x"),
	})
	_, err = pc.FinishRequest(ctx, nil, nil)
	require.Error(t, err)
}

func TestNewCertificateRequest(t *testing.T) {
	t.Parallel()
	key, err := testpki.NewKey(testpki.CurveP256)
	require.NoError(t, err)
	der, err := gds.NewCertificateRequest(key, "urn:a", "CN=A, O=B, OU=C, C=BE, ST=X, L=Y, DC=z", []string{"h", "::1"})
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	require.Equal(t, "A", csr.Subject.CommonName)
	require.Equal(t, []string{"h"}, csr.DNSNames)
	require.Len(t, csr.IPAddresses, 1)
	require.Equal(t, "urn:a", csr.URIs[0].String())

	_, err = gds.NewCertificateRequest(key, "no scheme", "", nil)
	require.Error(t, err)
	_, err = gds.NewCertificateRequest(key, "urn:a", "CN", nil)
	require.Error(t, err)
	_, err = gds.NewCertificateRequest(key, "urn:a", "X=1", nil)
	require.Error(t, err)
	ed448Key, err := testpki.NewKey(testpki.CurveEd448)
	require.NoError(t, err)
	der, err = gds.NewCertificateRequest(ed448Key, "urn:a", "CN=A/O=B", nil)
	require.NoError(t, err, "uapolicy makes Ed448 requests")
	csr, err = uapolicy.ParseCertificateRequest(der)
	require.NoError(t, err)
	require.NoError(t, uapolicy.CheckCertificateRequestSignature(csr))
}
