// SPDX-License-Identifier: MIT

package gds_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

func TestConfigurationMethods(t *testing.T) {
	p := pki(t)
	srv, url := newServer(t, server.PushManagement{})
	g := admin(t, url)
	ctx := context.Background()

	types, certs, err := g.GetCertificates(ctx, nil)
	require.NoError(t, err)
	require.Equal(t, []*ua.NodeID{gds.RsaSha256ApplicationCertificateType}, types)
	require.Equal(t, [][]byte{p.ServerCert}, certs)

	cert, err := g.CreateSelfSignedCertificate(ctx, &gds.SelfSignedCertificate{
		CertificateType: gds.RsaSha256ApplicationCertificateType,
		SubjectName:     "CN=renewed/O=otfabric",
		DNSNames:        []string{"localhost"},
		LifetimeInDays:  10,
	})
	require.NoError(t, err)
	parsed, err := uapolicy.ParseCertificate(cert)
	require.NoError(t, err)
	require.Equal(t, "renewed", parsed.Subject.CommonName)
	d, err := g.TransactionDiagnostics(ctx)
	require.NoError(t, err)
	require.Equal(t, []*ua.NodeID{gds.DefaultApplicationGroup}, d.AffectedCertificateGroups)
	require.Empty(t, d.AffectedTrustLists)
	require.True(t, d.EndTime.IsZero() || d.EndTime.Before(d.StartTime), "in progress")
	require.NoError(t, g.ApplyChanges(ctx))
	_, certs, err = g.GetCertificates(ctx, gds.DefaultApplicationGroup)
	require.NoError(t, err)
	require.Equal(t, [][]byte{cert}, certs)
	d, err = g.TransactionDiagnostics(ctx)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, d.Result)

	// The HTTPS trust list over its own TrustList object.
	h := g.WithTrustList(gds.HTTPSTrustList)
	require.NoError(t, h.AddCertificate(ctx, p.CACert, true))
	require.NoError(t, h.RemoveCertificate(ctx, gds.Thumbprint(p.CACert), true))
	require.NoError(t, h.AddCertificate(ctx, p.CACert, false))
	required, err := h.WriteTrustList(ctx, &ua.TrustListDataType{SpecifiedLists: uint32(ua.TrustListMasksTrustedCertificates), TrustedCertificates: [][]byte{p.UserCert}})
	require.NoError(t, err)
	require.True(t, required)
	d, err = g.TransactionDiagnostics(ctx)
	require.NoError(t, err)
	require.Equal(t, []*ua.NodeID{gds.HTTPSTrustList}, d.AffectedTrustLists)
	require.NoError(t, g.ApplyChanges(ctx))
	tl, err := h.ReadTrustList(ctx, ua.TrustListMasksAll)
	require.NoError(t, err)
	require.Equal(t, [][]byte{p.UserCert}, tl.TrustedCertificates)
	require.Equal(t, [][]byte{p.CACert}, tl.IssuerCertificates)
	require.Equal(t, tl.TrustedCertificates, srv.GroupTrustList(gds.DefaultHTTPSGroup).TrustedCertificates)

	require.NoError(t, g.ResetToServerDefaults(ctx))
	_, certs, err = g.GetCertificates(ctx, nil)
	require.NoError(t, err)
	require.Equal(t, [][]byte{p.ServerCert}, certs)
	require.Empty(t, srv.GroupTrustList(gds.DefaultHTTPSGroup).TrustedCertificates)

	// Not for others.
	op, err := dial(t, url, ua.MessageSecurityModeSignAndEncrypt, identity{p.ClientCert, p.ClientKey}, opUser, opPass)
	require.NoError(t, err)
	_, err = gds.New(op).TransactionDiagnostics(ctx)
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
	_, err = gds.New(op).CreateSelfSignedCertificate(ctx, &gds.SelfSignedCertificate{})
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
	require.ErrorIs(t, gds.New(op).ResetToServerDefaults(ctx), ua.StatusBadUserAccessDenied)
}

// TestMisbehavingConfigurationServer: a push server whose methods answer
// what a misbehaving server could.
func TestMisbehavingConfigurationServer(t *testing.T) {
	p := pki(t)
	srv, err := server.New(
		server.EndPoint("localhost", 0),
		server.Certificate(p.ServerCert),
		server.PrivateKey(p.ServerKey),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.WithPushManagement(server.PushManagement{TrustList: &ua.TrustListDataType{TrustedCertificates: [][]byte{p.ClientCert}}}),
	)
	require.NoError(t, err)
	reg := func(m uint32, h handler) {
		srv.RegisterMethod(ua.NewNumericNodeID(0, id.ServerConfiguration), ua.NewNumericNodeID(0, m),
			func(_ context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
				return h(args)
			})
	}
	reg(id.ServerConfigurationGetCertificates, out([]*ua.NodeID{gds.HTTPSCertificateType}, [][]byte{}))
	reg(id.ServerConfigurationCreateSelfSignedCertificate, out([]byte{}))
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })
	c, err := dial(t, fmt.Sprintf("opc.tcp://localhost:%d", srv.Port()), ua.MessageSecurityModeSignAndEncrypt, identity{p.ClientCert, p.ClientKey}, "", "")
	require.NoError(t, err)
	g := gds.New(c)
	ctx := context.Background()
	_, _, err = g.GetCertificates(ctx, nil)
	require.ErrorContains(t, err, "same length")
	_, err = g.CreateSelfSignedCertificate(ctx, &gds.SelfSignedCertificate{})
	require.ErrorContains(t, err, "no certificate")
	_, err = g.TransactionDiagnostics(ctx)
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)

	reg(id.ServerConfigurationGetCertificates, out(nil, nil))
	types, certs, err := g.GetCertificates(ctx, gds.DefaultUserTokenGroup)
	require.NoError(t, err)
	require.Empty(t, types)
	require.Empty(t, certs)
	reg(id.ServerConfigurationGetCertificates, out("x", 1))
	_, _, err = g.GetCertificates(ctx, nil)
	require.Error(t, err)

	require.NoError(t, c.Close(ctx))
	_, err = g.TransactionDiagnostics(ctx)
	require.Error(t, err)
	_, _, err = g.GetCertificates(ctx, nil)
	require.Error(t, err)
	_, err = gds.New(c).CreateSelfSignedCertificate(ctx, &gds.SelfSignedCertificate{})
	require.Error(t, err)
	require.Error(t, gds.New(c).ResetToServerDefaults(ctx))
}
