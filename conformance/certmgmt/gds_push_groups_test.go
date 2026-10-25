// SPDX-License-Identifier: MIT

package certmgmt

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

// tlsPeerCertificate returns the certificate an HTTPS listener presents.
func tlsPeerCertificate(t *testing.T, addr net.Addr) []byte {
	t.Helper()
	d := &tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // the test reads the certificate only
	conn, err := d.DialContext(context.Background(), "tcp", addr.String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	return conn.(*tls.Conn).ConnectionState().PeerCertificates[0].Raw
}

// TestGDSPush_HTTPSGroup: Part 12 §7.8.3 and §7.10 (1.05): GetCertificates
// of the groups, CreateSelfSignedCertificate of the TLS certificate that the
// opc.https listener presents after ApplyChanges, the TransactionDiagnostics
// of that transaction, and ResetToServerDefaults.
func TestGDSPush_HTTPSGroup(t *testing.T) {
	p := pki(t)
	srv, url := pushServerWith(t, server.PushManagement{}, server.HTTPSEndPoint("localhost", 0))
	_, g := pushAdminClient(t, url)
	ctx := context.Background()

	types, certs, err := g.GetCertificates(ctx, nil)
	require.NoError(t, err)
	require.Equal(t, []*ua.NodeID{gds.RsaSha256ApplicationCertificateType}, types)
	require.Equal(t, [][]byte{p.serverCert}, certs)
	types, certs, err = g.GetCertificates(ctx, gds.DefaultHTTPSGroup)
	require.NoError(t, err)
	require.Equal(t, []*ua.NodeID{gds.HTTPSCertificateType}, types)
	require.Equal(t, [][]byte{p.serverCert}, certs)
	types, _, err = g.GetCertificates(ctx, gds.DefaultUserTokenGroup)
	require.NoError(t, err)
	require.Empty(t, types)
	require.Equal(t, p.serverCert, tlsPeerCertificate(t, srv.HTTPSAddr()))

	tlsCert, err := g.CreateSelfSignedCertificate(ctx, &gds.SelfSignedCertificate{
		CertificateGroup: gds.DefaultHTTPSGroup,
		SubjectName:      "CN=https/O=otfabric",
		DNSNames:         []string{"localhost"},
		IPAddresses:      []string{"127.0.0.1"},
		LifetimeInDays:   2,
	})
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(tlsCert)
	require.NoError(t, err)
	require.Equal(t, "https", parsed.Subject.CommonName)
	require.Equal(t, p.serverCert, tlsPeerCertificate(t, srv.HTTPSAddr()), "not before ApplyChanges")
	require.NoError(t, g.ApplyChanges(ctx))
	require.Equal(t, tlsCert, tlsPeerCertificate(t, srv.HTTPSAddr()))
	// The application instance certificate stays.
	_, certs, err = g.GetCertificates(ctx, gds.DefaultApplicationGroup)
	require.NoError(t, err)
	require.Equal(t, [][]byte{p.serverCert}, certs)

	d, err := g.TransactionDiagnostics(ctx)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, d.Result)
	require.Equal(t, []*ua.NodeID{gds.DefaultHTTPSGroup}, d.AffectedCertificateGroups)
	require.False(t, d.EndTime.Before(d.StartTime))
	require.Empty(t, d.Errors)

	require.NoError(t, g.ResetToServerDefaults(ctx))
	require.Equal(t, p.serverCert, tlsPeerCertificate(t, srv.HTTPSAddr()))

	// The TransactionDiagnostics are for SecurityAdmin only.
	anon, err := pushDial(t, url, ua.MessageSecurityModeSignAndEncrypt, p.clientCert, p.clientKey, false)
	require.NoError(t, err)
	_, err = gds.New(anon).TransactionDiagnostics(ctx)
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
	_, _, err = gds.New(anon).GetCertificates(ctx, nil)
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
}

// TestGDSPush_UserTokenGroup: X.509 user identity tokens are validated
// against the trust list of the DefaultUserTokenGroup, which the admin
// changes over its own TrustList object.
func TestGDSPush_UserTokenGroup(t *testing.T) {
	p := pki(t)
	_, url := pushServerWith(t, server.PushManagement{}, server.EnableAuthMode(ua.UserTokenTypeCertificate))
	_, g := pushAdminClient(t, url)
	ctx := context.Background()
	ep := endpointFor(t, url, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)
	dialUser := func() error {
		_, err := dialClient(t, url,
			opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeCertificate),
			opcua.Certificate(p.clientCert),
			opcua.PrivateKey(p.clientKey),
			opcua.InsecureSkipVerify(),
			opcua.AuthCertificate(p.userCert),
			opcua.AuthPrivateKey(p.userKey),
		)
		return err
	}
	require.ErrorIs(t, dialUser(), ua.StatusBadIdentityTokenRejected)
	rejected, err := g.GetRejectedList(ctx)
	require.NoError(t, err)
	require.Contains(t, rejected, p.userCert)

	ut := g.WithTrustList(gds.UserTokenTrustList)
	require.NoError(t, ut.AddCertificate(ctx, p.userCert, true))
	require.NoError(t, g.ApplyChanges(ctx))
	require.NoError(t, dialUser())
	tl, err := ut.ReadTrustList(ctx, ua.TrustListMasksAll)
	require.NoError(t, err)
	require.Equal(t, [][]byte{p.userCert}, tl.TrustedCertificates)
	// The application trust list is another one.
	app, err := g.ReadTrustList(ctx, ua.TrustListMasksTrustedCertificates)
	require.NoError(t, err)
	require.Equal(t, [][]byte{p.clientCert}, app.TrustedCertificates)
}

// TestGDSPush_PFXAndAlarms: UpdateCertificate with the key in a PKCS #12
// file, and the CertificateExpired alarm of the DefaultApplicationGroup,
// active because the certificate expires within ExpirationLimit.
func TestGDSPush_PFXAndAlarms(t *testing.T) {
	p := pki(t)
	src, err := testpki.Get()
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(src.CACert)
	require.NoError(t, err)
	url := pushServer(t, server.PushManagement{
		PFXPassword: func(context.Context, *ua.NodeID, *ua.NodeID) (string, error) { return "pfx-secret", nil },
		// The certificates of the PKI are valid for a day.
		Alarms: &server.CertificateAlarms{ExpirationLimit: 48 * time.Hour},
	})
	c, g := pushAdminClient(t, url)
	ctx := context.Background()

	path := func(names ...string) *ua.NodeID {
		t.Helper()
		qn := make([]*ua.QualifiedName, len(names))
		for i, n := range names {
			qn[i] = &ua.QualifiedName{Name: n}
		}
		nid, err := c.Node(gds.ServerConfiguration).TranslateBrowsePathsToNodeIDs(ctx, qn)
		require.NoError(t, err, "%v", names)
		return nid
	}
	read := func(n *ua.NodeID) any {
		t.Helper()
		dv, err := c.ReadValue(ctx, n)
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, dv.Status)
		return dv.Value.Value()
	}
	alarm := []string{"CertificateGroups", "DefaultApplicationGroup", "CertificateExpired"}
	require.Equal(t, true, read(path(append(alarm, "ActiveState", "Id")...)))
	serverX, err := x509.ParseCertificate(p.serverCert)
	require.NoError(t, err)
	require.Equal(t, serverX.NotAfter.UTC().Truncate(time.Millisecond), read(path(append(alarm, "ExpirationDate")...)).(time.Time).Truncate(time.Millisecond))
	require.Equal(t, p.serverCert, read(path(append(alarm, "Certificate")...)))
	require.Equal(t, false, read(path("CertificateGroups", "DefaultApplicationGroup", "TrustListOutOfDate", "ActiveState", "Id")))

	// The CA issues a certificate for the current key, which goes with
	// that key in a password-protected PFX.
	csr, err := g.CreateSigningRequest(ctx, &gds.SigningRequest{CertificateType: gds.RsaSha256ApplicationCertificateType})
	require.NoError(t, err)
	cert, err := testpki.IssueFromCSR(csr, ca, src.CAKey)
	require.NoError(t, err)
	pfx, err := uapolicy.EncodePFX(p.serverKey, [][]byte{cert, src.CACert}, "pfx-secret")
	require.NoError(t, err)
	required, err := g.UpdateCertificate(ctx, &gds.CertificateUpdate{
		CertificateType:    gds.RsaSha256ApplicationCertificateType,
		Certificate:        cert,
		IssuerCertificates: [][]byte{src.CACert},
		PrivateKeyFormat:   "PFX",
		PrivateKey:         pfx,
	})
	require.NoError(t, err)
	require.True(t, required)
	require.NoError(t, g.ApplyChanges(ctx))
	require.Equal(t, cert, endpointFor(t, url, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt).ServerCertificate)
	// The alarm follows the new certificate (evaluated by the server's
	// goroutine after ApplyChanges).
	require.Eventually(t, func() bool {
		dv, err := c.ReadValue(ctx, path(append(alarm, "Certificate")...))
		return err == nil && dv.Value != nil && string(dv.Value.Value().([]byte)) == string(cert)
	}, 10*time.Second, 5*time.Millisecond)

	// A PFX with another password is refused.
	wrong, err := uapolicy.EncodePFX(p.serverKey, nil, "other")
	require.NoError(t, err)
	_, err = g.UpdateCertificate(ctx, &gds.CertificateUpdate{
		CertificateType: gds.RsaSha256ApplicationCertificateType, Certificate: cert,
		PrivateKeyFormat: "PFX", PrivateKey: wrong,
	})
	require.ErrorIs(t, err, ua.StatusBadSecurityChecksFailed)
}
