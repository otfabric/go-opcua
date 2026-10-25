// SPDX-License-Identifier: MIT

package gds_test

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

const (
	adminUser = "admin"
	adminPass = "admin-secret"
	opUser    = "operator"
	opPass    = "operator-secret"
)

func pki(t *testing.T) *testpki.PKI {
	t.Helper()
	p, err := testpki.Get()
	require.NoError(t, err)
	return p
}

func users(user, pass string) error {
	if (user == adminUser && pass == adminPass) || (user == opUser && pass == opPass) {
		return nil
	}
	return ua.StatusBadUserAccessDenied
}

// roles grants the SecurityAdmin role to the admin user.
func roles(tok ua.IdentityToken) []*ua.NodeID {
	if u, ok := tok.(*ua.UserNameIdentityToken); ok && u.UserName == adminUser {
		return []*ua.NodeID{ua.RoleAuthenticatedUser.NodeID(), ua.RoleSecurityAdmin.NodeID()}
	}
	return server.DefaultRoleMapper(tok)
}

// newServer starts a server with push management whose trust list holds
// the client certificate of the PKI.
func newServer(t *testing.T, pm server.PushManagement, extra ...server.Option) (*server.Server, string) {
	t.Helper()
	p := pki(t)
	if pm.TrustList == nil {
		pm.TrustList = &ua.TrustListDataType{TrustedCertificates: [][]byte{p.ClientCert}}
	}
	opts := append([]server.Option{
		server.EndPoint("localhost", 0),
		server.Certificate(p.ServerCert),
		server.PrivateKey(p.ServerKey),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSign),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.WithUsernameValidator(users),
		server.WithRoleMapper(roles),
		server.WithPushManagement(pm),
	}, extra...)
	srv, err := server.New(opts...)
	require.NoError(t, err)
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })
	return srv, fmt.Sprintf("opc.tcp://localhost:%d", srv.Port())
}

func endpoint(t *testing.T, url string, mode ua.MessageSecurityMode) *ua.EndpointDescription {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	eps, err := opcua.GetEndpoints(ctx, url)
	require.NoError(t, err)
	for _, ep := range eps {
		if ep.SecurityPolicyURI == ua.SecurityPolicyURIBasic256Sha256 && ep.SecurityMode == mode {
			return ep
		}
	}
	t.Fatalf("no Basic256Sha256 %v endpoint", mode)
	return nil
}

type identity struct {
	cert []byte
	key  *rsa.PrivateKey
}

// dial connects with the application certificate id over a Basic256Sha256
// channel of the mode; user empty is anonymous.
func dial(t *testing.T, url string, mode ua.MessageSecurityMode, id identity, user, pass string) (*opcua.Client, error) {
	t.Helper()
	ep := endpoint(t, url, mode)
	tok := ua.UserTokenTypeAnonymous
	if user != "" {
		tok = ua.UserTokenTypeUserName
	}
	opts := []opcua.Option{
		opcua.SecurityFromEndpoint(ep, tok),
		opcua.Certificate(id.cert),
		opcua.PrivateKey(id.key),
		opcua.InsecureSkipVerify(),
		opcua.AutoReconnect(false),
		opcua.DialTimeout(30 * time.Second),
		opcua.RequestTimeout(30 * time.Second),
	}
	if user != "" {
		opts = append(opts, opcua.AuthUsername(user, pass))
	}
	c, err := opcua.NewClient(url, opts...)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		_ = c.Close(context.Background())
		return nil, err
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c, nil
}

func admin(t *testing.T, url string) *gds.Client {
	t.Helper()
	p := pki(t)
	c, err := dial(t, url, ua.MessageSecurityModeSignAndEncrypt, identity{p.ClientCert, p.ClientKey}, adminUser, adminPass)
	require.NoError(t, err)
	return gds.New(c)
}

func TestTrustListRoundTrip(t *testing.T) {
	p := pki(t)
	srv, url := newServer(t, server.PushManagement{})
	g := admin(t, url)
	ctx := context.Background()

	tl, err := g.ReadTrustList(ctx, ua.TrustListMasksAll)
	require.NoError(t, err)
	require.Equal(t, uint32(ua.TrustListMasksAll), tl.SpecifiedLists)
	require.Equal(t, [][]byte{p.ClientCert}, tl.TrustedCertificates)

	only, err := g.ReadTrustList(ctx, ua.TrustListMasksIssuerCertificates)
	require.NoError(t, err)
	require.Equal(t, uint32(ua.TrustListMasksIssuerCertificates), only.SpecifiedLists)
	require.Empty(t, only.TrustedCertificates)

	// The CA-issued client is not trusted yet.
	issued := identity{p.IssuedCert, p.IssuedKey}
	_, err = dial(t, url, ua.MessageSecurityModeSignAndEncrypt, issued, "", "")
	require.ErrorIs(t, err, ua.StatusBadCertificateUntrusted)

	required, err := g.WriteTrustList(ctx, &ua.TrustListDataType{
		SpecifiedLists:      uint32(ua.TrustListMasksTrustedCertificates),
		TrustedCertificates: [][]byte{p.ClientCert, p.CACert},
	})
	require.NoError(t, err)
	require.True(t, required)
	// Not applied yet.
	require.Equal(t, [][]byte{p.ClientCert}, srv.TrustList().TrustedCertificates)
	_, err = dial(t, url, ua.MessageSecurityModeSignAndEncrypt, issued, "", "")
	require.ErrorIs(t, err, ua.StatusBadCertificateUntrusted)

	require.NoError(t, g.ApplyChanges(ctx))
	require.Equal(t, [][]byte{p.ClientCert, p.CACert}, srv.TrustList().TrustedCertificates)
	c, err := dial(t, url, ua.MessageSecurityModeSignAndEncrypt, issued, "", "")
	require.NoError(t, err)
	_, err = c.ReadValue(ctx, ua.NewNumericNodeID(0, id.ServerServerStatusState))
	require.NoError(t, err)

	tl, err = g.ReadTrustList(ctx, ua.TrustListMasksAll)
	require.NoError(t, err)
	require.Equal(t, [][]byte{p.ClientCert, p.CACert}, tl.TrustedCertificates)
}

func TestAddRemoveCertificateAndRejectedList(t *testing.T) {
	p := pki(t)
	srv, url := newServer(t, server.PushManagement{})
	g := admin(t, url)
	ctx := context.Background()
	stranger := identity{p.StrangerCert, p.StrangerKey}

	_, err := dial(t, url, ua.MessageSecurityModeSignAndEncrypt, stranger, "", "")
	require.ErrorIs(t, err, ua.StatusBadCertificateUntrusted)
	rejected, err := g.GetRejectedList(ctx)
	require.NoError(t, err)
	require.Contains(t, rejected, p.StrangerCert)
	require.Contains(t, srv.RejectedCertificates(), p.StrangerCert)

	require.NoError(t, g.AddCertificate(ctx, p.StrangerCert, true))
	require.NoError(t, g.ApplyChanges(ctx))
	c, err := dial(t, url, ua.MessageSecurityModeSignAndEncrypt, stranger, "", "")
	require.NoError(t, err)
	require.NoError(t, c.Close(ctx))

	require.NoError(t, g.RemoveCertificate(ctx, gds.Thumbprint(p.StrangerCert), true))
	require.NoError(t, g.ApplyChanges(ctx))
	_, err = dial(t, url, ua.MessageSecurityModeSignAndEncrypt, stranger, "", "")
	require.ErrorIs(t, err, ua.StatusBadCertificateUntrusted)

	err = g.RemoveCertificate(ctx, gds.Thumbprint(p.StrangerCert), true)
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
	var ge *gds.Error
	require.ErrorAs(t, err, &ge)
	require.Equal(t, "RemoveCertificate", ge.Method)
}

func TestSigningRequestAndUpdateCertificate(t *testing.T) {
	p := pki(t)
	srv, url := newServer(t, server.PushManagement{})
	g := admin(t, url)
	ctx := context.Background()
	ca, err := x509.ParseCertificate(p.CACert)
	require.NoError(t, err)

	props, err := g.Properties(ctx)
	require.NoError(t, err)
	require.Equal(t, []string{"PEM", "PFX"}, props.SupportedPrivateKeyFormats)
	require.Len(t, props.CertificateTypes, 1)
	require.True(t, props.CertificateTypes[0].Equal(gds.RsaSha256ApplicationCertificateType))

	csr, err := g.CreateSigningRequest(ctx, &gds.SigningRequest{
		CertificateType:      gds.RsaSha256ApplicationCertificateType,
		SubjectName:          "CN=renewed server/O=otfabric",
		RegeneratePrivateKey: true,
	})
	require.NoError(t, err)
	req, err := x509.ParseCertificateRequest(csr)
	require.NoError(t, err)
	require.Equal(t, "renewed server", req.Subject.CommonName)
	require.Equal(t, testpki.ServerAppURI, req.URIs[0].String())
	cert, err := testpki.IssueFromCSR(csr, ca, p.CAKey)
	require.NoError(t, err)

	required, err := g.UpdateCertificate(ctx, &gds.CertificateUpdate{
		CertificateType:    gds.RsaSha256ApplicationCertificateType,
		Certificate:        cert,
		IssuerCertificates: [][]byte{p.CACert},
	})
	require.NoError(t, err)
	require.True(t, required)
	require.Equal(t, p.ServerCert, endpoint(t, url, ua.MessageSecurityModeSignAndEncrypt).ServerCertificate)

	require.NoError(t, g.ApplyChanges(ctx))
	require.Equal(t, cert, endpoint(t, url, ua.MessageSecurityModeSignAndEncrypt).ServerCertificate)

	// A new channel presents the new certificate ...
	c, err := dial(t, url, ua.MessageSecurityModeSignAndEncrypt, identity{p.ClientCert, p.ClientKey}, adminUser, adminPass)
	require.NoError(t, err)
	require.Equal(t, cert, c.SecureChannel().RemoteCertificate())
	// ... and the channel opened before keeps working with the old one.
	_, err = g.Properties(ctx)
	require.NoError(t, err)
	_ = srv
}

func TestUpdateCertificateWithPrivateKey(t *testing.T) {
	p := pki(t)
	_, url := newServer(t, server.PushManagement{ApplyImmediately: true})
	g := admin(t, url)
	ctx := context.Background()

	cert, key, err := testpki.SelfSigned("replacement server", testpki.ServerAppURI)
	require.NoError(t, err)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	required, err := g.UpdateCertificate(ctx, &gds.CertificateUpdate{
		CertificateType:  gds.RsaSha256ApplicationCertificateType,
		Certificate:      cert,
		PrivateKeyFormat: "PEM",
		PrivateKey:       pemKey,
	})
	require.NoError(t, err)
	require.False(t, required)
	require.Equal(t, cert, endpoint(t, url, ua.MessageSecurityModeSignAndEncrypt).ServerCertificate)

	// A certificate for another application is refused.
	other, otherKey, err := testpki.SelfSigned("impostor", "urn:otfabric:impostor")
	require.NoError(t, err)
	_, err = g.UpdateCertificate(ctx, &gds.CertificateUpdate{
		CertificateType:  gds.RsaSha256ApplicationCertificateType,
		Certificate:      other,
		PrivateKeyFormat: "PEM",
		PrivateKey:       pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(otherKey)}),
	})
	require.ErrorIs(t, err, ua.StatusBadCertificateURIInvalid)
	// A certificate whose key the server no longer has.
	_, err = g.UpdateCertificate(ctx, &gds.CertificateUpdate{CertificateType: gds.RsaSha256ApplicationCertificateType, Certificate: p.ServerCert})
	require.ErrorIs(t, err, ua.StatusBadSecurityChecksFailed)
}

func TestAuthorization(t *testing.T) {
	p := pki(t)
	_, url := newServer(t, server.PushManagement{})
	ctx := context.Background()
	self := identity{p.ClientCert, p.ClientKey}

	for _, tc := range []struct {
		name       string
		mode       ua.MessageSecurityMode
		user, pass string
		want       ua.StatusCode
	}{
		{"Anonymous", ua.MessageSecurityModeSignAndEncrypt, "", "", ua.StatusBadUserAccessDenied},
		{"Operator", ua.MessageSecurityModeSignAndEncrypt, opUser, opPass, ua.StatusBadUserAccessDenied},
		{"AdminOnSign", ua.MessageSecurityModeSign, adminUser, adminPass, ua.StatusBadSecurityModeInsufficient},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := dial(t, url, tc.mode, self, tc.user, tc.pass)
			require.NoError(t, err)
			g := gds.New(c)
			_, err = g.ReadTrustList(ctx, ua.TrustListMasksAll)
			require.ErrorIs(t, err, tc.want)
			_, err = g.GetRejectedList(ctx)
			require.ErrorIs(t, err, tc.want)
			require.ErrorIs(t, g.ApplyChanges(ctx), tc.want)
			require.ErrorIs(t, g.AddCertificate(ctx, p.StrangerCert, true), tc.want)
		})
	}
}

func TestTransactionOfOneSession(t *testing.T) {
	p := pki(t)
	srv, url := newServer(t, server.PushManagement{})
	ctx := context.Background()
	a, b := admin(t, url), admin(t, url)

	require.NoError(t, a.AddCertificate(ctx, p.StrangerCert, true))
	require.ErrorIs(t, b.AddCertificate(ctx, p.CACert, true), ua.StatusBadTransactionPending)
	require.ErrorIs(t, b.ApplyChanges(ctx), ua.StatusBadTransactionPending)
	require.NoError(t, a.CancelChanges(ctx))
	require.Equal(t, [][]byte{p.ClientCert}, srv.TrustList().TrustedCertificates)

	require.NoError(t, b.AddCertificate(ctx, p.CACert, false))
	require.NoError(t, b.ApplyChanges(ctx))
	require.Equal(t, [][]byte{p.CACert}, srv.TrustList().IssuerCertificates)
}

func TestTrustListCodec(t *testing.T) {
	p := pki(t)
	tl := &ua.TrustListDataType{SpecifiedLists: uint32(ua.TrustListMasksAll), TrustedCertificates: [][]byte{p.ClientCert}}
	b, err := gds.EncodeTrustList(tl)
	require.NoError(t, err)
	got, err := gds.DecodeTrustList(b)
	require.NoError(t, err)
	require.Equal(t, tl, got)
	_, err = gds.DecodeTrustList(append(b, 0))
	require.Error(t, err)
	_, err = gds.DecodeTrustList(b[:3])
	require.Error(t, err)
	_, err = gds.EncodeTrustList(nil)
	require.Error(t, err)
}

// newCRL returns a CRL of the CA of the PKI that revokes serial.
func newCRL(t *testing.T, serial *big.Int) []byte {
	t.Helper()
	p := pki(t)
	ca, err := x509.ParseCertificate(p.CACert)
	require.NoError(t, err)
	crl, err := x509.CreateRevocationList(nil, &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now().Add(-time.Hour),
		NextUpdate:                time.Now().Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: serial, RevocationTime: time.Now()}},
		Issuer:                    pkix.Name{},
	}, ca, p.CAKey)
	require.NoError(t, err)
	return crl
}

func TestRevokedCertificate(t *testing.T) {
	p := pki(t)
	issued, err := x509.ParseCertificate(p.IssuedCert)
	require.NoError(t, err)
	_, url := newServer(t, server.PushManagement{TrustList: &ua.TrustListDataType{
		TrustedCertificates: [][]byte{p.ClientCert, p.CACert},
		TrustedCrls:         [][]byte{newCRL(t, issued.SerialNumber)},
	}})
	_, err = dial(t, url, ua.MessageSecurityModeSignAndEncrypt, identity{p.IssuedCert, p.IssuedKey}, "", "")
	require.ErrorIs(t, err, ua.StatusBadCertificateRevoked)
}
