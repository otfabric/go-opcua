// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"math/big"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

const (
	mGetCerts   = id.ServerConfigurationGetCertificates
	mSelfSigned = id.ServerConfigurationCreateSelfSignedCertificate
	mReset      = id.ServerConfigurationResetToServerDefaults

	httpsTL = id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustList
	userTL  = id.ServerConfigurationCertificateGroupsDefaultUserTokenGroupTrustList
)

var (
	httpsGroup = ua.NewNumericNodeID(0, id.ServerConfigurationCertificateGroupsDefaultHTTPSGroup)
	userGroup  = ua.NewNumericNodeID(0, id.ServerConfigurationCertificateGroupsDefaultUserTokenGroup)
	httpsType  = ua.NewNumericNodeID(0, id.HTTPSCertificateType)
	nullNode   = ua.NewTwoByteNodeID(0)
)

func selfSigned(t *testing.T, s *Server, ctx context.Context, group, typ *ua.NodeID, subject string, dns, ips []string, days, bits uint16) ([]byte, ua.StatusCode) {
	t.Helper()
	if dns == nil {
		dns = []string{}
	}
	if ips == nil {
		ips = []string{}
	}
	out, sc := pushCall(t, s, ctx, scObj, mSelfSigned, group, typ, subject, dns, ips, days, bits)
	if sc != ua.StatusOK {
		return nil, sc
	}
	return out[0].Value().([]byte), sc
}

func TestPushGetCertificates(t *testing.T) {
	p := pushPKI(t)
	p256 := p.ECC.Server[testpki.CurveP256]
	s := newPushServer(t, PushManagement{}, ApplicationIdentity(p256.Cert, p256.Key))
	ctx, _ := adminCtx(s)

	out, sc := pushCall(t, s, ctx, scObj, mGetCerts, defaultGroup)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, []*ua.NodeID{rsaType, ua.NewNumericNodeID(0, id.EccNistP256ApplicationCertificateType)}, out[0].Value())
	require.Equal(t, [][]byte{p.ServerCert, p256.Cert}, out[1].Value())

	// A null group is the DefaultApplicationGroup.
	out2, sc := pushCall(t, s, ctx, scObj, mGetCerts, nullNode)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, out[1].Value(), out2[1].Value())

	// Without TLSConfig the HTTPS group has the RSA certificate.
	out, sc = pushCall(t, s, ctx, scObj, mGetCerts, httpsGroup)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, []*ua.NodeID{httpsType}, out[0].Value())
	require.Equal(t, [][]byte{p.ServerCert}, out[1].Value())
	require.Equal(t, p.ServerCert, s.HTTPSCertificate())

	out, sc = pushCall(t, s, ctx, scObj, mGetCerts, userGroup)
	require.Equal(t, ua.StatusOK, sc)
	require.Empty(t, out[0].Value())
	require.Empty(t, out[1].Value())

	_, sc = pushCall(t, s, ctx, scObj, mGetCerts, ua.NewNumericNodeID(0, id.Server))
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	_, sc = pushCall(t, s, ctx, scObj, mGetCerts, ua.NewStringNodeID(1, "x"))
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	_, sc = pushCall(t, s, ctx, scObj, mGetCerts, "x")
	require.Equal(t, ua.StatusBadTypeMismatch, sc)

	// Only SecurityAdmin.
	other, _ := pushCallerCtx(s, ua.MessageSecurityModeSignAndEncrypt)
	_, sc = pushCall(t, s, other, scObj, mGetCerts, defaultGroup)
	require.Equal(t, ua.StatusBadUserAccessDenied, sc)

	// The group's CertificateTypes.
	require.Equal(t, []*ua.NodeID{httpsType}, s.push.groupTypes(s.push.groups[groupHTTPS]))
	require.Empty(t, s.push.groupTypes(s.push.groups[groupUserToken]))
	require.Nil(t, s.GroupTrustList(nil))
	require.Nil(t, s.GroupTrustList(ua.NewNumericNodeID(0, id.Server)))
	require.NotNil(t, s.GroupTrustList(httpsGroup))
}

func TestPushCreateSelfSignedCertificate(t *testing.T) {
	p := pushPKI(t)
	ids := []Option{}
	for _, c := range testpki.Curves {
		x := p.ECC.Server[c]
		ids = append(ids, ApplicationIdentity(x.Cert, x.Key))
	}
	s := newPushServer(t, PushManagement{}, ids...)
	ctx, _ := adminCtx(s)

	for _, tc := range []struct {
		typ  uint32
		bits uint16
		key  func(crypto.PublicKey) bool
	}{
		{id.RsaSha256ApplicationCertificateType, 3072, func(k crypto.PublicKey) bool { r, ok := k.(*rsa.PublicKey); return ok && r.N.BitLen() == 3072 }},
		{id.EccNistP256ApplicationCertificateType, 256, func(k crypto.PublicKey) bool {
			e, ok := k.(*ecdsa.PublicKey)
			return ok && e.Curve == elliptic.P256()
		}},
		{id.EccNistP384ApplicationCertificateType, 0, func(k crypto.PublicKey) bool {
			e, ok := k.(*ecdsa.PublicKey)
			return ok && e.Curve == elliptic.P384()
		}},
		{id.EccBrainpoolP256r1ApplicationCertificateType, 0, func(k crypto.PublicKey) bool { e, ok := k.(*ecdsa.PublicKey); return ok && e.Params().BitSize == 256 }},
		{id.EccBrainpoolP384r1ApplicationCertificateType, 384, func(k crypto.PublicKey) bool { e, ok := k.(*ecdsa.PublicKey); return ok && e.Params().BitSize == 384 }},
		{id.EccCurve25519ApplicationCertificateType, 0, func(k crypto.PublicKey) bool { _, ok := k.(ed25519.PublicKey); return ok }},
		{id.EccCurve448ApplicationCertificateType, 448, func(k crypto.PublicKey) bool { _, ok := k.(ed448.PublicKey); return ok }},
	} {
		typ := ua.NewNumericNodeID(0, tc.typ)
		der, sc := selfSigned(t, s, ctx, defaultGroup, typ, "CN=self,O=otfabric", []string{"host.example"}, []string{"127.0.0.1"}, 30, tc.bits)
		require.Equal(t, ua.StatusOK, sc, "type %d", tc.typ)
		cert, err := uapolicy.ParseCertificate(der)
		require.NoError(t, err)
		require.True(t, tc.key(cert.PublicKey), "type %d: %T", tc.typ, cert.PublicKey)
		require.Equal(t, "self", cert.Subject.CommonName)
		require.Equal(t, []string{"host.example"}, cert.DNSNames)
		require.Equal(t, "127.0.0.1", cert.IPAddresses[0].String())
		require.Equal(t, testpki.ServerAppURI, cert.URIs[0].String())
		require.WithinDuration(t, time.Now().Add(30*24*time.Hour), cert.NotAfter, time.Hour)
		pool := x509.NewCertPool()
		pool.AddCert(cert)
		require.NoError(t, uapolicy.VerifyCertificate([]*x509.Certificate{cert}, pool, []*x509.Certificate{cert}))
	}
	// Nothing changes before ApplyChanges.
	got, _, _ := s.cfg.identityFor(ua.SecurityPolicyURIECCCurve448)
	require.Equal(t, p.ECC.Server[testpki.CurveEd448].Cert, got)
	_, sc := pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusOK, sc)
	got, key, ok := s.cfg.identityFor(ua.SecurityPolicyURIECCCurve448)
	require.True(t, ok)
	require.NotEqual(t, p.ECC.Server[testpki.CurveEd448].Cert, got)
	require.True(t, uapolicy.KeyMatchesCertificate(key, got))
	_, certs := s.push.groupCerts(s.push.groups[groupApplication])
	require.Len(t, certs, 1+len(testpki.Curves))

	// Defaults: the current subject and names, a year, the key size of the
	// current key.
	curDER, _, _ := s.cfg.identityFor(ua.SecurityPolicyURIBasic256Sha256)
	der, sc := selfSigned(t, s, ctx, nullNode, nullNode, "", nil, nil, 0, 0)
	require.Equal(t, ua.StatusOK, sc)
	cert, err := uapolicy.ParseCertificate(der)
	require.NoError(t, err)
	cur, err := x509.ParseCertificate(curDER)
	require.NoError(t, err)
	require.Equal(t, cur.Subject.CommonName, cert.Subject.CommonName)
	require.Equal(t, cur.DNSNames, cert.DNSNames)
	require.WithinDuration(t, time.Now().Add(365*24*time.Hour), cert.NotAfter, time.Hour)
	require.Equal(t, cur.PublicKey.(*rsa.PublicKey).N.BitLen(), cert.PublicKey.(*rsa.PublicKey).N.BitLen())

	// Errors.
	for _, tc := range []struct {
		group, typ *ua.NodeID
		subject    string
		dns, ips   []string
		bits       uint16
		want       ua.StatusCode
	}{
		{userGroup, nullNode, "", nil, nil, 0, ua.StatusBadInvalidArgument},
		{defaultGroup, httpsType, "", nil, nil, 0, ua.StatusBadInvalidArgument},
		{defaultGroup, rsaType, "X=1", nil, nil, 0, ua.StatusBadInvalidArgument},
		{defaultGroup, rsaType, "", []string{"bad name"}, nil, 0, ua.StatusBadInvalidArgument},
		{defaultGroup, rsaType, "", nil, []string{"300.1.1.1"}, 0, ua.StatusBadInvalidArgument},
		{defaultGroup, rsaType, "", nil, nil, 1024, ua.StatusBadInvalidArgument},
		{defaultGroup, ua.NewNumericNodeID(0, id.RsaMinApplicationCertificateType), "", nil, nil, 2047, ua.StatusBadInvalidArgument},
		{defaultGroup, ua.NewNumericNodeID(0, id.EccNistP256ApplicationCertificateType), "", nil, nil, 384, ua.StatusBadInvalidArgument},
		{httpsGroup, httpsType, "", nil, nil, 1000, ua.StatusBadInvalidArgument},
	} {
		_, sc := selfSigned(t, s, ctx, tc.group, tc.typ, tc.subject, tc.dns, tc.ips, 1, tc.bits)
		require.Equal(t, tc.want, sc, "%+v", tc)
	}
	_, sc = pushCall(t, s, ctx, scObj, mSelfSigned, defaultGroup, rsaType, "", "x", []string{}, uint16(1), uint16(0))
	require.Equal(t, ua.StatusBadTypeMismatch, sc)
	_, sc = pushCall(t, s, ctx, scObj, mSelfSigned, defaultGroup, rsaType, "", ua.MustVariant(nil), ua.MustVariant(nil), uint16(1), uint16(0))
	require.Equal(t, ua.StatusOK, sc)

	// The HTTPS group: a new TLS certificate of the kind of the current one.
	der, sc = selfSigned(t, s, ctx, httpsGroup, nullNode, "CN=tls", []string{"localhost"}, nil, 1, 0)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, der, s.HTTPSCertificate())
}

func TestPushHTTPSGroup(t *testing.T) {
	p := pushPKI(t)
	ca, err := testpki.NewCA(testpki.CurveP256, "tls ca")
	require.NoError(t, err)
	s := newPushServer(t, PushManagement{HTTPSClientCertificates: HTTPSClientCertificatesVerifyIfGiven,
		HTTPSTrustList: &ua.TrustListDataType{TrustedCertificates: [][]byte{ca.Cert}}})
	ctx, _ := adminCtx(s)
	cfg := s.push.tlsConfig(&tls.Config{})
	require.Equal(t, tls.RequestClientCert, cfg.ClientAuth)
	got, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	require.Equal(t, p.ServerCert, got.Certificate[0])

	// UpdateCertificate with an ECDSA TLS certificate and its PEM key.
	tlsID, err := testpki.NewIdentity(testpki.CurveP256, "tls", "", ca.X509, ca.Key)
	require.NoError(t, err)
	pemKey, err := uapolicy.MarshalPrivateKey(tlsID.Key)
	require.NoError(t, err)
	out, sc := pushCall(t, s, ctx, scObj, mUpdate, httpsGroup, httpsType, tlsID.Cert, [][]byte{ca.Cert}, "PEM", pemKey)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, true, out[0].Value())
	got, err = cfg.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	require.Equal(t, p.ServerCert, got.Certificate[0], "not before ApplyChanges")
	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusOK, sc)
	got, err = cfg.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	require.Equal(t, [][]byte{tlsID.Cert, ca.Cert}, got.Certificate)
	// The application instance certificate is unchanged.
	cert, _, _ := s.cfg.identityFor(ua.SecurityPolicyURIBasic256Sha256)
	require.Equal(t, p.ServerCert, cert)

	// Keys crypto/tls cannot use, and application certificate types, are
	// refused for the HTTPS group.
	bp := p.ECC.Server[testpki.CurveBrainpoolP256r1]
	bpKey, err := uapolicy.MarshalPrivateKey(bp.Key)
	require.NoError(t, err)
	_, sc = pushCall(t, s, ctx, scObj, mUpdate, httpsGroup, httpsType, bp.Cert, [][]byte{}, "PEM", bpKey)
	require.Equal(t, ua.StatusBadCertificateInvalid, sc)
	_, sc = pushCall(t, s, ctx, scObj, mUpdate, httpsGroup, rsaType, tlsID.Cert, [][]byte{}, "PEM", pemKey)
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	_, sc = pushCall(t, s, ctx, scObj, mUpdate, userGroup, nullNode, tlsID.Cert, [][]byte{}, "PEM", pemKey)
	require.Equal(t, ua.StatusBadInvalidArgument, sc)

	// A signing request for the TLS certificate with a new key.
	out, sc = pushCall(t, s, ctx, scObj, mCSR, httpsGroup, nullNode, "", true, make([]byte, 32))
	require.Equal(t, ua.StatusOK, sc)
	req, err := uapolicy.ParseCertificateRequest(out[0].Value().([]byte))
	require.NoError(t, err)
	require.IsType(t, &ecdsa.PublicKey{}, req.PublicKey)
	issued, err := testpki.IssueFromCSR(out[0].Value().([]byte), ca.X509, ca.Key)
	require.NoError(t, err)
	_, sc = pushCall(t, s, ctx, scObj, mUpdate, httpsGroup, httpsType, issued, [][]byte{ca.Cert}, "", []byte{})
	require.Equal(t, ua.StatusOK, sc)
	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, issued, s.HTTPSCertificate())

	// TLS client certificates are validated against the HTTPS trust list.
	client, err := testpki.NewIdentity(testpki.CurveP256, "tls client", "", ca.X509, ca.Key)
	require.NoError(t, err)
	require.NoError(t, cfg.VerifyPeerCertificate(nil, nil))
	require.NoError(t, cfg.VerifyPeerCertificate([][]byte{client.Cert}, nil))
	require.Equal(t, ua.StatusBadCertificateUntrusted, cfg.VerifyPeerCertificate([][]byte{p.ClientCert}, nil))
	require.Equal(t, ua.StatusBadCertificateInvalid, cfg.VerifyPeerCertificate([][]byte{{1, 2}}, nil))
	require.Contains(t, s.RejectedCertificates(), p.ClientCert)

	req2 := s.push.tlsConfig(&tls.Config{})
	_ = req2
	s.push.cfg.HTTPSClientCertificates = HTTPSClientCertificatesRequire
	require.Equal(t, tls.RequireAnyClientCert, s.push.tlsConfig(&tls.Config{}).ClientAuth)
	s.push.cfg.HTTPSClientCertificates = HTTPSClientCertificatesIgnore
	ign := s.push.tlsConfig(&tls.Config{ClientAuth: tls.NoClientCert})
	require.Nil(t, ign.VerifyPeerCertificate)

	// Without a certificate of the group the TLS configuration's own is
	// used.
	s.push.https.Store(nil)
	own := &tls.Certificate{Certificate: [][]byte{p.ServerCert}, PrivateKey: p.ServerKey}
	c := s.push.tlsConfig(&tls.Config{Certificates: []tls.Certificate{*own}})
	got, err = c.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	require.Equal(t, own.Certificate, got.Certificate)
	c = s.push.tlsConfig(&tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return own, nil }})
	got, err = c.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	require.Equal(t, own, got)
	_, err = s.push.tlsConfig(&tls.Config{}).GetCertificate(&tls.ClientHelloInfo{})
	require.Error(t, err)
	require.Nil(t, s.HTTPSCertificate())

	// A CSR for a group without a certificate needs a subject and a new key.
	_, sc = pushCall(t, s, ctx, scObj, mCSR, httpsGroup, nullNode, "", true, make([]byte, 32))
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	out, sc = pushCall(t, s, ctx, scObj, mCSR, httpsGroup, nullNode, "CN=fresh", true, make([]byte, 32))
	require.Equal(t, ua.StatusOK, sc)
	req, err = uapolicy.ParseCertificateRequest(out[0].Value().([]byte))
	require.NoError(t, err)
	require.IsType(t, &rsa.PublicKey{}, req.PublicKey)
	_, sc = selfSigned(t, s, ctx, httpsGroup, nullNode, "", nil, nil, 1, 0)
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
}

func TestPushGenerateKey(t *testing.T) {
	_, err := generateRSA(nil, 4096, true)
	require.ErrorIs(t, err, errKeySize)
	k, err := generateRSA(nil, 0, true)
	require.NoError(t, err)
	require.Equal(t, 2048, k.N.BitLen())
	_, err = generateKey(id.EccNistP256ApplicationCertificateType, nil, 384)
	require.Error(t, err)
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, err = generateKey(id.HTTPSCertificateType, p256, 384)
	require.ErrorIs(t, err, errKeySize)
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, err = generateKey(id.HTTPSCertificateType, ed, 448)
	require.ErrorIs(t, err, errKeySize)
}

func TestPushInitialTLSIdentity(t *testing.T) {
	p := pushPKI(t)
	key := p.ECC.Server[testpki.CurveP256]
	sc := &serverConfig{tlsConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{key.Cert, p.CACert}, PrivateKey: key.Key}}}}
	x := initialTLSIdentity(sc)
	require.Equal(t, key.Cert, x.cert)
	require.Equal(t, [][]byte{p.CACert}, x.issuers)
	require.Nil(t, initialTLSIdentity(&serverConfig{tlsConfig: &tls.Config{}}))
	require.Nil(t, initialTLSIdentity(&serverConfig{tlsConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{key.Cert}, PrivateKey: struct{}{}}}}}))
	require.Nil(t, initialTLSIdentity(&serverConfig{}))

	require.True(t, tlsKeySupported(&p.ServerKey.PublicKey))
	require.False(t, tlsKeySupported(p.ECC.Server[testpki.CurveEd448].Key.Public()))
	require.True(t, tlsKeySupported(p.ECC.Server[testpki.CurveEd25519].Key.Public()))
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	require.False(t, tlsKeySupported(&small.PublicKey))
}

func TestPushUserTokenGroup(t *testing.T) {
	p := pushPKI(t)
	var asked []byte
	s := newPushServer(t, PushManagement{UserTokenTrustList: &ua.TrustListDataType{TrustedCertificates: [][]byte{p.UserCert}}},
		WithX509UserValidator(func(der []byte) error {
			asked = der
			if string(der) == string(p.IssuedCert) {
				return errors.New("refused by the application")
			}
			return nil
		}))
	v := s.cfg.x509UserValidator
	require.NoError(t, v(p.UserCert))
	require.Equal(t, p.UserCert, asked)
	asked = nil
	require.ErrorIs(t, v(p.StrangerCert), ua.StatusBadCertificateUntrusted)
	require.Nil(t, asked, "the application is not asked about an untrusted certificate")
	require.Contains(t, s.RejectedCertificates(), p.StrangerCert)

	// The user token trust list is managed like the others.
	ctx, _ := adminCtx(s)
	_, sc := pushCall(t, s, ctx, userTL, id.ServerConfigurationCertificateGroupsDefaultUserTokenGroupTrustListAddCertificate, p.CACert, true)
	require.Equal(t, ua.StatusOK, sc)
	require.ErrorIs(t, v(p.IssuedCert), ua.StatusBadCertificateUntrusted, "not before ApplyChanges")
	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusOK, sc)
	require.EqualError(t, v(p.IssuedCert), "refused by the application")
	require.Len(t, s.GroupTrustList(userGroup).TrustedCertificates, 2)
	require.Len(t, s.TrustList().TrustedCertificates, 1, "the application trust list is unchanged")

	// Without an application validator the trust list decides alone.
	s2 := newPushServer(t, PushManagement{UserTokenTrustList: &ua.TrustListDataType{TrustedCertificates: [][]byte{p.UserCert}}})
	require.NoError(t, s2.cfg.x509UserValidator(p.UserCert))
}

func TestPushGroupTrustListFiles(t *testing.T) {
	p := pushPKI(t)
	s := newPushServer(t, PushManagement{})
	ctx, _ := adminCtx(s)
	// Each group has its own TrustList file and handles.
	out, sc := pushCall(t, s, ctx, httpsTL, id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustListOpen, byte(0x06))
	require.Equal(t, ua.StatusOK, sc)
	h := out[0].Value().(uint32)
	_, sc = pushCall(t, s, ctx, tlObj, mClose, h)
	require.Equal(t, ua.StatusBadInvalidArgument, sc, "a handle of another group")
	_, sc = pushCall(t, s, ctx, httpsTL, id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustListWrite, h,
		encodeTL(t, &ua.TrustListDataType{SpecifiedLists: uint32(ua.TrustListMasksTrustedCertificates), TrustedCertificates: [][]byte{p.CACert}}))
	require.Equal(t, ua.StatusOK, sc)
	// The application group's trust list can be changed meanwhile.
	_, sc = tlCall(t, s, ctx, mAdd, p.CACert, false)
	require.Equal(t, ua.StatusOK, sc)
	out, sc = pushCall(t, s, ctx, httpsTL, id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustListCloseAndUpdate, h)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, true, out[0].Value())
	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, [][]byte{p.CACert}, s.GroupTrustList(httpsGroup).TrustedCertificates)
	require.Equal(t, [][]byte{p.CACert}, s.TrustList().IssuerCertificates)
	require.Empty(t, s.GroupTrustList(userGroup).TrustedCertificates)
}

func TestPushPFX(t *testing.T) {
	p := pushPKI(t)
	var mu sync.Mutex
	var asked []*ua.NodeID
	s := newPushServer(t, PushManagement{PFXPassword: func(_ context.Context, group, typ *ua.NodeID) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		asked = []*ua.NodeID{group, typ}
		if typ.IntID() == id.HTTPSCertificateType {
			return "", errors.New("no password")
		}
		return "secret", nil
	}})
	ctx, _ := adminCtx(s)
	newCert, newKey, err := testpki.SelfSigned("pfx server", testpki.ServerAppURI)
	require.NoError(t, err)

	pfx, err := uapolicy.EncodePFX(newKey, [][]byte{newCert}, "secret")
	require.NoError(t, err)
	_, sc := pushCall(t, s, ctx, scObj, mUpdate, defaultGroup, rsaType, newCert, [][]byte{}, "PFX", pfx)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, []*ua.NodeID{defaultGroup, rsaType}, asked)
	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusOK, sc)
	cert, key, _ := s.cfg.identityFor(ua.SecurityPolicyURIBasic256Sha256)
	require.Equal(t, newCert, cert)
	require.True(t, key.(*rsa.PrivateKey).Equal(newKey))

	// A wrong password, a PFX of another key, no password.
	wrong, err := uapolicy.EncodePFX(newKey, [][]byte{newCert}, "other")
	require.NoError(t, err)
	_, sc = pushCall(t, s, ctx, scObj, mUpdate, defaultGroup, rsaType, newCert, [][]byte{}, "pfx", wrong)
	require.Equal(t, ua.StatusBadSecurityChecksFailed, sc)
	other, err := uapolicy.EncodePFX(p.ClientKey, [][]byte{p.ClientCert}, "secret")
	require.NoError(t, err)
	_, sc = pushCall(t, s, ctx, scObj, mUpdate, defaultGroup, rsaType, newCert, [][]byte{}, "PFX", other)
	require.Equal(t, ua.StatusBadSecurityChecksFailed, sc)
	_, sc = pushCall(t, s, ctx, scObj, mUpdate, httpsGroup, httpsType, newCert, [][]byte{}, "PFX", pfx)
	require.Equal(t, ua.StatusBadSecurityChecksFailed, sc)

	// Without PFXPassword only PFX files without a password are read.
	s2 := newPushServer(t, PushManagement{})
	ctx2, _ := adminCtx(s2)
	bare, err := uapolicy.EncodePFX(newKey, nil, "")
	require.NoError(t, err)
	_, sc = pushCall(t, s2, ctx2, scObj, mUpdate, defaultGroup, rsaType, newCert, [][]byte{}, "PFX", bare)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = pushCall(t, s2, ctx2, scObj, mUpdate, defaultGroup, rsaType, newCert, [][]byte{}, "PFX", pfx)
	require.Equal(t, ua.StatusBadSecurityChecksFailed, sc)
}

func TestPushResetToServerDefaults(t *testing.T) {
	p := pushPKI(t)
	p256 := p.ECC.Server[testpki.CurveP256]
	st := &groupStore{}
	s := newPushServer(t, PushManagement{Store: st}, ApplicationIdentity(p256.Cert, p256.Key))
	ctx, sess := adminCtx(s)
	initial := s.TrustList()

	// Change everything.
	_, sc := tlCall(t, s, ctx, mAdd, p.CACert, true)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = pushCall(t, s, ctx, userTL, id.ServerConfigurationCertificateGroupsDefaultUserTokenGroupTrustListAddCertificate, p.UserCert, true)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = selfSigned(t, s, ctx, defaultGroup, rsaType, "", nil, nil, 1, 0)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = selfSigned(t, s, ctx, defaultGroup, ua.NewNumericNodeID(0, id.EccNistP256ApplicationCertificateType), "", nil, nil, 1, 0)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = selfSigned(t, s, ctx, httpsGroup, nullNode, "", nil, nil, 1, 0)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusOK, sc)
	cert, _, _ := s.cfg.identityFor(ua.SecurityPolicyURIBasic256Sha256)
	require.NotEqual(t, p.ServerCert, cert)
	require.NotEqual(t, p.ServerCert, s.HTTPSCertificate())
	st.reset()

	// A pending transaction, a CSR key and an open handle.
	_, sc = tlCall(t, s, ctx, mRemove, gdsThumb(p.CACert), true)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = pushCall(t, s, ctx, scObj, mCSR, defaultGroup, rsaType, "", true, make([]byte, 32))
	require.Equal(t, ua.StatusOK, sc)
	_, sc = tlCall(t, s, ctx, mOpen, byte(1))
	require.Equal(t, ua.StatusOK, sc)

	// Another session's transaction blocks the reset.
	other, otherSess := adminCtx(s)
	_ = sess
	_, sc = pushCall(t, s, other, scObj, mReset)
	require.Equal(t, ua.StatusBadTransactionPending, sc)
	require.NoError(t, s.sb.Close(otherSess.AuthTokenID))

	_, sc = pushCall(t, s, ctx, scObj, mReset)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, initial, s.TrustList())
	require.Empty(t, s.GroupTrustList(userGroup).TrustedCertificates)
	cert, _, _ = s.cfg.identityFor(ua.SecurityPolicyURIBasic256Sha256)
	require.Equal(t, p.ServerCert, cert)
	cert, _, _ = s.cfg.identityFor(ua.SecurityPolicyURIECCNistP256)
	require.Equal(t, p256.Cert, cert)
	require.Equal(t, p.ServerCert, s.HTTPSCertificate())
	require.Nil(t, s.push.tx)
	require.Empty(t, s.push.csrKeys)
	require.Zero(t, s.push.groups[groupApplication].openCount.Load())
	d := s.push.diagnostics()
	require.Equal(t, ua.StatusBadRequestCancelledByClient, d.result)

	// What the reset applied was stored.
	st.mu.Lock()
	require.Len(t, st.trust, 3)
	require.ElementsMatch(t, [][]byte{p.ServerCert, p256.Cert, p.ServerCert}, st.certs)
	st.mu.Unlock()

	// A failing store keeps everything.
	_, sc = tlCall(t, s, ctx, mAdd, p.CACert, true)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusOK, sc)
	st.setErr(errors.New("disk full"))
	_, sc = pushCall(t, s, ctx, scObj, mReset)
	require.Equal(t, ua.StatusBadInternalError, sc)
	require.Len(t, s.TrustList().TrustedCertificates, 2)
}

// groupStore is a CertificateGroupStore that records what it is given.
type groupStore struct {
	recordingStore
	mu    sync.Mutex
	trust map[string]*ua.TrustListDataType
	certs [][]byte
	err   error
}

func (g *groupStore) reset() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.trust, g.certs = nil, nil
}

func (g *groupStore) setErr(err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.err = err
}

func (g *groupStore) StoreGroupTrustList(_ context.Context, group *ua.NodeID, tl *ua.TrustListDataType) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.err != nil {
		return g.err
	}
	if g.trust == nil {
		g.trust = map[string]*ua.TrustListDataType{}
	}
	g.trust[group.String()] = tl
	return nil
}

func (g *groupStore) StoreGroupCertificate(_ context.Context, _, _ *ua.NodeID, cert []byte, _ [][]byte, _ crypto.Signer) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.err != nil {
		return g.err
	}
	g.certs = append(g.certs, cert)
	return nil
}

func gdsThumb(der []byte) string {
	return toUpper(hex.EncodeToString(uapolicy.Thumbprint(der)))
}

func TestPushGroupStore(t *testing.T) {
	p := pushPKI(t)
	st := &groupStore{}
	s := newPushServer(t, PushManagement{Store: st})
	ctx, _ := adminCtx(s)
	_, sc := pushCall(t, s, ctx, httpsTL, id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustListAddCertificate, p.CACert, true)
	require.Equal(t, ua.StatusOK, sc)
	der, sc := selfSigned(t, s, ctx, httpsGroup, nullNode, "", nil, nil, 1, 0)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusOK, sc)
	st.mu.Lock()
	require.Contains(t, st.trust, httpsGroup.String())
	require.Equal(t, [][]byte{der}, st.certs)
	st.mu.Unlock()
	// The CertificateStore methods are not used.
	require.Empty(t, st.tls)

	st.setErr(errors.New("disk full"))
	_, sc = pushCall(t, s, ctx, httpsTL, id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustListRemoveCertificate, gdsThumb(p.CACert), true)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusBadInternalError, sc)
	d := s.push.diagnostics()
	require.Equal(t, ua.StatusBadInternalError, d.result)
	require.Len(t, d.errs, 1)
	require.True(t, d.errs[0].TargetID.Equal(ua.NewNumericNodeID(0, httpsTL)))
	st.setErr(nil)
	_, sc = selfSigned(t, s, ctx, httpsGroup, nullNode, "", nil, nil, 1, 0)
	require.Equal(t, ua.StatusOK, sc)
	st.setErr(errors.New("disk full"))
	s.push.mu.Lock()
	delete(s.push.tx.trust, groupHTTPS)
	s.push.mu.Unlock()
	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusBadInternalError, sc)

	// A plain CertificateStore persists the DefaultApplicationGroup only.
	rs := &recordingStore{}
	s2 := newPushServer(t, PushManagement{Store: rs, ApplyImmediately: true})
	ctx2, _ := adminCtx(s2)
	_, sc = pushCall(t, s2, ctx2, httpsTL, id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustListAddCertificate, p.CACert, true)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = selfSigned(t, s2, ctx2, httpsGroup, nullNode, "", nil, nil, 1, 0)
	require.Equal(t, ua.StatusOK, sc)
	rs.mu.Lock()
	require.Empty(t, rs.tls)
	rs.mu.Unlock()
}

func TestPushTransactionDiagnostics(t *testing.T) {
	p := pushPKI(t)
	s := newPushServer(t, PushManagement{})
	clock := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	s.push.now = func() time.Time { return clock }
	ctx, sess := adminCtx(s)
	value := func(nid uint32) any {
		t.Helper()
		dv := s.Node(ua.NewNumericNodeID(0, nid)).Value()
		require.NotNil(t, dv)
		return dv.Value.Value()
	}
	require.Equal(t, ua.StatusOK, value(id.ServerConfigurationTransactionDiagnosticsResult))
	require.Equal(t, []*ua.NodeID{}, value(id.ServerConfigurationTransactionDiagnosticsAffectedTrustLists))

	_, sc := tlCall(t, s, ctx, mAdd, p.CACert, true)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = pushCall(t, s, ctx, httpsTL, id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustListAddCertificate, p.CACert, true)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = selfSigned(t, s, ctx, defaultGroup, rsaType, "", nil, nil, 1, 0)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, clock, value(id.ServerConfigurationTransactionDiagnosticsStartTime))
	require.Equal(t, []*ua.NodeID{ua.NewNumericNodeID(0, tlObj), ua.NewNumericNodeID(0, httpsTL)}, value(id.ServerConfigurationTransactionDiagnosticsAffectedTrustLists))
	require.Equal(t, []*ua.NodeID{defaultGroup}, value(id.ServerConfigurationTransactionDiagnosticsAffectedCertificateGroups))
	clock = clock.Add(time.Minute)
	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, clock, value(id.ServerConfigurationTransactionDiagnosticsEndTime))
	require.Equal(t, ua.StatusOK, value(id.ServerConfigurationTransactionDiagnosticsResult))
	require.Equal(t, []*ua.ExtensionObject{}, value(id.ServerConfigurationTransactionDiagnosticsErrors))

	// CancelChanges.
	_, sc = tlCall(t, s, ctx, mRemove, gdsThumb(p.CACert), true)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = pushCall(t, s, ctx, scObj, mCancel)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, ua.StatusBadRequestCancelledByClient, value(id.ServerConfigurationTransactionDiagnosticsResult))

	// A transaction of a closed session is dropped by the next one.
	_, sc = tlCall(t, s, ctx, mRemove, gdsThumb(p.CACert), true)
	require.Equal(t, ua.StatusOK, sc)
	require.NoError(t, s.sb.Close(sess.AuthTokenID))
	other, _ := adminCtx(s)
	_, sc = pushCall(t, s, other, scObj, mCancel)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, ua.StatusBadSessionClosed, value(id.ServerConfigurationTransactionDiagnosticsResult))
	_, sc = tlCall(t, s, other, mRemove, gdsThumb(p.CACert), true)
	require.Equal(t, ua.StatusOK, sc)
	s.push.mu.Lock()
	s.push.tx.session = ua.NewStringNodeID(1, "gone")
	s.push.mu.Unlock()
	_, sc = tlCall(t, s, other, mAdd, p.IssuedCert, true)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, ua.StatusOK, value(id.ServerConfigurationTransactionDiagnosticsResult))

	// Errors are bounded.
	for i := range maxTransactionErrors + 3 {
		s.push.recordError(defaultGroup, ua.StatusBadInternalError, string(rune('a'+i)))
	}
	require.Len(t, s.push.diagnostics().errs, maxTransactionErrors)
	errs := value(id.ServerConfigurationTransactionDiagnosticsErrors).([]*ua.ExtensionObject)
	require.Len(t, errs, maxTransactionErrors)

	// Only SecurityAdmin reads them.
	plain := s.sb.NewSession()
	admin := s.sb.NewSession()
	admin.roles = []*ua.NodeID{ua.RoleSecurityAdmin.NodeID()}
	for nid := uint32(id.ServerConfigurationTransactionDiagnostics); nid <= id.ServerConfigurationTransactionDiagnosticsErrors; nid++ {
		require.Equal(t, ua.StatusBadUserAccessDenied, s.checkRead(context.Background(), plain, ua.NewNumericNodeID(0, nid)))
		require.Equal(t, ua.StatusOK, s.checkRead(context.Background(), admin, ua.NewNumericNodeID(0, nid)))
	}
	require.Equal(t, ua.StatusOK, s.checkRead(context.Background(), plain, ua.NewNumericNodeID(0, id.ServerConfiguration)))
	require.Equal(t, ua.StatusOK, s.checkRead(context.Background(), plain, ua.NewStringNodeID(0, "x")))
	var none *pushManager
	require.Equal(t, ua.StatusOK, none.checkRead(plain, ua.NewNumericNodeID(0, id.ServerConfigurationTransactionDiagnosticsResult)))
}

func TestPushCertificateAlarms(t *testing.T) {
	p := pushPKI(t)
	soon, err := testpki.NewIdentity(testpki.CurveP256, "soon", testpki.ServerAppURI, nil, nil)
	require.NoError(t, err)
	s := newPushServer(t, PushManagement{
		TrustListUpdateFrequency: time.Hour,
		Alarms:                   &CertificateAlarms{ExpirationLimit: 2 * time.Hour},
	}, ApplicationIdentity(soon.Cert, soon.Key))
	a := s.push.alarms
	require.NotNil(t, a)
	require.Len(t, a.expiry, 2)
	require.Len(t, a.outOfDate, 3)
	require.Equal(t, time.Minute, a.cfg.CheckInterval)

	// The alarm is a component of its group with the BrowseName of
	// CertificateGroupType and the properties of its type.
	app := a.expiry[0]
	root := s.Node(app.cond.NodeID())
	require.Equal(t, &ua.QualifiedName{Name: "CertificateExpired"}, root.BrowseName())
	require.True(t, app.cond.Source().Equal(defaultGroup))
	require.True(t, app.cond.TypeID().Equal(ua.NewNumericNodeID(0, id.CertificateExpirationAlarmType)))
	ev := func(c *Condition) *BaseEvent {
		c.mu.RLock()
		defer c.mu.RUnlock()
		return c.eventLocked()
	}
	e := ev(app.cond)
	require.False(t, app.cond.State().Active)
	require.Equal(t, float64(2*time.Hour/time.Millisecond), e.Fields["ExpirationLimit"].Value())
	soonX, err := x509.ParseCertificate(soon.Cert)
	require.NoError(t, err)
	srvX, err := x509.ParseCertificate(p.ServerCert)
	require.NoError(t, err)
	first, firstType, firstCert := soonX.NotAfter, uint32(id.EccNistP256ApplicationCertificateType), soon.Cert
	if srvX.NotAfter.Before(first) {
		first, firstType, firstCert = srvX.NotAfter, id.RsaSha256ApplicationCertificateType, p.ServerCert
	}
	require.Equal(t, first.UTC(), e.Fields["ExpirationDate"].Value())
	require.Equal(t, ua.NewNumericNodeID(0, firstType), e.Fields["CertificateType"].Value())
	require.Equal(t, firstCert, e.Fields["Certificate"].Value())

	// The clock reaches the limit, then the expiry.
	s.push.now = func() time.Time { return first.Add(-time.Hour) }
	a.evaluate()
	st := app.cond.State()
	require.True(t, st.Active)
	require.Equal(t, uint16(severityCertExpiring), st.Severity)
	s.push.now = func() time.Time { return first.Add(time.Hour) }
	a.evaluate()
	st = app.cond.State()
	require.True(t, st.Active)
	require.Equal(t, uint16(severityCertExpired), st.Severity)
	id1 := app.cond.State().EventID
	a.evaluate()
	require.Equal(t, id1, app.cond.State().EventID, "no event without a change")

	// The trust list alarms follow UpdateFrequency.
	tl := a.outOfDate[0]
	require.True(t, tl.cond.State().Active)
	require.Equal(t, ua.NewNumericNodeID(0, tlObj), ev(tl.cond).Fields["TrustListId"].Value())
	require.Equal(t, float64(time.Hour/time.Millisecond), ev(tl.cond).Fields["UpdateFrequency"].Value())

	// A new trust list and a renewed certificate end the alarms.
	s.push.now = time.Now
	ctx, _ := adminCtx(s)
	_, sc := tlCall(t, s, ctx, mAdd, p.CACert, true)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = selfSigned(t, s, ctx, defaultGroup, ua.NewNumericNodeID(0, firstType), "", nil, nil, 400, 0)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusOK, sc)
	// ApplyChanges asks the goroutine of the alarms, which runs after
	// Start; here the evaluation is run directly.
	select {
	case <-a.kickc:
	default:
		t.Fatal("ApplyChanges did not ask for an evaluation")
	}
	a.evaluate()
	require.False(t, tl.cond.State().Active)
	require.False(t, app.cond.State().Active)
	require.Equal(t, uint16(severityCertInactive), app.cond.State().Severity)

	// A group without a certificate.
	s.push.https.Store(nil)
	a.evaluate()
	require.False(t, a.expiry[1].cond.State().Active)
	require.Nil(t, ev(a.expiry[1].cond).Fields["Certificate"].Value())

	// The goroutine evaluates on a kick and stops.
	s.push.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	a.start()
	a.start() // once
	s.push.evaluateAlarms()
	require.Eventually(t, func() bool { return a.outOfDate[2].cond.State().Active }, 5*time.Second, time.Millisecond)
	a.stop()
	a.stop()
}

func TestPushCertificateAlarmsOptions(t *testing.T) {
	_, err := New(WithPushManagement(PushManagement{Alarms: &CertificateAlarms{ExpirationLimit: -1}}))
	require.Error(t, err)
	_, err = New(WithPushManagement(PushManagement{TrustListUpdateFrequency: -1}))
	require.Error(t, err)
	_, err = New(WithPushManagement(PushManagement{HTTPSClientCertificates: 7}))
	require.Error(t, err)
	_, err = New(WithPushManagement(PushManagement{HTTPSTrustList: &ua.TrustListDataType{TrustedCertificates: [][]byte{{1}}}}))
	require.Error(t, err)

	// Without UpdateFrequency the trust list alarms stay inactive and the
	// property is absent.
	s := newPushServer(t, PushManagement{Alarms: &CertificateAlarms{}})
	require.Equal(t, 14*24*time.Hour, s.push.alarms.cfg.ExpirationLimit)
	require.False(t, s.push.alarms.outOfDate[0].cond.State().Active)
	require.Nil(t, s.Node(ua.NewNumericNodeID(0, id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListUpdateFrequency)))
	s2 := newPushServer(t, PushManagement{TrustListUpdateFrequency: time.Minute})
	n := s2.Node(ua.NewNumericNodeID(0, id.ServerConfigurationCertificateGroupsDefaultHTTPSGroupTrustListUpdateFrequency))
	require.NotNil(t, n)
	require.Equal(t, float64(60000), n.Value().Value.Value())

	// The alarms go to an existing namespace of that URI.
	s3, err := New(EndPoint("localhost", 0), WithPushManagement(PushManagement{}))
	require.NoError(t, err)
	NewNodeNameSpace(s3, CertificateAlarmsNamespaceURI)
	s3.push.cfg.Alarms = &CertificateAlarms{ExpirationLimit: time.Hour, CheckInterval: time.Hour}
	require.NoError(t, s3.push.buildAlarms())
	require.Len(t, s3.Conditions(), 5)
	// A second build fails: the conditions exist.
	s3.push.cfg.Alarms = &CertificateAlarms{ExpirationLimit: time.Hour, CheckInterval: time.Hour}
	require.NoError(t, s3.RemoveCondition(s3.push.alarms.outOfDate[0].cond.NodeID()))
	require.Len(t, s3.Conditions(), 4)
}

func TestPushMethodNodes(t *testing.T) {
	s := newPushServer(t, PushManagement{})
	for _, tc := range []struct {
		method uint32
		in     []string
		out    []string
	}{
		{mGetCerts, []string{"CertificateGroupId"}, []string{"CertificateTypeIds", "Certificates"}},
		{mSelfSigned, []string{"CertificateGroupId", "CertificateTypeId", "SubjectName", "DnsNames", "IpAddresses", "LifetimeInDays", "KeySizeInBits"}, []string{"Certificate"}},
	} {
		args := declaredInputArguments(s, ua.NewNumericNodeID(0, tc.method))
		var names []string
		for _, a := range args {
			names = append(names, a.Name)
		}
		require.Equal(t, tc.in, names)
		n := s.Node(ua.NewNumericNodeID(0, tc.method+2))
		require.NotNil(t, n, "OutputArguments of %d", tc.method)
		var outs []string
		for _, eo := range n.Value().Value.Value().([]*ua.ExtensionObject) {
			outs = append(outs, eo.Value.(*ua.Argument).Name)
		}
		require.Equal(t, tc.out, outs)
	}
	// ResetToServerDefaults has no arguments.
	require.Nil(t, declaredInputArguments(s, ua.NewNumericNodeID(0, mReset)))
	// A second build changes nothing.
	s.addPushMethod(mGetCerts, "GetCertificates", id.ServerConfigurationTypeGetCertificates)
	s.addPushProperty(id.ServerConfiguration, id.ServerConfigurationApplicationURI, "ApplicationUri", id.String, static(""))
	s.addPushMethod(1, "x", 2)
}

// TestPushBrainpoolEd448CRLs: CRLs of Brainpool and Ed448 CAs revoke the
// certificates they issued.
func TestPushBrainpoolEd448CRLs(t *testing.T) {
	for _, curve := range []string{testpki.CurveBrainpoolP256r1, testpki.CurveBrainpoolP384r1, testpki.CurveEd448} {
		t.Run(curve, func(t *testing.T) {
			ca, err := testpki.NewCA(curve, "ca "+curve)
			require.NoError(t, err)
			leaf, err := testpki.NewIdentity(curve, "leaf", testpki.ClientAppURI, ca.X509, ca.Key)
			require.NoError(t, err)
			crl, err := uapolicy.CreateRevocationList(rand.Reader, &x509.RevocationList{
				Number:     big.NewInt(1),
				ThisUpdate: time.Now().Add(-time.Hour),
				NextUpdate: time.Now().Add(time.Hour),
				RevokedCertificateEntries: []x509.RevocationListEntry{
					{SerialNumber: leaf.X509.SerialNumber, RevocationTime: time.Now().Add(-time.Minute)},
				},
			}, ca.X509, ca.Key)
			require.NoError(t, err)
			m := newPushManager(&PushManagement{MaxTrustListSize: defaultMaxTrustListSize, MaxRejectedCertificates: 4,
				TrustList: &ua.TrustListDataType{TrustedCertificates: [][]byte{ca.Cert}}}, &serverConfig{})
			require.NoError(t, m.validateClient(leaf.Cert))
			tl, sc := newTrustList(&ua.TrustListDataType{TrustedCertificates: [][]byte{ca.Cert}, TrustedCrls: [][]byte{crl}}, 0)
			require.Equal(t, ua.StatusOK, sc)
			m.groups[groupApplication].trust.Store(tl)
			require.Equal(t, ua.StatusBadCertificateRevoked, m.validateClient(leaf.Cert))
			require.Equal(t, ca.X509.RawSubject, crlIssuer(crl))

			// A CRL signed by another key of the same name is not used.
			fake, err := testpki.NewCA(curve, "ca "+curve)
			require.NoError(t, err)
			fakeCRL, err := uapolicy.CreateRevocationList(rand.Reader, &x509.RevocationList{
				Number: big.NewInt(2), ThisUpdate: time.Now(), NextUpdate: time.Now().Add(time.Hour),
				RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: leaf.X509.SerialNumber, RevocationTime: time.Now()}},
			}, fake.X509, fake.Key)
			require.NoError(t, err)
			tl, sc = newTrustList(&ua.TrustListDataType{TrustedCertificates: [][]byte{ca.Cert}, IssuerCrls: [][]byte{fakeCRL}}, 0)
			require.Equal(t, ua.StatusOK, sc)
			m.groups[groupApplication].trust.Store(tl)
			require.NoError(t, m.validateClient(leaf.Cert))
		})
	}
}

// TestPushEd448SigningRequest: a signing request for an Ed448 application
// instance certificate, issued by an Ed448 CA and installed.
func TestPushEd448SigningRequest(t *testing.T) {
	p := pushPKI(t)
	ed := p.ECC.Server[testpki.CurveEd448]
	s := newPushServer(t, PushManagement{}, ApplicationIdentity(ed.Cert, ed.Key))
	ctx, _ := adminCtx(s)
	typ := ua.NewNumericNodeID(0, id.EccCurve448ApplicationCertificateType)
	for _, regen := range []bool{false, true} {
		out, sc := pushCall(t, s, ctx, scObj, mCSR, defaultGroup, typ, "", regen, make([]byte, 32))
		require.Equal(t, ua.StatusOK, sc)
		req, err := uapolicy.ParseCertificateRequest(out[0].Value().([]byte))
		require.NoError(t, err)
		require.NoError(t, uapolicy.CheckCertificateRequestSignature(req))
		pub, ok := req.PublicKey.(ed448.PublicKey)
		require.True(t, ok)
		require.Equal(t, !regen, slices.Equal(pub, ed.Key.Public().(ed448.PublicKey)))
		if !regen {
			continue
		}
		ca, err := testpki.NewCA(testpki.CurveEd448, "ed448 ca")
		require.NoError(t, err)
		cert, err := testpki.IssueFromCSR(out[0].Value().([]byte), ca.X509, ca.Key)
		require.NoError(t, err)
		_, sc = pushCall(t, s, ctx, scObj, mUpdate, defaultGroup, typ, cert, [][]byte{ca.Cert}, "", []byte{})
		require.Equal(t, ua.StatusOK, sc)
		_, sc = pushCall(t, s, ctx, scObj, mApply)
		require.Equal(t, ua.StatusOK, sc)
		got, key, _ := s.cfg.identityFor(ua.SecurityPolicyURIECCCurve448)
		require.Equal(t, cert, got)
		require.True(t, uapolicy.KeyMatchesCertificate(key, cert))
	}
}
