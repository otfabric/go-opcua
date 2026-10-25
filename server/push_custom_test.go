// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/ua"
)

var (
	tlsClientType = ua.NewNumericNodeID(0, id.TLSClientCertificateType)
	userCertType  = ua.NewNumericNodeID(0, id.UserCertificateType)
)

// rsaSigner is an RSA key that is not an *rsa.PrivateKey (an HSM key).
type rsaSigner struct{ crypto.Signer }

func mustParse(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return c
}

// nodeCall calls a method of an object with NodeIds.
func nodeCall(t *testing.T, s *Server, ctx context.Context, obj, method *ua.NodeID, args ...any) ([]*ua.Variant, ua.StatusCode) {
	t.Helper()
	s.mu.Lock()
	h := s.methods[methodKey(obj, method)]
	s.mu.Unlock()
	require.NotNil(t, h, "method %v of %v not registered", method, obj)
	vs := make([]*ua.Variant, len(args))
	for i, a := range args {
		vs[i] = ua.MustVariant(a)
	}
	return h(ctx, obj, method, vs)
}

// customGroupPKI is a TLS client certificate of a group of the
// application.
func customGroupPKI(t *testing.T) *testpki.Identity {
	t.Helper()
	x, err := testpki.NewIdentity(testpki.CurveP256, "outgoing", testpki.ServerAppURI, nil, nil)
	require.NoError(t, err)
	return x
}

func newCustomServer(t *testing.T, pm PushManagement, opts ...Option) (*Server, *testpki.Identity) {
	t.Helper()
	p := pushPKI(t)
	tlsc := customGroupPKI(t)
	pm.CertificateGroups = append([]CertificateGroup{{
		Name:             "Outgoing",
		CertificateTypes: []*ua.NodeID{tlsClientType, p256Type},
		TrustList:        &ua.TrustListDataType{TrustedCertificates: [][]byte{p.CACert}},
		Certificates:     []GroupCertificate{{CertificateType: tlsClientType, Certificate: tlsc.Cert, PrivateKey: tlsc.Key}},
	}, {
		Name: "Partners",
	}}, pm.CertificateGroups...)
	return newPushServer(t, pm, opts...), tlsc
}

func TestPushCustomGroupOptions(t *testing.T) {
	p := pushPKI(t)
	tlsc := customGroupPKI(t)
	p256 := p.ECC.Server[testpki.CurveP256]
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	for name, g := range map[string][]CertificateGroup{
		"empty name":         {{}},
		"default name":       {{Name: "DefaultHttpsGroup"}},
		"repeated name":      {{Name: "a"}, {Name: "a"}},
		"trust list":         {{Name: "a", TrustList: &ua.TrustListDataType{TrustedCertificates: [][]byte{{1}}}}},
		"abstract type":      {{Name: "a", CertificateTypes: []*ua.NodeID{ua.NewNumericNodeID(0, id.ApplicationCertificateType)}}},
		"nil type":           {{Name: "a", CertificateTypes: []*ua.NodeID{nil}}},
		"repeated type":      {{Name: "a", CertificateTypes: []*ua.NodeID{tlsClientType, tlsClientType}}},
		"type of no group":   {{Name: "a", Certificates: []GroupCertificate{{CertificateType: tlsClientType, Certificate: tlsc.Cert, PrivateKey: tlsc.Key}}}},
		"bad certificate":    {{Name: "a", CertificateTypes: []*ua.NodeID{tlsClientType}, Certificates: []GroupCertificate{{CertificateType: tlsClientType, Certificate: []byte{1}, PrivateKey: tlsc.Key}}}},
		"key of other":       {{Name: "a", CertificateTypes: []*ua.NodeID{tlsClientType}, Certificates: []GroupCertificate{{CertificateType: tlsClientType, Certificate: tlsc.Cert, PrivateKey: other}}}},
		"no key":             {{Name: "a", CertificateTypes: []*ua.NodeID{tlsClientType}, Certificates: []GroupCertificate{{CertificateType: tlsClientType, Certificate: tlsc.Cert}}}},
		"wrong key for type": {{Name: "a", CertificateTypes: []*ua.NodeID{rsaType}, Certificates: []GroupCertificate{{CertificateType: rsaType, Certificate: p256.Cert, PrivateKey: p256.Key}}}},
		"bad issuer":         {{Name: "a", CertificateTypes: []*ua.NodeID{tlsClientType}, Certificates: []GroupCertificate{{CertificateType: tlsClientType, Certificate: tlsc.Cert, PrivateKey: tlsc.Key, Issuers: [][]byte{{1}}}}}},
		"two of a type": {{Name: "a", CertificateTypes: []*ua.NodeID{tlsClientType}, Certificates: []GroupCertificate{
			{CertificateType: tlsClientType, Certificate: tlsc.Cert, PrivateKey: tlsc.Key},
			{CertificateType: tlsClientType, Certificate: tlsc.Cert, PrivateKey: tlsc.Key},
		}}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := New(WithPushManagement(PushManagement{CertificateGroups: g}))
			require.Error(t, err)
		})
	}
	// An RSA type needs an *rsa.PrivateKey.
	_, err = checkCertificateGroups([]CertificateGroup{{Name: "a", CertificateTypes: []*ua.NodeID{rsaType},
		Certificates: []GroupCertificate{{CertificateType: rsaType, Certificate: p.ServerCert, PrivateKey: rsaSigner{p.ServerKey}}}}}, defaultMaxTrustListSize)
	require.ErrorIs(t, err, errGroupCertificate)

	// The configuration is copied.
	g := []CertificateGroup{{Name: "a", CertificateTypes: []*ua.NodeID{ua.NewFourByteNodeID(0, id.UserCertificateType)},
		Certificates: []GroupCertificate{{CertificateType: userCertType, Certificate: slices.Clone(p.UserCert), PrivateKey: p.UserKey, Issuers: [][]byte{p.CACert}}}}}
	cp, err := checkCertificateGroups(g, defaultMaxTrustListSize)
	require.NoError(t, err)
	g[0].Certificates[0].Certificate[0] ^= 0xff
	require.Equal(t, p.UserCert, cp[0].Certificates[0].Certificate)
	require.True(t, cp[0].CertificateTypes[0].Equal(userCertType))
}

// TestPushCustomGroups: a group of the application is a CertificateGroupType
// object in the CertificateGroups folder with its trust list and
// certificates, which the methods of ServerConfiguration manage.
func TestPushCustomGroups(t *testing.T) {
	p := pushPKI(t)
	st := &deleteStore{}
	s, tlsc := newCustomServer(t, PushManagement{Store: st, TrustListUpdateFrequency: time.Hour})
	ctx, _ := adminCtx(s)

	gid := s.CertificateGroupID("Outgoing")
	require.NotNil(t, gid)
	require.Equal(t, "CertificateGroups.Outgoing", gid.StringID())
	require.True(t, s.CertificateGroupID("DefaultHttpsGroup").Equal(httpsGroup))
	require.Nil(t, s.CertificateGroupID("nope"))
	partners := s.CertificateGroupID("Partners")
	tlID := ua.NewStringNodeID(gid.Namespace(), "CertificateGroups.Outgoing.TrustList")

	// The nodes.
	folder := s.Node(ua.NewNumericNodeID(0, id.ServerConfigurationCertificateGroups))
	require.True(t, hasForwardRef(folder, gid, id.Organizes))
	gn := s.Node(gid)
	require.NotNil(t, gn)
	require.Equal(t, "Outgoing", gn.BrowseName().Name)
	require.True(t, hasForwardRef(gn, ua.NewNumericNodeID(0, id.CertificateGroupType), id.HasTypeDefinition))
	require.True(t, hasForwardRef(gn, tlID, id.HasComponent))
	tn := s.Node(tlID)
	require.True(t, hasForwardRef(tn, ua.NewNumericNodeID(0, id.CertificateGroupTypeTrustListOpen), id.HasComponent))
	value := func(name string) any {
		t.Helper()
		n := s.Node(ua.NewStringNodeID(gid.Namespace(), name))
		require.NotNil(t, n, name)
		return n.Value().Value.Value()
	}
	require.Equal(t, []*ua.NodeID{tlsClientType, p256Type}, value("CertificateGroups.Outgoing.CertificateTypes"))
	require.Equal(t, []*ua.NodeID{}, value("CertificateGroups.Partners.CertificateTypes"))
	require.Equal(t, true, value("CertificateGroups.Outgoing.TrustList.Writable"))
	require.Equal(t, uint16(0), value("CertificateGroups.Outgoing.TrustList.OpenCount"))
	require.NotZero(t, value("CertificateGroups.Outgoing.TrustList.Size"))
	require.Equal(t, float64(time.Hour/time.Millisecond), value("CertificateGroups.Outgoing.TrustList.UpdateFrequency"))
	require.Equal(t, uint32(maxTrustListRead), value("CertificateGroups.Outgoing.TrustList.MaxByteStringLength"))
	require.IsType(t, time.Time{}, value("CertificateGroups.Outgoing.TrustList.LastUpdateTime"))

	// The trust list: the methods of the TrustList, the application's
	// validation.
	require.Equal(t, [][]byte{p.CACert}, s.GroupTrustList(gid).TrustedCertificates)
	require.NoError(t, s.VerifyGroupCertificate(gid, p.IssuedCert))
	require.ErrorIs(t, s.VerifyGroupCertificate(partners, p.IssuedCert), ua.StatusBadCertificateUntrusted)
	require.Contains(t, s.RejectedCertificates(), p.IssuedCert)
	require.ErrorIs(t, s.VerifyGroupCertificate(ua.NewStringNodeID(1, "x"), p.IssuedCert), ua.StatusBadInvalidArgument)
	open := ua.NewNumericNodeID(0, id.CertificateGroupTypeTrustListOpen)
	out, sc := nodeCall(t, s, ctx, tlID, open, byte(1))
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, uint16(1), value("CertificateGroups.Outgoing.TrustList.OpenCount"))
	_, sc = nodeCall(t, s, ctx, tlID, ua.NewNumericNodeID(0, id.CertificateGroupTypeTrustListClose), out[0].Value())
	require.Equal(t, ua.StatusOK, sc)
	partnersTL := ua.NewStringNodeID(gid.Namespace(), "CertificateGroups.Partners.TrustList")
	_, sc = nodeCall(t, s, ctx, partnersTL, ua.NewNumericNodeID(0, id.CertificateGroupTypeTrustListAddCertificate), p.CACert, true)
	require.Equal(t, ua.StatusOK, sc)
	// The methods of another TrustList are not those of the group.
	s.mu.Lock()
	_, ok := s.methods[methodKey(partnersTL, ua.NewNumericNodeID(0, mOpen))]
	s.mu.Unlock()
	require.False(t, ok)

	// The certificates: GetCertificates, CreateSelfSignedCertificate,
	// CreateSigningRequest and UpdateCertificate for an empty type.
	types, certs := getCerts(t, s, ctx, gid)
	require.Equal(t, []*ua.NodeID{tlsClientType}, types)
	require.Equal(t, [][]byte{tlsc.Cert}, certs)
	cert, _, key := s.GroupCertificate(gid, nil)
	require.Equal(t, tlsc.Cert, cert)
	require.Equal(t, tlsc.Key, key)
	newTLS, sc := selfSigned(t, s, ctx, gid, ua.NewNumericNodeID(0, id.TLSCertificateType), "", nil, nil, 30, 0)
	require.Equal(t, ua.StatusOK, sc)
	out, sc = pushCall(t, s, ctx, scObj, mCSR, gid, p256Type, "CN=outgoing-ecc", true, make([]byte, 32))
	require.Equal(t, ua.StatusOK, sc)
	ca := p.ECC.CAs[testpki.CurveP256]
	caX := mustParse(t, ca.Cert)
	issued, err := testpki.IssueFromCSR(out[0].Value().([]byte), caX, ca.Key)
	require.NoError(t, err)
	out, sc = pushCall(t, s, ctx, scObj, mUpdate, gid, p256Type, issued, [][]byte{ca.Cert}, "", []byte{})
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, true, out[0].Value())
	// The certificates of the other types do not fit.
	_, sc = pushCall(t, s, ctx, scObj, mUpdate, gid, p256Type, p.ServerCert, [][]byte{}, "", []byte{})
	require.Equal(t, ua.StatusBadCertificateInvalid, sc)
	_, sc = pushCall(t, s, ctx, scObj, mUpdate, gid, rsaType, p.ServerCert, [][]byte{}, "", []byte{})
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	_, sc = pushCall(t, s, ctx, scObj, mUpdate, partners, nullNode, p.ServerCert, [][]byte{}, "", []byte{})
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	d := s.push.diagnostics()
	require.Contains(t, d.groups, gid)
	require.Contains(t, d.trustLists, partnersTL)
	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusOK, sc)
	types, certs = getCerts(t, s, ctx, gid)
	require.Equal(t, []*ua.NodeID{tlsClientType, p256Type}, types)
	require.Equal(t, [][]byte{newTLS, issued}, certs)
	cert, issuers, _ := s.GroupCertificate(gid, p256Type)
	require.Equal(t, issued, cert)
	require.Equal(t, [][]byte{ca.Cert}, issuers)
	require.Len(t, s.GroupTrustList(partners).TrustedCertificates, 1)
	st.mu.Lock()
	require.Contains(t, st.trust, partners.String())
	require.Contains(t, st.certs, issued)
	st.mu.Unlock()

	// DeleteCertificate; ResetToServerDefaults restores the certificates
	// and trust lists the groups started with and deletes the others.
	_, sc = pushCall(t, s, ctx, scObj, mDelete, gid, tlsClientType)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusOK, sc)
	cert, _, _ = s.GroupCertificate(gid, tlsClientType)
	require.Nil(t, cert)
	_, sc = pushCall(t, s, ctx, scObj, mReset)
	require.Equal(t, ua.StatusOK, sc)
	types, certs = getCerts(t, s, ctx, gid)
	require.Equal(t, []*ua.NodeID{tlsClientType}, types)
	require.Equal(t, [][]byte{tlsc.Cert}, certs)
	require.Empty(t, s.GroupTrustList(partners).TrustedCertificates)
	require.Contains(t, st.deletions(), gid.String()+" "+p256Type.String())

	// Unknown arguments of the server API.
	cert, _, _ = s.GroupCertificate(ua.NewStringNodeID(1, "x"), nil)
	require.Nil(t, cert)
	cert, _, _ = s.GroupCertificate(gid, ua.NewStringNodeID(1, "x"))
	require.Nil(t, cert)
	cert, _, _ = s.GroupCertificate(partners, nil)
	require.Nil(t, cert)
	cert, _, _ = s.GroupCertificate(nil, nil)
	require.Equal(t, p.ServerCert, cert)
}

// TestPushCustomGroupTypes: the types of a group of the application and
// the keys CreateSelfSignedCertificate makes for them.
func TestPushCustomGroupTypes(t *testing.T) {
	p := pushPKI(t)
	types := []*ua.NodeID{rsaType, userCertType, httpsType, ua.NewNumericNodeID(0, id.TLSServerCertificateType)}
	s := newPushServer(t, PushManagement{ApplyImmediately: true, CertificateGroups: []CertificateGroup{{
		Name: "All", CertificateTypes: types,
		Certificates: []GroupCertificate{{CertificateType: userCertType, Certificate: p.UserCert, PrivateKey: p.UserKey}},
	}}})
	ctx, _ := adminCtx(s)
	gid := s.CertificateGroupID("All")
	for _, tc := range []struct {
		want, have *ua.NodeID
	}{
		{nullNode, rsaType},
		{ua.NewNumericNodeID(0, id.RsaMinApplicationCertificateType), rsaType},
		{ua.NewNumericNodeID(0, id.CertificateType), rsaType},
		{userCertType, userCertType},
		{httpsType, httpsType},
		{ua.NewNumericNodeID(0, id.TLSCertificateType), ua.NewNumericNodeID(0, id.TLSServerCertificateType)},
	} {
		der, sc := selfSigned(t, s, ctx, gid, tc.want, "CN=x", nil, nil, 1, 0)
		require.Equal(t, ua.StatusOK, sc, "%v", tc.want)
		cert, _, key := s.GroupCertificate(gid, tc.have)
		require.Equal(t, der, cert, "%v", tc.want)
		require.NotNil(t, key)
	}
	_, sc := selfSigned(t, s, ctx, gid, p256Type, "CN=x", nil, nil, 1, 0)
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	_, sc = selfSigned(t, s, ctx, gid, ua.NewNumericNodeID(0, id.TLSClientCertificateType), "CN=x", nil, nil, 1, 0)
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	require.True(t, groupTypeMatches(0, id.UserCertificateType))
	require.False(t, groupTypeMatches(id.HTTPSCertificateType, id.UserCertificateType))
	require.True(t, isTLSType(id.HTTPSCertificateType))
	require.False(t, isAppType(id.EccApplicationCertificateType))
}

// TestPushCustomGroupAlarms: the groups of the application have alarms.
func TestPushCustomGroupAlarms(t *testing.T) {
	s, tlsc := newCustomServer(t, PushManagement{
		TrustListUpdateFrequency: time.Hour,
		Alarms:                   &CertificateAlarms{ExpirationLimit: time.Hour},
	})
	a := s.push.alarms
	// Expiry: the two default groups with certificates and Outgoing; out
	// of date: all five.
	require.Len(t, a.expiry, 3)
	require.Len(t, a.outOfDate, 5)
	gid := s.CertificateGroupID("Outgoing")
	x := a.expiry[2]
	require.True(t, x.cond.Source().Equal(gid))
	a.evaluate()
	a.propMu.Lock()
	require.Equal(t, tlsc.Cert, x.cert)
	a.propMu.Unlock()
	require.True(t, slices.ContainsFunc(a.outOfDate, func(o *outOfDateAlarm) bool { return o.cond.Source().Equal(s.CertificateGroupID("Partners")) }))
}

// TestPushCustomGroupsWithoutModel: without ServerConfiguration in the
// address space the groups have no nodes but work through the API.
func TestPushCustomGroupsWithoutModel(t *testing.T) {
	m := newPushManager(&PushManagement{MaxTrustListSize: defaultMaxTrustListSize, CertificateGroups: []CertificateGroup{{Name: "a"}}}, &serverConfig{})
	require.Len(t, m.groups, 4)
	require.Nil(t, m.groups[3].nodeID())
	_, ok := m.group(ua.NewStringNodeID(1, "CertificateGroups.a"))
	require.False(t, ok)
}
