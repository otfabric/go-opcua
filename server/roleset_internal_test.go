// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

// newRoleSetTestServer returns a server (not started) with the managed
// RoleSet configured by rm.
func newRoleSetTestServer(t *testing.T, rm RoleManagement, opts ...Option) *Server {
	t.Helper()
	s, err := New(append([]Option{InsecureNoSecurity(), EndPoint("localhost", 0), WithRoleManagement(rm)}, opts...)...)
	require.NoError(t, err)
	s.initEndpoints()
	require.NotNil(t, s.RoleSet())
	return s
}

func userRule(name string) *ua.IdentityMappingRuleType {
	return &ua.IdentityMappingRuleType{CriteriaType: ua.IdentityCriteriaTypeUserName, Criteria: name}
}

// roleCallerCtx returns the context of a Method call by a new session of s
// with the mode and roles.
func roleCallerCtx(s *Server, mode ua.MessageSecurityMode, roles ...*ua.NodeID) context.Context {
	ctx, _ := pushCallerCtx(s, mode, roles...)
	return ctx
}

func roleAdminCtx(s *Server) context.Context {
	return roleCallerCtx(s, ua.MessageSecurityModeSignAndEncrypt, ua.RoleSecurityAdmin.NodeID())
}

// callRole calls the Method method of obj as registered.
func callRole(t *testing.T, s *Server, ctx context.Context, obj, method *ua.NodeID, args ...*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	t.Helper()
	s.mu.Lock()
	h := s.methods[methodKey(obj, method)]
	s.mu.Unlock()
	require.NotNil(t, h, "method %v of %v not registered", method, obj)
	return h(ctx, obj, method, args)
}

// The RoleSet without WithRoleManagement: nothing of it.
func TestRoleSetDisabled(t *testing.T) {
	t.Parallel()
	s, err := New(InsecureNoSecurity(), EndPoint("localhost", 0))
	require.NoError(t, err)
	require.Nil(t, s.RoleSet())
	s.mu.Lock()
	_, ok := s.methods[methodKey(roleSetNodeID, roleSetAddRoleID)]
	s.mu.Unlock()
	require.False(t, ok)

	sess := s.sb.NewSession()
	s.grantRoles(nil, sess, &ua.UserNameIdentityToken{UserName: "alice"})
	require.Equal(t, []string{"i=15656"}, nodeStrings(sess.currentRoles()))
	require.Nil(t, sess.roleFacts)
}

func TestRoleSetDefaults(t *testing.T) {
	t.Parallel()
	s := newRoleSetTestServer(t, RoleManagement{})
	rs := s.RoleSet()
	require.Equal(t, DefaultMaxRoles, rs.maxRoles)
	require.Equal(t, DefaultMaxRoleEntries, rs.maxEntries)

	roles := rs.Roles()
	require.Len(t, roles, 12, "the well-known roles of the NodeSet")
	byName := map[string]Role{}
	for _, r := range roles {
		byName[r.BrowseName.Name] = r
		require.False(t, r.Removable)
		require.True(t, r.ApplicationsExclude)
		require.True(t, r.EndpointsExclude)
	}
	anon := byName["Anonymous"]
	require.True(t, anon.Fixed)
	require.Len(t, anon.Identities, 2)
	require.Equal(t, ua.IdentityCriteriaTypeAnonymous, anon.Identities[0].CriteriaType)
	require.Equal(t, ua.IdentityCriteriaTypeAuthenticatedUser, anon.Identities[1].CriteriaType)
	require.True(t, byName["AuthenticatedUser"].Fixed)
	require.True(t, byName["TrustedApplication"].Fixed)
	require.False(t, byName["Observer"].Fixed)
	require.Empty(t, byName["Observer"].Identities)

	r, ok := rs.Role(ua.RoleObserver.NodeID())
	require.True(t, ok)
	require.Equal(t, "Observer", r.BrowseName.Name)
	_, ok = rs.Role(ua.NewNumericNodeID(0, 1))
	require.False(t, ok)
	_, ok = rs.Role(nil)
	require.False(t, ok)

	// The Properties serve the configuration.
	ids := s.Node(ns0(id.WellKnownRoleAnonymousIDentities)).Value()
	require.Len(t, ids.Value.Value(), 2)
	require.NoError(t, rs.AddApplication(ua.RoleObserver.NodeID(), "urn:a"))
	require.Equal(t, []string{"urn:a"}, s.Node(ns0(id.WellKnownRoleObserverApplications)).Value().Value.Value())
	require.Equal(t, true, s.Node(ns0(id.WellKnownRoleObserverApplicationsExclude)).Value().Value.Value())
	require.Equal(t, []string{}, s.Node(ns0(id.WellKnownRoleOperatorApplications)).Value().Value.Value())
	require.Len(t, s.Node(ns0(id.WellKnownRoleObserverEndpoints)).Value().Value.Value(), 0)
	require.Equal(t, true, s.Node(ns0(id.WellKnownRoleObserverEndpointsExclude)).Value().Value.Value())
	require.Equal(t, false, s.Node(ns0(id.WellKnownRoleObserverCustomConfiguration)).Value().Value.Value())
}

func TestRoleSetIdentities(t *testing.T) {
	t.Parallel()
	s := newRoleSetTestServer(t, RoleManagement{MaxEntries: 2})
	rs := s.RoleSet()
	obs := ua.RoleObserver.NodeID()

	require.ErrorIs(t, rs.AddIdentity(obs, nil), ua.StatusBadInvalidArgument)
	require.ErrorIs(t, rs.AddIdentity(obs, userRule(strings.Repeat("u", maxRoleText+1))), ua.StatusBadInvalidArgument)
	require.ErrorIs(t, rs.AddIdentity(ua.NewNumericNodeID(0, 1), userRule("a")), ua.StatusBadNodeIDUnknown)
	require.ErrorIs(t, rs.AddIdentity(ua.RoleAnonymous.NodeID(), userRule("a")), ua.StatusBadRequestNotAllowed)
	for _, admin := range []*ua.NodeID{ua.RoleSecurityAdmin.NodeID(), ua.RoleConfigureAdmin.NodeID(), ns0(id.WellKnownRoleSecurityKeyServerAdmin)} {
		require.ErrorIs(t, rs.AddIdentity(admin, &ua.IdentityMappingRuleType{CriteriaType: ua.IdentityCriteriaTypeAnonymous}),
			ua.StatusBadRequestNotAllowed)
	}
	require.NoError(t, rs.AddIdentity(obs, userRule("a")))
	require.ErrorIs(t, rs.AddIdentity(obs, userRule("a")), ua.StatusBadAlreadyExists)
	require.NoError(t, rs.AddIdentity(obs, &ua.IdentityMappingRuleType{CriteriaType: ua.IdentityCriteriaTypeAnonymous}))
	require.ErrorIs(t, rs.AddIdentity(obs, userRule("b")), ua.StatusBadResourceUnavailable)

	require.ErrorIs(t, rs.RemoveIdentity(obs, userRule("b")), ua.StatusBadNotFound)
	require.ErrorIs(t, rs.RemoveIdentity(obs, nil), ua.StatusBadNotFound)
	require.NoError(t, rs.RemoveIdentity(obs, userRule("a")))
	r, _ := rs.Role(obs)
	require.Len(t, r.Identities, 1)
	require.Equal(t, ua.IdentityCriteriaTypeAnonymous, r.Identities[0].CriteriaType)
	require.ErrorIs(t, rs.RemoveIdentity(ua.RoleAuthenticatedUser.NodeID(), userRule("a")), ua.StatusBadRequestNotAllowed)
}

func TestRoleSetCheckRule(t *testing.T) {
	t.Parallel()
	s := newRoleSetTestServer(t, RoleManagement{})
	jwt := newRoleSetTestServer(t, RoleManagement{}, WithIssuedTokenPolicy(IssuedTokenTypeJWT, ""))
	rule := func(c ua.IdentityCriteriaType, v string) *ua.IdentityMappingRuleType {
		return &ua.IdentityMappingRuleType{CriteriaType: c, Criteria: v}
	}
	for _, tc := range []struct {
		rule      *ua.IdentityMappingRuleType
		want, jwt error
	}{
		{rule(ua.IdentityCriteriaTypeAnonymous, ""), nil, nil},
		{rule(ua.IdentityCriteriaTypeAnonymous, "x"), ua.StatusBadInvalidArgument, ua.StatusBadInvalidArgument},
		{rule(ua.IdentityCriteriaTypeAuthenticatedUser, ""), nil, nil},
		{rule(ua.IdentityCriteriaTypeTrustedApplication, "x"), ua.StatusBadInvalidArgument, ua.StatusBadInvalidArgument},
		{rule(ua.IdentityCriteriaTypeUserName, ""), ua.StatusBadInvalidArgument, ua.StatusBadInvalidArgument},
		{rule(ua.IdentityCriteriaTypeRole, ""), ua.StatusBadInvalidArgument, ua.StatusBadInvalidArgument},
		{rule(ua.IdentityCriteriaTypeRole, "iss/admins"), ua.StatusBadNotSupported, nil},
		{rule(ua.IdentityCriteriaTypeGroupID, "g"), ua.StatusBadNotSupported, nil},
		{rule(ua.IdentityCriteriaTypeThumbprint, strings.Repeat("A1", 20)), nil, nil},
		{rule(ua.IdentityCriteriaTypeThumbprint, strings.Repeat("a1", 20)), ua.StatusBadInvalidArgument, ua.StatusBadInvalidArgument},
		{rule(ua.IdentityCriteriaTypeThumbprint, "A1"), ua.StatusBadInvalidArgument, ua.StatusBadInvalidArgument},
		{rule(ua.IdentityCriteriaTypeApplication, "urn:app"), nil, nil},
		{rule(ua.IdentityCriteriaTypeApplication, "app"), ua.StatusBadInvalidArgument, ua.StatusBadInvalidArgument},
		{rule(ua.IdentityCriteriaTypeX509Subject, `CN="op"/O="Plant"`), nil, nil},
		{rule(ua.IdentityCriteriaTypeX509Subject, `CN=op`), ua.StatusBadInvalidArgument, ua.StatusBadInvalidArgument},
		{rule(ua.IdentityCriteriaType(0), ""), ua.StatusBadInvalidArgument, ua.StatusBadInvalidArgument},
		{rule(ua.IdentityCriteriaType(10), ""), ua.StatusBadInvalidArgument, ua.StatusBadInvalidArgument},
	} {
		require.Equal(t, tc.want, s.RoleSet().checkRule(tc.rule), "%v %q", tc.rule.CriteriaType, tc.rule.Criteria)
		require.Equal(t, tc.jwt, jwt.RoleSet().checkRule(tc.rule), "jwt %v %q", tc.rule.CriteriaType, tc.rule.Criteria)
	}
}

func TestRoleSetApplicationsAndEndpoints(t *testing.T) {
	t.Parallel()
	s := newRoleSetTestServer(t, RoleManagement{MaxEntries: 1})
	rs := s.RoleSet()
	op := ua.RoleOperator.NodeID()

	require.ErrorIs(t, rs.AddApplication(op, ""), ua.StatusBadInvalidArgument)
	require.ErrorIs(t, rs.AddApplication(ua.NewNumericNodeID(0, 1), "urn:a"), ua.StatusBadNodeIDUnknown)
	require.NoError(t, rs.AddApplication(op, "urn:a"))
	require.ErrorIs(t, rs.AddApplication(op, "urn:a"), ua.StatusBadAlreadyExists)
	require.ErrorIs(t, rs.AddApplication(op, "urn:b"), ua.StatusBadResourceUnavailable)
	require.ErrorIs(t, rs.RemoveApplication(op, "urn:b"), ua.StatusBadNotFound)
	require.NoError(t, rs.RemoveApplication(op, "urn:a"))

	ep := &ua.EndpointType{EndpointURL: "opc.tcp://host:4840", SecurityMode: ua.MessageSecurityModeSign}
	require.ErrorIs(t, rs.AddEndpoint(op, nil), ua.StatusBadInvalidArgument)
	require.NoError(t, rs.AddEndpoint(op, ep))
	require.ErrorIs(t, rs.AddEndpoint(op, &ua.EndpointType{EndpointURL: "OPC.TCP://HOST:4840", SecurityMode: ua.MessageSecurityModeSign}),
		ua.StatusBadAlreadyExists, "the URL compared as GetEndpoints compares it")
	require.ErrorIs(t, rs.AddEndpoint(op, &ua.EndpointType{EndpointURL: "opc.tcp://other:4840"}), ua.StatusBadResourceUnavailable)
	require.ErrorIs(t, rs.RemoveEndpoint(op, &ua.EndpointType{EndpointURL: "opc.tcp://host:4840"}), ua.StatusBadNotFound)
	r, _ := rs.Role(op)
	require.Len(t, r.Endpoints, 1)
	r.Endpoints[0].EndpointURL = "opc.tcp://changed"
	again, _ := rs.Role(op)
	require.Equal(t, ep.EndpointURL, again.Endpoints[0].EndpointURL, "Role returns a copy")
	require.NoError(t, rs.RemoveEndpoint(op, ep))

	require.NoError(t, rs.SetApplicationsExclude(op, false))
	require.NoError(t, rs.SetEndpointsExclude(op, false))
	r, _ = rs.Role(op)
	require.False(t, r.ApplicationsExclude)
	require.False(t, r.EndpointsExclude)
	require.ErrorIs(t, rs.SetApplicationsExclude(ua.RoleTrustedApplication.NodeID(), false), ua.StatusBadRequestNotAllowed)
	require.ErrorIs(t, rs.SetEndpointsExclude(ua.NewNumericNodeID(0, 1), false), ua.StatusBadNodeIDUnknown)
}

func TestRoleSetValidators(t *testing.T) {
	t.Parallel()
	for s, want := range map[string]bool{
		"urn:a": true, "http://x/y": true, "": false, "a b": false, "urn:\x01": false,
		"%zz:x": false, "urn:" + strings.Repeat("a", maxRoleText): false,
	} {
		require.Equal(t, want, validURI(s), s)
	}
	long := strings.Repeat("a", maxRoleText+1)
	for _, tc := range []struct {
		ep   *ua.EndpointType
		want bool
	}{
		{&ua.EndpointType{EndpointURL: "opc.tcp://h:1"}, true},
		{&ua.EndpointType{EndpointURL: "opc.wss://h/x"}, true},
		{&ua.EndpointType{EndpointURL: "opc.https://h"}, true},
		{&ua.EndpointType{EndpointURL: "https://h"}, true},
		{&ua.EndpointType{EndpointURL: "WSS://h"}, true},
		{&ua.EndpointType{EndpointURL: "http://h"}, false},
		{&ua.EndpointType{EndpointURL: "opc.tcp://"}, false},
		{&ua.EndpointType{EndpointURL: "opc.tcp://h:x:y%"}, false},
		{&ua.EndpointType{EndpointURL: "opc.tcp://h\x01"}, false},
		{&ua.EndpointType{EndpointURL: "opc.tcp://" + long}, false},
		{&ua.EndpointType{EndpointURL: "opc.tcp://h", SecurityPolicyURI: long}, false},
		{&ua.EndpointType{EndpointURL: "opc.tcp://h", TransportProfileURI: long}, false},
		{&ua.EndpointType{EndpointURL: "opc.tcp://h", SecurityMode: ua.MessageSecurityModeSignAndEncrypt}, true},
		{&ua.EndpointType{EndpointURL: "opc.tcp://h", SecurityMode: ua.MessageSecurityMode(4)}, false},
		{nil, false},
	} {
		require.Equal(t, tc.want, validEndpoint(tc.ep), "%+v", tc.ep)
	}
	require.True(t, validThumbprint(strings.Repeat("0F", 20)))
	require.False(t, validThumbprint(strings.Repeat("0G", 20)))
}

func TestRoleSetSubjectCriteria(t *testing.T) {
	t.Parallel()
	atv := func(oid asn1.ObjectIdentifier, v any) pkix.AttributeTypeAndValue {
		return pkix.AttributeTypeAndValue{Type: oid, Value: v}
	}
	cn, o, ou, dc := subjectNames[0].oid, subjectNames[1].oid, subjectNames[2].oid, subjectNames[3].oid
	got, ok := subjectCriteria(pkix.Name{Names: []pkix.AttributeTypeAndValue{
		atv(ou, "b"), atv(dc, "plant"), atv(o, "Org"), atv(ou, "a"), atv(cn, "op"),
		atv(asn1.ObjectIdentifier{1, 2, 3}, "ignored"),
	}})
	require.True(t, ok)
	require.Equal(t, `CN="op"/O="Org"/OU="b"/OU="a"/DC="plant"`, got, "Table 10 order, repeated names in certificate order")
	require.True(t, validSubjectCriteria(got))

	for _, n := range []pkix.Name{
		{},
		{Names: []pkix.AttributeTypeAndValue{atv(cn, `a"b`)}},
		{Names: []pkix.AttributeTypeAndValue{atv(cn, "a\nb")}},
		{Names: []pkix.AttributeTypeAndValue{atv(cn, 7)}},
		{Names: []pkix.AttributeTypeAndValue{atv(asn1.ObjectIdentifier{1, 2, 3}, "x")}},
	} {
		_, ok := subjectCriteria(n)
		require.False(t, ok, "%v", n.Names)
	}

	for s, want := range map[string]bool{
		`CN="a"`:                           true,
		`CN="a"/CN="b"`:                    true,
		`CN="a/b"/S="x"/serialNumber="1"`:  true,
		`dnQualifier="q"/serialNumber="1"`: true,
		``:                                 false,
		`CN`:                               false,
		`XX="a"`:                           false,
		`O="a"/CN="b"`:                     false,
		`CN=a`:                             false,
		`CN="a`:                            false,
		`CN="a"x`:                          false,
		`CN="a"/`:                          false,
		"CN=\"\x01\"":                      false,
	} {
		require.Equal(t, want, validSubjectCriteria(s), s)
	}
}

func testJWT(payload string) []byte {
	enc := base64.RawURLEncoding.EncodeToString
	return []byte(enc([]byte(`{"alg":"none"}`)) + "." + enc([]byte(payload)) + ".sig")
}

func TestRoleSetJWTClaims(t *testing.T) {
	t.Parallel()
	c, ok := parseJWTClaims(testJWT(`{"iss":"idp","roles":["r"],"groups":["g1","g2"]}`))
	require.True(t, ok)
	roles, groups := c.qualified()
	require.Equal(t, []string{"idp/r"}, roles)
	require.Equal(t, []string{"idp/g1", "idp/g2"}, groups)

	c, ok = parseJWTClaims(testJWT(`{"roles":["r"]}`))
	require.True(t, ok)
	roles, groups = c.qualified()
	require.Equal(t, []string{"r"}, roles)
	require.Nil(t, groups)

	padded := strings.Replace(string(testJWT(`{"a":1}`)), ".sig", "", 1)
	_, ok = parseJWTClaims([]byte(padded + "==.sig"))
	require.True(t, ok, "padding is tolerated")

	for _, data := range [][]byte{nil, []byte("a.b"), []byte("a.!!.c"), testJWT(`not json`), testJWT(`{"roles":"r"}`)} {
		_, ok := parseJWTClaims(data)
		require.False(t, ok, "%q", data)
	}
}

// userCert returns a certificate with the subject of the CN op and the O
// Plant, issued by itself.
func userCert(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "op", Organization: []string{"Plant"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return der
}

func TestRoleSetFacts(t *testing.T) {
	t.Parallel()
	s := newRoleSetTestServer(t, RoleManagement{})
	sess := s.sb.NewSession()

	f := s.newRoleFacts(nil, sess, nil)
	require.True(t, f.anonymous)
	require.False(t, f.signed)
	require.Empty(t, f.endpoints, "no endpointUrl")
	require.True(t, s.newRoleFacts(nil, sess, &ua.AnonymousIdentityToken{}).anonymous)

	f = s.newRoleFacts(nil, sess, &ua.UserNameIdentityToken{UserName: "alice"})
	require.True(t, f.isUser)
	require.Equal(t, "alice", f.userName)

	cert := userCert(t)
	f = s.newRoleFacts(nil, sess, &ua.X509IdentityToken{CertificateData: cert})
	require.Equal(t, thumbprint(cert), f.thumbprint)
	require.Equal(t, `CN="op"/O="Plant"`, f.subject)
	require.Equal(t, `CN="op"/O="Plant"`, f.issuer)
	require.Empty(t, s.newRoleFacts(nil, sess, &ua.X509IdentityToken{CertificateData: []byte{1}}).thumbprint)

	tok := &ua.IssuedIdentityToken{TokenData: testJWT(`{"iss":"idp","roles":["r"]}`)}
	require.Empty(t, s.newRoleFacts(nil, sess, tok).roles, "no JWT policy")
	jwt := newRoleSetTestServer(t, RoleManagement{}, WithIssuedTokenPolicy(IssuedTokenTypeJWT, ""))
	require.Equal(t, []string{"idp/r"}, jwt.newRoleFacts(nil, jwt.sb.NewSession(), tok).roles)
	require.Empty(t, jwt.newRoleFacts(nil, jwt.sb.NewSession(), &ua.IssuedIdentityToken{TokenData: []byte("x")}).roles)

	// The channel: signed, the Client Certificate and its ApplicationUri,
	// trusted only with a validator.
	p := pushPKI(t)
	sc := uasc.NewCryptoChannel(&uasc.Config{SecurityMode: ua.MessageSecurityModeSign,
		SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256, RemoteCertificate: p.ClientCert})
	f = s.newRoleFacts(sc, sess, nil)
	require.True(t, f.signed)
	require.False(t, f.trusted)
	require.Equal(t, "urn:otfabric:conformance:client", f.appURI)
	v := newRoleSetTestServer(t, RoleManagement{}, WithClientCertificateValidator(func([]byte) error { return nil }))
	f = v.newRoleFacts(sc, v.sb.NewSession(), nil)
	require.True(t, f.trustedApp())
	selfNoURI := uasc.NewCryptoChannel(&uasc.Config{SecurityMode: ua.MessageSecurityModeSignAndEncrypt,
		SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256, RemoteCertificate: cert})
	f = v.newRoleFacts(selfNoURI, v.sb.NewSession(), nil)
	require.True(t, f.trustedApp())
	require.Empty(t, f.appURI)

	// The Endpoint: the one of the endpointUrl, policy and mode.
	ep := s.Endpoints()[0]
	sess.obs.describe(sess.ID, &ua.CreateSessionRequest{EndpointURL: ep.EndpointURL})
	f = s.newRoleFacts(scNone(), sess, nil)
	require.Len(t, f.endpoints, 1)
	require.Equal(t, ep.EndpointURL, f.endpoints[0].EndpointURL)
	require.Empty(t, s.newRoleFacts(sc, sess, nil).endpoints, "no such Endpoint")
}

func TestRoleSetRuleMatches(t *testing.T) {
	t.Parallel()
	rule := func(c ua.IdentityCriteriaType, v string) *ua.IdentityMappingRuleType {
		return &ua.IdentityMappingRuleType{CriteriaType: c, Criteria: v}
	}
	user := &roleFacts{isUser: true, userName: "alice"}
	anon := &roleFacts{anonymous: true}
	cert := &roleFacts{thumbprint: "AB", subject: `CN="op"`, issuer: `CN="ca"`}
	jwt := &roleFacts{roles: []string{"idp/r"}, groups: []string{"idp/g"}}
	app := &roleFacts{anonymous: true, signed: true, trusted: true, appURI: "urn:app"}
	untrusted := &roleFacts{anonymous: true, signed: true, appURI: "urn:app"}
	for _, tc := range []struct {
		rule *ua.IdentityMappingRuleType
		f    *roleFacts
		want bool
	}{
		{rule(ua.IdentityCriteriaTypeUserName, "alice"), user, true},
		{rule(ua.IdentityCriteriaTypeUserName, "bob"), user, false},
		{rule(ua.IdentityCriteriaTypeUserName, ""), anon, false},
		{rule(ua.IdentityCriteriaTypeThumbprint, "AB"), cert, true},
		{rule(ua.IdentityCriteriaTypeThumbprint, ""), anon, false},
		{rule(ua.IdentityCriteriaTypeRole, "idp/r"), jwt, true},
		{rule(ua.IdentityCriteriaTypeRole, "r"), jwt, false},
		{rule(ua.IdentityCriteriaTypeGroupID, "idp/g"), jwt, true},
		{rule(ua.IdentityCriteriaTypeAnonymous, ""), anon, true},
		{rule(ua.IdentityCriteriaTypeAnonymous, ""), user, false},
		{rule(ua.IdentityCriteriaTypeAuthenticatedUser, ""), user, true},
		{rule(ua.IdentityCriteriaTypeAuthenticatedUser, ""), anon, false},
		{rule(ua.IdentityCriteriaTypeApplication, "urn:app"), app, true},
		{rule(ua.IdentityCriteriaTypeApplication, "urn:app"), untrusted, false},
		{rule(ua.IdentityCriteriaTypeX509Subject, `CN="op"`), cert, true},
		{rule(ua.IdentityCriteriaTypeX509Subject, `CN="ca"`), cert, true /* the issuing CA (errata) */},
		{rule(ua.IdentityCriteriaTypeX509Subject, `CN="op"`), anon, false},
		{rule(ua.IdentityCriteriaTypeTrustedApplication, ""), app, true},
		{rule(ua.IdentityCriteriaTypeTrustedApplication, ""), untrusted, false},
		{rule(ua.IdentityCriteriaType(42), ""), user, false},
	} {
		require.Equal(t, tc.want, ruleMatches(tc.rule, tc.f), "%v %q %+v", tc.rule.CriteriaType, tc.rule.Criteria, tc.f)
	}
}

func TestRoleSetGrants(t *testing.T) {
	t.Parallel()
	ep := &ua.EndpointDescription{EndpointURL: "opc.tcp://h:4840", SecurityMode: ua.MessageSecurityModeSign,
		SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256, TransportProfileURI: "tcp"}
	f := &roleFacts{isUser: true, userName: "alice", signed: true, trusted: true, appURI: "urn:app", endpoints: []*ua.EndpointDescription{ep}}
	r := &managedRole{identities: []*ua.IdentityMappingRuleType{userRule("alice")}, appsExclude: true, epExclude: true}
	require.True(t, r.grants(f))
	require.False(t, (&managedRole{appsExclude: true, epExclude: true}).grants(f), "no Identities")
	require.False(t, (&managedRole{identities: r.identities, epExclude: true}).grants(f), "an empty include list")

	r.applications = []string{"urn:app"}
	require.False(t, r.grants(f), "excluded")
	r.appsExclude = false
	require.True(t, r.grants(f), "included")
	require.False(t, r.grants(&roleFacts{isUser: true, userName: "alice", trusted: true, appURI: "urn:app"}), "not signed")
	r.applications = nil
	r.appsExclude = true

	for _, x := range []*ua.EndpointType{
		{EndpointURL: "opc.tcp://H:4840"},
		{EndpointURL: "opc.tcp://h:4840", SecurityMode: ua.MessageSecurityModeSign},
		{EndpointURL: "opc.tcp://h:4840", SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256},
		{EndpointURL: "opc.tcp://h:4840", TransportProfileURI: "tcp"},
	} {
		require.True(t, endpointMatches(x, ep), "%+v", x)
	}
	for _, x := range []*ua.EndpointType{
		{EndpointURL: "opc.tcp://other:4840"},
		{EndpointURL: "opc.tcp://h:4840", SecurityMode: ua.MessageSecurityModeSignAndEncrypt},
		{EndpointURL: "opc.tcp://h:4840", SecurityPolicyURI: ua.SecurityPolicyURINone},
		{EndpointURL: "opc.tcp://h:4840", TransportProfileURI: "wss"},
	} {
		require.False(t, endpointMatches(x, ep), "%+v", x)
	}
	r.endpoints = []*ua.EndpointType{{EndpointURL: "opc.tcp://h:4840"}}
	require.False(t, r.grants(f), "excluded")
	r.epExclude = false
	require.True(t, r.grants(f), "included")
	require.False(t, r.grants(&roleFacts{isUser: true, userName: "alice"}), "no Endpoint")
}

func TestRoleSetGrantAndReevaluate(t *testing.T) {
	t.Parallel()
	mapped := ua.NewNumericNodeID(1, 99)
	s := newRoleSetTestServer(t, RoleManagement{}, WithRoleMapper(func(ua.IdentityToken) []*ua.NodeID {
		return []*ua.NodeID{mapped, ua.RoleObserver.NodeID(), nil}
	}))
	rs := s.RoleSet()
	sess := s.sb.NewSession()
	idle := s.sb.NewSession() // not activated: no facts
	require.NoError(t, rs.AddIdentity(ua.RoleObserver.NodeID(), userRule("alice")))
	s.grantRoles(nil, sess, &ua.UserNameIdentityToken{UserName: "alice"})
	require.Equal(t, []string{"ns=1;i=99", "i=15668", "i=15644", "i=15656"}, nodeStrings(sess.currentRoles()),
		"the RoleMapper first, each role once; Anonymous has AuthenticatedUser (§4.3)")

	require.NoError(t, rs.AddIdentity(ua.RoleOperator.NodeID(), userRule("alice")))
	require.Equal(t, []string{"ns=1;i=99", "i=15668", "i=15644", "i=15656", "i=15680"},
		nodeStrings(sess.currentRoles()))
	sess.diag.mu.Lock()
	require.Len(t, sess.diag.roles, 5, "the diagnostics follow")
	sess.diag.mu.Unlock()
	require.Nil(t, idle.currentRoles())

	require.NoError(t, rs.RemoveIdentity(ua.RoleOperator.NodeID(), userRule("alice")))
	require.Len(t, sess.currentRoles(), 4)
}

func TestRoleSetAddRemoveRole(t *testing.T) {
	t.Parallel()
	s := newRoleSetTestServer(t, RoleManagement{MaxRoles: 2})
	rs := s.RoleSet()

	for _, name := range []string{"", "a\x00", strings.Repeat("n", maxRoleText+1)} {
		_, err := rs.AddRole(name, "")
		require.ErrorIs(t, err, ua.StatusBadInvalidArgument, "%q", name)
	}
	_, err := rs.AddRole("Engineer", uaNamespaceURI)
	require.ErrorIs(t, err, ua.StatusBadAlreadyExists)
	_, err = rs.AddRole("Custom", uaNamespaceURI)
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
	_, err = rs.AddRole("Custom", "urn:unknown")
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)

	app := NewNodeNameSpace(s, "urn:app")
	nid, err := rs.AddRole("Maintainer", "")
	require.NoError(t, err)
	rolesNS, ok := s.namespaceLookup(RolesNamespaceURI)
	require.True(t, ok)
	require.Equal(t, ua.NewStringNodeID(rolesNS, itoa(int(rolesNS))+":Maintainer"), nid)
	_, err = rs.AddRole("Maintainer", RolesNamespaceURI)
	require.ErrorIs(t, err, ua.StatusBadAlreadyExists)
	nid2, err := rs.AddRole("Maintainer", "urn:app")
	require.NoError(t, err)
	require.Equal(t, ua.NewStringNodeID(rolesNS, itoa(int(app.ID()))+":Maintainer"), nid2)
	_, err = rs.AddRole("Third", "")
	require.ErrorIs(t, err, ua.StatusBadNotSupported, "MaxRoles")

	// The nodes of the role: RoleType, the Properties and the Methods.
	obj := s.Node(nid)
	require.NotNil(t, obj)
	require.Equal(t, "Maintainer", obj.BrowseName().Name)
	require.True(t, ns0(id.RoleType).Equal(nodeTypeDefinition(obj)))
	require.True(t, s.isRoleObject(obj))
	var props, methods []string
	for _, ref := range obj.refsSnapshot() {
		switch {
		case isForwardRef(ref, id.HasProperty):
			props = append(props, s.Node(ref.NodeID.NodeID).BrowseName().Name)
		case isForwardRef(ref, id.HasComponent):
			methods = append(methods, s.Node(ref.NodeID.NodeID).BrowseName().Name)
		}
	}
	require.ElementsMatch(t, []string{"Identities", "Applications", "ApplicationsExclude", "Endpoints", "EndpointsExclude", "CustomConfiguration"}, props)
	require.ElementsMatch(t, []string{"AddIdentity", "RemoveIdentity", "AddApplication", "RemoveApplication", "AddEndpoint", "RemoveEndpoint"}, methods)
	in := s.childNamed(s.childNamed(obj, id.HasComponent, "AddIdentity"), id.HasProperty, "InputArguments")
	require.NotNil(t, in)
	require.Len(t, in.Value().Value.Value(), 1)
	require.NotNil(t, s.childNamed(obj, id.HasProperty, "ApplicationsExclude").ValueWriter())
	require.NotEmpty(t, obj.rolePermissions, "those of Observer")
	found := false
	for _, ref := range s.Node(roleSetNodeID).refsSnapshot() {
		found = found || (isForwardRef(ref, id.HasComponent) && ref.NodeID.NodeID.Equal(nid))
	}
	require.True(t, found, "a component of the RoleSet")
	r, ok := rs.Role(nid)
	require.True(t, ok)
	require.True(t, r.Removable)
	require.True(t, r.ApplicationsExclude)

	// The Methods work on it.
	_, sc := callRole(t, s, roleAdminCtx(s), nid, s.childNamed(obj, id.HasComponent, "AddIdentity").ID(),
		ua.MustVariant(ua.NewExtensionObject(userRule("alice"))))
	require.Equal(t, ua.StatusOK, sc)
	r, _ = rs.Role(nid)
	require.Len(t, r.Identities, 1)

	// RemoveRole.
	require.ErrorIs(t, rs.RemoveRole(ua.RoleObserver.NodeID()), ua.StatusBadRequestNotAllowed)
	require.ErrorIs(t, rs.RemoveRole(ua.NewStringNodeID(rolesNS, "x")), ua.StatusBadNodeIDUnknown)
	other := ua.RoleOperator.NodeID()
	v := app.AddNewVariableStringNode("v", int32(1))
	v.rolePermissions = []*ua.RolePermissionType{{RoleID: nid, Permissions: ua.PermissionTypeRead}, {RoleID: other, Permissions: ua.PermissionTypeRead}, nil}
	w := app.AddNewVariableStringNode("w", int32(1))
	w.rolePermissions = []*ua.RolePermissionType{{RoleID: other, Permissions: ua.PermissionTypeRead}}
	require.NoError(t, s.SetNamespaceDefaults("urn:app", NamespaceDefaults{RolePermissions: []*ua.RolePermissionType{
		{RoleID: nid, Permissions: ua.PermissionTypeRead}, {RoleID: other, Permissions: ua.PermissionTypeBrowse},
	}}))
	sess := s.sb.NewSession()
	s.grantRoles(nil, sess, &ua.UserNameIdentityToken{UserName: "alice"})
	require.Contains(t, sess.currentRoles(), nid)

	require.NoError(t, rs.RemoveRole(nid))
	require.Nil(t, s.Node(nid))
	for _, n := range roleChildIDs(nid) {
		require.Nil(t, s.Node(n))
	}
	require.NotContains(t, sess.currentRoles(), nid, "re-evaluated")
	require.Equal(t, []*ua.RolePermissionType{{RoleID: other, Permissions: ua.PermissionTypeRead}, nil}, v.rolePermissions)
	require.Len(t, w.rolePermissions, 1)
	d, _ := s.NamespaceDefaults("urn:app")
	require.Equal(t, []*ua.RolePermissionType{{RoleID: other, Permissions: ua.PermissionTypeBrowse}}, d.RolePermissions)
	s.mu.Lock()
	for k := range s.methods {
		require.NotContains(t, k, nid.String())
	}
	s.mu.Unlock()
	for _, ref := range s.Node(roleSetNodeID).refsSnapshot() {
		require.False(t, ref.NodeID.NodeID.Equal(nid))
	}
	require.ErrorIs(t, rs.RemoveRole(nid), ua.StatusBadNodeIDUnknown)

	// Room for another role again.
	_, err = rs.AddRole("Third", "")
	require.NoError(t, err)
}

// nodeIDs returns the NodeIds AddRole gave the children of the role nid.
func roleChildIDs(nid *ua.NodeID) []*ua.NodeID {
	var out []*ua.NodeID
	for _, p := range roleProperties {
		out = append(out, ua.NewStringNodeID(nid.Namespace(), nid.StringID()+"/"+p.name))
	}
	for _, m := range roleMethods {
		out = append(out, ua.NewStringNodeID(nid.Namespace(), nid.StringID()+"/"+m.name),
			ua.NewStringNodeID(nid.Namespace(), nid.StringID()+"/"+m.name+"/InputArguments"))
	}
	return out
}

// The roles namespace is found when the application added it first.
func TestRoleSetExistingNamespace(t *testing.T) {
	t.Parallel()
	s := newRoleSetTestServer(t, RoleManagement{})
	ns := NewNodeNameSpace(s, RolesNamespaceURI)
	nid, err := s.RoleSet().AddRole("Maintainer", "")
	require.NoError(t, err)
	require.Equal(t, ns.ID(), nid.Namespace())
	require.Nil(t, s.namespaceAt(999))

	// A namespace of that URI the RoleSet cannot add nodes to.
	b := newRoleSetTestServer(t, RoleManagement{})
	require.Positive(t, b.AddNamespace(blindNameSpace{NewNameSpace(RolesNamespaceURI)}))
	_, err = b.RoleSet().AddRole("Maintainer", "")
	require.ErrorIs(t, err, ua.StatusBadNotSupported)
	require.NoError(t, b.SetNamespaceDefaults(RolesNamespaceURI, NamespaceDefaults{RolePermissions: []*ua.RolePermissionType{
		{RoleID: ua.RoleOperator.NodeID(), Permissions: ua.PermissionTypeBrowse},
	}}))
	b.deleteRolePermissions(ua.RoleObserver.NodeID()) // skips the namespace and its defaults
	d, _ := b.NamespaceDefaults(RolesNamespaceURI)
	require.Len(t, d.RolePermissions, 1)
}

// A role Object with a Property that is none of RoleType: left alone.
func TestRoleSetBindRoleOtherProperty(t *testing.T) {
	t.Parallel()
	s := newRoleSetTestServer(t, RoleManagement{})
	ns := NewNodeNameSpace(s, "urn:other")
	obj := ns.AddNewVariableStringNode("Role", int32(0))
	extra := ns.AddNewVariableStringNode("Extra", int32(1))
	linkChild(obj, extra, id.HasProperty)
	r := &managedRole{id: obj.ID()}
	s.RoleSet().bindRole(r, obj)
	require.Empty(t, r.props)
	require.Equal(t, int32(1), extra.Value().Value.Value())
}

func TestRoleSetAuthorize(t *testing.T) {
	t.Parallel()
	s := newRoleSetTestServer(t, RoleManagement{})
	rs := s.RoleSet()
	enc := ua.MessageSecurityModeSignAndEncrypt
	sid := ua.NewNumericNodeID(1, 1)
	ctx := context.Background()
	require.Equal(t, ua.StatusBadUserAccessDenied, rs.authorize(ctx, nil, "AddRole"))
	require.Equal(t, ua.StatusBadUserAccessDenied, rs.authorize(ctx, &MethodCaller{SecurityMode: enc}, "AddRole"))
	require.Equal(t, ua.StatusBadSecurityModeInsufficient, rs.authorize(ctx, &MethodCaller{SessionID: sid,
		SecurityMode: ua.MessageSecurityModeSign, Roles: []*ua.NodeID{ua.RoleSecurityAdmin.NodeID()}}, "AddRole"))
	require.Equal(t, ua.StatusBadUserAccessDenied, rs.authorize(ctx, &MethodCaller{SessionID: sid, SecurityMode: enc,
		Roles: []*ua.NodeID{ua.RoleConfigureAdmin.NodeID()}}, "AddRole"))
	require.Equal(t, ua.StatusOK, rs.authorize(ctx, &MethodCaller{SessionID: sid, SecurityMode: enc,
		Roles: []*ua.NodeID{ua.RoleSecurityAdmin.NodeID()}}, "AddRole"))
	require.Equal(t, ua.StatusBadUserAccessDenied, rs.authorizeSession(ctx, nil, "ApplicationsExclude"))

	var asked []string
	a := newRoleSetTestServer(t, RoleManagement{Authorizer: func(_ context.Context, c *MethodCaller, method string) ua.StatusCode {
		asked = append(asked, method)
		if c.Identity == nil {
			return ua.StatusBadUserAccessDenied
		}
		return ua.StatusOK
	}})
	c := &MethodCaller{SessionID: sid, SecurityMode: enc}
	require.Equal(t, ua.StatusBadUserAccessDenied, a.RoleSet().authorize(ctx, c, "AddRole"))
	c.Identity = &ua.UserNameIdentityToken{UserName: "admin"}
	require.Equal(t, ua.StatusOK, a.RoleSet().authorize(ctx, c, "RemoveRole"))
	require.Equal(t, []string{"AddRole", "RemoveRole"}, asked)
}

func TestRoleSetHandlers(t *testing.T) {
	t.Parallel()
	s := newRoleSetTestServer(t, RoleManagement{})
	s.SetAuditing(true) // the audit events are made
	ctx := roleAdminCtx(s)
	str := ua.MustVariant
	obs := ua.RoleObserver.NodeID()
	call := func(method uint32, args ...*ua.Variant) ua.StatusCode {
		_, sc := callRole(t, s, ctx, obs, s.childNamed(s.Node(obs), id.HasComponent, methodName(method)).ID(), args...)
		return sc
	}
	rule := ua.MustVariant(ua.NewExtensionObject(userRule("alice")))
	ep := ua.MustVariant(ua.NewExtensionObject(&ua.EndpointType{EndpointURL: "opc.tcp://h:1"}))
	for _, tc := range []struct {
		method uint32
		ok     *ua.Variant
	}{
		{id.RoleTypeAddIdentity, rule},
		{id.RoleTypeRemoveIdentity, rule},
		{id.RoleTypeAddApplication, str("urn:a")},
		{id.RoleTypeRemoveApplication, str("urn:a")},
		{id.RoleTypeAddEndpoint, ep},
		{id.RoleTypeRemoveEndpoint, ep},
	} {
		require.Equal(t, ua.StatusBadArgumentsMissing, call(tc.method), methodName(tc.method))
		require.Equal(t, ua.StatusOK, call(tc.method, tc.ok), methodName(tc.method))
	}
	require.Equal(t, ua.StatusBadNotFound, call(id.RoleTypeRemoveApplication, str("urn:a")))

	// AddRole and RemoveRole.
	out, sc := callRole(t, s, ctx, roleSetNodeID, roleSetAddRoleID, str("Maintainer"), str(""))
	require.Equal(t, ua.StatusOK, sc)
	require.Len(t, out, 1)
	nid := out[0].Value().(*ua.NodeID)
	_, sc = callRole(t, s, ctx, roleSetNodeID, roleSetAddRoleID, str("Maintainer"), str(""))
	require.Equal(t, ua.StatusBadAlreadyExists, sc)
	_, sc = callRole(t, s, ctx, roleSetNodeID, roleSetAddRoleID, str("Maintainer"))
	require.Equal(t, ua.StatusBadArgumentsMissing, sc)
	_, sc = callRole(t, s, ctx, roleSetNodeID, roleSetRemoveRoleID)
	require.Equal(t, ua.StatusBadArgumentsMissing, sc)
	_, sc = callRole(t, s, ctx, roleSetNodeID, roleSetRemoveRoleID, ua.MustVariant(nid))
	require.Equal(t, ua.StatusOK, sc)

	// A caller without the SecurityAdmin role.
	_, sc = callRole(t, s, roleCallerCtx(s, ua.MessageSecurityModeSignAndEncrypt), roleSetNodeID, roleSetAddRoleID, str("X"), str(""))
	require.Equal(t, ua.StatusBadUserAccessDenied, sc)
	_, sc = callRole(t, s, context.Background(), roleSetNodeID, roleSetAddRoleID, str("X"), str(""))
	require.Equal(t, ua.StatusBadUserAccessDenied, sc)
	require.Nil(t, s.RoleSet().roleMethod(&managedRole{id: obs}, "NoMethod"))
}

func methodName(decl uint32) string {
	for _, m := range roleMethods {
		if m.decl == decl {
			return m.name
		}
	}
	return ""
}

func TestRoleSetPropertyWriter(t *testing.T) {
	t.Parallel()
	s := newRoleSetTestServer(t, RoleManagement{})
	rs := s.RoleSet()
	r := rs.findLocked(ua.RoleObserver.NodeID())
	require.Nil(t, rs.propertyWriter(r, propIdentities))
	require.Nil(t, rs.propertyValue(r, "Other"))
	w := rs.propertyWriter(r, propEndpointsExclude)
	ctx := context.Background()
	require.Equal(t, ua.StatusBadUserAccessDenied, w(ctx, &ValueWrite{Value: &ua.DataValue{Value: ua.MustVariant(false)}}))

	sess := s.sb.NewSession()
	sess.setRoles([]*ua.NodeID{ua.RoleSecurityAdmin.NodeID()})
	write := func(v *ua.DataValue) ua.StatusCode { return w(ctx, &ValueWrite{Session: sess.handle(), Value: v}) }
	require.Equal(t, ua.StatusBadSecurityModeInsufficient, write(&ua.DataValue{Value: ua.MustVariant(false)}), "no channel")
	sess.channel.Store(uasc.NewCryptoChannel(&uasc.Config{SecurityMode: ua.MessageSecurityModeSignAndEncrypt,
		SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256}))
	require.Equal(t, ua.StatusBadTypeMismatch, write(nil))
	require.Equal(t, ua.StatusBadTypeMismatch, write(&ua.DataValue{}))
	require.Equal(t, ua.StatusBadTypeMismatch, write(&ua.DataValue{Value: ua.MustVariant(int32(0))}))
	require.Equal(t, ua.StatusOK, write(&ua.DataValue{Value: ua.MustVariant(false)}))
	got, _ := rs.Role(ua.RoleObserver.NodeID())
	require.False(t, got.EndpointsExclude)

	aw := rs.propertyWriter(rs.findLocked(ua.RoleAnonymous.NodeID()), propApplicationsExclude)
	require.Equal(t, ua.StatusBadRequestNotAllowed, aw(ctx, &ValueWrite{Session: sess.handle(), Value: &ua.DataValue{Value: ua.MustVariant(false)}}))
	// The ns0 Property is writable for the writer to decide.
	require.Equal(t, ua.StatusOK, s.Node(ns0(id.WellKnownRoleObserverEndpointsExclude)).AccessStatus(ua.AccessLevelTypeCurrentWrite))
}

func TestRoleSetHelpers(t *testing.T) {
	t.Parallel()
	require.Equal(t, ua.StatusOK, roleStatus(nil))
	require.Equal(t, ua.StatusBadNotFound, roleStatus(ua.StatusBadNotFound))
	require.Equal(t, ua.StatusBadInternalError, roleStatus(errors.New("x")))
	require.Equal(t, []string{}, orEmpty(nil))
	require.False(t, isForwardRef(nil, id.HasComponent))
	require.False(t, isForwardRef(&ua.ReferenceDescription{IsForward: true, ReferenceTypeID: ns0(id.HasComponent)}, id.HasComponent))
	require.False(t, sameRule(nil, userRule("a")))
	require.False(t, sameEndpoint(&ua.EndpointType{}, nil))

	s := newRoleSetTestServer(t, RoleManagement{})
	require.Nil(t, s.childNamed(nil, id.HasProperty, "x"))
	require.Nil(t, s.childNamed(s.Node(ua.RoleObserver.NodeID()), id.HasProperty, "x"))
	require.Equal(t, "", s.childName(ua.NewNumericNodeID(5, 5)))
	n := NewNode(ua.NewNumericNodeID(1, 1), Attributes{}, nil, nil)
	copyAccess(n, nil)
	require.Nil(t, n.rolePermissions)
	require.False(t, s.isRoleObject(s.Node(ns0(id.Server))))
	r := newWellKnownRole(NewNode(ua.NewStringNodeID(2, "r"), Attributes{}, nil, nil))
	require.False(t, r.fixed)
	require.Empty(t, r.identities)
}

func nodeStrings(xs []*ua.NodeID) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = x.String()
	}
	return out
}
