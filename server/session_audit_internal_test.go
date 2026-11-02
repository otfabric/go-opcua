// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // the thumbprint is SHA-1
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// rejectRecorder records the rejections a SessionObserver is told about.
type rejectRecorder struct {
	BaseSessionObserver
	mu  sync.Mutex
	got []Rejection
}

func (r *rejectRecorder) OnRejected(rej Rejection) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, rej)
}

func (r *rejectRecorder) all() []Rejection {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Rejection(nil), r.got...)
}

func TestCertificateAuditType(t *testing.T) {
	t.Parallel()
	for st, want := range map[ua.StatusCode]uint32{
		ua.StatusBadCertificateTimeInvalid:             id.AuditCertificateExpiredEventType,
		ua.StatusBadCertificateIssuerTimeInvalid:       id.AuditCertificateExpiredEventType,
		ua.StatusBadCertificateUntrusted:               id.AuditCertificateUntrustedEventType,
		ua.StatusBadCertificateChainIncomplete:         id.AuditCertificateUntrustedEventType,
		ua.StatusBadCertificateRevoked:                 id.AuditCertificateRevokedEventType,
		ua.StatusBadCertificateIssuerRevoked:           id.AuditCertificateRevokedEventType,
		ua.StatusBadCertificateRevocationUnknown:       id.AuditCertificateRevokedEventType,
		ua.StatusBadCertificateIssuerRevocationUnknown: id.AuditCertificateRevokedEventType,
		ua.StatusBadCertificateUseNotAllowed:           id.AuditCertificateMismatchEventType,
		ua.StatusBadCertificateIssuerUseNotAllowed:     id.AuditCertificateMismatchEventType,
		ua.StatusBadCertificatePolicyCheckFailed:       id.AuditCertificateMismatchEventType,
		ua.StatusBadCertificateURIInvalid:              id.AuditCertificateDataMismatchEventType,
		ua.StatusBadCertificateHostNameInvalid:         id.AuditCertificateDataMismatchEventType,
		ua.StatusBadCertificateInvalid:                 id.AuditCertificateInvalidEventType,
	} {
		got, ok := certificateAuditType(st)
		require.True(t, ok, st.Error())
		require.Equal(t, want, got, st.Error())
	}
	_, ok := certificateAuditType(ua.StatusBadUserAccessDenied)
	require.False(t, ok)
}

func selfSignedCert(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "audit"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return der
}

func TestThumbprint(t *testing.T) {
	t.Parallel()
	require.Empty(t, thumbprint(nil))
	cert := selfSignedCert(t)
	sum := sha1.Sum(cert) //nolint:gosec // see the import
	want := strings.ToUpper(hex.EncodeToString(sum[:]))
	require.Equal(t, want, thumbprint(cert))
	require.Equal(t, want, thumbprint(append(append([]byte(nil), cert...), selfSignedCert(t)...)), "the leaf of a chain")
	require.Len(t, thumbprint([]byte("not a certificate")), 40)
}

func TestWithoutSecrets(t *testing.T) {
	t.Parallel()
	u := &ua.UserNameIdentityToken{UserName: "alice", Password: []byte("pw"), EncryptionAlgorithm: "alg"}
	got := withoutSecrets(u).(*ua.UserNameIdentityToken)
	require.Equal(t, "alice", got.UserName)
	require.Nil(t, got.Password)
	require.Empty(t, got.EncryptionAlgorithm)
	require.Equal(t, []byte("pw"), u.Password, "the token itself is not changed")

	i := &ua.IssuedIdentityToken{PolicyID: "p", TokenData: []byte("jwt")}
	gotI := withoutSecrets(i).(*ua.IssuedIdentityToken)
	require.Nil(t, gotI.TokenData)
	require.Equal(t, "p", gotI.PolicyID)

	x := &ua.X509IdentityToken{CertificateData: []byte{1}}
	require.Same(t, x, withoutSecrets(x))
	require.Nil(t, withoutSecrets(nil))
}

func TestAuditUserID(t *testing.T) {
	t.Parallel()
	require.Equal(t, "alice", auditUserID(&ua.UserNameIdentityToken{UserName: "alice"}))
	require.Equal(t, "CN=audit", auditUserID(&ua.X509IdentityToken{CertificateData: selfSignedCert(t)}))
	require.Equal(t, "X509", auditUserID(&ua.X509IdentityToken{CertificateData: []byte("x")}))
	require.Equal(t, "IssuedToken", auditUserID(&ua.IssuedIdentityToken{}))
	require.Equal(t, "Anonymous", auditUserID(nil))
	require.Empty(t, auditEntryOf(nil))
	require.Equal(t, "e", auditEntryOf(&ua.RequestHeader{AuditEntryID: "e"}))
}

func TestRequestedIdentity(t *testing.T) {
	t.Parallel()
	_, ok := requestedIdentity(&ua.ActivateSessionRequest{}).(*ua.AnonymousIdentityToken)
	require.True(t, ok, "no token is anonymous")
	_, ok = requestedIdentity(&ua.ActivateSessionRequest{UserIdentityToken: ua.NewExtensionObject(&ua.ReadRequest{})}).(*ua.AnonymousIdentityToken)
	require.True(t, ok)
	u := &ua.UserNameIdentityToken{UserName: "u"}
	require.Same(t, u, requestedIdentity(&ua.ActivateSessionRequest{UserIdentityToken: ua.NewExtensionObject(u)}))
}

func TestSessionAuditHelpers_NoChannel(t *testing.T) {
	t.Parallel()
	s := newTestServer()
	require.Empty(t, channelIDString(0))
	require.Equal(t, "7", channelIDString(7))
	require.Empty(t, s.channelIDOf(nil))
	require.Nil(t, remoteAddrOf(nil))
	require.Equal(t, ua.SecurityPolicyURINone, policyOf(nil))
	require.Equal(t, ua.MessageSecurityModeNone, modeOf(nil))
	require.Nil(t, certificateOf(nil, nil))
	require.Equal(t, []byte{1}, certificateOf(nil, &session{remoteCertificate: []byte{1}}))
	require.Equal(t, uint32(0), (&channelBroker{s: nil}).channelID(scNone()))
}

// The audit and rejection paths that the end-to-end tests do not reach: a
// renewal that succeeds is not audited, a failed one and a certificate
// error are; a refused CreateSession and a failed CloseSession are.
func TestSessionAudit_Paths(t *testing.T) {
	t.Parallel()
	s := newTestServer()
	rec := &rejectRecorder{}
	s.cfg.sessionObserver = rec
	s.SetAuditing(true)
	sc := scNone()

	s.channelOpened(sc, 3, &ua.OpenSecureChannelRequest{RequestType: ua.SecurityTokenRequestTypeRenew}, ua.StatusOK)
	s.channelOpened(sc, 3, &ua.OpenSecureChannelRequest{RequestType: ua.SecurityTokenRequestTypeRenew,
		SecurityMode: ua.MessageSecurityModeSign}, ua.StatusBadSecurityModeRejected)
	s.channelClosed(3)
	require.NotNil(t, s.auditCertificate(selfSignedCert(t), ua.StatusBadCertificateURIInvalid, "urn:x"))
	require.Nil(t, s.auditCertificate(nil, ua.StatusBadCertificateUntrusted, ""))
	require.Nil(t, s.auditCertificate([]byte{1}, ua.StatusBadUserAccessDenied, ""))

	s.sessionServiceDone(sc, &ua.CreateSessionRequest{RequestHeader: reqHeader(), SessionName: "refused",
		ClientCertificate: selfSignedCert(t)}, nil, ua.StatusBadCertificateUntrusted)
	s.sessionServiceDone(sc, &ua.CloseSessionRequest{RequestHeader: reqHeader()}, nil, ua.StatusBadSessionIDInvalid)
	s.sessionServiceDone(sc, &ua.CloseSessionRequest{RequestHeader: reqHeader()}, &ua.CloseSessionResponse{ResponseHeader: &ua.ResponseHeader{}}, nil)
	s.sessionServiceDone(sc, &ua.ActivateSessionRequest{RequestHeader: reqHeader(),
		UserIdentityToken: ua.NewExtensionObject(&ua.X509IdentityToken{CertificateData: selfSignedCert(t)})}, nil, ua.StatusBadCertificateRevoked)
	s.sessionServiceDone(sc, &ua.ReadRequest{}, nil, nil)

	got := rec.all()
	require.Len(t, got, 3)
	require.Equal(t, RejectedOpenSecureChannel, got[0].Service)
	require.Equal(t, ua.MessageSecurityModeSign, got[0].SecurityMode, "the mode the client asked for")
	require.Equal(t, RejectedCreateSession, got[1].Service)
	require.Equal(t, "refused", got[1].Session.Name)
	require.Nil(t, got[1].Session.ID)
	require.NotEmpty(t, got[1].ClientCertificate)
	require.Equal(t, RejectedActivateSession, got[2].Service)
	require.Equal(t, ua.UserTokenTypeCertificate, got[2].Session.IdentityType)
	require.Equal(t, "CN=audit", got[2].Session.User)
	require.Nil(t, got[2].Session.ID, "no such session")

	// A session that was never created (its CreateSession failed) has no
	// end to audit.
	s.auditSessionEnd(s.sb.NewSession(), SessionClosedByClient)
}

// The session keeps the user name token without its password; the role
// mapper gets it with the password.
func TestSessionService_ActivateSession_NoPasswordKept(t *testing.T) {
	srv := newTestServer()
	srv.cfg.usernameValidator = func(user, pass string) error { return nil }
	var mapped ua.IdentityToken
	srv.cfg.roleMapper = func(tok ua.IdentityToken) []*ua.NodeID {
		mapped = tok
		return DefaultRoleMapper(tok)
	}
	offerTokens(srv, ua.SecurityPolicyURINone, ua.MessageSecurityModeNone, ua.UserTokenTypeUserName)
	svc := &SessionService{srv: srv}
	sc := scNone()
	ctx := context.Background()
	resp, err := svc.CreateSession(ctx, sc, &ua.CreateSessionRequest{
		RequestHeader: reqHeader(), EndpointURL: "opc.tcp://localhost:4840", RequestedSessionTimeout: 5000, ClientNonce: []byte("n"),
	}, 1)
	require.NoError(t, err)
	token := resp.(*ua.CreateSessionResponse).AuthenticationToken
	_, err = svc.ActivateSession(ctx, sc, &ua.ActivateSessionRequest{
		RequestHeader:     &ua.RequestHeader{RequestHandle: 2, AuthenticationToken: token},
		ClientSignature:   &ua.SignatureData{},
		UserIdentityToken: ua.NewExtensionObject(&ua.UserNameIdentityToken{UserName: "alice", Password: []byte("secret")}),
	}, 2)
	require.NoError(t, err)

	require.Equal(t, []byte("secret"), mapped.(*ua.UserNameIdentityToken).Password)
	kept, ok := srv.sb.Session(token).handle().Identity().(*ua.UserNameIdentityToken)
	require.True(t, ok)
	require.Equal(t, "alice", kept.UserName)
	require.Nil(t, kept.Password)
}
