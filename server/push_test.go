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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

func pushPKI(t *testing.T) *testpki.PKI {
	t.Helper()
	p, err := testpki.Get()
	require.NoError(t, err)
	return p
}

// newPushServer returns a server (not started) with push management and the
// RSA server certificate of the PKI, whose trust list holds its client
// certificate.
func newPushServer(t *testing.T, pm PushManagement, opts ...Option) *Server {
	t.Helper()
	p := pushPKI(t)
	if pm.TrustList == nil {
		pm.TrustList = &ua.TrustListDataType{TrustedCertificates: [][]byte{p.ClientCert}}
	}
	all := append([]Option{
		EndPoint("localhost", 0),
		Certificate(p.ServerCert),
		PrivateKey(p.ServerKey),
		WithPushManagement(pm),
	}, opts...)
	s, err := New(append([]Option{InsecureNoSecurity()}, all...)...)
	require.NoError(t, err)
	s.initEndpoints()
	return s
}

// pushCallerCtx returns the context of a call by a new session of s with the
// security mode and roles.
func pushCallerCtx(s *Server, mode ua.MessageSecurityMode, roles ...*ua.NodeID) (context.Context, *session) {
	sess := s.sb.NewSession()
	c := &MethodCaller{SessionID: sess.ID, SecurityMode: mode, Roles: roles}
	return context.WithValue(context.Background(), methodCallerKey{}, c), sess
}

func adminCtx(s *Server) (context.Context, *session) {
	return pushCallerCtx(s, ua.MessageSecurityModeSignAndEncrypt, ua.RoleSecurityAdmin.NodeID())
}

func pushCall(t *testing.T, s *Server, ctx context.Context, obj, method uint32, args ...any) ([]*ua.Variant, ua.StatusCode) {
	t.Helper()
	s.mu.Lock()
	h := s.methods[methodKey(ua.NewNumericNodeID(0, obj), ua.NewNumericNodeID(0, method))]
	s.mu.Unlock()
	require.NotNil(t, h, "method %d of %d not registered", method, obj)
	vs := make([]*ua.Variant, len(args))
	for i, a := range args {
		if v, ok := a.(*ua.Variant); ok {
			vs[i] = v
			continue
		}
		vs[i] = ua.MustVariant(a)
	}
	return h(ctx, ua.NewNumericNodeID(0, obj), ua.NewNumericNodeID(0, method), vs)
}

const (
	tlObj = id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustList
	scObj = id.ServerConfiguration
)

func tlCall(t *testing.T, s *Server, ctx context.Context, method uint32, args ...any) ([]*ua.Variant, ua.StatusCode) {
	t.Helper()
	return pushCall(t, s, ctx, tlObj, method, args...)
}

const (
	mOpen      = id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListOpen
	mOpenMasks = id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListOpenWithMasks
	mClose     = id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListClose
	mRead      = id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListRead
	mWrite     = id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListWrite
	mGetPos    = id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListGetPosition
	mSetPos    = id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListSetPosition
	mCloseUpd  = id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListCloseAndUpdate
	mAdd       = id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListAddCertificate
	mRemove    = id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListRemoveCertificate
	mUpdate    = id.ServerConfigurationUpdateCertificate
	mCSR       = id.ServerConfigurationCreateSigningRequest
	mRejected  = id.ServerConfigurationGetRejectedList
	mApply     = id.ServerConfigurationApplyChanges
	mCancel    = id.ServerConfigurationCancelChanges
)

var (
	defaultGroup = ua.NewNumericNodeID(0, id.ServerConfigurationCertificateGroupsDefaultApplicationGroup)
	rsaType      = ua.NewNumericNodeID(0, id.RsaSha256ApplicationCertificateType)
)

// writeTrustList writes content to a new write handle and calls
// CloseAndUpdate.
func writeTrustList(t *testing.T, s *Server, ctx context.Context, content []byte) ([]*ua.Variant, ua.StatusCode) {
	t.Helper()
	out, sc := tlCall(t, s, ctx, mOpen, byte(0x06))
	require.Equal(t, ua.StatusOK, sc)
	h := out[0].Value().(uint32)
	_, sc = tlCall(t, s, ctx, mWrite, h, content)
	require.Equal(t, ua.StatusOK, sc)
	return tlCall(t, s, ctx, mCloseUpd, h)
}

func encodeTL(t *testing.T, d *ua.TrustListDataType) []byte {
	t.Helper()
	b, err := ua.Encode(d)
	require.NoError(t, err)
	return b
}

func TestPushOptionErrors(t *testing.T) {
	p := pushPKI(t)
	_, err := New(InsecureNoSecurity(), WithPushManagement(PushManagement{TrustList: &ua.TrustListDataType{TrustedCertificates: [][]byte{{1, 2, 3}}}}))
	require.ErrorContains(t, err, "invalid trust list")
	_, err = New(InsecureNoSecurity(), WithClientCertificateTrustList(p.CACert), WithPushManagement(PushManagement{}))
	require.ErrorContains(t, err, "WithClientCertificateTrustList")

	// Without push management there is nothing to report.
	s := newTestServer()
	require.Nil(t, s.TrustList())
	require.Nil(t, s.RejectedCertificates())
}

func TestPushAuthorize(t *testing.T) {
	s := newPushServer(t, PushManagement{})
	ctx := context.Background()
	_, sc := tlCall(t, s, ctx, mOpen, byte(1))
	require.Equal(t, ua.StatusBadUserAccessDenied, sc)

	sign, _ := pushCallerCtx(s, ua.MessageSecurityModeSign, ua.RoleSecurityAdmin.NodeID())
	_, sc = tlCall(t, s, sign, mOpen, byte(1))
	require.Equal(t, ua.StatusBadSecurityModeInsufficient, sc)

	user, _ := pushCallerCtx(s, ua.MessageSecurityModeSignAndEncrypt, ua.RoleAuthenticatedUser.NodeID())
	_, sc = pushCall(t, s, user, scObj, mApply)
	require.Equal(t, ua.StatusBadUserAccessDenied, sc)

	var mu sync.Mutex
	var seen []string
	s2 := newPushServer(t, PushManagement{Authorizer: func(_ context.Context, c *MethodCaller, method string) ua.StatusCode {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, method)
		if method == "ApplyChanges" {
			return ua.StatusOK
		}
		return ua.StatusBadUserAccessDenied
	}})
	user2, _ := pushCallerCtx(s2, ua.MessageSecurityModeSignAndEncrypt)
	_, sc = pushCall(t, s2, user2, scObj, mApply)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = pushCall(t, s2, user2, scObj, mRejected)
	require.Equal(t, ua.StatusBadUserAccessDenied, sc)
	require.Equal(t, []string{"ApplyChanges", "GetRejectedList"}, seen)
}

func TestPushFileHandles(t *testing.T) {
	p := pushPKI(t)
	s := newPushServer(t, PushManagement{})
	ctx, _ := adminCtx(s)
	other, _ := adminCtx(s)

	_, sc := tlCall(t, s, ctx, mOpen, "x")
	require.Equal(t, ua.StatusBadTypeMismatch, sc)
	_, sc = tlCall(t, s, ctx, mOpen, byte(0x02))
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	_, sc = tlCall(t, s, ctx, mOpenMasks, "x")
	require.Equal(t, ua.StatusBadTypeMismatch, sc)

	out, sc := tlCall(t, s, ctx, mOpen, byte(0x01))
	require.Equal(t, ua.StatusOK, sc)
	h := out[0].Value().(uint32)
	require.EqualValues(t, 1, s.push.groups[groupApplication].openCount.Load())

	// Another session cannot use the handle.
	_, sc = tlCall(t, s, other, mRead, h, int32(10))
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	_, sc = tlCall(t, s, ctx, mRead, "h", int32(10))
	require.Equal(t, ua.StatusBadTypeMismatch, sc)
	_, sc = tlCall(t, s, ctx, mRead, h, "n")
	require.Equal(t, ua.StatusBadTypeMismatch, sc)
	_, sc = tlCall(t, s, ctx, mRead, h, int32(-1))
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	_, sc = tlCall(t, s, ctx, mWrite, h, []byte{1})
	require.Equal(t, ua.StatusBadInvalidState, sc)
	_, sc = tlCall(t, s, ctx, mCloseUpd, h)
	require.Equal(t, ua.StatusBadInvalidState, sc)

	// Read in two parts, with positions.
	out, sc = tlCall(t, s, ctx, mRead, h, int32(5))
	require.Equal(t, ua.StatusOK, sc)
	first := out[0].Value().([]byte)
	require.Len(t, first, 5)
	out, sc = tlCall(t, s, ctx, mGetPos, h)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, uint64(5), out[0].Value())
	_, sc = tlCall(t, s, ctx, mSetPos, h, "p")
	require.Equal(t, ua.StatusBadTypeMismatch, sc)
	_, sc = tlCall(t, s, ctx, mSetPos, h, uint64(0))
	require.Equal(t, ua.StatusOK, sc)
	out, sc = tlCall(t, s, ctx, mRead, h, int32(1<<20))
	require.Equal(t, ua.StatusOK, sc)
	d, sc := decodeTrustList(out[0].Value().([]byte))
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, [][]byte{p.ClientCert}, d.TrustedCertificates)
	_, sc = tlCall(t, s, ctx, mSetPos, h, uint64(1<<40))
	require.Equal(t, ua.StatusOK, sc)
	_, sc = tlCall(t, s, other, mGetPos, h)
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	_, sc = tlCall(t, s, other, mSetPos, h, uint64(0))
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	_, sc = tlCall(t, s, other, mWrite, h, []byte{1})
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	_, sc = tlCall(t, s, other, mCloseUpd, h)
	require.Equal(t, ua.StatusBadInvalidArgument, sc)

	// Reading is shared, writing is exclusive; Add and Remove wait.
	out2, sc := tlCall(t, s, other, mOpenMasks, uint32(ua.TrustListMasksTrustedCertificates))
	require.Equal(t, ua.StatusOK, sc)
	_, sc = tlCall(t, s, other, mOpen, byte(0x06))
	require.Equal(t, ua.StatusBadNotWritable, sc)
	_, sc = tlCall(t, s, ctx, mAdd, p.StrangerCert, true)
	require.Equal(t, ua.StatusBadInvalidState, sc)
	_, sc = tlCall(t, s, ctx, mRemove, "00", true)
	require.Equal(t, ua.StatusBadInvalidState, sc)
	_, sc = tlCall(t, s, other, mClose, out2[0].Value().(uint32))
	require.Equal(t, ua.StatusOK, sc)
	_, sc = tlCall(t, s, other, mClose, h)
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	_, sc = tlCall(t, s, ctx, mClose, h)
	require.Equal(t, ua.StatusOK, sc)

	out, sc = tlCall(t, s, ctx, mOpen, byte(0x06))
	require.Equal(t, ua.StatusOK, sc)
	w := out[0].Value().(uint32)
	_, sc = tlCall(t, s, other, mOpen, byte(0x01))
	require.Equal(t, ua.StatusBadNotReadable, sc)
	_, sc = tlCall(t, s, ctx, mRead, w, int32(1))
	require.Equal(t, ua.StatusBadInvalidState, sc)
	_, sc = tlCall(t, s, ctx, mWrite, w, int32(3))
	require.Equal(t, ua.StatusBadTypeMismatch, sc)
	_, sc = tlCall(t, s, ctx, mWrite, w, make([]byte, defaultMaxTrustListSize+1))
	require.Equal(t, ua.StatusBadEncodingLimitsExceeded, sc)
	_, sc = tlCall(t, s, ctx, mWrite, w, ua.MustVariant([]byte(nil)))
	require.Equal(t, ua.StatusOK, sc)
	_, sc = tlCall(t, s, ctx, mClose, w)
	require.Equal(t, ua.StatusOK, sc)
	require.EqualValues(t, 0, s.push.groups[groupApplication].openCount.Load())
}

func TestPushFileHandleLimitAndPrune(t *testing.T) {
	s := newPushServer(t, PushManagement{})
	ctx, sess := adminCtx(s)
	for range maxTrustListHandles {
		_, sc := tlCall(t, s, ctx, mOpen, byte(0x01))
		require.Equal(t, ua.StatusOK, sc)
	}
	_, sc := tlCall(t, s, ctx, mOpen, byte(0x01))
	require.Equal(t, ua.StatusBadTooManyOperations, sc)

	// The handles of a closed session are dropped.
	require.NoError(t, s.sb.Close(sess.AuthTokenID))
	ctx2, _ := adminCtx(s)
	_, sc = tlCall(t, s, ctx2, mOpen, byte(0x06))
	require.Equal(t, ua.StatusOK, sc)
	require.EqualValues(t, 1, s.push.groups[groupApplication].openCount.Load())
}

func TestPushCloseAndUpdate(t *testing.T) {
	p := pushPKI(t)
	limit := len(encodeTL(t, &ua.TrustListDataType{TrustedCertificates: [][]byte{p.ClientCert}, IssuerCertificates: [][]byte{p.CACert}})) + 64
	s := newPushServer(t, PushManagement{MaxTrustListSize: uint32(limit)})
	ctx, _ := adminCtx(s)

	_, sc := writeTrustList(t, s, ctx, []byte{1, 2})
	require.Equal(t, ua.StatusBadDecodingError, sc)
	_, sc = writeTrustList(t, s, ctx, encodeTL(t, &ua.TrustListDataType{SpecifiedLists: 0x10}))
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	_, sc = writeTrustList(t, s, ctx, encodeTL(t, &ua.TrustListDataType{SpecifiedLists: 1, TrustedCertificates: [][]byte{{0x30, 0}}}))
	require.Equal(t, ua.StatusBadCertificateInvalid, sc)
	_, sc = writeTrustList(t, s, ctx, encodeTL(t, &ua.TrustListDataType{SpecifiedLists: 4, IssuerCertificates: [][]byte{{0x30, 0}}}))
	require.Equal(t, ua.StatusBadCertificateInvalid, sc)
	_, sc = writeTrustList(t, s, ctx, encodeTL(t, &ua.TrustListDataType{SpecifiedLists: 2, TrustedCrls: [][]byte{{0x30, 0}}}))
	require.Equal(t, ua.StatusBadCertificateInvalid, sc)
	// What is written fits, the trust list it makes does not.
	_, sc = writeTrustList(t, s, ctx, encodeTL(t, &ua.TrustListDataType{SpecifiedLists: 4, IssuerCertificates: [][]byte{p.CACert, p.StrangerCert}}))
	require.Equal(t, ua.StatusBadEncodingLimitsExceeded, sc)
	_, sc = tlCall(t, s, ctx, mCloseUpd, "h")
	require.Equal(t, ua.StatusBadTypeMismatch, sc)

	// The issuer list is replaced, the trusted list kept.
	out, sc := writeTrustList(t, s, ctx, encodeTL(t, &ua.TrustListDataType{SpecifiedLists: uint32(ua.TrustListMasksIssuerCertificates), IssuerCertificates: [][]byte{p.CACert, p.CACert}}))
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, true, out[0].Value())
	require.Empty(t, s.TrustList().IssuerCertificates)
	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusOK, sc)
	tl := s.TrustList()
	require.Equal(t, [][]byte{p.ClientCert}, tl.TrustedCertificates)
	require.Equal(t, [][]byte{p.CACert}, tl.IssuerCertificates) // deduplicated
	// Nothing pending.
	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = pushCall(t, s, ctx, scObj, mCancel)
	require.Equal(t, ua.StatusOK, sc)
}

func TestPushAddRemove(t *testing.T) {
	p := pushPKI(t)
	s := newPushServer(t, PushManagement{ApplyImmediately: true})
	ctx, _ := adminCtx(s)

	_, sc := tlCall(t, s, ctx, mAdd, "x", true)
	require.Equal(t, ua.StatusBadTypeMismatch, sc)
	_, sc = tlCall(t, s, ctx, mAdd, []byte{0x30, 0}, true)
	require.Equal(t, ua.StatusBadCertificateInvalid, sc)
	_, sc = tlCall(t, s, ctx, mRemove, int32(1), true)
	require.Equal(t, ua.StatusBadTypeMismatch, sc)

	ca, err := x509.ParseCertificate(p.CACert)
	require.NoError(t, err)
	crl := testCRL(t, ca, p.CAKey)
	tl, sc := newTrustList(&ua.TrustListDataType{IssuerCertificates: [][]byte{p.CACert}, IssuerCrls: [][]byte{crl}}, 0)
	require.Equal(t, ua.StatusOK, sc)
	s.push.groups[groupApplication].trust.Store(tl)

	_, sc = tlCall(t, s, ctx, mAdd, p.StrangerCert, true)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, [][]byte{p.StrangerCert}, s.TrustList().TrustedCertificates)

	// Removing the CA removes its CRL; the thumbprint is not case sensitive.
	thumb := hex.EncodeToString(uapolicy.Thumbprint(p.CACert))
	_, sc = tlCall(t, s, ctx, mRemove, thumb, true)
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	_, sc = tlCall(t, s, ctx, mRemove, " "+toUpper(thumb)+" ", false)
	require.Equal(t, ua.StatusOK, sc)
	got := s.TrustList()
	require.Empty(t, got.IssuerCertificates)
	require.Empty(t, got.IssuerCrls)

	// Changes beyond the size limit are refused.
	s2 := newPushServer(t, PushManagement{MaxTrustListSize: uint32(len(encodeTL(t, &ua.TrustListDataType{TrustedCertificates: [][]byte{p.ClientCert}})) + 10)})
	ctx2, _ := adminCtx(s2)
	_, sc = tlCall(t, s2, ctx2, mAdd, p.StrangerCert, true)
	require.Equal(t, ua.StatusBadEncodingLimitsExceeded, sc)
}

func toUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}

func testCRL(t *testing.T, ca *x509.Certificate, key crypto.Signer, serials ...*big.Int) []byte {
	t.Helper()
	var entries []x509.RevocationListEntry
	for _, s := range serials {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: s, RevocationTime: time.Now()})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: time.Now().Add(-time.Hour), NextUpdate: time.Now().Add(time.Hour),
		RevokedCertificateEntries: entries,
	}, ca, key)
	require.NoError(t, err)
	return der
}

func TestPushTransactions(t *testing.T) {
	p := pushPKI(t)
	s := newPushServer(t, PushManagement{})
	a, sessA := adminCtx(s)
	b, _ := adminCtx(s)

	_, sc := tlCall(t, s, a, mAdd, p.StrangerCert, true)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = tlCall(t, s, b, mAdd, p.CACert, true)
	require.Equal(t, ua.StatusBadTransactionPending, sc)
	_, sc = pushCall(t, s, b, scObj, mCancel)
	require.Equal(t, ua.StatusBadTransactionPending, sc)
	// The session sees its own pending trust list.
	_, sc = tlCall(t, s, a, mAdd, p.CACert, false)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, [][]byte{p.ClientCert}, s.TrustList().TrustedCertificates)

	// The transaction of a closed session is dropped.
	require.NoError(t, s.sb.Close(sessA.AuthTokenID))
	_, sc = pushCall(t, s, b, scObj, mApply)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, [][]byte{p.ClientCert}, s.TrustList().TrustedCertificates)
	require.Empty(t, s.TrustList().IssuerCertificates)
}

type recordingStore struct {
	mu    sync.Mutex
	fail  error
	tls   []*ua.TrustListDataType
	certs [][]byte
	types []*ua.NodeID
}

func (r *recordingStore) StoreTrustList(_ context.Context, tl *ua.TrustListDataType) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail != nil {
		return r.fail
	}
	r.tls = append(r.tls, tl)
	return nil
}

func (r *recordingStore) StoreCertificate(_ context.Context, typ *ua.NodeID, cert []byte, _ [][]byte, _ crypto.Signer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail != nil {
		return r.fail
	}
	r.certs = append(r.certs, cert)
	r.types = append(r.types, typ)
	return nil
}

func TestPushStore(t *testing.T) {
	p := pushPKI(t)
	st := &recordingStore{fail: errors.New("disk full")}
	s := newPushServer(t, PushManagement{Store: st})
	ctx, _ := adminCtx(s)

	_, sc := tlCall(t, s, ctx, mAdd, p.StrangerCert, true)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusBadInternalError, sc)
	require.Equal(t, [][]byte{p.ClientCert}, s.TrustList().TrustedCertificates)

	st.mu.Lock()
	st.fail = nil
	st.mu.Unlock()
	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusOK, sc)
	require.Len(t, st.tls, 1)
	require.Equal(t, [][]byte{p.ClientCert, p.StrangerCert}, st.tls[0].TrustedCertificates)

	// A certificate that fails to be stored stays pending.
	cert := reissue(t, p.ServerCert, p.ServerKey, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	_, sc = pushCall(t, s, ctx, scObj, mUpdate, defaultGroup, rsaType, cert, [][]byte{}, "", []byte{})
	require.Equal(t, ua.StatusOK, sc)
	st.mu.Lock()
	st.fail = errors.New("disk full")
	st.mu.Unlock()
	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusBadInternalError, sc)
	st.mu.Lock()
	st.fail = nil
	st.mu.Unlock()
	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, [][]byte{cert}, st.certs)
	require.True(t, st.types[0].Equal(rsaType))
	c, _ := s.cfg.primaryIdentity()
	require.Equal(t, cert, c)
}

// reissue returns a self-signed certificate for the key of cert with
// another validity.
func reissue(t *testing.T, cert []byte, key crypto.Signer, from, to time.Time) []byte {
	t.Helper()
	c, err := uapolicy.ParseCertificate(cert)
	require.NoError(t, err)
	tmpl := *c
	tmpl.SerialNumber = big.NewInt(time.Now().UnixNano())
	tmpl.NotBefore, tmpl.NotAfter = from, to
	der, err := uapolicy.CreateCertificate(rand.Reader, &tmpl, &tmpl, key.Public(), key)
	require.NoError(t, err)
	return der
}

func TestPushUpdateCertificateErrors(t *testing.T) {
	p := pushPKI(t)
	s := newPushServer(t, PushManagement{})
	ctx, _ := adminCtx(s)
	update := func(args ...any) ua.StatusCode {
		t.Helper()
		_, sc := pushCall(t, s, ctx, scObj, mUpdate, args...)
		return sc
	}
	good := reissue(t, p.ServerCert, p.ServerKey, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	p256 := ua.NewNumericNodeID(0, id.EccNistP256ApplicationCertificateType)

	require.Equal(t, ua.StatusBadTypeMismatch, update("g", rsaType, good, [][]byte{}, "", []byte{}))
	require.Equal(t, ua.StatusBadInvalidArgument, update(rsaType, rsaType, good, [][]byte{}, "", []byte{}))
	require.Equal(t, ua.StatusBadInvalidArgument, update(defaultGroup, ua.NewStringNodeID(1, "x"), good, [][]byte{}, "", []byte{}))
	require.Equal(t, ua.StatusBadInvalidArgument, update(defaultGroup, p256, good, [][]byte{}, "", []byte{}))
	require.Equal(t, ua.StatusBadTypeMismatch, update(defaultGroup, rsaType, "c", [][]byte{}, "", []byte{}))
	require.Equal(t, ua.StatusBadTypeMismatch, update(defaultGroup, rsaType, good, "i", "", []byte{}))
	require.Equal(t, ua.StatusBadTypeMismatch, update(defaultGroup, rsaType, good, [][]byte{}, "", "k"))
	require.Equal(t, ua.StatusBadCertificateInvalid, update(defaultGroup, rsaType, []byte{0x30, 0}, [][]byte{}, "", []byte{}))
	ecc := p.ECC.Server[testpki.CurveP256]
	require.Equal(t, ua.StatusBadCertificateInvalid, update(defaultGroup, rsaType, ecc.Cert, [][]byte{}, "", []byte{}))
	expired := reissue(t, p.ServerCert, p.ServerKey, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	require.Equal(t, ua.StatusBadCertificateTimeInvalid, update(defaultGroup, rsaType, expired, [][]byte{}, "", []byte{}))
	require.Equal(t, ua.StatusBadCertificateInvalid, update(defaultGroup, rsaType, good, [][]byte{{0x30, 0}}, "", []byte{}))
	require.Equal(t, ua.StatusBadInvalidArgument, update(defaultGroup, rsaType, good, [][]byte{}, "", []byte{1}))
	require.Equal(t, ua.StatusBadSecurityChecksFailed, update(defaultGroup, rsaType, good, [][]byte{}, "PFX", []byte{1}))
	require.Equal(t, ua.StatusBadNotSupported, update(defaultGroup, rsaType, good, [][]byte{}, "DER", []byte{1}))
	require.Equal(t, ua.StatusBadSecurityChecksFailed, update(defaultGroup, rsaType, good, [][]byte{}, "PEM", []byte("junk")))
	other := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(p.ClientKey)})
	require.Equal(t, ua.StatusBadSecurityChecksFailed, update(defaultGroup, rsaType, good, [][]byte{}, "pem", other))

	// A CA-issued certificate with the wrong issuer.
	ca, err := x509.ParseCertificate(p.CACert)
	require.NoError(t, err)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "s"}, URIs: ca.URIs}, p.ServerKey)
	require.NoError(t, err)
	issued, err := testpki.IssueFromCSR(csr, ca, p.CAKey)
	require.NoError(t, err)
	_ = issued // no ApplicationUri: refused before the issuers are looked at
	require.Equal(t, ua.StatusBadCertificateURIInvalid, update(defaultGroup, rsaType, issued, [][]byte{p.CACert}, "", []byte{}))
	sc := reqURI(t, p)
	issued, err = testpki.IssueFromCSR(sc, ca, p.CAKey)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadSecurityChecksFailed, update(defaultGroup, rsaType, issued, [][]byte{p.StrangerCert}, "", []byte{}))
	require.Equal(t, ua.StatusOK, update(defaultGroup, rsaType, issued, [][]byte{p.CACert}, "", []byte{}))
	// A null group and type pick the default group and the first certificate.
	require.Equal(t, ua.StatusOK, update(ua.NewTwoByteNodeID(0), ua.NewTwoByteNodeID(0), good, [][]byte{}, "", []byte{}))
	require.Equal(t, ua.StatusOK, update(defaultGroup, ua.NewNumericNodeID(0, id.RsaMinApplicationCertificateType), good, ua.MustVariant([][]byte(nil)), "", ua.MustVariant([]byte(nil))))
}

// reqURI returns a CSR for the server key with the server's ApplicationUri.
func reqURI(t *testing.T, p *testpki.PKI) []byte {
	t.Helper()
	srv, err := x509.ParseCertificate(p.ServerCert)
	require.NoError(t, err)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "s"}, URIs: srv.URIs}, p.ServerKey)
	require.NoError(t, err)
	return csr
}

func TestPushCreateSigningRequest(t *testing.T) {
	p := pushPKI(t)
	s := newPushServer(t, PushManagement{})
	ctx, _ := adminCtx(s)
	csr := func(args ...any) ([]byte, ua.StatusCode) {
		t.Helper()
		out, sc := pushCall(t, s, ctx, scObj, mCSR, args...)
		if sc != ua.StatusOK {
			return nil, sc
		}
		return out[0].Value().([]byte), sc
	}
	nonce := make([]byte, 32)

	_, sc := csr(defaultGroup, rsaType, int32(1), false, nonce)
	require.Equal(t, ua.StatusBadTypeMismatch, sc)
	_, sc = csr(defaultGroup, rsaType, "", false, "n")
	require.Equal(t, ua.StatusBadTypeMismatch, sc)
	_, sc = csr(defaultGroup, ua.NewNumericNodeID(0, id.EccApplicationCertificateType), "", false, nonce)
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	_, sc = csr(defaultGroup, rsaType, "CN", false, nonce)
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	_, sc = csr(defaultGroup, rsaType, "", true, nonce[:31])
	require.Equal(t, ua.StatusBadInvalidArgument, sc)

	// The existing key, the subject of the certificate.
	b, sc := csr(defaultGroup, rsaType, "", false, ua.MustVariant([]byte(nil)))
	require.Equal(t, ua.StatusOK, sc)
	req, err := x509.ParseCertificateRequest(b)
	require.NoError(t, err)
	require.Equal(t, "conformance server", req.Subject.CommonName)
	require.True(t, req.PublicKey.(*rsa.PublicKey).Equal(&p.ServerKey.PublicKey))
	require.Equal(t, testpki.ServerAppURI, req.URIs[0].String())
}

func TestPushECCIdentities(t *testing.T) {
	p := pushPKI(t)
	p256, ed := p.ECC.Server[testpki.CurveP256], p.ECC.Server[testpki.CurveEd25519]
	bp := p.ECC.Server[testpki.CurveBrainpoolP256r1]
	s := newPushServer(t, PushManagement{},
		ApplicationIdentity(p256.Cert, p256.Key), ApplicationIdentity(ed.Cert, ed.Key), ApplicationIdentity(bp.Cert, bp.Key))
	ctx, _ := adminCtx(s)
	nonce := make([]byte, 32)

	require.Equal(t, []*ua.NodeID{
		rsaType,
		ua.NewNumericNodeID(0, id.EccNistP256ApplicationCertificateType),
		ua.NewNumericNodeID(0, id.EccCurve25519ApplicationCertificateType),
		ua.NewNumericNodeID(0, id.EccBrainpoolP256r1ApplicationCertificateType),
	}, s.cfg.certificateTypes())

	for _, tc := range []struct {
		typ  uint32
		want ua.StatusCode
	}{
		{id.EccNistP256ApplicationCertificateType, ua.StatusOK},
		{id.EccApplicationCertificateType, ua.StatusOK},
		{id.EccCurve25519ApplicationCertificateType, ua.StatusOK},
		{id.EccBrainpoolP256r1ApplicationCertificateType, ua.StatusOK},
	} {
		out, sc := pushCall(t, s, ctx, scObj, mCSR, defaultGroup, ua.NewNumericNodeID(0, tc.typ), "CN=ecc,O=otfabric", true, nonce)
		require.Equal(t, tc.want, sc, "type %d", tc.typ)
		if sc != ua.StatusOK {
			continue
		}
		req, err := uapolicy.ParseCertificateRequest(out[0].Value().([]byte))
		require.NoError(t, err)
		require.NoError(t, uapolicy.CheckCertificateRequestSignature(req))
		require.Equal(t, "ecc", req.Subject.CommonName)
	}

	// The P-256 certificate issued for the new key replaces the old one.
	out, sc := pushCall(t, s, ctx, scObj, mCSR, defaultGroup, ua.NewNumericNodeID(0, id.EccNistP256ApplicationCertificateType), "", true, nonce)
	require.Equal(t, ua.StatusOK, sc)
	ca, err := testpki.NewCA(testpki.CurveP256, "ecc ca")
	require.NoError(t, err)
	cert, err := testpki.IssueFromCSR(out[0].Value().([]byte), ca.X509, ca.Key)
	require.NoError(t, err)
	_, sc = pushCall(t, s, ctx, scObj, mUpdate, defaultGroup, ua.NewNumericNodeID(0, id.EccNistP256ApplicationCertificateType), cert, [][]byte{ca.Cert}, "", []byte{})
	require.Equal(t, ua.StatusOK, sc)
	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusOK, sc)
	got, key, ok := s.cfg.identityFor(ua.SecurityPolicyURIECCNistP256)
	require.True(t, ok)
	require.Equal(t, cert, got)
	require.True(t, uapolicy.KeyMatchesCertificate(key, cert))
}

func TestPushHelpers(t *testing.T) {
	for _, tc := range []struct {
		want, have uint32
		ok         bool
	}{
		{0, id.EccNistP256ApplicationCertificateType, true},
		{id.ApplicationCertificateType, id.RsaSha256ApplicationCertificateType, true},
		{id.RsaMinApplicationCertificateType, id.RsaSha256ApplicationCertificateType, true},
		{id.RsaSha256ApplicationCertificateType, id.EccNistP256ApplicationCertificateType, false},
		{id.EccApplicationCertificateType, id.EccCurve448ApplicationCertificateType, true},
		{id.EccApplicationCertificateType, id.RsaSha256ApplicationCertificateType, false},
		{id.EccNistP384ApplicationCertificateType, id.EccNistP256ApplicationCertificateType, false},
	} {
		require.Equal(t, tc.ok, typeMatches(tc.want, tc.have), "%d/%d", tc.want, tc.have)
	}

	_, ok := certTypeOf([]byte{1})
	require.False(t, ok)
	p := pushPKI(t)
	for curve, want := range map[string]uint32{
		testpki.CurveP256:            id.EccNistP256ApplicationCertificateType,
		testpki.CurveP384:            id.EccNistP384ApplicationCertificateType,
		testpki.CurveEd25519:         id.EccCurve25519ApplicationCertificateType,
		testpki.CurveEd448:           id.EccCurve448ApplicationCertificateType,
		testpki.CurveBrainpoolP256r1: id.EccBrainpoolP256r1ApplicationCertificateType,
		testpki.CurveBrainpoolP384r1: id.EccBrainpoolP384r1ApplicationCertificateType,
	} {
		got, ok := certTypeOf(p.ECC.Server[curve].Cert)
		require.True(t, ok)
		require.Equal(t, want, got, curve)
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	tmpl := testpki.CertTemplate("small", "")
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &small.PublicKey, small)
	require.NoError(t, err)
	got, ok := certTypeOf(der)
	require.True(t, ok)
	require.Equal(t, uint32(id.RsaMinApplicationCertificateType), got)

	n, err := parseSubjectName(`/CN=App/O=Company/OU=Unit/L=Town/ST=State/C=NL/STREET=Main 1/DC=example`)
	require.NoError(t, err)
	require.Equal(t, "App", n.CommonName)
	require.Equal(t, []string{"Company"}, n.Organization)
	require.Equal(t, []string{"Unit"}, n.OrganizationalUnit)
	require.Equal(t, []string{"Town"}, n.Locality)
	require.Equal(t, []string{"State"}, n.Province)
	require.Equal(t, []string{"NL"}, n.Country)
	require.Equal(t, []string{"Main 1"}, n.StreetAddress)
	require.Len(t, n.ExtraNames, 1)
	n, err = parseSubjectName(`CN="Quoted", S=Prov`)
	require.NoError(t, err)
	require.Equal(t, "Quoted", n.CommonName)
	require.Equal(t, []string{"Prov"}, n.Province)
	for _, bad := range []string{"CN=", "X=1", "=1", "CN"} {
		_, err := parseSubjectName(bad)
		require.Error(t, err, bad)
	}

	for _, k := range []crypto.Signer{
		mustECDSA(t, elliptic.P384()),
		func() crypto.Signer { _, k, _ := ed25519.GenerateKey(rand.Reader); return k }(),
	} {
		nk, err := generateKey(id.HTTPSCertificateType, k, 0)
		require.NoError(t, err)
		require.IsType(t, k, nk)
	}

	require.True(t, isNullNodeID(nil))
	require.True(t, isNullNodeID(ua.NewNumericNodeID(0, 0)))
	require.False(t, isNullNodeID(ua.NewStringNodeID(0, "")))
	require.Nil(t, crlIssuer([]byte{1}))
}

func mustECDSA(t *testing.T, c elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	require.NoError(t, err)
	return k
}

func TestPushValidateClient(t *testing.T) {
	p := pushPKI(t)
	ca, err := x509.ParseCertificate(p.CACert)
	require.NoError(t, err)

	// An intermediate CA, issued by the CA, that issues a leaf.
	interKey := mustECDSA(t, elliptic.P256())
	interTmpl := testpki.CertTemplate("intermediate", "")
	interTmpl.IsCA = true
	interTmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, ca, &interKey.PublicKey, p.CAKey)
	require.NoError(t, err)
	inter, err := x509.ParseCertificate(interDER)
	require.NoError(t, err)
	leafKey := mustECDSA(t, elliptic.P256())
	leafDER, err := x509.CreateCertificate(rand.Reader, testpki.CertTemplate("leaf", testpki.ClientAppURI), inter, &leafKey.PublicKey, interKey)
	require.NoError(t, err)

	m := newPushManager(&PushManagement{MaxTrustListSize: defaultMaxTrustListSize, MaxRejectedCertificates: 2,
		TrustList: &ua.TrustListDataType{TrustedCertificates: [][]byte{p.CACert}}}, &serverConfig{})
	require.NoError(t, m.validateClient(nil))
	require.Equal(t, ua.StatusBadCertificateInvalid, m.validateClient([]byte{1, 2}))
	// The leaf needs its intermediate: presented in the chain, or in the
	// issuer list.
	require.Equal(t, ua.StatusBadCertificateUntrusted, m.validateClient(leafDER))
	require.NoError(t, m.validateClient(append(append([]byte{}, leafDER...), interDER...)))
	tl, sc := newTrustList(&ua.TrustListDataType{TrustedCertificates: [][]byte{p.CACert}, IssuerCertificates: [][]byte{interDER}}, 0)
	require.Equal(t, ua.StatusOK, sc)
	m.groups[groupApplication].trust.Store(tl)
	require.NoError(t, m.validateClient(leafDER))

	// The CA revokes the intermediate.
	tl, sc = newTrustList(&ua.TrustListDataType{TrustedCertificates: [][]byte{p.CACert}, IssuerCertificates: [][]byte{interDER},
		TrustedCrls: [][]byte{testCRL(t, ca, p.CAKey, inter.SerialNumber)}}, 0)
	require.Equal(t, ua.StatusOK, sc)
	m.groups[groupApplication].trust.Store(tl)
	require.Equal(t, ua.StatusBadCertificateIssuerRevoked, m.validateClient(leafDER))

	// A CRL whose issuer is not in the lists is not used.
	other, err := testpki.NewCA(testpki.CurveP256, "other")
	require.NoError(t, err)
	tl, sc = newTrustList(&ua.TrustListDataType{TrustedCertificates: [][]byte{p.CACert}, IssuerCertificates: [][]byte{interDER},
		IssuerCrls: [][]byte{testCRL(t, other.X509, other.Key, inter.SerialNumber)}}, 0)
	require.Equal(t, ua.StatusOK, sc)
	m.groups[groupApplication].trust.Store(tl)
	require.NoError(t, m.validateClient(leafDER))

	// The rejected list holds the latest MaxRejectedCertificates.
	m.reject([]byte{1})
	m.reject([]byte{2})
	m.reject([]byte{1})
	require.Equal(t, [][]byte{{2}, {1}}, m.rejectedList())

	many := make([][]byte, maxTrustListEntries+1)
	for i := range many {
		many[i] = []byte{byte(i), byte(i >> 8)}
	}
	_, sc = newTrustList(&ua.TrustListDataType{TrustedCertificates: many}, 0)
	require.Equal(t, ua.StatusBadEncodingLimitsExceeded, sc)
}

func TestPushModel(t *testing.T) {
	s := newPushServer(t, PushManagement{})
	value := func(nid uint32) any {
		t.Helper()
		n := s.Node(ua.NewNumericNodeID(0, nid))
		require.NotNil(t, n)
		dv := n.Value()
		require.NotNil(t, dv)
		return dv.Value.Value()
	}
	require.Equal(t, []string{"PEM", "PFX"}, value(id.ServerConfigurationSupportedPrivateKeyFormats))
	require.Equal(t, []string{"NA"}, value(id.ServerConfigurationServerCapabilities))
	require.Equal(t, uint32(defaultMaxTrustListSize), value(id.ServerConfigurationMaxTrustListSize))
	require.Equal(t, false, value(id.ServerConfigurationMulticastDNSEnabled))
	require.Equal(t, testpki.ServerAppURI, value(id.ServerConfigurationApplicationURI))
	require.NotEmpty(t, value(id.ServerConfigurationProductURI))
	require.Equal(t, int32(ua.ApplicationTypeServer), value(id.ServerConfigurationApplicationType))
	require.Equal(t, uint64(s.push.groups[groupApplication].trust.Load().size), value(id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListSize))
	require.Equal(t, uint16(0), value(id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListOpenCount))
	require.IsType(t, time.Time{}, value(id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListLastUpdateTime))
	require.Equal(t, []*ua.NodeID{rsaType}, value(id.ServerConfigurationCertificateGroupsDefaultApplicationGroupCertificateTypes))

	g := s.Node(ua.NewNumericNodeID(0, id.ServerConfigurationCertificateGroups))
	var groups []uint32
	for _, r := range g.refsSnapshot() {
		if r.IsForward && r.ReferenceTypeID.IntID() == id.HasComponent {
			groups = append(groups, r.NodeID.NodeID.IntID())
		}
	}
	require.Subset(t, groups, []uint32{id.ServerConfigurationCertificateGroupsDefaultApplicationGroup,
		id.ServerConfigurationCertificateGroupsDefaultHTTPSGroup, id.ServerConfigurationCertificateGroupsDefaultUserTokenGroup})

	// Rejected list over the method.
	ctx, _ := adminCtx(s)
	out, sc := pushCall(t, s, ctx, scObj, mRejected)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, [][]byte{}, out[0].Value())
}
