// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/ua"
)

// batchStore is a CertificateBatchStore and CertificateLoadStore in
// memory: it records every StoreChanges and returns load from
// LoadCertificates.
type batchStore struct {
	mu      sync.Mutex
	fail    error
	changes []CertificateChanges
	single  int // calls of the methods of CertificateStore

	load    CertificateChanges
	loadErr error
}

var (
	_ CertificateBatchStore = (*batchStore)(nil)
	_ CertificateLoadStore  = (*batchStore)(nil)
)

func (b *batchStore) StoreTrustList(context.Context, *ua.TrustListDataType) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.single++
	return nil
}

func (b *batchStore) StoreCertificate(context.Context, *ua.NodeID, []byte, [][]byte, crypto.Signer) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.single++
	return nil
}

func (b *batchStore) StoreChanges(_ context.Context, c CertificateChanges) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fail != nil {
		return b.fail
	}
	b.changes = append(b.changes, c)
	return nil
}

func (b *batchStore) LoadCertificates(context.Context) (CertificateChanges, error) {
	return b.load, b.loadErr
}

func (b *batchStore) setFail(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.fail = err
}

func (b *batchStore) stored() []CertificateChanges {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]CertificateChanges(nil), b.changes...)
}

// TestPushBatchStore: one ApplyChanges of several groups, a new
// certificate and a deletion is one StoreChanges, with the group names and
// the LastUpdateTime the trust lists take; the methods of CertificateStore
// are not called.
func TestPushBatchStore(t *testing.T) {
	p := pushPKI(t)
	p256 := p.ECC.Server[testpki.CurveP256]
	st := &batchStore{}
	s, _ := newCustomServer(t, PushManagement{Store: st}, ApplicationIdentity(p256.Cert, p256.Key))
	ctx, _ := adminCtx(s)

	_, sc := tlCall(t, s, ctx, mAdd, p.CACert, true)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = pushCall(t, s, ctx, userTL, id.ServerConfigurationCertificateGroupsDefaultUserTokenGroupTrustListAddCertificate, p.UserCert, true)
	require.Equal(t, ua.StatusOK, sc)
	tls, sc := selfSigned(t, s, ctx, httpsGroup, nullNode, "CN=tls", nil, nil, 1, 0)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = pushCall(t, s, ctx, scObj, mDelete, defaultGroup, p256Type)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusOK, sc)

	require.Zero(t, st.single)
	got := st.stored()
	require.Len(t, got, 1)
	c := got[0]
	require.False(t, c.Reset)
	require.Len(t, c.TrustLists, 2)
	require.Equal(t, "DefaultApplicationGroup", c.TrustLists[0].Group)
	require.Equal(t, [][]byte{p.ClientCert, p.CACert}, c.TrustLists[0].TrustList.TrustedCertificates)
	require.Equal(t, "DefaultUserTokenGroup", c.TrustLists[1].Group)
	require.Equal(t, s.push.groups[groupApplication].lastUpdate.Load(), c.TrustLists[0].LastUpdateTime.UnixNano())
	require.Len(t, c.Certificates, 2)
	require.Equal(t, "DefaultApplicationGroup", c.Certificates[0].Group)
	require.True(t, c.Certificates[0].CertificateType.Equal(p256Type))
	require.True(t, c.Certificates[0].Deleted())
	require.Equal(t, "DefaultHttpsGroup", c.Certificates[1].Group)
	require.Equal(t, tls, c.Certificates[1].Certificate)
	require.NotNil(t, c.Certificates[1].PrivateKey)
	require.False(t, c.Certificates[1].Deleted())

	// A group of the application by its name.
	gid := s.CertificateGroupID("Outgoing")
	der, sc := selfSigned(t, s, ctx, gid, p256Type, "CN=out", nil, nil, 1, 0)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusOK, sc)
	got = st.stored()
	require.Len(t, got, 2)
	require.Equal(t, []CertificateGroupChange{{Group: "Outgoing", CertificateType: p256Type, Certificate: der,
		PrivateKey: got[1].Certificates[0].PrivateKey}}, got[1].Certificates)
	require.Empty(t, got[1].TrustLists)

	// ResetToServerDefaults is one StoreChanges marked Reset, with the
	// trust lists of every group.
	_, sc = pushCall(t, s, ctx, scObj, mReset)
	require.Equal(t, ua.StatusOK, sc)
	got = st.stored()
	require.Len(t, got, 3)
	require.True(t, got[2].Reset)
	require.Len(t, got[2].TrustLists, len(s.push.groups))
	require.Zero(t, st.single)
}

// TestPushBatchStoreFailure: a StoreChanges that fails applies nothing,
// discards the transaction (Part 12 §7.10.2) and records an error for every
// trust list and group of it; ResetToServerDefaults that cannot be stored
// changes nothing.
func TestPushBatchStoreFailure(t *testing.T) {
	p := pushPKI(t)
	st := &batchStore{}
	s := newPushServer(t, PushManagement{Store: st})
	ctx, _ := adminCtx(s)
	tls0 := s.HTTPSCertificate()

	st.setFail(errors.New("disk full"))
	_, sc := tlCall(t, s, ctx, mAdd, p.CACert, true)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = selfSigned(t, s, ctx, httpsGroup, nullNode, "CN=tls", nil, nil, 1, 0)
	require.Equal(t, ua.StatusOK, sc)
	before := s.push.groups[groupApplication].lastUpdate.Load()
	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusBadInternalError, sc)
	require.Nil(t, s.push.tx)
	require.Equal(t, [][]byte{p.ClientCert}, s.TrustList().TrustedCertificates)
	require.Equal(t, tls0, s.HTTPSCertificate())
	require.Equal(t, before, s.push.groups[groupApplication].lastUpdate.Load())
	d := s.push.diagnostics()
	require.Equal(t, ua.StatusBadInternalError, d.result)
	require.Len(t, d.errs, 2)
	require.True(t, d.errs[0].TargetID.Equal(ua.NewNumericNodeID(0, tlObj)))
	require.True(t, d.errs[1].TargetID.Equal(httpsGroup))
	// Nothing is left to apply.
	st.setFail(nil)
	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusBadNothingToDo, sc)
	require.Empty(t, st.stored())

	// ApplyImmediately: the change that cannot be stored is not made.
	s2 := newPushServer(t, PushManagement{Store: st, ApplyImmediately: true})
	ctx2, _ := adminCtx(s2)
	st.setFail(errors.New("disk full"))
	_, sc = pushCall(t, s2, ctx2, tlObj, mAdd, p.CACert, true)
	require.Equal(t, ua.StatusBadInternalError, sc)
	require.Nil(t, s2.push.tx)
	require.Equal(t, [][]byte{p.ClientCert}, s2.TrustList().TrustedCertificates)

	// ResetToServerDefaults keeps the pending transaction and changes
	// nothing when the store fails.
	st.setFail(nil)
	_, sc = pushCall(t, s, ctx, tlObj, mAdd, p.CACert, true)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = pushCall(t, s, ctx, tlObj, mRemove, gdsThumb(p.CACert), true)
	require.Equal(t, ua.StatusOK, sc)
	st.setFail(errors.New("disk full"))
	_, sc = pushCall(t, s, ctx, scObj, mReset)
	require.Equal(t, ua.StatusBadInternalError, sc)
	require.NotNil(t, s.push.tx)
	require.Equal(t, [][]byte{p.ClientCert, p.CACert}, s.TrustList().TrustedCertificates)
}

// restoreServer returns a server whose store restores c.
func restoreServer(t *testing.T, c CertificateChanges, opts ...Option) (*Server, error) {
	t.Helper()
	p := pushPKI(t)
	tlsc := customGroupPKI(t)
	pm := PushManagement{
		Store:     &batchStore{load: c},
		TrustList: &ua.TrustListDataType{TrustedCertificates: [][]byte{p.ClientCert}},
		CertificateGroups: []CertificateGroup{{
			Name:             "Outgoing",
			CertificateTypes: []*ua.NodeID{tlsClientType, p256Type},
			Certificates:     []GroupCertificate{{CertificateType: tlsClientType, Certificate: tlsc.Cert, PrivateKey: tlsc.Key}},
		}},
	}
	return New(append([]Option{InsecureNoSecurity(), EndPoint("localhost", 0), Certificate(p.ServerCert), PrivateKey(p.ServerKey),
		WithPushManagement(pm)}, opts...)...)
}

// TestPushRestore: New applies what a CertificateLoadStore restores on top
// of the configuration, and ResetToServerDefaults still goes back to the
// configuration.
func TestPushRestore(t *testing.T) {
	p := pushPKI(t)
	p256 := p.ECC.Server[testpki.CurveP256]
	p384 := p.ECC.Server[testpki.CurveP384]
	rsa2 := reissue(t, p.ServerCert, p.ServerKey, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	tls2, err := testpki.NewIdentity(testpki.CurveP256, "tls", testpki.ServerAppURI, nil, nil)
	require.NoError(t, err)
	out2 := customGroupPKI(t)
	when := time.Date(2026, 11, 1, 2, 3, 4, 0, time.UTC)

	c := CertificateChanges{
		TrustLists: []CertificateGroupTrustList{
			{Group: "DefaultApplicationGroup", TrustList: &ua.TrustListDataType{TrustedCertificates: [][]byte{p.CACert}}, LastUpdateTime: when},
			{Group: "DefaultUserTokenGroup", TrustList: &ua.TrustListDataType{TrustedCertificates: [][]byte{p.UserCert}}},
			{Group: "Gone", TrustList: &ua.TrustListDataType{}},
		},
		Certificates: []CertificateGroupChange{
			// Replaces the RSA certificate of the configuration.
			{Group: "DefaultApplicationGroup", CertificateType: rsaType, Certificate: rsa2, PrivateKey: p.ServerKey},
			// Adds a P-384 certificate, removes the P-256 one.
			{Group: "DefaultApplicationGroup", CertificateType: ua.NewNumericNodeID(0, id.EccNistP384ApplicationCertificateType), Certificate: p384.Cert, PrivateKey: p384.Key},
			{Group: "DefaultApplicationGroup", CertificateType: p256Type},
			{Group: "DefaultHttpsGroup", CertificateType: httpsType, Certificate: tls2.Cert, Issuers: [][]byte{p.CACert}, PrivateKey: tls2.Key},
			{Group: "Outgoing", CertificateType: tlsClientType},
			{Group: "Outgoing", CertificateType: p256Type, Certificate: out2.Cert, PrivateKey: out2.Key},
			// Ignored: a group or a type the server does not have.
			{Group: "Gone", CertificateType: rsaType},
			{Group: "DefaultUserTokenGroup", CertificateType: rsaType},
			{Group: "DefaultApplicationGroup", CertificateType: httpsType},
			{Group: "DefaultApplicationGroup", CertificateType: ua.NewStringNodeID(1, "x")},
			{Group: "DefaultApplicationGroup"},
			{Group: "DefaultHttpsGroup", CertificateType: rsaType},
			{Group: "Outgoing", CertificateType: userCertType},
		},
	}
	s, err := restoreServer(t, c, ApplicationIdentity(p256.Cert, p256.Key))
	require.NoError(t, err)
	s.initEndpoints()

	require.Equal(t, [][]byte{p.CACert}, s.TrustList().TrustedCertificates)
	require.Equal(t, when.UnixNano(), s.push.groups[groupApplication].lastUpdate.Load())
	require.Equal(t, [][]byte{p.UserCert}, s.GroupTrustList(userGroup).TrustedCertificates)
	require.NotEqual(t, when.UnixNano(), s.push.groups[groupUserToken].lastUpdate.Load())
	primary, _ := s.cfg.primaryIdentity()
	require.Equal(t, rsa2, primary)
	require.Equal(t, [][]byte{rsa2, p384.Cert}, identityCertsOf(s))
	require.Contains(t, s.push.appTypes, uint32(id.EccNistP384ApplicationCertificateType))
	require.Equal(t, tls2.Cert, s.HTTPSCertificate())
	require.Equal(t, [][]byte{p.CACert}, s.push.https.Load().issuers)
	out := s.push.groups[numDefaultGroups].custom
	_, ok := out.get(id.TLSClientCertificateType)
	require.False(t, ok)
	x, ok := out.get(id.EccNistP256ApplicationCertificateType)
	require.True(t, ok)
	require.Equal(t, out2.Cert, x.cert)
	// The trust list of the restored DefaultApplicationGroup validates the
	// clients.
	require.NoError(t, s.push.validateClient(p.IssuedCert))
	require.Error(t, s.push.validateClient(p.ClientCert))

	// ResetToServerDefaults: the configuration again.
	ctx, _ := pushCallerCtx(s, ua.MessageSecurityModeSignAndEncrypt, ua.RoleSecurityAdmin.NodeID())
	_, sc := pushCall(t, s, ctx, scObj, mReset)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, [][]byte{p.ClientCert}, s.TrustList().TrustedCertificates)
	primary, _ = s.cfg.primaryIdentity()
	require.Equal(t, p.ServerCert, primary)
	require.Equal(t, [][]byte{p.ServerCert, p256.Cert}, identityCertsOf(s))

	// A certificate that the restore adds to an empty https slot, and an
	// HTTPS deletion.
	s2, err := restoreServer(t, CertificateChanges{Certificates: []CertificateGroupChange{
		{Group: "DefaultHttpsGroup", CertificateType: httpsType},
		{Group: "Outgoing", CertificateType: p256Type, Certificate: out2.Cert, PrivateKey: out2.Key},
	}})
	require.NoError(t, err)
	require.Nil(t, s2.HTTPSCertificate())
}

// identityCertsOf returns the application instance certificates of s.
func identityCertsOf(s *Server) [][]byte {
	var out [][]byte
	for _, x := range s.cfg.identityCerts() {
		out = append(out, x.certificate)
	}
	return out
}

// TestPushRestoreErrors: New fails on a store that does not load, and on
// a stored trust list or certificate that is not valid.
func TestPushRestoreErrors(t *testing.T) {
	p := pushPKI(t)
	p256 := p.ECC.Server[testpki.CurveP256]
	for name, c := range map[string]CertificateChanges{
		"trust list": {TrustLists: []CertificateGroupTrustList{{Group: "DefaultApplicationGroup",
			TrustList: &ua.TrustListDataType{TrustedCertificates: [][]byte{{1, 2, 3}}}}}},
		"certificate": {Certificates: []CertificateGroupChange{{Group: "DefaultApplicationGroup", CertificateType: rsaType,
			Certificate: []byte{1, 2, 3}, PrivateKey: p.ServerKey}}},
		"type": {Certificates: []CertificateGroupChange{{Group: "DefaultApplicationGroup", CertificateType: rsaType,
			Certificate: p256.Cert, PrivateKey: p256.Key}}},
		"key": {Certificates: []CertificateGroupChange{{Group: "DefaultApplicationGroup", CertificateType: rsaType,
			Certificate: p.ServerCert, PrivateKey: p.ClientKey}}},
		"no key": {Certificates: []CertificateGroupChange{{Group: "DefaultHttpsGroup", CertificateType: httpsType,
			Certificate: p.ServerCert}}},
		"rsa signer": {Certificates: []CertificateGroupChange{{Group: "DefaultApplicationGroup", CertificateType: rsaType,
			Certificate: p.ServerCert, PrivateKey: rsaSigner{p.ServerKey}}}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := restoreServer(t, c)
			require.ErrorContains(t, err, "push management: the stored")
		})
	}
	_, err := New(EndPoint("localhost", 0), Certificate(p.ServerCert), PrivateKey(p.ServerKey), InsecureNoSecurity(),
		WithPushManagement(PushManagement{Store: &batchStore{loadErr: errors.New("corrupt")}}))
	require.ErrorContains(t, err, "load the certificate store: corrupt")
}
