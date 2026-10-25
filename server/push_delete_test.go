// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/ua"
)

const mDelete = id.ServerConfigurationDeleteCertificate

var p256Type = ua.NewNumericNodeID(0, id.EccNistP256ApplicationCertificateType)

// deleteStore is a CertificateDeleteStore that records the deletions.
type deleteStore struct {
	groupStore
	dmu     sync.Mutex
	deleted []string
	derr    error
}

func (d *deleteStore) DeleteGroupCertificate(_ context.Context, group, typ *ua.NodeID) error {
	d.dmu.Lock()
	defer d.dmu.Unlock()
	if d.derr != nil {
		return d.derr
	}
	d.deleted = append(d.deleted, group.String()+" "+typ.String())
	return nil
}

func (d *deleteStore) deletions() []string {
	d.dmu.Lock()
	defer d.dmu.Unlock()
	return append([]string(nil), d.deleted...)
}

func getCerts(t *testing.T, s *Server, ctx context.Context, group *ua.NodeID) ([]*ua.NodeID, [][]byte) {
	t.Helper()
	out, sc := pushCall(t, s, ctx, scObj, mGetCerts, group)
	require.Equal(t, ua.StatusOK, sc)
	return out[0].Value().([]*ua.NodeID), out[1].Value().([][]byte)
}

// TestPushDeleteCertificate: DeleteCertificate removes a certificate when
// the changes are applied, and a deleted type can be filled again.
func TestPushDeleteCertificate(t *testing.T) {
	p := pushPKI(t)
	p256 := p.ECC.Server[testpki.CurveP256]
	st := &deleteStore{}
	s := newPushServer(t, PushManagement{Store: st},
		ApplicationIdentity(p256.Cert, p256.Key),
		EnableSecurity(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt))
	ctx, _ := adminCtx(s)

	// The method has its instance node with the arguments of the type and
	// no output arguments.
	require.NotNil(t, s.Node(ua.NewNumericNodeID(0, mDelete)))
	var names []string
	for _, a := range declaredInputArguments(s, ua.NewNumericNodeID(0, mDelete)) {
		names = append(names, a.Name)
	}
	require.Equal(t, []string{"CertificateGroupId", "CertificateTypeId"}, names)

	out, sc := pushCall(t, s, ctx, scObj, mDelete, defaultGroup, p256Type)
	require.Equal(t, ua.StatusOK, sc)
	require.Empty(t, out)
	// The deletion is pending: the certificate is in use until ApplyChanges,
	// and a second deletion finds the type empty.
	_, certs := getCerts(t, s, ctx, defaultGroup)
	require.Contains(t, certs, p256.Cert)
	_, sc = pushCall(t, s, ctx, scObj, mDelete, defaultGroup, p256Type)
	require.Equal(t, ua.StatusBadInvalidState, sc)
	d := s.push.diagnostics()
	require.Contains(t, d.groups, defaultGroup)

	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusOK, sc)
	_, ok := func() ([]byte, bool) { c, _, ok := s.cfg.identityFor(ua.SecurityPolicyURIECCNistP256); return c, ok }()
	require.False(t, ok)
	types, certs := getCerts(t, s, ctx, defaultGroup)
	require.NotContains(t, certs, p256.Cert)
	require.Len(t, types, 1)
	require.Equal(t, []string{defaultGroup.String() + " " + p256Type.String()}, st.deletions())
	// The type stays one of the group, empty.
	require.Contains(t, s.push.groupTypes(s.push.groups[groupApplication]), p256Type)
	_, sc = pushCall(t, s, ctx, scObj, mDelete, defaultGroup, p256Type)
	require.Equal(t, ua.StatusBadInvalidState, sc)
	// A signing request for the empty type needs a subject and a new key.
	_, sc = pushCall(t, s, ctx, scObj, mCSR, defaultGroup, p256Type, "", true, make([]byte, 32))
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	_, sc = selfSigned(t, s, ctx, defaultGroup, p256Type, "", nil, nil, 1, 0)
	require.Equal(t, ua.StatusBadInvalidArgument, sc)

	// CreateSelfSignedCertificate fills it again.
	der, sc := selfSigned(t, s, ctx, defaultGroup, p256Type, "CN=again/O=otfabric", nil, nil, 1, 0)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusOK, sc)
	cert, _, ok := s.cfg.identityFor(ua.SecurityPolicyURIECCNistP256)
	require.True(t, ok)
	require.Equal(t, der, cert)

	// Delete and create in one transaction replace the certificate.
	_, sc = pushCall(t, s, ctx, scObj, mDelete, defaultGroup, p256Type)
	require.Equal(t, ua.StatusOK, sc)
	der2, sc := selfSigned(t, s, ctx, defaultGroup, p256Type, "", nil, nil, 1, 0)
	require.Equal(t, ua.StatusOK, sc)
	// Created after the deletion, the type has a certificate again.
	_, sc = pushCall(t, s, ctx, scObj, mDelete, defaultGroup, p256Type)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = pushCall(t, s, ctx, scObj, mDelete, defaultGroup, p256Type)
	require.Equal(t, ua.StatusBadInvalidState, sc)
	_, sc = selfSigned(t, s, ctx, defaultGroup, p256Type, "", nil, nil, 1, 0)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusOK, sc)
	cert, _, _ = s.cfg.identityFor(ua.SecurityPolicyURIECCNistP256)
	require.NotEqual(t, der, cert)
	require.NotEqual(t, der2, cert)
	_, certs = getCerts(t, s, ctx, defaultGroup)
	require.Len(t, certs, 2)

	// The certificate the channels start with, which the endpoints
	// advertise, is not deleted: ApplyChanges fails and the transaction
	// stays pending.
	_, sc = pushCall(t, s, ctx, scObj, mDelete, defaultGroup, rsaType)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusBadInvalidState, sc)
	d = s.push.diagnostics()
	require.Equal(t, ua.StatusBadInvalidState, d.result)
	require.Len(t, d.errs, 1)
	require.True(t, d.errs[0].TargetID.Equal(defaultGroup))
	require.NotNil(t, s.push.tx)
	_, sc = pushCall(t, s, ctx, scObj, mCancel)
	require.Equal(t, ua.StatusOK, sc)
	cert, _, _ = s.cfg.identityFor(ua.SecurityPolicyURIBasic256Sha256)
	require.Equal(t, p.ServerCert, cert)

	// The DefaultUserTokenGroup has no certificates; arguments are checked.
	_, sc = pushCall(t, s, ctx, scObj, mDelete, userGroup, nullNode)
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	_, sc = pushCall(t, s, ctx, scObj, mDelete, defaultGroup, "x")
	require.Equal(t, ua.StatusBadTypeMismatch, sc)
	_, sc = pushCall(t, s, ctx, scObj, mDelete, defaultGroup, ua.NewStringNodeID(1, "x"))
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	// SecurityAdmin only.
	user, _ := pushCallerCtx(s, ua.MessageSecurityModeSignAndEncrypt)
	_, sc = pushCall(t, s, user, scObj, mDelete, defaultGroup, p256Type)
	require.Equal(t, ua.StatusBadUserAccessDenied, sc)

	// A failing store keeps the deletion pending.
	st.dmu.Lock()
	st.derr = errors.New("disk full")
	st.dmu.Unlock()
	_, sc = pushCall(t, s, ctx, scObj, mDelete, defaultGroup, p256Type)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusBadInternalError, sc)
	_, ok = func() ([]byte, bool) { c, _, ok := s.cfg.identityFor(ua.SecurityPolicyURIECCNistP256); return c, ok }()
	require.True(t, ok)
}

// TestPushDeleteCertificateEndpoints: a certificate an endpoint advertises
// is not deleted, nor the TLS certificate of opc.https endpoints.
func TestPushDeleteCertificateEndpoints(t *testing.T) {
	p := pushPKI(t)
	p256 := p.ECC.Server[testpki.CurveP256]
	s := newPushServer(t, PushManagement{ApplyImmediately: true},
		ApplicationIdentity(p256.Cert, p256.Key),
		EnableSecurity(ua.SecurityPolicyURIECCNistP256, ua.MessageSecurityModeSignAndEncrypt),
		HTTPSEndPoint("localhost", 0))
	ctx, _ := adminCtx(s)
	// ApplyImmediately: the refused deletion does not stay pending.
	_, sc := pushCall(t, s, ctx, scObj, mDelete, defaultGroup, p256Type)
	require.Equal(t, ua.StatusBadInvalidState, sc)
	require.Nil(t, s.push.tx)
	require.Equal(t, ua.StatusBadInvalidState, s.push.diagnostics().result)
	_, sc = pushCall(t, s, ctx, scObj, mDelete, httpsGroup, httpsType)
	require.Equal(t, ua.StatusBadInvalidState, sc)
	require.Equal(t, p.ServerCert, s.HTTPSCertificate())

	// Without opc.https and opc.wss endpoints the TLS certificate goes.
	s2 := newPushServer(t, PushManagement{ApplyImmediately: true})
	ctx2, _ := adminCtx(s2)
	_, sc = pushCall(t, s2, ctx2, scObj, mDelete, httpsGroup, nullNode)
	require.Equal(t, ua.StatusOK, sc)
	require.Nil(t, s2.HTTPSCertificate())
	types, _ := getCerts(t, s2, ctx2, httpsGroup)
	require.Empty(t, types)
	_, sc = pushCall(t, s2, ctx2, scObj, mDelete, httpsGroup, nullNode)
	require.Equal(t, ua.StatusBadInvalidState, sc)
	// ResetToServerDefaults brings it back.
	_, sc = pushCall(t, s2, ctx2, scObj, mReset)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, p.ServerCert, s2.HTTPSCertificate())
}

// TestPushResetDeletesCertificates: ResetToServerDefaults deletes the TLS
// certificate a server without one at the start was given.
func TestPushResetDeletesCertificates(t *testing.T) {
	st := &deleteStore{}
	s := newPushServer(t, PushManagement{Store: st})
	s.push.initial.https = nil
	s.push.https.Store(nil)
	ctx, _ := adminCtx(s)
	_, sc := selfSigned(t, s, ctx, httpsGroup, nullNode, "CN=tls", nil, nil, 1, 0)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusOK, sc)
	require.NotNil(t, s.HTTPSCertificate())
	_, sc = pushCall(t, s, ctx, scObj, mReset)
	require.Equal(t, ua.StatusOK, sc)
	require.Nil(t, s.HTTPSCertificate())
	require.Equal(t, []string{httpsGroup.String() + " " + httpsType.String()}, st.deletions())
}
