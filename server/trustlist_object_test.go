// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"encoding/hex"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

// tlStore is the trust list behind a TrustListObject under test.
type tlStore struct {
	mu   sync.Mutex
	tl   *ua.TrustListDataType
	fail ua.StatusCode
}

func (s *tlStore) load() *ua.TrustListDataType {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneTrustListData(s.tl)
}

func (s *tlStore) update(_ context.Context, _ *MethodCaller, tl *ua.TrustListDataType) ua.StatusCode {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != ua.StatusOK {
		return s.fail
	}
	s.tl = tl
	return ua.StatusOK
}

// newTrustListServer serves the TrustList of the ServerConfiguration
// object of a server without push management with ServeTrustList.
func newTrustListServer(t *testing.T, cfg TrustListConfig) (*Server, *TrustListObject) {
	t.Helper()
	s, err := New(EndPoint("localhost", 0))
	require.NoError(t, err)
	s.initEndpoints()
	obj, err := s.ServeTrustList(ua.NewNumericNodeID(0, tlObj), cfg)
	require.NoError(t, err)
	return s, obj
}

func TestServeTrustList_Errors(t *testing.T) {
	s, err := New(EndPoint("localhost", 0))
	require.NoError(t, err)
	load := func() *ua.TrustListDataType { return nil }
	_, err = s.ServeTrustList(ua.NewNumericNodeID(0, 1), TrustListConfig{Load: load})
	require.Error(t, err, "no such node")
	_, err = s.ServeTrustList(ua.NewNumericNodeID(0, tlObj), TrustListConfig{})
	require.Error(t, err, "no Load")
	_, err = s.ServeTrustList(ua.NewNumericNodeID(0, id.Server), TrustListConfig{Load: load})
	require.Error(t, err, "not a TrustList")
}

func TestServeTrustList_ReadOnly(t *testing.T) {
	p := pushPKI(t)
	store := &tlStore{tl: &ua.TrustListDataType{TrustedCertificates: [][]byte{p.CACert}}}
	s, obj := newTrustListServer(t, TrustListConfig{Load: store.load})
	ctx, _ := adminCtx(s)

	out, sc := tlCall(t, s, ctx, mOpen, byte(fileModeRead))
	require.Equal(t, ua.StatusOK, sc)
	h := out[0].Value().(uint32)
	out, sc = tlCall(t, s, ctx, mRead, h, int32(1<<20))
	require.Equal(t, ua.StatusOK, sc)
	got, sc := decodeTrustList(out[0].Value().([]byte))
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, [][]byte{p.CACert}, got.TrustedCertificates)
	out, sc = tlCall(t, s, ctx, mGetPos, h)
	require.Equal(t, ua.StatusOK, sc)
	require.NotZero(t, out[0].Value().(uint64))
	_, sc = tlCall(t, s, ctx, mSetPos, h, uint64(1))
	require.Equal(t, ua.StatusOK, sc)
	_, sc = tlCall(t, s, ctx, mSetPos, h, "x")
	require.Equal(t, ua.StatusBadTypeMismatch, sc)
	_, sc = tlCall(t, s, ctx, mWrite, h, []byte{1})
	require.Equal(t, ua.StatusBadInvalidState, sc)
	_, sc = tlCall(t, s, ctx, mCloseUpd, h)
	require.Equal(t, ua.StatusBadInvalidState, sc)
	_, sc = tlCall(t, s, ctx, mRead, h, int32(-1))
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	_, sc = tlCall(t, s, ctx, mRead, h, "x")
	require.Equal(t, ua.StatusBadTypeMismatch, sc)
	require.Equal(t, 1, int(obj.openCount.Load()))
	_, sc = tlCall(t, s, ctx, mClose, h)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = tlCall(t, s, ctx, mClose, h)
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	_, sc = tlCall(t, s, ctx, mClose, "x")
	require.Equal(t, ua.StatusBadTypeMismatch, sc)

	// Writing is refused.
	_, sc = tlCall(t, s, ctx, mOpen, byte(fileModeWrite|fileModeEraseExisting))
	require.Equal(t, ua.StatusBadNotWritable, sc)
	_, sc = tlCall(t, s, ctx, mOpen, byte(0x40))
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	_, sc = tlCall(t, s, ctx, mOpen, "x")
	require.Equal(t, ua.StatusBadTypeMismatch, sc)
	_, sc = tlCall(t, s, ctx, mOpenMasks, "x")
	require.Equal(t, ua.StatusBadTypeMismatch, sc)
	_, sc = tlCall(t, s, ctx, mAdd, p.CACert, true)
	require.Equal(t, ua.StatusBadNotWritable, sc)
	_, sc = tlCall(t, s, ctx, mRemove, "00", true)
	require.Equal(t, ua.StatusBadNotWritable, sc)
	_, sc = tlCall(t, s, ctx, mAdd, "x", true)
	require.Equal(t, ua.StatusBadTypeMismatch, sc)
	_, sc = tlCall(t, s, ctx, mRemove, int32(1), true)
	require.Equal(t, ua.StatusBadTypeMismatch, sc)

	// The properties.
	readProp := func(nid uint32) any {
		t.Helper()
		n := s.Node(ua.NewNumericNodeID(0, nid))
		require.NotNil(t, n)
		return n.Value().Value.Value()
	}
	require.Equal(t, false, readProp(id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListWritable))
	require.NotZero(t, readProp(id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListSize))
	require.Equal(t, uint16(0), readProp(id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListOpenCount))
	require.NotNil(t, readProp(id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListLastUpdateTime))

	// A Load that returns nil serves an empty list.
	s2, _ := newTrustListServer(t, TrustListConfig{Load: func() *ua.TrustListDataType { return nil }})
	ctx2, _ := adminCtx(s2)
	_, sc = tlCall(t, s2, ctx2, mOpenMasks, uint32(ua.TrustListMasksAll))
	require.Equal(t, ua.StatusOK, sc)
}

func TestServeTrustList_Write(t *testing.T) {
	p := pushPKI(t)
	store := &tlStore{tl: &ua.TrustListDataType{}}
	var denied bool
	s, _ := newTrustListServer(t, TrustListConfig{
		Load:   store.load,
		Update: store.update,
		Authorize: func(_ context.Context, _ *MethodCaller, _ string, write bool) ua.StatusCode {
			if write && denied {
				return ua.StatusBadUserAccessDenied
			}
			return ua.StatusOK
		},
		MaxSize: 64 << 10,
	})
	ctx, _ := adminCtx(s)

	content := encodeTL(t, &ua.TrustListDataType{SpecifiedLists: uint32(ua.TrustListMasksTrustedCertificates), TrustedCertificates: [][]byte{p.CACert}})
	out, sc := tlCall(t, s, ctx, mOpen, byte(fileModeWrite|fileModeEraseExisting))
	require.Equal(t, ua.StatusOK, sc)
	h := out[0].Value().(uint32)

	// While a writer has the file: no other handle, no Add/Remove.
	other, _ := adminCtx(s)
	_, sc = tlCall(t, s, other, mOpen, byte(fileModeRead))
	require.Equal(t, ua.StatusBadNotReadable, sc)
	_, sc = tlCall(t, s, other, mAdd, p.CACert, true)
	require.Equal(t, ua.StatusBadInvalidState, sc)
	_, sc = tlCall(t, s, other, mRemove, "00", true)
	require.Equal(t, ua.StatusBadInvalidState, sc)
	_, sc = tlCall(t, s, other, mWrite, h, []byte{1})
	require.Equal(t, ua.StatusBadInvalidArgument, sc, "the handle of another session")

	_, sc = tlCall(t, s, ctx, mWrite, h, content)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = tlCall(t, s, ctx, mWrite, h, int32(5))
	require.Equal(t, ua.StatusBadTypeMismatch, sc)
	_, sc = tlCall(t, s, ctx, mWrite, h, make([]byte, 64<<10))
	require.Equal(t, ua.StatusBadEncodingLimitsExceeded, sc)
	_, sc = tlCall(t, s, ctx, mRead, h, int32(10))
	require.Equal(t, ua.StatusBadInvalidState, sc)
	out, sc = tlCall(t, s, ctx, mCloseUpd, h)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, false, out[0].Value())
	require.Equal(t, [][]byte{p.CACert}, store.load().TrustedCertificates)

	// A file that is no trust list, and an Update that fails.
	out, sc = tlCall(t, s, ctx, mOpen, byte(fileModeWrite|fileModeEraseExisting))
	require.Equal(t, ua.StatusOK, sc)
	h = out[0].Value().(uint32)
	_, sc = tlCall(t, s, ctx, mWrite, h, []byte{1, 2, 3})
	require.Equal(t, ua.StatusOK, sc)
	_, sc = tlCall(t, s, ctx, mCloseUpd, h)
	require.NotEqual(t, ua.StatusOK, sc)
	store.fail = ua.StatusBadInternalError
	out, sc = tlCall(t, s, ctx, mOpen, byte(fileModeWrite|fileModeEraseExisting))
	require.Equal(t, ua.StatusOK, sc)
	h = out[0].Value().(uint32)
	_, sc = tlCall(t, s, ctx, mWrite, h, content)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = tlCall(t, s, ctx, mCloseUpd, h)
	require.Equal(t, ua.StatusBadInternalError, sc)
	store.fail = ua.StatusOK

	// AddCertificate and RemoveCertificate.
	_, sc = tlCall(t, s, ctx, mAdd, []byte("junk"), true)
	require.Equal(t, ua.StatusBadCertificateInvalid, sc)
	_, sc = tlCall(t, s, ctx, mAdd, p.ClientCert, false)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, [][]byte{p.ClientCert}, store.load().IssuerCertificates)
	thumb := hex.EncodeToString(uapolicy.Thumbprint(p.ClientCert))
	_, sc = tlCall(t, s, ctx, mRemove, thumb, true)
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	_, sc = tlCall(t, s, ctx, mRemove, thumb, false)
	require.Equal(t, ua.StatusOK, sc)
	require.Empty(t, store.load().IssuerCertificates)
	_, sc = tlCall(t, s, ctx, mRemove, hex.EncodeToString(uapolicy.Thumbprint(p.CACert)), true)
	require.Equal(t, ua.StatusOK, sc)

	// Authorize decides.
	denied = true
	_, sc = tlCall(t, s, ctx, mAdd, p.CACert, true)
	require.Equal(t, ua.StatusBadUserAccessDenied, sc)
	_, sc = tlCall(t, s, ctx, mOpen, byte(fileModeWrite|fileModeEraseExisting))
	require.Equal(t, ua.StatusBadUserAccessDenied, sc)
	_, sc = tlCall(t, s, ctx, mOpen, byte(fileModeRead))
	require.Equal(t, ua.StatusOK, sc)

	// Without a session.
	_, sc = tlCall(t, s, context.Background(), mOpen, byte(fileModeRead))
	require.Equal(t, ua.StatusBadUserAccessDenied, sc)
}

func TestServeTrustList_PruneAndLimit(t *testing.T) {
	s, obj := newTrustListServer(t, TrustListConfig{Load: func() *ua.TrustListDataType { return &ua.TrustListDataType{} }})
	ctx, sess := adminCtx(s)
	for range maxTrustListHandles {
		_, sc := tlCall(t, s, ctx, mOpenMasks, uint32(ua.TrustListMasksAll))
		require.Equal(t, ua.StatusOK, sc)
	}
	_, sc := tlCall(t, s, ctx, mOpenMasks, uint32(ua.TrustListMasksAll))
	require.Equal(t, ua.StatusBadTooManyOperations, sc)
	// The handles of a closed session are dropped.
	require.NoError(t, s.sb.Close(sess.AuthTokenID))
	ctx2, _ := adminCtx(s)
	_, sc = tlCall(t, s, ctx2, mOpenMasks, uint32(ua.TrustListMasksAll))
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, int32(1), obj.openCount.Load())
	obj.Changed()
}
