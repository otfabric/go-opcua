// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"slices"
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// TestPushApplyChangesOpenForWriting: "ApplyChanges returns Bad_InvalidState
// if any TrustList is still open for writing. No changes are applied and
// ApplyChanges can be called again after the TrustList is closed" (Part 12
// §7.10.9). A handle open for reading does not block it.
func TestPushApplyChangesOpenForWriting(t *testing.T) {
	p := pushPKI(t)
	s := newPushServer(t, PushManagement{})
	ctx, _ := adminCtx(s)

	_, sc := tlCall(t, s, ctx, mAdd, p.CACert, true)
	require.Equal(t, ua.StatusOK, sc)
	out, sc := tlCall(t, s, ctx, mOpen, byte(0x06)) // Write | EraseExisting
	require.Equal(t, ua.StatusOK, sc)
	h := out[0].Value().(uint32)

	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusBadInvalidState, sc)
	require.NotNil(t, s.push.tx, "the transaction stays pending")
	require.False(t, slices.ContainsFunc(s.TrustList().TrustedCertificates, func(c []byte) bool { return bytes.Equal(c, p.CACert) }), "no change applied")

	_, sc = tlCall(t, s, ctx, mClose, h)
	require.Equal(t, ua.StatusOK, sc)
	out, sc = tlCall(t, s, ctx, mOpen, byte(0x01)) // Read
	require.Equal(t, ua.StatusOK, sc)
	_, sc = pushCall(t, s, ctx, scObj, mApply)
	require.Equal(t, ua.StatusOK, sc, "a reader does not block ApplyChanges")
	require.True(t, slices.ContainsFunc(s.TrustList().TrustedCertificates, func(c []byte) bool { return bytes.Equal(c, p.CACert) }))
	_, sc = tlCall(t, s, ctx, mClose, out[0].Value().(uint32))
	require.Equal(t, ua.StatusOK, sc)
}

// TestPushApplyChangesOtherSession: ApplyChanges and CancelChanges of a
// session that did not create the transaction are Bad_SessionIdInvalid
// ("The session is not valid for the active transaction", Part 12 §7.10.9,
// §7.10.11) and leave it alone; without a transaction both are
// Bad_NothingToDo.
func TestPushApplyChangesOtherSession(t *testing.T) {
	p := pushPKI(t)
	s := newPushServer(t, PushManagement{})
	a, _ := adminCtx(s)
	b, _ := adminCtx(s)

	for _, m := range []uint32{mApply, mCancel} {
		_, sc := pushCall(t, s, a, scObj, m)
		require.Equal(t, ua.StatusBadNothingToDo, sc)
	}
	_, sc := tlCall(t, s, a, mAdd, p.CACert, true)
	require.Equal(t, ua.StatusOK, sc)
	for _, m := range []uint32{mApply, mCancel} {
		_, sc = pushCall(t, s, b, scObj, m)
		require.Equal(t, ua.StatusBadSessionIDInvalid, sc)
	}
	require.NotNil(t, s.push.tx)
	_, sc = pushCall(t, s, a, scObj, mCancel)
	require.Equal(t, ua.StatusOK, sc)
	require.Nil(t, s.push.tx)
	require.Equal(t, ua.StatusBadRequestCancelledByClient, s.push.diagnostics().result)
}

// TestPushApplyChangesGoneSession: a transaction whose session is gone
// without the server having cancelled it yet is dropped by the next
// ApplyChanges, which then has nothing to do ("Transactions are
// automatically cancelled when the Session that created it is closed", Part
// 12 §7.10.2).
func TestPushApplyChangesGoneSession(t *testing.T) {
	s := newPushServer(t, PushManagement{})
	b, _ := adminCtx(s)
	s.push.mu.Lock()
	s.push.tx = &pushTx{session: ua.NewGUIDNodeID(1, "5d1b0a51-0000-4000-8000-000000000000")}
	s.push.startDiagnostics()
	s.push.mu.Unlock()

	_, sc := pushCall(t, s, b, scObj, mApply)
	require.Equal(t, ua.StatusBadNothingToDo, sc)
	require.Nil(t, s.push.tx)
	require.Equal(t, ua.StatusBadSessionClosed, s.push.diagnostics().result)
}

// TestFileOpenForWriting: openForWriting sees a valid handle opened with the
// Write bit, not a reader.
func TestFileOpenForWriting(t *testing.T) {
	s := newPushServer(t, PushManagement{})
	ctx, _ := adminCtx(s)
	f := s.push.groups[groupApplication].file
	require.False(t, f.openForWriting())
	out, sc := tlCall(t, s, ctx, mOpen, byte(0x01))
	require.Equal(t, ua.StatusOK, sc)
	require.False(t, f.openForWriting(), "a reader")
	_, sc = tlCall(t, s, ctx, mClose, out[0].Value().(uint32))
	require.Equal(t, ua.StatusOK, sc)
	out, sc = tlCall(t, s, ctx, mOpen, byte(0x06))
	require.Equal(t, ua.StatusOK, sc)
	require.True(t, f.openForWriting(), "a writer")
	_, sc = tlCall(t, s, ctx, mClose, out[0].Value().(uint32))
	require.Equal(t, ua.StatusOK, sc)
	require.False(t, f.openForWriting())
}
