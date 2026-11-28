// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
)

// sessionEnds are the ways a session leaves the server; each must release
// the file handles of the session at once (OPC 10000-20 §4.2.2: "a file
// handle that is valid while the session is open").
var sessionEnds = []struct {
	name string
	end  func(t *testing.T, s *Server, sess *session)
}{
	{"CloseSession", func(t *testing.T, s *Server, sess *session) {
		require.NoError(t, s.sb.Close(sess.AuthTokenID))
	}},
	{"timeout", func(t *testing.T, s *Server, sess *session) {
		require.Equal(t, []*session{sess}, s.sb.reapExpired(time.Now().Add(sessionTimeoutDefault+time.Hour)))
	}},
	{"Server.CloseSession", func(t *testing.T, s *Server, sess *session) {
		require.NoError(t, s.CloseSession(sess.ID))
	}},
	{"reclaimed", func(t *testing.T, s *Server, sess *session) {
		sess.channelID.Store(7) // a channel that is gone
		created, reclaimed := s.sb.newSessionWithin(1, func(uint32) bool { return false })
		require.NotNil(t, created)
		require.Equal(t, sess, reclaimed)
		require.NoError(t, s.sb.Close(created.AuthTokenID))
	}},
	{"shutdown", func(t *testing.T, s *Server, sess *session) {
		s.sb.closeAll()
		s.sb.reopen()
	}},
}

// fileState is the state of f without pruning: what the end of a session
// left, not what the next Open or OpenCount would clean up.
func fileState(f *FileObject) (handles, open int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.handles), f.open
}

// TestFileSessionEndPaths: every end of a session closes its handles at
// once, without another Open or OpenCount: the count, the handle, the
// buffer of a writer and its exclusive lock. The writes of a SnapshotFile
// (TrustList, PubSubConfiguration, ConnectionManagerConfiguration) that no
// CloseAndUpdate took are discarded.
func TestFileSessionEndPaths(t *testing.T) {
	for _, e := range sessionEnds {
		t.Run(e.name, func(t *testing.T) {
			s := newFileServer(t)
			committed := []byte("committed")
			f := newTestFile(t, s, FileConfig{Writable: true, Backend: &SnapshotFile{
				Content: func(context.Context) ([]byte, error) { return committed, nil },
			}})
			ctxA, sessA := fileSession(s)
			w, sc := f.Open(ctxA, fileModeWrite|fileModeEraseExisting)
			require.Equal(t, ua.StatusOK, sc)
			require.Equal(t, ua.StatusOK, f.Write(ctxA, w, []byte("uncommitted")))
			f.mu.Lock()
			x := f.handles[w]
			f.mu.Unlock()
			require.NotNil(t, x)

			e.end(t, s, sessA)

			handles, open := fileState(f)
			require.Zero(t, handles, "handles of the ended session")
			require.Zero(t, open, "OpenCount")
			x.mu.Lock()
			require.True(t, x.closed, "the content of the handle is closed")
			require.Nil(t, x.content.(*bytesContent).commit, "a snapshot is never committed by Close")
			x.mu.Unlock()
			require.Equal(t, "committed", string(committed))

			ctxB, _ := fileSession(s)
			r, sc := f.Open(ctxB, fileModeRead)
			require.Equal(t, ua.StatusOK, sc, "the exclusive lock of the writer is released")
			got, sc := f.Read(ctxB, r, 100)
			require.Equal(t, ua.StatusOK, sc)
			require.Equal(t, "committed", string(got))
			require.Equal(t, ua.StatusOK, f.Close(ctxB, r))
			_, sc = f.Read(ctxA, w, 1)
			require.Equal(t, ua.StatusBadInvalidArgument, sc, "the handle of the ended session is invalid")
		})
	}
}

// TestFileSessionEndConcurrent: the end of a session, CloseAll, Close and
// Open of other sessions run concurrently on the same files; every handle
// is closed once and the count matches (run with -race).
func TestFileSessionEndConcurrent(t *testing.T) {
	s := newFileServer(t)
	files := []*FileObject{
		newTestFile(t, s, FileConfig{Backend: NewMemoryFile([]byte("x")), Writable: true}),
		newTestFile(t, s, FileConfig{Backend: &SnapshotFile{Content: func(context.Context) ([]byte, error) { return []byte("y"), nil }}, Writable: true}),
	}
	for range 20 {
		ctxA, sessA := fileSession(s)
		ctxB, sessB := fileSession(s)
		var hs []uint32
		for _, f := range files {
			for range 3 {
				h, sc := f.Open(ctxA, fileModeRead)
				require.Equal(t, ua.StatusOK, sc)
				hs = append(hs, h)
			}
		}
		var wg sync.WaitGroup
		for range 4 {
			wg.Go(func() { s.files.sessionEnded(sessA.ID) })
		}
		wg.Go(func() { require.NoError(t, s.sb.Close(sessA.AuthTokenID)) })
		for _, f := range files {
			wg.Go(func() {
				for _, h := range hs {
					_ = f.Close(ctxA, h) // closed here or by the end of the session
				}
			})
			wg.Go(func() {
				if h, sc := f.Open(ctxB, fileModeRead); sc == ua.StatusOK {
					_ = f.Close(ctxB, h)
				}
			})
			wg.Go(f.CloseAll)
		}
		wg.Wait()
		for _, f := range files {
			handles, open := fileState(f)
			require.Zero(t, handles)
			require.Zero(t, open)
		}
		require.NoError(t, s.sb.Close(sessB.AuthTokenID))
	}
	// Twice for the same session, and for one the files never saw.
	s.files.sessionEnded(ua.NewStringNodeID(1, "gone"))
	s.files.sessionEnded(ua.NewStringNodeID(1, "gone"))
}

// TestPushSessionEndCancelsTransaction: the end of the session of a push
// transaction cancels it at once, "Transactions are automatically cancelled
// when the Session that created it is closed" (OPC 10000-12 §7.10.2), and
// "all pending changes are discarded" (§7.10.9): a pending trust list and
// a TrustList written without CloseAndUpdate. Another session then starts
// its own transaction.
func TestPushSessionEndCancelsTransaction(t *testing.T) {
	for _, e := range sessionEnds {
		t.Run(e.name, func(t *testing.T) {
			p := pushPKI(t)
			s := newPushServer(t, PushManagement{})
			ctx, sess := adminCtx(s)
			_, sc := tlCall(t, s, ctx, mAdd, p.StrangerCert, true)
			require.Equal(t, ua.StatusOK, sc)
			out, sc := tlCall(t, s, ctx, mOpen, byte(0x06))
			require.Equal(t, ua.StatusOK, sc)
			w := out[0].Value().(uint32)
			_, sc = tlCall(t, s, ctx, mWrite, w, encodeTL(t, &ua.TrustListDataType{
				SpecifiedLists:      uint32(ua.TrustListMasksTrustedCertificates),
				TrustedCertificates: [][]byte{p.CACert},
			}))
			require.Equal(t, ua.StatusOK, sc)

			e.end(t, s, sess)

			s.push.mu.Lock()
			tx := s.push.tx
			s.push.mu.Unlock()
			require.Nil(t, tx, "the transaction is cancelled with its session")
			require.Equal(t, ua.StatusBadSessionClosed, s.push.diagnostics().result)
			handles, open := fileState(s.push.groups[groupApplication].file)
			require.Zero(t, handles)
			require.Zero(t, open)
			require.Equal(t, [][]byte{p.ClientCert}, s.TrustList().TrustedCertificates, "nothing pending is applied")

			// The cancelled changes stay discarded: the next session's
			// transaction starts from the active trust list.
			ctx2, _ := adminCtx(s)
			out, sc = tlCall(t, s, ctx2, mOpen, byte(0x06))
			require.Equal(t, ua.StatusOK, sc, "the TrustList is not locked by the ended session")
			_, sc = tlCall(t, s, ctx2, mClose, out[0].Value().(uint32))
			require.Equal(t, ua.StatusOK, sc)
			_, sc = pushCall(t, s, ctx2, scObj, mApply)
			require.Equal(t, ua.StatusOK, sc)
			require.Equal(t, [][]byte{p.ClientCert}, s.TrustList().TrustedCertificates)
			require.Empty(t, s.TrustList().IssuerCertificates)
		})
	}

	// The end of another session leaves the transaction alone.
	s := newPushServer(t, PushManagement{})
	ctx, _ := adminCtx(s)
	_, other := adminCtx(s)
	_, sc := tlCall(t, s, ctx, mAdd, pushPKI(t).StrangerCert, true)
	require.Equal(t, ua.StatusOK, sc)
	require.NoError(t, s.CloseSession(other.ID))
	s.push.mu.Lock()
	require.NotNil(t, s.push.tx)
	s.push.mu.Unlock()
	var none *pushManager
	none.sessionEnded(other.ID)
}
