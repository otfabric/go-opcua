// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/testutil/cleanup"
	"github.com/otfabric/go-opcua/ua"
)

// newFileServer returns a server (not started) for the FileType tests.
func newFileServer(t *testing.T) *Server {
	t.Helper()
	s, err := New(EndPoint("localhost", 0), InsecureNoSecurity())
	require.NoError(t, err)
	return s
}

// fileSession returns the context of a call by a new session of s.
func fileSession(s *Server) (context.Context, *session) {
	sess := s.sb.NewSession()
	return context.WithValue(context.Background(), methodCallerKey{}, &MethodCaller{SessionID: sess.ID}), sess
}

func newTestFile(t *testing.T, s *Server, cfg FileConfig) *FileObject {
	t.Helper()
	f, err := s.NewFile(cfg)
	require.NoError(t, err)
	return f
}

func TestNewFileErrors(t *testing.T) {
	var nilServer *Server
	_, err := nilServer.NewFile(FileConfig{Backend: NewMemoryFile(nil)})
	require.ErrorContains(t, err, "nil server")
	s := newFileServer(t)
	_, err = s.NewFile(FileConfig{})
	require.ErrorContains(t, err, "Backend is required")
	_, err = s.NewFile(FileConfig{Backend: NewMemoryFile(nil), Modes: []ua.OpenFileMode{fileModeEraseExisting}})
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
	_, err = s.NewFile(FileConfig{Backend: NewMemoryFile(nil), Modes: []ua.OpenFileMode{0x10 | fileModeRead}})
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
}

// TestFileOpenModes: the mode of Open (OPC 10000-20 §4.2.2, Table 4).
func TestFileOpenModes(t *testing.T) {
	s := newFileServer(t)
	ctx, _ := fileSession(s)
	f := newTestFile(t, s, FileConfig{Backend: NewMemoryFile([]byte("abc")), Writable: true})
	for _, tc := range []struct {
		name string
		mode ua.OpenFileMode
		want ua.StatusCode
	}{
		{"reserved bit 4", 0x10 | fileModeRead, ua.StatusBadInvalidArgument},
		{"reserved bit 7", 0x80 | fileModeRead, ua.StatusBadInvalidArgument},
		{"EraseExisting without Write", fileModeRead | fileModeEraseExisting, ua.StatusBadInvalidArgument},
		{"Read", fileModeRead, ua.StatusOK},
		{"Write", fileModeWrite, ua.StatusOK},
		{"Read Write", fileModeRead | fileModeWrite, ua.StatusOK},
		{"Write EraseExisting", fileModeWrite | fileModeEraseExisting, ua.StatusOK},
		{"Write Append", fileModeWrite | fileModeAppend, ua.StatusOK},
		{"Append alone", fileModeAppend, ua.StatusOK},
		{"none", 0, ua.StatusOK},
	} {
		h, sc := f.Open(ctx, tc.mode)
		assert.Equal(t, tc.want, sc, tc.name)
		if sc == ua.StatusOK {
			assert.NotZero(t, h, tc.name)
			assert.Equal(t, ua.StatusOK, f.Close(ctx, h), tc.name)
		}
	}

	// Modes narrow them.
	tl := newTestFile(t, s, FileConfig{Backend: NewMemoryFile(nil), Writable: true, Modes: trustListModes})
	_, sc := tl.Open(ctx, fileModeRead|fileModeWrite)
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	h, sc := tl.Open(ctx, fileModeWrite|fileModeEraseExisting)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, ua.StatusOK, tl.Close(ctx, h))

	// A file that is not Writable.
	ro := newTestFile(t, s, FileConfig{Backend: NewMemoryFile(nil)})
	_, sc = ro.Open(ctx, fileModeWrite)
	require.Equal(t, ua.StatusBadNotWritable, sc)

	// Authorize decides after the checks of the mode.
	var asked []ua.OpenFileMode
	auth := newTestFile(t, s, FileConfig{Backend: NewMemoryFile(nil), Writable: true, Authorize: func(_ context.Context, c *MethodCaller, m ua.OpenFileMode) ua.StatusCode {
		require.NotNil(t, c.SessionID)
		asked = append(asked, m)
		if m&fileModeWrite != 0 {
			return ua.StatusBadUserAccessDenied
		}
		return ua.StatusOK
	}})
	_, sc = auth.Open(ctx, fileModeWrite)
	require.Equal(t, ua.StatusBadUserAccessDenied, sc)
	_, sc = auth.Open(ctx, 0x20)
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	_, sc = auth.Open(ctx, fileModeRead)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, []ua.OpenFileMode{fileModeWrite, fileModeRead}, asked)

	// Without a session.
	_, sc = f.Open(context.Background(), fileModeRead)
	require.Equal(t, ua.StatusBadSessionIDInvalid, sc)
	_, sc = f.OpenBytes(context.Background(), nil)
	require.Equal(t, ua.StatusBadSessionIDInvalid, sc)
}

// TestFileHandles: concurrent opens and the handles of a session (OPC
// 10000-20 §4.2.2).
func TestFileHandles(t *testing.T) {
	s := newFileServer(t)
	ctx1, _ := fileSession(s)
	ctx2, _ := fileSession(s)
	changed := make(chan struct{}, 64)
	f := newTestFile(t, s, FileConfig{Backend: NewMemoryFile([]byte("abc")), Writable: true, MaxHandles: 3, OnChange: func() { changed <- struct{}{} }})

	// "Clients can open the same file several times for read."
	r1, sc := f.Open(ctx1, fileModeRead)
	require.Equal(t, ua.StatusOK, sc)
	r2, sc := f.Open(ctx2, fileModeRead)
	require.Equal(t, ua.StatusOK, sc)
	require.NotEqual(t, r1, r2)
	require.Equal(t, 2, f.OpenCount())
	<-changed

	// "A request to open for writing shall return Bad_NotWritable when the
	// file is already opened."
	_, sc = f.Open(ctx1, fileModeWrite)
	require.Equal(t, ua.StatusBadNotWritable, sc)
	_, sc = f.Open(ctx2, fileModeRead|fileModeWrite)
	require.Equal(t, ua.StatusBadNotWritable, sc)

	// The handle of another session is not one of the caller.
	_, sc = f.Read(ctx2, r1, 1)
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	require.Equal(t, ua.StatusBadInvalidArgument, f.Close(ctx2, r1))
	_, sc = f.GetPosition(ctx2, r1)
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	require.Equal(t, ua.StatusBadInvalidArgument, f.SetPosition(ctx2, r1, 0))
	require.Equal(t, ua.StatusBadInvalidArgument, f.Write(ctx2, r1, []byte{1}))
	// An unknown handle, and no session.
	_, sc = f.Read(ctx1, 999, 1)
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	_, sc = f.Read(context.Background(), r1, 1)
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	require.Equal(t, ua.StatusBadInvalidArgument, f.Close(context.Background(), r1))

	// MaxHandles.
	r3, sc := f.Open(ctx1, fileModeRead)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = f.Open(ctx1, fileModeRead)
	require.Equal(t, ua.StatusBadTooManyOperations, sc)

	// "When a client closes a file the handle becomes invalid."
	for _, h := range []uint32{r1, r3} {
		require.Equal(t, ua.StatusOK, f.Close(ctx1, h))
	}
	require.Equal(t, ua.StatusBadInvalidArgument, f.Close(ctx1, r1))
	require.Equal(t, ua.StatusOK, f.Close(ctx2, r2))
	require.Equal(t, 0, f.OpenCount())

	// "A request to open for reading shall return Bad_NotReadable when the
	// file is already opened for writing."
	w, sc := f.Open(ctx1, fileModeWrite)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = f.Open(ctx2, fileModeRead)
	require.Equal(t, ua.StatusBadNotReadable, sc)
	_, sc = f.Open(ctx1, fileModeRead)
	require.Equal(t, ua.StatusBadNotReadable, sc, "the same session too")
	require.Equal(t, ua.StatusOK, f.Close(ctx1, w))
}

// TestFileHandleNeverZero: a handle is never 0, which CreateFile returns
// for no handle (OPC 10000-20 §4.3.4), and not one that is open.
func TestFileHandleNeverZero(t *testing.T) {
	s := newFileServer(t)
	ctx, _ := fileSession(s)
	f := newTestFile(t, s, FileConfig{Backend: NewMemoryFile(nil)})
	f.next = 1<<32 - 2
	h1, sc := f.Open(ctx, fileModeRead)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, uint32(1<<32-1), h1)
	f.mu.Lock()
	f.handles[1] = &fileHandle{session: ua.NewNumericNodeID(9, 9), opening: true}
	f.mu.Unlock()
	h2, sc := f.Open(ctx, fileModeRead)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, uint32(2), h2)
}

func TestFileReadWritePosition(t *testing.T) {
	s := newFileServer(t)
	ctx, _ := fileSession(s)
	mf := NewMemoryFile([]byte("hello world"))
	f := newTestFile(t, s, FileConfig{Backend: mf, Writable: true, MaxByteStringLength: 4})

	h, sc := f.Open(ctx, fileModeRead)
	require.Equal(t, ua.StatusOK, sc)
	// "Only positive values are allowed."
	for _, n := range []int32{0, -1} {
		_, sc = f.Read(ctx, h, n)
		require.Equal(t, ua.StatusBadInvalidArgument, sc, "length %d", n)
	}
	// At most MaxByteStringLength per Read.
	b, sc := f.Read(ctx, h, 100)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, "hell", string(b))
	b, sc = f.Read(ctx, h, 2)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, "o ", string(b))
	pos, sc := f.GetPosition(ctx, h)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, uint64(6), pos)
	// "If the position is higher than the file size the position is set to
	// the end of the file."
	require.Equal(t, ua.StatusOK, f.SetPosition(ctx, h, 1000))
	pos, _ = f.GetPosition(ctx, h)
	require.Equal(t, uint64(11), pos)
	b, sc = f.Read(ctx, h, 4)
	require.Equal(t, ua.StatusOK, sc)
	require.Empty(t, b, "the end of the file")
	require.Equal(t, ua.StatusOK, f.SetPosition(ctx, h, 6))
	b, _ = f.Read(ctx, h, 4)
	require.Equal(t, "worl", string(b))
	// A handle not opened for writing.
	require.Equal(t, ua.StatusBadInvalidState, f.Write(ctx, h, []byte("x")))
	require.Equal(t, ua.StatusOK, f.Close(ctx, h))

	// Write: at the position, which advances; empty is Good without effect.
	w, sc := f.Open(ctx, fileModeWrite)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = f.Read(ctx, w, 1)
	require.Equal(t, ua.StatusBadInvalidState, sc, "not opened for reading")
	require.Equal(t, ua.StatusOK, f.Write(ctx, w, nil))
	require.Equal(t, ua.StatusOK, f.Write(ctx, w, []byte("J")))
	require.Equal(t, ua.StatusOK, f.SetPosition(ctx, w, 6))
	require.Equal(t, ua.StatusOK, f.Write(ctx, w, []byte("there!")))
	pos, _ = f.GetPosition(ctx, w)
	require.Equal(t, uint64(12), pos)
	require.Equal(t, "hello world", string(mf.Bytes()), "a MemoryFile changes when the handle closes")
	require.Equal(t, ua.StatusOK, f.Close(ctx, w))
	require.Equal(t, "Jello there!", string(mf.Bytes()))

	// Append: "File is opened at end of the file."
	a, sc := f.Open(ctx, fileModeWrite|fileModeAppend)
	require.Equal(t, ua.StatusOK, sc)
	pos, _ = f.GetPosition(ctx, a)
	require.Equal(t, uint64(12), pos)
	require.Equal(t, ua.StatusOK, f.Write(ctx, a, []byte("!")))
	require.Equal(t, ua.StatusOK, f.Close(ctx, a))
	require.Equal(t, "Jello there!!", string(mf.Bytes()))

	// EraseExisting: "File is erased" (the content of the handle is empty).
	e, sc := f.Open(ctx, fileModeRead|fileModeWrite|fileModeEraseExisting)
	require.Equal(t, ua.StatusOK, sc)
	b, _ = f.Read(ctx, e, 10)
	require.Empty(t, b)
	require.Equal(t, ua.StatusOK, f.Write(ctx, e, []byte("new")))
	require.Equal(t, ua.StatusOK, f.SetPosition(ctx, e, 0))
	b, _ = f.Read(ctx, e, 10)
	require.Equal(t, "new", string(b))
	require.Equal(t, ua.StatusOK, f.Close(ctx, e))
	require.Equal(t, "new", string(mf.Bytes()))

	// MaxSize of a MemoryFile.
	mf.MaxSize = 4
	w, _ = f.Open(ctx, fileModeWrite|fileModeEraseExisting)
	require.Equal(t, ua.StatusBadResourceUnavailable, f.Write(ctx, w, []byte("12345")))
	require.Equal(t, ua.StatusOK, f.Close(ctx, w))
}

// TestFileSessionEnd: the handles of a session are closed when the session
// ends, which OPC 10000-20 §4.2.5 leaves to the server for what was
// written; a MemoryFile keeps it.
func TestFileSessionEnd(t *testing.T) {
	s := newFileServer(t)
	ctx1, sess1 := fileSession(s)
	ctx2, _ := fileSession(s)
	mf := NewMemoryFile(nil)
	f := newTestFile(t, s, FileConfig{Backend: mf, Writable: true})
	w, sc := f.Open(ctx1, fileModeWrite)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, ua.StatusOK, f.Write(ctx1, w, []byte("kept")))
	_, sc = f.Open(ctx2, fileModeRead)
	require.Equal(t, ua.StatusBadNotReadable, sc)

	require.NoError(t, s.sb.Close(sess1.AuthTokenID))
	require.Equal(t, 0, f.OpenCount())
	require.Equal(t, "kept", string(mf.Bytes()))
	r, sc := f.Open(ctx2, fileModeRead)
	require.Equal(t, ua.StatusOK, sc, "the writer is gone")
	require.Equal(t, ua.StatusOK, f.Close(ctx2, r))

	// A session that ended before the FileObject was told: its handles are
	// pruned when the handles are counted or opened.
	gone := context.WithValue(context.Background(), methodCallerKey{}, &MethodCaller{SessionID: ua.NewStringNodeID(1, "gone")})
	h, sc := f.Open(gone, fileModeWrite)
	require.Equal(t, ua.StatusOK, sc)
	require.NotZero(t, h)
	require.Equal(t, 0, f.OpenCount())
	r, sc = f.Open(ctx2, fileModeRead)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, ua.StatusOK, f.Close(ctx2, r))

	// CloseAll closes every handle.
	_, sc = f.Open(ctx2, fileModeRead)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = f.Open(ctx2, fileModeRead)
	require.Equal(t, ua.StatusOK, sc)
	f.CloseAll()
	require.Equal(t, 0, f.OpenCount())
}

// blockingFile is a backend whose Open waits for release.
type blockingFile struct {
	*MemoryFile
	opening, release chan struct{}
}

func (b *blockingFile) Open(ctx context.Context, mode ua.OpenFileMode) (FileContent, error) {
	b.opening <- struct{}{}
	<-b.release
	return b.MemoryFile.Open(ctx, mode)
}

// TestFileOpenRace: a second writer is refused while the first one opens
// the content, and a handle whose session ends while it opens is not
// returned.
func TestFileOpenRace(t *testing.T) {
	s := newFileServer(t)
	ctx, _ := fileSession(s)
	b := &blockingFile{MemoryFile: NewMemoryFile([]byte("x")), opening: make(chan struct{}), release: make(chan struct{})}
	f := newTestFile(t, s, FileConfig{Backend: b, Writable: true})

	var wg sync.WaitGroup
	var sc1 ua.StatusCode
	wg.Go(func() { _, sc1 = f.Open(ctx, fileModeWrite|fileModeEraseExisting) })
	<-b.opening
	_, sc := f.Open(ctx, fileModeWrite)
	require.Equal(t, ua.StatusBadNotWritable, sc, "refused before the backend opens")
	require.Equal(t, 0, f.OpenCount(), "a handle being opened is not counted")
	f.CloseAll()
	close(b.release)
	wg.Wait()
	require.Equal(t, ua.StatusBadSessionClosed, sc1)
	require.Equal(t, "x", string(b.Bytes()), "the handle never written to")
	require.Equal(t, 0, f.OpenCount())

	// The same for the end of the session, with CloseAll of an opening
	// handle in sessionEnded.
	ctx2, sess2 := fileSession(s)
	b.release = make(chan struct{})
	wg.Go(func() { _, sc1 = f.Open(ctx2, fileModeRead) })
	<-b.opening
	require.NoError(t, s.sb.Close(sess2.AuthTokenID))
	close(b.release)
	wg.Wait()
	require.Equal(t, ua.StatusBadSessionClosed, sc1)
}

// faultyFile is a backend whose operations fail as set.
type faultyFile struct {
	openErr, sizeErr, modErr    error
	readErr, writeErr, closeErr error
	contentSizeErr              error
}

func (f *faultyFile) Open(context.Context, ua.OpenFileMode) (FileContent, error) {
	if f.openErr != nil {
		return nil, f.openErr
	}
	return &faultyContent{f: f}, nil
}
func (f *faultyFile) Size() (uint64, error)       { return 3, f.sizeErr }
func (f *faultyFile) ModTime() (time.Time, error) { return time.Unix(1, 0), f.modErr }

type faultyContent struct{ f *faultyFile }

func (c *faultyContent) ReadAt(p []byte, _ int64) (int, error) {
	if c.f.readErr != nil {
		return 0, c.f.readErr
	}
	return copy(p, "abc"), nil
}
func (c *faultyContent) WriteAt(p []byte, _ int64) (int, error) { return len(p), c.f.writeErr }
func (c *faultyContent) Size() (int64, error)                   { return 3, c.f.contentSizeErr }
func (c *faultyContent) Close() error                           { return c.f.closeErr }

func TestFileBackendErrors(t *testing.T) {
	s := newFileServer(t)
	ctx, _ := fileSession(s)
	b := &faultyFile{}
	f := newTestFile(t, s, FileConfig{Backend: b, Writable: true})

	b.openErr = ua.StatusBadNotFound
	_, sc := f.Open(ctx, fileModeRead)
	require.Equal(t, ua.StatusBadNotFound, sc)
	b.openErr = errors.New("disk")
	_, sc = f.Open(ctx, fileModeRead)
	require.Equal(t, ua.StatusBadUnexpectedError, sc)
	b.openErr = nil
	require.Equal(t, 0, f.OpenCount(), "a failed Open leaves no handle")

	// Append needs the size of the content.
	b.contentSizeErr = ua.StatusBadResourceUnavailable
	_, sc = f.Open(ctx, fileModeWrite|fileModeAppend)
	require.Equal(t, ua.StatusBadResourceUnavailable, sc)
	h, sc := f.Open(ctx, fileModeRead|fileModeWrite)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = f.Read(ctx, h, 1)
	require.Equal(t, ua.StatusBadResourceUnavailable, sc)
	require.Equal(t, ua.StatusBadResourceUnavailable, f.SetPosition(ctx, h, 1))
	b.contentSizeErr = nil

	b.readErr = errors.New("io")
	_, sc = f.Read(ctx, h, 1)
	require.Equal(t, ua.StatusBadUnexpectedError, sc)
	b.readErr = io.EOF
	got, sc := f.Read(ctx, h, 1)
	require.Equal(t, ua.StatusOK, sc, "EOF is the end, not an error")
	require.Empty(t, got)
	b.readErr = nil
	b.writeErr = ua.StatusBadOutOfRange
	require.Equal(t, ua.StatusBadOutOfRange, f.Write(ctx, h, []byte{1}))
	b.writeErr = nil
	b.closeErr = errors.New("flush")
	require.Equal(t, ua.StatusBadUnexpectedError, f.Close(ctx, h))
	require.Equal(t, 0, f.OpenCount(), "the handle is closed anyway")
	b.closeErr = nil

	// CloseAndTake reads the content.
	h, _ = f.Open(ctx, fileModeRead|fileModeWrite)
	b.contentSizeErr = ua.StatusBadInternalError
	_, sc = f.CloseAndTake(ctx, h, nil)
	require.Equal(t, ua.StatusBadInternalError, sc)
	b.contentSizeErr = nil
	b.readErr = errors.New("io")
	_, sc = f.CloseAndTake(ctx, h, nil)
	require.Equal(t, ua.StatusBadUnexpectedError, sc)
	b.readErr = nil
	b.closeErr = ua.StatusBadInternalError
	_, sc = f.CloseAndTake(ctx, h, nil)
	require.Equal(t, ua.StatusBadInternalError, sc)
	b.closeErr = nil
	data, sc := func() ([]byte, ua.StatusCode) {
		h, _ := f.Open(ctx, fileModeWrite)
		return f.CloseAndTake(ctx, h, nil)
	}()
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, "abc", string(data))

	// The Properties report the errors of the backend as their status.
	b.sizeErr = ua.StatusBadNotSupported
	require.Equal(t, ua.StatusBadNotSupported, f.Property("Size")().Status)
	b.sizeErr = errors.New("stat")
	require.Equal(t, ua.StatusBadUnexpectedError, f.Property("Size")().Status)
	b.modErr = errors.New("stat")
	require.Equal(t, ua.StatusBadUnexpectedError, f.Property("LastModifiedTime")().Status)
	b.modErr = nil
	require.Equal(t, time.Unix(1, 0).UTC(), f.Property("LastModifiedTime")().Value.Value())
	require.Equal(t, ua.StatusBadUnexpectedError, fileStatus(ua.StatusOK, ua.StatusBadUnexpectedError))
}

func TestFileCloseAndTake(t *testing.T) {
	s := newFileServer(t)
	ctx, _ := fileSession(s)
	content := []byte("old")
	f := newTestFile(t, s, FileConfig{Writable: true, Backend: &SnapshotFile{
		Content: func(context.Context) ([]byte, error) { return content, nil },
		MaxSize: 8,
	}})

	require.Equal(t, uint64(3), f.Property("Size")().Value.Value())
	r, sc := f.Open(ctx, fileModeRead)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = f.CloseAndTake(ctx, r, nil)
	require.Equal(t, ua.StatusBadInvalidState, sc, "not opened for writing")
	require.Equal(t, ua.StatusOK, f.Close(ctx, r))

	w, _ := f.Open(ctx, fileModeWrite|fileModeEraseExisting)
	require.Equal(t, ua.StatusOK, f.Write(ctx, w, []byte("new")))
	require.Equal(t, ua.StatusBadResourceUnavailable, f.Write(ctx, w, []byte("too long")), "MaxSize")
	// A failing check keeps the handle open.
	_, sc = f.CloseAndTake(ctx, w, func(b []byte) ua.StatusCode {
		require.Equal(t, "new", string(b))
		return ua.StatusBadNothingToDo
	})
	require.Equal(t, ua.StatusBadNothingToDo, sc)
	require.Equal(t, 1, f.OpenCount())
	data, sc := f.CloseAndTake(ctx, w, func([]byte) ua.StatusCode { return ua.StatusOK })
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, "new", string(data))
	require.Equal(t, 0, f.OpenCount())
	require.Equal(t, "old", string(content), "a SnapshotFile is not changed by its handles")

	// Without EraseExisting a writer starts with the content.
	w, _ = f.Open(ctx, fileModeRead|fileModeWrite)
	b, _ := f.Read(ctx, w, 10)
	require.Equal(t, "old", string(b))
	require.Equal(t, ua.StatusOK, f.Close(ctx, w), "Close discards")

	// OpenBytes is a read handle on other bytes.
	h, sc := f.OpenBytes(ctx, []byte("masked"))
	require.Equal(t, ua.StatusOK, sc)
	b, _ = f.Read(ctx, h, 10)
	require.Equal(t, "masked", string(b))
	require.Equal(t, ua.StatusBadInvalidState, f.Write(ctx, h, []byte("x")))
	_, sc = f.Open(ctx, fileModeWrite)
	require.Equal(t, ua.StatusBadNotWritable, sc)
	require.Equal(t, ua.StatusOK, f.Close(ctx, h))

	// The error of Content.
	failing := newTestFile(t, s, FileConfig{Backend: &SnapshotFile{Content: func(context.Context) ([]byte, error) {
		return nil, ua.StatusBadNotReadable
	}, SizeExceeded: ua.StatusBadEncodingLimitsExceeded}})
	_, sc = failing.Open(ctx, fileModeRead)
	require.Equal(t, ua.StatusBadNotReadable, sc)
	require.Equal(t, ua.StatusBadNotReadable, failing.Property("Size")().Status)
	require.Nil(t, failing.Property("LastModifiedTime"), "a SnapshotFile has no modification time")
}

func TestBytesContent(t *testing.T) {
	c := &bytesContent{data: []byte("ab")}
	_, err := c.ReadAt(make([]byte, 1), -1)
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
	n, err := c.ReadAt(make([]byte, 1), 0)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	n, err = c.ReadAt(make([]byte, 4), 1)
	require.ErrorIs(t, err, io.EOF, "a short read")
	require.Equal(t, 1, n)
	_, err = c.WriteAt([]byte("x"), 3)
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
	_, err = c.WriteAt([]byte("x"), -1)
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
	_, err = (&bytesContent{readOnly: true}).WriteAt([]byte("x"), 0)
	require.ErrorIs(t, err, ua.StatusBadInvalidState)
}

func TestFileProperties(t *testing.T) {
	s := newFileServer(t)
	ctx, _ := fileSession(s)
	mf := NewMemoryFile([]byte("abc"))
	f := newTestFile(t, s, FileConfig{Backend: mf, Writable: true, MimeType: "text/plain", MaxByteStringLength: 100})
	val := func(name string) any { return f.Property(name)().Value.Value() }
	require.Equal(t, uint64(3), val("Size"))
	require.Equal(t, true, val("Writable"))
	require.Equal(t, true, val("UserWritable"))
	require.Equal(t, uint16(0), val("OpenCount"))
	require.Equal(t, uint32(100), val("MaxByteStringLength"))
	require.Equal(t, "text/plain", val("MimeType"))
	mod, err := mf.ModTime()
	require.NoError(t, err)
	require.Equal(t, mod.UTC(), val("LastModifiedTime"))
	require.Nil(t, f.Property("Other"))
	require.Nil(t, f.Method("Other"))

	_, sc := f.Open(ctx, fileModeRead)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, uint16(1), val("OpenCount"))
	mf.SetBytes([]byte("abcdef"))
	f.Changed()
	require.Equal(t, uint64(6), val("Size"))

	def := newTestFile(t, s, FileConfig{Backend: mf})
	require.Nil(t, def.Property("MimeType"))
	require.Equal(t, uint32(DefaultFileMaxByteStringLength), def.Property("MaxByteStringLength")().Value.Value())
	require.Equal(t, false, def.Property("Writable")().Value.Value())
}

// TestFileMethodHandlers: the handlers check their arguments against the
// declarations (package uamethod) and return the status of the Method.
func TestFileMethodHandlers(t *testing.T) {
	s := newFileServer(t)
	ctx, _ := fileSession(s)
	f := newTestFile(t, s, FileConfig{Backend: NewMemoryFile([]byte("abc")), Writable: true})
	call := func(name string, args ...any) ([]*ua.Variant, ua.StatusCode) {
		vs := make([]*ua.Variant, len(args))
		for i, a := range args {
			vs[i] = ua.MustVariant(a)
		}
		return f.Method(name)(ctx, nil, nil, vs)
	}
	for name, n := range map[string]int{"Open": 1, "Close": 1, "Read": 2, "Write": 2, "GetPosition": 1, "SetPosition": 2} {
		_, sc := call(name)
		require.Equal(t, ua.StatusBadArgumentsMissing, sc, name)
		args := make([]any, n)
		for i := range args {
			args[i] = "x"
		}
		_, sc = call(name, args...)
		require.Equal(t, ua.StatusBadInvalidArgument, sc, name)
		_, sc = call(name, append(args, "x")...)
		require.Equal(t, ua.StatusBadTooManyArguments, sc, name)
	}
	_, sc := call("Open", uint8(0x40))
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	out, sc := call("Open", uint8(fileModeRead|fileModeWrite))
	require.Equal(t, ua.StatusOK, sc)
	h := out[0].Value().(uint32)
	_, sc = call("Write", h, []byte("xy"))
	require.Equal(t, ua.StatusOK, sc)
	_, sc = call("Write", uint32(99), []byte("xy"))
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	out, sc = call("GetPosition", h)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, uint64(2), out[0].Value())
	_, sc = call("GetPosition", uint32(99))
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	_, sc = call("SetPosition", h, uint64(0))
	require.Equal(t, ua.StatusOK, sc)
	out, sc = call("Read", h, int32(10))
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, []byte("xyc"), out[0].Value())
	_, sc = call("Read", h, int32(0))
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	_, sc = call("Close", h)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = call("Close", h)
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
}

func TestOSFile(t *testing.T) {
	s := newFileServer(t)
	ctx, _ := fileSession(s)
	path := filepath.Join(t.TempDir(), "f.txt")
	o := NewOSFile(path)
	f := newTestFile(t, s, FileConfig{Backend: o, Writable: true})

	_, sc := f.Open(ctx, fileModeRead)
	require.Equal(t, ua.StatusBadNotFound, sc, "a file that does not exist")
	require.Equal(t, ua.StatusBadNotFound, f.Property("Size")().Status)
	require.Equal(t, ua.StatusBadNotFound, f.Property("LastModifiedTime")().Status)

	w, sc := f.Open(ctx, fileModeWrite)
	require.Equal(t, ua.StatusOK, sc, "Write creates it")
	require.Equal(t, ua.StatusOK, f.Write(ctx, w, []byte("hello")))
	require.Equal(t, ua.StatusOK, f.Close(ctx, w))
	fi, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	require.Equal(t, uint64(5), f.Property("Size")().Value.Value())
	require.Equal(t, fi.ModTime().UTC(), f.Property("LastModifiedTime")().Value.Value())

	rw, _ := f.Open(ctx, fileModeRead|fileModeWrite|fileModeAppend)
	pos, _ := f.GetPosition(ctx, rw)
	require.Equal(t, uint64(5), pos)
	require.Equal(t, ua.StatusOK, f.Write(ctx, rw, []byte("!")))
	require.Equal(t, ua.StatusOK, f.SetPosition(ctx, rw, 0))
	b, _ := f.Read(ctx, rw, 10)
	require.Equal(t, "hello!", string(b))
	require.Equal(t, ua.StatusOK, f.Close(ctx, rw))

	e, _ := f.Open(ctx, fileModeWrite|fileModeEraseExisting)
	require.Equal(t, ua.StatusOK, f.Close(ctx, e))
	b, err = os.ReadFile(path)
	require.NoError(t, err)
	require.Empty(t, b, "EraseExisting truncates")

	// Perm, and an error that is not Bad_NotFound.
	o.Perm = 0o640
	o.Path = filepath.Join(t.TempDir(), "g")
	w, _ = f.Open(ctx, fileModeWrite)
	require.Equal(t, ua.StatusOK, f.Close(ctx, w))
	fi, err = os.Stat(o.Path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o640), fi.Mode().Perm())
	o.Path = t.TempDir()
	_, sc = f.Open(ctx, fileModeWrite)
	require.Equal(t, ua.StatusBadUnexpectedError, sc, "a directory")

	// The content of a closed *os.File fails.
	c := osContent{f: mustCreate(t)}
	require.NoError(t, c.Close())
	_, err = c.Size()
	require.Error(t, err)
}

func mustCreate(t *testing.T) *os.File {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), "x"))
	require.NoError(t, err)
	return f
}

// TestConfigFileInternals: CloseAndUpdate of PubSubConfiguration checks the
// type of its handle itself, and the reservations of a session that ended
// are forgotten (Part 14 §9.1.3.7.5).
func TestConfigFileInternals(t *testing.T) {
	s := newTestServer()
	s.cfg.pubsub = &pubsubConfig{}
	require.NotNil(t, s.PubSub())
	cleanup.Register(t, s.closePubSub)
	require.NoError(t, s.buildPubSubModel())
	f := s.ps.model.file
	require.NotNil(t, f)
	ctx, _ := fileSession(s)
	// The arguments of the declaration (Part 4 §5.12.2.4): too few, then
	// a handle that is no UInt32.
	_, sc := f.closeAndUpdate(ctx, nil, []*ua.Variant{ua.MustVariant("h")})
	require.Equal(t, ua.StatusBadArgumentsMissing, sc)
	_, sc = f.closeAndUpdate(ctx, nil, []*ua.Variant{ua.MustVariant("h"), ua.MustVariant(false), ua.MustVariant([]*ua.ExtensionObject{})})
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	h, sc := f.file.Open(ctx, fileModeWrite|fileModeEraseExisting)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = f.closeAndUpdate(ctx, nil, []*ua.Variant{ua.MustVariant(h), ua.MustVariant("x"), ua.MustVariant("y")})
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	// A null element of ConfigurationReferences is no
	// PubSubConfigurationRefDataType.
	_, sc = f.closeAndUpdate(ctx, nil, []*ua.Variant{ua.MustVariant(h), ua.MustVariant(false), ua.MustVariant([]*ua.ExtensionObject{ua.NewExtensionObject(nil)})})
	require.Equal(t, ua.StatusBadTypeMismatch, sc)
	// The second argument of ReserveIds is missing.
	_, sc = f.reserveIDs(ctx, nil, []*ua.Variant{ua.MustVariant("profile")})
	require.Equal(t, ua.StatusBadArgumentsMissing, sc)
	require.Equal(t, 1, f.file.OpenCount(), "the handle stays open")

	f.mu.Lock()
	f.reserved["gone"] = &idReservation{session: ua.NewStringNodeID(1, "gone")}
	f.pruneLocked()
	_, ok := f.reserved["gone"]
	f.mu.Unlock()
	require.False(t, ok)
}
