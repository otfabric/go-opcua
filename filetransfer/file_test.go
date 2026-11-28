// SPDX-License-Identifier: MIT

package filetransfer_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/filetransfer"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uamethod"
)

type env struct {
	srv *server.Server
	ns  *server.NodeNameSpace
	url string
	c   *opcua.Client
}

func newEnv(t *testing.T) *env {
	t.Helper()
	srv, url := testutil.NewTestServer(t)
	ns := server.NewNodeNameSpace(srv, "urn:test:filetransfer")
	return &env{srv: srv, ns: ns, url: url, c: testutil.NewTestClient(t, url)}
}

func (e *env) addFile(t *testing.T, name string, cfg server.FileConfig) (*ua.NodeID, *server.FileObject) {
	t.Helper()
	nid := ua.NewStringNodeID(e.ns.ID(), name)
	f, err := e.srv.AddFile(ua.NewNumericNodeID(0, id.ObjectsFolder), nid, &ua.QualifiedName{NamespaceIndex: e.ns.ID(), Name: name}, cfg)
	require.NoError(t, err)
	return nid, f
}

func TestFile(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	mf := server.NewMemoryFile([]byte("hello world"))
	nid, sf := e.addFile(t, "f", server.FileConfig{Backend: mf, Writable: true, MimeType: "text/plain", MaxByteStringLength: 4})

	o := filetransfer.NewObject(e.c, nid)
	o.Chunk = 3
	require.Equal(t, nid, o.NodeID())

	info, err := o.Info(ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(11), info.Size)
	require.True(t, info.Writable)
	require.True(t, info.UserWritable)
	require.Equal(t, uint16(0), info.OpenCount)
	require.Equal(t, "text/plain", info.MimeType)
	require.Equal(t, uint32(4), info.MaxByteStringLength)
	require.False(t, info.LastModifiedTime.IsZero())

	b, err := o.ReadAll(ctx, 0)
	require.NoError(t, err)
	require.Equal(t, "hello world", string(b))
	_, err = o.ReadAll(ctx, 5)
	require.ErrorContains(t, err, "filetransfer: the file exceeds 5 bytes")
	require.Equal(t, 0, sf.OpenCount(), "closed after the error")

	require.NoError(t, o.WriteAll(ctx, []byte("replaced content")))
	require.Equal(t, "replaced content", string(mf.Bytes()))

	f, err := o.Open(ctx, ua.OpenFileModeRead|ua.OpenFileModeWrite)
	require.NoError(t, err)
	require.NotZero(t, f.Handle())
	require.Equal(t, ua.OpenFileModeRead|ua.OpenFileModeWrite, f.Mode())
	chunk, err := f.Read(ctx, 100)
	require.NoError(t, err)
	require.Equal(t, "repl", string(chunk), "at most MaxByteStringLength")
	pos, err := f.Position(ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(4), pos)
	require.NoError(t, f.SetPosition(ctx, 0))
	_, err = io.Copy(f.Writer(ctx), bytes.NewReader([]byte("REPL")))
	require.NoError(t, err)
	require.NoError(t, f.SetPosition(ctx, 0))
	all, err := io.ReadAll(f.Reader(ctx))
	require.NoError(t, err)
	require.Equal(t, "REPLaced content", string(all))
	_, err = f.Read(ctx, 1)
	require.ErrorIs(t, err, io.EOF)
	_, err = f.Read(ctx, 0)
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
	var ce *uamethod.CallError
	require.ErrorAs(t, err, &ce)
	n, err := f.Reader(ctx).Read(nil)
	require.NoError(t, err)
	require.Zero(t, n)
	require.NoError(t, f.Close(ctx))
	require.NoError(t, f.Close(ctx), "closing again does nothing")
	require.Equal(t, "REPLaced content", string(mf.Bytes()))

	// Errors of the server.
	w, err := o.Open(ctx, ua.OpenFileModeWrite)
	require.NoError(t, err)
	_, err = o.Open(ctx, ua.OpenFileModeRead)
	require.ErrorIs(t, err, ua.StatusBadNotReadable)
	_, err = o.ReadAll(ctx, 0)
	require.ErrorIs(t, err, ua.StatusBadNotReadable)
	require.ErrorIs(t, o.WriteAll(ctx, nil), ua.StatusBadNotWritable)
	_, err = w.Read(ctx, 1)
	require.ErrorIs(t, err, ua.StatusBadInvalidState)
	_, err = io.ReadAll(w.Reader(ctx))
	require.ErrorIs(t, err, ua.StatusBadInvalidState)
	require.NoError(t, w.Close(ctx))
	_, err = w.Position(ctx)
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument, "a closed handle")
	require.ErrorIs(t, w.SetPosition(ctx, 0), ua.StatusBadInvalidArgument)
	require.ErrorIs(t, w.Write(ctx, []byte("x")), ua.StatusBadInvalidArgument)
	_, err = w.Writer(ctx).Write([]byte("x"))
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
	_, err = o.Open(ctx, 0x100)
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
	_, err = o.Open(ctx, 0x10)
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
	require.Error(t, o.Attach(77, ua.OpenFileModeRead).Close(ctx))
	_, err = o.Attach(77, ua.OpenFileModeRead).ReadAllAndClose(ctx, 0)
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)

	// A file that is not writable, and the ReadAll of a read-only file.
	ro, _ := e.addFile(t, "ro", server.FileConfig{Backend: server.NewMemoryFile([]byte("x"))})
	ro2 := filetransfer.NewObject(e.c, ro)
	require.ErrorIs(t, ro2.WriteAll(ctx, []byte("y")), ua.StatusBadNotWritable)
	info, err = ro2.Info(ctx)
	require.NoError(t, err)
	require.False(t, info.Writable)
	require.Empty(t, info.MimeType)

	// A failing Write closes the handle in WriteAll.
	small := server.NewMemoryFile(nil)
	small.MaxSize = 2
	sm, smf := e.addFile(t, "small", server.FileConfig{Backend: small, Writable: true})
	require.ErrorIs(t, filetransfer.NewObject(e.c, sm).WriteAll(ctx, []byte("123")), ua.StatusBadResourceUnavailable)
	require.Equal(t, 0, smf.OpenCount())
}

// TestFileOfType: an Object of a subtype, or one whose Methods cannot be
// browsed, is called with the declarations of FileType, which the server
// maps to the Methods of the Object (Part 4 §5.12.2.2 in 1.05.06).
func TestFileOfType(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	nid, _ := e.addFile(t, "f", server.FileConfig{Backend: server.NewMemoryFile([]byte("abc"))})

	// A client that is closed fails to browse, and to call.
	c := testutil.NewTestClient(t, e.url)
	o := filetransfer.NewObject(c, nid)
	require.NoError(t, c.Close(ctx))
	_, err := o.ReadAll(ctx, 0)
	require.Error(t, err)
	_, err = o.Info(ctx)
	require.ErrorContains(t, err, "filetransfer: browsing")

	// An Object without the Properties.
	_, err = filetransfer.NewObject(e.c, ua.NewNumericNodeID(0, id.ObjectsFolder)).Info(ctx)
	require.ErrorIs(t, err, ua.StatusBadNotFound)
	_, err = filetransfer.ObjectFunc(nil).Info(ctx)
	require.ErrorContains(t, err, "needs an Object of NewObject")

	// The declarations: an Object that has no Methods of the names.
	_, err = filetransfer.NewObject(e.c, ua.NewNumericNodeID(0, id.ObjectsFolder)).Open(ctx, ua.OpenFileModeRead)
	require.Error(t, err)
}

// fakeCall is a CallFunc that records the calls.
type fakeCall struct {
	calls []string
	out   map[string][]*ua.Variant
	err   map[string]error
}

func (f *fakeCall) call(_ context.Context, m *uamethod.Method, _ []*ua.Variant) ([]*ua.Variant, error) {
	f.calls = append(f.calls, m.Name)
	return f.out[m.Name], f.err[m.Name]
}

func TestObjectFunc(t *testing.T) {
	ctx := context.Background()
	fc := &fakeCall{
		out: map[string][]*ua.Variant{
			"Open": {ua.MustVariant(uint32(5))},
			"Read": {ua.MustVariant("not bytes")},
		},
		err: map[string]error{},
	}
	o := filetransfer.ObjectFunc(fc.call)
	require.Nil(t, o.NodeID())
	f, err := o.Open(ctx, ua.OpenFileModeRead)
	require.NoError(t, err)
	require.Equal(t, uint32(5), f.Handle())
	_, err = f.Read(ctx, 1)
	require.ErrorIs(t, err, ua.StatusBadTypeMismatch, "outputs are checked")
	_, err = f.Position(ctx)
	require.ErrorIs(t, err, ua.StatusBadArgumentsMissing)
	fc.out["Open"] = []*ua.Variant{ua.MustVariant("h")}
	_, err = o.Open(ctx, ua.OpenFileModeRead)
	require.ErrorIs(t, err, ua.StatusBadTypeMismatch)

	// A failing Write and Close are both reported.
	fc.out["Open"] = []*ua.Variant{ua.MustVariant(uint32(5))}
	fc.err["Write"] = errors.New("write failed")
	fc.err["Close"] = errors.New("close failed")
	err = o.WriteAll(ctx, []byte("x"))
	require.ErrorContains(t, err, "write failed")
	require.ErrorContains(t, err, "close failed")
	// A failing Close after reading.
	fc.out["Read"] = []*ua.Variant{ua.MustVariant([]byte{})}
	_, err = o.ReadAll(ctx, 0)
	require.ErrorContains(t, err, "close failed")
	fc.err["Open"] = errors.New("open failed")
	_, err = o.ReadAll(ctx, 0)
	require.ErrorContains(t, err, "open failed")
	require.ErrorContains(t, o.WriteAll(ctx, nil), "open failed")

	// The default chunk, and one that is too large for a Read.
	fc.err = map[string]error{}
	fc.calls = nil
	require.NoError(t, o.WriteAll(ctx, make([]byte, filetransfer.DefaultChunk+1)))
	require.Equal(t, []string{"Open", "Write", "Write", "Close"}, fc.calls)
	o.Chunk = 1 << 40
	fc.calls = nil
	_, err = o.ReadAll(ctx, 0)
	require.NoError(t, err)
	require.Equal(t, []string{"Open", "Read", "Close"}, fc.calls)

	// A server that returns more than asked for is read on.
	fc.out["Read"] = []*ua.Variant{ua.MustVariant([]byte("abcdef"))}
	r := o.Attach(1, ua.OpenFileModeRead).Reader(ctx)
	p := make([]byte, 4)
	n, err := r.Read(p)
	require.NoError(t, err)
	require.Equal(t, "abcd", string(p[:n]))
	n, err = r.Read(p)
	require.NoError(t, err)
	require.Equal(t, "ef", string(p[:n]))
}

func TestDirectory(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	md := server.NewMemoryDirectory()
	require.NoError(t, md.WriteFile("README", []byte("read me")))
	root := ua.NewStringNodeID(e.ns.ID(), "fs")
	_, err := e.srv.AddFileDirectory(ua.NewNumericNodeID(0, id.ObjectsFolder), root, &ua.QualifiedName{Name: "FileSystem"}, server.FileDirectoryConfig{
		Backend: md,
		File:    server.FileConfig{Writable: true},
	})
	require.NoError(t, err)

	d := filetransfer.NewDirectory(e.c, root)
	require.Equal(t, root, d.NodeID())
	es, err := d.Entries(ctx)
	require.NoError(t, err)
	require.Equal(t, []filetransfer.Entry{{NodeID: ua.NewStringNodeID(e.ns.ID(), "fs/README"), Name: "README"}}, es)

	logs, err := d.CreateDirectory(ctx, "logs")
	require.NoError(t, err)
	_, err = d.CreateDirectory(ctx, "logs")
	require.ErrorIs(t, err, ua.StatusBadBrowseNameDuplicated)
	ld := d.Directory(logs)
	o, f, err := ld.CreateFile(ctx, "today", true)
	require.NoError(t, err)
	require.NotNil(t, f)
	require.Equal(t, ua.OpenFileModeRead|ua.OpenFileModeWrite, f.Mode())
	require.NoError(t, f.Write(ctx, []byte("entry")))
	require.NoError(t, f.Close(ctx))
	b, err := o.ReadAll(ctx, 0)
	require.NoError(t, err)
	require.Equal(t, "entry", string(b))
	o2, f2, err := ld.CreateFile(ctx, "empty", false)
	require.NoError(t, err)
	require.Nil(t, f2)
	_, _, err = ld.CreateFile(ctx, "empty", false)
	require.ErrorIs(t, err, ua.StatusBadBrowseNameDuplicated)

	es, err = d.Entries(ctx)
	require.NoError(t, err)
	require.Len(t, es, 2)
	for _, x := range es {
		if x.Name == "logs" {
			require.True(t, x.Dir)
			require.Equal(t, logs, x.NodeID)
		}
	}

	moved, err := ld.MoveOrCopy(ctx, o.NodeID(), root, true, "copy")
	require.NoError(t, err)
	b, err = d.File(moved).ReadAll(ctx, 0)
	require.NoError(t, err)
	require.Equal(t, "entry", string(b))
	_, err = ld.MoveOrCopy(ctx, o.NodeID(), root, false, "copy")
	require.ErrorIs(t, err, ua.StatusBadBrowseNameDuplicated)
	require.NoError(t, ld.Delete(ctx, o2.NodeID()))
	require.ErrorIs(t, ld.Delete(ctx, o2.NodeID()), ua.StatusBadNotFound)
	require.NoError(t, d.Delete(ctx, logs))
	es, err = d.Entries(ctx)
	require.NoError(t, err)
	require.Len(t, es, 2)

	// Opening a created file can fail (a read-only file system), and a
	// directory that is not one has no Methods.
	_, err = e.srv.AddFileDirectory(ua.NewNumericNodeID(0, id.ObjectsFolder), ua.NewStringNodeID(e.ns.ID(), "ro"), &ua.QualifiedName{Name: "RO"}, server.FileDirectoryConfig{Backend: server.NewMemoryDirectory()})
	require.NoError(t, err)
	_, _, err = filetransfer.NewDirectory(e.c, ua.NewStringNodeID(e.ns.ID(), "ro")).CreateFile(ctx, "x", true)
	require.ErrorIs(t, err, ua.StatusBadNotWritable)
	objects := filetransfer.NewDirectory(e.c, ua.NewNumericNodeID(0, id.ObjectsFolder))
	_, err = objects.CreateDirectory(ctx, "x")
	require.Error(t, err)
	_, _, err = objects.CreateFile(ctx, "x", false)
	require.Error(t, err)
	_, err = objects.MoveOrCopy(ctx, root, root, false, "")
	require.Error(t, err)
	es, err = objects.Entries(ctx)
	require.NoError(t, err)
	for _, x := range es {
		require.NotEqual(t, "Server", x.Name, "an Object that is not a directory or a file is left out")
	}

	// A closed client.
	c := testutil.NewTestClient(t, e.url)
	require.NoError(t, c.Close(ctx))
	_, err = filetransfer.NewDirectory(c, root).Entries(ctx)
	require.ErrorContains(t, err, "filetransfer: browsing")
}
