// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// fileNS returns the namespace of the FileType tests and the Objects
// folder.
func fileNS(t *testing.T, s *Server) (*NodeNameSpace, *ua.NodeID) {
	t.Helper()
	ns := NewNodeNameSpace(s, "urn:test:files")
	return ns, ua.NewNumericNodeID(0, id.ObjectsFolder)
}

// methodCall calls the Method name of obj as the Call service finds it.
func methodCall(t *testing.T, s *Server, ctx context.Context, obj *ua.NodeID, name string, args ...any) ([]*ua.Variant, ua.StatusCode) {
	t.Helper()
	s.mu.Lock()
	h := s.methods[methodKey(obj, childPropertyID(obj, name))]
	s.mu.Unlock()
	if h == nil {
		return nil, ua.StatusBadMethodInvalid
	}
	vs := make([]*ua.Variant, len(args))
	for i, a := range args {
		if v, ok := a.(*ua.Variant); ok {
			vs[i] = v
			continue
		}
		vs[i] = ua.MustVariant(a)
	}
	return h(ctx, obj, childPropertyID(obj, name), vs)
}

func TestAddFile(t *testing.T) {
	s := newFileServer(t)
	ctx, _ := fileSession(s)
	ns, objects := fileNS(t, s)
	nid := ua.NewStringNodeID(ns.ID(), "log")
	name := &ua.QualifiedName{NamespaceIndex: ns.ID(), Name: "Log"}

	for _, tc := range []struct {
		name           string
		parent, nodeID *ua.NodeID
		browseName     *ua.QualifiedName
		want           ua.StatusCode
	}{
		{name: "no parent", nodeID: nid, browseName: name, want: ua.StatusBadInvalidArgument},
		{name: "no name", parent: objects, nodeID: nid, browseName: &ua.QualifiedName{}, want: ua.StatusBadInvalidArgument},
		{name: "unknown parent", parent: ua.NewNumericNodeID(0, 999999), nodeID: nid, browseName: name, want: ua.StatusBadParentNodeIDInvalid},
		{name: "unknown namespace", parent: objects, nodeID: ua.NewStringNodeID(99, "x"), browseName: name, want: ua.StatusBadNodeIDInvalid},
		{name: "exists", parent: objects, nodeID: objects, browseName: name, want: ua.StatusBadNodeIDExists},
	} {
		_, err := s.AddFile(tc.parent, tc.nodeID, tc.browseName, FileConfig{Backend: NewMemoryFile(nil)})
		assert.ErrorIs(t, err, tc.want, tc.name)
	}
	_, err := s.AddFile(objects, nid, name, FileConfig{})
	require.ErrorContains(t, err, "Backend is required")

	mf := NewMemoryFile([]byte("abc"))
	f, err := s.AddFile(objects, nid, name, FileConfig{Backend: mf, Writable: true, MimeType: "text/plain"})
	require.NoError(t, err)
	obj := s.Node(nid)
	require.NotNil(t, obj)
	require.Equal(t, ua.NodeClassObject, obj.NodeClass())
	// The children of FileType (OPC 10000-20 §4.2.1, Table 1).
	got := map[string]bool{}
	for _, c := range s.fileChildren(obj) {
		got[c.name] = true
	}
	for _, n := range []string{"Size", "Writable", "UserWritable", "OpenCount", "MimeType", "MaxByteStringLength", "LastModifiedTime", "Open", "Close", "Read", "Write", "GetPosition", "SetPosition"} {
		require.True(t, got[n], n)
	}
	// The Methods have the arguments of the declarations.
	open := s.Node(childPropertyID(nid, "Open"))
	require.NotNil(t, open)
	in := s.Node(childPropertyID(open.ID(), "InputArguments"))
	require.NotNil(t, in)
	require.Nil(t, s.Node(childPropertyID(childPropertyID(nid, "Close"), "OutputArguments")))
	size := s.Node(childPropertyID(nid, "Size"))
	require.Equal(t, uint64(3), size.Value().Value.Value())

	out, sc := methodCall(t, s, ctx, nid, "Open", uint8(fileModeRead))
	require.Equal(t, ua.StatusOK, sc)
	out, sc = methodCall(t, s, ctx, nid, "Read", out[0], int32(10))
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, []byte("abc"), out[0].Value())
	require.Equal(t, 1, f.OpenCount())
	require.Equal(t, uint16(1), s.Node(childPropertyID(nid, "OpenCount")).Value().Value.Value())

	// ServeFile on the Object: the handlers are replaced.
	f2, err := s.ServeFile(nid, FileConfig{Backend: NewMemoryFile([]byte("other"))})
	require.NoError(t, err)
	out, sc = methodCall(t, s, ctx, nid, "Open", uint8(fileModeRead))
	require.Equal(t, ua.StatusOK, sc)
	out, sc = methodCall(t, s, ctx, nid, "Read", out[0], int32(10))
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, []byte("other"), out[0].Value())
	require.Equal(t, uint64(5), size.Value().Value.Value())
	require.Equal(t, "text/plain", s.Node(childPropertyID(nid, "MimeType")).Value().Value.Value(), "left as it was")
	require.Equal(t, 1, f2.OpenCount())

	_, err = s.ServeFile(ua.NewStringNodeID(ns.ID(), "none"), FileConfig{Backend: mf})
	require.ErrorIs(t, err, ua.StatusBadNodeIDUnknown)
	_, err = s.ServeFile(objects, FileConfig{})
	require.ErrorContains(t, err, "Backend is required")
	// A reference to a node that does not exist is passed over.
	obj.AddRef(NewNode(ua.NewStringNodeID(ns.ID(), "dangling"), nil, nil, nil), RefType(id.HasComponent), true)
	_, err = s.ServeFile(nid, FileConfig{Backend: mf})
	require.NoError(t, err)
	_, err = s.ServeFile(objects, FileConfig{Backend: mf})
	require.ErrorIs(t, err, ua.StatusBadNodeIDUnknown, "no Method Open")
}

func TestFileDirectory(t *testing.T) {
	s := newFileServer(t)
	ctx, _ := fileSession(s)
	ns, objects := fileNS(t, s)
	md := NewMemoryDirectory()
	require.NoError(t, md.Mkdir("etc"))
	require.NoError(t, md.WriteFile("etc/a.conf", []byte("a=1")))
	require.NoError(t, md.WriteFile("README", []byte("hi")))
	require.NoError(t, md.WriteFile("bad\\name", nil), "a name the address space cannot have is left out")

	root := ua.NewStringNodeID(ns.ID(), "fs")
	_, err := s.AddFileDirectory(objects, root, &ua.QualifiedName{Name: "FileSystem"}, FileDirectoryConfig{})
	require.ErrorContains(t, err, "Backend is required")
	_, err = s.AddFileDirectory(objects, root, &ua.QualifiedName{Name: "FileSystem"}, FileDirectoryConfig{Backend: md, File: FileConfig{Modes: []ua.OpenFileMode{0x40}}})
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
	_, err = s.AddFileDirectory(nil, root, &ua.QualifiedName{Name: "FileSystem"}, FileDirectoryConfig{Backend: md})
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)

	var denied string
	d, err := s.AddFileDirectory(objects, root, &ua.QualifiedName{Name: "FileSystem"}, FileDirectoryConfig{
		Backend: md,
		File:    FileConfig{Writable: true},
		Authorize: func(_ context.Context, _ *MethodCaller, op, p string) ua.StatusCode {
			if op+" "+p == denied {
				return ua.StatusBadUserAccessDenied
			}
			return ua.StatusOK
		},
	})
	require.NoError(t, err)
	require.Equal(t, root, d.NodeID())
	etc, _, ok := d.Lookup("etc")
	require.True(t, ok)
	require.Equal(t, ua.NewStringNodeID(ns.ID(), "fs/etc"), etc)
	aID, aFile, ok := d.Lookup("etc/a.conf")
	require.True(t, ok)
	require.NotNil(t, aFile)
	_, _, ok = d.Lookup("bad\\name")
	require.False(t, ok)
	_, _, ok = d.Lookup("etc/none")
	require.False(t, ok)
	require.Equal(t, uint64(3), s.Node(childPropertyID(aID, "Size")).Value().Value.Value())

	// CreateDirectory (§4.3.3).
	out, sc := methodCall(t, s, ctx, root, "CreateDirectory", "var")
	require.Equal(t, ua.StatusOK, sc)
	varID := out[0].Value().(*ua.NodeID)
	require.Equal(t, ua.NewStringNodeID(ns.ID(), "fs/var"), varID)
	_, sc = methodCall(t, s, ctx, root, "CreateDirectory", "var")
	require.Equal(t, ua.StatusBadBrowseNameDuplicated, sc)
	_, sc = methodCall(t, s, ctx, root, "CreateDirectory", "README")
	require.Equal(t, ua.StatusBadBrowseNameDuplicated, sc, "a file of the name")
	for _, bad := range []string{"", ".", "..", "a/b", "a\\b", "a\x00"} {
		_, sc = methodCall(t, s, ctx, root, "CreateDirectory", bad)
		require.Equal(t, ua.StatusBadInvalidArgument, sc, "%q", bad)
	}
	denied = "CreateDirectory var/x"
	_, sc = methodCall(t, s, ctx, varID, "CreateDirectory", "x")
	require.Equal(t, ua.StatusBadUserAccessDenied, sc)
	_, sc = methodCall(t, s, ctx, root, "CreateDirectory")
	require.Equal(t, ua.StatusBadArgumentsMissing, sc)

	// CreateFile (§4.3.4): without open the handle is 0; with open the file
	// is opened with Read and Write.
	out, sc = methodCall(t, s, ctx, varID, "CreateFile", "log", false)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, uint32(0), out[1].Value())
	_, sc = methodCall(t, s, ctx, varID, "CreateFile", "log", false)
	require.Equal(t, ua.StatusBadBrowseNameDuplicated, sc)
	out, sc = methodCall(t, s, ctx, varID, "CreateFile", "new", true)
	require.Equal(t, ua.StatusOK, sc)
	newID, h := out[0].Value().(*ua.NodeID), out[1].Value().(uint32)
	require.NotZero(t, h)
	_, sc = methodCall(t, s, ctx, newID, "Write", h, []byte("data"))
	require.Equal(t, ua.StatusOK, sc)
	_, sc = methodCall(t, s, ctx, newID, "SetPosition", h, uint64(0))
	require.Equal(t, ua.StatusOK, sc)
	out, sc = methodCall(t, s, ctx, newID, "Read", h, int32(10))
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, []byte("data"), out[0].Value())
	_, sc = methodCall(t, s, ctx, varID, "CreateFile", "x")
	require.Equal(t, ua.StatusBadArgumentsMissing, sc)
	denied = "CreateFile var/y"
	_, sc = methodCall(t, s, ctx, varID, "CreateFile", "y", false)
	require.Equal(t, ua.StatusBadUserAccessDenied, sc)

	// Delete (§4.3.5): a file with an open handle "is locked and thus
	// cannot be deleted".
	_, sc = methodCall(t, s, ctx, varID, "Delete", newID)
	require.Equal(t, ua.StatusBadInvalidState, sc)
	_, sc = methodCall(t, s, ctx, root, "Delete", varID)
	require.Equal(t, ua.StatusBadInvalidState, sc, "a directory with a locked file below it")
	_, sc = methodCall(t, s, ctx, newID, "Close", h)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, "data", string(md.File("var/new").(*MemoryFile).Bytes()))
	_, sc = methodCall(t, s, ctx, root, "Delete", newID)
	require.Equal(t, ua.StatusBadNotFound, sc, "not organized by this object")
	_, sc = methodCall(t, s, ctx, root, "Delete", ua.NewTwoByteNodeID(0))
	require.Equal(t, ua.StatusBadNotFound, sc)
	_, sc = methodCall(t, s, ctx, root, "Delete", ua.MustVariant((*ua.NodeID)(nil)))
	require.Equal(t, ua.StatusBadNotFound, sc, "a nil NodeId")
	denied = "Delete var/new"
	_, sc = methodCall(t, s, ctx, varID, "Delete", newID)
	require.Equal(t, ua.StatusBadUserAccessDenied, sc)
	denied = ""
	_, sc = methodCall(t, s, ctx, varID, "Delete", newID)
	require.Equal(t, ua.StatusOK, sc)
	require.Nil(t, s.Node(newID))
	require.Nil(t, s.Node(childPropertyID(newID, "Open")))
	_, sc = methodCall(t, s, ctx, newID, "Open", uint8(1))
	require.Equal(t, ua.StatusBadMethodInvalid, sc, "the Methods are gone")
	_, _, ok = d.Lookup("var/new")
	require.False(t, ok)
	_, sc = methodCall(t, s, ctx, varID, "Delete", "x")
	require.Equal(t, ua.StatusBadTypeMismatch, sc)

	// MoveOrCopy (§4.3.6): a rename has the directory itself as target.
	logID, _, _ := d.Lookup("var/log")
	out, sc = methodCall(t, s, ctx, varID, "MoveOrCopy", logID, varID, false, "log.1")
	require.Equal(t, ua.StatusOK, sc)
	log1 := out[0].Value().(*ua.NodeID)
	require.Equal(t, ua.NewStringNodeID(ns.ID(), "fs/var/log.1"), log1)
	require.Nil(t, s.Node(logID))
	// A copy of a directory, with what is below it.
	out, sc = methodCall(t, s, ctx, root, "MoveOrCopy", etc, varID, true, "")
	require.Equal(t, ua.StatusOK, sc)
	etcCopy := out[0].Value().(*ua.NodeID)
	require.Equal(t, ua.NewStringNodeID(ns.ID(), "fs/var/etc"), etcCopy)
	_, f, ok := d.Lookup("var/etc/a.conf")
	require.True(t, ok)
	require.NotNil(t, f)
	require.NotNil(t, s.Node(etc), "the copied directory stays")
	// A move of a directory.
	out, sc = methodCall(t, s, ctx, varID, "MoveOrCopy", etcCopy, root, false, "etc2")
	require.Equal(t, ua.StatusOK, sc)
	_, _, ok = d.Lookup("etc2/a.conf")
	require.True(t, ok)
	_, _, ok = d.Lookup("var/etc")
	require.False(t, ok)
	etc2 := out[0].Value().(*ua.NodeID)

	_, sc = methodCall(t, s, ctx, root, "MoveOrCopy", etc2, root, false, "etc")
	require.Equal(t, ua.StatusBadBrowseNameDuplicated, sc)
	_, sc = methodCall(t, s, ctx, root, "MoveOrCopy", etc2, etc2, false, "")
	require.Equal(t, ua.StatusBadInvalidArgument, sc, "into itself")
	sub, _, _ := d.Lookup("etc2")
	_, sc = methodCall(t, s, ctx, root, "MoveOrCopy", etc, sub, false, "")
	require.Equal(t, ua.StatusOK, sc)
	movedEtc, _, _ := d.Lookup("etc2/etc")
	_, sc = methodCall(t, s, ctx, root, "MoveOrCopy", etc2, movedEtc, false, "")
	require.Equal(t, ua.StatusBadInvalidArgument, sc, "below itself")
	a2, _, _ := d.Lookup("etc2/a.conf")
	_, sc = methodCall(t, s, ctx, etc2, "MoveOrCopy", a2, a2, false, "")
	require.Equal(t, ua.StatusBadInvalidArgument, sc, "a target that is a file")
	_, sc = methodCall(t, s, ctx, etc2, "MoveOrCopy", a2, ua.NewTwoByteNodeID(0), false, "")
	require.Equal(t, ua.StatusBadInvalidArgument, sc, "a target outside the file system")
	_, sc = methodCall(t, s, ctx, root, "MoveOrCopy", a2, root, false, "")
	require.Equal(t, ua.StatusBadNotFound, sc, "not organized by this object")
	_, sc = methodCall(t, s, ctx, etc2, "MoveOrCopy", a2, root, false)
	require.Equal(t, ua.StatusBadArgumentsMissing, sc)
	_, sc = methodCall(t, s, ctx, etc2, "MoveOrCopy", a2, root, false, "bad/name")
	require.Equal(t, ua.StatusBadInvalidArgument, sc)
	// A locked file is not moved or copied.
	_, af, _ := d.Lookup("etc2/a.conf")
	ah, sc := af.Open(ctx, fileModeRead)
	require.Equal(t, ua.StatusOK, sc)
	_, sc = methodCall(t, s, ctx, etc2, "MoveOrCopy", a2, root, true, "")
	require.Equal(t, ua.StatusBadInvalidState, sc)
	require.Equal(t, ua.StatusOK, af.Close(ctx, ah))
	denied = "MoveOrCopy a.conf"
	_, sc = methodCall(t, s, ctx, etc2, "MoveOrCopy", a2, root, true, "")
	require.Equal(t, ua.StatusBadUserAccessDenied, sc)
	denied = ""
	out, sc = methodCall(t, s, ctx, etc2, "MoveOrCopy", a2, root, true, "")
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, ua.NewStringNodeID(ns.ID(), "fs/a.conf"), out[0].Value())
	require.Equal(t, "a=1", string(md.File("a.conf").(*MemoryFile).Bytes()))

	// The handles of a file are closed when it is deleted with its
	// directory; the root itself is not organized by itself.
	_, sc = methodCall(t, s, ctx, root, "Delete", root)
	require.Equal(t, ua.StatusBadNotFound, sc)
	_, sc = methodCall(t, s, ctx, root, "Delete", etc2)
	require.Equal(t, ua.StatusOK, sc)
	_, _, ok = d.Lookup("etc2/etc/a.conf")
	require.False(t, ok)
	es, err := md.ReadDir("")
	require.NoError(t, err)
	var names []string
	for _, e := range es {
		names = append(names, e.Name)
	}
	require.Equal(t, []string{"README", "a.conf", "bad\\name", "var"}, names)
}

// faultyDir is a DirectoryBackend whose operations fail as set.
type faultyDir struct {
	*MemoryDirectory
	readDirErr, mkdirErr, createErr, removeErr, renameErr, copyErr error
	nilFile                                                        bool
}

func (f *faultyDir) ReadDir(p string) ([]DirEntry, error) {
	if f.readDirErr != nil {
		return nil, f.readDirErr
	}
	return f.MemoryDirectory.ReadDir(p)
}

func (f *faultyDir) Mkdir(p string) error {
	if f.mkdirErr != nil {
		return f.mkdirErr
	}
	return f.MemoryDirectory.Mkdir(p)
}

func (f *faultyDir) CreateFile(p string) error {
	if f.createErr != nil {
		return f.createErr
	}
	return f.MemoryDirectory.CreateFile(p)
}

func (f *faultyDir) File(p string) FileBackend {
	if f.nilFile {
		return nil
	}
	return f.MemoryDirectory.File(p)
}

func (f *faultyDir) Remove(p string) error {
	if f.removeErr != nil {
		return f.removeErr
	}
	return f.MemoryDirectory.Remove(p)
}

func (f *faultyDir) Rename(from, to string) error {
	if f.renameErr != nil {
		return f.renameErr
	}
	return f.MemoryDirectory.Rename(from, to)
}

func (f *faultyDir) Copy(from, to string) error {
	if f.copyErr != nil {
		return f.copyErr
	}
	return f.MemoryDirectory.Copy(from, to)
}

func TestFileDirectoryBackendErrors(t *testing.T) {
	s := newFileServer(t)
	ctx, _ := fileSession(s)
	ns, objects := fileNS(t, s)
	b := &faultyDir{MemoryDirectory: NewMemoryDirectory(), readDirErr: errors.New("io")}
	root := ua.NewStringNodeID(ns.ID(), "fs")
	name := &ua.QualifiedName{Name: "FileSystem"}
	_, err := s.AddFileDirectory(objects, root, name, FileDirectoryConfig{Backend: b})
	require.ErrorContains(t, err, "io")
	require.Nil(t, s.Node(root), "removed again")
	b.readDirErr = nil
	require.NoError(t, b.MemoryDirectory.Mkdir("d"))
	require.NoError(t, b.WriteFile("d/f", nil))
	b.nilFile = true
	_, err = s.AddFileDirectory(objects, root, name, FileDirectoryConfig{Backend: b})
	require.ErrorContains(t, err, "Backend is required")
	require.Nil(t, s.Node(root))
	b.nilFile = false
	d, err := s.AddFileDirectory(objects, root, name, FileDirectoryConfig{Backend: b})
	require.NoError(t, err)
	dID, _, _ := d.Lookup("d")
	fID, _, _ := d.Lookup("d/f")

	b.mkdirErr = fs.ErrExist
	_, sc := methodCall(t, s, ctx, root, "CreateDirectory", "x")
	require.Equal(t, ua.StatusBadBrowseNameDuplicated, sc)
	b.mkdirErr = fs.ErrNotExist
	_, sc = methodCall(t, s, ctx, root, "CreateDirectory", "x")
	require.Equal(t, ua.StatusBadNotFound, sc)
	b.mkdirErr = ua.StatusBadOutOfMemory
	_, sc = methodCall(t, s, ctx, root, "CreateDirectory", "x")
	require.Equal(t, ua.StatusBadOutOfMemory, sc)
	b.mkdirErr = errors.New("io")
	_, sc = methodCall(t, s, ctx, root, "CreateDirectory", "x")
	require.Equal(t, ua.StatusBadUnexpectedError, sc)

	b.createErr = errors.New("io")
	_, sc = methodCall(t, s, ctx, root, "CreateFile", "x", false)
	require.Equal(t, ua.StatusBadUnexpectedError, sc)
	b.createErr = nil
	b.nilFile = true
	_, sc = methodCall(t, s, ctx, root, "CreateFile", "x", false)
	require.Equal(t, ua.StatusBadUnexpectedError, sc)
	b.nilFile = false

	// A file whose Open fails stays created.
	ro, err := s.AddFileDirectory(objects, ua.NewStringNodeID(ns.ID(), "ro"), &ua.QualifiedName{Name: "RO"}, FileDirectoryConfig{Backend: NewMemoryDirectory()})
	require.NoError(t, err)
	_, sc = methodCall(t, s, ctx, ro.NodeID(), "CreateFile", "x", true)
	require.Equal(t, ua.StatusBadNotWritable, sc)
	_, _, ok := ro.Lookup("x")
	require.True(t, ok)

	b.removeErr = errors.New("io")
	_, sc = methodCall(t, s, ctx, dID, "Delete", fID)
	require.Equal(t, ua.StatusBadUnexpectedError, sc)
	b.renameErr = fs.ErrExist
	_, sc = methodCall(t, s, ctx, dID, "MoveOrCopy", fID, root, false, "")
	require.Equal(t, ua.StatusBadBrowseNameDuplicated, sc)
	b.copyErr = errors.New("io")
	_, sc = methodCall(t, s, ctx, dID, "MoveOrCopy", fID, root, true, "")
	require.Equal(t, ua.StatusBadUnexpectedError, sc)
	b.copyErr = nil
	b.nilFile = true
	_, sc = methodCall(t, s, ctx, dID, "MoveOrCopy", fID, root, true, "")
	require.Equal(t, ua.StatusBadUnexpectedError, sc)
	b.nilFile = false
	// A copied directory whose content cannot be read.
	b.readDirErr = errors.New("io")
	_, sc = methodCall(t, s, ctx, root, "MoveOrCopy", dID, root, true, "d2")
	require.Equal(t, ua.StatusBadUnexpectedError, sc)
}

func TestMemoryDirectory(t *testing.T) {
	m := NewMemoryDirectory()
	require.ErrorIs(t, m.Mkdir("a/b"), fs.ErrNotExist)
	require.NoError(t, m.Mkdir("a"))
	require.ErrorIs(t, m.Mkdir("a"), fs.ErrExist)
	require.NoError(t, m.WriteFile("a/f", []byte("x")))
	require.ErrorIs(t, m.WriteFile("a/f", nil), fs.ErrExist)
	require.ErrorIs(t, m.CreateFile("a"), fs.ErrExist)
	_, err := m.ReadDir("none")
	require.ErrorIs(t, err, fs.ErrNotExist)
	_, err = m.ReadDir("a/f")
	require.ErrorIs(t, err, fs.ErrNotExist, "a file is not a directory")
	require.ErrorIs(t, m.Remove(""), fs.ErrNotExist)
	require.ErrorIs(t, m.Remove("a/none"), fs.ErrNotExist)
	require.ErrorIs(t, m.Rename("none", "b"), fs.ErrNotExist)
	require.ErrorIs(t, m.Rename("a/f", "none/f"), fs.ErrNotExist)
	require.ErrorIs(t, m.Copy("none", "b"), fs.ErrNotExist)
	require.ErrorIs(t, m.Copy("a/f", "a/f"), fs.ErrExist)

	_, err = m.File("none/f").Open(context.Background(), fileModeRead)
	require.ErrorIs(t, err, ua.StatusBadNotFound)
	_, err = m.File("a/none").Size()
	require.ErrorIs(t, err, ua.StatusBadNotFound)

	// A copy of a directory is a deep copy.
	require.NoError(t, m.Mkdir("a/sub"))
	require.NoError(t, m.Copy("a", "c"))
	m.File("c/f").(*MemoryFile).SetBytes([]byte("changed"))
	require.Equal(t, "x", string(m.File("a/f").(*MemoryFile).Bytes()))
	es, err := m.ReadDir("c")
	require.NoError(t, err)
	require.Equal(t, []DirEntry{{Name: "f"}, {Name: "sub", Dir: true}}, es)
	require.NoError(t, m.Rename("c/sub", "sub"))
	require.NoError(t, m.Remove("c"))
}

func TestOSDirectory(t *testing.T) {
	_, err := NewOSDirectory(filepath.Join(t.TempDir(), "none"))
	require.Error(t, err)
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, "etc"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "etc", "a"), []byte("a=1"), 0o600))
	require.NoError(t, os.Symlink(filepath.Join(dir, "etc", "a"), filepath.Join(dir, "link")))
	d, err := NewOSDirectory(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = d.Close() })

	es, err := d.ReadDir("")
	require.NoError(t, err)
	require.Equal(t, []DirEntry{{Name: "etc", Dir: true}}, es, "a symbolic link is left out")
	_, err = d.ReadDir("none")
	require.ErrorIs(t, err, fs.ErrNotExist)

	require.NoError(t, d.Mkdir("var"))
	require.ErrorIs(t, d.Mkdir("var"), fs.ErrExist)
	require.NoError(t, d.CreateFile("var/log"))
	require.ErrorIs(t, d.CreateFile("var/log"), fs.ErrExist)
	fi, err := os.Stat(filepath.Join(dir, "var", "log"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	d.Perm = 0o640
	require.NoError(t, d.CreateFile("var/log2"))
	fi, err = os.Stat(filepath.Join(dir, "var", "log2"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o640), fi.Mode().Perm())
	require.Error(t, d.CreateFile("../escape"), "no path leaves the root")

	// The files of the directory.
	s := newFileServer(t)
	ctx, _ := fileSession(s)
	fb := d.File("etc/a")
	f := newTestFile(t, s, FileConfig{Backend: fb, Writable: true})
	n, err := fb.Size()
	require.NoError(t, err)
	require.Equal(t, uint64(3), n)
	mt, err := fb.(FileModTimer).ModTime()
	require.NoError(t, err)
	require.False(t, mt.IsZero())
	h, sc := f.Open(ctx, fileModeRead|fileModeWrite|fileModeAppend)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, ua.StatusOK, f.Write(ctx, h, []byte(";b=2")))
	require.Equal(t, ua.StatusOK, f.Close(ctx, h))
	b, err := os.ReadFile(filepath.Join(dir, "etc", "a"))
	require.NoError(t, err)
	require.Equal(t, "a=1;b=2", string(b))
	missing := d.File("etc/none")
	_, err = missing.Open(context.Background(), fileModeRead)
	require.ErrorIs(t, err, ua.StatusBadNotFound)
	_, err = missing.Size()
	require.ErrorIs(t, err, ua.StatusBadNotFound)
	_, err = missing.(FileModTimer).ModTime()
	require.ErrorIs(t, err, ua.StatusBadNotFound)

	// Copy, Rename and Remove.
	require.NoError(t, d.Copy("etc", "etc2"))
	b, err = os.ReadFile(filepath.Join(dir, "etc2", "a"))
	require.NoError(t, err)
	require.Equal(t, "a=1;b=2", string(b))
	require.ErrorIs(t, d.Copy("etc", "etc2"), fs.ErrExist)
	require.ErrorIs(t, d.Copy("none", "x"), fs.ErrNotExist)
	require.ErrorIs(t, d.Copy("etc", "none/x"), fs.ErrNotExist)
	require.ErrorIs(t, d.Copy("etc/a", "none/x"), fs.ErrNotExist)
	require.NoError(t, d.Rename("etc2", "etc3"))
	require.ErrorIs(t, d.Rename("etc3", "etc"), fs.ErrExist)
	require.NoError(t, d.Remove("etc3"))
	require.ErrorIs(t, d.Remove("etc3"), fs.ErrNotExist)
	_, err = os.Stat(filepath.Join(dir, "etc3"))
	require.ErrorIs(t, err, fs.ErrNotExist)

	// What cannot be read is not copied (as root everything can be).
	require.NoError(t, d.Mkdir("locked"))
	require.NoError(t, d.CreateFile("locked/f"))
	require.NoError(t, os.Chmod(filepath.Join(dir, "locked", "f"), 0))
	errFile := d.Copy("locked", "locked2")
	require.NoError(t, os.Chmod(filepath.Join(dir, "locked", "f"), 0o600))
	require.NoError(t, os.Chmod(filepath.Join(dir, "locked"), 0o300))
	errDir := d.Copy("locked", "locked3")
	require.NoError(t, os.Chmod(filepath.Join(dir, "locked"), 0o700))
	if os.Geteuid() == 0 {
		require.NoError(t, errFile)
		require.NoError(t, errDir)
	} else {
		require.ErrorIs(t, errFile, fs.ErrPermission)
		require.ErrorIs(t, errDir, fs.ErrPermission)
	}

	// A FileDirectory on it.
	ns, objects := fileNS(t, s)
	fd, err := s.AddFileDirectory(objects, ua.NewStringNodeID(ns.ID(), "os"), &ua.QualifiedName{Name: "FileSystem"}, FileDirectoryConfig{Backend: d})
	require.NoError(t, err)
	_, af, ok := fd.Lookup("etc/a")
	require.True(t, ok)
	require.Equal(t, uint64(7), af.Property("Size")().Value.Value())
}
