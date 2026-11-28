// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uamethod"
)

// FileDirectoryConfig configures a [FileDirectory].
type FileDirectoryConfig struct {
	// Backend is the storage of the directories and files; it is
	// required.
	Backend DirectoryBackend

	// File configures the FileObjects of the files; its Backend is
	// ignored (each file has the backend DirectoryBackend.File returns).
	File FileConfig

	// Authorize, if set, decides whether the caller may call a Method of a
	// directory: op is the BrowseName of the Method (CreateDirectory,
	// CreateFile, Delete, MoveOrCopy) and path the path of the directory or
	// file it creates or changes. ua.StatusOK allows the call; OPC 10000-20
	// §4.3.3 to §4.3.6 give Bad_UserAccessDenied for a refused one. nil
	// allows every call.
	Authorize func(ctx context.Context, caller *MethodCaller, op, path string) ua.StatusCode
}

// FileDirectory is a file system of OPC 10000-20 §4.3: a FileDirectoryType
// Object whose subdirectories (FileDirectoryType Objects) and files
// (FileType Objects, each a [FileObject]) it Organizes, with the Methods
// CreateDirectory, CreateFile, Delete and MoveOrCopy on each directory.
// [Server.AddFileDirectory] adds one.
//
// The children of a directory have string NodeIds in the namespace of the
// root: "<root>/<path>" where <root> is the identifier of the root (see
// [Node.SetMethodArguments]) and <path> the slash-separated names; a moved
// object gets the NodeId of its new path, which MoveOrCopy returns ("Even
// if the Object is moved, the Server may return a new NodeId", §4.3.6).
type FileDirectory struct {
	s    *Server
	cfg  FileDirectoryConfig
	ns   NameSpace
	base string // the identifier of the root

	mu   sync.Mutex
	root *dirEntry
	byID map[string]*dirEntry
}

// dirEntry is a directory or a file of a FileDirectory.
type dirEntry struct {
	path     string
	dir      bool
	parent   *dirEntry
	children map[string]*dirEntry // of a directory
	file     *FileObject          // of a file
	nodes    []*ua.NodeID         // the nodes of the entry, the Object first
	methods  []*ua.NodeID         // the Methods registered on the Object
}

func (e *dirEntry) id() *ua.NodeID { return e.nodes[0] }

func (e *dirEntry) name() string { _, n := splitPath(e.path); return n }

// dirMethods are the Methods of FileDirectoryType.
var dirMethods = []*uamethod.Method{
	uamethod.FileDirectoryTypeCreateDirectory, uamethod.FileDirectoryTypeCreateFile,
	uamethod.FileDirectoryTypeDelete, uamethod.FileDirectoryTypeMoveOrCopy,
}

// AddFileDirectory adds the root of a file system, a FileDirectoryType
// Object (OPC 10000-20 §4.3.1) with the NodeId nodeID and the BrowseName
// name, as a component of parent, with the directories and files the
// backend has. "The Object representing the root of a file directory
// structure shall have the BrowseName FileSystem" (§4.3.2); a directory
// that is not the root of a file system may have another name.
func (s *Server) AddFileDirectory(parent, nodeID *ua.NodeID, name *ua.QualifiedName, cfg FileDirectoryConfig) (*FileDirectory, error) {
	if cfg.Backend == nil {
		return nil, errors.New("server: AddFileDirectory: Backend is required")
	}
	for _, m := range cfg.File.Modes {
		if sc := validFileMode(m); sc != ua.StatusOK {
			return nil, fmt.Errorf("server: AddFileDirectory: mode %#x is not a mode of OPC 10000-20 §4.2.2: %w", uint32(m), sc)
		}
	}
	p, ns, err := s.newChildObject("AddFileDirectory", parent, nodeID, name)
	if err != nil {
		return nil, err
	}
	d := &FileDirectory{s: s, cfg: cfg, ns: ns, base: childIdentifier(nodeID), byID: map[string]*dirEntry{}}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.root = &dirEntry{dir: true, children: map[string]*dirEntry{}}
	d.addDirNodes(d.root, p, nodeID, name, id.HasComponent)
	d.byID[nodeID.String()] = d.root
	if err := d.loadLocked(d.root); err != nil {
		d.removeLocked(d.root)
		return nil, fmt.Errorf("server: AddFileDirectory: %w", err)
	}
	return d, nil
}

// NodeID returns the NodeId of the root.
func (d *FileDirectory) NodeID() *ua.NodeID { return d.root.id() }

// Lookup returns the NodeId of the directory or file of a path ("" is the
// root) and, for a file, its FileObject.
func (d *FileDirectory) Lookup(p string) (*ua.NodeID, *FileObject, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	e := d.root
	if p != "" {
		for _, name := range strings.Split(p, "/") {
			if e = e.children[name]; e == nil {
				return nil, nil, false
			}
		}
	}
	return e.id(), e.file, true
}

// loadLocked adds the nodes of what the backend has below a directory.
func (d *FileDirectory) loadLocked(dir *dirEntry) error {
	es, err := d.cfg.Backend.ReadDir(dir.path)
	if err != nil {
		return err
	}
	for _, e := range es {
		if validName(e.Name) != ua.StatusOK {
			continue // a name the address space cannot have
		}
		c, err := d.addEntryLocked(dir, e.Name, e.Dir)
		if err != nil {
			return err
		}
		if e.Dir {
			if err := d.loadLocked(c); err != nil {
				return err
			}
		}
	}
	return nil
}

// childPath returns the path of the entry name of a directory.
func childPath(dir *dirEntry, name string) string {
	if dir.path == "" {
		return name
	}
	return dir.path + "/" + name
}

// addEntryLocked adds the nodes of a directory or file of the backend.
func (d *FileDirectory) addEntryLocked(dir *dirEntry, name string, isDir bool) (*dirEntry, error) {
	if isDir {
		return d.addDirLocked(dir, name), nil
	}
	return d.addFileLocked(dir, name)
}

// newEntry returns the entry name of dir, with its NodeId and BrowseName.
func (d *FileDirectory) newEntry(dir *dirEntry, name string, isDir bool) (*dirEntry, *ua.NodeID, *ua.QualifiedName) {
	e := &dirEntry{path: childPath(dir, name), dir: isDir, parent: dir}
	nid := ua.NewStringNodeID(dir.id().Namespace(), d.base+"/"+e.path)
	return e, nid, &ua.QualifiedName{NamespaceIndex: dir.id().Namespace(), Name: name}
}

// linkLocked adds e to its directory.
func (d *FileDirectory) linkLocked(e *dirEntry) {
	e.parent.children[e.name()] = e
	d.byID[e.id().String()] = e
}

// addDirLocked adds the nodes of a directory of the backend.
func (d *FileDirectory) addDirLocked(dir *dirEntry, name string) *dirEntry {
	e, nid, bn := d.newEntry(dir, name, true)
	e.children = map[string]*dirEntry{}
	d.addDirNodes(e, d.s.Node(dir.id()), nid, bn, id.Organizes)
	d.linkLocked(e)
	return e
}

// addFileLocked adds the nodes of a file of the backend.
func (d *FileDirectory) addFileLocked(dir *dirEntry, name string) (*dirEntry, error) {
	e, nid, bn := d.newEntry(dir, name, false)
	cfg := d.cfg.File
	cfg.Backend = d.cfg.Backend.File(e.path)
	f, err := d.s.NewFile(cfg)
	if err != nil {
		return nil, err
	}
	e.file = f
	e.nodes = d.s.addFileNodes(f, d.ns, d.s.Node(dir.id()), nid, bn, id.Organizes)
	for _, n := range e.nodes[1:] {
		if mn := d.s.Node(n); mn != nil && mn.NodeClass() == ua.NodeClassMethod {
			e.methods = append(e.methods, n)
		}
	}
	d.linkLocked(e)
	return e, nil
}

// addDirNodes adds the FileDirectoryType Object of a directory.
func (d *FileDirectory) addDirNodes(e *dirEntry, parent *Node, nid *ua.NodeID, name *ua.QualifiedName, refType uint32) {
	obj := d.s.addObjectNode(d.ns, parent, nid, name, id.FileDirectoryType, refType)
	e.nodes = []*ua.NodeID{obj.ID()}
	handlers := map[string]MethodHandler{
		"CreateDirectory": d.createDirectory(e),
		"CreateFile":      d.createFile(e),
		"Delete":          d.delete(e),
		"MoveOrCopy":      d.moveOrCopy(e),
	}
	for _, m := range dirMethods {
		added := d.s.addMethodNode(d.ns, obj, m, handlers[m.Name])
		e.nodes = append(e.nodes, added...)
		e.methods = append(e.methods, added[0])
	}
}

// removeLocked removes the nodes of an entry and of all below it.
func (d *FileDirectory) removeLocked(e *dirEntry) {
	for _, c := range e.children {
		d.removeLocked(c)
	}
	obj := e.id()
	for _, m := range e.methods {
		d.s.unregisterMethod(obj, m)
	}
	if e.file != nil {
		e.file.CloseAll()
		d.s.files.remove(e.file)
	}
	if e.parent != nil {
		if p := d.s.Node(e.parent.id()); p != nil {
			p.RemoveRef(ua.NewExpandedNodeID(obj, "", 0), ua.NewNumericNodeID(0, id.Organizes), true)
		}
		delete(e.parent.children, e.name())
	}
	for i := len(e.nodes) - 1; i >= 0; i-- {
		_ = d.ns.DeleteNode(e.nodes[i]) // a node the directory added
	}
	delete(d.byID, obj.String())
}

// lockedLocked reports whether a file at or below e has an open handle:
// such a file "is locked and thus cannot be deleted", moved or copied
// (OPC 10000-20 §4.3.5, §4.3.6).
func lockedLocked(e *dirEntry) bool {
	if e.file != nil && e.file.OpenCount() > 0 {
		return true
	}
	for _, c := range e.children {
		if lockedLocked(c) {
			return true
		}
	}
	return false
}

// validName checks the name of a directory or file (library
// interpretation: OPC 10000-20 names no rule): it is the name of a
// BrowseName and of an entry of a file system, so it is not empty, not "."
// or "..", and has no "/", "\" or NUL. Another name is Bad_InvalidArgument.
func validName(name string) ua.StatusCode {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00") {
		return ua.StatusBadInvalidArgument
	}
	return ua.StatusOK
}

// dirStatus is the status of an error of a DirectoryBackend.
func dirStatus(err error) ua.StatusCode {
	switch {
	case errors.Is(err, fs.ErrExist):
		return ua.StatusBadBrowseNameDuplicated
	case errors.Is(err, fs.ErrNotExist):
		return ua.StatusBadNotFound
	}
	return fileStatus(err, ua.StatusBadUnexpectedError)
}

func (d *FileDirectory) authorize(ctx context.Context, op, p string) ua.StatusCode {
	if d.cfg.Authorize == nil {
		return ua.StatusOK
	}
	c, _ := MethodCallerFromContext(ctx)
	return d.cfg.Authorize(ctx, c, op, p)
}

// newEntryLocked checks a name for a new entry of dir: "A directory with
// the name already exists" or a file is Bad_BrowseNameDuplicated (OPC
// 10000-20 §4.3.3, §4.3.4: the name is the BrowseName of the Object, which
// is unique among those dir Organizes).
func (d *FileDirectory) newEntryLocked(ctx context.Context, op string, dir *dirEntry, name string) ua.StatusCode {
	if sc := validName(name); sc != ua.StatusOK {
		return sc
	}
	if _, ok := dir.children[name]; ok {
		return ua.StatusBadBrowseNameDuplicated
	}
	return d.authorize(ctx, op, childPath(dir, name))
}

// createDirectory is CreateDirectory (OPC 10000-20 §4.3.3).
func (d *FileDirectory) createDirectory(dir *dirEntry) MethodHandler {
	return func(ctx context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		var in uamethod.FileDirectoryTypeCreateDirectoryInput
		if err := in.Unpack(args); err != nil {
			return nil, uamethod.StatusOf(err)
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		if sc := d.newEntryLocked(ctx, "CreateDirectory", dir, in.DirectoryName); sc != ua.StatusOK {
			return nil, sc
		}
		if err := d.cfg.Backend.Mkdir(childPath(dir, in.DirectoryName)); err != nil {
			return nil, dirStatus(err)
		}
		e := d.addDirLocked(dir, in.DirectoryName)
		return (&uamethod.FileDirectoryTypeCreateDirectoryOutput{DirectoryNodeID: e.id()}).Pack(), ua.StatusOK
	}
}

// createFile is CreateFile (OPC 10000-20 §4.3.4): with requestFileOpen
// "the new file is opened with the Write and Read bits set in the open mode
// after the creation of the file"; otherwise "the returned value shall be
// 0". A file whose Open fails stays created, and the call returns the
// status of Open.
func (d *FileDirectory) createFile(dir *dirEntry) MethodHandler {
	return func(ctx context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		var in uamethod.FileDirectoryTypeCreateFileInput
		if err := in.Unpack(args); err != nil {
			return nil, uamethod.StatusOf(err)
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		if sc := d.newEntryLocked(ctx, "CreateFile", dir, in.FileName); sc != ua.StatusOK {
			return nil, sc
		}
		if err := d.cfg.Backend.CreateFile(childPath(dir, in.FileName)); err != nil {
			return nil, dirStatus(err)
		}
		e, err := d.addFileLocked(dir, in.FileName)
		if err != nil {
			return nil, dirStatus(err)
		}
		out := &uamethod.FileDirectoryTypeCreateFileOutput{FileNodeID: e.id()}
		if in.RequestFileOpen {
			h, sc := e.file.Open(ctx, fileModeRead|fileModeWrite)
			if sc != ua.StatusOK {
				return nil, sc
			}
			out.FileHandle = h
		}
		return out.Pack(), ua.StatusOK
	}
}

// childLocked returns the entry of a NodeId that dir Organizes: "A file or
// directory with the provided NodeId is not organized by this object" is
// Bad_NotFound (OPC 10000-20 §4.3.5, §4.3.6).
func (d *FileDirectory) childLocked(dir *dirEntry, nid *ua.NodeID) (*dirEntry, ua.StatusCode) {
	if nid == nil {
		return nil, ua.StatusBadNotFound
	}
	e := d.byID[nid.String()]
	if e == nil || e.parent != dir {
		return nil, ua.StatusBadNotFound
	}
	return e, ua.StatusOK
}

// delete is Delete (OPC 10000-20 §4.3.5).
func (d *FileDirectory) delete(dir *dirEntry) MethodHandler {
	return func(ctx context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		var in uamethod.FileDirectoryTypeDeleteInput
		if err := in.Unpack(args); err != nil {
			return nil, uamethod.StatusOf(err)
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		e, sc := d.childLocked(dir, in.ObjectToDelete)
		if sc != ua.StatusOK {
			return nil, sc
		}
		if lockedLocked(e) {
			return nil, ua.StatusBadInvalidState
		}
		if sc := d.authorize(ctx, "Delete", e.path); sc != ua.StatusOK {
			return nil, sc
		}
		if err := d.cfg.Backend.Remove(e.path); err != nil {
			return nil, dirStatus(err)
		}
		d.removeLocked(e)
		return nil, ua.StatusOK
	}
}

// moveOrCopy is MoveOrCopy (OPC 10000-20 §4.3.6): "If the file or directory
// is just renamed, the targetDirectory matches the ObjectId passed to the
// method call"; an empty newName keeps the name. A targetDirectory that is
// not a directory of the file system, or a directory moved or copied into
// itself, is Bad_InvalidArgument (library interpretation: §4.3.6 names no
// code for it).
func (d *FileDirectory) moveOrCopy(dir *dirEntry) MethodHandler {
	return func(ctx context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		var in uamethod.FileDirectoryTypeMoveOrCopyInput
		if err := in.Unpack(args); err != nil {
			return nil, uamethod.StatusOf(err)
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		e, sc := d.childLocked(dir, in.ObjectToMoveOrCopy)
		if sc != ua.StatusOK {
			return nil, sc
		}
		var target *dirEntry
		if in.TargetDirectory != nil {
			target = d.byID[in.TargetDirectory.String()]
		}
		if target == nil || !target.dir {
			return nil, ua.StatusBadInvalidArgument
		}
		for t := target; t != nil; t = t.parent {
			if t == e {
				return nil, ua.StatusBadInvalidArgument
			}
		}
		name := in.NewName
		if name == "" {
			name = e.name()
		}
		if lockedLocked(e) {
			return nil, ua.StatusBadInvalidState
		}
		if sc := d.newEntryLocked(ctx, "MoveOrCopy", target, name); sc != ua.StatusOK {
			return nil, sc
		}
		to := childPath(target, name)
		var err error
		if in.CreateCopy {
			err = d.cfg.Backend.Copy(e.path, to)
		} else {
			err = d.cfg.Backend.Rename(e.path, to)
		}
		if err != nil {
			return nil, dirStatus(err)
		}
		if !in.CreateCopy {
			d.removeLocked(e)
		}
		n, err := d.addEntryLocked(target, name, e.dir)
		if err == nil && n.dir {
			err = d.loadLocked(n)
		}
		if err != nil {
			return nil, dirStatus(err)
		}
		return (&uamethod.FileDirectoryTypeMoveOrCopyOutput{NewNodeID: n.id()}).Pack(), ua.StatusOK
	}
}
