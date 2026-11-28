// SPDX-License-Identifier: MIT

package filetransfer

import (
	"context"
	"fmt"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uamethod"
)

// Directory is a FileDirectoryType Object of a server (OPC 10000-20
// §4.3.1): the root of a file system (the FileSystem Object, §4.3.2) or a
// directory below it.
type Directory struct {
	c   *opcua.Client
	id  *ua.NodeID
	res *resolver
}

// NewDirectory returns the FileDirectoryType Object obj of the server of c.
func NewDirectory(c *opcua.Client, obj *ua.NodeID) *Directory {
	return &Directory{c: c, id: obj, res: newResolver(c, obj)}
}

// NodeID returns the NodeId of the directory.
func (d *Directory) NodeID() *ua.NodeID { return d.id }

// Entry is a directory or a file a directory Organizes.
type Entry struct {
	NodeID *ua.NodeID
	Name   string
	// Dir reports a FileDirectoryType Object (or a subtype), else a
	// FileType Object.
	Dir bool
}

// Entries returns the directories and files of the directory: the Objects
// it Organizes whose TypeDefinition is FileDirectoryType or FileType
// (OPC 10000-20 §4.3.1, Table 8). An Object of a subtype of either is
// recognized by the TypeDefinition of the type only, which this method
// does not follow.
func (d *Directory) Entries(ctx context.Context) ([]Entry, error) {
	refs, err := d.c.Node(d.id).References(ctx, id.Organizes, ua.BrowseDirectionForward, ua.NodeClassObject, true)
	if err != nil {
		return nil, fmt.Errorf("filetransfer: browsing %v: %w", d.id, err)
	}
	var out []Entry
	for _, r := range refs {
		if r.NodeID == nil || r.BrowseName == nil || r.TypeDefinition == nil || r.TypeDefinition.NodeID == nil {
			continue
		}
		td := r.TypeDefinition.NodeID
		if td.Namespace() != 0 {
			continue
		}
		switch td.IntID() {
		case id.FileDirectoryType:
			out = append(out, Entry{NodeID: r.NodeID.NodeID, Name: r.BrowseName.Name, Dir: true})
		case id.FileType:
			out = append(out, Entry{NodeID: r.NodeID.NodeID, Name: r.BrowseName.Name})
		}
	}
	return out, nil
}

// Directory returns the directory of a NodeId of an Entry.
func (d *Directory) Directory(nodeID *ua.NodeID) *Directory { return NewDirectory(d.c, nodeID) }

// File returns the FileType Object of a NodeId of an Entry.
func (d *Directory) File(nodeID *ua.NodeID) *Object { return NewObject(d.c, nodeID) }

func (d *Directory) call(ctx context.Context, m *uamethod.Method, in []*ua.Variant) ([]*ua.Variant, error) {
	return m.Call(ctx, d.c, d.id, d.res.method(ctx, m.Name), in)
}

// CreateDirectory calls CreateDirectory (OPC 10000-20 §4.3.3) and returns
// the NodeId of the new directory. A name that exists is
// Bad_BrowseNameDuplicated.
func (d *Directory) CreateDirectory(ctx context.Context, name string) (*ua.NodeID, error) {
	out, err := d.call(ctx, uamethod.FileDirectoryTypeCreateDirectory, (&uamethod.FileDirectoryTypeCreateDirectoryInput{DirectoryName: name}).Pack())
	if err != nil {
		return nil, err
	}
	var r uamethod.FileDirectoryTypeCreateDirectoryOutput
	if err := r.Unpack(out); err != nil {
		return nil, err
	}
	return r.DirectoryNodeID, nil
}

// CreateFile calls CreateFile (OPC 10000-20 §4.3.4) and returns the
// FileType Object of the new file. With open, the file is "opened with the
// Write and Read bits set", and the File of the handle is returned too.
func (d *Directory) CreateFile(ctx context.Context, name string, open bool) (*Object, *File, error) {
	out, err := d.call(ctx, uamethod.FileDirectoryTypeCreateFile, (&uamethod.FileDirectoryTypeCreateFileInput{FileName: name, RequestFileOpen: open}).Pack())
	if err != nil {
		return nil, nil, err
	}
	var r uamethod.FileDirectoryTypeCreateFileOutput
	if err := r.Unpack(out); err != nil {
		return nil, nil, err
	}
	o := NewObject(d.c, r.FileNodeID)
	if !open {
		return o, nil, nil
	}
	return o, o.Attach(r.FileHandle, ua.OpenFileModeRead|ua.OpenFileModeWrite), nil
}

// Delete calls Delete (OPC 10000-20 §4.3.5) for a file or directory the
// directory Organizes; a directory is deleted with all below it.
func (d *Directory) Delete(ctx context.Context, obj *ua.NodeID) error {
	_, err := d.call(ctx, uamethod.FileDirectoryTypeDelete, (&uamethod.FileDirectoryTypeDeleteInput{ObjectToDelete: obj}).Pack())
	return err
}

// MoveOrCopy calls MoveOrCopy (OPC 10000-20 §4.3.6) for a file or directory
// the directory Organizes: it is moved, or copied with createCopy, to the
// directory target with the name newName ("" keeps the name). A rename has
// the directory itself as target. It returns the NodeId of the moved or
// copied object, which may be a new one even for a move.
func (d *Directory) MoveOrCopy(ctx context.Context, obj, target *ua.NodeID, createCopy bool, newName string) (*ua.NodeID, error) {
	out, err := d.call(ctx, uamethod.FileDirectoryTypeMoveOrCopy, (&uamethod.FileDirectoryTypeMoveOrCopyInput{
		ObjectToMoveOrCopy: obj, TargetDirectory: target, CreateCopy: createCopy, NewName: newName,
	}).Pack())
	if err != nil {
		return nil, err
	}
	var r uamethod.FileDirectoryTypeMoveOrCopyOutput
	if err := r.Unpack(out); err != nil {
		return nil, err
	}
	return r.NewNodeID, nil
}
