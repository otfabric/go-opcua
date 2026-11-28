// SPDX-License-Identifier: MIT

// Package filetransfer is the client of the File Transfer of OPC 10000-20:
// a FileType Object (§4.2) read and written through a handle of its Open
// Method, with io.Reader and io.Writer adapters, and the directories of a
// FileDirectoryType Object (§4.3): CreateDirectory, CreateFile, Delete and
// MoveOrCopy.
//
// The Methods are called with the contracts of package uamethod: the
// arguments are packed and the results checked against the declarations of
// namespace 0. A Method of the Object is found by its BrowseName below the
// Object; an Object without it is called with the declaration of the type,
// which Part 4 §5.12.2.2 (1.05.06) allows. A Bad result is a
// *uamethod.CallError, so errors.Is(err, ua.StatusBadInvalidState) holds.
package filetransfer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uamethod"
)

// DefaultChunk is the length of one Read and the most bytes of one Write
// when Object.Chunk is zero. A server may return less than asked for (OPC
// 10000-20 §4.2.4).
const DefaultChunk = 64 << 10

// CallFunc calls the Method m of an Object with the input arguments and
// returns the output arguments; a Bad result is an error.
type CallFunc func(ctx context.Context, m *uamethod.Method, in []*ua.Variant) ([]*ua.Variant, error)

// Object is a FileType Object of a server (OPC 10000-20 §4.2.1).
type Object struct {
	// Chunk is the length of one Read and the most bytes of one Write; zero
	// is DefaultChunk.
	Chunk int

	c    *opcua.Client
	id   *ua.NodeID
	call CallFunc
}

// NewObject returns the FileType Object obj of the server of c.
func NewObject(c *opcua.Client, obj *ua.NodeID) *Object {
	return &Object{c: c, id: obj, call: newResolver(c, obj).call}
}

// ObjectFunc returns a FileType Object whose Methods are called with call:
// for a client that finds and calls the Methods of the Object itself, as
// packages gds and pubsub/remote do.
func ObjectFunc(call CallFunc) *Object { return &Object{call: call} }

// NodeID returns the NodeId of the Object, nil for an Object of ObjectFunc.
func (o *Object) NodeID() *ua.NodeID { return o.id }

func (o *Object) chunk() int {
	if o.Chunk > 0 {
		return min(o.Chunk, 1<<31-1)
	}
	return DefaultChunk
}

// Open calls Open with mode (OPC 10000-20 §4.2.2) and returns the File of
// the handle. ua.OpenFileModeRead reads the file; ua.OpenFileModeWrite with
// ua.OpenFileModeEraseExisting replaces it.
func (o *Object) Open(ctx context.Context, mode ua.OpenFileMode) (*File, error) {
	if mode > 0xff {
		return nil, fmt.Errorf("filetransfer: mode %#x is not a Byte: %w", uint32(mode), ua.StatusBadInvalidArgument)
	}
	out, err := o.call(ctx, uamethod.FileTypeOpen, (&uamethod.FileTypeOpenInput{Mode: uint8(mode)}).Pack())
	if err != nil {
		return nil, err
	}
	var r uamethod.FileTypeOpenOutput
	if err := r.Unpack(out); err != nil {
		return nil, err
	}
	return o.Attach(r.FileHandle, mode), nil
}

// Attach returns the File of a handle opened otherwise: by OpenWithMasks of
// a TrustList (Part 12 §7.8.2.2), or CreateFile of a directory (OPC
// 10000-20 §4.3.4).
func (o *Object) Attach(handle uint32, mode ua.OpenFileMode) *File {
	return &File{o: o, handle: handle, mode: mode}
}

// ReadAll opens the file for reading, reads it to its end and closes it.
// More than limit bytes (limit > 0) is an error.
func (o *Object) ReadAll(ctx context.Context, limit int) ([]byte, error) {
	f, err := o.Open(ctx, ua.OpenFileModeRead)
	if err != nil {
		return nil, err
	}
	return f.ReadAllAndClose(ctx, limit)
}

// WriteAll replaces the content of the file with data: Open with Write and
// EraseExisting, Write and Close.
func (o *Object) WriteAll(ctx context.Context, data []byte) error {
	f, err := o.Open(ctx, ua.OpenFileModeWrite|ua.OpenFileModeEraseExisting)
	if err != nil {
		return err
	}
	if err := f.Write(ctx, data); err != nil {
		return errors.Join(err, f.Close(ctx))
	}
	return f.Close(ctx)
}

// Info are the Properties of a FileType Object (OPC 10000-20 §4.2.1). An
// optional Property the Object does not have is zero.
type Info struct {
	Size                uint64
	Writable            bool
	UserWritable        bool
	OpenCount           uint16
	MimeType            string
	MaxByteStringLength uint32
	LastModifiedTime    time.Time
}

// Info reads the Properties of the Object. It needs an Object of NewObject.
func (o *Object) Info(ctx context.Context) (*Info, error) {
	if o.c == nil {
		return nil, errors.New("filetransfer: Info needs an Object of NewObject")
	}
	refs, err := o.c.Node(o.id).References(ctx, id.HasProperty, ua.BrowseDirectionForward, ua.NodeClassVariable, true)
	if err != nil {
		return nil, fmt.Errorf("filetransfer: browsing %v: %w", o.id, err)
	}
	info := &Info{}
	var nodes []*ua.ReadValueID
	var names []string
	for _, r := range refs {
		if r.BrowseName == nil || r.BrowseName.NamespaceIndex != 0 || r.NodeID == nil {
			continue
		}
		switch r.BrowseName.Name {
		case "Size", "Writable", "UserWritable", "OpenCount", "MimeType", "MaxByteStringLength", "LastModifiedTime":
			nodes = append(nodes, &ua.ReadValueID{NodeID: r.NodeID.NodeID, AttributeID: ua.AttributeIDValue})
			names = append(names, r.BrowseName.Name)
		}
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("filetransfer: %v has no Properties of FileType: %w", o.id, ua.StatusBadNotFound)
	}
	res, err := o.c.Read(ctx, &ua.ReadRequest{NodesToRead: nodes, TimestampsToReturn: ua.TimestampsToReturnNeither})
	if err != nil {
		return nil, fmt.Errorf("filetransfer: reading the Properties of %v: %w", o.id, err)
	}
	if len(res.Results) != len(nodes) {
		return nil, fmt.Errorf("filetransfer: %d results for %d Properties: %w", len(res.Results), len(nodes), ua.StatusBadUnknownResponse)
	}
	for i, dv := range res.Results {
		if dv == nil || dv.Value == nil {
			continue
		}
		switch v := dv.Value.Value(); names[i] {
		case "Size":
			info.Size, _ = v.(uint64)
		case "Writable":
			info.Writable, _ = v.(bool)
		case "UserWritable":
			info.UserWritable, _ = v.(bool)
		case "OpenCount":
			info.OpenCount, _ = v.(uint16)
		case "MimeType":
			info.MimeType, _ = v.(string)
		case "MaxByteStringLength":
			info.MaxByteStringLength, _ = v.(uint32)
		case "LastModifiedTime":
			info.LastModifiedTime, _ = v.(time.Time)
		}
	}
	return info, nil
}

// File is an open handle of a FileType Object. A File is for one goroutine
// at a time, as the position of the handle is.
type File struct {
	o      *Object
	handle uint32
	mode   ua.OpenFileMode
	closed bool
}

// Handle returns the fileHandle of Open.
func (f *File) Handle() uint32 { return f.handle }

// Mode returns the mode the handle was opened with.
func (f *File) Mode() ua.OpenFileMode { return f.mode }

// Read calls Read once (OPC 10000-20 §4.2.4) for up to length bytes from the
// position of the handle; length must be positive. An empty result is the
// end of the file, io.EOF.
func (f *File) Read(ctx context.Context, length int32) ([]byte, error) {
	out, err := f.o.call(ctx, uamethod.FileTypeRead, (&uamethod.FileTypeReadInput{FileHandle: f.handle, Length: length}).Pack())
	if err != nil {
		return nil, err
	}
	var r uamethod.FileTypeReadOutput
	if err := r.Unpack(out); err != nil {
		return nil, err
	}
	if len(r.Data) == 0 {
		return nil, io.EOF
	}
	return r.Data, nil
}

// ReadAllAndClose reads from the position of the handle to the end of the
// file and closes the handle, whatever the outcome. More than limit bytes
// (limit > 0) is an error.
func (f *File) ReadAllAndClose(ctx context.Context, limit int) ([]byte, error) {
	var b []byte
	for {
		chunk, err := f.Read(ctx, int32(f.o.chunk()))
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errors.Join(err, f.Close(ctx))
		}
		if limit > 0 && len(b)+len(chunk) > limit {
			return nil, errors.Join(fmt.Errorf("filetransfer: the file exceeds %d bytes", limit), f.Close(ctx))
		}
		b = append(b, chunk...)
	}
	if err := f.Close(ctx); err != nil {
		return nil, err
	}
	return b, nil
}

// Write calls Write (OPC 10000-20 §4.2.5) with data at the position of the
// handle, in chunks of Object.Chunk bytes.
func (f *File) Write(ctx context.Context, data []byte) error {
	for len(data) > 0 {
		n := min(len(data), f.o.chunk())
		if _, err := f.o.call(ctx, uamethod.FileTypeWrite, (&uamethod.FileTypeWriteInput{FileHandle: f.handle, Data: data[:n]}).Pack()); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

// Position calls GetPosition (OPC 10000-20 §4.2.6).
func (f *File) Position(ctx context.Context) (uint64, error) {
	out, err := f.o.call(ctx, uamethod.FileTypeGetPosition, (&uamethod.FileTypeGetPositionInput{FileHandle: f.handle}).Pack())
	if err != nil {
		return 0, err
	}
	var r uamethod.FileTypeGetPositionOutput
	if err := r.Unpack(out); err != nil {
		return 0, err
	}
	return r.Position, nil
}

// SetPosition calls SetPosition (OPC 10000-20 §4.2.7): a position past the
// end of the file is the end.
func (f *File) SetPosition(ctx context.Context, pos uint64) error {
	_, err := f.o.call(ctx, uamethod.FileTypeSetPosition, (&uamethod.FileTypeSetPositionInput{FileHandle: f.handle, Position: pos}).Pack())
	return err
}

// Close calls Close (OPC 10000-20 §4.2.3); the handle is no longer valid.
// Closing a File again does nothing.
func (f *File) Close(ctx context.Context) error {
	if f.closed {
		return nil
	}
	f.closed = true
	_, err := f.o.call(ctx, uamethod.FileTypeClose, (&uamethod.FileTypeCloseInput{FileHandle: f.handle}).Pack())
	return err
}

// Reader returns an io.Reader of the file from the position of the
// handle: each Read of it is one Read call of up to len(p) bytes.
func (f *File) Reader(ctx context.Context) io.Reader { return &reader{ctx: ctx, f: f} }

type reader struct {
	ctx context.Context
	f   *File
	buf []byte
}

func (r *reader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.buf) == 0 {
		b, err := r.f.Read(r.ctx, int32(min(len(p), r.f.o.chunk())))
		if err != nil {
			return 0, err
		}
		r.buf = b
	}
	// A server returns at most the length asked for; one that returns
	// more is read on the next call.
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

// Writer returns an io.Writer of the file at the position of the handle.
func (f *File) Writer(ctx context.Context) io.Writer { return writer{ctx: ctx, f: f} }

type writer struct {
	ctx context.Context
	f   *File
}

func (w writer) Write(p []byte) (int, error) {
	if err := w.f.Write(w.ctx, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// resolver finds the Methods of an Object by their BrowseName.
type resolver struct {
	c   *opcua.Client
	obj *ua.NodeID

	mu      sync.Mutex
	methods map[string]*ua.NodeID // nil until browsed
}

func newResolver(c *opcua.Client, obj *ua.NodeID) *resolver { return &resolver{c: c, obj: obj} }

// method returns the NodeId of the Method name of the Object, nil for the
// declaration of the type when the Object has none of that name or cannot
// be browsed (the Call service then reports the status).
func (r *resolver) method(ctx context.Context, name string) *ua.NodeID {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.methods == nil {
		refs, err := r.c.Node(r.obj).References(ctx, id.HasComponent, ua.BrowseDirectionForward, ua.NodeClassMethod, true)
		if err != nil {
			return nil // not cached: the next call browses again
		}
		r.methods = map[string]*ua.NodeID{}
		for _, ref := range refs {
			if ref.BrowseName != nil && ref.BrowseName.NamespaceIndex == 0 && ref.NodeID != nil {
				if _, dup := r.methods[ref.BrowseName.Name]; !dup {
					r.methods[ref.BrowseName.Name] = ref.NodeID.NodeID
				}
			}
		}
	}
	return r.methods[name]
}

func (r *resolver) call(ctx context.Context, m *uamethod.Method, in []*ua.Variant) ([]*ua.Variant, error) {
	return m.Call(ctx, r.c, r.obj, r.method(ctx, m.Name), in)
}
