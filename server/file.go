// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uamethod"
)

// This file is the FileType of OPC 10000-20 §4.2: the handles a client
// opens with Open, and the Methods and Properties of a FileType Object. The
// TrustList objects (Part 12 §7.8.2), the PubSubConfiguration object
// (Part 14 §9.1.3.7) and the ConnectionManagerConfiguration of OPC UA FX
// (uafx/fxserver) are files of it with Methods of their own.

// DefaultFileMaxByteStringLength is the most one Read of a FileObject
// returns when FileConfig.MaxByteStringLength is zero.
const DefaultFileMaxByteStringLength = 1 << 20

// defaultFileMaxHandles bounds the handles of a FileObject open at once
// when FileConfig.MaxHandles is zero.
const defaultFileMaxHandles = 32

// FileBackend is the content of a file that a [FileObject] serves.
//
// The methods are called from the goroutines of the requests; a backend is
// used by one FileObject. Errors may be ua.StatusCode values, which the
// Method returns; another error is Bad_UnexpectedError (OPC 10000-20 §4.2.2,
// Table 4, §4.2.4, Table 6).
type FileBackend interface {
	// Open opens the content for a new handle with the mode of the Open
	// Method, after the FileObject checked the mode and that the handle
	// may be opened (OPC 10000-20 §4.2.2): with EraseExisting the content
	// of the handle is empty. The FileObject reads and writes the content
	// at the position of the handle and closes it with Close, at the end
	// of the session of the handle or with [FileObject.CloseAll].
	Open(ctx context.Context, mode ua.OpenFileMode) (FileContent, error)

	// Size is the value of the Size Property: "The size of the file in
	// Bytes" (OPC 10000-20 §4.2.1). A ua.StatusCode error is the status of
	// the value, so Bad_NotSupported for a size the backend cannot tell.
	Size() (uint64, error)
}

// FileModTimer is a FileBackend that knows when its content was last
// modified: the LastModifiedTime Property of the FileObject (OPC 10000-20
// §4.2.1).
type FileModTimer interface {
	ModTime() (time.Time, error)
}

// FileContent is the content of an open handle of a FileObject.
type FileContent interface {
	io.ReaderAt
	io.WriterAt
	// Size returns the size of the content in bytes: Append opens at it
	// and SetPosition does not go past it (OPC 10000-20 §4.2.2, §4.2.7).
	Size() (int64, error)
	// Close closes the content: the client closed the handle (Close), or
	// its session ended, which OPC 10000-20 §4.2.5 leaves to the server:
	// "It is server-dependent whether the written data are persistently
	// stored if the session is ended without calling the Close Method".
	Close() error
}

// FileConfig configures a [FileObject].
type FileConfig struct {
	// Backend is the content of the file; it is required.
	Backend FileBackend

	// Writable is the value of the Writable and UserWritable Properties
	// (OPC 10000-20 §4.2.1). Open with the Write bit of a file that is not
	// writable returns Bad_NotWritable.
	Writable bool

	// Modes are the modes Open accepts; nil accepts every mode OPC
	// 10000-20 §4.2.2 allows (Table 4: the reserved bits 4 to 7 zero,
	// EraseExisting only with Write). Another mode is Bad_InvalidArgument
	// ("Mode setting is invalid"). A subtype narrows them: a TrustList
	// takes Read and Write with EraseExisting only (Part 12 §7.8.2.1).
	Modes []ua.OpenFileMode

	// MaxByteStringLength is the most bytes one Read returns and the value
	// of the MaxByteStringLength Property (OPC 10000-20 §4.2.1). Zero is
	// DefaultFileMaxByteStringLength.
	MaxByteStringLength uint32

	// MimeType is the value of the MimeType Property (OPC 10000-20 §4.2.1,
	// "based on RFC 2046"); "" leaves the Property out.
	MimeType string

	// MaxHandles bounds the handles open at once; Open returns
	// Bad_TooManyOperations beyond it. Zero is 32.
	MaxHandles int

	// Authorize, if set, decides whether the caller may open the file with
	// the mode, after the checks of the mode: ua.StatusOK allows it,
	// another status is the result of Open.
	Authorize func(ctx context.Context, caller *MethodCaller, mode ua.OpenFileMode) ua.StatusCode

	// OnChange, if set, is called in a goroutine of its own after Open or
	// Close changed the OpenCount, and after a handle that was opened for
	// writing is closed (Size and LastModifiedTime may change).
	OnChange func()
}

// FileObject is a file of the FileType of OPC 10000-20 §4.2.1: the handles
// that sessions opened, with their position, and the Methods Open, Close,
// Read, Write, GetPosition and SetPosition on them.
//
// [Server.AddFile] adds a FileType Object to the address space and
// [Server.ServeFile] serves one that exists (an imported NodeSet); with
// [Server.NewFile] the caller attaches the handlers of [FileObject.Method]
// and the values of [FileObject.Property] to nodes of its own, and a
// subtype adds Methods that use the handles ([FileObject.OpenBytes],
// [FileObject.CloseAndTake]).
//
// A handle belongs to the session that opened it: "The fileHandle is
// generated by the server and is unique for the Session. Clients cannot
// transfer the fileHandle to another Session" (OPC 10000-20 §4.2.2). A
// handle of another session is Bad_InvalidArgument, as an unknown one, and
// the handles of a session are closed when the session ends.
type FileObject struct {
	s       *Server
	cfg     FileConfig
	maxRead int

	mu      sync.Mutex
	handles map[uint32]*fileHandle
	next    uint32
	open    int // the handles that are not being opened

	nodes []*ua.NodeID // the Properties that change, notified by notify
}

// fileHandle is an open handle. mu serializes the operations on it; the
// FileObject's mu is taken first.
type fileHandle struct {
	session *ua.NodeID
	mode    ua.OpenFileMode
	opening bool // the backend is opening the content

	mu      sync.Mutex
	content FileContent
	pos     int64
	closed  bool
}

// The bits of the mode of Open (OPC 10000-20 §4.2.2, Table 4).
const (
	fileModeRead          = ua.OpenFileModeRead
	fileModeWrite         = ua.OpenFileModeWrite
	fileModeEraseExisting = ua.OpenFileModeEraseExisting
	fileModeAppend        = ua.OpenFileModeAppend
	// fileModeReserved are bits 4 to 7, which are "Reserved for future
	// use. Shall always be zero." (Table 4).
	fileModeReserved = ^(fileModeRead | fileModeWrite | fileModeEraseExisting | fileModeAppend)
)

// NewFile returns a FileObject of the server that is not in the address
// space: see [FileObject.Method] and [FileObject.Property].
func (s *Server) NewFile(cfg FileConfig) (*FileObject, error) {
	if s == nil {
		return nil, errors.New("server: NewFile: nil server")
	}
	if cfg.Backend == nil {
		return nil, errors.New("server: NewFile: Backend is required")
	}
	for _, m := range cfg.Modes {
		if sc := validFileMode(m); sc != ua.StatusOK {
			return nil, fmt.Errorf("server: NewFile: mode %#x is not a mode of OPC 10000-20 §4.2.2: %w", uint32(m), sc)
		}
	}
	if cfg.MaxByteStringLength == 0 {
		cfg.MaxByteStringLength = DefaultFileMaxByteStringLength
	}
	if cfg.MaxHandles <= 0 {
		cfg.MaxHandles = defaultFileMaxHandles
	}
	cfg.Modes = slices.Clone(cfg.Modes)
	f := &FileObject{s: s, cfg: cfg, handles: map[uint32]*fileHandle{}}
	// Read's length is an Int32.
	f.maxRead = int(min(uint64(cfg.MaxByteStringLength), uint64(1<<31-1)))
	s.files.add(f)
	return f, nil
}

// validFileMode checks a mode against Table 4 of OPC 10000-20 §4.2.2: the
// reserved bits "Shall always be zero", and EraseExisting "can only be set
// if the file is opened for writing".
func validFileMode(m ua.OpenFileMode) ua.StatusCode {
	if m&fileModeReserved != 0 || m&fileModeEraseExisting != 0 && m&fileModeWrite == 0 {
		return ua.StatusBadInvalidArgument
	}
	return ua.StatusOK
}

// Method returns the handler of a Method of FileType by its BrowseName:
// Open, Close, Read, Write, GetPosition or SetPosition (OPC 10000-20 §4.2.2
// to §4.2.7); nil for another name. The arguments are checked against the
// declarations of namespace 0 (package uamethod).
func (f *FileObject) Method(name string) MethodHandler {
	switch name {
	case "Open":
		return f.handleOpen
	case "Close":
		return f.handleClose
	case "Read":
		return f.handleRead
	case "Write":
		return f.handleWrite
	case "GetPosition":
		return f.handleGetPosition
	case "SetPosition":
		return f.handleSetPosition
	}
	return nil
}

// fileMethods are the Methods of FileType.
var fileMethods = []*uamethod.Method{
	uamethod.FileTypeOpen, uamethod.FileTypeClose, uamethod.FileTypeRead,
	uamethod.FileTypeWrite, uamethod.FileTypeGetPosition, uamethod.FileTypeSetPosition,
}

// Property returns the value of a Property of FileType by its BrowseName:
// Size, Writable, UserWritable, OpenCount, MaxByteStringLength, MimeType
// (when FileConfig.MimeType is set) or LastModifiedTime (when the backend
// is a FileModTimer) (OPC 10000-20 §4.2.1); nil for another name.
func (f *FileObject) Property(name string) ValueFunc {
	switch name {
	case "Size":
		return func() *ua.DataValue {
			n, err := f.cfg.Backend.Size()
			if err != nil {
				return badValue(fileStatus(err, ua.StatusBadUnexpectedError))
			}
			return DataValueFromValue(n)
		}
	case "Writable", "UserWritable":
		return static(f.cfg.Writable)
	case "OpenCount":
		return func() *ua.DataValue { return DataValueFromValue(uint16(min(f.OpenCount(), 1<<16-1))) }
	case "MaxByteStringLength":
		return static(f.cfg.MaxByteStringLength)
	case "MimeType":
		if f.cfg.MimeType != "" {
			return static(f.cfg.MimeType)
		}
	case "LastModifiedTime":
		if mt, ok := f.cfg.Backend.(FileModTimer); ok {
			return func() *ua.DataValue {
				t, err := mt.ModTime()
				if err != nil {
					return badValue(fileStatus(err, ua.StatusBadUnexpectedError))
				}
				return DataValueFromValue(t.UTC())
			}
		}
	}
	return nil
}

// fileProperties are the Properties of FileType with their DataType; the
// first four are Mandatory (OPC 10000-20 §4.2.1, Table 1).
var fileProperties = []struct {
	name     string
	dataType uint32
}{
	{"Size", 9}, {"Writable", 1}, {"UserWritable", 1}, {"OpenCount", 5},
	{"MimeType", 12}, {"MaxByteStringLength", 7}, {"LastModifiedTime", 294},
}

// fileStatus returns the status an error of a backend stands for: a
// ua.StatusCode in its chain, else def.
func fileStatus(err error, def ua.StatusCode) ua.StatusCode {
	var sc ua.StatusCode
	if errors.As(err, &sc) && sc != ua.StatusOK {
		return sc
	}
	return def
}

// OpenCount is the number of open handles, the value of the OpenCount
// Property: "the number of currently valid file handles on the file"
// (OPC 10000-20 §4.2.1).
func (f *FileObject) OpenCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pruneLocked()
	return f.open
}

// CloseAll closes every handle, as the end of their sessions does.
func (f *FileObject) CloseAll() {
	f.mu.Lock()
	var hs []*fileHandle
	for h, x := range f.handles {
		delete(f.handles, h)
		if !x.opening {
			f.open--
			hs = append(hs, x)
		}
	}
	f.mu.Unlock()
	f.closeHandles(hs)
}

// sessionEnded closes the handles of a session that ended.
func (f *FileObject) sessionEnded(session *ua.NodeID) {
	f.mu.Lock()
	var hs []*fileHandle
	for h, x := range f.handles {
		if x.session.Equal(session) {
			delete(f.handles, h)
			if !x.opening {
				f.open--
				hs = append(hs, x)
			}
		}
	}
	f.mu.Unlock()
	f.closeHandles(hs)
}

// pruneLocked forgets the handles of sessions the server no longer has,
// for a session that ended before the FileObject was told.
func (f *FileObject) pruneLocked() {
	var hs []*fileHandle
	for h, x := range f.handles {
		if !x.opening && !f.s.sb.hasID(x.session) {
			delete(f.handles, h)
			f.open--
			hs = append(hs, x)
		}
	}
	if len(hs) > 0 {
		go f.closeHandles(hs)
	}
}

// closeHandles closes the content of removed handles and notifies.
func (f *FileObject) closeHandles(hs []*fileHandle) {
	for _, x := range hs {
		x.mu.Lock()
		if !x.closed {
			x.closed = true
			_ = x.content.Close() // nothing to report it to
		}
		x.mu.Unlock()
	}
	if len(hs) > 0 {
		f.notify()
	}
}

// notify tells OnChange and the monitored items of the Properties that the
// file changed.
func (f *FileObject) notify() {
	go func() {
		f.mu.Lock()
		nodes := slices.Clone(f.nodes)
		f.mu.Unlock()
		for _, n := range nodes {
			f.s.ChangeNotification(n)
		}
		if f.cfg.OnChange != nil {
			f.cfg.OnChange()
		}
	}()
}

// fileCaller returns the caller of a Method that has a session.
func fileCaller(ctx context.Context) (*MethodCaller, bool) {
	c, ok := MethodCallerFromContext(ctx)
	return c, ok && c.SessionID != nil
}

// Open is the Open Method (OPC 10000-20 §4.2.2) for the caller of ctx.
func (f *FileObject) Open(ctx context.Context, mode ua.OpenFileMode) (uint32, ua.StatusCode) {
	c, ok := fileCaller(ctx)
	if !ok {
		return 0, ua.StatusBadSessionIDInvalid
	}
	if sc := validFileMode(mode); sc != ua.StatusOK {
		return 0, sc
	}
	if f.cfg.Modes != nil && !slices.Contains(f.cfg.Modes, mode) {
		return 0, ua.StatusBadInvalidArgument
	}
	if mode&fileModeWrite != 0 && !f.cfg.Writable {
		return 0, ua.StatusBadNotWritable
	}
	if a := f.cfg.Authorize; a != nil {
		if sc := a(ctx, c, mode); sc != ua.StatusOK {
			return 0, sc
		}
	}
	return f.openWith(c.SessionID, mode, func() (FileContent, error) { return f.cfg.Backend.Open(ctx, mode) })
}

// OpenBytes opens a handle for reading on data, for an Open Method of a
// subtype of FileType whose content is not that of the backend
// (OpenWithMasks of TrustListType, Part 12 §7.8.2.2). The handle is as one
// of Open with the Read bit.
func (f *FileObject) OpenBytes(ctx context.Context, data []byte) (uint32, ua.StatusCode) {
	c, ok := fileCaller(ctx)
	if !ok {
		return 0, ua.StatusBadSessionIDInvalid
	}
	return f.openWith(c.SessionID, fileModeRead, func() (FileContent, error) {
		return &bytesContent{data: data, readOnly: true}, nil
	})
}

// openWith opens a handle: the rules of OPC 10000-20 §4.2.2 for the handles
// already open, then the content. The handle is reserved while the backend
// opens the content, so that a second writer is refused before the first
// one erased the file.
func (f *FileObject) openWith(sess *ua.NodeID, mode ua.OpenFileMode, open func() (FileContent, error)) (uint32, ua.StatusCode) {
	f.mu.Lock()
	f.pruneLocked()
	for _, o := range f.handles {
		// "Clients can open the same file several times for read. A
		// request to open for writing shall return Bad_NotWritable when
		// the file is already opened. A request to open for reading shall
		// return Bad_NotReadable when the file is already opened for
		// writing." (OPC 10000-20 §4.2.2)
		if mode&fileModeWrite != 0 {
			f.mu.Unlock()
			return 0, ua.StatusBadNotWritable
		}
		if o.mode&fileModeWrite != 0 {
			f.mu.Unlock()
			return 0, ua.StatusBadNotReadable
		}
	}
	if len(f.handles) >= f.cfg.MaxHandles {
		f.mu.Unlock()
		return 0, ua.StatusBadTooManyOperations
	}
	// A handle is never 0: CreateFile returns 0 for no handle (OPC
	// 10000-20 §4.3.4).
	for {
		f.next++
		if _, used := f.handles[f.next]; f.next != 0 && !used {
			break
		}
	}
	h := f.next
	x := &fileHandle{session: sess, mode: mode, opening: true}
	f.handles[h] = x
	f.mu.Unlock()

	content, err := open()
	var pos int64
	if err == nil && mode&fileModeAppend != 0 {
		// "File is opened at end of the file." (Table 4)
		pos, err = content.Size()
		if err != nil {
			_ = content.Close() // the Open fails with err
		}
	}

	f.mu.Lock()
	if f.handles[h] != x {
		// The session ended, or CloseAll ran, meanwhile.
		f.mu.Unlock()
		if err == nil {
			// The handle was never returned: nothing was written with it.
			if d, ok := content.(fileDiscarder); ok {
				d.discard()
			}
			_ = content.Close() // nothing to report it to
		}
		return 0, ua.StatusBadSessionClosed
	}
	if err != nil {
		delete(f.handles, h)
		f.mu.Unlock()
		return 0, fileStatus(err, ua.StatusBadUnexpectedError)
	}
	x.content, x.pos, x.opening = content, pos, false
	f.open++
	f.mu.Unlock()
	f.notify()
	return h, ua.StatusOK
}

// handle returns the handle h of the caller of ctx, locked: "Invalid file
// handle in call" is Bad_InvalidArgument (OPC 10000-20 §4.2.3 to §4.2.7).
func (f *FileObject) handle(ctx context.Context, h uint32) (*fileHandle, ua.StatusCode) {
	c, ok := fileCaller(ctx)
	f.mu.Lock()
	defer f.mu.Unlock()
	x := f.handles[h]
	if !ok || x == nil || x.opening || !x.session.Equal(c.SessionID) {
		return nil, ua.StatusBadInvalidArgument
	}
	x.mu.Lock()
	return x, ua.StatusOK
}

// Close is the Close Method (OPC 10000-20 §4.2.3): "When a client closes a
// file the handle becomes invalid.".
func (f *FileObject) Close(ctx context.Context, h uint32) ua.StatusCode {
	x, sc := f.remove(ctx, h, nil)
	if sc != ua.StatusOK {
		return sc
	}
	return f.closeContent(x)
}

// remove removes the handle h of the caller, after check (if not nil)
// accepted it; the handle stays locked.
func (f *FileObject) remove(ctx context.Context, h uint32, check func(*fileHandle) ua.StatusCode) (*fileHandle, ua.StatusCode) {
	c, ok := fileCaller(ctx)
	f.mu.Lock()
	defer f.mu.Unlock()
	x := f.handles[h]
	if !ok || x == nil || x.opening || !x.session.Equal(c.SessionID) {
		return nil, ua.StatusBadInvalidArgument
	}
	x.mu.Lock()
	if check != nil {
		if sc := check(x); sc != ua.StatusOK {
			x.mu.Unlock()
			return nil, sc
		}
	}
	delete(f.handles, h)
	f.open--
	return x, ua.StatusOK
}

// closeContent closes the content of a removed, locked handle.
func (f *FileObject) closeContent(x *fileHandle) ua.StatusCode {
	x.closed = true
	err := x.content.Close()
	x.mu.Unlock()
	f.notify()
	if err != nil {
		return fileStatus(err, ua.StatusBadUnexpectedError)
	}
	return ua.StatusOK
}

// CloseAndTake closes the handle h of the caller of ctx, which must have
// been opened for writing, and returns what was written: the CloseAndUpdate
// Method of a subtype of FileType (TrustListType, Part 12 §7.8.2.3;
// PubSubConfigurationType, Part 14 §9.1.3.7.6) applies it. A handle that was
// not opened for writing is Bad_InvalidState. check, if not nil, is called
// with the content first: a status other than Good is returned and the
// handle stays open.
func (f *FileObject) CloseAndTake(ctx context.Context, h uint32, check func(data []byte) ua.StatusCode) ([]byte, ua.StatusCode) {
	var data []byte
	x, sc := f.remove(ctx, h, func(x *fileHandle) ua.StatusCode {
		if x.mode&fileModeWrite == 0 {
			return ua.StatusBadInvalidState
		}
		b, sc := readContentAll(x.content)
		if sc != ua.StatusOK {
			return sc
		}
		if check != nil {
			if sc := check(b); sc != ua.StatusOK {
				return sc
			}
		}
		data = b
		return ua.StatusOK
	})
	if sc != ua.StatusOK {
		return nil, sc
	}
	if sc := f.closeContent(x); sc != ua.StatusOK {
		return nil, sc
	}
	return data, ua.StatusOK
}

// readContentAll returns the whole content.
func readContentAll(c FileContent) ([]byte, ua.StatusCode) {
	if b, ok := c.(*bytesContent); ok {
		return b.data, ua.StatusOK
	}
	n, err := c.Size()
	if err != nil {
		return nil, fileStatus(err, ua.StatusBadUnexpectedError)
	}
	b := make([]byte, n)
	k, err := c.ReadAt(b, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fileStatus(err, ua.StatusBadUnexpectedError)
	}
	return b[:k], ua.StatusOK
}

// Read is the Read Method (OPC 10000-20 §4.2.4): up to length bytes from
// the position of the handle, at most MaxByteStringLength; an empty result
// is the end of the file. "Only positive values are allowed" for length:
// zero or less is Bad_InvalidArgument ("non-positive length", Table 6). A
// handle not opened for reading is Bad_InvalidState.
func (f *FileObject) Read(ctx context.Context, h uint32, length int32) ([]byte, ua.StatusCode) {
	x, sc := f.handle(ctx, h)
	if sc != ua.StatusOK {
		return nil, sc
	}
	defer x.mu.Unlock()
	if length <= 0 {
		return nil, ua.StatusBadInvalidArgument
	}
	if x.mode&fileModeRead == 0 {
		return nil, ua.StatusBadInvalidState
	}
	size, err := x.content.Size()
	if err != nil {
		return nil, fileStatus(err, ua.StatusBadUnexpectedError)
	}
	n := min(int64(length), int64(f.maxRead), max(size-x.pos, 0))
	b := make([]byte, n)
	k, err := x.content.ReadAt(b, x.pos)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fileStatus(err, ua.StatusBadUnexpectedError)
	}
	x.pos += int64(k)
	return b[:k], ua.StatusOK
}

// Write is the Write Method (OPC 10000-20 §4.2.5): data at the position of
// the handle, which advances by the bytes written. "Writing an empty or null
// ByteString returns a Good result code without any affect on the file." A
// handle not opened for writing is Bad_InvalidState.
func (f *FileObject) Write(ctx context.Context, h uint32, data []byte) ua.StatusCode {
	x, sc := f.handle(ctx, h)
	if sc != ua.StatusOK {
		return sc
	}
	defer x.mu.Unlock()
	if x.mode&fileModeWrite == 0 {
		return ua.StatusBadInvalidState
	}
	if len(data) == 0 {
		return ua.StatusOK
	}
	k, err := x.content.WriteAt(data, x.pos)
	x.pos += int64(k)
	if err != nil {
		return fileStatus(err, ua.StatusBadUnexpectedError)
	}
	return ua.StatusOK
}

// GetPosition is the GetPosition Method (OPC 10000-20 §4.2.6).
func (f *FileObject) GetPosition(ctx context.Context, h uint32) (uint64, ua.StatusCode) {
	x, sc := f.handle(ctx, h)
	if sc != ua.StatusOK {
		return 0, sc
	}
	defer x.mu.Unlock()
	return uint64(x.pos), ua.StatusOK
}

// SetPosition is the SetPosition Method (OPC 10000-20 §4.2.7), which clamps
// the position: "If the position is higher than the file size the position
// is set to the end of the file." (§4.2.7).
func (f *FileObject) SetPosition(ctx context.Context, h uint32, pos uint64) ua.StatusCode {
	x, sc := f.handle(ctx, h)
	if sc != ua.StatusOK {
		return sc
	}
	defer x.mu.Unlock()
	size, err := x.content.Size()
	if err != nil {
		return fileStatus(err, ua.StatusBadUnexpectedError)
	}
	x.pos = int64(min(pos, uint64(max(size, 0))))
	return ua.StatusOK
}

// The Method handlers: the arguments are those of the declarations of
// namespace 0, which the Call service has checked already when the Method
// node has them (validateMethodInputs).

func (f *FileObject) handleOpen(ctx context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	var in uamethod.FileTypeOpenInput
	if err := in.Unpack(args); err != nil {
		return nil, uamethod.StatusOf(err)
	}
	h, sc := f.Open(ctx, ua.OpenFileMode(in.Mode))
	if sc != ua.StatusOK {
		return nil, sc
	}
	return (&uamethod.FileTypeOpenOutput{FileHandle: h}).Pack(), ua.StatusOK
}

func (f *FileObject) handleClose(ctx context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	var in uamethod.FileTypeCloseInput
	if err := in.Unpack(args); err != nil {
		return nil, uamethod.StatusOf(err)
	}
	return nil, f.Close(ctx, in.FileHandle)
}

func (f *FileObject) handleRead(ctx context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	var in uamethod.FileTypeReadInput
	if err := in.Unpack(args); err != nil {
		return nil, uamethod.StatusOf(err)
	}
	b, sc := f.Read(ctx, in.FileHandle, in.Length)
	if sc != ua.StatusOK {
		return nil, sc
	}
	return (&uamethod.FileTypeReadOutput{Data: b}).Pack(), ua.StatusOK
}

func (f *FileObject) handleWrite(ctx context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	var in uamethod.FileTypeWriteInput
	if err := in.Unpack(args); err != nil {
		return nil, uamethod.StatusOf(err)
	}
	return nil, f.Write(ctx, in.FileHandle, in.Data)
}

func (f *FileObject) handleGetPosition(ctx context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	var in uamethod.FileTypeGetPositionInput
	if err := in.Unpack(args); err != nil {
		return nil, uamethod.StatusOf(err)
	}
	pos, sc := f.GetPosition(ctx, in.FileHandle)
	if sc != ua.StatusOK {
		return nil, sc
	}
	return (&uamethod.FileTypeGetPositionOutput{Position: pos}).Pack(), ua.StatusOK
}

func (f *FileObject) handleSetPosition(ctx context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	var in uamethod.FileTypeSetPositionInput
	if err := in.Unpack(args); err != nil {
		return nil, uamethod.StatusOf(err)
	}
	return nil, f.SetPosition(ctx, in.FileHandle, in.Position)
}

// fileRegistry are the FileObjects of a server, whose handles end with
// their session.
type fileRegistry struct {
	mu    sync.Mutex
	files map[*FileObject]struct{}
}

func (r *fileRegistry) add(f *FileObject) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.files == nil {
		r.files = map[*FileObject]struct{}{}
	}
	r.files[f] = struct{}{}
}

func (r *fileRegistry) remove(f *FileObject) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.files, f)
}

// sessionEnded closes the handles of a session in every file.
func (r *fileRegistry) sessionEnded(session *ua.NodeID) {
	r.mu.Lock()
	fs := make([]*FileObject, 0, len(r.files))
	for f := range r.files {
		fs = append(fs, f)
	}
	r.mu.Unlock()
	for _, f := range fs {
		f.sessionEnded(session)
	}
}
