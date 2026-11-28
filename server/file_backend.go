// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/ua"
)

// The backends of a FileObject: SnapshotFile for the files of a subtype
// whose writes a CloseAndUpdate Method applies, MemoryFile and OSFile for a
// plain file.

// bytesContent is the content of a handle held in memory.
type bytesContent struct {
	data     []byte
	readOnly bool
	// maxSize bounds the content when > 0; a Write past it fails with
	// exceeded.
	maxSize  int
	exceeded ua.StatusCode
	// commit, if set, is called by Close of a content opened for writing.
	commit func([]byte)
}

func (b *bytesContent) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, ua.StatusBadInvalidArgument
	}
	if off >= int64(len(b.data)) {
		return 0, io.EOF
	}
	n := copy(p, b.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (b *bytesContent) WriteAt(p []byte, off int64) (int, error) {
	if b.readOnly {
		return 0, ua.StatusBadInvalidState
	}
	if off < 0 || off > int64(len(b.data)) {
		return 0, ua.StatusBadInvalidArgument
	}
	end := off + int64(len(p))
	if b.maxSize > 0 && end > int64(b.maxSize) {
		return 0, b.exceeded
	}
	if end > int64(len(b.data)) {
		b.data = append(b.data, make([]byte, end-int64(len(b.data)))...)
	}
	return copy(b.data[off:], p), nil
}

func (b *bytesContent) Size() (int64, error) { return int64(len(b.data)), nil }

// fileDiscarder is a FileContent whose Close can drop what the handle
// holds instead of keeping it: a MemoryFile does not replace its content
// with that of a handle that Open never returned.
type fileDiscarder interface{ discard() }

func (b *bytesContent) discard() { b.commit = nil }

func (b *bytesContent) Close() error {
	if b.commit != nil {
		b.commit(b.data)
	}
	return nil
}

// SnapshotFile is a FileBackend whose content is made by Content for each
// handle, and whose writes stay with the handle: Close discards them, the
// CloseAndUpdate Method of a subtype of FileType takes them with
// [FileObject.CloseAndTake]. It is the file of a TrustList (Part 12
// §7.8.2: "the Server shall not apply the changes until the CloseAndUpdate
// Method is called"), of the PubSubConfiguration (Part 14 §9.1.3.7) and of
// the ConnectionManagerConfiguration of OPC UA FX.
type SnapshotFile struct {
	// Content returns the content of the file. A handle opened without
	// EraseExisting starts with it.
	Content func(ctx context.Context) ([]byte, error)
	// MaxSize bounds what a handle holds; zero is no bound.
	MaxSize int
	// SizeExceeded is the status of a Write past MaxSize; zero is
	// Bad_ResourceUnavailable. OPC 10000-20 §4.2.5 names no code for it.
	SizeExceeded ua.StatusCode
}

// Open implements FileBackend.
func (f *SnapshotFile) Open(ctx context.Context, mode ua.OpenFileMode) (FileContent, error) {
	c := &bytesContent{readOnly: mode&fileModeWrite == 0, maxSize: f.MaxSize, exceeded: f.SizeExceeded}
	if c.exceeded == 0 {
		c.exceeded = ua.StatusBadResourceUnavailable
	}
	if mode&fileModeEraseExisting == 0 {
		b, err := f.Content(ctx)
		if err != nil {
			return nil, err
		}
		if !c.readOnly {
			b = slices.Clone(b)
		}
		c.data = b
	}
	return c, nil
}

// Size implements FileBackend: the size of Content.
func (f *SnapshotFile) Size() (uint64, error) {
	b, err := f.Content(context.Background())
	if err != nil {
		return 0, err
	}
	return uint64(len(b)), nil
}

// MemoryFile is a FileBackend held in memory. A handle opened for writing
// works on a copy, which becomes the content when the handle is closed:
// with Close, or at the end of its session (OPC 10000-20 §4.2.5 leaves that
// to the server). Readers see the content of the time they opened the file.
type MemoryFile struct {
	// MaxSize bounds the content; a Write past it is
	// Bad_ResourceUnavailable. Zero is no bound.
	MaxSize int

	mu   sync.Mutex
	data []byte
	mod  time.Time
}

// NewMemoryFile returns a MemoryFile with a copy of data.
func NewMemoryFile(data []byte) *MemoryFile {
	return &MemoryFile{data: slices.Clone(data), mod: time.Now()}
}

// Bytes returns a copy of the content.
func (m *MemoryFile) Bytes() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.data)
}

// SetBytes replaces the content with a copy of data. A FileObject of the
// file does not know: call its Changed when the Properties should be
// notified.
func (m *MemoryFile) SetBytes(data []byte) {
	m.set(slices.Clone(data))
}

func (m *MemoryFile) set(data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data, m.mod = data, time.Now()
}

// Open implements FileBackend.
func (m *MemoryFile) Open(_ context.Context, mode ua.OpenFileMode) (FileContent, error) {
	m.mu.Lock()
	data := m.data
	m.mu.Unlock()
	if mode&fileModeWrite == 0 {
		// The content is never changed in place: a writer replaces it.
		return &bytesContent{data: data, readOnly: true}, nil
	}
	c := &bytesContent{maxSize: m.MaxSize, exceeded: ua.StatusBadResourceUnavailable, commit: m.set}
	if mode&fileModeEraseExisting == 0 {
		c.data = slices.Clone(data)
	}
	return c, nil
}

// Size implements FileBackend.
func (m *MemoryFile) Size() (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return uint64(len(m.data)), nil
}

// ModTime implements FileModTimer: when the content was last replaced.
func (m *MemoryFile) ModTime() (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mod, nil
}

// OSFile is a FileBackend of a file of the operating system. A handle is an
// open *os.File: writes go to the file as they come. Open for writing
// creates a file that does not exist (with Perm); for reading, a file that
// does not exist is Bad_NotFound.
type OSFile struct {
	Path string
	// Perm is the permission of a file Open creates; zero is 0o600.
	Perm fs.FileMode
}

// NewOSFile returns the OSFile of path.
func NewOSFile(path string) *OSFile { return &OSFile{Path: path} }

// Open implements FileBackend.
func (o *OSFile) Open(_ context.Context, mode ua.OpenFileMode) (FileContent, error) {
	f, err := os.OpenFile(o.Path, osFlags(mode), o.perm())
	if err != nil {
		return nil, osStatus(err)
	}
	return osContent{f}, nil
}

func (o *OSFile) perm() fs.FileMode {
	if o.Perm == 0 {
		return 0o600
	}
	return o.Perm
}

// osFlags are the flags of os.OpenFile for a mode of Open.
func osFlags(mode ua.OpenFileMode) int {
	flag := os.O_RDONLY
	switch {
	case mode&fileModeWrite != 0 && mode&fileModeRead != 0:
		flag = os.O_RDWR | os.O_CREATE
	case mode&fileModeWrite != 0:
		flag = os.O_WRONLY | os.O_CREATE
	}
	if mode&fileModeEraseExisting != 0 {
		flag |= os.O_TRUNC
	}
	return flag
}

// Size implements FileBackend.
func (o *OSFile) Size() (uint64, error) {
	fi, err := os.Stat(o.Path)
	if err != nil {
		return 0, osStatus(err)
	}
	return uint64(fi.Size()), nil
}

// ModTime implements FileModTimer.
func (o *OSFile) ModTime() (time.Time, error) {
	fi, err := os.Stat(o.Path)
	if err != nil {
		return time.Time{}, osStatus(err)
	}
	return fi.ModTime(), nil
}

// osStatus returns Bad_NotFound for a file that does not exist (OPC
// 10000-20 §4.2.2, Table 4), err otherwise.
func osStatus(err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return errors.Join(ua.StatusBadNotFound, err)
	}
	return err
}

// osContent is the content of a handle of an OSFile.
type osContent struct{ f *os.File }

func (c osContent) ReadAt(p []byte, off int64) (int, error)  { return c.f.ReadAt(p, off) }
func (c osContent) WriteAt(p []byte, off int64) (int, error) { return c.f.WriteAt(p, off) }
func (c osContent) Close() error                             { return c.f.Close() }

func (c osContent) Size() (int64, error) {
	fi, err := c.f.Stat()
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}
