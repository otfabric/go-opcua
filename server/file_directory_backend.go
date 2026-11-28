// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/ua"
)

// DirectoryBackend is the storage of a [FileDirectory] (OPC 10000-20 §4.3).
// A path is the slash-separated names below the root of the FileSystem, ""
// for the root; the FileDirectory checks every name before it calls the
// backend. An error that wraps fs.ErrExist is Bad_BrowseNameDuplicated,
// one that wraps fs.ErrNotExist Bad_NotFound, a ua.StatusCode is that
// status, another error Bad_UnexpectedError.
type DirectoryBackend interface {
	// ReadDir lists the files and directories of a directory.
	ReadDir(path string) ([]DirEntry, error)
	// Mkdir creates a directory (CreateDirectory, §4.3.3).
	Mkdir(path string) error
	// CreateFile creates an empty file (CreateFile, §4.3.4).
	CreateFile(path string) error
	// File returns the content of a file.
	File(path string) FileBackend
	// Remove deletes a file, or a directory with all below it (Delete,
	// §4.3.5: "all file and directory Objects below the directory to
	// delete are deleted recursively").
	Remove(path string) error
	// Rename moves a file or directory (MoveOrCopy, §4.3.6).
	Rename(from, to string) error
	// Copy copies a file, or a directory with all below it (MoveOrCopy
	// with createCopy).
	Copy(from, to string) error
}

// DirEntry is an entry of a directory.
type DirEntry struct {
	Name string
	Dir  bool
}

// MemoryDirectory is a DirectoryBackend held in memory; its files are
// MemoryFiles.
type MemoryDirectory struct {
	mu   sync.Mutex
	root *memDir
}

type memDir struct {
	dirs  map[string]*memDir
	files map[string]*MemoryFile
}

func newMemDir() *memDir {
	return &memDir{dirs: map[string]*memDir{}, files: map[string]*MemoryFile{}}
}

// NewMemoryDirectory returns an empty MemoryDirectory.
func NewMemoryDirectory() *MemoryDirectory { return &MemoryDirectory{root: newMemDir()} }

// splitPath returns the directory and the name of a path.
func splitPath(p string) (dir, name string) {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[:i], p[i+1:]
	}
	return "", p
}

// dirLocked returns the directory of a path, nil if there is none.
func (m *MemoryDirectory) dirLocked(p string) *memDir {
	d := m.root
	if p == "" {
		return d
	}
	for _, name := range strings.Split(p, "/") {
		if d = d.dirs[name]; d == nil {
			return nil
		}
	}
	return d
}

// parentLocked returns the directory a new entry of path goes to.
func (m *MemoryDirectory) parentLocked(p string) (*memDir, string, error) {
	dir, name := splitPath(p)
	d := m.dirLocked(dir)
	if d == nil {
		return nil, "", fs.ErrNotExist
	}
	if _, ok := d.dirs[name]; ok {
		return nil, "", fs.ErrExist
	}
	if _, ok := d.files[name]; ok {
		return nil, "", fs.ErrExist
	}
	return d, name, nil
}

// ReadDir implements DirectoryBackend; the entries are sorted by name.
func (m *MemoryDirectory) ReadDir(p string) ([]DirEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d := m.dirLocked(p)
	if d == nil {
		return nil, fs.ErrNotExist
	}
	var out []DirEntry
	for name := range d.dirs {
		out = append(out, DirEntry{Name: name, Dir: true})
	}
	for name := range d.files {
		out = append(out, DirEntry{Name: name})
	}
	slices.SortFunc(out, func(a, b DirEntry) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// Mkdir implements DirectoryBackend.
func (m *MemoryDirectory) Mkdir(p string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, name, err := m.parentLocked(p)
	if err != nil {
		return err
	}
	d.dirs[name] = newMemDir()
	return nil
}

// CreateFile implements DirectoryBackend.
func (m *MemoryDirectory) CreateFile(p string) error { return m.WriteFile(p, nil) }

// WriteFile creates a file with a copy of data.
func (m *MemoryDirectory) WriteFile(p string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, name, err := m.parentLocked(p)
	if err != nil {
		return err
	}
	d.files[name] = NewMemoryFile(data)
	return nil
}

// File implements DirectoryBackend: the MemoryFile of the path, or a
// backend that reports Bad_NotFound.
func (m *MemoryDirectory) File(p string) FileBackend {
	m.mu.Lock()
	defer m.mu.Unlock()
	dir, name := splitPath(p)
	if d := m.dirLocked(dir); d != nil {
		if f := d.files[name]; f != nil {
			return f
		}
	}
	return missingFile{}
}

// missingFile is the backend of a file that does not exist.
type missingFile struct{}

func (missingFile) Open(context.Context, ua.OpenFileMode) (FileContent, error) {
	return nil, ua.StatusBadNotFound
}
func (missingFile) Size() (uint64, error) { return 0, ua.StatusBadNotFound }

// lookupLocked returns the directory that holds the entry of a path.
func (m *MemoryDirectory) lookupLocked(p string) (*memDir, string, error) {
	dir, name := splitPath(p)
	d := m.dirLocked(dir)
	if d == nil || p == "" {
		return nil, "", fs.ErrNotExist
	}
	if _, ok := d.dirs[name]; !ok {
		if _, ok := d.files[name]; !ok {
			return nil, "", fs.ErrNotExist
		}
	}
	return d, name, nil
}

// Remove implements DirectoryBackend.
func (m *MemoryDirectory) Remove(p string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, name, err := m.lookupLocked(p)
	if err != nil {
		return err
	}
	delete(d.dirs, name)
	delete(d.files, name)
	return nil
}

// Rename implements DirectoryBackend.
func (m *MemoryDirectory) Rename(from, to string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	src, name, err := m.lookupLocked(from)
	if err != nil {
		return err
	}
	dst, newName, err := m.parentLocked(to)
	if err != nil {
		return err
	}
	if sub, ok := src.dirs[name]; ok {
		delete(src.dirs, name)
		dst.dirs[newName] = sub
		return nil
	}
	f := src.files[name]
	delete(src.files, name)
	dst.files[newName] = f
	return nil
}

// Copy implements DirectoryBackend.
func (m *MemoryDirectory) Copy(from, to string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	src, name, err := m.lookupLocked(from)
	if err != nil {
		return err
	}
	dst, newName, err := m.parentLocked(to)
	if err != nil {
		return err
	}
	if sub, ok := src.dirs[name]; ok {
		dst.dirs[newName] = sub.clone()
		return nil
	}
	dst.files[newName] = NewMemoryFile(src.files[name].Bytes())
	return nil
}

func (d *memDir) clone() *memDir {
	c := newMemDir()
	for name, sub := range d.dirs {
		c.dirs[name] = sub.clone()
	}
	for name, f := range d.files {
		c.files[name] = NewMemoryFile(f.Bytes())
	}
	return c
}

// OSDirectory is a DirectoryBackend of a directory of the operating system,
// opened with os.OpenRoot: no path leaves it (a symbolic link out of it is
// an error).
type OSDirectory struct {
	root *os.Root
	// Perm is the permission of the files CreateFile creates; zero is
	// 0o600. Directories get 0o700.
	Perm fs.FileMode
}

// NewOSDirectory opens the directory dir.
func NewOSDirectory(dir string) (*OSDirectory, error) {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &OSDirectory{root: r}, nil
}

// Close closes the directory.
func (d *OSDirectory) Close() error { return d.root.Close() }

func osPath(p string) string {
	if p == "" {
		return "."
	}
	return p
}

// ReadDir implements DirectoryBackend; entries that are neither a regular
// file nor a directory are left out.
func (d *OSDirectory) ReadDir(p string) ([]DirEntry, error) {
	es, err := fs.ReadDir(d.root.FS(), osPath(p))
	if err != nil {
		return nil, err
	}
	var out []DirEntry
	for _, e := range es {
		switch {
		case e.IsDir():
			out = append(out, DirEntry{Name: e.Name(), Dir: true})
		case e.Type().IsRegular():
			out = append(out, DirEntry{Name: e.Name()})
		}
	}
	return out, nil
}

// Mkdir implements DirectoryBackend.
func (d *OSDirectory) Mkdir(p string) error { return d.root.Mkdir(p, 0o700) }

func (d *OSDirectory) perm() fs.FileMode {
	if d.Perm == 0 {
		return 0o600
	}
	return d.Perm
}

// CreateFile implements DirectoryBackend.
func (d *OSDirectory) CreateFile(p string) error {
	f, err := d.root.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, d.perm())
	if err != nil {
		return err
	}
	return f.Close()
}

// File implements DirectoryBackend.
func (d *OSDirectory) File(p string) FileBackend { return &rootFile{d: d, path: p} }

// Remove implements DirectoryBackend.
func (d *OSDirectory) Remove(p string) error {
	if _, err := d.root.Lstat(p); err != nil {
		return err
	}
	return d.root.RemoveAll(p)
}

// Rename implements DirectoryBackend; an existing target is fs.ErrExist.
func (d *OSDirectory) Rename(from, to string) error {
	if _, err := d.root.Lstat(to); err == nil {
		return fs.ErrExist
	}
	return d.root.Rename(from, to)
}

// Copy implements DirectoryBackend.
func (d *OSDirectory) Copy(from, to string) error {
	fi, err := d.root.Stat(from)
	if err != nil {
		return err
	}
	if _, err := d.root.Lstat(to); err == nil {
		return fs.ErrExist
	}
	if !fi.IsDir() {
		return d.copyFile(from, to)
	}
	if err := d.root.Mkdir(to, 0o700); err != nil {
		return err
	}
	es, err := d.ReadDir(from)
	if err != nil {
		return err
	}
	for _, e := range es {
		if err := d.Copy(path.Join(from, e.Name), path.Join(to, e.Name)); err != nil {
			return err
		}
	}
	return nil
}

func (d *OSDirectory) copyFile(from, to string) error {
	src, err := d.root.Open(from)
	if err != nil {
		return err
	}
	dst, err := d.root.OpenFile(to, os.O_CREATE|os.O_EXCL|os.O_WRONLY, d.perm())
	if err != nil {
		return errors.Join(err, src.Close())
	}
	_, err = io.Copy(dst, src)
	return errors.Join(err, dst.Close(), src.Close())
}

// rootFile is the FileBackend of a file of an OSDirectory.
type rootFile struct {
	d    *OSDirectory
	path string
}

func (f *rootFile) Open(_ context.Context, mode ua.OpenFileMode) (FileContent, error) {
	h, err := f.d.root.OpenFile(f.path, osFlags(mode), f.d.perm())
	if err != nil {
		return nil, osStatus(err)
	}
	return osContent{h}, nil
}

func (f *rootFile) Size() (uint64, error) {
	fi, err := f.d.root.Stat(f.path)
	if err != nil {
		return 0, osStatus(err)
	}
	return uint64(fi.Size()), nil
}

func (f *rootFile) ModTime() (time.Time, error) {
	fi, err := f.d.root.Stat(f.path)
	if err != nil {
		return time.Time{}, osStatus(err)
	}
	return fi.ModTime(), nil
}
