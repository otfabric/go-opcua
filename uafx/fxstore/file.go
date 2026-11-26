// SPDX-License-Identifier: MIT

package fxstore

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// FileStore is a Store in a local directory: a lock file and one data file
// with the whole state. Apply writes the new state to a temporary file,
// fsyncs it, renames it over the data file and fsyncs the directory, so a
// committed Apply survives a crash of the process and, where the file system
// honours fsync, a power loss (prefix durability: every Apply rewrites the
// whole state). An error before the rename is ErrNotCommitted; an error at
// or after it, the directory fsync included, is an unknown outcome.
//
// One FileStore owns its directory: Open takes an exclusive lock (flock on
// Unix, an exclusive open of the lock file on Windows) and holds it until
// Close; a second Open, in this process or another, fails with ErrLocked.
// It is safe for concurrent use; Applies are serialized.
//
// Platform limits: on Windows a directory cannot be fsynced, so a renamed
// data file survives a crash of the process but its rename is only as
// durable as the file system's metadata journal makes it: Durability is
// DurabilityProcessCrash there, DurabilityPowerLoss elsewhere. Network file
// systems (NFS, SMB) and file systems that ignore fsync or advisory locks
// are not supported: neither the lock nor the durability holds on them.
// Platforms without flock (other than Unix systems with it and Windows)
// cannot open a FileStore.
//
// The directory is created 0700 if missing; a directory that the group or
// others may write is refused, and the files are created 0600. The data is
// stored as written: an application that needs encryption at rest wraps
// the Store.
//
// FileStore is meant for the size of a configuration (a few MiB): Apply is
// O(state).
type FileStore struct {
	dir    string
	limits Limits

	mu     sync.Mutex
	lock   io.Closer
	state  map[string][]byte // the data file as last written or read
	stale  bool              // state may differ from the data file
	closed bool
}

var (
	_ Store   = (*FileStore)(nil)
	_ Durable = (*FileStore)(nil)
)

// File names in the directory of a FileStore.
const (
	lockName = "LOCK"
	dataName = "state"
	tempName = "state.tmp"
)

// The data file: magic, a format version, the number of entries, the
// entries (key length, key, value length, value), and the CRC-32C of
// everything before it. All integers are little endian uint32.
var fileMagic = [4]byte{'F', 'X', 'S', 'T'}

const fileVersion = 1

// headerLen is magic, version and count; entryOverhead the two lengths of
// an entry; trailerLen the checksum.
const (
	headerLen     = 12
	entryOverhead = 8
	trailerLen    = 4
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// Test hooks: the file operations of Apply, replaced to inject faults.
var (
	syncFile = func(f *os.File) error { return f.Sync() }
	rename   = os.Rename
	syncDir  = syncDirectory
)

// OpenFile opens the FileStore in dir, creating dir and an empty store if
// missing. It removes a temporary file a crash left. It fails with
// ErrLocked when another writer has the store, with ErrCorrupt when the
// data file does not decode, and with ErrLimit when it is over limits.
func OpenFile(dir string, limits Limits) (*FileStore, error) {
	if dir == "" {
		return nil, errors.New("fxstore: no directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("fxstore: %w", err)
	}
	if err := checkDirMode(dir); err != nil {
		return nil, err
	}
	l, err := lockDir(filepath.Join(dir, lockName))
	if err != nil {
		return nil, err
	}
	f := &FileStore{dir: dir, limits: limits.withDefaults(), lock: l}
	if err := os.Remove(filepath.Join(dir, tempName)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		_ = l.Close()
		return nil, fmt.Errorf("fxstore: %w", err)
	}
	state, err := f.read()
	if err != nil {
		_ = l.Close()
		return nil, err
	}
	f.state = state
	return f, nil
}

// checkDirMode refuses a directory the group or others may write.
func checkDirMode(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("fxstore: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("fxstore: %s is not a directory", dir)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("fxstore: %s is writable by the group or others (mode %v)", dir, fi.Mode().Perm())
	}
	return nil
}

// Dir returns the directory of the store.
func (f *FileStore) Dir() string { return f.dir }

// Durability is DurabilityPowerLoss, or DurabilityProcessCrash on Windows.
func (f *FileStore) Durability() Durability {
	if runtime.GOOS == "windows" {
		return DurabilityProcessCrash
	}
	return DurabilityPowerLoss
}

// Load reads the data file.
func (f *FileStore) Load(ctx context.Context) (map[string][]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil, ErrClosed
	}
	state, err := f.read()
	if err != nil {
		return nil, err
	}
	f.state, f.stale = state, false
	return cloneState(state), nil
}

// Apply writes the state with b applied.
func (f *FileStore) Apply(ctx context.Context, b Batch) error {
	if err := ctx.Err(); err != nil {
		return AsNotCommitted(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return ErrClosed
	}
	if f.stale {
		// After an unknown outcome the data file is the truth: the next
		// state is built on it (prefix durability).
		state, err := f.read()
		if err != nil {
			return AsNotCommitted(err)
		}
		f.state, f.stale = state, false
	}
	next := applyBatch(f.state, b)
	if err := f.limits.check(next); err != nil {
		return AsNotCommitted(err)
	}
	data := encodeState(next)
	tmp := filepath.Join(f.dir, tempName)
	if err := writeFile(tmp, data); err != nil {
		_ = os.Remove(tmp)
		return AsNotCommitted(err)
	}
	if err := ctx.Err(); err != nil {
		_ = os.Remove(tmp)
		return AsNotCommitted(err)
	}
	if err := rename(tmp, filepath.Join(f.dir, dataName)); err != nil {
		// A failed rename may have happened all the same on some systems.
		f.stale = true
		return fmt.Errorf("fxstore: rename: %w", err)
	}
	if err := syncDir(f.dir); err != nil {
		f.stale = true
		return fmt.Errorf("fxstore: sync directory: %w", err)
	}
	f.state = next
	return nil
}

// Close releases the lock. Load and Apply then return ErrClosed.
func (f *FileStore) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed, f.state = true, nil
	return f.lock.Close()
}

// read reads and decodes the data file; a missing file is an empty state.
// The size is checked before the file is read.
func (f *FileStore) read() (map[string][]byte, error) {
	h, err := os.Open(filepath.Join(f.dir, dataName))
	if errors.Is(err, fs.ErrNotExist) {
		return map[string][]byte{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("fxstore: %w", err)
	}
	defer h.Close()
	fi, err := h.Stat()
	if err != nil {
		return nil, fmt.Errorf("fxstore: %w", err)
	}
	maxFile := maxFileSize(f.limits)
	if fi.Size() > maxFile {
		return nil, fmt.Errorf("%w: data file of %d bytes", ErrLimit, fi.Size())
	}
	data, err := io.ReadAll(io.LimitReader(h, maxFile+1))
	if err != nil {
		return nil, fmt.Errorf("fxstore: %w", err)
	}
	return decodeState(data, f.limits)
}

// maxFileSize is the largest data file within l.
func maxFileSize(l Limits) int64 {
	return headerLen + l.MaxTotal + int64(l.MaxKeys)*entryOverhead + trailerLen
}

func writeFile(name string, data []byte) error {
	h, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := h.Write(data); err != nil {
		_ = h.Close()
		return err
	}
	if err := syncFile(h); err != nil {
		_ = h.Close()
		return err
	}
	return h.Close()
}

// encodeState returns the data file of state, its keys sorted.
func encodeState(state map[string][]byte) []byte {
	keys := sortedKeys(state)
	n := headerLen + trailerLen
	for _, k := range keys {
		n += entryOverhead + len(k) + len(state[k])
	}
	b := make([]byte, 0, n)
	b = append(b, fileMagic[:]...)
	b = binary.LittleEndian.AppendUint32(b, fileVersion)
	b = appendLen(b, len(keys))
	for _, k := range keys {
		b = appendLen(b, len(k))
		b = append(b, k...)
		v := state[k]
		b = appendLen(b, len(v))
		b = append(b, v...)
	}
	return binary.LittleEndian.AppendUint32(b, crc32.Checksum(b, castagnoli))
}

// appendLen appends the length n, which Limits keep far below 2^32.
func appendLen(b []byte, n int) []byte {
	if n < 0 || uint64(n) > math.MaxUint32 {
		panic("fxstore: length out of range")
	}
	return binary.LittleEndian.AppendUint32(b, uint32(n))
}

// decodeState decodes a data file within l.
func decodeState(data []byte, l Limits) (map[string][]byte, error) {
	l = l.withDefaults()
	corrupt := func(what string) error { return fmt.Errorf("%w: %s", ErrCorrupt, what) }
	if len(data) < headerLen+trailerLen {
		return nil, corrupt("short data file")
	}
	if !bytes.Equal(data[:4], fileMagic[:]) {
		return nil, corrupt("not a store data file")
	}
	body, sum := data[:len(data)-trailerLen], binary.LittleEndian.Uint32(data[len(data)-trailerLen:])
	if crc32.Checksum(body, castagnoli) != sum {
		return nil, corrupt("checksum mismatch")
	}
	if v := binary.LittleEndian.Uint32(data[4:]); v != fileVersion {
		return nil, fmt.Errorf("%w: data file version %d", ErrCorrupt, v)
	}
	count := binary.LittleEndian.Uint32(data[8:])
	if int64(count) > int64(l.MaxKeys) {
		return nil, fmt.Errorf("%w: %d keys", ErrLimit, count)
	}
	state := make(map[string][]byte, count)
	p := body[headerLen:]
	var total int64
	next := func(limit int) ([]byte, error) {
		if len(p) < 4 {
			return nil, corrupt("truncated entry")
		}
		n := binary.LittleEndian.Uint32(p)
		p = p[4:]
		if int64(n) > int64(limit) {
			return nil, fmt.Errorf("%w: entry of %d bytes", ErrLimit, n)
		}
		if int64(n) > int64(len(p)) {
			return nil, corrupt("truncated entry")
		}
		x := p[:n]
		p = p[n:]
		return x, nil
	}
	for range count {
		k, err := next(l.MaxKey)
		if err != nil {
			return nil, err
		}
		v, err := next(l.MaxValue)
		if err != nil {
			return nil, err
		}
		if len(k) == 0 {
			return nil, corrupt("empty key")
		}
		if _, dup := state[string(k)]; dup {
			return nil, corrupt("duplicate key")
		}
		total += int64(len(k)) + int64(len(v))
		if total > l.MaxTotal {
			return nil, fmt.Errorf("%w: total size over %d", ErrLimit, l.MaxTotal)
		}
		state[string(k)] = clone(v)
	}
	if len(p) != 0 {
		return nil, corrupt("trailing data")
	}
	return state, nil
}
