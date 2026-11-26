// SPDX-License-Identifier: MIT

package fxstore

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func openTemp(t *testing.T) (*FileStore, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "s")
	f, err := OpenFile(dir, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f, dir
}

func TestFileStoreLock(t *testing.T) {
	f, dir := openTemp(t)
	if _, err := OpenFile(dir, Limits{}); !errors.Is(err, ErrLocked) {
		t.Fatalf("second OpenFile: %v; want ErrLocked", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	g, err := OpenFile(dir, Limits{})
	if err != nil {
		t.Fatalf("OpenFile after Close: %v", err)
	}
	_ = g.Close()
	if g.Dir() != dir {
		t.Errorf("Dir = %q", g.Dir())
	}
}

func TestFileStoreOpenErrors(t *testing.T) {
	if _, err := OpenFile("", Limits{}); err == nil {
		t.Error("OpenFile with no directory")
	}
	base := t.TempDir()
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(file, Limits{}); err == nil {
		t.Error("OpenFile on a file")
	}
	if _, err := OpenFile(filepath.Join(file, "sub"), Limits{}); err == nil {
		t.Error("OpenFile below a file")
	}
	if runtime.GOOS != "windows" {
		open := filepath.Join(base, "open")
		if err := os.Mkdir(open, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(open, 0o777); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFile(open, Limits{}); err == nil {
			t.Error("OpenFile on a directory others may write")
		}
	}
	// A data file that is a directory cannot be read.
	bad := filepath.Join(base, "bad")
	if err := os.MkdirAll(filepath.Join(bad, dataName, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(bad, Limits{}); err == nil {
		t.Error("OpenFile with a data file that is a directory")
	}
	// A temporary file that cannot be removed.
	tmp := filepath.Join(base, "tmp")
	if err := os.MkdirAll(filepath.Join(tmp, tempName, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(tmp, Limits{}); err == nil {
		t.Error("OpenFile with a temporary file that cannot be removed")
	}
}

func TestFileStoreRemovesTemp(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "s")
	f, err := OpenFile(dir, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Apply(context.Background(), Batch{Puts: map[string][]byte{"a": []byte("1")}}); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if err := os.WriteFile(filepath.Join(dir, tempName), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	g, err := OpenFile(dir, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if _, err := os.Stat(filepath.Join(dir, tempName)); !os.IsNotExist(err) {
		t.Errorf("temporary file left: %v", err)
	}
	st, _ := g.Load(context.Background())
	if string(st["a"]) != "1" {
		t.Errorf("state = %v", st)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(filepath.Join(dir, dataName))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("data file mode %v, %v", fi.Mode().Perm(), err)
		}
	}
}

func TestFileStoreCorrupt(t *testing.T) {
	good := encodeState(map[string][]byte{"a": []byte("1"), "b": []byte("22")})
	sum := func(b []byte) []byte {
		return binary.LittleEndian.AppendUint32(b, crc32.Checksum(b, castagnoli))
	}
	body := func(count uint32, entries ...[]byte) []byte {
		b := append([]byte(nil), fileMagic[:]...)
		b = binary.LittleEndian.AppendUint32(b, fileVersion)
		b = binary.LittleEndian.AppendUint32(b, count)
		for _, e := range entries {
			b = append(b, e...)
		}
		return sum(b)
	}
	entry := func(k, v string) []byte {
		b := binary.LittleEndian.AppendUint32(nil, uint32(len(k)))
		b = append(b, k...)
		b = binary.LittleEndian.AppendUint32(b, uint32(len(v)))
		return append(b, v...)
	}
	flipped := append([]byte(nil), good...)
	flipped[len(flipped)/2] ^= 0xff
	version := append([]byte(nil), good[:len(good)-4]...)
	binary.LittleEndian.PutUint32(version[4:], 9)
	magic := append([]byte(nil), good[:len(good)-4]...)
	magic[0] = 'X'
	for name, data := range map[string][]byte{
		"short":       {1, 2, 3},
		"magic":       sum(magic),
		"checksum":    flipped,
		"version":     sum(version),
		"too many":    body(DefaultMaxKeys + 1),
		"truncated":   body(1, entry("a", "1")[:6]),
		"no length":   body(1, entry("a", "1")[:2]),
		"long key":    body(1, entry(string(make([]byte, DefaultMaxKey+1)), "")),
		"empty key":   body(1, entry("", "x")),
		"duplicate":   body(2, entry("a", "1"), entry("a", "2")),
		"trailing":    body(1, entry("a", "1"), []byte{0}),
		"value short": body(1, entry("a", "")[:5], binary.LittleEndian.AppendUint32(nil, 10)),
	} {
		if _, err := decodeState(data, Limits{}); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	if _, err := decodeState(body(2, entry("a", "12345"), entry("b", "12345")), Limits{MaxTotal: 8}); !errors.Is(err, ErrLimit) {
		t.Errorf("total over limit: %v", err)
	}
	st, err := decodeState(good, Limits{})
	if err != nil || len(st) != 2 || string(st["b"]) != "22" {
		t.Errorf("good file: %v, %v", st, err)
	}

	dir := filepath.Join(t.TempDir(), "s")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, dataName), flipped, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(dir, Limits{}); !errors.Is(err, ErrCorrupt) {
		t.Errorf("OpenFile of a corrupt store: %v", err)
	}
	// A file over the limits is refused before it is read.
	if err := os.WriteFile(filepath.Join(dir, dataName), make([]byte, 200), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(dir, Limits{MaxTotal: 10, MaxKeys: 1}); !errors.Is(err, ErrLimit) {
		t.Errorf("OpenFile of an oversized store: %v", err)
	}
}

func FuzzDecodeState(f *testing.F) {
	f.Add(encodeState(map[string][]byte{"ac/meta": {1, 2}, "ac/ep/x": []byte("value")}))
	f.Add(encodeState(map[string][]byte{}))
	f.Add([]byte("FXST"))
	f.Fuzz(func(t *testing.T, data []byte) {
		st, err := decodeState(data, Limits{MaxKeys: 64, MaxValue: 1 << 12, MaxTotal: 1 << 14})
		if err != nil {
			return
		}
		if !bytes.Equal(encodeState(st), data) {
			t.Fatalf("decoded file does not encode back")
		}
	})
}

type faultHooks struct {
	syncFile, rename, syncDir bool
}

func withFaults(t *testing.T, h faultHooks) {
	t.Helper()
	sf, rn, sd := syncFile, rename, syncDir
	t.Cleanup(func() { syncFile, rename, syncDir = sf, rn, sd })
	boom := errors.New("boom")
	if h.syncFile {
		syncFile = func(*os.File) error { return boom }
	}
	if h.rename {
		rename = func(string, string) error { return boom }
	}
	if h.syncDir {
		syncDir = func(string) error { return boom }
	}
}

func TestFileStoreFaults(t *testing.T) {
	ctx := context.Background()
	t.Run("fsync of the file fails: not committed", func(t *testing.T) {
		f, _ := openTemp(t)
		withFaults(t, faultHooks{syncFile: true})
		err := f.Apply(ctx, Batch{Puts: map[string][]byte{"a": []byte("1")}})
		if OutcomeOf(err) != NotCommitted {
			t.Fatalf("Apply: %v", err)
		}
		st, _ := f.Load(ctx)
		if len(st) != 0 {
			t.Fatalf("state after a failed fsync: %v", st)
		}
	})
	t.Run("rename fails: unknown, rebuilt on the file", func(t *testing.T) {
		f, _ := openTemp(t)
		if err := f.Apply(ctx, Batch{Puts: map[string][]byte{"a": []byte("1")}}); err != nil {
			t.Fatal(err)
		}
		withFaults(t, faultHooks{rename: true})
		if err := f.Apply(ctx, Batch{Puts: map[string][]byte{"b": []byte("2")}}); OutcomeOf(err) != Unknown {
			t.Fatalf("Apply: %v", err)
		}
		rename = os.Rename
		if err := f.Apply(ctx, Batch{Puts: map[string][]byte{"c": []byte("3")}}); err != nil {
			t.Fatal(err)
		}
		st, _ := f.Load(ctx)
		if len(st) != 2 || st["b"] != nil {
			t.Fatalf("the next Apply is not built on the data file: %v", st)
		}
	})
	t.Run("directory fsync fails: unknown though visible", func(t *testing.T) {
		f, _ := openTemp(t)
		withFaults(t, faultHooks{syncDir: true})
		err := f.Apply(ctx, Batch{Puts: map[string][]byte{"a": []byte("1")}})
		if OutcomeOf(err) != Unknown {
			t.Fatalf("Apply: %v", err)
		}
		st, _ := f.Load(ctx)
		if string(st["a"]) != "1" {
			t.Fatalf("the renamed file is not visible: %v", st)
		}
	})
	t.Run("stale state that cannot be reread: not committed", func(t *testing.T) {
		f, dir := openTemp(t)
		withFaults(t, faultHooks{syncDir: true})
		_ = f.Apply(ctx, Batch{Puts: map[string][]byte{"a": []byte("1")}})
		syncDir = syncDirectory
		if err := os.WriteFile(filepath.Join(dir, dataName), []byte("junk"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := f.Apply(ctx, Batch{}); OutcomeOf(err) != NotCommitted {
			t.Fatalf("Apply on a corrupt data file: %v", err)
		}
		if _, err := f.Load(ctx); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Load of a corrupt data file: %v", err)
		}
	})
	t.Run("write fails: not committed", func(t *testing.T) {
		f, dir := openTemp(t)
		if err := os.Mkdir(filepath.Join(dir, tempName), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := f.Apply(ctx, Batch{Puts: map[string][]byte{"a": nil}}); OutcomeOf(err) != NotCommitted {
			t.Fatalf("Apply: %v", err)
		}
	})
}

func TestFileStoreDurability(t *testing.T) {
	f, _ := openTemp(t)
	want := DurabilityPowerLoss
	if runtime.GOOS == "windows" {
		want = DurabilityProcessCrash
	}
	if f.Durability() != want {
		t.Errorf("Durability = %v; want %v", f.Durability(), want)
	}
}

func TestAppendLen(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("appendLen(-1) did not panic")
		}
	}()
	appendLen(nil, -1)
}
