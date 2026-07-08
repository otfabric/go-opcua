// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverEnumTypes(t *testing.T) {
	types, err := discoverEnumTypes("../../../ua", "enums*.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(types) == 0 {
		t.Fatal("expected at least one enum type")
	}
	// Verify sorted
	for i := 1; i < len(types); i++ {
		if types[i] < types[i-1] {
			t.Errorf("types not sorted: %s before %s", types[i-1], types[i])
		}
	}
	// Verify no duplicates
	seen := map[string]bool{}
	for _, typ := range types {
		if seen[typ] {
			t.Errorf("duplicate type: %s", typ)
		}
		seen[typ] = true
	}
}

func TestDiscoverEnumTypes_NoMatch(t *testing.T) {
	types, err := discoverEnumTypes("../../../ua", "nonexistent*.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(types) != 0 {
		t.Errorf("expected no types, got %d", len(types))
	}
}

func TestCleanFiles(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "test_gen.go")
	if err := os.WriteFile(f, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	// Clean should remove existing file
	if err := cleanFiles([]string{f}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Error("file should have been removed")
	}

	// Clean should tolerate already-missing files
	if err := cleanFiles([]string{f}); err != nil {
		t.Error("clean should not error on missing files")
	}
}

func TestGeneratedFileList(t *testing.T) {
	// Verify no duplicates in generatedFiles
	seen := map[string]bool{}
	for _, f := range generatedFiles {
		if seen[f] {
			t.Errorf("duplicate in generatedFiles: %s", f)
		}
		seen[f] = true
	}
}
