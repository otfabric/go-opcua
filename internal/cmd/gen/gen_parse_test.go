// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverEnumTypes_ParseError(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "broken.go")
	if err := os.WriteFile(bad, []byte("package p\nfunc {"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := discoverEnumTypes(dir, "*.go")
	if err == nil {
		t.Fatal("expected parse error for invalid Go syntax")
	}
}
