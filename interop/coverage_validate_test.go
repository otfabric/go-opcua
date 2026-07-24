// SPDX-License-Identifier: MIT

package interop_test

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCoverageManifestValid(t *testing.T) {
	root := findModuleRoot(t)
	// Re-run the renderer validation by invoking the same files the tool uses.
	capPath := filepath.Join(root, "interop", "capabilities.json")
	covPath := filepath.Join(root, "interop", "coverage.json")

	caps := mustReadJSON[struct {
		Capabilities []struct {
			ID                   string   `json:"id"`
			ApplicableDirections []string `json:"applicableDirections"`
		} `json:"capabilities"`
	}](t, capPath)

	cov := mustReadJSON[struct {
		InteropVersion string `json:"interopVersion"`
		Entries        []struct {
			Capability string `json:"capability"`
			Direction  string `json:"direction"`
			Status     string `json:"status"`
			Test       string `json:"test"`
			Issue      string `json:"issue"`
			Reason     string `json:"reason"`
		} `json:"entries"`
	}](t, covPath)

	if cov.InteropVersion != "v0.5.0" {
		t.Fatalf("interopVersion = %q, want v0.5.0", cov.InteropVersion)
	}

	tests := listInteropTestFuncs(t, filepath.Join(root, "interop"))
	for _, e := range cov.Entries {
		switch e.Status {
		case "verified", "blocked":
			if e.Test == "" {
				t.Errorf("%s/%s: %s missing test", e.Capability, e.Direction, e.Status)
				continue
			}
			if !tests[e.Test] {
				t.Errorf("%s/%s: test %q not found in interop package", e.Capability, e.Direction, e.Test)
			}
			if e.Status == "blocked" && (e.Issue == "" || e.Reason == "") {
				t.Errorf("%s/%s: blocked requires issue and reason", e.Capability, e.Direction)
			}
		}
	}

	capIDs := map[string]bool{}
	for _, c := range caps.Capabilities {
		capIDs[c.ID] = true
	}
	for _, e := range cov.Entries {
		if !capIDs[e.Capability] {
			t.Errorf("unknown capability %q", e.Capability)
		}
	}
}

func listInteropTestFuncs(t *testing.T, dir string) map[string]bool {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "*_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	out := map[string]bool{}
	for _, path := range matches {
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Name == nil {
				continue
			}
			name := fn.Name.Name
			if strings.HasPrefix(name, "Test") {
				out[name] = true
			}
		}
	}
	return out
}

func findModuleRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		p := filepath.Dir(dir)
		if p == dir {
			t.Fatal("go.mod not found")
		}
		dir = p
	}
}

func mustReadJSON[T any](t *testing.T, path string) T {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}
