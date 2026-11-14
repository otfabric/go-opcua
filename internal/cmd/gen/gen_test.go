// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
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

// stringerOutput is a String method as stringer writes it for a run of
// values starting at k.
func stringerOutput(typ string, k int) string {
	return fmt.Sprintf(`func (i %[1]s) String() string {
	idx := int(i) - %[2]d
	if i < %[2]d || idx >= len(_%[1]s_index)-1 {
		return "%[1]s(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _%[1]s_name[_%[1]s_index[idx]:_%[1]s_index[idx+1]]
}
`, typ, k)
}

func TestBoundIndexes(t *testing.T) {
	in := "package ua\n\n" + stringerOutput("A", 0) + stringerOutput("B", 1) +
		"func (i C) String() string {\n\tswitch {\n\tcase i <= 2:\n\t\treturn _C_name_0[_C_index_0[i]:_C_index_0[i+1]]\n\t}\n\treturn \"\"\n}\n"
	out, err := boundIndexes([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"\tif i < 0 || uint64(i)-0 >= uint64(len(_A_index)-1) {\n\t\treturn \"A(\" + strconv.FormatInt(int64(i), 10) + \")\"\n\t}\n\tidx := int(i) - 0\n\treturn _A_name[",
		"\tif i < 1 || uint64(i)-1 >= uint64(len(_B_index)-1) {\n\t\treturn \"B(\" + strconv.FormatInt(int64(i), 10) + \")\"\n\t}\n\tidx := int(i) - 1\n\treturn _B_name[",
		"\tcase i <= 2:\n\t\treturn _C_name_0[_C_index_0[i]:_C_index_0[i+1]]\n",
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("output lacks\n%s\nin\n%s", want, out)
		}
	}
	if _, err := parser.ParseFile(token.NewFileSet(), "x.go", out, 0); err != nil {
		t.Errorf("output does not parse: %v", err)
	}
	again, err := boundIndexes(out)
	if err != nil || string(again) != string(out) {
		t.Errorf("a second pass changes the output (err %v)", err)
	}
	// A range check of another shape is not left as it is.
	other := strings.Replace(stringerOutput("D", 0), "\tif i < 0 ||", "\tif false ||", 1)
	if _, err := boundIndexes([]byte(other)); err == nil {
		t.Error("an unknown range check passed")
	}
}

// TestGeneratedStringersAreBounded: the generated String methods of the
// module have the rewritten range checks.
func TestGeneratedStringersAreBounded(t *testing.T) {
	for _, f := range []string{"../../../ua/enums_strings_gen.go", "../../../connstate_strings_gen.go"} {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		out, err := boundIndexes(data)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if string(out) != string(data) {
			t.Errorf("%s has range checks that are not rewritten: run make gen", f)
		}
	}
}
