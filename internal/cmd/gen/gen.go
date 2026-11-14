// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
)

// discoverEnumTypes parses Go files matching the glob pattern in dir
// and returns all exported type names declared in those files, sorted
// and deduplicated.
func discoverEnumTypes(dir, pattern string) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return nil, fmt.Errorf("glob %s/%s: %w", dir, pattern, err)
	}

	fset := token.NewFileSet()
	var types []string
	for _, path := range matches {
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts := spec.(*ast.TypeSpec)
				if ts.Name.IsExported() {
					types = append(types, ts.Name.Name)
				}
			}
		}
	}
	sort.Strings(types)
	types = slices.Compact(types)
	return types, nil
}

// cleanFiles removes the listed files. Ignores files that don't exist.
func cleanFiles(files []string) error {
	for _, f := range files {
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("clean %s: %w", f, err)
		}
	}
	return nil
}

// stringerIndex is the range check stringer writes for a run of
// consecutive values starting at k:
//
//	idx := int(i) - k
//	if i < k || idx >= len(_T_index)-1 {
//		return "T(" + strconv.FormatInt(int64(i), 10) + ")"
//	}
var stringerIndex = regexp.MustCompile(`\tidx := int\(i\) - (\d+)\n\tif i < (\d+) \|\| idx >= len\((\w+)\)-1 \{\n(\t\treturn [^\n]*\n)\t\}\n`)

// boundIndexes rewrites the range checks of stringer output so that the
// value is compared as a 64-bit unsigned number, i >= k and then i-k
// against the number of names, before it is converted to int, which has
// 32 bits on some platforms. The conversion that follows is of a value
// below the number of names. An output with a range check of another
// shape is an error, so a stringer version that writes one is noticed.
func boundIndexes(src []byte) ([]byte, error) {
	out := stringerIndex.ReplaceAll(src, []byte("\tif i < ${2} || uint64(i)-${2} >= uint64(len(${3})-1) {\n${4}\t}\n\tidx := int(i) - ${1}\n"))
	if bytes.Contains(out, []byte("idx >= len(")) {
		return nil, fmt.Errorf("stringer output has a range check boundIndexes does not rewrite")
	}
	return out, nil
}

// boundStringerIndexes applies boundIndexes to a stringer-generated file.
func boundStringerIndexes(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("boundStringerIndexes %s: %w", path, err)
	}
	out, err := boundIndexes(data)
	if err != nil {
		return fmt.Errorf("boundStringerIndexes %s: %w", path, err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		return fmt.Errorf("boundStringerIndexes %s: %w", path, err)
	}
	return nil
}
