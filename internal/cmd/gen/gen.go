// Copyright 2018-2024 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
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
