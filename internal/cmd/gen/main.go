// Copyright 2018-2024 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

// Command gen is the Go-based code generation driver for go-opcua.
//
// It replaces the former generate.sh with a deterministic, tested Go
// program that:
//   - cleans an explicit list of generated files (no shell globs)
//   - runs each generator in order
//   - discovers enum types and runs stringer via go tool
//   - does not install tools or run go mod tidy
//
// Invoke via: go generate ./...  (from module root)
// Or directly: go run ./internal/cmd/gen
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// generatedFiles is the explicit list of all generated output files,
// relative to the module root. This replaces wildcard shell globs.
var generatedFiles = []string{
	"connstate_strings_gen.go",
	"id/id_DataType_gen.go",
	"id/id_Method_gen.go",
	"id/id_names_gen.go",
	"id/id_Object_gen.go",
	"id/id_ObjectType_gen.go",
	"id/id_ReferenceType_gen.go",
	"id/id_Variable_gen.go",
	"id/id_VariableType_gen.go",
	"server/default_permissions_gen.go",
	"ua/enums_attribute_id_gen.go",
	"ua/enums_gen.go",
	"ua/enums_strings_gen.go",
	"ua/extobjs_gen.go",
	"ua/register_extobjs_gen.go",
	"ua/server_capabilities_gen.go",
	"ua/service_gen.go",
	"ua/status_gen.go",
}

// generators lists the generators to run, in dependency order.
var generators = [][]string{
	{"go", "run", "./cmd/id"},
	{"go", "run", "./cmd/status"},
	{"go", "run", "./cmd/attrid"},
	{"go", "run", "./cmd/capability"},
	{"go", "run", "./cmd/permissions"},
	{"go", "run", "./cmd/service"},
}

func main() {
	log.SetFlags(0)

	clean()
	generate()
	stringer()
}

// clean removes all known generated files. Ignores files that don't exist.
func clean() {
	for _, f := range generatedFiles {
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
			log.Fatalf("clean: %v", err)
		}
	}
}

// generate runs each code generator.
func generate() {
	for _, args := range generators {
		run(args[0], args[1:]...)
	}
}

// stringer discovers enum types in ua/enums*.go files and runs
// `go tool stringer` to generate String() methods.
func stringer() {
	enums := discoverEnumTypes("ua", "enums*.go")
	if len(enums) == 0 {
		log.Fatal("stringer: no enum types found in ua/enums*.go")
	}

	run("go", "tool", "stringer",
		"-type", strings.Join(enums, ","),
		"-output", "ua/enums_strings_gen.go",
		"./ua",
	)
	fmt.Println("Wrote ua/enums_strings_gen.go")

	run("go", "tool", "stringer",
		"-type", "ConnState",
		"-output", "connstate_strings_gen.go",
		".",
	)
	fmt.Println("Wrote connstate_strings_gen.go")
}

// discoverEnumTypes parses Go files matching the glob pattern in dir
// and returns all exported type names declared in those files, sorted.
func discoverEnumTypes(dir, pattern string) []string {
	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		log.Fatalf("glob %s/%s: %v", dir, pattern, err)
	}

	fset := token.NewFileSet()
	var types []string
	for _, path := range matches {
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			log.Fatalf("parse %s: %v", path, err)
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
	return types
}

// run executes a command, forwarding stdout/stderr. Exits on failure.
func run(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("%s %s: %v", name, strings.Join(args, " "), err)
	}
}
