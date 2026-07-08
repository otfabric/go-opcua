// SPDX-License-Identifier: MIT

// Command gen is the Go-based code generation driver for go-opcua.
//
// It replaces the former generate.sh with a deterministic, tested Go
// program that:
//   - runs each generator in order (overwriting output files in place)
//   - discovers enum types and runs stringer via go tool
//   - does not install tools or run go mod tidy
//
// Generated files are NOT cleaned before regeneration because the
// generators import the ua package which depends on its own generated
// files. Deleting them first creates a circular dependency that breaks
// compilation on cold caches (e.g. CI).
//
// Invoke via: go generate ./...  (from module root)
// Or directly: go run ./internal/cmd/gen
package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
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

	if err := generate(); err != nil {
		log.Fatal("generate: ", err)
	}
	if err := stringer(); err != nil {
		log.Fatal("stringer: ", err)
	}
}

// generate runs each code generator.
func generate() error {
	for _, args := range generators {
		if err := run(args[0], args[1:]...); err != nil {
			return err
		}
	}
	return nil
}

// stringer discovers enum types in ua/enums*.go files and runs
// `go tool stringer` to generate String() methods.
func stringer() error {
	enums, err := discoverEnumTypes("ua", "enums*.go")
	if err != nil {
		return fmt.Errorf("stringer: %w", err)
	}
	if len(enums) == 0 {
		return fmt.Errorf("stringer: no enum types found in ua/enums*.go")
	}

	if err := run("go", "tool", "stringer",
		"-type", strings.Join(enums, ","),
		"-output", "ua/enums_strings_gen.go",
		"./ua",
	); err != nil {
		return err
	}
	if err := prependSPDX("ua/enums_strings_gen.go"); err != nil {
		return err
	}
	fmt.Println("Wrote ua/enums_strings_gen.go")

	if err := run("go", "tool", "stringer",
		"-type", "ConnState",
		"-output", "connstate_strings_gen.go",
		".",
	); err != nil {
		return err
	}
	if err := prependSPDX("connstate_strings_gen.go"); err != nil {
		return err
	}
	fmt.Println("Wrote connstate_strings_gen.go")

	return nil
}

// prependSPDX inserts the SPDX license identifier at the top of a
// stringer-generated file. Unlike the in-repo generators, stringer does
// not let us customize its header, so we add the line afterwards to keep
// every generated file's header aligned. The "// Code generated ... DO NOT
// EDIT." line stays before the package clause, so Go still treats the file
// as generated.
func prependSPDX(path string) error {
	const header = "// SPDX-License-Identifier: MIT\n\n"
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("prependSPDX %s: %w", path, err)
	}
	if strings.HasPrefix(string(data), header) {
		return nil
	}
	if err := os.WriteFile(path, append([]byte(header), data...), 0o644); err != nil {
		return fmt.Errorf("prependSPDX %s: %w", path, err)
	}
	return nil
}

// run executes a command, forwarding stdout/stderr.
func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run %s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}
