// SPDX-License-Identifier: MIT

// Command gen is the Go-based code generation driver for go-opcua.
//
// It replaces the former generate.sh with a deterministic, tested Go
// program that:
//   - checks the vendored inputs against schema/manifest.json
//     (internal/cmd/schemamanifest verify), so code is only generated from
//     the pinned upstream files
//   - runs each generator in order (overwriting output files in place)
//   - discovers enum types and runs stringer via go tool
//   - does not install tools or run go mod tidy
//
// The generators import none of the generated packages, but stringer, run
// last, type-checks ./ua and the root package, so their generated files
// must compile together when it runs; the files are therefore overwritten
// in place rather than deleted first. The NodeId packages (cmd/id) are
// generated before cmd/uafx, whose output refers to their names, and
// cmd/methods (the Method contracts of package uamethod) reads the NodeSet
// the manifest pins. internal/cmd/profiles, last, writes docs/profiles.md
// and the default ServerProfileArray from the Profile inventory of
// internal/profiles, and fails when a test the inventory names is gone.
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

// generatedFiles is the list of the files the generators and stringer
// write, relative to the module root. Every one is named *_gen.go or
// *_gen_test.go, which `make check-gen` relies on to find new untracked
// output; TestGeneratedFileList checks the list against the module.
var generatedFiles = []string{
	"connstate_strings_gen.go",
	"di/diid/id_DataType_gen.go",
	"di/diid/id_Method_gen.go",
	"di/diid/id_ObjectType_gen.go",
	"di/diid/id_Object_gen.go",
	"di/diid/id_ReferenceType_gen.go",
	"di/diid/id_VariableType_gen.go",
	"di/diid/id_Variable_gen.go",
	"di/diid/id_names_gen.go",
	"gds/gdsid/id_DataType_gen.go",
	"gds/gdsid/id_Method_gen.go",
	"gds/gdsid/id_ObjectType_gen.go",
	"gds/gdsid/id_Object_gen.go",
	"gds/gdsid/id_Variable_gen.go",
	"gds/gdsid/id_names_gen.go",
	"id/id_DataType_gen.go",
	"id/id_Method_gen.go",
	"id/id_ObjectType_gen.go",
	"id/id_Object_gen.go",
	"id/id_ReferenceType_gen.go",
	"id/id_VariableType_gen.go",
	"id/id_Variable_gen.go",
	"id/id_names_gen.go",
	"server/default_permissions_gen.go",
	"server/server_profiles_gen.go",
	"ua/enums_attribute_id_gen.go",
	"ua/enums_gen.go",
	"ua/enums_strings_gen.go",
	"ua/extobjs_gen.go",
	"ua/register_extobjs_gen.go",
	"ua/server_capabilities_gen.go",
	"ua/service_gen.go",
	"ua/status_gen.go",
	"ua/typeinfo_gen.go",
	"uafx/codec_gen.go",
	"uafx/schema_gen_test.go",
	"uafx/types_gen.go",
	"uafx/fxacid/id_DataType_gen.go",
	"uafx/fxacid/id_Method_gen.go",
	"uafx/fxacid/id_ObjectType_gen.go",
	"uafx/fxacid/id_Object_gen.go",
	"uafx/fxacid/id_ReferenceType_gen.go",
	"uafx/fxacid/id_VariableType_gen.go",
	"uafx/fxacid/id_Variable_gen.go",
	"uafx/fxacid/id_names_gen.go",
	"uafx/fxcmid/id_DataType_gen.go",
	"uafx/fxcmid/id_Method_gen.go",
	"uafx/fxcmid/id_ObjectType_gen.go",
	"uafx/fxcmid/id_Object_gen.go",
	"uafx/fxcmid/id_ReferenceType_gen.go",
	"uafx/fxcmid/id_VariableType_gen.go",
	"uafx/fxcmid/id_Variable_gen.go",
	"uafx/fxcmid/id_names_gen.go",
	"uafx/fxdataid/id_DataType_gen.go",
	"uafx/fxdataid/id_Method_gen.go",
	"uafx/fxdataid/id_ObjectType_gen.go",
	"uafx/fxdataid/id_Object_gen.go",
	"uafx/fxdataid/id_Variable_gen.go",
	"uafx/fxdataid/id_names_gen.go",
	"uamethod/methods_gen.go",
	"uamethod/pubsub_gen.go",
	"uamethod/roles_gen.go",
	"uamethod/trustlist_gen.go",
}

// generators lists the generators to run, in dependency order.
var generators = [][]string{
	{"go", "run", "./internal/cmd/schemamanifest", "verify"},
	{"go", "run", "./cmd/id"},
	{"go", "run", "./cmd/id", "-in", "schema/Opc.Ua.Gds.NodeIds.csv", "-out", "gds/gdsid/id_*_gen.go", "-pkg", "gdsid"},
	{"go", "run", "./cmd/id", "-in", "schema/Opc.Ua.Di.NodeIds.csv", "-out", "di/diid/id_*_gen.go", "-pkg", "diid"},
	{"go", "run", "./cmd/id", "-in", "schema/opc.ua.fx.data.nodeset2.csv", "-out", "uafx/fxdataid/id_*_gen.go", "-pkg", "fxdataid"},
	{"go", "run", "./cmd/id", "-in", "schema/opc.ua.fx.ac.nodeset2.csv", "-out", "uafx/fxacid/id_*_gen.go", "-pkg", "fxacid"},
	{"go", "run", "./cmd/id", "-in", "schema/opc.ua.fx.cm.nodeset2.csv", "-out", "uafx/fxcmid/id_*_gen.go", "-pkg", "fxcmid"},
	{"go", "run", "./cmd/uafx"},
	{"go", "run", "./cmd/methods"},
	{"go", "run", "./cmd/status"},
	{"go", "run", "./cmd/attrid"},
	{"go", "run", "./cmd/capability"},
	{"go", "run", "./cmd/permissions"},
	{"go", "run", "./cmd/service"},
	{"go", "run", "./internal/cmd/profiles"},
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
	if err := boundStringerIndexes("ua/enums_strings_gen.go"); err != nil {
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
	if err := boundStringerIndexes("connstate_strings_gen.go"); err != nil {
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
