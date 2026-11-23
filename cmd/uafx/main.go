// SPDX-License-Identifier: MIT

// Command uafx generates the DataTypes of OPC UA FX (OPC 10000-81) for
// package uafx from the NodeSets of the UAFX Data, AutomationComponent and
// ConnectionManager namespaces (uafx/internal/model): the enumerations and
// OptionSets, the structures (with their supertypes' fields, optional
// fields and unions, Part 6 §5.2.6 to §5.2.8), the interfaces of the
// abstract structures, and their binary encoding with the namespace index
// the server has for each namespace.
//
// It writes uafx/types_gen.go, uafx/codec_gen.go and
// uafx/schema_gen_test.go, which the tests compare with the Binary Schemas
// of the NodeSets (schema/opc.ua.fx.*.nodeset2.bsd).
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

func main() {
	log.SetFlags(0)
	in := flag.String("in", "uafx/internal/model", "the directory of the UAFX NodeSets")
	out := flag.String("out", "uafx", "the directory of package uafx")
	flag.Parse()
	if err := run(*in, *out); err != nil {
		log.Fatal("uafx: ", err)
	}
}

func run(in, out string) error {
	m, err := load(in)
	if err != nil {
		return err
	}
	for name, f := range map[string]func(*emitter){
		"types_gen.go":       (*emitter).types,
		"codec_gen.go":       (*emitter).codec,
		"schema_gen_test.go": (*emitter).schema,
	} {
		e := &emitter{m: m}
		f(e)
		src, err := e.source()
		if err != nil {
			return fmt.Errorf("%s: %w\n%s", name, err, src)
		}
		path := filepath.Join(out, name)
		if err := os.WriteFile(path, src, 0o644); err != nil {
			return err
		}
		fmt.Println("Wrote", path)
	}
	return nil
}
