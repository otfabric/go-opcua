// SPDX-License-Identifier: MIT

// Command methods generates the contracts of OPC UA Methods from the
// InputArguments and OutputArguments of their declarations in a NodeSet
// (Part 3 §5.7.1, the Argument DataType of §8.6), for the ObjectTypes that
// config.go selects: for each Method a uamethod.Method with the NodeIds of
// the declaration and of its ObjectType, an Input and an Output structure
// with Pack and Unpack (the number, built-in type and ValueRank of the
// arguments are checked as the Call service checks them) and a Call
// function for a client.
//
// The NodeSets are read with internal/nodeset; they are the pinned inputs of
// schema/manifest.json. It runs from the module root (internal/cmd/gen).
package main

import (
	"fmt"
	"log"
	"os"
)

func main() {
	log.SetFlags(0)
	if err := run(families); err != nil {
		log.Fatal("methods: ", err)
	}
}

func run(fs []family) error {
	for _, f := range fs {
		types, err := load(f)
		if err != nil {
			return err
		}
		src, err := emit(f, types)
		if err != nil {
			return fmt.Errorf("%s: %w\n%s", f.Out, err, src)
		}
		if err := os.WriteFile(f.Out, src, 0o644); err != nil {
			return err
		}
		fmt.Println("Wrote", f.Out)
	}
	return nil
}
