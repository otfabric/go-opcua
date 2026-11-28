// SPDX-License-Identifier: MIT

// Command schemamanifest pins the inputs of the code generators to a commit
// of the OPC Foundation UA-Nodeset repository and records them in
// schema/manifest.json: per input the upstream path, the commit, the
// SHA-256 of the vendored copy and, for a NodeSet, the Model it defines
// with its RequiredModels (OPC 10000-6 §F.2, Table F.1).
//
// Usage, from the module root:
//
//	go run ./internal/cmd/schemamanifest verify
//	go run ./internal/cmd/schemamanifest update [-ref REF]
//	go run ./internal/cmd/schemamanifest diff OLD NEW
//
// verify checks that every vendored input matches the manifest and that
// the RequiredModels of every vendored NodeSet are satisfied by a vendored
// model; the gen driver runs it before the generators, so code is only
// generated from the recorded inputs. update downloads every input at REF
// (a commit, branch or tag; default: the commit of the manifest) and
// rewrites the manifest; schema/update-schema.sh runs it. diff writes a
// Markdown report of the inputs and models that differ between two
// manifests, for the weekly upstream check.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
)

func main() {
	log.SetFlags(0)
	if err := run(os.Args[1:], os.Stdout); err != nil {
		log.Fatal("schemamanifest: ", err)
	}
}

func run(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: schemamanifest verify | update [-ref REF] | diff OLD NEW")
	}
	switch args[0] {
	case "verify":
		m, err := readManifest(manifestPath)
		if err != nil {
			return err
		}
		if err := verify(".", m); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "Vendored schema matches %s (UA-Nodeset %s)\n", manifestPath, short(m.Commit))
		return nil
	case "update":
		fs := flag.NewFlagSet("update", flag.ContinueOnError)
		ref := fs.String("ref", "", "the UA-Nodeset commit, branch or tag (default: the commit of the manifest)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return update(".", *ref, defaultUpstream(), stdout)
	case "diff":
		if len(args) != 3 {
			return fmt.Errorf("usage: schemamanifest diff OLD NEW")
		}
		old, err := readManifest(args[1])
		if err != nil {
			return err
		}
		cur, err := readManifest(args[2])
		if err != nil {
			return err
		}
		_, err = io.WriteString(stdout, diff(old, cur))
		return err
	}
	return fmt.Errorf("unknown command %q", args[0])
}

func short(commit string) string {
	if len(commit) > 12 {
		return commit[:12]
	}
	return commit
}
