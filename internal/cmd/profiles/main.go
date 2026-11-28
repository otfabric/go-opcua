// SPDX-License-Identifier: MIT

// Command profiles writes docs/profiles.md and server/server_profiles_gen.go
// from the pinned profile set and the inventory of internal/profiles. Run
// from the module root; `make gen` runs it.
package main

import (
	"log"
	"os"
	"path/filepath"
	"sort"

	"github.com/otfabric/go-opcua/internal/profiles"
)

func main() {
	log.SetFlags(0)
	files, err := profiles.Generate(".")
	if err != nil {
		log.Fatal(err)
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := os.WriteFile(filepath.FromSlash(name), files[name], 0o644); err != nil {
			log.Fatal(err)
		}
		log.Printf("Wrote %s", name)
	}
}
