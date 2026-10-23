// SPDX-License-Identifier: MIT

// Command coverage-gate checks the statement coverage of every library
// package against a minimum, excluding generated code.
//
//	go test -coverpkg=<packages> -coverprofile=coverage.out ./...
//	go run ./internal/cmd/coverage-gate -profile coverage.out -min 90
//
// The profile of a multi-package `go test -coverpkg` run lists every block
// once per test binary; the blocks are merged (a block is covered if any
// test binary covered it). Files whose header carries the standard
// "// Code generated ... DO NOT EDIT." marker are left out. Packages without
// statements after that are not reported.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var generatedMarker = regexp.MustCompile(`^// Code generated .* DO NOT EDIT\.$`)

type block struct {
	stmts   int
	covered bool
}

func main() {
	profile := flag.String("profile", "coverage.out", "merged coverage profile")
	minPct := flag.Float64("min", 90, "minimum statement coverage per package, in percent")
	module := flag.String("module", "github.com/otfabric/go-opcua", "module path the profile's file names start with")
	root := flag.String("root", ".", "module root on disk")
	flag.Parse()

	if err := run(os.Stdout, *profile, *module, *root, *minPct); err != nil {
		fmt.Fprintln(os.Stderr, "coverage-gate:", err)
		os.Exit(1)
	}
}

func run(w io.Writer, profile, module, root string, minPct float64) error {
	blocks, err := readProfile(profile)
	if err != nil {
		return err
	}

	generated := map[string]bool{}
	isGenerated := func(file string) bool {
		g, ok := generated[file]
		if !ok {
			g = fileIsGenerated(filepath.Join(root, strings.TrimPrefix(strings.TrimPrefix(file, module), "/")))
			generated[file] = g
		}
		return g
	}

	type pkgStat struct{ total, covered int }
	stats := map[string]*pkgStat{}
	for key, b := range blocks {
		file := key[:strings.LastIndex(key, ":")]
		if isGenerated(file) {
			continue
		}
		pkg := filepath.ToSlash(filepath.Dir(file))
		st := stats[pkg]
		if st == nil {
			st = &pkgStat{}
			stats[pkg] = st
		}
		st.total += b.stmts
		if b.covered {
			st.covered += b.stmts
		}
	}

	pkgs := make([]string, 0, len(stats))
	for p, st := range stats {
		if st.total > 0 {
			pkgs = append(pkgs, p)
		}
	}
	sort.Strings(pkgs)

	var failed []string
	var total, covered int
	for _, p := range pkgs {
		st := stats[p]
		total += st.total
		covered += st.covered
		pct := 100 * float64(st.covered) / float64(st.total)
		mark := "ok  "
		if pct < minPct {
			mark = "FAIL"
			failed = append(failed, fmt.Sprintf("%s (%.1f%%)", p, pct))
		}
		_, _ = fmt.Fprintf(w, "%s %6.1f%% %7d statements  %s\n", mark, pct, st.total, p)
	}
	if total > 0 {
		_, _ = fmt.Fprintf(w, "total %.1f%% of %d statements (generated code excluded)\n", 100*float64(covered)/float64(total), total)
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d package(s) below %.0f%%: %s", len(failed), minPct, strings.Join(failed, ", "))
	}
	return nil
}

// readProfile merges the blocks of a coverage profile.
func readProfile(path string) (map[string]block, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	blocks := map[string]block{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		text := sc.Text()
		if line == 1 && strings.HasPrefix(text, "mode:") {
			continue
		}
		if text == "" {
			continue
		}
		// file.go:startLine.startCol,endLine.endCol numStmts count
		fields := strings.Fields(text)
		if len(fields) != 3 {
			return nil, fmt.Errorf("%s:%d: malformed line %q", path, line, text)
		}
		stmts, err1 := strconv.Atoi(fields[1])
		count, err2 := strconv.Atoi(fields[2])
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("%s:%d: malformed line %q", path, line, text)
		}
		b := blocks[fields[0]]
		b.stmts = stmts
		b.covered = b.covered || count > 0
		blocks[fields[0]] = b
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return blocks, nil
}

// fileIsGenerated reports whether a Go file carries the generated-code
// marker before its package clause.
func fileIsGenerated(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		text := sc.Text()
		if generatedMarker.MatchString(text) {
			return true
		}
		if strings.HasPrefix(text, "package ") {
			return false
		}
	}
	return false
}
