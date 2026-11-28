// SPDX-License-Identifier: MIT

package profiles

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

// LedgerPath is the interop ledger, relative to the module root.
const LedgerPath = "interop/coverage.json"

// CheckEvidence checks that the evidence of the inventory exists in the
// module at root: every test is a top-level function of a _test.go file of
// its directory (build tags are ignored, so interop tests count), every
// ledger row is a verified row of the ledger, and every document, and its
// anchor, exists. A renamed test, a row that is no longer verified or a
// moved heading fails it.
func CheckEvidence(root string, inv *Inventory, ledger *Ledger) error {
	tests := map[string]map[string]bool{}
	anchors := map[string]map[string]bool{}
	var errs []error
	for _, e := range inv.Units {
		for _, ref := range e.Tests {
			if err := checkTest(root, tests, ref); err != nil {
				errs = append(errs, fmt.Errorf("%s %q: %w", e.Role, e.Name, err))
			}
		}
		for _, row := range e.Ledger {
			if !ledger.Verified[row] {
				errs = append(errs, fmt.Errorf("%s %q: %s is no verified row of %s", e.Role, e.Name, row, LedgerPath))
			}
		}
		for _, doc := range e.Docs {
			if err := checkDoc(root, anchors, doc); err != nil {
				errs = append(errs, fmt.Errorf("%s %q: %w", e.Role, e.Name, err))
			}
		}
	}
	return errors.Join(errs...)
}

// Ledger is the interop ledger, interop/coverage.json.
type Ledger struct {
	// InteropVersion is the pinned opcua-interop release.
	InteropVersion string
	// Verified are the verified rows, "capability|direction".
	Verified map[string]bool
}

// ReadLedger reads the interop ledger.
func ReadLedger(path string) (*Ledger, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("profiles: %w", err)
	}
	var l struct {
		InteropVersion string `json:"interopVersion"`
		Entries        []struct {
			Capability string `json:"capability"`
			Direction  string `json:"direction"`
			Status     string `json:"status"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(data, &l); err != nil {
		return nil, fmt.Errorf("profiles: %s: %w", path, err)
	}
	out := &Ledger{InteropVersion: l.InteropVersion, Verified: map[string]bool{}}
	for _, e := range l.Entries {
		if e.Status == "verified" {
			out.Verified[e.Capability+"|"+e.Direction] = true
		}
	}
	return out, nil
}

func checkTest(root string, cache map[string]map[string]bool, ref string) error {
	dir, name, ok := strings.Cut(ref, ":")
	if !ok || !strings.HasPrefix(name, "Test") {
		return fmt.Errorf("test %q is not dir:TestName", ref)
	}
	funcs, ok := cache[dir]
	if !ok {
		var err error
		if funcs, err = testFuncs(filepath.Join(root, dir)); err != nil {
			return err
		}
		cache[dir] = funcs
	}
	if !funcs[name] {
		return fmt.Errorf("test %s: no func %s in %s", ref, name, dir)
	}
	return nil
}

// testFuncs returns the top-level functions of the _test.go files of dir.
func testFuncs(dir string) (map[string]bool, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*_test.go"))
	if err == nil && len(files) == 0 {
		err = fmt.Errorf("no test files in %s", dir)
	}
	if err != nil {
		return nil, err
	}
	funcs := map[string]bool{}
	fset := token.NewFileSet()
	for _, f := range files {
		af, err := parser.ParseFile(fset, f, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		for _, d := range af.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil {
				funcs[fd.Name.Name] = true
			}
		}
	}
	return funcs, nil
}

func checkDoc(root string, cache map[string]map[string]bool, ref string) error {
	path, anchor, _ := strings.Cut(ref, "#")
	slugs, ok := cache[path]
	if !ok {
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			return fmt.Errorf("document %s: %w", ref, err)
		}
		slugs = headingSlugs(data)
		cache[path] = slugs
	}
	if anchor != "" && !slugs[anchor] {
		return fmt.Errorf("document %s: no heading with anchor %q", path, anchor)
	}
	return nil
}

// headingSlugs returns the anchors of the ATX headings of a Markdown
// document, as GitHub derives them: lower case, spaces to hyphens, other
// punctuation than hyphens and underscores dropped, and -1, -2 appended to
// repeats. Headings in fenced code blocks are skipped.
func headingSlugs(data []byte) map[string]bool {
	slugs := map[string]bool{}
	count := map[string]int{}
	fenced := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "```") {
			fenced = !fenced
			continue
		}
		text, ok := strings.CutPrefix(strings.TrimLeft(line, "#"), " ")
		if fenced || !ok || !strings.HasPrefix(line, "#") {
			continue
		}
		slug := slugify(text)
		if n := count[slug]; n > 0 {
			count[slug]++
			slug = fmt.Sprintf("%s-%d", slug, n)
		} else {
			count[slug] = 1
		}
		slugs[slug] = true
	}
	return slugs
}

func slugify(heading string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(heading)) {
		switch {
		case r == ' ':
			b.WriteRune('-')
		case r == '-' || r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
		}
	}
	return b.String()
}
