// SPDX-License-Identifier: MIT

// Command render-interop-coverage validates interop/capabilities.json and
// interop/coverage.json, then writes interop/COVERAGE.md.
//
//	go run ./internal/cmd/render-interop-coverage
//	go run ./internal/cmd/render-interop-coverage -summary
//	go run ./internal/cmd/render-interop-coverage -summary -group-by=status,reason
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	interopVersionPin = "v0.5.0"
)

var allowedStatuses = map[string]string{
	"verified":       "✅",
	"unverified":     "⬜",
	"unsupported":    "N/A",
	"not-applicable": "N/A",
	"deferred":       "Deferred",
	"blocked":        "Blocked",
}

// Controlled vocabulary for unverified rows (plan: Close core interop evidence gaps).
var allowedUnverifiedReasons = map[string]bool{
	"test-missing":            true,
	"adapter-command-missing": true,
	"adapter-fixture-missing": true,
	"fault-harness-missing":   true,
	"consumer-demand-missing": true,
	"peer-capability-unknown": true,
}

var allDirections = []string{
	"go-client-to-open62541-server",
	"go-client-to-milo-server",
	"open62541-client-to-go-server",
	"milo-client-to-go-server",
}

var directionHeaders = map[string]string{
	"go-client-to-open62541-server": "C→O",
	"go-client-to-milo-server":      "C→M",
	"open62541-client-to-go-server": "O→S",
	"milo-client-to-go-server":      "M→S",
}

type capability struct {
	ID                   string   `json:"id"`
	Title                string   `json:"title"`
	Profile              string   `json:"profile"`
	ApplicableDirections []string `json:"applicableDirections"`
}

type peerInfo struct {
	Stack   string `json:"stack,omitempty"`
	Version string `json:"version,omitempty"`
}

type coverageEntry struct {
	Capability     string    `json:"capability"`
	Direction      string    `json:"direction"`
	Status         string    `json:"status"`
	Test           string    `json:"test,omitempty"`
	Case           string    `json:"case,omitempty"`
	Fixture        string    `json:"fixture,omitempty"`
	InteropVersion string    `json:"interopVersion,omitempty"`
	Peer           *peerInfo `json:"peer,omitempty"`
	Issue          string    `json:"issue,omitempty"`
	Reason         string    `json:"reason,omitempty"`
	NextAction     string    `json:"nextAction,omitempty"`
}

type catalogFile struct {
	Capabilities []capability `json:"capabilities"`
}

type coverageFile struct {
	InteropVersion string          `json:"interopVersion"`
	Entries        []coverageEntry `json:"entries"`
}

func main() {
	summary := flag.Bool("summary", false, "print gap summary grouped by status/reason and exit")
	groupBy := flag.String("group-by", "status,reason", "comma-separated grouping keys for -summary (status,reason,capability,profile)")
	writeGaps := flag.String("write-gaps", "", "with -summary, also write markdown report to this path")
	flag.Parse()

	root := findRepoRoot()
	capPath := filepath.Join(root, "interop", "capabilities.json")
	covPath := filepath.Join(root, "interop", "coverage.json")
	outPath := filepath.Join(root, "interop", "COVERAGE.md")

	caps, err := loadCatalog(capPath)
	must(err)
	cov, err := loadCoverage(covPath)
	must(err)

	must(validate(caps, cov))

	if *summary {
		must(printSummary(os.Stdout, caps, cov, strings.Split(*groupBy, ",")))
		if *writeGaps != "" {
			path := *writeGaps
			if !filepath.IsAbs(path) {
				path = filepath.Join(root, path)
			}
			var b strings.Builder
			must(writeGapsMarkdown(&b, caps, cov))
			must(os.WriteFile(path, []byte(b.String()), 0o644))
			fmt.Printf("wrote %s\n", path)
		}
		return
	}

	must(writeMarkdown(outPath, caps, cov))
	fmt.Printf("wrote %s (%d capabilities, %d coverage rows)\n", outPath, len(caps), len(cov.Entries))
}

func findRepoRoot() string {
	wd, err := os.Getwd()
	must(err)
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			must(fmt.Errorf("go.mod not found from %s", wd))
		}
		dir = parent
	}
}

func loadCatalog(path string) ([]capability, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f catalogFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	if len(f.Capabilities) == 0 {
		return nil, fmt.Errorf("%s: empty capabilities", path)
	}
	return f.Capabilities, nil
}

func loadCoverage(path string) (*coverageFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f coverageFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	if f.InteropVersion == "" {
		return nil, fmt.Errorf("%s: missing interopVersion", path)
	}
	return &f, nil
}

func validate(caps []capability, cov *coverageFile) error {
	byID := map[string]capability{}
	for _, c := range caps {
		if c.ID == "" || c.Title == "" || c.Profile == "" {
			return fmt.Errorf("capability missing id/title/profile: %+v", c)
		}
		if _, dup := byID[c.ID]; dup {
			return fmt.Errorf("duplicate capability id %q", c.ID)
		}
		if len(c.ApplicableDirections) == 0 {
			return fmt.Errorf("capability %q has no applicableDirections", c.ID)
		}
		for _, d := range c.ApplicableDirections {
			if !validDirection(d) {
				return fmt.Errorf("capability %q: unknown direction %q", c.ID, d)
			}
		}
		byID[c.ID] = c
	}

	if cov.InteropVersion != interopVersionPin {
		return fmt.Errorf("coverage interopVersion %q != pinned %q", cov.InteropVersion, interopVersionPin)
	}

	seen := map[string]bool{}
	for i, e := range cov.Entries {
		key := e.Capability + "|" + e.Direction
		if seen[key] {
			return fmt.Errorf("duplicate coverage row %s", key)
		}
		seen[key] = true

		cap, ok := byID[e.Capability]
		if !ok {
			return fmt.Errorf("entry[%d]: unknown capability %q", i, e.Capability)
		}
		if !validDirection(e.Direction) {
			return fmt.Errorf("entry[%d]: unknown direction %q", i, e.Direction)
		}
		if _, ok := allowedStatuses[e.Status]; !ok {
			return fmt.Errorf("entry[%d]: invalid status %q", i, e.Status)
		}

		applicable := contains(cap.ApplicableDirections, e.Direction)
		switch {
		case e.Status == "not-applicable" && applicable:
			return fmt.Errorf("entry[%d]: %s/%s marked not-applicable but direction is applicable", i, e.Capability, e.Direction)
		case e.Status != "not-applicable" && !applicable:
			return fmt.Errorf("entry[%d]: %s/%s not in applicableDirections (use not-applicable)", i, e.Capability, e.Direction)
		}

		switch e.Status {
		case "verified", "blocked":
			if e.Test == "" {
				return fmt.Errorf("entry[%d]: %s requires test", i, e.Status)
			}
			if e.Status == "blocked" && (e.Issue == "" || e.Reason == "") {
				return fmt.Errorf("entry[%d]: blocked requires issue and reason", i)
			}
			if e.InteropVersion != "" && e.InteropVersion != cov.InteropVersion {
				return fmt.Errorf("entry[%d]: interopVersion %q != file %q", i, e.InteropVersion, cov.InteropVersion)
			}
		case "unverified":
			if e.Reason == "" {
				return fmt.Errorf("entry[%d]: unverified %s/%s requires controlled reason", i, e.Capability, e.Direction)
			}
			if !allowedUnverifiedReasons[e.Reason] {
				return fmt.Errorf("entry[%d]: unverified reason %q not in vocabulary", i, e.Reason)
			}
		}
	}

	// Every applicable direction for every capability must have a row.
	for _, cap := range caps {
		for _, d := range allDirections {
			key := cap.ID + "|" + d
			if seen[key] {
				continue
			}
			if contains(cap.ApplicableDirections, d) {
				return fmt.Errorf("missing coverage row for applicable %s / %s", cap.ID, d)
			}
			return fmt.Errorf("missing not-applicable coverage row for %s / %s", cap.ID, d)
		}
	}
	return nil
}

func printSummary(w *os.File, caps []capability, cov *coverageFile, groups []string) error {
	profileOf := map[string]string{}
	for _, c := range caps {
		profileOf[c.ID] = c.Profile
	}

	type row struct {
		status, reason, capability, profile, direction string
	}
	var rows []row
	for _, e := range cov.Entries {
		rows = append(rows, row{
			status:     e.Status,
			reason:     e.Reason,
			capability: e.Capability,
			profile:    profileOf[e.Capability],
			direction:  directionHeaders[e.Direction],
		})
	}

	// Status totals
	statusCounts := map[string]int{}
	for _, r := range rows {
		statusCounts[r.status]++
	}
	write := func(format string, args ...any) error {
		_, err := fmt.Fprintf(w, format, args...)
		return err
	}
	if err := write("# Interop coverage summary\n\n"); err != nil {
		return err
	}
	if err := write("interopVersion: %s\n", cov.InteropVersion); err != nil {
		return err
	}
	if err := write("total rows: %d\n\n", len(rows)); err != nil {
		return err
	}
	if err := write("## By status\n"); err != nil {
		return err
	}
	var statuses []string
	for s := range statusCounts {
		statuses = append(statuses, s)
	}
	sort.Strings(statuses)
	for _, s := range statuses {
		if err := write("- %s: %d\n", s, statusCounts[s]); err != nil {
			return err
		}
	}

	// Grouping
	keys := normalizeGroups(groups)
	if err := write("\n## Grouped by %s\n", strings.Join(keys, ", ")); err != nil {
		return err
	}
	counts := map[string]int{}
	for _, r := range rows {
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			switch k {
			case "status":
				parts = append(parts, r.status)
			case "reason":
				if r.reason == "" {
					parts = append(parts, "-")
				} else {
					parts = append(parts, r.reason)
				}
			case "capability":
				parts = append(parts, r.capability)
			case "profile":
				parts = append(parts, r.profile)
			case "direction":
				parts = append(parts, r.direction)
			}
		}
		counts[strings.Join(parts, " | ")]++
	}
	var groupKeys []string
	for k := range counts {
		groupKeys = append(groupKeys, k)
	}
	sort.Strings(groupKeys)
	for _, k := range groupKeys {
		if err := write("- %s: %d\n", k, counts[k]); err != nil {
			return err
		}
	}

	// Unverified detail
	if err := write("\n## Unverified rows\n"); err != nil {
		return err
	}
	var unverified []coverageEntry
	for _, e := range cov.Entries {
		if e.Status == "unverified" {
			unverified = append(unverified, e)
		}
	}
	sort.Slice(unverified, func(i, j int) bool {
		if unverified[i].Reason != unverified[j].Reason {
			return unverified[i].Reason < unverified[j].Reason
		}
		if unverified[i].Capability != unverified[j].Capability {
			return unverified[i].Capability < unverified[j].Capability
		}
		return unverified[i].Direction < unverified[j].Direction
	})
	for _, e := range unverified {
		next := e.NextAction
		if next == "" {
			next = "—"
		}
		if err := write("- %s %s [%s] next=%s\n",
			e.Capability, directionHeaders[e.Direction], e.Reason, next); err != nil {
			return err
		}
	}
	return nil
}

func writeGapsMarkdown(b *strings.Builder, caps []capability, cov *coverageFile) error {
	profileOf := map[string]string{}
	for _, c := range caps {
		profileOf[c.ID] = c.Profile
	}
	b.WriteString("# Interop coverage gaps\n\n")
	b.WriteString("<!-- Generated by render-interop-coverage -summary -write-gaps. DO NOT EDIT. -->\n\n")
	fmt.Fprintf(b, "Pinned opcua-interop version: **%s**\n\n", cov.InteropVersion)

	statusCounts := map[string]int{}
	reasonCounts := map[string]int{}
	for _, e := range cov.Entries {
		statusCounts[e.Status]++
		if e.Status == "unverified" {
			reasonCounts[e.Reason]++
		}
	}
	b.WriteString("## Status totals\n\n")
	var statuses []string
	for s := range statusCounts {
		statuses = append(statuses, s)
	}
	sort.Strings(statuses)
	for _, s := range statuses {
		fmt.Fprintf(b, "- `%s`: %d\n", s, statusCounts[s])
	}
	b.WriteString("\n## Unverified by reason\n\n")
	var reasons []string
	for r := range reasonCounts {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	for _, r := range reasons {
		fmt.Fprintf(b, "- `%s`: %d\n", r, reasonCounts[r])
	}
	b.WriteString("\n## Unverified rows\n\n")
	b.WriteString("| Capability | Dir | Reason | Next action |\n|---|:---:|---|---|\n")
	var unverified []coverageEntry
	for _, e := range cov.Entries {
		if e.Status == "unverified" {
			unverified = append(unverified, e)
		}
	}
	sort.Slice(unverified, func(i, j int) bool {
		if unverified[i].Reason != unverified[j].Reason {
			return unverified[i].Reason < unverified[j].Reason
		}
		if unverified[i].Capability != unverified[j].Capability {
			return unverified[i].Capability < unverified[j].Capability
		}
		return unverified[i].Direction < unverified[j].Direction
	})
	for _, e := range unverified {
		next := e.NextAction
		if next == "" {
			next = "—"
		}
		fmt.Fprintf(b, "| `%s` | %s | `%s` | %s |\n",
			e.Capability, directionHeaders[e.Direction], e.Reason, next)
	}
	b.WriteString("\n")
	return nil
}

func normalizeGroups(groups []string) []string {
	allowed := map[string]bool{
		"status": true, "reason": true, "capability": true, "profile": true, "direction": true,
	}
	var out []string
	for _, g := range groups {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if !allowed[g] {
			must(fmt.Errorf("unknown -group-by key %q", g))
		}
		out = append(out, g)
	}
	if len(out) == 0 {
		return []string{"status", "reason"}
	}
	return out
}

func writeMarkdown(path string, caps []capability, cov *coverageFile) error {
	byCapDir := map[string]coverageEntry{}
	for _, e := range cov.Entries {
		byCapDir[e.Capability+"|"+e.Direction] = e
	}

	profiles := map[string][]capability{}
	var profileOrder []string
	for _, c := range caps {
		if _, ok := profiles[c.Profile]; !ok {
			profileOrder = append(profileOrder, c.Profile)
		}
		profiles[c.Profile] = append(profiles[c.Profile], c)
	}
	sort.Strings(profileOrder)

	var b strings.Builder
	b.WriteString("# go-opcua Interoperability Coverage\n\n")
	b.WriteString("<!-- Code generated by internal/cmd/render-interop-coverage. DO NOT EDIT. -->\n\n")
	b.WriteString("Source of truth: [`capabilities.json`](capabilities.json) + [`coverage.json`](coverage.json).\n")
	b.WriteString("Regenerate with `go generate ./interop`.\n")
	b.WriteString("Gap summary: `go run ./internal/cmd/render-interop-coverage -summary`.\n\n")
	fmt.Fprintf(&b, "Pinned opcua-interop version: **%s**\n\n", cov.InteropVersion)
	b.WriteString("| Status | Meaning |\n|---|---|\n")
	b.WriteString("| ✅ verified | Peer direction proven by named non-skipping interop test |\n")
	b.WriteString("| ⬜ unverified | Relevant to current scope; evidence pending (requires controlled `reason`) |\n")
	b.WriteString("| N/A unsupported | Peer stack cannot exercise the operation |\n")
	b.WriteString("| N/A not-applicable | Direction is nonsensical for this capability |\n")
	b.WriteString("| Deferred | Deliberately excluded from the current parity claim |\n")
	b.WriteString("| Blocked | Temporary; requires linked issue |\n\n")
	b.WriteString("Directions: **C→O** Go client→open62541, **C→M** Go client→Milo, **O→S** open62541→Go server, **M→S** Milo→Go server.\n")
	b.WriteString("Go↔Go tests never earn ✅.\n\n")

	for _, profile := range profileOrder {
		b.WriteString("## " + profile + "\n\n")
		b.WriteString("| Capability | C→O | C→M | O→S | M→S | Evidence |\n")
		b.WriteString("|---|:---:|:---:|:---:|:---:|---|\n")
		for _, cap := range profiles[profile] {
			cells := make([]string, 0, 4)
			var evidence []string
			for _, d := range allDirections {
				e := byCapDir[cap.ID+"|"+d]
				render := allowedStatuses[e.Status]
				if e.Status == "unsupported" || e.Status == "not-applicable" {
					render = "N/A"
				}
				cells = append(cells, render)
				if e.Status == "verified" && e.Test != "" {
					ev := e.Test
					if e.Case != "" {
						ev += " / " + e.Case
					}
					evidence = append(evidence, directionHeaders[d]+": `"+ev+"`")
				}
			}
			evCol := "—"
			if len(evidence) > 0 {
				evCol = strings.Join(evidence, "; ")
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n",
				cap.Title, cells[0], cells[1], cells[2], cells[3], evCol)
		}
		b.WriteString("\n")
	}

	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func validDirection(d string) bool {
	return contains(allDirections, d)
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
