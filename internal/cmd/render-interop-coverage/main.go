// SPDX-License-Identifier: MIT

// Command render-interop-coverage validates interop/capabilities.json and
// interop/coverage.json, then writes interop/COVERAGE.md.
//
//	go run ./internal/cmd/render-interop-coverage
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
)

const (
	interopVersionPin = "v0.5.0"
	fixtureBaseline   = "baseline"
)

var allowedStatuses = map[string]string{
	"verified":       "✅",
	"unverified":     "⬜",
	"unsupported":    "N/A",
	"not-applicable": "N/A",
	"deferred":       "Deferred",
	"blocked":        "Blocked",
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
}

type catalogFile struct {
	Capabilities []capability `json:"capabilities"`
}

type coverageFile struct {
	InteropVersion string          `json:"interopVersion"`
	Entries        []coverageEntry `json:"entries"`
}

func main() {
	root := findRepoRoot()
	capPath := filepath.Join(root, "interop", "capabilities.json")
	covPath := filepath.Join(root, "interop", "coverage.json")
	outPath := filepath.Join(root, "interop", "COVERAGE.md")

	caps, err := loadCatalog(capPath)
	must(err)
	cov, err := loadCoverage(covPath)
	must(err)

	must(validate(caps, cov))
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
	b.WriteString("Regenerate with `go generate ./interop`.\n\n")
	fmt.Fprintf(&b, "Pinned opcua-interop version: **%s**\n\n", cov.InteropVersion)
	b.WriteString("| Status | Meaning |\n|---|---|\n")
	b.WriteString("| ✅ verified | Peer direction proven by named interop test |\n")
	b.WriteString("| ⬜ unverified | Relevant but not yet peer-proven |\n")
	b.WriteString("| N/A unsupported | Peer stack cannot exercise the operation |\n")
	b.WriteString("| N/A not-applicable | Direction is nonsensical for this capability |\n")
	b.WriteString("| Deferred | Optional profile deliberately postponed |\n")
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

	// Keep tabwriter unused if we change format later.
	_ = tabwriter.NewWriter
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
