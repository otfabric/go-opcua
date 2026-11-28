// SPDX-License-Identifier: MIT

package profiles

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// The statuses of an Entry.
const (
	// StatusEvidenced: the library does what the ConformanceUnit requires
	// and the tests of the entry assert it.
	StatusEvidenced = "evidenced"
	// StatusPartial: a part is implemented or tested; the note says what
	// is missing.
	StatusPartial = "partial"
	// StatusMissing: not implemented, or implemented without a test.
	StatusMissing = "missing"
)

// The roles of a Target and an Entry: the Profile category the evidence is
// for.
const (
	RoleServer = "server"
	RoleClient = "client"
)

// Inventory is inventory.json: the target Profiles and the evidence of
// each of their ConformanceUnits.
type Inventory struct {
	Targets []Target `json:"targets"`
	Units   []Entry  `json:"units"`
}

// Target is a Profile the inventory covers.
type Target struct {
	URI  string `json:"uri"`
	Role string `json:"role"`
}

// Entry is the evidence of one ConformanceUnit for one role.
type Entry struct {
	Role string `json:"role"`
	// Name is the name of the ConformanceUnit, as in the profile set.
	Name   string `json:"unit"`
	Status string `json:"status"`
	// Tests are top-level test functions, "dir:TestName", dir relative
	// to the module root ("." for the root package).
	Tests []string `json:"tests,omitempty"`
	// Ledger are rows of interop/coverage.json, "capability|direction",
	// with status verified.
	Ledger []string `json:"ledger,omitempty"`
	// Docs are documents, "path" or "path#anchor", relative to the
	// module root.
	Docs []string `json:"docs,omitempty"`
	Note string   `json:"note"`
}

type entryKey struct{ role, unit string }

// ParseInventory reads inventory.json and checks every entry on its own:
// a known role and status, a note, a test for an evidenced unit, and one
// entry per role and unit.
func ParseInventory(data []byte) (*Inventory, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	inv := &Inventory{}
	if err := dec.Decode(inv); err != nil {
		return nil, fmt.Errorf("profiles: inventory: %w", err)
	}
	var errs []error
	for _, t := range inv.Targets {
		if !validRole(t.Role) {
			errs = append(errs, fmt.Errorf("target %s: role %q", t.URI, t.Role))
		}
	}
	seen := map[entryKey]bool{}
	for _, e := range inv.Units {
		k := entryKey{e.Role, e.Name}
		switch {
		case !validRole(e.Role):
			errs = append(errs, fmt.Errorf("%q: role %q", e.Name, e.Role))
		case seen[k]:
			errs = append(errs, fmt.Errorf("%s %q: more than one entry", e.Role, e.Name))
		case e.Status != StatusEvidenced && e.Status != StatusPartial && e.Status != StatusMissing:
			errs = append(errs, fmt.Errorf("%s %q: status %q", e.Role, e.Name, e.Status))
		case e.Note == "":
			errs = append(errs, fmt.Errorf("%s %q: no note", e.Role, e.Name))
		case e.Status == StatusEvidenced && len(e.Tests) == 0:
			errs = append(errs, fmt.Errorf("%s %q: evidenced without a test", e.Role, e.Name))
		}
		seen[k] = true
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("profiles: inventory: %w", err)
	}
	return inv, nil
}

func validRole(r string) bool { return r == RoleServer || r == RoleClient }

func (inv *Inventory) entries() map[entryKey]Entry {
	m := make(map[entryKey]Entry, len(inv.Units))
	for _, e := range inv.Units {
		m[entryKey{e.Role, e.Name}] = e
	}
	return m
}
