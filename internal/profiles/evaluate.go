// SPDX-License-Identifier: MIT

package profiles

import (
	"errors"
	"fmt"
	"sort"
)

// Report is the evaluation of the target Profiles against the inventory.
type Report struct {
	Source  Source
	Group   string
	Targets []TargetReport
}

// TargetReport is one target Profile with the status of each of its
// ConformanceUnits.
type TargetReport struct {
	Profile  *Profile
	Role     string
	Included []*Profile
	// Rows are the mandatory units, then the optional ones, each by name.
	Rows []Row
	// Claimed: every mandatory unit is evidenced, so the Profile may be
	// claimed.
	Claimed bool
}

// Row is a ConformanceUnit of a target with its evidence.
type Row struct {
	Requirement
	Entry
}

// Count returns the number of mandatory (optional false) or optional units
// with the status.
func (t *TargetReport) Count(optional bool, status string) int {
	n := 0
	for _, r := range t.Rows {
		if r.Optional == optional && r.Status == status {
			n++
		}
	}
	return n
}

// Evaluate maps every ConformanceUnit of the targets to its entry. It
// fails when a target is not a current Profile of the set, when a unit has
// no entry for the role of its target, and when an entry is for no unit of
// a target of its role (a stale entry).
func Evaluate(ps *ProfileSet, inv *Inventory) (*Report, error) {
	entries := inv.entries()
	used := map[entryKey]bool{}
	rep := &Report{Group: ps.Group}
	var errs []error
	for _, t := range inv.Targets {
		p, reqs, err := ps.Requirements(t.URI)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if p.Deprecated {
			errs = append(errs, fmt.Errorf("profiles: target %s is deprecated", p.Name))
			continue
		}
		tr := TargetReport{Profile: p, Role: t.Role, Included: ps.Included(p), Claimed: true}
		for _, req := range reqs {
			k := entryKey{t.Role, req.Unit.Name}
			e, ok := entries[k]
			if !ok {
				errs = append(errs, fmt.Errorf("profiles: %s: no %s entry for %q", p.Name, t.Role, req.Unit.Name))
				continue
			}
			used[k] = true
			tr.Rows = append(tr.Rows, Row{Requirement: req, Entry: e})
			if !req.Optional && e.Status != StatusEvidenced {
				tr.Claimed = false
			}
		}
		sort.SliceStable(tr.Rows, func(i, j int) bool { return !tr.Rows[i].Optional && tr.Rows[j].Optional })
		rep.Targets = append(rep.Targets, tr)
	}
	for _, e := range inv.Units {
		if !used[entryKey{e.Role, e.Name}] {
			errs = append(errs, fmt.Errorf("profiles: %s entry %q is for no unit of a target", e.Role, e.Name))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return rep, nil
}

// ServerProfiles returns the URIs of the claimed server Profiles, in the
// order of the targets: the ServerProfileArray the inventory supports.
func (r *Report) ServerProfiles() []string {
	out := []string{}
	for _, t := range r.Targets {
		if t.Role == RoleServer && t.Claimed {
			out = append(out, t.Profile.URI)
		}
	}
	return out
}
