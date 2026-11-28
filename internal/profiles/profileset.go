// SPDX-License-Identifier: MIT

// Package profiles is the Profile and ConformanceUnit inventory of the
// library (docs/roadmap.md, phase 5). It reads the Profiles of OPC 10000-7
// from a pinned export of the OPC Foundation profile database
// (testdata/ProfileSet_UACore_1.05.xml, provenance in
// testdata/ProfileSet_UACore_1.05.source.json), maps every ConformanceUnit
// of the target Profiles to the tests and interop ledger rows that
// exercise it (inventory.json), and renders docs/profiles.md and the
// Profiles the server may claim in its ServerProfileArray (OPC 10000-5
// §6.3.2), server/server_profiles_gen.go. A Profile is claimed only when
// every mandatory ConformanceUnit of it and of the Profiles it includes is
// evidenced.
//
// internal/cmd/profiles writes the files; `make gen` runs it.
package profiles

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"sort"
	"strings"
)

// ProfileSet is a UAProfileSet document: the Profiles and ConformanceUnits
// of a profile group of the OPC Foundation profile database.
type ProfileSet struct {
	// Group is the FullName of the profile group, "UACore 1.05".
	Group    string
	Profiles []*Profile
	// Units are the ConformanceUnits by Id.
	Units map[string]Unit

	byID  map[string]*Profile
	byURI map[string]*Profile
}

// Profile is a Profile or Facet.
type Profile struct {
	ID   string
	Name string
	URI  string
	// Deprecated is ReleaseStatus="Deprecated" in the export.
	Deprecated bool
	// Includes are the Ids of the Profiles it includes.
	Includes []string
	Units    []UnitRef
}

// UnitRef is an IncludedConformanceUnit of a Profile.
type UnitRef struct {
	ID       string
	Optional bool
}

// Unit is a ConformanceUnit.
type Unit struct {
	ID   string
	Name string
}

type xmlProfileSet struct {
	Groups []struct {
		FullName string `xml:"FullName,attr"`
	} `xml:"ProfileGroups>ProfileGroup"`
	Profiles []struct {
		ID            string   `xml:"Id,attr"`
		Name          string   `xml:"Name,attr"`
		ReleaseStatus string   `xml:"ReleaseStatus,attr"`
		URI           string   `xml:"ProfileUri"`
		Includes      []string `xml:"Profiles>ProfileId"`
		Units         []struct {
			ID       string `xml:"Id,attr"`
			Optional bool   `xml:"IsOptional,attr"`
		} `xml:"ConformanceUnits>IncludedConformanceUnit"`
	} `xml:"Profiles>Profile"`
	Units []struct {
		ID   string `xml:"Id,attr"`
		Name string `xml:"Name,attr"`
	} `xml:"ConformanceUnits>ConformanceUnit"`
}

// ParseProfileSet reads a UAProfileSet document, the XML export of a
// profile group of the profile database. The names of the
// ConformanceUnits are trimmed: the database has one with a leading space.
func ParseProfileSet(data []byte) (*ProfileSet, error) {
	var x xmlProfileSet
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if err := xml.Unmarshal(data, &x); err != nil {
		return nil, fmt.Errorf("profiles: profile set: %w", err)
	}
	if len(x.Groups) != 1 {
		return nil, fmt.Errorf("profiles: profile set has %d profile groups, want 1", len(x.Groups))
	}
	ps := &ProfileSet{
		Group: x.Groups[0].FullName,
		Units: map[string]Unit{},
		byID:  map[string]*Profile{},
		byURI: map[string]*Profile{},
	}
	for _, u := range x.Units {
		ps.Units[u.ID] = Unit{ID: u.ID, Name: strings.TrimSpace(u.Name)}
	}
	for _, xp := range x.Profiles {
		p := &Profile{
			ID:         xp.ID,
			Name:       xp.Name,
			URI:        strings.TrimSpace(xp.URI),
			Deprecated: xp.ReleaseStatus == "Deprecated",
			Includes:   xp.Includes,
		}
		for _, u := range xp.Units {
			p.Units = append(p.Units, UnitRef{ID: u.ID, Optional: u.Optional})
		}
		ps.Profiles = append(ps.Profiles, p)
		ps.byID[p.ID] = p
		ps.byURI[p.URI] = p
	}
	return ps, nil
}

// Requirement is a ConformanceUnit a Profile requires, itself or through
// the Profiles it includes. It is mandatory when any of them lists it as
// mandatory.
type Requirement struct {
	Unit     Unit
	Optional bool
	// From are the names of the Profiles that list the unit.
	From []string
}

// Requirements returns the Profile with the URI and its ConformanceUnits,
// with those of every Profile it includes, sorted by name. Every included
// Profile is required: the export has no optional included Profile.
func (ps *ProfileSet) Requirements(uri string) (*Profile, []Requirement, error) {
	root, ok := ps.byURI[uri]
	if !ok {
		return nil, nil, fmt.Errorf("profiles: no profile %s in %s", uri, ps.Group)
	}
	reqs := map[string]*Requirement{}
	seen := map[string]bool{}
	var walk func(p *Profile) error
	walk = func(p *Profile) error {
		if seen[p.ID] {
			return nil
		}
		seen[p.ID] = true
		for _, ref := range p.Units {
			u, ok := ps.Units[ref.ID]
			if !ok {
				return fmt.Errorf("profiles: %s lists unknown conformance unit %s", p.Name, ref.ID)
			}
			r, ok := reqs[u.Name]
			if !ok {
				r = &Requirement{Unit: u, Optional: true}
				reqs[u.Name] = r
			}
			r.Optional = r.Optional && ref.Optional
			r.From = append(r.From, p.Name)
		}
		for _, id := range p.Includes {
			inc, ok := ps.byID[id]
			if !ok {
				return fmt.Errorf("profiles: %s includes unknown profile %s", p.Name, id)
			}
			if err := walk(inc); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(root); err != nil {
		return nil, nil, err
	}
	out := make([]Requirement, 0, len(reqs))
	for _, r := range reqs {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Unit.Name < out[j].Unit.Name })
	return root, out, nil
}

// Included returns the Profiles a Profile includes, directly and through
// the others, each once, depth first in the order of the export.
func (ps *ProfileSet) Included(p *Profile) []*Profile {
	var out []*Profile
	seen := map[string]bool{p.ID: true}
	var walk func(p *Profile)
	walk = func(p *Profile) {
		for _, id := range p.Includes {
			inc, ok := ps.byID[id]
			if !ok || seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, inc)
			walk(inc)
		}
	}
	walk(p)
	return out
}
