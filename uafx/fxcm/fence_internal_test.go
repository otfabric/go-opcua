// SPDX-License-Identifier: MIT

package fxcm

import (
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestFencedOf: the narrowing of the fence (fencedOf, design §6.3, §6.4).
// The participants of an owed set change are fenced; an owed call fences
// the sets that share its server; other owed work fences the sets that
// share a server of the owing set only while a record on it is not
// verified.
func TestFencedOf(t *testing.T) {
	t.Parallel()
	const x, y = "opc.tcp://x", "opc.tcp://y"
	l := &loaded{eps: map[string]*epStored{
		"e1": {SetName: "One", Address: x},
		"e2": {SetName: "Two", Address: x},
		"e3": {SetName: "Three", Address: y},
	}}
	one := keyString(SetKey{Name: "One"})
	fenced := func(w OwedWork, unverified ...string) []string {
		un := map[string]bool{}
		for _, a := range unverified {
			un[a] = true
		}
		return slices.Sorted(maps.Keys(fencedOf(l, map[string][]OwedWork{one: {w}}, un)))
	}
	two, three := keyString(SetKey{Name: "Two"}), keyString(SetKey{Name: "Three"})
	for _, tc := range []struct {
		name       string
		w          OwedWork
		unverified []string
		want       []string
	}{
		{"rollback, server not verified", OwedWork{Kind: OwedRollback, Run: 1}, []string{x}, []string{two}},
		{"rollback, server verified", OwedWork{Kind: OwedRollback, Run: 1}, nil, []string{}},
		{"reconcile, other server not verified", OwedWork{Kind: OwedReconcile, Run: 1}, []string{y}, []string{}},
		{"call", OwedWork{Kind: OwedCall, Run: 1, Address: x}, nil, []string{two}},
		{"call on another server", OwedWork{Kind: OwedCall, Run: 1, Address: y}, nil, []string{three}},
		{"set change: its participants", OwedWork{Kind: OwedSetChange, Run: 1, Changes: []PlannedChange{{Set: SetKey{Name: "Three"}}}}, nil, []string{three}},
		{"set change, servers not verified", OwedWork{Kind: OwedSetChange, Run: 1, Changes: []PlannedChange{{Set: SetKey{Name: "Three"}}}}, []string{x}, []string{three, two}},
	} {
		got := fenced(tc.w, tc.unverified...)
		want := slices.Sorted(slices.Values(tc.want))
		assert.Equal(t, want, got, tc.name)
	}
}

// TestFencedOfAliases: two addresses of one server, by the ApplicationUri
// its records were made with, are one domain: an owed call on one fences
// the sets on the other.
func TestFencedOfAliases(t *testing.T) {
	t.Parallel()
	const x, x2, y = "opc.tcp://x", "opc.tcp://x-alias", "opc.tcp://y"
	l := &loaded{eps: map[string]*epStored{
		"e1": {SetName: "One", Address: x, Server: serverEvidence{ApplicationURI: "urn:x", Source: identityReported}},
		"e2": {SetName: "Two", Address: x2, Server: serverEvidence{ApplicationURI: "urn:x", Source: identityReported}},
		"e3": {SetName: "Three", Address: y, Server: serverEvidence{ApplicationURI: "urn:y", Source: identityReported}},
	}}
	one := keyString(SetKey{Name: "One"})
	got := fencedOf(l, map[string][]OwedWork{one: {{Kind: OwedCall, Run: 1, Address: x}}}, nil)
	assert.Equal(t, []string{keyString(SetKey{Name: "Two"})}, slices.Sorted(maps.Keys(got)))
}
