// SPDX-License-Identifier: MIT

package fxcm

import (
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/otfabric/go-opcua/ua"
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

// TestFencedBy: the check before an intent is written (fenceIntents). An
// intent of another set on the same server fences once its run ended, and
// while its run is active only when its outcome is unknown (retained); an
// intent of the set itself, or on another server, does not.
func TestFencedBy(t *testing.T) {
	t.Parallel()
	const x, y = "opc.tcp://x", "opc.tcp://y"
	one := SetKey{Name: "One"}
	c := &callRecord{Address: x, Server: serverEvidence{ApplicationURI: "urn:x"}}
	calls := map[string]*callRecord{
		"call/7/1": {Run: 7, SetName: "Two", Address: x},
	}
	for _, tc := range []struct {
		name     string
		calls    map[string]*callRecord
		active   map[RunID]bool
		retained map[string]bool
		fenced   bool
	}{
		{"ended run", calls, nil, nil, true},
		{"active run in flight", calls, map[RunID]bool{7: true}, nil, false},
		{"active run, outcome unknown", calls, map[RunID]bool{7: true}, map[string]bool{"call/7/1": true}, true},
		{"its own set", map[string]*callRecord{"call/7/1": {Run: 7, SetName: "One", Address: x}}, nil, nil, false},
		{"another server", map[string]*callRecord{"call/7/1": {Run: 7, SetName: "Two", Address: y}}, nil, nil, false},
		{"an alias of the server", map[string]*callRecord{"call/7/1": {Run: 7, SetName: "Two", Address: y, Server: serverEvidence{ApplicationURI: "urn:x"}}}, nil, nil, true},
	} {
		err := fencedBy(one, c, tc.calls, tc.active, tc.retained)
		if tc.fenced {
			assert.ErrorIs(t, err, ua.StatusBadInvalidState, tc.name)
		} else {
			assert.NoError(t, err, tc.name)
		}
	}
}
