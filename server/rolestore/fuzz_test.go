// SPDX-License-Identifier: MIT

package rolestore

import (
	"slices"
	"testing"

	"github.com/otfabric/go-opcua/server"
)

// FuzzRecords decodes a root record and a role record, alone and as a
// state, as Open does with the bytes of a file: nothing panics, and a
// state that decodes encodes again to records that decode to the same
// roles.
func FuzzRecords(f *testing.F) {
	recs, err := records(roles("A"), nsA)
	if err != nil {
		f.Fatal(err)
	}
	for k, v := range recs {
		if k != rootKey {
			f.Add(recs[rootKey], v)
		}
	}
	f.Add([]byte{1, 1, 0}, []byte{1, 0, 0, 0})
	f.Add([]byte{1, 0}, []byte{})
	f.Fuzz(func(t *testing.T, rootRec, roleRec []byte) {
		state := map[string][]byte{rootKey: rootRec}
		if x, err := decodeRecord(roleRec); err == nil {
			// Under the key of its role, which the root has to name.
			state[roleKey(x.nodeNS, x.b.NodeID)] = roleRec
		}
		recs, err := decodeState(state)
		if err != nil || recs == nil {
			return
		}
		// The namespaces of the records, in the order they first appear.
		var ns []string
		for _, x := range recs {
			for _, u := range []string{x.nodeNS, x.nameNS} {
				if !slices.Contains(ns, u) {
					ns = append(ns, u)
				}
			}
		}
		toRoles := func(recs []*record) []server.Role {
			var out []server.Role
			for _, x := range recs {
				r, err := x.role(ns)
				if err != nil {
					t.Fatalf("a decoded record has no role: %v", err)
				}
				out = append(out, r)
			}
			return out
		}
		rs := toRoles(recs)
		again, err := records(rs, ns)
		if err != nil {
			t.Fatalf("decoded roles do not encode: %v", err)
		}
		recs2, err := decodeState(again)
		if err != nil {
			t.Fatalf("the records of decoded roles do not decode: %v", err)
		}
		if !slices.Equal(show(rs), show(toRoles(recs2))) {
			t.Fatal("the roles changed in a round trip")
		}
	})
}
