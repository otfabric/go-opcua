// SPDX-License-Identifier: MIT

package uamethod_test

import (
	"testing"

	"github.com/otfabric/go-opcua/ua"
)

// FuzzUnpack: the arguments of a call come from a peer; Unpack of every
// contract checks them without panicking, and what it accepts packs to
// arguments it accepts again.
func FuzzUnpack(f *testing.F) {
	for _, a := range filled() {
		b, err := ua.Encode(a.Pack())
		if err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		var vs []*ua.Variant
		if _, err := ua.Decode(b, &vs); err != nil {
			return
		}
		for _, a := range filled() {
			x := fresh(a)
			if x.Unpack(vs) != nil {
				continue
			}
			if err := fresh(a).Unpack(x.Pack()); err != nil {
				t.Fatalf("%T: %v", x, err)
			}
		}
	})
}
