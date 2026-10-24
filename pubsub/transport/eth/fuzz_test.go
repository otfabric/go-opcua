// SPDX-License-Identifier: MIT

package eth

import (
	"testing"
)

// FuzzParseURL parses arbitrary opc.eth:// addresses, which a client can
// send with AddConnection: ParseURL must not panic, and an address it
// accepts must print as a URL that parses to the same address.
func FuzzParseURL(f *testing.F) {
	for _, s := range []string{
		"opc.eth://01-23-45-67-89-ab", "opc.eth://1-2-3-4-5-6:100.5", "opc.eth://ff-ff-ff-ff-ff-ff:0.7",
		"opc.eth://01-00-5e-00-00-01:4094.0/path?q#f", "opc.eth://", "opc.eth://:12", "opc.eth://01-23-45-67-89-ab:",
		"opc.eth://01-23-45-67-89-ab:4095", "opc.eth://host:1.8", "opc.eth://[::1]:4840", "opc.udp://x",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		a, err := ParseURL(s)
		if err != nil {
			return
		}
		if a.VID > 4094 || a.PCP > 7 || (a.MAC != nil && len(a.MAC) != 6) || (!a.VLAN && (a.VID != 0 || a.PCP != 0)) {
			t.Fatalf("%q: out of range address %+v", s, a)
		}
		b, err := ParseURL(a.URL())
		if err != nil {
			t.Fatalf("%q: %q does not parse: %v", s, a.URL(), err)
		}
		if b.String() != a.String() || b.VLAN != a.VLAN || b.VID != a.VID || b.PCP != a.PCP {
			t.Fatalf("%q: %+v != %+v", s, a, b)
		}
	})
}
