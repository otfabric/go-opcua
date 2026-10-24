// SPDX-License-Identifier: MIT

package server

import "testing"

// The first chunk of a channel carries seed+1; with the legacy policies it
// must be below 1024. A seed of 1023 made it 1024, which async-opcua
// (rightly) rejects with BadSequenceNumberInvalid.
func TestSequenceNumberSeed_FirstNumberBelow1024(t *testing.T) {
	for _, pick := range []string{"lowest", "highest"} {
		seed := sequenceNumberSeed(func(n int32) int32 {
			if n != 1023 {
				t.Fatalf("Int31n(%d), want Int31n(1023)", n)
			}
			if pick == "lowest" {
				return 0
			}
			return n - 1
		})
		if first := seed + 1; first < 1 || first > 1023 {
			t.Errorf("%s seed %d: first sequence number %d, want 1..1023", pick, seed, first)
		}
	}
}
