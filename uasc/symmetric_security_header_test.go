// SPDX-License-Identifier: MIT

package uasc

import (
	"testing"
)

func TestSymmetricSecurityHeader(t *testing.T) {
	cases := []CodecTestCase{
		{
			Name: "normal",
			Struct: NewSymmetricSecurityHeader(
				0x11223344,
			),
			Bytes: []byte{
				// TokenID
				0x44, 0x33, 0x22, 0x11,
			},
		}, {
			Name: "no-payload",
			Struct: NewSymmetricSecurityHeader(
				0x11223344,
			),
			Bytes: []byte{
				// TokenID
				0x44, 0x33, 0x22, 0x11,
			},
		},
	}
	RunCodecTest(t, cases)
}

func TestSymmetricSecurityHeaderStringAndLen(t *testing.T) {
	h := NewSymmetricSecurityHeader(0x11223344)
	if h.String() != "TokenID: 287454020" {
		t.Fatalf("String: got %q", h.String())
	}
	if h.Len() != 4 {
		t.Fatalf("Len: got %d", h.Len())
	}
}
