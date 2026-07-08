// SPDX-License-Identifier: MIT

package ua

import (
	"testing"
)

func TestSignatureData(t *testing.T) {
	cases := []CodecTestCase{
		{
			Name:   "empty",
			Struct: &SignatureData{},
			Bytes: []byte{
				// Algorithm
				0xff, 0xff, 0xff, 0xff,
				// Signature
				0xff, 0xff, 0xff, 0xff,
			},
		},
		{
			Name:   "dummy data",
			Struct: &SignatureData{Algorithm: "alg", Signature: []byte{0xde, 0xad, 0xbe, 0xef}},
			Bytes: []byte{
				// Algorithm
				0x03, 0x00, 0x00, 0x00, 0x61, 0x6c, 0x67,
				// Signature
				0x04, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef,
			},
		},
	}
	RunCodecTest(t, cases)
}
