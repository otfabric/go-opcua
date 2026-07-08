// SPDX-License-Identifier: MIT

package ua

import (
	"testing"
)

func TestExtensionObject(t *testing.T) {
	cases := []CodecTestCase{
		{
			Name:   "anonymous-user-identity-token",
			Struct: NewExtensionObject(&AnonymousIdentityToken{PolicyID: "anonymous"}),
			Bytes: []byte{
				// TypeID
				0x01, 0x00, 0x41, 0x01,
				// EncodingMask
				0x01,
				// Length
				0x0d, 0x00, 0x00, 0x00,
				// AnonymousIdentityToken
				0x09, 0x00, 0x00, 0x00, 0x61, 0x6e, 0x6f, 0x6e, 0x79, 0x6d, 0x6f, 0x75, 0x73,
			},
		},
	}
	RunCodecTest(t, cases)
}
