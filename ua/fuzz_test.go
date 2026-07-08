// SPDX-License-Identifier: MIT

package ua

import (
	"testing"
)

func FuzzVariantDecode(f *testing.F) {
	// seed corpus: a few valid Variant encodings
	f.Add([]byte{0x01, 0x01})                                           // Boolean true
	f.Add([]byte{0x06, 0x2a, 0x00, 0x00, 0x00})                         // Int32(42)
	f.Add([]byte{0x0c, 0x04, 0x00, 0x00, 0x00, 0x74, 0x65, 0x73, 0x74}) // String "test"
	f.Add([]byte{0x00})                                                 // Null
	f.Fuzz(func(t *testing.T, data []byte) {
		v := new(Variant)
		n, err := v.Decode(data)
		if err != nil {
			return
		}
		if n > len(data) {
			t.Fatalf("Decode consumed %d bytes but input was %d", n, len(data))
		}
	})
}

func FuzzNodeIDDecode(f *testing.F) {
	f.Add([]byte{0x00, 0x0d})                               // TwoByte: i=13
	f.Add([]byte{0x01, 0x00, 0x0d, 0x00})                   // FourByte: i=13
	f.Add([]byte{0x02, 0x01, 0x00, 0x0d, 0x00, 0x00, 0x00}) // Numeric
	f.Fuzz(func(t *testing.T, data []byte) {
		n := new(NodeID)
		consumed, err := n.Decode(data)
		if err != nil {
			return
		}
		if consumed > len(data) {
			t.Fatalf("Decode consumed %d bytes but input was %d", consumed, len(data))
		}
	})
}

func FuzzExtensionObjectDecode(f *testing.F) {
	f.Add([]byte{0x00, 0x00, 0x00})
	f.Add([]byte{0x01, 0x00, 0x0d, 0x01, 0x00, 0x00, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		e := new(ExtensionObject)
		consumed, err := e.Decode(data)
		if err != nil {
			return
		}
		if consumed > len(data) {
			t.Fatalf("Decode consumed %d bytes but input was %d", consumed, len(data))
		}
	})
}
