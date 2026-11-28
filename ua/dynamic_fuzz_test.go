// SPDX-License-Identifier: MIT

package ua

import (
	"testing"
)

// FuzzDynamicTypes decodes untrusted bodies with the DataTypes of dynSet:
// the decoder must not panic or allocate beyond its input, and what it
// decodes must encode and decode again.
func FuzzDynamicTypes(f *testing.F) {
	s := dynSet(f)
	types := []uint32{dtOuter, dtInner, dtTypeA, dtType1, dtType2, dtSubtyped, dtSubUnion, dtRecursive, dtEmpty}
	f.Add(uint8(2), []byte{0x02, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0xff, 0x09, 0x00, 0x00, 0x00})
	f.Add(uint8(3), []byte{0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00})
	f.Add(uint8(7), []byte{0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff})
	f.Add(uint8(1), []byte{0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x41})
	v, err := s.New(dynID(dtOuter))
	if err != nil {
		f.Fatal(err)
	}
	b, err := v.Encode()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(uint8(0), b)
	f.Fuzz(func(t *testing.T, which uint8, body []byte) {
		dt := types[int(which)%len(types)]
		eo := &ExtensionObject{TypeID: &ExpandedNodeID{NodeID: dynID(dt + 1)}, EncodingMask: ExtensionObjectBinary, RawBody: body}
		if err := s.DecodeExtensionObject(eo); err != nil {
			return
		}
		v, ok := eo.Value.(*DynamicStructure)
		if !ok {
			t.Fatalf("decoded %T", eo.Value)
		}
		b, err := v.Encode()
		if err != nil {
			t.Fatalf("a decoded value does not encode: %v", err)
		}
		again := &ExtensionObject{TypeID: eo.TypeID, EncodingMask: ExtensionObjectBinary, RawBody: b}
		if err := s.DecodeExtensionObject(again); err != nil {
			t.Fatalf("re-encoded body does not decode: %v", err)
		}
	})
}
