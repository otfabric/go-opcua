// SPDX-License-Identifier: MIT

package ua

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtensionObject_XMLBodyRoundTrip(t *testing.T) {
	x := XMLElement("<a>1</a>")
	eo := NewExtensionObject(&x)
	require.Equal(t, uint8(ExtensionObjectXML), eo.EncodingMask)

	b, err := eo.Encode()
	require.NoError(t, err)

	var got ExtensionObject
	n, err := got.Decode(b)
	require.NoError(t, err)
	require.Equal(t, len(b), n)
	require.Equal(t, uint8(ExtensionObjectXML), got.EncodingMask)
	body, ok := got.Value.(*XMLElement)
	require.True(t, ok)
	require.Equal(t, x, *body)
}

func TestExtensionObject_DecodeEdgeCases(t *testing.T) {
	typeID := []byte{0x01, 0x00, 0x41, 0x01} // four byte, ns=0, i=321 (AnonymousIdentityToken)

	t.Run("no body", func(t *testing.T) {
		var eo ExtensionObject
		b := append(append([]byte{}, typeID...), ExtensionObjectEmpty)
		n, err := eo.Decode(b)
		require.NoError(t, err)
		require.Equal(t, len(b), n)
		require.Nil(t, eo.Value)
	})

	for name, length := range map[string][]byte{
		"zero length body": {0x00, 0x00, 0x00, 0x00},
		"null length body": {0xff, 0xff, 0xff, 0xff},
	} {
		t.Run(name, func(t *testing.T) {
			var eo ExtensionObject
			b := append(append(append([]byte{}, typeID...), ExtensionObjectBinary), length...)
			n, err := eo.Decode(b)
			require.NoError(t, err)
			require.Equal(t, len(b), n)
			require.Nil(t, eo.Value)
		})
	}

	t.Run("body shorter than its length", func(t *testing.T) {
		var eo ExtensionObject
		b := append(append(append([]byte{}, typeID...), ExtensionObjectBinary), 0x10, 0x00, 0x00, 0x00, 0x01)
		_, err := eo.Decode(b)
		require.Error(t, err)
		require.Nil(t, eo.Value)
	})

	t.Run("truncated before length", func(t *testing.T) {
		var eo ExtensionObject
		_, err := eo.Decode(append(append([]byte{}, typeID...), ExtensionObjectBinary, 0x01))
		require.Error(t, err)
	})

	t.Run("unknown type keeps the stream position", func(t *testing.T) {
		var eo ExtensionObject
		// numeric ns=7;i=0xfffffff0 is not a registered encoding id
		b := []byte{0x02, 0x07, 0x00, 0xf0, 0xff, 0xff, 0xff, ExtensionObjectBinary, 0x02, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc}
		n, err := eo.Decode(b)
		require.NoError(t, err)
		require.Equal(t, len(b)-1, n, "exactly the declared body must be skipped")
		require.Nil(t, eo.Value)
		require.Equal(t, uint32(0xfffffff0), eo.TypeID.NodeID.IntID())
		require.Equal(t, uint16(7), eo.TypeID.NodeID.Namespace())
	})

	t.Run("known type with malformed body", func(t *testing.T) {
		var eo ExtensionObject
		// AnonymousIdentityToken whose PolicyID claims 9 bytes but carries 1.
		b := append(append(append([]byte{}, typeID...), ExtensionObjectBinary), 0x05, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x61)
		_, err := eo.Decode(b)
		require.Error(t, err)
	})
}

func TestExtensionObject_EncodeEdgeCases(t *testing.T) {
	// A nil extension object encodes as the null object.
	b, err := (*ExtensionObject)(nil).Encode()
	require.NoError(t, err)
	require.Equal(t, []byte{0x00, 0x00, 0x00}, b)

	// A body that cannot be encoded is reported instead of producing a partial object.
	eo := &ExtensionObject{TypeID: NewTwoByteExpandedNodeID(0), EncodingMask: ExtensionObjectBinary, Value: make(chan int)}
	b, err = eo.Encode()
	require.Error(t, err)
	require.Nil(t, b)

	eo = &ExtensionObject{}
	eo.UpdateMask()
	require.Equal(t, uint8(ExtensionObjectEmpty), eo.EncodingMask)

	// Unknown value types map to the null type id.
	require.Equal(t, NewTwoByteExpandedNodeID(0), ExtensionObjectTypeID(struct{}{}))

	require.Panics(t, func() {
		// i=321 is already registered as AnonymousIdentityToken.
		RegisterExtensionObject(NewFourByteNodeID(0, 321), new(UserNameIdentityToken))
	})
}
