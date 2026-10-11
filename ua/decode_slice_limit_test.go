// SPDX-License-Identifier: MIT

package ua

import (
	"encoding/base64"
	"encoding/binary"
	"runtime"
	"testing"

	"github.com/otfabric/go-opcua/errors"
	"github.com/stretchr/testify/require"
)

// allocated returns the number of bytes fn allocates.
func allocated(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// TestDecodeSliceLengthIsBoundedByInput: the binary decoder used to allocate
// an array as long as its length prefix said, before reading a single
// element. Four bytes of input asked for up to 2^31 elements - 8 GB for a
// []uint32, 16 GB for an array of structures - in any array of any message,
// and in the binary body of an ExtensionObject in a JSON or XML document.
func TestDecodeSliceLengthIsBoundedByInput(t *testing.T) {
	const huge = 0x7fffffff
	prefix := binary.LittleEndian.AppendUint32(nil, huge)

	t.Run("array of numbers", func(t *testing.T) {
		var v []uint32
		var err error
		n := allocated(func() { _, err = Decode(append(prefix, 1, 0, 0, 0), &v) })
		require.ErrorIs(t, err, errors.ErrArrayTooLarge)
		require.Less(t, n, uint64(1<<20), "bytes allocated for a 8 byte message")
	})

	t.Run("array of structures", func(t *testing.T) {
		var v []*ReadValueID
		var err error
		n := allocated(func() { _, err = Decode(prefix, &v) })
		require.ErrorIs(t, err, errors.ErrArrayTooLarge)
		require.Less(t, n, uint64(1<<20))
	})

	t.Run("array in a service request", func(t *testing.T) {
		req := &ReadRequest{RequestHeader: &RequestHeader{AuthenticationToken: NewTwoByteNodeID(0), AdditionalHeader: NewExtensionObject(nil)}}
		msg, err := Encode(req)
		require.NoError(t, err)
		// NodesToRead is the last field: a null array, i.e. 0xffffffff.
		binary.LittleEndian.PutUint32(msg[len(msg)-4:], huge)
		var got ReadRequest
		n := allocated(func() { _, err = Decode(msg, &got) })
		require.ErrorIs(t, err, errors.ErrArrayTooLarge)
		require.Less(t, n, uint64(1<<20))
	})

	t.Run("binary body in JSON and XML", func(t *testing.T) {
		// An Argument whose ArrayDimensions claim 2^31-1 elements.
		arg, err := Encode(&Argument{Name: "x", DataType: NewTwoByteNodeID(6), ValueRank: 1, Description: &LocalizedText{}})
		require.NoError(t, err)
		// Name(4+1) DataType(2) ValueRank(4), then the array length.
		binary.LittleEndian.PutUint32(arg[11:], huge)
		body := base64.StdEncoding.EncodeToString(arg[:15])

		var eo ExtensionObject
		n := allocated(func() {
			err = DecodeJSON([]byte(`{"UaTypeId":"i=296","UaEncoding":1,"UaBody":"`+body+`"}`), &eo)
		})
		require.ErrorIs(t, err, errors.ErrArrayTooLarge)
		require.Less(t, n, uint64(1<<20))

		n = allocated(func() {
			err = DecodeXML([]byte(`<ExtensionObject><TypeId><Identifier>i=297</Identifier></TypeId><Body><ByteString>`+body+`</ByteString></Body></ExtensionObject>`), &eo)
		})
		require.ErrorIs(t, err, errors.ErrArrayTooLarge)
		require.Less(t, n, uint64(1<<20))
	})

	t.Run("what fits is decoded", func(t *testing.T) {
		in := []uint32{1, 2, 3}
		b, err := Encode(in)
		require.NoError(t, err)
		var out []uint32
		_, err = Decode(b, &out)
		require.NoError(t, err)
		require.Equal(t, in, out)

		// Structures without fields have an empty encoding: an array of
		// them is longer than the input that holds it.
		empties := make([]*Union, 300)
		for i := range empties {
			empties[i] = &Union{}
		}
		b, err = Encode(empties)
		require.NoError(t, err)
		require.Len(t, b, 4)
		var back []*Union
		_, err = Decode(b, &back)
		require.NoError(t, err)
		require.Len(t, back, 300)

		_, err = Decode(prefix, &back)
		require.ErrorIs(t, err, errors.ErrArrayTooLarge)
	})
}
