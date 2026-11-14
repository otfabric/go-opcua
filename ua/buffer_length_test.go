// SPDX-License-Identifier: MIT

package ua

import (
	"encoding/binary"
	"io"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

// declaredLengths are the boundaries of a UInt32 length against a short
// input: around the input length, around the largest value of a 32-bit int
// and at the top of the UInt32 range (0xffffffff is the null value).
var declaredLengths = []uint32{
	5, 6, 0xffff, 0x10000,
	0x7ffffffc, 0x7ffffffd, 0x7ffffffe, 0x7fffffff,
	0x80000000, 0x80000001, 0xfffffffe,
}

// TestReadBytesLengthBoundaries: the length of a String or ByteString is
// compared with the bytes that are left as an unsigned number, so every
// length the input cannot hold is io.ErrUnexpectedEOF, whatever the width of
// int. The lengths from 0x80000000 on have no value in a 32-bit int.
func TestReadBytesLengthBoundaries(t *testing.T) {
	body := []byte("abcd")
	in := func(n uint32) []byte { return append(binary.LittleEndian.AppendUint32(nil, n), body...) }

	t.Run("lengths the input holds", func(t *testing.T) {
		for n, want := range map[uint32][]byte{0: nil, 1: []byte("a"), 3: []byte("abc"), 4: body, null: nil} {
			b := NewBuffer(in(n))
			require.Equal(t, want, b.ReadBytes(), "length %#x", n)
			require.NoError(t, b.Error(), "length %#x", n)
		}
		b := NewBuffer(in(4))
		require.Equal(t, "abcd", b.ReadString())
		require.NoError(t, b.Error())
		require.Equal(t, 8, b.Pos())
	})

	t.Run("lengths beyond the input", func(t *testing.T) {
		for _, n := range declaredLengths {
			b := NewBuffer(in(n))
			var got []byte
			alloc := allocated(func() { got = b.ReadBytes() })
			require.Nil(t, got, "length %#x", n)
			require.ErrorIs(t, b.Error(), io.ErrUnexpectedEOF, "length %#x", n)
			require.Less(t, alloc, uint64(1<<16), "bytes allocated, length %#x", n)

			b = NewBuffer(in(n))
			require.Empty(t, b.ReadString(), "length %#x", n)
			require.ErrorIs(t, b.Error(), io.ErrUnexpectedEOF, "length %#x", n)

			// The same length in values that are decoded by reflection.
			var s string
			_, err := Decode(in(n), &s)
			require.ErrorIs(t, err, io.ErrUnexpectedEOF, "length %#x", n)
			var bs []byte
			_, err = Decode(in(n), &bs)
			require.Error(t, err, "length %#x", n)
			require.Nil(t, bs, "length %#x", n)
		}
	})
}

// TestReadNBoundaries: ReadN gives the bytes that are there and
// io.ErrUnexpectedEOF for a count that is negative or beyond them.
func TestReadNBoundaries(t *testing.T) {
	data := []byte{1, 2, 3, 4}
	for _, tt := range []struct {
		n    int
		want []byte
	}{
		{0, []byte{}},
		{1, []byte{1}},
		{3, []byte{1, 2, 3}},
		{4, data},
	} {
		b := NewBuffer(data)
		require.Equal(t, tt.want, b.ReadN(tt.n), "n=%d", tt.n)
		require.NoError(t, b.Error(), "n=%d", tt.n)
		require.Equal(t, tt.n, b.Pos(), "n=%d", tt.n)
	}
	for _, n := range []int{5, math.MaxInt32, math.MaxInt, -1, -4, math.MinInt32, math.MinInt} {
		b := NewBuffer(data)
		require.Nil(t, b.ReadN(n), "n=%d", n)
		require.ErrorIs(t, b.Error(), io.ErrUnexpectedEOF, "n=%d", n)
		require.Equal(t, 0, b.Pos(), "n=%d: the position stays", n)
		// The buffer stays in its error state.
		require.Nil(t, b.ReadN(1))
	}
}

// TestExtensionObjectBodyLengthBoundaries: the body length of an
// ExtensionObject is checked like the length of a ByteString.
func TestExtensionObjectBodyLengthBoundaries(t *testing.T) {
	// TypeId i=0 (two byte NodeId), a binary body, its length, 4 bytes.
	in := func(n uint32) []byte {
		b := []byte{0x00, 0x00, ExtensionObjectBinary}
		return append(binary.LittleEndian.AppendUint32(b, n), 1, 2, 3, 4)
	}

	t.Run("lengths the input holds", func(t *testing.T) {
		for n, want := range map[uint32][]byte{0: nil, 1: {1}, 4: {1, 2, 3, 4}, 0xffffffff: nil} {
			var eo ExtensionObject
			pos, err := eo.Decode(in(n))
			require.NoError(t, err, "length %#x", n)
			require.Equal(t, want, eo.RawBody, "length %#x", n)
			require.Equal(t, 7+len(want), pos, "length %#x", n)
		}
	})

	t.Run("lengths beyond the input", func(t *testing.T) {
		for _, n := range declaredLengths {
			var eo ExtensionObject
			var err error
			alloc := allocated(func() { _, err = eo.Decode(in(n)) })
			require.ErrorIs(t, err, io.ErrUnexpectedEOF, "length %#x", n)
			require.Less(t, alloc, uint64(1<<16), "bytes allocated, length %#x", n)

			// In a Variant, the way it arrives in a service message.
			var v Variant
			_, err = v.Decode(append([]byte{byte(TypeIDExtensionObject)}, in(n)...))
			require.ErrorIs(t, err, io.ErrUnexpectedEOF, "length %#x", n)
		}
	})
}
