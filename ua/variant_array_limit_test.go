// SPDX-License-Identifier: MIT

package ua

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// variantArray is the encoding of a Variant array of type id with the
// declared length n, followed by body.
func variantArray(id TypeID, n int32, body ...byte) []byte {
	b := []byte{VariantArrayValues | byte(id)}
	b = binary.LittleEndian.AppendUint32(b, uint32(n))
	return append(b, body...)
}

// TestVariantArrayLengthIsBoundedByInput: an element of every built-in type
// takes at least one byte, so the length of a Variant array is checked
// against the bytes that remain before the array is allocated, at every
// nesting level, and the first element that does not decode ends the array.
func TestVariantArrayLengthIsBoundedByInput(t *testing.T) {
	const budget = 1 << 20

	t.Run("one level", func(t *testing.T) {
		// 65535 Variants, none of them in the input.
		in := variantArray(TypeIDVariant, int32(MaxVariantArrayLength))
		var v Variant
		var err error
		n := allocated(func() { _, err = v.Decode(in) })
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
		require.Less(t, n, uint64(budget), "bytes allocated for a %d byte input", len(in))
	})

	t.Run("nested to the depth limit", func(t *testing.T) {
		// An array of Variants whose first element is such an array again,
		// as deep as the decoder goes; each declares 65535 elements.
		var in []byte
		for range MaxBinaryNestingDepth - 1 {
			in = append(in, variantArray(TypeIDVariant, int32(MaxVariantArrayLength))...)
		}
		var v Variant
		var err error
		n := allocated(func() { _, err = v.Decode(in) })
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
		require.Less(t, n, uint64(budget), "bytes allocated for a %d byte input", len(in))
	})

	t.Run("nested, every length fits the input that follows it", func(t *testing.T) {
		// Each level declares one element per byte that follows it. The
		// first element takes them all, so the second one ends the array.
		const levels = MaxBinaryNestingDepth - 1
		var in []byte
		for i := range levels {
			in = append(in, variantArray(TypeIDVariant, int32(5*(levels-1-i)))...)
		}
		var v Variant
		var err error
		n := allocated(func() { _, err = v.Decode(in) })
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
		require.Less(t, n, uint64(budget), "bytes allocated for a %d byte input", len(in))
	})

	t.Run("every built-in type", func(t *testing.T) {
		for id := TypeIDBoolean; id <= TypeIDDiagnosticInfo; id++ {
			t.Run(fmt.Sprint(id), func(t *testing.T) {
				// One byte of input, 65535 elements declared.
				in := variantArray(id, int32(MaxVariantArrayLength), 0)
				var v Variant
				var err error
				n := allocated(func() { _, err = v.Decode(in) })
				require.ErrorIs(t, err, io.ErrUnexpectedEOF)
				require.Less(t, n, uint64(budget))
			})
		}
	})

	t.Run("in a structure", func(t *testing.T) {
		// A DataValue whose value is the array.
		in := append([]byte{DataValueValue}, variantArray(TypeIDVariant, int32(MaxVariantArrayLength))...)
		var dv DataValue
		var err error
		n := allocated(func() { _, err = Decode(in, &dv) })
		require.Error(t, err)
		require.Less(t, n, uint64(budget))
	})
}

// TestVariantArrayLengthBoundaries is the boundary table of the array length
// of a Variant against the input that holds its elements.
func TestVariantArrayLengthBoundaries(t *testing.T) {
	limit := MaxVariantArrayLength
	for _, tt := range []struct {
		name     string
		declared int32
		elements int // one byte each
		err      error
	}{
		{"null array", -1, 0, nil},
		{"empty array", 0, 0, nil},
		{"one element", 1, 1, nil},
		{"one element, none in the input", 1, 0, io.ErrUnexpectedEOF},
		{"one more than the input holds", 4, 3, io.ErrUnexpectedEOF},
		{"as many as the input holds", 4, 4, nil},
		{"fewer than the input holds", 3, 4, nil},
		{"limit minus one", int32(limit - 1), limit - 1, nil},
		{"limit", int32(limit), limit, nil},
		{"limit, one element short", int32(limit), limit - 1, io.ErrUnexpectedEOF},
		{"limit plus one", int32(limit + 1), limit + 1, StatusBadEncodingLimitsExceeded},
		{"negative", -2, 0, StatusBadEncodingLimitsExceeded},
		{"largest Int32", 0x7fffffff, 8, StatusBadEncodingLimitsExceeded},
		{"smallest Int32", -0x80000000, 8, StatusBadEncodingLimitsExceeded},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, id := range []TypeID{TypeIDBoolean, TypeIDByte, TypeIDVariant} {
				in := variantArray(id, tt.declared, make([]byte, tt.elements)...)
				var v Variant
				n, err := v.Decode(in)
				if tt.err != nil {
					require.ErrorIs(t, err, tt.err, "type %d", id)
					continue
				}
				require.NoError(t, err, "type %d", id)
				want := max(int(tt.declared), 0)
				require.Equal(t, 5+want, n, "bytes read, type %d", id)
				require.Equal(t, tt.declared, v.ArrayLength())
				switch a := v.Value().(type) {
				case []bool:
					require.Len(t, a, want)
				case ByteArray:
					require.Len(t, a, want)
				case []*Variant:
					require.Len(t, a, want)
				default:
					t.Fatalf("value of type %T", a)
				}
			}
		})
	}
}

// TestVariantArrayDimensionsStopAtTheEndOfInput: the dimensions of an array
// are read while the input lasts; an array whose dimensions are cut short is
// io.ErrUnexpectedEOF.
func TestVariantArrayDimensionsStopAtTheEndOfInput(t *testing.T) {
	full, err := MustVariant([][]uint32{{1, 2, 3}, {4, 5, 6}}).Encode()
	require.NoError(t, err)
	var v Variant
	_, err = v.Decode(full)
	require.NoError(t, err)
	require.Equal(t, []int32{2, 3}, v.ArrayDimensions())

	// mask, length, 6 elements, then the number of dimensions and two of them.
	dims := 1 + 4 + 6*4
	for cut := dims; cut < len(full); cut++ {
		var v Variant
		_, err := v.Decode(full[:cut])
		require.ErrorIs(t, err, io.ErrUnexpectedEOF, "input of %d of %d bytes", cut, len(full))
	}

	// Elements cut short end the array as well.
	for cut := 5; cut < dims; cut++ {
		var v Variant
		_, err := v.Decode(full[:cut])
		require.ErrorIs(t, err, io.ErrUnexpectedEOF, "input of %d of %d bytes", cut, len(full))
	}
}

// TestVariantArraysDecodeAsEncoded: arrays of every built-in type decode to
// what was encoded, with the length check in place.
func TestVariantArraysDecodeAsEncoded(t *testing.T) {
	for _, in := range []any{
		[]bool{true, false},
		[]int8{-1, 2},
		ByteArray{1, 2, 3},
		[]int16{-1, 2},
		[]uint16{1, 2},
		[]int32{-1, 2},
		[]uint32{1, 2},
		[]int64{-1, 2},
		[]uint64{1, 2},
		[]float32{1.5, -2},
		[]float64{1.5, -2},
		[]string{"a", "", "bc"},
		[]*GUID{NewGUID("AAAABBBB-CCDD-EEFF-0101-0123456789AB")},
		[][]byte{{1}, {2, 3}},
		[]XMLElement{"<a/>"},
		[]*NodeID{NewTwoByteNodeID(1), NewStringNodeID(2, "x")},
		[]*ExpandedNodeID{NewTwoByteExpandedNodeID(1)},
		[]StatusCode{StatusOK, StatusBad},
		[]*QualifiedName{{NamespaceIndex: 1, Name: "n"}},
		[]*LocalizedText{{}, NewLocalizedText("t")},
		[]*ExtensionObject{NewExtensionObject(nil)},
		[]*DataValue{{}, {EncodingMask: DataValueValue, Value: MustVariant(int32(1))}},
		[]*Variant{{}, MustVariant("x"), MustVariant([]*Variant{{}, {}})},
		[]*DiagnosticInfo{{}},
		[][]int32{{1, 2}, {3, 4}, {5, 6}},
	} {
		t.Run(fmt.Sprintf("%T", in), func(t *testing.T) {
			want := MustVariant(in)
			b, err := want.Encode()
			require.NoError(t, err)
			var got Variant
			n, err := got.Decode(b)
			require.NoError(t, err)
			require.Equal(t, len(b), n)
			back, err := got.Encode()
			require.NoError(t, err)
			require.True(t, bytes.Equal(b, back), "encoding of the decoded value")
			require.Equal(t, want.ArrayLength(), got.ArrayLength())
			require.Equal(t, want.ArrayDimensions(), got.ArrayDimensions())
		})
	}
}
