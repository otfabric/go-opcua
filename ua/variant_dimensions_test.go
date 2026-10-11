// SPDX-License-Identifier: MIT

package ua

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// binaryMatrix returns the binary encoding of an Int32 matrix Variant with
// the given elements and dimensions.
func binaryMatrix(elems []int32, dims []int32) []byte {
	b := []byte{byte(TypeIDInt32) | VariantArrayValues | VariantArrayDimensions}
	b = binary.LittleEndian.AppendUint32(b, uint32(len(elems)))
	for _, e := range elems {
		b = binary.LittleEndian.AppendUint32(b, uint32(e))
	}
	b = binary.LittleEndian.AppendUint32(b, uint32(len(dims)))
	for _, d := range dims {
		b = binary.LittleEndian.AppendUint32(b, uint32(d))
	}
	return b
}

// TestVariantDimensionsProductOverflow: the product of the dimensions used
// to be formed in 32 bits. 65536 x 65536 wraps around to 0 and passed for
// the dimensions of an empty array; with a third dimension the decoder then
// built 2^32 slices from a message of 21 bytes.
func TestVariantDimensionsProductOverflow(t *testing.T) {
	for _, dims := range [][]int32{
		{65536, 65536},
		{65536, 65536, 1},
		{65536, 65536, 65536, 65536},
		{1 << 30, 4},
		{2, 1 << 30, 2},
	} {
		var v Variant
		_, err := v.Decode(binaryMatrix(nil, dims))
		require.ErrorIs(t, err, errUnbalancedSlice, "dimensions %v", dims)
	}

	// The legitimate cases still decode.
	var v Variant
	_, err := v.Decode(binaryMatrix([]int32{1, 2, 3, 4, 5, 6}, []int32{2, 3}))
	require.NoError(t, err)
	require.Equal(t, [][]int32{{1, 2, 3}, {4, 5, 6}}, v.Value())
	require.Equal(t, []int32{2, 3}, v.ArrayDimensions())
}

// TestVariantDimensionCountIsLimited: every dimension is a level of nested
// slices with a Go type of its own. A document with one element and
// thousands of dimensions of length 1 used to be accepted in the binary,
// JSON and XML encoding, at the cost of a recursion as deep as the document
// is long and of a new slice type per dimension.
func TestVariantDimensionCountIsLimited(t *testing.T) {
	ones := func(n int) []int32 {
		d := make([]int32, n)
		for i := range d {
			d[i] = 1
		}
		return d
	}
	jsonDoc := func(n int) []byte {
		return []byte(`{"UaType":6,"Value":[7],"Dimensions":[` + strings.TrimSuffix(strings.Repeat("1,", n), ",") + `]}`)
	}
	xmlDoc := func(n int) []byte {
		return []byte(`<Variant><Value><Matrix><Dimensions>` + strings.Repeat(`<Int32>1</Int32>`, n) +
			`</Dimensions><Elements><Int32>7</Int32></Elements></Matrix></Value></Variant>`)
	}

	for _, n := range []int{maxVariantArrayDimensions + 1, 5000} {
		t.Run(fmt.Sprintf("%d dimensions", n), func(t *testing.T) {
			var v Variant
			_, err := v.Decode(binaryMatrix([]int32{7}, ones(n)))
			require.ErrorIs(t, err, StatusBadEncodingLimitsExceeded, "binary")

			err = DecodeJSON(jsonDoc(n), &v)
			require.Error(t, err, "json")
			require.True(t, errors.Is(err, StatusBadDecodingError) || errors.Is(err, StatusBadEncodingLimitsExceeded), "json: %v", err)

			err = DecodeXML(xmlDoc(n), &v)
			require.Error(t, err, "xml")
			require.True(t, errors.Is(err, StatusBadDecodingError) || errors.Is(err, StatusBadEncodingLimitsExceeded), "xml: %v", err)
		})
	}

	// The limit itself is accepted, in every encoding, and survives a
	// round trip.
	n := maxVariantArrayDimensions
	var fromBinary, fromJSON, fromXML Variant
	_, err := fromBinary.Decode(binaryMatrix([]int32{7}, ones(n)))
	require.NoError(t, err)
	require.Len(t, fromBinary.ArrayDimensions(), n)
	require.NoError(t, DecodeJSON(jsonDoc(n), &fromJSON))
	require.NoError(t, DecodeXML(xmlDoc(n), &fromXML))
	want, err := fromBinary.Encode()
	require.NoError(t, err)
	for name, v := range map[string]*Variant{"json": &fromJSON, "xml": &fromXML} {
		got, err := v.Encode()
		require.NoError(t, err, name)
		require.Equal(t, want, got, name)
	}
}
