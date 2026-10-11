// SPDX-License-Identifier: MIT

package ua

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseNumericRanges_Malformed(t *testing.T) {
	for _, s := range []string{"", "   ", "1:2:3", ":2", "1:", "a", "-1", "1:a", "a:1", "-1:2", "2:1", "0,,1", ",0"} {
		t.Run(s, func(t *testing.T) {
			_, err := ParseNumericRanges(s)
			require.Equal(t, StatusBadIndexRangeInvalid, err)
		})
	}

	got, err := ParseNumericRanges(" 1:2 , 3 ")
	require.NoError(t, err)
	require.Equal(t, []NumericRange{{1, 2}, {3, 3}}, got)
}

func TestSliceVariantRead_Errors(t *testing.T) {
	arr := MustVariant([]int32{10, 20, 30})
	bs := MustVariant([]byte("abc"))
	mat := MustVariant([][]int32{{1, 2, 3}, {4, 5, 6}})

	tests := []struct {
		name string
		v    *Variant
		rng  string
		want StatusCode
	}{
		{"nil variant", nil, "0", StatusBadIndexRangeInvalid},
		{"malformed range", arr, "1:2:3", StatusBadIndexRangeInvalid},
		{"scalar is not indexable", MustVariant(int32(7)), "0", StatusBadIndexRangeInvalid},
		{"bytestring with two dimensions", bs, "0,0", StatusBadIndexRangeInvalid},
		{"bytestring start past end", bs, "3", StatusBadIndexRangeNoData},
		{"empty bytestring", MustVariant([]byte{}), "0", StatusBadIndexRangeNoData},
		{"array start past end", arr, "3:4", StatusBadIndexRangeNoData},
		{"empty array", MustVariant([]int32{}), "0", StatusBadIndexRangeNoData},
		{"array with two dimensions", arr, "0,0", StatusBadIndexRangeInvalid},
		{"matrix second dimension past end", mat, "0,3", StatusBadIndexRangeNoData},
		{"matrix with three dimensions", mat, "0,0,0", StatusBadIndexRangeInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, sc := SliceVariantRead(tt.v, tt.rng)
			require.Equal(t, tt.want, sc)
			require.Nil(t, out)
		})
	}
}

func TestSliceVariantRead_ClampsEndToLength(t *testing.T) {
	out, sc := SliceVariantRead(MustVariant([]byte("abc")), "1:99")
	require.Equal(t, StatusOK, sc)
	require.Equal(t, []byte("bc"), out.Value())

	out, sc = SliceVariantRead(MustVariant([]int32{10, 20, 30}), "1:99")
	require.Equal(t, StatusOK, sc)
	require.Equal(t, []int32{20, 30}, out.Value())

	// Both dimensions of a matrix are clamped independently.
	mat := MustVariant([][]int32{{1, 2, 3}, {4, 5, 6}})
	out, sc = SliceVariantRead(mat, "1:9,1:9")
	require.Equal(t, StatusOK, sc)
	require.Equal(t, [][]int32{{5, 6}}, out.Value())

	// A three-dimensional selection keeps its rank.
	cube := MustVariant([][][]int32{{{1, 2}, {3, 4}}, {{5, 6}, {7, 8}}})
	out, sc = SliceVariantRead(cube, "1,0:1,1")
	require.Equal(t, StatusOK, sc)
	require.Equal(t, [][][]int32{{{6}, {8}}}, out.Value())
}

func TestMergeVariantWrite_Errors(t *testing.T) {
	arr := MustVariant([]int32{10, 20, 30})
	bs := MustVariant([]byte("abc"))
	mat := MustVariant([][]int32{{1, 2, 3}, {4, 5, 6}})
	one := MustVariant(int32(1))

	tests := []struct {
		name    string
		current *Variant
		rng     string
		newVal  *Variant
		want    StatusCode
	}{
		{"nil current", nil, "0", one, StatusBadIndexRangeInvalid},
		{"nil new value", arr, "0", nil, StatusBadTypeMismatch},
		{"null new value", arr, "0", MustVariant(nil), StatusBadTypeMismatch},
		{"malformed range", arr, "x", one, StatusBadIndexRangeInvalid},
		{"scalar current", one, "0", one, StatusBadIndexRangeInvalid},
		{"bytestring with two dimensions", bs, "0,0", MustVariant([]byte("x")), StatusBadIndexRangeInvalid},
		{"bytestring range past end", bs, "2:3", MustVariant([]byte("xy")), StatusBadIndexRangeNoData},
		{"bytestring patched with a string", bs, "0", MustVariant("x"), StatusBadTypeMismatch},
		{"bytestring patch length mismatch", bs, "0:1", MustVariant([]byte("x")), StatusBadIndexRangeDataMismatch},
		{"array with two dimensions", arr, "0,0", one, StatusBadIndexRangeInvalid},
		{"array range past end", arr, "2:3", MustVariant([]int32{1, 2}), StatusBadIndexRangeNoData},
		{"scalar patch for a two element range", arr, "0:1", one, StatusBadIndexRangeDataMismatch},
		{"scalar patch of another type", arr, "0", MustVariant(int64(1)), StatusBadTypeMismatch},
		{"array patch length mismatch", arr, "0:1", MustVariant([]int32{1}), StatusBadIndexRangeDataMismatch},
		{"array patch of another type", arr, "0:1", MustVariant([]int64{1, 2}), StatusBadTypeMismatch},
		{"matrix range past end", mat, "0:2,0", MustVariant([][]int32{{1}, {2}, {3}}), StatusBadIndexRangeNoData},
		{"matrix patch of another type", mat, "0,0:1", MustVariant([][]float64{{1, 2}}), StatusBadTypeMismatch},
		{"matrix patch too small", mat, "0,0:1", MustVariant([][]int32{{1}}), StatusBadIndexRangeDataMismatch},
		{"matrix with one dimension", mat, "0", one, StatusBadIndexRangeInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, sc := MergeVariantWrite(tt.current, tt.rng, tt.newVal)
			require.Equal(t, tt.want, sc)
			require.Nil(t, out)
		})
	}

	// The inputs are never modified by a rejected or accepted merge.
	require.Equal(t, []int32{10, 20, 30}, arr.Value())
	require.Equal(t, []byte("abc"), bs.Value())
	require.Equal(t, [][]int32{{1, 2, 3}, {4, 5, 6}}, mat.Value())
}

func TestMergeVariantWrite_Success(t *testing.T) {
	cur := MustVariant([]byte("abcdef"))
	out, sc := MergeVariantWrite(cur, "1:2", MustVariant([]byte("XY")))
	require.Equal(t, StatusOK, sc)
	require.Equal(t, []byte("aXYdef"), out.Value())
	require.Equal(t, []byte("abcdef"), cur.Value(), "current value must not be aliased")

	arr := MustVariant([]int32{10, 20, 30})
	out, sc = MergeVariantWrite(arr, "2", MustVariant(int32(99)))
	require.Equal(t, StatusOK, sc)
	require.Equal(t, []int32{10, 20, 99}, out.Value())
	require.Equal(t, []int32{10, 20, 30}, arr.Value())

	// A scalar patch fills a single matrix cell.
	mat := MustVariant([][]int32{{1, 2, 3}, {4, 5, 6}})
	out, sc = MergeVariantWrite(mat, "1,2", MustVariant(int32(60)))
	require.Equal(t, StatusOK, sc)
	require.Equal(t, [][]int32{{1, 2, 3}, {4, 5, 60}}, out.Value())
}

func TestApplyTimestampsToReturn_Edges(t *testing.T) {
	require.Equal(t, StatusOK, ApplyTimestampsToReturn(nil, TimestampsToReturnBoth))

	src := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	mk := func() *DataValue {
		return &DataValue{
			EncodingMask:      DataValueValue | DataValueSourceTimestamp | DataValueSourcePicoseconds,
			Value:             MustVariant(int32(1)),
			SourceTimestamp:   src,
			SourcePicoseconds: 5,
		}
	}

	dv := mk()
	require.Equal(t, StatusBadTimestampsToReturnInvalid, ApplyTimestampsToReturn(dv, TimestampsToReturnInvalid))
	require.Equal(t, StatusBadTimestampsToReturnInvalid, ApplyTimestampsToReturn(dv, TimestampsToReturn(99)))
	assert.Equal(t, mk(), dv, "an invalid request must leave the value untouched")

	// Server: the source timestamp is dropped and a missing server timestamp is filled in.
	dv = mk()
	before := time.Now().UTC()
	require.Equal(t, StatusOK, ApplyTimestampsToReturn(dv, TimestampsToReturnServer))
	assert.True(t, dv.SourceTimestamp.IsZero())
	assert.Zero(t, dv.SourcePicoseconds)
	assert.Equal(t, byte(DataValueValue|DataValueServerTimestamp), dv.EncodingMask)
	assert.False(t, dv.ServerTimestamp.Before(before))

	// Both: source is kept, server is filled in.
	dv = mk()
	require.Equal(t, StatusOK, ApplyTimestampsToReturn(dv, TimestampsToReturnBoth))
	assert.Equal(t, src, dv.SourceTimestamp)
	assert.False(t, dv.ServerTimestamp.IsZero())
	assert.NotZero(t, dv.EncodingMask&DataValueServerTimestamp)
	assert.NotZero(t, dv.EncodingMask&DataValueSourceTimestamp)

	// Source: a value without a source timestamp does not grow one.
	dv = &DataValue{EncodingMask: DataValueValue | DataValueServerTimestamp, Value: MustVariant(int32(1)), ServerTimestamp: src}
	require.Equal(t, StatusOK, ApplyTimestampsToReturn(dv, TimestampsToReturnSource))
	assert.Equal(t, byte(DataValueValue), dv.EncodingMask)
	assert.True(t, dv.ServerTimestamp.IsZero())
	assert.True(t, dv.SourceTimestamp.IsZero())
}
