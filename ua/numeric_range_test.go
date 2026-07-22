// SPDX-License-Identifier: MIT

package ua

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParseNumericRange(t *testing.T) {
	r, err := ParseNumericRange("0:1")
	require.NoError(t, err)
	require.Equal(t, NumericRange{0, 1}, r)
	require.Equal(t, 2, r.Len())

	r, err = ParseNumericRange("3")
	require.NoError(t, err)
	require.Equal(t, NumericRange{3, 3}, r)

	_, err = ParseNumericRange("1:0")
	require.Equal(t, StatusBadIndexRangeInvalid, err)

	_, err = ParseNumericRange("0:1,0:1")
	require.Equal(t, StatusBadIndexRangeInvalid, err)
}

func TestSliceVariantRead(t *testing.T) {
	v := MustVariant([]int32{0, 1, -1, 2147483647, -2147483648, -123456789})
	out, sc := SliceVariantRead(v, "0:1")
	require.Equal(t, StatusOK, sc)
	require.Equal(t, []int32{0, 1}, out.Value())

	_, sc = SliceVariantRead(v, "100:101")
	require.Equal(t, StatusBadIndexRangeNoData, sc)

	scalar := MustVariant(int32(42))
	_, sc = SliceVariantRead(scalar, "0")
	require.Equal(t, StatusBadIndexRangeInvalid, sc)
}

func TestMergeVariantWrite(t *testing.T) {
	cur := MustVariant([]int32{0, 1, 2, 3, 4})
	patch := MustVariant([]int32{90, 91})
	out, sc := MergeVariantWrite(cur, "1:2", patch)
	require.Equal(t, StatusOK, sc)
	require.Equal(t, []int32{0, 90, 91, 3, 4}, out.Value())

	_, sc = MergeVariantWrite(cur, "1:2", MustVariant([]int32{1}))
	require.Equal(t, StatusBadIndexRangeDataMismatch, sc)
}

func TestApplyTimestampsToReturn(t *testing.T) {
	src := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	dv := &DataValue{
		EncodingMask:    DataValueValue | DataValueSourceTimestamp | DataValueServerTimestamp,
		Value:           MustVariant(int32(1)),
		SourceTimestamp: src,
		ServerTimestamp: src.Add(time.Second),
	}
	require.Equal(t, StatusOK, ApplyTimestampsToReturn(dv, TimestampsToReturnNeither))
	require.Equal(t, byte(DataValueValue), dv.EncodingMask)
	require.True(t, dv.SourceTimestamp.IsZero())
	require.True(t, dv.ServerTimestamp.IsZero())
}

func TestParseNumericRangesMultiDim(t *testing.T) {
	ranges, err := ParseNumericRanges("0:1,0:1")
	require.NoError(t, err)
	require.Equal(t, []NumericRange{{0, 1}, {0, 1}}, ranges)

	_, err = ParseNumericRanges("0:1,")
	require.Equal(t, StatusBadIndexRangeInvalid, err)
}

func TestSliceVariantReadMatrix(t *testing.T) {
	mat := MustVariant([][]float64{{1.1, 2.2}, {3.3, 4.4}, {5.5, 6.6}})
	out, sc := SliceVariantRead(mat, "0,0")
	require.Equal(t, StatusOK, sc)
	got, ok := out.Value().([][]float64)
	require.True(t, ok)
	require.Equal(t, [][]float64{{1.1}}, got)

	out, sc = SliceVariantRead(mat, "0:1,0:1")
	require.Equal(t, StatusOK, sc)
	require.Equal(t, [][]float64{{1.1, 2.2}, {3.3, 4.4}}, out.Value())

	_, sc = SliceVariantRead(mat, "0:1")
	require.Equal(t, StatusBadIndexRangeInvalid, sc)

	_, sc = SliceVariantRead(mat, "10:11,0:1")
	require.Equal(t, StatusBadIndexRangeNoData, sc)
}

func TestMergeVariantWriteMatrix(t *testing.T) {
	cur := MustVariant([][]float64{{1.1, 2.2}, {3.3, 4.4}, {5.5, 6.6}})
	patch := MustVariant([][]float64{{9.1, 9.2}, {9.3, 9.4}})
	out, sc := MergeVariantWrite(cur, "0:1,0:1", patch)
	require.Equal(t, StatusOK, sc)
	got := out.Value().([][]float64)
	require.Equal(t, 9.1, got[0][0])
	require.Equal(t, 9.4, got[1][1])
	require.Equal(t, 5.5, got[2][0])

	_, sc = MergeVariantWrite(cur, "0:1,0:1", MustVariant([][]float64{{1.0}}))
	require.Equal(t, StatusBadIndexRangeDataMismatch, sc)
}

func TestSliceVariantReadByteString(t *testing.T) {
	v := MustVariant([]byte("opcua-compat"))
	out, sc := SliceVariantRead(v, "0:4")
	require.Equal(t, StatusOK, sc)
	require.Equal(t, []byte("opcua"), out.Value())
}
