// SPDX-License-Identifier: MIT

package server

import (
	"math"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDataValueFromValue(t *testing.T) {
	existing := &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int32(1))}
	assert.Same(t, existing, DataValueFromValue(existing))

	byVal := ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int32(2))}
	got := DataValueFromValue(byVal)
	require.NotNil(t, got)
	assert.Equal(t, int32(2), got.Value.Value())

	variant := *ua.MustVariant(int32(3))
	got = DataValueFromValue(variant)
	require.NotNil(t, got)
	assert.Equal(t, int32(3), got.Value.Value())
	assert.False(t, got.SourceTimestamp.IsZero())

	ptr := ua.MustVariant(int32(4))
	got = DataValueFromValue(ptr)
	require.NotNil(t, got)
	assert.Equal(t, int32(4), got.Value.Value())

	got = DataValueFromValue(99)
	require.NotNil(t, got)
	assert.Equal(t, int32(99), got.Value.Value())

	got = DataValueFromValue(float64(1.5))
	require.NotNil(t, got)
	assert.Equal(t, float64(1.5), got.Value.Value())
}

// TestDataValueFromValue_IntRange checks that a Go int outside the Int32
// range becomes an Int64 instead of being cut, the same in DataValueFromValue
// and variantOf.
func TestDataValueFromValue_IntRange(t *testing.T) {
	if math.MaxInt == math.MaxInt32 {
		t.Skip("int is 32 bits: every int fits an Int32")
	}
	// The inputs are int64 so that the file also builds where int is 32 bits.
	for _, tc := range []struct {
		in   int64
		want any
	}{
		{math.MaxInt32, int32(math.MaxInt32)},
		{math.MinInt32, int32(math.MinInt32)},
		{math.MaxInt32 + 1, int64(math.MaxInt32 + 1)},
		{math.MinInt32 - 1, int64(math.MinInt32 - 1)},
		{math.MaxInt64, int64(math.MaxInt64)},
	} {
		in := int(tc.in)
		assert.Equal(t, tc.want, DataValueFromValue(in).Value.Value(), "DataValueFromValue(%d)", in)
		assert.Equal(t, tc.want, variantOf(in).Value(), "variantOf(%d)", in)
	}
}

func TestNewAttrValue(t *testing.T) {
	dv := DataValueFromValue(int32(7))
	av := NewAttrValue(dv)
	require.NotNil(t, av)
	assert.Same(t, dv, av.Value)
	assert.True(t, av.SourceTimestamp.IsZero())
	av.SourceTimestamp = time.Now()
	assert.False(t, av.SourceTimestamp.IsZero())
}
