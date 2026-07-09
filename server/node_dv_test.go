// SPDX-License-Identifier: MIT

package server

import (
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

func TestNewAttrValue(t *testing.T) {
	dv := DataValueFromValue(int32(7))
	av := NewAttrValue(dv)
	require.NotNil(t, av)
	assert.Same(t, dv, av.Value)
	assert.True(t, av.SourceTimestamp.IsZero())
	av.SourceTimestamp = time.Now()
	assert.False(t, av.SourceTimestamp.IsZero())
}
