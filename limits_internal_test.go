// SPDX-License-Identifier: MIT

package opcua

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
)

// TestNodeClassOf: a NodeClass from the server that does not fit is refused,
// not truncated into another node class.
func TestNodeClassOf(t *testing.T) {
	t.Parallel()
	got, err := nodeClassOf(ua.MustVariant(int32(ua.NodeClassVariable)))
	require.NoError(t, err)
	require.Equal(t, ua.NodeClassVariable, got)

	for _, v := range []any{int32(-1), int64(math.MaxUint32 + 2), int64(-1 << 40)} {
		_, err := nodeClassOf(ua.MustVariant(v))
		require.Error(t, err, "%v", v)
	}
}

// TestClampMillis: the secure channel lifetime is a UInt32 of milliseconds
// (Part 4 §5.5.2.2); durations outside it are clamped, not wrapped.
func TestClampMillis(t *testing.T) {
	t.Parallel()
	require.EqualValues(t, 10, clampMillis(10*time.Millisecond))
	require.EqualValues(t, 0, clampMillis(-time.Second))
	require.EqualValues(t, uint32(math.MaxUint32), clampMillis(50*24*time.Hour))
	require.EqualValues(t, uint32(math.MaxUint32), clampMillis(math.MaxUint32*time.Millisecond))
}
