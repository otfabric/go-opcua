// SPDX-License-Identifier: MIT

package jsonmsg

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/pubsub/message"
)

// TestUintValueBoundaries: an unsigned integer is taken as written, or
// with a fraction or exponent if its value is integral, when it fits the
// limit; a number of 2^64 or more is refused before it is converted.
func TestUintValueBoundaries(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		in   string
		max  uint64
		want uint64
		ok   bool
	}{
		{"0", math.MaxUint64, 0, true},
		{"1", math.MaxUint64, 1, true},
		{`"7"`, math.MaxUint64, 7, true},
		{"1.0", math.MaxUint64, 1, true},
		{"1e3", math.MaxUint64, 1000, true},
		{"18446744073709551614", math.MaxUint64, math.MaxUint64 - 1, true},
		{"18446744073709551615", math.MaxUint64, math.MaxUint64, true},
		{`"18446744073709551615"`, math.MaxUint64, math.MaxUint64, true},
		// The largest float64 below 2^64.
		{"18446744073709549568.0", math.MaxUint64, 18446744073709549568, true},
		{"1.8446744073709549568e19", math.MaxUint64, 18446744073709549568, true},
		// 2^64 and above, also where float64 rounds up to 2^64.
		{"18446744073709551616", math.MaxUint64, 0, false},
		{"18446744073709551616.0", math.MaxUint64, 0, false},
		{"18446744073709551615.0", math.MaxUint64, 0, false},
		{"1.8446744073709551616e19", math.MaxUint64, 0, false},
		{"1.8446744073709552e19", math.MaxUint64, 0, false},
		{`"18446744073709551616"`, math.MaxUint64, 0, false},
		{"3.6893488147419103e19", math.MaxUint64, 0, false},
		{"1e300", math.MaxUint64, 0, false},
		{"1e400", math.MaxUint64, 0, false},
		// Smaller limits.
		{"4294967295", math.MaxUint32, math.MaxUint32, true},
		{"4294967295.0", math.MaxUint32, math.MaxUint32, true},
		{"4294967296", math.MaxUint32, 0, false},
		{"4294967296.0", math.MaxUint32, 0, false},
		{"65535", math.MaxUint16, math.MaxUint16, true},
		{"65536", math.MaxUint16, 0, false},
		{"6.5536e4", math.MaxUint16, 0, false},
		// Not unsigned integers.
		{"-1", math.MaxUint64, 0, false},
		{"-0.5", math.MaxUint64, 0, false},
		{"1.5", math.MaxUint64, 0, false},
		{"x", math.MaxUint64, 0, false},
		{`""`, math.MaxUint64, 0, false},
	} {
		got, err := uintValue([]byte(tt.in), "N", tt.max)
		if !tt.ok {
			require.ErrorIs(t, err, ErrDecode, "%s (max %d)", tt.in, tt.max)
			continue
		}
		require.NoError(t, err, "%s (max %d)", tt.in, tt.max)
		require.Equal(t, tt.want, got, "%s (max %d)", tt.in, tt.max)
	}

	// A numeric PublisherId of 2^64 is refused in a message.
	_, err := Decode([]byte(`{"MessageType":"ua-data","PublisherId":18446744073709551616,"Messages":[]}`), nil)
	require.ErrorIs(t, err, ErrDecode)
	_, err = Decode([]byte(`{"MessageType":"ua-data","PublisherId":1.8446744073709551616e19,"Messages":[]}`), nil)
	require.ErrorIs(t, err, ErrDecode)
	nm, err := Decode([]byte(`{"MessageType":"ua-data","PublisherId":18446744073709551615,"Messages":[]}`), nil)
	require.NoError(t, err)
	require.Equal(t, message.NewPublisherID(message.PublisherIDUInt64, math.MaxUint64), nm.PublisherID)
}
