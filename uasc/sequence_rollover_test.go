// SPDX-License-Identifier: MIT

package uasc

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNextSequenceNumber_RolloversNearMaxUint32 verifies the Part 6 rollover
// window: sequence numbers wrap to 1 before MaxUint32.
func TestNextSequenceNumber_RolloversNearMaxUint32(t *testing.T) {
	ci := &channelInstance{sequenceNumber: math.MaxUint32 - 1023}
	got := ci.nextSequenceNumber()
	require.Equal(t, uint32(1), got, "must wrap when exceeding MaxUint32-1023")

	ci.sequenceNumber = math.MaxUint32 - 1024
	got = ci.nextSequenceNumber()
	require.Equal(t, uint32(math.MaxUint32-1023), got)

	ci.sequenceNumber = 0
	got = ci.nextSequenceNumber()
	require.Equal(t, uint32(1), got)
}
