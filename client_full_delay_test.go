// SPDX-License-Identifier: MIT

package opcua

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The wait after Bad_TooManySessions doubles up to maxFullDelay.
func TestNextFullDelay(t *testing.T) {
	require.Equal(t, time.Second, nextFullDelay(0))
	require.Equal(t, 100*time.Millisecond, nextFullDelay(50*time.Millisecond))
	require.Equal(t, 28*time.Second, nextFullDelay(14*time.Second))
	require.Equal(t, maxFullDelay, nextFullDelay(maxFullDelay/2))
	require.Equal(t, maxFullDelay, nextFullDelay(time.Hour))
}
