// SPDX-License-Identifier: MIT

package testport

import (
	"net"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUDP(t *testing.T) {
	seen := map[int]bool{}
	for range 50 {
		p := UDP(t)
		require.GreaterOrEqual(t, p, lowPort)
		require.Less(t, p, highPort)
		require.False(t, seen[p], "port %d handed out twice", p)
		seen[p] = true
		c, err := net.ListenPacket("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
		require.NoError(t, err)
		require.NoError(t, c.Close())
	}

	// A bound port is not free.
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.False(t, free(c.LocalAddr().(*net.UDPAddr).Port))
}
