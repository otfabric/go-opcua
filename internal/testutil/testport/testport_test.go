// SPDX-License-Identifier: MIT

package testport

import (
	"net"
	"os"
	"strconv"
	"syscall"
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
	require.False(t, freeUDP(c.LocalAddr().(*net.UDPAddr).Port))
}

func TestTCP(t *testing.T) {
	p := TCP(t)
	require.GreaterOrEqual(t, p, lowPort)
	require.Less(t, p, highPort)
	l, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	require.False(t, freeTCP(p))
	require.NotEqual(t, p, UDP(t), "no number twice")
}

func TestFreeOnIPv6Wildcard(t *testing.T) {
	// A port held only on the IPv6 wildcard is not free: a dual-stack bind
	// of it fails.
	c, err := net.ListenPacket("udp6", "[::]:0")
	if err != nil {
		t.Skipf("no IPv6: %v", err)
	}
	defer func() { _ = c.Close() }()
	require.False(t, freeUDP(c.LocalAddr().(*net.UDPAddr).Port))

	l, err := net.Listen("tcp6", "[::]:0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	require.False(t, freeTCP(l.Addr().(*net.TCPAddr).Port))
}

func TestBindUDP(t *testing.T) {
	// The first port is taken between hand-out and bind: BindUDP moves on.
	var conns []net.PacketConn
	t.Cleanup(func() {
		for _, c := range conns {
			_ = c.Close()
		}
	})
	attempts := 0
	p := BindUDP(t, func(port int) error {
		attempts++
		if attempts == 1 {
			return &net.OpError{Op: "listen", Net: "udp", Err: os.NewSyscallError("bind", syscall.EADDRINUSE)}
		}
		c, err := net.ListenPacket("udp", net.JoinHostPort("", strconv.Itoa(port)))
		if err != nil {
			return err
		}
		conns = append(conns, c)
		return nil
	})
	require.Equal(t, 2, attempts)
	require.Equal(t, p, conns[0].LocalAddr().(*net.UDPAddr).Port)
}

func TestBindTCP(t *testing.T) {
	var l net.Listener
	p := BindTCP(t, func(port int) error {
		var err error
		l, err = net.Listen("tcp", net.JoinHostPort("", strconv.Itoa(port)))
		return err
	})
	defer func() { _ = l.Close() }()
	require.Equal(t, p, l.Addr().(*net.TCPAddr).Port)
}

func TestEphemeral(t *testing.T) {
	lo, hi := ephemeralLow, ephemeralHigh
	t.Cleanup(func() { ephemeralLow, ephemeralHigh = lo, hi })
	ephemeralLow, ephemeralHigh = 25000, 40000
	require.True(t, ephemeral(25000))
	require.False(t, ephemeral(24999))
	ephemeralLow, ephemeralHigh = 1024, 65535 // covers the range: nothing excluded
	require.False(t, ephemeral(25000))
}
