// SPDX-License-Identifier: MIT

package mdns

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestMemNetwork_FaultAndInject covers the fault hooks of the in-memory link:
// a function that loses, duplicates and alters datagrams, and the injection
// of datagrams from a station that is not on the link.
func TestMemNetwork_FaultAndInject(t *testing.T) {
	link := NewMemNetwork()
	a, b := link.Conn(), link.Conn()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	read := func(c PacketConn) (string, netip.AddrPort) {
		buf := make([]byte, MaxPacketSize)
		n, src, err := c.ReadFrom(buf)
		require.NoError(t, err)
		return string(buf[:n]), src
	}
	pending := func(c PacketConn) int { return len(c.(*memConn).rx) }
	addrA := netip.AddrPortFrom(a.Addrs()[0], Port)

	// The function sees the sender and a copy of the datagram; what it
	// returns is delivered.
	var seen []netip.AddrPort
	link.SetFault(func(src netip.AddrPort, d []byte) [][]byte {
		seen = append(seen, src)
		switch string(d) {
		case "lose":
			return nil
		case "twice":
			return [][]byte{d, d}
		}
		d[0] = 'X'
		return [][]byte{d}
	})
	sent := []byte("alter")
	require.NoError(t, a.WriteMulticast(sent))
	require.Equal(t, "alter", string(sent), "the datagram of the sender is not touched")
	got, src := read(b)
	require.Equal(t, "Xlter", got)
	require.Equal(t, addrA, src)

	require.NoError(t, a.WriteMulticast([]byte("lose")))
	require.Zero(t, pending(b))
	require.NoError(t, a.WriteTo([]byte("twice"), netip.AddrPortFrom(b.Addrs()[0], Port)))
	require.Equal(t, 2, pending(b))
	got, _ = read(b)
	require.Equal(t, "twice", got)
	got, _ = read(b)
	require.Equal(t, "twice", got)
	require.Equal(t, []netip.AddrPort{addrA, addrA, addrA}, seen)

	// An injected datagram reaches every station but the one it claims to
	// come from, and bypasses the function.
	stranger := netip.MustParseAddrPort("10.255.200.1:5353")
	link.Inject(stranger, []byte("lose"))
	for _, c := range []PacketConn{a, b} {
		got, src = read(c)
		require.Equal(t, "lose", got)
		require.Equal(t, stranger, src)
	}
	link.Inject(addrA, []byte("echo"))
	require.Zero(t, pending(a))
	got, _ = read(b)
	require.Equal(t, "echo", got)
	require.Len(t, seen, 3)

	// Without the function the link delivers as before.
	link.SetFault(nil)
	require.NoError(t, a.WriteMulticast([]byte("lose")))
	got, _ = read(b)
	require.Equal(t, "lose", got)
}
