// SPDX-License-Identifier: MIT

package mdns

import (
	"errors"
	"net"
	"net/netip"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The tests in this file replace the operating system calls of conn_udp.go
// (netInterfaces, interfaceAddrs, listenMulticastUDP), so they must not run
// in parallel with each other.

// fakeOS is a scripted network configuration.
type fakeOS struct {
	t *testing.T

	mu         sync.Mutex
	ifaces     []net.Interface
	ifacesErr  error
	addrs      map[string][]net.Addr
	addrsErr   map[string]error
	addrsCalls int
	listenErr  map[string]error // by "<ifname>/<network>"
	listens    []listenCall
}

type listenCall struct {
	network, ifName string
	group           netip.AddrPort
}

func ipnet(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	ip, n, err := net.ParseCIDR(cidr)
	require.NoError(t, err)
	n.IP = ip
	return n
}

// install replaces the OS calls with f until the test ends.
func (f *fakeOS) install() {
	oldIfaces, oldAddrs, oldListen := netInterfaces, interfaceAddrs, listenMulticastUDP
	f.t.Cleanup(func() { netInterfaces, interfaceAddrs, listenMulticastUDP = oldIfaces, oldAddrs, oldListen })

	netInterfaces = func() ([]net.Interface, error) { return f.ifaces, f.ifacesErr }
	interfaceAddrs = func(ifi *net.Interface) ([]net.Addr, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.addrsCalls++
		return f.addrs[ifi.Name], f.addrsErr[ifi.Name]
	}
	listenMulticastUDP = func(network string, ifi *net.Interface, gaddr *net.UDPAddr) (*net.UDPConn, error) {
		group, ok := netip.AddrFromSlice(gaddr.IP)
		require.True(f.t, ok)
		f.mu.Lock()
		f.listens = append(f.listens, listenCall{network, ifi.Name, netip.AddrPortFrom(group.WithZone(gaddr.Zone), uint16(gaddr.Port))})
		err := f.listenErr[ifi.Name+"/"+network]
		f.mu.Unlock()
		if err != nil {
			return nil, err
		}
		// A real socket, so that everything after the listen call (socket
		// options, Close) runs for real; where it is bound does not matter.
		return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	}
}

func (f *fakeOS) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.addrsCalls
}

func closeAll(t *testing.T, conns []PacketConn) {
	t.Helper()
	for _, c := range conns {
		require.NoError(t, c.Close())
	}
}

const upMulticast = net.FlagUp | net.FlagMulticast

func TestListen_SocketPerInterfaceAndFamily(t *testing.T) {
	f := &fakeOS{t: t,
		addrs: map[string][]net.Addr{
			"eth0":   {ipnet(t, "192.168.1.10/24"), ipnet(t, "fe80::1/64")},
			"wlan0":  {ipnet(t, "10.0.0.7/8")},
			"v6only": {ipnet(t, "2001:db8::1/64")},
			"broken": {ipnet(t, "172.16.0.1/12")},
		},
		listenErr: map[string]error{"broken/udp4": errors.New("join refused")},
	}
	f.install()

	conns, errs, err := Listen(ListenOptions{Interfaces: []net.Interface{
		{Index: 2, Name: "eth0", Flags: upMulticast},
		{Index: 3, Name: "wlan0", Flags: upMulticast},
		{Index: 4, Name: "v6only", Flags: upMulticast},
		{Index: 5, Name: "down0", Flags: net.FlagMulticast},
		{Index: 6, Name: "nomcast0", Flags: net.FlagUp},
		{Index: 7, Name: "broken", Flags: upMulticast},
	}})
	require.NoError(t, err)
	defer closeAll(t, conns)

	// eth0 has both families, wlan0 and v6only one each; broken failed.
	require.Equal(t, []listenCall{
		{"udp4", "eth0", netip.MustParseAddrPort("224.0.0.251:5353")},
		{"udp6", "eth0", netip.MustParseAddrPort("[ff02::fb%eth0]:5353")},
		{"udp4", "wlan0", netip.MustParseAddrPort("224.0.0.251:5353")},
		{"udp6", "v6only", netip.MustParseAddrPort("[ff02::fb%v6only]:5353")},
		{"udp4", "broken", netip.MustParseAddrPort("224.0.0.251:5353")},
	}, f.listens)
	require.Len(t, conns, 4)

	groups := make([]string, 0, len(conns))
	for _, c := range conns {
		u := c.(*udpConn)
		require.Equal(t, u.group.Addr().Is6(), u.v6)
		groups = append(groups, u.ifi.Name+" "+u.group.String())
	}
	require.Equal(t, []string{
		"eth0 224.0.0.251:5353",
		"eth0 [ff02::fb%eth0]:5353",
		"wlan0 224.0.0.251:5353",
		"v6only [ff02::fb%v6only]:5353",
	}, groups)

	require.Len(t, errs, 3)
	require.ErrorContains(t, errs[0], "interface down0 is down or not multicast capable")
	require.ErrorContains(t, errs[1], "interface nomcast0 is down or not multicast capable")
	require.ErrorContains(t, errs[2], "mdns: listen on broken (udp4): join refused")
}

func TestListen_DisableFamilies(t *testing.T) {
	f := &fakeOS{t: t, addrs: map[string][]net.Addr{"eth0": {ipnet(t, "192.168.1.10/24"), ipnet(t, "fe80::1/64")}}}
	f.install()
	eth0 := []net.Interface{{Index: 2, Name: "eth0", Flags: upMulticast}}

	conns, errs, err := Listen(ListenOptions{Interfaces: eth0, DisableIPv6: true})
	require.NoError(t, err)
	require.Empty(t, errs)
	require.Len(t, conns, 1)
	require.False(t, conns[0].(*udpConn).v6)
	closeAll(t, conns)

	conns, _, err = Listen(ListenOptions{Interfaces: eth0, DisableIPv4: true})
	require.NoError(t, err)
	require.Len(t, conns, 1)
	require.True(t, conns[0].(*udpConn).v6)
	closeAll(t, conns)

	conns, errs, err = Listen(ListenOptions{Interfaces: eth0, DisableIPv4: true, DisableIPv6: true})
	require.ErrorContains(t, err, "no usable multicast interface")
	require.Nil(t, conns)
	require.Empty(t, errs)
}

func TestListen_AllSocketsFail(t *testing.T) {
	join := errors.New("no multicast route")
	f := &fakeOS{t: t,
		addrs:     map[string][]net.Addr{"eth0": {ipnet(t, "192.168.1.10/24")}},
		listenErr: map[string]error{"eth0/udp4": join},
	}
	f.install()
	conns, errs, err := Listen(ListenOptions{Interfaces: []net.Interface{{Index: 2, Name: "eth0", Flags: upMulticast}}})
	require.ErrorIs(t, err, join, "the reasons are joined into the error")
	require.Nil(t, conns)
	require.Len(t, errs, 1)
	require.ErrorIs(t, errs[0], join)
}

func TestListen_DefaultInterfaces(t *testing.T) {
	f := &fakeOS{t: t,
		ifaces: []net.Interface{
			{Index: 1, Name: "lo", Flags: upMulticast | net.FlagLoopback},
			{Index: 2, Name: "eth0", Flags: upMulticast},
			{Index: 3, Name: "tun0", Flags: upMulticast | net.FlagPointToPoint},
			{Index: 4, Name: "eth1", Flags: net.FlagMulticast}, // down
			{Index: 5, Name: "eth2", Flags: upMulticast},
		},
		addrs: map[string][]net.Addr{
			"lo": {ipnet(t, "127.0.0.1/8")}, "tun0": {ipnet(t, "10.8.0.2/32")},
			"eth0": {ipnet(t, "192.168.1.10/24")}, "eth2": {ipnet(t, "192.168.2.10/24")},
		},
	}
	f.install()

	ifaces, err := DefaultInterfaces()
	require.NoError(t, err)
	names := make([]string, 0, len(ifaces))
	for _, ifi := range ifaces {
		names = append(names, ifi.Name)
	}
	require.Equal(t, []string{"eth0", "eth2"}, names)

	conns, errs, err := Listen(ListenOptions{})
	require.NoError(t, err)
	require.Empty(t, errs)
	defer closeAll(t, conns)
	require.Len(t, f.listens, 2)
	require.Equal(t, "eth0", f.listens[0].ifName)
	require.Equal(t, "eth2", f.listens[1].ifName)

	// Without any usable interface Listen fails.
	f.ifaces = f.ifaces[:1]
	_, _, err = Listen(ListenOptions{})
	require.ErrorContains(t, err, "no usable multicast interface")

	// An error listing the interfaces is returned.
	f.ifacesErr = errors.New("netlink unavailable")
	_, err = DefaultInterfaces()
	require.ErrorIs(t, err, f.ifacesErr)
	_, _, err = Listen(ListenOptions{})
	require.ErrorIs(t, err, f.ifacesErr)
	require.ErrorContains(t, err, "mdns: list interfaces")
}

func TestInterfacePrefixes(t *testing.T) {
	f := &fakeOS{t: t,
		addrs: map[string][]net.Addr{"eth0": {
			&net.IPAddr{IP: net.ParseIP("192.168.9.9")},                      // not a network: skipped
			&net.IPNet{IP: net.IP{1, 2, 3, 4, 5}, Mask: net.CIDRMask(8, 32)}, // no valid IP: skipped
			ipnet(t, "192.168.1.10/24"),
			&net.IPNet{IP: net.ParseIP("10.1.2.3"), Mask: net.CIDRMask(16, 32)}, // 16-byte form of an IPv4 address
			ipnet(t, "fe80::1/64"),
		}},
		addrsErr: map[string]error{"gone0": errors.New("no such interface")},
	}
	f.install()

	require.Equal(t, []netip.Prefix{
		netip.MustParsePrefix("192.168.1.10/24"),
		netip.MustParsePrefix("10.1.2.3/16"),
		netip.MustParsePrefix("fe80::1/64"),
	}, interfacePrefixes(&net.Interface{Name: "eth0"}))

	got := interfacePrefixes(&net.Interface{Name: "gone0"})
	require.NotNil(t, got, "an error yields an empty, cacheable result")
	require.Empty(t, got)
}

func TestUDPConn_PrefixCache(t *testing.T) {
	f := &fakeOS{t: t, addrs: map[string][]net.Addr{"eth0": {ipnet(t, "192.168.1.10/24"), ipnet(t, "fe80::1/64")}}}
	f.install()
	u := &udpConn{ifi: net.Interface{Name: "eth0"}}

	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.168.1.10"), netip.MustParseAddr("fe80::1")}, u.Addrs())
	require.Equal(t, 1, f.calls())
	u.Addrs()
	u.currentPrefixes()
	require.Equal(t, 1, f.calls(), "the prefixes are cached")

	// Addresses change (DHCP); after a few seconds they are read again.
	f.mu.Lock()
	f.addrs["eth0"] = []net.Addr{ipnet(t, "192.168.1.11/24")}
	f.mu.Unlock()
	u.mu.Lock()
	u.fetched = time.Now().Add(-6 * time.Second)
	u.mu.Unlock()
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.168.1.11")}, u.Addrs())
	require.Equal(t, 2, f.calls())

	// An interface whose addresses cannot be read has none, and the empty
	// result is cached like any other.
	g := &udpConn{ifi: net.Interface{Name: "gone0"}}
	f.addrsErr = map[string]error{"gone0": errors.New("gone")}
	require.Empty(t, g.Addrs())
	require.Empty(t, g.Addrs())
	require.Equal(t, 3, f.calls())
}

// loopbackConn returns a udpConn on a unicast loopback socket whose interface
// has the given prefixes.
func loopbackConn(t *testing.T, ip string, prefixes ...string) *udpConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		t.Skipf("cannot bind %s: %v", ip, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	u := &udpConn{c: c, ifi: net.Interface{Name: "lo-test"}, prefixes: []netip.Prefix{}, fetched: time.Now().Add(time.Hour)}
	for _, p := range prefixes {
		u.prefixes = append(u.prefixes, netip.MustParsePrefix(p))
	}
	return u
}

func localAddrPort(u *udpConn) netip.AddrPort {
	return u.c.LocalAddr().(*net.UDPAddr).AddrPort()
}

func TestUDPConn_ReadWrite(t *testing.T) {
	rx := loopbackConn(t, "127.0.0.1", "127.0.0.0/8")
	tx := loopbackConn(t, "127.0.0.1", "127.0.0.0/8")
	// WriteMulticast sends to the group of the conn; here the group of tx
	// is rx and the other way round.
	tx.group = localAddrPort(rx)
	rx.group = localAddrPort(tx)

	buf := make([]byte, MaxPacketSize)
	require.NoError(t, tx.WriteMulticast([]byte("to the group")))
	n, src, err := rx.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, "to the group", string(buf[:n]))
	require.Equal(t, localAddrPort(tx), src)

	require.NoError(t, rx.WriteTo([]byte("unicast reply"), src))
	n, from, err := tx.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, "unicast reply", string(buf[:n]))
	require.Equal(t, localAddrPort(rx), from)

	// After Close reads and writes fail.
	require.NoError(t, rx.Close())
	_, _, err = rx.ReadFrom(buf)
	require.ErrorIs(t, err, net.ErrClosed)
	require.ErrorIs(t, rx.WriteTo([]byte("x"), src), net.ErrClosed)
	require.ErrorIs(t, rx.WriteMulticast([]byte("x")), net.ErrClosed)
	require.Error(t, rx.Close(), "a second Close fails")

	// Writing to a closed peer is not an error for UDP, but a datagram that
	// cannot be sent at all is.
	require.Error(t, tx.WriteTo([]byte("x"), netip.AddrPort{}))
}

// TestUDPConn_ReadFromDropsOffLinkSources: ReadFrom skips datagrams whose
// source is not on the link of the interface (RFC 6762 §11) and returns the
// next acceptable one.
func TestUDPConn_ReadFromDropsOffLinkSources(t *testing.T) {
	rx := loopbackConn(t, "127.0.0.1", "127.0.0.1/32")
	onLinkTx := loopbackConn(t, "127.0.0.1")
	// 127.0.0.2 is a loopback address on Linux; elsewhere it may not be
	// configured, and the test is skipped.
	offLinkTx := loopbackConn(t, "127.0.0.2")

	dst := localAddrPort(rx)
	require.NoError(t, offLinkTx.WriteTo([]byte("off link"), dst))
	require.NoError(t, onLinkTx.WriteTo([]byte("on link"), dst))

	buf := make([]byte, MaxPacketSize)
	n, src, err := rx.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, "on link", string(buf[:n]))
	require.Equal(t, localAddrPort(onLinkTx), src)
}

// TestListenUDP_Real opens a real multicast socket on an interface of this
// host. Where the host has no interface that allows it, it is skipped.
func TestListenUDP_Real(t *testing.T) {
	all, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot list interfaces: %v", err)
	}
	// Prefer the loopback interface (nothing leaves the host), then any.
	sort.SliceStable(all, func(i, j int) bool {
		return all[i].Flags&net.FlagLoopback != 0 && all[j].Flags&net.FlagLoopback == 0
	})
	for _, ifi := range all {
		if !usable(ifi) {
			continue
		}
		for _, p := range interfacePrefixes(&ifi) {
			if !p.Addr().Is4() {
				continue
			}
			u, err := listenUDP(ifi, false)
			if err != nil {
				t.Logf("%s: %v", ifi.Name, err)
				continue
			}
			require.Equal(t, netip.MustParseAddrPort("224.0.0.251:5353"), u.group)
			require.Equal(t, ifi.Name, u.ifi.Name)
			require.Contains(t, u.Addrs(), p.Addr())
			require.NoError(t, u.Close())
			_, _, err = u.ReadFrom(make([]byte, 16))
			require.ErrorIs(t, err, net.ErrClosed)
			return
		}
	}
	t.Skip("no interface of this host allows joining the mDNS group")
}
