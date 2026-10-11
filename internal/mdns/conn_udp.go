// SPDX-License-Identifier: MIT

package mdns

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

var (
	groupV4 = netip.MustParseAddr("224.0.0.251")
	groupV6 = netip.MustParseAddr("ff02::fb")
)

// ListenOptions selects the sockets [Listen] opens.
type ListenOptions struct {
	// Interfaces restricts mDNS to these interfaces. Empty selects every
	// interface that is up, multicast capable and neither a loopback nor a
	// point-to-point interface.
	Interfaces []net.Interface
	// DisableIPv4 and DisableIPv6 turn one address family off.
	DisableIPv4, DisableIPv6 bool
}

// DefaultInterfaces returns the interfaces mDNS runs on when none are named.
func DefaultInterfaces() ([]net.Interface, error) {
	all, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []net.Interface
	for _, ifi := range all {
		if usable(ifi) && ifi.Flags&(net.FlagLoopback|net.FlagPointToPoint) == 0 {
			out = append(out, ifi)
		}
	}
	return out, nil
}

func usable(ifi net.Interface) bool {
	return ifi.Flags&net.FlagUp != 0 && ifi.Flags&net.FlagMulticast != 0
}

// Listen opens one multicast socket per interface and address family. An
// interface on which a socket cannot be opened is skipped; these errors are
// returned alongside the conns that did open. It is an error if no socket
// could be opened at all.
func Listen(opts ListenOptions) ([]PacketConn, []error, error) {
	ifaces := opts.Interfaces
	if len(ifaces) == 0 {
		var err error
		if ifaces, err = DefaultInterfaces(); err != nil {
			return nil, nil, fmt.Errorf("mdns: list interfaces: %w", err)
		}
	}
	var (
		conns []PacketConn
		errs  []error
	)
	open := func(ifi net.Interface, v6 bool) {
		c, err := listenUDP(ifi, v6)
		if err != nil {
			errs = append(errs, err)
			return
		}
		conns = append(conns, c)
	}
	for _, ifi := range ifaces {
		if !usable(ifi) {
			errs = append(errs, fmt.Errorf("mdns: interface %s is down or not multicast capable", ifi.Name))
			continue
		}
		has4, has6 := false, false
		for _, p := range interfacePrefixes(&ifi) {
			if p.Addr().Is4() {
				has4 = true
			} else {
				has6 = true
			}
		}
		if has4 && !opts.DisableIPv4 {
			open(ifi, false)
		}
		if has6 && !opts.DisableIPv6 {
			open(ifi, true)
		}
	}
	if len(conns) == 0 {
		return nil, errs, fmt.Errorf("mdns: no usable multicast interface: %w", errors.Join(errs...))
	}
	return conns, errs, nil
}

type udpConn struct {
	c     *net.UDPConn
	ifi   net.Interface
	v6    bool
	group netip.AddrPort

	mu       sync.Mutex
	prefixes []netip.Prefix
	fetched  time.Time
}

func listenUDP(ifi net.Interface, v6 bool) (*udpConn, error) {
	network, group := "udp4", groupV4
	if v6 {
		network, group = "udp6", groupV6.WithZone(ifi.Name)
	}
	// ListenMulticastUDP binds the wildcard address with SO_REUSEADDR (and
	// SO_REUSEPORT where it is needed), joins the group on the interface
	// and selects the interface for outgoing multicast.
	c, err := net.ListenMulticastUDP(network, &ifi, &net.UDPAddr{IP: group.AsSlice(), Port: Port, Zone: group.Zone()})
	if err != nil {
		return nil, fmt.Errorf("mdns: listen on %s (%s): %w", ifi.Name, network, err)
	}
	// Best effort: a hop limit of 255 (RFC 6762 §11) and multicast loopback,
	// without which two processes on one host cannot see each other.
	if raw, rerr := c.SyscallConn(); rerr == nil {
		_ = raw.Control(func(fd uintptr) { setMulticastOptions(fd, v6) })
	}
	return &udpConn{c: c, ifi: ifi, v6: v6, group: netip.AddrPortFrom(group, Port)}, nil
}

func (u *udpConn) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	for {
		n, src, err := u.c.ReadFromUDPAddrPort(b)
		if err != nil {
			return 0, netip.AddrPort{}, err
		}
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		if onLink(src.Addr(), u.v6, u.ifi.Name, u.currentPrefixes()) {
			return n, src, nil
		}
	}
}

// onLink implements the source-address check of RFC 6762 §11: a packet is
// only accepted if its source is on the link of the conn's interface. With
// one socket per interface it also keeps a datagram from being processed once
// per socket on systems that deliver it to all of them.
func onLink(src netip.Addr, v6 bool, ifName string, prefixes []netip.Prefix) bool {
	if src.Is4() == v6 {
		return false
	}
	if v6 {
		if z := src.Zone(); z != "" && z != ifName {
			return false
		}
		if src.IsLinkLocalUnicast() {
			return true
		}
		src = src.WithZone("")
	}
	for _, p := range prefixes {
		if p.Contains(src) {
			return true
		}
	}
	return false
}

// currentPrefixes returns the address prefixes of the interface. They are
// re-read every few seconds because addresses come and go (DHCP).
func (u *udpConn) currentPrefixes() []netip.Prefix {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.prefixes == nil || time.Since(u.fetched) > 5*time.Second {
		u.prefixes = interfacePrefixes(&u.ifi)
		u.fetched = time.Now()
	}
	return u.prefixes
}

func interfacePrefixes(ifi *net.Interface) []netip.Prefix {
	addrs, err := ifi.Addrs()
	if err != nil {
		return []netip.Prefix{}
	}
	out := make([]netip.Prefix, 0, len(addrs))
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		ones, _ := ipn.Mask.Size()
		if p := netip.PrefixFrom(ip.Unmap(), ones); p.IsValid() {
			out = append(out, p)
		}
	}
	return out
}

func (u *udpConn) WriteMulticast(b []byte) error {
	_, err := u.c.WriteToUDPAddrPort(b, u.group)
	return err
}

func (u *udpConn) WriteTo(b []byte, dst netip.AddrPort) error {
	_, err := u.c.WriteToUDPAddrPort(b, dst)
	return err
}

func (u *udpConn) Addrs() []netip.Addr {
	prefixes := u.currentPrefixes()
	out := make([]netip.Addr, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, p.Addr())
	}
	return out
}

func (u *udpConn) Close() error { return u.c.Close() }
