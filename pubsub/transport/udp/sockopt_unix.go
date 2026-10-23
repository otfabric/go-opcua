// SPDX-License-Identifier: MIT

//go:build linux || darwin || dragonfly || freebsd || netbsd || openbsd

package udp

import (
	"net"
	"net/netip"
	"syscall"
)

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// setReuse lets several sockets bind the same address and port: needed for
// several subscribers of one multicast group on a host. SO_REUSEPORT is only
// set for multicast, where every socket gets every datagram; for unicast it
// would spread the datagrams over the sockets on Linux.
func setReuse(fd uintptr, port bool) error {
	if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return err
	}
	if port {
		return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1)
	}
	return nil
}

func setBroadcast(fd uintptr) error {
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
}

func joinGroup(fd uintptr, v6 bool, group netip.Addr, ifi *net.Interface) error {
	if v6 {
		mreq := &syscall.IPv6Mreq{Multiaddr: group.As16()}
		if ifi != nil {
			mreq.Interface = uint32(ifi.Index)
		}
		return syscall.SetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_JOIN_GROUP, mreq)
	}
	mreq := &syscall.IPMreq{Multiaddr: group.As4(), Interface: interfaceIPv4(ifi)}
	return syscall.SetsockoptIPMreq(int(fd), syscall.IPPROTO_IP, syscall.IP_ADD_MEMBERSHIP, mreq)
}

func setMulticastInterface(fd uintptr, v6 bool, ifi *net.Interface) error {
	if v6 {
		return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_IF, ifi.Index)
	}
	return syscall.SetsockoptInet4Addr(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, interfaceIPv4(ifi))
}

func setMulticastTTL(fd uintptr, v6 bool, ttl int) error {
	if v6 {
		return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_HOPS, ttl)
	}
	return setIPv4Option(int(fd), syscall.IP_MULTICAST_TTL, ttl)
}

func setMulticastLoop(fd uintptr, v6 bool, on bool) error {
	if v6 {
		return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_LOOP, boolInt(on))
	}
	return setIPv4Option(int(fd), syscall.IP_MULTICAST_LOOP, boolInt(on))
}

// growBuffer raises the socket buffer opt (SO_SNDBUF, SO_RCVBUF) to at least
// n bytes. On macOS the send buffer (9216 bytes by default) also limits the
// size of a datagram.
func growBuffer(fd uintptr, opt, n int) error {
	cur, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, opt)
	if err == nil && cur >= n {
		return nil
	}
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, opt, n)
}

const (
	soSndBuf = syscall.SO_SNDBUF
	soRcvBuf = syscall.SO_RCVBUF
)
