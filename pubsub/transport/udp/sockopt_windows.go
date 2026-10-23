// SPDX-License-Identifier: MIT

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

// setReuse sets SO_REUSEADDR, which on Windows lets several sockets share a
// multicast port. There is no SO_REUSEPORT.
func setReuse(fd uintptr, _ bool) error {
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
}

func setBroadcast(fd uintptr) error {
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
}

func joinGroup(fd uintptr, v6 bool, group netip.Addr, ifi *net.Interface) error {
	h := syscall.Handle(fd)
	if v6 {
		mreq := &syscall.IPv6Mreq{Multiaddr: group.As16()}
		if ifi != nil {
			mreq.Interface = uint32(ifi.Index)
		}
		return syscall.SetsockoptIPv6Mreq(h, syscall.IPPROTO_IPV6, syscall.IPV6_JOIN_GROUP, mreq)
	}
	mreq := &syscall.IPMreq{Multiaddr: group.As4(), Interface: interfaceIPv4(ifi)}
	return syscall.SetsockoptIPMreq(h, syscall.IPPROTO_IP, syscall.IP_ADD_MEMBERSHIP, mreq)
}

func setMulticastInterface(fd uintptr, v6 bool, ifi *net.Interface) error {
	h := syscall.Handle(fd)
	if v6 {
		return syscall.SetsockoptInt(h, syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_IF, ifi.Index)
	}
	return syscall.SetsockoptInet4Addr(h, syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, interfaceIPv4(ifi))
}

func setMulticastTTL(fd uintptr, v6 bool, ttl int) error {
	h := syscall.Handle(fd)
	if v6 {
		return syscall.SetsockoptInt(h, syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_HOPS, ttl)
	}
	return syscall.SetsockoptInt(h, syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL, ttl)
}

func setMulticastLoop(fd uintptr, v6 bool, on bool) error {
	h := syscall.Handle(fd)
	if v6 {
		return syscall.SetsockoptInt(h, syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_LOOP, boolInt(on))
	}
	return syscall.SetsockoptInt(h, syscall.IPPROTO_IP, syscall.IP_MULTICAST_LOOP, boolInt(on))
}

const (
	soSndBuf = syscall.SO_SNDBUF
	soRcvBuf = syscall.SO_RCVBUF
)

func growBuffer(fd uintptr, opt, n int) error {
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, opt, n)
}
