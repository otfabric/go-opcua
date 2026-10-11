// SPDX-License-Identifier: MIT

package mdns

import (
	"errors"
	"net"
	"net/netip"
	"sync"
)

// MemNetwork is an in-memory multicast link. Every datagram written to the
// group by one of its conns is delivered to all the others, which makes it a
// stand-in for a network segment in tests that must not depend on multicast
// being available on the machine.
type MemNetwork struct {
	mu    sync.Mutex
	conns map[*memConn]struct{}
	next  uint16
	drop  func(b []byte) bool
	fault func(src netip.AddrPort, b []byte) [][]byte
}

// NewMemNetwork returns an empty link.
func NewMemNetwork() *MemNetwork {
	return &MemNetwork{conns: map[*memConn]struct{}{}}
}

// SetFilter installs a function that is called for every datagram sent on the
// link; the datagram is dropped if it returns true. Nil removes the filter.
func (m *MemNetwork) SetFilter(drop func(b []byte) bool) {
	m.mu.Lock()
	m.drop = drop
	m.mu.Unlock()
}

// SetFault installs a function that is called for every datagram sent on the
// link, after the filter of [MemNetwork.SetFilter], with the address of the
// sender and a copy of the datagram. The datagrams it returns are delivered
// instead: none loses the datagram, several duplicate it, and a changed one
// corrupts it. Nil removes the function. fn is called with the link locked:
// it must not block and must not call methods of the link. A datagram can be
// delayed, and thereby reordered, by dropping it and handing it to
// [MemNetwork.Inject] later.
func (m *MemNetwork) SetFault(fn func(src netip.AddrPort, b []byte) [][]byte) {
	m.mu.Lock()
	m.fault = fn
	m.mu.Unlock()
}

// Inject delivers a datagram to every station on the link as if a station
// with the address src had sent it to the group. It bypasses the functions
// set with [MemNetwork.SetFilter] and [MemNetwork.SetFault], and it does not
// limit the size of the datagram: a station reads as much as fits its buffer.
func (m *MemNetwork) Inject(src netip.AddrPort, b []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for peer := range m.conns {
		if peer.addr == src {
			continue
		}
		peer.enqueue(memPacket{data: append([]byte(nil), b...), src: src})
	}
}

// Conn attaches a new station to the link. Its address is 10.255.0.x with
// source port 5353, like a real mDNS responder.
func (m *MemNetwork) Conn() PacketConn {
	return m.ConnWithPort(Port)
}

// ConnWithPort attaches a station that sends from the given source port. A
// port other than 5353 makes it a legacy unicast querier (RFC 6762 §6.7).
func (m *MemNetwork) ConnWithPort(port uint16) PacketConn {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.next++
	c := &memConn{
		net:  m,
		addr: netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 255, byte(m.next >> 8), byte(m.next)}), port),
		rx:   make(chan memPacket, 256),
		done: make(chan struct{}),
	}
	m.conns[c] = struct{}{}
	return c
}

type memPacket struct {
	data []byte
	src  netip.AddrPort
}

type memConn struct {
	net  *MemNetwork
	addr netip.AddrPort
	rx   chan memPacket
	done chan struct{}
	once sync.Once
}

func (c *memConn) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	select {
	case <-c.done:
		return 0, netip.AddrPort{}, net.ErrClosed
	default:
	}
	select {
	case p := <-c.rx:
		return copy(b, p.data), p.src, nil
	case <-c.done:
		return 0, netip.AddrPort{}, net.ErrClosed
	}
}

func (c *memConn) deliver(b []byte, to func(*memConn) bool) error {
	select {
	case <-c.done:
		return net.ErrClosed
	default:
	}
	if len(b) > MaxPacketSize {
		return errors.New("mdns: datagram too large")
	}
	c.net.mu.Lock()
	defer c.net.mu.Unlock()
	if c.net.drop != nil && c.net.drop(b) {
		return nil
	}
	out := [][]byte{b}
	if c.net.fault != nil {
		out = c.net.fault(c.addr, append([]byte(nil), b...))
	}
	for _, d := range out {
		for peer := range c.net.conns {
			if peer == c || !to(peer) {
				continue
			}
			peer.enqueue(memPacket{data: append([]byte(nil), d...), src: c.addr})
		}
	}
	return nil
}

// enqueue hands a datagram to the station. A full receive queue drops it,
// like UDP does.
func (c *memConn) enqueue(p memPacket) {
	select {
	case c.rx <- p:
	default:
	}
}

func (c *memConn) WriteMulticast(b []byte) error {
	return c.deliver(b, func(*memConn) bool { return true })
}

func (c *memConn) WriteTo(b []byte, dst netip.AddrPort) error {
	return c.deliver(b, func(p *memConn) bool { return p.addr == dst })
}

func (c *memConn) Addrs() []netip.Addr { return []netip.Addr{c.addr.Addr()} }

func (c *memConn) Close() error {
	c.once.Do(func() {
		c.net.mu.Lock()
		delete(c.net.conns, c)
		c.net.mu.Unlock()
		close(c.done)
	})
	return nil
}
