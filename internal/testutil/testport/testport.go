// SPDX-License-Identifier: MIT

// Package testport hands out TCP and UDP ports for tests that must configure
// a fixed port (a PubSub connection URL, a port Docker publishes) instead of
// binding port 0.
//
// A port found by binding port 0 and closing the socket is taken from the
// kernel's ephemeral range, which every outgoing socket of every process
// draws from as well; with packages running in parallel another socket may
// take it before the test binds it. These ports come from a range outside
// the ephemeral ranges of Linux (32768-60999 by default, the configured
// range when it reaches lower), macOS and Windows (49152-65535), are free on
// IPv4 and IPv6 when handed out, and are never handed out twice in one
// process.
//
// A port that is free when it is handed out can still be taken before the
// test binds it. Where the test binds the port itself, BindUDP and BindTCP
// close that gap: they bind first and pick another port when the bind finds
// it taken, before anything else has been told the port.
package testport

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
)

const (
	lowPort  = 20000
	highPort = 32000 // exclusive

	// bindAttempts bounds the ports BindUDP and BindTCP try.
	bindAttempts = 20
)

var (
	mu   sync.Mutex
	used = map[int]bool{}

	// ephemeralLow and ephemeralHigh are the kernel's ephemeral port range
	// (inclusive), 0 if unknown.
	ephemeralOnce               sync.Once
	ephemeralLow, ephemeralHigh int
)

// UDP returns a UDP port that is free on 127.0.0.1 and on the IPv4 and IPv6
// wildcard addresses. It fails the test if it finds none.
func UDP(tb testing.TB) int {
	tb.Helper()
	return pick(tb, "udp", freeUDP)
}

// TCP returns a TCP port that is free on 127.0.0.1 and on the IPv4 and IPv6
// wildcard addresses (where Docker publishes container ports). It fails the
// test if it finds none.
func TCP(tb testing.TB) int {
	tb.Helper()
	return pick(tb, "tcp", freeTCP)
}

// BindUDP calls bind with UDP ports of UDP until bind returns nil, and
// returns that port. bind binds the port and keeps it; when its error is
// InUse (another socket took the port after it was found free)
// the next port is tried, any other error fails the test.
func BindUDP(tb testing.TB, bind func(port int) error) int {
	tb.Helper()
	return bindRetry(tb, "udp", UDP, bind)
}

// BindTCP is BindUDP for TCP ports.
func BindTCP(tb testing.TB, bind func(port int) error) int {
	tb.Helper()
	return bindRetry(tb, "tcp", TCP, bind)
}

func bindRetry(tb testing.TB, proto string, next func(testing.TB) int, bind func(int) error) int {
	tb.Helper()
	var err error
	for range bindAttempts {
		p := next(tb)
		if err = bind(p); err == nil {
			return p
		}
		if !InUse(err) {
			tb.Fatalf("testport: bind %s port %d: %v", proto, p, err)
		}
	}
	tb.Fatalf("testport: no %s port could be bound in %d attempts: %v", proto, bindAttempts, err)
	return 0
}

// pick returns a port of the range that free reports free and that was not
// handed out before. TCP and UDP share the bookkeeping, so a test never gets
// the same number for both.
func pick(tb testing.TB, proto string, free func(int) bool) int {
	tb.Helper()
	ephemeralOnce.Do(func() { ephemeralLow, ephemeralHigh = ephemeralRange() })
	mu.Lock()
	defer mu.Unlock()
	for range 400 {
		p := lowPort + rand.IntN(highPort-lowPort)
		if used[p] || ephemeral(p) || !free(p) {
			continue
		}
		used[p] = true
		return p
	}
	tb.Fatalf("testport: no free %s port", proto)
	return 0
}

// ephemeral reports whether p is in the kernel's ephemeral range. When that
// range covers all of lowPort-highPort nothing is excluded.
func ephemeral(p int) bool {
	if ephemeralLow == 0 || (ephemeralLow <= lowPort && ephemeralHigh >= highPort-1) {
		return false
	}
	return p >= ephemeralLow && p <= ephemeralHigh
}

// ephemeralRange reads the Linux ephemeral port range; 0, 0 elsewhere.
func ephemeralRange() (int, int) {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		return 0, 0
	}
	var lo, hi int
	if _, err := fmt.Sscan(string(b), &lo, &hi); err != nil || lo <= 0 || hi < lo {
		return 0, 0
	}
	return lo, hi
}

// freeUDP reports whether nothing is bound to UDP port p.
func freeUDP(p int) bool {
	for _, a := range addrs(p) {
		c, err := net.ListenPacket("udp"+a.v, a.addr)
		if err != nil {
			if a.v == "6" && noIPv6(err) {
				continue
			}
			return false
		}
		_ = c.Close()
	}
	return true
}

// freeTCP reports whether nothing listens on TCP port p.
func freeTCP(p int) bool {
	for _, a := range addrs(p) {
		l, err := net.Listen("tcp"+a.v, a.addr)
		if err != nil {
			if a.v == "6" && noIPv6(err) {
				continue
			}
			return false
		}
		_ = l.Close()
	}
	return true
}

type addr struct{ v, addr string }

// addrs are the addresses a port must be free on: the IPv4 loopback and
// wildcard, and the IPv6 wildcard, which a dual-stack socket (":port", what
// the PubSub UDP transport and Docker bind) occupies as well.
func addrs(p int) []addr {
	return []addr{
		{"4", fmt.Sprintf("127.0.0.1:%d", p)},
		{"4", fmt.Sprintf("0.0.0.0:%d", p)},
		{"6", fmt.Sprintf("[::]:%d", p)},
	}
}

// InUse reports whether err is a bind error because the address is in use
// (EADDRINUSE, WSAEADDRINUSE on Windows).
func InUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE) || (err != nil && strings.Contains(err.Error(), "Only one usage of each socket address"))
}

// noIPv6 reports whether err means the host has no IPv6, as opposed to the
// port being taken.
func noIPv6(err error) bool {
	return errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.EPROTONOSUPPORT)
}
