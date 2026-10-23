// SPDX-License-Identifier: MIT

// Package testport hands out TCP and UDP ports for tests that must configure
// a fixed port (a PubSub connection URL, a port Docker publishes) instead of
// binding port 0.
//
// A port found by binding port 0 and closing the socket is taken from the
// kernel's ephemeral range, which every outgoing socket of every process
// draws from as well; with packages running in parallel another socket may
// take it before the test binds it. These ports come from a range outside
// the ephemeral ranges of Linux (32768-60999), macOS and Windows
// (49152-65535), are free when handed out, and are never handed out twice
// in one process.
package testport

import (
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"testing"
)

const (
	lowPort  = 20000
	highPort = 32000 // exclusive
)

var (
	mu   sync.Mutex
	used = map[int]bool{}
)

// UDP returns a UDP port that is free on 127.0.0.1 and on the wildcard
// address. It fails the test if it finds none.
func UDP(tb testing.TB) int {
	tb.Helper()
	return pick(tb, "udp", freeUDP)
}

// TCP returns a TCP port that is free on 127.0.0.1 and on the wildcard
// address (where Docker publishes container ports). It fails the test if it
// finds none.
func TCP(tb testing.TB) int {
	tb.Helper()
	return pick(tb, "tcp", freeTCP)
}

// pick returns a port of the range that free reports free and that was not
// handed out before. TCP and UDP share the bookkeeping, so a test never gets
// the same number for both.
func pick(tb testing.TB, proto string, free func(int) bool) int {
	tb.Helper()
	mu.Lock()
	defer mu.Unlock()
	for range 200 {
		p := lowPort + rand.IntN(highPort-lowPort)
		if used[p] || !free(p) {
			continue
		}
		used[p] = true
		return p
	}
	tb.Fatalf("testport: no free %s port", proto)
	return 0
}

// freeUDP reports whether nothing is bound to UDP port p.
func freeUDP(p int) bool {
	for _, addr := range addrs(p) {
		c, err := net.ListenPacket("udp4", addr)
		if err != nil {
			return false
		}
		_ = c.Close()
	}
	return true
}

// freeTCP reports whether nothing listens on TCP port p.
func freeTCP(p int) bool {
	for _, addr := range addrs(p) {
		l, err := net.Listen("tcp4", addr)
		if err != nil {
			return false
		}
		_ = l.Close()
	}
	return true
}

func addrs(p int) []string {
	return []string{fmt.Sprintf("127.0.0.1:%d", p), fmt.Sprintf("0.0.0.0:%d", p)}
}
