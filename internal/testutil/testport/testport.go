// SPDX-License-Identifier: MIT

// Package testport hands out UDP ports for tests that must configure a fixed
// port (a PubSub connection URL) instead of binding port 0.
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
	tb.Fatal("testport: no free UDP port")
	return 0
}

// free reports whether nothing is bound to UDP port p.
func free(p int) bool {
	for _, addr := range []string{fmt.Sprintf("127.0.0.1:%d", p), fmt.Sprintf("0.0.0.0:%d", p)} {
		c, err := net.ListenPacket("udp4", addr)
		if err != nil {
			return false
		}
		_ = c.Close()
	}
	return true
}
