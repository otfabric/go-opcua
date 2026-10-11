// SPDX-License-Identifier: MIT

package chaoskit

import (
	"sync/atomic"
	"testing"
	"time"
)

// StallMonitor measures for how long the test binary did not get to run: a
// goroutine that sleeps for 10 ms at a time records by how much it overslept.
//
// A few scenarios are fault-free and yet depend on time: a secure channel
// with a lifetime of 3 s is lost when its renewal is not handled within
// 1.5 s. On a machine that stops the process for that long (a CI runner that
// runs several test binaries, a laptop that is busy otherwise) such a
// scenario loses its channels although client and server did everything
// right. It then says nothing about them, and reports that instead of
// failing.
type StallMonitor struct {
	max  atomic.Int64
	stop chan struct{}
	done chan struct{}
}

// WatchStalls starts a monitor that is stopped when the test ends.
func WatchStalls(t *testing.T) *StallMonitor {
	m := &StallMonitor{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(m.done)
		const step = 10 * time.Millisecond
		for {
			begin := time.Now()
			select {
			case <-m.stop:
				return
			case <-time.After(step):
			}
			if late := int64(time.Since(begin) - step); late > m.max.Load() {
				m.max.Store(late)
			}
		}
	}()
	t.Cleanup(func() { close(m.stop); <-m.done })
	return m
}

// Max returns the longest stall seen so far.
func (m *StallMonitor) Max() time.Duration { return time.Duration(m.max.Load()) }

// SkipIfStalled skips the test when the binary was stalled for limit or
// longer. It is called by a time-dependent scenario that is about to fail.
func (m *StallMonitor) SkipIfStalled(t *testing.T, limit time.Duration, what string) {
	t.Helper()
	if stall := m.Max(); stall >= limit {
		t.Skipf("the test binary was not scheduled for %v (limit %v): %s; the scenario says nothing about client and server in this run",
			stall.Round(time.Millisecond), limit, what)
	}
}
