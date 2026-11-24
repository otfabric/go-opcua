// SPDX-License-Identifier: MIT

package fxcm

import "context"

// The hooks of the tests in fxcm_test, which import fxserver and so cannot
// be in package fxcm (fxserver imports fxcm).

// DropSessions closes the pooled sessions of m, so the next run dials again.
func DropSessions(m *Manager) {
	m.pool.mu.Lock()
	open := map[ServerAddress]Session{}
	for addr, e := range m.pool.sessions {
		open[addr] = e.s
	}
	m.pool.mu.Unlock()
	for addr, s := range open {
		m.pool.drop(context.Background(), addr, s)
	}
}

// NewPendingRun is a Run that never ends.
func NewPendingRun() *Run { return &Run{done: make(chan struct{})} }
