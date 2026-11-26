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

// SetCrashPoint makes f run at every point of the journal of m; nil
// removes it.
func SetCrashPoint(m *Manager, f func(string)) {
	if f == nil {
		m.crash.Store(nil)
		return
	}
	m.crash.Store(&f)
}

// The records of the store, for the tests of what a Manager writes.
type (
	StoredSet      = setRecord
	StoredEndpoint = epStored
	StoredRun      = runRecord
	StoredCall     = callRecord
	StoredTx       = txRecord
)

// PhaseRollbackRequired is the phase of a run record whose rollback is
// owed.
const PhaseRollbackRequired = phaseRollbackRequired

// DecodeStored decodes the record b of the store.
func DecodeStored[T any](b []byte) (*T, error) {
	v := new(T)
	if err := decodeRecord(b, v); err != nil {
		return nil, err
	}
	return v, nil
}
