// SPDX-License-Identifier: MIT

package fxstore

import (
	"context"
	"sync"
)

// MemoryStore is a Store in memory: it implements the logical transactions
// of the contract (atomic Apply, the outcomes, Close, Limits) and nothing
// else. It is not durable: its state goes with the process. Use it for
// tests, and for the protocols of the persistent connections without
// persistence.
//
// A MemoryStore is safe for concurrent use. Its zero value is ready to use
// with the default Limits.
type MemoryStore struct {
	// Limits bound the state; the zero value is the defaults.
	Limits Limits

	mu     sync.Mutex
	state  map[string][]byte
	closed bool
}

var (
	_ Store   = (*MemoryStore)(nil)
	_ Durable = (*MemoryStore)(nil)
)

// Load returns a copy of the state.
func (m *MemoryStore) Load(ctx context.Context) (map[string][]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, ErrClosed
	}
	return cloneState(m.state), nil
}

// Apply applies b atomically. It never returns an unknown outcome.
func (m *MemoryStore) Apply(ctx context.Context, b Batch) error {
	if err := ctx.Err(); err != nil {
		return AsNotCommitted(err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	next := applyBatch(m.state, b)
	if err := m.Limits.check(next); err != nil {
		return AsNotCommitted(err)
	}
	m.state = next
	return nil
}

// Close makes Load and Apply fail with ErrClosed; the state is dropped.
func (m *MemoryStore) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed, m.state = true, nil
	return nil
}

// Durability is DurabilityNone.
func (m *MemoryStore) Durability() Durability { return DurabilityNone }
