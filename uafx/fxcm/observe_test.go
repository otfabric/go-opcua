// SPDX-License-Identifier: MIT

package fxcm

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/uafx"
)

// The helpers of the internal tests; the e2e tests, which need fxserver
// and so live in fxcm_test, have their own.

// cmURI is the ApplicationUri of the ConnectionManagers of the tests.
const cmURI = "urn:go-opcua:fxcm:test"

// eventLog is an Observer that keeps the Events.
type eventLog struct {
	mu     sync.Mutex
	events []Event
}

func (l *eventLog) Observe(e Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
}

func (l *eventLog) of(k EventKind) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Event
	for _, e := range l.events {
		if e.Kind == k {
			out = append(out, e)
		}
	}
	return out
}

// transitions are the transitions that ended runs (2 and 3, §6.9.2).
func (l *eventLog) transitions() []Transition {
	var out []Transition
	for _, e := range l.of(EventTransition) {
		if e.Transition == ProcessingToReady || e.Transition == ProcessingToError {
			out = append(out, e.Transition)
		}
	}
	return out
}

func newManager(t *testing.T, opts Options) *Manager {
	t.Helper()
	if opts.Dialer == nil {
		opts.Dialer = &ClientDialer{Options: []opcua.Option{opcua.ApplicationURI(cmURI), opcua.AutoReconnect(false), opcua.InsecureNoSecurity()}}
	}
	if opts.ApplicationURI == "" {
		opts.ApplicationURI = cmURI
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.CallTimeout == 0 {
		opts.CallTimeout = 10 * time.Second
	}
	m, err := New(opts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func process(t *testing.T, m *Manager, action uafx.FxProcess, k SetKey) *RunResult {
	t.Helper()
	st := m.Process(action, k)
	require.Len(t, st, 1)
	require.NoError(t, st[0].Err)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := st[0].Run.Wait(ctx)
	require.NoError(t, err)
	return res
}
