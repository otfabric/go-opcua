// SPDX-License-Identifier: MIT

package fxcm_test

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxcm"
	"github.com/otfabric/go-opcua/uafx/fxserver"
	"github.com/otfabric/go-opcua/uafx/fxstore"
	"github.com/otfabric/go-opcua/uafx/fxstore/storetest"
)

// storedKeys returns the keys of the cm namespace of s with prefix.
func storedKeys(t *testing.T, s fxstore.Store, prefix string) []string {
	t.Helper()
	st, err := s.Load(context.Background())
	require.NoError(t, err)
	var out []string
	for k := range st {
		if strings.HasPrefix(k, "cm/"+prefix) {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

func classes(st fxcm.Status) []fxcm.Ownership {
	var out []fxcm.Ownership
	for _, e := range st.Endpoints {
		out = append(out, e.Class)
	}
	return out
}

// TestStoreRestartE2E: a Manager with a Store keeps its set and the
// records of the endpoints it established across a restart, and trusts
// none of them: after the restart every record is Unverified, an establish
// fails the Connections whose Names they hold and a removal closes nothing
// (design §6.4, decision C3-D9). Settle decides them; then the removal
// closes them.
func TestStoreRestartE2E(t *testing.T) {
	t.Parallel()
	a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
	mem := &fxstore.MemoryStore{}
	m := newManager(t, fxcm.Options{Store: mem})
	cfg, err := m.Add(e2eConf(t, "Durable", a, b))
	require.NoError(t, err)
	k := cfg.Key()
	res := process(t, m, uafx.ActionEstablishConnectionsEnabled, k)
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	require.Len(t, res.Created, 2)
	assert.Len(t, storedKeys(t, mem, "ep/"), 2, "the records of the endpoints")
	assert.Empty(t, storedKeys(t, mem, "run/"), "the run ended: its record is gone")
	assert.Empty(t, storedKeys(t, mem, "call/"), "every intent completed")
	ss, _ := m.StoreStatus()
	assert.False(t, ss.Store.Fenced)

	require.NoError(t, m.Close())
	m2 := newManager(t, fxcm.Options{Store: mem})
	st, ok := m2.Status(k)
	require.True(t, ok)
	assert.Equal(t, fxcm.StateReady, st.State, "nothing owed")
	assert.Equal(t, []fxcm.Ownership{fxcm.Unverified, fxcm.Unverified}, classes(st))
	require.NotNil(t, st.Recovery)
	assert.Equal(t, 2, st.Recovery.Pending)
	assert.Len(t, st.Recovery.Unverified, 2)
	assert.Empty(t, st.Recovery.Owed)
	assert.False(t, st.Recovery.Done)

	// An establish fails the Connections their Names hold; nothing on the
	// AutomationComponents changes.
	res = process(t, m2, uafx.ActionEstablishConnectionsEnabled, k)
	require.Equal(t, fxcm.StateError, res.State)
	assert.Empty(t, res.Created)
	assert.Equal(t, []string{"ToB"}, a.endpoints())
	assert.Equal(t, []string{"ToA"}, b.endpoints())
	// A removal closes none of them.
	res = process(t, m2, uafx.ActionRemoveConnections, k)
	require.Equal(t, fxcm.StateError, res.State)
	assert.Empty(t, res.Closed)
	assert.Equal(t, []string{"ToB"}, a.endpoints())
	st, _ = m2.Status(k)
	assert.Equal(t, []fxcm.Ownership{fxcm.Unverified, fxcm.Unverified}, classes(st), "unchanged")

	// Settle decides them; the verdict is durable.
	for _, e := range st.Endpoints {
		require.NoError(t, m2.Settle(k, e.Endpoint, fxcm.SettleOwned))
	}
	require.NoError(t, m2.Close())
	m3 := newManager(t, fxcm.Options{Store: mem})
	st, _ = m3.Status(k)
	assert.Equal(t, []fxcm.Ownership{fxcm.Unverified, fxcm.Unverified}, classes(st), "loaded again: unverified again")
	for _, e := range st.Endpoints {
		require.NoError(t, m3.Settle(k, e.Endpoint, fxcm.SettleOwned))
	}
	res = process(t, m3, uafx.ActionRemoveConnections, k)
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	assert.Empty(t, a.endpoints())
	assert.Empty(t, b.endpoints())
	assert.Empty(t, storedKeys(t, mem, "ep/"))
	st, _ = m3.Status(k)
	assert.True(t, st.Recovery.Done)
}

// failing is a store that gives a fault to the first Apply for which when
// returns true.
type failing struct {
	fxstore.Store
	mu    sync.Mutex
	when  func(b fxstore.Batch) bool
	fault storetest.Fault
	hit   int
}

func (f *failing) Apply(ctx context.Context, b fxstore.Batch) error {
	f.mu.Lock()
	hit := f.when != nil && f.when(b)
	if hit {
		f.when = nil
		f.hit++
	}
	fault := f.fault
	f.mu.Unlock()
	if !hit {
		return f.Store.Apply(ctx, b)
	}
	inner := storetest.NewFaulty(f.Store)
	inner.FailApply(fault)
	return inner.Apply(ctx, b)
}

func (f *failing) arm(fault storetest.Fault, when func(b fxstore.Batch) bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fault, f.when = fault, when
}

func putsPrefix(prefix string) func(b fxstore.Batch) bool {
	return func(b fxstore.Batch) bool {
		for k := range b.Puts {
			if strings.HasPrefix(k, "cm/"+prefix) {
				return true
			}
		}
		return false
	}
}

func deletesPrefix(prefix string) func(b fxstore.Batch) bool {
	return func(b fxstore.Batch) bool {
		for _, k := range b.Deletes {
			if strings.HasPrefix(k, "cm/"+prefix) {
				return true
			}
		}
		return false
	}
}

// TestStoreJournalE2E: a call whose intent is not written is not sent; a
// call whose completion is not written leaves its endpoints Unresolved in
// memory and its intent and run record in the store, which a restarted
// Manager reports as owed and never resends (design §6.3, §7.2).
func TestStoreJournalE2E(t *testing.T) {
	t.Parallel()
	t.Run("intent not written", func(t *testing.T) {
		t.Parallel()
		a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
		f := &failing{Store: &fxstore.MemoryStore{}}
		m := newManager(t, fxcm.Options{Store: f})
		cfg, err := m.Add(e2eConf(t, "NoIntent", a, b))
		require.NoError(t, err)
		f.arm(storetest.FailNotCommitted, putsPrefix("call/"))
		res := process(t, m, uafx.ActionEstablishConnectionsEnabled, cfg.Key())
		require.Equal(t, fxcm.StateError, res.State)
		require.True(t, slices.ContainsFunc(res.Failures, func(f fxcm.Failure) bool {
			return f.Status == ua.StatusBadResourceUnavailable
		}), "%+v", res.Failures)
		assert.Empty(t, a.endpoints(), "nothing was sent")
		assert.Empty(t, b.endpoints())
		assert.Empty(t, storedKeys(t, f, "run/"))
		assert.Empty(t, storedKeys(t, f, "call/"))
	})
	t.Run("run record not written", func(t *testing.T) {
		t.Parallel()
		a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
		f := &failing{Store: &fxstore.MemoryStore{}}
		m := newManager(t, fxcm.Options{Store: f})
		cfg, err := m.Add(e2eConf(t, "NoRun", a, b))
		require.NoError(t, err)
		f.arm(storetest.FailNotCommitted, putsPrefix("run/"))
		res := process(t, m, uafx.ActionEstablishConnectionsEnabled, cfg.Key())
		require.Equal(t, fxcm.StateError, res.State)
		assert.Empty(t, a.endpoints(), "no run record, no call")
		assert.Zero(t, m.Counters().EstablishCallCount)
	})
	t.Run("completion lost", func(t *testing.T) {
		t.Parallel()
		a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
		mem := &fxstore.MemoryStore{}
		f := &failing{Store: mem}
		m := newManager(t, fxcm.Options{Store: f})
		cfg, err := m.Add(e2eConf(t, "Lost", a, b))
		require.NoError(t, err)
		k := cfg.Key()
		// The first write that completes an intent with endpoint
		// records: its outcome is unknown and it did not land.
		f.arm(storetest.FailLost, func(b fxstore.Batch) bool {
			return deletesPrefix("call/")(b) && putsPrefix("ep/")(b)
		})
		res := process(t, m, uafx.ActionEstablishConnectionsEnabled, k)
		require.Equal(t, fxcm.StateError, res.State)
		require.Equal(t, 1, f.hit)
		st, _ := m.Status(k)
		assert.True(t, slices.ContainsFunc(st.Endpoints, func(e fxcm.EndpointRecord) bool { return e.Class == fxcm.Unresolved }),
			"an endpoint whose record was not written is not trusted: %+v", st.Endpoints)
		require.Eventually(t, func() bool { ss, _ := m.StoreStatus(); return !ss.Store.Fenced }, 10*time.Second, 10*time.Millisecond)
		assert.Len(t, storedKeys(t, mem, "call/"), 1, "the intent of the call whose outcome was not written stays")
		assert.Len(t, storedKeys(t, mem, "run/"), 1, "and so does the run record")
		require.NoError(t, m.Close())

		calls := m.Counters().EstablishCallCount
		m2 := newManager(t, fxcm.Options{Store: mem})
		st, _ = m2.Status(k)
		assert.Equal(t, fxcm.StateError, st.State, "the journal shows owed work")
		require.NotNil(t, st.Recovery)
		kinds := map[fxcm.OwedKind]bool{}
		for _, w := range st.Recovery.Owed {
			kinds[w.Kind] = true
		}
		assert.True(t, kinds[fxcm.OwedCall], "%+v", st.Recovery.Owed)
		assert.True(t, kinds[fxcm.OwedReconcile] || kinds[fxcm.OwedRollback], "%+v", st.Recovery.Owed)
		assert.False(t, st.Recovery.Done)
		assert.Zero(t, m2.Counters().EstablishCallCount, "nothing is resent")
		assert.Positive(t, calls)
	})
}
