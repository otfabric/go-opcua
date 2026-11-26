// SPDX-License-Identifier: MIT

package fxcm

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxstore"
	"github.com/otfabric/go-opcua/uafx/fxstore/storetest"
)

// storeManager returns a Manager without servers on the store s.
func storeManager(t *testing.T, s fxstore.Store) *Manager {
	t.Helper()
	return offlineManager(t, Options{Store: s})
}

// reopen closes m and returns a Manager on the same store.
func reopen(t *testing.T, m *Manager, s fxstore.Store) *Manager {
	t.Helper()
	require.NoError(t, m.Close())
	return storeManager(t, s)
}

func keyNames(m *Manager) []string {
	var out []string
	for _, k := range m.Keys() {
		out = append(out, k.Name)
	}
	return out
}

// TestStoreSets: with a Store, Add, Replace, Remove, Update and a commit
// are durable before they are visible, and a restarted Manager has the
// sets as committed, with their Version (design §6.1, §6.2).
func TestStoreSets(t *testing.T) {
	t.Parallel()
	mem := &fxstore.MemoryStore{}
	m := storeManager(t, mem)
	_, err := m.Add(named("a"))
	require.NoError(t, err)
	_, err = m.Add(named("b"))
	require.NoError(t, err)
	_, err = m.Add(named("c"))
	require.NoError(t, err)

	// A commit: Version 2 of a.
	ka := KeyOf(named("a"))
	e, err := m.StartEdit(ka, "owner")
	require.NoError(t, err)
	e.Conf().Version = 2
	cfg, ok, err := m.CommitEdit(ka, "owner")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, uint32(2), cfg.Version())

	// Replace b, remove c.
	nb := named("b")
	_, err = m.Replace(context.Background(), nb)
	require.NoError(t, err)
	require.NoError(t, m.Remove(context.Background(), KeyOf(named("c"))))

	// An update: add d and e.
	applied, results := m.Update(context.Background(), []Operation{{Op: uafx.ElementAdd, Conf: named("d")}, {Op: uafx.ElementAdd, Conf: named("e")}}, true)
	require.True(t, applied, "%v", results)

	m2 := reopen(t, m, mem)
	require.Equal(t, []string{"a", "b", "d", "e"}, keyNames(m2))
	got, ok := m2.Config(ka)
	require.True(t, ok)
	assert.Equal(t, uint32(2), got.Version(), "the committed Version survives")
	st, ok := m2.Status(ka)
	require.True(t, ok)
	assert.Equal(t, StateReady, st.State)
	require.NotNil(t, st.Recovery)
	assert.True(t, st.Recovery.Done)
	ss, ok := m2.StoreStatus()
	require.True(t, ok)
	assert.Empty(t, ss.Failed)
	assert.False(t, ss.Store.Fenced)

	_, ok = offlineManager(t, Options{}).StoreStatus()
	assert.False(t, ok, "no store")
}

// TestStoreSetOutcomes: a set change whose write definitely did not commit
// fails with Bad_ResourceUnavailable and changes nothing; one whose outcome
// is unknown fails with Bad_InternalError, stays out of memory, and fences
// the store: later changes are refused until it is settled, and then the
// sets follow what the store committed (design §3.5, §6.2, C3-D13).
func TestStoreSetOutcomes(t *testing.T) {
	t.Parallel()
	mem := &fxstore.MemoryStore{}
	f := storetest.NewFaulty(mem)
	m := storeManager(t, f)

	f.FailApply(storetest.FailNotCommitted)
	_, err := m.Add(named("a"))
	require.ErrorIs(t, err, ua.StatusBadResourceUnavailable)
	require.Empty(t, keyNames(m))
	_, err = m.Add(named("a"))
	require.NoError(t, err, "nothing is fenced after a definite failure")

	// Unknown and not landed: the settle keeps the set out.
	f.FailLoadsWith(errors.New("load down"))
	f.FailApply(storetest.FailLost)
	_, err = m.Add(named("b"))
	require.ErrorIs(t, err, ua.StatusBadInternalError)
	require.Equal(t, []string{"a"}, keyNames(m), "an unknown change stays out of memory")
	_, err = m.Add(named("c"))
	require.ErrorIs(t, err, ua.StatusBadResourceUnavailable, "fenced")
	ss, _ := m.StoreStatus()
	require.True(t, ss.Store.Fenced)
	f.FailLoadsWith(nil)
	require.Eventually(t, func() bool { ss, _ := m.StoreStatus(); return !ss.Store.Fenced }, 10*time.Second, 10*time.Millisecond)
	require.Equal(t, []string{"a"}, keyNames(m))

	// Unknown and landed: the settle brings the set in.
	f.FailApply(storetest.FailApplied)
	_, err = m.Add(named("d"))
	require.ErrorIs(t, err, ua.StatusBadInternalError)
	require.Eventually(t, func() bool { return len(keyNames(m)) == 2 }, 10*time.Second, 10*time.Millisecond)
	require.Equal(t, []string{"a", "d"}, keyNames(m))

	// A commit that fails leaves the edit open.
	ka := KeyOf(named("a"))
	_, err = m.StartEdit(ka, "owner")
	require.NoError(t, err)
	f.FailApply(storetest.FailNotCommitted)
	_, ok, err := m.CommitEdit(ka, "owner")
	require.ErrorIs(t, err, ua.StatusBadResourceUnavailable)
	require.False(t, ok)
	st, _ := m.Status(ka)
	require.True(t, st.Editing, "the edit stays open")
	_, ok, err = m.CommitEdit(ka, "owner")
	require.NoError(t, err)
	require.True(t, ok)

	// A complete update whose write fails applies nothing.
	f.FailApply(storetest.FailNotCommitted)
	applied, results := m.Update(context.Background(), []Operation{{Op: uafx.ElementAdd, Conf: named("e")}, {Op: uafx.ElementRemove, Conf: named("d")}}, true)
	require.False(t, applied)
	for _, r := range results {
		require.ErrorIs(t, r, ua.StatusBadResourceUnavailable)
	}
	require.Equal(t, []string{"a", "d"}, keyNames(m))

	m2 := reopen(t, m, mem)
	require.Equal(t, []string{"a", "d"}, keyNames(m2))
	cfg, _ := m2.Config(ka)
	require.Equal(t, uint32(2), cfg.Version())
}

// TestStoreOpen: a store of another ApplicationURI fails New; a record that
// does not decode is reported, kept, and holds its key.
func TestStoreOpen(t *testing.T) {
	t.Parallel()
	mem := &fxstore.MemoryStore{}
	m := storeManager(t, mem)
	_, err := m.Add(named("a"))
	require.NoError(t, err)
	require.NoError(t, m.Close())

	_, err = New(Options{Dialer: offline{}, ApplicationURI: "urn:other", Store: mem})
	require.ErrorIs(t, err, fxstore.ErrForeignOwner)

	// Corrupt the record of a.
	k := "cm/" + setStoreKey(KeyOf(named("a")))
	require.NoError(t, mem.Apply(context.Background(), fxstore.Batch{Puts: map[string][]byte{k: {1, 2, 3}}}))
	m2 := storeManager(t, mem)
	require.Empty(t, keyNames(m2))
	ss, _ := m2.StoreStatus()
	require.Contains(t, ss.Failed, setStoreKey(KeyOf(named("a"))))
	_, err = m2.Add(named("a"))
	require.ErrorIs(t, err, ua.StatusBadInvalidState, "the key of a failed record is not taken")
	_, err = m2.Add(named("b"))
	require.NoError(t, err)
}

// TestStoreFollowWaits (design §3.3): memory follows the store only when
// no set is being processed, replaced or removed and no Add holds the key
// of a stored set; until then the fence stays.
func TestStoreFollowWaits(t *testing.T) {
	t.Parallel()
	mem := &fxstore.MemoryStore{}
	m := storeManager(t, mem)
	_, err := m.Add(named("a"))
	require.NoError(t, err)
	s := m.lookup(KeyOf(named("a")))
	s.mu.Lock()
	s.current = &Run{done: make(chan struct{})}
	s.mu.Unlock()
	assert.False(t, m.p.follow(), "a set is being processed")
	s.mu.Lock()
	s.current, s.held = nil, true
	s.mu.Unlock()
	assert.False(t, m.p.follow(), "a set is held")
	s.mu.Lock()
	s.held = false
	s.mu.Unlock()
	m.mu.Lock()
	m.reserved = map[string]bool{keyString(KeyOf(named("a"))): true}
	m.mu.Unlock()
	assert.False(t, m.p.follow(), "an Add holds the key of a stored set")
	m.mu.Lock()
	m.reserved = nil
	m.mu.Unlock()
	assert.True(t, m.p.follow())
}
