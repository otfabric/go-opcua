// SPDX-License-Identifier: MIT

package fxcm_test

import (
	"context"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxcm"
	"github.com/otfabric/go-opcua/uafx/fxserver"
	"github.com/otfabric/go-opcua/uafx/fxstore"
	"github.com/otfabric/go-opcua/uafx/fxstore/storetest"
)

// classWatch is a store that remembers every transition of the class of
// an endpoint record it commits, by key.
type classWatch struct {
	fxstore.Store
	mu    sync.Mutex
	last  map[string]int64
	moves []string
}

func (w *classWatch) Apply(ctx context.Context, b fxstore.Batch) error {
	err := w.Store.Apply(ctx, b)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.last == nil {
		w.last = map[string]int64{}
	}
	for k, v := range b.Puts {
		if !strings.HasPrefix(k, "cm/ep/") {
			continue
		}
		r, derr := fxcm.DecodeStored[fxcm.StoredEndpoint](v)
		if derr != nil {
			continue
		}
		if old, ok := w.last[k]; ok && old != r.Class {
			w.moves = append(w.moves, fxcm.Ownership(old).String()+"->"+fxcm.Ownership(r.Class).String())
		}
		w.last[k] = r.Class
	}
	for _, k := range b.Deletes {
		delete(w.last, k)
	}
	return nil
}

func (w *classWatch) transitions() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.moves...)
}

// TestSettleRebuildsMemory (design §3.3, §3.5, §6.4): the completion write
// of an establish has an unknown outcome, which landed (its records and
// the completion of its intent are committed) or was lost. After the
// settle the memory of the Manager is the committed state: a record whose
// stored value differs from memory is the stored one, Unverified, and the
// background verification re-proves it without a Process; the next
// Process then establishes the set. No stored record goes from KnownOwned
// to Unresolved on the way.
func TestSettleRebuildsMemory(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		fault storetest.Fault
	}{
		{"landed", storetest.FailApplied},
		{"lost", storetest.FailLost},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
			mem := &fxstore.MemoryStore{}
			watch := &classWatch{Store: mem}
			f := &failing{Store: watch}
			m := newManager(t, fxcm.Options{Store: f, ExclusiveApplicationURI: true, Verify: fxcm.VerifyOptions{RetryInitial: 50 * time.Millisecond}})
			cfg, err := m.Add(e2eConf(t, "S", a, b))
			require.NoError(t, err)
			k := cfg.Key()
			f.arm(tc.fault, putsPrefix("ep/"))
			res := process(t, m, uafx.ActionEstablishConnectionsEnabled, k)
			require.Equal(t, fxcm.StateError, res.State)
			require.Equal(t, 1, f.hit)
			waitUnfenced(t, m)

			// The verification starts after the settle, without a
			// Process, and decides every record and every intent the
			// failed run left (design §6.4).
			require.Eventually(t, func() bool {
				st, _ := m.Status(k)
				return st.Recovery != nil && st.Recovery.Pending == 0 && !slices.ContainsFunc(st.Recovery.Owed, func(w fxcm.OwedWork) bool { return w.Kind == fxcm.OwedCall })
			}, 15*time.Second, 20*time.Millisecond)
			st, _ := m.Status(k)
			eps := stored[fxcm.StoredEndpoint](t, mem, "ep/")
			byName := map[string]int64{}
			for _, r := range eps {
				byName[r.Name] = r.Class
			}
			for _, e := range st.Endpoints {
				if c, ok := byName[e.Name]; ok {
					assert.Equal(t, fxcm.Ownership(c), e.Class, "%s: memory follows the store", e.Name)
				}
			}

			res = process(t, m, uafx.ActionEstablishConnectionsEnabled, k)
			require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
			st, _ = m.Status(k)
			require.Len(t, st.Endpoints, 2)
			for _, e := range st.Endpoints {
				assert.Equal(t, fxcm.KnownOwned, e.Class, e.Name)
			}
			for _, r := range stored[fxcm.StoredEndpoint](t, mem, "ep/") {
				assert.Equal(t, int64(fxcm.KnownOwned), r.Class, r.Name)
			}
			assert.True(t, st.Recovery.Done, "%+v", st.Recovery)
			assert.NotContains(t, watch.transitions(), "KnownOwned->Unresolved")
			assert.Len(t, a.endpoints(), 1)
			assert.Len(t, b.endpoints(), 1)
		})
	}
}

// TestSettleStartsVerification (design §6.4): the completion of the closes
// of a Remove is lost; after the settle the endpoint records the store
// still has are Unverified, and the background verification decides them
// without a Process of the set.
func TestSettleStartsVerification(t *testing.T) {
	t.Parallel()
	a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
	mem := &fxstore.MemoryStore{}
	f := &failing{Store: mem}
	m := newManager(t, fxcm.Options{Store: f, ExclusiveApplicationURI: true, Verify: fxcm.VerifyOptions{RetryInitial: 50 * time.Millisecond}})
	cfg, err := m.Add(e2eConf(t, "S", a, b))
	require.NoError(t, err)
	k := cfg.Key()
	res := process(t, m, uafx.ActionEstablishConnectionsEnabled, k)
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	f.arm(storetest.FailLost, deletesPrefix("ep/"))
	res = process(t, m, uafx.ActionRemoveConnections, k)
	require.Equal(t, fxcm.StateError, res.State)
	require.Equal(t, 1, f.hit)
	require.Len(t, storedKeys(t, mem, "ep/"), 2, "the lost write left the records")
	waitUnfenced(t, m)
	// The settled memory has the records the store still has (Unverified
	// until the verification, which starts with the end of the fence,
	// decides them). A verdict deletes a record from the store before
	// memory, so memory, read first, never has fewer than the store.
	st, _ := m.Status(k)
	left := storedKeys(t, mem, "ep/")
	require.GreaterOrEqual(t, len(st.Endpoints), len(left), "memory does not have the stored records: %+v", st.Endpoints)
	if len(left) == 2 {
		for _, e := range st.Endpoints {
			assert.Equal(t, fxcm.Unverified, e.Class, e.Name)
		}
	}
	require.Eventually(t, func() bool {
		st, _ := m.Status(k)
		return st.Recovery != nil && st.Recovery.Pending == 0
	}, 15*time.Second, 20*time.Millisecond)
	st, _ = m.Status(k)
	for _, e := range st.Endpoints {
		assert.NotEqual(t, fxcm.Unverified, e.Class, e.Name)
	}
	// The verification proved the closes: the records are gone from
	// memory and store, and the AutomationComponents have no endpoints.
	require.Eventually(t, func() bool { return len(storedKeys(t, mem, "ep/")) == 0 }, 5*time.Second, 20*time.Millisecond)
	st, _ = m.Status(k)
	assert.Empty(t, st.Endpoints)
	assert.Empty(t, a.endpoints())
	assert.Empty(t, b.endpoints())
}

// blockingLoad is a store whose Load, once armed, waits for the end of its
// context: a store that does not answer.
type blockingLoad struct {
	fxstore.Store
	armed   atomic.Bool
	entered chan struct{}
	once    sync.Once
}

func (s *blockingLoad) Load(ctx context.Context) (map[string][]byte, error) {
	if !s.armed.Load() {
		return s.Store.Load(ctx)
	}
	s.once.Do(func() { close(s.entered) })
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestCloseDuringSettle: Close cancels a settle attempt that waits for the
// store, instead of waiting for StoreTimeout; the domain stays fenced.
func TestCloseDuringSettle(t *testing.T) {
	t.Parallel()
	a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
	bl := &blockingLoad{Store: &fxstore.MemoryStore{}, entered: make(chan struct{})}
	f := &failing{Store: bl}
	m := newManager(t, fxcm.Options{Store: f, StoreTimeout: 30 * time.Second})
	bl.armed.Store(true)
	f.arm(storetest.FailLost, putsPrefix("set/"))
	_, err := m.Add(e2eConf(t, "S", a, b))
	require.Error(t, err)
	select {
	case <-bl.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the settle never loaded the store")
	}
	start := time.Now()
	require.NoError(t, m.Close())
	assert.Less(t, time.Since(start), 5*time.Second, "Close waited for the store")
	ss, _ := m.StoreStatus()
	assert.True(t, ss.Store.Fenced)
}
