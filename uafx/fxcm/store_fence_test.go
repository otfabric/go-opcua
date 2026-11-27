// SPDX-License-Identifier: MIT

package fxcm_test

import (
	"context"
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

// requireFenced checks that the set k, which owes nothing itself, is
// fenced by the work of another set: its remote operations and its
// CommitEdit are refused, and nothing is closed.
func requireFenced(t *testing.T, m *fxcm.Manager, k fxcm.SetKey, conf *uafx.ConnectionConfigurationSetConf) {
	t.Helper()
	st, ok := m.Status(k)
	require.True(t, ok)
	assert.Empty(t, st.Recovery.Owed, "the set owes nothing itself")
	require.NotEmpty(t, st.Recovery.Fenced, "the work of another set fences it")
	assert.False(t, st.Recovery.Done)
	closes := m.Counters().CloseCallCount
	for _, a := range []uafx.FxProcess{uafx.ActionEstablishConnectionsEnabled, uafx.ActionRemoveConnections} {
		started := m.Process(a, k)
		require.Len(t, started, 1)
		requireInvalidState(t, started[0].Err)
	}
	requireInvalidState(t, m.Reconcile(k).Err)
	_, err := m.Replace(context.Background(), conf)
	requireInvalidState(t, err)
	requireInvalidState(t, m.Remove(context.Background(), k))
	e, err := m.StartEdit(k, "e")
	require.NoError(t, err, "an edit is local")
	e.Conf().Connections[0].Endpoint1.ConfigurationData[0].Value = ua.MustVariant(4.5)
	_, ok, err = m.CommitEdit(k, "e")
	requireInvalidState(t, err)
	assert.False(t, ok)
	open, err := m.DiscardEdit(k, "e")
	require.NoError(t, err)
	assert.True(t, open, "the refused commit left the edit open")
	assert.Equal(t, closes, m.Counters().CloseCallCount, "no close while fenced")
}

// TestStoreCrossSetFenceE2E (design §6.3, library interpretation): work a
// set owes fences the other sets that share an AutomationComponent with
// it, live and after a restart; a set on other servers is not fenced.
func TestStoreCrossSetFenceE2E(t *testing.T) {
	t.Parallel()
	a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
	c, d := newAC(t, "c", fxserver.ConnectionOptions{}), newAC(t, "d", fxserver.ConnectionOptions{})
	mem := &fxstore.MemoryStore{}
	f := &failing{Store: mem}
	m := newManager(t, fxcm.Options{Store: f})
	conf := e2eConf(t, "Owed", a, b)
	conf.RollbackOnError = false
	owed, err := m.Add(conf)
	require.NoError(t, err)
	shared := e2eConf(t, "Shared", a, c)
	_, err = m.Add(shared)
	require.NoError(t, err)
	apart := e2eConf(t, "Apart", c, d)
	_, err = m.Add(apart)
	require.NoError(t, err)
	f.arm(storetest.FailLost, func(b fxstore.Batch) bool {
		return deletesPrefix("call/")(b) && putsPrefix("ep/")(b)
	})
	res := process(t, m, uafx.ActionEstablishConnectionsEnabled, owed.Key())
	require.Equal(t, fxcm.StateError, res.State)
	waitUnfenced(t, m)
	st, _ := m.Status(owed.Key())
	require.True(t, owesKind(st.Recovery.Owed, fxcm.OwedCall), "%+v", st.Recovery.Owed)

	sharedKey, apartKey := fxcm.SetKey{Name: "Shared"}, fxcm.SetKey{Name: "Apart"}
	requireFenced(t, m, sharedKey, shared)
	st, _ = m.Status(apartKey)
	assert.Empty(t, st.Recovery.Fenced, "no server in common")
	res = process(t, m, uafx.ActionEstablishConnectionsEnabled, apartKey)
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	require.NoError(t, m.Close())

	m2 := newManager(t, fxcm.Options{Store: mem})
	requireFenced(t, m2, sharedKey, shared)
	st, _ = m2.Status(apartKey)
	assert.Empty(t, st.Recovery.Fenced)
}

// TestStoreUpdateParticipantFenceE2E (design §6.2, §6.3): an owed set
// change of a complete Update fences every existing set it operates on,
// not only the one whose Connections it closed: live and after a restart.
func TestStoreUpdateParticipantFenceE2E(t *testing.T) {
	t.Parallel()
	a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
	c, d := newAC(t, "c", fxserver.ConnectionOptions{}), newAC(t, "d", fxserver.ConnectionOptions{})
	mem := &fxstore.MemoryStore{}
	f := &failing{Store: mem}
	m := newManager(t, fxcm.Options{Store: f})
	old, err := m.Add(e2eConf(t, "Old", a, b))
	require.NoError(t, err)
	res := process(t, m, uafx.ActionEstablishConnectionsEnabled, old.Key())
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	peerConf := e2eConf(t, "Peer", c, d) // other servers, nothing to close
	_, err = m.Add(peerConf)
	require.NoError(t, err)
	f.arm(storetest.FailLost, func(b fxstore.Batch) bool {
		return putsPrefix("set/")(b) || deletesPrefix("set/")(b)
	})
	ops := []fxcm.Operation{{Op: uafx.ElementReplace, Conf: e2eConf(t, "Old", a, b)}, {Op: uafx.ElementReplace, Conf: e2eConf(t, "Peer", c, d)}}
	applied, results := m.Update(context.Background(), ops, true)
	require.False(t, applied, "%v", results)
	waitUnfenced(t, m)
	st, _ := m.Status(old.Key())
	w := owedWork(st.Recovery.Owed, fxcm.OwedSetChange)
	require.NotNil(t, w, "%+v", st.Recovery.Owed)
	require.Len(t, w.Changes, 2)

	peer := fxcm.SetKey{Name: "Peer"}
	requireFenced(t, m, peer, peerConf)
	require.NoError(t, m.Close())

	m2 := newManager(t, fxcm.Options{Store: mem})
	st, _ = m2.Status(old.Key())
	require.True(t, owesKind(st.Recovery.Owed, fxcm.OwedSetChange))
	requireFenced(t, m2, peer, peerConf)
}

// TestStorePartialSetChangeE2E (design §6.2): a Replace or Remove whose
// close succeeded on one AutomationComponent and definitely failed on the
// other keeps its whole transaction and owes its set change, live and
// after a restart: what was closed cannot be undone (Table 24). One whose
// closes all failed definitely, before any remote effect, is abandoned.
func TestStorePartialSetChangeE2E(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		replace bool
		partial bool
	}{
		{"remove partial", false, true},
		{"replace partial", true, true},
		{"remove nothing closed", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
			mem := &fxstore.MemoryStore{}
			dl := newHookDialer()
			dl.answer = func(addr fxcm.ServerAddress, req *ua.CallMethodRequest) *ua.CallMethodResult {
				if closes(req) && (addr.Address == b.url || !tc.partial) {
					// A definite refusal: nothing was closed.
					return &ua.CallMethodResult{StatusCode: ua.StatusBadUserAccessDenied}
				}
				return nil
			}
			m := newManager(t, fxcm.Options{Store: mem, Dialer: dl})
			cfg, err := m.Add(e2eConf(t, "Part", a, b))
			require.NoError(t, err)
			k := cfg.Key()
			res := process(t, m, uafx.ActionEstablishConnectionsEnabled, k)
			require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
			require.NotEmpty(t, a.endpoints())
			require.NotEmpty(t, b.endpoints())
			if tc.replace {
				_, err = m.Replace(context.Background(), e2eConf(t, "Part", a, b))
			} else {
				err = m.Remove(context.Background(), k)
			}
			require.Error(t, err)
			assert.NotEmpty(t, b.endpoints(), "the failed close")

			check := func(m *fxcm.Manager) {
				t.Helper()
				st, ok := m.Status(k)
				require.True(t, ok, "the set stays")
				if !tc.partial {
					assert.Empty(t, st.Recovery.Owed, "nothing was closed: the change is abandoned")
					assert.Empty(t, storedKeys(t, mem, "run/"))
					assert.Empty(t, storedKeys(t, mem, "tx/"))
					return
				}
				w := owedWork(st.Recovery.Owed, fxcm.OwedSetChange)
				require.NotNil(t, w, "%+v", st.Recovery.Owed)
				require.Len(t, w.Changes, 1)
				assert.Len(t, storedKeys(t, mem, "run/"), 1, "the run record stays")
				assert.Len(t, storedKeys(t, mem, "tx/"), 1, "the whole transaction stays")
				started := m.Process(uafx.ActionEstablishConnectionsEnabled, k)
				requireInvalidState(t, started[0].Err)
				requireInvalidState(t, m.Remove(context.Background(), k))
				_, err := m.StartEdit(k, "e")
				require.NoError(t, err)
				_, _, err = m.CommitEdit(k, "e")
				requireInvalidState(t, err) // the owed change commits its Versions
				_, err = m.DiscardEdit(k, "e")
				require.NoError(t, err)
			}
			if tc.partial {
				assert.Empty(t, a.endpoints(), "the close that succeeded")
			} else {
				assert.NotEmpty(t, a.endpoints())
			}
			check(m)
			require.NoError(t, m.Close())
			check(newManager(t, fxcm.Options{Store: mem}))
		})
	}
}

// TestStoreFollowObserverReentrant: the events of follow (a commit whose
// acknowledgement was lost and that landed) reach the Observer after the
// Manager lock is released: an Observer may call into the Manager.
func TestStoreFollowObserverReentrant(t *testing.T) {
	t.Parallel()
	a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
	mem := &fxstore.MemoryStore{}
	f := &failing{Store: mem}
	var m *fxcm.Manager
	var mu sync.Mutex
	var seen []fxcm.Status
	blocked := false
	ready := make(chan struct{})
	m = newManager(t, fxcm.Options{Store: f, Observer: fxcm.ObserverFunc(func(e fxcm.Event) {
		<-ready
		if e.Kind != fxcm.EventCommitted {
			return
		}
		got := make(chan fxcm.Status, 1)
		go func() {
			st, _ := m.Status(e.Set) // takes the Manager lock
			got <- st
		}()
		select {
		case st := <-got:
			mu.Lock()
			seen = append(seen, st)
			mu.Unlock()
		case <-time.After(5 * time.Second):
			mu.Lock()
			blocked = true // observed under the Manager lock
			mu.Unlock()
		}
	})})
	close(ready)
	cfg, err := m.Add(e2eConf(t, "Reentrant", a, b))
	require.NoError(t, err)
	k := cfg.Key()
	e, err := m.StartEdit(k, "e")
	require.NoError(t, err)
	e.Conf().Connections[0].Endpoint1.ConfigurationData[0].Value = ua.MustVariant(3.5)
	f.arm(storetest.FailApplied, putsPrefix("set/"))
	_, _, err = m.CommitEdit(k, "e")
	require.Error(t, err)
	waitUnfenced(t, m)
	mu.Lock()
	defer mu.Unlock()
	require.False(t, blocked, "the Observer was called under the Manager lock")
	require.Len(t, seen, 1, "the landed commit, observed once")
	assert.Equal(t, uint32(2), seen[0].Version)
}
