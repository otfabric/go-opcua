// SPDX-License-Identifier: MIT

package fxcm_test

import (
	"context"
	"crypto/sha256"
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

// stored decodes the records of the cm namespace of s with prefix.
func stored[T any](t *testing.T, s fxstore.Store, prefix string) map[string]*T {
	t.Helper()
	st, err := s.Load(context.Background())
	require.NoError(t, err)
	out := map[string]*T{}
	for k, v := range st {
		if strings.HasPrefix(k, "cm/"+prefix) {
			r, err := fxcm.DecodeStored[T](v)
			require.NoError(t, err, k)
			out[k] = r
		}
	}
	return out
}

func onlySet(t *testing.T, s fxstore.Store) *fxcm.StoredSet {
	t.Helper()
	sets := stored[fxcm.StoredSet](t, s, "set/")
	require.Len(t, sets, 1)
	for _, r := range sets {
		return r
	}
	return nil
}

func waitUnfenced(t *testing.T, m *fxcm.Manager) {
	t.Helper()
	require.Eventually(t, func() bool {
		ss, _ := m.StoreStatus()
		return !ss.Store.Fenced && !ss.Reconciling
	}, 10*time.Second, 10*time.Millisecond)
}

func requireInvalidState(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	assert.Equal(t, ua.StatusBadInvalidState, fxcm.StatusOf(err), "%v", err)
}

// TestStoreEvidenceE2E (design §6.5): the endpoint records a run writes
// carry the evidence of ownership: the identity of the server (its
// ApplicationUri), its NamespaceArray and namespace-qualified NodeIds, the
// CreationTime and the ConnectionManagerApplicationUri read from the
// endpoint, the fingerprint of what was sent for it, and the generation
// and fingerprint of the configuration the run started with, not of one
// committed while it ran.
func TestStoreEvidenceE2E(t *testing.T) {
	t.Parallel()
	a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
	mem := &fxstore.MemoryStore{}
	m := newManager(t, fxcm.Options{Store: mem})
	cfg, err := m.Add(e2eConf(t, "Evidence", a, b))
	require.NoError(t, err)
	k := cfg.Key()
	before := onlySet(t, mem)

	// A Version committed while the run is between its first intent and
	// its call.
	_, err = m.StartEdit(k, "e")
	require.NoError(t, err)
	hold, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	fxcm.SetCrashPoint(m, func(p string) {
		if p == "call.after-intent" {
			once.Do(func() { close(hold); <-release })
		}
	})
	st := m.Process(uafx.ActionEstablishConnectionsEnabled, k)
	require.Len(t, st, 1)
	require.NoError(t, st[0].Err)
	<-hold
	_, ok, err := m.CommitEdit(k, "e")
	require.NoError(t, err)
	require.True(t, ok)
	after := onlySet(t, mem)
	require.Greater(t, after.Generation, before.Generation)
	close(release)
	res, err := st[0].Run.Wait(context.Background())
	require.NoError(t, err)
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)

	eps := stored[fxcm.StoredEndpoint](t, mem, "ep/")
	require.Len(t, eps, 2)
	uris := map[string]bool{}
	for key, r := range eps {
		uris[r.Server.ApplicationURI] = true
		assert.False(t, r.Server.Secured, key)
		assert.Empty(t, r.Server.Thumbprint, "no thumbprint without security")
		assert.Equal(t, fxcm.IdentityReported, r.Server.Source, "reported over SecurityMode None, not authenticated")
		require.NotEmpty(t, r.Namespaces, key)
		require.NotNil(t, r.ACNode, key)
		require.NotNil(t, r.FunctionalEntity, key)
		require.NotNil(t, r.NodeID, key)
		for _, q := range [][2]string{
			{r.ACNode.NamespaceURI, r.ACNode.ID}, {r.FunctionalEntity.NamespaceURI, r.FunctionalEntity.ID}, {r.NodeID.NamespaceURI, r.NodeID.ID},
		} {
			assert.NotEmpty(t, q[0], "qualified by URI: %s", key)
			assert.False(t, strings.HasPrefix(q[1], "ns="), "no namespace index in %q", q[1])
		}
		assert.True(t, r.CMObserved, key)
		assert.Equal(t, cmURI, r.CMApplicationURI)
		assert.False(t, r.CreationTime.IsZero(), "the Diagnostics CreationTime: %s", key)
		assert.WithinDuration(t, time.Now(), r.CreationTime, time.Minute)
		assert.Len(t, r.EndpointFingerprint, sha256.Size)
		assert.Equal(t, before.Generation, r.Generation, "the run's configuration, not the one committed while it ran")
		assert.Equal(t, before.Fingerprint, r.Fingerprint)
		assert.Equal(t, int64(fxcm.KnownOwned), r.Class)
	}
	assert.Equal(t, map[string]bool{a.uri: true, b.uri: true}, uris, "the ApplicationUri each server reported")
}

// TestStoreCompletionConcurrentE2E (design §6.3): the completions of
// calls on two AutomationComponents of one run are serialized with the
// records they write. One of them does not commit: only the records of
// that completion become Unresolved and stay out of the store; the other's
// committed records are unchanged in memory and in the store.
func TestStoreCompletionConcurrentE2E(t *testing.T) {
	t.Parallel()
	a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
	mem := &fxstore.MemoryStore{}
	f := &failing{Store: mem}
	m := newManager(t, fxcm.Options{Store: f})
	conf := e2eConf(t, "Concurrent", a, b)
	conf.RollbackOnError = false
	cfg, err := m.Add(conf)
	require.NoError(t, err)
	k := cfg.Key()
	f.arm(storetest.FailNotCommitted, func(b fxstore.Batch) bool {
		return deletesPrefix("call/")(b) && putsPrefix("ep/")(b)
	})
	res := process(t, m, uafx.ActionEstablishConnectionsEnabled, k)
	require.Equal(t, fxcm.StateError, res.State)
	require.Equal(t, 1, f.hit)
	st, _ := m.Status(k)
	require.Len(t, st.Endpoints, 2)
	byClass := map[fxcm.Ownership][]fxcm.EndpointRecord{}
	for _, e := range st.Endpoints {
		byClass[e.Class] = append(byClass[e.Class], e)
	}
	require.Len(t, byClass[fxcm.Unresolved], 1, "%+v", st.Endpoints)
	require.Len(t, byClass[fxcm.KnownOwned], 1, "%+v", st.Endpoints)
	// The store never shows the failed completion's endpoint as owned:
	// the run's end writes it as memory has it, Unresolved.
	for _, r := range stored[fxcm.StoredEndpoint](t, mem, "ep/") {
		switch r.Name {
		case byClass[fxcm.KnownOwned][0].Name:
			assert.Equal(t, int64(fxcm.KnownOwned), r.Class, "the committed completion is unchanged")
		default:
			assert.Equal(t, int64(fxcm.Unresolved), r.Class)
		}
	}
	assert.Len(t, storedKeys(t, mem, "call/"), 1, "the intent whose completion failed")
	accountedFor(t, mem, st)
}

// accountedFor checks that every endpoint of st the Manager could not
// prove keeps the evidence of its call: an intent in the store that names
// it, on its server.
func accountedFor(t *testing.T, mem fxstore.Store, st fxcm.Status) {
	t.Helper()
	calls := stored[fxcm.StoredCall](t, mem, "call/")
	for _, e := range st.Endpoints {
		if e.Class != fxcm.Unresolved {
			continue
		}
		found := false
		for _, c := range calls {
			if c.Server.ApplicationURI == e.ServerURI && slices.Contains(c.Names, e.Name) {
				found = true
				assert.Len(t, c.EndpointFingerprints, len(c.Names), "the intent is whole")
			}
		}
		assert.True(t, found, "the unresolved %s of %s keeps its intent: %+v", e.Name, e.ServerURI, calls)
	}
}

// TestStoreFenceFollowE2E (design §3.3, §6.2): a write whose outcome is
// unknown fences the Manager until the store is settled and memory has
// followed it: a write that landed is the Manager's state afterwards, one
// that did not is not, and the generation it consumed is never reused.
func TestStoreFenceFollowE2E(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		fault  storetest.Fault
		landed bool
	}{{"not landed", storetest.FailLost, false}, {"landed", storetest.FailApplied, true}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
			mem := &fxstore.MemoryStore{}
			f := &failing{Store: mem}
			m := newManager(t, fxcm.Options{Store: f})
			var lost uint64
			armSet := func() {
				f.arm(tc.fault, func(b fxstore.Batch) bool {
					for key, v := range b.Puts {
						if strings.HasPrefix(key, "cm/set/") {
							r, err := fxcm.DecodeStored[fxcm.StoredSet](v)
							require.NoError(t, err)
							lost = max(lost, r.Generation)
						}
					}
					return putsPrefix("set/")(b) || deletesPrefix("set/")(b)
				})
			}

			// Add.
			armSet()
			_, err := m.Add(e2eConf(t, "Added", a, b))
			require.Error(t, err)
			waitUnfenced(t, m)
			_, ok := m.Status(fxcm.SetKey{Name: "Added"})
			assert.Equal(t, tc.landed, ok, "memory follows the store")
			if !tc.landed {
				cfg, err := m.Add(e2eConf(t, "Added", a, b))
				require.NoError(t, err)
				assert.Equal(t, uint32(1), cfg.Version())
			}
			g := onlySet(t, mem).Generation
			if !tc.landed {
				assert.Greater(t, g, lost, "the generation of the lost write is not reused")
			}
			k := fxcm.SetKey{Name: "Added"}

			// CommitEdit.
			e, err := m.StartEdit(k, "e")
			require.NoError(t, err)
			e.Conf().Connections[0].Endpoint1.ConfigurationData[0].Value = ua.MustVariant(3.5)
			armSet()
			_, _, err = m.CommitEdit(k, "e")
			require.Error(t, err)
			waitUnfenced(t, m)
			c, _ := m.Config(k)
			if tc.landed {
				assert.Equal(t, uint32(2), c.Version(), "the landed Version is the set's")
				// The commit whose acknowledgement was lost ended its
				// edit, exactly once: CommitUpdates again is no new
				// Version or generation.
				g := onlySet(t, mem).Generation
				_, ok, err := m.CommitEdit(k, "e")
				require.NoError(t, err)
				assert.False(t, ok, "the set is not in edit")
				c, _ = m.Config(k)
				assert.Equal(t, uint32(2), c.Version())
				assert.Equal(t, g, onlySet(t, mem).Generation)
				open, err := m.DiscardEdit(k, "e")
				require.NoError(t, err)
				assert.False(t, open)
			} else {
				assert.Equal(t, uint32(1), c.Version())
				_, ok, err := m.CommitEdit(k, "e")
				require.NoError(t, err, "the edit stays open")
				require.True(t, ok)
				assert.Greater(t, onlySet(t, mem).Generation, lost)
			}

			// Replace: the switch write.
			res := process(t, m, uafx.ActionEstablishConnectionsEnabled, k)
			require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
			armSet()
			_, err = m.Replace(context.Background(), e2eConf(t, "Added", a, b))
			require.Error(t, err)
			waitUnfenced(t, m)
			st, _ := m.Status(k)
			assert.Empty(t, st.Endpoints, "the closes completed")
			c, _ = m.Config(k)
			if tc.landed {
				assert.Equal(t, uint32(1), c.Version(), "the replacement")
				assert.Empty(t, storedKeys(t, mem, "run/"))
			} else {
				assert.Equal(t, uint32(2), c.Version(), "the old set stays")
				w := owedWork(st.Recovery.Owed, fxcm.OwedSetChange)
				require.NotNil(t, w, "its switch is owed: %+v", st.Recovery.Owed)
				require.Len(t, w.Changes, 1)
				assert.Equal(t, uafx.ElementReplace, w.Changes[0].Op)
				// Owed work blocks what would act on it.
				_, err = m.Replace(context.Background(), e2eConf(t, "Added", a, b))
				requireInvalidState(t, err)
				requireInvalidState(t, m.Remove(context.Background(), k))
				return
			}

			// Remove.
			armSet()
			require.Error(t, m.Remove(context.Background(), k))
			waitUnfenced(t, m)
			_, ok = m.Status(k)
			assert.False(t, ok, "the landed removal")
			assert.Empty(t, stored[fxcm.StoredSet](t, mem, "set/"))
		})
	}
}

// TestStoreOwedEnforcedE2E (design §6.3): a call whose completion was not
// written owes its intent, live and after a restart: nothing that acts on
// the endpoints of the set runs, closes (RemoveConnections, Reconcile) and
// Settle included, until recovery (C3.3). A restarted Manager holds the
// Names of the intent with Unverified records.
func TestStoreOwedEnforcedE2E(t *testing.T) {
	t.Parallel()
	a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
	mem := &fxstore.MemoryStore{}
	f := &failing{Store: mem}
	m := newManager(t, fxcm.Options{Store: f})
	conf := e2eConf(t, "Owed", a, b)
	conf.RollbackOnError = false
	cfg, err := m.Add(conf)
	require.NoError(t, err)
	k := cfg.Key()
	f.arm(storetest.FailLost, func(b fxstore.Batch) bool {
		return deletesPrefix("call/")(b) && putsPrefix("ep/")(b)
	})
	res := process(t, m, uafx.ActionEstablishConnectionsEnabled, k)
	require.Equal(t, fxcm.StateError, res.State)
	waitUnfenced(t, m)

	check := func(m *fxcm.Manager) {
		t.Helper()
		st, _ := m.Status(k)
		w := owedWork(st.Recovery.Owed, fxcm.OwedCall)
		require.NotNil(t, w, "%+v", st.Recovery.Owed)
		assert.NotEmpty(t, w.Names)
		started := m.Process(uafx.ActionEstablishConnectionsEnabled, k)
		require.Len(t, started, 1)
		requireInvalidState(t, started[0].Err)
		_, err := m.Replace(context.Background(), conf)
		requireInvalidState(t, err)
		requireInvalidState(t, m.Remove(context.Background(), k))
		// Closes and verdicts too: whether they conflict with the
		// obligation is what recovery proves (C3.3).
		requireInvalidState(t, m.Reconcile(k).Err)
		started = m.Process(uafx.ActionRemoveConnections, k)
		requireInvalidState(t, started[0].Err)
		for _, e := range st.Endpoints {
			requireInvalidState(t, m.Settle(k, e.Endpoint, fxcm.SettleForeign))
		}
		assert.Zero(t, m.Counters().CloseCallCount, "no close while the set owes work")
	}
	check(m)
	require.NoError(t, m.Close())

	m2 := newManager(t, fxcm.Options{Store: mem})
	st, _ := m2.Status(k)
	names := map[string]bool{}
	for _, e := range st.Endpoints {
		assert.Equal(t, fxcm.Unverified, e.Class)
		names[e.Name] = true
	}
	w := owedWork(st.Recovery.Owed, fxcm.OwedCall)
	require.NotNil(t, w)
	for _, n := range w.Names {
		assert.True(t, names[n], "the Name %s of the intent is held", n)
	}
	check(m2)
}

// TestStoreRollbackObligationE2E (design §6.3): a rollback whose
// rollback-required phase is not written sends no close and owes the
// rollback; a rollback whose close fails keeps its run record, phase
// rollback-required, after the run.
func TestStoreRollbackObligationE2E(t *testing.T) {
	t.Parallel()
	t.Run("phase not written", func(t *testing.T) {
		t.Parallel()
		a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
		mem := &fxstore.MemoryStore{}
		f := &failing{Store: mem}
		m := newManager(t, fxcm.Options{Store: f})
		conf := e2eConf(t, "NoPhase", a, b)
		conf.Connections[0].Endpoint2.ConfigurationData[0].Value = ua.MustVariant("not a Double")
		cfg, err := m.Add(conf)
		require.NoError(t, err)
		f.arm(storetest.FailNotCommitted, func(b fxstore.Batch) bool {
			for key, v := range b.Puts {
				if strings.HasPrefix(key, "cm/run/") {
					r, err := fxcm.DecodeStored[fxcm.StoredRun](v)
					if err == nil && r.Phase == fxcm.PhaseRollbackRequired {
						return true
					}
				}
			}
			return false
		})
		res := process(t, m, uafx.ActionEstablishConnectionsEnabled, cfg.Key())
		require.Equal(t, fxcm.StateError, res.State)
		require.Equal(t, 1, f.hit)
		assert.Zero(t, m.Counters().CloseCallCount, "no rollback close without its durable obligation")
		assert.NotEmpty(t, a.endpoints(), "the endpoint the run made stays")
		assert.Len(t, storedKeys(t, mem, "run/"), 1)
		st, _ := m.Status(cfg.Key())
		assert.True(t, owesKind(st.Recovery.Owed, fxcm.OwedRollback), "%+v", st.Recovery.Owed)
	})
	t.Run("close fails", func(t *testing.T) {
		t.Parallel()
		a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
		mem := &fxstore.MemoryStore{}
		d := newHookDialer()
		d.hook = func(_ fxcm.ServerAddress, req *ua.CallMethodRequest) (bool, error) {
			if len(req.InputArguments) == 2 {
				return false, ua.StatusBadCommunicationError // CloseConnections
			}
			return true, nil
		}
		m := newManager(t, fxcm.Options{Store: mem, Dialer: d})
		conf := e2eConf(t, "NoClose", a, b)
		conf.Connections[0].Endpoint2.ConfigurationData[0].Value = ua.MustVariant("not a Double")
		cfg, err := m.Add(conf)
		require.NoError(t, err)
		res := process(t, m, uafx.ActionEstablishConnectionsEnabled, cfg.Key())
		require.Equal(t, fxcm.StateError, res.State)
		assert.False(t, res.RollbackComplete)
		runs := stored[fxcm.StoredRun](t, mem, "run/")
		require.Len(t, runs, 1, "the run ended, its obligation did not")
		for _, r := range runs {
			assert.Equal(t, fxcm.PhaseRollbackRequired, r.Phase)
		}
		st, _ := m.Status(cfg.Key())
		assert.True(t, owesKind(st.Recovery.Owed, fxcm.OwedRollback), "%+v", st.Recovery.Owed)
	})
}

func owesKind(ws []fxcm.OwedWork, k fxcm.OwedKind) bool { return owedWork(ws, k) != nil }

// owedWork returns the first owed work of kind k.
func owedWork(ws []fxcm.OwedWork, k fxcm.OwedKind) *fxcm.OwedWork {
	for i := range ws {
		if ws[i].Kind == k {
			return &ws[i]
		}
	}
	return nil
}

// TestStoreUpdateTransactionE2E (design §6.2): a complete Update that
// closes sets journals the whole change, with the generations it
// reserves, before its first close; the switch takes them. When the switch
// is not written the change is owed, its Add key is held, and the
// generations are not reused.
func TestStoreUpdateTransactionE2E(t *testing.T) {
	t.Parallel()
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "switched", true: "switch lost"}[fail], func(t *testing.T) {
			t.Parallel()
			a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
			mem := &fxstore.MemoryStore{}
			f := &failing{Store: mem}
			m := newManager(t, fxcm.Options{Store: f})
			cfg, err := m.Add(e2eConf(t, "Old", a, b))
			require.NoError(t, err)
			res := process(t, m, uafx.ActionEstablishConnectionsEnabled, cfg.Key())
			require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
			var tx *fxcm.StoredTx
			var mu sync.Mutex
			f.arm(storetest.FailLost, func(b fxstore.Batch) bool {
				mu.Lock()
				defer mu.Unlock()
				for key, v := range b.Puts {
					if strings.HasPrefix(key, "cm/tx/") && tx == nil {
						var err error
						tx, err = fxcm.DecodeStored[fxcm.StoredTx](v)
						require.NoError(t, err)
					}
				}
				return fail && (putsPrefix("set/")(b) || deletesPrefix("set/")(b))
			})
			ops := []fxcm.Operation{{Op: uafx.ElementReplace, Conf: e2eConf(t, "Old", a, b)}, {Op: uafx.ElementAdd, Conf: e2eConf(t, "New", a, b)}}
			applied, results := m.Update(context.Background(), ops, true)
			mu.Lock()
			require.NotNil(t, tx, "the change is journaled before the closes")
			require.Len(t, tx.Ops, 2)
			assert.NotZero(t, tx.Ops[0].Old)
			assert.NotZero(t, tx.Ops[0].New)
			assert.NotZero(t, tx.Ops[1].New)
			assert.Zero(t, tx.Ops[1].Old)
			mu.Unlock()
			if !fail {
				require.True(t, applied, "%v", results)
				sets := stored[fxcm.StoredSet](t, mem, "set/")
				gens := map[string]uint64{}
				for _, r := range sets {
					gens[r.Name] = r.Generation
				}
				assert.Equal(t, map[string]uint64{"Old": tx.Ops[0].New, "New": tx.Ops[1].New}, gens, "the reserved generations")
				assert.Empty(t, storedKeys(t, mem, "tx/"))
				assert.Empty(t, storedKeys(t, mem, "run/"))
				return
			}
			require.False(t, applied)
			waitUnfenced(t, m)
			_, ok := m.Status(fxcm.SetKey{Name: "New"})
			require.False(t, ok)
			st, _ := m.Status(fxcm.SetKey{Name: "Old"})
			w := owedWork(st.Recovery.Owed, fxcm.OwedSetChange)
			require.NotNil(t, w, "%+v", st.Recovery.Owed)
			assert.Len(t, w.Changes, 2, "the parent transaction")
			_, err = m.Add(e2eConf(t, "New", a, b))
			requireInvalidState(t, err)
			ss, _ := m.StoreStatus()
			assert.Contains(t, ss.Orphaned, "New")
			_, err = m.Add(e2eConf(t, "Other", a, b))
			require.NoError(t, err)
			for _, r := range stored[fxcm.StoredSet](t, mem, "set/") {
				if r.Name == "Other" {
					assert.Greater(t, r.Generation, max(tx.Ops[0].New, tx.Ops[1].New), "reserved generations are not reused")
				}
			}
		})
	}
}

// mangleCall replaces the result of the first call with method input
// arguments (EstablishConnections or CloseConnections), after the
// AutomationComponent ran it, with mangle's.
func mangleCall(method func(*ua.CallMethodRequest) bool, mangle func(out *ua.CallMethodResult) *ua.CallMethodResult) func(fxcm.ServerAddress, *ua.CallMethodRequest, *ua.CallMethodResult) (*ua.CallMethodResult, error) {
	var mu sync.Mutex
	done := false
	return func(_ fxcm.ServerAddress, req *ua.CallMethodRequest, out *ua.CallMethodResult) (*ua.CallMethodResult, error) {
		mu.Lock()
		defer mu.Unlock()
		if done || !method(req) {
			return out, nil
		}
		done = true
		return mangle(out), nil
	}
}

// creates is an EstablishConnections that creates endpoints (step 3,
// E.2.2.2), the first call that changes what an AutomationComponent has
// (ReserveCommunicationIds before it reserves for the session only, CL-2).
func creates(req *ua.CallMethodRequest) bool {
	return len(req.InputArguments) > 2 && commandMask(req)&uafx.CreateConnectionEndpointCmd != 0
}

// closes is a CloseConnections (two input arguments, Table 23).
func closes(req *ua.CallMethodRequest) bool { return len(req.InputArguments) == 2 }

// TestStoreAmbiguousE2E (design §6.7, decision C3-D13): a result that does
// not prove the outcome of a state-changing call — an ambiguous status of
// the call or of an operation, a result that does not decode or does not
// answer the call — leaves its intent in the store and its Names
// Unresolved; a definite failure does not.
func TestStoreAmbiguousE2E(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		method    func(*ua.CallMethodRequest) bool
		mangle    func(out *ua.CallMethodResult) *ua.CallMethodResult
		ambiguous bool
	}{
		{"call Bad_InternalError", creates, func(*ua.CallMethodResult) *ua.CallMethodResult {
			return &ua.CallMethodResult{StatusCode: ua.StatusBadInternalError}
		}, true},
		{"call Bad_Timeout", creates, func(*ua.CallMethodResult) *ua.CallMethodResult {
			return &ua.CallMethodResult{StatusCode: ua.StatusBadTimeout}
		}, true},
		{"call Bad_ResourceUnavailable", creates, func(*ua.CallMethodResult) *ua.CallMethodResult {
			return &ua.CallMethodResult{StatusCode: ua.StatusBadResourceUnavailable}
		}, false},
		{"output does not decode", creates, func(out *ua.CallMethodResult) *ua.CallMethodResult {
			out.OutputArguments = []*ua.Variant{ua.MustVariant("x")}
			return out
		}, true},
		{"too few results", creates, func(out *ua.CallMethodResult) *ua.CallMethodResult {
			out.OutputArguments[1] = ua.MustVariant([]*ua.ExtensionObject{}) // ConnectionEndpointConfigurationResults
			return out
		}, true},
		{"close Bad_InternalError", closes, func(*ua.CallMethodResult) *ua.CallMethodResult {
			return &ua.CallMethodResult{StatusCode: ua.StatusBadInternalError}
		}, true},
		{"close result Bad_InternalError", closes, func(out *ua.CallMethodResult) *ua.CallMethodResult {
			if rs, ok := out.OutputArguments[0].Value().([]ua.StatusCode); ok {
				for i := range rs {
					rs[i] = ua.StatusBadInternalError
				}
				out.OutputArguments[0] = ua.MustVariant(rs)
			}
			return out
		}, true},
		{"close Bad_NotSupported", closes, func(*ua.CallMethodResult) *ua.CallMethodResult {
			return &ua.CallMethodResult{StatusCode: ua.StatusBadNotSupported}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
			mem := &fxstore.MemoryStore{}
			d := newHookDialer()
			m := newManager(t, fxcm.Options{Store: mem, Dialer: d})
			conf := e2eConf(t, "Ambiguous", a, b)
			conf.RollbackOnError = false
			cfg, err := m.Add(conf)
			require.NoError(t, err)
			k := cfg.Key()
			if tc.method(&ua.CallMethodRequest{InputArguments: make([]*ua.Variant, 2)}) {
				res := process(t, m, uafx.ActionEstablishConnectionsEnabled, k)
				require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
				d.result = mangleCall(tc.method, tc.mangle)
				res = process(t, m, uafx.ActionRemoveConnections, k)
				require.Equal(t, fxcm.StateError, res.State)
			} else {
				d.result = mangleCall(tc.method, tc.mangle)
				res := process(t, m, uafx.ActionEstablishConnectionsEnabled, k)
				require.Equal(t, fxcm.StateError, res.State)
			}
			calls := stored[fxcm.StoredCall](t, mem, "call/")
			st, _ := m.Status(k)
			if !tc.ambiguous {
				assert.Empty(t, calls, "a definite failure completes its intent")
				assert.Empty(t, st.Recovery.Owed, "%+v", st.Recovery.Owed)
				return
			}
			require.Len(t, calls, 1, "the intent of the unproven call stays")
			assert.True(t, owesKind(st.Recovery.Owed, fxcm.OwedCall), "%+v", st.Recovery.Owed)
			started := m.Process(uafx.ActionEstablishConnectionsEnabled, k)
			requireInvalidState(t, started[0].Err)
			if !tc.method(&ua.CallMethodRequest{InputArguments: make([]*ua.Variant, 2)}) {
				assert.True(t, hasClass(st, fxcm.Unresolved), "%+v", st.Endpoints)
			}
		})
	}
}

func hasClass(st fxcm.Status, c fxcm.Ownership) bool {
	for _, e := range st.Endpoints {
		if e.Class == c {
			return true
		}
	}
	return false
}

// TestStorePersistentACE2E (decision C3-D13) against real persistent
// AutomationComponents (C3.1): when the store of B has an unknown outcome
// B answers Bad_InternalError and may restore the endpoint later, so its
// Name stays Unresolved and the intent owed, even though B shows nothing
// now; when B's store definitely did not commit (Bad_ResourceUnavailable)
// the failure is definite and nothing is owed.
func TestStorePersistentACE2E(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		fault     storetest.Fault
		ambiguous bool
	}{{"unknown outcome", storetest.FailLost, true}, {"not committed", storetest.FailNotCommitted, false}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			bs := &failing{Store: &fxstore.MemoryStore{}}
			a := newAC(t, "a", fxserver.ConnectionOptions{Store: &fxstore.MemoryStore{}})
			b := newAC(t, "b", fxserver.ConnectionOptions{Store: bs})
			mem := &fxstore.MemoryStore{}
			m := newManager(t, fxcm.Options{Store: mem})
			conf := e2eConf(t, "Persistent", a, b)
			conf.RollbackOnError = false
			for _, ep := range []*uafx.ConnectionEndpointConfigurationConf{conf.Connections[0].Endpoint1, conf.Connections[0].Endpoint2} {
				ep.IsPersistent = true
			}
			cfg, err := m.Add(conf)
			require.NoError(t, err)
			k := cfg.Key()
			bs.arm(tc.fault, func(fxstore.Batch) bool { return true })
			res := process(t, m, uafx.ActionEstablishConnectionsEnabled, k)
			require.Equal(t, fxcm.StateError, res.State)
			require.Equal(t, 1, bs.hit, "B's store write failed")
			assert.Empty(t, b.endpoints(), "B undid the call")
			st, _ := m.Status(k)
			var bClass *fxcm.Ownership
			for _, e := range st.Endpoints {
				if e.Name == "ToA" {
					c := e.Class
					bClass = &c
				}
			}
			calls := stored[fxcm.StoredCall](t, mem, "call/")
			if !tc.ambiguous {
				assert.Nil(t, bClass, "absent, proven: %+v", st.Endpoints)
				assert.Empty(t, calls)
				return
			}
			require.NotNil(t, bClass, "B's Name is held: %+v", st.Endpoints)
			assert.Equal(t, fxcm.Unresolved, *bClass)
			require.Len(t, calls, 1)
			for _, c := range calls {
				assert.Equal(t, []string{"ToA"}, c.Names)
				assert.Equal(t, b.uri, c.Server.ApplicationURI)
			}
			_, err = m.Replace(context.Background(), conf)
			requireInvalidState(t, err)
			// No Reconcile may forget it either.
			requireInvalidState(t, m.Reconcile(k).Err)
			st, _ = m.Status(k)
			assert.True(t, hasName(st, "ToA", fxcm.Unresolved), "%+v", st.Endpoints)
		})
	}
}

func hasName(st fxcm.Status, name string, c fxcm.Ownership) bool {
	for _, e := range st.Endpoints {
		if e.Name == name && e.Class == c {
			return true
		}
	}
	return false
}

// TestStorePartialOutcomeE2E (decision C3-D13, second C3.2 review): a
// definite failure of an operation does not prove it had no effect. The
// AutomationComponent created the endpoint but the result says
// Bad_ResourceUnavailable, without a NodeId: the Manager browses for the
// Name and finds the endpoint. With ExclusiveApplicationURI that proves it
// ours (ResolveLostResponse): it is recorded, the rollback closes it and
// the intent completes. Without, it is Unresolved: reported, never
// closed, the intent and the rollback owed.
func TestStorePartialOutcomeE2E(t *testing.T) {
	t.Parallel()
	for _, exclusive := range []bool{true, false} {
		t.Run(map[bool]string{true: "proven ours", false: "unproven"}[exclusive], func(t *testing.T) {
			t.Parallel()
			a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
			mem := &fxstore.MemoryStore{}
			d := newHookDialer()
			m := newManager(t, fxcm.Options{Store: mem, Dialer: d, ExclusiveApplicationURI: exclusive})
			cfg, err := m.Add(e2eConf(t, "Partial", a, b))
			require.NoError(t, err)
			d.result = mangleCall(creates, func(out *ua.CallMethodResult) *ua.CallMethodResult {
				res, err := uafx.DecodeEstablishConnectionsResult(out.OutputArguments, e2eData)
				require.NoError(t, err)
				require.NotEmpty(t, res.ConnectionEndpointConfigurationResults)
				res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointResult = ua.StatusBadResourceUnavailable
				res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointID = nil
				out.OutputArguments, err = uafx.EncodeEstablishConnectionsResult(res, e2eData)
				require.NoError(t, err)
				return out
			})
			res := process(t, m, uafx.ActionEstablishConnectionsEnabled, cfg.Key())
			require.Equal(t, fxcm.StateError, res.State)
			st, _ := m.Status(cfg.Key())
			left := len(a.endpoints()) + len(b.endpoints())
			if exclusive {
				assert.Zero(t, left, "the endpoint the result denied was found and rolled back")
				assert.Empty(t, storedKeys(t, mem, "call/"), "every Name proven: no intent left")
				assert.Empty(t, st.Recovery.Owed, "%+v", st.Recovery.Owed)
				return
			}
			assert.Equal(t, 1, left, "found, not proven ours: never closed")
			assert.True(t, hasClass(st, fxcm.Unresolved), "%+v", st.Endpoints)
			assert.Len(t, storedKeys(t, mem, "call/"), 1, "the evidence of the partial outcome stays")
			assert.True(t, owesKind(st.Recovery.Owed, fxcm.OwedCall), "%+v", st.Recovery.Owed)
			assert.True(t, owesKind(st.Recovery.Owed, fxcm.OwedRollback), "%+v", st.Recovery.Owed)
		})
	}
}
