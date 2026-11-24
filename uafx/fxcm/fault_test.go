// SPDX-License-Identifier: MIT

package fxcm

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/fxtest"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxserver"
)

// faults counts the services the sessions of a hookDialer use, and fails
// one: the n-th use of method (from 1).
type faults struct {
	mu     sync.Mutex
	counts map[string]int
	method string
	n      int
	hit    bool
}

func (f *faults) fault(method string, _ ServerAddress) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counts[method]++
	if method == f.method && f.counts[method] == f.n {
		f.hit = true
		return fmt.Errorf("injected: %w", ua.StatusBadCommunicationError)
	}
	return nil
}

// cleanAC closes the endpoints a test left on x, but Preset.
func cleanAC(t *testing.T, x *ac) {
	t.Helper()
	var eps []*ua.NodeID
	for _, e := range x.conns.Endpoints() {
		if !e.Equal(x.id(fxtest.ConnPreset)) {
			eps = append(eps, e)
		}
	}
	if len(eps) == 0 {
		return
	}
	c := testutil.NewTestClient(t, x.url)
	_, _, err := uafx.CloseConnections(context.Background(), c, x.id(fxtest.ConnCtl), eps, true)
	require.NoError(t, err)
	_ = c.Close(context.Background())
}

// TestFaults fails each use of each service of a run in turn (a dial, the
// NamespaceArray, Read, Browse, TranslateBrowsePaths, Call before it is
// sent). Every run ends: in Error when the fault mattered, with the
// endpoints it made rolled back, or in Ready.
func TestFaults(t *testing.T) {
	t.Parallel()
	verifier := func(context.Context, *ua.NodeID, uafx.AssetVerificationMode, []*ua.KeyValuePair, []*uafx.NodeIDValuePair) (uafx.AssetVerificationResult, []ua.StatusCode, []ua.StatusCode, ua.StatusCode) {
		return uafx.AssetVerificationMatch, nil, nil, ua.StatusOK
	}
	a := newAC(t, "a", fxserver.ConnectionOptions{AssetVerifier: verifier})
	b := newACWith(t, "b", fxserver.ConnectionOptions{MaxConnectionsPerCall: 1, CommandBundleRequired: true}, capabilitiesNodeSet)
	conf := pathsConf(t, a, b)

	run := func(f *faults, action uafx.FxProcess) (*RunResult, *Manager, SetKey) {
		d := newHookDialer()
		d.fault = f.fault
		m := newManager(t, Options{Dialer: d, ExclusiveApplicationURI: true})
		cfg, err := m.Add(conf)
		require.NoError(t, err)
		return process(t, m, action, cfg.Key()), m, cfg.Key()
	}
	// The baseline: how often a good establish and remove use each service.
	base := &faults{counts: map[string]int{}}
	res, m, k := run(base, uafx.ActionEstablishConnectionsEnabled)
	require.Equal(t, StateReady, res.State, "%+v", res.Failures)
	res = process(t, m, uafx.ActionRemoveConnections, k)
	require.Equal(t, StateReady, res.State, "%+v", res.Failures)
	require.NoError(t, m.Close())
	counts := base.counts
	t.Logf("services: %v", counts)

	for _, method := range []string{"Dial", "NamespaceArray", "Read", "Browse", "TranslateBrowsePaths", "Call"} {
		for n := 1; n <= counts[method]; n++ {
			f := &faults{counts: map[string]int{}, method: method, n: n}
			res, m, k := run(f, uafx.ActionEstablishConnectionsEnabled)
			name := fmt.Sprintf("%s#%d", method, n)
			switch res.State {
			case StateError:
				assert.NotEmpty(t, res.Failures, name)
				for _, fl := range res.Failures {
					assert.NotEqual(t, ua.StatusGood, fl.Status, name)
				}
				// Nothing survives the rollback but what it could not close.
				st, _ := m.Status(k)
				if len(st.Endpoints) == 0 {
					assert.Empty(t, a.endpoints(), name)
					assert.Empty(t, b.endpoints(), name)
				}
			case StateReady:
				// The fault may hit the remove: its closes stay pending, and
				// the next remove closes them.
				res = process(t, m, uafx.ActionRemoveConnections, k)
				if res.State == StateError {
					assert.True(t, f.hit, name)
					for _, fl := range res.Failures {
						assert.Equal(t, uafx.FxErrorCloseConnectionError, fl.FxError, name)
					}
					res = process(t, m, uafx.ActionRemoveConnections, k)
				}
				assert.Equal(t, StateReady, res.State, "%s: remove: %+v", name, res.Failures)
				assert.Empty(t, a.endpoints(), name)
				assert.Empty(t, b.endpoints(), name)
			default:
				t.Fatalf("%s: state %v", name, res.State)
			}
			require.NoError(t, m.Close())
			cleanAC(t, a)
			cleanAC(t, b)
		}
	}
}

// TestLostResponses sends each call of a run but drops its response
// (design §5.4). With ExclusiveApplicationURI what the calls made is found
// again and owned: after the run, a Reconcile, and a remove where needed,
// nothing is left on the ACs.
func TestLostResponses(t *testing.T) {
	t.Parallel()
	a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
	conf := e2eConf(t, "Lost", a, b)
	for _, action := range []uafx.FxProcess{uafx.ActionEstablishConnectionsEnabled, uafx.ActionEstablishConnectionsDisabled} {
		for n := 1; n <= 6; n++ {
			name := fmt.Sprintf("%v call %d", action, n)
			d := newHookDialer()
			var calls atomic.Int32
			d.hook = func(addr ServerAddress, req *ua.CallMethodRequest) (bool, error) {
				if int(calls.Add(1)) == n {
					return true, ua.StatusBadTimeout
				}
				return false, nil
			}
			m := newManager(t, Options{Dialer: d, ExclusiveApplicationURI: true})
			cfg, err := m.Add(conf)
			require.NoError(t, err)
			k := cfg.Key()
			res := process(t, m, action, k)
			if res.State == StateReady {
				// The lost call was a close of a later run, or none.
				res = process(t, m, uafx.ActionRemoveConnections, k)
				if res.State == StateError {
					res = process(t, m, uafx.ActionRemoveConnections, k)
				}
				require.Equal(t, StateReady, res.State, "%s: %+v", name, res.Failures)
			} else {
				assert.Empty(t, res.Unresolved, name)
				st := m.Reconcile(k)
				require.NoError(t, st.Err, name)
				r, err := st.Run.Wait(context.Background())
				require.NoError(t, err)
				assert.Equal(t, StateReady, r.State, "%s: reconcile: %+v", name, r.Failures)
			}
			assert.Empty(t, a.endpoints(), name)
			assert.Empty(t, b.endpoints(), name)
			require.NoError(t, m.Close())
			cleanAC(t, a)
			cleanAC(t, b)
		}
	}
}

// TestEnableFaults fails each service in turn during an Enable run
// (§6.7.5.3.3) of a set established disabled: the run ends in Error with
// the failure on its endpoints, or in Ready when the fault did not matter,
// and the set is removed afterwards.
func TestEnableFaults(t *testing.T) {
	t.Parallel()
	a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
	conf := e2eConf(t, "EnableFaults", a, b)
	for _, method := range []string{"Dial", "NamespaceArray", "Read", "Browse", "TranslateBrowsePaths", "Call"} {
		f := &faults{counts: map[string]int{}}
		d := newHookDialer()
		d.fault = f.fault
		m := newManager(t, Options{Dialer: d})
		cfg, err := m.Add(conf)
		require.NoError(t, err)
		k := cfg.Key()
		res := process(t, m, uafx.ActionEstablishConnectionsDisabled, k)
		require.Equal(t, StateReady, res.State, "%s: %+v", method, res.Failures)
		// Drop the sessions so the Enable run dials again.
		m.pool.mu.Lock()
		open := map[ServerAddress]Session{}
		for addr, e := range m.pool.sessions {
			open[addr] = e.s
		}
		m.pool.mu.Unlock()
		for addr, s := range open {
			m.pool.drop(context.Background(), addr, s)
		}
		f.mu.Lock()
		f.counts, f.method, f.n = map[string]int{}, method, 1
		f.mu.Unlock()
		res = process(t, m, uafx.ActionEnableConnections, k)
		switch res.State {
		case StateError:
			assert.True(t, f.hit, method)
			require.NotEmpty(t, res.Failures, method)
			for _, fl := range res.Failures {
				assert.Contains(t, []uafx.FxError{uafx.FxErrorTargetServerConnectionError, uafx.FxErrorResolvingNamespacesError, uafx.FxErrorEnableCommunicationError}, fl.FxError, method)
			}
		case StateReady:
			// Only the NamespacePublicationDates may fail without failing
			// the run (they are read with Browse, TranslateBrowsePaths and Read).
			if f.hit {
				assert.Contains(t, []string{"Read", "Browse", "TranslateBrowsePaths"}, method)
			}
		default:
			t.Fatalf("%s: state %v", method, res.State)
		}
		res = process(t, m, uafx.ActionRemoveConnections, k)
		assert.Equal(t, StateReady, res.State, "%s: remove: %+v", method, res.Failures)
		require.NoError(t, m.Close())
		cleanAC(t, a)
		cleanAC(t, b)
	}
}
