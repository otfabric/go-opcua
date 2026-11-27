// SPDX-License-Identifier: MIT

package fxcm_test

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxcm"
	"github.com/otfabric/go-opcua/uafx/fxserver"
	"github.com/otfabric/go-opcua/uafx/fxstore"
)

// The re-proof of the outcome of an interrupted call (design
// docs/design/uafx-persistent-connections.md §6.3, §6.5, decision C3-D13):
// ownership is not an outcome. A call whose response was lost is decided by
// its postcondition on the server its intent names, and an operation whose
// postcondition does not hold is never sent again by the Manager: its
// endpoints stay Unresolved and its intent stays, until new evidence or
// Settle decides them.

// enables is an EstablishConnections with EnableCommunicationCmd alone
// (§6.2.4.3.10.2).
func enables(req *ua.CallMethodRequest) bool {
	return len(req.InputArguments) > 2 && commandMask(req) == uafx.EnableCommunicationCmd
}

// disables is a CloseConnections with Remove FALSE (§6.2.5.2).
func disables(req *ua.CallMethodRequest) bool {
	if len(req.InputArguments) != 2 {
		return false
	}
	remove, ok := req.InputArguments[1].Value().(bool)
	return ok && !remove
}

// lose makes d lose the response of the first call match finds; the call
// is made when send is set. It returns the counter of the calls match
// finds, the lost one included.
func lose(d *hookDialer, match func(*ua.CallMethodRequest) bool, send bool) *atomic.Int32 {
	var n atomic.Int32
	d.hook = func(_ fxcm.ServerAddress, req *ua.CallMethodRequest) (bool, error) {
		if !match(req) {
			return true, nil
		}
		if n.Add(1) == 1 {
			return send, ua.StatusBadCommunicationError
		}
		return true, nil
	}
	return &n
}

// callsOfKind returns the intents of kind k in mem.
func callsOfKind(t *testing.T, mem fxstore.Store, k uint8) int {
	t.Helper()
	n := 0
	for _, c := range stored[fxcm.StoredCall](t, mem, "call/") {
		if c.Kind == k {
			n++
		}
	}
	return n
}

// TestLostEnableE2E: the response of the EnableCommunicationCmd of an
// adoption (§6.6) is lost. Its intent names the endpoints it addresses
// (CallEnable), and they are Unresolved until the next run re-proves the
// outcome, live or after a restart: communication enabled, the
// postcondition, makes them KnownOwned again; still disabled, they stay
// Unresolved and nothing enables them again.
func TestLostEnableE2E(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		sent    bool
		restart bool
	}{
		{"done", true, false},
		{"done, restart", true, true},
		{"not done", false, false},
		{"not done, restart", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
			// RollbackOnError FALSE: the endpoint of the other AC stays.
			mem, k, nodes := establishedWith(t, a, b, fxcm.Options{}, false)
			d := newHookDialer()
			opts := fxcm.Options{Store: mem, Dialer: d, Verify: fxcm.VerifyOptions{Manual: true}}
			m := newManager(t, opts)
			res := process(t, m, uafx.ActionEstablishConnectionsDisabled, k)
			require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
			require.Len(t, res.Adopted, 2)

			n := lose(d, enables, tc.sent)
			res = process(t, m, uafx.ActionEstablishConnectionsEnabled, k)
			require.Equal(t, fxcm.StateError, res.State)
			require.Len(t, res.Adopted, 2)
			assert.Positive(t, callsOfKind(t, mem, fxcm.CallEnable), "the intent names the endpoints it enables")
			st, _ := m.Status(k)
			assert.True(t, hasClass(st, fxcm.Unresolved), "%+v", st.Endpoints)

			if tc.restart {
				require.NoError(t, m.Close())
				m = newManager(t, opts)
			}
			sent := n.Load()
			res = process(t, m, uafx.ActionEstablishConnectionsEnabled, k)
			assert.Equal(t, nodeSet(nodes), nodeSet(endpointsOf(a, b)), "nothing closed or made again")
			if tc.sent {
				// Enabled: the outcome is proven; this run adopts and
				// enables them as its own action.
				require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
				assert.Zero(t, callsOfKind(t, mem, fxcm.CallEnable))
				assert.Len(t, res.Adopted, 2)
				return
			}
			assert.Equal(t, fxcm.StateError, res.State)
			assert.Positive(t, callsOfKind(t, mem, fxcm.CallEnable), "the intent stays")
			st, _ = m.Status(k)
			assert.True(t, hasClass(st, fxcm.Unresolved), "%+v", st.Endpoints)
			assert.Empty(t, res.Adopted, "an Unresolved endpoint is never adopted")
			// The enablement of the endpoint b's intent holds is not sent
			// again (a's, a separate call, completed).
			assert.LessOrEqual(t, n.Load()-sent, int32(1))
		})
	}
}

// TestLostDisableE2E: the response of a CloseConnections with Remove FALSE
// is lost. Disabled, the postcondition, the endpoint is KnownOwned again;
// still enabled, it stays Unresolved and is never disabled again by the
// Manager.
func TestLostDisableE2E(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		sent bool
	}{{"done", true}, {"not done", false}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
			mem, k, _ := establishedWith(t, a, b, fxcm.Options{}, false)
			d := newHookDialer()
			n := lose(d, disables, tc.sent)
			opts := fxcm.Options{Store: mem, Dialer: d, Verify: fxcm.VerifyOptions{Manual: true}}
			m := newManager(t, opts)
			res := process(t, m, uafx.ActionDisableConnections, k)
			require.Equal(t, fxcm.StateError, res.State)
			st, _ := m.Status(k)
			require.True(t, hasClass(st, fxcm.Unresolved), "%+v", st.Endpoints)
			require.Positive(t, callsOfKind(t, mem, fxcm.CallClose))

			require.NoError(t, m.Close())
			m = newManager(t, opts)
			before := n.Load()
			res = process(t, m, uafx.ActionDisableConnections, k)
			st, _ = m.Status(k)
			if tc.sent {
				require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
				assert.False(t, hasClass(st, fxcm.Unresolved), "%+v", st.Endpoints)
				assert.Zero(t, callsOfKind(t, mem, fxcm.CallClose))
				return
			}
			assert.Equal(t, fxcm.StateError, res.State)
			assert.True(t, hasClass(st, fxcm.Unresolved), "%+v", st.Endpoints)
			assert.Positive(t, callsOfKind(t, mem, fxcm.CallClose), "the intent stays")
			// Only the endpoint whose disablement is proven is disabled
			// again by this run; the other is not touched.
			assert.LessOrEqual(t, n.Load()-before, int32(1))
		})
	}
}

// TestLostEstablishReproofE2E: the response of the EstablishConnections
// that created an endpoint is lost, and the run could not re-prove it
// (C2 §5.4). After a restart its intent decides it (§6.5) only on the
// server it was sent to and with the configuration it sent: another server
// at the address, or a configuration changed since, leave it Unresolved.
func TestLostEstablishReproofE2E(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		change func(t *testing.T, b *ac, d *hookDialer)
		want   fxcm.Ownership
	}{
		{"proven", func(*testing.T, *ac, *hookDialer) {}, fxcm.KnownOwned},
		{"another server", func(_ *testing.T, _ *ac, d *hookDialer) {
			d.ident = func(id fxcm.ServerIdentity) fxcm.ServerIdentity {
				id.ApplicationURI = "urn:go-opcua:fxcm:replaced"
				return id
			}
		}, fxcm.Unresolved},
		{"configuration changed", func(t *testing.T, b *ac, _ *hookDialer) {
			setProperty(t, b, ownEndpoint(t, b), "CleanupTimeout", 7.0)
		}, fxcm.Unresolved},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
			mem := &fxstore.MemoryStore{}
			d := newHookDialer()
			var lost atomic.Bool
			d.hook = func(addr fxcm.ServerAddress, req *ua.CallMethodRequest) (bool, error) {
				if addr.Address == b.url && creates(req) && lost.CompareAndSwap(false, true) {
					return true, ua.StatusBadCommunicationError
				}
				return true, nil
			}
			// The re-proof of the run cannot browse b after the loss.
			d.fault = func(method string, addr fxcm.ServerAddress) error {
				if method == "Browse" && addr.Address == b.url && lost.Load() {
					return ua.StatusBadCommunicationError
				}
				return nil
			}
			m := newManager(t, fxcm.Options{Store: mem, Dialer: d, ExclusiveApplicationURI: true})
			conf := e2eConf(t, "Lost", a, b)
			conf.RollbackOnError = false
			cfg, err := m.Add(conf)
			require.NoError(t, err)
			res := process(t, m, uafx.ActionEstablishConnectionsEnabled, cfg.Key())
			require.Equal(t, fxcm.StateError, res.State)
			require.Equal(t, []string{"ToA"}, b.endpoints(), "made, its response lost")
			require.Equal(t, 1, callsOfKind(t, mem, fxcm.CallEstablish))
			require.NoError(t, m.Close())

			d2 := newHookDialer()
			tc.change(t, b, d2)
			m2 := newManager(t, fxcm.Options{Store: mem, Dialer: d2, ExclusiveApplicationURI: true, Verify: fxcm.VerifyOptions{RetryInitial: 5 * time.Millisecond}})
			var st fxcm.Status
			require.Eventually(t, func() bool {
				st, _ = m2.Status(cfg.Key())
				return !hasClass(st, fxcm.Unverified)
			}, 10*time.Second, 5*time.Millisecond)
			for _, e := range st.Endpoints {
				if e.ServerURI == b.uri {
					assert.Equal(t, tc.want, e.Class, "%+v", e)
				}
			}
			if tc.want == fxcm.KnownOwned {
				assert.Zero(t, callsOfKind(t, mem, fxcm.CallEstablish), "the intent is complete")
			} else {
				assert.Equal(t, 1, callsOfKind(t, mem, fxcm.CallEstablish), "the intent stays")
			}
			assert.Equal(t, []string{"ToA"}, b.endpoints(), "nothing closed")
		})
	}
}
