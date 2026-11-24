// SPDX-License-Identifier: MIT

package fxcm

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

// offline is a Dialer that never connects: the Manager tests that need no
// server use it.
type offline struct{}

func (offline) Dial(context.Context, ServerAddress) (Session, error) {
	return nil, ua.StatusBadCommunicationError
}

func offlineManager(t *testing.T, opts Options) *Manager {
	t.Helper()
	opts.Dialer = offline{}
	return newManager(t, opts)
}

func named(name string) *uafx.ConnectionConfigurationSetConf {
	c := validConf()
	c.BrowseName = name
	return c
}

func TestNewOptions(t *testing.T) {
	t.Parallel()
	_, err := New(Options{ApplicationURI: cmURI})
	assert.ErrorIs(t, err, ua.StatusBadInvalidArgument)
	_, err = New(Options{Dialer: offline{}})
	assert.ErrorIs(t, err, ua.StatusBadInvalidArgument)
	m, err := New(Options{Dialer: offline{}, ApplicationURI: cmURI, Retry: &RetryPolicy{}, Monitor: &MonitorOptions{}})
	require.NoError(t, err)
	assert.Equal(t, DefaultCallTimeout, m.opts.CallTimeout)
	assert.Equal(t, DefaultRollbackTimeout, m.opts.RollbackTimeout)
	assert.Equal(t, DefaultParallelism, m.opts.Parallelism)
	assert.Equal(t, DefaultMaxConnectionConfigurationSets, m.opts.MaxConnectionConfigurationSets)
	assert.Equal(t, RetryPolicy{Initial: 1e9, Max: 1e9, Attempts: 1}, *m.opts.Retry)
	require.NoError(t, m.Close())
	require.NoError(t, m.Close(), "Close twice")
	_, err = m.Add(validConf())
	assert.ErrorIs(t, err, ua.StatusBadShutdown)
	assert.ErrorIs(t, m.Process(uafx.ActionEstablishConnections, KeyOf(validConf()))[0].Err, ua.StatusBadShutdown)
}

// TestSets: Add, Keys, Config, Replace, Remove and the limits (F.3.3.2,
// §6.7.6).
func TestSets(t *testing.T) {
	t.Parallel()
	m := offlineManager(t, Options{MaxConnectionConfigurationSets: 2})
	b, err := m.Add(named("B"))
	require.NoError(t, err)
	_, err = m.Add(named("A"))
	require.NoError(t, err)
	_, err = m.Add(named("B"))
	assert.ErrorIs(t, err, ua.StatusBadBrowseNameDuplicated)
	_, err = m.Add(named("C"))
	assert.ErrorIs(t, err, ua.StatusBadResourceUnavailable)
	bad := named("D")
	bad.ServerAddresses = nil
	_, err = m.Add(bad)
	var ce *ConfigError
	assert.ErrorAs(t, err, &ce)

	keys := m.Keys()
	require.Len(t, keys, 2)
	assert.Equal(t, "A", keys[0].Name)
	got, ok := m.Config(b.Key())
	require.True(t, ok)
	assert.Same(t, b, got)
	_, ok = m.Config(SetKey{Name: "none"})
	assert.False(t, ok)
	_, ok = m.Status(SetKey{Name: "none"})
	assert.False(t, ok)

	// Replace: a new Version 1 in Ready, nothing to close.
	c := named("B")
	c.RollbackOnError = false
	r, err := m.Replace(context.Background(), c)
	require.NoError(t, err)
	assert.Equal(t, uint32(1), r.Version())
	assert.False(t, r.RollbackOnError())
	st, _ := m.Status(b.Key())
	assert.Equal(t, StateReady, st.State)
	assert.Nil(t, st.Current)
	_, err = m.Replace(context.Background(), named("X"))
	assert.ErrorIs(t, err, ua.StatusBadNoMatch)
	_, err = m.Replace(context.Background(), bad)
	assert.ErrorAs(t, err, &ce)

	assert.ErrorIs(t, m.Remove(context.Background(), SetKey{Name: "none"}), ua.StatusBadNoMatch)
	require.NoError(t, m.Remove(context.Background(), b.Key()))
	assert.Len(t, m.Keys(), 1)
	assert.ErrorIs(t, m.Process(uafx.ActionEstablishConnections, b.Key())[0].Err, ua.StatusBadNodeIDUnknown)
	assert.ErrorIs(t, m.Reconcile(b.Key()).Err, ua.StatusBadNodeIDUnknown)
}

// TestUpdate: the batch of CloseAndUpdate (F.3.3, design §5.8).
func TestUpdate(t *testing.T) {
	t.Parallel()
	m := offlineManager(t, Options{MaxConnectionConfigurationSets: 3})
	_, err := m.Add(named("Old"))
	require.NoError(t, err)
	invalid := named("Bad")
	invalid.ServerAddresses = nil

	// One check fails: with RequireCompleteUpdate nothing is applied.
	applied, res := m.Update(context.Background(), []Operation{
		{Op: uafx.ElementAdd, Conf: named("New")},
		{Op: uafx.ElementRemove, Conf: named("None")},
	}, true)
	assert.False(t, applied)
	assert.NoError(t, res[0])
	assert.ErrorIs(t, res[1], ua.StatusBadNoMatch)
	assert.Len(t, m.Keys(), 1)

	// Without it the failed operations are dropped.
	applied, res = m.Update(context.Background(), []Operation{
		{Op: uafx.ElementAdd, Conf: named("New")},
		{Op: uafx.ElementAdd, Conf: named("New")},
		{Op: 0, Conf: named("X")},
		{Op: uafx.ElementAdd | uafx.ElementRemove, Conf: named("X")},
		{Op: uafx.ElementAdd},
		{Op: uafx.ElementAdd, Conf: invalid},
		{Op: uafx.ElementReplace, Conf: named("Old")},
		{Op: uafx.ElementAdd, Conf: named("Third")},
		{Op: uafx.ElementAdd, Conf: named("Fourth")},
	}, false)
	assert.False(t, applied)
	assert.NoError(t, res[0])
	assert.ErrorIs(t, res[1], ua.StatusBadBrowseNameDuplicated)
	assert.ErrorIs(t, res[2], ua.StatusBadNothingToDo)
	assert.ErrorIs(t, res[3], ua.StatusBadInvalidArgument)
	assert.ErrorIs(t, res[4], ua.StatusBadInvalidArgument)
	var ce *ConfigError
	assert.ErrorAs(t, res[5], &ce)
	assert.NoError(t, res[6])
	assert.NoError(t, res[7])
	assert.ErrorIs(t, res[8], ua.StatusBadResourceUnavailable)
	assert.Len(t, m.Keys(), 3)

	// A remove makes room for an add of the same batch.
	applied, res = m.Update(context.Background(), []Operation{
		{Op: uafx.ElementRemove, Conf: named("Third")},
		{Op: uafx.ElementAdd, Conf: named("Fourth")},
	}, true)
	assert.True(t, applied, "%v", res)
	assert.Equal(t, []error{nil, nil}, res)

	// A set in edit cannot be replaced.
	_, err = m.StartEdit(KeyOf(named("Old")), "c")
	require.NoError(t, err)
	_, res = m.Update(context.Background(), []Operation{{Op: uafx.ElementReplace, Conf: named("Old")}}, true)
	assert.ErrorIs(t, res[0], ua.StatusBadInvalidState)
	assert.ErrorIs(t, m.Remove(context.Background(), KeyOf(named("Old"))), ua.StatusBadInvalidState)
}

// TestEdits: StartEditing, CommitUpdates, DiscardUpdates and the end of
// the Lock (§6.7.4).
func TestEdits(t *testing.T) {
	t.Parallel()
	m := offlineManager(t, Options{})
	cfg, err := m.Add(validConf())
	require.NoError(t, err)
	k := cfg.Key()
	none := SetKey{Name: "none"}
	_, err = m.StartEdit(none, "a")
	assert.ErrorIs(t, err, ua.StatusBadNodeIDUnknown)
	_, _, err = m.CommitEdit(none, "a")
	assert.ErrorIs(t, err, ua.StatusBadNodeIDUnknown)
	_, err = m.DiscardEdit(none, "a")
	assert.ErrorIs(t, err, ua.StatusBadNodeIDUnknown)
	assert.False(t, m.EditLockLost(none))

	e, err := m.StartEdit(k, "a")
	require.NoError(t, err)
	_, err = m.StartEdit(k, "b")
	assert.ErrorIs(t, err, ua.StatusBadInvalidState)
	st, _ := m.Status(k)
	assert.True(t, st.Editing)
	e.Conf().Connections = e.Conf().Connections[:1]
	next, ok, err := m.CommitEdit(k, "a")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, uint32(2), next.Version())
	assert.Equal(t, []string{"C1"}, next.Connections())
	st, _ = m.Status(k)
	assert.Len(t, st.Diagnostics, 1)
	assert.Equal(t, "C1", st.Diagnostics[0].Name.Name)

	// A Name of an established endpoint cannot change (§6.12).
	s := m.lookup(k)
	s.mu.Lock()
	s.records["x"] = &record{EndpointRecord: EndpointRecord{Endpoint: EndpointRef{"C1", 1}, Class: KnownOwned}}
	s.mu.Unlock()
	e, err = m.StartEdit(k, "a")
	require.NoError(t, err)
	e.Conf().Connections[0].Endpoint1.Name = "Other"
	e.Conf().Connections[0].Endpoint1.NameSelection = nil
	_, _, err = m.CommitEdit(k, "a")
	assert.ErrorIs(t, err, ua.StatusBadInvalidState)
	ok, err = m.DiscardEdit(k, "a")
	require.NoError(t, err)
	assert.True(t, ok)
	ok, err = m.DiscardEdit(k, "a")
	require.NoError(t, err)
	assert.False(t, ok)
	_, err = m.StartEdit(k, "b")
	require.NoError(t, err)
	assert.True(t, m.EditLockLost(k))
	assert.False(t, m.EditLockLost(k))

	// Settle decides only Unresolved endpoints.
	assert.ErrorIs(t, m.Settle(k, EndpointRef{"C1", 1}, 0), ua.StatusBadInvalidArgument)
	assert.ErrorIs(t, m.Settle(none, EndpointRef{"C1", 1}, SettleOwned), ua.StatusBadNoMatch)
	assert.ErrorIs(t, m.Settle(k, EndpointRef{"C1", 2}, SettleOwned), ua.StatusBadNoMatch)
	assert.ErrorIs(t, m.Settle(k, EndpointRef{"C1", 1}, SettleOwned), ua.StatusBadInvalidState)
}

// TestOfflineRun: a run against servers that cannot be reached fails every
// endpoint with TargetServerConnectionError (Table 79 step 1), which is
// transient: the RetryPolicy retries it.
func TestOfflineRun(t *testing.T) {
	t.Parallel()
	events := &eventLog{}
	m := offlineManager(t, Options{Observer: events, Retry: &RetryPolicy{Initial: 1, Max: 1, Attempts: 2}})
	cfg, err := m.Add(validConf())
	require.NoError(t, err)
	res := process(t, m, uafx.ActionEstablishConnectionsEnabled, cfg.Key())
	require.Equal(t, StateError, res.State)
	for _, f := range res.Failures {
		assert.Equal(t, uafx.FxErrorTargetServerConnectionError, f.FxError)
		assert.True(t, f.Transient())
	}
	require.Eventually(t, func() bool { return len(events.of(EventRetry)) == 2 && len(events.transitions()) == 3 }, 5e9, 1e6)
	st, _ := m.Status(cfg.Key())
	require.NotNil(t, st.Last)
	assert.Equal(t, cfg.Key(), st.Last.Key())
	// No endpoint was made: Disable, Enable and Remove have nothing to do.
	for _, a := range []uafx.FxProcess{uafx.ActionDisableConnections, uafx.ActionEnableConnections, uafx.ActionRemoveConnections} {
		require.Eventually(t, func() bool { st, _ := m.Status(cfg.Key()); return st.State != StateProcessing }, 5e9, 1e6)
		res = process(t, m, a, cfg.Key())
		assert.Equal(t, StateReady, res.State, "%v", a)
	}
}

// TestClaimReserves: a Replace or Remove puts the set in Processing in the
// same step that claims it, so a Process between the claim and the close
// is refused (Table 86) and cannot replace the run of the removal.
func TestClaimReserves(t *testing.T) {
	t.Parallel()
	m := offlineManager(t, Options{})
	cfg, err := m.Add(named("A"))
	require.NoError(t, err)
	s, prev, err := m.claim(cfg.Key())
	require.NoError(t, err)
	assert.Equal(t, StateReady, prev)
	st, _ := m.Status(cfg.Key())
	assert.Equal(t, StateProcessing, st.State)
	removal := st.Current
	require.NotNil(t, removal)
	assert.Equal(t, ActionRemoveSet, removal.Action())

	started := m.Process(uafx.ActionEstablishConnectionsEnabled, cfg.Key())
	assert.Nil(t, started[0].Run)
	assert.ErrorIs(t, started[0].Err, ua.StatusBadInvalidState)
	_, _, err = m.claim(cfg.Key())
	assert.ErrorIs(t, err, ua.StatusBadInvalidState)
	st, _ = m.Status(cfg.Key())
	assert.Same(t, removal, st.Current)

	require.NoError(t, m.removeConnections(context.Background(), s, prev))
	m.wg.Done()
}

// TestCloseWaitsForClaim: Close waits for a Replace or Remove that has
// claimed its set, as it waits for a run, and stops its closes; after
// Close both are ua.StatusBadShutdown.
func TestCloseWaitsForClaim(t *testing.T) {
	t.Parallel()
	m := offlineManager(t, Options{})
	cfg, err := m.Add(named("A"))
	require.NoError(t, err)
	_, err = m.Add(named("B"))
	require.NoError(t, err)
	s, prev, err := m.claim(cfg.Key())
	require.NoError(t, err)
	closed := make(chan struct{})
	go func() {
		assert.NoError(t, m.Close())
		close(closed)
	}()
	require.Eventually(t, func() bool {
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.closed
	}, 5*time.Second, time.Millisecond)
	select {
	case <-closed:
		t.Fatal("Close returned while a Remove held its set")
	case <-time.After(50 * time.Millisecond):
	}
	assert.Error(t, m.ctx.Err(), "Close stops what the claim does")
	require.NoError(t, m.removeConnections(context.Background(), s, prev))
	m.wg.Done()
	<-closed
	assert.ErrorIs(t, m.Remove(context.Background(), KeyOf(named("B"))), ua.StatusBadShutdown)
	_, err = m.Replace(context.Background(), named("B"))
	assert.ErrorIs(t, err, ua.StatusBadShutdown)
}
