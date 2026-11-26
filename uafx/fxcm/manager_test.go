// SPDX-License-Identifier: MIT

package fxcm

import (
	"context"
	"slices"
	"sync"
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
	assert.True(t, applied, "F.3.3 Table F.39: one or more changes were applied")
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

	// Without RequireCompleteUpdate and no operation applied: FALSE.
	applied, res = m.Update(context.Background(), []Operation{{Op: uafx.ElementAdd, Conf: named("New")}}, false)
	assert.False(t, applied)
	assert.ErrorIs(t, res[0], ua.StatusBadBrowseNameDuplicated)

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

// TestUpdateComplete: with RequireCompleteUpdate a batch is applied whole
// or not at all (F.3.3, Table F.39): an Add before a Remove whose close
// fails is not kept, and a batch that would close the Connections of two
// sets is refused before anything is closed.
func TestUpdateComplete(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := offlineManager(t, Options{})
	for _, n := range []string{"B", "C", "D"} {
		_, err := m.Add(named(n))
		require.NoError(t, err)
	}
	established := func(n string) {
		s := m.lookup(KeyOf(named(n)))
		s.mu.Lock()
		s.records["x"] = &record{EndpointRecord: EndpointRecord{Endpoint: EndpointRef{"C1", 1}, Class: KnownOwned, NodeID: ua.NewNumericNodeID(1, 1)},
			addr: ServerAddress{Address: "opc.tcp://offline:4840"}}
		s.mu.Unlock()
	}
	state := func(n string) State {
		st, ok := m.Status(KeyOf(named(n)))
		require.True(t, ok, n)
		return st.State
	}
	established("B")
	established("C")
	var mu sync.Mutex
	transitions := map[string][]Transition{}
	defer m.AddObserver(ObserverFunc(func(e Event) {
		if e.Kind == EventTransition {
			mu.Lock()
			transitions[e.Set.Name] = append(transitions[e.Set.Name], e.Transition)
			mu.Unlock()
		}
	}))()
	took := func(n string) []Transition {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(transitions[n])
	}

	// Two sets with Connections to close: refused, nothing closed.
	applied, res := m.Update(ctx, []Operation{
		{Op: uafx.ElementAdd, Conf: named("N")},
		{Op: uafx.ElementRemove, Conf: named("B")},
		{Op: uafx.ElementReplace, Conf: named("C")},
	}, true)
	assert.False(t, applied)
	for _, e := range res {
		assert.ErrorIs(t, e, ua.StatusBadInvalidState)
	}
	assert.Contains(t, res[2].Error(), "one set only")
	assert.ElementsMatch(t, []string{"B", "C", "D"}, names(m))
	assert.Equal(t, StateReady, state("B"), "unclaimed")
	assert.Equal(t, StateReady, state("C"))
	// A refused batch processed nothing: no transition and so no
	// ProcessingStarted or ProcessingSucceeded event (§8.6 to §8.8).
	assert.Empty(t, took("B"))
	assert.Empty(t, took("C"))
	assert.Empty(t, took("D"))

	// [Add N, Remove B] with a close of B that fails: N is not added and B
	// stays, in Error; the key N is free again.
	applied, res = m.Update(ctx, []Operation{
		{Op: uafx.ElementAdd, Conf: named("N")},
		{Op: uafx.ElementRemove, Conf: named("B")},
	}, true)
	assert.False(t, applied, "Table F.39: FALSE, nothing was applied")
	assert.ErrorIs(t, res[0], ua.StatusBadInvalidState)
	assert.Error(t, res[1])
	assert.ElementsMatch(t, []string{"B", "C", "D"}, names(m))
	assert.Equal(t, StateError, state("B"))
	assert.Empty(t, m.reserved)
	_, err := m.Add(named("N"))
	require.NoError(t, err)
	require.NoError(t, m.Remove(ctx, KeyOf(named("N"))))

	// A claim of D holds it: no run or edit starts meanwhile, but the set
	// is not processed: no run, no transition. An unclaim gives it back
	// without a trace.
	s, err := m.claim(KeyOf(named("D")))
	require.NoError(t, err)
	st, _ := m.Status(KeyOf(named("D")))
	assert.Nil(t, st.Current, "a claim is no run")
	assert.Equal(t, StateReady, st.State)
	assert.ErrorIs(t, m.Process(uafx.ActionEstablishConnections, KeyOf(named("D")))[0].Err, ua.StatusBadInvalidState)
	_, err = m.StartEdit(KeyOf(named("D")), "e")
	assert.ErrorIs(t, err, ua.StatusBadInvalidState)
	m.unclaim(s)
	assert.Equal(t, StateReady, state("D"))
	assert.Empty(t, took("D"), "an unclaim takes no transition")
	st, _ = m.Status(KeyOf(named("D")))
	assert.Nil(t, st.Last)
	_, err = m.StartEdit(KeyOf(named("D")), "e")
	require.NoError(t, err)
	_, err = m.DiscardEdit(KeyOf(named("D")), "e")
	require.NoError(t, err)

	// [Add N, Replace D]: nothing to close, applied whole; D goes through
	// its remove run at the commit, which ends with a result.
	m.beforeCommit = func() {
		st, _ := m.Status(KeyOf(named("D")))
		assert.Nil(t, st.Current, "nothing is processed before the commit")
	}
	applied, res = m.Update(ctx, []Operation{
		{Op: uafx.ElementAdd, Conf: named("N")},
		{Op: uafx.ElementReplace, Conf: named("D")},
	}, true)
	m.beforeCommit = nil
	assert.True(t, applied, "%v", res)
	assert.Equal(t, []error{nil, nil}, res)
	assert.ElementsMatch(t, []string{"B", "C", "D", "N"}, names(m))
	assert.Equal(t, StateReady, state("D"))
	assert.Equal(t, []Transition{ReadyToProcessing, ProcessingToReady}, took("D"))
	st, _ = m.Status(KeyOf(named("D")))
	assert.Equal(t, ProcessingToReady, st.Transition)
	require.NotNil(t, st.Last)
	rr, err := st.Last.Wait(ctx)
	require.NoError(t, err)
	require.NotNil(t, rr, "the remove run has a result")
	assert.Equal(t, StateReady, rr.State)
	assert.Empty(t, rr.Failures)

	// An empty batch applies nothing, with or without requireComplete.
	for _, complete := range []bool{false, true} {
		applied, res = m.Update(ctx, nil, complete)
		assert.False(t, applied, "requireComplete %v", complete)
		assert.Empty(t, res)
	}

	// The limit counts the keys the batch adds.
	m2 := offlineManager(t, Options{MaxConnectionConfigurationSets: 1})
	applied, res = m2.Update(ctx, []Operation{{Op: uafx.ElementAdd, Conf: named("X")}, {Op: uafx.ElementAdd, Conf: named("Y")}}, true)
	assert.False(t, applied)
	assert.ErrorIs(t, res[1], ua.StatusBadResourceUnavailable)
	assert.Empty(t, m2.Keys())
}

// TestUpdateCompleteClose: an add-only complete update is counted as a
// run, so Close waits for it, and one that Close overtakes before anything
// irreversible happened applies nothing (ua.StatusBadShutdown). The update
// is held right before its commit until Close has marked the Manager
// closed, so the commit always sees it.
func TestUpdateCompleteClose(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := offlineManager(t, Options{})
	entered, release := make(chan struct{}), make(chan struct{})
	m.beforeCommit = func() {
		close(entered)
		<-release
	}
	type out struct {
		applied bool
		res     []error
	}
	updated := make(chan out, 1)
	go func() {
		a, r := m.Update(ctx, []Operation{{Op: uafx.ElementAdd, Conf: named("N")}}, true)
		updated <- out{a, r}
	}()
	<-entered
	closed := make(chan struct{})
	go func() {
		_ = m.Close()
		close(closed)
	}()
	// Close has marked the Manager closed and waits for the update.
	require.Eventually(t, func() bool {
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.closed
	}, 5*time.Second, time.Millisecond)
	select {
	case <-closed:
		t.Fatal("Close returned while the update was running")
	default:
	}
	close(release)
	u := <-updated
	<-closed
	assert.False(t, u.applied)
	require.Len(t, u.res, 1)
	assert.ErrorIs(t, u.res[0], ua.StatusBadShutdown)
	assert.Empty(t, m.Keys(), "nothing was added after Close")
	assert.Empty(t, m.reserved)

	// After Close a complete update is refused at once.
	applied, res := m.Update(ctx, []Operation{{Op: uafx.ElementAdd, Conf: named("M")}}, true)
	assert.False(t, applied)
	assert.ErrorIs(t, res[0], ua.StatusBadShutdown)
}

func names(m *Manager) []string {
	var out []string
	for _, k := range m.Keys() {
		out = append(out, k.Name)
	}
	return out
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
	// LastTransition is the transition taken (§6.9.2): a run from Ready
	// starts with ReadyToProcessing even after a run that ended in Error.
	var starts []Transition
	for _, e := range events.of(EventTransition) {
		if e.Transition == ReadyToProcessing || e.Transition == ErrorToProcessing {
			starts = append(starts, e.Transition)
		}
	}
	// The first run, its two retries and Disable start from Error; Enable
	// and Remove from Ready.
	assert.Equal(t, []Transition{ReadyToProcessing, ErrorToProcessing, ErrorToProcessing, ErrorToProcessing, ReadyToProcessing, ReadyToProcessing}, starts)
	st, _ = m.Status(cfg.Key())
	assert.Equal(t, ProcessingToReady, st.Transition)
}

// TestClaimReserves: a Replace or Remove holds the set in the same step
// that claims it, so a Process or another claim between the claim and the
// close is refused (Table 86) and cannot replace the run of the removal;
// the remove run starts with the close.
func TestClaimReserves(t *testing.T) {
	t.Parallel()
	m := offlineManager(t, Options{})
	cfg, err := m.Add(named("A"))
	require.NoError(t, err)
	s, err := m.claim(cfg.Key())
	require.NoError(t, err)
	st, _ := m.Status(cfg.Key())
	assert.Equal(t, StateReady, st.State)
	assert.Nil(t, st.Current)

	started := m.Process(uafx.ActionEstablishConnectionsEnabled, cfg.Key())
	assert.Nil(t, started[0].Run)
	assert.ErrorIs(t, started[0].Err, ua.StatusBadInvalidState)
	_, err = m.claim(cfg.Key())
	assert.ErrorIs(t, err, ua.StatusBadInvalidState)

	_, err = m.removeConnections(context.Background(), s)
	require.NoError(t, err)
	st, _ = m.Status(cfg.Key())
	require.NotNil(t, st.Last)
	assert.Equal(t, ActionRemoveSet, st.Last.Action())
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
	s, err := m.claim(cfg.Key())
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
	_, err = m.removeConnections(context.Background(), s)
	require.NoError(t, err)
	m.wg.Done()
	<-closed
	assert.ErrorIs(t, m.Remove(context.Background(), KeyOf(named("B"))), ua.StatusBadShutdown)
	_, err = m.Replace(context.Background(), named("B"))
	assert.ErrorIs(t, err, ua.StatusBadShutdown)
}
