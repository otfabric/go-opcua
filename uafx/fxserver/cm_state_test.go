// SPDX-License-Identifier: MIT

package fxserver_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/testutil/cleanup"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxcm"
	"github.com/otfabric/go-opcua/uafx/fxcmid"
	"github.com/otfabric/go-opcua/uafx/fxserver"
)

// gatedDialer holds every Dial while the gate is shut, then fails it: a
// run stays in Processing as long as the test wants. The gate stays open
// after release until the next hold, so that a Dial that comes late (the
// run started before release but dials after it) is not held by the gate
// of a later run.
type gatedDialer struct {
	mu   sync.Mutex
	open chan struct{}
}

func (d *gatedDialer) gate() chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.open
}

func (d *gatedDialer) Dial(ctx context.Context, _ fxcm.ServerAddress) (fxcm.Session, error) {
	select {
	case <-d.gate():
	case <-ctx.Done():
	}
	return nil, errors.New("offline")
}

// hold shuts the gate for the next run.
func (d *gatedDialer) hold() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.open = make(chan struct{})
}

// release opens the gate; it stays open until the next hold.
func (d *gatedDialer) release() {
	d.mu.Lock()
	defer d.mu.Unlock()
	select {
	case <-d.open:
	default:
		close(d.open)
	}
}

// TestConnectionManagerStateOnReturn: when ProcessConnectionConfigurationSets
// returns Good for a set, a read of its state right after it is
// Processing (§6.7.5, §6.9.2), not the state before the run; after
// StartEditing the Lock belongs to the caller. Before any run the set has
// no LastTransition.
func TestConnectionManagerStateOnReturn(t *testing.T) {
	t.Parallel()
	d := &gatedDialer{open: make(chan struct{})}
	cleanup.Register(t, d.release)
	srv := newServer(t, server.WithRoleMapper(func(tok ua.IdentityToken) []*ua.NodeID {
		return append(server.DefaultRoleMapper(tok), fxserver.ConfigureAdmin())
	}))
	ns, err := fxserver.AddModel(srv, fxserver.ModelCM)
	require.NoError(t, err)
	m, err := fxcm.New(fxcm.Options{Dialer: d, ApplicationURI: "urn:test:cm", Logger: slog.New(slog.DiscardHandler)})
	require.NoError(t, err)
	cleanup.Register(t, func() { _ = m.Close() })
	_, err = m.Add(cmConf("Line1"))
	require.NoError(t, err)
	cm, err := fxserver.EnableConnectionManager(srv, ns, fxserver.ConnectionManagerOptions{Manager: m, Editable: true, Logger: slog.New(slog.DiscardHandler)})
	require.NoError(t, err)
	cleanup.Register(t, func() { _ = cm.Close() })
	f := &cmFX{srv: srv, ns: ns, m: m, cm: cm}
	f.c = start(t, srv)
	f.set, _ = cm.SetNode(fxcm.SetKey{Folder: []string{"Plant"}, Name: "Line1"})
	require.NotNil(t, f.set)

	assert.Equal(t, "", f.value(t, ".LastTransition").(*ua.LocalizedText).Text, "no transition yet")
	assert.True(t, f.value(t, ".LastTransition.Id").(*ua.NodeID).Equal(ua.NewTwoByteNodeID(0)))

	state := func() uint32 { return f.value(t, ".CurrentState.Id").(*ua.NodeID).IntID() }
	for i := range 20 {
		d.hold()
		sc, rs, err := uafx.ProcessConnectionConfigurationSets(context.Background(), f.c, uafx.ActionEstablishConnections, []*ua.NodeID{f.set})
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, sc, "run %d", i)
		require.Equal(t, ua.StatusOK, rs[0], "run %d", i)
		require.Equal(t, uint32(fxcmid.ConnectionConfigurationSetStateMachineTypeProcessing), state(), "run %d: the state right after the Method", i)
		d.release()
		// CurrentState.Id and LastTransition are published one after the
		// other: wait for both of the end of the run.
		require.Eventually(t, func() bool {
			return state() == fxcmid.ConnectionConfigurationSetStateMachineTypeError &&
				f.value(t, ".LastTransition").(*ua.LocalizedText).Text == "ProcessingToError"
		}, 10*time.Second, time.Millisecond, "run %d", i)
	}

	for i := range 20 {
		sc, _ := f.edit(t, f.c, uafx.StartEditing, f.set)
		require.Equal(t, ua.StatusOK, sc)
		require.NotEqual(t, "CM", f.value(t, ".Lock.LockingUser"), "edit %d: the Lock right after StartEditing", i)
		sc, _ = f.edit(t, f.c, uafx.DiscardUpdates, f.set)
		require.Equal(t, ua.StatusOK, sc)
		require.Equal(t, "CM", f.value(t, ".Lock.LockingUser"), "edit %d: the Lock right after DiscardUpdates", i)
	}
}

// TestConnectionManagerStaleEditEnded: the EventEditEnded of an edit whose
// Lock went (ExitLock, expiry, §6.7.4, OPC 10000-100 §7.2) may still be
// queued when another session gets the Lock with StartEditing. Applying it
// then must not end the new edit: the Lock, the working copy and its
// commit stay with the new owner.
func TestConnectionManagerStaleEditEnded(t *testing.T) {
	t.Parallel()
	f := newCMFX(t, fxserver.ConnectionManagerOptions{Editable: true})
	other := f.client(t, "urn:test:other", true)
	key := fxcm.SetKey{Folder: []string{"Plant"}, Name: "Line1"}
	pi := f.node(".Flow[Flow1].PublishingInterval")
	var now atomic.Int64
	now.Store(time.Now().UnixNano())
	fxserver.SetCMClock(f.cm, func() time.Time { return time.Unix(0, now.Load()) })

	losses := []struct {
		name string
		lose func()
	}{
		{"ExitLock", func() {
			st, sc := f.lockCall(t, f.c, "ExitLock")
			require.Equal(t, ua.StatusOK, sc)
			require.Equal(t, int32(0), st)
		}},
		{"expiry", func() {
			now.Add(int64(61 * time.Second))
			fxserver.TickCMLocks(f.cm)
		}},
	}
	for i, l := range losses {
		sc, _ := f.edit(t, f.c, uafx.StartEditing, f.set)
		require.Equal(t, ua.StatusOK, sc, l.name)
		l.lose()
		require.Equal(t, false, f.value(t, ".Edit"), l.name)

		sc, rs := f.edit(t, other, uafx.StartEditing, f.set)
		require.Equal(t, ua.StatusOK, sc, l.name)
		require.Equal(t, []ua.StatusCode{ua.StatusOK}, rs, l.name)
		owner := f.value(t, ".Lock.LockingClient")

		// The event of the lost edit arrives after the new StartEditing.
		fxserver.ApplyCMEvent(f.cm, fxcm.Event{Kind: fxcm.EventEditEnded, Set: key})
		f.cm.Flush()

		assert.Equal(t, true, f.value(t, ".Edit"), l.name)
		assert.Equal(t, owner, f.value(t, ".Lock.LockingClient"), l.name)
		v := []float64{10, 20}[i] // values of the SelectionList
		require.Equal(t, ua.StatusOK, f.write(t, other, pi, v), "%s: the new owner writes its working copy", l.name)
		version := f.value(t, ".Version").(uint32)
		sc, rs = f.edit(t, other, uafx.CommitUpdates, f.set)
		require.Equal(t, ua.StatusOK, sc, l.name)
		require.Equal(t, []ua.StatusCode{ua.StatusOK}, rs, l.name)
		assert.Equal(t, version+1, f.value(t, ".Version"), l.name)
		assert.Equal(t, v, f.value(t, ".Flow[Flow1].PublishingInterval"), l.name)
		assert.Equal(t, false, f.value(t, ".Edit"), l.name)
	}
}

// TestConnectionManagerEditHandover: two sessions take the Lock in turn
// while the loop of the ConnectionManager drains the events of the
// previous edit concurrently; each StartEditing leaves the caller the owner
// of the Lock and of a writable working copy.
func TestConnectionManagerEditHandover(t *testing.T) {
	t.Parallel()
	f := newCMFX(t, fxserver.ConnectionManagerOptions{Editable: true})
	other := f.client(t, "urn:test:other", true)
	pi := f.node(".Flow[Flow1].PublishingInterval")
	for i := range 20 {
		sc, _ := f.edit(t, f.c, uafx.StartEditing, f.set)
		require.Equal(t, ua.StatusOK, sc, "round %d", i)
		st, sc := f.lockCall(t, f.c, "ExitLock")
		require.Equal(t, ua.StatusOK, sc, "round %d", i)
		require.Equal(t, int32(0), st, "round %d", i)

		sc, rs := f.edit(t, other, uafx.StartEditing, f.set)
		require.Equal(t, ua.StatusOK, sc, "round %d", i)
		require.Equal(t, []ua.StatusCode{ua.StatusOK}, rs, "round %d", i)
		f.cm.Flush()
		require.Equal(t, true, f.value(t, ".Edit"), "round %d: the edit of the new owner", i)
		require.Equal(t, ua.StatusOK, f.write(t, other, pi, 10.0), "round %d", i)
		sc, rs = f.edit(t, other, uafx.DiscardUpdates, f.set)
		require.Equal(t, ua.StatusOK, sc, "round %d", i)
		require.Equal(t, []ua.StatusCode{ua.StatusOK}, rs, "round %d", i)
	}
}

// TestConnectionManagerFastRun: a run may end before
// ProcessConnectionConfigurationSets answers (here: no server to reach, no
// endpoint to remove). A Good result then guarantees the nodes show the
// run it started or a later state of that run (§6.7.5, §6.9.2), not that
// the set is still in Processing: never the state before the call. The
// nodes of a set change one after the other, so a Read while the run ends
// may see its end state beside the start transition.
func TestConnectionManagerFastRun(t *testing.T) {
	t.Parallel()
	f := newCMFX(t, fxserver.ConnectionManagerOptions{})
	const (
		ready      = fxcmid.ConnectionConfigurationSetStateMachineTypeReady
		processing = fxcmid.ConnectionConfigurationSetStateMachineTypeProcessing
		failed     = fxcmid.ConnectionConfigurationSetStateMachineTypeError
	)
	runs := []struct {
		action uafx.FxProcess
		end    uint32 // the state the run ends in
		before uint32 // the state before the call
		start  string // the transition that starts the run
		last   string // the transition that ends it
	}{
		{uafx.ActionEstablishConnections, failed, ready, "ReadyToProcessing", "ProcessingToError"},
		{uafx.ActionRemoveConnections, ready, failed, "ErrorToProcessing", "ProcessingToReady"},
	}
	for i := range 20 {
		r := runs[i%2]
		sc, rs, err := uafx.ProcessConnectionConfigurationSets(context.Background(), f.c, r.action, []*ua.NodeID{f.set})
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, sc, "run %d", i)
		require.Equal(t, ua.StatusOK, rs[0], "run %d", i)
		state := f.value(t, ".CurrentState.Id").(*ua.NodeID).IntID()
		require.NotEqual(t, r.before, state, "run %d: the state before the call", i)
		require.Contains(t, []uint32{processing, r.end}, state, "run %d", i)
		// Read after the state: the transition of this run, never one of
		// the run before.
		assert.Contains(t, []string{r.start, r.last}, f.value(t, ".LastTransition").(*ua.LocalizedText).Text, "run %d", i)
		// Both of the end of the run, published one after the other.
		require.Eventually(t, func() bool {
			return f.value(t, ".CurrentState.Id").(*ua.NodeID).IntID() == r.end &&
				f.value(t, ".LastTransition").(*ua.LocalizedText).Text == r.last
		}, 10*time.Second, time.Millisecond, "run %d", i)
	}
}

// TestConnectionManagerDrainUnderLoad: while other sets keep the Manager
// reporting events, each run followed by a Flush as a Method drains after
// it, the Methods on one set keep answering in bounded time with their
// state shown on return: the drain of a Method applies the events queued
// before it, not the ones that keep coming, and the drains do not
// deadlock. Not parallel: the load takes the CPU the other tests time on.
func TestConnectionManagerDrainUnderLoad(t *testing.T) {
	f := newCMFX(t, fxserver.ConnectionManagerOptions{Editable: true})
	var keys []fxcm.SetKey
	for i := range 8 {
		cfg, err := f.m.Add(cmConf(fmt.Sprintf("Load%d", i)))
		require.NoError(t, err)
		keys = append(keys, cfg.Key())
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	var events atomic.Int64
	for _, k := range keys {
		wg.Go(func() {
			// As fast as the address space follows: a run, then the drain
			// a Method does after it.
			for ctx.Err() == nil {
				for _, st := range f.m.Process(uafx.ActionEstablishConnections, k) {
					if st.Err == nil {
						events.Add(1)
					}
				}
				f.cm.Flush()
			}
		})
	}
	cleanup.Register(t, func() { cancel(); wg.Wait() })

	// The slowest call of each Method, each timed on its own.
	worst := map[string]time.Duration{}
	timed := func(method string, call func()) {
		t0 := time.Now()
		call()
		worst[method] = max(worst[method], time.Since(t0))
	}
	for i := range 15 {
		var (
			sc  ua.StatusCode
			rs  []ua.StatusCode
			err error
		)
		timed("Process", func() {
			sc, rs, err = uafx.ProcessConnectionConfigurationSets(context.Background(), f.c, uafx.ActionEstablishConnections, []*ua.NodeID{f.set})
		})
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, sc, "run %d", i)
		require.Equal(t, ua.StatusOK, rs[0], "run %d", i)
		if i == 0 {
			require.NotEqual(t, uint32(fxcmid.ConnectionConfigurationSetStateMachineTypeReady), f.value(t, ".CurrentState.Id").(*ua.NodeID).IntID(), "the state before the first run")
		}
		require.Eventually(t, func() bool {
			return f.value(t, ".CurrentState.Id").(*ua.NodeID).IntID() == fxcmid.ConnectionConfigurationSetStateMachineTypeError
		}, 10*time.Second, time.Millisecond, "run %d", i)

		timed("StartEditing", func() { sc, _ = f.edit(t, f.c, uafx.StartEditing, f.set) })
		require.Equal(t, ua.StatusOK, sc, "edit %d", i)
		require.Equal(t, true, f.value(t, ".Edit"), "edit %d: the edit right after StartEditing", i)
		timed("DiscardUpdates", func() { sc, _ = f.edit(t, f.c, uafx.DiscardUpdates, f.set) })
		require.Equal(t, ua.StatusOK, sc, "edit %d", i)
		require.Equal(t, false, f.value(t, ".Edit"), "edit %d: no edit right after DiscardUpdates", i)
	}
	cancel()
	wg.Wait()
	t.Logf("%d runs of the other sets, the slowest calls %v", events.Load(), worst)
	assert.Positive(t, events.Load())
	for _, m := range []string{"Process", "StartEditing", "DiscardUpdates"} {
		assert.Less(t, worst[m], 2*time.Second, "%s held up by the events of other sets", m)
	}
}
