// SPDX-License-Identifier: MIT

package server_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/remote"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// recordingHook records the changes it sees and fails them with err.
type recordingHook struct {
	mu      sync.Mutex
	changes []*server.PubSubChange
	err     error
	groups  []uint16
	writers []uint16
	refuse  bool
}

func (h *recordingHook) PubSubConfigurationChanged(ch *server.PubSubChange) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.changes = append(h.changes, ch)
	return h.err
}

func (h *recordingHook) HeldPubSubIDs() ([]uint16, []uint16, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.groups, h.writers, h.refuse
}

func (h *recordingHook) set(err error, refuse bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.err, h.refuse = err, refuse
}

func (h *recordingHook) take() []*server.PubSubChange {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := h.changes
	h.changes = nil
	return out
}

func connNames(cfg *ua.PubSubConfigurationDataType) []string {
	var out []string
	if cfg == nil {
		return out
	}
	for _, c := range cfg.Connections {
		out = append(out, c.Name)
	}
	return out
}

// TestPubSubConfigurationHook: the hook sees every change, whatever makes
// it (a Method of Part 14 §9.1.3, UpdatePubSubConfiguration, Revert,
// ChangePubSubConfiguration), with the configuration before and after; an
// error undoes the change and fails it with its StatusCode; no change, no
// call; held ids are not handed out and refuse fails ReserveIds.
func TestPubSubConfigurationHook(t *testing.T) {
	t.Parallel()
	b := newBridgeServer(t, server.WithPubSub(nil))
	rt := b.srv.PubSub()
	h := &recordingHook{}
	b.srv.SetPubSubConfigurationHook(h)
	ctx := context.Background()
	r := remote.New(testutil.NewTestClient(t, b.url))

	// A Method.
	id, err := r.AddConnection(ctx, pubsub.UDPConnection("M", "opc.udp://239.0.0.1:4840", uint16(3)))
	require.NoError(t, err)
	ch := h.take()
	require.Len(t, ch, 1)
	require.Empty(t, connNames(ch[0].Before))
	require.Equal(t, []string{"M"}, connNames(ch[0].After))
	require.False(t, ch[0].Revert)
	require.NotNil(t, ch[0].Context)

	// A Method that fails changes nothing: no call.
	_, err = r.AddConnection(ctx, &ua.PubSubConnectionDataType{Name: "x"})
	require.Error(t, err)
	require.Empty(t, h.take())

	// Refused: the change is undone, the Method fails with the StatusCode.
	h.set(ua.StatusBadInvalidState, false)
	require.ErrorIs(t, r.RemoveConnection(ctx, id), ua.StatusBadInvalidState)
	_, ok := rt.Lookup(pubsub.KindConnection, pubsub.Root, "M")
	require.True(t, ok, "the refused removal is undone")
	require.Len(t, h.take(), 1)
	// Any other error is Bad_InternalError.
	h.set(errors.New("store down"), false)
	_, err = r.AddConnection(ctx, pubsub.UDPConnection("N", "opc.udp://239.0.0.1:4840", uint16(4)))
	require.ErrorIs(t, err, ua.StatusBadInternalError)
	_, ok = rt.Lookup(pubsub.KindConnection, pubsub.Root, "N")
	require.False(t, ok)
	h.take()
	h.set(nil, false)

	// UpdatePubSubConfiguration, with the context of the call, and Revert.
	var u *server.PubSubConfigurationUpdate
	require.Equal(t, ua.StatusOK, b.call(t, func(ctx context.Context) ua.StatusCode {
		var sc ua.StatusCode
		u, sc = b.srv.UpdatePubSubConfiguration(ctx, bridgeConfig("A"), true,
			[]*ua.PubSubConfigurationRefDataType{{ConfigurationMask: refAdd | refConn}, {ConfigurationMask: refAdd | refWG}})
		return sc
	}))
	ch = h.take()
	require.Len(t, ch, 1)
	require.ElementsMatch(t, []string{"M", "A"}, connNames(ch[0].After))
	require.NoError(t, u.Revert())
	ch = h.take()
	require.Len(t, ch, 1)
	require.True(t, ch[0].Revert)
	require.ElementsMatch(t, []string{"M", "A"}, connNames(ch[0].Before))
	require.Equal(t, []string{"M"}, connNames(ch[0].After))

	// A refused update fails and is undone.
	h.set(ua.StatusBadResourceUnavailable, false)
	require.Equal(t, ua.StatusBadResourceUnavailable, b.call(t, func(ctx context.Context) ua.StatusCode {
		_, sc := b.srv.UpdatePubSubConfiguration(ctx, bridgeConfig("A"), true,
			[]*ua.PubSubConfigurationRefDataType{{ConfigurationMask: refAdd | refConn}})
		return sc
	}))
	_, ok = rt.Lookup(pubsub.KindConnection, pubsub.Root, "A")
	require.False(t, ok)
	h.take()
	h.set(nil, false)

	// ChangePubSubConfiguration.
	require.NoError(t, b.srv.ChangePubSubConfiguration(func(rt *pubsub.PubSub) error {
		_, err := rt.AddConnection(pubsub.UDPConnection("C", "opc.udp://239.0.0.1:4840", uint16(5)))
		return err
	}))
	ch = h.take()
	require.Len(t, ch, 1)
	require.Equal(t, context.Background(), ch[0].Context)
	// fn fails after a change: the hook sees what it changed.
	boom := errors.New("boom")
	err = b.srv.ChangePubSubConfiguration(func(rt *pubsub.PubSub) error {
		_, err := rt.AddConnection(pubsub.UDPConnection("D", "opc.udp://239.0.0.1:4840", uint16(6)))
		require.NoError(t, err)
		return boom
	})
	require.ErrorIs(t, err, boom)
	require.Len(t, h.take(), 1)
	// Both fail.
	h.set(ua.StatusBadInvalidState, false)
	err = b.srv.ChangePubSubConfiguration(func(rt *pubsub.PubSub) error {
		_, err := rt.AddConnection(pubsub.UDPConnection("E", "opc.udp://239.0.0.1:4840", uint16(7)))
		require.NoError(t, err)
		return boom
	})
	require.ErrorIs(t, err, boom)
	require.ErrorIs(t, err, ua.StatusBadInvalidState)
	_, ok = rt.Lookup(pubsub.KindConnection, pubsub.Root, "E")
	require.False(t, ok)
	// Refused.
	err = b.srv.ChangePubSubConfiguration(func(rt *pubsub.PubSub) error {
		_, err := rt.AddConnection(pubsub.UDPConnection("F", "opc.udp://239.0.0.1:4840", uint16(8)))
		return err
	})
	require.ErrorIs(t, err, ua.StatusBadInvalidState)
	h.take()
	h.set(nil, false)

	// Held ids are not handed out; refuse fails ReserveIds.
	h.mu.Lock()
	h.groups, h.writers = []uint16{0x8000, 0x8001}, []uint16{0x8000}
	h.mu.Unlock()
	ids, err := r.ReserveIDs(ctx, transport.ProfileUDPUADP, 1, 1)
	require.NoError(t, err)
	require.Equal(t, []uint16{0x8002}, ids.WriterGroupIDs)
	require.Equal(t, []uint16{0x8001}, ids.DataSetWriterIDs)
	h.set(nil, true)
	_, err = r.ReserveIDs(ctx, transport.ProfileUDPUADP, 1, 1)
	require.ErrorIs(t, err, ua.StatusBadResourceUnavailable)
	h.set(nil, false)

	// nil removes the hook.
	b.srv.SetPubSubConfigurationHook(nil)
	_, err = r.AddConnection(ctx, pubsub.UDPConnection("G", "opc.udp://239.0.0.1:4840", uint16(9)))
	require.NoError(t, err)
	require.Empty(t, h.take())
	require.NoError(t, b.srv.ChangePubSubConfiguration(func(rt *pubsub.PubSub) error { return nil }))
}

// TestBuildPubSubModel: the model is built before Start, once; a server
// without PubSub has none.
func TestBuildPubSubModel(t *testing.T) {
	t.Parallel()
	cfg := pubsub.NewConfiguration(nil, pubsub.AttachWriterGroups(pubsub.UDPConnection("conn", "opc.udp://239.0.0.1:4840", uint16(4)),
		pubsub.WriterGroup("wg", 0x8000, time.Second)))
	srv, err := server.New(server.WithPubSub(cfg))
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })
	require.NoError(t, srv.BuildPubSubModel())
	conn, ok := srv.PubSub().Lookup(pubsub.KindConnection, pubsub.Root, "conn")
	require.True(t, ok)
	n, ok := srv.PubSubNodeID(conn)
	require.True(t, ok)
	require.NotNil(t, n)
	require.NoError(t, srv.BuildPubSubModel(), "idempotent")

	plain, err := server.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = plain.Close() })
	require.Error(t, plain.BuildPubSubModel())
}

// funcHook runs f for every change.
type funcHook struct {
	f func(ch *server.PubSubChange) error
}

func (h funcHook) PubSubConfigurationChanged(ch *server.PubSubChange) error { return h.f(ch) }

func (funcHook) HeldPubSubIDs() ([]uint16, []uint16, bool) { return nil, nil, false }

// TestPubSubHookRefusesRevert: a hook that refuses a Revert keeps the
// update: the runtime goes back to the updated configuration, Revert fails
// with the StatusCode and can be retried.
func TestPubSubHookRefusesRevert(t *testing.T) {
	t.Parallel()
	b := newBridgeServer(t, server.WithPubSub(nil))
	rt := b.srv.PubSub()
	h := &recordingHook{}
	b.srv.SetPubSubConfigurationHook(h)
	var u *server.PubSubConfigurationUpdate
	require.Equal(t, ua.StatusOK, b.call(t, func(ctx context.Context) ua.StatusCode {
		var sc ua.StatusCode
		u, sc = b.srv.UpdatePubSubConfiguration(ctx, bridgeConfig("A"), true,
			[]*ua.PubSubConfigurationRefDataType{{ConfigurationMask: refAdd | refConn}, {ConfigurationMask: refAdd | refWG}})
		return sc
	}))
	h.take()

	h.set(ua.StatusBadInvalidState, false)
	require.ErrorIs(t, u.Revert(), ua.StatusBadInvalidState)
	ch := h.take()
	require.Len(t, ch, 1)
	require.True(t, ch[0].Revert)
	_, ok := rt.Lookup(pubsub.KindConnection, pubsub.Root, "A")
	require.True(t, ok, "the refused revert is undone")

	h.set(nil, false)
	require.NoError(t, u.Revert(), "a refused revert can be retried")
	_, ok = rt.Lookup(pubsub.KindConnection, pubsub.Root, "A")
	require.False(t, ok)
}

// TestPubSubHookRestoreFails: when the configuration a hook refused cannot
// be restored, the refusal is still the error (the failed restore is
// logged).
func TestPubSubHookRestoreFails(t *testing.T) {
	t.Parallel()
	b := newBridgeServer(t, server.WithPubSub(nil))
	b.srv.SetPubSubConfigurationHook(funcHook{f: func(ch *server.PubSubChange) error {
		// A hook that breaks its contract: Before names a connection the
		// runtime cannot add, so restoring it fails.
		ch.Before.Connections = append(ch.Before.Connections, &ua.PubSubConnectionDataType{Name: "x"})
		return ua.StatusBadInvalidState
	}})
	err := b.srv.ChangePubSubConfiguration(func(rt *pubsub.PubSub) error {
		_, err := rt.AddConnection(pubsub.UDPConnection("C", "opc.udp://239.0.0.1:4840", uint16(5)))
		return err
	})
	require.ErrorIs(t, err, ua.StatusBadInvalidState)
}

// TestChangePubSubConfigurationThen: then runs in the transaction of the
// change, after the hook and after the restore of a refused change: it
// sees the restored component (under a new ComponentID), and a change
// waiting for the transaction runs only after it.
func TestChangePubSubConfigurationThen(t *testing.T) {
	t.Parallel()
	b := newBridgeServer(t, server.WithPubSub(nil))
	rt := b.srv.PubSub()
	conn := pubsub.UDPConnection("C", "opc.udp://239.0.0.1:4840", uint16(5))
	cid, err := rt.AddConnection(conn)
	require.NoError(t, err)
	h := &recordingHook{}
	b.srv.SetPubSubConfigurationHook(h)

	// Without PubSub: neither fn nor then.
	none := newBridgeServer(t)
	require.ErrorIs(t, none.srv.ChangePubSubConfigurationThen(func(*pubsub.PubSub) error {
		t.Fatal("fn called")
		return nil
	}, func(*pubsub.PubSub, error) { t.Fatal("then called") }), ua.StatusBadNotSupported)

	h.set(ua.StatusBadResourceUnavailable, false)
	waiting := make(chan struct{})
	ran := make(chan struct{})
	var seen pubsub.ComponentID
	var seenErr error
	err = b.srv.ChangePubSubConfigurationThen(func(rt *pubsub.PubSub) error {
		return rt.RemoveConnection(cid)
	}, func(rt *pubsub.PubSub, err error) {
		seenErr = err
		seen, _ = rt.Lookup(pubsub.KindConnection, pubsub.Root, "C")
		go func() {
			close(waiting)
			_ = b.srv.ChangePubSubConfiguration(func(*pubsub.PubSub) error {
				close(ran)
				return nil
			})
		}()
		<-waiting
		select {
		case <-ran:
			t.Error("a change ran inside the transaction of then")
		case <-time.After(50 * time.Millisecond):
		}
	})
	require.ErrorIs(t, err, ua.StatusBadResourceUnavailable)
	require.ErrorIs(t, seenErr, ua.StatusBadResourceUnavailable, "then gets the result")
	require.NotZero(t, seen, "then sees the restored connection")
	require.NotEqual(t, cid, seen, "under a new ComponentID")
	<-ran
	require.Len(t, h.take(), 1)
}

// restoringHook refuses every change and records the moves it is told.
type restoringHook struct {
	recordingHook
	moves [][]server.PubSubComponentMove
	srv   *server.Server
	nodes []bool // whether each move's ToNode was the node of To when told
}

func (h *restoringHook) PubSubConfigurationRestored(_ *server.PubSubChange, moved []server.PubSubComponentMove) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.moves = append(h.moves, moved)
	for _, m := range moved {
		n, ok := h.srv.PubSubNodeID(m.To)
		h.nodes = append(h.nodes, ok && n.Equal(m.ToNode))
	}
}

// TestPubSubConfigurationRestorer: a hook that is a
// PubSubConfigurationRestorer is told, in the transaction, which
// components a refused change brought back under a new ComponentID and
// node, whatever mechanism made the change; nothing for an accepted one.
func TestPubSubConfigurationRestorer(t *testing.T) {
	t.Parallel()
	b := newBridgeServer(t, server.WithPubSub(nil))
	rt := b.srv.PubSub()
	conn, err := rt.AddConnection(pubsub.UDPConnection("C", "opc.udp://239.0.0.1:4840", uint16(5)))
	require.NoError(t, err)
	require.NoError(t, b.srv.BuildPubSubModel())
	before, ok := b.srv.PubSubNodeID(conn)
	require.True(t, ok)
	h := &restoringHook{srv: b.srv}
	b.srv.SetPubSubConfigurationHook(h)

	// Accepted: no moves.
	_, err = rt.AddConnection(pubsub.UDPConnection("D", "opc.udp://239.0.0.1:4841", uint16(6)))
	require.NoError(t, err) // outside a transaction: no hook at all
	require.NoError(t, b.srv.ChangePubSubConfiguration(func(rt *pubsub.PubSub) error {
		id, _ := rt.Lookup(pubsub.KindConnection, pubsub.Root, "D")
		return rt.RemoveConnection(id)
	}))
	require.Empty(t, h.moves)

	// Refused: C comes back under a new id and node, and the hook is told.
	h.set(ua.StatusBadResourceUnavailable, false)
	err = b.srv.ChangePubSubConfiguration(func(rt *pubsub.PubSub) error { return rt.RemoveConnection(conn) })
	require.ErrorIs(t, err, ua.StatusBadResourceUnavailable)
	cur, ok := rt.Lookup(pubsub.KindConnection, pubsub.Root, "C")
	require.True(t, ok)
	require.Len(t, h.moves, 1)
	require.Equal(t, []server.PubSubComponentMove{{From: conn, To: cur, FromNode: before, ToNode: h.moves[0][0].ToNode}}, h.moves[0])
	require.NotNil(t, h.moves[0][0].ToNode)
	require.False(t, before.Equal(h.moves[0][0].ToNode))
	require.Equal(t, []bool{true}, h.nodes, "the new node is in place when the hook is told")
}

// TestPubSubUpdateMoved: an update that replaces a component in place
// (ElementModify) lists it in Moved, with its old and new ComponentID and
// node, and so does the PubSubChange of the hook; RevertMoves lists what the
// revert put back; a component removed and added again under the same
// Name in one update (ElementRemove, ElementAdd) is a new one, not a move.
func TestPubSubUpdateMoved(t *testing.T) {
	t.Parallel()
	b := newBridgeServer(t, server.WithPubSub(nil))
	rt := b.srv.PubSub()
	h := &recordingHook{}
	b.srv.SetPubSubConfigurationHook(h)
	update := func(cfg *ua.PubSubConfiguration2DataType, refs ...*ua.PubSubConfigurationRefDataType) *server.PubSubConfigurationUpdate {
		t.Helper()
		var u *server.PubSubConfigurationUpdate
		require.Equal(t, ua.StatusOK, b.call(t, func(ctx context.Context) ua.StatusCode {
			var sc ua.StatusCode
			u, sc = b.srv.UpdatePubSubConfiguration(ctx, cfg, true, refs)
			return sc
		}))
		require.True(t, u.ChangesApplied)
		return u
	}
	group := func() (pubsub.ComponentID, *ua.NodeID) {
		t.Helper()
		c, ok := rt.Lookup(pubsub.KindConnection, pubsub.Root, "A")
		require.True(t, ok)
		g, ok := rt.Lookup(pubsub.KindWriterGroup, c, "G")
		require.True(t, ok)
		n, ok := b.srv.PubSubNodeID(g)
		require.True(t, ok)
		return g, n
	}
	u := update(bridgeConfig("A"), &ua.PubSubConfigurationRefDataType{ConfigurationMask: refAdd | refConn}, &ua.PubSubConfigurationRefDataType{ConfigurationMask: refAdd | refWG})
	require.Empty(t, u.Moved, "nothing was there before")
	h.take()

	g0, n0 := group()
	changed := bridgeConfig("A")
	changed.Connections[0].WriterGroups[0].KeepAliveTime = 4242
	u = update(changed, &ua.PubSubConfigurationRefDataType{ConfigurationMask: ua.PubSubConfigurationRefMaskElementModify | refWG})
	g1, n1 := group()
	require.NotEqual(t, g0, g1, "the modify replaced the group")
	want := []server.PubSubComponentMove{{From: g0, To: g1, FromNode: n0, ToNode: n1}}
	require.Equal(t, want, u.Moved)
	ch := h.take()
	require.Len(t, ch, 1)
	require.Equal(t, want, ch[0].Moved, "the hook sees the moves")

	// A revert the runtime refuses changes nothing and reports no moves.
	bad := rt.Configuration()
	bad.Connections = append(bad.Connections, &ua.PubSubConnectionDataType{Name: "Bad"})
	server.SetPubSubUpdateBefore(u, bad)
	moved, err := u.RevertMoves()
	require.ErrorContains(t, err, "revert the PubSub configuration")
	require.Nil(t, moved)
	gb, _ := group()
	require.Equal(t, g1, gb, "the refused revert left the group")
	_, ok := rt.Lookup(pubsub.KindConnection, pubsub.Root, "Bad")
	require.False(t, ok)

	u = update(bridgeConfig("A"), &ua.PubSubConfigurationRefDataType{ConfigurationMask: ua.PubSubConfigurationRefMaskElementModify | refWG})
	require.Len(t, u.Moved, 1)
	g1, n1 = group()
	moved, err = u.RevertMoves()
	require.NoError(t, err)
	g2, n2 := group()
	require.Equal(t, []server.PubSubComponentMove{{From: g1, To: g2, FromNode: n1, ToNode: n2}}, moved)
	moved, err = u.RevertMoves()
	require.NoError(t, err)
	require.Empty(t, moved, "reverted already")

	// Removed and added again in one update: a new group.
	u = update(changed, &ua.PubSubConfigurationRefDataType{ConfigurationMask: ua.PubSubConfigurationRefMaskElementRemove | refWG},
		&ua.PubSubConfigurationRefDataType{ConfigurationMask: refAdd | refWG})
	g3, _ := group()
	require.NotEqual(t, g2, g3)
	require.Empty(t, u.Moved, "a component added under a removed path is not the removed one")
}
