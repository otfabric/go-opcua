// SPDX-License-Identifier: MIT

package server_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/remote"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/server/pubsubstore"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxstore"
	"github.com/otfabric/go-opcua/uafx/fxstore/storetest"
)

const psOwner = "urn:otfabric:test:pubsub-store"

// psStoreServer is a server with a PubSub store on backend, the namespaces
// uris registered before Start.
type psStoreServer struct {
	srv *server.Server
	url string
	st  *pubsubstore.Store
	rt  *pubsub.PubSub
	fn  func(ctx context.Context) ua.StatusCode
}

var psStoreBridge = ua.NewStringNodeID(0, "pubsub-store-bridge")

func startPSStore(t *testing.T, backend fxstore.Store, uris []string, opts ...server.Option) *psStoreServer {
	t.Helper()
	st, err := pubsubstore.Open(context.Background(), backend, pubsubstore.Options{Owner: psOwner})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	all := append([]server.Option{server.EndPoint("localhost", 0), server.InsecureNoSecurity(),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous), server.WithPubSub(nil), server.WithPubSubStore(st)}, opts...)
	srv, err := server.New(all...)
	require.NoError(t, err)
	for _, u := range uris {
		server.NewNodeNameSpace(srv, u)
	}
	p := &psStoreServer{srv: srv, st: st, rt: srv.PubSub()}
	srv.RegisterMethod(nid(id.Server), psStoreBridge, func(ctx context.Context, _, _ *ua.NodeID, _ []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		return nil, p.fn(ctx)
	})
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })
	p.url = fmt.Sprintf("opc.tcp://localhost:%d", srv.Port())
	return p
}

// call runs fn in a Method call of a session, as a companion
// specification's Method would.
func (p *psStoreServer) call(t *testing.T, fn func(ctx context.Context) ua.StatusCode) ua.StatusCode {
	t.Helper()
	p.fn = fn
	return psCall(t, testutil.NewTestClient(t, p.url), nid(id.Server), psStoreBridge).StatusCode
}

func (p *psStoreServer) uris() []string {
	var out []string
	for _, ns := range p.srv.Namespaces() {
		out = append(out, ns.Name())
	}
	return out
}

// stored returns what the store holds, in the namespaces of the server.
func (p *psStoreServer) stored(t *testing.T) *ua.PubSubConfigurationDataType {
	t.Helper()
	cfg, err := p.st.LoadPubSubConfiguration(context.Background(), p.uris())
	require.NoError(t, err)
	return cfg
}

func encodedConfig(t *testing.T, cfg *ua.PubSubConfigurationDataType) []byte {
	t.Helper()
	b, err := ua.Encode(cfg)
	require.NoError(t, err)
	return b
}

func requireConfig(t *testing.T, want, got *ua.PubSubConfigurationDataType, msg ...any) {
	t.Helper()
	require.NotNil(t, got, msg...)
	require.Equal(t, string(encodedConfig(t, want)), string(encodedConfig(t, got)), msg...)
}

// restart closes p and starts a server on the same backend.
func (p *psStoreServer) restart(t *testing.T, backend fxstore.Store, uris []string, opts ...server.Option) *psStoreServer {
	t.Helper()
	require.NoError(t, p.srv.Close())
	require.NoError(t, p.st.Close())
	return startPSStore(t, backend, uris, opts...)
}

func psConn(name string, pub uint16) *ua.PubSubConnectionDataType {
	return pubsub.UDPConnection(name, "opc.udp://239.0.0.1:4840", pub)
}

// TestPubSubStoreRestart: every change through each entry point (the
// Methods of Part 14 §9.1.3, CloseAndUpdate §9.1.3.7.6,
// UpdatePubSubConfiguration and Revert, ChangePubSubConfiguration, and a
// change on the runtime with PersistPubSubConfiguration) is in the store
// when it returns and is the configuration of the server after a restart
// (§9.1.2), with its NodeIds in the namespaces of the restarted server.
func TestPubSubStoreRestart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	backend := &fxstore.MemoryStore{}
	uris := []string{"urn:app"}
	p := startPSStore(t, backend, uris)
	// After a restart urn:app is namespace 3, not 2.
	moved := []string{"urn:other", "urn:app"}
	check := func(what string) {
		t.Helper()
		want := p.rt.Configuration()
		requireConfig(t, want, p.stored(t), what+": stored")
		p = p.restart(t, backend, moved)
		uris, moved = moved, uris
		got := p.rt.Configuration()
		// The NodeIds moved with the namespace.
		wb, gb := encodedConfig(t, want), encodedConfig(t, got)
		require.Len(t, gb, len(wb), what)
		requireConfig(t, p.stored(t), got, what+": restored")
	}
	appNS := func() uint16 {
		for i, u := range p.uris() {
			if u == "urn:app" {
				return uint16(i)
			}
		}
		t.Fatal("no urn:app")
		return 0
	}

	// A Method.
	r := remote.New(testutil.NewTestClient(t, p.url))
	conn, err := r.AddConnection(ctx, psConn("M", 1))
	require.NoError(t, err)
	_, err = r.AddWriterGroup(ctx, conn, pubsub.WriterGroup("G", 1, time.Second))
	require.NoError(t, err)
	require.NoError(t, r.Disable(ctx, conn))
	check("Methods")
	cid, ok := p.rt.Lookup(pubsub.KindConnection, pubsub.Root, "M")
	require.True(t, ok)
	cfg, err := p.rt.ConnectionConfig(cid)
	require.NoError(t, err)
	require.False(t, cfg.Enabled)
	require.Len(t, cfg.WriterGroups, 1)

	// CloseAndUpdate, with a published variable of the application.
	pds := pubsub.PublishedDataItems("Data", pubsub.Var("x", ua.NewStringNodeID(appNS(), "x"), ua.TypeIDDouble))
	c2 := psConn("F", 2)
	c2.WriterGroups = []*ua.WriterGroupDataType{pubsub.WriterGroup("FG", 2, time.Second, pubsub.DataSetWriter("FW", 2, "Data"))}
	r = remote.New(testutil.NewTestClient(t, p.url))
	res, err := r.UpdateConfiguration(ctx, &ua.PubSubConfiguration2DataType{PublishedDataSets: []*ua.PublishedDataSetDataType{pds}, Connections: []*ua.PubSubConnectionDataType{c2}},
		[]*ua.PubSubConfigurationRefDataType{remote.Ref(refAdd, refPDS, 0, 0, 0), remote.Ref(refAdd, refConn, 0, 0, 0), remote.Ref(refAdd, refWG, 0, 0, 0),
			remote.Ref(refAdd, ua.PubSubConfigurationRefMaskReferenceWriter, 0, 0, 0)}, true)
	require.NoError(t, err)
	require.True(t, res.ChangesApplied)
	check("CloseAndUpdate")
	pid, ok := p.rt.Lookup(pubsub.KindPublishedDataSet, pubsub.Root, "Data")
	require.True(t, ok)
	d, err := p.rt.PublishedDataSetConfig(pid)
	require.NoError(t, err)
	items := d.DataSetSource.Value.(*ua.PublishedDataItemsDataType)
	require.Equal(t, ua.NewStringNodeID(appNS(), "x").String(), items.PublishedData[0].PublishedVariable.String())

	// ChangePubSubConfiguration.
	require.NoError(t, p.srv.ChangePubSubConfiguration(func(rt *pubsub.PubSub) error {
		_, err := rt.AddConnection(psConn("Go", 3))
		return err
	}))
	check("ChangePubSubConfiguration")
	_, ok = p.rt.Lookup(pubsub.KindConnection, pubsub.Root, "Go")
	require.True(t, ok)

	// UpdatePubSubConfiguration, then Revert.
	var u *server.PubSubConfigurationUpdate
	require.Equal(t, ua.StatusOK, p.call(t, func(ctx context.Context) ua.StatusCode {
		var sc ua.StatusCode
		u, sc = p.srv.UpdatePubSubConfiguration(ctx, bridgeConfig("U"), true,
			[]*ua.PubSubConfigurationRefDataType{{ConfigurationMask: refAdd | refConn}, {ConfigurationMask: refAdd | refWG}})
		return sc
	}))
	require.True(t, u.ChangesApplied)
	requireConfig(t, p.rt.Configuration(), p.stored(t), "update")
	require.NoError(t, u.Revert())
	_, ok = p.rt.Lookup(pubsub.KindConnection, pubsub.Root, "U")
	require.False(t, ok)
	check("Revert")
	_, ok = p.rt.Lookup(pubsub.KindConnection, pubsub.Root, "U")
	require.False(t, ok)

	// A change on the runtime is stored by PersistPubSubConfiguration.
	_, err = p.rt.AddConnection(psConn("Direct", 4))
	require.NoError(t, err)
	_, ok = connNamed(p.stored(t), "Direct")
	require.False(t, ok, "outside the transaction")
	require.NoError(t, p.srv.PersistPubSubConfiguration(ctx))
	check("PersistPubSubConfiguration")
	_, ok = p.rt.Lookup(pubsub.KindConnection, pubsub.Root, "Direct")
	require.True(t, ok)

	// RemoveConnection and Disable of PublishSubscribe.
	r = remote.New(testutil.NewTestClient(t, p.url))
	conns, err := r.Connections(ctx)
	require.NoError(t, err)
	for _, c := range conns {
		if c.Name == "Go" {
			require.NoError(t, r.RemoveConnection(ctx, c.NodeID))
		}
	}
	require.NoError(t, r.Disable(ctx, nid(id.PublishSubscribe)))
	check("RemoveConnection, Disable")
	_, ok = p.rt.Lookup(pubsub.KindConnection, pubsub.Root, "Go")
	require.False(t, ok)
	require.False(t, p.rt.Configuration().Enabled)
}

func connNamed(cfg *ua.PubSubConfigurationDataType, name string) (*ua.PubSubConnectionDataType, bool) {
	if cfg == nil {
		return nil, false
	}
	i := slices.IndexFunc(cfg.Connections, func(c *ua.PubSubConnectionDataType) bool { return c.Name == name })
	if i < 0 {
		return nil, false
	}
	return cfg.Connections[i], true
}

// TestPubSubStoreReplacesConfiguration: a store that holds a configuration
// replaces the one of WithPubSub; an empty store keeps it, and a
// configuration emptied by its clients stays empty after a restart.
func TestPubSubStoreReplacesConfiguration(t *testing.T) {
	t.Parallel()
	backend := &fxstore.MemoryStore{}
	initial := pubsub.NewConfiguration(nil, psConn("Initial", 1))
	p := startPSStore(t, backend, nil, server.WithPubSub(initial))
	_, ok := p.rt.Lookup(pubsub.KindConnection, pubsub.Root, "Initial")
	require.True(t, ok, "an empty store keeps the configuration of WithPubSub")
	require.Nil(t, p.stored(t))
	require.NoError(t, p.srv.ChangePubSubConfiguration(func(rt *pubsub.PubSub) error {
		cid, _ := rt.Lookup(pubsub.KindConnection, pubsub.Root, "Initial")
		return rt.RemoveConnection(cid)
	}))
	p = p.restart(t, backend, nil, server.WithPubSub(initial))
	require.Empty(t, p.rt.Configuration().Connections, "the store replaces the configuration of WithPubSub")
}

// TestPubSubStoreNotPersisted: a component with 0:NotPersisted TRUE (Part
// 14 §6.2.2 Table 4, §9.1.2) is not stored, nor what is below it; one
// without it, with FALSE or with a value that is not a Boolean is.
func TestPubSubStoreNotPersisted(t *testing.T) {
	t.Parallel()
	np := func(v any) []*ua.KeyValuePair {
		return []*ua.KeyValuePair{{Key: &ua.QualifiedName{Name: "Other"}, Value: ua.MustVariant(true)},
			{Key: &ua.QualifiedName{Name: "NotPersisted"}, Value: ua.MustVariant(v)}}
	}
	backend := &fxstore.MemoryStore{}
	p := startPSStore(t, backend, nil)
	require.NoError(t, p.srv.ChangePubSubConfiguration(func(rt *pubsub.PubSub) error {
		gone := psConn("Gone", 1)
		gone.ConnectionProperties = np(true)
		gone.WriterGroups = []*ua.WriterGroupDataType{pubsub.WriterGroup("Below", 1, time.Second)}
		kept := psConn("Kept", 2)
		kept.ConnectionProperties = np(false)
		wg := pubsub.WriterGroup("WG", 2, time.Second, pubsub.DataSetWriter("W", 2, ""), pubsub.DataSetWriter("NW", 3, ""))
		wg.DataSetWriters[1].DataSetWriterProperties = np(true)
		nwg := pubsub.WriterGroup("NWG", 3, time.Second)
		nwg.GroupProperties = np(true)
		odd := pubsub.WriterGroup("Odd", 4, time.Second)
		odd.GroupProperties = np("true")
		null := pubsub.WriterGroup("Null", 5, time.Second)
		null.GroupProperties = []*ua.KeyValuePair{nil, {Key: &ua.QualifiedName{NamespaceIndex: 1, Name: "NotPersisted"}, Value: ua.MustVariant(true)},
			{Key: &ua.QualifiedName{Name: "NotPersisted"}}}
		kept.WriterGroups = []*ua.WriterGroupDataType{wg, nwg, odd, null}
		rg := pubsub.ReaderGroup("RG", pubsub.DataSetReader("R", uint16(9), 1, 1, nil), pubsub.DataSetReader("NR", uint16(9), 1, 2, nil))
		rg.DataSetReaders[1].DataSetReaderProperties = np(true)
		nrg := pubsub.ReaderGroup("NRG")
		nrg.GroupProperties = np(true)
		kept.ReaderGroups = []*ua.ReaderGroupDataType{rg, nrg}
		for _, c := range []*ua.PubSubConnectionDataType{gone, kept} {
			if _, err := rt.AddConnection(c); err != nil {
				return err
			}
		}
		return nil
	}))
	check := func(cfg *ua.PubSubConfigurationDataType) {
		t.Helper()
		_, ok := connNamed(cfg, "Gone")
		require.False(t, ok)
		c, ok := connNamed(cfg, "Kept")
		require.True(t, ok)
		var groups, writers, readers []string
		for _, g := range c.WriterGroups {
			groups = append(groups, g.Name)
			for _, w := range g.DataSetWriters {
				writers = append(writers, w.Name)
			}
		}
		for _, g := range c.ReaderGroups {
			groups = append(groups, g.Name)
			for _, r := range g.DataSetReaders {
				readers = append(readers, r.Name)
			}
		}
		require.Equal(t, []string{"WG", "Odd", "Null", "RG"}, groups)
		require.Equal(t, []string{"W"}, writers)
		require.Equal(t, []string{"R"}, readers)
	}
	check(p.stored(t))
	p = p.restart(t, backend, nil)
	check(p.rt.Configuration())
}

// TestPubSubStoreNotPersistedInvalid: a configuration that would not be
// valid without its components that are not persisted (an Action
// WriterGroup without a PublishingInterval and its writer) is refused
// with Bad_ConfigurationError and undone.
func TestPubSubStoreNotPersistedInvalid(t *testing.T) {
	t.Parallel()
	p := startPSStore(t, &fxstore.MemoryStore{}, nil)
	err := p.srv.ChangePubSubConfiguration(func(rt *pubsub.PubSub) error {
		if _, err := rt.AddPublishedDataSet(calcAction()); err != nil {
			return err
		}
		c := psConn("A", 1)
		w := pubsub.DataSetWriter("W", 1, "Calc")
		w.DataSetWriterProperties = []*ua.KeyValuePair{{Key: &ua.QualifiedName{Name: "NotPersisted"}, Value: ua.MustVariant(true)}}
		c.WriterGroups = []*ua.WriterGroupDataType{pubsub.WriterGroup("Actions", 1, 0, w)}
		_, err := rt.AddConnection(c)
		return err
	})
	require.ErrorIs(t, err, ua.StatusBadConfigurationError)
	require.Empty(t, p.rt.Configuration().Connections)
	require.Empty(t, p.rt.Configuration().PublishedDataSets)
	require.Nil(t, p.stored(t))
}

// keyRecorder records the keys of the Applies of a backend and fails those
// that write fail, as fault.
type keyRecorder struct {
	fxstore.Store
	mu    sync.Mutex
	keys  []string
	fail  string
	fault storetest.Fault
}

func (k *keyRecorder) Apply(ctx context.Context, b fxstore.Batch) error {
	k.mu.Lock()
	fail, fault := k.fail, k.fault
	k.keys = k.keys[:0]
	for key := range b.Puts {
		k.keys = append(k.keys, key)
	}
	k.keys = append(k.keys, b.Deletes...)
	slices.Sort(k.keys)
	k.mu.Unlock()
	_, put := b.Puts[fail]
	if fail == "" || !put && !slices.Contains(b.Deletes, fail) {
		return k.Store.Apply(ctx, b)
	}
	if fault == storetest.FailNotCommitted {
		return fxstore.AsNotCommitted(storetest.ErrInjected)
	}
	if fault == storetest.FailApplied {
		if err := k.Store.Apply(ctx, b); err != nil {
			return err
		}
	}
	return storetest.ErrInjected
}

func (k *keyRecorder) set(key string, fault storetest.Fault) []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.fail, k.fault = key, fault
	return slices.Clone(k.keys)
}

// TestPubSubStoreFailedCommit: a CloseAndUpdate whose write fails on any
// of its keys, not committed, lost or landed with an unknown outcome, is
// Bad_InternalError and leaves the runtime and the store as they were; an
// unknown outcome fences the store, and Settle (or the next change)
// resolves it.
func TestPubSubStoreFailedCommit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	refs := []*ua.PubSubConfigurationRefDataType{remote.Ref(refAdd, refPDS, 0, 0, 0), remote.Ref(refAdd, refConn, 0, 0, 0),
		remote.Ref(refAdd, refConn, 1, 0, 0), remote.Ref(refRemove, refConn, 2, 0, 0)}
	file := &ua.PubSubConfiguration2DataType{PublishedDataSets: []*ua.PublishedDataSetDataType{calcAction()},
		Connections: []*ua.PubSubConnectionDataType{psConn("B", 2), psConn("C", 3), psConn("A", 1)}}
	setup := func(t *testing.T) (*psStoreServer, *keyRecorder, *remote.Client, *ua.PubSubConfigurationDataType) {
		k := &keyRecorder{Store: &fxstore.MemoryStore{}}
		p := startPSStore(t, k, nil)
		require.NoError(t, p.srv.ChangePubSubConfiguration(func(rt *pubsub.PubSub) error {
			_, err := rt.AddConnection(psConn("A", 1))
			return err
		}))
		return p, k, remote.New(testutil.NewTestClient(t, p.url)), p.rt.Configuration()
	}
	// The keys of the update.
	p, k, r, _ := setup(t)
	_, err := r.UpdateConfiguration(ctx, file, refs, true)
	require.NoError(t, err)
	keys := k.set("", 0)
	require.Len(t, keys, 6, "the meta record, root, the PublishedDataSet, B, C and A deleted: %v", keys)
	require.NoError(t, p.srv.Close())

	for _, fault := range []storetest.Fault{storetest.FailNotCommitted, storetest.FailLost, storetest.FailApplied} {
		for _, key := range keys {
			t.Run(fmt.Sprintf("%d/%s", fault, key), func(t *testing.T) {
				p, k, r, before := setup(t)
				k.set(key, fault)
				_, err := r.UpdateConfiguration(ctx, file, refs, true)
				require.ErrorIs(t, err, ua.StatusBadInternalError)
				requireConfig(t, before, p.rt.Configuration(), "the runtime is unchanged")
				require.Equal(t, fault != storetest.FailNotCommitted, p.st.Status().Fenced)
				k.set("", 0)
				ok, err := p.st.Settle(ctx)
				require.NoError(t, err)
				require.True(t, ok)
				requireConfig(t, before, p.stored(t), "the store holds the configuration before")
				// A restart brings back the configuration before.
				p = p.restart(t, k, nil)
				requireConfig(t, before, p.rt.Configuration())
			})
		}
	}

	// An unknown outcome is settled by the next change.
	f := storetest.NewFaulty(&fxstore.MemoryStore{})
	p = startPSStore(t, f, nil)
	r = remote.New(testutil.NewTestClient(t, p.url))
	f.FailApply(storetest.FailApplied)
	_, err = r.AddConnection(ctx, psConn("X", 1))
	require.ErrorIs(t, err, ua.StatusBadInternalError)
	_, ok := p.rt.Lookup(pubsub.KindConnection, pubsub.Root, "X")
	require.False(t, ok)
	require.True(t, p.st.Status().Fenced)
	_, err = r.AddConnection(ctx, psConn("Y", 2))
	require.NoError(t, err)
	require.False(t, p.st.Status().Fenced)
	requireConfig(t, p.rt.Configuration(), p.stored(t))
	_, ok = connNamed(p.stored(t), "X")
	require.False(t, ok)

	// A Disable of PublishSubscribe the store refuses is undone.
	f.FailApply(storetest.FailNotCommitted)
	require.ErrorIs(t, r.Disable(ctx, nid(id.PublishSubscribe)), ua.StatusBadInternalError)
	require.True(t, p.rt.Configuration().Enabled)

	// PersistPubSubConfiguration reports a failure and changes nothing.
	_, err = p.rt.AddConnection(psConn("Z", 3))
	require.NoError(t, err)
	f.FailApply(storetest.FailNotCommitted)
	require.ErrorIs(t, p.srv.PersistPubSubConfiguration(ctx), ua.StatusBadInternalError)
	_, ok = p.rt.Lookup(pubsub.KindConnection, pubsub.Root, "Z")
	require.True(t, ok)
	require.NoError(t, p.srv.PersistPubSubConfiguration(ctx))
	requireConfig(t, p.rt.Configuration(), p.stored(t))
}

// TestPubSubStoreHook: a change the hook refuses is not written; when the
// store refuses a change the hook accepted, the hook sees the undo as a
// Revert from the refused configuration, with the components the undo
// brought back under a new ComponentID.
func TestPubSubStoreHook(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := storetest.NewFaulty(&fxstore.MemoryStore{})
	p := startPSStore(t, f, nil)
	h := &recordingHook{}
	p.srv.SetPubSubConfigurationHook(h)
	require.NoError(t, p.srv.ChangePubSubConfiguration(func(rt *pubsub.PubSub) error {
		_, err := rt.AddConnection(psConn("A", 1))
		return err
	}))
	h.take()

	n := f.Applies()
	h.set(ua.StatusBadInvalidState, false)
	err := p.srv.ChangePubSubConfiguration(func(rt *pubsub.PubSub) error {
		_, err := rt.AddConnection(psConn("B", 2))
		return err
	})
	require.ErrorIs(t, err, ua.StatusBadInvalidState)
	require.Equal(t, n, f.Applies(), "a refused change is not written")
	h.take()
	h.set(nil, false)

	// The store refuses a modification of A: A comes back under a new id.
	old, ok := p.rt.Lookup(pubsub.KindConnection, pubsub.Root, "A")
	require.True(t, ok)
	f.FailApply(storetest.FailNotCommitted)
	r := remote.New(testutil.NewTestClient(t, p.url))
	m := psConn("A", 9)
	_, err = r.UpdateConfiguration(ctx, &ua.PubSubConfiguration2DataType{Connections: []*ua.PubSubConnectionDataType{m}},
		[]*ua.PubSubConfigurationRefDataType{remote.Ref(refModify, refConn, 0, 0, 0)}, true)
	require.ErrorIs(t, err, ua.StatusBadInternalError)
	ch := h.take()
	require.Len(t, ch, 2)
	require.False(t, ch[0].Revert)
	require.True(t, ch[1].Revert)
	requireConfig(t, ch[0].After, ch[1].Before)
	requireConfig(t, ch[0].Before, ch[1].After)
	requireConfig(t, ch[0].Before, p.rt.Configuration())
	require.Len(t, ch[1].Moved, 1)
	cur, ok := p.rt.Lookup(pubsub.KindConnection, pubsub.Root, "A")
	require.True(t, ok)
	require.Equal(t, cur, ch[1].Moved[0].To)
	require.NotEqual(t, old, cur)

	// A hook that refuses the undo is logged; the change fails all the same.
	h.mu.Lock()
	h.err = nil
	h.mu.Unlock()
	refuseUndo := &undoRefuser{}
	p.srv.SetPubSubConfigurationHook(refuseUndo)
	f.FailApply(storetest.FailNotCommitted)
	err = p.srv.ChangePubSubConfiguration(func(rt *pubsub.PubSub) error {
		_, err := rt.AddConnection(psConn("C", 3))
		return err
	})
	require.ErrorIs(t, err, ua.StatusBadInternalError)
	_, ok = p.rt.Lookup(pubsub.KindConnection, pubsub.Root, "C")
	require.False(t, ok)
	require.Equal(t, 2, refuseUndo.calls)
}

// undoRefuser accepts changes and refuses reverts.
type undoRefuser struct{ calls int }

func (u *undoRefuser) PubSubConfigurationChanged(ch *server.PubSubChange) error {
	u.calls++
	if ch.Revert {
		return errors.New("no")
	}
	return nil
}

func (u *undoRefuser) HeldPubSubIDs() ([]uint16, []uint16, bool) { return nil, nil, false }

// owner owns the components whose last name is in names.
type owner struct {
	mu    sync.Mutex
	names []string
	seen  int
}

func (o *owner) OwnsPubSubComponent(ch *server.PubSubChange, _ pubsub.ComponentKind, path []string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if ch == nil || ch.After == nil {
		panic("no change")
	}
	o.seen++
	return slices.Contains(o.names, path[len(path)-1])
}

// TestPubSubStoreOwner: the components a PubSubComponentOwner keeps are
// not stored, nor what is below them, nor a writer of a PublishedDataSet
// it keeps; PersistPubSubConfiguration hands over what it no longer keeps.
func TestPubSubStoreOwner(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := startPSStore(t, &fxstore.MemoryStore{}, nil)
	o := &owner{names: []string{"Owned", "OG", "OW", "OR", "Calc"}}
	p.srv.SetPubSubComponentOwner(o)
	require.NoError(t, p.srv.ChangePubSubConfiguration(func(rt *pubsub.PubSub) error {
		if _, err := rt.AddPublishedDataSet(calcAction()); err != nil {
			return err
		}
		owned := psConn("Owned", 1)
		owned.WriterGroups = []*ua.WriterGroupDataType{pubsub.WriterGroup("Below", 1, time.Second)}
		mine := psConn("Mine", 2)
		mine.WriterGroups = []*ua.WriterGroupDataType{
			pubsub.WriterGroup("G", 2, time.Second, pubsub.DataSetWriter("W", 2, ""), pubsub.DataSetWriter("OW", 3, ""), pubsub.DataSetWriter("CW", 4, "Calc")),
			pubsub.WriterGroup("OG", 3, time.Second),
		}
		mine.ReaderGroups = []*ua.ReaderGroupDataType{pubsub.ReaderGroup("RG", pubsub.DataSetReader("R", uint16(9), 1, 1, nil), pubsub.DataSetReader("OR", uint16(9), 1, 2, nil))}
		for _, c := range []*ua.PubSubConnectionDataType{owned, mine} {
			if _, err := rt.AddConnection(c); err != nil {
				return err
			}
		}
		return nil
	}))
	got := p.stored(t)
	require.Empty(t, got.PublishedDataSets)
	require.Len(t, got.Connections, 1)
	c := got.Connections[0]
	require.Equal(t, "Mine", c.Name)
	require.Len(t, c.WriterGroups, 1)
	require.Equal(t, []string{"W"}, []string{c.WriterGroups[0].DataSetWriters[0].Name})
	require.Len(t, c.WriterGroups[0].DataSetWriters, 1)
	require.Len(t, c.ReaderGroups[0].DataSetReaders, 1)

	// The owner lets go of everything: PersistPubSubConfiguration stores it.
	o.mu.Lock()
	o.names = nil
	o.mu.Unlock()
	require.NoError(t, p.srv.PersistPubSubConfiguration(ctx))
	requireConfig(t, p.rt.Configuration(), p.stored(t))
	p.srv.SetPubSubComponentOwner(nil)
	require.NoError(t, p.srv.ChangePubSubConfiguration(func(rt *pubsub.PubSub) error {
		_, err := rt.AddConnection(psConn("After", 5))
		return err
	}))
	requireConfig(t, p.rt.Configuration(), p.stored(t))
}

// TestPubSubStoreSecured: a restored secured WriterGroup, ReaderGroup or
// DataSetReader gates its SecurityGroup (Part 14 §7.2.3, §7.2.4.4.3); the
// configuration of WithPubSub of an empty store is not gated.
func TestPubSubStoreSecured(t *testing.T) {
	t.Parallel()
	backend := &fxstore.MemoryStore{}
	c := psConn("S", 1)
	wg := pubsub.WriterGroup("WG", 1, time.Second)
	wg.SecurityMode, wg.SecurityGroupID = ua.MessageSecurityModeSign, "w"
	rg := pubsub.ReaderGroup("RG", pubsub.DataSetReader("R", uint16(9), 1, 1, nil))
	rg.SecurityMode, rg.SecurityGroupID = ua.MessageSecurityModeSignAndEncrypt, "r"
	rg.DataSetReaders[0].SecurityMode, rg.DataSetReaders[0].SecurityGroupID = ua.MessageSecurityModeSign, "d"
	none := pubsub.WriterGroup("None", 2, time.Second)
	none.SecurityGroupID = "n"
	c.WriterGroups, c.ReaderGroups = []*ua.WriterGroupDataType{wg, none}, []*ua.ReaderGroupDataType{rg}
	cfg := pubsub.NewConfiguration(nil, c)
	p := startPSStore(t, backend, nil, server.WithPubSub(cfg))
	gated, _ := p.rt.SecurityGroupGate("w")
	require.False(t, gated)
	require.NoError(t, p.srv.PersistPubSubConfiguration(context.Background()))
	p = p.restart(t, backend, nil, server.WithPubSub(cfg))
	for g, want := range map[string]bool{"w": true, "r": true, "d": true, "n": false} {
		gated, _ := p.rt.SecurityGroupGate(g)
		require.Equal(t, want, gated, g)
	}
}

// failingLoad is a PubSubConfigurationStore whose Load fails or returns
// cfg.
type failingLoad struct {
	err   error
	cfg   *ua.PubSubConfigurationDataType
	loads int
}

func (f *failingLoad) LoadPubSubConfiguration(context.Context, []string) (*ua.PubSubConfigurationDataType, error) {
	f.loads++
	return f.cfg, f.err
}

func (f *failingLoad) StorePubSubConfiguration(context.Context, *ua.PubSubConfigurationDataType, []string) error {
	return nil
}

// TestPubSubStoreRestoreErrors: a store that does not load, a stored
// configuration that is not valid or a NodeId of a namespace the server
// does not have fail BuildPubSubModel, Start and ChangePubSubConfiguration
// (fail closed), until the restore succeeds; WithPubSubStore needs a store
// and WithPubSub.
func TestPubSubStoreRestoreErrors(t *testing.T) {
	t.Parallel()
	_, err := server.New(server.WithPubSubStore(nil))
	require.Error(t, err)
	_, err = server.New(server.WithPubSubStore(&failingLoad{}))
	require.Error(t, err)

	fl := &failingLoad{err: errors.New("disk gone")}
	srv, err := server.New(server.EndPoint("localhost", 0), server.InsecureNoSecurity(), server.WithPubSub(nil), server.WithPubSubStore(fl))
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })
	require.ErrorIs(t, srv.BuildPubSubModel(), fl.err)
	require.ErrorIs(t, srv.Start(context.Background()), fl.err)
	require.ErrorIs(t, srv.ChangePubSubConfiguration(func(*pubsub.PubSub) error { return nil }), fl.err)
	require.ErrorIs(t, srv.PersistPubSubConfiguration(context.Background()), fl.err)

	// Not valid.
	fl.err, fl.cfg = nil, &ua.PubSubConfigurationDataType{Connections: []*ua.PubSubConnectionDataType{{Name: "x"}}}
	require.Error(t, srv.BuildPubSubModel())
	// Valid: the restore succeeds once, then is not repeated.
	fl.cfg = pubsub.NewConfiguration(nil, psConn("R", 1))
	require.NoError(t, srv.BuildPubSubModel())
	n := fl.loads
	require.NoError(t, srv.BuildPubSubModel())
	require.NoError(t, srv.ChangePubSubConfiguration(func(*pubsub.PubSub) error { return nil }))
	require.Equal(t, n, fl.loads)
	_, ok := srv.PubSub().Lookup(pubsub.KindConnection, pubsub.Root, "R")
	require.True(t, ok)

	// A namespace the server does not have.
	backend := &fxstore.MemoryStore{}
	p := startPSStore(t, backend, []string{"urn:app"})
	require.NoError(t, p.srv.ChangePubSubConfiguration(func(rt *pubsub.PubSub) error {
		_, err := rt.AddPublishedDataSet(pubsub.PublishedDataItems("D", pubsub.Var("x", ua.NewStringNodeID(2, "x"), ua.TypeIDDouble)))
		return err
	}))
	require.NoError(t, p.srv.Close())
	require.NoError(t, p.st.Close())
	st, err := pubsubstore.Open(context.Background(), backend, pubsubstore.Options{Owner: psOwner})
	require.NoError(t, err)
	srv2, err := server.New(server.EndPoint("localhost", 0), server.InsecureNoSecurity(), server.WithPubSub(nil), server.WithPubSubStore(st))
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv2.Close() })
	require.ErrorIs(t, srv2.Start(context.Background()), pubsubstore.ErrNamespace)
}

// TestPubSubStoreWithoutStore: PersistPubSubConfiguration does nothing
// without a store and is Bad_NotSupported without PubSub.
func TestPubSubStoreWithoutStore(t *testing.T) {
	t.Parallel()
	srv, _ := testutil.NewTestServer(t, server.WithPubSub(nil))
	require.NoError(t, srv.PersistPubSubConfiguration(context.Background()))
	plain, _ := testutil.NewTestServer(t)
	require.ErrorIs(t, plain.PersistPubSubConfiguration(context.Background()), ua.StatusBadNotSupported)
}

// TestPubSubStoreConcurrent: the Methods of Part 14 §9.1.3 racing
// CloseAndUpdate of the file and ChangePubSubConfiguration (Part 14 §9.1.2:
// the mechanisms coordinate access) leave the store with the configuration
// of the runtime, and a restart with it.
func TestPubSubStoreConcurrent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	backend := &fxstore.MemoryStore{}
	p := startPSStore(t, backend, nil)
	var wg sync.WaitGroup
	for i := range 3 {
		r := remote.New(testutil.NewTestClient(t, p.url))
		wg.Go(func() {
			for j := range 5 {
				name := fmt.Sprintf("M%d-%d", i, j)
				c, err := r.AddConnection(ctx, psConn(name, uint16(10*i+j+1)))
				if err != nil {
					t.Error(err)
					return
				}
				if j%2 == 0 {
					if err := r.RemoveConnection(ctx, c); err != nil {
						t.Error(err)
					}
				}
			}
		})
	}
	for i := range 2 {
		r := remote.New(testutil.NewTestClient(t, p.url))
		wg.Go(func() {
			for j := range 5 {
				file := &ua.PubSubConfiguration2DataType{Connections: []*ua.PubSubConnectionDataType{psConn(fmt.Sprintf("F%d-%d", i, j), uint16(100+10*i+j))}}
				// One client writes the file at a time (OPC 10000-20 §4.2.2
				// Open: Bad_NotWritable while it is open): the other retries.
				for {
					_, err := r.UpdateConfiguration(ctx, file, []*ua.PubSubConfigurationRefDataType{remote.Ref(refAdd, refConn, 0, 0, 0)}, true)
					if errors.Is(err, ua.StatusBadNotWritable) {
						time.Sleep(time.Millisecond)
						continue
					}
					if err != nil {
						t.Error(err)
					}
					break
				}
			}
		})
	}
	wg.Go(func() {
		for j := range 5 {
			if err := p.srv.ChangePubSubConfiguration(func(rt *pubsub.PubSub) error {
				_, err := rt.AddConnection(psConn(fmt.Sprintf("G%d", j), uint16(200+j)))
				return err
			}); err != nil {
				t.Error(err)
			}
		}
	})
	wg.Wait()
	want := p.rt.Configuration()
	require.Len(t, want.Connections, 3*2+2*5+5)
	requireConfig(t, want, p.stored(t))
	p = p.restart(t, backend, nil)
	got := p.rt.Configuration()
	require.True(t, bytes.Equal(encodedConfig(t, want), encodedConfig(t, got)))
}

// TestPubSubHookRefusesRootDisable: a Disable of PublishSubscribe the
// PubSubConfigurationHook refuses is undone, without a store too.
func TestPubSubHookRefusesRootDisable(t *testing.T) {
	t.Parallel()
	srv, url := testutil.NewTestServer(t, server.WithPubSub(nil))
	h := &recordingHook{}
	srv.SetPubSubConfigurationHook(h)
	h.set(ua.StatusBadInvalidState, false)
	r := remote.New(testutil.NewTestClient(t, url))
	require.ErrorIs(t, r.Disable(context.Background(), nid(id.PublishSubscribe)), ua.StatusBadInvalidState)
	require.True(t, srv.PubSub().Configuration().Enabled)
}
