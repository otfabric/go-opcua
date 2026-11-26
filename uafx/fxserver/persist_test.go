// SPDX-License-Identifier: MIT

package fxserver_test

import (
	"context"
	"crypto/rand"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil/fxtest"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/remote"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxserver"
	"github.com/otfabric/go-opcua/uafx/fxstore"
	"github.com/otfabric/go-opcua/uafx/fxstore/storetest"
)

// persistentRequest is fullRequest with IsPersistent TRUE.
func (f *fx) persistentRequest(name string) *uafx.EstablishConnectionsRequest {
	r := f.fullRequest(name)
	r.ConnectionEndpointConfigurations[0].ConnectionEndpoint.Parameter.IsPersistent = true
	return r
}

// persistent establishes the persistent endpoint name and waits until it
// is Operational.
func (f *fx) persistent(t *testing.T, name string) *ua.NodeID {
	t.Helper()
	res := f.establish(t, f.persistentRequest(name))
	require.Equal(t, ua.StatusOK, res.Status, "%+v", res.ConnectionEndpointConfigurationResults[0])
	ep := res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointID
	f.waitStatus(t, ep, uafx.ConnectionEndpointOperational)
	return ep
}

func (f *fx) waitStatus(t *testing.T, ep *ua.NodeID, want uafx.ConnectionEndpointStatus) {
	t.Helper()
	require.Eventually(t, func() bool { st, ok := f.conns.Status(ep); return ok && st == want }, 5*time.Second, 5*time.Millisecond,
		"the Status of %v does not become %v", ep, want)
}

// stop stops the server of f as a restart does.
func (f *fx) stop(t *testing.T) {
	t.Helper()
	require.NoError(t, f.conns.Close())
	_ = f.c.Close(context.Background())
	require.NoError(t, f.srv.Close())
}

// restart stops f and starts a server with the same nodes on the store of
// opts.
func (f *fx) restart(t *testing.T, opts fxserver.ConnectionOptions) *fx {
	t.Helper()
	f.stop(t)
	return newFX(t, opts)
}

// reserve calls ReserveIds as a client (Part 14 §9.1.3.7.5).
func (f *fx) reserve(t *testing.T) (*remote.ReservedIDs, ua.StatusCode) {
	t.Helper()
	ids, err := remote.New(f.c).ReserveIDs(context.Background(), "http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp", 1, 1)
	return ids, statusOf(t, err)
}

// update applies cfg with CloseAndUpdate as a client and returns the
// first Bad status.
func (f *fx) update(t *testing.T, cfg *ua.PubSubConfiguration2DataType, refs ...*ua.PubSubConfigurationRefDataType) ua.StatusCode {
	t.Helper()
	res, err := remote.New(f.c).UpdateConfiguration(context.Background(), cfg, refs, false)
	if sc := statusOf(t, err); sc != ua.StatusOK {
		return sc
	}
	for _, r := range res.Results {
		if r != ua.StatusOK {
			return r
		}
	}
	return ua.StatusOK
}

func statusOf(t *testing.T, err error) ua.StatusCode {
	t.Helper()
	if err == nil {
		return ua.StatusOK
	}
	var sc ua.StatusCode
	require.True(t, errors.As(err, &sc), "%v", err)
	return sc
}

// child returns the hierarchical child of n with the BrowseName name, as a
// client browses it.
func (f *fx) child(t *testing.T, n *ua.NodeID, name string) *ua.NodeID {
	t.Helper()
	nodes, err := f.c.Node(n).ReferencedNodes(context.Background(), id.HierarchicalReferences, ua.BrowseDirectionForward, ua.NodeClassAll, true)
	require.NoError(t, err)
	for _, x := range nodes {
		bn, err := x.BrowseName(context.Background())
		require.NoError(t, err)
		if bn.Name == name {
			return x.ID
		}
	}
	return nil
}

func (f *fx) read(t *testing.T, n *ua.NodeID) any {
	t.Helper()
	require.NotNil(t, n)
	v, err := f.c.Node(n).Value(context.Background())
	require.NoError(t, err)
	return v.Value()
}

// endpointNamed returns the endpoint of the connections with the
// BrowseName name.
func (f *fx) endpointNamed(name string) *ua.NodeID {
	for _, n := range f.conns.Endpoints() {
		if bn := f.srv.Node(n).BrowseName(); bn != nil && bn.Name == name {
			return n
		}
	}
	return nil
}

// TestPersistentRestored: a persistent endpoint is stored and restored
// after a restart at its NodeId, with its CreationTime, enabled, and
// communicates again (Part 81 §6.6.2, AP-5, AP-14); SupportsPersistence is
// TRUE (§6.2.6).
func TestPersistentRestored(t *testing.T) {
	t.Parallel()
	store := &fxstore.MemoryStore{}
	opts := fxserver.ConnectionOptions{Store: store}
	f := newFX(t, opts)
	caps := f.child(t, f.id(ctlID), "ComponentCapabilities")
	require.Equal(t, true, f.read(t, f.child(t, caps, "SupportsPersistence")))

	ep := f.persistent(t, "P")
	require.Equal(t, true, f.read(t, f.child(t, ep, "IsPersistent")))
	diag := f.child(t, ep, "Diagnostics")
	require.NotNil(t, diag)
	created, ok := f.read(t, f.child(t, diag, "CreationTime")).(time.Time)
	require.True(t, ok)
	require.WithinDuration(t, time.Now(), created, time.Minute)
	st := f.conns.Persistence()
	require.True(t, st.Enabled)
	require.Equal(t, 1, st.Records)
	require.False(t, st.Store.Fenced)

	f = f.restart(t, opts)
	require.Equal(t, []*ua.NodeID{ep}, f.conns.Persistence().Restored)
	require.Empty(t, f.conns.Quarantined())
	f.waitStatus(t, ep, uafx.ConnectionEndpointOperational)
	require.Equal(t, true, f.read(t, f.child(t, ep, "IsPersistent")))
	diag = f.child(t, ep, "Diagnostics")
	again, _ := f.read(t, f.child(t, diag, "CreationTime")).(time.Time)
	require.True(t, created.Equal(again), "CreationTime %v, after the restart %v", created, again)
	caps = f.child(t, f.id(ctlID), "ComponentCapabilities")
	require.Equal(t, true, f.read(t, f.child(t, caps, "SupportsPersistence")))

	// Restored once, after a second restart too.
	f = f.restart(t, opts)
	f.waitStatus(t, ep, uafx.ConnectionEndpointOperational)
	require.Len(t, f.conns.Endpoints(), 2)

	// A non-persistent endpoint is not restored (AP-6), and nothing of its
	// PubSub configuration.
	opts = fxserver.ConnectionOptions{Store: &fxstore.MemoryStore{}}
	f = newFX(t, opts)
	np := f.operational(t, "N", -1)
	require.Equal(t, 0, f.conns.Persistence().Records)
	f = f.restart(t, opts)
	require.Nil(t, f.srv.Node(np))
	require.Nil(t, f.endpointNamed("N"))
	require.Empty(t, f.srv.PubSub().Configuration().Connections)
}

// TestPersistentDisableAndRemove: CloseConnections with Remove FALSE is
// durable, the endpoint is restored disabled with its control; enabling it
// again is durable; Remove TRUE prevents its restoration (C3-D8).
func TestPersistentDisableAndRemove(t *testing.T) {
	t.Parallel()
	store := &fxstore.MemoryStore{}
	opts := fxserver.ConnectionOptions{Store: store}
	f := newFX(t, opts)
	ep := f.persistent(t, "P")

	sc, res := f.close(t, false, ep)
	require.Equal(t, ua.StatusOK, sc, "%v", res)
	f.waitStatus(t, ep, uafx.ConnectionEndpointReady)
	f = f.restart(t, opts)
	f.waitStatus(t, ep, uafx.ConnectionEndpointReady)
	time.Sleep(50 * time.Millisecond)
	st, _ := f.conns.Status(ep)
	require.Equal(t, uafx.ConnectionEndpointReady, st, "restored disabled")

	// Enable again: durable as well.
	er := f.establish(t, &uafx.EstablishConnectionsRequest{CommandMask: uafx.EnableCommunicationCmd,
		ConnectionEndpointConfigurations: []*uafx.ConnectionEndpointConfiguration{{FunctionalEntityNode: f.id(motionID),
			ConnectionEndpoint: &uafx.ConnectionEndpointDefinition{Node: ep}}}})
	require.Equal(t, ua.StatusOK, er.Status, "%+v", er.ConnectionEndpointConfigurationResults[0])
	f.waitStatus(t, ep, uafx.ConnectionEndpointOperational)
	f = f.restart(t, opts)
	f.waitStatus(t, ep, uafx.ConnectionEndpointOperational)

	sc, res = f.close(t, true, ep)
	require.Equal(t, ua.StatusOK, sc, "%v", res)
	require.Nil(t, f.srv.Node(ep))
	require.Equal(t, 0, f.conns.Persistence().Records)
	f = f.restart(t, opts)
	require.Nil(t, f.srv.Node(ep))
	require.Len(t, f.conns.Endpoints(), 1, "only the preconfigured endpoint")
	require.Empty(t, f.srv.PubSub().Configuration().Connections)
	keys, err := store.Load(context.Background())
	require.NoError(t, err)
	for k := range keys {
		require.True(t, k == "ac/meta", "key %q left", k)
	}
}

// TestPersistentValidation: IsPersistent TRUE needs SupportsPersistence
// (Bad_NotSupported, Part 81 Table 12) and a negative finite
// CleanupTimeout (C3-D4: Bad_InvalidArgument), checked before anything
// changes.
func TestPersistentValidation(t *testing.T) {
	t.Parallel()
	f := newFX(t, fxserver.ConnectionOptions{})
	res := f.establish(t, f.persistentRequest("P"))
	require.Equal(t, ua.StatusUncertain, res.Status)
	require.Equal(t, ua.StatusBadNotSupported, res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointResult)
	require.Equal(t, ua.StatusBadNothingToDo, res.ConnectionEndpointConfigurationResults[0].VerificationStatus, "nothing ran")
	require.Nil(t, f.endpointNamed("P"))
	require.Empty(t, f.conns.Persistence().Restored)
	require.False(t, f.conns.Persistence().Enabled)

	f = newFX(t, fxserver.ConnectionOptions{Store: &fxstore.MemoryStore{}})
	for _, ct := range []float64{0, 5, math.NaN(), math.Inf(1), math.Inf(-1)} {
		r := f.persistentRequest("P")
		r.ConnectionEndpointConfigurations[0].ConnectionEndpoint.Parameter.CleanupTimeout = ct
		res := f.establish(t, r)
		require.Equal(t, ua.StatusUncertain, res.Status, "%v", ct)
		require.Equal(t, ua.StatusBadInvalidArgument, res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointResult, "%v", ct)
		require.Nil(t, f.endpointNamed("P"))
		require.Empty(t, f.srv.PubSub().Configuration().Connections)
	}
	require.Equal(t, 0, f.conns.Persistence().Records)
}

// TestPersistentCommitFaults: the outcomes of the commit point (design
// §4.3, C3-D13): not committed is Bad_ResourceUnavailable and nothing
// stays; unknown is Bad_InternalError, the call is rolled back, the store
// fenced until settled, and the store then holds nothing of the call.
func TestPersistentCommitFaults(t *testing.T) {
	t.Parallel()
	store := storetest.NewFaulty(&fxstore.MemoryStore{})
	f := newFX(t, fxserver.ConnectionOptions{Store: store})

	store.FailApply(storetest.FailNotCommitted)
	res := f.establish(t, f.persistentRequest("P"))
	require.Equal(t, ua.StatusUncertain, res.Status)
	er := res.ConnectionEndpointConfigurationResults[0]
	require.Equal(t, ua.StatusBadResourceUnavailable, er.ConnectionEndpointResult)
	require.Equal(t, ua.StatusBadNothingToDo, er.EnableCommunicationResult)
	require.Nil(t, f.endpointNamed("P"))
	require.Empty(t, f.srv.PubSub().Configuration().Connections)
	require.False(t, f.conns.Persistence().Store.Fenced)

	for _, fault := range []storetest.Fault{storetest.FailLost, storetest.FailApplied} {
		// The fence holds while the settling cannot load the store.
		store.FailLoadsWith(storetest.ErrInjected)
		store.FailApply(fault)
		res = f.establish(t, f.persistentRequest("P"))
		require.Equal(t, ua.StatusUncertain, res.Status)
		require.Equal(t, ua.StatusBadInternalError, res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointResult)
		require.Nil(t, f.endpointNamed("P"))
		require.Empty(t, f.srv.PubSub().Configuration().Connections)
		require.True(t, f.conns.Persistence().Store.Fenced)
		// Fenced: refused before anything changes; reads go on.
		require.Equal(t, ua.StatusBadResourceUnavailable, f.callStatus(t, f.persistentRequest("Q")))
		_, sc := f.reserve(t)
		require.Equal(t, ua.StatusBadResourceUnavailable, sc, "no id is handed out while fenced")
		store.FailLoadsWith(nil)
		require.Eventually(t, func() bool { return !f.conns.Persistence().Store.Fenced }, 5*time.Second, 10*time.Millisecond)
		require.Equal(t, 0, f.conns.Persistence().Records, "%v", fault)
	}
	f.persistent(t, "P")
	require.Equal(t, 1, f.conns.Persistence().Records)
}

// TestPersistentCloseFaults: the intent of a close is durable first (design
// §4.4): not committed changes nothing (Bad_ResourceUnavailable); unknown
// acts in the safe direction (Bad_InternalError) and the store follows.
func TestPersistentCloseFaults(t *testing.T) {
	t.Parallel()
	mem := &fxstore.MemoryStore{}
	store := storetest.NewFaulty(mem)
	opts := fxserver.ConnectionOptions{Store: store}
	f := newFX(t, opts)
	ep := f.persistent(t, "P")

	for _, remove := range []bool{false, true} {
		store.FailApply(storetest.FailNotCommitted)
		sc, res := f.close(t, remove, ep)
		require.Equal(t, ua.StatusUncertain, sc)
		require.Equal(t, []ua.StatusCode{ua.StatusBadResourceUnavailable}, res)
		f.waitStatus(t, ep, uafx.ConnectionEndpointOperational)
	}

	// Disable with an unknown outcome: disabled; the record follows.
	store.FailApply(storetest.FailLost)
	_, res := f.close(t, false, ep)
	require.Equal(t, []ua.StatusCode{ua.StatusBadInternalError}, res)
	f.waitStatus(t, ep, uafx.ConnectionEndpointReady)
	require.Eventually(t, func() bool { return !f.conns.Persistence().Store.Fenced }, 5*time.Second, 10*time.Millisecond)
	f = f.restart(t, opts)
	f.waitStatus(t, ep, uafx.ConnectionEndpointReady)

	// Remove with an unknown intent: removed; the record goes.
	store.FailApply(storetest.FailLost)
	_, res = f.close(t, true, ep)
	require.Equal(t, []ua.StatusCode{ua.StatusBadInternalError}, res)
	require.Nil(t, f.srv.Node(ep))
	require.Eventually(t, func() bool { return !f.conns.Persistence().Store.Fenced }, 5*time.Second, 10*time.Millisecond)
	require.Equal(t, 0, f.conns.Persistence().Records)
	f = f.restart(t, opts)
	require.Nil(t, f.srv.Node(ep))
}

// TestPersistentHook: changes from other mechanisms follow into the records
// (design §4.5): a modification is restored, a removal is not undone by a
// restart, NotPersisted TRUE is refused, and a change whose record is not
// committed is refused.
func TestPersistentHook(t *testing.T) {
	t.Parallel()
	mem := &fxstore.MemoryStore{}
	store := storetest.NewFaulty(mem)
	opts := fxserver.ConnectionOptions{Store: store}
	f := newFX(t, opts)
	ep := f.persistent(t, "P")

	modify := func(mod func(c *ua.PubSubConfiguration2DataType)) ua.StatusCode {
		cfg := f.pubsubConfig(0)
		mod(cfg)
		return f.update(t, cfg, ref(ua.PubSubConfigurationRefMaskElementModify|refWG, 0, 0, 0))
	}
	interval := func(f *fx) float64 {
		g := f.lookupGroup(t, pubConn, wgName)
		cfg, err := f.srv.PubSub().WriterGroupConfig(g)
		require.NoError(t, err)
		return cfg.PublishingInterval
	}
	// NotPersisted TRUE on a persisted component: refused.
	np := []*ua.KeyValuePair{{Key: &ua.QualifiedName{Name: "NotPersisted"}, Value: ua.MustVariant(true)}}
	require.Equal(t, ua.StatusBadInvalidState, modify(func(c *ua.PubSubConfiguration2DataType) {
		c.Connections[0].WriterGroups[0].GroupProperties = np
	}))
	// A record that is not committed: refused, the runtime unchanged.
	store.FailApply(storetest.FailNotCommitted)
	require.Equal(t, ua.StatusBadResourceUnavailable, modify(func(c *ua.PubSubConfiguration2DataType) {
		c.Connections[0].WriterGroups[0].PublishingInterval = 30
	}))
	require.Equal(t, 10.0, interval(f))
	// A modification: restored as modified.
	require.Equal(t, ua.StatusOK, modify(func(c *ua.PubSubConfiguration2DataType) {
		c.Connections[0].WriterGroups[0].PublishingInterval = 20
	}))
	require.Equal(t, 20.0, interval(f))
	f = f.restart(t, opts)
	f.waitStatus(t, ep, uafx.ConnectionEndpointOperational)
	require.Equal(t, 20.0, interval(f))

	// A removal by another mechanism: not re-created.
	reader := f.lookup(t, pubsub.KindDataSetReader, subConn, rgName, readerName)
	require.NoError(t, f.srv.ChangePubSubConfiguration(func(rt *pubsub.PubSub) error { return rt.RemoveDataSetReader(reader) }))
	f = f.restart(t, opts)
	require.NotNil(t, f.srv.Node(ep), "the endpoint stays")
	g := f.lookupGroup(t, subConn, rgName)
	_, ok := f.srv.PubSub().Lookup(pubsub.KindDataSetReader, g, readerName)
	require.False(t, ok, "the removed reader is not re-created")
}

// lookupGroup returns the WriterGroup or ReaderGroup group of conn.
func (f *fx) lookupGroup(t *testing.T, conn, group string) pubsub.ComponentID {
	t.Helper()
	rt := f.srv.PubSub()
	c, ok := rt.Lookup(pubsub.KindConnection, pubsub.Root, conn)
	require.True(t, ok, conn)
	for _, k := range []pubsub.ComponentKind{pubsub.KindWriterGroup, pubsub.KindReaderGroup} {
		if g, ok := rt.Lookup(k, c, group); ok {
			return g
		}
	}
	t.Fatalf("no group %s/%s", conn, group)
	return 0
}

// TestPersistedCheck: the persisted check of SetCommunicationConfigurationCmd
// (Part 81 §6.2.4.3.9.2): a persistent endpoint's reader, writer and their
// parents must not have NotPersisted TRUE (PC-1); with StrictNotPersisted a
// non-persistent endpoint's must (PC-2). Otherwise Bad_InvalidState.
func TestPersistedCheck(t *testing.T) {
	t.Parallel()
	np := []*ua.KeyValuePair{{Key: &ua.QualifiedName{Name: "NotPersisted"}, Value: ua.MustVariant(true)}}
	f := newFX(t, fxserver.ConnectionOptions{Store: &fxstore.MemoryStore{}})
	for name, mod := range map[string]func(c *ua.PubSubConfiguration2DataType){
		"reader": func(c *ua.PubSubConfiguration2DataType) {
			c.Connections[1].ReaderGroups[0].DataSetReaders[0].DataSetReaderProperties = np
		},
		"writer": func(c *ua.PubSubConfiguration2DataType) {
			c.Connections[0].WriterGroups[0].DataSetWriters[0].DataSetWriterProperties = np
		},
		"group":      func(c *ua.PubSubConfiguration2DataType) { c.Connections[1].ReaderGroups[0].GroupProperties = np },
		"connection": func(c *ua.PubSubConfiguration2DataType) { c.Connections[0].ConnectionProperties = np },
	} {
		r := f.persistentRequest("P")
		mod(r.CommunicationConfigurations[0].PubSubConfiguration)
		res := f.establish(t, r)
		require.Equal(t, ua.StatusUncertain, res.Status, name)
		require.Equal(t, ua.StatusBadInvalidState, res.ConnectionEndpointConfigurationResults[0].CommunicationLinksResult, name)
		require.Nil(t, f.endpointNamed("P"), name)
	}
	// Without StrictNotPersisted a non-persistent endpoint needs nothing.
	f.operational(t, "N", -1)

	f = newFX(t, fxserver.ConnectionOptions{Store: &fxstore.MemoryStore{}, StrictNotPersisted: true})
	res := f.establish(t, f.fullRequest("N"))
	require.Equal(t, ua.StatusBadInvalidState, res.ConnectionEndpointConfigurationResults[0].CommunicationLinksResult)
	r := f.fullRequest("N")
	c := r.CommunicationConfigurations[0].PubSubConfiguration
	c.Connections[1].ReaderGroups[0].DataSetReaders[0].DataSetReaderProperties = np
	c.Connections[0].WriterGroups[0].DataSetWriters[0].DataSetWriterProperties = np
	res = f.establish(t, r)
	require.Equal(t, ua.StatusOK, res.Status, "%+v", res.ConnectionEndpointConfigurationResults[0])
	require.Equal(t, 0, f.conns.Persistence().Records)
}

// corrupt flips a byte of the record of the endpoint name in mem: in its
// identity header, or in its body.
func corrupt(t *testing.T, mem *fxstore.MemoryStore, identity bool) string {
	t.Helper()
	ctx := context.Background()
	st, err := mem.Load(ctx)
	require.NoError(t, err)
	for k, v := range st {
		if !strings.HasPrefix(k, "ac/ep/") {
			continue
		}
		v = append([]byte(nil), v...)
		if identity {
			v[10] ^= 0xff
		} else {
			v[len(v)-6] ^= 0xff
		}
		require.NoError(t, mem.Apply(ctx, fxstore.Batch{Puts: map[string][]byte{k: v}}))
		return k
	}
	t.Fatal("no endpoint record")
	return ""
}

// TestQuarantine: a record that fails is quarantined, not restored and not
// deleted; it reserves its Name and PubSub ids, a record whose identities
// cannot be read fences its AutomationComponent and the PubSub id
// allocation of the server, and Discard releases it (design §4.7, C3-D10).
func TestQuarantine(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, identity := range []bool{false, true} {
		mem := &fxstore.MemoryStore{}
		opts := fxserver.ConnectionOptions{Store: mem}
		f := newFX(t, opts)
		f.persistent(t, "P")
		f.stop(t)
		corrupt(t, mem, identity)
		f = newFX(t, opts)
		q := f.conns.Quarantined()
		require.Len(t, q, 1)
		require.Nil(t, f.endpointNamed("P"))
		require.False(t, q[0].Retryable)
		require.Equal(t, identity, q[0].Fences)
		require.Error(t, f.conns.RetryRestore(ctx, q[0].ID))
		require.Equal(t, 1, f.conns.Persistence().Quarantined)
		if identity {
			require.Equal(t, ua.StatusBadResourceUnavailable, f.callStatus(t, f.fullRequest("X")))
			_, sc := f.reserve(t)
			require.Equal(t, ua.StatusBadResourceUnavailable, sc)
		} else {
			require.Equal(t, "P", q[0].Name)
			require.NotEmpty(t, q[0].WriterGroupIDs)
			res := f.establish(t, f.persistentRequest("P"))
			require.Equal(t, ua.StatusBadBrowseNameDuplicated, res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointResult)
			ids, sc := f.reserve(t)
			require.Equal(t, ua.StatusOK, sc)
			require.NotContains(t, ids.WriterGroupIDs, q[0].WriterGroupIDs[0])
		}
		// The quarantine survives a restart.
		f = f.restart(t, opts)
		require.Len(t, f.conns.Quarantined(), 1)
		require.NoError(t, f.conns.Discard(ctx, f.conns.Quarantined()[0].ID))
		require.Empty(t, f.conns.Quarantined())
		require.Error(t, f.conns.Discard(ctx, "nothing"))
		f.persistent(t, "P")
	}
}

// TestQuarantineConflict: a record whose component differs from what the
// application configured is quarantined as retryable; RetryRestore restores
// it once the conflict is gone.
func TestQuarantineConflict(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	mem := &fxstore.MemoryStore{}
	opts := fxserver.ConnectionOptions{Store: mem}
	f := newFX(t, opts)
	ep := f.persistent(t, "P")
	udp := f.udp
	f.stop(t)
	conflict := func(srv *server.Server) (fxserver.Namespaces, uint16, error) {
		ns, idx, err := fxtest.PrepareConnections(srv)
		if err == nil {
			_, err = srv.PubSub().AddConnection(pubsub.UDPConnection(pubConn, udp, uint16(99)))
		}
		return ns, idx, err
	}
	opts.Logger = nil
	f = newFXWith(t, conflict, opts)
	q := f.conns.Quarantined()
	require.Len(t, q, 1)
	require.True(t, q[0].Retryable, q[0].Reason)
	require.Nil(t, f.srv.Node(ep))
	require.Error(t, f.conns.RetryRestore(ctx, q[0].ID))
	conn, ok := f.srv.PubSub().Lookup(pubsub.KindConnection, pubsub.Root, pubConn)
	require.True(t, ok)
	require.NoError(t, f.srv.PubSub().RemoveConnection(conn))
	require.NoError(t, f.conns.RetryRestore(ctx, q[0].ID))
	require.Empty(t, f.conns.Quarantined())
	f.waitStatus(t, ep, uafx.ConnectionEndpointOperational)
	f = f.restart(t, fxserver.ConnectionOptions{Store: mem})
	f.waitStatus(t, ep, uafx.ConnectionEndpointOperational)
}

// TestPersistenceStart: a store that cannot be opened or has another owner
// fails EnableConnections (C3-D1).
func TestPersistenceStart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	mem := &fxstore.MemoryStore{}
	d, err := fxstore.OpenDomain(ctx, mem, fxstore.DomainOptions{Namespace: "ac", Owner: "urn:other", Schema: 1})
	require.NoError(t, err)
	_, err = d.Apply(ctx, fxstore.Batch{Puts: map[string][]byte{"x": {1}}})
	require.NoError(t, err)
	srv := newServer(t, server.WithPubSub(nil))
	ns, _, err := fxtest.PrepareConnections(srv)
	require.NoError(t, err)
	_, err = fxserver.EnableConnections(srv, ns, fxserver.ConnectionOptions{Store: mem})
	require.ErrorIs(t, err, fxserver.ErrConnections)
	require.ErrorIs(t, err, fxstore.ErrForeignOwner)

	faulty := storetest.NewFaulty(&fxstore.MemoryStore{})
	faulty.FailLoads(1)
	_, err = fxserver.EnableConnections(srv, ns, fxserver.ConnectionOptions{Store: faulty})
	require.ErrorIs(t, err, storetest.ErrInjected)
}

// TestPersistentSecuredGate: a restored secured group publishes and
// accepts messages only under a key that became current after the
// restart: with the static key of before it stays gated and the endpoint
// does not become Operational; a rotation delivered by the key source
// opens the gate (design §4.10, Part 14 §7.2.3).
func TestPersistentSecuredGate(t *testing.T) {
	t.Parallel()
	policy := security.Aes128CTR()
	newKey := func() []byte {
		k := make([]byte, policy.KeyLength())
		_, err := rand.Read(k)
		require.NoError(t, err)
		return k
	}
	ring := security.NewKeyRing("sg", policy)
	require.NoError(t, ring.SetKeys(policy.URI(), 1, [][]byte{newKey()}, 0, 0))
	withRing := func(srv *server.Server) (fxserver.Namespaces, uint16, error) {
		srv.PubSub().SetKeySource("sg", ring)
		return fxtest.PrepareConnections(srv)
	}
	secured := func(f *fx) *uafx.EstablishConnectionsRequest {
		req := f.persistentRequest("S")
		cfg := req.CommunicationConfigurations[0].PubSubConfiguration
		pubsub.Secure(cfg.Connections[0].WriterGroups[0], ua.MessageSecurityModeSignAndEncrypt, "sg")
		pubsub.Secure(cfg.Connections[1].ReaderGroups[0], ua.MessageSecurityModeSignAndEncrypt, "sg")
		return req
	}
	mem := &fxstore.MemoryStore{}
	opts := fxserver.ConnectionOptions{Store: mem}
	f := newFXWith(t, withRing, opts)
	res := f.establish(t, secured(f))
	require.Equal(t, ua.StatusOK, res.Status, "%+v", res.ConnectionEndpointConfigurationResults[0])
	ep := res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointID
	f.waitStatus(t, ep, uafx.ConnectionEndpointOperational)
	gated, _ := f.srv.PubSub().SecurityGroupGate("sg")
	require.False(t, gated, "a group established in this run is not gated")

	f.stop(t)
	f = newFXWith(t, withRing, opts)
	require.NotNil(t, f.srv.Node(ep), "restored")
	gated, open := f.srv.PubSub().SecurityGroupGate("sg")
	require.True(t, gated)
	require.False(t, open)
	time.Sleep(200 * time.Millisecond)
	st, ok := f.conns.Status(ep)
	require.True(t, ok)
	require.NotEqual(t, uafx.ConnectionEndpointOperational, st, "no message under the key of before the restart")
	_, open = f.srv.PubSub().SecurityGroupGate("sg")
	require.False(t, open, "a static key never opens the gate")

	// The SKS rotates: the key current at once is not fresh, the next one is.
	require.NoError(t, ring.SetKeys(policy.URI(), 2, [][]byte{newKey(), newKey()}, 100*time.Millisecond, time.Hour))
	f.waitStatus(t, ep, uafx.ConnectionEndpointOperational)
	_, open = f.srv.PubSub().SecurityGroupGate("sg")
	require.True(t, open)
}

// TestPersistentUnknownKey: a key in the store that is none of the records
// is quarantined and fences establishes and the PubSub id allocation of
// the whole server, until it is discarded (design §4.7).
func TestPersistentUnknownKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	mem := &fxstore.MemoryStore{}
	opts := fxserver.ConnectionOptions{Store: mem}
	f := newFX(t, opts)
	f.persistent(t, "P")
	f.stop(t)
	require.NoError(t, mem.Apply(ctx, fxstore.Batch{Puts: map[string][]byte{"ac/zz/unknown": {1, 2, 3}}}))
	f = newFX(t, opts)
	q := f.conns.Quarantined()
	require.Len(t, q, 1)
	require.True(t, q[0].Fences)
	require.NotNil(t, f.endpointNamed("P"), "the other records are restored")
	require.Equal(t, ua.StatusBadResourceUnavailable, f.callStatus(t, f.fullRequest("X")))
	_, sc := f.reserve(t)
	require.Equal(t, ua.StatusBadResourceUnavailable, sc)
	require.NoError(t, f.conns.Discard(ctx, q[0].ID))
	_, sc = f.reserve(t)
	require.Equal(t, ua.StatusOK, sc)
	require.Zero(t, f.conns.Persistence().Quarantined)
	f = f.restart(t, opts)
	require.Empty(t, f.conns.Quarantined(), "the discard is durable")
	require.NotNil(t, f.endpointNamed("P"))
}

// TestPersistentRollbackAfterCommit: a call that fails after its commit
// point (the second endpoint cannot be enabled, Part 81 Table 17) is rolled
// back and its records removed again (design §4.3); when that removal does
// not commit it is owed, the store fenced until it is written, and a
// restart restores nothing of the call.
func TestPersistentRollbackAfterCommit(t *testing.T) {
	t.Parallel()
	for _, owed := range []bool{false, true} {
		store := storetest.NewFaulty(&fxstore.MemoryStore{})
		opts := fxserver.ConnectionOptions{Store: store}
		f := newFX(t, opts)
		r := f.persistentRequest("One")
		two := *r.ConnectionEndpointConfigurations[0]
		p := f.endpointParam("Two")
		p.IsPersistent = true
		two.ConnectionEndpoint = &uafx.ConnectionEndpointDefinition{Parameter: p}
		two.ConfigurationData, two.ExpectedVerificationVariables = nil, nil
		r.ConnectionEndpointConfigurations = append(r.ConnectionEndpointConfigurations, &two)
		if owed {
			store.FailLoadsWith(storetest.ErrInjected)
			store.OnApply = func(fxstore.Batch) {
				if store.Applies() == 2 {
					store.FailApply(storetest.FailLost)
				}
			}
		}
		base := len(f.conns.Endpoints())
		res := f.establish(t, r)
		require.Equal(t, ua.StatusUncertain, res.Status)
		require.Equal(t, ua.StatusBadRequestNotAllowed, res.ConnectionEndpointConfigurationResults[1].EnableCommunicationResult)
		require.Len(t, f.conns.Endpoints(), base)
		if owed {
			require.True(t, f.conns.Persistence().Store.Fenced)
			store.FailLoadsWith(nil)
			require.Eventually(t, func() bool { return !f.conns.Persistence().Store.Fenced }, 5*time.Second, 10*time.Millisecond)
		}
		require.Zero(t, f.conns.Persistence().Records)
		f = f.restart(t, fxserver.ConnectionOptions{Store: store})
		require.Len(t, f.conns.Endpoints(), base, "only the preconfigured endpoint")
		require.Nil(t, f.endpointNamed("One"))
		require.Empty(t, f.conns.Quarantined())
	}
}

// TestQuarantineRecords: a component record that does not decode, a
// quarantine record that does not decode and a key of the quarantine that
// is none of the records are quarantined; the last two fence every
// AutomationComponent until they are discarded.
func TestQuarantineRecords(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	mem := &fxstore.MemoryStore{}
	opts := fxserver.ConnectionOptions{Store: mem}
	f := newFX(t, opts)
	f.persistent(t, "P")
	f.stop(t)
	st, err := mem.Load(ctx)
	require.NoError(t, err)
	puts := map[string][]byte{"ac/q/junk": {1, 2, 3}}
	for k, v := range st {
		if strings.HasPrefix(k, "ac/pc/") {
			v = append([]byte(nil), v...)
			v[len(v)-6] ^= 0xff
			puts[k] = v
			break
		}
	}
	require.Len(t, puts, 2)
	require.NoError(t, mem.Apply(ctx, fxstore.Batch{Puts: puts}))
	f = newFX(t, opts)
	q := f.conns.Quarantined()
	require.Len(t, q, 3, "the component, the junk record and the endpoint that needs the component: %+v", q)
	require.Nil(t, f.endpointNamed("P"))
	require.Equal(t, ua.StatusBadResourceUnavailable, f.callStatus(t, f.fullRequest("X")))
	for _, x := range q {
		require.NoError(t, f.conns.Discard(ctx, x.ID), x.Reason)
	}
	require.Empty(t, f.conns.Quarantined())
	f = f.restart(t, opts)
	require.Empty(t, f.conns.Quarantined())
	f.persistent(t, "P")
}

// TestPersistentPreconfigured: a preconfigured endpoint taken with
// IsPersistent TRUE (Part 81 §6.2.4.3.5) is restored onto the preconfigured
// endpoint after a restart, and a removal leaves it in place and restores
// nothing; a record whose FunctionalEntity is gone is quarantined as
// retryable.
func TestPersistentPreconfigured(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	mem := &fxstore.MemoryStore{}
	opts := fxserver.ConnectionOptions{Store: mem}
	f := newFX(t, opts)
	preset := func(f *fx) *uafx.EstablishConnectionsRequest {
		r := f.persistentRequest("Preset")
		p := r.ConnectionEndpointConfigurations[0].ConnectionEndpoint.Parameter
		p.IsPreconfigured, p.Mode, p.OutputVariableIDs = true, uafx.PubSubSubscriber, nil
		r.ConnectionEndpointConfigurations[0].CommunicationLinks.DataSetWriterRef = nil
		r.CommunicationConfigurations[0].PubSubConfiguration.Connections[0].WriterGroups[0].DataSetWriters[0].Enabled = true
		return r
	}
	res := f.establish(t, preset(f))
	require.Equal(t, ua.StatusOK, res.Status, "%+v", res.ConnectionEndpointConfigurationResults[0])
	ep := res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointID
	require.True(t, sameNode(f.id(presetID), ep))
	f.waitStatus(t, f.id(presetID), uafx.ConnectionEndpointOperational)
	require.Equal(t, 1, f.conns.Persistence().Records)

	f = f.restart(t, opts)
	require.Empty(t, f.conns.Quarantined())
	require.Len(t, f.conns.Persistence().Restored, 1)
	// The subscriber side is restored and enabled; the writer, which the
	// endpoint does not reference, is not persisted (design §4.2).
	rt := f.srv.PubSub()
	sub, ok := rt.Lookup(pubsub.KindConnection, pubsub.Root, subConn)
	require.True(t, ok)
	info, err := rt.Component(sub)
	require.NoError(t, err)
	require.True(t, info.Enabled)
	_, ok = rt.Lookup(pubsub.KindConnection, pubsub.Root, pubConn)
	require.False(t, ok)
	again := f.establish(t, preset(f))
	require.Equal(t, ua.StatusBadInvalidState, again.ConnectionEndpointConfigurationResults[0].ConnectionEndpointResult, "restored in use")

	sc, results, err := uafx.CloseConnections(ctx, f.c, f.id(ctlID), []*ua.NodeID{f.id(presetID)}, true)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, results)
	require.NotNil(t, f.srv.Node(f.id(presetID)), "a preconfigured endpoint stays")
	require.Zero(t, f.conns.Persistence().Records)
	f = f.restart(t, opts)
	require.Empty(t, f.conns.Persistence().Restored)

	// A FunctionalEntity that is not there at the restore.
	f.persistent(t, "P")
	f.stop(t)
	noFE := func(srv *server.Server) (fxserver.Namespaces, uint16, error) {
		ns, idx, err := fxtest.PrepareConnections(srv)
		if err == nil {
			// Motion is no longer below Ctl/FunctionalEntities.
			srv.Node(ua.NewNumericNodeID(idx, motionID)).RemoveRef(ua.NewExpandedNodeID(ua.NewNumericNodeID(idx, 1001), "", 0), ua.NewNumericNodeID(0, id.Organizes), false)
		}
		return ns, idx, err
	}
	f = newFXWith(t, noFE, opts)
	q := f.conns.Quarantined()
	require.Len(t, q, 1)
	require.True(t, q[0].Retryable, q[0].Reason)
	require.Error(t, f.conns.RetryRestore(ctx, q[0].ID))
}

// TestQuarantineReservesComponents: what a quarantined record reserves is
// refused to every configuration mechanism of the server: its component
// paths and its WriterGroupIds and DataSetWriterIds; a record whose
// identity cannot be read refuses every addition with ids (design §4.7).
func TestQuarantineReservesComponents(t *testing.T) {
	t.Parallel()
	for _, identity := range []bool{false, true} {
		mem := &fxstore.MemoryStore{}
		opts := fxserver.ConnectionOptions{Store: mem}
		f := newFX(t, opts)
		f.persistent(t, "P")
		f.stop(t)
		corrupt(t, mem, identity)
		f = newFX(t, opts)
		q := f.conns.Quarantined()
		require.Len(t, q, 1)
		add := func(c *ua.PubSubConnectionDataType) error {
			return f.srv.ChangePubSubConfiguration(func(rt *pubsub.PubSub) error {
				_, err := rt.AddConnection(c)
				return err
			})
		}
		if !identity {
			require.ErrorIs(t, add(pubsub.UDPConnection(pubConn, f.udp, uint16(5))), ua.StatusBadResourceUnavailable, "the path is reserved")
			wg := pubsub.WriterGroup("Other", q[0].WriterGroupIDs[0], time.Second)
			require.ErrorIs(t, add(pubsub.AttachWriterGroups(pubsub.UDPConnection("X", f.udp, uint16(5)), wg)), ua.StatusBadResourceUnavailable, "the WriterGroupId is reserved")
			w := pubsub.DataSetWriter("W2", q[0].DataSetWriterIDs[0], "")
			require.ErrorIs(t, add(pubsub.AttachWriterGroups(pubsub.UDPConnection("Y", f.udp, uint16(5)), pubsub.WriterGroup("G", 0x7000, time.Second, w))),
				ua.StatusBadResourceUnavailable, "the DataSetWriterId is reserved")
			require.NoError(t, add(pubsub.UDPConnection("Free", f.udp, uint16(5))))

			// A new id on an existing component is an allocation too: a
			// modify (Part 14 §9.1.3.7.4) cannot take a reserved one.
			free := func(group, writer uint16) *ua.PubSubConfiguration2DataType {
				return &ua.PubSubConfiguration2DataType{Connections: []*ua.PubSubConnectionDataType{
					pubsub.AttachWriterGroups(pubsub.UDPConnection("Mod", f.udp, uint16(6)),
						pubsub.WriterGroup("MG", group, time.Second, pubsub.DataSetWriter("MW", writer, "")))}}
			}
			require.Equal(t, ua.StatusOK, f.update(t, free(0x7100, 0x7101), ref(refAdd|refConn, 0, 0, 0), ref(refAdd|refWG, 0, 0, 0), ref(refAdd|refWriter, 0, 0, 0)))
			modify := ua.PubSubConfigurationRefMaskElementModify
			require.Equal(t, ua.StatusBadResourceUnavailable, f.update(t, free(q[0].WriterGroupIDs[0], 0x7101), ref(modify|refWG, 0, 0, 0)),
				"a WriterGroup cannot take a reserved WriterGroupId")
			require.Equal(t, ua.StatusBadResourceUnavailable, f.update(t, free(0x7100, q[0].DataSetWriterIDs[0]), ref(modify|refWriter, 0, 0, 0)),
				"a DataSetWriter cannot take a reserved DataSetWriterId")
			mg := f.lookupGroup(t, "Mod", "MG")
			cfg, err := f.srv.PubSub().WriterGroupConfig(mg)
			require.NoError(t, err)
			require.Equal(t, uint16(0x7100), cfg.WriterGroupID, "the refused modify is undone")
			require.Equal(t, ua.StatusOK, f.update(t, free(0x7102, 0x7103), ref(modify|refWG, 0, 0, 0)), "a free id can be taken")
		} else {
			wg := pubsub.WriterGroup("Other", 0x7001, time.Second)
			require.ErrorIs(t, add(pubsub.AttachWriterGroups(pubsub.UDPConnection("X", f.udp, uint16(5)), wg)), ua.StatusBadResourceUnavailable, "no id while the identities are unknown")
		}
		_, ok := f.srv.PubSub().Lookup(pubsub.KindConnection, pubsub.Root, "X")
		require.False(t, ok, "the refused change is undone")
	}
}

// refusingHook is a PubSub configuration hook that refuses the n-th
// change after it was applied (1-based; 0: none).
type refusingHook struct {
	mu      sync.Mutex
	n, seen int
}

func (h *refusingHook) failNth(n int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.n, h.seen = n, 0
}

func (h *refusingHook) refused() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.n > 0 && h.seen >= h.n
}

func (h *refusingHook) PubSubConfigurationChanged(*server.PubSubChange) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.n == 0 {
		return nil
	}
	h.seen++
	if h.seen == h.n {
		return ua.StatusBadResourceUnavailable
	}
	return nil
}

func (*refusingHook) HeldPubSubIDs() ([]uint16, []uint16, bool) { return nil, nil, false }

// requireLinked checks that the ToDataSetReader and ToDataSetWriter
// References of ep lead to components of the runtime.
func (f *fx) requireLinked(t *testing.T, ep *ua.NodeID) {
	t.Helper()
	for _, rt := range []uint32{fxacid.ToDataSetReader, fxacid.ToDataSetWriter} {
		for _, n := range f.targets(t, ep, rt) {
			_, ok := f.srv.PubSubComponentID(n)
			require.True(t, ok, "%v leads to %v, which is no component", ep, n)
		}
	}
}

// TestCloseHookRefused: CloseConnections' runtime changes run in PubSub
// transactions that a PubSub configuration hook can refuse after the
// change succeeded; the runtime is then back where it was, and so is the
// endpoint: the close fails, the endpoint keeps its References and what its
// calls created, and a second close finishes it, leaving nothing behind.
// Each refusal point of a disable and of a removal (the reader, the writer,
// their groups, connections and PublishedDataSet) is tried.
func TestCloseHookRefused(t *testing.T) {
	t.Parallel()
	t.Run("disable", func(t *testing.T) {
		t.Parallel()
		f := newFX(t, fxserver.ConnectionOptions{})
		h := &refusingHook{}
		f.srv.SetPubSubConfigurationHook(h)
		ep := f.operational(t, "D", -1)
		h.failNth(1)
		sc, res := f.close(t, false, ep)
		require.Equal(t, ua.StatusUncertain, sc)
		require.Equal(t, []ua.StatusCode{ua.StatusBadResourceUnavailable}, res)
		f.requireLinked(t, ep)
		h.failNth(0)
		sc, res = f.close(t, false, ep)
		require.Equal(t, ua.StatusOK, sc, "%v", res)
		f.waitStatus(t, ep, uafx.ConnectionEndpointReady)
	})
	for n := 1; ; n++ {
		f := newFX(t, fxserver.ConnectionOptions{})
		h := &refusingHook{}
		f.srv.SetPubSubConfigurationHook(h)
		ep := f.operational(t, "R", -1)
		h.failNth(n)
		sc, res := f.close(t, true, ep)
		if !h.refused() {
			// Past the last transaction of the removal.
			require.Equal(t, ua.StatusOK, sc, "%v", res)
			require.Greater(t, n, 3, "the removal has transactions to refuse")
			f.stop(t)
			break
		}
		require.Equal(t, ua.StatusUncertain, sc, "refusal %d", n)
		require.Equal(t, []ua.StatusCode{ua.StatusBadResourceUnavailable}, res, "refusal %d", n)
		require.NotNil(t, f.srv.Node(ep), "refusal %d: the endpoint stays", n)
		f.requireLinked(t, ep)
		h.failNth(0)
		sc, res = f.close(t, true, ep)
		require.Equal(t, ua.StatusOK, sc, "refusal %d: %v", n, res)
		require.Nil(t, f.srv.Node(ep))
		require.Empty(t, f.srv.PubSub().Configuration().Connections, "refusal %d: what the call created goes", n)
		require.Empty(t, f.srv.PubSub().Configuration().PublishedDataSets, "refusal %d", n)
		f.stop(t)
	}
}

// TestQuarantineMissingNamespace: a record with a NodeId in a namespace the
// server does not have is not restored and not lost: it is quarantined,
// retryable, names the namespace, reserves its Name and NodeIds, survives
// a restart, and is restored by RetryRestore once the namespace is there,
// or at a start that has it (design §4.6, §4.7, C3-D10).
func TestQuarantineMissingNamespace(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	const late = "urn:go-opcua:uafx:test:late"
	mem := &fxstore.MemoryStore{}
	opts := fxserver.ConnectionOptions{Store: mem}
	f := newFX(t, opts)
	ep := f.persistent(t, "P")
	f.stop(t)
	st, err := mem.Load(ctx)
	require.NoError(t, err)
	n := 0
	for k, v := range st {
		if strings.HasPrefix(k, "ac/ep/") {
			v, err = fxserver.WithLateNode(v, late, "late-1")
			require.NoError(t, err)
			require.NoError(t, mem.Apply(ctx, fxstore.Batch{Puts: map[string][]byte{k: v}}))
			n++
		}
	}
	require.Equal(t, 1, n)

	f = newFX(t, opts)
	q := f.conns.Quarantined()
	require.Len(t, q, 1)
	require.True(t, q[0].Retryable, q[0].Reason)
	require.Equal(t, []string{late}, q[0].MissingNamespaces)
	require.Equal(t, "P", q[0].Name)
	require.Nil(t, f.srv.Node(ep))
	res := f.establish(t, f.persistentRequest("P"))
	require.Equal(t, ua.StatusBadBrowseNameDuplicated, res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointResult,
		"the Name stays reserved")
	require.ErrorIs(t, f.conns.RetryRestore(ctx, q[0].ID), fxserver.ErrQuarantine, "the namespace is still missing")
	f = f.restart(t, opts)
	q = f.conns.Quarantined()
	require.Len(t, q, 1, "kept across a restart")

	// The namespace comes: RetryRestore restores it.
	server.NewNodeNameSpace(f.srv, late)
	require.NoError(t, f.conns.RetryRestore(ctx, q[0].ID))
	require.Empty(t, f.conns.Quarantined())
	f.waitStatus(t, ep, uafx.ConnectionEndpointOperational)

	// A start that has the namespace restores it at once.
	f.stop(t)
	withLate := func(srv *server.Server) (fxserver.Namespaces, uint16, error) {
		ns, idx, err := fxtest.PrepareConnections(srv)
		server.NewNodeNameSpace(srv, late)
		return ns, idx, err
	}
	f = newFXWith(t, withLate, opts)
	require.Empty(t, f.conns.Quarantined())
	f.waitStatus(t, ep, uafx.ConnectionEndpointOperational)
}

// TestQuarantineUnknownOutcomes: the move of a record to quarantine and a
// Discard whose outcome is unknown are followed once the store is settled,
// whether they committed or not: the quarantine names the record where the
// store has it, and a discarded record is gone with its reservations
// (design §3.3, §4.7).
func TestQuarantineUnknownOutcomes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, fault := range []storetest.Fault{storetest.FailApplied, storetest.FailLost} {
		mem := &fxstore.MemoryStore{}
		store := storetest.NewFaulty(mem)
		opts := fxserver.ConnectionOptions{Store: store}
		f := newFX(t, opts)
		f.persistent(t, "P")
		udp := f.udp
		f.stop(t)
		conflict := func(srv *server.Server) (fxserver.Namespaces, uint16, error) {
			ns, idx, err := fxtest.PrepareConnections(srv)
			if err == nil {
				_, err = srv.PubSub().AddConnection(pubsub.UDPConnection(pubConn, udp, uint16(99)))
			}
			return ns, idx, err
		}
		settled := func(f *fx) {
			t.Helper()
			require.Eventually(t, func() bool { return !f.conns.Persistence().Store.Fenced }, 5*time.Second, 10*time.Millisecond)
		}
		has := func(prefix string) bool {
			st, err := mem.Load(ctx)
			require.NoError(t, err)
			for k := range st {
				if strings.HasPrefix(k, "ac/"+prefix) {
					return true
				}
			}
			return false
		}

		// The move to q/ of the record the conflict quarantines.
		store.FailApply(fault)
		f = newFXWith(t, conflict, opts)
		settled(f)
		q := f.conns.Quarantined()
		require.Len(t, q, 1, "%v", fault)
		// FailApplied: the move committed; FailLost: it did not.
		committed := fault == storetest.FailApplied
		require.Equal(t, committed, has("q/"), "%v", fault)
		require.Equal(t, !committed, has("ep/"), "%v", fault)
		want := "ep/"
		if committed {
			want = "q/"
		}
		require.True(t, strings.HasPrefix(q[0].ID, want), "%v: the quarantine follows the store: %s", fault, q[0].ID)
		res := f.establish(t, f.persistentRequest("P"))
		require.Equal(t, ua.StatusBadBrowseNameDuplicated, res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointResult)

		// A restart loads the quarantine (moved now, if it was not), and
		// it still reserves the Name.
		f.stop(t)
		f = newFXWith(t, conflict, opts)
		q = f.conns.Quarantined()
		require.Len(t, q, 1, "%v", fault)
		require.True(t, strings.HasPrefix(q[0].ID, "q/"), "%v: %s", fault, q[0].ID)
		require.Equal(t, "P", q[0].Name)
		res = f.establish(t, f.persistentRequest("P"))
		require.Equal(t, ua.StatusBadBrowseNameDuplicated, res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointResult)

		// Discard with an unknown outcome.
		store.FailApply(fault)
		require.Error(t, f.conns.Discard(ctx, q[0].ID))
		settled(f)
		require.Equal(t, committed, !has("q/") && !has("ep/"), "%v", fault)
		if committed {
			require.Empty(t, f.conns.Quarantined(), "%v: the discard committed", fault)
			res = f.establish(t, f.persistentRequest("P"))
			require.NotEqual(t, ua.StatusBadBrowseNameDuplicated, res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointResult,
				"%v: the Name is free again", fault)
		} else {
			q = f.conns.Quarantined()
			require.Len(t, q, 1, "%v: the discard did not commit", fault)
			require.NoError(t, f.conns.Discard(ctx, q[0].ID))
			require.Empty(t, f.conns.Quarantined())
		}
		f.stop(t)
	}
}

// rewrite applies f to the records of mem with the prefix (after "ac/")
// and returns how many it changed.
func rewrite(t *testing.T, mem *fxstore.MemoryStore, prefix string, f func(v []byte) ([]byte, bool)) int {
	t.Helper()
	ctx := context.Background()
	st, err := mem.Load(ctx)
	require.NoError(t, err)
	n := 0
	for k, v := range st {
		if !strings.HasPrefix(k, "ac/"+prefix) {
			continue
		}
		if out, ok := f(v); ok {
			require.NoError(t, mem.Apply(ctx, fxstore.Batch{Puts: map[string][]byte{k: out}}))
			n++
		}
	}
	return n
}

// TestQuarantineMissingNamespaceComponent: an endpoint whose component
// record uses a namespace the server does not have is quarantined,
// retryable; a RemovePending record that does is completed all the same:
// a removal needs no NodeId (design §4.4, §4.6).
func TestQuarantineMissingNamespaceComponent(t *testing.T) {
	t.Parallel()
	const late = "urn:go-opcua:uafx:test:late"
	mem := &fxstore.MemoryStore{}
	opts := fxserver.ConnectionOptions{Store: mem}
	f := newFX(t, opts)
	ep := f.persistent(t, "P")
	f.stop(t)
	n := rewrite(t, mem, "pc/", func(v []byte) ([]byte, bool) {
		out, ok, err := fxserver.WithLateComponent(v, late)
		require.NoError(t, err)
		return out, ok
	})
	require.Positive(t, n, "a component record has NodeIds")
	f = newFX(t, opts)
	q := f.conns.Quarantined()
	require.Len(t, q, 1)
	require.True(t, q[0].Retryable, q[0].Reason)
	require.Contains(t, q[0].Reason, "component record")
	require.Contains(t, q[0].Reason, late)
	require.Nil(t, f.srv.Node(ep))

	// The same record, RemovePending: completed, not quarantined.
	f.stop(t)
	require.Equal(t, 1, rewrite(t, mem, "ep/", func(v []byte) ([]byte, bool) {
		out, err := fxserver.RemovePending(v)
		require.NoError(t, err)
		return out, true
	}))
	require.Equal(t, 1, rewrite(t, mem, "ep/", func(v []byte) ([]byte, bool) {
		out, err := fxserver.WithLateNode(v, late, "late-1")
		require.NoError(t, err)
		return out, true
	}))
	f = newFX(t, opts)
	require.Empty(t, f.conns.Quarantined())
	require.Nil(t, f.srv.Node(ep))
	require.Zero(t, rewrite(t, mem, "ep/", func([]byte) ([]byte, bool) { return nil, true }), "the removal is completed")
}
