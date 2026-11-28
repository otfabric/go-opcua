// SPDX-License-Identifier: MIT

package fxserver_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/testutil/fxtest"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/server/pubsubstore"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxserver"
	"github.com/otfabric/go-opcua/uafx/fxstore"
	"github.com/otfabric/go-opcua/uafx/fxstore/storetest"
)

// newFXStored is newFX on a server whose PubSub configuration is in a
// pubsubstore on backend.
func newFXStored(t *testing.T, opts fxserver.ConnectionOptions, backend fxstore.Store) (*fx, *pubsubstore.Store) {
	t.Helper()
	st, err := pubsubstore.Open(context.Background(), backend, pubsubstore.Options{Owner: appURI})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	return newFX(t, opts, server.WithPubSubStore(st)), st
}

func storedNames(t *testing.T, f *fx, st *pubsubstore.Store) (conns, pds []string) {
	t.Helper()
	var uris []string
	for _, n := range f.srv.Namespaces() {
		uris = append(uris, n.Name())
	}
	cfg, err := st.LoadPubSubConfiguration(context.Background(), uris)
	require.NoError(t, err)
	if cfg == nil {
		return nil, nil
	}
	for _, c := range cfg.Connections {
		conns = append(conns, c.Name)
	}
	for _, d := range cfg.PublishedDataSets {
		pds = append(pds, d.Name)
	}
	return conns, pds
}

// TestPubSubStoreCoexistence: the PubSub configuration store of the
// server (server.WithPubSubStore) leaves the components EstablishConnections
// created to the connections, which restore them with a persistent
// endpoint and drop them with a non-persistent one (Part 81 §5.5.5,
// §6.6.2), and keeps the rest: a component another mechanism added, and
// one the CommunicationConfiguration of a call added that no endpoint
// uses. After a restart each comes back once, from its own store.
func TestPubSubStoreCoexistence(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	acMem, psMem := &fxstore.MemoryStore{}, &fxstore.MemoryStore{}
	opts := fxserver.ConnectionOptions{Store: acMem}
	f, st := newFXStored(t, opts, psMem)
	require.NoError(t, f.srv.ChangePubSubConfiguration(func(rt *pubsub.PubSub) error {
		_, err := rt.AddConnection(pubsub.UDPConnection("Own", f.udp, uint16(5)))
		return err
	}))
	r := f.persistentRequest("P")
	cc := r.CommunicationConfigurations[0]
	cc.PubSubConfiguration.Connections = append(cc.PubSubConfiguration.Connections, pubsub.UDPConnection("Extra", f.udp, uint16(6)))
	cc.ConfigurationReferences = append(slices.Clone(cc.ConfigurationReferences), ref(refAdd|refConn, 2, 0, 0))
	res := f.establish(t, r)
	require.Equal(t, ua.StatusOK, res.Status, "%+v", res.ConnectionEndpointConfigurationResults[0])
	ep := res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointID
	f.waitStatus(t, ep, uafx.ConnectionEndpointOperational)

	conns, pds := storedNames(t, f, st)
	require.Equal(t, []string{"Own", "Extra"}, conns, "the components the call created are the connections'")
	require.Empty(t, pds)

	f.stop(t)
	require.NoError(t, st.Close())
	f, st = newFXStored(t, opts, psMem)
	f.waitStatus(t, ep, uafx.ConnectionEndpointOperational)
	require.Empty(t, f.conns.Quarantined())
	rt := f.srv.PubSub()
	for _, name := range []string{"Own", "Extra", pubConn, subConn} {
		_, ok := rt.Lookup(pubsub.KindConnection, pubsub.Root, name)
		require.True(t, ok, name)
	}
	require.Len(t, rt.Configuration().Connections, 4)
	conns, _ = storedNames(t, f, st)
	require.Equal(t, []string{"Own", "Extra"}, conns)

	// Removed with its endpoint, the connections' components are gone from
	// both stores; a non-persistent endpoint's never reach either.
	sc, _, err := uafx.CloseConnections(ctx, f.c, f.id(ctlID), []*ua.NodeID{ep}, true)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, sc)
	np := f.operational(t, "N", -1)
	conns, _ = storedNames(t, f, st)
	require.Equal(t, []string{"Own", "Extra"}, conns)
	f.stop(t)
	require.NoError(t, st.Close())
	f, _ = newFXStored(t, opts, psMem)
	require.Nil(t, f.srv.Node(np))
	var names []string
	for _, c := range f.srv.PubSub().Configuration().Connections {
		names = append(names, c.Name)
	}
	require.Equal(t, []string{"Own", "Extra"}, names)
}

// TestPubSubStoreCoexistenceWithoutStore: without ConnectionOptions.Store
// the components of the calls are not persisted either: they go with
// their endpoint at a restart.
func TestPubSubStoreCoexistenceWithoutStore(t *testing.T) {
	t.Parallel()
	psMem := &fxstore.MemoryStore{}
	f, st := newFXStored(t, fxserver.ConnectionOptions{}, psMem)
	f.operational(t, "N", -1)
	conns, pds := storedNames(t, f, st)
	require.Empty(t, conns)
	require.Empty(t, pds)
	f.stop(t)
	require.NoError(t, st.Close())
	f, _ = newFXStored(t, fxserver.ConnectionOptions{}, psMem)
	require.Empty(t, f.srv.PubSub().Configuration().Connections)
}

// TestPubSubStoreCoexistenceErrors: EnableConnections fails when the
// PubSub configuration store of the server does not restore, and leaves no
// owner behind; a failed write after a call is logged, and the next one
// writes.
func TestPubSubStoreCoexistenceErrors(t *testing.T) {
	t.Parallel()
	faulty := storetest.NewFaulty(&fxstore.MemoryStore{})
	st, err := pubsubstore.Open(context.Background(), faulty, pubsubstore.Options{Owner: appURI})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	f := newFX(t, fxserver.ConnectionOptions{}, server.WithPubSubStore(st))
	faulty.FailApply(storetest.FailNotCommitted)
	res := f.establish(t, func() *uafx.EstablishConnectionsRequest {
		// Not enabled: EnableCommunicationCmd would change the
		// configuration outside the call's own changes, and write Extra.
		r := f.fullRequest("N")
		r.CommandMask &^= uafx.EnableCommunicationCmd
		cc := r.CommunicationConfigurations[0]
		cc.PubSubConfiguration.Connections = append(cc.PubSubConfiguration.Connections, pubsub.UDPConnection("Extra", f.udp, uint16(6)))
		cc.ConfigurationReferences = append(slices.Clone(cc.ConfigurationReferences), ref(refAdd|refConn, 2, 0, 0))
		return r
	}())
	require.Equal(t, ua.StatusOK, res.Status, "the call's own changes are not the store's")
	conns, _ := storedNames(t, f, st)
	require.Empty(t, conns, "the hand-over failed")
	require.NoError(t, f.srv.PersistPubSubConfiguration(context.Background()))
	conns, _ = storedNames(t, f, st)
	require.Equal(t, []string{"Extra"}, conns)

	// A store that does not load fails EnableConnections.
	srv := newServer(t, server.WithPubSub(nil), server.WithPubSubStore(failingStore{}))
	ns, _, err := fxtest.PrepareConnections(srv)
	require.NoError(t, err)
	_, err = fxserver.EnableConnections(srv, ns, fxserver.ConnectionOptions{Interval: time.Millisecond})
	require.ErrorIs(t, err, fxserver.ErrConnections)
	require.ErrorIs(t, err, errLoad)
}

var errLoad = errors.New("the store does not load")

// failingStore is a server.PubSubConfigurationStore that does not load.
type failingStore struct{}

func (failingStore) LoadPubSubConfiguration(context.Context, []string) (*ua.PubSubConfigurationDataType, error) {
	return nil, errLoad
}

func (failingStore) StorePubSubConfiguration(context.Context, *ua.PubSubConfigurationDataType, []string) error {
	return nil
}

// TestPubSubStoreCoexistenceReader: a DataSetReader an endpoint owns in a
// ReaderGroup of the server is the connections'; the group and its
// PubSubConnection stay in the server's store.
func TestPubSubStoreCoexistenceReader(t *testing.T) {
	t.Parallel()
	f, st := newFXStored(t, fxserver.ConnectionOptions{}, &fxstore.MemoryStore{})
	require.NoError(t, f.srv.ChangePubSubConfiguration(func(rt *pubsub.PubSub) error {
		_, err := rt.AddConnection(pubsub.AttachReaderGroups(pubsub.UDPConnection(subConn, f.udp, nil), pubsub.ReaderGroup(rgName)))
		return err
	}))
	r := f.fullRequest("N")
	r.CommunicationConfigurations[0].ConfigurationReferences = []*ua.PubSubConfigurationRefDataType{
		ref(refAdd|refPDS, 0, 0, 0), ref(refAdd|refConn, 0, 0, 0), ref(refAdd|refWG, 0, 0, 0),
		ref(refAdd|refWriter, 0, 0, 0), ref(refAdd|refReader, 1, 0, 0),
	}
	res := f.establish(t, r)
	require.Equal(t, ua.StatusOK, res.Status, "%+v", res.ConnectionEndpointConfigurationResults[0])
	conns, _ := storedNames(t, f, st)
	require.Equal(t, []string{subConn}, conns)
	var uris []string
	for _, n := range f.srv.Namespaces() {
		uris = append(uris, n.Name())
	}
	cfg, err := st.LoadPubSubConfiguration(context.Background(), uris)
	require.NoError(t, err)
	require.Len(t, cfg.Connections[0].ReaderGroups, 1)
	require.Empty(t, cfg.Connections[0].ReaderGroups[0].DataSetReaders, "the reader is the endpoint's")
	rt := f.srv.PubSub()
	cid, ok := rt.Lookup(pubsub.KindConnection, pubsub.Root, subConn)
	require.True(t, ok)
	gid, ok := rt.Lookup(pubsub.KindReaderGroup, cid, rgName)
	require.True(t, ok)
	_, ok = rt.Lookup(pubsub.KindDataSetReader, gid, readerName)
	require.True(t, ok)
}
