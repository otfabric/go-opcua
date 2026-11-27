// SPDX-License-Identifier: MIT

package fxcm_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxcm"
	"github.com/otfabric/go-opcua/uafx/fxserver"
	"github.com/otfabric/go-opcua/uafx/fxstore"
)

// The gate of stage C3.3 (design docs/design/uafx-persistent-connections.md
// §8): the ConnectionManager and the AutomationComponents restart
// independently without an unsafe removal or a needless interruption.

// persistentSet adds the set "Restart" over a and b with persistent
// endpoints (§6.6.2 IsPersistent, C3-D2) to m, establishes it and returns
// its key.
func persistentSet(t *testing.T, m *fxcm.Manager, a, b *ac) fxcm.SetKey {
	t.Helper()
	conf := e2eConf(t, "Restart", a, b)
	for _, ep := range []*uafx.ConnectionEndpointConfigurationConf{conf.Connections[0].Endpoint1, conf.Connections[0].Endpoint2} {
		ep.IsPersistent = true
	}
	cfg, err := m.Add(conf)
	require.NoError(t, err)
	res := process(t, m, uafx.ActionEstablishConnectionsEnabled, cfg.Key())
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	return cfg.Key()
}

// TestACRestartE2E: an AutomationComponent restarts under a live
// ConnectionManager. Restored from its own store (C3.1), its endpoint has
// the NodeId and CreationTime the Manager recorded: the next establish
// proves it again (§6.5, §6.6) and keeps both endpoints in place, no
// CloseConnections. Restarted with an empty store, its endpoint is gone and
// one of the Name is made again; nothing of another is closed.
func TestACRestartE2E(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		restored bool
	}{{"restored", true}, {"with an empty store", false}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			storeB := &fxstore.MemoryStore{}
			a := newAC(t, "a", fxserver.ConnectionOptions{Store: &fxstore.MemoryStore{}})
			b := newAC(t, "b", fxserver.ConnectionOptions{Store: storeB})
			m := newManager(t, fxcm.Options{Store: &fxstore.MemoryStore{}})
			k := persistentSet(t, m, a, b)
			nodes := endpointsOf(a, b)

			b.stop()
			// Without its store: a new, empty one (an AC without a
			// store refuses IsPersistent, C3-D2).
			opts := fxserver.ConnectionOptions{Store: &fxstore.MemoryStore{}}
			if tc.restored {
				opts.Store = storeB
			}
			b2 := buildAC(t, "b", opts, "", b.port, nil)
			if tc.restored {
				require.Equal(t, nodeSet(b.conns.Endpoints()), nodeSet(b2.conns.Endpoints()), "restored")
			} else {
				require.Empty(t, b2.endpoints())
			}

			// The session of the Manager went with the server: the run
			// reads the NamespaceArray once more on a new one (design
			// §5.1).
			before := m.Counters()
			res := process(t, m, uafx.ActionEstablishConnectionsEnabled, k)
			require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
			if tc.restored {
				assert.Len(t, res.Adopted, 2, "%+v", res)
				assert.Empty(t, res.Created)
				assert.Equal(t, before.CloseCallCount, m.Counters().CloseCallCount, "no CloseConnections")
				assert.Equal(t, nodeSet(nodes), nodeSet(endpointsOf(a, b2)), "kept in place")
				return
			}
			assert.Empty(t, res.Adopted)
			assert.Equal(t, []string{"ToA"}, b2.endpoints(), "made again")
			assert.Equal(t, []string{"ToB"}, a.endpoints())
		})
	}
}

// TestNamespaceReorderE2E (§4.8, §6.1): the ConnectionManager and an
// AutomationComponent restart, and the AC's NamespaceArray is another
// order: every namespace of its model moved up by one. The records map by
// namespace URI: the endpoints are proven at their new NodeIds and kept in
// place, and the node that now has the NodeId an endpoint had before is
// neither closed nor touched.
func TestNamespaceReorderE2E(t *testing.T) {
	t.Parallel()
	storeA, storeB := &fxstore.MemoryStore{}, &fxstore.MemoryStore{}
	a := newAC(t, "a", fxserver.ConnectionOptions{Store: storeA})
	b := newAC(t, "b", fxserver.ConnectionOptions{Store: storeB})
	mem := &fxstore.MemoryStore{}
	m := newManager(t, fxcm.Options{Store: mem})
	k := persistentSet(t, m, a, b)
	old := ownEndpoint(t, b)
	require.NoError(t, m.Close())

	b.stop()
	b2 := buildAC(t, "b", fxserver.ConnectionOptions{Store: storeB}, "", b.port, func(srv *server.Server) {
		// Namespace 1 stays the ApplicationUri (Part 5 §6.3.1).
		srv.AddNamespace(server.NewNodeNameSpace(srv, b.uri))
		srv.AddNamespace(server.NewNodeNameSpace(srv, "urn:go-opcua:fxcm:first"))
	})
	require.Equal(t, b.test+1, b2.test, "the namespaces moved up")
	moved := ownEndpoint(t, b2)
	require.Equal(t, old.StringID(), moved.StringID(), "restored under its identifier")
	require.Equal(t, old.Namespace()+1, moved.Namespace())
	// A node of another namespace at the NodeId the endpoint had.
	ns, err := b2.srv.Namespace(int(old.Namespace()))
	require.NoError(t, err)
	nns, ok := ns.(*server.NodeNameSpace)
	require.True(t, ok, "%T", ns)
	nns.AddNode(server.NewFolderNode(old, "ToA"))

	m2 := newManager(t, fxcm.Options{Store: mem})
	res := process(t, m2, uafx.ActionEstablishConnectionsEnabled, k)
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	assert.Len(t, res.Adopted, 2, "%+v", res)
	assert.Zero(t, m2.Counters().CloseCallCount, "no CloseConnections")
	assert.True(t, ownEndpoint(t, b2).Equal(moved), "kept in place")
	assert.NotNil(t, b2.srv.Node(old), "the node at the old NodeId is untouched")
	st, _ := m2.Status(k)
	for _, e := range st.Endpoints {
		assert.Equal(t, fxcm.KnownOwned, e.Class)
		if e.ServerURI == b.uri {
			assert.True(t, e.NodeID.Equal(moved), "the record follows the NamespaceArray: %v", e.NodeID)
		}
	}
}
