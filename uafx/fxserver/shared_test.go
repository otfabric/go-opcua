// SPDX-License-Identifier: MIT

package fxserver_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/remote"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxserver"
	"github.com/otfabric/go-opcua/uafx/fxstore"
)

// sharedPair establishes, in one call, Pub (PublisherSubscriber) and Pub2
// (Publisher), which share the DataSetWriter; persistent[i] sets
// IsPersistent of each.
func (f *fx) sharedPair(t *testing.T, persistent [2]bool) (ep, ep2 *ua.NodeID) {
	t.Helper()
	r := f.fullRequest("Pub")
	r.ConnectionEndpointConfigurations[0].ConnectionEndpoint.Parameter.IsPersistent = persistent[0]
	p2 := f.endpointParam("Pub2")
	p2.Mode, p2.InputVariableIDs, p2.IsPersistent = uafx.PubSubPublisher, nil, persistent[1]
	r.ConnectionEndpointConfigurations = append(r.ConnectionEndpointConfigurations, &uafx.ConnectionEndpointConfiguration{
		FunctionalEntityNode: f.id(motionID), ConnectionEndpoint: &uafx.ConnectionEndpointDefinition{Parameter: p2},
		CommunicationLinks: &uafx.PubSubCommunicationLinkConfiguration{DataSetWriterRef: ref(refWriter, 0, 0, 0)},
	})
	res := f.establish(t, r)
	require.Equal(t, ua.StatusOK, res.Status, "%+v", res.ConnectionEndpointConfigurationResults)
	ep, ep2 = res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointID, res.ConnectionEndpointConfigurationResults[1].ConnectionEndpointID
	f.waitStatus(t, ep, uafx.ConnectionEndpointOperational)
	return ep, ep2
}

// writerState returns whether the shared DataSetWriter exists and whether
// it is enabled.
func (f *fx) writerState(t *testing.T) (exists, enabled bool) {
	t.Helper()
	rt := f.srv.PubSub()
	c, ok := rt.Lookup(pubsub.KindConnection, pubsub.Root, pubConn)
	if !ok {
		return false, false
	}
	g, ok := rt.Lookup(pubsub.KindWriterGroup, c, wgName)
	if !ok {
		return false, false
	}
	w, ok := rt.Lookup(pubsub.KindDataSetWriter, g, writerName)
	if !ok {
		return false, false
	}
	info, err := rt.Component(w)
	require.NoError(t, err)
	return true, info.Enabled
}

// TestSharedComponent: a DataSetWriter two endpoints share stays enabled
// while one of them demands it, is disabled once neither does, whatever
// references it, in either order; it is removed with the last endpoint
// that references it, in either order, also when the endpoint whose call
// created it goes first (Part 81 §6.2.5.2; design §4.4).
func TestSharedComponent(t *testing.T) {
	t.Parallel()
	for _, order := range [][2]int{{0, 1}, {1, 0}} {
		f := newFX(t, fxserver.ConnectionOptions{})
		ep, ep2 := f.sharedPair(t, [2]bool{})
		eps := [2]*ua.NodeID{ep, ep2}

		// Disable both, one after the other.
		sc, res := f.close(t, false, eps[order[0]])
		require.Equal(t, ua.StatusOK, sc, "%v", res)
		_, on := f.writerState(t)
		require.True(t, on, "order %v: the other endpoint demands it", order)
		sc, res = f.close(t, false, eps[order[1]])
		require.Equal(t, ua.StatusOK, sc, "%v", res)
		exists, on := f.writerState(t)
		require.True(t, exists)
		require.False(t, on, "order %v: no endpoint demands it: disabled although both reference it", order)

		// Remove both, one after the other.
		sc, res = f.close(t, true, eps[order[0]])
		require.Equal(t, ua.StatusOK, sc, "%v", res)
		exists, _ = f.writerState(t)
		require.True(t, exists, "order %v: the other endpoint references it", order)
		sc, res = f.close(t, true, eps[order[1]])
		require.Equal(t, ua.StatusOK, sc, "%v", res)
		exists, _ = f.writerState(t)
		require.False(t, exists, "order %v: removed with the last endpoint that references it", order)
		require.Empty(t, f.srv.PubSub().Configuration().Connections, "order %v: nothing the call created is left", order)
		f.stop(t)
	}
}

// TestSharedComponentPersistent: the demand of a persistent endpoint
// survives a restart, that of a non-persistent one does not: after a
// restart the shared writer is enabled only when a restored endpoint is.
func TestSharedComponentPersistent(t *testing.T) {
	t.Parallel()
	t.Run("both persistent", func(t *testing.T) {
		t.Parallel()
		opts := fxserver.ConnectionOptions{Store: &fxstore.MemoryStore{}}
		f := newFX(t, opts)
		ep, ep2 := f.sharedPair(t, [2]bool{true, true})
		sc, res := f.close(t, false, ep2)
		require.Equal(t, ua.StatusOK, sc, "%v", res)
		f = f.restart(t, opts)
		f.waitStatus(t, ep, uafx.ConnectionEndpointOperational)
		_, on := f.writerState(t)
		require.True(t, on, "Pub is restored enabled")
		sc, res = f.close(t, false, ep)
		require.Equal(t, ua.StatusOK, sc, "%v", res)
		_, on = f.writerState(t)
		require.False(t, on, "neither demands it")
		f = f.restart(t, opts)
		exists, on := f.writerState(t)
		require.True(t, exists)
		require.False(t, on, "restored disabled")
		f.waitStatus(t, ep2, uafx.ConnectionEndpointReady)
	})
	t.Run("mixed", func(t *testing.T) {
		t.Parallel()
		opts := fxserver.ConnectionOptions{Store: &fxstore.MemoryStore{}}
		f := newFX(t, opts)
		ep, ep2 := f.sharedPair(t, [2]bool{true, false})
		// The persistent one disabled: the non-persistent one still
		// demands the writer.
		sc, res := f.close(t, false, ep)
		require.Equal(t, ua.StatusOK, sc, "%v", res)
		_, on := f.writerState(t)
		require.True(t, on)
		// A restart: only the persistent, disabled endpoint comes back.
		f = f.restart(t, opts)
		require.Nil(t, f.srv.Node(ep2), "a non-persistent endpoint is not restored")
		f.waitStatus(t, ep, uafx.ConnectionEndpointReady)
		exists, on := f.writerState(t)
		require.True(t, exists, "the persistent endpoint's writer is restored")
		require.False(t, on, "and nothing demands it")
		// Removing it removes what its call created.
		sc, res = f.close(t, true, ep)
		require.Equal(t, ua.StatusOK, sc, "%v", res)
		require.Empty(t, f.srv.PubSub().Configuration().Connections)
	})
}

// TestNativeEnableDisable: Enable and Disable of a component with the
// Methods of its Status Object (PubSubStatusType) are runtime only: they are not written
// to the store, and after a restart the enablement of a persisted reader
// or writer follows its endpoints' control state (EnableCommunicationCmd,
// CloseConnections), which is what is durable (docs/uafx.md#persistence,
// LIMITATIONS.md).
func TestNativeEnableDisable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	opts := fxserver.ConnectionOptions{Store: &fxstore.MemoryStore{}}
	f := newFX(t, opts)
	ep := f.persistent(t, "P")
	writerNode := func(f *fx) *ua.NodeID {
		t.Helper()
		n, ok := f.srv.PubSubNodeID(f.lookup(t, pubsub.KindDataSetWriter, pubConn, wgName, writerName))
		require.True(t, ok)
		return n
	}
	records := func(f *fx) uint64 { return f.conns.Persistence().Store.Revision }

	// A native Disable of the writer of an enabled endpoint.
	rev := records(f)
	require.NoError(t, remote.New(f.c).Disable(ctx, writerNode(f)))
	_, on := f.writerState(t)
	require.False(t, on)
	require.Equal(t, rev, records(f), "not written to the store")
	f = f.restart(t, opts)
	f.waitStatus(t, ep, uafx.ConnectionEndpointOperational)
	_, on = f.writerState(t)
	require.True(t, on, "the endpoint is enabled: so is its writer after a restart")

	// A native Enable of the writer of a disabled endpoint.
	sc, res := f.close(t, false, ep)
	require.Equal(t, ua.StatusOK, sc, "%v", res)
	require.NoError(t, remote.New(f.c).Enable(ctx, writerNode(f)))
	_, on = f.writerState(t)
	require.True(t, on)
	f = f.restart(t, opts)
	f.waitStatus(t, ep, uafx.ConnectionEndpointReady)
	_, on = f.writerState(t)
	require.False(t, on, "the endpoint is disabled: so is its writer after a restart")
}

// TestSharedOwnershipRestored: the ownership of a shared writer comes from
// its component record, which every endpoint that references it shares,
// not from the record of the endpoint: an endpoint whose record does not
// own the writer (it linked a writer another call created) and that the
// owner handed it over to, or that is restored without the owner (not
// persistent), owns it after a restart, and removing it removes what the
// call created (Part 81 §6.2.5.2; design §4.2, §4.4).
func TestSharedOwnershipRestored(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		persistent [2]bool
		removeOwn  bool
	}{
		{"both persistent, owner removed", [2]bool{true, true}, true},
		{"owner not persistent, removed", [2]bool{false, true}, true},
		{"owner not persistent, not restored", [2]bool{false, true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mem := &fxstore.MemoryStore{}
			opts := fxserver.ConnectionOptions{Store: mem}
			f := newFX(t, opts)
			ep, ep2 := f.sharedPair(t, tc.persistent)
			if tc.removeOwn {
				sc, res := f.close(t, true, ep)
				require.Equal(t, ua.StatusOK, sc, "%v", res)
				exists, _ := f.writerState(t)
				require.True(t, exists, "Pub2 references it")
			}
			f.stop(t)
			// Pub2's record as a later call that linked the writer
			// writes it: the hand-over is in memory only.
			require.Equal(t, 1, rewrite(t, mem, "ep/", func(v []byte) ([]byte, bool) {
				out, ok, err := fxserver.NotOwner(v, "Pub2")
				require.NoError(t, err)
				return out, ok
			}))
			f = newFX(t, opts)
			require.Nil(t, f.srv.Node(ep))
			require.NotNil(t, f.srv.Node(ep2))
			exists, _ := f.writerState(t)
			require.True(t, exists, "restored with Pub2")
			sc, res := f.close(t, true, ep2)
			require.Equal(t, ua.StatusOK, sc, "%v", res)
			exists, _ = f.writerState(t)
			require.False(t, exists, "removed with the last endpoint that references it")
			require.Empty(t, f.srv.PubSub().Configuration().Connections, "nothing the call created is left")
			require.Equal(t, 0, f.conns.Persistence().Records)
		})
	}
}
