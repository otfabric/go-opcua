// SPDX-License-Identifier: MIT

package fxserver_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxserver"
	"github.com/otfabric/go-opcua/uafx/fxstore"
)

// joinRequest is a second EstablishConnections call that creates Pub2, a
// Publisher on the existing DataSetWriter of Pub: a reference to an
// existing element needs an operation (Part 14 §9.1.3.7.4), so it sends
// an ElementModify of the writer, which the runtime applies by replacing
// it (the writer of pubsubConfig is disabled: it differs from the running
// one). With enable, it enables Pub2.
func (f *fx) joinRequest(persistent, enable bool) *uafx.EstablishConnectionsRequest {
	p2 := f.endpointParam("Pub2")
	p2.Mode, p2.InputVariableIDs, p2.IsPersistent = uafx.PubSubPublisher, nil, persistent
	mask := uafx.CreateConnectionEndpointCmd | uafx.SetCommunicationConfigurationCmd
	if enable {
		mask |= uafx.EnableCommunicationCmd
	}
	return &uafx.EstablishConnectionsRequest{CommandMask: mask,
		ConnectionEndpointConfigurations: []*uafx.ConnectionEndpointConfiguration{{
			FunctionalEntityNode: f.id(motionID), ConnectionEndpoint: &uafx.ConnectionEndpointDefinition{Parameter: p2},
			CommunicationLinks: &uafx.PubSubCommunicationLinkConfiguration{DataSetWriterRef: ref(refWriter, 0, 0, 0)},
		}},
		CommunicationConfigurations: []*uafx.PubSubCommunicationConfiguration{{PubSubConfiguration: f.pubsubConfig(0),
			ConfigurationReferences: []*ua.PubSubConfigurationRefDataType{ref(ua.PubSubConfigurationRefMaskElementModify|refWriter, 0, 0, 0)}}},
	}
}

// joinLater establishes Pub, then Pub2 on its writer in a second call.
func (f *fx) joinLater(t *testing.T, persistent [2]bool) (ep, ep2 *ua.NodeID) {
	t.Helper()
	r := f.fullRequest("Pub")
	r.ConnectionEndpointConfigurations[0].ConnectionEndpoint.Parameter.IsPersistent = persistent[0]
	res := f.establish(t, r)
	require.Equal(t, ua.StatusOK, res.Status, "%+v", res.ConnectionEndpointConfigurationResults)
	ep = res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointID
	f.waitStatus(t, ep, uafx.ConnectionEndpointOperational)
	before := f.writerNode(t)
	res = f.establish(t, f.joinRequest(persistent[1], true))
	require.Equal(t, ua.StatusOK, res.Status, "%+v", res.ConnectionEndpointConfigurationResults[0])
	ep2 = res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointID
	require.False(t, before.Equal(f.writerNode(t)), "the ElementModify replaced the writer")
	f.requireWriterRefs(t, ep, ep2)
	f.waitStatus(t, ep, uafx.ConnectionEndpointOperational)
	f.waitStatus(t, ep2, uafx.ConnectionEndpointOperational)
	return ep, ep2
}

// writerNode returns the node of the shared DataSetWriter.
func (f *fx) writerNode(t *testing.T) *ua.NodeID {
	t.Helper()
	n, ok := f.srv.PubSubNodeID(f.lookup(t, pubsub.KindDataSetWriter, pubConn, wgName, writerName))
	require.True(t, ok)
	return n
}

// requireWriterRefs checks that each endpoint references the live writer.
func (f *fx) requireWriterRefs(t *testing.T, eps ...*ua.NodeID) {
	t.Helper()
	w := f.writerNode(t)
	for _, ep := range eps {
		require.Equal(t, []*ua.NodeID{w}, f.targets(t, ep, fxacid.ToDataSetWriter), "%v references the writer as it is now", ep)
	}
}

// TestSharedAcrossCalls: an endpoint that a later EstablishConnections call
// links to an existing DataSetWriter (ElementModify) shares it with the
// endpoint whose call created it. The modify replaces the writer, and both
// endpoints follow the replacement: References, enablement (Pub demands
// it), and the removal in either order, persistent, mixed and with a
// restart between the removals (Part 81 §6.2.5.2; design §4.2, §4.4).
func TestSharedAcrossCalls(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		persistent [2]bool
		first      int  // the endpoint removed first: 0 Pub, 1 Pub2
		restart    bool // a restart between the removals
	}{
		{"Pub first", [2]bool{}, 0, false},
		{"Pub2 first", [2]bool{}, 1, false},
		{"persistent, Pub first, restart", [2]bool{true, true}, 0, true},
		{"persistent, Pub2 first, restart", [2]bool{true, true}, 1, true},
		{"mixed, Pub first, restart", [2]bool{false, true}, 0, true},
		{"mixed, Pub2 first", [2]bool{true, false}, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := fxserver.ConnectionOptions{}
			if tc.persistent != [2]bool{} {
				opts.Store = &fxstore.MemoryStore{}
			}
			f := newFX(t, opts)
			ep, ep2 := f.joinLater(t, tc.persistent)
			eps := [2]*ua.NodeID{ep, ep2}
			first, last := eps[tc.first], eps[1-tc.first]

			sc, res := f.close(t, true, first)
			require.Equal(t, ua.StatusOK, sc, "%v", res)
			exists, on := f.writerState(t)
			require.True(t, exists, "the other endpoint references it")
			require.True(t, on, "and demands it")
			f.requireWriterRefs(t, last)
			if tc.restart {
				f = f.restart(t, opts)
				require.NotNil(t, f.srv.Node(last), "the persistent endpoint is restored")
				f.requireWriterRefs(t, last)
			}
			sc, res = f.close(t, true, last)
			require.Equal(t, ua.StatusOK, sc, "%v", res)
			exists, _ = f.writerState(t)
			require.False(t, exists, "removed with the last endpoint that references it")
			require.Empty(t, f.srv.PubSub().Configuration().Connections, "nothing the calls created is left")
			if opts.Store != nil {
				require.Equal(t, 0, f.conns.Persistence().Records)
			}
		})
	}
}

// TestSharedAcrossCallsDemand: the replaced writer is enabled again for
// the endpoint that demands it, also when the later call does not enable
// anything (the configuration it sends has the writer disabled), and a
// rollback of that call leaves the first endpoint with a valid reference
// and an enabled writer.
func TestSharedAcrossCallsDemand(t *testing.T) {
	t.Parallel()
	f := newFX(t, fxserver.ConnectionOptions{})
	res := f.establish(t, f.fullRequest("Pub"))
	require.Equal(t, ua.StatusOK, res.Status)
	ep := res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointID
	f.waitStatus(t, ep, uafx.ConnectionEndpointOperational)

	res = f.establish(t, f.joinRequest(false, false))
	require.Equal(t, ua.StatusOK, res.Status, "%+v", res.ConnectionEndpointConfigurationResults[0])
	ep2 := res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointID
	f.requireWriterRefs(t, ep, ep2)
	_, on := f.writerState(t)
	require.True(t, on, "Pub demands it")
	f.waitStatus(t, ep, uafx.ConnectionEndpointOperational)

	// A call that fails after its update: rolled back, the writer of
	// before is back (a new one again), and Pub follows it.
	bad := f.joinRequest(false, true)
	bad.ConnectionEndpointConfigurations[0].ConnectionEndpoint.Parameter.Name = "Pub3"
	// A version the PublishedDataSet does not have: the link check after
	// the update fails (Part 81 §6.2.4.3.9.2).
	bad.ConnectionEndpointConfigurations[0].CommunicationLinks.ExpectedPublishedDataSetVersion = &ua.ConfigurationVersionDataType{MajorVersion: 99, MinorVersion: 99}
	before := f.writerNode(t)
	res = f.establish(t, bad)
	require.NotEqual(t, ua.StatusOK, res.Status)
	require.False(t, before.Equal(f.writerNode(t)), "the update ran and was reverted")
	f.requireWriterRefs(t, ep, ep2)
	_, on = f.writerState(t)
	require.True(t, on)
	f.waitStatus(t, ep, uafx.ConnectionEndpointOperational)
}

// TestSharedNotAdoptedByName: a component another mechanism removes and
// adds again under the same Name in one CloseAndUpdate (ElementRemove,
// ElementAdd) is a new component, not the endpoint's: the endpoint does
// not take it over, whereas an ElementModify of another mechanism is
// followed (design §4.5).
func TestSharedNotAdoptedByName(t *testing.T) {
	t.Parallel()
	opts := fxserver.ConnectionOptions{Store: &fxstore.MemoryStore{}}
	f := newFX(t, opts)
	ep := f.persistent(t, "P")

	// ElementModify by another mechanism: followed.
	cfg := f.pubsubConfig(0)
	require.Equal(t, ua.StatusOK, f.update(t, cfg, ref(ua.PubSubConfigurationRefMaskElementModify|refWriter, 0, 0, 0)))
	f.requireWriterRefs(t, ep)

	// ElementRemove and ElementAdd under the same Name: not adopted.
	old := f.writerNode(t)
	require.Equal(t, ua.StatusOK, f.update(t, cfg,
		ref(ua.PubSubConfigurationRefMaskElementRemove|refWriter, 0, 0, 0), ref(refAdd|refWriter, 0, 0, 0)))
	now := f.writerNode(t)
	require.False(t, old.Equal(now))
	refs := f.targets(t, ep, fxacid.ToDataSetWriter)
	for _, n := range refs {
		require.False(t, n.Equal(now), "the endpoint does not take over a new writer of the same Name")
	}
}
