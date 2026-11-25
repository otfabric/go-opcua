// SPDX-License-Identifier: MIT

package fxserver_test

import (
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxserver"
)

// TestCloseConnectionsPrune: CloseConnections with Remove removes the
// groups, PubSubConnections and PublishedDataSets the EstablishConnections
// calls created once nothing uses them (Part 81 §6.2.5.2: "all related
// communication model Objects if not referenced from other
// ConnectionEndpoints"); preconfigured ones stay.
func TestCloseConnectionsPrune(t *testing.T) {
	t.Parallel()

	t.Run("bounded", func(t *testing.T) {
		t.Parallel()
		f := newFX(t, fxserver.ConnectionOptions{})
		rt := f.srv.PubSub()
		baseline := len(rt.Components())
		for i := range 5 {
			ep := f.operational(t, fmt.Sprintf("Cycle%d", i), -1)
			assert.Greater(t, len(rt.Components()), baseline)
			sc, results := f.close(t, true, ep)
			require.Equal(t, ua.StatusOK, sc, "%v", results)
			assert.Len(t, rt.Components(), baseline, "cycle %d leaves nothing behind", i)
		}
	})

	t.Run("preconfigured", func(t *testing.T) {
		t.Parallel()
		f := newFX(t, fxserver.ConnectionOptions{})
		rt := f.srv.PubSub()
		pre, err := rt.AddConnection(pubsub.UDPConnection(subConn, f.udp, nil))
		require.NoError(t, err)
		// The call matches the connection the AC has (ElementMatch, OPC
		// 10000-14 §9.1.3.7.2) and adds a group to it.
		r := f.fullRequest("Pre")
		r.ConnectionEndpointConfigurations[0].ConnectionEndpoint.Parameter.CleanupTimeout = -1
		refs := append([]*ua.PubSubConfigurationRefDataType{}, addAll...)
		refs[2] = ref(ua.PubSubConfigurationRefMaskElementMatch|refConn, 1, 0, 0)
		r.CommunicationConfigurations[0].ConfigurationReferences = refs
		res := f.establish(t, r)
		require.Equal(t, ua.StatusOK, res.Status, "%+v", res.CommunicationConfigurationResults)
		ep := res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointID
		c, ok := rt.Lookup(pubsub.KindConnection, pubsub.Root, subConn)
		require.True(t, ok)
		require.Equal(t, pre, c, "the call matched the preconfigured connection")
		sc, results := f.close(t, true, ep)
		require.Equal(t, ua.StatusOK, sc, "%v", results)
		_, ok = rt.Lookup(pubsub.KindReaderGroup, pre, rgName)
		assert.False(t, ok, "the group the call created goes")
		_, err = rt.Component(pre)
		require.NoError(t, err, "the preconfigured connection stays")
		_, ok = rt.Lookup(pubsub.KindConnection, pubsub.Root, pubConn)
		assert.False(t, ok, "the connection the call created goes")
	})

	// Another client adds a PubSubConnection of the Name the call matches
	// while the call runs, right before its update: it is not the call's,
	// and the close leaves it (only the group the call added goes).
	t.Run("concurrent", func(t *testing.T) {
		t.Parallel()
		f := newFX(t, fxserver.ConnectionOptions{})
		rt := f.srv.PubSub()
		var foreign pubsub.ComponentID
		fxserver.SetBeforeUpdate(f.conns, func() {
			id, err := rt.AddConnection(pubsub.UDPConnection(subConn, f.udp, nil))
			assert.NoError(t, err)
			foreign = id
		})
		r := f.fullRequest("Race")
		r.ConnectionEndpointConfigurations[0].ConnectionEndpoint.Parameter.CleanupTimeout = -1
		refs := append([]*ua.PubSubConfigurationRefDataType{}, addAll...)
		refs[2] = ref(ua.PubSubConfigurationRefMaskElementMatch|refConn, 1, 0, 0)
		r.CommunicationConfigurations[0].ConfigurationReferences = refs
		res := f.establish(t, r)
		require.Equal(t, ua.StatusOK, res.Status, "%+v", res.CommunicationConfigurationResults)
		fxserver.SetBeforeUpdate(f.conns, nil)
		c, ok := rt.Lookup(pubsub.KindConnection, pubsub.Root, subConn)
		require.True(t, ok)
		require.Equal(t, foreign, c, "the call matched the foreign connection")
		ep := res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointID
		sc, results := f.close(t, true, ep)
		require.Equal(t, ua.StatusOK, sc, "%v", results)
		_, err := rt.Component(foreign)
		require.NoError(t, err, "the foreign connection survives the close")
		_, ok = rt.Lookup(pubsub.KindReaderGroup, foreign, rgName)
		assert.False(t, ok, "the group the call added goes")
	})

	t.Run("shared", func(t *testing.T) {
		t.Parallel()
		f := newFX(t, fxserver.ConnectionOptions{})
		rt := f.srv.PubSub()
		ep := f.operational(t, "One", -1)
		// A reader another call added to the group the first call created
		// keeps the group and its connection.
		g := f.lookup(t, pubsub.KindDataSetReader, subConn, rgName, readerName)
		info, err := rt.Component(g)
		require.NoError(t, err)
		extra := pubsub.DataSetReader("Extra", uint16(78), 10, 12, md)
		extra.Enabled = false
		_, err = rt.AddDataSetReader(info.Parent, extra)
		require.NoError(t, err)
		sc, results := f.close(t, true, ep)
		require.Equal(t, ua.StatusOK, sc, "%v", results)
		_, err = rt.Component(info.Parent)
		require.NoError(t, err, "a group in use stays")
		_, ok := rt.Lookup(pubsub.KindConnection, pubsub.Root, subConn)
		assert.True(t, ok, "and so does its connection")
		_, ok = rt.Lookup(pubsub.KindConnection, pubsub.Root, pubConn)
		assert.False(t, ok, "the publisher side is not in use")
	})

	// A second writer with its own PublishedDataSet in the WriterGroup the
	// call created keeps the group, its connection and the second writer;
	// the PublishedDataSet of the departing writer, which nothing else
	// uses, goes all the same.
	t.Run("shared writer group", func(t *testing.T) {
		t.Parallel()
		f := newFX(t, fxserver.ConnectionOptions{})
		rt := f.srv.PubSub()
		ep := f.operational(t, "One", -1)
		w := f.lookup(t, pubsub.KindDataSetWriter, pubConn, wgName, writerName)
		info, err := rt.Component(w)
		require.NoError(t, err)
		other, err := rt.AddPublishedDataSet(pubsub.PublishedDataItems("Other", pubsub.Var("x", f.id(actualID), ua.TypeIDDouble)))
		require.NoError(t, err)
		w2 := pubsub.DataSetWriter("W2", 12, "Other")
		w2.Enabled = false
		second, err := rt.AddDataSetWriter(info.Parent, w2)
		require.NoError(t, err)
		sc, results := f.close(t, true, ep)
		require.Equal(t, ua.StatusOK, sc, "%v", results)
		_, ok := rt.Lookup(pubsub.KindPublishedDataSet, pubsub.Root, pdsName)
		assert.False(t, ok, "the PublishedDataSet of the departing writer goes")
		_, err = rt.Component(info.Parent)
		require.NoError(t, err, "the shared group stays")
		_, ok = rt.Lookup(pubsub.KindConnection, pubsub.Root, pubConn)
		assert.True(t, ok, "and so does its connection")
		_, err = rt.Component(second)
		require.NoError(t, err, "the second writer stays")
		_, err = rt.Component(other)
		require.NoError(t, err, "and so does its PublishedDataSet")
	})

	// A removal that fails is the result of the endpoint (Table 23:
	// Uncertain), the endpoint stays, and a later close removes what is
	// left; each remover fails once in turn.
	for _, which := range []string{"group", "connection", "pds"} {
		t.Run("failure "+which, func(t *testing.T) {
			t.Parallel()
			f := newFX(t, fxserver.ConnectionOptions{})
			rt := f.srv.PubSub()
			baseline := len(rt.Components())
			var failed atomic.Int32
			boom := func(real func(pubsub.ComponentID) error) func(pubsub.ComponentID) error {
				return func(id pubsub.ComponentID) error {
					if failed.Add(1) == 1 {
						return ua.StatusBadResourceUnavailable
					}
					return real(id)
				}
			}
			var g, c, p func(pubsub.ComponentID) error
			switch which {
			case "group":
				g = boom(rt.RemoveGroup)
			case "connection":
				c = boom(rt.RemoveConnection)
			default:
				p = boom(rt.RemovePublishedDataSet)
			}
			fxserver.SetPruneOps(f.conns, g, c, p)
			ep := f.operational(t, "Fail", -1)
			sc, results := f.close(t, true, ep)
			assert.Equal(t, ua.StatusUncertain, sc)
			assert.Equal(t, []ua.StatusCode{ua.StatusBadResourceUnavailable}, results)
			require.NotNil(t, f.srv.Node(ep), "the endpoint stays for a retry")
			assert.Greater(t, len(rt.Components()), baseline)

			sc, results = f.close(t, true, ep)
			require.Equal(t, ua.StatusOK, sc, "%v", results)
			assert.Nil(t, f.srv.Node(ep))
			assert.Len(t, rt.Components(), baseline, "the retry removed what was left")
		})
	}
}
