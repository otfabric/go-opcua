// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/testutil/cleanup"
	"github.com/otfabric/go-opcua/internal/testutil/conformkit"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/remote"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/server/pubsubstore"
	"github.com/otfabric/go-opcua/ua"
)

const psStoreOwner = "urn:otfabric:test:conformance:pubsub-store"

// TestPubSub_ConfigurationStoreRestart: what a client configures with the
// Methods of PublishSubscribe (OPC 10000-14 §9.1.3) and CloseAndUpdate of
// the PubSubConfiguration file (§9.1.3.7.6) on a server with
// server.WithPubSubStore is there after the server is created again on the
// same directory ("shall be available after a restart", §9.1.2), the
// published variable in the namespace of its URI although that namespace
// has another index; a PubSubConnection with 0:NotPersisted TRUE (§6.2.2
// Table 4) is not.
func TestPubSub_ConfigurationStoreRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	open := func() *pubsubstore.Store {
		st, err := pubsubstore.OpenDir(ctx, dir, pubsubstore.Options{Owner: psStoreOwner})
		require.NoError(t, err)
		cleanup.Register(t, func() { _ = st.Close() })
		return st
	}
	var x *server.Node
	st := open()
	srv, url := conformkit.NewServerPrepared(t, func(srv *server.Server) {
		x = server.NewNodeNameSpace(srv, "urn:pubsub:store:app").AddNewVariableStringNode("x", 1.5)
	}, server.WithPubSub(nil), server.WithPubSubStore(st))
	r := remote.New(newClient(t, url))

	res, err := r.AddPublishedDataItems(ctx, "pds", []string{"x"}, nil, []*ua.PublishedVariableDataType{
		{PublishedVariable: x.ID(), AttributeID: ua.AttributeIDValue},
	})
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, res.AddResults)
	conn, err := r.AddConnection(ctx, pubsub.UDPConnection("conn", psUDPURL(t), uint16(7)))
	require.NoError(t, err)
	wg, err := r.AddWriterGroup(ctx, conn, pubsub.WriterGroup("wg", 1, psInterval))
	require.NoError(t, err)
	_, err = r.AddDataSetWriter(ctx, wg, pubsub.DataSetWriter("w", 1, "pds"))
	require.NoError(t, err)
	require.NoError(t, r.Disable(ctx, conn))
	temp := pubsub.UDPConnection("temp", psUDPURL(t), uint16(8))
	temp.ConnectionProperties = []*ua.KeyValuePair{{Key: &ua.QualifiedName{Name: "NotPersisted"}, Value: ua.MustVariant(true)}}
	up, err := r.UpdateConfiguration(ctx, &ua.PubSubConfiguration2DataType{Connections: []*ua.PubSubConnectionDataType{temp, pubsub.UDPConnection("file", psUDPURL(t), uint16(9))}},
		[]*ua.PubSubConfigurationRefDataType{
			{ConfigurationMask: ua.PubSubConfigurationRefMaskElementAdd | ua.PubSubConfigurationRefMaskReferenceConnection, ConnectionIndex: 0},
			{ConfigurationMask: ua.PubSubConfigurationRefMaskElementAdd | ua.PubSubConfigurationRefMaskReferenceConnection, ConnectionIndex: 1},
		}, true)
	require.NoError(t, err)
	require.True(t, up.ChangesApplied)
	require.Equal(t, []string{"conn", "temp", "file"}, psNames(t, func() ([]remote.Component, error) { return r.Connections(ctx) }))

	require.NoError(t, srv.Close())
	require.NoError(t, st.Close())
	st = open()
	// The namespace of the application has another index now.
	var ns2 *server.NodeNameSpace
	srv2, url2 := conformkit.NewServerPrepared(t, func(srv *server.Server) {
		server.NewNodeNameSpace(srv, "urn:pubsub:store:other")
		ns2 = server.NewNodeNameSpace(srv, "urn:pubsub:store:app")
		ns2.AddNewVariableStringNode("x", 2.5)
	}, server.WithPubSub(nil), server.WithPubSubStore(st))
	require.NotEqual(t, x.ID().Namespace(), ns2.ID())
	r2 := remote.New(newClient(t, url2))
	require.Equal(t, []string{"conn", "file"}, psNames(t, func() ([]remote.Component, error) { return r2.Connections(ctx) }))
	require.Equal(t, []string{"pds"}, psNames(t, func() ([]remote.Component, error) { return r2.PublishedDataSets(ctx) }))
	conns, err := r2.Connections(ctx)
	require.NoError(t, err)
	psState(t, r2, conns[0].NodeID, ua.PubSubStateDisabled)
	wgs, err := r2.WriterGroups(ctx, conns[0].NodeID)
	require.NoError(t, err)
	require.Len(t, wgs, 1)
	require.Equal(t, []string{"w"}, psNames(t, func() ([]remote.Component, error) { return r2.DataSetWriters(ctx, wgs[0].NodeID) }))

	rt := srv2.PubSub()
	pid, ok := rt.Lookup(pubsub.KindPublishedDataSet, pubsub.Root, "pds")
	require.True(t, ok)
	d, err := rt.PublishedDataSetConfig(pid)
	require.NoError(t, err)
	items := d.DataSetSource.Value.(*ua.PublishedDataItemsDataType)
	require.Equal(t, ua.NewStringNodeID(ns2.ID(), "x").String(), items.PublishedData[0].PublishedVariable.String())
}
