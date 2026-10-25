// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/remote"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func psNames(t *testing.T, list func() ([]remote.Component, error)) []string {
	t.Helper()
	cs, err := list()
	require.NoError(t, err)
	out := []string{}
	for _, c := range cs {
		out = append(out, c.Name)
	}
	return out
}

func psState(t *testing.T, r *remote.Client, n *ua.NodeID, want ua.PubSubState) {
	t.Helper()
	eventually(t, func() bool {
		s, err := r.State(context.Background(), n)
		return err == nil && s == want
	}, "State "+want.String())
}

// TestPubSub_InformationModelConfiguration configures a publisher server and
// a subscriber server entirely through the methods of the PublishSubscribe
// information model (pubsub/remote): AddPublishedDataItems, AddConnection,
// AddWriterGroup, AddDataSetWriter, AddReaderGroup, AddDataSetReader with
// TargetVariables, Enable. Data then flows from the published variables to
// the target variables; the PublishSubscribe tree shows the components with
// their properties; Disable and Enable of a connection and of
// PublishSubscribe itself propagate to the states of the components below;
// the Remove methods remove them.
func TestPubSub_InformationModelConfiguration(t *testing.T) {
	pubSrv, pubURL := newServer(t, server.WithPubSub(nil))
	subSrv, subURL := newServer(t, server.WithPubSub(nil))
	pns := server.NewNodeNameSpace(pubSrv, "urn:pubsub:model:pub")
	sns := server.NewNodeNameSpace(subSrv, "urn:pubsub:model:sub")
	src1 := pns.AddNewVariableStringNode("speed", int32(120))
	src2 := pns.AddNewVariableStringNode("label", "line 1")
	tgt1 := sns.AddNewVariableStringNode("speed", int32(0))
	tgt2 := sns.AddNewVariableStringNode("label", "")
	rp, rs := remote.New(newClient(t, pubURL)), remote.New(newClient(t, subURL))
	sc := newClient(t, subURL)
	ctx := context.Background()
	url := psUDPURL(t)

	// Publisher.
	res, err := rp.AddPublishedDataItems(ctx, "pds", []string{"speed", "label"}, nil, []*ua.PublishedVariableDataType{
		{PublishedVariable: src1.ID(), AttributeID: ua.AttributeIDValue},
		{PublishedVariable: src2.ID(), AttributeID: ua.AttributeIDValue},
	})
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusOK}, res.AddResults)
	require.NotNil(t, res.ConfigurationVersion)
	require.NotZero(t, res.ConfigurationVersion.MajorVersion)
	pconnCfg := pubsub.UDPConnection("conn", url, uint16(77))
	pconnCfg.Enabled = false
	pconn, err := rp.AddConnection(ctx, pconnCfg)
	require.NoError(t, err)
	wg, err := rp.AddWriterGroup(ctx, pconn, pubsub.WriterGroup("wg", 1, psInterval))
	require.NoError(t, err)
	w, err := rp.AddDataSetWriter(ctx, wg, pubsub.DataSetWriter("w", 1, "pds"))
	require.NoError(t, err)
	psState(t, rp, pconn, ua.PubSubStateDisabled)
	psState(t, rp, wg, ua.PubSubStatePaused)

	// Subscriber.
	sconnCfg := pubsub.UDPConnection("conn", url, nil)
	sconnCfg.Enabled = false
	sconn, err := rs.AddConnection(ctx, sconnCfg)
	require.NoError(t, err)
	rg, err := rs.AddReaderGroup(ctx, sconn, pubsub.ReaderGroup("rg"))
	require.NoError(t, err)
	rd := pubsub.SetTargetVariables(pubsub.DataSetReader("r", uint16(77), 1, 1,
		pubsub.MetaData("pds", pubsub.Field{Name: "speed", Type: ua.TypeIDInt32}, pubsub.Field{Name: "label", Type: ua.TypeIDString})),
		pubsub.Target(tgt1.ID()), pubsub.Target(tgt2.ID()))
	rd.MessageReceiveTimeout = 300
	r, err := rs.AddDataSetReader(ctx, rg, rd)
	require.NoError(t, err)

	// Enable both connections: data flows.
	require.NoError(t, rp.Enable(ctx, pconn))
	require.NoError(t, rs.Enable(ctx, sconn))
	require.ErrorIs(t, rs.Enable(ctx, sconn), ua.StatusBadInvalidState)
	for _, n := range []*ua.NodeID{pconn, wg, w} {
		psState(t, rp, n, ua.PubSubStateOperational)
	}
	psState(t, rs, r, ua.PubSubStateOperational)
	target := func(speed int32, label string) {
		t.Helper()
		eventually(t, func() bool {
			v1, err1 := sc.Node(tgt1.ID()).Value(ctx)
			v2, err2 := sc.Node(tgt2.ID()).Value(ctx)
			return err1 == nil && err2 == nil && v1.Value() == speed && v2.Value() == label
		}, "the target variables take the published values")
	}
	target(120, "line 1")
	require.NoError(t, src1.SetAttribute(ua.AttributeIDValue, server.DataValueFromValue(int32(-3))))
	target(-3, "line 1")

	// The tree and its properties.
	require.Equal(t, []string{"conn"}, psNames(t, func() ([]remote.Component, error) { return rp.Connections(ctx) }))
	require.Equal(t, []string{"wg"}, psNames(t, func() ([]remote.Component, error) { return rp.WriterGroups(ctx, pconn) }))
	require.Equal(t, []string{"w"}, psNames(t, func() ([]remote.Component, error) { return rp.DataSetWriters(ctx, wg) }))
	require.Equal(t, []string{"pds"}, psNames(t, func() ([]remote.Component, error) { return rp.PublishedDataSets(ctx) }))
	require.Equal(t, []string{"rg"}, psNames(t, func() ([]remote.Component, error) { return rs.ReaderGroups(ctx, sconn) }))
	require.Equal(t, []string{"r"}, psNames(t, func() ([]remote.Component, error) { return rs.DataSetReaders(ctx, rg) }))
	for _, p := range []struct {
		r    *remote.Client
		n    *ua.NodeID
		name string
		want any
	}{
		{rp, pconn, "PublisherId", uint16(77)},
		{rp, pconn, "TransportProfileUri", pconnCfg.TransportProfileURI},
		{rp, wg, "WriterGroupId", uint16(1)},
		{rp, wg, "PublishingInterval", float64(psInterval / time.Millisecond)},
		{rp, w, "DataSetWriterId", uint16(1)},
		{rs, r, "PublisherId", uint16(77)},
		{rs, r, "WriterGroupId", uint16(1)},
		{rs, r, "MessageReceiveTimeout", float64(300)},
	} {
		v, err := p.r.Property(ctx, p.n, p.name)
		require.NoError(t, err, p.name)
		require.Equal(t, p.want, v.Value(), p.name)
	}
	v, err := rs.Property(ctx, r, "DataSetMetaData")
	require.NoError(t, err)
	md, ok := v.Value().(*ua.ExtensionObject).Value.(*ua.DataSetMetaDataType)
	require.True(t, ok)
	require.Equal(t, "speed", md.Fields[0].Name)

	// Disable the publisher's connection: it is Disabled, its group and
	// writer Paused; the reader times out.
	require.NoError(t, rp.Disable(ctx, pconn))
	psState(t, rp, pconn, ua.PubSubStateDisabled)
	psState(t, rp, wg, ua.PubSubStatePaused)
	psState(t, rp, w, ua.PubSubStatePaused)
	psState(t, rs, r, ua.PubSubStateError)
	require.NoError(t, rp.Enable(ctx, pconn))
	psState(t, rp, w, ua.PubSubStateOperational)
	psState(t, rs, r, ua.PubSubStateOperational)

	// Disable PublishSubscribe of the subscriber: everything below pauses.
	require.NoError(t, rs.Disable(ctx, nil))
	psState(t, rs, nil, ua.PubSubStateDisabled)
	psState(t, rs, sconn, ua.PubSubStatePaused)
	psState(t, rs, r, ua.PubSubStatePaused)
	require.NoError(t, rs.Enable(ctx, nil))
	psState(t, rs, r, ua.PubSubStateOperational)
	require.NoError(t, src2.SetAttribute(ua.AttributeIDValue, server.DataValueFromValue("line 2")))
	target(-3, "line 2")

	// Remove.
	require.NoError(t, rp.RemoveDataSetWriter(ctx, wg, w))
	require.Empty(t, psNames(t, func() ([]remote.Component, error) { return rp.DataSetWriters(ctx, wg) }))
	require.NoError(t, rs.RemoveDataSetReader(ctx, rg, r))
	require.NoError(t, rs.RemoveGroup(ctx, sconn, rg))
	require.Empty(t, psNames(t, func() ([]remote.Component, error) { return rs.ReaderGroups(ctx, sconn) }))
	require.NoError(t, rp.RemoveConnection(ctx, pconn))
	require.NoError(t, rs.RemoveConnection(ctx, sconn))
	require.Empty(t, psNames(t, func() ([]remote.Component, error) { return rp.Connections(ctx) }))
	require.NoError(t, rp.RemovePublishedDataSet(ctx, res.DataSetNodeID))
	require.Empty(t, psNames(t, func() ([]remote.Component, error) { return rp.PublishedDataSets(ctx) }))
	require.Empty(t, pubSrv.PubSub().Components())
	require.Empty(t, subSrv.PubSub().Components())
}
