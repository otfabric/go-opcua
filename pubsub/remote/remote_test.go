// SPDX-License-Identifier: MIT

package remote_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/remote"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func udpURL(t *testing.T) string {
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	return fmt.Sprintf("opc.udp://127.0.0.1:%d", c.LocalAddr().(*net.UDPAddr).Port)
}

// TestRemoteConfiguration configures a publisher and a subscriber of a
// go-opcua server through the PubSub methods and checks that the subscriber
// writes the published variable to its target variable.
func TestRemoteConfiguration(t *testing.T) {
	t.Parallel()
	srv, url := testutil.NewTestServer(t, server.WithPubSub(nil))
	ns := server.NewNodeNameSpace(srv, "test")
	src := ns.AddNewVariableStringNode("source", int32(7))
	dst := ns.AddNewVariableStringNode("target", int32(0))
	c := testutil.NewTestClient(t, url)
	r := remote.New(c)
	ctx := context.Background()

	state, err := r.State(ctx, nil)
	require.NoError(t, err)
	require.Equal(t, ua.PubSubStateOperational, state)

	// Published data set.
	res, err := r.AddPublishedDataItems(ctx, "pds", []string{"value", "missing"}, nil, []*ua.PublishedVariableDataType{
		{PublishedVariable: src.ID(), AttributeID: ua.AttributeIDValue},
		{PublishedVariable: ua.NewStringNodeID(ns.ID(), "nosuch"), AttributeID: ua.AttributeIDValue},
	})
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusBadNodeIDUnknown}, res.AddResults)
	require.NotZero(t, res.ConfigurationVersion.MajorVersion)
	pdsList, err := r.PublishedDataSets(ctx)
	require.NoError(t, err)
	require.Len(t, pdsList, 1)
	require.Equal(t, "pds", pdsList[0].Name)
	mdv, err := r.Property(ctx, res.DataSetNodeID, "DataSetMetaData")
	require.NoError(t, err)
	md := mdv.Value().(*ua.ExtensionObject).Value.(*ua.DataSetMetaDataType)
	require.Len(t, md.Fields, 1)
	require.Equal(t, "value", md.Fields[0].Name)
	require.Equal(t, uint8(ua.TypeIDInt32), md.Fields[0].BuiltInType)

	tmpl, results, err := r.AddPublishedDataItemsTemplate(ctx, "tmpl", pubsub.MetaData("tmpl", pubsub.Field{Name: "x", Type: ua.TypeIDInt32}),
		[]*ua.PublishedVariableDataType{{PublishedVariable: src.ID(), AttributeID: ua.AttributeIDValue}})
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, results)
	require.NoError(t, r.RemovePublishedDataSet(ctx, tmpl))
	require.ErrorIs(t, r.RemovePublishedDataSet(ctx, tmpl), ua.StatusBadNodeIDUnknown)

	// Publisher connection, built step by step.
	addr := udpURL(t)
	conn, err := r.AddConnection(ctx, pubsub.UDPConnection("pub", addr, uint16(9)))
	require.NoError(t, err)
	conns, err := r.Connections(ctx)
	require.NoError(t, err)
	require.Equal(t, []remote.Component{{NodeID: conn, Name: "pub"}}, conns)
	pid, err := r.Property(ctx, conn, "PublisherId")
	require.NoError(t, err)
	require.Equal(t, uint16(9), pid.Value())
	wg, err := r.AddWriterGroup(ctx, conn, pubsub.WriterGroup("wg", 1, 20*time.Millisecond))
	require.NoError(t, err)
	w, err := r.AddDataSetWriter(ctx, wg, pubsub.DataSetWriter("w", 1, "pds"))
	require.NoError(t, err)
	wgs, err := r.WriterGroups(ctx, conn)
	require.NoError(t, err)
	require.Len(t, wgs, 1)
	ws, err := r.DataSetWriters(ctx, wg)
	require.NoError(t, err)
	require.Equal(t, w, ws[0].NodeID)

	// Subscriber connection with a reader that writes the target variable.
	sconn, err := r.AddConnection(ctx, pubsub.UDPConnection("sub", addr, nil))
	require.NoError(t, err)
	rg, err := r.AddReaderGroup(ctx, sconn, pubsub.ReaderGroup("rg"))
	require.NoError(t, err)
	reader := pubsub.SetTargetVariables(pubsub.DataSetReader("r", uint16(9), 1, 1, md), pubsub.Target(dst.ID()))
	reader.MessageReceiveTimeout = 200
	rd, err := r.AddDataSetReader(ctx, rg, reader)
	require.NoError(t, err)
	rgs, err := r.ReaderGroups(ctx, sconn)
	require.NoError(t, err)
	require.Len(t, rgs, 1)
	rds, err := r.DataSetReaders(ctx, rg)
	require.NoError(t, err)
	require.Equal(t, rd, rds[0].NodeID)

	require.Eventually(t, func() bool {
		v, err := c.Node(dst.ID()).Value(ctx)
		return err == nil && v.Value() == int32(7)
	}, 5*time.Second, 5*time.Millisecond)
	st, err := r.State(ctx, rd)
	require.NoError(t, err)
	require.Equal(t, ua.PubSubStateOperational, st)

	// Disabling the writer group makes the reader time out.
	require.NoError(t, r.Disable(ctx, wg))
	require.ErrorIs(t, r.Disable(ctx, wg), ua.StatusBadInvalidState)
	require.Eventually(t, func() bool {
		st, err := r.State(ctx, rd)
		return err == nil && st == ua.PubSubStateError
	}, 5*time.Second, 5*time.Millisecond)
	st, err = r.State(ctx, w)
	require.NoError(t, err)
	require.Equal(t, ua.PubSubStatePaused, st)
	require.NoError(t, r.Enable(ctx, wg))
	require.ErrorIs(t, r.Enable(ctx, wg), ua.StatusBadInvalidState)
	require.Eventually(t, func() bool {
		st, err := r.State(ctx, rd)
		return err == nil && st == ua.PubSubStateOperational
	}, 5*time.Second, 5*time.Millisecond)

	// The whole runtime.
	require.NoError(t, r.Disable(ctx, nil))
	st, err = r.State(ctx, conn)
	require.NoError(t, err)
	require.Equal(t, ua.PubSubStatePaused, st)
	require.NoError(t, r.Enable(ctx, nil))

	// Errors.
	_, err = r.AddWriterGroup(ctx, conn, pubsub.WriterGroup("wg", 2, time.Second))
	require.ErrorIs(t, err, ua.StatusBadBrowseNameDuplicated)
	_, err = r.AddDataSetWriter(ctx, wg, pubsub.DataSetWriter("w2", 2, "nosuch"))
	require.ErrorIs(t, err, ua.StatusBadConfigurationError)
	var re *remote.Error
	require.ErrorAs(t, err, &re)
	require.Equal(t, "AddDataSetWriter", re.Method)
	require.Contains(t, re.Error(), "AddDataSetWriter")
	require.ErrorIs(t, r.RemoveGroup(ctx, sconn, wg), ua.StatusBadNodeIDUnknown, "wg is not a group of sconn")
	require.ErrorIs(t, r.RemoveDataSetWriter(ctx, wg, rd), ua.StatusBadNodeIDUnknown)
	require.ErrorIs(t, r.RemoveDataSetReader(ctx, rg, w), ua.StatusBadNodeIDUnknown)
	require.ErrorIs(t, r.RemoveConnection(ctx, wg), ua.StatusBadNodeIDUnknown)
	_, err = r.State(ctx, src.ID())
	require.ErrorIs(t, err, ua.StatusBadNotFound)

	// Removal.
	require.NoError(t, r.RemoveDataSetReader(ctx, rg, rd))
	require.NoError(t, r.RemoveDataSetWriter(ctx, wg, w))
	require.NoError(t, r.RemoveGroup(ctx, sconn, rg))
	require.NoError(t, r.RemoveGroup(ctx, conn, wg))
	require.NoError(t, r.RemoveConnection(ctx, sconn))
	require.NoError(t, r.RemoveConnection(ctx, conn))
	require.NoError(t, r.RemovePublishedDataSet(ctx, res.DataSetNodeID))
	conns, err = r.Connections(ctx)
	require.NoError(t, err)
	require.Empty(t, conns)
	require.Empty(t, srv.PubSub().Components())
	_, err = c.Node(conn).Value(ctx)
	require.Error(t, err)
}

// TestRemoteAddConnectionNested adds a connection with its groups in one
// call, as open62541's AddConnection does.
func TestRemoteAddConnectionNested(t *testing.T) {
	t.Parallel()
	srv, url := testutil.NewTestServer(t, server.WithPubSub(pubsub.NewConfiguration(
		[]*ua.PublishedDataSetDataType{pubsub.PublishedDataItems("pds", pubsub.Var("t", ua.NewNumericNodeID(0, id.ServerServerStatusCurrentTime), ua.TypeIDDateTime))})))
	c := testutil.NewTestClient(t, url)
	r := remote.New(c)
	ctx := context.Background()
	cfg := pubsub.AttachReaderGroups(
		pubsub.AttachWriterGroups(pubsub.UDPConnection("c", udpURL(t), "pub"),
			pubsub.WriterGroup("wg", 1, time.Second, pubsub.DataSetWriter("w", 1, "pds"))),
		pubsub.ReaderGroup("rg", pubsub.DataSetReader("r", "pub", 1, 1, nil)))
	conn, err := r.AddConnection(ctx, cfg)
	require.NoError(t, err)
	wgs, err := r.WriterGroups(ctx, conn)
	require.NoError(t, err)
	require.Len(t, wgs, 1)
	ws, err := r.DataSetWriters(ctx, wgs[0].NodeID)
	require.NoError(t, err)
	require.Len(t, ws, 1)
	_, err = r.AddConnection(ctx, cfg)
	require.ErrorIs(t, err, ua.StatusBadBrowseNameDuplicated)
	require.Len(t, srv.PubSub().Components(), 6)
}

func TestRemoteErrors(t *testing.T) {
	t.Parallel()
	srv, url := testutil.NewTestServer(t, server.WithPubSub(nil))
	ns := server.NewNodeNameSpace(srv, "test")
	v := ns.AddNewVariableStringNode("v", int32(1))
	c := testutil.NewTestClient(t, url)
	r := remote.New(c)
	ctx := context.Background()

	res, err := r.AddPublishedDataItems(ctx, "p", nil, nil, nil)
	require.NoError(t, err)
	require.Empty(t, res.AddResults)
	_, err = r.AddPublishedDataItems(ctx, "q", []string{"a"}, []ua.DataSetFieldFlags{ua.DataSetFieldFlagsPromotedField},
		[]*ua.PublishedVariableDataType{{PublishedVariable: v.ID(), AttributeID: ua.AttributeIDValue}})
	require.NoError(t, err)
	_, err = r.AddPublishedDataItems(ctx, "q", []string{"a", "b"}, nil, []*ua.PublishedVariableDataType{{PublishedVariable: v.ID()}})
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
	_, _, err = r.AddPublishedDataItemsTemplate(ctx, "t", pubsub.MetaData("t"), []*ua.PublishedVariableDataType{{PublishedVariable: v.ID()}})
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
	_, err = r.AddConnection(ctx, &ua.PubSubConnectionDataType{Name: "x"})
	require.ErrorIs(t, err, ua.StatusBadConfigurationError)

	_, err = r.Property(ctx, remote.PublishSubscribe, "nosuch")
	require.ErrorIs(t, err, ua.StatusBadNotFound)
	require.ErrorIs(t, r.Enable(ctx, v.ID()), ua.StatusBadNotFound)
	require.ErrorIs(t, r.Disable(ctx, v.ID()), ua.StatusBadNotFound)
	_, err = r.State(ctx, remote.PublishedDataSets)
	require.ErrorIs(t, err, ua.StatusBadNotFound)
	wgs, _ := r.WriterGroups(ctx, ua.NewStringNodeID(ns.ID(), "nosuch"))
	require.Empty(t, wgs)
	_, err = r.AddWriterGroup(ctx, v.ID(), pubsub.WriterGroup("wg", 1, time.Second))
	require.Error(t, err)
}
