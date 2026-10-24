// SPDX-License-Identifier: MIT

package server_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/internal/testutil/testport"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func pubsubUDPURL(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("opc.udp://127.0.0.1:%d", testport.UDP(t))
}

func nid(n uint32) *ua.NodeID { return ua.NewNumericNodeID(0, n) }

func psCall(t *testing.T, c *opcua.Client, obj, method *ua.NodeID, args ...*ua.Variant) *ua.CallMethodResult {
	t.Helper()
	res, err := c.Call(context.Background(), &ua.CallMethodRequest{ObjectID: obj, MethodID: method, InputArguments: args})
	require.NoError(t, err)
	return res
}

func eoArg(v any) *ua.Variant { return ua.MustVariant(ua.NewExtensionObject(v)) }

func browseNames(t *testing.T, c *opcua.Client, n *ua.NodeID) map[string]*ua.ReferenceDescription {
	t.Helper()
	refs, err := c.Node(n).References(context.Background(), id.References, ua.BrowseDirectionForward, ua.NodeClassAll, true)
	require.NoError(t, err)
	out := map[string]*ua.ReferenceDescription{}
	for _, r := range refs {
		out[r.BrowseName.Name] = r
	}
	return out
}

func TestPubSubInformationModel(t *testing.T) {
	t.Parallel()
	url := pubsubUDPURL(t)
	pds := pubsub.PublishedDataItems("pds", pubsub.Var("time", nid(id.ServerServerStatusCurrentTime), ua.TypeIDDateTime))
	w := pubsub.DataSetWriter("w", 3, "pds")
	cfg := pubsub.NewConfiguration([]*ua.PublishedDataSetDataType{pds},
		pubsub.AttachReaderGroups(pubsub.AttachWriterGroups(pubsub.UDPConnection("conn", url, uint16(4)),
			pubsub.WriterGroup("wg", 2, time.Second, w)),
			pubsub.ReaderGroup("rg", pubsub.SetMirror(pubsub.DataSetReader("r", uint16(4), 2, 3, nil), "Mirror"))))
	srv, surl := testutil.NewTestServer(t, server.WithPubSub(cfg))
	c := testutil.NewTestClient(t, surl)
	ctx := context.Background()

	root := browseNames(t, c, nid(id.PublishSubscribe))
	require.Contains(t, root, "conn")
	require.Contains(t, root, "AddConnection")
	require.Contains(t, root, "Status")
	require.Equal(t, uint32(id.HasPubSubConnection), root["conn"].ReferenceTypeID.IntID())
	require.Equal(t, uint32(id.PubSubConnectionType), root["conn"].TypeDefinition.NodeID.IntID())
	conn := root["conn"].NodeID.NodeID

	cn := browseNames(t, c, conn)
	for _, name := range []string{"PublisherId", "TransportProfileUri", "ConnectionProperties", "Address", "Status", "wg", "rg", "AddWriterGroup", "AddReaderGroup", "RemoveGroup"} {
		require.Contains(t, cn, name)
	}
	addr := browseNames(t, c, cn["Address"].NodeID.NodeID)
	v, err := c.Node(addr["Url"].NodeID.NodeID).Value(ctx)
	require.NoError(t, err)
	require.Equal(t, url, v.Value())

	wg := browseNames(t, c, cn["wg"].NodeID.NodeID)
	for _, name := range []string{"WriterGroupId", "PublishingInterval", "KeepAliveTime", "SecurityMode", "MessageSettings", "w", "AddDataSetWriter", "RemoveDataSetWriter", "Status"} {
		require.Contains(t, wg, name)
	}
	v, err = c.Node(wg["PublishingInterval"].NodeID.NodeID).Value(ctx)
	require.NoError(t, err)
	require.Equal(t, 1000.0, v.Value())
	ms := browseNames(t, c, wg["MessageSettings"].NodeID.NodeID)
	require.Contains(t, ms, "GroupVersion")

	wn := browseNames(t, c, wg["w"].NodeID.NodeID)
	v, err = c.Node(wn["DataSetWriterId"].NodeID.NodeID).Value(ctx)
	require.NoError(t, err)
	require.Equal(t, uint16(3), v.Value())
	st := browseNames(t, c, wn["Status"].NodeID.NodeID)
	require.Contains(t, st, "Enable")
	require.Contains(t, st, "Disable")
	v, err = c.Node(st["State"].NodeID.NodeID).Value(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(ua.PubSubStateOperational), v.Value())

	rn := browseNames(t, c, browseNames(t, c, cn["rg"].NodeID.NodeID)["r"].NodeID.NodeID)
	for _, name := range []string{"PublisherId", "WriterGroupId", "DataSetWriterId", "DataSetMetaData", "MessageReceiveTimeout", "SubscribedDataSet", "Status"} {
		require.Contains(t, rn, name)
	}

	pdsRefs := browseNames(t, c, nid(id.PublishSubscribePublishedDataSets))
	require.Contains(t, pdsRefs, "pds")
	require.Contains(t, pdsRefs, "AddPublishedDataItems")
	require.Contains(t, pdsRefs, "RemovePublishedDataSet")
	pn := browseNames(t, c, pdsRefs["pds"].NodeID.NodeID)
	for _, name := range []string{"PublishedData", "ConfigurationVersion", "DataSetMetaData", "w"} {
		require.Contains(t, pn, name)
	}
	v, err = c.Node(pn["PublishedData"].NodeID.NodeID).Value(ctx)
	require.NoError(t, err)
	require.Len(t, v.Value(), 1)

	v, err = c.Node(nid(id.PublishSubscribeStatusState)).Value(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(ua.PubSubStateOperational), v.Value())
	v, err = c.Node(nid(id.PublishSubscribeSupportedTransportProfiles)).Value(ctx)
	require.NoError(t, err)
	require.Len(t, v.Value(), 5)
	v, err = c.Node(nid(id.PublishSubscribePubSubCapablitiesMaxPubSubConnections)).Value(ctx)
	require.NoError(t, err)
	require.Equal(t, uint32(0), v.Value())

	// The subscriber of the same server receives the publisher's messages
	// and mirrors them; the metadata it learned is not configured, so the
	// mirror names fields by position.
	require.Eventually(t, func() bool {
		sds := browseNames(t, c, rn["SubscribedDataSet"].NodeID.NodeID)
		m, ok := sds["Mirror"]
		if !ok {
			return false
		}
		f, ok := browseNames(t, c, m.NodeID.NodeID)["Field0"]
		if !ok {
			return false
		}
		v, err := c.Node(f.NodeID.NodeID).Value(ctx)
		return err == nil && v.Type() == ua.TypeIDDateTime
	}, 5*time.Second, 5*time.Millisecond)

	// NodeIds and component ids map both ways.
	cid, ok := srv.PubSubComponentID(conn)
	require.True(t, ok)
	back, ok := srv.PubSubNodeID(cid)
	require.True(t, ok)
	require.Equal(t, conn, back)
	rootID, ok := srv.PubSubNodeID(pubsub.Root)
	require.True(t, ok)
	require.Equal(t, uint32(id.PublishSubscribe), rootID.IntID())
	_, ok = srv.PubSubNodeID(9999)
	require.False(t, ok)
	_, ok = srv.PubSubComponentID(nid(1))
	require.False(t, ok)

	// A component added in Go appears in the model; removing it removes
	// its nodes.
	pid, err := srv.PubSub().AddPublishedDataSet(pubsub.PublishedDataItems("go"))
	require.NoError(t, err)
	n, ok := srv.PubSubNodeID(pid)
	require.True(t, ok)
	require.NoError(t, srv.PubSub().RemovePublishedDataSet(pid))
	_, err = c.Node(n).Value(ctx)
	require.Error(t, err)
	require.NotContains(t, browseNames(t, c, nid(id.PublishSubscribePublishedDataSets)), "go")
}

func TestPubSubMethodArguments(t *testing.T) {
	t.Parallel()
	var calls []string
	var mu sync.Mutex
	srv, surl := testutil.NewTestServer(t, server.WithPubSub(nil), server.WithPubSubAuthorizer(func(ctx context.Context, caller *server.MethodCaller, method string) ua.StatusCode {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, method)
		require.NotNil(t, caller)
		if method == "RemoveConnection" {
			return ua.StatusBadUserAccessDenied
		}
		return ua.StatusOK
	}))
	ns := server.NewNodeNameSpace(srv, "test")
	v := ns.AddNewVariableStringNode("v", []int32{1, 2, 3})
	c := testutil.NewTestClient(t, surl)
	ps := nid(id.PublishSubscribe)
	dir := nid(id.PublishSubscribePublishedDataSets)

	res := psCall(t, c, ps, nid(id.PublishSubscribeAddConnection), eoArg(pubsub.UDPConnection("c", pubsubUDPURL(t), uint16(1))))
	require.Equal(t, ua.StatusOK, res.StatusCode)
	conn := res.OutputArguments[0].Value().(*ua.NodeID)
	// Wrong structure, invalid configuration, denied.
	res = psCall(t, c, ps, nid(id.PublishSubscribeAddConnection), eoArg(&ua.WriterGroupDataType{}))
	require.Equal(t, ua.StatusBadTypeMismatch, res.StatusCode)
	res = psCall(t, c, ps, nid(id.PublishSubscribeAddConnection), eoArg(&ua.PubSubConnectionDataType{Name: "x"}))
	require.Equal(t, ua.StatusBadConfigurationError, res.StatusCode)
	res = psCall(t, c, ps, nid(id.PublishSubscribeRemoveConnection), ua.MustVariant(conn))
	require.Equal(t, ua.StatusBadUserAccessDenied, res.StatusCode)
	res = psCall(t, c, ps, nid(id.PublishSubscribeAddConnection))
	require.Equal(t, ua.StatusBadArgumentsMissing, res.StatusCode)

	for _, m := range []uint32{id.PubSubConnectionTypeAddWriterGroup, id.PubSubConnectionTypeAddReaderGroup} {
		res = psCall(t, c, conn, nid(m), eoArg(&ua.PubSubConnectionDataType{}))
		require.Equal(t, ua.StatusBadTypeMismatch, res.StatusCode)
	}
	res = psCall(t, c, conn, nid(id.PubSubConnectionTypeAddWriterGroup), eoArg(pubsub.WriterGroup("wg", 1, time.Second)))
	require.Equal(t, ua.StatusOK, res.StatusCode)
	wg := res.OutputArguments[0].Value().(*ua.NodeID)
	res = psCall(t, c, wg, nid(id.WriterGroupTypeAddDataSetWriter), eoArg(&ua.WriterGroupDataType{}))
	require.Equal(t, ua.StatusBadTypeMismatch, res.StatusCode)
	res = psCall(t, c, conn, nid(id.PubSubConnectionTypeAddReaderGroup), eoArg(pubsub.ReaderGroup("rg")))
	require.Equal(t, ua.StatusOK, res.StatusCode)
	rg := res.OutputArguments[0].Value().(*ua.NodeID)
	res = psCall(t, c, rg, nid(id.ReaderGroupTypeAddDataSetReader), eoArg(&ua.WriterGroupDataType{}))
	require.Equal(t, ua.StatusBadTypeMismatch, res.StatusCode)

	// AddPublishedDataItems: argument lengths must agree; flags and index
	// ranges are kept.
	vars := []*ua.ExtensionObject{ua.NewExtensionObject(&ua.PublishedVariableDataType{PublishedVariable: v.ID(), IndexRange: "1"})}
	res = psCall(t, c, dir, nid(id.DataSetFolderTypeAddPublishedDataItems), ua.MustVariant("p"), ua.MustVariant([]string{}), ua.MustVariant([]uint16{}), ua.MustVariant(vars))
	require.Equal(t, ua.StatusBadInvalidArgument, res.StatusCode)
	res = psCall(t, c, dir, nid(id.DataSetFolderTypeAddPublishedDataItems), ua.MustVariant("p"), ua.MustVariant([]string{"x"}), ua.MustVariant([]uint16{uint16(ua.DataSetFieldFlagsPromotedField)}), ua.MustVariant(vars))
	require.Equal(t, ua.StatusOK, res.StatusCode)
	cid, ok := srv.PubSubComponentID(res.OutputArguments[0].Value().(*ua.NodeID))
	require.True(t, ok)
	pcfg, err := srv.PubSub().PublishedDataSetConfig(cid)
	require.NoError(t, err)
	require.Equal(t, ua.DataSetFieldFlagsPromotedField, pcfg.DataSetMetaData.Fields[0].FieldFlags)
	require.Equal(t, int32(1), pcfg.DataSetMetaData.Fields[0].ValueRank)
	res = psCall(t, c, dir, nid(id.DataSetFolderTypeAddPublishedDataItems), ua.MustVariant("p"), ua.MustVariant([]string{"x"}), ua.MustVariant([]uint16{}), ua.MustVariant(vars))
	require.Equal(t, ua.StatusBadBrowseNameDuplicated, res.StatusCode)
	res = psCall(t, c, dir, nid(id.DataSetFolderTypeAddPublishedDataItemsTemplate), ua.MustVariant("t"), eoArg(pubsub.MetaData("t")), ua.MustVariant(vars))
	require.Equal(t, ua.StatusBadInvalidArgument, res.StatusCode)
	res = psCall(t, c, dir, nid(id.DataSetFolderTypeAddPublishedDataItemsTemplate), ua.MustVariant("t"), eoArg(&ua.WriterGroupDataType{}), ua.MustVariant(vars))
	require.Equal(t, ua.StatusBadTypeMismatch, res.StatusCode)
	res = psCall(t, c, dir, nid(id.DataSetFolderTypeRemovePublishedDataSet), ua.MustVariant(conn))
	require.Equal(t, ua.StatusBadNodeIDUnknown, res.StatusCode)

	// Enable on an enabled component.
	res = psCall(t, c, nid(id.PublishSubscribeStatus), nid(id.PubSubStatusTypeEnable))
	require.Equal(t, ua.StatusBadInvalidState, res.StatusCode)
	mu.Lock()
	require.Contains(t, calls, "AddPublishedDataItemsTemplate")
	require.Contains(t, calls, "Enable")
	mu.Unlock()
}

func TestPubSubDataFlowAndEvents(t *testing.T) {
	t.Parallel()
	url := pubsubUDPURL(t)
	var mu sync.Mutex
	var got []*pubsub.ReceivedDataSet
	srv, err := server.New(server.EndPoint("localhost", 0), server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous), server.WithPubSub(nil, pubsub.WithDataSetHandler(func(d *pubsub.ReceivedDataSet) {
			mu.Lock()
			got = append(got, d)
			mu.Unlock()
		})))
	require.NoError(t, err)
	require.NotNil(t, srv.PubSub())
	ns := server.NewNodeNameSpace(srv, "test")
	arr := ns.AddNewVariableStringNode("arr", []int32{1, 2, 3, 4})
	tgt := ns.AddNewVariableStringNode("tgt", []int32{0, 0, 0, 0})
	ps := srv.PubSub()
	ctx := context.Background()

	_, err = ps.AddPublishedDataSet(pubsub.PublishedDataItems("pds",
		pubsub.PublishedField{Field: pubsub.Field{Name: "slice", Type: ua.TypeIDInt32, Array: true}, NodeID: arr.ID(), IndexRange: "1:2"},
		pubsub.PublishedField{Field: pubsub.Field{Name: "bad", Type: ua.TypeIDInt32}, NodeID: ua.NewStringNodeID(ns.ID(), "nosuch"), Substitute: int32(-1)},
	))
	require.NoError(t, err)
	_, err = ps.AddPublishedDataSet(&ua.PublishedDataSetDataType{Name: "events", DataSetSource: ua.NewExtensionObject(&ua.PublishedEventsDataType{
		EventNotifier:  nid(id.Server),
		SelectedFields: []*ua.SimpleAttributeOperand{{BrowsePath: []*ua.QualifiedName{{Name: "Message"}}}, {BrowsePath: []*ua.QualifiedName{{Name: "Severity"}}}},
		Filter: &ua.ContentFilter{Elements: []*ua.ContentFilterElement{{
			FilterOperator: ua.FilterOperatorGreaterThan,
			FilterOperands: []*ua.ExtensionObject{
				ua.NewExtensionObject(&ua.SimpleAttributeOperand{BrowsePath: []*ua.QualifiedName{{Name: "Severity"}}, AttributeID: ua.AttributeIDValue}),
				ua.NewExtensionObject(&ua.LiteralOperand{Value: ua.MustVariant(uint16(100))}),
			},
		}}},
	})})
	require.NoError(t, err)
	evw := pubsub.DataSetWriter("ev", 2, "events")
	evw.KeyFrameCount = 0
	_, err = ps.AddConnection(pubsub.AttachWriterGroups(pubsub.UDPConnection("pub", url, uint16(1)),
		pubsub.WriterGroup("wg", 1, 10*time.Millisecond, pubsub.DataSetWriter("w", 1, "pds"), evw)))
	require.NoError(t, err)
	tv := pubsub.Target(tgt.ID())
	tv.WriteIndexRange = "2:3"
	_, err = ps.AddConnection(pubsub.AttachReaderGroups(pubsub.UDPConnection("sub", url, nil),
		pubsub.ReaderGroup("rg",
			pubsub.SetTargetVariables(pubsub.DataSetReader("r", uint16(1), 1, 1, pubsub.MetaData("m", pubsub.Field{Name: "slice", Type: ua.TypeIDInt32, Array: true}, pubsub.Field{Name: "bad", Type: ua.TypeIDInt32})), tv),
			pubsub.DataSetReader("events", uint16(1), 1, 2, nil))))
	require.NoError(t, err)

	require.NoError(t, srv.Start(ctx))
	t.Cleanup(func() { _ = srv.Close() })

	require.Eventually(t, func() bool {
		dv := tgt.Value()
		return dv != nil && fmt.Sprint(dv.Value.Value()) == "[0 0 2 3]"
	}, 5*time.Second, 5*time.Millisecond)
	mu.Lock()
	var first *pubsub.ReceivedDataSet
	for _, d := range got {
		if d.ReaderName == "r" {
			first = d
			break
		}
	}
	mu.Unlock()
	require.NotNil(t, first)
	require.Equal(t, int32(-1), first.Field("bad").Value.Value())

	for _, sev := range []uint16{50, 500} {
		require.NoError(t, srv.EmitBaseEvent(nid(id.Server), &server.BaseEvent{
			EventType: nid(id.BaseEventType), Message: ua.NewLocalizedText(fmt.Sprint("sev ", sev)), Severity: sev,
		}))
	}
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		var events []string
		for _, d := range got {
			if d.ReaderName == "events" && d.MessageType == 2 {
				events = append(events, d.Fields[0].Value.Value.Value().(*ua.LocalizedText).Text)
			}
		}
		return fmt.Sprint(events) == "[sev 500]"
	}, 5*time.Second, 5*time.Millisecond)
}

func TestPubSubServerOptions(t *testing.T) {
	t.Parallel()
	_, err := server.New(server.WithPubSub(&ua.PubSubConfigurationDataType{Connections: []*ua.PubSubConnectionDataType{{}}}))
	require.ErrorIs(t, err, ua.StatusBadConfigurationError)
	srv, err := server.New(server.EndPoint("localhost", 0))
	require.NoError(t, err)
	require.Nil(t, srv.PubSub())
	_, ok := srv.PubSubNodeID(pubsub.Root)
	require.False(t, ok)
	_, ok = srv.PubSubComponentID(nid(id.PublishSubscribe))
	require.False(t, ok)
}

func TestPubSubRemoveMethods(t *testing.T) {
	t.Parallel()
	srv, surl := testutil.NewTestServer(t, server.WithPubSub(nil))
	ns := server.NewNodeNameSpace(srv, "test")
	// A variable of an enumeration type and one of a structure type.
	enum := ns.AddNewVariableStringNode("enum", int32(1))
	require.NoError(t, enum.SetAttribute(ua.AttributeIDDataType, server.DataValueFromValue(nid(id.ServerState))))
	strct := ns.AddNewVariableStringNode("struct", ua.NewExtensionObject(&ua.BuildInfo{}))
	require.NoError(t, strct.SetAttribute(ua.AttributeIDDataType, server.DataValueFromValue(nid(id.BuildInfo))))
	c := testutil.NewTestClient(t, surl)
	ps := nid(id.PublishSubscribe)
	dir := nid(id.PublishSubscribePublishedDataSets)

	vars := ua.MustVariant([]*ua.ExtensionObject{
		ua.NewExtensionObject(&ua.PublishedVariableDataType{PublishedVariable: enum.ID()}),
		ua.NewExtensionObject(&ua.PublishedVariableDataType{PublishedVariable: strct.ID()}),
	})
	res := psCall(t, c, dir, nid(id.DataSetFolderTypeAddPublishedDataItems), ua.MustVariant("p"), ua.MustVariant([]string{"", "s"}), ua.MustVariant([]uint16{}), vars)
	require.Equal(t, ua.StatusOK, res.StatusCode)
	pdsNode := res.OutputArguments[0].Value().(*ua.NodeID)
	cid, _ := srv.PubSubComponentID(pdsNode)
	pcfg, err := srv.PubSub().PublishedDataSetConfig(cid)
	require.NoError(t, err)
	require.Equal(t, "enum", pcfg.DataSetMetaData.Fields[0].Name)
	require.Equal(t, uint8(ua.TypeIDInt32), pcfg.DataSetMetaData.Fields[0].BuiltInType)
	require.Equal(t, uint8(ua.TypeIDExtensionObject), pcfg.DataSetMetaData.Fields[1].BuiltInType)

	res = psCall(t, c, ps, nid(id.PublishSubscribeAddConnection), eoArg(pubsub.UDPConnection("c", pubsubUDPURL(t), uint16(1))))
	require.Equal(t, ua.StatusOK, res.StatusCode)
	conn := res.OutputArguments[0].Value().(*ua.NodeID)
	res = psCall(t, c, conn, nid(id.PubSubConnectionTypeAddWriterGroup), eoArg(pubsub.WriterGroup("wg", 1, time.Second)))
	wg := res.OutputArguments[0].Value().(*ua.NodeID)
	res = psCall(t, c, wg, nid(id.WriterGroupTypeAddDataSetWriter), eoArg(pubsub.DataSetWriter("w", 1, "p")))
	require.Equal(t, ua.StatusOK, res.StatusCode)
	w := res.OutputArguments[0].Value().(*ua.NodeID)
	res = psCall(t, c, wg, nid(id.WriterGroupTypeAddDataSetWriter), eoArg(pubsub.DataSetWriter("w", 1, "p")))
	require.Equal(t, ua.StatusBadBrowseNameDuplicated, res.StatusCode)
	res = psCall(t, c, conn, nid(id.PubSubConnectionTypeAddReaderGroup), eoArg(pubsub.ReaderGroup("rg")))
	rg := res.OutputArguments[0].Value().(*ua.NodeID)
	res = psCall(t, c, conn, nid(id.PubSubConnectionTypeAddReaderGroup), eoArg(pubsub.ReaderGroup("rg")))
	require.Equal(t, ua.StatusBadBrowseNameDuplicated, res.StatusCode)
	res = psCall(t, c, conn, nid(id.PubSubConnectionTypeAddWriterGroup), eoArg(pubsub.WriterGroup("wg", 1, time.Second)))
	require.Equal(t, ua.StatusBadBrowseNameDuplicated, res.StatusCode)
	res = psCall(t, c, rg, nid(id.ReaderGroupTypeAddDataSetReader), eoArg(pubsub.DataSetReader("r", nil, 0, 0, nil)))
	require.Equal(t, ua.StatusOK, res.StatusCode)
	r := res.OutputArguments[0].Value().(*ua.NodeID)
	res = psCall(t, c, rg, nid(id.ReaderGroupTypeAddDataSetReader), eoArg(pubsub.DataSetReader("r", nil, 0, 0, nil)))
	require.Equal(t, ua.StatusBadBrowseNameDuplicated, res.StatusCode)

	// Wrong argument types and wrong parents.
	for _, tc := range []struct{ obj, method *ua.NodeID }{
		{ps, nid(id.PublishSubscribeRemoveConnection)},
		{conn, nid(id.PubSubConnectionTypeRemoveGroup)},
		{wg, nid(id.WriterGroupTypeRemoveDataSetWriter)},
		{rg, nid(id.ReaderGroupTypeRemoveDataSetReader)},
		{dir, nid(id.DataSetFolderTypeRemovePublishedDataSet)},
	} {
		res = psCall(t, c, tc.obj, tc.method, ua.MustVariant("x"))
		require.Equal(t, ua.StatusBadTypeMismatch, res.StatusCode)
		res = psCall(t, c, tc.obj, tc.method, ua.MustVariant(nid(1)))
		require.Equal(t, ua.StatusBadNodeIDUnknown, res.StatusCode)
	}
	require.Equal(t, ua.StatusBadNodeIDUnknown, psCall(t, c, rg, nid(id.ReaderGroupTypeRemoveDataSetReader), ua.MustVariant(w)).StatusCode)

	// Disable and Enable through the Status objects.
	st := browseNames(t, c, w)["Status"].NodeID.NodeID
	require.Equal(t, ua.StatusOK, psCall(t, c, st, nid(id.PubSubStatusTypeDisable)).StatusCode)
	require.Equal(t, ua.StatusBadInvalidState, psCall(t, c, st, nid(id.PubSubStatusTypeDisable)).StatusCode)
	require.Equal(t, ua.StatusOK, psCall(t, c, st, nid(id.PubSubStatusTypeEnable)).StatusCode)

	require.Equal(t, ua.StatusOK, psCall(t, c, rg, nid(id.ReaderGroupTypeRemoveDataSetReader), ua.MustVariant(r)).StatusCode)
	require.Equal(t, ua.StatusOK, psCall(t, c, wg, nid(id.WriterGroupTypeRemoveDataSetWriter), ua.MustVariant(w)).StatusCode)
	require.Equal(t, ua.StatusOK, psCall(t, c, conn, nid(id.PubSubConnectionTypeRemoveGroup), ua.MustVariant(rg)).StatusCode)
	require.Equal(t, ua.StatusOK, psCall(t, c, conn, nid(id.PubSubConnectionTypeRemoveGroup), ua.MustVariant(wg)).StatusCode)
	require.Equal(t, ua.StatusOK, psCall(t, c, ps, nid(id.PublishSubscribeRemoveConnection), ua.MustVariant(conn)).StatusCode)
	require.Equal(t, ua.StatusOK, psCall(t, c, dir, nid(id.DataSetFolderTypeRemovePublishedDataSet), ua.MustVariant(pdsNode)).StatusCode)
	// The methods of removed objects are gone.
	require.Equal(t, ua.StatusBadNodeIDUnknown, psCall(t, c, conn, nid(id.PubSubConnectionTypeAddWriterGroup), eoArg(pubsub.WriterGroup("wg", 1, time.Second))).StatusCode)
	require.Empty(t, srv.PubSub().Components())

	// Template with structure arguments.
	res = psCall(t, c, dir, nid(id.DataSetFolderTypeAddPublishedDataItemsTemplate), ua.MustVariant("t"),
		eoArg(pubsub.MetaData("t", pubsub.Field{Name: "x"})), ua.MustVariant([]*ua.ExtensionObject{ua.NewExtensionObject(&ua.PublishedVariableDataType{PublishedVariable: ua.NewStringNodeID(9, "nope")})}))
	require.Equal(t, ua.StatusOK, res.StatusCode)
	require.Equal(t, []ua.StatusCode{ua.StatusBadNodeIDUnknown}, res.OutputArguments[1].Value())
	res = psCall(t, c, dir, nid(id.DataSetFolderTypeAddPublishedDataItemsTemplate), ua.MustVariant("t"),
		eoArg(pubsub.MetaData("t", pubsub.Field{Name: "x"})), ua.MustVariant([]*ua.ExtensionObject{ua.NewExtensionObject(&ua.KeyValuePair{})}))
	require.Equal(t, ua.StatusBadTypeMismatch, res.StatusCode)
	res = psCall(t, c, dir, nid(id.DataSetFolderTypeAddPublishedDataItemsTemplate), ua.MustVariant("t"),
		eoArg(pubsub.MetaData("t", pubsub.Field{Name: "x"})), ua.MustVariant([]*ua.ExtensionObject{ua.NewExtensionObject(&ua.PublishedVariableDataType{PublishedVariable: ua.NewStringNodeID(9, "nope")})}))
	require.Equal(t, ua.StatusBadBrowseNameDuplicated, res.StatusCode)
}

func TestPubSubTargetErrors(t *testing.T) {
	t.Parallel()
	srv, err := server.New(server.EndPoint("localhost", 0), server.WithPubSub(nil))
	require.NoError(t, err)
	ns := server.NewNodeNameSpace(srv, "test")
	ro := ns.AddNewVariableStringNode("ro", int32(1))
	require.NoError(t, ro.SetAttribute(ua.AttributeIDUserAccessLevel, server.DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead))))
	url := pubsubUDPURL(t)
	md := pubsub.MetaData("m", pubsub.Field{Name: "a", Type: ua.TypeIDInt32})
	targets := []*ua.FieldTargetDataType{
		pubsub.Target(ro.ID()),
		pubsub.Target(ua.NewStringNodeID(99, "x")),
		{TargetNodeID: ro.ID(), AttributeID: ua.AttributeIDValue, WriteIndexRange: "1"},
	}
	ps := srv.PubSub()
	_, err = ps.AddConnection(pubsub.AttachReaderGroups(pubsub.UDPConnection("sub", url, nil),
		pubsub.ReaderGroup("rg", pubsub.SetTargetVariables(pubsub.DataSetReader("r", nil, 0, 0, md), targets[0]),
			pubsub.SetTargetVariables(pubsub.DataSetReader("r2", nil, 0, 0, md), targets[1]),
			pubsub.SetTargetVariables(pubsub.DataSetReader("r3", nil, 0, 0, md), targets[2]))))
	require.NoError(t, err)
	_, err = ps.AddPublishedDataSet(pubsub.PublishedDataItems("p", pubsub.Var("a", ro.ID(), ua.TypeIDInt32),
		pubsub.PublishedField{Field: pubsub.Field{Name: "bad"}, NodeID: ua.NewStringNodeID(99, "x")},
		pubsub.PublishedField{Field: pubsub.Field{Name: "rng"}, NodeID: ro.ID(), IndexRange: "1"}))
	require.NoError(t, err)
	_, err = ps.AddConnection(pubsub.AttachWriterGroups(pubsub.UDPConnection("pub", url, uint16(1)), pubsub.WriterGroup("wg", 1, 10*time.Millisecond, pubsub.DataSetWriter("w", 1, "p"))))
	require.NoError(t, err)
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })
	require.Eventually(t, func() bool {
		st, err := ps.Status(pubsub.Root)
		return err == nil && st.Counters.TargetWriteErrors >= 3
	}, 5*time.Second, 5*time.Millisecond)
}
