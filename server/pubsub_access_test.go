// SPDX-License-Identifier: MIT

package server_test

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestPubSubModel_ConnectionPropertiesRedactCredentials(t *testing.T) {
	t.Parallel()
	conn := pubsub.UDPConnection("conn", pubsubUDPURL(t), uint16(4))
	kv := func(k, v string) *ua.KeyValuePair {
		return &ua.KeyValuePair{Key: &ua.QualifiedName{Name: k}, Value: ua.MustVariant(v)}
	}
	conn.ConnectionProperties = []*ua.KeyValuePair{kv("username", "plant"), kv("password", "pw-1"), kv("Client-Secret", "s-2")}
	srv, surl := testutil.NewTestServer(t, server.WithPubSub(pubsub.NewConfiguration(nil, conn)))
	c := testutil.NewTestClient(t, surl)
	ctx := context.Background()

	root := browseNames(t, c, nid(id.PublishSubscribe))
	props := browseNames(t, c, root["conn"].NodeID.NodeID)["ConnectionProperties"]
	require.NotNil(t, props)
	v, err := c.Node(props.NodeID.NodeID).Value(ctx)
	require.NoError(t, err)
	got := map[string]any{}
	for _, e := range v.Value().([]*ua.ExtensionObject) {
		p := e.Value.(*ua.KeyValuePair)
		got[p.Key.Name] = p.Value.Value()
	}
	require.Equal(t, map[string]any{"username": "plant", "password": nil, "Client-Secret": nil}, got)

	// The runtime keeps the real values.
	cid, ok := srv.PubSubComponentID(root["conn"].NodeID.NodeID)
	require.True(t, ok)
	cfg, err := srv.PubSub().ConnectionConfig(cid)
	require.NoError(t, err)
	require.Equal(t, "pw-1", cfg.ConnectionProperties[1].Value.Value())
}

// targetDenier refuses writes and reads of one node to every session.
type targetDenier struct {
	server.DefaultAccessController
	node *ua.NodeID
}

func (d *targetDenier) CheckWrite(_ context.Context, s *server.Session, n *ua.NodeID) ua.StatusCode {
	if s != nil && n.Equal(d.node) {
		return ua.StatusBadUserAccessDenied
	}
	return ua.StatusOK
}

func (d *targetDenier) CheckRead(_ context.Context, s *server.Session, n *ua.NodeID) ua.StatusCode {
	if s != nil && n.Equal(d.node) {
		return ua.StatusBadUserAccessDenied
	}
	return ua.StatusOK
}

func TestPubSubConfig_TargetVariablesRespectAccessController(t *testing.T) {
	t.Parallel()
	ac := &targetDenier{}
	srv, surl := testutil.NewTestServer(t, server.WithPubSub(nil), server.WithAccessController(ac))
	ns := server.NewNodeNameSpace(srv, "test")
	secret := ns.AddNewVariableStringNode("secret", int32(1))
	ac.node = secret.ID()
	ro := ns.AddNewVariableStringNode("ro", int32(2))
	require.NoError(t, ro.SetAttribute(ua.AttributeIDAccessLevel, server.DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead))))
	open := ns.AddNewVariableStringNode("open", int32(3))
	named := ns.AddNewVariableStringNode("named", int32(4))
	require.NoError(t, named.SetAttribute(ua.AttributeIDWriteMask, server.DataValueFromValue(uint32(ua.AttributeWriteMaskDisplayName))))
	c := testutil.NewTestClient(t, surl)

	md := pubsub.MetaData("m", pubsub.Field{Name: "a", Type: ua.TypeIDInt32})
	reader := func(targets ...*ua.FieldTargetDataType) *ua.DataSetReaderDataType {
		return pubsub.SetTargetVariables(pubsub.DataSetReader("r", uint16(1), 1, 1, md), targets...)
	}
	attrTarget := func(n *ua.NodeID, a ua.AttributeID) *ua.FieldTargetDataType {
		return &ua.FieldTargetDataType{TargetNodeID: n, AttributeID: a}
	}

	ps := nid(id.PublishSubscribe)
	addConn := func(name string, r *ua.DataSetReaderDataType) ua.StatusCode {
		conn := pubsub.AttachReaderGroups(pubsub.UDPConnection(name, pubsubUDPURL(t), nil), pubsub.ReaderGroup("rg", r))
		return psCall(t, c, ps, nid(id.PublishSubscribeAddConnection), eoArg(conn)).StatusCode
	}
	require.Equal(t, ua.StatusBadUserAccessDenied, addConn("c1", reader(pubsub.Target(secret.ID()))))
	require.Equal(t, ua.StatusBadNotWritable, addConn("c2", reader(pubsub.Target(ro.ID()))))
	require.Equal(t, ua.StatusBadNotWritable, addConn("c3", reader(attrTarget(ro.ID(), ua.AttributeIDAccessLevel))))
	require.Equal(t, ua.StatusBadNotWritable, addConn("c4", reader(attrTarget(named.ID(), ua.AttributeIDDescription))))
	require.Equal(t, ua.StatusOK, addConn("c5", reader(attrTarget(named.ID(), ua.AttributeIDDisplayName))))
	require.Equal(t, ua.StatusOK, addConn("c6", reader(pubsub.Target(open.ID()))))
	// A target that does not exist yet is left to the runtime.
	require.Equal(t, ua.StatusOK, addConn("c6b", reader(pubsub.Target(ua.NewStringNodeID(ns.ID(), "later")))))

	// The reader group and reader methods check the same.
	res := psCall(t, c, ps, nid(id.PublishSubscribeAddConnection), eoArg(pubsub.UDPConnection("c7", pubsubUDPURL(t), nil)))
	require.Equal(t, ua.StatusOK, res.StatusCode)
	conn := res.OutputArguments[0].Value().(*ua.NodeID)
	res = psCall(t, c, conn, nid(id.PubSubConnectionTypeAddReaderGroup), eoArg(pubsub.ReaderGroup("rg2", reader(pubsub.Target(secret.ID())))))
	require.Equal(t, ua.StatusBadUserAccessDenied, res.StatusCode)
	res = psCall(t, c, conn, nid(id.PubSubConnectionTypeAddReaderGroup), eoArg(pubsub.ReaderGroup("rg3")))
	require.Equal(t, ua.StatusOK, res.StatusCode)
	rg := res.OutputArguments[0].Value().(*ua.NodeID)
	res = psCall(t, c, rg, nid(id.ReaderGroupTypeAddDataSetReader), eoArg(reader(pubsub.Target(secret.ID()))))
	require.Equal(t, ua.StatusBadUserAccessDenied, res.StatusCode)
	res = psCall(t, c, rg, nid(id.ReaderGroupTypeAddDataSetReader), eoArg(reader(pubsub.Target(open.ID()))))
	require.Equal(t, ua.StatusOK, res.StatusCode)

	// Published variables need CheckRead.
	dir := nid(id.PublishSubscribePublishedDataSets)
	vars := []*ua.ExtensionObject{
		ua.NewExtensionObject(&ua.PublishedVariableDataType{PublishedVariable: secret.ID()}),
		ua.NewExtensionObject(&ua.PublishedVariableDataType{PublishedVariable: open.ID()}),
	}
	res = psCall(t, c, dir, nid(id.DataSetFolderTypeAddPublishedDataItems), ua.MustVariant("p"), ua.MustVariant([]string{"s", "o"}), ua.MustVariant([]uint16{}), ua.MustVariant(vars))
	require.Equal(t, ua.StatusOK, res.StatusCode)
	require.Equal(t, []ua.StatusCode{ua.StatusBadUserAccessDenied, ua.StatusOK}, res.OutputArguments[2].Value())
	res = psCall(t, c, dir, nid(id.DataSetFolderTypeAddPublishedDataItemsTemplate), ua.MustVariant("t"),
		eoArg(pubsub.MetaData("t", pubsub.Field{Name: "s"}, pubsub.Field{Name: "o"})), ua.MustVariant(vars))
	require.Equal(t, ua.StatusBadUserAccessDenied, res.StatusCode)

	// Configured through the Go API, the operator decides.
	_, err := srv.PubSub().AddConnection(pubsub.AttachReaderGroups(pubsub.UDPConnection("op", pubsubUDPURL(t), nil), pubsub.ReaderGroup("rg", reader(pubsub.Target(secret.ID())))))
	require.NoError(t, err)
}

func TestPubSubConfig_MethodsRestrictedUnderRBAC(t *testing.T) {
	t.Parallel()
	srv, surl := testutil.NewTestServer(t, server.WithPubSub(nil), server.WithAccessController(server.NewRBACAccessController(nil)))
	ns := server.NewNodeNameSpace(srv, "test")
	v := ns.AddNewVariableStringNode("v", int32(1))
	c := testutil.NewTestClient(t, surl)
	vars := []*ua.ExtensionObject{ua.NewExtensionObject(&ua.PublishedVariableDataType{PublishedVariable: v.ID()})}
	res := psCall(t, c, nid(id.PublishSubscribePublishedDataSets), nid(id.DataSetFolderTypeAddPublishedDataItems),
		ua.MustVariant("p"), ua.MustVariant([]string{"v"}), ua.MustVariant([]uint16{}), ua.MustVariant(vars))
	require.Equal(t, ua.StatusBadUserAccessDenied, res.StatusCode)
	res = psCall(t, c, nid(id.PublishSubscribeStatus), nid(id.PubSubStatusTypeDisable))
	require.Equal(t, ua.StatusBadUserAccessDenied, res.StatusCode)
	res = psCall(t, c, nid(id.PublishSubscribe), nid(id.PublishSubscribeAddConnection), eoArg(pubsub.UDPConnection("c", pubsubUDPURL(t), nil)))
	require.Equal(t, ua.StatusBadUserAccessDenied, res.StatusCode)
}
