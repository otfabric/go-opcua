// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// hookNS is a NameSpace that answers selected Attribute reads itself, as a
// namespace implemented by an application may do.
type hookNS struct {
	*NodeNameSpace
	attr func(id *ua.NodeID, a ua.AttributeID) (*ua.DataValue, bool)
}

func (h *hookNS) Attribute(id *ua.NodeID, a ua.AttributeID) *ua.DataValue {
	if dv, ok := h.attr(id, a); ok {
		return dv
	}
	return h.NodeNameSpace.Attribute(id, a)
}

// installHookNS adds a namespace whose Attribute reads go through attr first.
func installHookNS(s *Server, attr func(*ua.NodeID, ua.AttributeID) (*ua.DataValue, bool)) *NodeNameSpace {
	ns := NewNodeNameSpace(s, "urn:cov:hook")
	s.mu.Lock()
	s.namespaces[ns.ID()] = &hookNS{NodeNameSpace: ns, attr: attr}
	s.mu.Unlock()
	return ns
}

func newDataTypeNode(nodeID *ua.NodeID, name string) *Node {
	return NewNode(nodeID, map[ua.AttributeID]*ua.DataValue{
		ua.AttributeIDNodeClass:  DataValueFromValue(uint32(ua.NodeClassDataType)),
		ua.AttributeIDBrowseName: DataValueFromValue(attrs.BrowseName(name)),
	}, nil, nil)
}

func TestPubSubCov_ReadPublished(t *testing.T) {
	s := newTestServer()
	var nilNode *ua.NodeID
	ns := installHookNS(s, func(n *ua.NodeID, _ ua.AttributeID) (*ua.DataValue, bool) {
		if n.StringID() == "vanished" {
			return nil, true
		}
		return nil, false
	})
	arr := ns.AddNewVariableStringNode("arr", []int32{10, 20, 30})
	src := serverDataSource{s}

	out := src.ReadPublishedData(context.Background(), []*ua.PublishedVariableDataType{
		nil,
		{PublishedVariable: nilNode},
		{PublishedVariable: ua.NewStringNodeID(77, "x"), AttributeID: ua.AttributeIDValue}, // unknown namespace
		{PublishedVariable: ua.NewStringNodeID(ns.ID(), "vanished"), AttributeID: ua.AttributeIDValue},
		{PublishedVariable: arr.ID()}, // AttributeID 0 reads the Value
		{PublishedVariable: arr.ID(), AttributeID: ua.AttributeIDValue, IndexRange: "1"},
		{PublishedVariable: arr.ID(), AttributeID: ua.AttributeIDBrowseName, IndexRange: "1"},
		{PublishedVariable: ua.NewStringNodeID(ns.ID(), "missing"), AttributeID: ua.AttributeIDValue, IndexRange: "1"},
		{PublishedVariable: arr.ID(), AttributeID: ua.AttributeIDValue, IndexRange: "7"},
	})
	require.Len(t, out, 9)
	for i := 0; i < 4; i++ {
		require.Equal(t, ua.StatusBadNodeIDUnknown, out[i].Status, "entry %d", i)
	}
	require.Equal(t, ua.StatusOK, out[4].Status)
	require.Equal(t, []int32{10, 20, 30}, out[4].Value.Value())
	require.Equal(t, ua.StatusOK, out[5].Status)
	require.Equal(t, []int32{20}, out[5].Value.Value())
	require.Equal(t, ua.StatusBadIndexRangeInvalid, out[6].Status, "IndexRange on a non-Value attribute")
	require.Equal(t, ua.StatusBadIndexRangeInvalid, out[7].Status, "IndexRange on a Bad value")
	require.Equal(t, ua.StatusBadIndexRangeNoData, out[8].Status)
}

func TestPubSubCov_FieldMetaData(t *testing.T) {
	s := newTestServer()
	ns := installHookNS(s, func(n *ua.NodeID, a ua.AttributeID) (*ua.DataValue, bool) {
		if n.StringID() == "expanded" && a == ua.AttributeIDDataType {
			return DataValueFromValue(ua.NewNumericExpandedNodeID(0, id.Double)), true
		}
		return nil, false
	})
	src := serverDataSource{s}

	// Unknown node and non-Value attributes have no field metadata.
	require.Nil(t, src.FieldMetaData(&ua.PublishedVariableDataType{PublishedVariable: ua.NewStringNodeID(ns.ID(), "nope")}))
	scalar := ns.AddNewVariableStringNode("scalar", int32(1))
	require.Nil(t, src.FieldMetaData(&ua.PublishedVariableDataType{PublishedVariable: scalar.ID(), AttributeID: ua.AttributeIDDisplayName}))

	// A DataType given as ExpandedNodeID.
	exp := ns.AddNewVariableStringNode("expanded", 1.5)
	f := src.FieldMetaData(&ua.PublishedVariableDataType{PublishedVariable: exp.ID()})
	require.NotNil(t, f)
	require.Equal(t, "expanded", f.Name)
	require.Equal(t, ua.NewNumericNodeID(0, id.Double), f.DataType)
	require.Equal(t, uint8(ua.TypeIDDouble), f.BuiltInType)

	// No DataType attribute: BaseDataType, encoded as Variant.
	untyped := NewNode(ua.NewStringNodeID(ns.ID(), "untyped"), map[ua.AttributeID]*ua.DataValue{
		ua.AttributeIDNodeClass:  DataValueFromValue(uint32(ua.NodeClassVariable)),
		ua.AttributeIDBrowseName: DataValueFromValue(attrs.BrowseName("untyped")),
	}, nil, func() *ua.DataValue { return DataValueFromValue(int32(1)) })
	ns.AddNode(untyped)
	f = src.FieldMetaData(&ua.PublishedVariableDataType{PublishedVariable: untyped.ID(), AttributeID: ua.AttributeIDValue})
	require.NotNil(t, f)
	require.Equal(t, ua.NewNumericNodeID(0, id.BaseDataType), f.DataType)
	require.Equal(t, uint8(ua.TypeIDVariant), f.BuiltInType)
	require.Equal(t, int32(-1), f.ValueRank)

	// An explicit ValueRank attribute wins; a range of an array stays an array.
	matrix := ns.AddNewVariableStringNode("matrix", []int32{1, 2, 3, 4})
	require.NoError(t, matrix.SetAttribute(ua.AttributeIDValueRank, DataValueFromValue(int32(2))))
	f = src.FieldMetaData(&ua.PublishedVariableDataType{PublishedVariable: matrix.ID()})
	require.Equal(t, int32(2), f.ValueRank)
	f = src.FieldMetaData(&ua.PublishedVariableDataType{PublishedVariable: matrix.ID(), IndexRange: "0:1"})
	require.Equal(t, int32(1), f.ValueRank)
}

func TestPubSubCov_BuiltinType(t *testing.T) {
	s := newTestServer()
	ns := NewNodeNameSpace(s, "urn:cov:types")

	// A structure-less custom type derived from Int32.
	derived := newDataTypeNode(ua.NewStringNodeID(ns.ID(), "Derived"), "Derived")
	derived.AddRef(s.Node(ua.NewNumericNodeID(0, id.Int32)), id.HasSubtype, false)
	ns.AddNode(derived)
	require.Equal(t, uint8(ua.TypeIDInt32), s.builtinType(derived.ID()))
	require.True(t, ua.NewNumericNodeID(0, id.Int32).Equal(s.superType(derived.ID())))

	// A type without a supertype and a type that does not exist.
	orphan := newDataTypeNode(ua.NewStringNodeID(ns.ID(), "Orphan"), "Orphan")
	ns.AddNode(orphan)
	require.Nil(t, s.superType(orphan.ID()))
	require.Equal(t, uint8(ua.TypeIDVariant), s.builtinType(orphan.ID()))
	ghost := ua.NewStringNodeID(ns.ID(), "Ghost")
	require.Nil(t, s.superType(ghost))
	require.Equal(t, uint8(ua.TypeIDVariant), s.builtinType(ghost))
	require.Equal(t, uint8(ua.TypeIDVariant), s.builtinType(nil))

	// A cyclic hierarchy must not loop forever.
	a := newDataTypeNode(ua.NewStringNodeID(ns.ID(), "A"), "A")
	b := newDataTypeNode(ua.NewStringNodeID(ns.ID(), "B"), "B")
	a.AddRef(b, id.HasSubtype, false)
	b.AddRef(a, id.HasSubtype, false)
	ns.AddNode(a)
	ns.AddNode(b)
	require.Equal(t, uint8(ua.TypeIDVariant), s.builtinType(a.ID()))
}

func TestPubSubCov_WriteTarget(t *testing.T) {
	s := newTestServer()
	ns := NewNodeNameSpace(s, "urn:cov:targets")
	arr := ns.AddNewVariableStringNode("arr", []int32{0, 0, 0})
	hidden := ns.AddNewVariableStringNode("hidden", []int32{0, 0})
	require.NoError(t, hidden.SetAttribute(ua.AttributeIDAccessLevel, DataValueFromValue(byte(ua.AccessLevelTypeNone))))
	require.NoError(t, hidden.SetAttribute(ua.AttributeIDUserAccessLevel, DataValueFromValue(byte(ua.AccessLevelTypeNone))))
	w := serverTargetWriter{s}

	val := DataValueFromValue([]int32{7, 8, 9})
	errs := w.WriteTargets(context.Background(), []pubsub.TargetWrite{
		{Target: &ua.FieldTargetDataType{TargetNodeID: arr.ID()}, Value: val}, // AttributeID 0 writes the Value
	})
	require.Equal(t, []error{nil}, errs)
	require.Equal(t, []int32{7, 8, 9}, arr.Value().Value.Value())

	require.Equal(t, ua.StatusBadNodeIDUnknown, s.writeTarget(nil, val))
	require.Equal(t, ua.StatusBadNodeIDUnknown, s.writeTarget(&ua.FieldTargetDataType{TargetNodeID: arr.ID()}, nil))
	require.Equal(t, ua.StatusBadNodeIDUnknown, s.writeTarget(&ua.FieldTargetDataType{TargetNodeID: ua.NewStringNodeID(88, "x")}, val))

	one := DataValueFromValue([]int32{5})
	// A WriteIndexRange needs the Value attribute and a value to merge.
	require.Equal(t, ua.StatusBadIndexRangeInvalid, s.writeTarget(&ua.FieldTargetDataType{
		TargetNodeID: arr.ID(), AttributeID: ua.AttributeIDDisplayName, WriteIndexRange: "1"}, one))
	require.Equal(t, ua.StatusBadIndexRangeInvalid, s.writeTarget(&ua.FieldTargetDataType{
		TargetNodeID: arr.ID(), WriteIndexRange: "1"}, &ua.DataValue{}))
	// The current value cannot be read: nothing to merge the range into.
	require.Equal(t, ua.StatusBadIndexRangeInvalid, s.writeTarget(&ua.FieldTargetDataType{
		TargetNodeID: hidden.ID(), WriteIndexRange: "1"}, one))
	require.Equal(t, ua.StatusBadIndexRangeInvalid, s.writeTarget(&ua.FieldTargetDataType{
		TargetNodeID: ua.NewStringNodeID(ns.ID(), "missing"), WriteIndexRange: "1"}, one))

	require.Equal(t, ua.StatusOK, s.writeTarget(&ua.FieldTargetDataType{TargetNodeID: arr.ID(), WriteIndexRange: "1"}, one))
	require.Equal(t, []int32{7, 5, 9}, arr.Value().Value.Value())
}

func TestPubSubCov_EventSource(t *testing.T) {
	s := newTestServer()
	src := serverEventSource{s}
	ctx := context.Background()

	_, err := src.SubscribeEvents(ctx, nil, func([]*ua.Variant) {})
	require.Error(t, err)
	_, err = src.SubscribeEvents(ctx, &ua.PublishedEventsDataType{}, func([]*ua.Variant) {})
	require.Error(t, err)

	notifier := ua.NewNumericNodeID(0, id.Server)
	var got [][]*ua.Variant
	cancel, err := src.SubscribeEvents(ctx, &ua.PublishedEventsDataType{
		EventNotifier:  notifier,
		SelectedFields: []*ua.SimpleAttributeOperand{{BrowsePath: []*ua.QualifiedName{{Name: "Severity"}}}},
	}, func(v []*ua.Variant) { got = append(got, v) })
	require.NoError(t, err)

	ev := &BaseEvent{EventType: ua.NewNumericNodeID(0, id.BaseEventType), Severity: 300}
	s.forwardPubSubEvent(nil, ev)
	s.forwardPubSubEvent(notifier, nil)
	s.forwardPubSubEvent(ua.NewNumericNodeID(0, id.ObjectsFolder), ev) // other notifier
	require.Empty(t, got)

	s.forwardPubSubEvent(notifier, ev)
	require.Len(t, got, 1)
	require.Equal(t, uint16(300), got[0][0].Value())

	cancel()
	s.forwardPubSubEvent(notifier, ev)
	require.Len(t, got, 1, "no delivery after unsubscribing")
}

func TestPubSubCov_StartFailures(t *testing.T) {
	// Without the PublishSubscribe object in namespace 0 the information
	// model cannot be built: Start fails and the server reports Failed.
	s, err := newServerNoNS(EndPoint("localhost", 0), EnableSecurity("None", ua.MessageSecurityModeNone),
		EnableAuthMode(ua.UserTokenTypeAnonymous), WithPubSub(nil))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	err = s.Start(context.Background())
	require.ErrorContains(t, err, "PublishSubscribe object is missing")
	s.mu.Lock()
	require.Equal(t, ua.ServerStateFailed, s.status.State)
	s.mu.Unlock()

	// A runtime that cannot be created. WithPubSub validates its
	// configuration, so this is a configuration set without it.
	s2, err := newServerNoNS(EndPoint("localhost", 0))
	require.NoError(t, err)
	s2.cfg.pubsub = &pubsubConfig{cfg: &ua.PubSubConfigurationDataType{Connections: []*ua.PubSubConnectionDataType{{}}}}
	require.Nil(t, s2.PubSub())
	err = s2.startPubSub(context.Background())
	require.ErrorIs(t, err, ua.StatusBadConfigurationError)
	require.ErrorContains(t, err, "server: pubsub")
	s2.closePubSub() // nothing to close
}
