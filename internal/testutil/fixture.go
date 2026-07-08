// SPDX-License-Identifier: MIT

package testutil

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
)

// Fixture is a rich set of server-side nodes used by the conformance and
// adversarial test suites. It exposes typed node IDs so tests can exercise the
// full client/server API surface (scalars of every common type, arrays, access
// control, a callable method, and an event source) against a single server.
type Fixture struct {
	Srv     *server.Server
	NS      *server.NodeNameSpace
	NSIndex uint16

	// Scalar variables (read/write) of each common data type.
	Bool       *ua.NodeID
	SByte      *ua.NodeID
	Byte       *ua.NodeID
	Int16      *ua.NodeID
	Uint16     *ua.NodeID
	Int32      *ua.NodeID
	Uint32     *ua.NodeID
	Int64      *ua.NodeID
	Uint64     *ua.NodeID
	Float      *ua.NodeID
	Double     *ua.NodeID
	String     *ua.NodeID
	ByteString *ua.NodeID

	// Array variables.
	Int32Array  *ua.NodeID
	StringArray *ua.NodeID

	// Access-controlled variables.
	Writable *ua.NodeID // read + write
	ReadOnly *ua.NodeID // read only
	NoAccess *ua.NodeID // neither read nor write

	// Object that owns SquareMethod, plus the callable method node.
	MethodObject *ua.NodeID
	SquareMethod *ua.NodeID

	// Object that emits events (has the EventNotifier attribute set).
	EventObject *ua.NodeID

	// Custom VariableType hierarchy used to exercise Query type/subtype
	// matching: CustomVarSubType is a HasSubtype of CustomVarType.
	CustomVarType    *ua.NodeID
	CustomVarSubType *ua.NodeID

	// Instances typed via HasTypeDefinition. CustomVarA/B are of CustomVarType,
	// CustomSubVar is of CustomVarSubType.
	CustomVarA   *ua.NodeID
	CustomVarB   *ua.NodeID
	CustomSubVar *ua.NodeID
}

// nodeID builds a string node id in the fixture namespace.
func (f *Fixture) nodeID(name string) *ua.NodeID {
	return ua.NewStringNodeID(f.NSIndex, name)
}

// AddFixture registers a rich namespace of nodes on the given server and returns
// a Fixture describing them. It must be called before the client connects.
func AddFixture(t *testing.T, srv *server.Server) *Fixture {
	t.Helper()

	root, err := srv.Namespace(0)
	if err != nil {
		t.Fatalf("testutil: namespace 0: %v", err)
	}
	rootObj := root.Objects()

	ns := server.NewNodeNameSpace(srv, "http://otfabric.com/conformance")
	obj := ns.Objects()
	rootObj.AddRef(obj, id.HasComponent, true)

	f := &Fixture{Srv: srv, NS: ns, NSIndex: ns.ID()}

	// Helper that adds a variable node under the namespace Objects folder.
	add := func(name string, value any) *ua.NodeID {
		n := ns.AddNewVariableStringNode(name, value)
		obj.AddRef(n, id.HasComponent, true)
		return n.ID()
	}

	f.Bool = add("Bool", true)
	f.SByte = add("SByte", int8(-7))
	f.Byte = add("Byte", byte(200))
	f.Int16 = add("Int16", int16(-1234))
	f.Uint16 = add("Uint16", uint16(4321))
	f.Int32 = add("Int32", int32(42))
	f.Uint32 = add("Uint32", uint32(4242))
	f.Int64 = add("Int64", int64(-9_000_000_000))
	f.Uint64 = add("Uint64", uint64(9_000_000_000))
	f.Float = add("Float", float32(3.5))
	f.Double = add("Double", float64(3.14159))
	f.String = add("String", "hello")
	f.ByteString = add("ByteString", []byte{0x01, 0x02, 0x03})

	f.Int32Array = add("Int32Array", []int32{1, 2, 3, 4, 5})
	f.StringArray = add("StringArray", []string{"a", "b", "c"})

	// Access-controlled nodes.
	f.Writable = f.addAccessNode(t, ns, obj, "Writable",
		ua.AccessLevelTypeCurrentRead|ua.AccessLevelTypeCurrentWrite, int32(10))
	f.ReadOnly = f.addAccessNode(t, ns, obj, "ReadOnly",
		ua.AccessLevelTypeCurrentRead, int32(20))
	f.NoAccess = f.addAccessNode(t, ns, obj, "NoAccess",
		ua.AccessLevelTypeNone, int32(30))

	// Method: Square(int32) -> int32.
	f.MethodObject = obj.ID()
	methodID := f.nodeID("Square")
	methodNode := server.NewFolderNode(methodID, "Square")
	methodNode.SetNodeClass(ua.NodeClassMethod)
	ns.AddNode(methodNode)
	obj.AddRef(methodNode, id.HasComponent, true)
	f.SquareMethod = methodID

	// Expose the method signature so Client.MethodArguments can report it. The
	// Description fields are non-nil on purpose to guard against a past
	// nil-pointer encoding regression.
	addArgumentsProperty(ns, methodNode, f.NSIndex, "Square", "InputArguments", &ua.Argument{
		Name:        "n",
		DataType:    ua.NewNumericNodeID(0, id.Int32),
		ValueRank:   -1,
		Description: ua.NewLocalizedText("value to square"),
	})
	addArgumentsProperty(ns, methodNode, f.NSIndex, "Square", "OutputArguments", &ua.Argument{
		Name:        "result",
		DataType:    ua.NewNumericNodeID(0, id.Int32),
		ValueRank:   -1,
		Description: ua.NewLocalizedText("n squared"),
	})

	srv.RegisterMethod(f.MethodObject, methodID,
		func(_ context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			if len(args) != 1 || args[0] == nil {
				return nil, ua.StatusBadArgumentsMissing
			}
			n, ok := args[0].Value().(int32)
			if !ok {
				return nil, ua.StatusBadInvalidArgument
			}
			return []*ua.Variant{ua.MustVariant(n * n)}, ua.StatusOK
		})

	// Event source object: an object node with the EventNotifier attribute set.
	eventID := f.nodeID("EventSource")
	eventNode := server.NewFolderNode(eventID, "EventSource")
	if err := eventNode.SetAttribute(ua.AttributeIDEventNotifier, server.DataValueFromValue(byte(1))); err != nil {
		t.Fatalf("testutil: set EventNotifier: %v", err)
	}
	ns.AddNode(eventNode)
	obj.AddRef(eventNode, id.HasComponent, true)
	f.EventObject = eventID

	f.addQueryTypes(ns, obj)

	return f
}

// addQueryTypes builds a small custom VariableType hierarchy and typed
// instances so the Query service's type/subtype matching can be exercised in a
// user namespace deterministically (ns=0 has no nodes of these custom types).
func (f *Fixture) addQueryTypes(ns *server.NodeNameSpace, obj *server.Node) {
	// CustomVarType is a subtype of BaseDataVariableType.
	customType := server.NewNode(
		f.nodeID("CustomVarType"),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:  server.DataValueFromValue(uint32(ua.NodeClassVariableType)),
			ua.AttributeIDBrowseName: server.DataValueFromValue(attrs.BrowseName("CustomVarType")),
		},
		nil, nil,
	)
	ns.AddNode(customType)
	if base := f.Srv.Node(ua.NewNumericNodeID(0, id.BaseDataVariableType)); base != nil {
		base.AddRef(customType, id.HasSubtype, true)
	}
	f.CustomVarType = customType.ID()

	// CustomVarSubType is a subtype of CustomVarType.
	customSubType := server.NewNode(
		f.nodeID("CustomVarSubType"),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:  server.DataValueFromValue(uint32(ua.NodeClassVariableType)),
			ua.AttributeIDBrowseName: server.DataValueFromValue(attrs.BrowseName("CustomVarSubType")),
		},
		nil, nil,
	)
	ns.AddNode(customSubType)
	customType.AddRef(customSubType, id.HasSubtype, true)
	f.CustomVarSubType = customSubType.ID()

	f.CustomVarA = f.addTypedVar(ns, obj, "CustomVarA", int32(10), customType)
	f.CustomVarB = f.addTypedVar(ns, obj, "CustomVarB", int32(20), customType)
	f.CustomSubVar = f.addTypedVar(ns, obj, "CustomSubVar", int32(30), customSubType)
}

// addTypedVar creates a variable node with an explicit HasTypeDefinition
// reference to typeNode and links it under obj.
func (f *Fixture) addTypedVar(ns *server.NodeNameSpace, obj *server.Node, name string, value any, typeNode *server.Node) *ua.NodeID {
	n := ns.AddNewVariableStringNode(name, value)
	obj.AddRef(n, id.HasComponent, true)
	n.AddRef(typeNode, id.HasTypeDefinition, true)
	return n.ID()
}

func (f *Fixture) addAccessNode(t *testing.T, ns *server.NodeNameSpace, parent *server.Node, name string, access ua.AccessLevelType, value any) *ua.NodeID {
	t.Helper()
	n := ns.AddNewVariableStringNode(name, value)
	dv := &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(byte(access))}
	if err := n.SetAttribute(ua.AttributeIDAccessLevel, dv); err != nil {
		t.Fatalf("testutil: set AccessLevel on %q: %v", name, err)
	}
	if err := n.SetAttribute(ua.AttributeIDUserAccessLevel, dv); err != nil {
		t.Fatalf("testutil: set UserAccessLevel on %q: %v", name, err)
	}
	parent.AddRef(n, id.HasComponent, true)
	return n.ID()
}

// EmitTestEvent emits an event on the fixture's event source object. The event
// fields must line up with the select clauses requested by the client.
func (f *Fixture) EmitTestEvent(fields ...*ua.Variant) error {
	return f.Srv.EmitEvent(f.EventObject, &ua.EventFieldList{EventFields: fields})
}

// addArgumentsProperty attaches an InputArguments/OutputArguments property
// (a Variable holding an array of Argument) to a method node.
func addArgumentsProperty(ns *server.NodeNameSpace, methodNode *server.Node, nsIdx uint16, methodName, propName string, args ...*ua.Argument) {
	eos := make([]*ua.ExtensionObject, len(args))
	for i, a := range args {
		eos[i] = ua.NewExtensionObject(a)
	}
	value := &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(eos)}
	node := server.NewNode(
		ua.NewStringNodeID(nsIdx, methodName+"."+propName),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:  server.DataValueFromValue(uint32(ua.NodeClassVariable)),
			ua.AttributeIDBrowseName: server.DataValueFromValue(attrs.BrowseName(propName)),
			ua.AttributeIDDataType:   server.DataValueFromValue(ua.NewNumericExpandedNodeID(0, id.Argument)),
		},
		nil,
		func() *ua.DataValue { return value },
	)
	ns.AddNode(node)
	methodNode.AddRef(node, id.HasProperty, true)
}
