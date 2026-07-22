// SPDX-License-Identifier: MIT

// Package customtypes provides NodeSet2-style fixture types for WP5A custom
// DataType tests.
//
// Each Go struct is registered with ua.RegisterExtensionObject so that the
// go-opcua codec can encode and decode it as an ExtensionObject.  Registration
// happens automatically via init(); consumers need only import this package
// (or depend on a package that does) before connecting to a server.
//
// Fixture types (registered in namespace 2):
//
//   - MyEnum       – int32 enumeration: Off=0, Idle=1, Running=2
//   - FlatStruct   – flat structure with float32, int32, and string fields
//   - ArrayStruct  – structure with a string and an []int32 Values field
//   - NestedStruct – structure embedding a FlatStruct
//
// Call AddNodes to populate a server namespace with corresponding writable
// Variable nodes, and AddMethodNode to add a method exercising the codec
// through the method call path.
package customtypes

import (
	"context"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
)

// Numeric NodeID constants for the fixture DataTypes, all in namespace 2.
const (
	MyEnumDataTypeID       = uint32(3001)
	FlatStructDataTypeID   = uint32(3002)
	ArrayStructDataTypeID  = uint32(3003)
	NestedStructDataTypeID = uint32(3004)
)

// MyEnum is an int32 enumeration.
type MyEnum int32

const (
	MyEnumOff     MyEnum = 0
	MyEnumIdle    MyEnum = 1
	MyEnumRunning MyEnum = 2
)

// FlatStruct is a flat OPC UA Structure with three scalar fields.
type FlatStruct struct {
	Temperature float32
	Pressure    int32
	Label       string
}

// ArrayStruct is an OPC UA Structure whose Values field is an int32 array.
type ArrayStruct struct {
	Name   string
	Values []int32
}

// NestedStruct embeds a FlatStruct as a nested OPC UA Structure.
type NestedStruct struct {
	ID     int32
	Inner  FlatStruct
	Active bool
}

func ns2ID(n uint32) *ua.NodeID { return ua.NewNumericNodeID(2, n) }

func init() {
	ua.RegisterExtensionObject(ns2ID(MyEnumDataTypeID), new(MyEnum))
	ua.RegisterExtensionObject(ns2ID(FlatStructDataTypeID), new(FlatStruct))
	ua.RegisterExtensionObject(ns2ID(ArrayStructDataTypeID), new(ArrayStruct))
	ua.RegisterExtensionObject(ns2ID(NestedStructDataTypeID), new(NestedStruct))
}

// AddNodes adds one writable Variable node per custom type under parent and
// returns a map from type-name key to node ID.
func AddNodes(ns *server.NodeNameSpace, parent *server.Node) map[string]*ua.NodeID {
	nsIdx := ns.ID()

	add := func(name string, initial interface{}) *ua.NodeID {
		nodeID := ua.NewStringNodeID(nsIdx, name)
		eo := ua.NewExtensionObject(initial)
		// Use AddNewVariableStringNode's underlying NewVariableNode pattern:
		// store the initial value; subsequent writes replace n.val via SetAttribute.
		n := server.NewNode(
			nodeID,
			map[ua.AttributeID]*ua.DataValue{
				ua.AttributeIDNodeClass:   server.DataValueFromValue(uint32(ua.NodeClassVariable)),
				ua.AttributeIDBrowseName:  server.DataValueFromValue(attrs.BrowseName(name)),
				ua.AttributeIDDisplayName: server.DataValueFromValue(attrs.DisplayName(name, "en")),
				ua.AttributeIDValueRank:   server.DataValueFromValue(int32(-1)),
				// AccessLevel intentionally omitted → defaults to unrestricted (read + write).
			},
			nil,
			func() *ua.DataValue {
				return &ua.DataValue{
					EncodingMask: ua.DataValueValue,
					Value:        ua.MustVariant(eo),
				}
			},
		)
		ns.AddNode(n)
		parent.AddRef(n, id.HasComponent, true)
		return nodeID
	}

	enumVal := MyEnumIdle
	return map[string]*ua.NodeID{
		"MyEnum":       add("CustomTypes.MyEnum", &enumVal),
		"FlatStruct":   add("CustomTypes.FlatStruct", &FlatStruct{Temperature: 23.5, Pressure: 101325, Label: "ambient"}),
		"ArrayStruct":  add("CustomTypes.ArrayStruct", &ArrayStruct{Name: "readings", Values: []int32{10, 20, 30}}),
		"NestedStruct": add("CustomTypes.NestedStruct", &NestedStruct{ID: 1, Inner: FlatStruct{Temperature: 36.6, Pressure: 760, Label: "body"}, Active: true}),
	}
}

// AddMethodNode registers a method that accepts a FlatStruct argument and
// returns an ArrayStruct, exercising custom type encoding through the method
// call path. The method is added under methodParent.
func AddMethodNode(srv *server.Server, ns *server.NodeNameSpace, methodParent *server.Node) *ua.NodeID {
	nsIdx := ns.ID()
	methodID := ua.NewStringNodeID(nsIdx, "CustomTypes.ProcessFlat")
	methodNode := server.NewFolderNode(methodID, "ProcessFlat")
	methodNode.SetNodeClass(ua.NodeClassMethod)
	ns.AddNode(methodNode)
	methodParent.AddRef(methodNode, id.HasComponent, true)

	addArgProp(ns, methodNode, nsIdx, "CustomTypes.ProcessFlat", "InputArguments",
		&ua.Argument{
			Name:        "input",
			DataType:    ua.NewNumericNodeID(2, FlatStructDataTypeID),
			ValueRank:   -1,
			Description: ua.NewLocalizedText("FlatStruct to process"),
		})
	addArgProp(ns, methodNode, nsIdx, "CustomTypes.ProcessFlat", "OutputArguments",
		&ua.Argument{
			Name:        "result",
			DataType:    ua.NewNumericNodeID(2, ArrayStructDataTypeID),
			ValueRank:   -1,
			Description: ua.NewLocalizedText("ArrayStruct derived from input"),
		})

	srv.RegisterMethod(methodParent.ID(), methodID,
		func(_ context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			if len(args) != 1 || args[0] == nil {
				return nil, ua.StatusBadArgumentsMissing
			}
			eo, ok := args[0].Value().(*ua.ExtensionObject)
			if !ok {
				return nil, ua.StatusBadInvalidArgument
			}
			input, ok := eo.Value.(*FlatStruct)
			if !ok {
				return nil, ua.StatusBadInvalidArgument
			}
			result := &ArrayStruct{
				Name:   input.Label,
				Values: []int32{input.Pressure, int32(input.Temperature * 10)},
			}
			return []*ua.Variant{ua.MustVariant(ua.NewExtensionObject(result))}, ua.StatusOK
		})

	return methodID
}

func addArgProp(ns *server.NodeNameSpace, methodNode *server.Node, nsIdx uint16, methodName, propName string, args ...*ua.Argument) {
	if len(args) == 0 {
		return
	}
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
