// SPDX-License-Identifier: MIT

package server

import (
	"fmt"
	"strings"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
)

// SetMethodArguments gives the Method node n its InputArguments and
// OutputArguments Properties (Part 3 §5.7): Variables of the PropertyType
// with the DataType Argument, ValueRank OneDimension and an array of the
// arguments as value, referenced with HasProperty. Clients read the
// signature of the method from them (Client.MethodArguments) and the Call
// service checks the input arguments against InputArguments.
//
// n must be a Method node added to a namespace (with AddNode); the
// Properties are added to the same namespace. Their NodeIds are string
// NodeIds in the namespace of n: "<id>.InputArguments" and
// "<id>.OutputArguments", where <id> is the identifier of a string NodeId
// and the NodeId without namespace ("i=7001") otherwise. A nil or empty list
// leaves the Property out, as Part 3 §5.7 asks for a method without input or
// output arguments; calling SetMethodArguments again replaces the
// arguments, removing a Property whose list is now empty.
func (n *Node) SetMethodArguments(in, out []*ua.Argument) error {
	if n == nil {
		return fmt.Errorf("server: set method arguments: nil node: %w", ua.StatusBadNodeIDUnknown)
	}
	if n.NodeClass() != ua.NodeClassMethod {
		return fmt.Errorf("server: set method arguments: %s is a %s, not a Method: %w", n.ID(), n.NodeClass(), ua.StatusBadNodeClassInvalid)
	}
	n.mu.RLock()
	ns := n.ns
	n.mu.RUnlock()
	if ns == nil {
		return fmt.Errorf("server: set method arguments: %s is not in a namespace: %w", n.ID(), ua.StatusBadNodeIDUnknown)
	}
	for _, a := range []struct {
		name string
		args []*ua.Argument
	}{{"InputArguments", in}, {"OutputArguments", out}} {
		if err := n.setArgumentsProperty(ns, a.name, a.args); err != nil {
			return err
		}
	}
	return nil
}

// setArgumentsProperty adds, replaces or removes the Property name of the
// method node n.
func (n *Node) setArgumentsProperty(ns NameSpace, name string, args []*ua.Argument) error {
	propID := ua.NewStringNodeID(n.ID().Namespace(), argumentsPropertyIdentifier(n.ID())+"."+name)
	if ns.Node(propID) != nil {
		n.RemoveRef(ua.NewExpandedNodeID(propID, "", 0), ua.NewNumericNodeID(0, id.HasProperty), true)
		_ = ns.DeleteNode(propID) // it was just found
	}
	if len(args) == 0 {
		return nil
	}
	for i, a := range args {
		if a == nil {
			return fmt.Errorf("server: set method arguments: %s of %s: argument %d is nil: %w", name, n.ID(), i, ua.StatusBadInvalidArgument)
		}
	}
	eos := make([]*ua.ExtensionObject, len(args))
	for i, a := range args {
		eos[i] = ua.NewExtensionObject(a)
	}
	value := &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(eos)}
	readOnly := byte(ua.AccessLevelTypeCurrentRead)
	prop := NewNode(propID, Attributes{
		ua.AttributeIDNodeClass: DataValueFromValue(uint32(ua.NodeClassVariable)),
		// The BrowseNames of the Properties are those of Part 3 §5.7, in
		// namespace 0.
		ua.AttributeIDBrowseName:      DataValueFromValue(&ua.QualifiedName{Name: name}),
		ua.AttributeIDDisplayName:     DataValueFromValue(attrs.DisplayName(name, "")),
		ua.AttributeIDDescription:     DataValueFromValue(&ua.LocalizedText{}),
		ua.AttributeIDDataType:        DataValueFromValue(ua.NewNumericExpandedNodeID(0, id.Argument)),
		ua.AttributeIDValueRank:       DataValueFromValue(int32(1)),
		ua.AttributeIDArrayDimensions: DataValueFromValue([]uint32{uint32(len(args))}),
		ua.AttributeIDAccessLevel:     DataValueFromValue(readOnly),
		ua.AttributeIDUserAccessLevel: DataValueFromValue(readOnly),
	}, []*ua.ReferenceDescription{{
		ReferenceTypeID: ua.NewNumericNodeID(0, id.HasTypeDefinition),
		IsForward:       true,
		NodeID:          ua.NewNumericExpandedNodeID(0, id.PropertyType),
		BrowseName:      &ua.QualifiedName{Name: "PropertyType"},
		DisplayName:     attrs.DisplayName("PropertyType", ""),
		NodeClass:       ua.NodeClassVariableType,
		TypeDefinition:  ua.NewTwoByteExpandedNodeID(0),
	}}, func() *ua.DataValue { return value })
	prop = ns.AddNode(prop)
	n.AddRef(prop, RefType(id.HasProperty), true)
	prop.AddRef(n, RefType(id.HasProperty), false)
	return nil
}

// argumentsPropertyIdentifier returns the identifier the NodeIds of the
// argument Properties of the method methodID start with.
func argumentsPropertyIdentifier(methodID *ua.NodeID) string {
	if methodID.Type() == ua.NodeIDTypeString {
		return methodID.StringID()
	}
	s := methodID.String()
	if i := strings.IndexByte(s, ';'); i >= 0 && strings.HasPrefix(s, "ns=") {
		s = s[i+1:]
	}
	return s
}
