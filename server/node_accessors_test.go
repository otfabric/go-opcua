// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func nullDataValue() *ua.DataValue {
	return &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(nil)}
}

func TestNode_NullAttributesFallBackToEmptyValues(t *testing.T) {
	n := NewNode(ua.NewNumericNodeID(1, 1), Attributes{
		ua.AttributeIDBrowseName:  nullDataValue(),
		ua.AttributeIDDisplayName: nullDataValue(),
		ua.AttributeIDDescription: nullDataValue(),
		ua.AttributeIDNodeClass:   nullDataValue(),
	}, nil, nil)

	assert.Equal(t, &ua.QualifiedName{}, n.BrowseName())
	assert.Equal(t, "", n.DisplayName().Text)
	assert.Equal(t, &ua.LocalizedText{}, n.Description())
	assert.Equal(t, ua.NodeClassObject, n.NodeClass(), "a null node class defaults to Object")

	// A node class stored with an unexpected Go type also defaults to Object.
	n = NewNode(ua.NewNumericNodeID(1, 2), Attributes{ua.AttributeIDNodeClass: DataValueFromValue("Variable")}, nil, nil)
	assert.Equal(t, ua.NodeClassObject, n.NodeClass())

	// Both wire representations of the enumeration are understood.
	n.SetNodeClass(ua.NodeClassMethod)
	assert.Equal(t, ua.NodeClassMethod, n.NodeClass())
	n = NewNode(ua.NewNumericNodeID(1, 3), Attributes{ua.AttributeIDNodeClass: DataValueFromValue(int32(ua.NodeClassView))}, nil, nil)
	assert.Equal(t, ua.NodeClassView, n.NodeClass())
}

func TestNode_DisplayNameDefaultsToBrowseName(t *testing.T) {
	n := NewNode(ua.NewNumericNodeID(1, 1), Attributes{
		ua.AttributeIDBrowseName: DataValueFromValue(&ua.QualifiedName{NamespaceIndex: 1, Name: "Pump"}),
	}, nil, nil)
	assert.Equal(t, "Pump", n.DisplayName().Text)
	assert.Equal(t, "", n.Description().Text)

	n.SetDescription("a pump", "en")
	d := n.Description()
	assert.Equal(t, "a pump", d.Text)
	assert.Equal(t, "en", d.Locale)
	assert.NotZero(t, d.EncodingMask&ua.LocalizedTextText, "the text must be flagged for encoding")
}

func TestNode_DataType(t *testing.T) {
	var missing *Node
	assert.Equal(t, ua.NewTwoByteExpandedNodeID(0), missing.DataType())

	typeID := ua.NewNumericNodeID(0, id.BaseDataVariableType)
	n := NewNode(ua.NewNumericNodeID(1, 1), nil, References{
		{IsForward: true, NodeID: ua.NewExpandedNodeID(ua.NewNumericNodeID(0, 1), "", 0)}, // no reference type
		{IsForward: false, ReferenceTypeID: ua.NewNumericNodeID(0, id.HasTypeDefinition), NodeID: ua.NewExpandedNodeID(ua.NewNumericNodeID(0, 2), "", 0)},
		{IsForward: true, ReferenceTypeID: ua.NewNumericNodeID(0, id.HasComponent), NodeID: ua.NewExpandedNodeID(ua.NewNumericNodeID(0, 3), "", 0)},
		{IsForward: true, ReferenceTypeID: ua.NewNumericNodeID(0, id.HasTypeDefinition), NodeID: ua.NewExpandedNodeID(typeID, "", 0)},
	}, nil)
	// Without a DataType attribute the forward HasTypeDefinition target is used.
	assert.Equal(t, typeID.String(), n.DataType().NodeID.String())

	// An explicit DataType attribute wins.
	explicit := ua.NewNumericExpandedNodeID(0, id.Int32)
	require.NoError(t, n.SetAttribute(ua.AttributeIDDataType, DataValueFromValue(explicit)))
	assert.Equal(t, explicit, n.DataType())

	// Neither attribute nor type definition: the null node id.
	assert.Equal(t, ua.NewTwoByteExpandedNodeID(0), NewNode(ua.NewNumericNodeID(1, 2), nil, nil, nil).DataType())
}

func TestNode_ValueAttribute(t *testing.T) {
	// A node without a value function has no Value attribute.
	n := NewNode(ua.NewNumericNodeID(1, 1), nil, nil, nil)
	require.Nil(t, n.Value())
	_, err := n.Attribute(ua.AttributeIDValue)
	require.Equal(t, ua.StatusBadAttributeIDInvalid, err)

	// A value function that yields nothing is reported the same way.
	n = NewNode(ua.NewNumericNodeID(1, 2), nil, nil, func() *ua.DataValue { return nil })
	_, err = n.Attribute(ua.AttributeIDValue)
	require.Equal(t, ua.StatusBadAttributeIDInvalid, err)

	_, err = n.Attribute(ua.AttributeIDInverseName)
	require.Equal(t, ua.StatusBadAttributeIDInvalid, err)
	_, err = n.Attribute(ua.AttributeIDRolePermissions)
	require.Equal(t, ua.StatusBadAttributeIDInvalid, err, "no role permissions configured")
}

func TestNewVariableNode_ValueSources(t *testing.T) {
	nid := ua.NewNumericNodeID(1, 1)

	static := NewVariableNode(nid, "static", int32(5))
	require.Equal(t, int32(5), static.Value().Value.Value())
	require.Equal(t, ua.NodeClassVariable, static.NodeClass())
	require.Equal(t, "static", static.BrowseName().Name)

	calls := 0
	plain := NewVariableNode(nid, "plain", func() *ua.DataValue {
		calls++
		return DataValueFromValue(int32(calls))
	})
	require.Equal(t, int32(1), plain.Value().Value.Value())
	require.Equal(t, int32(2), plain.Value().Value.Value(), "the function is evaluated on every read")

	// The named ValueFunc type is accepted as a dynamic source as well.
	typed := NewVariableNode(nid, "typed", ValueFunc(func() *ua.DataValue { return DataValueFromValue("dynamic") }))
	require.Equal(t, "dynamic", typed.Value().Value.Value())
	av, err := typed.Attribute(ua.AttributeIDValue)
	require.NoError(t, err)
	require.Equal(t, "dynamic", av.Value.Value.Value())
}

func TestNode_AccessLevels(t *testing.T) {
	mk := func(attrs Attributes) *Node {
		return NewNode(ua.NewNumericNodeID(1, 1), attrs, nil, func() *ua.DataValue { return DataValueFromValue(int32(1)) })
	}
	rd, wr := ua.AccessLevelTypeCurrentRead, ua.AccessLevelTypeCurrentWrite
	newVal := &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int32(2))}

	t.Run("no access attributes means full access", func(t *testing.T) {
		n := mk(nil)
		assert.True(t, n.Access(rd))
		assert.True(t, n.Access(wr))
		require.NoError(t, n.SetAttribute(ua.AttributeIDValue, newVal))
		assert.Equal(t, int32(2), n.Value().Value.Value())
	})

	t.Run("read only access level", func(t *testing.T) {
		n := mk(Attributes{ua.AttributeIDAccessLevel: DataValueFromValue(byte(rd))})
		assert.True(t, n.Access(rd))
		assert.False(t, n.Access(wr))
		require.Equal(t, ua.StatusBadUserAccessDenied, n.SetAttribute(ua.AttributeIDValue, newVal))
		assert.Equal(t, int32(1), n.Value().Value.Value(), "a denied write must not change the value")
	})

	t.Run("user access level narrows access level", func(t *testing.T) {
		n := mk(Attributes{
			ua.AttributeIDAccessLevel:     DataValueFromValue(byte(rd | wr)),
			ua.AttributeIDUserAccessLevel: DataValueFromValue(byte(rd)),
		})
		assert.True(t, n.Access(rd))
		assert.False(t, n.Access(wr))
	})

	t.Run("access level of the wrong type denies access", func(t *testing.T) {
		n := mk(Attributes{ua.AttributeIDAccessLevel: DataValueFromValue(uint32(rd | wr))})
		assert.False(t, n.Access(rd))
		assert.False(t, n.Access(wr))
		n = mk(Attributes{ua.AttributeIDUserAccessLevel: DataValueFromValue(uint32(rd | wr))})
		assert.False(t, n.Access(rd))
	})

	t.Run("type changing write is rejected", func(t *testing.T) {
		n := mk(nil)
		err := n.SetAttribute(ua.AttributeIDValue, &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant("text")})
		require.Equal(t, ua.StatusBadTypeMismatch, err)
		assert.Equal(t, int32(1), n.Value().Value.Value())
	})
}

func TestNode_RemoveRef(t *testing.T) {
	target := ua.NewNumericNodeID(1, 9)
	hasComponent := ua.NewNumericNodeID(0, id.HasComponent)
	n := NewNode(ua.NewNumericNodeID(1, 1), nil, References{
		{IsForward: true, ReferenceTypeID: hasComponent}, // reference without a target
	}, nil)
	n.AddRef(NewNode(target, nil, nil, nil), id.HasComponent, true)
	n.AddRef(NewNode(ua.NewNumericNodeID(1, 10), nil, nil, nil), id.HasComponent, true)

	exp := ua.NewExpandedNodeID(target, "", 0)
	require.False(t, n.RemoveRef(nil, hasComponent, true), "nil target matches nothing")
	require.False(t, n.RemoveRef(exp, hasComponent, false), "direction must match")
	require.False(t, n.RemoveRef(exp, ua.NewNumericNodeID(0, id.Organizes), true), "reference type must match")
	require.Len(t, n.refsSnapshot(), 3)

	require.True(t, n.RemoveRef(exp, hasComponent, true))
	require.Len(t, n.refsSnapshot(), 2)
	require.False(t, hasReference(n, target, id.HasComponent, true))
	require.True(t, hasReference(n, ua.NewNumericNodeID(1, 10), id.HasComponent, true), "other references are kept")
	require.False(t, n.RemoveRef(exp, hasComponent, true), "already removed")
}
