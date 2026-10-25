// SPDX-License-Identifier: MIT

package server

import (
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func attrValue(t *testing.T, n *Node, a ua.AttributeID) any {
	t.Helper()
	v, err := n.Attribute(a)
	require.NoError(t, err, a)
	return v.Value.Value.Value()
}

func TestNewVariableNode_Attributes(t *testing.T) {
	nid := ua.NewNumericNodeID(3, 1001)
	cases := []struct {
		name  string
		value any
		dt    uint32
		rank  int32
		dims  []uint32
	}{
		{"double", 1.5, id.Double, -1, nil},
		{"float", float32(1), id.Float, -1, nil},
		{"int", 7, id.Int32, -1, nil},
		{"int64", int64(7), id.Int64, -1, nil},
		{"bool", true, id.Boolean, -1, nil},
		{"string", "x", id.String, -1, nil},
		{"bytes", []byte{1}, id.ByteString, -1, nil},
		{"time", time.Now(), id.DateTime, -1, nil},
		{"nodeid", ua.NewNumericNodeID(0, 1), id.NodeID, -1, nil},
		{"localizedtext", ua.NewLocalizedText("x"), id.LocalizedText, -1, nil},
		{"doubles", []float64{1, 2}, id.Double, 1, []uint32{0}},
		{"strings", []string{"a"}, id.String, 1, []uint32{0}},
		{"variant", ua.MustVariant(uint16(1)), id.UInt16, -1, nil},
		{"datavalue", DataValueFromValue(int16(1)), id.Int16, -1, nil},
		{"datavalue struct", ua.DataValue{Value: ua.MustVariant(uint8(1))}, id.Byte, -1, nil},
		{"variant struct", *ua.MustVariant(int8(1)), id.SByte, -1, nil},
		{"nil", nil, id.BaseDataType, -2, nil},
		{"nil datavalue", (*ua.DataValue)(nil), id.BaseDataType, -2, nil},
		{"unsupported", struct{}{}, id.BaseDataType, -2, nil},
		{"argument", ua.NewExtensionObject(&ua.Argument{Name: "a"}), id.Argument, -1, nil},
		{"arguments", []*ua.ExtensionObject{ua.NewExtensionObject(&ua.Argument{Name: "a"})}, id.Argument, 1, []uint32{0}},
		{"structure", &ua.ExtensionObject{TypeID: ua.NewNumericExpandedNodeID(2, 5001), Value: []byte{}}, id.Structure, -1, nil},
		{"structure string encoding", &ua.ExtensionObject{TypeID: ua.NewStringExpandedNodeID(0, "x"), Value: []byte{}}, id.Structure, -1, nil},
		{"structure no encoding", &ua.ExtensionObject{}, id.Structure, -1, nil},
		{"structure unknown encoding", &ua.ExtensionObject{TypeID: ua.NewNumericExpandedNodeID(0, id.Double), Value: []byte{}}, id.Structure, -1, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := NewVariableNode(nid, "Var", c.value)
			require.Equal(t, &ua.QualifiedName{NamespaceIndex: 3, Name: "Var"}, attrValue(t, n, ua.AttributeIDBrowseName))
			require.Equal(t, ua.NewNumericExpandedNodeID(0, c.dt).NodeID.String(), n.DataType().NodeID.String())
			require.Equal(t, c.rank, attrValue(t, n, ua.AttributeIDValueRank))
			if c.dims == nil {
				_, err := n.Attribute(ua.AttributeIDArrayDimensions)
				require.Error(t, err)
			} else {
				require.Equal(t, c.dims, attrValue(t, n, ua.AttributeIDArrayDimensions))
			}
		})
	}
}

func TestNewVariableNode_Func(t *testing.T) {
	for _, f := range []any{
		func() *ua.DataValue { return DataValueFromValue(2.5) },
		ValueFunc(func() *ua.DataValue { return DataValueFromValue(2.5) }),
	} {
		n := NewVariableNode(ua.NewStringNodeID(2, "f"), "f", f)
		require.Equal(t, 2.5, n.Value().Value.Value())
		require.Equal(t, int32(-2), attrValue(t, n, ua.AttributeIDValueRank))
		// The DataType is worked out from the value when it is read.
		require.Equal(t, ua.NewNumericNodeID(0, id.Double), variableDataType(n, n.attr[ua.AttributeIDDataType]))
	}
	// A function returning nothing reads as BaseDataType.
	n := NewVariableNode(ua.NewStringNodeID(2, "g"), "g", func() *ua.DataValue { return nil })
	require.Equal(t, ua.NewNumericNodeID(0, id.BaseDataType), variableDataType(n, n.attr[ua.AttributeIDDataType]))
	n = NewVariableNode(ua.NewStringNodeID(2, "v"), "v", func() *ua.DataValue { return DataValueFromValue(ua.MustVariant(ua.MustVariant(1.0))) })
	require.Equal(t, ua.NewNumericNodeID(0, id.BaseDataType), variableDataType(n, n.attr[ua.AttributeIDDataType]))
}

// TestNewVariableNode_ExplicitAttributes: attributes a caller sets after
// construction win, as before.
func TestNewVariableNode_ExplicitAttributes(t *testing.T) {
	n := NewVariableNode(ua.NewNumericNodeID(2, 1), "x", 1.0)
	require.NoError(t, n.SetAttribute(ua.AttributeIDDataType, DataValueFromValue(ua.NewNumericExpandedNodeID(0, id.Number))))
	require.NoError(t, n.SetAttribute(ua.AttributeIDBrowseName, DataValueFromValue(&ua.QualifiedName{NamespaceIndex: 5, Name: "y"})))
	require.Equal(t, uint32(id.Number), n.DataType().NodeID.IntID())
	require.Equal(t, &ua.QualifiedName{NamespaceIndex: 5, Name: "y"}, n.BrowseName())
}

func TestNewFolderNode_BrowseNameNamespace(t *testing.T) {
	require.Equal(t, &ua.QualifiedName{NamespaceIndex: 4, Name: "F"}, NewFolderNode(ua.NewStringNodeID(4, "F"), "F").BrowseName())
	require.Equal(t, &ua.QualifiedName{Name: "F"}, browseNameIn(nil, "F"))
}

func TestVariantValueRank_Matrix(t *testing.T) {
	v := ua.MustVariant([][]int32{{1, 2}, {3, 4}})
	rank, dims := variantValueRank(v)
	require.Equal(t, int32(2), rank)
	require.Equal(t, []uint32{0, 0}, dims)
	require.Equal(t, ua.NewNumericNodeID(0, id.BaseDataType), variantDataType(ua.MustVariant(nil)))
	require.Equal(t, ua.NewNumericNodeID(0, id.Structure), extensionObjectDataType([]*ua.ExtensionObject{}))
}
