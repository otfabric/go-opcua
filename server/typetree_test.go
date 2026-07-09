// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestNodeNameSpace_Nodes(t *testing.T) {
	srv := newTestServer()
	ns := NewNodeNameSpace(srv, "http://example.com/ns")
	n := ns.AddNewVariableStringNode("temp", float64(21.5))

	nodes := ns.Nodes()
	require.GreaterOrEqual(t, len(nodes), 1)
	var found bool
	for _, node := range nodes {
		if node.ID().String() == n.ID().String() {
			found = true
			break
		}
	}
	require.True(t, found)
}

func TestMapNamespace_Nodes(t *testing.T) {
	srv := newTestServer()
	ns := NewMapNamespace(srv, "map_ns")
	ns.SetValue("a", int32(1))
	ns.SetValue("b", int32(2))

	nodes := ns.Nodes()
	require.Len(t, nodes, 2)
}

func TestIsSubtypeOf(t *testing.T) {
	srv := newTestServer()
	rootNS, err := srv.Namespace(0)
	require.NoError(t, err)

	base := rootNS.Node(ua.NewNumericNodeID(0, id.BaseDataVariableType))
	require.NotNil(t, base)

	custom := NewNode(
		ua.NewStringNodeID(2, "CustomType"),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass: DataValueFromValue(uint32(ua.NodeClassVariableType)),
		},
		nil, nil,
	)
	customNS := NewNodeNameSpace(srv, "http://example.com/custom")
	customNS.AddNode(custom)
	base.AddRef(custom, id.HasSubtype, true)

	require.True(t, srv.isSubtypeOf(custom.ID(), base.ID()))
	require.True(t, srv.isSubtypeOf(custom.ID(), custom.ID()))
	require.False(t, srv.isSubtypeOf(base.ID(), custom.ID()))
}

func TestNodeTypeDefinition(t *testing.T) {
	srv := newTestServer()
	ns := NewNodeNameSpace(srv, "http://example.com/td")
	v := ns.AddNewVariableStringNode("v", int32(1))
	typedef := rootNSNode(srv, id.BaseDataVariableType)
	require.NotNil(t, typedef)
	v.AddRef(typedef, id.HasTypeDefinition, true)

	got := nodeTypeDefinition(v)
	require.NotNil(t, got)
	require.Equal(t, uint32(id.BaseDataVariableType), got.IntID())
}

func rootNSNode(srv *Server, numericID uint32) *Node {
	rootNS, err := srv.Namespace(0)
	if err != nil {
		return nil
	}
	return rootNS.Node(ua.NewNumericNodeID(0, numericID))
}
