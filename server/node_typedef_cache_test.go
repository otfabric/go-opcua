// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// DataType falls back to the node's type definition, which is cached because
// AddRef asks for it on every reference it adds. The cache must follow the
// reference list through appends and removals.
func TestNode_TypeDefinitionCacheFollowsReferences(t *testing.T) {
	newNode := func(name string) *Node {
		n := NewFolderNode(ua.NewStringNodeID(1, name), name)
		delete(n.attr, ua.AttributeIDDataType)
		return n
	}
	null := ua.NewTwoByteExpandedNodeID(0)

	n := newNode("n")
	typeA, typeB, other := newNode("TypeA"), newNode("TypeB"), newNode("Other")

	require.Equal(t, null.String(), n.DataType().String(), "no type definition yet")

	// Unrelated and inverse references do not supply a type definition.
	n.AddRef(other, RefType(id.HasComponent), true)
	n.AddRef(typeA, RefType(id.HasTypeDefinition), false)
	require.Equal(t, null.String(), n.DataType().String())

	// The first forward HasTypeDefinition wins, also after the answer "none"
	// has been cached.
	n.AddRef(typeA, RefType(id.HasTypeDefinition), true)
	require.Equal(t, typeA.ID().String(), n.DataType().NodeID.String())
	n.AddRef(typeB, RefType(id.HasTypeDefinition), true)
	require.Equal(t, typeA.ID().String(), n.DataType().NodeID.String(), "a later type definition must not replace the first")

	// Removing the first one promotes the next; removing that one clears it.
	hasTypeDef := ua.NewNumericNodeID(0, id.HasTypeDefinition)
	require.True(t, n.RemoveRef(ua.NewExpandedNodeID(typeA.ID(), "", 0), hasTypeDef, true))
	require.Equal(t, typeB.ID().String(), n.DataType().NodeID.String())
	require.True(t, n.RemoveRef(ua.NewExpandedNodeID(typeB.ID(), "", 0), hasTypeDef, true))
	require.Equal(t, null.String(), n.DataType().String())

	// The reference added to another node carries the target's definition.
	typed := newNode("typed")
	typed.AddRef(typeB, RefType(id.HasTypeDefinition), true)
	parent := newNode("parent")
	parent.AddRef(typed, RefType(id.HasComponent), true)
	refs := parent.refsSnapshot()
	require.Len(t, refs, 1)
	require.Equal(t, typeB.ID().String(), refs[0].TypeDefinition.NodeID.String())
}
