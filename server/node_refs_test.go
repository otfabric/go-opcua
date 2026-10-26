// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"sync"
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// countRefs counts the references of n of type rt and direction to target.
func countRefs(n *Node, target *ua.NodeID, rt uint32, forward bool) int {
	c := 0
	for _, r := range n.refsSnapshot() {
		if r != nil && r.IsForward == forward && r.ReferenceTypeID != nil && r.ReferenceTypeID.IntID() == rt &&
			r.NodeID != nil && r.NodeID.NodeID.String() == target.String() {
			c++
		}
	}
	return c
}

// AddRef records a reference on both ends (Part 3 §7.1), once, whichever
// end adds it and however often.
func TestAddRefRecordsBothEnds(t *testing.T) {
	ns := NewNameSpace("urn:test")
	parent := NewFolderNode(ua.NewStringNodeID(1, "Parent"), "Parent")
	child := NewFolderNode(ua.NewStringNodeID(1, "Child"), "Child")
	ns.AddNode(parent)
	ns.AddNode(child)

	parent.AddRef(child, id.Organizes, true)
	require.Equal(t, 1, countRefs(parent, child.ID(), id.Organizes, true))
	require.Equal(t, 1, countRefs(child, parent.ID(), id.Organizes, false))
	inv := child.refsSnapshot()[0]
	require.Equal(t, "Parent", inv.BrowseName.Name)
	require.Equal(t, ua.NodeClassObject, inv.NodeClass)
	require.NotNil(t, inv.TypeDefinition)

	// Again, and from the other end: no duplicates.
	parent.AddRef(child, id.Organizes, true)
	child.AddRef(parent, id.Organizes, false)
	require.Equal(t, 1, countRefs(parent, child.ID(), id.Organizes, true))
	require.Equal(t, 1, countRefs(child, parent.ID(), id.Organizes, false))

	// Inverse first: the forward end is recorded too.
	other := NewFolderNode(ua.NewStringNodeID(1, "Other"), "Other")
	other.AddRef(parent, id.HasComponent, false)
	require.Equal(t, 1, countRefs(parent, other.ID(), id.HasComponent, true))
	parent.AddRef(other, id.HasComponent, true)
	require.Equal(t, 1, countRefs(parent, other.ID(), id.HasComponent, true))
	require.Equal(t, 1, countRefs(other, parent.ID(), id.HasComponent, false))

	// Another reference type between the same nodes is another reference.
	parent.AddRef(child, id.HasComponent, true)
	require.Equal(t, 1, countRefs(child, parent.ID(), id.HasComponent, false))

	// A reference of a node to itself has both directions on the node.
	parent.AddRef(parent, id.HasNotifier, true)
	parent.AddRef(parent, id.HasNotifier, true)
	require.Equal(t, 1, countRefs(parent, parent.ID(), id.HasNotifier, true))
	require.Equal(t, 1, countRefs(parent, parent.ID(), id.HasNotifier, false))
}

// The inverse end of a HasTypeDefinition added from the type side gives the
// instance its type definition.
func TestAddRefInverseTypeDefinition(t *testing.T) {
	typ := NewFolderNode(ua.NewNumericNodeID(1, 9000), "T")
	typ.SetNodeClass(ua.NodeClassObjectType)
	inst := NewFolderNode(ua.NewStringNodeID(1, "I"), "I")
	require.Nil(t, inst.typeDefinition())
	typ.AddRef(inst, id.HasTypeDefinition, false)
	require.Equal(t, typ.ID().String(), inst.typeDefinition().NodeID.String())
}

// Deleting a node removes the inverse ends of its forward references from
// their targets, so the type nodes do not keep references to deleted
// instances; the references of which it is the target stay with their source.
func TestDeleteNodeUnlinksTargets(t *testing.T) {
	s := newTestServer()
	ns := NewNodeNameSpace(s, "urn:test:delete")
	typ := s.Node(ua.NewNumericNodeID(0, id.BaseObjectType))
	require.NotNil(t, typ)
	parent := NewFolderNode(ua.NewStringNodeID(ns.ID(), "Parent"), "Parent")
	child := NewFolderNode(ua.NewStringNodeID(ns.ID(), "Child"), "Child")
	ns.AddNode(parent)
	ns.AddNode(child)
	parent.AddRef(child, id.HasComponent, true)
	child.AddRef(typ, id.HasTypeDefinition, true)
	require.Equal(t, 1, countRefs(typ, child.ID(), id.HasTypeDefinition, false))

	require.Equal(t, ua.StatusGood, ns.DeleteNode(child.ID()))
	require.Zero(t, countRefs(typ, child.ID(), id.HasTypeDefinition, false))
	require.Equal(t, 1, countRefs(parent, child.ID(), id.HasComponent, true), "the parent removes its own reference")
	require.Equal(t, ua.StatusBadNodeIDUnknown, ns.DeleteNode(child.ID()))
}

// AddNodes and AddReferences give the new reference its inverse end: the
// added node is browsable back to its parent.
func TestNodeManagementInverseReferences(t *testing.T) {
	srv := newTestServer()
	ns, obj := addTestNamespace(srv)
	svc := &NodeManagementService{srv: srv}
	nid := ua.NewStringNodeID(ns.ID(), "added")
	resp, err := svc.AddNodes(context.Background(), nil, &ua.AddNodesRequest{
		RequestHeader: reqHeader(),
		NodesToAdd: []*ua.AddNodesItem{{
			ParentNodeID:       ua.NewExpandedNodeID(obj.ID(), "", 0),
			ReferenceTypeID:    ua.NewNumericNodeID(0, id.Organizes),
			RequestedNewNodeID: ua.NewExpandedNodeID(nid, "", 0),
			BrowseName:         &ua.QualifiedName{NamespaceIndex: ns.ID(), Name: "added"},
			NodeClass:          ua.NodeClassObject,
		}},
	}, 1)
	require.NoError(t, err)
	require.Equal(t, ua.StatusGood, resp.(*ua.AddNodesResponse).Results[0].StatusCode)
	added := ns.Node(nid)
	require.NotNil(t, added)
	require.Equal(t, 1, countRefs(added, obj.ID(), id.Organizes, false))

	view := &ViewService{srv: srv}
	br, err := view.Browse(context.Background(), nil, &ua.BrowseRequest{
		RequestHeader: reqHeader(),
		NodesToBrowse: []*ua.BrowseDescription{{
			NodeID: nid, BrowseDirection: ua.BrowseDirectionInverse,
			ReferenceTypeID: ua.NewNumericNodeID(0, id.HierarchicalReferences), IncludeSubtypes: true,
			ResultMask: uint32(ua.BrowseResultMaskAll),
		}},
	}, 2)
	require.NoError(t, err)
	res := br.(*ua.BrowseResponse).Results[0]
	require.Equal(t, ua.StatusGood, res.StatusCode)
	require.Len(t, res.References, 1)
	require.Equal(t, obj.ID().String(), res.References[0].NodeID.NodeID.String())
	require.False(t, res.References[0].IsForward)
}

// Concurrent AddRef calls between the same nodes are race free.
func TestAddRefConcurrent(t *testing.T) {
	a := NewFolderNode(ua.NewStringNodeID(1, "A"), "A")
	nodes := make([]*Node, 16)
	for i := range nodes {
		nodes[i] = NewFolderNode(ua.NewNumericNodeID(1, uint32(100+i)), "N")
	}
	var wg sync.WaitGroup
	for _, n := range nodes {
		wg.Add(2)
		go func() { defer wg.Done(); a.AddRef(n, id.Organizes, true) }()
		go func() { defer wg.Done(); n.AddRef(a, id.HasComponent, false) }()
	}
	wg.Wait()
	for _, n := range nodes {
		require.Equal(t, 1, countRefs(a, n.ID(), id.Organizes, true))
		require.Equal(t, 1, countRefs(n, a.ID(), id.Organizes, false))
		require.Equal(t, 1, countRefs(a, n.ID(), id.HasComponent, true))
	}
}
