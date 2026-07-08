// SPDX-License-Identifier: MIT

package conformance

import (
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestView_BrowseRaw(t *testing.T) {
	c, f, ctx := setup(t)

	resp, err := c.Browse(ctx, &ua.BrowseRequest{
		NodesToBrowse: []*ua.BrowseDescription{
			{
				NodeID:          f.MethodObject, // fixture Objects folder
				BrowseDirection: ua.BrowseDirectionForward,
				ReferenceTypeID: ua.NewNumericNodeID(0, id.HierarchicalReferences),
				IncludeSubtypes: true,
				ResultMask:      uint32(ua.BrowseResultMaskAll),
				NodeClassMask:   uint32(ua.NodeClassAll),
			},
		},
		RequestedMaxReferencesPerNode: 1000,
	})
	require.NoError(t, err)
	require.Len(t, resp.Results, 1)
	require.Equal(t, ua.StatusOK, resp.Results[0].StatusCode)
	require.NotEmpty(t, resp.Results[0].References, "fixture object folder should have children")
}

func TestView_BrowseAll(t *testing.T) {
	c, f, ctx := setup(t)

	refs, err := c.BrowseAll(ctx, f.MethodObject)
	require.NoError(t, err)
	require.NotEmpty(t, refs)

	names := map[string]bool{}
	for _, r := range refs {
		if r.BrowseName != nil {
			names[r.BrowseName.Name] = true
		}
	}
	require.True(t, names["Int32"], "expected Int32 child, got %v", names)
	require.True(t, names["Square"], "expected Square method child, got %v", names)
}

func TestView_NodeChildrenAndReferences(t *testing.T) {
	c, f, ctx := setup(t)

	n := c.Node(f.MethodObject)

	children, err := n.Children(ctx, id.HierarchicalReferences, ua.NodeClassAll)
	require.NoError(t, err)
	require.NotEmpty(t, children)

	refs, err := n.References(ctx, id.HierarchicalReferences, ua.BrowseDirectionForward, ua.NodeClassAll, true)
	require.NoError(t, err)
	require.NotEmpty(t, refs)
}

func TestView_TranslateBrowsePath(t *testing.T) {
	c, f, ctx := setup(t)

	// Browse names are registered in namespace 0 even for custom-namespace nodes.
	n := c.Node(f.MethodObject)
	target, err := n.TranslateBrowsePathInNamespaceToNodeID(ctx, 0, "Int32")
	require.NoError(t, err)
	require.NotNil(t, target)
	require.Equal(t, f.Int32.String(), target.String())
}

func TestView_NodeFromPath(t *testing.T) {
	c, _, ctx := setup(t)

	// "Server" is a well-known child of the Objects folder in namespace 0.
	node, err := c.NodeFromPath(ctx, "Server")
	require.NoError(t, err)
	require.NotNil(t, node)
	require.NotNil(t, node.ID)
}

func TestView_BrowseNext(t *testing.T) {
	c, f, ctx := setup(t)

	// Force the server to page results by requesting a single reference per node.
	resp, err := c.Browse(ctx, &ua.BrowseRequest{
		NodesToBrowse: []*ua.BrowseDescription{{
			NodeID:          f.MethodObject,
			BrowseDirection: ua.BrowseDirectionForward,
			ReferenceTypeID: ua.NewNumericNodeID(0, id.HierarchicalReferences),
			IncludeSubtypes: true,
			ResultMask:      uint32(ua.BrowseResultMaskAll),
			NodeClassMask:   uint32(ua.NodeClassAll),
		}},
		RequestedMaxReferencesPerNode: 1,
	})
	require.NoError(t, err)
	require.Len(t, resp.Results, 1)

	cp := resp.Results[0].ContinuationPoint
	if len(cp) == 0 {
		t.Skip("server did not return a continuation point; BrowseNext not exercised")
	}

	next, err := c.BrowseNext(ctx, &ua.BrowseNextRequest{
		ContinuationPoints:        [][]byte{cp},
		ReleaseContinuationPoints: false,
	})
	require.NoError(t, err)
	require.Len(t, next.Results, 1)
	require.Equal(t, ua.StatusOK, next.Results[0].StatusCode)
}

func TestView_RegisterUnregisterNodes(t *testing.T) {
	c, f, ctx := setup(t)

	reg, err := c.RegisterNodes(ctx, &ua.RegisterNodesRequest{
		NodesToRegister: []*ua.NodeID{f.Int32, f.Double},
	})
	require.NoError(t, err)
	require.Len(t, reg.RegisteredNodeIDs, 2)

	// A registered node id must still be readable.
	dv, err := c.ReadValue(ctx, reg.RegisteredNodeIDs[0])
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, dv.Status)

	_, err = c.UnregisterNodes(ctx, &ua.UnregisterNodesRequest{
		NodesToUnregister: reg.RegisteredNodeIDs,
	})
	require.NoError(t, err)
}
