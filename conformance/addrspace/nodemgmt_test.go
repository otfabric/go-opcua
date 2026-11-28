// SPDX-License-Identifier: MIT

package addrspace

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestNodeMgmt_AddWriteReadDelete(t *testing.T) {
	c, f, ctx := setupNodeMgmt(t)

	newID := ua.NewStringNodeID(f.NSIndex, "AddedVar")

	addResp, err := c.AddNodes(ctx, &ua.AddNodesRequest{
		NodesToAdd: []*ua.AddNodesItem{{
			ParentNodeID:       ua.NewExpandedNodeID(f.MethodObject, "", 0),
			ReferenceTypeID:    ua.NewNumericNodeID(0, id.HasComponent),
			RequestedNewNodeID: ua.NewExpandedNodeID(newID, "", 0),
			BrowseName:         &ua.QualifiedName{NamespaceIndex: f.NSIndex, Name: "AddedVar"},
			NodeClass:          ua.NodeClassVariable,
			TypeDefinition:     ua.NewNumericExpandedNodeID(0, 0),
		}},
	})
	require.NoError(t, err)
	require.Len(t, addResp.Results, 1)
	require.Equal(t, ua.StatusOK, addResp.Results[0].StatusCode)
	require.NotNil(t, addResp.Results[0].AddedNodeID)

	// The added node must accept a write and read it back.
	status, err := c.WriteValue(ctx, newID, &ua.DataValue{
		EncodingMask: ua.DataValueValue,
		Value:        ua.MustVariant(int32(7)),
	})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, status)

	dv, err := c.ReadValue(ctx, newID)
	require.NoError(t, err)
	require.Equal(t, int32(7), dv.Value.Value())

	// Adding the same node id again must fail.
	dup, err := c.AddNodes(ctx, &ua.AddNodesRequest{
		NodesToAdd: []*ua.AddNodesItem{{
			ParentNodeID:       ua.NewExpandedNodeID(f.MethodObject, "", 0),
			ReferenceTypeID:    ua.NewNumericNodeID(0, id.HasComponent),
			RequestedNewNodeID: ua.NewExpandedNodeID(newID, "", 0),
			BrowseName:         &ua.QualifiedName{NamespaceIndex: f.NSIndex, Name: "AddedVar"},
			NodeClass:          ua.NodeClassVariable,
			TypeDefinition:     ua.NewNumericExpandedNodeID(0, 0),
		}},
	})
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadNodeIDExists, dup.Results[0].StatusCode)

	// Delete the node.
	delResp, err := c.DeleteNodes(ctx, &ua.DeleteNodesRequest{
		NodesToDelete: []*ua.DeleteNodesItem{{NodeID: newID}},
	})
	require.NoError(t, err)
	require.Len(t, delResp.Results, 1)
	require.Equal(t, ua.StatusOK, delResp.Results[0])

	// Reading a deleted node must fail.
	dv, err = c.ReadValue(ctx, newID)
	require.NoError(t, err)
	require.NotEqual(t, ua.StatusOK, dv.Status)
}

func TestNodeMgmt_AddDeleteReferences(t *testing.T) {
	c, f, ctx := setupNodeMgmt(t)

	addRef, err := c.AddReferences(ctx, &ua.AddReferencesRequest{
		ReferencesToAdd: []*ua.AddReferencesItem{{
			SourceNodeID:    f.MethodObject,
			ReferenceTypeID: ua.NewNumericNodeID(0, id.Organizes),
			IsForward:       true,
			TargetNodeID:    ua.NewExpandedNodeID(f.Int32, "", 0),
			TargetNodeClass: ua.NodeClassVariable,
		}},
	})
	require.NoError(t, err)
	require.Len(t, addRef.Results, 1)
	require.Equal(t, ua.StatusOK, addRef.Results[0])

	delRef, err := c.DeleteReferences(ctx, &ua.DeleteReferencesRequest{
		ReferencesToDelete: []*ua.DeleteReferencesItem{{
			SourceNodeID:    f.MethodObject,
			ReferenceTypeID: ua.NewNumericNodeID(0, id.Organizes),
			IsForward:       true,
			TargetNodeID:    ua.NewExpandedNodeID(f.Int32, "", 0),
		}},
	})
	require.NoError(t, err)
	require.Len(t, delRef.Results, 1)
	require.Equal(t, ua.StatusOK, delRef.Results[0])
}

func TestNodeMgmt_Errors(t *testing.T) {
	c, _, ctx := setupNodeMgmt(t)

	// Requesting a node in a namespace that does not exist must be rejected.
	resp, err := c.AddNodes(ctx, &ua.AddNodesRequest{
		NodesToAdd: []*ua.AddNodesItem{{
			ParentNodeID:       ua.NewNumericExpandedNodeID(0, 0),
			ReferenceTypeID:    ua.NewNumericNodeID(0, id.HasComponent),
			RequestedNewNodeID: ua.NewExpandedNodeID(ua.NewStringNodeID(250, "ghost"), "", 0),
			BrowseName:         &ua.QualifiedName{NamespaceIndex: 250, Name: "ghost"},
			NodeClass:          ua.NodeClassVariable,
			TypeDefinition:     ua.NewNumericExpandedNodeID(0, 0),
		}},
	})
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadNodeIDUnknown, resp.Results[0].StatusCode)
}

// TestNodeMgmt_NodeVersion: a node AddNodes adds has a NodeVersion
// Property (WithNodeVersionOnAddNodes), which changes with each
// ModelChangeEvent issued for the node: AddReferences adds a Reference of
// it (Part 3 §9.32.2, §5.5.1).
func TestNodeMgmt_NodeVersion(t *testing.T) {
	c, f, _, _ := setupWith(t, nil,
		server.EnableNodeManagement(),
		server.WithNodeVersionOnAddNodes(true),
		server.WithModelChangeEvents(true),
		server.WithModelDefaultPermissions(true))
	ctx := context.Background()
	newID := ua.NewStringNodeID(f.NSIndex, "Versioned")
	addResp, err := c.AddNodes(ctx, &ua.AddNodesRequest{NodesToAdd: []*ua.AddNodesItem{{
		ParentNodeID:       ua.NewExpandedNodeID(f.MethodObject, "", 0),
		ReferenceTypeID:    ua.NewNumericNodeID(0, id.Organizes),
		RequestedNewNodeID: ua.NewExpandedNodeID(newID, "", 0),
		BrowseName:         &ua.QualifiedName{NamespaceIndex: f.NSIndex, Name: "Versioned"},
		NodeClass:          ua.NodeClassObject,
		TypeDefinition:     ua.NewNumericExpandedNodeID(0, id.FolderType),
	}}})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, addResp.Results[0].StatusCode)

	br, err := c.Browse(ctx, &ua.BrowseRequest{NodesToBrowse: []*ua.BrowseDescription{{
		NodeID: newID, BrowseDirection: ua.BrowseDirectionForward,
		ReferenceTypeID: ua.NewNumericNodeID(0, id.HasProperty), ResultMask: uint32(ua.BrowseResultMaskAll),
	}}})
	require.NoError(t, err)
	require.Len(t, br.Results[0].References, 1)
	require.Equal(t, "NodeVersion", br.Results[0].References[0].BrowseName.Name)
	versionID := br.Results[0].References[0].NodeID.NodeID
	version := func() string {
		t.Helper()
		dv, err := c.ReadValue(ctx, versionID)
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, dv.Status)
		return dv.Value.Value().(string)
	}
	require.Equal(t, "0", version())

	ar, err := c.AddReferences(ctx, &ua.AddReferencesRequest{ReferencesToAdd: []*ua.AddReferencesItem{{
		SourceNodeID: newID, ReferenceTypeID: ua.NewNumericNodeID(0, id.Organizes), IsForward: true,
		TargetNodeID: ua.NewExpandedNodeID(f.MethodObject, "", 0), TargetNodeClass: ua.NodeClassObject,
	}}})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, ar.Results[0])
	require.Equal(t, "1", version())
}
