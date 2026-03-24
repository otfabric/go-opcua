package server

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNodeManagementService_AddNodes(t *testing.T) {
	srv := newTestServer()
	ns, obj := addTestNamespace(srv)
	svc := &NodeManagementService{srv: srv}

	t.Run("add a new variable node", func(t *testing.T) {
		newNodeID := ua.NewStringNodeID(ns.ID(), "dynamic_var_1")
		req := &ua.AddNodesRequest{
			RequestHeader: reqHeader(),
			NodesToAdd: []*ua.AddNodesItem{{
				ParentNodeID:       ua.NewExpandedNodeID(obj.ID(), "", 0),
				ReferenceTypeID:    ua.NewNumericNodeID(0, id.HasComponent),
				RequestedNewNodeID: ua.NewExpandedNodeID(newNodeID, "", 0),
				BrowseName:         &ua.QualifiedName{NamespaceIndex: ns.ID(), Name: "dynamic_var_1"},
				NodeClass:          ua.NodeClassVariable,
				TypeDefinition:     ua.NewExpandedNodeID(nil, "", 0),
			}},
		}
		resp, err := svc.AddNodes(context.Background(), nil, req, 1)
		require.NoError(t, err)

		addResp := resp.(*ua.AddNodesResponse)
		require.Len(t, addResp.Results, 1)
		assert.Equal(t, ua.StatusGood, addResp.Results[0].StatusCode)
		assert.Equal(t, newNodeID.String(), addResp.Results[0].AddedNodeID.String())

		// Verify node exists.
		n := ns.Node(newNodeID)
		assert.NotNil(t, n, "node should exist in namespace after AddNodes")
	})

	t.Run("add duplicate node returns error", func(t *testing.T) {
		existingID := ua.NewStringNodeID(ns.ID(), "rw_int32")
		req := &ua.AddNodesRequest{
			RequestHeader: reqHeader(),
			NodesToAdd: []*ua.AddNodesItem{{
				RequestedNewNodeID: ua.NewExpandedNodeID(existingID, "", 0),
				BrowseName:         &ua.QualifiedName{NamespaceIndex: ns.ID(), Name: "dup"},
				NodeClass:          ua.NodeClassVariable,
			}},
		}
		resp, err := svc.AddNodes(context.Background(), nil, req, 2)
		require.NoError(t, err)

		addResp := resp.(*ua.AddNodesResponse)
		require.Len(t, addResp.Results, 1)
		assert.Equal(t, ua.StatusBadNodeIDExists, addResp.Results[0].StatusCode)
	})

	t.Run("add node with nil node ID returns error", func(t *testing.T) {
		req := &ua.AddNodesRequest{
			RequestHeader: reqHeader(),
			NodesToAdd: []*ua.AddNodesItem{{
				RequestedNewNodeID: nil,
				BrowseName:         &ua.QualifiedName{Name: "bad"},
				NodeClass:          ua.NodeClassVariable,
			}},
		}
		resp, err := svc.AddNodes(context.Background(), nil, req, 3)
		require.NoError(t, err)

		addResp := resp.(*ua.AddNodesResponse)
		require.Len(t, addResp.Results, 1)
		assert.Equal(t, ua.StatusBadNodeIDInvalid, addResp.Results[0].StatusCode)
	})

	t.Run("wrong request type", func(t *testing.T) {
		_, err := svc.AddNodes(context.Background(), nil, &ua.ReadRequest{RequestHeader: reqHeader()}, 1)
		assert.Error(t, err)
	})
}

func TestNodeManagementService_DeleteNodes(t *testing.T) {
	srv := newTestServer()
	ns, _ := addTestNamespace(srv)
	svc := &NodeManagementService{srv: srv}

	t.Run("delete existing node", func(t *testing.T) {
		// Verify node exists before deletion.
		nodeID := ua.NewStringNodeID(ns.ID(), "rw_int32")
		n := ns.Node(nodeID)
		require.NotNil(t, n, "node should exist before delete")

		req := &ua.DeleteNodesRequest{
			RequestHeader: reqHeader(),
			NodesToDelete: []*ua.DeleteNodesItem{{
				NodeID:                 nodeID,
				DeleteTargetReferences: true,
			}},
		}
		resp, err := svc.DeleteNodes(context.Background(), nil, req, 1)
		require.NoError(t, err)

		delResp := resp.(*ua.DeleteNodesResponse)
		require.Len(t, delResp.Results, 1)
		assert.Equal(t, ua.StatusGood, delResp.Results[0])

		// Verify node no longer exists.
		n = ns.Node(nodeID)
		assert.Nil(t, n, "node should be gone after delete")
	})

	t.Run("delete nonexistent node", func(t *testing.T) {
		req := &ua.DeleteNodesRequest{
			RequestHeader: reqHeader(),
			NodesToDelete: []*ua.DeleteNodesItem{{
				NodeID:                 ua.NewStringNodeID(ns.ID(), "nonexistent"),
				DeleteTargetReferences: true,
			}},
		}
		resp, err := svc.DeleteNodes(context.Background(), nil, req, 2)
		require.NoError(t, err)

		delResp := resp.(*ua.DeleteNodesResponse)
		require.Len(t, delResp.Results, 1)
		assert.Equal(t, ua.StatusBadNodeIDUnknown, delResp.Results[0])
	})

	t.Run("delete with nil node ID", func(t *testing.T) {
		req := &ua.DeleteNodesRequest{
			RequestHeader: reqHeader(),
			NodesToDelete: []*ua.DeleteNodesItem{{
				NodeID: nil,
			}},
		}
		resp, err := svc.DeleteNodes(context.Background(), nil, req, 3)
		require.NoError(t, err)

		delResp := resp.(*ua.DeleteNodesResponse)
		require.Len(t, delResp.Results, 1)
		assert.Equal(t, ua.StatusBadNodeIDInvalid, delResp.Results[0])
	})

	t.Run("wrong request type", func(t *testing.T) {
		_, err := svc.DeleteNodes(context.Background(), nil, &ua.ReadRequest{RequestHeader: reqHeader()}, 1)
		assert.Error(t, err)
	})
}

func TestNodeManagementService_AddReferences(t *testing.T) {
	srv := newTestServer()
	ns, obj := addTestNamespace(srv)
	svc := &NodeManagementService{srv: srv}

	t.Run("add reference between existing nodes", func(t *testing.T) {
		sourceID := obj.ID()
		targetID := ua.NewStringNodeID(ns.ID(), "rw_int32")
		req := &ua.AddReferencesRequest{
			RequestHeader: reqHeader(),
			ReferencesToAdd: []*ua.AddReferencesItem{
				{
					SourceNodeID:    sourceID,
					ReferenceTypeID: ua.NewNumericNodeID(0, id.HasComponent),
					IsForward:       true,
					TargetNodeID:    ua.NewExpandedNodeID(targetID, "", 0),
					TargetNodeClass: ua.NodeClassVariable,
				},
			},
		}
		resp, err := svc.AddReferences(context.Background(), nil, req, 1)
		require.NoError(t, err)

		addResp := resp.(*ua.AddReferencesResponse)
		require.Len(t, addResp.Results, 1)
		assert.Equal(t, ua.StatusOK, addResp.Results[0])
	})

	t.Run("add reference with nil source", func(t *testing.T) {
		targetID := ua.NewStringNodeID(ns.ID(), "rw_int32")
		req := &ua.AddReferencesRequest{
			RequestHeader: reqHeader(),
			ReferencesToAdd: []*ua.AddReferencesItem{
				{
					SourceNodeID:    nil,
					ReferenceTypeID: ua.NewNumericNodeID(0, id.HasComponent),
					IsForward:       true,
					TargetNodeID:    ua.NewExpandedNodeID(targetID, "", 0),
				},
			},
		}
		resp, err := svc.AddReferences(context.Background(), nil, req, 2)
		require.NoError(t, err)

		addResp := resp.(*ua.AddReferencesResponse)
		require.Len(t, addResp.Results, 1)
		assert.Equal(t, ua.StatusBadSourceNodeIDInvalid, addResp.Results[0])
	})

	t.Run("add reference with nil target", func(t *testing.T) {
		req := &ua.AddReferencesRequest{
			RequestHeader: reqHeader(),
			ReferencesToAdd: []*ua.AddReferencesItem{
				{
					SourceNodeID:    obj.ID(),
					ReferenceTypeID: ua.NewNumericNodeID(0, id.HasComponent),
					IsForward:       true,
					TargetNodeID:    nil,
				},
			},
		}
		resp, err := svc.AddReferences(context.Background(), nil, req, 3)
		require.NoError(t, err)

		addResp := resp.(*ua.AddReferencesResponse)
		require.Len(t, addResp.Results, 1)
		assert.Equal(t, ua.StatusBadTargetNodeIDInvalid, addResp.Results[0])
	})

	t.Run("add reference with nonexistent source", func(t *testing.T) {
		targetID := ua.NewStringNodeID(ns.ID(), "rw_int32")
		req := &ua.AddReferencesRequest{
			RequestHeader: reqHeader(),
			ReferencesToAdd: []*ua.AddReferencesItem{
				{
					SourceNodeID:    ua.NewStringNodeID(ns.ID(), "nonexistent"),
					ReferenceTypeID: ua.NewNumericNodeID(0, id.HasComponent),
					IsForward:       true,
					TargetNodeID:    ua.NewExpandedNodeID(targetID, "", 0),
				},
			},
		}
		resp, err := svc.AddReferences(context.Background(), nil, req, 4)
		require.NoError(t, err)

		addResp := resp.(*ua.AddReferencesResponse)
		require.Len(t, addResp.Results, 1)
		assert.Equal(t, ua.StatusBadSourceNodeIDInvalid, addResp.Results[0])
	})

	t.Run("add reference with nil reference type", func(t *testing.T) {
		targetID := ua.NewStringNodeID(ns.ID(), "rw_int32")
		req := &ua.AddReferencesRequest{
			RequestHeader: reqHeader(),
			ReferencesToAdd: []*ua.AddReferencesItem{
				{
					SourceNodeID:    obj.ID(),
					ReferenceTypeID: nil,
					IsForward:       true,
					TargetNodeID:    ua.NewExpandedNodeID(targetID, "", 0),
				},
			},
		}
		resp, err := svc.AddReferences(context.Background(), nil, req, 5)
		require.NoError(t, err)

		addResp := resp.(*ua.AddReferencesResponse)
		require.Len(t, addResp.Results, 1)
		assert.Equal(t, ua.StatusBadReferenceTypeIDInvalid, addResp.Results[0])
	})

	t.Run("wrong request type", func(t *testing.T) {
		_, err := svc.AddReferences(context.Background(), nil, &ua.ReadRequest{RequestHeader: reqHeader()}, 1)
		assert.Error(t, err)
	})
}

func TestNodeManagementService_DeleteReferences(t *testing.T) {
	srv := newTestServer()
	ns, obj := addTestNamespace(srv)
	svc := &NodeManagementService{srv: srv}

	t.Run("delete existing reference", func(t *testing.T) {
		// The "rw_int32" node was added as a child of obj via HasComponent.
		targetID := ua.NewStringNodeID(ns.ID(), "rw_int32")
		req := &ua.DeleteReferencesRequest{
			RequestHeader: reqHeader(),
			ReferencesToDelete: []*ua.DeleteReferencesItem{
				{
					SourceNodeID:        obj.ID(),
					ReferenceTypeID:     ua.NewNumericNodeID(0, id.HasComponent),
					IsForward:           true,
					TargetNodeID:        ua.NewExpandedNodeID(targetID, "", 0),
					DeleteBidirectional: false,
				},
			},
		}
		resp, err := svc.DeleteReferences(context.Background(), nil, req, 1)
		require.NoError(t, err)

		delResp := resp.(*ua.DeleteReferencesResponse)
		require.Len(t, delResp.Results, 1)
		assert.Equal(t, ua.StatusOK, delResp.Results[0])
	})

	t.Run("delete nonexistent reference", func(t *testing.T) {
		targetID := ua.NewStringNodeID(ns.ID(), "rw_float64")
		req := &ua.DeleteReferencesRequest{
			RequestHeader: reqHeader(),
			ReferencesToDelete: []*ua.DeleteReferencesItem{
				{
					SourceNodeID:        obj.ID(),
					ReferenceTypeID:     ua.NewNumericNodeID(0, 999),
					IsForward:           true,
					TargetNodeID:        ua.NewExpandedNodeID(targetID, "", 0),
					DeleteBidirectional: false,
				},
			},
		}
		resp, err := svc.DeleteReferences(context.Background(), nil, req, 2)
		require.NoError(t, err)

		delResp := resp.(*ua.DeleteReferencesResponse)
		require.Len(t, delResp.Results, 1)
		assert.Equal(t, ua.StatusBadNotFound, delResp.Results[0])
	})

	t.Run("delete with nil source", func(t *testing.T) {
		targetID := ua.NewStringNodeID(ns.ID(), "rw_int32")
		req := &ua.DeleteReferencesRequest{
			RequestHeader: reqHeader(),
			ReferencesToDelete: []*ua.DeleteReferencesItem{
				{
					SourceNodeID:    nil,
					ReferenceTypeID: ua.NewNumericNodeID(0, id.HasComponent),
					IsForward:       true,
					TargetNodeID:    ua.NewExpandedNodeID(targetID, "", 0),
				},
			},
		}
		resp, err := svc.DeleteReferences(context.Background(), nil, req, 3)
		require.NoError(t, err)

		delResp := resp.(*ua.DeleteReferencesResponse)
		require.Len(t, delResp.Results, 1)
		assert.Equal(t, ua.StatusBadSourceNodeIDInvalid, delResp.Results[0])
	})

	t.Run("wrong request type", func(t *testing.T) {
		_, err := svc.DeleteReferences(context.Background(), nil, &ua.ReadRequest{RequestHeader: reqHeader()}, 1)
		assert.Error(t, err)
	})
}
