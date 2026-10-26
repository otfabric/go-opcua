// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// DeleteReferences removes the source end, and the target end only with
// deleteBidirectional (Part 4 §5.7.5).
func TestNodeManagementService_DeleteReferencesEnds(t *testing.T) {
	srv := newTestServer()
	ns, obj := addTestNamespace(srv)
	svc := &NodeManagementService{srv: srv}
	hasComponent := ua.NewNumericNodeID(0, id.HasComponent)
	del := func(target *Node, bidirectional bool) ua.StatusCode {
		resp, err := svc.DeleteReferences(context.Background(), nil, &ua.DeleteReferencesRequest{
			RequestHeader: reqHeader(),
			ReferencesToDelete: []*ua.DeleteReferencesItem{{
				SourceNodeID: obj.ID(), ReferenceTypeID: hasComponent, IsForward: true,
				TargetNodeID: ua.NewExpandedNodeID(target.ID(), "", 0), DeleteBidirectional: bidirectional,
			}},
		}, 1)
		require.NoError(t, err)
		return resp.(*ua.DeleteReferencesResponse).Results[0]
	}

	one := ns.Node(ua.NewStringNodeID(ns.ID(), "rw_int32"))
	require.Equal(t, ua.StatusOK, del(one, false))
	require.Zero(t, countRefs(obj, one.ID(), id.HasComponent, true))
	require.Equal(t, 1, countRefs(one, obj.ID(), id.HasComponent, false), "the target keeps its end")

	both := ns.Node(ua.NewStringNodeID(ns.ID(), "ro_bool"))
	require.Equal(t, ua.StatusOK, del(both, true))
	require.Zero(t, countRefs(obj, both.ID(), id.HasComponent, true))
	require.Zero(t, countRefs(both, obj.ID(), id.HasComponent, false))
	require.Equal(t, ua.StatusBadNotFound, del(both, true))
}

// DeleteNodes removes the references of which the node is the target from
// their sources with deleteTargetReferences, and leaves them otherwise
// (Part 4 §5.7.4). Those of which it is the source go either way.
func TestNodeManagementService_DeleteNodesTargetReferences(t *testing.T) {
	for _, deleteTarget := range []bool{false, true} {
		srv := newTestServer()
		ns, obj := addTestNamespace(srv)
		svc := &NodeManagementService{srv: srv}
		n := ns.Node(ua.NewStringNodeID(ns.ID(), "rw_int32"))
		child := ns.AddNewVariableStringNode("child", int32(1))
		n.AddRef(child, id.HasProperty, true)

		resp, err := svc.DeleteNodes(context.Background(), nil, &ua.DeleteNodesRequest{
			RequestHeader: reqHeader(),
			NodesToDelete: []*ua.DeleteNodesItem{{NodeID: n.ID(), DeleteTargetReferences: deleteTarget}},
		}, 1)
		require.NoError(t, err)
		require.Equal(t, ua.StatusGood, resp.(*ua.DeleteNodesResponse).Results[0])

		require.Zero(t, countRefs(child, n.ID(), id.HasProperty, false), "deleteTargetReferences=%v", deleteTarget)
		want := 1
		if deleteTarget {
			want = 0
		}
		require.Equal(t, want, countRefs(obj, n.ID(), id.HasComponent, true), "deleteTargetReferences=%v", deleteTarget)
	}
}
