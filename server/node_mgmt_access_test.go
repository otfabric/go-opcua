// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// nodeMgmtCalls runs one operation of each Node Management service on the
// namespace of obj and returns their results: AddNodes below obj,
// AddReferences and DeleteReferences from obj, DeleteNodes of victim.
func nodeMgmtCalls(t *testing.T, svc *NodeManagementService, hdr *ua.RequestHeader, nsIdx uint16, obj, victim *ua.NodeID) (add, addRef, delRef, del ua.StatusCode) {
	t.Helper()
	ctx := context.Background()
	newID := ua.NewStringNodeID(nsIdx, "added")
	r1, err := svc.AddNodes(ctx, nil, &ua.AddNodesRequest{RequestHeader: hdr, NodesToAdd: []*ua.AddNodesItem{{
		ParentNodeID:       ua.NewExpandedNodeID(obj, "", 0),
		ReferenceTypeID:    ua.NewNumericNodeID(0, id.HasComponent),
		RequestedNewNodeID: ua.NewExpandedNodeID(newID, "", 0),
		BrowseName:         &ua.QualifiedName{NamespaceIndex: nsIdx, Name: "added"},
		NodeClass:          ua.NodeClassVariable,
	}}}, 1)
	require.NoError(t, err)
	r2, err := svc.AddReferences(ctx, nil, &ua.AddReferencesRequest{RequestHeader: hdr, ReferencesToAdd: []*ua.AddReferencesItem{{
		SourceNodeID:    obj,
		ReferenceTypeID: ua.NewNumericNodeID(0, id.Organizes),
		IsForward:       true,
		TargetNodeID:    ua.NewExpandedNodeID(victim, "", 0),
		TargetNodeClass: ua.NodeClassVariable,
	}}}, 1)
	require.NoError(t, err)
	r3, err := svc.DeleteReferences(ctx, nil, &ua.DeleteReferencesRequest{RequestHeader: hdr, ReferencesToDelete: []*ua.DeleteReferencesItem{{
		SourceNodeID:    obj,
		ReferenceTypeID: ua.NewNumericNodeID(0, id.Organizes),
		IsForward:       true,
		TargetNodeID:    ua.NewExpandedNodeID(victim, "", 0),
	}}}, 1)
	require.NoError(t, err)
	r4, err := svc.DeleteNodes(ctx, nil, &ua.DeleteNodesRequest{RequestHeader: hdr, NodesToDelete: []*ua.DeleteNodesItem{{NodeID: victim}}}, 1)
	require.NoError(t, err)
	return r1.(*ua.AddNodesResponse).Results[0].StatusCode, r2.(*ua.AddReferencesResponse).Results[0],
		r3.(*ua.DeleteReferencesResponse).Results[0], r4.(*ua.DeleteNodesResponse).Results[0]
}

func TestNodeManagement_DisabledByDefault(t *testing.T) {
	srv := newTestServer()
	ns, obj := addTestNamespace(srv)
	svc := &NodeManagementService{srv: srv}
	ctx := context.Background()
	victim := ua.NewStringNodeID(ns.ID(), "rw_int32")

	_, err := svc.AddNodes(ctx, nil, &ua.AddNodesRequest{RequestHeader: reqHeader(), NodesToAdd: []*ua.AddNodesItem{{}}}, 1)
	require.Equal(t, ua.StatusBadServiceUnsupported, err)
	_, err = svc.AddReferences(ctx, nil, &ua.AddReferencesRequest{RequestHeader: reqHeader()}, 1)
	require.Equal(t, ua.StatusBadServiceUnsupported, err)
	_, err = svc.DeleteReferences(ctx, nil, &ua.DeleteReferencesRequest{RequestHeader: reqHeader()}, 1)
	require.Equal(t, ua.StatusBadServiceUnsupported, err)
	_, err = svc.DeleteNodes(ctx, nil, &ua.DeleteNodesRequest{RequestHeader: reqHeader(), NodesToDelete: []*ua.DeleteNodesItem{{NodeID: victim}}}, 1)
	require.Equal(t, ua.StatusBadServiceUnsupported, err)
	require.NotNil(t, srv.Node(victim))
	require.NotNil(t, obj)

	// The option turns it on.
	s, err := New(EnableNodeManagement())
	require.NoError(t, err)
	require.True(t, s.cfg.nodeManagement)
}

func TestNodeManagement_DeniedByAccessController(t *testing.T) {
	srv := newTestServer()
	ns, obj := addTestNamespace(srv)
	srv.cfg.nodeManagement = true
	svc := &NodeManagementService{srv: srv}
	victim := ua.NewStringNodeID(ns.ID(), "rw_int32")

	// CheckWrite of the changed node decides with a plain AccessController.
	srv.cfg.accessController = noReads{}
	add, addRef, delRef, del := nodeMgmtCalls(t, svc, reqHeader(), ns.ID(), obj.ID(), victim)
	for _, st := range []ua.StatusCode{add, addRef, delRef, del} {
		require.Equal(t, ua.StatusBadUserAccessDenied, st)
	}
	require.NotNil(t, srv.Node(victim))
	require.Nil(t, srv.Node(ua.NewStringNodeID(ns.ID(), "added")))

	// Allowed: every operation is carried out.
	srv.cfg.accessController = DefaultAccessController{}
	add, addRef, delRef, del = nodeMgmtCalls(t, svc, reqHeader(), ns.ID(), obj.ID(), victim)
	require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusOK, ua.StatusOK, ua.StatusOK}, []ua.StatusCode{add, addRef, delRef, del})
	require.Nil(t, srv.Node(victim))
}

func TestNodeManagement_Namespace0Protected(t *testing.T) {
	srv := newTestServer()
	srv.cfg.nodeManagement = true
	svc := &NodeManagementService{srv: srv}
	caps := ua.NewNumericNodeID(0, id.ServerServerCapabilities)
	objects := ua.NewNumericNodeID(0, id.ObjectsFolder)
	ctx := context.Background()

	add, addRef, delRef, del := nodeMgmtCalls(t, svc, reqHeader(), 0, objects, caps)
	for _, st := range []ua.StatusCode{add, addRef, delRef, del} {
		require.Equal(t, ua.StatusBadUserAccessDenied, st)
	}
	require.NotNil(t, srv.Node(caps))

	// Below the Objects folder, in another namespace, nodes may be added.
	ns := NewNodeNameSpace(srv, "urn:test:nm")
	resp, err := svc.AddNodes(ctx, nil, &ua.AddNodesRequest{RequestHeader: reqHeader(), NodesToAdd: []*ua.AddNodesItem{{
		ParentNodeID:       ua.NewExpandedNodeID(objects, "", 0),
		ReferenceTypeID:    ua.NewNumericNodeID(0, id.Organizes),
		RequestedNewNodeID: ua.NewExpandedNodeID(ua.NewStringNodeID(ns.ID(), "x"), "", 0),
		BrowseName:         &ua.QualifiedName{NamespaceIndex: ns.ID(), Name: "x"},
		NodeClass:          ua.NodeClassObject,
	}, nil}}, 1)
	require.NoError(t, err)
	res := resp.(*ua.AddNodesResponse).Results
	require.Equal(t, ua.StatusOK, res[0].StatusCode)
	require.Equal(t, ua.StatusBadNodeIDInvalid, res[1].StatusCode)

	// Items without the node they change are invalid.
	r2, err := svc.AddReferences(ctx, nil, &ua.AddReferencesRequest{RequestHeader: reqHeader(), ReferencesToAdd: []*ua.AddReferencesItem{nil}}, 1)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadSourceNodeIDInvalid, r2.(*ua.AddReferencesResponse).Results[0])
	r3, err := svc.DeleteReferences(ctx, nil, &ua.DeleteReferencesRequest{RequestHeader: reqHeader(), ReferencesToDelete: []*ua.DeleteReferencesItem{nil}}, 1)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadSourceNodeIDInvalid, r3.(*ua.DeleteReferencesResponse).Results[0])
	r4, err := svc.DeleteNodes(ctx, nil, &ua.DeleteNodesRequest{RequestHeader: reqHeader(), NodesToDelete: []*ua.DeleteNodesItem{nil}}, 1)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadNodeIDInvalid, r4.(*ua.DeleteNodesResponse).Results[0])
	// AddNodes without a parent: CheckWrite of the requested node.
	srv.cfg.accessController = noReads{}
	resp, err = svc.AddNodes(ctx, nil, &ua.AddNodesRequest{RequestHeader: reqHeader(), NodesToAdd: []*ua.AddNodesItem{{
		RequestedNewNodeID: ua.NewExpandedNodeID(ua.NewStringNodeID(ns.ID(), "y"), "", 0),
		NodeClass:          ua.NodeClassObject,
	}, {NodeClass: ua.NodeClassObject}}}, 1)
	require.NoError(t, err)
	res = resp.(*ua.AddNodesResponse).Results
	require.Equal(t, ua.StatusBadUserAccessDenied, res[0].StatusCode)
	require.Equal(t, ua.StatusBadNodeIDInvalid, res[1].StatusCode)
}

// nmController decides node management by itself.
type nmController struct {
	DefaultAccessController
	allow bool
	seen  []string
}

func (c *nmController) decide(op string) ua.StatusCode {
	c.seen = append(c.seen, op)
	if c.allow {
		return ua.StatusOK
	}
	return ua.StatusBadUserAccessDenied
}

func (c *nmController) CheckAddNodes(_ context.Context, _ *Session, _ *ua.AddNodesItem) ua.StatusCode {
	return c.decide("AddNodes")
}

func (c *nmController) CheckDeleteNodes(_ context.Context, _ *Session, _ *ua.DeleteNodesItem) ua.StatusCode {
	return c.decide("DeleteNodes")
}

func (c *nmController) CheckAddReferences(_ context.Context, _ *Session, _ *ua.AddReferencesItem) ua.StatusCode {
	return c.decide("AddReferences")
}

func (c *nmController) CheckDeleteReferences(_ context.Context, _ *Session, _ *ua.DeleteReferencesItem) ua.StatusCode {
	return c.decide("DeleteReferences")
}

func TestNodeManagement_AccessControllerHook(t *testing.T) {
	srv := newTestServer()
	ns, obj := addTestNamespace(srv)
	srv.cfg.nodeManagement = true
	svc := &NodeManagementService{srv: srv}
	victim := ua.NewStringNodeID(ns.ID(), "rw_int32")

	c := &nmController{}
	srv.cfg.accessController = c
	add, addRef, delRef, del := nodeMgmtCalls(t, svc, reqHeader(), ns.ID(), obj.ID(), victim)
	for _, st := range []ua.StatusCode{add, addRef, delRef, del} {
		require.Equal(t, ua.StatusBadUserAccessDenied, st)
	}
	require.Equal(t, []string{"AddNodes", "AddReferences", "DeleteReferences", "DeleteNodes"}, c.seen)

	// The hook decides namespace 0 as well.
	c.allow = true
	srv.Node(ua.NewNumericNodeID(0, id.ObjectsFolder)).AddRef(srv.Node(victim), id.Organizes, true)
	_, _, delRef, _ = nodeMgmtCalls(t, svc, reqHeader(), 0, ua.NewNumericNodeID(0, id.ObjectsFolder), victim)
	require.Equal(t, ua.StatusOK, delRef)
}

func TestNodeManagement_RBAC(t *testing.T) {
	srv := newTestServer()
	ns, obj := addTestNamespace(srv)
	srv.cfg.nodeManagement = true
	srv.cfg.accessController = NewRBACAccessController(srv)
	svc := &NodeManagementService{srv: srv}
	victim := ua.NewStringNodeID(ns.ID(), "rw_int32")

	sess := srv.sb.NewSession()
	sess.roles = []*ua.NodeID{ua.RoleOperator.NodeID()}
	hdr := &ua.RequestHeader{RequestHandle: 1, AuthenticationToken: sess.AuthTokenID}

	// Nodes without RolePermissions refuse node management under RBAC.
	add, addRef, delRef, del := nodeMgmtCalls(t, svc, hdr, ns.ID(), obj.ID(), victim)
	for _, st := range []ua.StatusCode{add, addRef, delRef, del} {
		require.Equal(t, ua.StatusBadUserAccessDenied, st)
	}

	// Namespace 0 under the generated permissions: an Operator may not
	// delete ServerCapabilities.
	_, _, _, del = nodeMgmtCalls(t, svc, hdr, 0, ua.NewNumericNodeID(0, id.ObjectsFolder), ua.NewNumericNodeID(0, id.ServerServerCapabilities))
	require.Equal(t, ua.StatusBadUserAccessDenied, del)

	// Granted permissions allow each operation.
	grant := func(n *Node, p ua.PermissionType) {
		n.mu.Lock()
		n.rolePermissions = []*ua.RolePermissionType{{RoleID: ua.RoleOperator.NodeID(), Permissions: p}}
		n.mu.Unlock()
	}
	grant(obj, ua.PermissionTypeAddNode|ua.PermissionTypeAddReference|ua.PermissionTypeRemoveReference)
	grant(srv.Node(victim), ua.PermissionTypeDeleteNode)
	add, addRef, delRef, del = nodeMgmtCalls(t, svc, hdr, ns.ID(), obj.ID(), victim)
	require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusOK, ua.StatusOK, ua.StatusOK}, []ua.StatusCode{add, addRef, delRef, del})

	// The permission of another role does not help.
	other := ua.NewStringNodeID(ns.ID(), "rw_float64")
	n := srv.Node(other)
	n.mu.Lock()
	n.rolePermissions = []*ua.RolePermissionType{{RoleID: ua.RoleSecurityAdmin.NodeID(), Permissions: ua.PermissionTypeDeleteNode}}
	n.mu.Unlock()
	_, _, _, del = nodeMgmtCalls(t, svc, hdr, ns.ID(), obj.ID(), other)
	require.Equal(t, ua.StatusBadUserAccessDenied, del)

	// Unknown parent: refused; unknown node to delete: left to the service.
	ac := srv.cfg.accessController.(*RBACAccessController)
	require.Equal(t, ua.StatusBadUserAccessDenied, ac.CheckAddNodes(context.Background(), nil, &ua.AddNodesItem{}))
	require.Equal(t, ua.StatusBadUserAccessDenied, ac.CheckAddNodes(context.Background(), nil, nil))
	require.Equal(t, ua.StatusOK, ac.CheckDeleteNodes(context.Background(), nil, &ua.DeleteNodesItem{NodeID: ua.NewStringNodeID(ns.ID(), "gone")}))
	require.Equal(t, ua.StatusOK, ac.CheckDeleteNodes(context.Background(), nil, &ua.DeleteNodesItem{}))
	require.Equal(t, ua.StatusBadUserAccessDenied, ac.CheckDeleteNodes(context.Background(), nil, nil))
	require.Equal(t, ua.StatusBadUserAccessDenied, ac.CheckAddReferences(context.Background(), nil, nil))
	require.Equal(t, ua.StatusBadUserAccessDenied, ac.CheckDeleteReferences(context.Background(), nil, nil))
}
