// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// denyAllController denies all operations.
type denyAllController struct{}

func (denyAllController) CheckRead(_ context.Context, _ *session, _ *ua.NodeID) ua.StatusCode {
	return ua.StatusBadUserAccessDenied
}
func (denyAllController) CheckWrite(_ context.Context, _ *session, _ *ua.NodeID) ua.StatusCode {
	return ua.StatusBadUserAccessDenied
}
func (denyAllController) CheckBrowse(_ context.Context, _ *session, _ *ua.NodeID) ua.StatusCode {
	return ua.StatusBadUserAccessDenied
}
func (denyAllController) CheckCall(_ context.Context, _ *session, _ *ua.NodeID) ua.StatusCode {
	return ua.StatusBadUserAccessDenied
}

func TestAccessControl_ReadDenied(t *testing.T) {
	srv := newTestServer()
	srv.cfg.accessController = denyAllController{}
	ns, _ := addTestNamespace(srv)
	svc := &AttributeService{srv: srv}

	req := &ua.ReadRequest{
		RequestHeader: reqHeader(),
		NodesToRead: []*ua.ReadValueID{
			{NodeID: ua.NewStringNodeID(ns.ID(), "rw_int32"), AttributeID: ua.AttributeIDValue},
		},
	}
	resp, err := svc.Read(context.Background(), nil, req, 1)
	require.NoError(t, err)

	readResp := resp.(*ua.ReadResponse)
	require.Len(t, readResp.Results, 1)
	assert.Equal(t, ua.StatusBadUserAccessDenied, readResp.Results[0].Status)
}

func TestAccessControl_WriteDenied(t *testing.T) {
	srv := newTestServer()
	srv.cfg.accessController = denyAllController{}
	ns, _ := addTestNamespace(srv)
	svc := &AttributeService{srv: srv}

	req := &ua.WriteRequest{
		RequestHeader: reqHeader(),
		NodesToWrite: []*ua.WriteValue{
			{
				NodeID:      ua.NewStringNodeID(ns.ID(), "rw_int32"),
				AttributeID: ua.AttributeIDValue,
				Value: &ua.DataValue{
					EncodingMask: ua.DataValueValue,
					Value:        ua.MustVariant(int32(99)),
				},
			},
		},
	}
	resp, err := svc.Write(context.Background(), nil, req, 1)
	require.NoError(t, err)

	writeResp := resp.(*ua.WriteResponse)
	require.Len(t, writeResp.Results, 1)
	assert.Equal(t, ua.StatusBadUserAccessDenied, writeResp.Results[0])
}

func TestAccessControl_BrowseDenied(t *testing.T) {
	srv := newTestServer()
	srv.cfg.accessController = denyAllController{}
	ns, _ := addTestNamespace(srv)
	svc := &ViewService{srv: srv, cps: make(map[string]*continuationPoint)}

	req := &ua.BrowseRequest{
		RequestHeader: reqHeader(),
		NodesToBrowse: []*ua.BrowseDescription{{
			NodeID:          ua.NewNumericNodeID(ns.ID(), id.ObjectsFolder),
			BrowseDirection: ua.BrowseDirectionForward,
			ReferenceTypeID: ua.NewNumericNodeID(0, 0),
			IncludeSubtypes: true,
			ResultMask:      uint32(ua.BrowseResultMaskAll),
		}},
	}
	resp, err := svc.Browse(context.Background(), nil, req, 1)
	require.NoError(t, err)

	browseResp := resp.(*ua.BrowseResponse)
	require.Len(t, browseResp.Results, 1)
	assert.Equal(t, ua.StatusBadUserAccessDenied, browseResp.Results[0].StatusCode)
}

func TestAccessControl_CallDenied(t *testing.T) {
	srv := newTestServer()
	srv.cfg.accessController = denyAllController{}
	ns, obj := addTestNamespace(srv)
	svc := &MethodService{srv: srv}

	methodID := ua.NewStringNodeID(ns.ID(), "ac_method")
	methodNode := NewFolderNode(methodID, "ac_method")
	methodNode.SetNodeClass(ua.NodeClassMethod)
	ns.AddNode(methodNode)
	obj.AddRef(methodNode, RefType(id.HasComponent), true)

	srv.RegisterMethod(obj.ID(), methodID, func(ctx context.Context, oID, mID *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		return nil, ua.StatusOK
	})

	req := &ua.CallRequest{
		RequestHeader: reqHeader(),
		MethodsToCall: []*ua.CallMethodRequest{{
			ObjectID: obj.ID(),
			MethodID: methodID,
		}},
	}
	resp, err := svc.Call(context.Background(), nil, req, 1)
	require.NoError(t, err)

	callResp := resp.(*ua.CallResponse)
	require.Len(t, callResp.Results, 1)
	assert.Equal(t, ua.StatusBadUserAccessDenied, callResp.Results[0].StatusCode)
}

func TestAccessControl_DefaultAllows(t *testing.T) {
	ac := DefaultAccessController{}
	assert.Equal(t, ua.StatusOK, ac.CheckRead(context.Background(), nil, nil))
	assert.Equal(t, ua.StatusOK, ac.CheckWrite(context.Background(), nil, nil))
	assert.Equal(t, ua.StatusOK, ac.CheckBrowse(context.Background(), nil, nil))
	assert.Equal(t, ua.StatusOK, ac.CheckCall(context.Background(), nil, nil))
}

func TestAccessControl_WithAccessControllerOption(t *testing.T) {
	srv, err := New(EndPoint("localhost", 4840), WithAccessController(denyAllController{}))
	require.NoError(t, err)
	assert.IsType(t, denyAllController{}, srv.cfg.accessController)
}

func TestCheckAccessRestrictions(t *testing.T) {
	nodeWithRestriction := func(r ua.AccessRestrictionType) *Node {
		nid := ua.NewNumericNodeID(0, 9999)
		attrs := Attributes{
			ua.AttributeIDAccessRestrictions: DataValueFromValue(uint16(r)),
		}
		return NewNode(nid, attrs, nil, nil)
	}

	t.Run("no restrictions allows nil channel", func(t *testing.T) {
		n := nodeWithRestriction(ua.AccessRestrictionTypeNone)
		assert.Equal(t, ua.StatusOK, checkAccessRestrictions(nil, n))
	})

	t.Run("signing required denies nil channel", func(t *testing.T) {
		n := nodeWithRestriction(ua.AccessRestrictionTypeSigningRequired)
		assert.Equal(t, ua.StatusBadSecurityModeInsufficient, checkAccessRestrictions(nil, n))
	})

	t.Run("encryption required denies nil channel", func(t *testing.T) {
		n := nodeWithRestriction(ua.AccessRestrictionTypeEncryptionRequired)
		assert.Equal(t, ua.StatusBadSecurityModeInsufficient, checkAccessRestrictions(nil, n))
	})

	t.Run("no attribute means no restriction", func(t *testing.T) {
		nid := ua.NewNumericNodeID(0, 9999)
		n := NewNode(nid, Attributes{}, nil, nil)
		assert.Equal(t, ua.StatusOK, checkAccessRestrictions(nil, n))
	})

	t.Run("browse check skips without ApplyRestrictionsToBrowse", func(t *testing.T) {
		n := nodeWithRestriction(ua.AccessRestrictionTypeSigningRequired)
		assert.Equal(t, ua.StatusOK, checkAccessRestrictionsForBrowse(nil, n))
	})

	t.Run("browse check enforces with ApplyRestrictionsToBrowse", func(t *testing.T) {
		n := nodeWithRestriction(ua.AccessRestrictionTypeSigningRequired | ua.AccessRestrictionTypeApplyRestrictionsToBrowse)
		assert.Equal(t, ua.StatusBadSecurityModeInsufficient, checkAccessRestrictionsForBrowse(nil, n))
	})
}

func TestDefaultRoleMapper(t *testing.T) {
	t.Run("nil token maps to Anonymous", func(t *testing.T) {
		roles := DefaultRoleMapper(nil)
		require.Len(t, roles, 1)
		assert.Equal(t, ua.RoleAnonymous.NodeID().String(), roles[0].String())
	})

	t.Run("AnonymousIdentityToken maps to Anonymous", func(t *testing.T) {
		roles := DefaultRoleMapper(&ua.AnonymousIdentityToken{})
		require.Len(t, roles, 1)
		assert.Equal(t, ua.RoleAnonymous.NodeID().String(), roles[0].String())
	})

	t.Run("UserNameIdentityToken maps to AuthenticatedUser", func(t *testing.T) {
		roles := DefaultRoleMapper(&ua.UserNameIdentityToken{UserName: "admin"})
		require.Len(t, roles, 1)
		assert.Equal(t, ua.RoleAuthenticatedUser.NodeID().String(), roles[0].String())
	})
}

func TestRBACAccessController(t *testing.T) {
	srv := newTestServer()

	// Create a node with specific role permissions:
	// Anonymous → Browse only, AuthenticatedUser → Browse|Read|Write|Call
	nid := ua.NewNumericNodeID(0, 50000)
	attrs := Attributes{
		ua.AttributeIDNodeClass: DataValueFromValue(uint32(ua.NodeClassVariable)),
	}
	n := NewNode(nid, attrs, nil, nil)
	n.rolePermissions = []*ua.RolePermissionType{
		{RoleID: ua.RoleAnonymous.NodeID(), Permissions: ua.PermissionTypeBrowse},
		{RoleID: ua.RoleAuthenticatedUser.NodeID(), Permissions: ua.PermissionTypeBrowse | ua.PermissionTypeRead | ua.PermissionTypeWrite | ua.PermissionTypeCall},
	}
	ns0, _ := srv.Namespace(0)
	ns0.AddNode(n)

	ac := NewRBACAccessController(srv)

	anonSess := &session{roles: []*ua.NodeID{ua.RoleAnonymous.NodeID()}}
	authSess := &session{roles: []*ua.NodeID{ua.RoleAuthenticatedUser.NodeID()}}

	t.Run("anonymous can browse", func(t *testing.T) {
		assert.Equal(t, ua.StatusOK, ac.CheckBrowse(context.Background(), anonSess, nid))
	})

	t.Run("anonymous cannot read", func(t *testing.T) {
		assert.Equal(t, ua.StatusBadUserAccessDenied, ac.CheckRead(context.Background(), anonSess, nid))
	})

	t.Run("anonymous cannot write", func(t *testing.T) {
		assert.Equal(t, ua.StatusBadUserAccessDenied, ac.CheckWrite(context.Background(), anonSess, nid))
	})

	t.Run("authenticated can read", func(t *testing.T) {
		assert.Equal(t, ua.StatusOK, ac.CheckRead(context.Background(), authSess, nid))
	})

	t.Run("authenticated can write", func(t *testing.T) {
		assert.Equal(t, ua.StatusOK, ac.CheckWrite(context.Background(), authSess, nid))
	})

	t.Run("authenticated can call", func(t *testing.T) {
		assert.Equal(t, ua.StatusOK, ac.CheckCall(context.Background(), authSess, nid))
	})

	t.Run("node without permissions allows all", func(t *testing.T) {
		nid2 := ua.NewNumericNodeID(0, 50001)
		ns0.AddNode(NewNode(nid2, Attributes{}, nil, nil))
		assert.Equal(t, ua.StatusOK, ac.CheckRead(context.Background(), anonSess, nid2))
	})

	t.Run("nil session defaults to Anonymous role", func(t *testing.T) {
		assert.Equal(t, ua.StatusOK, ac.CheckBrowse(context.Background(), nil, nid))
		assert.Equal(t, ua.StatusBadUserAccessDenied, ac.CheckRead(context.Background(), nil, nid))
	})
}
