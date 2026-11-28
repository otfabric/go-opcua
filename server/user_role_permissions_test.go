// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// rolePermissionsOf returns the RolePermissionType entries of a
// RolePermissions or UserRolePermissions DataValue.
func rolePermissionsOf(t *testing.T, dv *ua.DataValue) []*ua.RolePermissionType {
	t.Helper()
	require.NotNil(t, dv)
	require.Equal(t, ua.StatusOK, dv.Status)
	eos, ok := dv.Value.Value().([]*ua.ExtensionObject)
	require.True(t, ok, "value %T", dv.Value.Value())
	out := make([]*ua.RolePermissionType, len(eos))
	for i, eo := range eos {
		out[i] = eo.Value.(*ua.RolePermissionType)
	}
	return out
}

// newRolePermissionsNode adds a node granting Anonymous Browse and
// AuthenticatedUser Browse|Read, and returns its NodeId.
func newRolePermissionsNode(t *testing.T, srv *Server) *ua.NodeID {
	t.Helper()
	ns, _ := addTestNamespace(srv)
	nid := ua.NewStringNodeID(ns.ID(), "urp")
	n := ns.AddNewVariableStringNode("urp", int32(1))
	n.rolePermissions = []*ua.RolePermissionType{
		{RoleID: ua.RoleAnonymous.NodeID(), Permissions: ua.PermissionTypeBrowse},
		{RoleID: ua.RoleAuthenticatedUser.NodeID(), Permissions: ua.PermissionTypeBrowse | ua.PermissionTypeRead},
	}
	return nid
}

// TestRead_UserRolePermissions reads UserRolePermissions with sessions of
// different roles: each sees the entries of its own roles only, while
// RolePermissions lists all of them (Part 3 §5.2.9, §5.2.10).
func TestRead_UserRolePermissions(t *testing.T) {
	srv := newTestServer()
	nid := newRolePermissionsNode(t, srv)
	svc := &AttributeService{srv: srv}

	read := func(t *testing.T, sess *session, attr ua.AttributeID) *ua.DataValue {
		t.Helper()
		hdr := reqHeader()
		if sess != nil {
			hdr.AuthenticationToken = sess.AuthTokenID
		}
		resp, err := svc.Read(context.Background(), nil, &ua.ReadRequest{
			RequestHeader: hdr,
			NodesToRead:   []*ua.ReadValueID{{NodeID: nid, AttributeID: attr}},
		}, 1)
		require.NoError(t, err)
		return resp.(*ua.ReadResponse).Results[0]
	}
	withRoles := func(roles ...*ua.NodeID) *session {
		s := srv.sb.NewSession()
		s.roles = roles
		return s
	}

	t.Run("RolePermissions lists every role", func(t *testing.T) {
		rps := rolePermissionsOf(t, read(t, withRoles(ua.RoleAnonymous.NodeID()), ua.AttributeIDRolePermissions))
		require.Len(t, rps, 2)
	})

	t.Run("anonymous session", func(t *testing.T) {
		rps := rolePermissionsOf(t, read(t, withRoles(ua.RoleAnonymous.NodeID()), ua.AttributeIDUserRolePermissions))
		require.Len(t, rps, 1)
		require.True(t, rps[0].RoleID.Equal(ua.RoleAnonymous.NodeID()))
		require.Equal(t, ua.PermissionTypeBrowse, rps[0].Permissions)
	})

	t.Run("authenticated session", func(t *testing.T) {
		rps := rolePermissionsOf(t, read(t, withRoles(ua.RoleAuthenticatedUser.NodeID()), ua.AttributeIDUserRolePermissions))
		require.Len(t, rps, 1)
		require.True(t, rps[0].RoleID.Equal(ua.RoleAuthenticatedUser.NodeID()))
	})

	t.Run("session with both roles", func(t *testing.T) {
		rps := rolePermissionsOf(t, read(t, withRoles(ua.RoleAnonymous.NodeID(), ua.RoleAuthenticatedUser.NodeID()), ua.AttributeIDUserRolePermissions))
		require.Len(t, rps, 2)
	})

	t.Run("session with a role the node does not list", func(t *testing.T) {
		rps := rolePermissionsOf(t, read(t, withRoles(ua.RoleOperator.NodeID()), ua.AttributeIDUserRolePermissions))
		require.Empty(t, rps)
	})

	t.Run("no session has the Anonymous role", func(t *testing.T) {
		rps := rolePermissionsOf(t, read(t, nil, ua.AttributeIDUserRolePermissions))
		require.Len(t, rps, 1)
		require.True(t, rps[0].RoleID.Equal(ua.RoleAnonymous.NodeID()))
	})

	t.Run("node without RolePermissions", func(t *testing.T) {
		resp, err := svc.Read(context.Background(), nil, &ua.ReadRequest{
			RequestHeader: reqHeader(),
			NodesToRead: []*ua.ReadValueID{{
				NodeID: ua.NewStringNodeID(nid.Namespace(), "rw_int32"), AttributeID: ua.AttributeIDUserRolePermissions,
			}},
		}, 1)
		require.NoError(t, err)
		require.Equal(t, ua.StatusBadAttributeIDInvalid, resp.(*ua.ReadResponse).Results[0].Status)
	})
}

// TestForSessionRoles_Edges covers the values forSessionRoles leaves alone
// and the entries it skips.
func TestForSessionRoles_Edges(t *testing.T) {
	require.Nil(t, forSessionRoles(nil, nil))
	empty := &ua.DataValue{}
	require.Same(t, empty, forSessionRoles(empty, nil))
	scalar := DataValueFromValue(int32(1))
	require.Same(t, scalar, forSessionRoles(scalar, nil))

	anon := ua.NewExtensionObject(&ua.RolePermissionType{RoleID: ua.RoleAnonymous.NodeID(), Permissions: ua.PermissionTypeBrowse})
	dv := DataValueFromValue([]*ua.ExtensionObject{
		nil,
		ua.NewExtensionObject(&ua.RolePermissionType{}),
		ua.NewExtensionObject(&ua.AnonymousIdentityToken{}),
		anon,
	})
	got := forSessionRoles(dv, nil)
	require.NotSame(t, dv, got)
	require.Equal(t, []*ua.ExtensionObject{anon}, got.Value.Value())
	require.Len(t, dv.Value.Value(), 4, "the input is not modified")
}

// TestReadSample_UserRolePermissions monitors UserRolePermissions: the
// samples carry the entries of the roles of the subscription's session.
func TestReadSample_UserRolePermissions(t *testing.T) {
	f := newSamplerFixture(t)
	nid := newRolePermissionsNode(t, f.srv)
	sess := f.srv.sb.NewSession()
	sess.roles = []*ua.NodeID{ua.RoleAuthenticatedUser.NodeID()}
	f.sub.Session = sess
	item := f.add(1, nid, func(mi *MonitoredItem) {
		mi.Req.ItemToMonitor.AttributeID = ua.AttributeIDUserRolePermissions
	})
	f.svc.Mu.Lock()
	dv := f.svc.readSample(item)
	f.svc.Mu.Unlock()
	rps := rolePermissionsOf(t, dv)
	require.Len(t, rps, 1)
	require.True(t, rps[0].RoleID.Equal(ua.RoleAuthenticatedUser.NodeID()))

	// An item without a subscription is sampled as it is.
	item.Sub = nil
	f.svc.Mu.Lock()
	dv = f.svc.readSample(item)
	f.svc.Mu.Unlock()
	require.Len(t, rolePermissionsOf(t, dv), 2)
}
