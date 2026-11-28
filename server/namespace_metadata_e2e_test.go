// SPDX-License-Identifier: MIT

package server_test

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// readWire reads the Value of nid with c.
func readWire(ctx context.Context, t *testing.T, c *opcua.Client, nid *ua.NodeID) *ua.DataValue {
	t.Helper()
	resp, err := c.Read(ctx, &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{{NodeID: nid, AttributeID: ua.AttributeIDValue}}})
	require.NoError(t, err)
	return resp.Results[0]
}

// metadataProperties browses the Namespaces Object for the
// NamespaceMetadata Object of uri and returns its Properties by BrowseName.
func metadataProperties(ctx context.Context, t *testing.T, c *opcua.Client, uri string) map[string]*ua.NodeID {
	t.Helper()
	browse := func(nid *ua.NodeID, refType uint32) []*ua.ReferenceDescription {
		resp, err := c.Browse(ctx, &ua.BrowseRequest{NodesToBrowse: []*ua.BrowseDescription{{
			NodeID: nid, BrowseDirection: ua.BrowseDirectionForward, ReferenceTypeID: ua.NewNumericNodeID(0, refType),
			IncludeSubtypes: true, ResultMask: uint32(ua.BrowseResultMaskAll),
		}}})
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, resp.Results[0].StatusCode)
		return resp.Results[0].References
	}
	for _, r := range browse(ua.NewNumericNodeID(0, id.ServerNamespaces), id.HasComponent) {
		if r.BrowseName.Name != uri {
			continue
		}
		require.True(t, ua.NewNumericNodeID(0, id.NamespaceMetadataType).Equal(r.TypeDefinition.NodeID))
		props := map[string]*ua.NodeID{}
		for _, p := range browse(r.NodeID.NodeID, id.HasProperty) {
			props[p.BrowseName.Name] = p.NodeID.NodeID
		}
		return props
	}
	t.Fatalf("no NamespaceMetadata for %s", uri)
	return nil
}

// TestNamespaceDefaultsOverTheWire: the NamespaceMetadata Object of a
// namespace of the program, its default permissions and their effect on a
// node without RolePermissions or AccessRestrictions (Part 3 §4.9.3, §5.2.9
// to §5.2.11; Part 5 §6.3.13).
func TestNamespaceDefaultsOverTheWire(t *testing.T) {
	t.Parallel()
	srv, err := server.New(server.EndPoint("localhost", 0),
		server.InsecureNoSecurity(),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.WithAccessController(server.NewRBACAccessController(nil)))
	require.NoError(t, err)
	const uri = "urn:e2e:defaults"
	ns := server.NewNodeNameSpace(srv, uri)
	v := ns.AddNewVariableStringNode("v", int32(7))
	ns.Objects().AddRef(v, id.HasComponent, true)
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })
	c := testutil.NewTestClient(t, srv.Endpoints()[0].EndpointURL)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Without defaults: allowed, as before.
	require.Equal(t, ua.StatusOK, readWire(ctx, t, c, v.ID()).Status)
	props := metadataProperties(ctx, t, c, uri)
	require.Equal(t, uri, readWire(ctx, t, c, props["NamespaceUri"]).Value.Value())
	require.Equal(t, false, readWire(ctx, t, c, props["IsNamespaceSubset"]).Value.Value())
	require.NotContains(t, props, "DefaultRolePermissions")

	// Defaults that do not grant Anonymous Read.
	require.NoError(t, srv.SetNamespaceDefaults(uri, server.NamespaceDefaults{RolePermissions: []*ua.RolePermissionType{
		{RoleID: ua.RoleAnonymous.NodeID(), Permissions: ua.PermissionTypeBrowse},
		{RoleID: ua.RoleOperator.NodeID(), Permissions: ua.PermissionTypeBrowse | ua.PermissionTypeRead},
	}}))
	require.Equal(t, ua.StatusBadUserAccessDenied, readWire(ctx, t, c, v.ID()).Status)
	props = metadataProperties(ctx, t, c, uri)
	// DefaultRolePermissions: administrators only (Part 3 §5.2.9).
	require.Equal(t, ua.StatusBadUserAccessDenied, readWire(ctx, t, c, props["DefaultRolePermissions"]).Status)
	// DefaultUserRolePermissions: those of the roles of the session.
	durp := readWire(ctx, t, c, props["DefaultUserRolePermissions"])
	require.Equal(t, ua.StatusOK, durp.Status)
	eos := durp.Value.Value().([]*ua.ExtensionObject)
	require.Len(t, eos, 1)
	rp := eos[0].Value.(*ua.RolePermissionType)
	require.True(t, ua.RoleAnonymous.NodeID().Equal(rp.RoleID))
	require.Equal(t, ua.PermissionTypeBrowse, rp.Permissions)

	// Defaults that grant it, and DefaultAccessRestrictions.
	require.NoError(t, srv.SetNamespaceDefaults(uri, server.NamespaceDefaults{
		RolePermissions:       []*ua.RolePermissionType{{RoleID: ua.RoleAnonymous.NodeID(), Permissions: ua.PermissionTypeBrowse | ua.PermissionTypeRead}},
		AccessRestrictions:    ua.AccessRestrictionTypeSigningRequired,
		HasAccessRestrictions: true,
	}))
	require.Equal(t, ua.StatusBadSecurityModeInsufficient, readWire(ctx, t, c, v.ID()).Status, "a channel without security")
	props = metadataProperties(ctx, t, c, uri)
	require.Equal(t, uint16(ua.AccessRestrictionTypeSigningRequired), readWire(ctx, t, c, props["DefaultAccessRestrictions"]).Value.Value())

	// Removed: as before.
	require.NoError(t, srv.SetNamespaceDefaults(uri, server.NamespaceDefaults{}))
	require.Equal(t, ua.StatusOK, readWire(ctx, t, c, v.ID()).Status)
}

// modelDefaultsDoc is a NodeSet whose Model has default RolePermissions
// (Operator: Browse and Read) and AccessRestrictions (SigningRequired).
const modelDefaultsDoc = `<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris><Uri>urn:e2e:model</Uri></NamespaceUris>
  <Models>
    <Model ModelUri="urn:e2e:model" Version="2.0" PublicationDate="2026-05-06T00:00:00Z" AccessRestrictions="1">
      <RolePermissions><RolePermission Permissions="33">i=15680</RolePermission></RolePermissions>
    </Model>
  </Models>
  <Aliases><Alias Alias="Organizes">i=35</Alias></Aliases>
  <UAVariable NodeId="ns=1;i=1" BrowseName="1:Level" DataType="i=11" AccessLevel="1">
    <DisplayName>Level</DisplayName>
    <References><Reference ReferenceType="Organizes" IsForward="false">i=85</Reference></References>
    <Value><Double xmlns="http://opcfoundation.org/UA/2008/02/Types.xsd">4.5</Double></Value>
  </UAVariable>
</UANodeSet>`

// TestModelDefaultsRestoreOverTheWire: the RolePermissions and
// AccessRestrictions of a NodeSet Model apply to its nodes (Part 6 §F.2,
// §F.3); WithModelDefaultPermissions(false) restores the old behaviour.
func TestModelDefaultsRestoreOverTheWire(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		opts []server.Option
		want ua.StatusCode
	}{
		{"model defaults", nil, ua.StatusBadSecurityModeInsufficient},
		{"restored", []server.Option{server.WithModelDefaultPermissions(false)}, ua.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := append([]server.Option{
				server.EndPoint("localhost", 0),
				server.InsecureNoSecurity(),
				server.EnableAuthMode(ua.UserTokenTypeAnonymous),
			}, tc.opts...)
			srv, err := server.New(opts...)
			require.NoError(t, err)
			require.NoError(t, srv.ImportNodeSetXML([]byte(modelDefaultsDoc)))
			require.NoError(t, srv.Start(context.Background()))
			t.Cleanup(func() { _ = srv.Close() })
			c := testutil.NewTestClient(t, srv.Endpoints()[0].EndpointURL)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			idx := ua.NewNumericNodeID(0, 0)
			for i, ns := range srv.Namespaces() {
				if ns.Name() == "urn:e2e:model" {
					idx = ua.NewNumericNodeID(uint16(i), 1)
				}
			}
			require.Equal(t, tc.want, readWire(ctx, t, c, idx).Status)
			// The NamespaceMetadata from the Model, either way.
			props := metadataProperties(ctx, t, c, "urn:e2e:model")
			require.Equal(t, "2.0", readWire(ctx, t, c, props["NamespaceVersion"]).Value.Value())
		})
	}
}

// TestNamespaceMetadataBrowsable: an anonymous session browses every
// NamespaceMetadata Object of a server with session diagnostics, whose
// namespace names sessions by string NodeIds, and reads its Properties.
func TestNamespaceMetadataBrowsable(t *testing.T) {
	t.Parallel()
	srv, url := testutil.NewTestServer(t)
	c := testutil.NewTestClient(t, url)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	resp, err := c.Browse(ctx, &ua.BrowseRequest{NodesToBrowse: []*ua.BrowseDescription{{
		NodeID: ua.NewNumericNodeID(0, id.ServerNamespaces), BrowseDirection: ua.BrowseDirectionForward,
		ReferenceTypeID: ua.NewNumericNodeID(0, id.HasComponent), IncludeSubtypes: true, ResultMask: uint32(ua.BrowseResultMaskAll),
	}}})
	require.NoError(t, err)
	require.Len(t, resp.Results[0].References, len(srv.Namespaces()), "one per namespace")
	for _, r := range resp.Results[0].References {
		props := metadataProperties(ctx, t, c, r.BrowseName.Name)
		require.Equal(t, r.BrowseName.Name, readWire(ctx, t, c, props["NamespaceUri"]).Value.Value())
	}
}
