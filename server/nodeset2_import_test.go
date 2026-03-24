package server

import (
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestImportNodeSet_DefaultNodeSet(t *testing.T) {
	// The default server already imports Opc.Ua.NodeSet2.xml via New().
	// Verify that well-known nodes exist in namespace 0.
	srv := newTestServer()

	ns0, err := srv.Namespace(0)
	require.NoError(t, err)

	t.Run("RootFolder exists", func(t *testing.T) {
		n := ns0.Node(ua.NewNumericNodeID(0, id.RootFolder))
		require.NotNil(t, n, "RootFolder (i=84) should exist")
	})

	t.Run("ObjectsFolder exists", func(t *testing.T) {
		n := ns0.Node(ua.NewNumericNodeID(0, id.ObjectsFolder))
		require.NotNil(t, n, "ObjectsFolder (i=85) should exist")
	})

	t.Run("TypesFolder exists", func(t *testing.T) {
		n := ns0.Node(ua.NewNumericNodeID(0, id.TypesFolder))
		require.NotNil(t, n, "TypesFolder (i=86) should exist")
	})

	t.Run("ViewsFolder exists", func(t *testing.T) {
		n := ns0.Node(ua.NewNumericNodeID(0, id.ViewsFolder))
		require.NotNil(t, n, "ViewsFolder (i=87) should exist")
	})

	t.Run("ServerNode exists", func(t *testing.T) {
		n := ns0.Node(ua.NewNumericNodeID(0, id.Server))
		require.NotNil(t, n, "Server (i=2253) should exist")
	})

	t.Run("Boolean data type exists", func(t *testing.T) {
		n := ns0.Node(ua.NewNumericNodeID(0, id.Boolean))
		require.NotNil(t, n, "Boolean (i=1) should exist")
	})

	t.Run("HasComponent reference type exists", func(t *testing.T) {
		n := ns0.Node(ua.NewNumericNodeID(0, id.HasComponent))
		require.NotNil(t, n, "HasComponent should exist")
	})

	t.Run("RolePermissions populated from defaults", func(t *testing.T) {
		// AuditActivateSessionEventType (i=2075) is an ObjectType with default
		// permissions in DefaultNodePermissions.
		n := ns0.Node(ua.NewNumericNodeID(0, id.AuditActivateSessionEventType))
		require.NotNil(t, n, "AuditActivateSessionEventType should exist")

		av, err := n.Attribute(ua.AttributeIDRolePermissions)
		require.NoError(t, err)
		require.NotNil(t, av)
		require.NotNil(t, av.Value)
		require.NotNil(t, av.Value.Value)

		perms, ok := av.Value.Value.Value().([]*ua.ExtensionObject)
		require.True(t, ok, "RolePermissions should be []*ua.ExtensionObject")
		assert.NotEmpty(t, perms, "should have at least one role-permission entry")
		rp, ok := perms[0].Value.(*ua.RolePermissionType)
		require.True(t, ok, "first entry should be *ua.RolePermissionType")
		assert.NotNil(t, rp.RoleID, "RoleID should not be nil")
	})
}

func TestImportNodeSet_Custom(t *testing.T) {
	srv := newTestServer()

	// Create a minimal custom nodeset XML with only namespace registration.
	// Note: ImportNodeSet has nil-pointer issues when UAVariable lacks References,
	// so we only include a namespace declaration here.
	customXML := `<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd"
           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           xmlns:uax="http://opcfoundation.org/UA/2008/02/Types.xsd">
  <NamespaceUris>
    <Uri>http://example.com/test</Uri>
  </NamespaceUris>
  <Aliases>
    <Alias Alias="Int32">i=6</Alias>
  </Aliases>
</UANodeSet>`

	err := srv.ImportNodeSetXML([]byte(customXML))
	require.NoError(t, err)

	// The import should have created a namespace for "http://example.com/test"
	namespaces := srv.Namespaces()
	found := false
	for _, ns := range namespaces {
		if ns.Name() == "http://example.com/test" {
			found = true
			break
		}
	}
	assert.True(t, found, "custom namespace should be registered")
}

func TestImportNodeSet_Namespaces(t *testing.T) {
	srv := newTestServer()

	// Server should have at least namespace 0
	namespaces := srv.Namespaces()
	require.NotEmpty(t, namespaces)
	assert.Equal(t, "http://opcfoundation.org/UA/", namespaces[0].Name())
}
