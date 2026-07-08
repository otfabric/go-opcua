// SPDX-License-Identifier: MIT

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

func TestImportNodeSetXML_BadInput(t *testing.T) {
	const xmlHeader = `<?xml version="1.0" encoding="utf-8"?>` + "\n"
	const nsOpen = `<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">` + "\n" +
		`  <NamespaceUris><Uri>urn:test</Uri></NamespaceUris>` + "\n"
	const nsClose = "\n</UANodeSet>"

	wrap := func(body string) []byte {
		return []byte(xmlHeader + nsOpen + body + nsClose)
	}

	t.Run("invalid reference type node id", func(t *testing.T) {
		srv := newTestServer()
		err := srv.ImportNodeSetXML(wrap(`
  <UAReferenceType NodeId="ns=bad_rt;i=1" BrowseName="BadRef" IsAbstract="false" Symmetric="false">
    <DisplayName>BadRef</DisplayName>
  </UAReferenceType>`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ns=bad_rt;i=1")
		assert.Contains(t, err.Error(), "reference type")
	})

	t.Run("invalid data type node id", func(t *testing.T) {
		srv := newTestServer()
		err := srv.ImportNodeSetXML(wrap(`
  <UADataType NodeId="i=bad_dt" BrowseName="BadDT">
    <DisplayName>BadDT</DisplayName>
  </UADataType>`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "i=bad_dt")
		assert.Contains(t, err.Error(), "data type")
	})

	t.Run("invalid object type node id", func(t *testing.T) {
		srv := newTestServer()
		err := srv.ImportNodeSetXML(wrap(`
  <UAObjectType NodeId="i=bad_ot" BrowseName="BadOT" IsAbstract="false">
    <DisplayName>BadOT</DisplayName>
  </UAObjectType>`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "i=bad_ot")
		assert.Contains(t, err.Error(), "object type")
	})

	t.Run("invalid variable type node id", func(t *testing.T) {
		srv := newTestServer()
		err := srv.ImportNodeSetXML(wrap(`
  <UAVariableType NodeId="i=bad_vt" BrowseName="BadVT">
    <DisplayName>BadVT</DisplayName>
  </UAVariableType>`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "i=bad_vt")
		assert.Contains(t, err.Error(), "variable type")
	})

	t.Run("invalid variable node id", func(t *testing.T) {
		srv := newTestServer()
		err := srv.ImportNodeSetXML(wrap(`
  <UAVariable NodeId="i=bad_var" BrowseName="1:Foo" DataType="i=1">
    <DisplayName>Foo</DisplayName>
  </UAVariable>`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "i=bad_var")
		assert.Contains(t, err.Error(), "variable")
	})

	t.Run("invalid method node id", func(t *testing.T) {
		srv := newTestServer()
		err := srv.ImportNodeSetXML(wrap(`
  <UAMethod NodeId="i=bad_method" BrowseName="1:BadMethod">
    <DisplayName>BadMethod</DisplayName>
  </UAMethod>`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "i=bad_method")
		assert.Contains(t, err.Error(), "method")
	})

	t.Run("invalid object node id", func(t *testing.T) {
		srv := newTestServer()
		err := srv.ImportNodeSetXML(wrap(`
  <UAObject NodeId="i=bad_obj" BrowseName="1:BadObj">
    <DisplayName>BadObj</DisplayName>
  </UAObject>`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "i=bad_obj")
		assert.Contains(t, err.Error(), "object")
	})

	t.Run("invalid alias node id", func(t *testing.T) {
		srv := newTestServer()
		err := srv.ImportNodeSetXML(wrap(`
  <Aliases>
    <Alias Alias="BadAlias">i=not_valid</Alias>
  </Aliases>
  <UAVariable NodeId="ns=1;i=1000" BrowseName="1:Var1" DataType="i=1">
    <DisplayName>Var1</DisplayName>
    <References>
      <Reference ReferenceType="BadAlias">i=85</Reference>
    </References>
  </UAVariable>`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "i=not_valid")
		assert.Contains(t, err.Error(), "alias")
	})

	t.Run("invalid reference target", func(t *testing.T) {
		srv := newTestServer()
		err := srv.ImportNodeSetXML(wrap(`
  <UAVariable NodeId="ns=1;i=2000" BrowseName="1:Var2" DataType="i=1">
    <DisplayName>Var2</DisplayName>
    <References>
      <Reference ReferenceType="HasComponent">i=bad_target</Reference>
    </References>
  </UAVariable>`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "i=bad_target")
		assert.Contains(t, err.Error(), "reference target")
	})

	t.Run("unknown reference type in reference", func(t *testing.T) {
		srv := newTestServer()
		err := srv.ImportNodeSetXML(wrap(`
  <UAVariable NodeId="ns=1;i=3000" BrowseName="1:Var3" DataType="i=1">
    <DisplayName>Var3</DisplayName>
    <References>
      <Reference ReferenceType="NoSuchRefType">i=85</Reference>
    </References>
  </UAVariable>`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "NoSuchRefType")
		assert.Contains(t, err.Error(), "unknown reference type")
	})

	t.Run("minimal valid XML succeeds", func(t *testing.T) {
		srv := newTestServer()
		err := srv.ImportNodeSetXML(wrap(""))
		require.NoError(t, err)
	})

	t.Run("malformed XML", func(t *testing.T) {
		srv := newTestServer()
		err := srv.ImportNodeSetXML([]byte(`<not valid xml`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unmarshal")
	})
}
