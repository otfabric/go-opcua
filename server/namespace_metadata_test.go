// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/nodeset"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// metadataValue returns the value of the Property name of the
// NamespaceMetadata Object of uri, nil when it has no value, and whether
// the Property exists.
func metadataValue(t *testing.T, s *Server, uri, name string) (any, bool) {
	t.Helper()
	obj := s.namespaceMetadataNode(uri)
	require.NotNil(t, obj, "no NamespaceMetadata for %s", uri)
	p := obj.property(name)
	if p == nil {
		return nil, false
	}
	dv := p.Value()
	if dv == nil || dv.Value == nil {
		return nil, true
	}
	return dv.Value.Value(), true
}

func TestNamespaceMetadataCreated(t *testing.T) {
	s := newTestServer()
	app := NewNodeNameSpace(s, "urn:test:app")
	require.Nil(t, s.namespaceMetadataNode("urn:test:app"), "before Start")
	s.startNamespaceMetadata()
	s.startNamespaceMetadata() // twice changes nothing

	obj := s.namespaceMetadataNode("urn:test:app")
	require.NotNil(t, obj)
	require.True(t, obj.ID().Equal(ua.NewStringNodeID(app.ID(), "NamespaceMetadata")))
	require.Equal(t, &ua.QualifiedName{NamespaceIndex: app.ID(), Name: "urn:test:app"}, obj.BrowseName())
	require.True(t, obj.typeDefinition().NodeID.Equal(ua.NewNumericNodeID(0, id.NamespaceMetadataType)))
	nsObj := s.Node(ua.NewNumericNodeID(0, id.ServerNamespaces))
	require.True(t, hasReference(nsObj, obj.ID(), id.HasComponent, true))

	want := map[string]any{
		"NamespaceUri":              "urn:test:app",
		"NamespaceVersion":          "",
		"NamespacePublicationDate":  time.Time{},
		"IsNamespaceSubset":         false,
		"StaticNodeIdTypes":         []int32{},
		"StaticNumericNodeIdRange":  []string{},
		"StaticStringNodeIdPattern": "",
	}
	for name, v := range want {
		got, ok := metadataValue(t, s, "urn:test:app", name)
		require.True(t, ok, name)
		require.Equal(t, v, got, name)
	}
	refs := 0
	for _, r := range obj.refsSnapshot() {
		if r.IsForward && r.ReferenceTypeID.IntID() == id.HasProperty {
			refs++
		}
	}
	require.Equal(t, len(want), refs, "no Property twice, no defaults")
	p := obj.property("NamespaceUri")
	require.True(t, p.ID().Equal(ua.NewStringNodeID(app.ID(), "NamespaceMetadata.NamespaceUri")))

	// Namespace 0 keeps the NamespaceMetadata of the NodeSet.
	ua0 := s.namespaceMetadataNode("http://opcfoundation.org/UA/")
	require.NotNil(t, ua0)
	require.True(t, ua0.ID().Equal(ua.NewNumericNodeID(0, id.OPCUANamespaceMetadata)))

	// A namespace added after Start gets one at once.
	NewNodeNameSpace(s, "urn:test:late")
	require.NotNil(t, s.namespaceMetadataNode("urn:test:late"))

	// A MapNamespace has none.
	NewMapNamespace(s, "urn:test:map")
	require.Nil(t, s.namespaceMetadataNode("urn:test:map"))
}

func TestNamespaceMetadataTakenNodeID(t *testing.T) {
	s := newTestServer()
	ns := NewNodeNameSpace(s, "urn:test:taken")
	ns.AddNode(NewFolderNode(ua.NewStringNodeID(ns.ID(), "NamespaceMetadata"), "x"))
	s.startNamespaceMetadata()
	require.Nil(t, s.namespaceMetadataNode("urn:test:taken"))
	// A Property NodeId that is taken: a numeric one.
	ns2 := newNodeNameSpace(s, "urn:test:taken2")
	ns2.AddNode(NewFolderNode(ua.NewStringNodeID(ns2.ID(), "NamespaceMetadata.NamespaceUri"), "x"))
	require.NoError(t, s.SetNamespaceDefaults("urn:test:taken2", NamespaceDefaults{HasAccessRestrictions: true}))
	p := s.namespaceMetadataNode("urn:test:taken2").property("NamespaceUri")
	require.NotEqual(t, ua.NodeIDTypeString, p.ID().Type())
}

func TestSetNamespaceDefaults(t *testing.T) {
	s := newTestServer()
	ns := NewNodeNameSpace(s, "urn:test:defaults")
	s.startNamespaceMetadata()
	require.Error(t, s.SetNamespaceDefaults("urn:test:none", NamespaceDefaults{}))
	_, ok := s.NamespaceDefaults("urn:test:none")
	require.False(t, ok)
	_, ok = s.NamespaceDefaults("urn:test:defaults")
	require.False(t, ok)

	rp := []*ua.RolePermissionType{{RoleID: ua.RoleOperator.NodeID(), Permissions: ua.PermissionTypeBrowse | ua.PermissionTypeRead}, nil}
	d := NamespaceDefaults{RolePermissions: rp, AccessRestrictions: ua.AccessRestrictionTypeSigningRequired, HasAccessRestrictions: true}
	require.NoError(t, s.SetNamespaceDefaults("urn:test:defaults", d))
	rp[0].Permissions = 0 // the server keeps its own copy
	got, ok := s.NamespaceDefaults("urn:test:defaults")
	require.True(t, ok)
	require.Len(t, got.RolePermissions, 1)
	require.Equal(t, ua.PermissionTypeBrowse|ua.PermissionTypeRead, got.RolePermissions[0].Permissions)
	require.Equal(t, ua.AccessRestrictionTypeSigningRequired, got.AccessRestrictions)

	v, ok := metadataValue(t, s, "urn:test:defaults", "DefaultRolePermissions")
	require.True(t, ok)
	eos := v.([]*ua.ExtensionObject)
	require.Len(t, eos, 1)
	require.Equal(t, ua.PermissionTypeBrowse|ua.PermissionTypeRead, eos[0].Value.(*ua.RolePermissionType).Permissions)
	v, _ = metadataValue(t, s, "urn:test:defaults", "DefaultAccessRestrictions")
	require.Equal(t, uint16(ua.AccessRestrictionTypeSigningRequired), v)
	obj := s.namespaceMetadataNode("urn:test:defaults")
	drp := obj.property("DefaultRolePermissions")
	require.Equal(t, adminReadPermissions(), drp.rolePermissions)
	durp := obj.property("DefaultUserRolePermissions")
	require.True(t, s.readsSessionRoles(durp.ID(), ua.AttributeIDValue))
	require.False(t, s.readsSessionRoles(drp.ID(), ua.AttributeIDValue))
	require.False(t, s.readsSessionRoles(drp.ID(), ua.AttributeIDDescription))
	require.False(t, s.readsSessionRoles(ua.NewStringNodeID(ns.ID(), "missing"), ua.AttributeIDValue))
	require.False(t, s.readsSessionRoles(nil, ua.AttributeIDValue))
	require.True(t, s.readsSessionRoles(nil, ua.AttributeIDUserRolePermissions))

	// The value of DefaultUserRolePermissions as a session reads it.
	anon := &session{roles: []*ua.NodeID{ua.RoleAnonymous.NodeID()}}
	op := &session{roles: []*ua.NodeID{ua.RoleOperator.NodeID()}}
	require.Empty(t, forSessionRoles(durp.Value(), anon).Value.Value())
	require.Len(t, forSessionRoles(durp.Value(), op).Value.Value(), 1)

	// Removing the defaults removes the values, not the Properties.
	require.NoError(t, s.SetNamespaceDefaults("urn:test:defaults", NamespaceDefaults{}))
	_, ok = s.NamespaceDefaults("urn:test:defaults")
	require.False(t, ok)
	for _, name := range []string{"DefaultRolePermissions", "DefaultUserRolePermissions", "DefaultAccessRestrictions"} {
		v, exists := metadataValue(t, s, "urn:test:defaults", name)
		require.True(t, exists, name)
		require.Nil(t, v, name)
	}
	// Removing them again changes nothing.
	require.NoError(t, s.SetNamespaceDefaults("urn:test:defaults", NamespaceDefaults{}))
}

func TestNamespaceDefaultRolePermissions(t *testing.T) {
	s := newTestServer()
	ns := NewNodeNameSpace(s, "urn:test:rbac")
	ac := NewRBACAccessController(s)
	ctx := context.Background()
	plain := ns.AddNewVariableStringNode("plain", int32(1))
	own := ns.AddNewVariableStringNode("own", int32(2))
	own.rolePermissions = []*ua.RolePermissionType{{RoleID: ua.RoleAnonymous.NodeID(), Permissions: ua.PermissionTypeBrowse | ua.PermissionTypeRead}}
	exempt := NewVariableNode(ua.NewStringNodeID(ns.ID(), "exempt"), "exempt", int32(3))
	exempt.noDefaultPermissions = true
	ns.AddNode(exempt)
	anon := (&session{roles: []*ua.NodeID{ua.RoleAnonymous.NodeID()}}).handle()
	op := (&session{roles: []*ua.NodeID{ua.RoleOperator.NodeID()}}).handle()
	del := &ua.DeleteNodesItem{NodeID: plain.ID()}

	// Without defaults: as before.
	require.Equal(t, ua.StatusOK, ac.CheckRead(ctx, anon, plain.ID()))
	require.Equal(t, ua.StatusBadUserAccessDenied, ac.CheckDeleteNodes(ctx, op, del))

	require.NoError(t, s.SetNamespaceDefaults("urn:test:rbac", NamespaceDefaults{RolePermissions: []*ua.RolePermissionType{
		{RoleID: ua.RoleOperator.NodeID(), Permissions: ua.PermissionTypeBrowse | ua.PermissionTypeRead | ua.PermissionTypeDeleteNode},
	}}))
	require.Equal(t, ua.StatusBadUserAccessDenied, ac.CheckRead(ctx, anon, plain.ID()))
	require.Equal(t, ua.StatusBadUserAccessDenied, ac.CheckBrowse(ctx, anon, plain.ID()))
	require.Equal(t, ua.StatusOK, ac.CheckRead(ctx, op, plain.ID()))
	require.Equal(t, ua.StatusBadUserAccessDenied, ac.CheckWrite(ctx, op, plain.ID()))
	require.Equal(t, ua.StatusOK, ac.CheckDeleteNodes(ctx, op, del))
	// The node's own RolePermissions decide, and an exempt node is allowed.
	require.Equal(t, ua.StatusOK, ac.CheckRead(ctx, anon, own.ID()))
	require.Equal(t, ua.StatusBadUserAccessDenied, ac.CheckRead(ctx, op, own.ID()))
	require.Equal(t, ua.StatusOK, ac.CheckRead(ctx, anon, exempt.ID()))
	require.Equal(t, ua.StatusBadUserAccessDenied, ac.CheckDeleteNodes(ctx, op, &ua.DeleteNodesItem{NodeID: exempt.ID()}))
	// Other namespaces are not affected.
	require.Equal(t, ua.StatusOK, ac.CheckRead(ctx, anon, ua.NewNumericNodeID(0, id.ServerServerStatus)))

	// Empty defaults grant nothing.
	require.NoError(t, s.SetNamespaceDefaults("urn:test:rbac", NamespaceDefaults{RolePermissions: []*ua.RolePermissionType{}}))
	require.Equal(t, ua.StatusBadUserAccessDenied, ac.CheckRead(ctx, op, plain.ID()))

	// Removed: allowed again.
	require.NoError(t, s.SetNamespaceDefaults("urn:test:rbac", NamespaceDefaults{}))
	require.Equal(t, ua.StatusOK, ac.CheckRead(ctx, anon, plain.ID()))
}

func TestNamespaceDefaultAccessRestrictions(t *testing.T) {
	s := newTestServer()
	ns := NewNodeNameSpace(s, "urn:test:ar")
	plain := ns.AddNewVariableStringNode("plain", int32(1))
	own := ns.AddNewVariableStringNode("own", int32(2))
	require.NoError(t, own.SetAttribute(ua.AttributeIDAccessRestrictions, DataValueFromValue(uint16(0))))
	inherit := NewVariableNode(ua.NewStringNodeID(ns.ID(), "inherit"), "inherit", int32(3))
	require.NoError(t, inherit.SetAttribute(ua.AttributeIDAccessRestrictions, DataValueFromValue(uint16(0))))
	inherit.inheritRestrictions = true
	ns.AddNode(inherit)
	odd := ns.AddNewVariableStringNode("odd", int32(4))
	require.NoError(t, odd.SetAttribute(ua.AttributeIDAccessRestrictions, DataValueFromValue("x")))
	none := ua.MessageSecurityModeNone

	for _, n := range []*Node{plain, own, inherit, odd} {
		require.Equal(t, ua.StatusOK, accessRestrictionsFor(none, n))
	}
	require.NoError(t, s.SetNamespaceDefaults("urn:test:ar", NamespaceDefaults{
		AccessRestrictions:    ua.AccessRestrictionTypeSigningRequired | ua.AccessRestrictionTypeApplyRestrictionsToBrowse,
		HasAccessRestrictions: true,
	}))
	require.Equal(t, ua.StatusBadSecurityModeInsufficient, accessRestrictionsFor(none, plain))
	require.Equal(t, ua.StatusOK, accessRestrictionsFor(ua.MessageSecurityModeSign, plain))
	require.Equal(t, ua.StatusBadSecurityModeInsufficient, accessRestrictionsFor(none, inherit))
	require.Equal(t, ua.StatusOK, accessRestrictionsFor(none, own), "its own AccessRestrictions")
	require.Equal(t, ua.StatusOK, accessRestrictionsFor(none, odd))
	require.Equal(t, ua.StatusBadSecurityModeInsufficient, checkAccessRestrictionsForBrowse(nil, plain))
	require.Equal(t, ua.StatusOK, checkAccessRestrictionsForBrowse(nil, own))
	// A node in no namespace has no defaults.
	require.Equal(t, ua.StatusOK, accessRestrictionsFor(none, NewVariableNode(ua.NewStringNodeID(ns.ID(), "free"), "free", 1)))
}

// modelNodeSet is a NodeSet with a Model that has default RolePermissions
// and AccessRestrictions, without a NamespaceMetadata Object.
const modelNodeSet = `<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <Aliases><Alias Alias="Organizes">i=35</Alias><Alias Alias="HasProperty">i=46</Alias><Alias Alias="HasComponent">i=47</Alias><Alias Alias="HasTypeDefinition">i=40</Alias></Aliases>
  <NamespaceUris><Uri>urn:test:model</Uri></NamespaceUris>
  <Models>
    <Model ModelUri="urn:test:model" Version="1.02" PublicationDate="2026-03-04T00:00:00Z" ModelVersion="1.2.0" AccessRestrictions="1">
      <RolePermissions>
        <RolePermission Permissions="33">i=15680</RolePermission>
      </RolePermissions>
    </Model>
  </Models>
  <UAObject NodeId="ns=1;i=1" BrowseName="1:Plain">
    <DisplayName>Plain</DisplayName>
    <References><Reference ReferenceType="Organizes" IsForward="false">i=85</Reference></References>
  </UAObject>
  <UAObject NodeId="ns=1;i=2" BrowseName="1:Exempt" HasNoPermissions="true" AccessRestrictions="0">
    <DisplayName>Exempt</DisplayName>
    <References><Reference ReferenceType="Organizes" IsForward="false">i=85</Reference></References>
  </UAObject>
</UANodeSet>`

func TestModelDefaultsFromImport(t *testing.T) {
	s := newTestServer()
	require.NoError(t, s.ImportNodeSetXML([]byte(modelNodeSet)))
	d, ok := s.NamespaceDefaults("urn:test:model")
	require.True(t, ok)
	require.Len(t, d.RolePermissions, 1)
	require.True(t, ua.RoleOperator.NodeID().Equal(d.RolePermissions[0].RoleID))
	require.Equal(t, ua.PermissionTypeBrowse|ua.PermissionTypeRead, d.RolePermissions[0].Permissions)
	require.True(t, d.HasAccessRestrictions)
	require.Equal(t, ua.AccessRestrictionTypeSigningRequired, d.AccessRestrictions)

	// The import created the NamespaceMetadata the NodeSet lacks, from its
	// Model.
	for name, v := range map[string]any{
		"NamespaceUri":             "urn:test:model",
		"NamespaceVersion":         "1.02",
		"NamespacePublicationDate": time.Date(2026, 3, 4, 0, 0, 0, 0, time.UTC),
		"IsNamespaceSubset":        true,
		"ModelVersion":             "1.2.0",
	} {
		got, ok := metadataValue(t, s, "urn:test:model", name)
		require.True(t, ok, name)
		require.Equal(t, v, got, name)
	}

	idx, _ := s.namespaceLookup("urn:test:model")
	plain, exempt := s.Node(ua.NewNumericNodeID(idx, 1)), s.Node(ua.NewNumericNodeID(idx, 2))
	ac := NewRBACAccessController(s)
	ctx := context.Background()
	anon := (&session{roles: []*ua.NodeID{ua.RoleAnonymous.NodeID()}}).handle()
	require.Equal(t, ua.StatusBadUserAccessDenied, ac.CheckRead(ctx, anon, plain.ID()))
	require.Equal(t, ua.StatusOK, ac.CheckRead(ctx, anon, exempt.ID()), "HasNoPermissions")
	require.Equal(t, ua.StatusBadSecurityModeInsufficient, accessRestrictionsFor(ua.MessageSecurityModeNone, plain))
	require.Equal(t, ua.StatusOK, accessRestrictionsFor(ua.MessageSecurityModeNone, exempt), "AccessRestrictions of its own")

	// SetNamespaceDefaults takes their place, also for a later import.
	require.NoError(t, s.SetNamespaceDefaults("urn:test:model", NamespaceDefaults{HasAccessRestrictions: true}))
	require.NoError(t, s.ImportNodeSetXML([]byte(modelNodeSet)))
	d, _ = s.NamespaceDefaults("urn:test:model")
	require.Nil(t, d.RolePermissions)
	require.Equal(t, ua.StatusOK, ac.CheckRead(ctx, anon, plain.ID()))
}

func TestModelDefaultsFromImportOff(t *testing.T) {
	s := newTestServer()
	require.NoError(t, WithModelDefaultPermissions(false)(s.cfg))
	s.startNamespaceMetadata()
	require.NoError(t, s.ImportNodeSetXML([]byte(modelNodeSet)))
	_, ok := s.NamespaceDefaults("urn:test:model")
	require.False(t, ok)
	idx, _ := s.namespaceLookup("urn:test:model")
	plain := s.Node(ua.NewNumericNodeID(idx, 1))
	anon := (&session{roles: []*ua.NodeID{ua.RoleAnonymous.NodeID()}}).handle()
	require.Equal(t, ua.StatusOK, NewRBACAccessController(s).CheckRead(context.Background(), anon, plain.ID()))
	require.Equal(t, ua.StatusOK, accessRestrictionsFor(ua.MessageSecurityModeNone, plain))
	// The NamespaceMetadata is there all the same, without defaults.
	_, ok = metadataValue(t, s, "urn:test:model", "DefaultRolePermissions")
	require.False(t, ok)
}

// A Model without defaults, and one whose role cannot be read, and a
// namespace whose NamespaceMetadata the NodeSet brings.
func TestModelDefaultsEdgeCases(t *testing.T) {
	s := newTestServer()
	doc := `<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <Aliases><Alias Alias="Organizes">i=35</Alias><Alias Alias="HasProperty">i=46</Alias><Alias Alias="HasComponent">i=47</Alias><Alias Alias="HasTypeDefinition">i=40</Alias></Aliases>
  <NamespaceUris><Uri>urn:test:a</Uri><Uri>urn:test:b</Uri></NamespaceUris>
  <Models>
    <Model ModelUri="urn:test:a" Version="1"/>
    <Model ModelUri="urn:test:b" PublicationDate="not a date">
      <RolePermissions><RolePermission Permissions="1">NoSuchRole</RolePermission></RolePermissions>
    </Model>
    <Model ModelUri="urn:test:unknown"/>
  </Models>
  <UAObject NodeId="ns=1;i=1" BrowseName="1:urn:test:a">
    <DisplayName>urn:test:a</DisplayName>
    <References>
      <Reference ReferenceType="HasComponent" IsForward="false">i=11715</Reference>
      <Reference ReferenceType="HasTypeDefinition">i=11616</Reference>
      <Reference ReferenceType="HasProperty">ns=1;i=2</Reference>
    </References>
  </UAObject>
  <UAVariable NodeId="ns=1;i=2" BrowseName="NamespaceVersion" ParentNodeId="ns=1;i=1" DataType="i=12">
    <DisplayName>NamespaceVersion</DisplayName>
    <Value><String xmlns="http://opcfoundation.org/UA/2008/02/Types.xsd">0.9</String></Value>
  </UAVariable>
</UANodeSet>`
	require.NoError(t, s.ImportNodeSetXML([]byte(doc)))
	_, ok := s.NamespaceDefaults("urn:test:a")
	require.False(t, ok)
	// The NamespaceMetadata of the NodeSet, found by its BrowseName, keeps
	// its NamespaceVersion and gets the mandatory Properties it lacks.
	obj := s.namespaceMetadataNode("urn:test:a")
	require.True(t, obj.ID().Equal(ua.NewNumericNodeID(1, 1)))
	v, _ := metadataValue(t, s, "urn:test:a", "NamespaceVersion")
	require.Equal(t, "0.9", v)
	v, _ = metadataValue(t, s, "urn:test:a", "IsNamespaceSubset")
	require.Equal(t, true, v)
	require.NotEqual(t, ua.NodeIDTypeString, obj.property("NamespaceUri").ID().Type())

	// A role that is no NodeId and no well-known role grants nothing.
	d, ok := s.NamespaceDefaults("urn:test:b")
	require.True(t, ok)
	require.NotNil(t, d.RolePermissions)
	require.Empty(t, d.RolePermissions)
	v, _ = metadataValue(t, s, "urn:test:b", "NamespacePublicationDate")
	require.Equal(t, time.Time{}, v)
	require.Empty(t, importRoles([]nodeset.RolePermission{{Role: "ns=x;i=?"}}))
}

func TestNamespaceDefaultsConcurrent(t *testing.T) {
	s := newTestServer()
	ns := NewNodeNameSpace(s, "urn:test:race")
	s.startNamespaceMetadata()
	n := ns.AddNewVariableStringNode("v", int32(1))
	ac := NewRBACAccessController(s)
	anon := (&session{roles: []*ua.NodeID{ua.RoleAnonymous.NodeID()}}).handle()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			d := NamespaceDefaults{}
			if i%2 == 0 {
				d = NamespaceDefaults{RolePermissions: []*ua.RolePermissionType{}, HasAccessRestrictions: true, AccessRestrictions: ua.AccessRestrictionTypeSigningRequired}
			}
			_ = s.SetNamespaceDefaults("urn:test:race", d)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			_ = ac.CheckRead(context.Background(), anon, n.ID())
			_ = accessRestrictionsFor(ua.MessageSecurityModeNone, n)
			_, _ = s.NamespaceDefaults("urn:test:race")
		}
	}()
	wg.Wait()
}

// The guards of the NamespaceMetadata code: a namespace that is not there
// or no NodeNameSpace, a node in no namespace, a Reference of the
// Namespaces Object to a node that is not there, and a server without the
// Namespaces Object.
func TestNamespaceMetadataGuards(t *testing.T) {
	s := newTestServer()
	s.nsMeta.mu.Lock()
	s.publishNamespaceMetadata(999, nil)
	s.nsMeta.mu.Unlock()
	require.Nil(t, s.createNamespaceMetadata(NewMapNamespace(s, "urn:test:guard-map")))

	loose := NewFolderNode(ua.NewStringNodeID(1, "loose"), "loose")
	s.fillMetadata(loose, propNamespaceURI, "urn:test:loose")
	s.setDefault(loose, propDefaultRestrictions, true, uint16(1), nil)
	require.Nil(t, loose.property(propNamespaceURI.name))
	require.Nil(t, loose.property(propDefaultRestrictions.name))

	nsObj := s.Node(ua.NewNumericNodeID(0, id.ServerNamespaces))
	nsObj.AddRef(NewFolderNode(ua.NewStringNodeID(0, "missing"), "missing"), id.HasComponent, true)
	require.Nil(t, s.namespaceMetadataNode("urn:test:none"))

	ns0, ok := s.namespaces[0].(*NodeNameSpace)
	require.True(t, ok)
	require.Equal(t, ua.StatusGood, ns0.DeleteNode(nsObj.ID()))
	require.Nil(t, s.namespaceMetadataNode("http://opcfoundation.org/UA/"))
	require.Nil(t, s.createNamespaceMetadata(NewNodeNameSpace(s, "urn:test:guard")))
}
