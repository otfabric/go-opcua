// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNodeNameSpace_AddNode(t *testing.T) {
	srv := newTestServer()
	ns := NewNodeNameSpace(srv, "test")

	n := NewVariableNode(ua.NewStringNodeID(ns.ID(), "myvar"), "myvar", int32(7))
	added := ns.AddNode(n)
	assert.NotNil(t, added)

	found := ns.Node(ua.NewStringNodeID(ns.ID(), "myvar"))
	require.NotNil(t, found)
	assert.Equal(t, "myvar", found.BrowseName().Name)
}

func TestNodeNameSpace_AddNewVariableNode(t *testing.T) {
	srv := newTestServer()
	ns := NewNodeNameSpace(srv, "test")

	n := ns.AddNewVariableNode("auto_id", float32(1.5))
	assert.NotNil(t, n)

	found := ns.Node(n.ID())
	require.NotNil(t, found)
	assert.Equal(t, "auto_id", found.BrowseName().Name)
}

func TestNodeNameSpace_AddNewVariableStringNode(t *testing.T) {
	srv := newTestServer()
	ns := NewNodeNameSpace(srv, "test")

	n := ns.AddNewVariableStringNode("str_var", "hello")
	assert.NotNil(t, n)
	assert.Equal(t, "str_var", n.ID().StringID())
}

func TestNodeNameSpace_Attribute(t *testing.T) {
	srv := newTestServer()
	ns := NewNodeNameSpace(srv, "test")
	ns.AddNewVariableStringNode("myvar", int32(42))

	t.Run("read value", func(t *testing.T) {
		dv := ns.Attribute(ua.NewStringNodeID(ns.ID(), "myvar"), ua.AttributeIDValue)
		assert.Equal(t, int32(42), dv.Value.Value())
	})

	t.Run("read browse name", func(t *testing.T) {
		dv := ns.Attribute(ua.NewStringNodeID(ns.ID(), "myvar"), ua.AttributeIDBrowseName)
		qn, ok := dv.Value.Value().(*ua.QualifiedName)
		require.True(t, ok)
		assert.Equal(t, "myvar", qn.Name)
	})

	t.Run("read node id", func(t *testing.T) {
		dv := ns.Attribute(ua.NewStringNodeID(ns.ID(), "myvar"), ua.AttributeIDNodeID)
		nid, ok := dv.Value.Value().(*ua.NodeID)
		require.True(t, ok)
		assert.Equal(t, "myvar", nid.StringID())
	})

	t.Run("unknown node returns bad status", func(t *testing.T) {
		dv := ns.Attribute(ua.NewStringNodeID(ns.ID(), "nonexistent"), ua.AttributeIDValue)
		assert.Equal(t, ua.StatusBadNodeIDUnknown, dv.Status)
	})

	t.Run("no access returns denied", func(t *testing.T) {
		noAccess := NewNode(
			ua.NewStringNodeID(ns.ID(), "locked"),
			map[ua.AttributeID]*ua.DataValue{
				ua.AttributeIDAccessLevel:     DataValueFromValue(byte(ua.AccessLevelTypeNone)),
				ua.AttributeIDUserAccessLevel: DataValueFromValue(byte(ua.AccessLevelTypeNone)),
				ua.AttributeIDBrowseName:      DataValueFromValue(attrs.BrowseName("locked")),
				ua.AttributeIDNodeClass:       DataValueFromValue(uint32(ua.NodeClassVariable)),
			},
			nil,
			func() *ua.DataValue { return DataValueFromValue(int32(0)) },
		)
		ns.AddNode(noAccess)
		dv := ns.Attribute(ua.NewStringNodeID(ns.ID(), "locked"), ua.AttributeIDValue)
		assert.Equal(t, ua.StatusBadUserAccessDenied, dv.Status)
	})
}

func TestNodeNameSpace_SetAttribute(t *testing.T) {
	srv := newTestServer()
	ns := NewNodeNameSpace(srv, "test")
	ns.AddNewVariableStringNode("writable", int32(1))

	t.Run("write succeeds", func(t *testing.T) {
		sc := ns.SetAttribute(
			ua.NewStringNodeID(ns.ID(), "writable"),
			ua.AttributeIDValue,
			&ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int32(99))},
		)
		assert.Equal(t, ua.StatusOK, sc)

		dv := ns.Attribute(ua.NewStringNodeID(ns.ID(), "writable"), ua.AttributeIDValue)
		assert.Equal(t, int32(99), dv.Value.Value())
	})

	t.Run("write to unknown node", func(t *testing.T) {
		sc := ns.SetAttribute(
			ua.NewStringNodeID(ns.ID(), "ghost"),
			ua.AttributeIDValue,
			&ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int32(0))},
		)
		assert.Equal(t, ua.StatusBadNodeIDUnknown, sc)
	})
}

func TestNodeNameSpace_Browse(t *testing.T) {
	srv := newTestServer()
	ns := NewNodeNameSpace(srv, "test")
	obj := ns.Objects()
	n := ns.AddNewVariableStringNode("child", int32(1))
	obj.AddRef(n, id.HasComponent, true)

	t.Run("browse objects returns child references", func(t *testing.T) {
		result := ns.Browse(&ua.BrowseDescription{
			NodeID:          ua.NewNumericNodeID(ns.ID(), id.ObjectsFolder),
			BrowseDirection: ua.BrowseDirectionForward,
			ReferenceTypeID: ua.NewNumericNodeID(0, 0),
			IncludeSubtypes: true,
			ResultMask:      uint32(ua.BrowseResultMaskAll),
		})
		assert.Equal(t, ua.StatusGood, result.StatusCode)
		assert.NotEmpty(t, result.References)

		found := false
		for _, ref := range result.References {
			if ref.BrowseName != nil && ref.BrowseName.Name == "child" {
				found = true
				break
			}
		}
		assert.True(t, found, "should find 'child' node in browse results")
	})

	t.Run("browse unknown node", func(t *testing.T) {
		result := ns.Browse(&ua.BrowseDescription{
			NodeID:          ua.NewStringNodeID(ns.ID(), "nope"),
			BrowseDirection: ua.BrowseDirectionBoth,
			ReferenceTypeID: ua.NewNumericNodeID(0, 0),
			IncludeSubtypes: true,
		})
		assert.Equal(t, ua.StatusBadNodeIDUnknown, result.StatusCode)
	})
}

func TestNodeNameSpace_Objects(t *testing.T) {
	srv := newTestServer()
	ns := NewNodeNameSpace(srv, "test_ns")
	obj := ns.Objects()
	require.NotNil(t, obj)
	assert.Equal(t, "test_ns", obj.BrowseName().Name)
}

func TestNodeNameSpace_Name(t *testing.T) {
	srv := newTestServer()
	ns := NewNodeNameSpace(srv, "my_namespace")
	assert.Equal(t, "my_namespace", ns.Name())
}

func TestNodeNameSpace_NilNodeID(t *testing.T) {
	srv := newTestServer()
	ns := NewNodeNameSpace(srv, "test")
	assert.Nil(t, ns.Node(nil))
}

func TestNewNameSpace(t *testing.T) {
	ns := NewNameSpace("bare")
	assert.Equal(t, "bare", ns.Name())
	assert.Nil(t, ns.Node(ua.NewNumericNodeID(0, 1)))
}

func TestNodeNameSpace_DeleteNode(t *testing.T) {
	srv := newTestServer()
	ns, _ := addTestNamespace(srv)

	t.Run("delete existing node", func(t *testing.T) {
		nodeID := ua.NewStringNodeID(ns.ID(), "rw_float64")
		require.NotNil(t, ns.Node(nodeID))

		sc := ns.DeleteNode(nodeID)
		assert.Equal(t, ua.StatusGood, sc)
		assert.Nil(t, ns.Node(nodeID))
	})

	t.Run("delete nonexistent node", func(t *testing.T) {
		nodeID := ua.NewStringNodeID(ns.ID(), "totally_missing")
		sc := ns.DeleteNode(nodeID)
		assert.Equal(t, ua.StatusBadNodeIDUnknown, sc)
	})
}

func TestNodeNameSpace_Root(t *testing.T) {
	srv := newTestServer()
	ns, err := srv.Namespace(0)
	require.NoError(t, err)
	root := ns.(*NodeNameSpace).Root()
	require.NotNil(t, root)
}

func TestNodeNameSpace_ChangeNotification(t *testing.T) {
	srv := newTestServer()
	ns := NewNodeNameSpace(srv, "test")
	n := ns.AddNewVariableNode("x", int32(1))
	// Should not panic.
	ns.ChangeNotification(n.ID())
}

func TestNode_Description(t *testing.T) {
	srv := newTestServer()
	ns := NewNodeNameSpace(srv, "test")
	n := ns.AddNewVariableNode("desc_node", int32(42))

	// Before setting description.
	d := n.Description()
	require.NotNil(t, d)

	// After setting description.
	n.SetDescription("A test node", "en-US")
	d = n.Description()
	require.Equal(t, "A test node", d.Text)
	require.Equal(t, "en-US", d.Locale)
}

func TestServerNodes_RootNode(t *testing.T) {
	rn := RootNode()
	require.NotNil(t, rn)
}

func TestNode_AddObjectAndVariable(t *testing.T) {
	srv := newTestServer()
	ns := NewNodeNameSpace(srv, "test")

	// Create a parent object node and register it in the namespace.
	parentID := ua.NewStringNodeID(ns.ID(), "parent")
	parent := NewFolderNode(parentID, "parent")
	ns.AddNode(parent) // n.ns is now set by AddNode

	// AddObject: add a child object under the parent.
	childObjID := ua.NewStringNodeID(ns.ID(), "childObj")
	childObj := NewFolderNode(childObjID, "childObj")
	result := parent.AddObject(childObj)
	require.NotNil(t, result, "AddObject should return the added node")

	// The child object should now be retrievable from the namespace.
	found := ns.Node(childObjID)
	require.NotNil(t, found, "child object should be in the namespace after AddObject")
	require.Equal(t, "childObj", found.BrowseName().Name)

	// Parent should now have a reference to the child.
	hasRef := false
	for _, ref := range parent.refs {
		if ref.NodeID != nil && ref.NodeID.NodeID != nil && ref.NodeID.NodeID.StringID() == "childObj" {
			hasRef = true
			break
		}
	}
	require.True(t, hasRef, "parent should have a reference to childObj")

	// AddVariable: add a child variable under the parent.
	childVarID := ua.NewStringNodeID(ns.ID(), "childVar")
	childVar := NewVariableNode(childVarID, "childVar", int32(42))
	result2 := parent.AddVariable(childVar)
	require.NotNil(t, result2, "AddVariable should return the added node")

	// The child variable should now be retrievable from the namespace.
	found2 := ns.Node(childVarID)
	require.NotNil(t, found2, "child variable should be in the namespace after AddVariable")
	require.Equal(t, "childVar", found2.BrowseName().Name)
}

// TestAddNamespace_SetsServerRef verifies that AddNamespace injects the server
// back-reference into a NodeNameSpace so that Browse and ChangeNotification
// do not panic.
func TestAddNamespace_SetsServerRef(t *testing.T) {
	srv := newTestServer()

	// Create a namespace WITHOUT using NewNodeNameSpace (no srv).
	bare := NewNameSpace("urn:test:bare")
	idx := srv.AddNamespace(bare)
	require.Greater(t, idx, 0)

	// The srv pointer must have been injected.
	require.NotNil(t, bare.srv, "AddNamespace must set srv on NodeNameSpace")

	// Browse must not panic now that srv is set.
	require.NotPanics(t, func() {
		bare.Browse(&ua.BrowseDescription{
			NodeID:          ua.NewStringNodeID(bare.ID(), "missing"),
			BrowseDirection: ua.BrowseDirectionForward,
			ReferenceTypeID: ua.NewNumericNodeID(0, 0),
			IncludeSubtypes: true,
		})
	})

	// ChangeNotification must not panic.
	n := bare.AddNewVariableNode("x", int32(1))
	require.NotPanics(t, func() {
		bare.ChangeNotification(n.ID())
	})
}

// TestBrowse_NilTypeDefinition_NoPanic verifies that Browse does not panic
// when a referenced node cannot be resolved (as.srv.Node returns nil).
func TestBrowse_NilTypeDefinition_NoPanic(t *testing.T) {
	srv := newTestServer()
	ns := NewNodeNameSpace(srv, "urn:test:tdnil")

	// Create a node that references a non-existent node ID.
	n := NewFolderNode(ua.NewStringNodeID(ns.ID(), "root"), "root")
	// Manually append a reference to a node that doesn't exist in any namespace.
	n.refs = append(n.refs, &ua.ReferenceDescription{
		ReferenceTypeID: ua.NewNumericNodeID(0, 47), // HasComponent
		IsForward:       true,
		NodeID:          ua.NewExpandedNodeID(ua.NewNumericNodeID(99, 9999), "", 0),
		BrowseName:      &ua.QualifiedName{Name: "ghost"},
		DisplayName:     &ua.LocalizedText{Text: "ghost"},
		NodeClass:       ua.NodeClassVariable,
		TypeDefinition:  ua.NewNumericExpandedNodeID(0, 62),
	})
	ns.AddNode(n)

	require.NotPanics(t, func() {
		ns.Browse(&ua.BrowseDescription{
			NodeID:          ua.NewStringNodeID(ns.ID(), "root"),
			BrowseDirection: ua.BrowseDirectionForward,
			ReferenceTypeID: ua.NewNumericNodeID(0, 0),
			IncludeSubtypes: true,
			ResultMask:      uint32(ua.BrowseResultMaskAll),
		})
	})
}

// TestDataType_NilReferenceTypeID verifies that DataType() skips (rather than
// panicking on) a reference whose ReferenceTypeID is nil.
func TestDataType_NilReferenceTypeID(t *testing.T) {
	srv := newTestServer()
	ns := NewNodeNameSpace(srv, "urn:test:nilref")
	n := NewVariableNode(ua.NewStringNodeID(ns.ID(), "nilref"), "nilref", int32(1))
	// Inject a reference with a nil ReferenceTypeID.
	n.refs = append(n.refs, &ua.ReferenceDescription{
		ReferenceTypeID: nil,
		IsForward:       true,
		NodeID:          ua.NewNumericExpandedNodeID(0, 1),
		BrowseName:      &ua.QualifiedName{Name: "bad"},
		DisplayName:     &ua.LocalizedText{Text: "bad"},
		TypeDefinition:  ua.NewNumericExpandedNodeID(0, 62),
	})
	ns.AddNode(n)

	require.NotPanics(t, func() {
		_ = n.DataType()
	})
}
