// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMapNamespace_GetSetValue(t *testing.T) {
	srv := newTestServer()
	ns := NewMapNamespace(srv, "map_ns")

	ns.SetValue("key1", int32(42))
	assert.Equal(t, int32(42), ns.GetValue("key1"))

	ns.SetValue("key1", int32(99))
	assert.Equal(t, int32(99), ns.GetValue("key1"))
}

func TestMapNamespace_Attribute(t *testing.T) {
	srv := newTestServer()
	ns := NewMapNamespace(srv, "map_ns")
	ns.SetValue("temp", float64(21.5))

	t.Run("read value", func(t *testing.T) {
		dv := ns.Attribute(ua.NewStringNodeID(ns.ID(), "temp"), ua.AttributeIDValue)
		assert.Equal(t, float64(21.5), dv.Value.Value())
	})

	t.Run("read browse name", func(t *testing.T) {
		dv := ns.Attribute(ua.NewStringNodeID(ns.ID(), "temp"), ua.AttributeIDBrowseName)
		qn, ok := dv.Value.Value().(*ua.QualifiedName)
		require.True(t, ok)
		assert.Equal(t, "temp", qn.Name)
	})

	t.Run("read node class", func(t *testing.T) {
		dv := ns.Attribute(ua.NewStringNodeID(ns.ID(), "temp"), ua.AttributeIDNodeClass)
		assert.Equal(t, int32(ua.NodeClassVariable), dv.Value.Value())
	})

	t.Run("read display name", func(t *testing.T) {
		dv := ns.Attribute(ua.NewStringNodeID(ns.ID(), "temp"), ua.AttributeIDDisplayName)
		lt, ok := dv.Value.Value().(*ua.LocalizedText)
		require.True(t, ok)
		assert.Equal(t, "temp", lt.Text)
	})

	t.Run("unknown key returns StatusBadNodeIDUnknown", func(t *testing.T) {
		dv := ns.Attribute(ua.NewStringNodeID(ns.ID(), "missing"), ua.AttributeIDValue)
		assert.Equal(t, ua.StatusBadNodeIDUnknown, dv.Status)
	})
}

func TestMapNamespace_SetAttribute(t *testing.T) {
	srv := newTestServer()
	ns := NewMapNamespace(srv, "map_ns")
	ns.SetValue("writable", int32(1))

	sc := ns.SetAttribute(
		ua.NewStringNodeID(ns.ID(), "writable"),
		ua.AttributeIDValue,
		&ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int32(42))},
	)
	assert.Equal(t, ua.StatusOK, sc)
	assert.Equal(t, int32(42), ns.GetValue("writable"))
}

func TestMapNamespace_TypeMapping(t *testing.T) {
	srv := newTestServer()
	ns := NewMapNamespace(srv, "map_ns")

	tests := []struct {
		name  string
		value any
	}{
		{"string", "hello"},
		{"int", int(1)},
		{"int32", int32(2)},
		{"float32", float32(1.5)},
		{"float64", float64(2.5)},
		{"bool", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := "type_" + tt.name
			ns.SetValue(key, tt.value)
			dv := ns.Attribute(ua.NewStringNodeID(ns.ID(), key), ua.AttributeIDValue)
			assert.NotNil(t, dv.Value)
		})
	}
}

func TestMapNamespace_Browse(t *testing.T) {
	srv := newTestServer()
	ns := NewMapNamespace(srv, "map_ns")
	ns.SetValue("a", int32(1))
	ns.SetValue("b", int32(2))

	root := ns.Browse(&ua.BrowseDescription{
		NodeID:          ua.NewNumericNodeID(0, id.RootFolder),
		BrowseDirection: ua.BrowseDirectionForward,
	})
	require.Equal(t, ua.StatusGood, root.StatusCode)
	require.Len(t, root.References, 1)

	objects := ns.Browse(&ua.BrowseDescription{
		NodeID:          ua.NewNumericNodeID(0, id.ObjectsFolder),
		BrowseDirection: ua.BrowseDirectionForward,
	})
	require.Equal(t, ua.StatusGood, objects.StatusCode)
	require.Len(t, objects.References, 2)

	unknown := ns.Browse(&ua.BrowseDescription{
		NodeID:          ua.NewNumericNodeID(0, 9999),
		BrowseDirection: ua.BrowseDirectionForward,
	})
	require.Equal(t, ua.StatusGood, unknown.StatusCode)
	require.Empty(t, unknown.References)
}

func TestMapNamespace_Name(t *testing.T) {
	srv := newTestServer()
	ns := NewMapNamespace(srv, "my_map")
	assert.Equal(t, "my_map", ns.Name())
}

func TestMapNamespace_ObjectsRootAndDelete(t *testing.T) {
	srv := newTestServer()
	ns := NewMapNamespace(srv, "my_map")

	obj := ns.Objects()
	require.NotNil(t, obj)
	require.NotNil(t, ns.Root())
	require.Same(t, obj, ns.AddNode(obj))

	nid := ua.NewStringNodeID(ns.ID(), "missing")
	require.Equal(t, ua.StatusBadNodeIDUnknown, ns.DeleteNode(nid))
	require.Nil(t, ns.Node(nid))
}

func TestMapNamespace_Attribute_NumericIDs(t *testing.T) {
	srv := newTestServer()
	ns := NewMapNamespace(srv, "map_ns_numeric")

	// IntID != 0 but == ObjectsFolder - exercises Objects() read path
	objFolderNID := ua.NewNumericNodeID(0, 85 /* id.ObjectsFolder */)
	dv := ns.Attribute(objFolderNID, ua.AttributeIDBrowseName)
	// May fail with bad attribute, but shouldn't panic.
	_ = dv

	// IntID != 0 and != ObjectsFolder - exercises BadNodeIDInvalid path
	unknownNumID := ua.NewNumericNodeID(0, 9999)
	dv2 := ns.Attribute(unknownNumID, ua.AttributeIDValue)
	require.Equal(t, ua.StatusBadNodeIDInvalid, dv2.Status)
}

func TestMapNamespace_Attribute_NodeID(t *testing.T) {
	srv := newTestServer()
	ns := NewMapNamespace(srv, "map_ns2")
	ns.SetValue("n", int32(7))
	nid := ua.NewStringNodeID(ns.ID(), "n")

	// NodeID attribute
	dv := ns.Attribute(nid, ua.AttributeIDNodeID)
	require.Equal(t, ua.StatusOK, dv.Status)
}
