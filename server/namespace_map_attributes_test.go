// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMapNamespace_ValueAndDataTypeByGoType(t *testing.T) {
	srv := newTestServer()
	ns := NewMapNamespace(srv, "map_types")

	tests := []struct {
		name     string
		value    any
		want     any
		dataType uint32
	}{
		{"string", "hello", "hello", id.String},
		{"int", int(7), int64(7), id.Int64},
		{"int32", int32(-2), int32(-2), id.Int32},
		{"float32", float32(1.5), float32(1.5), id.Float},
		{"float64", float64(2.5), float64(2.5), id.Double},
		{"bool", true, true, id.Boolean},
		{"uint16", uint16(9), uint16(9), id.BaseDataType},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns.SetValue(tt.name, tt.value)
			nid := ua.NewStringNodeID(ns.ID(), tt.name)

			dv := ns.Attribute(nid, ua.AttributeIDValue)
			require.Equal(t, ua.StatusOK, dv.Status)
			require.NotZero(t, dv.EncodingMask&ua.DataValueValue)
			require.Equal(t, tt.want, dv.Value.Value())

			dv = ns.Attribute(nid, ua.AttributeIDDataType)
			require.Equal(t, ua.StatusOK, dv.Status)
			require.Equal(t, ua.NewNumericNodeID(0, tt.dataType).String(), dv.Value.NodeID().String())
		})
	}
}

func TestMapNamespace_FixedAttributes(t *testing.T) {
	srv := newTestServer()
	ns := NewMapNamespace(srv, "map_fixed")
	ns.SetValue("k", int32(1))
	nid := ua.NewStringNodeID(ns.ID(), "k")

	read := func(a ua.AttributeID) *ua.DataValue {
		dv := ns.Attribute(nid, a)
		require.NotNil(t, dv)
		require.Equal(t, ua.StatusOK, dv.Status, "attribute %v", a)
		require.NotZero(t, dv.EncodingMask&ua.DataValueValue)
		require.False(t, dv.ServerTimestamp.IsZero())
		return dv
	}

	assert.Equal(t, nid.String(), read(ua.AttributeIDNodeID).Value.NodeID().String())
	assert.Equal(t, "", read(ua.AttributeIDDescription).Value.LocalizedText().Text)
	assert.Equal(t, "k", read(ua.AttributeIDDisplayName).Value.LocalizedText().Text)
	assert.Equal(t, "k", read(ua.AttributeIDBrowseName).Value.QualifiedName().Name)
	assert.Equal(t, int32(ua.NodeClassVariable), read(ua.AttributeIDNodeClass).Value.Value())
	assert.Equal(t, byte(ua.AccessLevelTypeCurrentRead|ua.AccessLevelTypeCurrentWrite), read(ua.AttributeIDAccessLevel).Value.Value())
	assert.Equal(t, byte(0), read(ua.AttributeIDEventNotifier).Value.Value())
	assert.Equal(t, int32(-1), read(ua.AttributeIDValueRank).Value.Value())
	assert.Equal(t, []uint32{}, read(ua.AttributeIDArrayDimensions).Value.Value())

	// Attributes the map namespace does not model are reported as Bad, without a value.
	dv := ns.Attribute(nid, ua.AttributeIDInverseName)
	assert.Equal(t, ua.StatusBad, dv.Status)
	assert.Nil(t, dv.Value)

	// Reading the value of a key that was never set.
	dv = ns.Attribute(ua.NewStringNodeID(ns.ID(), "absent"), ua.AttributeIDValue)
	assert.Equal(t, ua.StatusBadNodeIDUnknown, dv.Status)
	assert.Nil(t, dv.Value)
}

func TestMapNamespace_ObjectsFolderAttributes(t *testing.T) {
	srv := newTestServer()
	ns := NewMapNamespace(srv, "map_objects")
	objects := ua.NewNumericNodeID(ns.ID(), id.ObjectsFolder)

	dv := ns.Attribute(objects, ua.AttributeIDNodeClass)
	require.NotNil(t, dv)
	require.Equal(t, int32(ua.NodeClassObject), dv.Value.Value())

	// The synthesized Objects folder has no Value attribute.
	dv = ns.Attribute(objects, ua.AttributeIDValue)
	require.Equal(t, ua.StatusBadAttributeIDInvalid, dv.Status)
	require.Nil(t, dv.Value)
}

func TestMapNamespace_SetAttributeNotifiesApplication(t *testing.T) {
	srv := newTestServer()
	ns := NewMapNamespace(srv, "map_notify")
	ns.SetValue("w", int32(1))
	nid := ua.NewStringNodeID(ns.ID(), "w")
	val := &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int32(42))}

	// A buffered channel receives the key of the written value.
	ns.ExternalNotification = make(chan string, 1)
	require.Equal(t, ua.StatusOK, ns.SetAttribute(nid, ua.AttributeIDValue, val))
	require.Equal(t, int32(42), ns.GetValue("w"))
	select {
	case key := <-ns.ExternalNotification:
		require.Equal(t, "w", key)
	default:
		t.Fatal("no external notification was queued")
	}

	// With the buffer full the write still succeeds; the notification is dropped.
	ns.ExternalNotification <- "pending"
	val2 := &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int32(43))}
	require.Equal(t, ua.StatusOK, ns.SetAttribute(nid, ua.AttributeIDValue, val2))
	require.Equal(t, int32(43), ns.GetValue("w"))
	require.Equal(t, "pending", <-ns.ExternalNotification)
	require.Empty(t, ns.ExternalNotification)

	// Writing an attribute other than Value leaves the data untouched.
	require.Equal(t, ua.StatusOK, ns.SetAttribute(nid, ua.AttributeIDDisplayName, val))
	require.Equal(t, int32(43), ns.GetValue("w"))
}
