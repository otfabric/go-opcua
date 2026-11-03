// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// writeMaskFixture is a namespace with a Variable and an Object for the
// WriteMask tests of the Write service (Part 4 §5.10.4, Part 3 §5.2.7).
type writeMaskFixture struct {
	srv *Server
	ns  *NodeNameSpace
	svc *AttributeService
	v   *Node // Variable, Int32 Value
	o   *Node // Object
}

func newWriteMaskFixture(t *testing.T) *writeMaskFixture {
	t.Helper()
	srv := newTestServer()
	ns, obj := addTestNamespace(srv)
	v := ns.AddNewVariableStringNode("wm_var", int32(1))
	obj.AddRef(v, id.HasComponent, true)
	o := ns.AddNewVariableStringNode("wm_obj", int32(0))
	require.NoError(t, o.SetAttribute(ua.AttributeIDNodeClass, DataValueFromValue(uint32(ua.NodeClassObject))))
	obj.AddRef(o, id.Organizes, true)
	return &writeMaskFixture{srv: srv, ns: ns, svc: &AttributeService{srv: srv}, v: v, o: o}
}

func (f *writeMaskFixture) write(t *testing.T, n *Node, attr ua.AttributeID, value any) ua.StatusCode {
	t.Helper()
	var dv *ua.DataValue
	if value != nil {
		dv = &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(value)}
	}
	return f.writeDV(t, n.ID(), attr, dv)
}

func (f *writeMaskFixture) writeDV(t *testing.T, nid *ua.NodeID, attr ua.AttributeID, dv *ua.DataValue) ua.StatusCode {
	t.Helper()
	resp, err := f.svc.Write(context.Background(), nil, &ua.WriteRequest{
		RequestHeader: reqHeader(),
		NodesToWrite:  []*ua.WriteValue{{NodeID: nid, AttributeID: attr, Value: dv}},
	}, 1)
	require.NoError(t, err)
	res := resp.(*ua.WriteResponse).Results
	require.Len(t, res, 1)
	return res[0]
}

func setMask(t *testing.T, n *Node, attr ua.AttributeID, m ua.AttributeWriteMask) {
	t.Helper()
	require.NoError(t, n.SetAttribute(attr, DataValueFromValue(uint32(m))))
}

func attrOf(t *testing.T, n *Node, attr ua.AttributeID) any {
	t.Helper()
	a, err := n.Attribute(attr)
	require.NoError(t, err)
	return a.Value.Value.Value()
}

// TestWrite_NonValueAttributeNeedsWriteMaskBit: without a WriteMask, or with
// one that lacks the bit of the Attribute, a Write is Bad_NotWritable and the
// Attribute is unchanged (Part 3 §5.2.7, §8.60).
func TestWrite_NonValueAttributeNeedsWriteMaskBit(t *testing.T) {
	f := newWriteMaskFixture(t)
	before := attrOf(t, f.v, ua.AttributeIDDisplayName)

	cases := []struct {
		attr  ua.AttributeID
		value any
	}{
		{ua.AttributeIDDisplayName, ua.NewLocalizedText("x")},
		{ua.AttributeIDDescription, ua.NewLocalizedText("x")},
		{ua.AttributeIDBrowseName, &ua.QualifiedName{Name: "x"}},
		{ua.AttributeIDWriteMask, uint32(0xffffffff)},
		{ua.AttributeIDDataType, ua.NewNumericNodeID(0, id.String)},
		{ua.AttributeIDValueRank, int32(1)},
		{ua.AttributeIDArrayDimensions, []uint32{2}},
		{ua.AttributeIDAccessLevel, byte(0xff)},
		{ua.AttributeIDUserAccessLevel, byte(0xff)},
		{ua.AttributeIDMinimumSamplingInterval, float64(1)},
		{ua.AttributeIDHistorizing, true},
		{ua.AttributeIDAccessRestrictions, uint16(0)},
		{ua.AttributeIDAccessLevelEx, uint32(0)},
	}
	for _, tc := range cases {
		t.Run(tc.attr.String(), func(t *testing.T) {
			require.Equal(t, ua.StatusBadNotWritable, f.write(t, f.v, tc.attr, tc.value), "no WriteMask")
		})
	}
	require.Equal(t, ua.StatusBadNotWritable, f.write(t, f.o, ua.AttributeIDEventNotifier, byte(1)))

	// A WriteMask that allows other Attributes does not allow this one.
	setMask(t, f.v, ua.AttributeIDWriteMask, ua.AttributeWriteMaskDescription)
	require.Equal(t, ua.StatusBadNotWritable, f.write(t, f.v, ua.AttributeIDDisplayName, ua.NewLocalizedText("x")))
	require.Equal(t, before, attrOf(t, f.v, ua.AttributeIDDisplayName), "a refused write must not change the Attribute")

	// A WriteMask of the wrong DataType allows nothing.
	require.NoError(t, f.v.SetAttribute(ua.AttributeIDWriteMask, DataValueFromValue(int32(-1))))
	require.Equal(t, ua.StatusBadNotWritable, f.write(t, f.v, ua.AttributeIDDescription, ua.NewLocalizedText("x")))
}

// TestWrite_NonValueAttributeWithWriteMaskBit: with the bit set the Write
// succeeds and stores the value; the AccessLevel of the Value plays no part.
func TestWrite_NonValueAttributeWithWriteMaskBit(t *testing.T) {
	f := newWriteMaskFixture(t)
	setMask(t, f.v, ua.AttributeIDWriteMask, ua.AttributeWriteMaskDisplayName|ua.AttributeWriteMaskDescription|
		ua.AttributeWriteMaskMinimumSamplingInterval|ua.AttributeWriteMaskArrayDimensions|ua.AttributeWriteMaskWriteMask)
	// The Value is read-only: AccessLevel governs only the Value (Part 3 §5.6.2).
	require.NoError(t, f.v.SetAttribute(ua.AttributeIDAccessLevel, DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead))))

	require.Equal(t, ua.StatusOK, f.write(t, f.v, ua.AttributeIDDisplayName, ua.NewLocalizedText("Renamed")))
	require.Equal(t, "Renamed", attrOf(t, f.v, ua.AttributeIDDisplayName).(*ua.LocalizedText).Text)
	require.Equal(t, ua.StatusOK, f.write(t, f.v, ua.AttributeIDDescription, ua.NewLocalizedText("desc")))
	require.Equal(t, ua.StatusOK, f.write(t, f.v, ua.AttributeIDMinimumSamplingInterval, float64(250)))
	require.Equal(t, float64(250), attrOf(t, f.v, ua.AttributeIDMinimumSamplingInterval))
	require.Equal(t, ua.StatusOK, f.write(t, f.v, ua.AttributeIDArrayDimensions, []uint32{}))

	// The Value stays read-only.
	require.Equal(t, ua.StatusBadNotWritable, f.write(t, f.v, ua.AttributeIDValue, int32(5)))

	// Writing the WriteMask itself: clearing the DisplayName bit closes it.
	require.Equal(t, ua.StatusOK, f.write(t, f.v, ua.AttributeIDWriteMask, uint32(ua.AttributeWriteMaskWriteMask)))
	require.Equal(t, ua.StatusBadNotWritable, f.write(t, f.v, ua.AttributeIDDisplayName, ua.NewLocalizedText("again")))

	setMask(t, f.o, ua.AttributeIDWriteMask, ua.AttributeWriteMaskEventNotifier)
	require.Equal(t, ua.StatusOK, f.write(t, f.o, ua.AttributeIDEventNotifier, byte(ua.EventNotifierTypeSubscribeToEvents)))
	require.Equal(t, byte(ua.EventNotifierTypeSubscribeToEvents), attrOf(t, f.o, ua.AttributeIDEventNotifier))
}

// TestWrite_NonValueAttributeUserWriteMask: a UserWriteMask on the Node
// restricts the WriteMask (Part 3 §5.2.8): Bad_UserAccessDenied.
func TestWrite_NonValueAttributeUserWriteMask(t *testing.T) {
	f := newWriteMaskFixture(t)
	setMask(t, f.v, ua.AttributeIDWriteMask, ua.AttributeWriteMaskDisplayName|ua.AttributeWriteMaskDescription)
	setMask(t, f.v, ua.AttributeIDUserWriteMask, ua.AttributeWriteMaskDescription)

	require.Equal(t, ua.StatusBadUserAccessDenied, f.write(t, f.v, ua.AttributeIDDisplayName, ua.NewLocalizedText("x")))
	require.Equal(t, ua.StatusOK, f.write(t, f.v, ua.AttributeIDDescription, ua.NewLocalizedText("x")))
	// The UserWriteMask does not open what the WriteMask closes.
	setMask(t, f.v, ua.AttributeIDUserWriteMask, ua.AttributeWriteMaskBrowseName)
	require.Equal(t, ua.StatusBadNotWritable, f.write(t, f.v, ua.AttributeIDBrowseName, &ua.QualifiedName{Name: "x"}))
}

// TestWrite_NonValueAttributeTypeMismatch: a value that is not of the
// DataType of the Attribute (Part 3 §5.2 to §5.8) is Bad_TypeMismatch, also
// when the WriteMask allows the Attribute.
func TestWrite_NonValueAttributeTypeMismatch(t *testing.T) {
	f := newWriteMaskFixture(t)
	setMask(t, f.v, ua.AttributeIDWriteMask, 0x03ffffff) // every defined bit
	setMask(t, f.o, ua.AttributeIDWriteMask, 0x03ffffff)

	cases := []struct {
		name  string
		node  *Node
		attr  ua.AttributeID
		value any
	}{
		{"EventNotifier String", f.o, ua.AttributeIDEventNotifier, "x"},
		{"EventNotifier UInt32", f.o, ua.AttributeIDEventNotifier, uint32(1)},
		{"DisplayName String", f.v, ua.AttributeIDDisplayName, "x"},
		{"Description QualifiedName", f.v, ua.AttributeIDDescription, &ua.QualifiedName{Name: "x"}},
		{"BrowseName LocalizedText", f.v, ua.AttributeIDBrowseName, ua.NewLocalizedText("x")},
		{"InverseName Int32", f.v, ua.AttributeIDInverseName, int32(1)},
		{"WriteMask Int32", f.v, ua.AttributeIDWriteMask, int32(1)},
		{"UserWriteMask Byte", f.v, ua.AttributeIDUserWriteMask, byte(1)},
		{"AccessLevelEx Byte", f.v, ua.AttributeIDAccessLevelEx, byte(1)},
		{"Historizing Int32", f.v, ua.AttributeIDHistorizing, int32(1)},
		{"AccessLevel UInt32", f.v, ua.AttributeIDAccessLevel, uint32(1)},
		{"AccessRestrictions UInt32", f.v, ua.AttributeIDAccessRestrictions, uint32(1)},
		{"DataType String", f.v, ua.AttributeIDDataType, "i=6"},
		{"ValueRank UInt32", f.v, ua.AttributeIDValueRank, uint32(1)},
		{"ArrayDimensions scalar", f.v, ua.AttributeIDArrayDimensions, uint32(1)},
		{"ArrayDimensions Int32[]", f.v, ua.AttributeIDArrayDimensions, []int32{1}},
		{"MinimumSamplingInterval Float", f.v, ua.AttributeIDMinimumSamplingInterval, float32(1)},
		{"DataTypeDefinition wrong body", f.v, ua.AttributeIDDataTypeDefinition, ua.NewExtensionObject(&ua.RolePermissionType{})},
		{"DataTypeDefinition Int32", f.v, ua.AttributeIDDataTypeDefinition, int32(1)},
		{"RolePermissions wrong body", f.v, ua.AttributeIDRolePermissions, []*ua.ExtensionObject{ua.NewExtensionObject(&ua.StructureDefinition{})}},
		{"RolePermissions scalar", f.v, ua.AttributeIDRolePermissions, ua.NewExtensionObject(&ua.RolePermissionType{})},
		{"null value", f.v, ua.AttributeIDDescription, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, ua.StatusBadTypeMismatch, f.write(t, tc.node, tc.attr, tc.value))
		})
	}
	require.Equal(t, byte(0), eventNotifierOf(f.o), "a mismatched write must not change the Attribute")

	// The right types pass.
	require.Equal(t, ua.StatusOK, f.write(t, f.v, ua.AttributeIDDataTypeDefinition, ua.NewExtensionObject(&ua.StructureDefinition{})))
	require.Equal(t, ua.StatusOK, f.write(t, f.v, ua.AttributeIDRolePermissions, []*ua.ExtensionObject{ua.NewExtensionObject(&ua.RolePermissionType{})}))
	require.Equal(t, ua.StatusOK, f.write(t, f.v, ua.AttributeIDAccessRestrictions, uint16(0)))
	require.Equal(t, ua.StatusOK, f.write(t, f.v, ua.AttributeIDValueRank, int32(-1)))
	require.Equal(t, ua.StatusOK, f.write(t, f.v, ua.AttributeIDDataType, ua.NewNumericNodeID(0, id.Int32)))
	require.Equal(t, ua.StatusOK, f.write(t, f.v, ua.AttributeIDHistorizing, false))
}

// TestWrite_NodeIdAndNodeClassNeverWritable: this server cannot rename or
// re-class a Node, so NodeId and NodeClass are Bad_NotWritable even with
// their AttributeWriteMask bits (Part 3 §8.60 bits 13 and 14) set.
// UserRolePermissions has no bit and an unknown Attribute id is
// Bad_AttributeIdInvalid (Part 4 §5.10.4).
func TestWrite_NodeIdAndNodeClassNeverWritable(t *testing.T) {
	f := newWriteMaskFixture(t)
	setMask(t, f.v, ua.AttributeIDWriteMask, 0x03ffffff)

	require.Equal(t, ua.StatusBadNotWritable, f.write(t, f.v, ua.AttributeIDNodeID, ua.NewStringNodeID(f.ns.ID(), "renamed")))
	require.Equal(t, ua.StatusBadNotWritable, f.write(t, f.v, ua.AttributeIDNodeClass, int32(ua.NodeClassObject)))
	require.Equal(t, ua.StatusBadNotWritable, f.write(t, f.v, ua.AttributeIDNodeClass, uint32(ua.NodeClassObject)))
	require.Equal(t, ua.StatusBadNotWritable, f.write(t, f.v, ua.AttributeIDUserRolePermissions, []*ua.ExtensionObject{}))
	require.Equal(t, ua.StatusBadAttributeIDInvalid, f.write(t, f.v, ua.AttributeID(99), int32(1)))
	require.Equal(t, ua.StatusBadAttributeIDInvalid, f.write(t, f.v, ua.AttributeIDInvalid, int32(1)))

	require.Equal(t, uint32(ua.NodeClassVariable), attrOf(t, f.v, ua.AttributeIDNodeClass))
	require.NotNil(t, f.ns.Node(f.v.ID()), "the Node keeps its NodeId")
	_, err := f.v.Attribute(ua.AttributeID(99))
	require.Error(t, err, "an unknown Attribute id must not be stored")
}

// TestWrite_ValueUnaffectedByWriteMask: the Value is governed by AccessLevel
// as before; a WriteMask of 0 does not close it and a full one does not open
// a read-only Value.
func TestWrite_ValueUnaffectedByWriteMask(t *testing.T) {
	f := newWriteMaskFixture(t)
	require.Equal(t, ua.StatusOK, f.write(t, f.v, ua.AttributeIDValue, int32(7)))
	require.Equal(t, int32(7), f.v.Value().Value.Value())

	setMask(t, f.v, ua.AttributeIDWriteMask, 0)
	require.Equal(t, ua.StatusOK, f.write(t, f.v, ua.AttributeIDValue, int32(8)))
	require.Equal(t, ua.StatusBadTypeMismatch, f.write(t, f.v, ua.AttributeIDValue, "eight"))

	setMask(t, f.v, ua.AttributeIDWriteMask, 0x03ffffff)
	require.NoError(t, f.v.SetAttribute(ua.AttributeIDAccessLevel, DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead))))
	require.Equal(t, ua.StatusBadNotWritable, f.write(t, f.v, ua.AttributeIDValue, int32(9)))
	require.Equal(t, int32(8), f.v.Value().Value.Value())
}

// TestWrite_NonValueAttributeUnknownNode: an unknown Node is
// Bad_NodeIdUnknown, not Bad_NotWritable.
func TestWrite_NonValueAttributeUnknownNode(t *testing.T) {
	f := newWriteMaskFixture(t)
	require.Equal(t, ua.StatusBadNodeIDUnknown, f.writeDV(t, ua.NewStringNodeID(f.ns.ID(), "missing"),
		ua.AttributeIDDisplayName, DataValueFromValue(ua.NewLocalizedText("x"))))
}

// TestWrite_MapNamespaceNonValueAttribute: the MapNamespace exposes no
// WriteMask, so only its Values are writable through the service; a Value
// write without a value is refused instead of dereferencing nil.
func TestWrite_MapNamespaceNonValueAttribute(t *testing.T) {
	srv := newTestServer()
	ns := NewMapNamespace(srv, "map_wm")
	ns.SetValue("k", int32(1))
	svc := &AttributeService{srv: srv}
	nid := ua.NewStringNodeID(ns.ID(), "k")
	write := func(attr ua.AttributeID, dv *ua.DataValue) ua.StatusCode {
		resp, err := svc.Write(context.Background(), nil, &ua.WriteRequest{
			RequestHeader: reqHeader(),
			NodesToWrite:  []*ua.WriteValue{{NodeID: nid, AttributeID: attr, Value: dv}},
		}, 1)
		require.NoError(t, err)
		return resp.(*ua.WriteResponse).Results[0]
	}

	require.Equal(t, ua.StatusBadNotWritable, write(ua.AttributeIDDisplayName, DataValueFromValue(ua.NewLocalizedText("x"))))
	require.Equal(t, ua.StatusOK, write(ua.AttributeIDValue, DataValueFromValue(int32(2))))
	require.Equal(t, int32(2), ns.GetValue("k"))
	require.Equal(t, ua.StatusBadTypeMismatch, write(ua.AttributeIDValue, &ua.DataValue{}))
	require.Equal(t, ua.StatusBadTypeMismatch, ns.SetAttribute(nid, ua.AttributeIDValue, nil))
	require.Equal(t, int32(2), ns.GetValue("k"))
}

// TestNodeNameSpace_SetAttributeAccessLevelOnlyForValue: the Go API setter
// of the namespace applies AccessLevel to the Value only; server-internal
// code can still set other Attributes of a read-only Variable.
func TestNodeNameSpace_SetAttributeAccessLevelOnlyForValue(t *testing.T) {
	f := newWriteMaskFixture(t)
	require.NoError(t, f.v.SetAttribute(ua.AttributeIDAccessLevel, DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead))))
	require.Equal(t, ua.StatusBadNotWritable, f.ns.SetAttribute(f.v.ID(), ua.AttributeIDValue, DataValueFromValue(int32(3))))
	require.Equal(t, ua.StatusOK, f.ns.SetAttribute(f.v.ID(), ua.AttributeIDDescription, DataValueFromValue(ua.NewLocalizedText("internal"))))
	require.Equal(t, "internal", attrOf(t, f.v, ua.AttributeIDDescription).(*ua.LocalizedText).Text)
}
