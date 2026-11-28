// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// readAttrs reads attributes of nid with the Read service.
func readAttrs(t *testing.T, svc *AttributeService, nid *ua.NodeID, attrs ...ua.AttributeID) []*ua.DataValue {
	t.Helper()
	req := &ua.ReadRequest{RequestHeader: reqHeader()}
	for _, a := range attrs {
		req.NodesToRead = append(req.NodesToRead, &ua.ReadValueID{NodeID: nid, AttributeID: a})
	}
	resp, err := svc.Read(context.Background(), nil, req, 1)
	require.NoError(t, err)
	return resp.(*ua.ReadResponse).Results
}

// TestVariableMandatoryAttributes: a Variable made with NewVariableNode
// reports the Mandatory Attributes AccessLevel, UserAccessLevel and
// Historizing and AccessLevelEx (Part 3 §5.6.2, Table 13) with the values
// the server applies: read and write access, no history, atomic Read and
// Write, IndexRange Writes supported.
func TestVariableMandatoryAttributes(t *testing.T) {
	srv := newTestServer()
	ns, obj := addTestNamespace(srv)
	v := ns.AddNewVariableStringNode("plain", []int32{1, 2, 3})
	obj.AddRef(v, id.HasComponent, true)
	svc := &AttributeService{srv: srv}

	got := readAttrs(t, svc, v.ID(), ua.AttributeIDAccessLevel, ua.AttributeIDUserAccessLevel, ua.AttributeIDHistorizing, ua.AttributeIDAccessLevelEx)
	for i, want := range []any{
		byte(ua.AccessLevelTypeCurrentRead | ua.AccessLevelTypeCurrentWrite),
		byte(ua.AccessLevelTypeCurrentRead | ua.AccessLevelTypeCurrentWrite),
		false,
		uint32(ua.AccessLevelExTypeCurrentRead | ua.AccessLevelExTypeCurrentWrite),
	} {
		require.Equal(t, ua.StatusOK, got[i].Status, "attribute %d", i)
		require.Equal(t, want, got[i].Value.Value(), "attribute %d", i)
	}
	// What the attributes say is what the server does: the Value is read
	// and written.
	require.True(t, v.Access(ua.AccessLevelTypeCurrentRead))
	require.True(t, v.Access(ua.AccessLevelTypeCurrentWrite))

	// Stored attributes are reported as they are; the low byte of the
	// AccessLevelEx is the AccessLevel, and of its other bits only those
	// the server honours.
	ro := ns.AddNewVariableStringNode("stored", int32(1))
	obj.AddRef(ro, id.HasComponent, true)
	require.NoError(t, ro.SetAttribute(ua.AttributeIDAccessLevel, DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead|ua.AccessLevelTypeHistoryRead))))
	require.NoError(t, ro.SetAttribute(ua.AttributeIDUserAccessLevel, DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead))))
	require.NoError(t, ro.SetAttribute(ua.AttributeIDHistorizing, DataValueFromValue(true)))
	require.NoError(t, ro.SetAttribute(ua.AttributeIDAccessLevelEx, DataValueFromValue(uint32(0xFFFFFF02))))
	got = readAttrs(t, svc, ro.ID(), ua.AttributeIDAccessLevel, ua.AttributeIDUserAccessLevel, ua.AttributeIDHistorizing, ua.AttributeIDAccessLevelEx)
	require.Equal(t, byte(ua.AccessLevelTypeCurrentRead|ua.AccessLevelTypeHistoryRead), got[0].Value.Value())
	require.Equal(t, byte(ua.AccessLevelTypeCurrentRead), got[1].Value.Value())
	require.Equal(t, true, got[2].Value.Value())
	require.Equal(t, uint32(ua.AccessLevelExTypeCurrentRead|ua.AccessLevelExTypeHistoryRead|
		ua.AccessLevelExTypeNonatomicRead|ua.AccessLevelExTypeNonatomicWrite|ua.AccessLevelExTypeWriteFullArrayOnly), got[3].Value.Value(),
		"NoSubDataTypes, NonVolatile, Constant and the reserved bits are not served")

	// An AccessLevel of the wrong type grants nothing (Node.access) and is
	// reported as none; an AccessLevelEx of the wrong type sets no bit.
	odd := ns.AddNewVariableStringNode("odd", int32(1))
	obj.AddRef(odd, id.HasComponent, true)
	require.NoError(t, odd.SetAttribute(ua.AttributeIDAccessLevelEx, DataValueFromValue("not a UInt32")))
	odd.mu.Lock()
	odd.attr[ua.AttributeIDAccessLevel] = &ua.DataValue{}
	odd.mu.Unlock()
	require.Equal(t, byte(0), variableAttributeValue(t, odd, ua.AttributeIDAccessLevel))
	require.Equal(t, uint32(0), variableAttributeValue(t, odd, ua.AttributeIDAccessLevelEx))
	odd.mu.Lock()
	odd.attr[ua.AttributeIDAccessLevel] = DataValueFromValue("not a Byte")
	odd.mu.Unlock()
	require.Equal(t, byte(0), variableAttributeValue(t, odd, ua.AttributeIDAccessLevel))
	require.False(t, odd.Access(ua.AccessLevelTypeCurrentRead))

	// Not a Variable, or another Attribute: the stored attribute decides.
	_, ok := variableAttribute(obj, ua.AttributeIDAccessLevel)
	require.False(t, ok)
	_, ok = variableAttribute(v, ua.AttributeIDDisplayName)
	require.False(t, ok)
	got = readAttrs(t, svc, obj.ID(), ua.AttributeIDAccessLevelEx)
	require.Equal(t, ua.StatusBadAttributeIDInvalid, got[0].Status, "an Object has no AccessLevelEx")
}

func variableAttributeValue(t *testing.T, n *Node, attr ua.AttributeID) any {
	t.Helper()
	dv, ok := variableAttribute(n, attr)
	require.True(t, ok)
	return dv.Value.Value()
}

// TestWrite_WriteFullArrayOnly: a Variable whose AccessLevelEx sets
// WriteFullArrayOnly refuses a Write with an IndexRange with
// Bad_WriteNotSupported and takes the whole array (Part 3 §8.58, Part 4
// §5.11.4.2); without the bit the IndexRange is merged.
func TestWrite_WriteFullArrayOnly(t *testing.T) {
	srv := newTestServer()
	ns, obj := addTestNamespace(srv)
	full := ns.AddNewVariableStringNode("full", []int32{1, 2, 3})
	obj.AddRef(full, id.HasComponent, true)
	require.NoError(t, full.SetAttribute(ua.AttributeIDAccessLevelEx, DataValueFromValue(uint32(ua.AccessLevelExTypeWriteFullArrayOnly))))
	part := ns.AddNewVariableStringNode("part", []int32{1, 2, 3})
	obj.AddRef(part, id.HasComponent, true)
	svc := &AttributeService{srv: srv}

	write := func(nid *ua.NodeID, rng string, v []int32) ua.StatusCode {
		t.Helper()
		resp, err := svc.Write(context.Background(), nil, &ua.WriteRequest{
			RequestHeader: reqHeader(),
			NodesToWrite: []*ua.WriteValue{{
				NodeID: nid, AttributeID: ua.AttributeIDValue, IndexRange: rng,
				Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)},
			}},
		}, 1)
		require.NoError(t, err)
		return resp.(*ua.WriteResponse).Results[0]
	}
	require.Equal(t, ua.StatusBadWriteNotSupported, write(full.ID(), "1", []int32{9}))
	require.Equal(t, []int32{1, 2, 3}, readAttrs(t, svc, full.ID(), ua.AttributeIDValue)[0].Value.Value(), "nothing written")
	require.Equal(t, ua.StatusOK, write(full.ID(), "", []int32{7, 8}))
	require.Equal(t, []int32{7, 8}, readAttrs(t, svc, full.ID(), ua.AttributeIDValue)[0].Value.Value())
	require.Equal(t, uint32(ua.AccessLevelExTypeCurrentRead|ua.AccessLevelExTypeCurrentWrite|ua.AccessLevelExTypeWriteFullArrayOnly),
		readAttrs(t, svc, full.ID(), ua.AttributeIDAccessLevelEx)[0].Value.Value())

	require.Equal(t, ua.StatusOK, write(part.ID(), "1", []int32{9}))
	require.Equal(t, []int32{1, 9, 3}, readAttrs(t, svc, part.ID(), ua.AttributeIDValue)[0].Value.Value())
}
