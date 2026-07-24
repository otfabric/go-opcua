// SPDX-License-Identifier: MIT

// WP5A – Registered custom DataType tests (Go↔Go, no peer adapter required).
//
// These tests verify that Go types registered with ua.RegisterExtensionObject
// encode correctly on the wire, survive a server-side round-trip, and decode
// on the client side to the same concrete struct values.
//
// Fixture types (ns=2 numeric IDs 3001-3004):
//   - MyEnum       – int32 enumeration
//   - FlatStruct   – flat structure with scalar fields
//   - ArrayStruct  – structure with an int32 array field
//   - NestedStruct – structure embedding FlatStruct
//
// A ProcessFlat method is also exercised to confirm custom types propagate
// correctly through the method call codec path.
package conformance

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil/customtypes"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// setupCustomTypes starts a server with custom-type Variable nodes and method,
// connects a client, and returns (client, nodeIDs, methodObjectID, methodID, ctx).
// All resources are cleaned up via t.Cleanup.
func setupCustomTypes(t *testing.T) (*opcua.Client, map[string]*ua.NodeID, *ua.NodeID, *ua.NodeID, context.Context) {
	t.Helper()

	port := freeCustomPort(t)
	url := fmt.Sprintf("opc.tcp://localhost:%d", port)

	srv, err := server.New(
		server.EndPoint("localhost", port),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
	)
	require.NoError(t, err)

	ns := server.NewNodeNameSpace(srv, "http://otfabric.com/customtypes-test")
	obj := ns.Objects()

	// Link the namespace's Objects folder into the root.
	root, err := srv.Namespace(0)
	require.NoError(t, err)
	root.Objects().AddRef(obj, id.HasComponent, true)

	nodeIDs := customtypes.AddNodes(ns, obj)
	methodID := customtypes.AddMethodNode(srv, ns, obj)
	methodObjectID := obj.ID()

	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })

	c, err := opcua.NewClient(url,
		opcua.SecurityMode(ua.MessageSecurityModeNone),
		opcua.DialTimeout(15*time.Second),
		opcua.RequestTimeout(15*time.Second),
	)
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, c.Connect(ctx))
	t.Cleanup(func() { _ = c.Close(ctx) })

	return c, nodeIDs, methodObjectID, methodID, ctx
}

func freeCustomPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	p := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return p
}

// TestCustomTypes_FlatStruct_Read verifies that a server-side FlatStruct is
// correctly decoded by the client as a *customtypes.FlatStruct.
func TestCustomTypes_FlatStruct_Read(t *testing.T) {
	c, nodeIDs, _, _, ctx := setupCustomTypes(t)

	dv, err := c.ReadValue(ctx, nodeIDs["FlatStruct"])
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, dv.Status)

	eo, ok := dv.Value.Value().(*ua.ExtensionObject)
	require.True(t, ok, "expected *ua.ExtensionObject, got %T", dv.Value.Value())

	fs, ok := eo.Value.(*customtypes.FlatStruct)
	require.True(t, ok, "expected *FlatStruct inside ExtensionObject, got %T", eo.Value)
	require.InDelta(t, float64(23.5), float64(fs.Temperature), 0.001)
	require.Equal(t, int32(101325), fs.Pressure)
	require.Equal(t, "ambient", fs.Label)
}

// TestCustomTypes_FlatStruct_Write verifies that writing a new FlatStruct
// value round-trips correctly through the server and can be read back.
func TestCustomTypes_FlatStruct_Write(t *testing.T) {
	c, nodeIDs, _, _, ctx := setupCustomTypes(t)

	nodeID := nodeIDs["FlatStruct"]

	updated := &customtypes.FlatStruct{
		Temperature: 99.9,
		Pressure:    200000,
		Label:       "modified",
	}
	eo := ua.NewExtensionObject(updated)
	newVal := &ua.DataValue{
		EncodingMask: ua.DataValueValue,
		Value:        ua.MustVariant(eo),
	}

	writeReq := &ua.WriteRequest{
		NodesToWrite: []*ua.WriteValue{
			{
				NodeID:      nodeID,
				AttributeID: ua.AttributeIDValue,
				Value:       newVal,
			},
		},
	}
	writeResp, err := c.Write(ctx, writeReq)
	require.NoError(t, err)
	require.Len(t, writeResp.Results, 1)
	require.Equal(t, ua.StatusOK, writeResp.Results[0])

	// Read back and verify.
	dv, err := c.ReadValue(ctx, nodeID)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, dv.Status)

	eoRead, ok := dv.Value.Value().(*ua.ExtensionObject)
	require.True(t, ok)
	fsRead, ok := eoRead.Value.(*customtypes.FlatStruct)
	require.True(t, ok)
	require.InDelta(t, float64(99.9), float64(fsRead.Temperature), 0.01)
	require.Equal(t, int32(200000), fsRead.Pressure)
	require.Equal(t, "modified", fsRead.Label)
}

// TestCustomTypes_ArrayStruct_Read verifies round-trip for a struct whose
// Values field is a []int32 array.
func TestCustomTypes_ArrayStruct_Read(t *testing.T) {
	c, nodeIDs, _, _, ctx := setupCustomTypes(t)

	dv, err := c.ReadValue(ctx, nodeIDs["ArrayStruct"])
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, dv.Status)

	eo, ok := dv.Value.Value().(*ua.ExtensionObject)
	require.True(t, ok)
	as, ok := eo.Value.(*customtypes.ArrayStruct)
	require.True(t, ok, "expected *ArrayStruct, got %T", eo.Value)
	require.Equal(t, "readings", as.Name)
	require.Equal(t, []int32{10, 20, 30}, as.Values)
}

// TestCustomTypes_NestedStruct_Read verifies round-trip for a struct that
// embeds another struct (NestedStruct contains a FlatStruct).
func TestCustomTypes_NestedStruct_Read(t *testing.T) {
	c, nodeIDs, _, _, ctx := setupCustomTypes(t)

	dv, err := c.ReadValue(ctx, nodeIDs["NestedStruct"])
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, dv.Status)

	eo, ok := dv.Value.Value().(*ua.ExtensionObject)
	require.True(t, ok)
	ns, ok := eo.Value.(*customtypes.NestedStruct)
	require.True(t, ok, "expected *NestedStruct, got %T", eo.Value)
	require.Equal(t, int32(1), ns.ID)
	require.True(t, ns.Active)
	require.Equal(t, "body", ns.Inner.Label)
	require.InDelta(t, float64(36.6), float64(ns.Inner.Temperature), 0.01)
}

// TestCustomTypes_Enum_Read verifies round-trip for an int32 enumeration.
func TestCustomTypes_Enum_Read(t *testing.T) {
	c, nodeIDs, _, _, ctx := setupCustomTypes(t)

	dv, err := c.ReadValue(ctx, nodeIDs["MyEnum"])
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, dv.Status)

	eo, ok := dv.Value.Value().(*ua.ExtensionObject)
	require.True(t, ok)
	ev, ok := eo.Value.(*customtypes.MyEnum)
	require.True(t, ok, "expected *MyEnum, got %T", eo.Value)
	require.Equal(t, customtypes.MyEnumIdle, *ev)
}

// TestCustomTypes_Method_RoundTrip verifies that a method accepting a FlatStruct
// argument and returning an ArrayStruct works end-to-end through the codec.
func TestCustomTypes_Method_RoundTrip(t *testing.T) {
	c, _, methodObjectID, methodID, ctx := setupCustomTypes(t)

	input := &customtypes.FlatStruct{
		Temperature: 25.0,
		Pressure:    1000,
		Label:       "test",
	}
	inputEO := ua.NewExtensionObject(input)

	res, err := c.Call(ctx, &ua.CallMethodRequest{
		ObjectID:       methodObjectID,
		MethodID:       methodID,
		InputArguments: []*ua.Variant{ua.MustVariant(inputEO)},
	})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, res.StatusCode)
	require.Len(t, res.OutputArguments, 1)

	outEO, ok := res.OutputArguments[0].Value().(*ua.ExtensionObject)
	require.True(t, ok, "output should be *ua.ExtensionObject, got %T", res.OutputArguments[0].Value())

	result, ok := outEO.Value.(*customtypes.ArrayStruct)
	require.True(t, ok, "output EO should contain *ArrayStruct, got %T", outEO.Value)
	require.Equal(t, "test", result.Name)
	// Values: [Pressure=1000, int32(Temperature*10)=250]
	require.Equal(t, []int32{1000, 250}, result.Values)
}
