// SPDX-License-Identifier: MIT

// Dynamic decoding of custom structures (Go↔Go): a client without Go types
// for a model decodes its Structures and Unions with the DataTypeDefinition
// Attribute the go-opcua server gives every imported DataType (OPC 10000-3
// §5.8.3).
package conformance

import (
	"context"
	"fmt"
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

const dynamicNodeSet = `<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris><Uri>urn:conformance:dynamic</Uri></NamespaceUris>
  <Aliases>
    <Alias Alias="Int32">i=6</Alias>
    <Alias Alias="String">i=12</Alias>
    <Alias Alias="HasSubtype">i=45</Alias>
    <Alias Alias="HasEncoding">i=38</Alias>
    <Alias Alias="HasTypeDefinition">i=40</Alias>
  </Aliases>
  <UADataType NodeId="ns=1;i=3001" BrowseName="1:Pump">
    <DisplayName>Pump</DisplayName>
    <References><Reference ReferenceType="HasSubtype" IsForward="false">i=22</Reference></References>
    <Definition Name="1:Pump">
      <Field Name="Name" DataType="String"/>
      <Field Name="Speed" DataType="Int32"/>
      <Field Name="Tags" DataType="String" ValueRank="1"/>
      <Field Name="Limit" DataType="Int32" IsOptional="true"/>
    </Definition>
  </UADataType>
  <UAObject NodeId="ns=1;i=5001" BrowseName="Default Binary">
    <DisplayName>Default Binary</DisplayName>
    <References>
      <Reference ReferenceType="HasEncoding" IsForward="false">ns=1;i=3001</Reference>
      <Reference ReferenceType="HasTypeDefinition">i=76</Reference>
    </References>
  </UAObject>
  <UAVariable NodeId="ns=1;i=6001" BrowseName="1:Pump1" DataType="ns=1;i=3001" AccessLevel="1" UserAccessLevel="1">
    <DisplayName>Pump1</DisplayName>
    <References><Reference ReferenceType="HasTypeDefinition">i=63</Reference></References>
  </UAVariable>
</UANodeSet>`

func TestDynamicTypes_GoToGo(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	srv, err := server.New(server.EndPoint("localhost", 0), server.InsecureNoSecurity(), server.EnableAuthMode(ua.UserTokenTypeAnonymous))
	require.NoError(t, err)
	require.NoError(t, srv.ImportNodeSetXML([]byte(dynamicNodeSet)))
	require.NoError(t, srv.Start(ctx))
	t.Cleanup(func() { _ = srv.Close() })
	url := fmt.Sprintf("opc.tcp://localhost:%d", srv.Port())

	connect := func(opts ...opcua.Option) *opcua.Client {
		c, err := opcua.NewClient(url, append([]opcua.Option{opcua.InsecureNoSecurity(), opcua.AutoReconnect(false)}, opts...)...)
		require.NoError(t, err)
		require.NoError(t, c.Connect(ctx))
		t.Cleanup(func() { _ = c.Close(context.Background()) })
		return c
	}
	plain := connect()
	ns := uint16(0)
	for i, uri := range plain.Namespaces() {
		if uri == "urn:conformance:dynamic" {
			ns = uint16(i) // a namespace index
		}
	}
	require.NotZero(t, ns)
	pump, encoding, variable := ua.NewNumericNodeID(ns, 3001), ua.NewNumericNodeID(ns, 5001), ua.NewNumericNodeID(ns, 6001)

	// A value made from the DataTypeDefinition, without a Go type.
	require.NoError(t, plain.LoadDataTypes(ctx, pump))
	v, err := plain.DynamicTypes().New(pump)
	require.NoError(t, err)
	require.NoError(t, v.Set("Name", "P-101"))
	require.NoError(t, v.Set("Speed", int32(1450)))
	require.NoError(t, v.Set("Tags", []string{"water", "north"}))
	body, err := v.Encode()
	require.NoError(t, err)
	require.NoError(t, srv.Node(variable).SetAttribute(ua.AttributeIDValue, server.DataValueFromValue(ua.MustVariant(
		&ua.ExtensionObject{TypeID: &ua.ExpandedNodeID{NodeID: encoding}, EncodingMask: ua.ExtensionObjectBinary, Value: body}))))

	check := func(dv *ua.DataValue) {
		t.Helper()
		got, ok := dv.Value.Value().(*ua.ExtensionObject).Value.(*ua.DynamicStructure)
		require.True(t, ok)
		require.Equal(t, "Pump", got.Type.Name)
		require.Equal(t, []any{"P-101", int32(1450), []string{"water", "north"}, nil}, got.Fields)
	}

	// With the option the client decodes on Read.
	dynamic := connect(opcua.DynamicTypeDecoding(true))
	dv, err := dynamic.ReadValue(ctx, variable)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, dv.Status)
	check(dv)

	// Without it the body stays raw until the application asks.
	dv, err = plain.ReadValue(ctx, variable)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadDataTypeIDUnknown, dv.Status)
	require.NoError(t, plain.DecodeExtensionObjects(ctx, dv))
	check(dv)
}
