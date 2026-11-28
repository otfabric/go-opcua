// SPDX-License-Identifier: MIT

package opcua

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil/cleanup"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
	"github.com/stretchr/testify/require"
)

// These tests decode, against the go-opcua server, values of DataTypes the
// client has no Go type for, from the DataTypeDefinition Attribute of the
// server (OPC 10000-3 §5.8.3).

const dynNamespace = "urn:test:dyn"

// The DataTypes of dynNodeSet, with their Default Binary encodings.
const (
	dynInner    = 3001 // Structure {A Int32, B String}
	dynTypeA    = 3002 // optional fields, OPC 10000-6 §5.2.7
	dynChoice   = 3003 // Union {Num Int32, In Inner}
	dynMode     = 3004 // Enumeration
	dynOuter    = 3005
	dynAbstract = 3006 // abstract Structure without fields
	dynDerived  = 3007 // subtype of dynAbstract {X Int32}
	dynHolder   = 3008 // {P dynAbstract, AllowSubTypes}
	dynLabel    = 3010 // a String
	dynLabel2   = 3011 // a Label
	dynFlags    = 3012 // an OptionSet of a UInt32
	dynBits     = 3013 // a subtype of OptionSet
	dynNumber   = 3014 // an abstract Number
	dynSimple   = 3020 // {L Label, L2 Label2, F Flags, B Bits, N MyNumber}
	dynEncoding = 2000 // the encoding of DataType n is n + dynEncoding

	dynVarOuter   = 6001
	dynVarArray   = 6002
	dynVarBroken  = 6003
	dynVarUnknown = 6004
	dynVarHolder  = 6005
	dynVarSimple  = 6006
	dynMethod     = 7001
)

func dynDataType(n int, name, super, attrs, def string) string {
	out := `
  <UADataType NodeId="ns=1;i=` + strconv.Itoa(n) + `" BrowseName="1:` + name + `"` + attrs + `>
    <DisplayName>` + name + `</DisplayName>
    <References><Reference ReferenceType="HasSubtype" IsForward="false">` + super + `</Reference></References>
    ` + def + `
  </UADataType>`
	if attrs == "" {
		out += `
  <UAObject NodeId="ns=1;i=` + strconv.Itoa(n+dynEncoding) + `" BrowseName="Default Binary">
    <DisplayName>Default Binary</DisplayName>
    <References>
      <Reference ReferenceType="HasEncoding" IsForward="false">ns=1;i=` + strconv.Itoa(n) + `</Reference>
      <Reference ReferenceType="HasTypeDefinition">i=76</Reference>
    </References>
  </UAObject>`
	}
	return out
}

func dynVariable(n int, dataType string, valueRank int) string {
	return fmt.Sprintf(`
  <UAVariable NodeId="ns=1;i=%d" BrowseName="1:V%d" DataType="%s" ValueRank="%d" AccessLevel="1" UserAccessLevel="1" Historizing="false">
    <DisplayName>V%d</DisplayName>
    <References><Reference ReferenceType="HasTypeDefinition">i=63</Reference></References>
  </UAVariable>`, n, n, dataType, valueRank, n)
}

var dynNodeSet = []byte(`<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris><Uri>` + dynNamespace + `</Uri></NamespaceUris>
  <Aliases>
    <Alias Alias="Int32">i=6</Alias>
    <Alias Alias="String">i=12</Alias>
    <Alias Alias="HasSubtype">i=45</Alias>
    <Alias Alias="HasEncoding">i=38</Alias>
    <Alias Alias="HasTypeDefinition">i=40</Alias>
    <Alias Alias="HasComponent">i=47</Alias>
    <Alias Alias="HasProperty">i=46</Alias>
  </Aliases>` +
	dynDataType(dynInner, "Inner", "i=22", "", `<Definition Name="1:Inner">
      <Field Name="A" DataType="Int32"/><Field Name="B" DataType="String"/>
    </Definition>`) +
	dynDataType(dynTypeA, "TypeA", "i=22", "", `<Definition Name="1:TypeA">
      <Field Name="X" DataType="Int32"/><Field Name="O1" DataType="Int32" IsOptional="true"/>
      <Field Name="Y" DataType="i=2"/><Field Name="O2" DataType="Int32" IsOptional="true"/>
    </Definition>`) +
	dynDataType(dynChoice, "Choice", "i=12756", "", `<Definition Name="1:Choice" IsUnion="true">
      <Field Name="Num" DataType="Int32"/><Field Name="In" DataType="ns=1;i=3001"/>
    </Definition>`) +
	dynDataType(dynMode, "Mode", "i=29", ` IsAbstract="false"`, `<Definition Name="1:Mode">
      <Field Name="Off" Value="0"/><Field Name="On" Value="1"/>
    </Definition>`) +
	dynDataType(dynOuter, "Outer", "i=22", "", `<Definition Name="1:Outer">
      <Field Name="I" DataType="Int32"/>
      <Field Name="In" DataType="ns=1;i=3001"/>
      <Field Name="Ins" DataType="ns=1;i=3001" ValueRank="1"/>
      <Field Name="M" DataType="i=11" ValueRank="2"/>
      <Field Name="EU" DataType="i=887"/>
      <Field Name="Mode" DataType="ns=1;i=3004"/>
      <Field Name="Ch" DataType="ns=1;i=3003"/>
      <Field Name="Opt" DataType="ns=1;i=3002"/>
      <Field Name="Any" DataType="i=24"/>
      <Field Name="Values" DataType="Int32" ValueRank="1"/>
    </Definition>`) +
	dynDataType(dynAbstract, "Abstract", "i=22", ` IsAbstract="true"`, `<Definition Name="1:Abstract"/>`) +
	dynDataType(dynDerived, "Derived", "ns=1;i=3006", "", `<Definition Name="1:Derived">
      <Field Name="X" DataType="Int32"/>
    </Definition>`) +
	dynDataType(dynHolder, "Holder", "i=22", "", `<Definition Name="1:Holder">
      <Field Name="P" DataType="ns=1;i=3006" AllowSubTypes="true"/>
    </Definition>`) +
	// Simple DataTypes, without a StructureDefinition: their built-in
	// type is that of their supertypes (OPC 10000-3 §5.8.2).
	dynDataType(dynLabel, "Label", "i=12", ` IsAbstract="false"`, "") +
	dynDataType(dynLabel2, "Label2", "ns=1;i=3010", ` IsAbstract="false"`, "") +
	dynDataType(dynFlags, "Flags", "i=7", ` IsAbstract="false"`, `<Definition Name="1:Flags" IsOptionSet="true">
      <Field Name="A" Value="0"/><Field Name="B" Value="1"/>
    </Definition>`) +
	dynDataType(dynBits, "Bits", "i=12755", ` IsAbstract="false"`, `<Definition Name="1:Bits" IsOptionSet="true">
      <Field Name="A" Value="0"/>
    </Definition>`) +
	dynDataType(dynNumber, "MyNumber", "i=26", ` IsAbstract="true"`, "") +
	dynDataType(dynSimple, "Simple", "i=22", "", `<Definition Name="1:Simple">
      <Field Name="L" DataType="ns=1;i=3010"/><Field Name="L2" DataType="ns=1;i=3011"/>
      <Field Name="F" DataType="ns=1;i=3012"/><Field Name="B" DataType="ns=1;i=3013"/>
      <Field Name="N" DataType="ns=1;i=3014"/>
    </Definition>`) +
	dynVariable(dynVarSimple, "ns=1;i=3020", -1) +
	dynVariable(dynVarOuter, "ns=1;i=3005", -1) +
	dynVariable(dynVarArray, "ns=1;i=3001", 1) +
	dynVariable(dynVarBroken, "ns=1;i=3001", -1) +
	dynVariable(dynVarUnknown, "i=22", -1) +
	dynVariable(dynVarHolder, "ns=1;i=3008", -1) + `
  <UAMethod NodeId="ns=1;i=7001" BrowseName="1:Echo" ParentNodeId="i=85">
    <DisplayName>Echo</DisplayName>
    <References>
      <Reference ReferenceType="HasComponent" IsForward="false">i=85</Reference>
      <Reference ReferenceType="HasProperty">ns=1;i=7002</Reference>
    </References>
  </UAMethod>
  <UAVariable NodeId="ns=1;i=7002" BrowseName="InputArguments" DataType="i=296" ValueRank="1" ParentNodeId="ns=1;i=7001">
    <DisplayName>InputArguments</DisplayName>
    <References><Reference ReferenceType="HasTypeDefinition">i=68</Reference></References>
  </UAVariable>
</UANodeSet>`)

// dynServer starts a server with dynNodeSet after fillers namespaces of
// its own, so that the namespace index of dynNamespace differs between
// servers, and returns it with its URL and that index.
func dynServer(t *testing.T, fillers int, handlers map[uint16]server.Handler) (*server.Server, string, uint16) {
	t.Helper()
	srv, err := server.New(server.InsecureNoSecurity(), server.EnableAuthMode(ua.UserTokenTypeAnonymous), server.EndPoint("localhost", 0))
	require.NoError(t, err)
	for i := range fillers {
		server.NewNodeNameSpace(srv, "urn:test:filler:"+strconv.Itoa(i))
	}
	require.NoError(t, srv.ImportNodeSetXML(dynNodeSet))
	idx := -1
	for i, ns := range srv.Namespaces() {
		if ns.Name() == dynNamespace {
			idx = i
		}
	}
	require.Positive(t, idx)
	for typeID, h := range handlers {
		srv.RegisterHandler(typeID, h)
	}
	require.NoError(t, srv.Start(context.Background()))
	cleanup.Register(t, func() { _ = srv.Close() })
	return srv, fmt.Sprintf("opc.tcp://localhost:%d", srv.Port()), uint16(idx) // a namespace index
}

func dynClient(t *testing.T, url string, opts ...Option) *Client {
	t.Helper()
	c, err := NewClient(url, append([]Option{InsecureNoSecurity(), AutoReconnect(false), RequestTimeout(30 * time.Second)}, opts...)...)
	require.NoError(t, err)
	require.NoError(t, c.Connect(context.Background()))
	cleanup.Register(t, func() { _ = c.Close(context.Background()) })
	return c
}

// rawEO is an ExtensionObject the server sends as it is: the encoding and
// a binary body.
func rawEO(encoding *ua.NodeID, body []byte) *ua.ExtensionObject {
	return &ua.ExtensionObject{TypeID: &ua.ExpandedNodeID{NodeID: encoding}, EncodingMask: ua.ExtensionObjectBinary, Value: body}
}

// dynValues builds, with the types a client loaded from the server, the
// values of the variables of dynNodeSet, and sets them on srv.
type dynFixture struct {
	srv   *server.Server
	url   string
	ns    uint16
	outer []byte // the body of the Outer value
	eu    *ua.EUInformation
}

func (f *dynFixture) id(n uint32) *ua.NodeID { return ua.NewNumericNodeID(f.ns, n) }

func newDynFixture(t *testing.T, fillers int, handlers map[uint16]server.Handler) *dynFixture {
	t.Helper()
	srv, url, ns := dynServer(t, fillers, handlers)
	f := &dynFixture{srv: srv, url: url, ns: ns, eu: &ua.EUInformation{NamespaceURI: "http://www.opcfoundation.org/UA/units/un/cefact", UnitID: 4408652, DisplayName: ua.NewLocalizedText("°C"), Description: ua.NewLocalizedText("degree Celsius")}}
	ctx := context.Background()
	c := dynClient(t, url)
	require.NoError(t, c.LoadDataTypes(ctx, f.id(dynOuter), f.id(dynHolder), f.id(dynDerived), f.id(dynSimple)))
	types := c.DynamicTypes()
	newV := func(n uint32, fields ...any) *ua.DynamicStructure {
		v, err := types.New(f.id(n))
		require.NoError(t, err)
		for i := 0; i < len(fields); i += 2 {
			require.NoError(t, v.Set(fields[i].(string), fields[i+1]))
		}
		return v
	}
	encode := func(v *ua.DynamicStructure) []byte {
		b, err := v.Encode()
		require.NoError(t, err)
		return b
	}
	set := func(n uint32, v any) {
		require.NoError(t, srv.Node(f.id(n)).SetAttribute(ua.AttributeIDValue, server.DataValueFromValue(ua.MustVariant(v))))
	}
	f.outer = encode(newV(dynOuter,
		"I", int32(42),
		"In", newV(dynInner, "A", int32(1), "B", "one"),
		"Ins", []*ua.DynamicStructure{newV(dynInner, "A", int32(2)), newV(dynInner, "B", "three")},
		"M", &ua.DynamicMatrix{Dimensions: []int32{2, 2}, Values: []float64{1, 2, 3, 4}},
		"EU", f.eu,
		"Mode", int32(1),
		"Ch", newV(dynChoice, "In", newV(dynInner, "A", int32(5))),
		"Opt", newV(dynTypeA, "X", int32(7), "O2", int32(9)),
		"Any", ua.MustVariant("anything"),
		"Values", []int32{3, 2, 1},
	))
	set(dynVarOuter, rawEO(f.id(dynOuter+dynEncoding), f.outer))
	set(dynVarArray, []*ua.ExtensionObject{
		rawEO(f.id(dynInner+dynEncoding), encode(newV(dynInner, "A", int32(10)))),
		rawEO(f.id(dynInner+dynEncoding), encode(newV(dynInner, "A", int32(11)))),
	})
	set(dynVarSimple, rawEO(f.id(dynSimple+dynEncoding), encode(newV(dynSimple,
		"L", "label", "L2", "label2", "F", uint32(3),
		"B", &ua.OptionSet{Value: []byte{1}, ValidBits: []byte{1}},
		"N", ua.MustVariant(int16(4))))))
	set(dynVarBroken, rawEO(f.id(dynInner+dynEncoding), []byte{1, 0}))
	set(dynVarUnknown, rawEO(f.id(9999), []byte{1, 2, 3}))
	set(dynMethod+1, []*ua.ExtensionObject{ua.NewExtensionObject(&ua.Argument{Name: "In", DataType: f.id(dynOuter), ValueRank: -1})})
	set(dynVarHolder, rawEO(f.id(dynHolder+dynEncoding), encode(newV(dynHolder,
		"P", ua.NewExtensionObject(newV(dynDerived, "X", int32(77)))))))
	return f
}

// checkOuter checks the decoded value of dynVarOuter.
func (f *dynFixture) checkOuter(t *testing.T, v any) {
	t.Helper()
	eo, ok := v.(*ua.ExtensionObject)
	require.True(t, ok, "%T", v)
	d, ok := eo.Value.(*ua.DynamicStructure)
	require.True(t, ok, "%T", eo.Value)
	require.True(t, f.id(dynOuter).Equal(d.Type.DataTypeID))
	require.Equal(t, "Outer", d.Type.Name)
	field := func(name string) any {
		t.Helper()
		x, ok := d.Field(name)
		require.True(t, ok, name)
		return x
	}
	require.Equal(t, int32(42), field("I"))
	require.Equal(t, []any{int32(1), "one"}, field("In").(*ua.DynamicStructure).Fields)
	require.Len(t, field("Ins"), 2)
	require.Equal(t, &ua.DynamicMatrix{Dimensions: []int32{2, 2}, Values: []float64{1, 2, 3, 4}}, field("M"))
	// A field of a type with a Go type has the Go type.
	require.Equal(t, f.eu, field("EU"))
	require.Equal(t, int32(1), field("Mode"))
	ch := field("Ch").(*ua.DynamicStructure)
	require.Equal(t, uint32(2), ch.Switch)
	require.Equal(t, int32(5), ch.Fields[1].(*ua.DynamicStructure).Fields[0])
	require.Equal(t, []any{int32(7), nil, int8(0), int32(9)}, field("Opt").(*ua.DynamicStructure).Fields)
	require.Equal(t, "anything", field("Any").(*ua.Variant).Value())
	require.Equal(t, []int32{3, 2, 1}, field("Values"))
	// It encodes to the body the server sent.
	b, err := d.Encode()
	require.NoError(t, err)
	require.Equal(t, f.outer, b)
}

func TestDynamicTypeDecoding_Read(t *testing.T) {
	f := newDynFixture(t, 2, nil)
	ctx := context.Background()
	c := dynClient(t, f.url, DynamicTypeDecoding(true))

	res, err := c.Read(ctx, &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{
		{NodeID: f.id(dynVarOuter), AttributeID: ua.AttributeIDValue},
		{NodeID: f.id(dynVarArray), AttributeID: ua.AttributeIDValue},
		{NodeID: f.id(dynVarBroken), AttributeID: ua.AttributeIDValue},
		{NodeID: f.id(dynVarUnknown), AttributeID: ua.AttributeIDValue},
		{NodeID: f.id(dynVarHolder), AttributeID: ua.AttributeIDValue},
		{NodeID: ua.NewNumericNodeID(0, id.ServerServerStatus), AttributeID: ua.AttributeIDValue},
		{NodeID: f.id(dynVarSimple), AttributeID: ua.AttributeIDValue},
	}})
	require.NoError(t, err)
	require.Len(t, res.Results, 7)

	// The value decoded: its status is that of the server.
	require.Equal(t, ua.StatusOK, res.Results[0].Status)
	f.checkOuter(t, res.Results[0].Value.Value())

	arr := res.Results[1].Value.Value().([]*ua.ExtensionObject)
	require.Equal(t, int32(11), arr[1].Value.(*ua.DynamicStructure).Fields[0])

	// A body that does not match the definition, and a type the server
	// does not know, keep their RawBody, as without the option.
	for _, i := range []int{2, 3} {
		require.Equal(t, ua.StatusBadDataTypeIDUnknown, res.Results[i].Status, i)
		eo := res.Results[i].Value.Value().(*ua.ExtensionObject)
		require.Nil(t, eo.Value)
		require.NotEmpty(t, eo.RawBody)
	}
	d := c.dynamic()
	d.mu.Lock()
	require.True(t, d.unknown[f.id(9999).String()], "the unknown encoding is not asked again")
	d.mu.Unlock()

	// A field that allows subtypes holds an ExtensionObject of a subtype,
	// resolved in a second round.
	holder := res.Results[4].Value.Value().(*ua.ExtensionObject).Value.(*ua.DynamicStructure)
	p := holder.Fields[0].(*ua.ExtensionObject).Value.(*ua.DynamicStructure)
	require.Equal(t, "Derived", p.Type.Name)
	require.Equal(t, []any{int32(77)}, p.Fields)

	simple := res.Results[6].Value.Value().(*ua.ExtensionObject).Value.(*ua.DynamicStructure)
	require.Equal(t, []any{"label", "label2", uint32(3), &ua.OptionSet{Value: []byte{1}, ValidBits: []byte{1}}, ua.MustVariant(int16(4))}, simple.Fields)
	types := c.DynamicTypes()
	require.Equal(t, ua.TypeIDString, types.Type(f.id(dynLabel2)).BuiltIn)
	require.Equal(t, ua.TypeIDUint32, types.Type(f.id(dynFlags)).BuiltIn)
	require.IsType(t, &ua.EnumDefinition{}, types.Type(f.id(dynFlags)).Definition)
	require.Equal(t, ua.TypeIDExtensionObject, types.Type(f.id(dynBits)).BuiltIn)
	require.Equal(t, ua.TypeIDVariant, types.Type(f.id(dynNumber)).BuiltIn)
	require.True(t, types.Type(f.id(dynNumber)).IsAbstract)

	// Registered Go types come first.
	require.IsType(t, &ua.ServerStatusDataType{}, res.Results[5].Value.Value().(*ua.ExtensionObject).Value)

	// Read again: the types are cached, the unknown one is not asked.
	dv, err := c.ReadValue(ctx, f.id(dynVarUnknown))
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadDataTypeIDUnknown, dv.Status)
	dv, err = c.ReadValue(ctx, f.id(dynVarOuter))
	require.NoError(t, err)
	f.checkOuter(t, dv.Value.Value())
	v, err := c.Node(f.id(dynVarOuter)).Value(ctx)
	require.NoError(t, err)
	f.checkOuter(t, v.Value())
}

// TestDynamicTypeDecoding_Off: without the option nothing changes; the
// application decodes with DecodeExtensionObjects.
func TestDynamicTypeDecoding_Off(t *testing.T) {
	f := newDynFixture(t, 0, nil)
	ctx := context.Background()
	c := dynClient(t, f.url)
	dv, err := c.ReadValue(ctx, f.id(dynVarOuter))
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadDataTypeIDUnknown, dv.Status)
	eo := dv.Value.Value().(*ua.ExtensionObject)
	require.Nil(t, eo.Value)
	require.Equal(t, f.outer, eo.RawBody)

	require.NoError(t, c.DecodeExtensionObjects(ctx, dv))
	f.checkOuter(t, eo)

	dv, err = c.ReadValue(ctx, f.id(dynVarBroken))
	require.NoError(t, err)
	require.ErrorIs(t, c.DecodeExtensionObjects(ctx, dv), ua.StatusBadDecodingError)
	dv, err = c.ReadValue(ctx, f.id(dynVarUnknown))
	require.NoError(t, err)
	require.ErrorIs(t, c.DecodeExtensionObjects(ctx, dv), ua.StatusBadDataTypeIDUnknown)
	// Asked again, the unknown encoding is not resolved again.
	require.ErrorIs(t, c.DecodeExtensionObjects(ctx, []*ua.DataValue{dv}), ua.StatusBadDataTypeIDUnknown)
	require.NoError(t, c.DecodeExtensionObjects(ctx, nil))
}

// TestDynamicTypeDecoding_Namespaces: the types are kept by namespace URI;
// each session uses its own namespace indexes.
func TestDynamicTypeDecoding_Namespaces(t *testing.T) {
	f := newDynFixture(t, 1, nil)
	ctx := context.Background()
	c := dynClient(t, f.url, DynamicTypeDecoding(true))
	dv, err := c.ReadValue(ctx, f.id(dynVarOuter))
	require.NoError(t, err)
	f.checkOuter(t, dv.Value.Value())
	require.NotNil(t, c.DynamicTypes().Type(f.id(dynOuter)))

	// The same server with another namespace table, as after a
	// reconnect: the types move to the new index.
	ns := c.Namespaces()
	moved := append(append([]string(nil), ns[:f.ns]...), "urn:test:inserted")
	moved = append(moved, ns[f.ns:]...)
	c.setNamespaces(moved)
	types := c.DynamicTypes()
	require.Nil(t, types.Type(f.id(dynOuter)))
	at := ua.NewNumericNodeID(f.ns+1, dynOuter)
	require.NotNil(t, types.Type(at))
	sd := types.Type(at).Definition.(*ua.StructureDefinition)
	require.Equal(t, f.ns+1, sd.DefaultEncodingID.Namespace())
	require.Equal(t, f.ns+1, sd.Fields[1].DataType.Namespace())
	require.Equal(t, uint16(0), sd.Fields[4].DataType.Namespace(), "EUInformation stays in namespace 0")

	// A table without the namespace: the types are not usable.
	c.setNamespaces(ns[:f.ns])
	require.Nil(t, c.DynamicTypes().Type(at))
	c.setNamespaces(ns)
	require.NotNil(t, c.DynamicTypes().Type(f.id(dynOuter)))

	// A server with the namespace at another index.
	g := newDynFixture(t, 3, nil)
	require.NotEqual(t, f.ns, g.ns)
	c2 := dynClient(t, g.url, DynamicTypeDecoding(true))
	dv, err = c2.ReadValue(ctx, g.id(dynVarOuter))
	require.NoError(t, err)
	g.checkOuter(t, dv.Value.Value())
}

// TestDynamicTypeDecoding_Call sends a structure the client has no Go type
// for as an input argument, and decodes it in the output.
func TestDynamicTypeDecoding_Call(t *testing.T) {
	f := newDynFixture(t, 0, nil)
	var got []byte
	f.srv.RegisterMethod(ua.NewNumericNodeID(0, id.ObjectsFolder), f.id(dynMethod), func(_ context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		// The server has no Go type either: it keeps the body.
		eo := args[0].Value().(*ua.ExtensionObject)
		got = eo.RawBody
		return []*ua.Variant{ua.MustVariant(rawEO(eo.TypeID.NodeID, eo.RawBody))}, ua.StatusOK
	})
	ctx := context.Background()
	c := dynClient(t, f.url, DynamicTypeDecoding(true))
	require.NoError(t, c.LoadDataTypes(ctx, f.id(dynOuter)))
	in := new(ua.ExtensionObject)
	_, err := in.Decode(append(append([]byte{0x01, byte(f.ns), byte((dynOuter + dynEncoding) & 0xff), byte((dynOuter + dynEncoding) >> 8), 0x01},
		le32(len(f.outer))...), f.outer...))
	require.NoError(t, err)
	require.NoError(t, c.DynamicTypes().DecodeExtensionObject(in))

	res, err := c.CallMethod(ctx, ua.NewNumericNodeID(0, id.ObjectsFolder), f.id(dynMethod), in)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, res.StatusCode)
	require.Equal(t, f.outer, got)
	f.checkOuter(t, res.OutputArguments[0].Value())
}

func le32(n int) []byte {
	u := uint32(n) // a test body length
	return []byte{byte(u), byte(u >> 8), byte(u >> 16), byte(u >> 24)}
}

// TestDynamicTypeDecoding_History decodes the values of HistoryRead.
func TestDynamicTypeDecoding_History(t *testing.T) {
	var ns uint16
	var body []byte
	history := func(_ context.Context, _ *uasc.SecureChannel, r ua.Request, _ uint32) (ua.Response, error) {
		req := r.(*ua.HistoryReadRequest)
		dv := &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(rawEO(ua.NewNumericNodeID(ns, dynOuter+dynEncoding), body))}
		return &ua.HistoryReadResponse{
			ResponseHeader: &ua.ResponseHeader{Timestamp: time.Now(), RequestHandle: req.RequestHeader.RequestHandle, ServiceDiagnostics: &ua.DiagnosticInfo{}, AdditionalHeader: ua.NewExtensionObject(nil)},
			Results: []*ua.HistoryReadResult{
				{StatusCode: ua.StatusOK, HistoryData: ua.NewExtensionObject(&ua.HistoryData{DataValues: []*ua.DataValue{dv}})},
				nil,
			},
		}, nil
	}
	f := newDynFixture(t, 0, map[uint16]server.Handler{id.HistoryReadRequestEncodingDefaultBinary: history})
	ns, body = f.ns, f.outer
	ctx := context.Background()
	c := dynClient(t, f.url, DynamicTypeDecoding(true))
	nodes := []*ua.HistoryReadValueID{{NodeID: f.id(dynVarOuter)}}
	check := func(res *ua.HistoryReadResponse, err error) {
		t.Helper()
		require.NoError(t, err)
		f.checkOuter(t, res.Results[0].HistoryData.Value.(*ua.HistoryData).DataValues[0].Value.Value())
	}
	check(c.HistoryReadRawModified(ctx, nodes, &ua.ReadRawModifiedDetails{}))
	check(c.HistoryReadProcessed(ctx, nodes, &ua.ReadProcessedDetails{}))
	check(c.HistoryReadAtTime(ctx, nodes, &ua.ReadAtTimeDetails{}))
	res, err := c.HistoryReadEvent(ctx, nodes, &ua.ReadEventDetails{})
	require.NoError(t, err)
	require.Len(t, res.Results, 2)
}

// TestDynamicTypeDecoding_Subscription decodes the data changes of a
// subscription.
func TestDynamicTypeDecoding_Subscription(t *testing.T) {
	f := newDynFixture(t, 0, nil)
	ctx := context.Background()
	c := dynClient(t, f.url, DynamicTypeDecoding(true))
	ch := make(chan *PublishNotificationData, 8)
	sub, err := c.Subscribe(ctx, &SubscriptionParameters{Interval: 50 * time.Millisecond}, ch)
	require.NoError(t, err)
	cleanup.Register(t, func() { _ = sub.Cancel(context.Background()) })
	_, err = sub.Monitor(ctx, ua.TimestampsToReturnBoth, NewMonitoredItemCreateRequestWithDefaults(f.id(dynVarOuter), ua.AttributeIDValue, 1))
	require.NoError(t, err)
	for {
		select {
		case n := <-ch:
			require.NoError(t, n.Error)
			dc, ok := n.Value.(*ua.DataChangeNotification)
			if !ok {
				continue
			}
			f.checkOuter(t, dc.MonitoredItems[0].Value.Value.Value())
			return
		case <-time.After(20 * time.Second):
			t.Fatal("no data change")
		}
	}
}
