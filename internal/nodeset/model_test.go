// SPDX-License-Identifier: MIT

package nodeset

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
)

// vendored are the NodeSets of the repository the reader is checked on.
var vendored = []string{
	"../schema/Opc.Ua.NodeSet2.xml",
	"../schema/Opc.Ua.Gds.NodeSet2.xml",
	"../../uafx/internal/model/Opc.Ua.Di.NodeSet2.xml",
	"../../uafx/internal/model/opc.ua.fx.data.nodeset2.xml",
	"../../uafx/internal/model/opc.ua.fx.ac.nodeset2.xml",
	"../../uafx/internal/model/opc.ua.fx.cm.nodeset2.xml",
}

const sample = `<?xml version="1.0" encoding="utf-8"?>
<!-- a comment -->
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd" LastModified="2026-01-01T00:00:00Z">
  <NamespaceUris><Uri>urn:a</Uri><Uri>urn:b</Uri></NamespaceUris>
  <ServerUris><Uri>urn:server</Uri></ServerUris>
  <Models>
    <Model ModelUri="urn:a" XmlSchemaUri="urn:a/Types.xsd" Version="1.00" ModelVersion="1.0.0" PublicationDate="2026-01-01T00:00:00Z" AccessRestrictions="2">
      <RolePermissions><RolePermission Permissions="1">i=15668</RolePermission></RolePermissions>
      <RequiredModel ModelUri="http://opcfoundation.org/UA/" Version="1.05.07" ModelVersion="1.5.7" PublicationDate="2026-07-30T00:00:00Z"/>
    </Model>
  </Models>
  <Aliases>
    <Alias Alias="HasProperty">i=46</Alias>
    <Alias Alias="HasComponent"> ns=0;i=47 </Alias>
    <Alias Alias="Argument">i=296</Alias>
  </Aliases>
  <Extensions><Extension><X/></Extension></Extensions>
  <UAObjectType NodeId="ns=1;i=1" BrowseName="1:T" IsAbstract="true" SymbolicName="T_" WriteMask="3" UserWriteMask="4" AccessRestrictions="5" HasNoPermissions="true" ReleaseStatus="Draft">
    <DisplayName Locale="en">T</DisplayName>
    <DisplayName Locale="de">T-de</DisplayName>
    <Description>a type</Description>
    <Category>Cat</Category>
    <Documentation>https://reference.opcfoundation.org/x</Documentation>
    <References>
      <Reference ReferenceType="HasSubtype" IsForward="false">i=58</Reference>
      <Reference ReferenceType="HasComponent">ns=1;i=2</Reference>
    </References>
    <RolePermissions><RolePermission Permissions="7">i=15704</RolePermission></RolePermissions>
    <Extensions><Extension><Y a="1"/></Extension></Extensions>
  </UAObjectType>
  <UAMethod NodeId="ns=1;i=2" BrowseName="1:M" ParentNodeId="ns=1;i=1" MethodDeclarationId="ns=1;i=2" UserExecutable="false">
    <DisplayName>M</DisplayName>
    <ArgumentDescription><Name>A</Name><Description>first</Description></ArgumentDescription>
    <References>
      <Reference ReferenceType="HasModellingRule">i=78</Reference>
      <Reference ReferenceType="HasProperty">ns=1;i=3</Reference>
    </References>
  </UAMethod>
  <UAVariable NodeId="ns=1;i=3" BrowseName="InputArguments" ParentNodeId="ns=1;i=2" DataType="Argument" ValueRank="1" ArrayDimensions="2" AccessLevel="3" UserAccessLevel="1" MinimumSamplingInterval="100" Historizing="true" DesignToolOnly="true">
    <References>
      <Reference ReferenceType="HasTypeDefinition">i=68</Reference>
      <Reference ReferenceType="HasModellingRule">i=78</Reference>
    </References>
    <Value>
      <ListOfExtensionObject xmlns="http://opcfoundation.org/UA/2008/02/Types.xsd">
        <ExtensionObject>
          <TypeId><Identifier>i=297</Identifier></TypeId>
          <Body><Argument><Name>A</Name><DataType><Identifier>i=12</Identifier></DataType><ValueRank>-1</ValueRank><ArrayDimensions/><Description><Locale>en</Locale><Text>first</Text></Description></Argument></Body>
        </ExtensionObject>
        <ExtensionObject>
          <TypeId><Identifier>i=297</Identifier></TypeId>
          <Body><Argument><Name>B</Name><DataType><Identifier>ns=1;i=9</Identifier></DataType><ValueRank>1</ValueRank><ArrayDimensions><UInt32>3</UInt32></ArrayDimensions></Argument></Body>
        </ExtensionObject>
      </ListOfExtensionObject>
    </Value>
    <Translation><Text Locale="de">x</Text></Translation>
    <Translation><Field Name="F"><Text>y</Text></Field></Translation>
  </UAVariable>
  <UAVariable NodeId="ns=1;i=4" BrowseName="1:OutputArguments" DataType="i=296" ValueRank="1">
    <References><Reference ReferenceType="HasProperty" IsForward="false">ns=1;i=2</Reference></References>
    <Value><uax:ExtensionObject xmlns:uax="http://opcfoundation.org/UA/2008/02/Types.xsd"><uax:TypeId><uax:Identifier>i=297</uax:Identifier></uax:TypeId><uax:Body><uax:Argument><uax:Name>R</uax:Name></uax:Argument></uax:Body></uax:ExtensionObject></Value>
  </UAVariable>
  <UAVariable NodeId="ns=1;i=5" BrowseName="1:V"/>
  <UAVariableType NodeId="ns=1;i=6" BrowseName="1:VT" ValueRank="-2"><Value><Int32>5</Int32></Value></UAVariableType>
  <UADataType NodeId="ns=1;i=7" BrowseName="1:E" Purpose="ServicesOnly">
    <Definition Name="1:E" SymbolicName="E_" BaseType="x">
      <Field Name="Zero" Value="0"><DisplayName>Zero</DisplayName><Description>none</Description></Field>
      <Field Name="Unset"/>
    </Definition>
  </UADataType>
  <UADataType NodeId="ns=1;i=8" BrowseName="1:S">
    <Definition Name="1:S" IsUnion="true" IsOptionSet="true">
      <Field Name="A" SymbolicName="A_" DataType="i=12" ValueRank="1" ArrayDimensions="4" MaxStringLength="10" IsOptional="true" AllowSubTypes="true"/>
    </Definition>
  </UADataType>
  <UADataType NodeId="ns=1;i=9" BrowseName="1:N"/>
  <UAReferenceType NodeId="ns=1;i=10" BrowseName="1:R" Symmetric="true"><InverseName>RevR</InverseName></UAReferenceType>
  <UAView NodeId="ns=1;i=11" BrowseName="1:View" ContainsNoLoops="true" EventNotifier="1"/>
  <UAObject NodeId="ns=1;i=12" BrowseName="1:O" EventNotifier="5">
    <References><Reference ReferenceType="HasTypeDefinition">ns=1;i=1</Reference></References>
  </UAObject>
  <Unknown><UAObject NodeId="ns=1;i=99" BrowseName="hidden"/></Unknown>
</UANodeSet>
trailing`

func TestParse(t *testing.T) {
	s, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if s.LastModified != "2026-01-01T00:00:00Z" || !reflect.DeepEqual(s.NamespaceURIs, []string{"urn:a", "urn:b"}) ||
		!reflect.DeepEqual(s.ServerURIs, []string{"urn:server"}) {
		t.Errorf("header %q %v %v", s.LastModified, s.NamespaceURIs, s.ServerURIs)
	}
	wantModel := []Model{{
		ModelURI: "urn:a", XMLSchemaURI: "urn:a/Types.xsd", Version: "1.00", ModelVersion: "1.0.0",
		PublicationDate: "2026-01-01T00:00:00Z", AccessRestrictions: 2,
		RolePermissions: []RolePermission{{Role: "i=15668", Permissions: 1}},
		RequiredModels:  []Model{{ModelURI: "http://opcfoundation.org/UA/", Version: "1.05.07", ModelVersion: "1.5.7", PublicationDate: "2026-07-30T00:00:00Z"}},
	}}
	if !reflect.DeepEqual(s.Models, wantModel) {
		t.Errorf("Models = %+v", s.Models)
	}
	if len(s.Aliases) != 3 || s.Aliases[1] != (Alias{Alias: "HasComponent", NodeID: " ns=0;i=47 "}) {
		t.Errorf("Aliases = %+v", s.Aliases)
	}
	if !reflect.DeepEqual(s.Extensions, []string{"<X/>"}) {
		t.Errorf("Extensions = %q", s.Extensions)
	}
	if len(s.Nodes) != 12 {
		t.Fatalf("%d nodes", len(s.Nodes))
	}
	if s.Node("ns=1;i=99") != nil {
		t.Error("a node inside an unknown element was read")
	}

	typ := s.Node("ns=1;i=1")
	want := &Node{
		Class: ObjectType, NodeID: "ns=1;i=1", BrowseName: "1:T", SymbolicName: "T_", WriteMask: 3, UserWriteMask: 4,
		AccessRestrictions: 5, HasNoPermissions: true, ReleaseStatus: "Draft",
		DisplayName:   []LocalizedText{{"en", "T"}, {"de", "T-de"}},
		Description:   []LocalizedText{{"", "a type"}},
		Category:      []string{"Cat"},
		Documentation: "https://reference.opcfoundation.org/x",
		References: []Reference{
			{Type: "HasSubtype", IsForward: false, Target: "i=58"},
			{Type: "HasComponent", IsForward: true, Target: "ns=1;i=2"},
		},
		RolePermissions: []RolePermission{{Role: "i=15704", Permissions: 7}},
		Extensions:      []string{`<Y a="1"/>`},
		IsAbstract:      true,
	}
	if !reflect.DeepEqual(typ, want) {
		t.Errorf("ObjectType\n got %+v\nwant %+v", typ, want)
	}

	m := s.Node("ns=1;i=2")
	if m.Class != Method || m.ParentNodeID != "ns=1;i=1" || m.MethodDeclarationID != "ns=1;i=2" || !m.Executable || m.UserExecutable ||
		!reflect.DeepEqual(m.ArgumentDescription, []ArgumentDescription{{Name: "A", Description: []LocalizedText{{"", "first"}}}}) ||
		m.ReleaseStatus != "Released" {
		t.Errorf("Method %+v", m)
	}

	in := s.Node("ns=1;i=3")
	if in.Class != Variable || in.DataType != "Argument" || in.ValueRank != 1 || in.ArrayDimensions != "2" || in.AccessLevel != 3 ||
		in.UserAccessLevel != 1 || in.MinimumSamplingInterval != 100 || !in.Historizing || !in.DesignToolOnly || in.Value == nil ||
		!reflect.DeepEqual(in.Translation, []Translation{{Text: []LocalizedText{{"de", "x"}}}, {Fields: []FieldTranslation{{Name: "F", Text: []LocalizedText{{"", "y"}}}}}}) {
		t.Errorf("Variable %+v", in)
	}
	v := s.Node("ns=1;i=5")
	if v.DataType != "" || v.ValueRank != -1 || v.AccessLevel != 1 || v.UserAccessLevel != 1 || v.Value != nil {
		t.Errorf("defaults of a Variable: %+v", v)
	}
	vt := s.Node("ns=1;i=6")
	if vt.Class != VariableType || vt.DataType != "" || vt.ValueRank != -2 || vt.Value == nil || vt.Value.XML != "<Int32>5</Int32>" || vt.AccessLevel != 0 {
		t.Errorf("VariableType %+v", vt)
	}

	e := s.Node("ns=1;i=7")
	wantDef := &Definition{Name: "1:E", SymbolicName: "E_", BaseType: "x", Fields: []Field{
		{Name: "Zero", ValueRank: -1, Value: 0, DisplayName: []LocalizedText{{"", "Zero"}}, Description: []LocalizedText{{"", "none"}}},
		{Name: "Unset", ValueRank: -1, Value: -1},
	}}
	if e.Purpose != "ServicesOnly" || !reflect.DeepEqual(e.Definition, wantDef) {
		t.Errorf("DataType %+v %+v", e, e.Definition)
	}
	st := s.Node("ns=1;i=8")
	if st.Purpose != "Normal" || !st.Definition.IsUnion || !st.Definition.IsOptionSet ||
		!reflect.DeepEqual(st.Definition.Fields, []Field{{Name: "A", SymbolicName: "A_", DataType: "i=12", ValueRank: 1, ArrayDimensions: "4", MaxStringLength: 10, Value: -1, IsOptional: true, AllowSubTypes: true}}) {
		t.Errorf("structure %+v", st.Definition)
	}
	if s.Node("ns=1;i=9").Definition != nil {
		t.Error("a DataType without Definition has one")
	}
	rt := s.Node("ns=1;i=10")
	if rt.Class != ReferenceType || !rt.Symmetric || !reflect.DeepEqual(rt.InverseName, []LocalizedText{{"", "RevR"}}) {
		t.Errorf("ReferenceType %+v", rt)
	}
	view := s.Node("ns=1;i=11")
	if view.Class != View || !view.ContainsNoLoops || view.EventNotifier != 1 {
		t.Errorf("View %+v", view)
	}
	if o := s.Node("ns=1;i=12"); o.Class != Object || o.EventNotifier != 5 {
		t.Errorf("Object %+v", o)
	}

	if got := s.OfClass(Variable); len(got) != 3 || got[0].NodeID != "ns=1;i=3" || got[2].NodeID != "ns=1;i=5" {
		t.Errorf("OfClass(Variable) = %v", got)
	}
	if s.OfClass(0) != nil || s.OfClass(42) != nil {
		t.Error("OfClass of an unknown class")
	}
	if s.Node("Argument") != nil || s.Resolve(" Argument ") != "i=296" || s.Resolve("i=5") != "i=5" {
		t.Error("Resolve")
	}
}

func TestQueries(t *testing.T) {
	s, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	typ, m, o := s.Node("ns=1;i=1"), s.Node("ns=1;i=2"), s.Node("ns=1;i=12")
	// HasProperty on the Method to i=3, inverse on i=4 to the Method.
	if got := s.Related(m, "HasProperty", true); !reflect.DeepEqual(got, []string{"ns=1;i=3", "ns=1;i=4"}) {
		t.Errorf("Related(HasProperty) = %v", got)
	}
	// The alias HasComponent is " ns=0;i=47 ": one NodeId with i=47.
	if got := s.Related(typ, "i=47", true); !reflect.DeepEqual(got, []string{"ns=1;i=2"}) {
		t.Errorf("Related(i=47) = %v", got)
	}
	if got := s.Related(m, HasComponent, false); !reflect.DeepEqual(got, []string{"ns=1;i=1"}) {
		t.Errorf("Related(HasComponent, inverse) = %v", got)
	}
	if s.ModellingRule(m) != ModellingRuleMandatory || s.ModellingRule(typ) != "" {
		t.Error("ModellingRule")
	}
	if s.TypeDefinition(o) != "ns=1;i=1" || s.TypeDefinition(typ) != "" {
		t.Error("TypeDefinition")
	}
	if s.SuperType(typ) != "i=58" {
		t.Errorf("SuperType = %q", s.SuperType(typ))
	}
	if got := s.Children(typ); len(got) != 1 || got[0] != m {
		t.Errorf("Children(type) = %v", got)
	}
	if got := s.Children(m); len(got) != 2 {
		t.Errorf("Children(method) = %v", got)
	}

	in, out, err := s.MethodArguments(m)
	if err != nil {
		t.Fatal(err)
	}
	wantIn := []Argument{
		{Name: "A", DataType: "i=12", ValueRank: -1, Description: LocalizedText{Locale: "en", Text: "first"}},
		{Name: "B", DataType: "ns=1;i=9", ValueRank: 1, ArrayDimensions: []uint32{3}},
	}
	if !reflect.DeepEqual(in, wantIn) {
		t.Errorf("InputArguments = %+v", in)
	}
	if !reflect.DeepEqual(out, []Argument{{Name: "R"}}) {
		t.Errorf("OutputArguments = %+v", out)
	}
	if in, out, err := s.MethodArguments(typ); err != nil || in != nil || out != nil {
		t.Errorf("arguments of a node without them: %v %v %v", in, out, err)
	}
}

func TestMethodArgumentsErrors(t *testing.T) {
	doc := func(value string) string {
		return `<UANodeSet><UAMethod NodeId="i=1" BrowseName="M"><References><Reference ReferenceType="i=46">i=2</Reference><Reference ReferenceType="i=46">i=3</Reference><Reference ReferenceType="i=46">i=4</Reference><Reference ReferenceType="i=46">i=9</Reference></References></UAMethod>` +
			`<UAVariable NodeId="i=2" BrowseName="InputArguments">` + value + `</UAVariable>` +
			`<UAVariable NodeId="i=3" BrowseName="Other"><Value><Int32>1</Int32></Value></UAVariable>` +
			`<UAObject NodeId="i=4" BrowseName="OutputArguments"/></UANodeSet>`
	}
	// A Property without a value, one of another name and an Object are no arguments.
	s, err := Parse([]byte(doc("")))
	if err != nil {
		t.Fatal(err)
	}
	if in, out, err := s.MethodArguments(s.Node("i=1")); err != nil || in != nil || out != nil {
		t.Errorf("%v %v %v", in, out, err)
	}
	for _, value := range []string{
		`<Value><Int32>5</Int32></Value>`,
		`<Value><ExtensionObject><TypeId><Identifier>i=298</Identifier></TypeId><Body><Argument/></Body></ExtensionObject></Value>`,
		`<Value><ExtensionObject><TypeId><Identifier>i=297</Identifier></TypeId><Body><Other/></Body></ExtensionObject></Value>`,
		`<Value><ExtensionObject><TypeId><Identifier>i=297</Identifier></TypeId><Body><Argument><ValueRank>x</ValueRank></Argument></Body></ExtensionObject></Value>`,
		`<Value><ListOfExtensionObject><ExtensionObject></ListOfExtensionObject></Value>`,
	} {
		s, err := Parse([]byte(doc(value)))
		if err != nil {
			// Malformed XML inside the Value already fails the parse.
			continue
		}
		if _, _, err := s.MethodArguments(s.Node("i=1")); err == nil {
			t.Errorf("%s: no error", value)
		}
	}
	if _, err := (&Value{XML: "<ExtensionObject>"}).Arguments(); err == nil {
		t.Error("a truncated value decoded")
	}
	if args, err := (&Value{XML: "  "}).Arguments(); err != nil || args != nil {
		t.Errorf("an empty value: %v %v", args, err)
	}
}

func TestParseErrors(t *testing.T) {
	for _, doc := range []string{
		``,
		`<!-- nothing -->`,
		`<UANodeSet>`,
		`<UANodeSet><UAObject NodeId="i=1" BrowseName="O" EventNotifier="256"/></UANodeSet>`,
		`<UANodeSet><UAVariable NodeId="i=1" BrowseName="V" ValueRank="x"/></UANodeSet>`,
		`<UANodeSet><UAObject NodeId="i=1"><References><Reference IsForward="maybe">i=2</Reference></References></UAObject></UANodeSet>`,
		`<UANodeSet><NamespaceUris><Uri>a</Uri></NamespaceUri></UANodeSet>`,
		`<UANodeSet><ServerUris><Uri>a</ServerUris></UANodeSet>`,
		`<UANodeSet><Models><Model AccessRestrictions="-1"/></Models></UANodeSet>`,
		`<UANodeSet><Aliases><Alias Alias="a">i=1</Aliases></UANodeSet>`,
		`<UANodeSet><Unknown><x></Unknown></UANodeSet>`,
		`<UANodeSet><Extensions><Extension></Extensions></UANodeSet>`,
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("Parse(%q) passed", doc)
		}
	}
	// The import has always taken the children of any root element.
	s, err := Parse([]byte(`<Other><UAObject NodeId="i=1" BrowseName="O"/></Other>`))
	if err != nil || len(s.Nodes) != 1 {
		t.Errorf("another root element: %v", err)
	}
	// A NodeId the set declares twice: the first is the node of Node.
	s, err = Parse([]byte(`<UANodeSet><UAObject NodeId="i=1" BrowseName="A"/><UAObject NodeId="i=1" BrowseName="B"/></UANodeSet>`))
	if err != nil || len(s.Nodes) != 2 || s.Node("i=1").BrowseName != "A" {
		t.Errorf("a duplicate NodeId: %v", err)
	}
}

func TestNodeClassString(t *testing.T) {
	for c, want := range map[NodeClass]string{Object: "UAObject", ReferenceType: "UAReferenceType", 0: "NodeClass(0)", 42: "NodeClass(42)"} {
		if got := c.String(); got != want {
			t.Errorf("%d: %q, want %q", c, got, want)
		}
	}
}

func TestLocalName(t *testing.T) {
	for in, want := range map[string]string{"1:Name": "Name", "Name": "Name", ":Name": ":Name", "x:Name": "x:Name", "70000:Name": "70000:Name"} {
		if got := localName(in); got != want {
			t.Errorf("localName(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestVendoredNodeSets reads the NodeSets of the repository: every node
// has a NodeId and a BrowseName, and every Method with InputArguments or
// OutputArguments decodes them.
func TestVendoredNodeSets(t *testing.T) {
	for _, path := range vendored {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		s, err := Parse(data)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if len(s.Models) == 0 || len(s.Nodes) == 0 {
			t.Fatalf("%s: %d models, %d nodes", path, len(s.Models), len(s.Nodes))
		}
		methods, withArgs := 0, 0
		for _, n := range s.Nodes {
			if n.NodeID == "" || n.BrowseName == "" {
				t.Errorf("%s: a node without NodeId or BrowseName: %+v", path, n)
			}
			if n.Class != Method {
				continue
			}
			methods++
			in, out, err := s.MethodArguments(n)
			if err != nil {
				t.Errorf("%s: %v", path, err)
			}
			if in != nil || out != nil {
				withArgs++
			}
			for _, a := range append(in, out...) {
				if a.Name == "" || a.DataType == "" {
					t.Errorf("%s: %s: an Argument without Name or DataType: %+v", path, n.NodeID, a)
				}
			}
		}
		if methods > 0 && withArgs == 0 {
			t.Errorf("%s: %d Methods, none with arguments", path, methods)
		}
	}
}

// TestReaderCoversVendoredNodeSets: every attribute and element the
// vendored NodeSets use (outside Value and Extension content, which is
// kept as XML) is one the reader reads, so the model leaves nothing out.
func TestReaderCoversVendoredNodeSets(t *testing.T) {
	for _, path := range vendored {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		dec := xml.NewDecoder(bytes.NewReader(data))
		for {
			tok, err := dec.Token()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			se, ok := tok.(xml.StartElement)
			if !ok {
				continue
			}
			var typ reflect.Type
			switch name := se.Name.Local; {
			case name == "UANodeSet":
				for _, a := range se.Attr {
					if a.Name.Local != "LastModified" && a.Name.Space != "xmlns" && a.Name.Local != "xmlns" {
						t.Errorf("%s: UANodeSet@%s is not read", path, a.Name.Local)
					}
				}
				continue
			case classElements[name] != 0:
				typ = reflect.TypeOf(xmlNode{})
			case name == "Models":
				typ = reflect.TypeOf(struct {
					Models []xmlModel `xml:"Model"`
				}{})
			case name == "NamespaceUris", name == "ServerUris", name == "Aliases", name == "Extensions":
				if err := dec.Skip(); err != nil {
					t.Fatal(err)
				}
				continue
			default:
				t.Errorf("%s: %s is not read", path, name)
				if err := dec.Skip(); err != nil {
					t.Fatal(err)
				}
				continue
			}
			checkCovered(t, path, dec, se, typ)
		}
	}
}

// checkCovered checks the attributes and child elements of se against the
// xml tags of typ, recursively.
func checkCovered(t *testing.T, path string, dec *xml.Decoder, se xml.StartElement, typ reflect.Type) {
	t.Helper()
	attrs, elems := map[string]bool{}, map[string]reflect.Type{}
	inner := false
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		tag := f.Tag.Get("xml")
		name, opts, _ := strings.Cut(tag, ",")
		ft := f.Type
		for ft.Kind() == reflect.Pointer || ft.Kind() == reflect.Slice {
			ft = ft.Elem()
		}
		switch {
		case opts == "attr":
			attrs[name] = true
		case opts == "innerxml":
			inner = true
		case opts == "chardata":
		case name != "":
			// "References>Reference": the outer element, then the inner.
			if outer, rest, ok := strings.Cut(name, ">"); ok {
				elems[outer] = reflect.StructOf([]reflect.StructField{{Name: "X", Type: reflect.SliceOf(ft), Tag: reflect.StructTag(`xml:"` + rest + `"`)}})
			} else {
				elems[name] = ft
			}
		}
	}
	if inner {
		if err := dec.Skip(); err != nil {
			t.Fatal(err)
		}
		return
	}
	for _, a := range se.Attr {
		if a.Name.Space == "xmlns" || a.Name.Local == "xmlns" {
			continue
		}
		if !attrs[a.Name.Local] {
			t.Errorf("%s: %s@%s is not read", path, se.Name.Local, a.Name.Local)
		}
	}
	for {
		tok, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		switch x := tok.(type) {
		case xml.EndElement:
			return
		case xml.StartElement:
			ct, ok := elems[x.Name.Local]
			if !ok {
				t.Errorf("%s: %s/%s is not read", path, se.Name.Local, x.Name.Local)
				if err := dec.Skip(); err != nil {
					t.Fatal(err)
				}
				continue
			}
			if ct.Kind() != reflect.Struct {
				if err := dec.Skip(); err != nil {
					t.Fatal(err)
				}
				continue
			}
			checkCovered(t, path, dec, x, ct)
		}
	}
}

// BenchmarkParseUA parses the NodeSet of namespace 0, as a server does
// once per process.
func BenchmarkParseUA(b *testing.B) {
	data, err := os.ReadFile(vendored[0])
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Parse(data); err != nil {
			b.Fatal(err)
		}
	}
}

// FuzzParse feeds arbitrary documents, which ImportNodeSetXML takes from
// the application, to Parse and to the queries on what it returns: they
// never panic, and every node is found by its class and its NodeId.
func FuzzParse(f *testing.F) {
	f.Add([]byte(sample))
	f.Add([]byte(`<UANodeSet><Aliases><Alias Alias="A">i=1</Alias></Aliases><UAMethod NodeId="ns=1;i=1" BrowseName="1:M"><References><Reference ReferenceType="HasProperty">ns=1;i=2</Reference></References></UAMethod><UAVariable NodeId="ns=1;i=2" BrowseName="InputArguments"><Value><ExtensionObject/></Value></UAVariable></UANodeSet>`))
	f.Add([]byte(`<UANodeSet><UADataType NodeId="i=1"><Definition Name="D"><Field Name="f" Value="-"/></Definition></UADataType></UANodeSet>`))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := Parse(b)
		if err != nil {
			return
		}
		n := 0
		for c := Object; c <= ReferenceType; c++ {
			n += len(s.OfClass(c))
		}
		if n != len(s.Nodes) {
			t.Fatalf("%d nodes, %d by class", len(s.Nodes), n)
		}
		for _, node := range s.Nodes {
			if s.Node(node.NodeID) == nil {
				t.Fatalf("%q is not found", node.NodeID)
			}
			_ = s.Children(node)
			_ = s.ModellingRule(node)
			_ = s.TypeDefinition(node)
			_ = s.SuperType(node)
			if node.Class == Method {
				_, _, _ = s.MethodArguments(node)
			}
			if node.Value != nil {
				_, _ = node.Value.Arguments()
			}
		}
	})
}
