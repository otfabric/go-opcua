// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"log/slog"
	"strconv"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/nodeset"
	"github.com/otfabric/go-opcua/internal/testutil/cleanup"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// readDefinition returns the DataTypeDefinition Attribute of the node nid
// of s, or the error of the read.
func readDefinition(t *testing.T, s *Server, nid *ua.NodeID) (any, error) {
	t.Helper()
	n := s.Node(nid)
	require.NotNil(t, n, "node %s", nid)
	v, err := n.Attribute(ua.AttributeIDDataTypeDefinition)
	if err != nil {
		return nil, err
	}
	eo, ok := v.Value.Value.Value().(*ua.ExtensionObject)
	require.True(t, ok, "%s: %T", nid, v.Value.Value.Value())
	return eo.Value, nil
}

func structureDefinition(t *testing.T, s *Server, nid *ua.NodeID) *ua.StructureDefinition {
	t.Helper()
	v, err := readDefinition(t, s, nid)
	require.NoError(t, err, "%s", nid)
	sd, ok := v.(*ua.StructureDefinition)
	require.True(t, ok, "%s: %T", nid, v)
	return sd
}

func enumDefinition(t *testing.T, s *Server, nid *ua.NodeID) *ua.EnumDefinition {
	t.Helper()
	v, err := readDefinition(t, s, nid)
	require.NoError(t, err, "%s", nid)
	ed, ok := v.(*ua.EnumDefinition)
	require.True(t, ok, "%s: %T", nid, v)
	return ed
}

func ns0(i uint32) *ua.NodeID { return ua.NewNumericNodeID(0, i) }

type wantField struct {
	name     string
	dataType *ua.NodeID
	rank     int32
	dims     []uint32
	optional bool
}

func requireFields(t *testing.T, sd *ua.StructureDefinition, want []wantField) {
	t.Helper()
	require.Len(t, sd.Fields, len(want))
	for i, w := range want {
		f := sd.Fields[i]
		require.Equal(t, w.name, f.Name, "field %d", i)
		require.Equal(t, w.dataType.String(), f.DataType.String(), "field %s", w.name)
		require.Equal(t, w.rank, f.ValueRank, "field %s", w.name)
		require.Equal(t, w.dims, f.ArrayDimensions, "field %s", w.name)
		require.Equal(t, w.optional, f.IsOptional, "field %s", w.name)
	}
}

// TestDataTypeDefinition_Namespace0: every Structure of namespace 0 has a
// StructureDefinition and every Enumeration and OptionSet an
// EnumDefinition (Part 3 §5.8.3, Table 16), mapped from the Definition of
// the NodeSet (Part 6 §F.12).
func TestDataTypeDefinition_Namespace0(t *testing.T) {
	s := newGoldenServer(t)

	t.Run("BuildInfo", func(t *testing.T) {
		sd := structureDefinition(t, s, ns0(id.BuildInfo))
		require.Equal(t, ns0(id.BuildInfoEncodingDefaultBinary).String(), sd.DefaultEncodingID.String())
		require.Equal(t, ns0(id.Structure).String(), sd.BaseDataType.String())
		require.Equal(t, ua.StructureTypeStructure, sd.StructureType)
		str := ns0(id.String)
		requireFields(t, sd, []wantField{
			{"ProductUri", str, -1, nil, false},
			{"ManufacturerName", str, -1, nil, false},
			{"ProductName", str, -1, nil, false},
			{"SoftwareVersion", str, -1, nil, false},
			{"BuildNumber", str, -1, nil, false},
			{"BuildDate", ns0(id.UtcTime), -1, nil, false},
		})
	})
	t.Run("EUInformation", func(t *testing.T) {
		sd := structureDefinition(t, s, ns0(id.EUInformation))
		require.Equal(t, ns0(id.EUInformationEncodingDefaultBinary).String(), sd.DefaultEncodingID.String())
		requireFields(t, sd, []wantField{
			{"NamespaceUri", ns0(id.String), -1, nil, false},
			{"UnitId", ns0(id.Int32), -1, nil, false},
			{"DisplayName", ns0(id.LocalizedText), -1, nil, false},
			{"Description", ns0(id.LocalizedText), -1, nil, false},
		})
	})
	t.Run("NodeClass", func(t *testing.T) {
		ed := enumDefinition(t, s, ns0(id.NodeClass))
		want := []struct {
			name  string
			value int64
		}{{"Unspecified", 0}, {"Object", 1}, {"Variable", 2}, {"Method", 4}, {"ObjectType", 8}, {"VariableType", 16}, {"ReferenceType", 32}, {"DataType", 64}, {"View", 128}}
		require.Len(t, ed.Fields, len(want))
		for i, w := range want {
			require.Equal(t, w.name, ed.Fields[i].Name)
			require.Equal(t, w.value, ed.Fields[i].Value)
		}
		require.Equal(t, "No value is specified.", ed.Fields[0].Description.Text)
		require.NotNil(t, ed.Fields[0].DisplayName)
	})
	t.Run("AccessLevelType is an OptionSet of bit numbers", func(t *testing.T) {
		ed := enumDefinition(t, s, ns0(id.AccessLevelType))
		require.Len(t, ed.Fields, 7)
		for i, name := range []string{"CurrentRead", "CurrentWrite", "HistoryRead", "HistoryWrite", "SemanticChange", "StatusWrite", "TimestampWrite"} {
			require.Equal(t, name, ed.Fields[i].Name)
			require.Equal(t, int64(i), ed.Fields[i].Value)
		}
	})
	t.Run("OptionSet is a Structure", func(t *testing.T) {
		sd := structureDefinition(t, s, ns0(id.OptionSet))
		require.Nil(t, sd.DefaultEncodingID, "abstract")
		requireFields(t, sd, []wantField{
			{"Value", ns0(id.ByteString), -1, nil, false},
			{"ValidBits", ns0(id.ByteString), -1, nil, false},
		})
	})
	t.Run("Union", func(t *testing.T) {
		sd := structureDefinition(t, s, ns0(id.Union))
		require.Equal(t, ua.StructureTypeUnion, sd.StructureType)
		require.Equal(t, ns0(id.Structure).String(), sd.BaseDataType.String())
		require.Nil(t, sd.DefaultEncodingID)
		require.Empty(t, sd.Fields)
	})
	t.Run("abstract and inherited fields", func(t *testing.T) {
		sd := structureDefinition(t, s, ns0(id.UserIdentityToken))
		require.Nil(t, sd.DefaultEncodingID, "If the DataType is abstract the DefaultEncodingId shall be null")
		requireFields(t, sd, []wantField{{"PolicyId", ns0(id.String), -1, nil, false}})

		// AnonymousIdentityToken adds no field of its own.
		sd = structureDefinition(t, s, ns0(id.AnonymousIdentityToken))
		require.Equal(t, ns0(id.AnonymousIdentityTokenEncodingDefaultBinary).String(), sd.DefaultEncodingID.String())
		require.Equal(t, ns0(id.UserIdentityToken).String(), sd.BaseDataType.String())
		requireFields(t, sd, []wantField{{"PolicyId", ns0(id.String), -1, nil, false}})

		sd = structureDefinition(t, s, ns0(id.UserNameIdentityToken))
		require.Equal(t, "PolicyId", sd.Fields[0].Name)
		require.Equal(t, "UserName", sd.Fields[1].Name)
	})
	t.Run("optional fields", func(t *testing.T) {
		sd := structureDefinition(t, s, ns0(id.LogRecord))
		require.Equal(t, ua.StructureTypeStructureWithOptionalFields, sd.StructureType)
		requireFields(t, sd, []wantField{
			{"Time", ns0(id.DateTime), -1, nil, false},
			{"Severity", ns0(id.UInt16), -1, nil, false},
			{"EventType", ns0(id.NodeID), -1, nil, true},
			{"SourceNode", ns0(id.NodeID), -1, nil, true},
			{"SourceName", ns0(id.String), -1, nil, true},
			{"Message", ns0(id.LocalizedText), -1, nil, false},
			{"TraceContext", ns0(id.TraceContextDataType), -1, nil, true},
			{"AdditionalData", ns0(id.NameValuePair), 1, []uint32{0}, true},
		})
	})
	t.Run("subtyped values", func(t *testing.T) {
		sd := structureDefinition(t, s, ns0(id.PublishedDataSetDataType))
		require.Equal(t, ua.StructureTypeStructureWithSubtypedValues, sd.StructureType)
		requireFields(t, sd, []wantField{
			{"Name", ns0(id.String), -1, nil, false},
			{"DataSetFolder", ns0(id.String), 1, []uint32{0}, false},
			{"DataSetMetaData", ns0(id.DataSetMetaDataType), -1, nil, false},
			{"ExtensionFields", ns0(id.KeyValuePair), 1, []uint32{0}, false},
			// IsOptional says the field allows subtypes (Part 3 §8.51).
			{"DataSetSource", ns0(id.PublishedDataSetSourceDataType), -1, nil, true},
		})
	})
	t.Run("no attribute", func(t *testing.T) {
		// Optional for every DataType that is not derived from
		// Structure, Enumeration or OptionSet (Part 3 §5.8.3).
		for _, i := range []uint32{id.BaseDataType, id.Structure, id.Enumeration, id.Number, id.Int32, id.String, id.Duration, id.UtcTime, id.Image} {
			_, err := readDefinition(t, s, ns0(i))
			require.ErrorIs(t, err, ua.StatusBadAttributeIDInvalid, "i=%d", i)
		}
	})
	t.Run("every Structure and Enumeration", func(t *testing.T) {
		// Every DataType below Structure (but Structure) and below
		// Enumeration has the Attribute.
		var walk func(nid *ua.NodeID, structure bool)
		count := 0
		walk = func(nid *ua.NodeID, structure bool) {
			n := s.Node(nid)
			require.NotNil(t, n)
			for _, r := range n.refsSnapshot() {
				if !r.IsForward || r.ReferenceTypeID.IntID() != id.HasSubtype {
					continue
				}
				sub := r.NodeID.NodeID
				v, err := readDefinition(t, s, sub)
				require.NoError(t, err, "%s", sub)
				if structure {
					if _, ok := v.(*ua.StructureDefinition); !ok {
						_, ok = v.(*ua.EnumDefinition) // a subtype of OptionSet
						require.True(t, ok, "%s: %T", sub, v)
					}
				} else {
					require.IsType(t, &ua.EnumDefinition{}, v, "%s", sub)
				}
				count++
				walk(sub, structure)
			}
		}
		walk(ns0(id.Structure), true)
		walk(ns0(id.Enumeration), false)
		require.Greater(t, count, 200)
	})
}

// TestDataTypeDefinition_Read: a client reads the Attribute over the wire
// and decodes the StructureDefinition and the EnumDefinition.
func TestDataTypeDefinition_Read(t *testing.T) {
	srv, err := New(EndPoint("localhost", 0), InsecureNoSecurity(), EnableAuthMode(ua.UserTokenTypeAnonymous))
	require.NoError(t, err)
	require.NoError(t, srv.Start(context.Background()))
	cleanup.Register(t, func() { _ = srv.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := opcua.NewClient(srv.Endpoints()[0].EndpointURL, opcua.InsecureNoSecurity(), opcua.AutoReconnect(false))
	require.NoError(t, err)
	require.NoError(t, c.Connect(ctx))
	cleanup.Register(t, func() { _ = c.Close(context.Background()) })

	resp, err := c.Read(ctx, &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{
		{NodeID: ns0(id.BuildInfo), AttributeID: ua.AttributeIDDataTypeDefinition},
		{NodeID: ns0(id.NodeClass), AttributeID: ua.AttributeIDDataTypeDefinition},
		{NodeID: ns0(id.Int32), AttributeID: ua.AttributeIDDataTypeDefinition},
	}})
	require.NoError(t, err)
	require.Len(t, resp.Results, 3)
	require.Equal(t, ua.StatusOK, resp.Results[0].Status)
	sd, ok := resp.Results[0].Value.Value().(*ua.ExtensionObject).Value.(*ua.StructureDefinition)
	require.True(t, ok)
	require.Len(t, sd.Fields, 6)
	require.Equal(t, "BuildDate", sd.Fields[5].Name)
	ed, ok := resp.Results[1].Value.Value().(*ua.ExtensionObject).Value.(*ua.EnumDefinition)
	require.True(t, ok)
	require.Equal(t, "View", ed.Fields[8].Name)
	require.Equal(t, ua.StatusBadAttributeIDInvalid, resp.Results[2].Status)
}

// TestDataTypeDefinition_CompanionModels: the DataTypes of the GDS, DI and
// UAFX models, imported at the namespace indexes of the server, have the
// Attribute with the field DataTypes, supertypes and encodings in the
// namespaces of the server.
func TestDataTypeDefinition_CompanionModels(t *testing.T) {
	s := importGoldenNodeSets(t)
	idx := func(uri string) uint16 {
		i, ok := s.namespaceLookup(uri)
		require.True(t, ok, uri)
		return i
	}
	gds, di := idx("http://opcfoundation.org/UA/GDS/"), idx("http://opcfoundation.org/UA/DI/")
	fxData, fxAC, fxCM := idx("http://opcfoundation.org/UA/FX/Data/"), idx("http://opcfoundation.org/UA/FX/AC/"), idx("http://opcfoundation.org/UA/FX/CM/")

	t.Run("GDS ApplicationRecordDataType", func(t *testing.T) {
		sd := structureDefinition(t, s, ua.NewNumericNodeID(gds, 1))
		require.Equal(t, ua.StructureTypeStructure, sd.StructureType)
		require.Equal(t, gds, sd.DefaultEncodingID.Namespace())
		require.Equal(t, "ApplicationId", sd.Fields[0].Name)
		require.Equal(t, ns0(id.ApplicationType).String(), sd.Fields[2].DataType.String())
		require.Equal(t, int32(1), sd.Fields[3].ValueRank)
	})
	t.Run("DI enumeration and inherited fields", func(t *testing.T) {
		ed := enumDefinition(t, s, ua.NewNumericNodeID(di, 6244)) // DeviceHealthEnumeration
		require.Equal(t, "NORMAL", ed.Fields[0].Name)
		require.Equal(t, int64(1), ed.Fields[1].Value)

		sd := structureDefinition(t, s, ua.NewNumericNodeID(di, 6522)) // FetchResultDataType, abstract
		require.Nil(t, sd.DefaultEncodingID)
		require.Empty(t, sd.Fields)
		sd = structureDefinition(t, s, ua.NewNumericNodeID(di, 15889)) // TransferResultDataDataType
		require.Equal(t, ua.NewNumericNodeID(di, 6522).String(), sd.BaseDataType.String())
		require.Equal(t, ua.NewNumericNodeID(di, 6525).String(), sd.Fields[2].DataType.String())
	})
	t.Run("FX union", func(t *testing.T) {
		sd := structureDefinition(t, s, ua.NewNumericNodeID(fxAC, 3013)) // ApplicationId
		require.Equal(t, ua.StructureTypeUnion, sd.StructureType)
		require.Equal(t, ns0(id.Union).String(), sd.BaseDataType.String())
		requireFields(t, sd, []wantField{
			{"IdNumeric", ns0(id.UInt32), -1, nil, false},
			{"IdString", ns0(id.String), -1, nil, false},
			{"IdGuid", ns0(id.GUID), -1, nil, false},
			{"IdByteString", ns0(id.ByteString), -1, nil, false},
		})
	})
	t.Run("FX union with subtyped values", func(t *testing.T) {
		sd := structureDefinition(t, s, ua.NewNumericNodeID(fxData, 3011)) // ConnectionEndpointDefinitionDataType
		require.Equal(t, ua.StructureTypeUnionWithSubtypedValues, sd.StructureType)
		require.True(t, sd.Fields[0].IsOptional)
		require.Equal(t, fxData, sd.Fields[0].DataType.Namespace())
		require.False(t, sd.Fields[1].IsOptional)
	})
	t.Run("FX optional fields", func(t *testing.T) {
		found := 0
		for _, n := range s.namespaces[fxCM].(*NodeNameSpace).Nodes() {
			if n.NodeClass() != ua.NodeClassDataType {
				continue
			}
			v, err := readDefinition(t, s, n.ID())
			require.NoError(t, err, "%s", n.ID())
			sd, ok := v.(*ua.StructureDefinition)
			if !ok || sd.StructureType != ua.StructureTypeStructureWithOptionalFields {
				continue
			}
			found++
			optional := 0
			for _, f := range sd.Fields {
				if f.IsOptional {
					optional++
				}
			}
			require.Positive(t, optional, "%s", n.ID())
		}
		require.Positive(t, found)
	})
	t.Run("every DataType of the models", func(t *testing.T) {
		for _, ns := range []uint16{gds, di, fxData, fxAC, fxCM} {
			for _, n := range s.namespaces[ns].(*NodeNameSpace).Nodes() {
				if n.NodeClass() != ua.NodeClassDataType {
					continue
				}
				_, err := readDefinition(t, s, n.ID())
				require.NoError(t, err, "%s %s", n.ID(), n.BrowseName().Name)
			}
		}
	})
}

// definitionDoc is a NodeSet2 document in namespace urn:test:defs with the
// DataTypes types (UADataType elements) and the encodings encodings.
func definitionDoc(body string) []byte {
	return []byte(`<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris><Uri>urn:test:defs</Uri></NamespaceUris>
  <Aliases>
    <Alias Alias="Int32">i=6</Alias>
    <Alias Alias="String">i=12</Alias>
    <Alias Alias="HasSubtype">i=45</Alias>
    <Alias Alias="HasEncoding">i=38</Alias>
    <Alias Alias="HasTypeDefinition">i=40</Alias>
  </Aliases>` + body + `
</UANodeSet>`)
}

// dataType is a UADataType of definitionDoc, a subtype of super, with the
// definition def (without the Definition element when empty) and, when
// encoding is not 0, a Default Binary encoding with that identifier.
func dataType(nodeID int, name, super, def string, encoding int, attrs string) string {
	out := `
  <UADataType NodeId="ns=1;i=` + itoa(nodeID) + `" BrowseName="1:` + name + `"` + attrs + `>
    <DisplayName>` + name + `</DisplayName>
    <References><Reference ReferenceType="HasSubtype" IsForward="false">` + super + `</Reference></References>` + def + `
  </UADataType>`
	if encoding != 0 {
		out += `
  <UAObject NodeId="ns=1;i=` + itoa(encoding) + `" BrowseName="Default Binary">
    <DisplayName>Default Binary</DisplayName>
    <References>
      <Reference ReferenceType="HasEncoding" IsForward="false">ns=1;i=` + itoa(nodeID) + `</Reference>
      <Reference ReferenceType="HasTypeDefinition">i=76</Reference>
    </References>
  </UAObject>`
	}
	return out
}

func itoa(i int) string { return strconv.Itoa(i) }

// importDefinitions imports doc into a new server at the namespace index
// at (the document's namespace 1 lands there) and returns the server and
// the log.
func importDefinitions(t *testing.T, doc []byte, at int) (*Server, uint16, *bytes.Buffer) {
	t.Helper()
	var log bytes.Buffer
	s, err := New(SetLogger(slog.New(slog.NewTextHandler(&log, &slog.HandlerOptions{Level: slog.LevelWarn}))))
	require.NoError(t, err)
	cleanup.Register(t, func() { _ = s.Close() })
	for len(s.Namespaces()) < at {
		NewNodeNameSpace(s, "urn:test:filler:"+itoa(len(s.Namespaces())))
	}
	require.NoError(t, s.ImportNodeSetXML(doc))
	ns, ok := s.namespaceLookup("urn:test:defs")
	require.True(t, ok)
	return s, ns, &log
}

// TestDataTypeDefinition_Import: the mapping of Definitions of Part 6
// §F.12 and §F.13, the inheritance of fields through HasSubtype, and the
// Definitions that cannot be mapped, which are logged and left out.
func TestDataTypeDefinition_Import(t *testing.T) {
	doc := definitionDoc(
		// A Structure with an array field without ArrayDimensions, a
		// matrix, a field without DataType and a field of the set.
		dataType(100, "Base", "i=22", `
    <Definition Name="1:Base">
      <Field Name="A" DataType="Int32"><Description Locale="en">the a</Description></Field>
      <Field Name="List" DataType="String" ValueRank="1"/>
      <Field Name="Matrix" DataType="i=6" ValueRank="2" ArrayDimensions="2, 3"/>
      <Field Name="Any"/>
      <Field Name="Nested" DataType="ns=1;i=103" MaxStringLength="7"/>
    </Definition>`, 1100, "") +
			// A subtype: the fields of Base, then its own.
			dataType(101, "Derived", "ns=1;i=100", `
    <Definition Name="1:Derived"><Field Name="B" DataType="String"/></Definition>`, 1101, "") +
			// A subtype without fields of its own.
			dataType(102, "Same", "ns=1;i=101", "", 1102, "") +
			dataType(103, "Leaf", "i=22", `
    <Definition Name="1:Leaf"><Field Name="X" DataType="i=6"/></Definition>`, 0, "") +
			// Optional fields, inherited by a subtype.
			dataType(104, "Opt", "i=22", `
    <Definition Name="1:Opt"><Field Name="O" DataType="i=6" IsOptional="true"/><Field Name="M" DataType="i=6"/></Definition>`, 1104, "") +
			dataType(105, "OptSub", "ns=1;i=104", `
    <Definition Name="1:OptSub"><Field Name="N" DataType="i=6"/></Definition>`, 1105, "") +
			// An enumeration and a subtype of it without fields.
			dataType(106, "Colour", "i=29", `
    <Definition Name="1:Colour"><Field Name="Red" Value="1"><DisplayName>red</DisplayName></Field><Field Name="Blue" Value="5"/></Definition>`, 0, "") +
			dataType(107, "Shade", "ns=1;i=106", "", 0, "") +
			// An OptionSet of a UInteger.
			dataType(108, "Flags", "i=7", `
    <Definition Name="1:Flags" IsOptionSet="true"><Field Name="On" Value="0"/><Field Name="Fast" Value="3"/></Definition>`, 0, "") +
			// A union.
			dataType(109, "Choice", "i=12756", `
    <Definition Name="1:Choice" IsUnion="true"><Field Name="I" DataType="i=6"/><Field Name="S" DataType="i=12"/></Definition>`, 1109, "") +
			// A simple DataType: no Attribute.
			dataType(110, "Name", "i=12", "", 0, "") +
			// An abstract Structure with a Default Binary encoding all
			// the same: the DefaultEncodingId is null.
			dataType(111, "Abstract", "i=22", `
    <Definition Name="1:Abstract"><Field Name="X" DataType="i=6"/></Definition>`, 1111, ` IsAbstract="true"`))

	for _, at := range []int{0, 4} { // the document's index, and another
		s, ns, log := importDefinitions(t, doc, at)
		nid := func(i uint32) *ua.NodeID { return ua.NewNumericNodeID(ns, i) }

		base := structureDefinition(t, s, nid(100))
		require.Equal(t, nid(1100).String(), base.DefaultEncodingID.String())
		require.Equal(t, ns0(id.Structure).String(), base.BaseDataType.String())
		baseFields := []wantField{
			{"A", ns0(id.Int32), -1, nil, false},
			{"List", ns0(id.String), 1, []uint32{0}, false},
			{"Matrix", ns0(id.Int32), 2, []uint32{2, 3}, false},
			{"Any", ns0(id.BaseDataType), -1, nil, false},
			{"Nested", nid(103), -1, nil, false},
		}
		requireFields(t, base, baseFields)
		require.Equal(t, "the a", base.Fields[0].Description.Text)
		require.Equal(t, "en", base.Fields[0].Description.Locale)
		require.Equal(t, uint32(7), base.Fields[4].MaxStringLength)

		derived := structureDefinition(t, s, nid(101))
		require.Equal(t, nid(100).String(), derived.BaseDataType.String())
		requireFields(t, derived, append(append([]wantField{}, baseFields...), wantField{"B", ns0(id.String), -1, nil, false}))
		same := structureDefinition(t, s, nid(102))
		require.Equal(t, nid(1102).String(), same.DefaultEncodingID.String())
		require.Len(t, same.Fields, 6)
		// The copies of the inherited fields are the subtype's own.
		same.Fields[2].ArrayDimensions[0] = 9
		require.Equal(t, uint32(2), base.Fields[2].ArrayDimensions[0])

		leaf := structureDefinition(t, s, nid(103))
		require.Nil(t, leaf.DefaultEncodingID, "no Default Binary encoding")

		optSub := structureDefinition(t, s, nid(105))
		require.Equal(t, ua.StructureTypeStructureWithOptionalFields, optSub.StructureType, "Part 6 §5.2.7: the subtypes extend the EncodingMask")
		requireFields(t, optSub, []wantField{
			{"O", ns0(id.Int32), -1, nil, true},
			{"M", ns0(id.Int32), -1, nil, false},
			{"N", ns0(id.Int32), -1, nil, false},
		})

		colour := enumDefinition(t, s, nid(106))
		require.Equal(t, "Red", colour.Fields[0].Name)
		require.Equal(t, int64(1), colour.Fields[0].Value)
		require.Equal(t, "red", colour.Fields[0].DisplayName.Text)
		require.Equal(t, int64(5), colour.Fields[1].Value)
		require.Equal(t, colour, enumDefinition(t, s, nid(107)))

		flags := enumDefinition(t, s, nid(108))
		require.Equal(t, int64(3), flags.Fields[1].Value)

		choice := structureDefinition(t, s, nid(109))
		require.Equal(t, ua.StructureTypeUnion, choice.StructureType)
		require.Equal(t, ns0(id.Union).String(), choice.BaseDataType.String())
		require.Len(t, choice.Fields, 2)

		_, err := readDefinition(t, s, nid(110))
		require.ErrorIs(t, err, ua.StatusBadAttributeIDInvalid)

		abstract := structureDefinition(t, s, nid(111))
		require.Nil(t, abstract.DefaultEncodingID)
		require.Empty(t, log.String())
	}
}

// TestDataTypeDefinition_Invalid: a Definition this server cannot map is
// logged and the DataType has no Attribute; the import succeeds.
func TestDataTypeDefinition_Invalid(t *testing.T) {
	for _, tc := range []struct {
		name, types, warn string
	}{
		{"union with optional fields", dataType(100, "T", "i=12756", `<Definition Name="1:T" IsUnion="true"><Field Name="A" DataType="i=6" IsOptional="true"/></Definition>`, 0, ""), "Table F.13"},
		{"optional fields and subtyped values", dataType(100, "T", "i=22", `<Definition Name="1:T"><Field Name="A" DataType="i=6" IsOptional="true"/><Field Name="B" DataType="i=22" AllowSubTypes="true"/></Definition>`, 0, ""), "Table F.13"},
		{"subtype with optional fields of a subtyped structure", dataType(99, "P", "i=22", `<Definition Name="1:P"><Field Name="B" DataType="i=22" AllowSubTypes="true"/></Definition>`, 0, "") +
			dataType(100, "T", "ns=1;i=99", `<Definition Name="1:T"><Field Name="A" DataType="i=6" IsOptional="true"/></Definition>`, 0, ""), "Table F.13"},
		{"unknown alias", dataType(100, "T", "i=22", `<Definition Name="1:T"><Field Name="A" DataType="NoSuchType"/></Definition>`, 0, ""), "unknown DataType"},
		{"ValueRank 0", dataType(100, "T", "i=22", `<Definition Name="1:T"><Field Name="A" DataType="i=6" ValueRank="0"/></Definition>`, 0, ""), "ValueRank 0"},
		{"ValueRank Any", dataType(100, "T", "i=22", `<Definition Name="1:T"><Field Name="A" DataType="i=6" ValueRank="-2"/></Definition>`, 0, ""), "ValueRank -2"},
		{"ValueRank too large", dataType(100, "T", "i=22", `<Definition Name="1:T"><Field Name="A" DataType="i=6" ValueRank="4096"/></Definition>`, 0, ""), "ValueRank 4096"},
		{"ArrayDimensions for another rank", dataType(100, "T", "i=22", `<Definition Name="1:T"><Field Name="A" DataType="i=6" ValueRank="2" ArrayDimensions="3"/></Definition>`, 0, ""), "ArrayDimensions"},
		{"ArrayDimensions not a number", dataType(100, "T", "i=22", `<Definition Name="1:T"><Field Name="A" DataType="i=6" ValueRank="1" ArrayDimensions="x"/></Definition>`, 0, ""), "ArrayDimensions"},
		{"fields on a simple DataType", dataType(100, "T", "i=12", `<Definition Name="1:T"><Field Name="A" DataType="i=6"/></Definition>`, 0, ""), "no Structure"},
		{"supertype an OptionSet", dataType(99, "P", "i=12755", `<Definition Name="1:P" IsOptionSet="true"><Field Name="On" Value="0"/></Definition>`, 0, "") +
			dataType(100, "T", "ns=1;i=99", `<Definition Name="1:T"><Field Name="A" DataType="i=6"/></Definition>`, 0, ""), "no StructureDefinition"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, ns, log := importDefinitions(t, definitionDoc(tc.types), 0)
			_, err := readDefinition(t, s, ua.NewNumericNodeID(ns, 100))
			require.ErrorIs(t, err, ua.StatusBadAttributeIDInvalid)
			require.Contains(t, log.String(), "DataTypeDefinition left out")
			require.Contains(t, log.String(), tc.warn)
		})
	}
}

// TestDataTypeDefinition_Cycle: a HasSubtype cycle of a malformed model
// ends the walk.
func TestDataTypeDefinition_Cycle(t *testing.T) {
	doc := definitionDoc(
		dataType(100, "A", "ns=1;i=101", `<Definition Name="1:A"><Field Name="X" DataType="i=6"/></Definition>`, 0, "") +
			dataType(101, "B", "ns=1;i=100", `<Definition Name="1:B"><Field Name="Y" DataType="i=6"/></Definition>`, 0, ""))
	s, ns, _ := importDefinitions(t, doc, 0)
	for _, i := range []uint32{100, 101} {
		_, err := readDefinition(t, s, ua.NewNumericNodeID(ns, i))
		require.ErrorIs(t, err, ua.StatusBadAttributeIDInvalid)
	}
	kind, _ := s.kindOf(ua.NewNumericNodeID(ns, 100))
	require.Equal(t, kindOther, kind)
}

// TestDataTypeDefinition_SupertypeOfAnotherImport: a DataType inherits the
// fields of a supertype a NodeSet imported before declared, and of one a
// Go program gave the Attribute by hand.
func TestDataTypeDefinition_SupertypeOfAnotherImport(t *testing.T) {
	s, ns, log := importDefinitions(t, definitionDoc(dataType(100, "Base", "i=22", `<Definition Name="1:Base"><Field Name="A" DataType="i=6"/></Definition>`, 0, "")), 0)

	// A DataType of the program, with the Attribute set by hand.
	space := s.namespaces[ns].(*NodeNameSpace)
	byHand := NewNode(ua.NewNumericNodeID(ns, 300), Attributes{
		ua.AttributeIDNodeClass:  DataValueFromValue(uint32(ua.NodeClassDataType)),
		ua.AttributeIDBrowseName: DataValueFromValue(&ua.QualifiedName{NamespaceIndex: ns, Name: "ByHand"}),
		ua.AttributeIDDataTypeDefinition: DataValueFromValue(ua.NewExtensionObject(&ua.StructureDefinition{
			BaseDataType:  ns0(id.Structure),
			StructureType: ua.StructureTypeStructureWithOptionalFields,
			Fields:        []*ua.StructureField{{Name: "H", DataType: ns0(id.Double), ValueRank: -1, IsOptional: true}, nil},
		})),
	}, nil, nil)
	space.AddNode(byHand)
	s.Node(ns0(id.Structure)).AddRef(byHand, RefType(id.HasSubtype), true)
	// One without the Attribute.
	without := NewNode(ua.NewNumericNodeID(ns, 301), Attributes{
		ua.AttributeIDNodeClass:  DataValueFromValue(uint32(ua.NodeClassDataType)),
		ua.AttributeIDBrowseName: DataValueFromValue(&ua.QualifiedName{NamespaceIndex: ns, Name: "Without"}),
	}, nil, nil)
	space.AddNode(without)
	s.Node(ns0(id.Structure)).AddRef(without, RefType(id.HasSubtype), true)

	require.NoError(t, s.ImportNodeSetXML(definitionDoc(
		dataType(200, "Sub", "ns=1;i=100", `<Definition Name="1:Sub"><Field Name="B" DataType="i=12"/></Definition>`, 0, "")+
			dataType(201, "SubOfProgram", "ns=1;i=300", `<Definition Name="1:SubOfProgram"><Field Name="C" DataType="i=12"/></Definition>`, 0, "")+
			dataType(202, "SubOfWithout", "ns=1;i=301", `<Definition Name="1:SubOfWithout"><Field Name="D" DataType="i=12"/></Definition>`, 0, ""))))
	sd := structureDefinition(t, s, ua.NewNumericNodeID(ns, 200))
	requireFields(t, sd, []wantField{{"A", ns0(id.Int32), -1, nil, false}, {"B", ns0(id.String), -1, nil, false}})
	sd = structureDefinition(t, s, ua.NewNumericNodeID(ns, 201))
	require.Equal(t, ua.StructureTypeStructureWithOptionalFields, sd.StructureType)
	requireFields(t, sd, []wantField{{"H", ns0(id.Double), -1, nil, true}, {"C", ns0(id.String), -1, nil, false}})
	// Without the fields of the supertype there is no definition.
	_, err := readDefinition(t, s, ua.NewNumericNodeID(ns, 202))
	require.ErrorIs(t, err, ua.StatusBadAttributeIDInvalid)
	require.Contains(t, log.String(), "has no DataTypeDefinition")
}

// TestDataTypeDefinition_Guards: references to nodes the address space
// does not have, a node that is not in it.
func TestDataTypeDefinition_Guards(t *testing.T) {
	s := newTestServer()
	missing := ua.NewNumericNodeID(0, 999999)
	dangling := NewNode(ua.NewNumericNodeID(0, 999998), nil, References{
		{ReferenceTypeID: ns0(id.HasSubtype), IsForward: false, NodeID: ua.NewExpandedNodeID(missing, "", 0)},
		{ReferenceTypeID: ns0(id.HasEncoding), IsForward: true, NodeID: ua.NewExpandedNodeID(missing, "", 0)},
	}, nil)
	require.Equal(t, missing.String(), supertypeOf(dangling).String())
	kind, _ := s.kindOf(missing)
	require.Equal(t, kindOther, kind)
	require.Nil(t, s.defaultBinaryEncoding(dangling))
	require.Nil(t, attributeDefinition(nil))

	d := &definitionImport{s: s, byID: map[string]*nodeset.Node{}, done: map[string]*ua.ExtensionObject{}}
	eo, err := d.build(missing, &nodeset.Node{NodeID: missing.String()})
	require.NoError(t, err)
	require.Nil(t, eo)
}
