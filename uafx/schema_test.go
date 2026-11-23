// SPDX-License-Identifier: MIT

package uafx

import (
	"encoding/xml"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// schemaType and schemaField describe a generated DataType for the tests
// (schema_gen_test.go): what cmd/uafx took from the NodeSet.
type schemaType struct {
	ns, name      string
	enum          bool
	values        int
	union         bool
	abstract      bool
	binary        uint32 // the Default Binary encoding in the NodeSet
	encodingConst uint32 // the same from package fx*id
	value         Structure
	fields        []schemaField
}

type schemaField struct {
	name, dataType      string
	array, optional, eo bool
}

// --- Binary Schema (OPC 10000-3 Annex C / Part 6 §5.2.6) ---------------------

type bsdDictionary struct {
	Structs []bsdStruct `xml:"StructuredType"`
	Enums   []bsdEnum   `xml:"EnumeratedType"`
}

type bsdStruct struct {
	Name     string     `xml:"Name,attr"`
	BaseType string     `xml:"BaseType,attr"`
	Fields   []bsdField `xml:"Field"`
}

type bsdField struct {
	Name        string `xml:"Name,attr"`
	TypeName    string `xml:"TypeName,attr"`
	LengthField string `xml:"LengthField,attr"`
	SwitchField string `xml:"SwitchField,attr"`
	SwitchValue string `xml:"SwitchValue,attr"`
}

type bsdEnum struct {
	Name   string `xml:"Name,attr"`
	Values []struct {
		Name string `xml:"Name,attr"`
	} `xml:"EnumeratedValue"`
}

// wireField is a field as the Binary Schema encodes it.
type wireField struct {
	name, typeName  string
	array, optional bool
	bit             int    // the bit of the EncodingMask of an optional field
	switchValue     string // the SwitchValue of a union field
}

func loadBSD(t *testing.T, ns string) (map[string][]wireField, map[string]bool, map[string]int) {
	t.Helper()
	raw, err := os.ReadFile("../schema/opc.ua.fx." + ns + ".nodeset2.bsd")
	require.NoError(t, err)
	var d bsdDictionary
	require.NoError(t, xml.Unmarshal(raw, &d))
	structs := map[string][]wireField{}
	unions := map[string]bool{}
	for _, s := range d.Structs {
		unions[s.Name] = s.BaseType == "ua:Union"
		bits := map[string]int{}
		nbit := 0
		lengths := map[string]bool{}
		for _, f := range s.Fields {
			if f.LengthField != "" {
				lengths[f.LengthField] = true
			}
		}
		var out []wireField
		for _, f := range s.Fields {
			switch {
			case f.TypeName == "opc:Bit":
				if name, ok := strings.CutSuffix(f.Name, "Specified"); ok {
					bits[name] = nbit
					nbit++
				}
				continue
			case lengths[f.Name]:
				continue // the length of an array
			case unions[s.Name] && f.Name == "SwitchField":
				continue
			}
			w := wireField{name: f.Name, typeName: f.TypeName, array: f.LengthField != "", switchValue: f.SwitchValue}
			if b, ok := bits[f.Name]; ok {
				w.optional, w.bit = true, b
			}
			out = append(out, w)
		}
		structs[s.Name] = out
	}
	enums := map[string]int{}
	for _, e := range d.Enums {
		enums[e.Name] = len(e.Values)
	}
	return structs, unions, enums
}

// bsdTypes are the TypeNames of the Binary Schema of the DataTypes of
// namespace 0 the UAFX NodeSets use.
var bsdTypes = map[string]string{
	"Boolean": "opc:Boolean", "Byte": "opc:Byte", "UInt16": "opc:UInt16", "Int32": "opc:Int32",
	"UInt32": "opc:UInt32", "String": "opc:CharArray", "UriString": "opc:CharArray", "Duration": "opc:Double",
	"Guid": "opc:Guid", "ByteString": "opc:ByteString", "NodeId": "ua:NodeId", "StatusCode": "ua:StatusCode",
	"QualifiedName": "ua:QualifiedName", "LocalizedText": "ua:LocalizedText", "BaseDataType": "ua:Variant",
	"Structure": "ua:ExtensionObject",
}

// TestSchemaMatchesBinarySchema compares the structures cmd/uafx generated
// from the NodeSets with the Binary Schemas of the same NodeSets, which it
// does not read: every DataType of the schemas is generated, with the fields
// in the order of the encoding, the bits of the optional fields, the
// SwitchValues of the unions and the fields that are ExtensionObjects.
func TestSchemaMatchesBinarySchema(t *testing.T) {
	generated := map[string]schemaType{}
	for _, g := range generatedSchema {
		generated[g.ns+":"+g.name] = g
	}
	for _, ns := range []string{"data", "ac", "cm"} {
		structs, unions, enums := loadBSD(t, ns)
		for name, n := range enums {
			g, ok := generated[ns+":"+name]
			if assert.True(t, ok, "%s:%s is not generated", ns, name) {
				assert.True(t, g.enum, name)
				assert.Equal(t, n, g.values, name)
			}
		}
		for name, want := range structs {
			g, ok := generated[ns+":"+name]
			if !assert.True(t, ok, "%s:%s is not generated", ns, name) {
				continue
			}
			assert.Equal(t, unions[name], g.union, name)
			if !assert.Len(t, g.fields, len(want), "%s: fields", name) {
				continue
			}
			for i, w := range want {
				f := g.fields[i]
				assert.Equal(t, w.name, f.name, "%s field %d", name, i)
				assert.Equal(t, w.array, f.array, "%s.%s array", name, w.name)
				assert.Equal(t, w.optional, f.optional, "%s.%s optional", name, w.name)
				if g.union {
					assert.Equal(t, itoa(i+1), w.switchValue, "%s.%s SwitchValue", name, w.name)
				}
				switch {
				case f.eo:
					assert.Equal(t, "ua:ExtensionObject", w.typeName, "%s.%s", name, w.name)
				case bsdTypes[f.dataType] != "":
					assert.Equal(t, bsdTypes[f.dataType], w.typeName, "%s.%s", name, w.name)
				default:
					_, local, _ := strings.Cut(w.typeName, ":")
					assert.Equal(t, f.dataType, local, "%s.%s", name, w.name)
				}
			}
			if bits := optionalBits(g); bits != nil {
				var got []int
				for _, w := range want {
					if w.optional {
						got = append(got, w.bit)
					}
				}
				assert.Equal(t, bits, got, "%s EncodingMask bits", name)
			}
		}
		for key, g := range generated {
			if !strings.HasPrefix(key, ns+":") {
				continue
			}
			_, isStruct := structs[g.name]
			_, isEnum := enums[g.name]
			assert.True(t, isStruct || isEnum, "%s is generated but not in the Binary Schema", key)
		}
	}
}

// optionalBits are the EncodingMask bits the generated code gives the
// optional fields of g: their order among the optional fields.
func optionalBits(g schemaType) []int {
	var out []int
	for _, f := range g.fields {
		if f.optional {
			out = append(out, len(out))
		}
	}
	return out
}

// TestSchemaEncodings checks the Default Binary encodings the generated code
// uses against the NodeSet.
func TestSchemaEncodings(t *testing.T) {
	for _, g := range generatedSchema {
		if g.enum || g.abstract {
			continue
		}
		assert.NotZero(t, g.binary, g.name)
		assert.Equal(t, g.binary, g.encodingConst, g.name)
		assert.Equal(t, g.binary, g.value.encodingID().id, g.name)
		assert.NotNil(t, structures[g.value.encodingID()], g.name)
	}
}
