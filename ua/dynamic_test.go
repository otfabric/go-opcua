// SPDX-License-Identifier: MIT

package ua

import (
	"errors"
	"math"
	"reflect"
	"runtime"
	"testing"
	"time"

	uaerrors "github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/id"
	"github.com/stretchr/testify/require"
)

// The test DataTypes are in namespace 2: DataType n has the encoding n+1.
func dynID(n uint32) *NodeID { return NewFourByteNodeID(2, uint16(n)) }

func dynField(name string, dataType *NodeID, valueRank int32) *StructureField {
	return &StructureField{Name: name, DataType: dataType, ValueRank: valueRank}
}

func dynStructure(n uint32, st StructureType, fields ...*StructureField) *DynamicType {
	return &DynamicType{DataTypeID: dynID(n), Name: "T" + string(rune('A'+n%26)), Definition: &StructureDefinition{
		DefaultEncodingID: dynID(n + 1),
		BaseDataType:      NewNumericNodeID(0, id.Structure),
		StructureType:     st,
		Fields:            fields,
	}}
}

func ns0(n uint32) *NodeID { return NewNumericNodeID(0, n) }

const (
	dtInner      = 100
	dtOuter      = 110
	dtEnum       = 120
	dtOptionSet  = 121
	dtUIntOption = 122
	dtString     = 123
	dtAbstract   = 124
	dtTypeA      = 130 // OPC 10000-6 §5.2.7
	dtType1      = 140 // OPC 10000-6 §5.2.8
	dtType2      = 150
	dtSubtyped   = 160
	dtSubUnion   = 170
	dtRecursive  = 180
	dtEmpty      = 190
	dtUnknownFld = 200
)

// dynSet returns a set with every test DataType.
func dynSet(t testing.TB) *DynamicTypes {
	t.Helper()
	s := NewDynamicTypes()
	abstract := dynStructure(dtAbstract, StructureTypeStructure)
	abstract.IsAbstract = true
	abstract.Definition.(*StructureDefinition).DefaultEncodingID = nil
	optA := dynField("O1", ns0(id.Int32), -1)
	optA.IsOptional = true
	optB := dynField("O2", ns0(id.Int32), -1)
	optB.IsOptional = true
	subV := dynField("V", dynID(dtInner), -1)
	subV.IsOptional = true
	subW := dynField("W", ns0(id.Int32), -1)
	subW.IsOptional = true
	for _, dt := range []*DynamicType{
		dynStructure(dtInner, StructureTypeStructure,
			dynField("A", ns0(id.Int32), -1), dynField("B", ns0(id.String), -1)),
		dynStructure(dtOuter, StructureTypeStructure,
			dynField("I", ns0(id.Int32), -1),
			dynField("S", ns0(id.String), -1),
			dynField("LT", ns0(id.LocalizedText), -1),
			dynField("In", dynID(dtInner), -1),
			dynField("Arr", ns0(id.Int32), 1),
			dynField("Ins", dynID(dtInner), 1),
			dynField("M", ns0(id.Double), 2),
			dynField("V", ns0(id.BaseDataType), -1),
			dynField("N", ns0(id.Number), -1),
			dynField("St", ns0(id.Structure), -1),
			dynField("Dec", ns0(id.Decimal), -1),
			dynField("EU", ns0(id.EUInformation), -1),
			dynField("E", dynID(dtEnum), -1),
			dynField("OS", dynID(dtOptionSet), -1),
			dynField("U", dynID(dtUIntOption), -1),
			dynField("Str", dynID(dtString), -1),
			dynField("Abs", dynID(dtAbstract), -1),
			dynField("Opt", ns0(id.OptionSet), -1),
			dynField("EUs", ns0(id.EUInformation), 1),
			dynField("Time", ns0(id.DateTime), -1),
		),
		{DataTypeID: dynID(dtEnum), Definition: &EnumDefinition{Fields: []*EnumField{{Name: "Off", Value: 0}, {Name: "On", Value: 1}}}, BuiltIn: TypeIDInt32},
		{DataTypeID: dynID(dtOptionSet), Definition: &EnumDefinition{}, BuiltIn: TypeIDExtensionObject},
		{DataTypeID: dynID(dtUIntOption), Definition: &EnumDefinition{}, BuiltIn: TypeIDUint32},
		{DataTypeID: dynID(dtString), BuiltIn: TypeIDString},
		abstract,
		dynStructure(dtTypeA, StructureTypeStructureWithOptionalFields,
			dynField("X", ns0(id.Int32), -1), optA, dynField("Y", ns0(id.SByte), -1), optB),
		dynStructure(dtType1, StructureTypeUnion,
			dynField("Field1", ns0(id.Int32), -1), dynField("Field2", dynID(dtType2), -1)),
		dynStructure(dtType2, StructureTypeStructure,
			dynField("A", ns0(id.Int32), -1), dynField("B", ns0(id.Int32), -1)),
		dynStructure(dtSubtyped, StructureTypeStructureWithSubtypedValues,
			subV, subW, dynField("X", ns0(id.Int32), -1)),
		dynStructure(dtSubUnion, StructureTypeUnionWithSubtypedValues, subV, subW),
		dynStructure(dtRecursive, StructureTypeStructure, dynField("Next", dynID(dtRecursive), 1)),
		dynStructure(dtEmpty, StructureTypeStructure),
		dynStructure(dtUnknownFld, StructureTypeStructure, dynField("X", dynID(999), -1)),
	} {
		require.NoError(t, s.Add(dt))
	}
	return s
}

// dynEncode returns the binary ExtensionObject of v.
func dynEncode(t *testing.T, v *DynamicStructure) []byte {
	t.Helper()
	b, err := NewExtensionObject(v).Encode()
	require.NoError(t, err)
	return b
}

// dynDecode decodes the ExtensionObject b as a program without its Go
// type does, then with the set.
func dynDecode(t *testing.T, s *DynamicTypes, b []byte) (*ExtensionObject, error) {
	t.Helper()
	eo := new(ExtensionObject)
	n, err := eo.Decode(b)
	require.NoError(t, err)
	require.Equal(t, len(b), n)
	require.Nil(t, eo.Value)
	return eo, s.DecodeExtensionObject(eo)
}

func TestDynamicTypes_Add(t *testing.T) {
	s := NewDynamicTypes()
	bad := func(dt *DynamicType) {
		t.Helper()
		require.ErrorIs(t, s.Add(dt), StatusBadInvalidArgument)
	}
	bad(nil)
	bad(&DynamicType{})
	bad(&DynamicType{DataTypeID: dynID(1), Definition: "x"})
	bad(dynStructure(1, StructureType(5)))
	bad(dynStructure(1, StructureTypeStructure, nil))
	bad(dynStructure(1, StructureTypeStructure, &StructureField{Name: "X"}))
	for _, rank := range []int32{0, -2, -3} {
		bad(dynStructure(1, StructureTypeStructure, dynField("X", ns0(id.Int32), rank)))
	}
	var fields []*StructureField
	for range 33 {
		f := dynField("O", ns0(id.Int32), -1)
		f.IsOptional = true
		fields = append(fields, f)
	}
	bad(dynStructure(1, StructureTypeStructureWithOptionalFields, fields...))
	// 33 fields that "allow subtypes" are no optional fields.
	require.NoError(t, s.Add(dynStructure(1, StructureTypeStructureWithSubtypedValues, fields...)))
	require.NoError(t, s.Add(dynStructure(1, StructureTypeStructureWithOptionalFields, fields[:32]...)))

	// A DataType added again replaces the first, and its encoding.
	first := dynStructure(10, StructureTypeStructure)
	require.NoError(t, s.Add(first))
	require.Same(t, first, s.TypeByEncoding(dynID(11)))
	second := dynStructure(10, StructureTypeStructure)
	second.Definition.(*StructureDefinition).DefaultEncodingID = dynID(12)
	require.NoError(t, s.Add(second))
	require.Nil(t, s.TypeByEncoding(dynID(11)))
	require.Same(t, second, s.TypeByEncoding(dynID(12)))
	require.Same(t, second, s.Type(dynID(10)))
	require.Nil(t, s.Type(nil))
	require.Nil(t, s.TypeByEncoding(nil))

	// A DataType without a definition, and one with a null encoding.
	require.NoError(t, s.Add(&DynamicType{DataTypeID: dynID(20), BuiltIn: TypeIDString}))
	null := dynStructure(30, StructureTypeStructure)
	null.Definition.(*StructureDefinition).DefaultEncodingID = NewTwoByteNodeID(0)
	require.NoError(t, s.Add(null))
	require.Nil(t, s.TypeByEncoding(NewTwoByteNodeID(0)))

	_, err := s.New(dynID(20))
	require.ErrorIs(t, err, StatusBadDataTypeIDUnknown)
	_, err = s.New(dynID(99))
	require.ErrorIs(t, err, StatusBadDataTypeIDUnknown)
}

func TestDynamicStructure_RoundTrip(t *testing.T) {
	s := dynSet(t)
	v, err := s.New(dynID(dtOuter))
	require.NoError(t, err)
	inner := func(a int32, b string) *DynamicStructure {
		in, err := s.New(dynID(dtInner))
		require.NoError(t, err)
		require.NoError(t, in.Set("A", a))
		require.NoError(t, in.Set("B", b))
		return in
	}
	eu := &EUInformation{NamespaceURI: "http://www.opcfoundation.org/UA/units/un/cefact", UnitID: 4408652, DisplayName: NewLocalizedText("°C"), Description: NewLocalizedText("degree Celsius")}
	when := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	set := map[string]any{
		"I":    int32(-7),
		"S":    "pump",
		"LT":   NewLocalizedTextWithLocale("Pumpe", "de"),
		"In":   inner(1, "one"),
		"Arr":  []int32{1, 2, 3},
		"Ins":  []*DynamicStructure{inner(2, "two"), inner(3, "three")},
		"M":    &DynamicMatrix{Dimensions: []int32{2, 3}, Values: []float64{1, 2, 3, 4, 5, 6}},
		"V":    MustVariant(uint16(9)),
		"N":    MustVariant(3.5),
		"St":   NewExtensionObject(eu),
		"Dec":  &ExtensionObject{TypeID: NewFourByteExpandedNodeID(0, id.Decimal), EncodingMask: ExtensionObjectBinary, Value: []byte{0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x39, 0x30, 0x00, 0x00}},
		"EU":   eu,
		"E":    int32(1),
		"OS":   &OptionSet{Value: []byte{0x05}, ValidBits: []byte{0x07}},
		"U":    uint32(0x05),
		"Str":  "simple",
		"Abs":  NewExtensionObject(inner(4, "four")),
		"Opt":  &OptionSet{Value: []byte{0x01}, ValidBits: []byte{0x01}},
		"EUs":  []*EUInformation{eu, eu},
		"Time": when,
	}
	for name, x := range set {
		require.NoError(t, v.Set(name, x), name)
	}
	b := dynEncode(t, v)
	eo, err := dynDecode(t, s, b)
	require.NoError(t, err)
	require.Nil(t, eo.RawBody)
	got, ok := eo.Value.(*DynamicStructure)
	require.True(t, ok)
	require.Same(t, s.Type(dynID(dtOuter)), got.Type)

	field := func(name string) any {
		t.Helper()
		x, ok := got.Field(name)
		require.True(t, ok, name)
		return x
	}
	require.Equal(t, int32(-7), field("I"))
	require.Equal(t, "pump", field("S"))
	require.Equal(t, set["LT"], field("LT"))
	in := field("In").(*DynamicStructure)
	require.Equal(t, []any{int32(1), "one"}, in.Fields)
	require.Equal(t, []int32{1, 2, 3}, field("Arr"))
	ins := field("Ins").([]*DynamicStructure)
	require.Len(t, ins, 2)
	require.Equal(t, "three", ins[1].Fields[1])
	require.Equal(t, set["M"], field("M"))
	require.Equal(t, uint16(9), field("V").(*Variant).Value())
	require.Equal(t, 3.5, field("N").(*Variant).Value())
	require.Equal(t, eu, field("St").(*ExtensionObject).Value)
	require.Equal(t, set["Dec"].(*ExtensionObject).Value, field("Dec").(*ExtensionObject).Value)
	require.Equal(t, eu, field("EU"))
	require.Equal(t, int32(1), field("E"))
	require.Equal(t, set["OS"], field("OS"))
	require.Equal(t, uint32(5), field("U"))
	require.Equal(t, "simple", field("Str"))
	// The ExtensionObject of the abstract field is decoded with the set.
	abs := field("Abs").(*ExtensionObject).Value.(*DynamicStructure)
	require.Equal(t, []any{int32(4), "four"}, abs.Fields)
	require.Equal(t, set["Opt"], field("Opt"))
	require.Equal(t, []*EUInformation{eu, eu}, field("EUs"))
	require.Equal(t, when, field("Time"))
	_, ok = got.Field("missing")
	require.False(t, ok)

	// Encoded again, the decoded value gives the same bytes.
	require.Equal(t, b, dynEncode(t, got))
	// A second decode does nothing.
	require.NoError(t, s.DecodeExtensionObject(eo))
	require.Same(t, got, eo.Value)
}

func TestDynamicStructure_Defaults(t *testing.T) {
	s := dynSet(t)
	// Every field nil: the default value of each (OPC 10000-6 §5.2.6),
	// null arrays and matrices, the null ExtensionObject.
	v, err := s.New(dynID(dtOuter))
	require.NoError(t, err)
	eo, err := dynDecode(t, s, dynEncode(t, v))
	require.NoError(t, err)
	got := eo.Value.(*DynamicStructure)
	require.Equal(t, int32(0), got.Fields[0])
	require.Equal(t, "", got.Fields[1])
	require.Equal(t, []any{int32(0), ""}, got.Fields[3].(*DynamicStructure).Fields)
	require.Nil(t, got.Fields[4])
	require.Nil(t, got.Fields[5])
	require.Nil(t, got.Fields[6])
	st := got.Fields[9].(*ExtensionObject)
	require.Equal(t, uint8(ExtensionObjectEmpty), st.EncodingMask)

	// A nil *DynamicStructure is the default value too, and so are the
	// typed nils of pointer fields.
	require.NoError(t, v.Set("In", (*DynamicStructure)(nil)))
	require.NoError(t, v.Set("LT", (*LocalizedText)(nil)))
	require.NoError(t, v.Set("St", (*ExtensionObject)(nil)))
	require.NoError(t, v.Set("M", (*DynamicMatrix)(nil)))
	require.NoError(t, v.Set("M", &DynamicMatrix{Dimensions: []int32{0, 3}}))
	_, err = dynDecode(t, s, dynEncode(t, v))
	require.NoError(t, err)

	// A value whose Fields were not made by New.
	w := &DynamicStructure{Type: s.Type(dynID(dtInner))}
	require.NoError(t, w.Set("B", "x"))
	require.Equal(t, []any{nil, "x"}, w.Fields)
	short := &DynamicStructure{Type: s.Type(dynID(dtInner)), Fields: []any{int32(3)}}
	b, err := short.Encode()
	require.NoError(t, err)
	require.Equal(t, []byte{3, 0, 0, 0, 0xff, 0xff, 0xff, 0xff}, b, "the null String")
}

// TestDynamicStructure_Part6Samples decodes the samples of OPC 10000-6
// Table 32 and Table 33.
func TestDynamicStructure_Part6Samples(t *testing.T) {
	s := dynSet(t)
	// TypeA with O2 and without O1: 22 bytes in an ExtensionObject.
	typeA := []byte{
		0x01, 0x02, dtTypeA + 1, 0x00, // TypeId ns=2;i=131
		0x01,                   // ByteString
		0x0d, 0x00, 0x00, 0x00, // Length 13
		0x02, 0x00, 0x00, 0x00, // EncodingMask: O2
		0x07, 0x00, 0x00, 0x00, // X
		0xff,                   // Y
		0x09, 0x00, 0x00, 0x00, // O2
	}
	eo, err := dynDecode(t, s, typeA)
	require.NoError(t, err)
	got := eo.Value.(*DynamicStructure)
	require.Equal(t, []any{int32(7), nil, int8(-1), int32(9)}, got.Fields)
	require.Equal(t, typeA, dynEncode(t, got))

	// Type1 with Field1: 17 bytes.
	type1 := []byte{
		0x01, 0x02, dtType1 + 1, 0x00,
		0x01,
		0x08, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, // SwitchField: Field1
		0x05, 0x00, 0x00, 0x00, // Field1
	}
	eo, err = dynDecode(t, s, type1)
	require.NoError(t, err)
	got = eo.Value.(*DynamicStructure)
	require.Equal(t, uint32(1), got.Switch)
	require.Equal(t, []any{int32(5), nil}, got.Fields)
	require.Equal(t, type1, dynEncode(t, got))

	// Set selects the other field of the union.
	two, err := s.New(dynID(dtType2))
	require.NoError(t, err)
	require.NoError(t, two.Set("B", int32(2)))
	require.NoError(t, got.Set("Field2", two))
	require.Equal(t, uint32(2), got.Switch)
	require.Nil(t, got.Fields[0])
	eo, err = dynDecode(t, s, dynEncode(t, got))
	require.NoError(t, err)
	require.Equal(t, []any{int32(0), int32(2)}, eo.Value.(*DynamicStructure).Fields[1].(*DynamicStructure).Fields)

	// A union without a field.
	empty, err := s.New(dynID(dtType1))
	require.NoError(t, err)
	eo, err = dynDecode(t, s, dynEncode(t, empty))
	require.NoError(t, err)
	require.Equal(t, uint32(0), eo.Value.(*DynamicStructure).Switch)
}

func TestDynamicStructure_SubtypedValues(t *testing.T) {
	s := dynSet(t)
	inner, err := s.New(dynID(dtInner))
	require.NoError(t, err)
	require.NoError(t, inner.Set("A", int32(8)))
	v, err := s.New(dynID(dtSubtyped))
	require.NoError(t, err)
	// "all subtypes of Structure are encoded as an ExtensionObject ... all
	// DataTypes that are not subtypes of Structure are encoded as a
	// Variant" (OPC 10000-6 Table F.13).
	require.NoError(t, v.Set("V", NewExtensionObject(inner)))
	require.NoError(t, v.Set("W", MustVariant(int64(5))))
	require.NoError(t, v.Set("X", int32(1)))
	eo, err := dynDecode(t, s, dynEncode(t, v))
	require.NoError(t, err)
	got := eo.Value.(*DynamicStructure)
	require.Equal(t, int32(8), got.Fields[0].(*ExtensionObject).Value.(*DynamicStructure).Fields[0])
	require.Equal(t, int64(5), got.Fields[1].(*Variant).Value())

	u, err := s.New(dynID(dtSubUnion))
	require.NoError(t, err)
	require.NoError(t, u.Set("W", MustVariant("text")))
	eo, err = dynDecode(t, s, dynEncode(t, u))
	require.NoError(t, err)
	require.Equal(t, "text", eo.Value.(*DynamicStructure).Fields[1].(*Variant).Value())
}

func TestDynamicTypes_DecodeErrors(t *testing.T) {
	s := dynSet(t)
	body := func(dt uint32, b ...byte) *ExtensionObject {
		return &ExtensionObject{TypeID: &ExpandedNodeID{NodeID: dynID(dt + 1)}, EncodingMask: ExtensionObjectBinary, RawBody: b}
	}
	le := func(v int32) []byte {
		u := uint32(v)
		return []byte{byte(u), byte(u >> 8), byte(u >> 16), byte(u >> 24)}
	}
	cat := func(parts ...[]byte) []byte {
		var out []byte
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	cases := []struct {
		name string
		eo   *ExtensionObject
		want error
	}{
		{"unknown encoding", body(500, 0), StatusBadDataTypeIDUnknown},
		{"trailing bytes", body(dtType2, cat(le(1), le(2), []byte{0})...), StatusBadDecodingError},
		{"truncated field", body(dtType2, 1, 0, 0), nil},
		{"no encoding mask", body(dtTypeA, 1, 0), StatusBadDecodingError},
		{"unassigned mask bit", body(dtTypeA, cat(le(4), le(1), []byte{1})...), StatusBadDecodingError},
		{"truncated optional field", body(dtTypeA, cat(le(1), le(1), []byte{1}, []byte{1})...), nil},
		{"no switch", body(dtType1, 1), StatusBadDecodingError},
		{"switch beyond the fields", body(dtType1, le(3)...), StatusBadDecodingError},
		{"truncated union field", body(dtType1, cat(le(1), []byte{1})...), nil},
		{"no array length", body(dtRecursive, 1, 2), StatusBadDecodingError},
		{"array length -2", body(dtRecursive, le(-2)...), StatusBadDecodingError},
		{"array longer than the input", body(dtRecursive, le(math.MaxInt32)...), uaerrors.ErrArrayTooLarge},
		{"array element truncated", body(dtRecursive, cat(le(1), []byte{1})...), nil},
		{"unknown field DataType", body(dtUnknownFld, 0), StatusBadDataTypeIDUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw := append([]byte(nil), c.eo.RawBody...)
			err := s.DecodeExtensionObject(c.eo)
			require.Error(t, err)
			if c.want != nil {
				require.ErrorIs(t, err, c.want)
			}
			// It is left as it was.
			require.Nil(t, c.eo.Value)
			require.Equal(t, raw, c.eo.RawBody)
		})
	}

	// An array of values of no size is bounded by MaxVariantArrayLength.
	empties := dynStructure(300, StructureTypeStructure, dynField("E", dynID(dtEmpty), 1))
	require.NoError(t, s.Add(empties))
	err := s.DecodeExtensionObject(body(300, le(int32(MaxVariantArrayLength+1))...))
	require.ErrorIs(t, err, uaerrors.ErrArrayTooLarge)
	eo := body(300, le(3)...)
	require.NoError(t, s.DecodeExtensionObject(eo))
	require.Len(t, eo.Value.(*DynamicStructure).Fields[0], 3)

	// Matrices: the Dimensions, then the values (OPC 10000-6 Table 28).
	matrix := dynStructure(310, StructureTypeStructure, dynField("M", ns0(id.Int32), 2))
	require.NoError(t, s.Add(matrix))
	err = s.DecodeExtensionObject(body(310, cat(le(1), le(2))...))
	require.ErrorIs(t, err, StatusBadDecodingError, "one dimension for ValueRank 2")
	err = s.DecodeExtensionObject(body(310, cat(le(2), le(math.MaxInt32), le(math.MaxInt32))...))
	require.ErrorIs(t, err, uaerrors.ErrArrayTooLarge)
	err = s.DecodeExtensionObject(body(310, cat(le(2), le(1000), le(1000))...))
	require.ErrorIs(t, err, uaerrors.ErrArrayTooLarge)
	err = s.DecodeExtensionObject(body(310, cat(le(2), le(1), le(2), le(7))...))
	require.Error(t, err, "a value missing")
	err = s.DecodeExtensionObject(body(310, 1, 2))
	require.Error(t, err)
	eo = body(310, cat(le(2), le(-1), le(5))...)
	require.NoError(t, s.DecodeExtensionObject(eo))
	require.Equal(t, &DynamicMatrix{Dimensions: []int32{-1, 5}, Values: []int32{}}, eo.Value.(*DynamicStructure).Fields[0])
	eo = body(310, le(-1)...)
	require.NoError(t, s.DecodeExtensionObject(eo))
	require.Nil(t, eo.Value.(*DynamicStructure).Fields[0], "the null matrix")

	// A field of a Go type with a body that does not decode.
	goField := dynStructure(320, StructureTypeStructure, dynField("EU", ns0(id.EUInformation), -1))
	require.NoError(t, s.Add(goField))
	require.Error(t, s.DecodeExtensionObject(body(320, 1, 0)))

	// A nested ExtensionObject with a body of a type that does not
	// decode keeps it as its Value.
	eo = body(dtSubtyped, cat(
		[]byte{0x01, 0x02, dtInner + 1, 0x00, 0x01}, le(1), []byte{0xff}, // V: one byte for Inner
		[]byte{0x00}, // W: a null Variant
		le(1))...)
	require.NoError(t, s.DecodeExtensionObject(eo))
	v := eo.Value.(*DynamicStructure).Fields[0].(*ExtensionObject)
	require.Equal(t, []byte{0xff}, v.Value)
	require.Nil(t, v.RawBody)
}

func TestDynamicTypes_NestingDepth(t *testing.T) {
	s := dynSet(t)
	// Recursive{Next: [Recursive{Next: [...]}]}: one level per element.
	var b []byte
	for range MaxBinaryNestingDepth + 1 {
		b = append(b, 1, 0, 0, 0)
	}
	b = append(b, 0xff, 0xff, 0xff, 0xff)
	eo := &ExtensionObject{TypeID: &ExpandedNodeID{NodeID: dynID(dtRecursive + 1)}, EncodingMask: ExtensionObjectBinary, RawBody: b}
	require.ErrorIs(t, s.DecodeExtensionObject(eo), StatusBadEncodingLimitsExceeded)

	// The same depth on the encoding side.
	root, err := s.New(dynID(dtRecursive))
	require.NoError(t, err)
	cur := root
	for range MaxBinaryNestingDepth + 1 {
		next, err := s.New(dynID(dtRecursive))
		require.NoError(t, err)
		require.NoError(t, cur.Set("Next", []*DynamicStructure{next}))
		cur = next
	}
	_, err = root.Encode()
	require.ErrorIs(t, err, StatusBadEncodingLimitsExceeded)
}

func TestDynamicStructure_EncodeErrors(t *testing.T) {
	s := dynSet(t)
	newV := func(dt uint32) *DynamicStructure {
		v, err := s.New(dynID(dt))
		require.NoError(t, err)
		return v
	}
	encErr := func(v *DynamicStructure) error {
		t.Helper()
		_, err := v.Encode()
		require.Error(t, err)
		return err
	}
	var nilV *DynamicStructure
	require.ErrorIs(t, encErr(nilV), StatusBadEncodingError)
	require.ErrorIs(t, encErr(&DynamicStructure{}), StatusBadEncodingError)
	require.ErrorIs(t, encErr(&DynamicStructure{Type: &DynamicType{DataTypeID: dynID(1)}}), StatusBadEncodingError)

	set := func(dt uint32, name string, x any) *DynamicStructure {
		v := newV(dt)
		require.NoError(t, v.Set(name, x))
		return v
	}
	require.ErrorIs(t, encErr(set(dtInner, "A", "not an Int32")), StatusBadEncodingError)
	require.ErrorIs(t, encErr(set(dtOuter, "In", "not a structure")), StatusBadEncodingError)
	require.ErrorIs(t, encErr(set(dtOuter, "In", newV(dtType2))), StatusBadEncodingError)
	require.ErrorIs(t, encErr(set(dtOuter, "In", set(dtInner, "A", 1.5))), StatusBadEncodingError)
	require.ErrorIs(t, encErr(set(dtOuter, "Arr", []int64{1})), StatusBadEncodingError)
	require.ErrorIs(t, encErr(set(dtOuter, "Arr", int32(1))), StatusBadEncodingError)
	require.ErrorIs(t, encErr(set(dtOuter, "Ins", []*DynamicStructure{newV(dtType2)})), StatusBadEncodingError)
	require.ErrorIs(t, encErr(set(dtOuter, "M", []float64{1})), StatusBadEncodingError)
	require.ErrorIs(t, encErr(set(dtOuter, "M", &DynamicMatrix{Dimensions: []int32{2}, Values: []float64{1, 2}})), StatusBadEncodingError)
	require.ErrorIs(t, encErr(set(dtOuter, "M", &DynamicMatrix{Dimensions: []int32{2, 2}, Values: []float64{1, 2}})), StatusBadEncodingError)
	require.ErrorIs(t, encErr(set(dtOuter, "M", &DynamicMatrix{Dimensions: []int32{2, 2}, Values: 1.0})), StatusBadEncodingError)
	require.ErrorIs(t, encErr(set(dtOuter, "M", &DynamicMatrix{Dimensions: []int32{2, 2}, Values: []int32{1, 2, 3, 4}})), StatusBadEncodingError)
	require.ErrorIs(t, encErr(set(dtOuter, "M", &DynamicMatrix{Dimensions: []int32{math.MaxInt32, math.MaxInt32}})), uaerrors.ErrArrayTooLarge)
	require.ErrorIs(t, encErr(set(dtOuter, "EU", &LocalizedText{})), StatusBadEncodingError)
	require.ErrorIs(t, encErr(set(dtUnknownFld, "X", int32(1))), StatusBadDataTypeIDUnknown)

	u := newV(dtType1)
	u.Switch = 3
	require.ErrorIs(t, encErr(u), StatusBadEncodingError)
	require.ErrorIs(t, encErr(set(dtType1, "Field1", "x")), StatusBadEncodingError)
	require.ErrorIs(t, encErr(set(dtTypeA, "O1", "x")), StatusBadEncodingError)
	require.ErrorIs(t, encErr(set(dtTypeA, "X", "x")), StatusBadEncodingError)

	// The error reaches the ExtensionObject and the encoders.
	_, err := NewExtensionObject(set(dtInner, "A", "x")).Encode()
	require.Error(t, err)
	_, err = EncodeJSON(MustVariant(NewExtensionObject(set(dtInner, "A", "x"))))
	require.Error(t, err)
	_, err = EncodeXML(MustVariant(NewExtensionObject(set(dtInner, "A", "x"))))
	require.Error(t, err)

	require.ErrorIs(t, newV(dtInner).Set("missing", 1), StatusBadInvalidArgument)

	// Without its set, a value encodes the fields of built-in types only.
	alone := &DynamicStructure{Type: s.Type(dynID(dtOuter))}
	require.ErrorIs(t, encErr(alone), StatusBadDataTypeIDUnknown)
	b, err := (&DynamicStructure{Type: s.Type(dynID(dtInner))}).Encode()
	require.NoError(t, err)
	require.Len(t, b, 8)
}

func TestDynamicStructure_TypeID(t *testing.T) {
	s := dynSet(t)
	v, err := s.New(dynID(dtInner))
	require.NoError(t, err)
	require.Equal(t, dynID(dtInner+1), ExtensionObjectTypeID(v).NodeID)
	var nilV *DynamicStructure
	require.Equal(t, uint32(0), ExtensionObjectTypeID(nilV).NodeID.IntID())
	_, ok := nilV.Field("A")
	require.False(t, ok)
	abstract := &DynamicStructure{Type: s.Type(dynID(dtAbstract))}
	require.Equal(t, uint32(0), ExtensionObjectTypeID(abstract).NodeID.IntID())
}

func TestUndecodedBody(t *testing.T) {
	_, ok := UndecodedBody(nil)
	require.False(t, ok)
	_, ok = UndecodedBody(&ExtensionObject{EncodingMask: ExtensionObjectBinary})
	require.False(t, ok, "no TypeId")
	_, ok = UndecodedBody(&ExtensionObject{EncodingMask: ExtensionObjectBinary, TypeID: &ExpandedNodeID{}})
	require.False(t, ok, "no NodeId")
	_, ok = UndecodedBody(&ExtensionObject{EncodingMask: ExtensionObjectXML, TypeID: NewTwoByteExpandedNodeID(5)})
	require.False(t, ok, "an XML body")
	_, ok = UndecodedBody(NewExtensionObject(&EUInformation{}))
	require.False(t, ok, "a decoded body")
	b, ok := UndecodedBody(&ExtensionObject{EncodingMask: ExtensionObjectBinary, TypeID: NewTwoByteExpandedNodeID(5), RawBody: []byte{1}})
	require.True(t, ok)
	require.Equal(t, []byte{1}, b)
	b, ok = UndecodedBody(&ExtensionObject{EncodingMask: ExtensionObjectBinary, TypeID: NewTwoByteExpandedNodeID(5), Value: []byte{2}})
	require.True(t, ok)
	require.Equal(t, []byte{2}, b)

	// Nothing to decode is no error.
	require.NoError(t, NewDynamicTypes().DecodeExtensionObject(nil))
}

// TestDynamicStructure_JSONAndXML sends a value in the JSON and XML
// encodings, where it is a binary body (OPC 10000-6 §5.4.2.16, §5.3.1.16),
// and decodes the []byte body the decoders keep.
func TestDynamicStructure_JSONAndXML(t *testing.T) {
	s := dynSet(t)
	v, err := s.New(dynID(dtInner))
	require.NoError(t, err)
	require.NoError(t, v.Set("A", int32(42)))
	require.NoError(t, v.Set("B", "answer"))

	check := func(t *testing.T, got *Variant) {
		t.Helper()
		eo := got.Value().(*ExtensionObject)
		require.IsType(t, []byte{}, eo.Value)
		require.NoError(t, s.DecodeExtensionObject(eo))
		require.Equal(t, []any{int32(42), "answer"}, eo.Value.(*DynamicStructure).Fields)
	}
	t.Run("JSON", func(t *testing.T) {
		b, err := EncodeJSON(MustVariant(NewExtensionObject(v)))
		require.NoError(t, err)
		var got Variant
		require.NoError(t, DecodeJSON(b, &got))
		check(t, &got)
	})
	t.Run("XML", func(t *testing.T) {
		b, err := EncodeXML(MustVariant(NewExtensionObject(v)))
		require.NoError(t, err)
		var got Variant
		require.NoError(t, DecodeXML(b, &got))
		check(t, &got)
	})
}

func TestDynamicTypes_CodecOf(t *testing.T) {
	s := dynSet(t)
	// String, GUID and opaque NodeIds of namespace 0 are no built-in types.
	for _, n := range []*NodeID{NewStringNodeID(0, "x"), NewGUIDNodeID(0, "72962B91-FA75-4AE6-8D28-B404DC7DAF63"), NewByteStringNodeID(0, []byte{1})} {
		_, err := s.codecOf(n, false)
		require.ErrorIs(t, err, StatusBadDataTypeIDUnknown)
		_, ok := ns0GoCodec(n)
		require.False(t, ok)
	}
	// A DataType of namespace 0 without a name or Go type.
	_, ok := ns0GoCodec(ns0(1 << 30))
	require.False(t, ok)
	_, ok = ns0GoCodec(ns0(id.Enumeration))
	require.False(t, ok)
	_, ok = ns0GoCodec(ns0(id.Node)) // an encoding without a Go type
	require.False(t, ok)
	_, ok = ns0GoCodec(ns0(id.BuildInfo))
	require.True(t, ok)

	c, err := s.codecOf(ns0(id.Int32), true)
	require.NoError(t, err)
	require.Equal(t, TypeIDVariant, c.builtIn)
	c, err = s.codecOf(ns0(id.Structure), true)
	require.NoError(t, err)
	require.Equal(t, TypeIDExtensionObject, c.builtIn)
	c, err = s.codecOf(ns0(id.EUInformation), true)
	require.NoError(t, err)
	require.Equal(t, TypeIDExtensionObject, c.builtIn)
	c, err = s.codecOf(dynID(dtString), true)
	require.NoError(t, err)
	require.Equal(t, TypeIDVariant, c.builtIn)

	// A concrete Structure without a definition cannot be read, nor can a
	// DataType without a built-in type.
	require.NoError(t, s.Add(&DynamicType{DataTypeID: dynID(400), BuiltIn: TypeIDExtensionObject}))
	_, err = s.codecOf(dynID(400), false)
	require.ErrorIs(t, err, StatusBadDataTypeIDUnknown)
	require.NoError(t, s.Add(&DynamicType{DataTypeID: dynID(401)}))
	_, err = s.codecOf(dynID(401), false)
	require.ErrorIs(t, err, StatusBadDataTypeIDUnknown)
	require.NoError(t, s.Add(&DynamicType{DataTypeID: dynID(402), IsAbstract: true, BuiltIn: TypeIDExtensionObject}))
	c, err = s.codecOf(dynID(402), false)
	require.NoError(t, err)
	require.Equal(t, TypeIDExtensionObject, c.builtIn)

	// A Structure of the set whose encoding has a Go type is decoded
	// with it.
	require.NoError(t, s.Add(&DynamicType{DataTypeID: dynID(403), Definition: &StructureDefinition{DefaultEncodingID: ns0(id.EUInformationEncodingDefaultBinary)}}))
	c, err = s.codecOf(dynID(403), false)
	require.NoError(t, err)
	require.Equal(t, codecGo, c.kind)

	// minSize of each kind, and of a Structure that contains itself.
	require.Equal(t, 8, s.minSize(fieldCodec{kind: codecOptionSet}, 0))
	require.Equal(t, 4, s.minSize(fieldCodec{kind: codecDynamic, dyn: s.Type(dynID(dtTypeA))}, 0))
	self := dynStructure(410, StructureTypeStructure, dynField("Self", dynID(410), -1), dynField("X", dynID(999), -1))
	require.NoError(t, s.Add(self))
	require.Equal(t, 0, s.minSize(fieldCodec{kind: codecDynamic, dyn: self}, 0))
	require.Equal(t, 0, s.minSize(fieldCodec{kind: codecGo, goType: reflect.TypeOf(new(struct{}))}, 0))
}

func TestDynamicTypes_Errors(t *testing.T) {
	// Errors wrap a StatusCode.
	s := dynSet(t)
	err := s.DecodeExtensionObject(&ExtensionObject{TypeID: &ExpandedNodeID{NodeID: dynID(7)}, EncodingMask: ExtensionObjectBinary})
	var sc StatusCode
	require.True(t, errors.As(err, &sc))
	require.Equal(t, StatusBadDataTypeIDUnknown, sc)
}

// TestDynamicTypes_HostileLengths checks that a claimed length is checked
// against the input before anything is allocated for it.
func TestDynamicTypes_HostileLengths(t *testing.T) {
	s := dynSet(t)
	require.NoError(t, s.Add(dynStructure(500, StructureTypeStructure, dynField("M", ns0(id.Int64), 2))))
	require.NoError(t, s.Add(dynStructure(510, StructureTypeStructure, dynField("A", ns0(id.GUID), 1))))
	bodies := map[uint32][]byte{
		// A 46340 x 46340 matrix, just below MaxInt32 values.
		500: {2, 0, 0, 0, 0x04, 0xb5, 0, 0, 0x04, 0xb5, 0, 0},
		510: {0xff, 0xff, 0xff, 0x7f},
	}
	for dt, b := range bodies {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		eo := &ExtensionObject{TypeID: &ExpandedNodeID{NodeID: dynID(dt + 1)}, EncodingMask: ExtensionObjectBinary, RawBody: b}
		require.ErrorIs(t, s.DecodeExtensionObject(eo), uaerrors.ErrArrayTooLarge)
		runtime.ReadMemStats(&after)
		require.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(1<<20), "DataType %d", dt)
	}
}
