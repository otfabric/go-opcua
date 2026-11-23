// SPDX-License-Identifier: MIT

package uafx

import (
	"bytes"
	"encoding/hex"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
)

var testNS = NamespaceIndexes{Data: 5, AC: 6, CM: 300}

// --- byte fixtures worked out by hand from Part 6 and the Binary Schema ----

// eoBytes is the binary ExtensionObject (Part 6 §5.2.2.15) of body with the
// encoding NodeId ns;i=id in the numeric form (§5.2.2.9: 0x02, the UInt16
// namespace, the UInt32 identifier), the Binary encoding mask 0x01 and the
// length of the body.
func eoBytes(ns uint16, id uint32, body string) string {
	h := "02" + hex.EncodeToString([]byte{byte(ns), byte(ns >> 8), byte(id), byte(id >> 8), byte(id >> 16), byte(id >> 24)})
	n := len(body) / 2
	return h + "01" + hex.EncodeToString([]byte{byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24)}) + body
}

func TestStructureFixtures(t *testing.T) {
	yes := true
	for name, c := range map[string]struct {
		v    Structure
		ns   uint16
		id   uint32 // the Default Binary encoding of the NodeSet
		body string
	}{
		// A union (Part 6 §5.2.8): SwitchField 2 (IdString), then the
		// String "ab".
		"ApplicationId": {&ApplicationID{IDString: ptr("ab")}, testNS.AC, 5003,
			"02000000" + "02000000" + "6162"},
		// A union whose option 1 is abstract: SwitchField 2 (Node), then
		// the four-byte NodeId ns=1;i=7.
		"ConnectionEndpointDefinitionDataType/Node": {&ConnectionEndpointDefinition{Node: ua.NewFourByteNodeID(1, 7)}, testNS.Data, 5054,
			"02000000" + "01010700"},
		// The null union: SwitchField 0 and nothing else.
		"ConnectionEndpointDefinitionDataType/null": {&ConnectionEndpointDefinition{}, testNS.Data, 5054, "00000000"},
		// Optional fields (Part 6 §5.2.7): the EncodingMask has bit 1 for
		// AddressModify, the second optional field (AddressSelection is
		// the first); then Address "a", AddressModify true,
		// SecurityPolicyUri "p", ServerUri "s", UsePushModel true. The
		// absent optional fields take no bytes.
		"SecurityKeyServerAddressConfDataType": {&SecurityKeyServerAddressConf{Address: "a", AddressModify: &yes, SecurityPolicyURI: "p", ServerURI: "s", UsePushModel: true}, testNS.CM, 5050,
			"02000000" + "0100000061" + "01" + "0100000070" + "0100000073" + "01"},
		// An optional array that is present and empty: bit 0 of the
		// EncodingMask (AddressSelection), then Address "a", the
		// AddressSelection of length 0, SecurityPolicyUri "p", ServerUri "s"
		// and UsePushModel false.
		"SecurityKeyServerAddressConfDataType/empty array": {&SecurityKeyServerAddressConf{Address: "a", AddressSelection: []string{}, SecurityPolicyURI: "p", ServerURI: "s"}, testNS.CM, 5050,
			"01000000" + "0100000061" + "00000000" + "0100000070" + "0100000073" + "00"},
		// A subtype: the fields of PubSubReserveCommunicationIdsDataType
		// first (TransportProfileUri "t", 1, 2), then its own
		// RequestTransportSpecificInfo.
		"PubSubReserveCommunicationIds2DataType": {&PubSubReserveCommunicationIDs{TransportProfileURI: "t", NumReqWriterGroupIDs: 1, NumReqDataSetWriterIDs: 2, RequestTransportSpecificInfo: true}, testNS.Data, 5004,
			"0100000074" + "0100" + "0200" + "01"},
	} {
		t.Run(name, func(t *testing.T) {
			for _, ns := range []NamespaceIndexes{testNS, {Data: 2, AC: 3, CM: 4}} {
				idx := map[uint16]uint16{testNS.Data: ns.Data, testNS.AC: ns.AC, testNS.CM: ns.CM}[c.ns]
				eo, err := EncodeStructure(c.v, ns)
				require.NoError(t, err)
				b, err := ua.Encode(eo)
				require.NoError(t, err)
				want := eoBytes(idx, c.id, c.body)
				assert.Equal(t, want, hex.EncodeToString(b))

				raw, _ := hex.DecodeString(want)
				got := new(ua.ExtensionObject)
				_, err = got.Decode(raw)
				require.NoError(t, err)
				v, err := DecodeStructure(got, ns)
				require.NoError(t, err)
				assert.Equal(t, c.v, v)
			}
		})
	}
}

// TestOptionalNullArray: an optional field is present when its bit of the
// EncodingMask is set, whatever its value (Part 6 §5.2.7). A present array
// of length -1, the null array, decodes as an empty slice, not as nil, which
// is an absent field: encoded again, the bit stays set, with the length 0
// (Part 6 §5.1.11 makes null and empty arrays semantically the same).
func TestOptionalNullArray(t *testing.T) {
	c := codec{testNS}
	// Bit 0 (AddressSelection) and bit 2 (SecurityPolicyUriSelection), both
	// null; Address "a", SecurityPolicyUri "p", ServerUri "s", UsePushModel
	// false.
	body := "05000000" + "0100000061" + "ffffffff" + "0100000070" + "ffffffff" + "0100000073" + "00"
	raw, _ := hex.DecodeString(body)
	v, err := DecodeStructure(&ua.ExtensionObject{EncodingMask: ua.ExtensionObjectBinary, TypeID: ua.NewNumericExpandedNodeID(c.index(nsCM), 5050), Value: raw}, testNS)
	require.NoError(t, err)
	got := v.(*SecurityKeyServerAddressConf)
	require.NotNil(t, got.AddressSelection)
	require.NotNil(t, got.SecurityPolicyURISelection)
	assert.Empty(t, got.AddressSelection)
	assert.Nil(t, got.ServerURISelection, "bit 4 is not set")

	eo, err := EncodeStructure(got, testNS)
	require.NoError(t, err)
	assert.Equal(t, "05000000"+"0100000061"+"00000000"+"0100000070"+"00000000"+"0100000073"+"00", hex.EncodeToString(eo.Value.([]byte)))
}

func ptr[T any](v T) *T { return &v }

// --- every generated structure ---------------------------------------------

// schemaOf maps the Go types of the generated structures to their schema.
func schemaOf() map[reflect.Type]schemaType {
	out := map[reflect.Type]schemaType{}
	for _, g := range generatedSchema {
		if g.value != nil {
			out[reflect.TypeOf(g.value).Elem()] = g
		}
	}
	return out
}

// concreteOf returns the generated structures that implement the interface
// type it, in a stable order.
func concreteOf(it reflect.Type) []reflect.Type {
	var out []reflect.Type
	for _, g := range generatedSchema {
		if g.value != nil && reflect.TypeOf(g.value).Implements(it) {
			out = append(out, reflect.TypeOf(g.value))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

var structureType = reflect.TypeOf((*Structure)(nil)).Elem()

// filler sets every field of a structure: optional fields when optional is
// set, the option pick (modulo the number of options) of a union, and the
// subtype pick of an abstract field.
type filler struct {
	schema   map[reflect.Type]schemaType
	optional bool
	// empty sets the optional arrays present and empty, the state between
	// absent (nil) and filled.
	empty bool
	pick  int
}

func (f filler) fill(v reflect.Value) {
	switch v.Kind() {
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int32:
		v.SetInt(2)
	case reflect.Uint8, reflect.Uint16, reflect.Uint32:
		v.SetUint(3)
	case reflect.Float64:
		v.SetFloat(1.5)
	case reflect.String:
		v.SetString("s")
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), 2, 2)
		for i := range 2 {
			f.fill(s.Index(i))
		}
		v.Set(s)
	case reflect.Interface:
		cs := concreteOf(v.Type())
		c := reflect.New(cs[f.pick%len(cs)].Elem())
		f.fill(c.Elem())
		v.Set(c)
	case reflect.Pointer:
		v.Set(f.value(v.Type()))
	case reflect.Struct:
		g, ok := f.schema[v.Type()]
		if !ok {
			return // a structure of package ua: its zero value
		}
		if g.union {
			i := f.pick % v.NumField()
			f.fill(v.Field(i))
			return
		}
		for i := range v.NumField() {
			if g.fields[i].optional && !f.optional {
				continue
			}
			if g.fields[i].optional && f.empty && v.Field(i).Kind() == reflect.Slice {
				v.Field(i).Set(reflect.MakeSlice(v.Field(i).Type(), 0, 0))
				continue
			}
			f.fill(v.Field(i))
		}
	default:
		panic("filler: no value for " + v.Type().String())
	}
}

// value returns a non-nil value of the pointer type t.
func (f filler) value(t reflect.Type) reflect.Value {
	switch t {
	case reflect.TypeOf((*ua.NodeID)(nil)):
		return reflect.ValueOf(ua.NewNumericNodeID(1, 7))
	case reflect.TypeOf((*ua.Variant)(nil)):
		return reflect.ValueOf(ua.MustVariant(int32(5)))
	case reflect.TypeOf((*ua.LocalizedText)(nil)):
		return reflect.ValueOf(ua.NewLocalizedText("t"))
	case reflect.TypeOf((*ua.QualifiedName)(nil)):
		return reflect.ValueOf(&ua.QualifiedName{NamespaceIndex: 1, Name: "q"})
	case reflect.TypeOf((*ua.ExtensionObject)(nil)):
		return reflect.ValueOf(ua.NewExtensionObject(&ua.KeyValuePair{Key: &ua.QualifiedName{Name: "k"}, Value: ua.MustVariant("v")}))
	}
	p := reflect.New(t.Elem())
	f.fill(p.Elem())
	return p
}

// structureRoundTrip encodes v, decodes it and encodes it again, which must give the
// same bytes; the value decoded twice must be the same.
func structureRoundTrip(t *testing.T, v Structure) {
	t.Helper()
	eo, err := EncodeStructure(v, testNS)
	require.NoError(t, err, "%T", v)
	got, err := DecodeStructure(eo, testNS)
	require.NoError(t, err, "%T", v)
	require.IsType(t, v, got)
	again, err := EncodeStructure(got, testNS)
	require.NoError(t, err)
	assert.Equal(t, eo.Value, again.Value, "%T", v)
	got2, err := DecodeStructure(again, testNS)
	require.NoError(t, err)
	assert.Equal(t, got, got2, "%T", v)
}

func TestStructuresRoundTrip(t *testing.T) {
	schema := schemaOf()
	n, abstract := 0, 0
	for _, g := range generatedSchema {
		if g.abstract {
			abstract++
		}
		if g.value == nil {
			continue
		}
		n++
		t.Run(g.name, func(t *testing.T) {
			structureRoundTrip(t, reflect.New(reflect.TypeOf(g.value).Elem()).Interface().(Structure))
			for pick := range 4 {
				for _, f := range []filler{{optional: false}, {optional: true}, {optional: true, empty: true}} {
					f.schema, f.pick = schema, pick
					v := reflect.New(reflect.TypeOf(g.value).Elem())
					f.fill(v.Elem())
					structureRoundTrip(t, v.Interface().(Structure))
				}
			}
		})
	}
	// The UAFX NodeSets 1.00.04 define 56 structures, 8 of them abstract.
	assert.Equal(t, 48, n)
	assert.Equal(t, 8, abstract)
}

// --- errors -----------------------------------------------------------------

func TestStructureErrors(t *testing.T) {
	c := codec{testNS}
	_, err := EncodeStructure(nil, testNS)
	assert.ErrorIs(t, err, ErrCodec)
	_, err = EncodeStructure((*FxVersion)(nil), testNS)
	assert.ErrorIs(t, err, ErrCodec)
	_, err = EncodeStructure(&FxVersion{}, NamespaceIndexes{Data: 1})
	assert.ErrorContains(t, err, "namespace index of UAFX AC")

	v, err := DecodeStructure(nullEO(), testNS)
	assert.NoError(t, err)
	assert.Nil(t, v)

	bin := func(ns uint16, id uint32, body string) *ua.ExtensionObject {
		b, _ := hex.DecodeString(body)
		return &ua.ExtensionObject{EncodingMask: ua.ExtensionObjectBinary, TypeID: ua.NewNumericExpandedNodeID(ns, id), Value: b}
	}
	for name, eo := range map[string]*ua.ExtensionObject{
		"unknown encoding":  bin(testNS.Data, 1, ""),
		"other namespace":   bin(9, 5054, "00000000"),
		"trailing bytes":    bin(testNS.Data, 5054, "0000000000"),
		"truncated":         bin(testNS.Data, 5054, "000000"),
		"switch":            bin(testNS.Data, 5054, "03000000"),
		"union null option": bin(testNS.Data, 5054, "01000000"+"000000"),
		"reserved mask bit": bin(testNS.CM, 5050, "00000080"),
		"negative length":   bin(testNS.AC, 3008, "01000000"+"73"+"feffffff"),
		"long array":        bin(testNS.AC, 3008, "01000000"+"73"+"ffffff7f"),
	} {
		_, err := DecodeStructure(eo, testNS)
		assert.ErrorIs(t, err, ErrCodec, name)
	}

	// A field takes only the structures of its DataType, which is checked
	// before the body is decoded.
	inner, err := EncodeStructure(&FxVersion{}, testNS)
	require.NoError(t, err)
	b, err := ua.Encode(inner)
	require.NoError(t, err)
	wrong := bin(testNS.Data, 5054, "01000000"+hex.EncodeToString(b))
	_, err = DecodeStructure(wrong, testNS)
	assert.ErrorContains(t, err, "is not allowed here")

	_, err = decodeAs[*FxVersion](c, nullEO())
	assert.ErrorIs(t, err, ErrCodec)
	_, err = decodeAs[*FxVersion](c, inner)
	assert.NoError(t, err)
	_, err = decodeAs[*AggregatedHealth](c, inner)
	assert.ErrorIs(t, err, ErrCodec)

	// A union with two options set, inside a structure.
	_, err = EncodeStructure(&ApplicationIdentifier{UniqueIdentifier: &ApplicationID{IDNumeric: ptr(uint32(1)), IDString: ptr("x")}}, testNS)
	assert.ErrorContains(t, err, "more than one field")
	// A field of a structure of a namespace the server does not have.
	_, err = EncodeStructure(&ConnectionEndpointConfiguration{CommunicationLinks: &PubSubCommunicationLinkConfiguration{}}, NamespaceIndexes{Data: 5})
	assert.NoError(t, err)
	_, err = EncodeStructure(&AutomationComponentConfigurationConf{CommunicationModelConfig: &PubSubCommunicationModelConfiguration{}}, NamespaceIndexes{CM: 300})
	assert.NoError(t, err)

	w := &wbuf{Buffer: ua.NewBuffer(nil)}
	w.extensionObject(&FxVersion{})
	assert.Error(t, w.Error())
	w.fail("second")
	assert.NotContains(t, w.Error().Error(), "second")
	assert.False(t, w.length(1<<31, false))
	r := &rbuf{Buffer: ua.NewBuffer(nil)}
	assert.Nil(t, r.extensionObject(nil))
	r.fail("first")
	r.fail("second")
	assert.Equal(t, "first", r.Error().Error())
	assert.Nil(t, r.extensionObject(nil))
	assert.True(t, errors.Is(func() error { _, err := c.encode(nil); return err }(), ErrCodec))
	assert.Zero(t, c.index(0))
	assert.Zero(t, c.kind(0))
	assert.True(t, strings.Contains(nsNames[nsCM], "CM"))
}

// FuzzDecodeStructure decodes arbitrary bodies, which come from the other
// side of a connection, as each generated structure. What decodes must
// encode again, that encoding must decode, and encode to the same bytes.
// The first encoding may differ from the input: package ua normalizes some
// of the values of namespace 0 (an ExtensionObject of a type it does not
// know loses its body).
func FuzzDecodeStructure(f *testing.F) {
	var ids []encodingID
	for id := range structures {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		return ids[i].ns < ids[j].ns || ids[i].ns == ids[j].ns && ids[i].id < ids[j].id
	})
	f.Add(uint8(0), []byte{})
	f.Add(uint8(1), []byte{2, 0, 0, 0, 1, 1, 7, 0})
	f.Add(uint8(7), []byte{0xff, 0xff, 0xff, 0x7f})
	f.Add(uint8(30), []byte{2, 0, 0, 0, 1, 0, 0, 0, 'a', 1})
	c := codec{testNS}
	f.Fuzz(func(t *testing.T, which uint8, body []byte) {
		id := ids[int(which)%len(ids)]
		eo := &ua.ExtensionObject{EncodingMask: ua.ExtensionObjectBinary, TypeID: ua.NewNumericExpandedNodeID(c.index(id.ns), id.id), Value: body}
		v, err := DecodeStructure(eo, testNS)
		if err != nil {
			return
		}
		again, err := EncodeStructure(v, testNS)
		if err != nil {
			t.Fatalf("%T decoded from %x does not encode: %v", v, body, err)
		}
		v2, err := DecodeStructure(again, testNS)
		if err != nil {
			t.Fatalf("%T: the encoding %x does not decode: %v", v, again.Value, err)
		}
		third, err := EncodeStructure(v2, testNS)
		if err != nil {
			t.Fatalf("%T: %+v does not encode again: %v", v2, v2, err)
		}
		if !bytes.Equal(again.Value.([]byte), third.Value.([]byte)) {
			t.Fatalf("%T: %x encodes again as %x", v, again.Value, third.Value)
		}
	})
}
