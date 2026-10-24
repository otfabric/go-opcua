// SPDX-License-Identifier: MIT

package ua

import (
	"encoding/hex"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// binOf returns the binary encoding of v as hex. Comparing binary encodings
// is how the tests in this package decide that two values are the same: it
// is exact and independent of nil-vs-empty differences that have no meaning
// in OPC UA.
func binOf(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := Encode(v)
	require.NoError(t, err)
	return hex.EncodeToString(b)
}

// TestJSONEncodeForms pins the exact output of the four JSON forms for every
// built-in type.
func TestJSONEncodeForms(t *testing.T) {
	ts := mustTime("2024-02-29T12:34:56.7890123Z")
	guid := NewGUID("C496578A-0DFE-4B8F-870A-745238C6AEAE")
	rng := NewExtensionObject(&Range{Low: 1, High: 2})
	dv := &DataValue{Value: MustVariant(int32(5)), Status: StatusBadNodeIDUnknown, SourceTimestamp: ts, SourcePicoseconds: 3}
	dv.UpdateMask()
	xml := XMLElement("<a/>")
	opts := []CodecOption{
		WithNamespaceArray([]string{"http://opcfoundation.org/UA/", "urn:one", "urn:two"}),
		WithServerArray([]string{"urn:local", "urn:remote"}),
	}

	tests := []struct {
		name    string
		v       interface{}
		opts    []CodecOption
		compact string
		verbose string
		legacy  string
		nonRev  string
	}{
		{name: "Boolean", v: true, compact: `true`},
		{name: "Int32", v: int32(-5), compact: `-5`},
		{name: "Byte", v: uint8(255), compact: `255`},
		{name: "Int64", v: int64(math.MinInt64), compact: `"-9223372036854775808"`},
		{name: "UInt64", v: uint64(math.MaxUint64), compact: `"18446744073709551615"`},
		{name: "Float", v: float32(1.5), compact: `1.5`},
		{name: "Double NaN", v: math.NaN(), compact: `"NaN"`},
		{name: "Double +Inf", v: math.Inf(1), compact: `"Infinity"`},
		{name: "Double -Inf", v: math.Inf(-1), compact: `"-Infinity"`},
		{name: "String", v: "a\"b\\c\n\u0001\x7f", compact: `"a\"b\\c\n\u0001\u007f"`},
		{name: "String invalid UTF-8", v: "a\xffb", compact: `"a�b"`},
		{name: "DateTime", v: ts, compact: `"2024-02-29T12:34:56.7890123Z"`},
		{name: "DateTime null", v: time.Time{}, compact: `"1601-01-01T00:00:00Z"`},
		{name: "DateTime before the epoch", v: mustTime("1500-01-01T00:00:00Z"), compact: `"1601-01-01T00:00:00Z"`},
		{name: "DateTime beyond the range", v: time.Date(12000, 1, 1, 0, 0, 0, 0, time.UTC), compact: `"9999-12-31T23:59:59Z"`},
		{name: "Guid", v: guid, compact: `"C496578A-0DFE-4B8F-870A-745238C6AEAE"`},
		{name: "Guid nil", v: (*GUID)(nil), compact: `"00000000-0000-0000-0000-000000000000"`},
		{name: "ByteString", v: []byte("asdfasdf"), compact: `"YXNkZmFzZGY="`},
		{name: "ByteString null", v: []byte(nil), compact: `null`},
		{name: "ByteString empty", v: []byte{}, compact: `""`},
		{name: "XmlElement", v: xml, compact: `"<a/>"`},
		{name: "XmlElement pointer", v: &xml, compact: `"<a/>"`},
		{name: "nil", v: nil, compact: `null`},

		{name: "NodeId numeric", v: NewFourByteNodeID(4, 5555),
			compact: `"ns=4;i=5555"`, legacy: `{"Id":5555,"Namespace":4}`, nonRev: `{"Id":5555,"Namespace":4}`},
		{name: "NodeId string", v: NewStringNodeID(5, "foobar"),
			compact: `"ns=5;s=foobar"`, legacy: `{"IdType":1,"Id":"foobar","Namespace":5}`, nonRev: `{"IdType":1,"Id":"foobar","Namespace":5}`},
		{name: "NodeId guid", v: &NodeID{mask: NodeIDTypeGUID, gid: guid},
			compact: `"g=C496578A-0DFE-4B8F-870A-745238C6AEAE"`, legacy: `{"IdType":2,"Id":"C496578A-0DFE-4B8F-870A-745238C6AEAE"}`, nonRev: `{"IdType":2,"Id":"C496578A-0DFE-4B8F-870A-745238C6AEAE"}`},
		{name: "NodeId opaque", v: NewByteStringNodeID(5, []byte("asdfasdf")),
			compact: `"ns=5;b=YXNkZmFzZGY="`, legacy: `{"IdType":3,"Id":"YXNkZmFzZGY=","Namespace":5}`, nonRev: `{"IdType":3,"Id":"YXNkZmFzZGY=","Namespace":5}`},
		{name: "NodeId nil", v: (*NodeID)(nil), compact: `null`},
		{name: "NodeId with namespace table", v: NewFourByteNodeID(2, 7), opts: opts,
			compact: `"nsu=urn:two;i=7"`, legacy: `{"Id":7,"Namespace":2}`, nonRev: `{"Id":7,"Namespace":"urn:two"}`},
		{name: "NodeId namespace 1 with table", v: NewFourByteNodeID(1, 7), opts: opts,
			compact: `"nsu=urn:one;i=7"`, legacy: `{"Id":7,"Namespace":1}`, nonRev: `{"Id":7,"Namespace":1}`},

		{name: "ExpandedNodeId", v: NewExpandedNodeID(NewStringNodeID(0, "x"), "urn:other", 1),
			compact: `"svr=1;nsu=urn:other;s=x"`, legacy: `{"IdType":1,"Id":"x","Namespace":"urn:other","ServerUri":1}`, nonRev: `{"IdType":1,"Id":"x","Namespace":"urn:other","ServerUri":1}`},
		{name: "ExpandedNodeId with tables", v: NewExpandedNodeID(NewFourByteNodeID(2, 9), "", 1), opts: opts,
			compact: `"svu=urn:remote;nsu=urn:two;i=9"`, legacy: `{"Id":9,"Namespace":2,"ServerUri":1}`, nonRev: `{"Id":9,"Namespace":"urn:two","ServerUri":"urn:remote"}`},

		{name: "StatusCode Good", v: StatusOK, compact: `{}`, legacy: `0`, nonRev: `{"Code":0}`},
		{name: "StatusCode Bad", v: StatusBadNodeIDUnknown,
			compact: `{"Code":2150891520}`, verbose: `{"Code":2150891520,"Symbol":"BadNodeIdUnknown"}`,
			legacy: `2150891520`, nonRev: `{"Code":2150891520,"Symbol":"BadNodeIdUnknown"}`},
		// The symbol is looked up without the info bits (Part 6 §5.4.2.12);
		// open62541 reports the same symbol for this code.
		{name: "StatusCode with info bits", v: StatusCode(0x40920480),
			compact: `{"Code":1083311232}`, verbose: `{"Code":1083311232,"Symbol":"UncertainInitialValue"}`, legacy: `1083311232`},
		{name: "StatusCode unknown", v: StatusCode(0x8fff0000),
			compact: `{"Code":2415853568}`, legacy: `2415853568`},

		{name: "QualifiedName", v: &QualifiedName{NamespaceIndex: 1, Name: "derName"},
			compact: `"1:derName"`, legacy: `{"Name":"derName","Uri":1}`, nonRev: `{"Name":"derName","Uri":1}`},
		{name: "QualifiedName ns0", v: &QualifiedName{Name: "derName"},
			compact: `"derName"`, legacy: `{"Name":"derName"}`, nonRev: `{"Name":"derName"}`},
		{name: "QualifiedName ns0 that looks qualified", v: &QualifiedName{Name: "7:x"},
			compact: `"0:7:x"`, legacy: `{"Name":"7:x"}`, nonRev: `{"Name":"7:x"}`},
		{name: "QualifiedName with table", v: &QualifiedName{NamespaceIndex: 2, Name: "n"}, opts: opts,
			compact: `"nsu=urn:two;n"`, legacy: `{"Name":"n","Uri":2}`, nonRev: `{"Name":"n","Uri":"urn:two"}`},

		{name: "LocalizedText", v: NewLocalizedTextWithLocale("theText", "theLocale"),
			compact: `{"Locale":"theLocale","Text":"theText"}`, nonRev: `"theText"`},
		{name: "LocalizedText empty", v: &LocalizedText{}, compact: `{}`, nonRev: `""`},

		{name: "ExtensionObject null", v: NewExtensionObject(nil), compact: `null`},
		{name: "ExtensionObject structure", v: rng,
			compact: `{"UaTypeId":"i=884","Low":1,"High":2}`,
			legacy:  `{"TypeId":{"Id":15375},"Body":{"Low":1,"High":2}}`,
			nonRev:  `{"Low":1,"High":2}`},
		{name: "ExtensionObject XML body", v: &ExtensionObject{EncodingMask: ExtensionObjectXML, TypeID: NewFourByteExpandedNodeID(2, 1234), Value: &xml},
			compact: `{"UaTypeId":"ns=2;i=1234","UaEncoding":2,"UaBody":"<a/>"}`,
			legacy:  `{"TypeId":{"Id":1234,"Namespace":2},"Encoding":2,"Body":"<a/>"}`,
			nonRev:  `{"TypeId":{"Id":1234,"Namespace":2},"Encoding":2,"Body":"<a/>"}`},
		{name: "ExtensionObject binary body", v: &ExtensionObject{EncodingMask: ExtensionObjectBinary, TypeID: NewFourByteExpandedNodeID(2, 1234), Value: []byte{1, 2, 3}},
			compact: `{"UaTypeId":"ns=2;i=1234","UaEncoding":1,"UaBody":"AQID"}`,
			legacy:  `{"TypeId":{"Id":1234,"Namespace":2},"Encoding":1,"Body":"AQID"}`,
			nonRev:  `{"TypeId":{"Id":1234,"Namespace":2},"Encoding":1,"Body":"AQID"}`},

		{name: "Variant null", v: &Variant{}, compact: `null`},
		{name: "Variant scalar", v: MustVariant(uint64(345634563456)),
			compact: `{"UaType":9,"Value":"345634563456"}`, legacy: `{"Type":9,"Body":"345634563456"}`, nonRev: `"345634563456"`},
		{name: "Variant array", v: MustVariant([]uint16{42, 43}),
			compact: `{"UaType":5,"Value":[42,43]}`, legacy: `{"Type":5,"Body":[42,43]}`, nonRev: `[42,43]`},
		{name: "Variant byte array", v: MustVariant(ByteArray{42, 43}),
			compact: `{"UaType":3,"Value":[42,43]}`, legacy: `{"Type":3,"Body":[42,43]}`, nonRev: `[42,43]`},
		{name: "Variant matrix", v: MustVariant([][]uint16{{1, 2, 3}, {4, 5, 6}, {7, 8, 9}}),
			compact: `{"UaType":5,"Value":[1,2,3,4,5,6,7,8,9],"Dimensions":[3,3]}`,
			legacy:  `{"Type":5,"Body":[1,2,3,4,5,6,7,8,9],"Dimensions":[3,3]}`,
			nonRev:  `[[1,2,3],[4,5,6],[7,8,9]]`},
		{name: "Variant null array", v: MustVariant([]int32(nil)),
			compact: `{"UaType":6,"Value":[]}`, legacy: `{"Type":6,"Body":[]}`, nonRev: `[]`},
		{name: "Variant of structure", v: MustVariant(rng),
			compact: `{"UaType":22,"Value":{"UaTypeId":"i=884","Low":1,"High":2}}`,
			legacy:  `{"Type":22,"Body":{"TypeId":{"Id":15375},"Body":{"Low":1,"High":2}}}`,
			nonRev:  `{"Low":1,"High":2}`},

		{name: "DataValue", v: dv,
			compact: `{"UaType":6,"Value":5,"Status":{"Code":2150891520},"SourceTimestamp":"2024-02-29T12:34:56.7890123Z","SourcePicoseconds":3}`,
			verbose: `{"UaType":6,"Value":5,"Status":{"Code":2150891520,"Symbol":"BadNodeIdUnknown"},"SourceTimestamp":"2024-02-29T12:34:56.7890123Z","SourcePicoseconds":3}`,
			legacy:  `{"Value":{"Type":6,"Body":5},"Status":2150891520,"SourceTimestamp":"2024-02-29T12:34:56.7890123Z","SourcePicoseconds":3}`,
			nonRev:  `{"Value":5,"Status":{"Code":2150891520,"Symbol":"BadNodeIdUnknown"},"SourceTimestamp":"2024-02-29T12:34:56.7890123Z","SourcePicoseconds":3}`},
		{name: "DataValue empty", v: &DataValue{}, compact: `{}`},

		{name: "DiagnosticInfo", v: &DiagnosticInfo{EncodingMask: 0x7f, SymbolicID: 13, NamespaceURI: 15, Locale: 12, LocalizedText: 14, AdditionalInfo: "additionalInfo",
			InnerStatusCode: StatusBadArgumentsMissing, InnerDiagnosticInfo: &DiagnosticInfo{EncodingMask: DiagnosticInfoAdditionalInfo, AdditionalInfo: "INNER"}},
			compact: `{"SymbolicId":13,"NamespaceUri":15,"Locale":12,"LocalizedText":14,"AdditionalInfo":"additionalInfo","InnerStatusCode":{"Code":2155216896},"InnerDiagnosticInfo":{"AdditionalInfo":"INNER"}}`,
			verbose: `{"SymbolicId":13,"NamespaceUri":15,"Locale":12,"LocalizedText":14,"AdditionalInfo":"additionalInfo","InnerStatusCode":{"Code":2155216896,"Symbol":"BadArgumentsMissing"},"InnerDiagnosticInfo":{"AdditionalInfo":"INNER"}}`,
			legacy:  `{"SymbolicId":13,"NamespaceUri":15,"Locale":12,"LocalizedText":14,"AdditionalInfo":"additionalInfo","InnerStatusCode":2155216896,"InnerDiagnosticInfo":{"AdditionalInfo":"INNER"}}`,
			nonRev:  `{"SymbolicId":13,"NamespaceUri":15,"Locale":12,"LocalizedText":14,"AdditionalInfo":"additionalInfo","InnerStatusCode":{"Code":2155216896,"Symbol":"BadArgumentsMissing"},"InnerDiagnosticInfo":{"AdditionalInfo":"INNER"}}`},

		{name: "Enumeration", v: MessageSecurityModeSignAndEncrypt,
			compact: `3`, verbose: `"SignAndEncrypt_3"`, legacy: `3`, nonRev: `"SignAndEncrypt_3"`},
		{name: "Enumeration unknown value", v: MessageSecurityMode(77), compact: `77`},
		{name: "OptionSet", v: AccessLevelTypeCurrentRead | AccessLevelTypeCurrentWrite, compact: `3`},

		{name: "Structure", v: &ViewDescription{ViewID: NewNumericNodeID(0, 99999), Timestamp: mustTime("1970-01-15T06:56:07Z"), ViewVersion: 1236},
			// Compare the result of open62541's ViewDescription unit test.
			compact: `{"ViewId":"i=99999","Timestamp":"1970-01-15T06:56:07Z","ViewVersion":1236}`,
			legacy:  `{"ViewId":{"Id":99999},"Timestamp":"1970-01-15T06:56:07Z","ViewVersion":1236}`},
		{name: "Structure defaults", v: &UserTokenPolicy{PolicyID: "p"},
			compact: `{"PolicyId":"p"}`,
			verbose: `{"PolicyId":"p","TokenType":"Anonymous_0","IssuedTokenType":"","IssuerEndpointUrl":"","SecurityPolicyUri":""}`,
			legacy:  `{"PolicyId":"p","TokenType":0,"IssuedTokenType":"","IssuerEndpointUrl":"","SecurityPolicyUri":""}`,
			nonRev:  `{"PolicyId":"p","TokenType":"Anonymous_0","IssuedTokenType":"","IssuerEndpointUrl":"","SecurityPolicyUri":""}`},
		{name: "Structure nil", v: (*Range)(nil), compact: `null`},
		{name: "Structure arrays", v: &Argument{ArrayDimensions: []uint32{}, Name: "n"},
			compact: `{"Name":"n","ArrayDimensions":[]}`,
			verbose: `{"Name":"n","DataType":null,"ValueRank":0,"ArrayDimensions":[],"Description":null}`},
		{name: "Array", v: []*NodeID{NewTwoByteNodeID(1), nil}, compact: `["i=1",null]`, legacy: `[{"Id":1},null]`},
		{name: "Array null", v: []int32(nil), compact: `null`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := map[JSONForm]string{JSONCompact: tt.compact, JSONVerbose: tt.verbose, JSONLegacyReversible: tt.legacy, JSONLegacyNonReversible: tt.nonRev}
			for form, doc := range want {
				if doc == "" {
					if tt.verbose != "" || tt.legacy != "" || tt.nonRev != "" {
						continue // only the listed forms are pinned
					}
					doc = tt.compact // the form does not differ
				}
				got, err := EncodeJSON(tt.v, append([]CodecOption{WithJSONForm(form)}, tt.opts...)...)
				require.NoError(t, err)
				require.Equal(t, doc, string(got), "form %d", form)
			}
		})
	}
}

// TestJSONDecode feeds documents of all accepted forms to the decoder.
//
// Documents marked (open62541) are taken from the unit tests of open62541
// v1.5.9, tests/check_types_builtin_json.c. Documents marked (1.04) follow
// the reversible encoding of OPC UA 1.04 Part 6 §5.4 (Annex H of 1.05).
func TestJSONDecode(t *testing.T) {
	guid := NewGUID("00000001-0002-0003-0405-060708090A0B")
	xml := XMLElement("<a/>")
	opts := []CodecOption{
		WithNamespaceArray([]string{"http://opcfoundation.org/UA/", "urn:one", "urn:two"}),
		WithServerArray([]string{"urn:local", "urn:remote"}),
	}
	dv := &DataValue{EncodingMask: 0x3f, Value: MustVariant(true), Status: StatusCode(2153250816),
		SourceTimestamp: mustTime("1970-01-15T06:56:07Z"), ServerTimestamp: mustTime("1970-01-15T06:56:07Z")}

	tests := []struct {
		name string
		doc  string
		want interface{}
		opts []CodecOption
	}{
		// (open62541) Variant scalars at the limits of their type.
		{"Byte max", `{"UaType":3,"Value":255}`, MustVariant(uint8(255)), nil},
		{"UInt16 max", `{"UaType":5,"Value":65535}`, MustVariant(uint16(65535)), nil},
		{"UInt32 max", `{"UaType":7,"Value":4294967295}`, MustVariant(uint32(math.MaxUint32)), nil},
		{"UInt64 max", `{"UaType":9,"Value":"18446744073709551615"}`, MustVariant(uint64(math.MaxUint64)), nil},
		{"UInt64 as number", `{"UaType":9,"Value":18446744073709551615}`, MustVariant(uint64(math.MaxUint64)), nil},
		{"SByte min", `{"UaType":2,"Value":-128}`, MustVariant(int8(-128)), nil},
		{"Int16 min", `{"UaType":4,"Value":-32768}`, MustVariant(int16(-32768)), nil},
		{"Int32 min", `{"UaType":6,"Value":-2147483648}`, MustVariant(int32(math.MinInt32)), nil},
		{"Int64 min", `{"UaType":8,"Value":"-9223372036854775808"}`, MustVariant(int64(math.MinInt64)), nil},
		{"Float", `{"UaType":10,"Value":1}`, MustVariant(float32(1)), nil},
		{"Float -Infinity", `{"UaType":10,"Value":"-Infinity"}`, MustVariant(float32(math.Inf(-1))), nil},
		{"Float -NaN", `{"UaType":10,"Value":"-NaN"}`, MustVariant(float32(math.NaN())), nil},
		{"Double", `{"UaType":11,"Value":1.0000000000000002}`, MustVariant(1.0000000000000002), nil},
		{"Double -0", `{"UaType":11,"Value":-0}`, MustVariant(math.Copysign(0, -1)), nil},
		{"Double overflow", `{"UaType":11,"Value":1e999}`, MustVariant(math.Inf(1)), nil},
		{"String empty", `{"UaType":12,"Value":""}`, MustVariant(""), nil},
		{"String escape", `{"UaType":12,"Value":",#"}`, MustVariant(",#"), nil},
		{"String surrogate pair", `{"UaType":12,"Value":"𐀀"}`, MustVariant("\U00010000"), nil},
		{"ByteString null", `{"UaType":15,"Value":null}`, MustVariant([]byte(nil)), nil},
		{"Guid lower case", `{"UaType":14,"Value":"00000001-0002-0003-0405-060708090a0b"}`, MustVariant(guid), nil},
		{"StatusCode object", `{"UaType":19,"Value":{"Code":2}}`, MustVariant(StatusCode(2)), nil},
		{"StatusCode empty", `{"UaType":19,"Value":{}}`, MustVariant(StatusOK), nil},
		{"LocalizedText null", `{"UaType":21,"Value":null}`, MustVariant(&LocalizedText{}), nil},
		{"Variant without value", `{"UaType":1}`, MustVariant(false), nil},
		{"Variant array", `{"UaType":12,"Value":["1","2","3","4","5","6","7","8"]}`, MustVariant([]string{"1", "2", "3", "4", "5", "6", "7", "8"}), nil},
		{"Variant matrix", `{"UaType":17,"Value":["ns=1;i=1","ns=1;i=2","ns=1;i=3","ns=1;i=4"],"Dimensions":[2,2,1]}`,
			MustVariant([][][]*NodeID{{{NewFourByteNodeID(1, 1)}, {NewFourByteNodeID(1, 2)}}, {{NewFourByteNodeID(1, 3)}, {NewFourByteNodeID(1, 4)}}}), nil},
		{"Variant members in any order", `{"Dimensions":[1,2],"Value":[7,8],"UaType":6}`, MustVariant([][]int32{{7, 8}}), nil},
		{"Variant empty object", `{}`, &Variant{}, nil},
		{"Variant null", `null`, &Variant{}, nil},
		{"Variant array with null element", `{"UaType":22,"Value":[null]}`, MustVariant([]*ExtensionObject{NewExtensionObject(nil)}), nil},

		// (open62541) DataValue, ExtensionObject, DiagnosticInfo.
		{"DataValue", `{"UaType":1,"Value":true,"Status":{"Code":2153250816},"SourceTimestamp":"1970-01-15T06:56:07Z","SourcePicoseconds":0,"ServerTimestamp":"1970-01-15T06:56:07Z","ServerPicoseconds":0}`, dv, nil},
		{"DataValue null", `null`, &DataValue{}, nil},
		{"DataValue status only", `{"Status":{"Code":2151284736,"Symbol":"BadNotReadable"}}`, &DataValue{EncodingMask: DataValueStatusCode, Status: StatusBadNotReadable}, nil},
		{"ExtensionObject binary body of unknown type", `{"UaEncoding":1,"UaTypeId":"i=42","UaBody":"YXNkZmFzZGY="}`,
			&ExtensionObject{EncodingMask: ExtensionObjectBinary, TypeID: NewTwoByteExpandedNodeID(42), Value: []byte("asdfasdf")}, nil},
		{"ExtensionObject binary body of known type", `{"UaTypeId":"i=886","UaEncoding":1,"UaBody":"AAAAAAAA8D8AAAAAAAAAQA=="}`,
			NewExtensionObject(&Range{Low: 1, High: 2}), nil},
		{"ExtensionObject XML body", `{"UaTypeId":"ns=2;i=1234","UaEncoding":2,"UaBody":"<a/>"}`,
			&ExtensionObject{EncodingMask: ExtensionObjectXML, TypeID: NewFourByteExpandedNodeID(2, 1234), Value: &xml}, nil},
		{"ExtensionObject in place", `{"UaTypeId":"i=884","Low":1,"High":2}`, NewExtensionObject(&Range{Low: 1, High: 2}), nil},
		{"ExtensionObject type id last", `{"High":2,"Low":1,"UaTypeId":"i=884"}`, NewExtensionObject(&Range{Low: 1, High: 2}), nil},
		// open62541 only decodes the structure when it is wrapped in UaBody.
		{"ExtensionObject with UaBody", `{"UaTypeId":"i=884","UaBody":{"Low":1,"High":2}}`, NewExtensionObject(&Range{Low: 1, High: 2}), nil},
		{"ExtensionObject by binary encoding id", `{"UaTypeId":"i=886","Low":1,"High":2}`, NewExtensionObject(&Range{Low: 1, High: 2}), nil},
		{"ExtensionObject by XML encoding id", `{"UaTypeId":"i=885","Low":1,"High":2}`, NewExtensionObject(&Range{Low: 1, High: 2}), nil},
		{"ExtensionObject by JSON encoding id", `{"UaTypeId":"i=15375","Low":1,"High":2}`, NewExtensionObject(&Range{Low: 1, High: 2}), nil},
		{"ExtensionObject empty", `{}`, NewExtensionObject(nil), nil},
		{"DiagnosticInfo", `{"SymbolicId":13,"LocalizedText":14,"Locale":12,"AdditionalInfo":"additionalInfo","InnerStatusCode":{"Code":2155216896,"Symbol":"BadArgumentsMissing"},"InnerDiagnosticInfo":{"AdditionalInfo":"INNER ADDITION INFO"}}`,
			&DiagnosticInfo{EncodingMask: 0x7d, SymbolicID: 13, LocalizedText: 14, Locale: 12, AdditionalInfo: "additionalInfo", InnerStatusCode: StatusBadArgumentsMissing,
				InnerDiagnosticInfo: &DiagnosticInfo{EncodingMask: DiagnosticInfoAdditionalInfo, AdditionalInfo: "INNER ADDITION INFO"}}, nil},
		{"LocalizedText", `{"Locale":"t1","Text":"t2"}`, NewLocalizedTextWithLocale("t2", "t1"), nil},

		// (open62541) NodeId, ExpandedNodeId, QualifiedName strings.
		{"NodeId guid lower case", `"ns=5;g=00000001-0002-0003-0405-060708090a0b"`, &NodeID{mask: NodeIDTypeGUID, ns: 5, gid: guid}, nil},
		{"NodeId string with separators", `"s=a;b=c"`, NewStringNodeID(0, "a;b=c"), nil},
		{"NodeId URI", `"nsu=urn:two;i=7"`, NewFourByteNodeID(2, 7), opts},
		// Part 6 §5.4.2.10: what cannot be mapped becomes a String NodeId.
		{"NodeId unknown URI", `"nsu=urn:nope;i=7"`, NewStringNodeID(0, "nsu=urn:nope;i=7"), opts},
		{"NodeId not a NodeId", `"hello"`, NewStringNodeID(0, "hello"), nil},
		{"ExpandedNodeId", `"svr=1345;nsu=asdf;s=testtestTest"`, NewExpandedNodeID(NewStringNodeID(0, "testtestTest"), "asdf", 1345), nil},
		{"ExpandedNodeId server URI", `"svu=urn:remote;ns=1;s=testtestTest"`, NewExpandedNodeID(NewStringNodeID(1, "testtestTest"), "", 1), opts},
		{"ExpandedNodeId known URI", `"nsu=urn:one;i=5"`, NewFourByteExpandedNodeID(1, 5), opts},
		{"ExpandedNodeId unknown server URI", `"svu=urn:nope;i=5"`, &ExpandedNodeID{NodeID: NewStringNodeID(0, "svu=urn:nope;i=5")}, opts},
		{"QualifiedName", `"6789:derName"`, &QualifiedName{NamespaceIndex: 6789, Name: "derName"}, nil},
		{"QualifiedName URI", `"nsu=urn:two;n"`, &QualifiedName{NamespaceIndex: 2, Name: "n"}, opts},
		{"QualifiedName unknown URI", `"nsu=urn:nope;n"`, &QualifiedName{Name: "nsu=urn:nope;n"}, opts},
		{"QualifiedName explicit namespace 0", `"0:7:x"`, &QualifiedName{Name: "7:x"}, nil},

		// (1.04) the legacy reversible form.
		{"legacy NodeId numeric", `{"Id":5555,"Namespace":4}`, NewFourByteNodeID(4, 5555), nil},
		{"legacy NodeId explicit numeric", `{"IdType":0,"Id":85}`, NewTwoByteNodeID(85), nil},
		{"legacy NodeId string", `{"IdType":1,"Id":"foobar","Namespace":5}`, NewStringNodeID(5, "foobar"), nil},
		{"legacy NodeId guid", `{"IdType":2,"Id":"00000001-0002-0003-0405-060708090A0B"}`, &NodeID{mask: NodeIDTypeGUID, gid: guid}, nil},
		{"legacy NodeId opaque", `{"IdType":3,"Id":"YXNkZmFzZGY=","Namespace":5}`, NewByteStringNodeID(5, []byte("asdfasdf")), nil},
		{"legacy NodeId namespace URI", `{"Id":7,"Namespace":"urn:two"}`, NewFourByteNodeID(2, 7), opts},
		{"legacy ExpandedNodeId", `{"IdType":1,"Id":"x","Namespace":"urn:other","ServerUri":1}`, NewExpandedNodeID(NewStringNodeID(0, "x"), "urn:other", 1), nil},
		{"legacy ExpandedNodeId server URI", `{"Id":9,"Namespace":2,"ServerUri":"urn:remote"}`, NewExpandedNodeID(NewFourByteNodeID(2, 9), "", 1), opts},
		{"legacy StatusCode", `2150891520`, StatusBadNodeIDUnknown, nil},
		{"legacy QualifiedName", `{"Name":"derName","Uri":1}`, &QualifiedName{NamespaceIndex: 1, Name: "derName"}, nil},
		{"legacy QualifiedName URI", `{"Name":"n","Uri":"urn:two"}`, &QualifiedName{NamespaceIndex: 2, Name: "n"}, opts},
		{"legacy Variant", `{"Type":5,"Body":[1,2,3,4],"Dimensions":[2,2]}`, MustVariant([][]uint16{{1, 2}, {3, 4}}), nil},
		{"legacy DataValue", `{"Value":{"Type":6,"Body":5},"Status":2150891520,"SourcePicoseconds":3}`,
			&DataValue{EncodingMask: DataValueValue | DataValueStatusCode | DataValueSourcePicoseconds, Value: MustVariant(int32(5)), Status: StatusBadNodeIDUnknown, SourcePicoseconds: 3}, nil},
		{"legacy ExtensionObject", `{"TypeId":{"Id":15375},"Body":{"Low":1,"High":2}}`, NewExtensionObject(&Range{Low: 1, High: 2}), nil},
		{"legacy ExtensionObject binary", `{"TypeId":{"Id":886},"Encoding":1,"Body":"AAAAAAAA8D8AAAAAAAAAQA=="}`, NewExtensionObject(&Range{Low: 1, High: 2}), nil},
		{"non-reversible LocalizedText", `"just text"`, NewLocalizedText("just text"), nil},

		// Structures, enumerations and arrays.
		{"Structure", `{"ViewId":"i=99999","Timestamp":"1970-01-15T06:56:07Z","ViewVersion":1236}`,
			&ViewDescription{ViewID: NewNumericNodeID(0, 99999), Timestamp: mustTime("1970-01-15T06:56:07Z"), ViewVersion: 1236}, nil},
		{"Structure with unknown and null members", `{"Nope":[1,{"a":null}],"PolicyId":"p","TokenType":null}`, &UserTokenPolicy{PolicyID: "p"}, nil},
		{"Structure null", `null`, &Range{}, nil},
		{"Enumeration number", `3`, MessageSecurityModeSignAndEncrypt, nil},
		{"Enumeration verbose", `"SignAndEncrypt_3"`, MessageSecurityModeSignAndEncrypt, nil},
		{"Enumeration name only", `"SignAndEncrypt"`, MessageSecurityModeSignAndEncrypt, nil},
		{"Enumeration in a structure", `{"PolicyId":"p","TokenType":"UserName_1"}`, &UserTokenPolicy{PolicyID: "p", TokenType: UserTokenTypeUserName}, nil},
		{"Array", `["i=1",null]`, []*NodeID{NewTwoByteNodeID(1), NewTwoByteNodeID(0)}, nil},
		{"DateTime null literal", `"0001-01-01T00:00:00Z"`, time.Time{}, nil},
		{"DateTime epoch", `"1601-01-01T00:00:00Z"`, time.Time{}, nil},
		{"DateTime with offset", `"2024-02-29T13:34:56+01:00"`, mustTime("2024-02-29T12:34:56Z"), nil},
		{"DateTime max", `"9999-12-31T23:59:59Z"`, mustTime("9999-12-31T23:59:59Z"), nil},
		{"DateTime excess precision", `"2024-02-29T12:34:56.123456789Z"`, mustTime("2024-02-29T12:34:56.1234567Z"), nil},
		{"whitespace", " \t\r\n{ \"UaType\" : 6 , \"Value\" : [ 1 , 2 ] } \n", MustVariant([]int32{1, 2}), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := corpusTarget(tt.want)
			require.NoError(t, DecodeJSON([]byte(tt.doc), p, tt.opts...))
			got, err := corpusBinary(p)
			require.NoError(t, err)
			require.Equal(t, binOf(t, tt.want), hex.EncodeToString(got), "decoded %#v", reflect.ValueOf(p).Elem().Interface())
		})
	}
}

func TestJSONDecodeErrors(t *testing.T) {
	deep := strings.Repeat(`{"UaType":24,"Value":[`, 60) + `null` + strings.Repeat(`]}`, 60)
	tests := []struct {
		name   string
		doc    string
		target interface{}
		code   StatusCode
	}{
		// (open62541) documents its unit tests expect to be rejected.
		{"Int64 overflow", `{"UaType":8,"Value":"9223372036854775808"}`, new(Variant), StatusBadDecodingError},
		{"Int64 not a number", `{"UaType":8,"Value":"a"}`, new(Variant), StatusBadDecodingError},
		{"Double malformed", `{"UaType":11,"Value":1.12.34}`, new(Variant), StatusBadDecodingError},
		{"Guid too long", `{"UaType":14,"Value":"00000001-0002-0003-0405-060708090A0B00000001"}`, new(Variant), StatusBadDecodingError},
		{"Boolean from string", `{"UaType":1,"Value":""}`, new(Variant), StatusBadDecodingError},
		{"array element of the wrong type", `{"UaType":12,"Value":["1","2",true,"4"],"Dimensions":[2,2]}`, new(Variant), StatusBadDecodingError},

		{"empty input", ``, new(int32), StatusBadDecodingError},
		{"trailing data", `1 2`, new(int32), StatusBadDecodingError},
		{"trailing comma", `[1,]`, new([]int32), StatusBadDecodingError},
		{"unterminated string", `"abc`, new(string), StatusBadDecodingError},
		{"unterminated object", `{"a":1`, new(Range), StatusBadDecodingError},
		{"missing colon", `{"a" 1}`, new(Range), StatusBadDecodingError},
		{"missing member name", `{1:2}`, new(Range), StatusBadDecodingError},
		{"bad literal", `tru`, new(bool), StatusBadDecodingError},
		{"control character in string", "\"a\nb\"", new(string), StatusBadDecodingError},
		{"bad escape", `"\q"`, new(string), StatusBadDecodingError},
		{"bad number", `-`, new(int32), StatusBadDecodingError},
		{"bad fraction", `1.`, new(float64), StatusBadDecodingError},
		{"bad exponent", `1e`, new(float64), StatusBadDecodingError},
		{"leading zero", `01`, new(int32), StatusBadDecodingError},
		{"duplicate member", `{"Low":1,"Low":2}`, new(Range), StatusBadDecodingError},
		{"duplicate member in a large object", `{"a0":0,"a1":0,"a2":0,"a3":0,"a4":0,"a5":0,"a6":0,"a7":0,"a8":0,"a9":0,"b0":0,"b1":0,"b2":0,"b3":0,"b4":0,"b5":0,"b6":0,"b7":0,"b7":0}`, new(Range), StatusBadDecodingError},

		{"Byte out of range", `256`, new(uint8), StatusBadDecodingError},
		{"SByte out of range", `-129`, new(int8), StatusBadDecodingError},
		{"UInt32 negative", `-1`, new(uint32), StatusBadDecodingError},
		{"Int32 fraction", `1.5`, new(int32), StatusBadDecodingError},
		{"Int32 from bool", `true`, new(int32), StatusBadDecodingError},
		{"Float from bool", `true`, new(float32), StatusBadDecodingError},
		{"Float from text", `"fast"`, new(float32), StatusBadDecodingError},
		{"String from number", `1`, new(string), StatusBadDecodingError},
		{"DateTime malformed", `"yesterday"`, new(time.Time), StatusBadDecodingError},
		{"DateTime from number", `1`, new(time.Time), StatusBadDecodingError},
		{"ByteString not base64", `"@@"`, new([]byte), StatusBadDecodingError},
		{"ByteString from number", `1`, new([]byte), StatusBadDecodingError},
		{"XmlElement from number", `1`, new(XMLElement), StatusBadDecodingError},
		{"Guid from number", `1`, new(GUID), StatusBadDecodingError},
		{"NodeId from number", `1`, new(NodeID), StatusBadDecodingError},
		{"legacy NodeId bad IdType", `{"IdType":9,"Id":1}`, new(NodeID), StatusBadDecodingError},
		{"legacy NodeId string without Id", `{"IdType":1}`, new(NodeID), StatusBadDecodingError},
		{"legacy NodeId bad guid", `{"IdType":2,"Id":"x"}`, new(NodeID), StatusBadDecodingError},
		{"legacy NodeId bad base64", `{"IdType":3,"Id":"@"}`, new(NodeID), StatusBadDecodingError},
		{"legacy NodeId bad numeric", `{"Id":"x"}`, new(NodeID), StatusBadDecodingError},
		{"legacy NodeId bad namespace", `{"Id":1,"Namespace":true}`, new(NodeID), StatusBadDecodingError},
		{"legacy NodeId namespace too large", `{"Id":1,"Namespace":70000}`, new(NodeID), StatusBadDecodingError},
		{"legacy NodeId unknown namespace URI", `{"Id":1,"Namespace":"urn:nope"}`, new(NodeID), StatusBadDecodingError},
		{"legacy NodeId bad IdType type", `{"IdType":"x","Id":1}`, new(NodeID), StatusBadDecodingError},
		{"legacy ExpandedNodeId unknown server", `{"Id":1,"ServerUri":"urn:nope"}`, new(ExpandedNodeID), StatusBadDecodingError},
		{"legacy ExpandedNodeId bad server", `{"Id":1,"ServerUri":true}`, new(ExpandedNodeID), StatusBadDecodingError},
		{"legacy ExpandedNodeId bad server index", `{"Id":1,"ServerUri":-1}`, new(ExpandedNodeID), StatusBadDecodingError},
		{"StatusCode from string", `"Good"`, new(StatusCode), StatusBadDecodingError},
		{"StatusCode out of range", `{"Code":4294967296}`, new(StatusCode), StatusBadDecodingError},
		{"QualifiedName from number", `1`, new(QualifiedName), StatusBadDecodingError},
		{"legacy QualifiedName bad name", `{"Name":1}`, new(QualifiedName), StatusBadDecodingError},
		{"legacy QualifiedName bad namespace", `{"Name":"n","Uri":true}`, new(QualifiedName), StatusBadDecodingError},
		{"legacy QualifiedName namespace too large", `{"Name":"n","Uri":70000}`, new(QualifiedName), StatusBadDecodingError},
		{"legacy QualifiedName unknown URI", `{"Name":"n","Uri":"urn:nope"}`, new(QualifiedName), StatusBadDecodingError},
		{"LocalizedText from number", `1`, new(LocalizedText), StatusBadDecodingError},
		{"LocalizedText bad text", `{"Text":1}`, new(LocalizedText), StatusBadDecodingError},
		{"ExtensionObject from array", `[]`, new(ExtensionObject), StatusBadDecodingError},
		{"ExtensionObject without type", `{"Low":1}`, new(ExtensionObject), StatusBadDecodingError},
		{"ExtensionObject bad type id", `{"UaTypeId":1}`, new(ExtensionObject), StatusBadDecodingError},
		{"ExtensionObject unknown type", `{"UaTypeId":"i=4711","UaBody":{"unknown":"body"}}`, new(ExtensionObject), StatusBadDecodingError},
		{"ExtensionObject bad encoding", `{"UaTypeId":"i=884","UaEncoding":3}`, new(ExtensionObject), StatusBadDecodingError},
		{"ExtensionObject bad encoding type", `{"UaTypeId":"i=884","UaEncoding":"x"}`, new(ExtensionObject), StatusBadDecodingError},
		{"ExtensionObject binary body not base64", `{"UaTypeId":"i=884","UaEncoding":1,"UaBody":"@"}`, new(ExtensionObject), StatusBadDecodingError},
		{"ExtensionObject binary body not text", `{"UaTypeId":"i=884","UaEncoding":1,"UaBody":1}`, new(ExtensionObject), StatusBadDecodingError},
		{"ExtensionObject XML body not text", `{"UaTypeId":"i=884","UaEncoding":2,"UaBody":1}`, new(ExtensionObject), StatusBadDecodingError},
		{"ExtensionObject bad field", `{"UaTypeId":"i=884","Low":"x"}`, new(ExtensionObject), StatusBadDecodingError},
		{"legacy ExtensionObject without body", `{"TypeId":{"Id":15375}}`, new(ExtensionObject), StatusBadDecodingError},
		{"Variant from array", `[]`, new(Variant), StatusBadDecodingError},
		{"Variant value without type", `{"Value":1}`, new(Variant), StatusBadDecodingError},
		{"Variant bad type", `{"UaType":"x","Value":1}`, new(Variant), StatusBadDecodingError},
		{"Variant unknown type", `{"UaType":26,"Value":1}`, new(Variant), StatusBadDecodingError},
		{"Variant scalar with dimensions", `{"UaType":6,"Value":1,"Dimensions":[1]}`, new(Variant), StatusBadDecodingError},
		{"Variant dimensions mismatch", `{"UaType":6,"Value":[1,2,3],"Dimensions":[2,2]}`, new(Variant), StatusBadDecodingError},
		{"Variant dimensions not an array", `{"UaType":6,"Value":[1],"Dimensions":1}`, new(Variant), StatusBadDecodingError},
		{"Variant bad dimension", `{"UaType":6,"Value":[1],"Dimensions":["x"]}`, new(Variant), StatusBadDecodingError},
		{"Variant zero dimension", `{"UaType":6,"Value":[],"Dimensions":[0,2]}`, new(Variant), StatusBadDecodingError},
		{"Variant huge dimensions", `{"UaType":6,"Value":[1],"Dimensions":[2147483647,2147483647]}`, new(Variant), StatusBadDecodingError},
		{"DataValue from array", `[]`, new(DataValue), StatusBadDecodingError},
		{"DataValue bad value", `{"UaType":6,"Value":"x"}`, new(DataValue), StatusBadDecodingError},
		{"DataValue bad legacy value", `{"Value":1}`, new(DataValue), StatusBadDecodingError},
		{"DataValue bad status", `{"Status":"x"}`, new(DataValue), StatusBadDecodingError},
		{"DataValue bad timestamp", `{"SourceTimestamp":"x"}`, new(DataValue), StatusBadDecodingError},
		{"DataValue bad timestamp type", `{"ServerTimestamp":1}`, new(DataValue), StatusBadDecodingError},
		{"DataValue bad picoseconds", `{"ServerPicoseconds":70000}`, new(DataValue), StatusBadDecodingError},
		{"DiagnosticInfo from array", `[]`, new(DiagnosticInfo), StatusBadDecodingError},
		{"DiagnosticInfo bad index", `{"SymbolicId":"x"}`, new(DiagnosticInfo), StatusBadDecodingError},
		{"DiagnosticInfo bad info", `{"AdditionalInfo":1}`, new(DiagnosticInfo), StatusBadDecodingError},
		{"DiagnosticInfo bad status", `{"InnerStatusCode":"x"}`, new(DiagnosticInfo), StatusBadDecodingError},
		{"DiagnosticInfo bad inner", `{"InnerDiagnosticInfo":[]}`, new(DiagnosticInfo), StatusBadDecodingError},
		{"Structure from array", `[]`, new(Range), StatusBadDecodingError},
		{"Structure bad field", `{"Low":"x"}`, new(Range), StatusBadDecodingError},
		{"Structure bad nested field", `{"RequestHeader":{"RequestHandle":"x"}}`, new(ReadRequest), StatusBadDecodingError},
		{"Enumeration unknown name", `"Nope"`, new(MessageSecurityMode), StatusBadDecodingError},
		{"Enumeration from bool", `true`, new(MessageSecurityMode), StatusBadDecodingError},
		{"Enumeration negative", `"X_-1"`, new(MessageSecurityMode), StatusBadDecodingError},
		{"Enumeration overflow", `"X_4294967296"`, new(MessageSecurityMode), StatusBadDecodingError},
		{"Enumeration signed overflow", `"X_4294967296"`, new(testSignedEnum), StatusBadDecodingError},
		{"Array from object", `{}`, new([]int32), StatusBadDecodingError},
		{"Array bad element", `[1,"x"]`, new([]int32), StatusBadDecodingError},

		// Limits.
		{"nesting too deep", strings.Repeat("[", 200) + strings.Repeat("]", 200), new(Variant), StatusBadEncodingLimitsExceeded},
		{"object nesting too deep", deep + deep, new(Variant), StatusBadEncodingLimitsExceeded},
		{"Variant array too long", `{"UaType":1,"Value":[` + strings.Repeat("true,", MaxVariantArrayLength) + `true]}`, new(Variant), StatusBadEncodingLimitsExceeded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := DecodeJSON([]byte(tt.doc), tt.target)
			require.Error(t, err)
			require.True(t, errors.Is(err, tt.code), "got %v", err)
		})
	}

	t.Run("not a pointer", func(t *testing.T) {
		require.ErrorIs(t, DecodeJSON([]byte(`1`), int32(0)), StatusBadDecodingError)
		require.ErrorIs(t, DecodeJSON([]byte(`1`), (*int32)(nil)), StatusBadDecodingError)
		require.ErrorIs(t, DecodeJSON([]byte(`1`), nil), StatusBadDecodingError)
	})
	t.Run("unsupported target", func(t *testing.T) {
		require.ErrorIs(t, DecodeJSON([]byte(`1`), new(chan int)), StatusBadDecodingError)
		require.ErrorIs(t, DecodeJSON([]byte(`1`), new(interface{})), StatusBadDecodingError)
	})
}

type testSignedEnum int8

func TestJSONOptions(t *testing.T) {
	t.Run("indent", func(t *testing.T) {
		b, err := EncodeJSON(&Range{Low: 1, High: 2}, WithIndent("  "))
		require.NoError(t, err)
		require.Equal(t, "{\n  \"Low\": 1,\n  \"High\": 2\n}", string(b))
	})
	t.Run("max depth on encode", func(t *testing.T) {
		v := MustVariant([]*Variant{MustVariant([]*Variant{MustVariant(int32(1))})})
		_, err := EncodeJSON(v, WithMaxDepth(2))
		require.ErrorIs(t, err, StatusBadEncodingLimitsExceeded)
		_, err = EncodeJSON(v, WithJSONForm(JSONLegacyNonReversible), WithMaxDepth(2))
		require.ErrorIs(t, err, StatusBadEncodingLimitsExceeded)
		_, err = EncodeJSON(v)
		require.NoError(t, err)
	})
	t.Run("cyclic DiagnosticInfo", func(t *testing.T) {
		d := &DiagnosticInfo{EncodingMask: DiagnosticInfoInnerDiagnosticInfo}
		d.InnerDiagnosticInfo = d
		_, err := EncodeJSON(d)
		require.ErrorIs(t, err, StatusBadEncodingLimitsExceeded)
		_, err = EncodeXML(d)
		require.ErrorIs(t, err, StatusBadEncodingLimitsExceeded)
	})
	t.Run("max depth on decode", func(t *testing.T) {
		doc := []byte(`{"UaType":24,"Value":[{"UaType":6,"Value":1}]}`)
		require.NoError(t, DecodeJSON(doc, new(Variant), WithMaxDepth(3)))
		require.ErrorIs(t, DecodeJSON(doc, new(Variant), WithMaxDepth(2)), StatusBadEncodingLimitsExceeded)
		require.NoError(t, DecodeJSON(doc, new(Variant), WithMaxDepth(0)), "0 keeps the default")
	})
	t.Run("max array length", func(t *testing.T) {
		doc := []byte(`{"UaType":6,"Value":[1,2,3]}`)
		require.NoError(t, DecodeJSON(doc, new(Variant), WithMaxArrayLength(3)))
		require.ErrorIs(t, DecodeJSON(doc, new(Variant), WithMaxArrayLength(2)), StatusBadEncodingLimitsExceeded)
		require.NoError(t, DecodeJSON(doc, new(Variant), WithMaxArrayLength(0), nil), "0 keeps the default")
	})
	t.Run("unsupported value", func(t *testing.T) {
		_, err := EncodeJSON(make(chan int))
		require.ErrorIs(t, err, StatusBadEncodingError)
		_, err = EncodeJSON(struct{ C chan int }{C: make(chan int)})
		require.ErrorIs(t, err, StatusBadEncodingError)
		_, err = EncodeJSON([]interface{}{1})
		require.ErrorIs(t, err, StatusBadEncodingError)
	})
	t.Run("pointers and interfaces are followed", func(t *testing.T) {
		n := int32(7)
		p := &n
		b, err := EncodeJSON(&p)
		require.NoError(t, err)
		require.Equal(t, "7", string(b))
		var nilp *int32
		b, err = EncodeJSON(nilp)
		require.NoError(t, err)
		require.Equal(t, "null", string(b))
	})
	t.Run("decode into pointer to pointer", func(t *testing.T) {
		var n *NodeID
		require.NoError(t, DecodeJSON([]byte(`"i=5"`), &n))
		require.Equal(t, "i=5", n.String())
		var r *Range
		require.NoError(t, DecodeJSON([]byte(`null`), &r))
		require.Nil(t, r)
		var x *XMLElement
		require.NoError(t, DecodeJSON([]byte(`"<a/>"`), &x))
		require.Equal(t, XMLElement("<a/>"), *x)
	})
	t.Run("decode builtins held by value in a structure", func(t *testing.T) {
		type holder struct {
			ID   NodeID
			Text LocalizedText
			Var  Variant
		}
		var h holder
		require.NoError(t, DecodeJSON([]byte(`{"ID":"i=5","Text":{"Text":"t"},"Var":{"UaType":6,"Value":1}}`), &h))
		require.Equal(t, "i=5", h.ID.String())
		require.Equal(t, "t", h.Text.Text)
		require.Equal(t, int32(1), h.Var.Value())
		b, err := EncodeJSON(h)
		require.NoError(t, err)
		require.Equal(t, `{"ID":"i=5","Text":{"Text":"t"},"Var":{"UaType":6,"Value":1}}`, string(b))
		b, err = EncodeXML(h)
		require.NoError(t, err)
		var h2 holder
		require.NoError(t, DecodeXML(b, &h2))
		require.Equal(t, h.ID.String(), h2.ID.String())
		require.Equal(t, int32(1), h2.Var.Value())
	})
}

// TestNodeIDStringEscapesURIs pins the percent-encoding of ';' and '%' in the
// URIs of the string form of a NodeId, ExpandedNodeId and QualifiedName
// (Part 6 §5.1.12). Unescaped, a ';' in a namespace URI ended the URI early:
// the legacy {"Id":1,"Namespace":"urn:test;a"} was written as
// "nsu=urn:test;a;i=1" and read back as a String NodeId holding that text.
func TestNodeIDStringEscapesURIs(t *testing.T) {
	opts := []CodecOption{
		WithNamespaceArray([]string{"http://opcfoundation.org/UA/", "urn:a;b%c"}),
		WithServerArray([]string{"urn:local", "urn:srv;1"}),
	}
	tests := []struct {
		name    string
		v       interface{}
		opts    []CodecOption
		compact string
	}{
		{name: "ExpandedNodeId URI with ';'", v: NewExpandedNodeID(NewNumericNodeID(0, 346219405), "urn:test;a", 0),
			compact: `"nsu=urn:test%3Ba;i=346219405"`},
		{name: "ExpandedNodeId URI with '%'", v: NewExpandedNodeID(NewStringNodeID(0, "x;y"), "urn:100%3B", 7),
			compact: `"svr=7;nsu=urn:100%253B;s=x;y"`},
		{name: "ExpandedNodeId server URI", v: NewExpandedNodeID(NewFourByteNodeID(1, 9), "", 1), opts: opts,
			compact: `"svu=urn:srv%3B1;nsu=urn:a%3Bb%25c;i=9"`},
		{name: "NodeId with table", v: NewFourByteNodeID(1, 9), opts: opts,
			compact: `"nsu=urn:a%3Bb%25c;i=9"`},
		{name: "QualifiedName with table", v: &QualifiedName{NamespaceIndex: 1, Name: "n;m"}, opts: opts,
			compact: `"nsu=urn:a%3Bb%25c;n;m"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := EncodeJSON(tt.v, tt.opts...)
			require.NoError(t, err)
			require.Equal(t, tt.compact, string(b))
			again := reflect.New(reflect.TypeOf(tt.v).Elem())
			require.NoError(t, DecodeJSON(b, again.Interface(), tt.opts...))
			require.Equal(t, binOf(t, tt.v), binOf(t, again.Interface()))

			x, err := EncodeXML(tt.v, tt.opts...)
			require.NoError(t, err)
			again = reflect.New(reflect.TypeOf(tt.v).Elem())
			require.NoError(t, DecodeXML(x, again.Interface(), tt.opts...))
			require.Equal(t, binOf(t, tt.v), binOf(t, again.Interface()))
		})
	}

	// The legacy form carries the URI as it is; the compact form written
	// from it is a fixed point.
	var e ExpandedNodeID
	require.NoError(t, DecodeJSON([]byte(`{"Id":346219405,"Namespace":"urn:test;a"}`), &e))
	first, err := EncodeJSON(&e)
	require.NoError(t, err)
	var e2 ExpandedNodeID
	require.NoError(t, DecodeJSON(first, &e2))
	second, err := EncodeJSON(&e2)
	require.NoError(t, err)
	require.Equal(t, string(first), string(second))
	require.Equal(t, "urn:test;a", e2.NamespaceURI)

	// Lower case hex is read too; other percent-encodings are kept.
	require.NoError(t, DecodeJSON([]byte(`"nsu=urn:x%3by%20z;i=1"`), &e))
	require.Equal(t, "urn:x;y%20z", e.NamespaceURI)
}

// TestExistingMarshalJSONUnchanged guards the display format that
// encoding/json produces through the MarshalJSON methods of this package,
// which predates the OPC UA JSON DataEncoding and must not change.
func TestExistingMarshalJSONUnchanged(t *testing.T) {
	b, err := MustVariant(int32(42)).MarshalJSON()
	require.NoError(t, err)
	require.JSONEq(t, `{"type":"Int32","value":42}`, string(b))

	b, err = EncodeJSON(MustVariant(int32(42)))
	require.NoError(t, err)
	require.Equal(t, `{"UaType":6,"Value":42}`, string(b))
}
