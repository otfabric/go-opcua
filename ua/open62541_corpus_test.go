// SPDX-License-Identifier: MIT

package ua

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Cross-stack evidence against open62541 v1.5.9.
//
// testdata/open62541_corpus.json records, for every case below, what
// open62541's UA_encodeJson / UA_encodeXml produced for the value and what
// UA_decodeJson / UA_decodeXml made of the documents this package produces.
// The binary DataEncoding is the neutral reference in both directions: the
// two stacks interoperate on it on the wire.
//
// The corpus is committed so that the evidence is checked on every test run
// without Docker. To regenerate it (after adding cases or changing what the
// encoders emit) build the helper in testdata/open62541 and run:
//
//	docker build -t go-opcua-uacodec ua/testdata/open62541
//	OPEN62541_UACODEC="docker run -i --rm go-opcua-uacodec" \
//	    go test ./ua -run TestOpen62541Corpus -count=1
//
// See testdata/open62541/README.md.

const corpusFile = "testdata/open62541_corpus.json"

type corpusCase struct {
	name  string
	typ   string // open62541 type name (UA_TYPES[i].typeName)
	value interface{}
}

type corpusEntry struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Binary string `json:"binary"` // hex, the value in the binary DataEncoding

	// What open62541 encodes the value to ("ERR <status>" if it cannot).
	JSON string `json:"open62541Json"`
	XML  string `json:"open62541Xml"`

	// What go-opcua encodes the value to, and the binary encoding (hex) of
	// what open62541 decoded from that document ("ERR <status>" if it
	// rejected it).
	GoJSON        string `json:"goJson"`
	GoJSONDecoded string `json:"goJsonDecodedByOpen62541"`
	GoXML         string `json:"goXml"`
	GoXMLDecoded  string `json:"goXmlDecodedByOpen62541"`
}

func mustTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		panic(err)
	}
	return t
}

func corpusCases() []corpusCase {
	ts := mustTime("2024-02-29T12:34:56.789012300Z")
	guid := NewGUID("C496578A-0DFE-4B8F-870A-745238C6AEAE")
	arg := &Argument{
		Name:            "Input",
		DataType:        NewTwoByteNodeID(6),
		ValueRank:       1,
		ArrayDimensions: []uint32{3},
		Description:     NewLocalizedTextWithLocale("the input", "en"),
	}
	rng := &Range{Low: -1.5, High: 1e3}
	eu := &EUInformation{NamespaceURI: "http://www.opcfoundation.org/UA/units/un/cefact", UnitID: 4408652, DisplayName: NewLocalizedText("°C"), Description: NewLocalizedText("degree Celsius")}
	xml := XMLElement("<a x=\"1\"><b>t &amp; u</b></a>")
	dv := &DataValue{Value: MustVariant(int32(-7)), Status: StatusBadNodeIDUnknown, SourceTimestamp: ts, ServerTimestamp: ts, SourcePicoseconds: 12, ServerPicoseconds: 34}
	dv.UpdateMask()
	diag := &DiagnosticInfo{SymbolicID: 1, NamespaceURI: 2, Locale: 3, LocalizedText: 4, AdditionalInfo: "more", InnerStatusCode: StatusBadInternalError,
		InnerDiagnosticInfo: &DiagnosticInfo{AdditionalInfo: "inner"}}
	diag.InnerDiagnosticInfo.UpdateMask()
	diag.UpdateMask()

	cases := []corpusCase{
		{"boolean/true", "Boolean", true},
		{"boolean/false", "Boolean", false},
		{"sbyte/min", "SByte", int8(math.MinInt8)},
		{"sbyte/max", "SByte", int8(math.MaxInt8)},
		{"byte/max", "Byte", uint8(math.MaxUint8)},
		{"int16/min", "Int16", int16(math.MinInt16)},
		{"uint16/max", "UInt16", uint16(math.MaxUint16)},
		{"int32/min", "Int32", int32(math.MinInt32)},
		{"int32/max", "Int32", int32(math.MaxInt32)},
		{"uint32/max", "UInt32", uint32(math.MaxUint32)},
		{"int64/min", "Int64", int64(math.MinInt64)},
		{"int64/max", "Int64", int64(math.MaxInt64)},
		{"uint64/max", "UInt64", uint64(math.MaxUint64)},
		{"float/value", "Float", float32(3.1415927)},
		{"float/zero", "Float", float32(0)},
		{"float/negzero", "Float", float32(math.Copysign(0, -1))},
		{"float/max", "Float", float32(math.MaxFloat32)},
		{"float/smallest", "Float", float32(math.SmallestNonzeroFloat32)},
		{"float/nan", "Float", float32(math.NaN())},
		{"float/inf", "Float", float32(math.Inf(1))},
		{"float/neginf", "Float", float32(math.Inf(-1))},
		{"double/value", "Double", 2.718281828459045},
		{"double/integral", "Double", 1e21},
		{"double/max", "Double", math.MaxFloat64},
		{"double/smallest", "Double", math.SmallestNonzeroFloat64},
		{"double/nan", "Double", math.NaN()},
		{"double/inf", "Double", math.Inf(1)},
		{"double/neginf", "Double", math.Inf(-1)},
		{"string/plain", "String", "hello"},
		{"string/empty", "String", ""},
		{"string/escapes", "String", "quote\" backslash\\ slash/ tab\t nl\n cr\r <tag> & 'apos'"},
		{"string/unicode", "String", "äöü € 日本語 🙂"},
		{"datetime/value", "DateTime", ts},
		{"datetime/seconds", "DateTime", mustTime("1999-12-31T23:59:59Z")},
		{"datetime/null", "DateTime", time.Time{}},
		{"datetime/epoch+1tick", "DateTime", time.Date(1601, 1, 1, 0, 0, 0, 100, time.UTC)},
		{"datetime/year9999", "DateTime", mustTime("9999-12-31T23:59:58.9999999Z")},
		{"guid/value", "Guid", guid},
		{"guid/zero", "Guid", zeroGUID()},
		{"bytestring/value", "ByteString", []byte{0, 1, 2, 0xfd, 0xfe, 0xff}},
		{"bytestring/null", "ByteString", []byte(nil)},
		{"xmlelement/value", "XmlElement", xml},
		{"nodeid/null", "NodeId", NewTwoByteNodeID(0)},
		{"nodeid/numeric", "NodeId", NewTwoByteNodeID(85)},
		{"nodeid/numeric-ns", "NodeId", NewFourByteNodeID(2, 5001)},
		{"nodeid/numeric-max", "NodeId", NewNumericNodeID(65535, math.MaxUint32)},
		{"nodeid/string", "NodeId", NewStringNodeID(1, "Line 1;Tank=5.Level")},
		{"nodeid/string-ns0", "NodeId", NewStringNodeID(0, "plain")},
		{"nodeid/guid", "NodeId", &NodeID{mask: NodeIDTypeGUID, ns: 3, gid: guid}},
		{"nodeid/opaque", "NodeId", NewByteStringNodeID(4, []byte{0xde, 0xad, 0xbe, 0xef})},
		{"expandednodeid/plain", "ExpandedNodeId", NewFourByteExpandedNodeID(2, 5001)},
		{"expandednodeid/uri", "ExpandedNodeId", NewExpandedNodeID(NewStringNodeID(0, "id"), "urn:example:ns", 0)},
		{"expandednodeid/server", "ExpandedNodeId", NewExpandedNodeID(NewFourByteNodeID(1, 7), "", 3)},
		{"expandednodeid/uri+server", "ExpandedNodeId", NewExpandedNodeID(NewTwoByteNodeID(7), "urn:example:ns", 3)},
		{"statuscode/good", "StatusCode", StatusOK},
		{"statuscode/bad", "StatusCode", StatusBadNodeIDUnknown},
		{"statuscode/uncertain-bits", "StatusCode", StatusCode(0x40920480)},
		{"statuscode/unknown", "StatusCode", StatusCode(0x8fff0000)},
		{"qualifiedname/ns0", "QualifiedName", &QualifiedName{Name: "Name"}},
		{"qualifiedname/ns2", "QualifiedName", &QualifiedName{NamespaceIndex: 2, Name: "Na:me"}},
		{"qualifiedname/empty", "QualifiedName", &QualifiedName{}},
		{"localizedtext/full", "LocalizedText", NewLocalizedTextWithLocale("Grüße", "de-DE")},
		{"localizedtext/text", "LocalizedText", NewLocalizedText("text only")},
		{"localizedtext/empty", "LocalizedText", &LocalizedText{}},
		{"extensionobject/null", "ExtensionObject", NewExtensionObject(nil)},
		{"extensionobject/argument", "ExtensionObject", NewExtensionObject(arg)},
		{"extensionobject/range", "ExtensionObject", NewExtensionObject(rng)},
		{"extensionobject/euinformation", "ExtensionObject", NewExtensionObject(eu)},
		{"datavalue/empty", "DataValue", &DataValue{}},
		{"datavalue/value", "DataValue", &DataValue{EncodingMask: DataValueValue, Value: MustVariant(float64(1.5))}},
		{"datavalue/full", "DataValue", dv},
		{"datavalue/status-only", "DataValue", &DataValue{EncodingMask: DataValueStatusCode, Status: StatusBadNotReadable}},
		{"datavalue/array", "DataValue", &DataValue{EncodingMask: DataValueValue | DataValueSourceTimestamp, Value: MustVariant([]string{"a", "b"}), SourceTimestamp: ts}},
		{"diagnosticinfo/empty", "DiagnosticInfo", &DiagnosticInfo{}},
		{"diagnosticinfo/full", "DiagnosticInfo", diag},
		{"variant/null", "Variant", &Variant{}},
		{"variant/matrix-int32-2x3", "Variant", MustVariant([][]int32{{1, 2, 3}, {4, 5, 6}})},
		{"variant/matrix-string-2x2x2", "Variant", MustVariant([][][]string{{{"a", "b"}, {"c", "d"}}, {{"e", "f"}, {"g", "h"}}})},
		{"variant/matrix-double-3x1", "Variant", MustVariant([][]float64{{1.5}, {2.5}, {3.5}})},
		{"variant/array-variant", "Variant", MustVariant([]*Variant{MustVariant(int32(1)), MustVariant("two"), MustVariant([]bool{true, false})})},
		{"variant/array-extensionobject-mixed", "Variant", MustVariant([]*ExtensionObject{NewExtensionObject(arg), NewExtensionObject(rng), NewExtensionObject(nil)})},
		{"variant/array-empty-int32", "Variant", MustVariant([]int32{})},
		{"variant/bytearray", "Variant", MustVariant(ByteArray{1, 2, 3})},
		{"structure/argument", "Argument", arg},
		{"structure/range", "Range", rng},
		{"structure/euinformation", "EUInformation", eu},
		{"structure/buildinfo", "BuildInfo", &BuildInfo{ProductURI: "urn:p", ManufacturerName: "m", ProductName: "n", SoftwareVersion: "1.2", BuildNumber: "3", BuildDate: ts}},
		{"structure/serverstatus", "ServerStatusDataType", &ServerStatusDataType{StartTime: ts, CurrentTime: ts, State: ServerStateRunning,
			BuildInfo: &BuildInfo{ProductName: "n", BuildDate: ts}, SecondsTillShutdown: 5, ShutdownReason: NewLocalizedText("bye")}},
		{"structure/readvalueid", "ReadValueId", &ReadValueID{NodeID: NewFourByteNodeID(2, 5001), AttributeID: AttributeIDValue, IndexRange: "1:2", DataEncoding: &QualifiedName{Name: "Default Binary"}}},
		{"structure/keyvaluepair", "KeyValuePair", &KeyValuePair{Key: &QualifiedName{NamespaceIndex: 1, Name: "k"}, Value: MustVariant([]uint16{1, 2})}},
		{"structure/enumvaluetype", "EnumValueType", &EnumValueType{Value: -3, DisplayName: NewLocalizedText("Minus"), Description: NewLocalizedText("d")}},
		{"structure/usertokenpolicy", "UserTokenPolicy", &UserTokenPolicy{PolicyID: "anon", TokenType: UserTokenTypeUserName, SecurityPolicyURI: "http://opcfoundation.org/UA/SecurityPolicy#None"}},
		{"structure/endpointdescription", "EndpointDescription", &EndpointDescription{
			EndpointURL: "opc.tcp://host:4840", Server: &ApplicationDescription{ApplicationURI: "urn:app", ApplicationName: NewLocalizedText("app"), ApplicationType: ApplicationTypeClientAndServer, DiscoveryURLs: []string{"opc.tcp://host:4840"}},
			ServerCertificate: []byte{1, 2, 3}, SecurityMode: MessageSecurityModeSignAndEncrypt, SecurityPolicyURI: "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
			UserIdentityTokens: []*UserTokenPolicy{{PolicyID: "a", TokenType: UserTokenTypeAnonymous}}, TransportProfileURI: "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary", SecurityLevel: 3}},
		{"structure/readrequest", "ReadRequest", &ReadRequest{RequestHeader: &RequestHeader{AuthenticationToken: NewByteStringNodeID(0, []byte{1, 2}), Timestamp: ts, RequestHandle: 7, TimeoutHint: 1000, AdditionalHeader: NewExtensionObject(nil)},
			MaxAge: 500, TimestampsToReturn: TimestampsToReturnBoth, NodesToRead: []*ReadValueID{{NodeID: NewTwoByteNodeID(85), AttributeID: AttributeIDBrowseName}}}},
		{"structure/readresponse", "ReadResponse", &ReadResponse{ResponseHeader: &ResponseHeader{Timestamp: ts, RequestHandle: 7, ServiceResult: StatusBadTooManyOperations, ServiceDiagnostics: &DiagnosticInfo{}, StringTable: []string{"a"}, AdditionalHeader: NewExtensionObject(nil)},
			Results: []*DataValue{dv, {}}, DiagnosticInfos: []*DiagnosticInfo{diag}}},
		{"enum/messagesecuritymode", "MessageSecurityMode", MessageSecurityModeSignAndEncrypt},
		{"enum/nodeclass", "NodeClass", NodeClassVariable},
		{"enum/serverstate", "ServerState", ServerStateRunning},
	}

	// Every built-in type as a scalar and as an array in a Variant.
	scalars := map[TypeID][]interface{}{
		TypeIDBoolean:         {true, false},
		TypeIDSByte:           {int8(-1), int8(2)},
		TypeIDByte:            {uint8(1), uint8(200)},
		TypeIDInt16:           {int16(-300), int16(300)},
		TypeIDUint16:          {uint16(1), uint16(60000)},
		TypeIDInt32:           {int32(-70000), int32(70000)},
		TypeIDUint32:          {uint32(1), uint32(4000000000)},
		TypeIDInt64:           {int64(-5000000000), int64(5000000000)},
		TypeIDUint64:          {uint64(1), uint64(18000000000000000000)},
		TypeIDFloat:           {float32(1.25), float32(-2.5)},
		TypeIDDouble:          {1.125, -2.0625},
		TypeIDString:          {"one", "two"},
		TypeIDDateTime:        {ts, mustTime("2001-02-03T04:05:06Z")},
		TypeIDGUID:            {guid, NewGUID("00000001-0002-0003-0405-060708090A0B")},
		TypeIDByteString:      {[]byte{1, 2, 3}, []byte{4}},
		TypeIDXMLElement:      {xml, XMLElement("<c/>")},
		TypeIDNodeID:          {NewFourByteNodeID(1, 1000), NewStringNodeID(2, "two")},
		TypeIDExpandedNodeID:  {NewFourByteExpandedNodeID(1, 1000), NewExpandedNodeID(NewStringNodeID(0, "x"), "urn:example:ns", 0)},
		TypeIDStatusCode:      {StatusBadNodeIDUnknown, StatusOK},
		TypeIDQualifiedName:   {&QualifiedName{NamespaceIndex: 1, Name: "one"}, &QualifiedName{Name: "two"}},
		TypeIDLocalizedText:   {NewLocalizedTextWithLocale("one", "en"), NewLocalizedText("two")},
		TypeIDExtensionObject: {NewExtensionObject(rng), NewExtensionObject(eu)},
		TypeIDDataValue:       {dv, &DataValue{EncodingMask: DataValueValue, Value: MustVariant("v")}},
		TypeIDDiagnosticInfo:  {diag, &DiagnosticInfo{}},
	}
	for typ := TypeIDBoolean; typ <= TypeIDDiagnosticInfo; typ++ {
		vals, ok := scalars[typ]
		if !ok {
			continue
		}
		name := strings.ToLower(builtinTypeNames[typ])
		cases = append(cases, corpusCase{"variant/scalar-" + name, "Variant", MustVariant(vals[0])})
		st, _ := variantSliceType(typ)
		arr := reflect.MakeSlice(st, len(vals), len(vals))
		for i, v := range vals {
			arr.Index(i).Set(reflect.ValueOf(v))
		}
		cases = append(cases, corpusCase{"variant/array-" + name, "Variant", MustVariant(arr.Interface())})
	}
	return cases
}

// corpusDivergences lists where the two stacks knowingly disagree. Each
// entry is a finding, not a waiver for this package: the reason says which
// side deviates from Part 6. A case matches if its key
// "<case>/<direction>" matches the pattern.
//
// Directions: o2g-json / o2g-xml (go-opcua decodes what open62541 encoded),
// g2o-json / g2o-xml (open62541 decodes what go-opcua encoded).
var corpusDivergences = []struct {
	pattern *regexp.Regexp
	reason  string
}{
	{regexp.MustCompile(`^float/negzero/o2g-`),
		"open62541 writes -0.0 as 0.0 and loses the sign"},
	{regexp.MustCompile(`^(string|qualifiedname)/empty/g2o-`),
		"go-opcua has no null String: an empty string is the null String in its binary encoding, open62541 decodes \"\" to a non-null empty String"},
	{regexp.MustCompile(`^string/escapes/o2g-xml$`),
		"open62541 writes a carriage return as a raw character; XML line-end normalisation turns it into a line feed (it must be written as &#xD;)"},
	{regexp.MustCompile(`^bytestring/null/o2g-xml$`),
		"open62541 writes a null ByteString as the text \"null\", which is valid base64 for three bytes"},
	{regexp.MustCompile(`^bytestring/null/g2o-json$`),
		"open62541 rejects a top-level JSON null for a ByteString (it accepts it as a structure field)"},
	{regexp.MustCompile(`^bytestring/null/g2o-xml$`),
		"open62541 ignores xsi:nil and decodes an empty instead of a null ByteString"},
	{regexp.MustCompile(`xmlelement.*/g2o-xml$`),
		"open62541 does not implement decoding of XmlElement from XML"},
	{regexp.MustCompile(`^(extensionobject/(argument|range|euinformation)|variant/(scalar|array)-extensionobject(-mixed)?)/g2o-json$`),
		"open62541 cannot decode a structure encoded in place in an ExtensionObject (the 1.05 form it emits itself): it treats UaTypeId as an unknown field"},
	{regexp.MustCompile(`^datavalue/status-only/g2o-json$`),
		"open62541 cannot decode a DataValue without a value (the document it emits itself)"},
	{regexp.MustCompile(`^(datavalue/.*|diagnosticinfo/.*|variant/(scalar|array)-(datavalue|diagnosticinfo)|structure/readresponse)/(o2g|g2o)-xml$`),
		"open62541 does not implement DataValue and DiagnosticInfo in XML"},
	{regexp.MustCompile(`^(structure|enum)/.*/o2g-xml$`),
		"open62541 does not implement encoding of structures and enumerations to XML"},
	{regexp.MustCompile(`^(extensionobject/(argument|range|euinformation)|variant/(scalar|array)-extensionobject(-mixed)?)/o2g-xml$`),
		"open62541 does not implement encoding of structures to XML"},
	{regexp.MustCompile(`^variant/(null|matrix-.*)/o2g-xml$`),
		"open62541 does not implement encoding of a null Variant or a matrix to XML"},
	{regexp.MustCompile(`^(enum/.*|structure/(serverstatus|usertokenpolicy|endpointdescription|readrequest))/g2o-xml$`),
		"open62541 only reads enumerations as numbers from XML; Part 6 §5.3.4 defines the Name_Value string written here"},
}

func corpusDivergence(key string) (string, bool) {
	for _, d := range corpusDivergences {
		if d.pattern.MatchString(key) {
			return d.reason, true
		}
	}
	return "", false
}

// corpusTarget returns a pointer to a new value of the Go type of v, to
// decode into.
func corpusTarget(v interface{}) interface{} {
	t := reflect.TypeOf(v)
	if t.Kind() == reflect.Pointer && t.Elem().Kind() == reflect.Struct {
		return reflect.New(t.Elem()).Interface()
	}
	return reflect.New(t).Interface()
}

// corpusBinary returns the binary encoding of what a decoder stored in p.
func corpusBinary(p interface{}) ([]byte, error) {
	rv := reflect.ValueOf(p)
	if kindOf(rv.Type()) != kindInvalid && rv.Type().Elem().Kind() == reflect.Struct && rv.Type().Elem() != timeType {
		return Encode(p)
	}
	return Encode(rv.Elem().Interface())
}

func TestOpen62541Corpus(t *testing.T) {
	cases := corpusCases()
	if cmd := os.Getenv("OPEN62541_UACODEC"); cmd != "" {
		regenerateCorpus(t, cmd, cases)
	}

	raw, err := os.ReadFile(corpusFile)
	if err != nil {
		t.Fatal(err)
	}
	var entries []corpusEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatal(err)
	}
	byName := map[string]corpusEntry{}
	for _, e := range entries {
		byName[e.Name] = e
	}
	if len(entries) != len(cases) {
		t.Fatalf("corpus has %d entries for %d cases: regenerate it (see the comment at the top of this file)", len(entries), len(cases))
	}

	check := func(t *testing.T, key string, ok bool, detail string) {
		t.Helper()
		reason, expected := corpusDivergence(key)
		switch {
		case ok && expected:
			t.Errorf("%s: listed as a divergence (%s) but the stacks agree; remove it from corpusDivergences", key, reason)
		case !ok && !expected:
			t.Errorf("%s: %s", key, detail)
		}
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			e, ok := byName[c.name]
			if !ok {
				t.Fatalf("not in the corpus: regenerate it")
			}
			bin, err := Encode(c.value)
			if err != nil {
				t.Fatal(err)
			}
			want := hex.EncodeToString(bin)
			if e.Binary != want || e.Type != c.typ {
				t.Fatalf("corpus is stale: regenerate it\n corpus: %s\n case:   %s", e.Binary, want)
			}

			// go-opcua must decode what open62541 encoded.
			decode := func(dir, doc string, fn func([]byte, interface{}, ...CodecOption) error) {
				if strings.HasPrefix(doc, "ERR ") {
					check(t, c.name+"/"+dir, false, "open62541 cannot encode this value: "+doc)
					return
				}
				p := corpusTarget(c.value)
				if err := fn([]byte(doc), p); err != nil {
					check(t, c.name+"/"+dir, false, fmt.Sprintf("decode %s: %v", doc, err))
					return
				}
				got, err := corpusBinary(p)
				if err != nil {
					t.Fatal(err)
				}
				check(t, c.name+"/"+dir, hex.EncodeToString(got) == want,
					fmt.Sprintf("decoded a different value from %s\n want %s\n got  %x", doc, want, got))
			}
			decode("o2g-json", e.JSON, DecodeJSON)
			decode("o2g-xml", e.XML, DecodeXML)

			// The documents open62541 was given are still what we emit...
			goJSON, err := EncodeJSON(c.value)
			if err != nil {
				t.Fatal(err)
			}
			goXML, err := EncodeXML(c.value)
			if err != nil {
				t.Fatal(err)
			}
			if string(goJSON) != e.GoJSON || string(goXML) != e.GoXML {
				t.Fatalf("the encoders changed their output: regenerate the corpus\n json: %s\n was:  %s\n xml:  %s\n was:  %s", goJSON, e.GoJSON, goXML, e.GoXML)
			}
			// ...and open62541 decoded them to the same value.
			check(t, c.name+"/g2o-json", e.GoJSONDecoded == want, fmt.Sprintf("open62541 decoded %s to %s, want %s", e.GoJSON, e.GoJSONDecoded, want))
			check(t, c.name+"/g2o-xml", e.GoXMLDecoded == want, fmt.Sprintf("open62541 decoded %s to %s, want %s", e.GoXML, e.GoXMLDecoded, want))
		})
	}
}

// regenerateCorpus drives the uacodec helper (testdata/open62541) and
// rewrites the corpus file.
func regenerateCorpus(t *testing.T, command string, cases []corpusCase) {
	t.Helper()
	var in bytes.Buffer
	entries := make([]corpusEntry, len(cases))
	for i, c := range cases {
		bin, err := Encode(c.value)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		goJSON, err := EncodeJSON(c.value)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		goXML, err := EncodeXML(c.value)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		entries[i] = corpusEntry{Name: c.name, Type: c.typ, Binary: hex.EncodeToString(bin), GoJSON: string(goJSON), GoXML: string(goXML)}
		fmt.Fprintf(&in, "enc json %s %x\n", c.typ, bin)
		fmt.Fprintf(&in, "enc xml %s %x\n", c.typ, bin)
		fmt.Fprintf(&in, "dec json %s %x\n", c.typ, goJSON)
		fmt.Fprintf(&in, "dec xml %s %x\n", c.typ, goXML)
	}
	args := strings.Fields(command)
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = &in
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s: %v", command, err)
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	next := func(text bool) string {
		if !sc.Scan() {
			t.Fatalf("uacodec returned too few lines")
		}
		line := sc.Text()
		if !strings.HasPrefix(line, "OK") {
			return line // "ERR <status>"
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "OK"))
		if !text {
			return payload
		}
		doc, err := hex.DecodeString(payload)
		if err != nil {
			t.Fatal(err)
		}
		return string(doc)
	}
	for i := range entries {
		entries[i].JSON = next(true)
		entries[i].XML = next(true)
		entries[i].GoJSONDecoded = next(false)
		entries[i].GoXMLDecoded = next(false)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	if err := enc.Encode(entries); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(corpusFile, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s (%d cases)", corpusFile, len(entries))
}
