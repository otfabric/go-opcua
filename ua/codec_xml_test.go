// SPDX-License-Identifier: MIT

package ua

import (
	"bytes"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/internal/schema"
	"github.com/stretchr/testify/require"
)

const xmlnsAttr = ` xmlns="http://opcfoundation.org/UA/2008/02/Types.xsd"`

// TestXMLEncode pins the exact output for every built-in type. The element
// and child names are those of Part 6 §5.3 / Opc.Ua.Types.xsd.
func TestXMLEncode(t *testing.T) {
	ts := mustTime("2024-02-29T12:34:56.7890123Z")
	guid := NewGUID("C496578A-0DFE-4B8F-870A-745238C6AEAE")
	xmlEl := XMLElement(`<a x="1">t</a>`)
	dv := &DataValue{Value: MustVariant(int32(5)), Status: StatusBadNodeIDUnknown, SourceTimestamp: ts, SourcePicoseconds: 3, ServerTimestamp: ts, ServerPicoseconds: 4}
	dv.UpdateMask()

	tests := []struct {
		name string
		v    interface{}
		want string // without the xmlns declaration of the root element
		opts []CodecOption
	}{
		{"Boolean", true, `<Boolean>true</Boolean>`, nil},
		{"SByte", int8(-1), `<SByte>-1</SByte>`, nil},
		{"Byte", uint8(255), `<Byte>255</Byte>`, nil},
		{"Int64", int64(math.MinInt64), `<Int64>-9223372036854775808</Int64>`, nil},
		{"UInt64", uint64(math.MaxUint64), `<UInt64>18446744073709551615</UInt64>`, nil},
		{"Float", float32(1.5), `<Float>1.5</Float>`, nil},
		{"Double NaN", math.NaN(), `<Double>NaN</Double>`, nil},
		{"Double INF", math.Inf(1), `<Double>INF</Double>`, nil},
		{"Double -INF", math.Inf(-1), `<Double>-INF</Double>`, nil},
		{"String", "a<b>&\"'\r\n", `<String>a&lt;b&gt;&amp;&#34;&#39;&#xD;&#xA;</String>`, nil},
		{"DateTime", ts, `<DateTime>2024-02-29T12:34:56.7890123Z</DateTime>`, nil},
		{"DateTime null", time.Time{}, `<DateTime>1601-01-01T00:00:00Z</DateTime>`, nil},
		{"Guid", guid, `<Guid><String>C496578A-0DFE-4B8F-870A-745238C6AEAE</String></Guid>`, nil},
		{"Guid nil", (*GUID)(nil), `<Guid><String>00000000-0000-0000-0000-000000000000</String></Guid>`, nil},
		{"ByteString", []byte("asdfasdf"), `<ByteString>YXNkZmFzZGY=</ByteString>`, nil},
		{"ByteString empty", []byte{}, `<ByteString></ByteString>`, nil},
		{"XmlElement", xmlEl, `<XmlElement><a x="1">t</a></XmlElement>`, nil},
		{"XmlElement pointer", &xmlEl, `<XmlElement><a x="1">t</a></XmlElement>`, nil},
		{"NodeId", NewStringNodeID(1, "a<b"), `<NodeId><Identifier>ns=1;s=a&lt;b</Identifier></NodeId>`, nil},
		{"NodeId nil", (*NodeID)(nil), `<NodeId></NodeId>`, nil},
		{"ExpandedNodeId", NewExpandedNodeID(NewTwoByteNodeID(7), "urn:x", 2), `<ExpandedNodeId><Identifier>svr=2;nsu=urn:x;i=7</Identifier></ExpandedNodeId>`, nil},
		{"StatusCode", StatusBadNodeIDUnknown, `<StatusCode><Code>2150891520</Code></StatusCode>`, nil},
		{"QualifiedName", &QualifiedName{NamespaceIndex: 2, Name: "n"}, `<QualifiedName><NamespaceIndex>2</NamespaceIndex><Name>n</Name></QualifiedName>`, nil},
		{"LocalizedText", NewLocalizedTextWithLocale("t", "en"), `<LocalizedText><Locale>en</Locale><Text>t</Text></LocalizedText>`, nil},
		{"LocalizedText empty", &LocalizedText{}, `<LocalizedText></LocalizedText>`, nil},
		{"ExtensionObject null", NewExtensionObject(nil), `<ExtensionObject></ExtensionObject>`, nil},
		{"ExtensionObject structure", NewExtensionObject(&Range{Low: 1, High: 2}),
			`<ExtensionObject><TypeId><Identifier>i=885</Identifier></TypeId><Body><Range><Low>1</Low><High>2</High></Range></Body></ExtensionObject>`, nil},
		{"ExtensionObject XML body", &ExtensionObject{EncodingMask: ExtensionObjectXML, TypeID: NewFourByteExpandedNodeID(2, 1234), Value: &xmlEl},
			`<ExtensionObject><TypeId><Identifier>ns=2;i=1234</Identifier></TypeId><Body><a x="1">t</a></Body></ExtensionObject>`, nil},
		{"ExtensionObject XML body by value", &ExtensionObject{EncodingMask: ExtensionObjectXML, TypeID: NewFourByteExpandedNodeID(2, 1234), Value: xmlEl},
			`<ExtensionObject><TypeId><Identifier>ns=2;i=1234</Identifier></TypeId><Body><a x="1">t</a></Body></ExtensionObject>`, nil},
		{"ExtensionObject binary body", &ExtensionObject{EncodingMask: ExtensionObjectBinary, TypeID: NewFourByteExpandedNodeID(2, 1234), Value: []byte{1, 2, 3}},
			`<ExtensionObject><TypeId><Identifier>ns=2;i=1234</Identifier></TypeId><Body><ByteString>AQID</ByteString></Body></ExtensionObject>`, nil},
		{"DataValue", dv, `<DataValue><Value><Value><Int32>5</Int32></Value></Value><StatusCode><Code>2150891520</Code></StatusCode>` +
			`<SourceTimestamp>2024-02-29T12:34:56.7890123Z</SourceTimestamp><SourcePicoseconds>3</SourcePicoseconds>` +
			`<ServerTimestamp>2024-02-29T12:34:56.7890123Z</ServerTimestamp><ServerPicoseconds>4</ServerPicoseconds></DataValue>`, nil},
		{"Variant null", &Variant{}, `<Variant></Variant>`, nil},
		{"Variant scalar", MustVariant(int32(42)), `<Variant><Value><Int32>42</Int32></Value></Variant>`, nil},
		{"Variant array", MustVariant([]string{"a", "b"}), `<Variant><Value><ListOfString><String>a</String><String>b</String></ListOfString></Value></Variant>`, nil},
		{"Variant byte array", MustVariant(ByteArray{1, 2}), `<Variant><Value><ListOfByte><Byte>1</Byte><Byte>2</Byte></ListOfByte></Value></Variant>`, nil},
		{"Variant matrix", MustVariant([][]int32{{1, 2}, {3, 4}}),
			`<Variant><Value><Matrix><Dimensions><Int32>2</Int32><Int32>2</Int32></Dimensions><Elements><Int32>1</Int32><Int32>2</Int32><Int32>3</Int32><Int32>4</Int32></Elements></Matrix></Value></Variant>`, nil},
		{"DiagnosticInfo", &DiagnosticInfo{EncodingMask: 0x7f, SymbolicID: 1, NamespaceURI: 2, Locale: 3, LocalizedText: 4, AdditionalInfo: "i", InnerStatusCode: StatusBadInternalError,
			InnerDiagnosticInfo: &DiagnosticInfo{EncodingMask: DiagnosticInfoAdditionalInfo, AdditionalInfo: "j"}},
			`<DiagnosticInfo><SymbolicId>1</SymbolicId><NamespaceUri>2</NamespaceUri><Locale>3</Locale><LocalizedText>4</LocalizedText><AdditionalInfo>i</AdditionalInfo>` +
				`<InnerStatusCode><Code>2147614720</Code></InnerStatusCode><InnerDiagnosticInfo><AdditionalInfo>j</AdditionalInfo></InnerDiagnosticInfo></DiagnosticInfo>`, nil},
		{"Enumeration", MessageSecurityModeSignAndEncrypt, `<MessageSecurityMode>SignAndEncrypt_3</MessageSecurityMode>`, nil},
		{"Enumeration unknown value", MessageSecurityMode(77), `<MessageSecurityMode>77</MessageSecurityMode>`, nil},
		{"OptionSet", AccessLevelTypeCurrentRead | AccessLevelTypeCurrentWrite, `<AccessLevelType>3</AccessLevelType>`, nil},
		{"Structure", &Argument{Name: "n", DataType: NewTwoByteNodeID(6), ValueRank: 1, ArrayDimensions: []uint32{3}, Description: NewLocalizedText("d")},
			`<Argument><Name>n</Name><DataType><Identifier>i=6</Identifier></DataType><ValueRank>1</ValueRank><ArrayDimensions><UInt32>3</UInt32></ArrayDimensions><Description><Text>d</Text></Description></Argument>`, nil},
		{"Structure with null fields", &Argument{Name: "n"}, `<Argument><Name>n</Name><ValueRank>0</ValueRank></Argument>`, nil},
		{"Structure nil", (*Range)(nil), `<Range></Range>`, nil},
		{"Structure array field", &ApplicationDescription{DiscoveryURLs: []string{"a", "b"}, ApplicationType: ApplicationTypeClient},
			`<ApplicationDescription><ApplicationUri></ApplicationUri><ProductUri></ProductUri><ApplicationType>Client_1</ApplicationType>` +
				`<GatewayServerUri></GatewayServerUri><DiscoveryProfileUri></DiscoveryProfileUri><DiscoveryUrls><String>a</String><String>b</String></DiscoveryUrls></ApplicationDescription>`, nil},
		{"Array", []*Range{{Low: 1}, nil}, `<ListOfRange><Range><Low>1</Low><High>0</High></Range><Range></Range></ListOfRange>`, nil},
		{"root name", int32(1), `<Value>1</Value>`, []CodecOption{WithXMLRootName("Value")}},
		{"nil", nil, `<Null></Null>`, nil},
		{"namespace table", NewFourByteNodeID(2, 7), `<NodeId><Identifier>nsu=urn:two;i=7</Identifier></NodeId>`,
			[]CodecOption{WithNamespaceArray([]string{"", "urn:one", "urn:two"})}},
		{"server table", NewExpandedNodeID(NewTwoByteNodeID(7), "", 1), `<ExpandedNodeId><Identifier>svu=urn:remote;i=7</Identifier></ExpandedNodeId>`,
			[]CodecOption{WithServerArray([]string{"urn:local", "urn:remote"})}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeXML(tt.v, append([]CodecOption{WithoutXMLNamespace()}, tt.opts...)...)
			require.NoError(t, err)
			require.Equal(t, tt.want, string(got))

			// With the namespace declaration the document is otherwise the
			// same; only the content of an XmlElement is kept out of the
			// default namespace (see TestXMLElementNamespace).
			got, err = EncodeXML(tt.v, tt.opts...)
			require.NoError(t, err)
			i := strings.IndexByte(tt.want, '>')
			want := tt.want[:i] + xmlnsAttr + tt.want[i:]
			if strings.HasPrefix(tt.name, "XmlElement") {
				want = strings.Replace(want, `<a x="1">`, `<a xmlns="" x="1">`, 1)
			}
			require.Equal(t, want, string(got))
		})
	}

	t.Run("xsi:nil", func(t *testing.T) {
		got, err := EncodeXML(MustVariant([]int32(nil)))
		require.NoError(t, err)
		require.Equal(t, `<Variant`+xmlnsAttr+` xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><Value><ListOfInt32 xsi:nil="true"></ListOfInt32></Value></Variant>`, string(got))
		got, err = EncodeXML([]byte(nil), WithoutXMLNamespace())
		require.NoError(t, err)
		require.Equal(t, `<ByteString xsi:nil="true" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"></ByteString>`, string(got))
		got, err = EncodeXML([]int32(nil), WithoutXMLNamespace())
		require.NoError(t, err)
		require.Equal(t, `<ListOfInt32 xsi:nil="true" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"></ListOfInt32>`, string(got))
	})
	t.Run("indent", func(t *testing.T) {
		got, err := EncodeXML(MustVariant([]int32{1, 2}), WithIndent("  "), WithoutXMLNamespace())
		require.NoError(t, err)
		require.Equal(t, "<Variant>\n  <Value>\n    <ListOfInt32>\n      <Int32>1</Int32>\n      <Int32>2</Int32>\n    </ListOfInt32>\n  </Value>\n</Variant>", string(got))
		var v Variant
		require.NoError(t, DecodeXML(got, &v))
		require.Equal(t, []int32{1, 2}, v.Value())
	})
	t.Run("unsupported value", func(t *testing.T) {
		_, err := EncodeXML(make(chan int))
		require.ErrorIs(t, err, StatusBadEncodingError)
		_, err = EncodeXML(MustVariant([]*Variant{MustVariant([]*Variant{MustVariant(int32(1))})}), WithMaxDepth(3))
		require.ErrorIs(t, err, StatusBadEncodingLimitsExceeded)
	})
	t.Run("pointers are followed", func(t *testing.T) {
		n := int32(7)
		p := &n
		got, err := EncodeXML(&p, WithoutXMLNamespace(), WithXMLRootName("V"))
		require.NoError(t, err)
		require.Equal(t, "<V>7</V>", string(got))
		var nilp *int32
		got, err = EncodeXML(&nilp, WithoutXMLNamespace(), WithXMLRootName("V"))
		require.NoError(t, err)
		require.Equal(t, "<V></V>", string(got))
	})
}

// TestXMLDecode covers what other producers write: namespace prefixes, the
// bare NodeSet2 <Value> form, pretty printing, CDATA and character
// references.
func TestXMLDecode(t *testing.T) {
	guid := NewGUID("00000001-0002-0003-0405-060708090A0B")
	body := XMLElement(`<x:Unknown xmlns:x="urn:x"><x:A>1</x:A></x:Unknown>`)
	tests := []struct {
		name string
		doc  string
		want interface{}
	}{
		// The form of NodeSet2 files (Part 6 Annex F): the <Value> element
		// of a UAVariable holds the typed element directly.
		{"NodeSet value with prefix", `<Value><uax:Int32 xmlns:uax="http://opcfoundation.org/UA/2008/02/Types.xsd">42</uax:Int32></Value>`, MustVariant(int32(42))},
		{"NodeSet value with default namespace", `<Value><String xmlns="http://opcfoundation.org/UA/2008/02/Types.xsd">http://opcfoundation.org/UA/</String></Value>`, MustVariant("http://opcfoundation.org/UA/")},
		{"NodeSet list", `<Value><uax:ListOfLocalizedText xmlns:uax="x"><uax:LocalizedText><uax:Text>A</uax:Text></uax:LocalizedText><uax:LocalizedText><uax:Locale>en</uax:Locale><uax:Text>B</uax:Text></uax:LocalizedText></uax:ListOfLocalizedText></Value>`,
			MustVariant([]*LocalizedText{NewLocalizedText("A"), NewLocalizedTextWithLocale("B", "en")})},
		// Taken from the EnumValues property of NamingRuleType in
		// Opc.Ua.NodeSet2.xml (schema/, i=12169).
		{"NodeSet extension objects", `<Value>
      <ListOfExtensionObject xmlns="http://opcfoundation.org/UA/2008/02/Types.xsd">
        <ExtensionObject>
          <TypeId>
            <Identifier>i=7616</Identifier>
          </TypeId>
          <Body>
            <EnumValueType>
              <Value>1</Value>
              <DisplayName>
                <Text>Mandatory</Text>
              </DisplayName>
              <Description>
                <Text>The BrowseName must appear in all instances of the type.</Text>
              </Description>
            </EnumValueType>
          </Body>
        </ExtensionObject>
      </ListOfExtensionObject>
    </Value>`, MustVariant([]*ExtensionObject{NewExtensionObject(&EnumValueType{Value: 1, DisplayName: NewLocalizedText("Mandatory"),
			Description: NewLocalizedText("The BrowseName must appear in all instances of the type.")})})},
		{"empty NodeSet value", `<Value/>`, &Variant{}},

		// The form EncodeXML and open62541 write.
		{"Variant wrapper", `<Variant><Value><Int32>42</Int32></Value></Variant>`, MustVariant(int32(42))},
		{"Variant empty", `<Variant></Variant>`, &Variant{}},
		{"Variant empty value", `<Variant><Value/></Variant>`, &Variant{}},
		{"Variant null array", `<Variant><Value><ListOfInt32 xsi:nil="true" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/></Value></Variant>`, MustVariant([]int32(nil))},
		{"Variant empty array", `<Variant><Value><ListOfInt32/></Value></Variant>`, MustVariant([]int32{})},
		{"Variant matrix", `<Variant><Value><Matrix><Dimensions><Int32>2</Int32><Int32>1</Int32></Dimensions><Elements><Int32>5</Int32><Int32>6</Int32></Elements></Matrix></Value></Variant>`, MustVariant([][]int32{{5}, {6}})},
		{"Variant byte array", `<Variant><Value><ListOfByte><Byte>1</Byte><Byte>2</Byte></ListOfByte></Value></Variant>`, MustVariant(ByteArray{1, 2})},
		{"Variant null element", `<Variant><Value><ListOfByteString><ByteString xsi:nil="true" xmlns:xsi="x"/><ByteString>AQ==</ByteString></ListOfByteString></Value></Variant>`, MustVariant([][]byte{nil, {1}})},
		{"Variant of Variants", `<Variant><Value><ListOfVariant><Variant><Value><Boolean>1</Boolean></Value></Variant><Variant/></ListOfVariant></Value></Variant>`, MustVariant([]*Variant{MustVariant(true), {}})},
		// open62541 also accepts a structure under its own name.
		{"Variant of bare structure", `<Variant><Value><Range><Low>1</Low><High>2</High></Range></Value></Variant>`, MustVariant(NewExtensionObject(&Range{Low: 1, High: 2}))},
		{"Variant of bare structures", `<Variant><Value><ListOfRange><Range><Low>1</Low><High>2</High></Range></ListOfRange></Value></Variant>`, MustVariant([]*ExtensionObject{NewExtensionObject(&Range{Low: 1, High: 2})})},

		{"Boolean numeric", `<Boolean> 0 </Boolean>`, false},
		{"Int32 with whitespace", "<Int32>\n  -5\n</Int32>", int32(-5)},
		{"Float INF", `<Float>INF</Float>`, float32(math.Inf(1))},
		{"Double NaN", `<Double>NaN</Double>`, math.NaN()},
		{"String with references", `<String>a&lt;b&#x41;&#65;&amp;</String>`, "a<bAA&"},
		{"String CDATA", `<String><![CDATA[<raw> & text]]></String>`, "<raw> & text"},
		{"String keeps whitespace", `<String> a b </String>`, " a b "},
		{"String with comment", `<String>a<!-- c -->b</String>`, "ab"},
		{"DateTime without zone", `<DateTime>2024-02-29T12:34:56</DateTime>`, mustTime("2024-02-29T12:34:56Z")},
		{"DateTime null literal", `<DateTime>0001-01-01T00:00:00Z</DateTime>`, time.Time{}},
		{"Guid", `<Guid><String>00000001-0002-0003-0405-060708090a0b</String></Guid>`, guid},
		{"Guid as text", `<Guid>00000001-0002-0003-0405-060708090A0B</Guid>`, guid},
		{"Guid empty", `<Guid/>`, zeroGUID()},
		{"ByteString with line breaks", "<ByteString>YXNk\n  ZmFzZGY=\n</ByteString>", []byte("asdfasdf")},
		{"ByteString empty", `<ByteString/>`, []byte{}},
		{"ByteString nil", `<ByteString xsi:nil="true" xmlns:xsi="x"/>`, []byte(nil)},
		{"XmlElement", `<XmlElement><a x="1"><b>t &amp; u</b></a></XmlElement>`, XMLElement(`<a x="1"><b>t &amp; u</b></a>`)},
		{"NodeId", `<NodeId><Identifier>ns=1;s=Line 1;Tank=5</Identifier></NodeId>`, NewStringNodeID(1, "Line 1;Tank=5")},
		{"NodeId pretty printed", "<NodeId>\n  <Identifier>\n    i=85\n  </Identifier>\n</NodeId>", NewTwoByteNodeID(85)},
		{"NodeId empty", `<NodeId/>`, NewTwoByteNodeID(0)},
		{"NodeId not mappable", `<NodeId><Identifier>nsu=urn:nope;i=1</Identifier></NodeId>`, NewStringNodeID(0, "nsu=urn:nope;i=1")},
		{"ExpandedNodeId", `<ExpandedNodeId><Identifier>svr=2;nsu=urn:x;i=7</Identifier></ExpandedNodeId>`, NewExpandedNodeID(NewTwoByteNodeID(7), "urn:x", 2)},
		{"ExpandedNodeId not a NodeId", `<ExpandedNodeId><Identifier>hello</Identifier></ExpandedNodeId>`, &ExpandedNodeID{NodeID: NewStringNodeID(0, "hello")}},
		{"ExpandedNodeId empty", `<ExpandedNodeId/>`, NewTwoByteExpandedNodeID(0)},
		{"StatusCode", `<StatusCode><Code>2150891520</Code></StatusCode>`, StatusBadNodeIDUnknown},
		{"StatusCode empty", `<StatusCode/>`, StatusOK},
		{"QualifiedName", `<QualifiedName><NamespaceIndex>2</NamespaceIndex><Name>n</Name></QualifiedName>`, &QualifiedName{NamespaceIndex: 2, Name: "n"}},
		{"QualifiedName fields in any order", `<QualifiedName><Name>n</Name><NamespaceIndex>2</NamespaceIndex></QualifiedName>`, &QualifiedName{NamespaceIndex: 2, Name: "n"}},
		{"LocalizedText", `<LocalizedText><Locale>en</Locale><Text>t</Text></LocalizedText>`, NewLocalizedTextWithLocale("t", "en")},
		{"ExtensionObject", `<ExtensionObject><TypeId><Identifier>i=885</Identifier></TypeId><Body><Range><Low>1</Low><High>2</High></Range></Body></ExtensionObject>`, NewExtensionObject(&Range{Low: 1, High: 2})},
		{"ExtensionObject by DataType id", `<ExtensionObject><TypeId><Identifier>i=884</Identifier></TypeId><Body><Range><Low>1</Low><High>2</High></Range></Body></ExtensionObject>`, NewExtensionObject(&Range{Low: 1, High: 2})},
		{"ExtensionObject binary body", `<ExtensionObject><TypeId><Identifier>i=886</Identifier></TypeId><Body><ByteString>AAAAAAAA8D8AAAAAAAAAQA==</ByteString></Body></ExtensionObject>`, NewExtensionObject(&Range{Low: 1, High: 2})},
		{"ExtensionObject binary body of unknown type", `<ExtensionObject><TypeId><Identifier>i=42</Identifier></TypeId><Body><ByteString>AQID</ByteString></Body></ExtensionObject>`,
			&ExtensionObject{EncodingMask: ExtensionObjectBinary, TypeID: NewTwoByteExpandedNodeID(42), Value: []byte{1, 2, 3}}},
		{"ExtensionObject of unknown type", `<ExtensionObject><TypeId><Identifier>ns=2;i=4711</Identifier></TypeId><Body><x:Unknown xmlns:x="urn:x"><x:A>1</x:A></x:Unknown></Body></ExtensionObject>`,
			&ExtensionObject{EncodingMask: ExtensionObjectXML, TypeID: NewFourByteExpandedNodeID(2, 4711), Value: &body}},
		{"ExtensionObject without body", `<ExtensionObject><TypeId><Identifier>i=885</Identifier></TypeId></ExtensionObject>`, NewExtensionObject(nil)},
		{"DataValue", `<DataValue><Value><Value><Int32>5</Int32></Value></Value><StatusCode><Code>2150891520</Code></StatusCode><SourceTimestamp>2024-02-29T12:34:56Z</SourceTimestamp><SourcePicoseconds>3</SourcePicoseconds><ServerTimestamp>2024-02-29T12:34:57Z</ServerTimestamp><ServerPicoseconds>4</ServerPicoseconds></DataValue>`,
			&DataValue{EncodingMask: 0x3f, Value: MustVariant(int32(5)), Status: StatusBadNodeIDUnknown, SourceTimestamp: mustTime("2024-02-29T12:34:56Z"), SourcePicoseconds: 3, ServerTimestamp: mustTime("2024-02-29T12:34:57Z"), ServerPicoseconds: 4}},
		{"DataValue empty", `<DataValue/>`, &DataValue{}},
		{"DataValue null value", `<DataValue><Value/></DataValue>`, &DataValue{}},
		{"DiagnosticInfo", `<DiagnosticInfo><SymbolicId>1</SymbolicId><NamespaceUri>2</NamespaceUri><Locale>3</Locale><LocalizedText>4</LocalizedText><AdditionalInfo>i</AdditionalInfo><InnerStatusCode><Code>2147614720</Code></InnerStatusCode><InnerDiagnosticInfo><AdditionalInfo>j</AdditionalInfo></InnerDiagnosticInfo></DiagnosticInfo>`,
			&DiagnosticInfo{EncodingMask: 0x7f, SymbolicID: 1, NamespaceURI: 2, Locale: 3, LocalizedText: 4, AdditionalInfo: "i", InnerStatusCode: StatusBadInternalError,
				InnerDiagnosticInfo: &DiagnosticInfo{EncodingMask: DiagnosticInfoAdditionalInfo, AdditionalInfo: "j"}}},
		{"Enumeration", `<MessageSecurityMode>SignAndEncrypt_3</MessageSecurityMode>`, MessageSecurityModeSignAndEncrypt},
		// open62541 reads and writes enumerations as numbers.
		{"Enumeration number", `<MessageSecurityMode>3</MessageSecurityMode>`, MessageSecurityModeSignAndEncrypt},
		{"Enumeration name", `<MessageSecurityMode>SignAndEncrypt</MessageSecurityMode>`, MessageSecurityModeSignAndEncrypt},
		{"Structure", `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE Argument><Argument><Unknown><X/></Unknown><Name>n</Name><ArrayDimensions><UInt32>3</UInt32></ArrayDimensions></Argument>`,
			&Argument{Name: "n", ArrayDimensions: []uint32{3}}},
		{"Structure null array", `<Argument><ArrayDimensions xsi:nil="true" xmlns:xsi="x"/></Argument>`, &Argument{}},
		{"Structure null nested", `<ReadRequest><RequestHeader xsi:nil="true" xmlns:xsi="x"/><MaxAge>1</MaxAge></ReadRequest>`, &ReadRequest{MaxAge: 1}},
		{"Array", `<ListOfRange><Range><Low>1</Low></Range><Range/></ListOfRange>`, []*Range{{Low: 1}, {}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := corpusTarget(tt.want)
			require.NoError(t, DecodeXML([]byte(tt.doc), p))
			got, err := corpusBinary(p)
			require.NoError(t, err)
			require.Equal(t, binOf(t, tt.want), hex.EncodeToString(got), "decoded %#v", reflect.ValueOf(p).Elem().Interface())
		})
	}

	t.Run("namespace tables", func(t *testing.T) {
		opts := []CodecOption{WithNamespaceArray([]string{"", "urn:one", "urn:two"}), WithServerArray([]string{"urn:local", "urn:remote"})}
		var n NodeID
		require.NoError(t, DecodeXML([]byte(`<NodeId><Identifier>nsu=urn:two;i=7</Identifier></NodeId>`), &n, opts...))
		require.Equal(t, "ns=2;i=7", n.String())
		var e ExpandedNodeID
		require.NoError(t, DecodeXML([]byte(`<ExpandedNodeId><Identifier>svu=urn:remote;nsu=urn:one;i=7</Identifier></ExpandedNodeId>`), &e, opts...))
		require.Equal(t, uint32(1), e.ServerIndex)
		require.Equal(t, uint16(1), e.NodeID.Namespace())
	})
	t.Run("pointer targets", func(t *testing.T) {
		var x *XMLElement
		require.NoError(t, DecodeXML([]byte(`<XmlElement><a/></XmlElement>`), &x))
		require.Equal(t, XMLElement("<a/>"), *x)
		var r *Range
		require.NoError(t, DecodeXML([]byte(`<Range xsi:nil="true" xmlns:xsi="x"/>`), &r))
		require.Nil(t, r)
	})
}

func TestXMLDecodeErrors(t *testing.T) {
	tests := []struct {
		name   string
		doc    string
		target interface{}
		code   StatusCode
	}{
		{"empty input", ``, new(int32), StatusBadDecodingError},
		{"not XML", `hello`, new(int32), StatusBadDecodingError},
		{"unclosed element", `<Int32>1`, new(int32), StatusBadDecodingError},
		{"mismatched element", `<Int32>1</Int16>`, new(int32), StatusBadDecodingError},
		{"two roots", `<Int32>1</Int32><Int32>2</Int32>`, new(int32), StatusBadDecodingError},
		{"undefined entity", `<String>&nope;</String>`, new(string), StatusBadDecodingError},
		{"entity declared in a DTD", `<!DOCTYPE s [<!ENTITY a "aaaa">]><String>&a;</String>`, new(string), StatusBadDecodingError},
		{"other charset", `<?xml version="1.0" encoding="ISO-8859-1"?><String>a</String>`, new(string), StatusBadDecodingError},
		{"nesting too deep", strings.Repeat("<a>", 200) + strings.Repeat("</a>", 200), new(Variant), StatusBadEncodingLimitsExceeded},

		{"Boolean", `<Boolean>yes</Boolean>`, new(bool), StatusBadDecodingError},
		{"Byte out of range", `<Byte>256</Byte>`, new(uint8), StatusBadDecodingError},
		{"Int32 empty", `<Int32/>`, new(int32), StatusBadDecodingError},
		{"UInt32 negative", `<UInt32>-1</UInt32>`, new(uint32), StatusBadDecodingError},
		{"Float", `<Float>fast</Float>`, new(float32), StatusBadDecodingError},
		{"DateTime", `<DateTime>yesterday</DateTime>`, new(time.Time), StatusBadDecodingError},
		{"ByteString", `<ByteString>@@</ByteString>`, new([]byte), StatusBadDecodingError},
		{"Guid", `<Guid><String>x</String></Guid>`, new(GUID), StatusBadDecodingError},
		{"Guid as text", `<Guid>x</Guid>`, new(GUID), StatusBadDecodingError},
		{"StatusCode", `<StatusCode><Code>x</Code></StatusCode>`, new(StatusCode), StatusBadDecodingError},
		{"QualifiedName", `<QualifiedName><NamespaceIndex>70000</NamespaceIndex></QualifiedName>`, new(QualifiedName), StatusBadDecodingError},
		{"ExtensionObject two bodies", `<ExtensionObject><Body><a/><b/></Body></ExtensionObject>`, new(ExtensionObject), StatusBadDecodingError},
		{"ExtensionObject bad binary body", `<ExtensionObject><Body><ByteString>@</ByteString></Body></ExtensionObject>`, new(ExtensionObject), StatusBadDecodingError},
		{"ExtensionObject bad field", `<ExtensionObject><TypeId><Identifier>i=885</Identifier></TypeId><Body><Range><Low>x</Low></Range></Body></ExtensionObject>`, new(ExtensionObject), StatusBadDecodingError},
		{"DataValue bad value", `<DataValue><Value><Value><Int32>x</Int32></Value></Value></DataValue>`, new(DataValue), StatusBadDecodingError},
		{"DataValue bad status", `<DataValue><StatusCode><Code>x</Code></StatusCode></DataValue>`, new(DataValue), StatusBadDecodingError},
		{"DataValue bad timestamp", `<DataValue><SourceTimestamp>x</SourceTimestamp></DataValue>`, new(DataValue), StatusBadDecodingError},
		{"DataValue bad picoseconds", `<DataValue><ServerPicoseconds>x</ServerPicoseconds></DataValue>`, new(DataValue), StatusBadDecodingError},
		{"Variant two values", `<Variant><Value><Int32>1</Int32><Int32>2</Int32></Value></Variant>`, new(Variant), StatusBadDecodingError},
		{"Variant unknown type", `<Variant><Value><Nope>1</Nope></Value></Variant>`, new(Variant), StatusBadDecodingError},
		{"Variant unknown list type", `<Variant><Value><ListOfNope/></Value></Variant>`, new(Variant), StatusBadDecodingError},
		{"Variant bad element", `<Variant><Value><ListOfInt32><Int32>x</Int32></ListOfInt32></Value></Variant>`, new(Variant), StatusBadDecodingError},
		{"Variant bad bare structure", `<Variant><Value><Range><Low>x</Low></Range></Value></Variant>`, new(Variant), StatusBadDecodingError},
		{"Matrix without elements", `<Variant><Value><Matrix><Dimensions><Int32>1</Int32></Dimensions></Matrix></Value></Variant>`, new(Variant), StatusBadDecodingError},
		{"Matrix empty", `<Variant><Value><Matrix><Dimensions><Int32>1</Int32></Dimensions><Elements/></Matrix></Value></Variant>`, new(Variant), StatusBadDecodingError},
		{"Matrix bad dimension", `<Variant><Value><Matrix><Dimensions><Int32>x</Int32></Dimensions><Elements><Int32>1</Int32></Elements></Matrix></Value></Variant>`, new(Variant), StatusBadDecodingError},
		{"Matrix dimension mismatch", `<Variant><Value><Matrix><Dimensions><Int32>2</Int32><Int32>2</Int32></Dimensions><Elements><Int32>1</Int32></Elements></Matrix></Value></Variant>`, new(Variant), StatusBadDecodingError},
		{"Matrix unknown type", `<Variant><Value><Matrix><Dimensions><Int32>1</Int32></Dimensions><Elements><Nope/></Elements></Matrix></Value></Variant>`, new(Variant), StatusBadDecodingError},
		{"Variant array too long", `<Variant><Value><ListOfBoolean>` + strings.Repeat("<Boolean>1</Boolean>", 4) + `</ListOfBoolean></Value></Variant>`, new(Variant), StatusBadEncodingLimitsExceeded},
		{"DiagnosticInfo bad index", `<DiagnosticInfo><SymbolicId>x</SymbolicId></DiagnosticInfo>`, new(DiagnosticInfo), StatusBadDecodingError},
		{"DiagnosticInfo bad status", `<DiagnosticInfo><InnerStatusCode><Code>x</Code></InnerStatusCode></DiagnosticInfo>`, new(DiagnosticInfo), StatusBadDecodingError},
		{"DiagnosticInfo bad inner", `<DiagnosticInfo><InnerDiagnosticInfo><Locale>x</Locale></InnerDiagnosticInfo></DiagnosticInfo>`, new(DiagnosticInfo), StatusBadDecodingError},
		{"Enumeration", `<MessageSecurityMode>Nope</MessageSecurityMode>`, new(MessageSecurityMode), StatusBadDecodingError},
		{"Enumeration overflow", `<MessageSecurityMode>X_4294967296</MessageSecurityMode>`, new(MessageSecurityMode), StatusBadDecodingError},
		{"Enumeration negative", `<MessageSecurityMode>X_-1</MessageSecurityMode>`, new(MessageSecurityMode), StatusBadDecodingError},
		{"Enumeration signed overflow", `<E>X_4294967296</E>`, new(testSignedEnum), StatusBadDecodingError},
		{"Structure bad field", `<Range><Low>x</Low></Range>`, new(Range), StatusBadDecodingError},
		{"Structure bad nested field", `<ReadRequest><RequestHeader><RequestHandle>x</RequestHandle></RequestHeader></ReadRequest>`, new(ReadRequest), StatusBadDecodingError},
		{"Array bad element", `<ListOfInt32><Int32>x</Int32></ListOfInt32>`, new([]int32), StatusBadDecodingError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var opts []CodecOption
			if tt.name == "Variant array too long" {
				opts = append(opts, WithMaxArrayLength(3))
			}
			err := DecodeXML([]byte(tt.doc), tt.target, opts...)
			require.Error(t, err)
			require.True(t, errors.Is(err, tt.code), "got %v", err)
		})
	}
	t.Run("not a pointer", func(t *testing.T) {
		require.ErrorIs(t, DecodeXML([]byte(`<a/>`), int32(0)), StatusBadDecodingError)
		require.ErrorIs(t, DecodeXML([]byte(`<a/>`), (*int32)(nil)), StatusBadDecodingError)
	})
	t.Run("unsupported target", func(t *testing.T) {
		require.ErrorIs(t, DecodeXML([]byte(`<a/>`), new(chan int)), StatusBadDecodingError)
	})
}

// TestXMLDecodeStandardNodeSet decodes every <Value> of the standard
// Opc.Ua.NodeSet2.xml shipped with the server: 1400+ real-world documents
// written by the OPC Foundation's tooling, covering scalars, arrays and
// arrays of structures (Argument, EnumValueType, ...). Each value must also
// survive a second trip through EncodeXML unchanged.
func TestXMLDecodeStandardNodeSet(t *testing.T) {
	var set struct {
		Variables []struct {
			NodeID string `xml:"NodeId,attr"`
			Value  *struct {
				Inner string `xml:",innerxml"`
			} `xml:"Value"`
		} `xml:"UAVariable"`
	}
	require.NoError(t, xml.Unmarshal(schema.OpcUaNodeSet2, &set))

	n, structures := 0, 0
	for _, v := range set.Variables {
		if v.Value == nil {
			continue
		}
		n++
		doc := "<Value>" + v.Value.Inner + "</Value>"
		var val Variant
		if err := DecodeXML([]byte(doc), &val); err != nil {
			t.Errorf("%s: %v\n%s", v.NodeID, err, doc)
			continue
		}
		if val.Type() == TypeIDNull {
			t.Errorf("%s: decoded to a null Variant\n%s", v.NodeID, doc)
			continue
		}
		if val.Type() == TypeIDExtensionObject {
			structures++
			for _, el := range flattenVariant(reflect.ValueOf(val.Value()), nil) {
				if _, raw := el.Interface().(*ExtensionObject).Value.(*XMLElement); raw {
					t.Errorf("%s: structure of an unregistered type\n%s", v.NodeID, doc)
				}
			}
		}
		again, err := EncodeXML(&val)
		require.NoError(t, err, v.NodeID)
		var val2 Variant
		require.NoError(t, DecodeXML(again, &val2), v.NodeID)
		require.Equal(t, binOf(t, &val), binOf(t, &val2), v.NodeID)
	}
	if n < 1000 || structures < 100 {
		t.Fatalf("decoded only %d values (%d with structures); is the node set embedded?", n, structures)
	}
	t.Logf("decoded %d values, %d of them structures or arrays of structures", n, structures)
}

// TestXMLElementNamespace is the regression test for an interop finding
// (Eclipse Milo): the content of an XmlElement must not inherit the default
// namespace of the OPC UA document it is embedded in.
func TestXMLElementNamespace(t *testing.T) {
	const ns = ` xmlns="` + XMLTypesNamespace + `"`
	cases := []struct {
		name     string
		fragment string
		doc      string // content of <XmlElement> in the document
	}{
		{"unprefixed", `<compat>test</compat>`, `<compat xmlns="">test</compat>`},
		{"attributes and children", `<a x="1"><b>t &amp; u</b></a>`, `<a xmlns="" x="1"><b>t &amp; u</b></a>`},
		{"self closing", `<a/>`, `<a xmlns=""/>`},
		{"two top-level elements", `<a>1</a> <b/>`, `<a xmlns="">1</a> <b xmlns=""/>`},
		{"own default namespace", `<a xmlns="urn:x"><b/></a>`, `<a xmlns="urn:x"><b/></a>`},
		{"prefixed", `<x:a xmlns:x="urn:x"><x:b/></x:a>`, `<x:a xmlns:x="urn:x"><x:b/></x:a>`},
		{"text only", `plain`, `plain`},
		{"empty", ``, ``},
		{"not well-formed", `<a><b></a>`, `<a><b></a>`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := EncodeXML(XMLElement(tc.fragment))
			require.NoError(t, err)
			require.Equal(t, `<XmlElement`+ns+`>`+tc.doc+`</XmlElement>`, string(got))

			// Without the default namespace there is nothing to inherit.
			plain, err := EncodeXML(XMLElement(tc.fragment), WithoutXMLNamespace())
			require.NoError(t, err)
			require.Equal(t, `<XmlElement>`+tc.fragment+`</XmlElement>`, string(plain))

			if tc.name == "not well-formed" {
				return
			}
			var back XMLElement
			require.NoError(t, DecodeXML(got, &back))
			require.Equal(t, XMLElement(tc.fragment), back)
		})
	}

	// A namespace-aware reader sees the element in no namespace.
	doc, err := EncodeXML(MustVariant(XMLElement(`<compat>test</compat>`)))
	require.NoError(t, err)
	dec := xml.NewDecoder(bytes.NewReader(doc))
	found := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == "compat" {
			found = true
			require.Empty(t, se.Name.Space, "the fragment inherited the OPC UA types namespace")
		}
	}
	require.True(t, found)

	// In an array, and decoded from a peer that resets the namespace.
	arr, err := EncodeXML(MustVariant([]XMLElement{`<a/>`, `<b>1</b>`}))
	require.NoError(t, err)
	var v Variant
	require.NoError(t, DecodeXML(arr, &v))
	require.Equal(t, []XMLElement{`<a/>`, `<b>1</b>`}, v.Value())
	var x XMLElement
	require.NoError(t, DecodeXML([]byte(`<XmlElement><a xmlns="">1</a><b xmlns="" y="2"><c xmlns="">3</c></b></XmlElement>`), &x))
	require.Equal(t, XMLElement(`<a>1</a><b y="2"><c xmlns="">3</c></b>`), x, "only top-level resets are removed")
}
