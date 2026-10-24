# JSON and XML Data Encodings

> `ua.EncodeJSON`, `ua.DecodeJSON`, `ua.EncodeXML` and `ua.DecodeXML` in
> `github.com/otfabric/go-opcua/ua`.

---

## What this is, and what it is not

OPC UA defines three *DataEncodings* for the same values (Part 6 §5): UA
Binary, JSON (§5.4) and XML (§5.3). go-opcua speaks UA Binary on the wire and
that does not change: **the transport is OPC UA TCP with the binary encoding
only**. There is no HTTPS/JSON or WebSocket transport.

JSON and XML are available as encodings of *values*, for everything that is
not the wire:

- tooling and logs - print a `DataValue`, a `ReadResponse` or a custom
  structure in a form other OPC UA tools read,
- REST or MQTT gateways and PubSub-style payloads,
- configuration files that hold typed OPC UA values,
- NodeSet2 files, whose `<Value>` elements are the XML encoding (the server's
  `ImportNodeSetXML` uses `ua.DecodeXML` for them).

```go
dv := &ua.DataValue{Value: ua.MustVariant([]float64{1.5, 2.5}), Status: ua.StatusOK}
dv.UpdateMask()

doc, _ := ua.EncodeJSON(dv)
// {"UaType":11,"Value":[1.5,2.5]}

var back ua.DataValue
_ = ua.DecodeJSON(doc, &back)

doc, _ = ua.EncodeXML(dv.Value)
// <Variant xmlns="http://opcfoundation.org/UA/2008/02/Types.xsd"><Value><ListOfDouble><Double>1.5</Double><Double>2.5</Double></ListOfDouble></Value></Variant>
```

Both encoders accept a value of a built-in type (`bool`, `int32`, `string`,
`time.Time`, `[]byte`, `*ua.NodeID`, `*ua.Variant`, `*ua.DataValue`,
`*ua.ExtensionObject`, ...), a pointer to any generated structure
(`*ua.ReadRequest`, `*ua.Argument`, ...) or registered custom structure, an
enumeration, or a slice of these. Both decoders take a non-nil pointer to the
same.

> **Not `encoding/json`.** `json.Marshal(variant)` keeps producing the display
> format of the `MarshalJSON` methods (`{"type":"Int32","value":42}`), which
> predates this feature and is unchanged. The OPC UA encoding is only produced
> by `ua.EncodeJSON`.

## JSON forms

Part 6 changed its JSON encoding in OPC UA 1.05.04. `WithJSONForm` selects
what `EncodeJSON` writes; `DecodeJSON` needs no option and accepts the first
three forms, even mixed in one document.

| Form | Encode | Decode | What it is |
|------|:------:|:------:|------------|
| `ua.JSONCompact` (default) | ✅ | ✅ | 1.05.04 Compact. Structure fields with a default value are omitted, enumerations are numbers, a StatusCode is `{"Code":n}`. **This is what open62541 1.5 reads and writes.** |
| `ua.JSONVerbose` | ✅ | ✅ | 1.05.04 Verbose. All fields are written, enumerations are `"Name_Value"` strings, a StatusCode carries its `Symbol`. |
| `ua.JSONLegacyReversible` | ✅ | ✅ | 1.04 reversible (Annex H of 1.05; `UA_ENABLE_JSON_ENCODING_LEGACY` in open62541). NodeIds, QualifiedNames, Variants and ExtensionObjects are objects (`{"IdType":1,"Id":"x","Namespace":2}`, `{"Type":6,"Body":5}`), a StatusCode is a number. |
| `ua.JSONLegacyNonReversible` | ✅ | — | 1.04 non-reversible. Drops type information (a Variant is just its value, a matrix is nested arrays, a LocalizedText just its text) and so cannot be decoded. |

How the built-in types look in the two 1.05 forms:

| Type | JSON |
|------|------|
| Boolean, integers up to 32 bit, Float, Double | literals and numbers |
| Int64, UInt64 | decimal string: `"-9223372036854775808"` |
| NaN, ±Infinity | `"NaN"`, `"Infinity"`, `"-Infinity"` |
| DateTime | ISO 8601 with 100 ns resolution: `"2024-02-29T12:34:56.7890123Z"` |
| Guid | `"C496578A-0DFE-4B8F-870A-745238C6AEAE"` |
| ByteString | base64 string; `null` for a null ByteString |
| NodeId, ExpandedNodeId | `"ns=2;s=Name"`, `"nsu=urn:x;i=7"`, `"svr=1;nsu=urn:x;i=7"` |
| QualifiedName | `"2:Name"` (`"Name"` in namespace 0) |
| LocalizedText | `{"Locale":"en","Text":"hello"}` |
| StatusCode | `{"Code":2150891520}`, plus `"Symbol":"BadNodeIdUnknown"` in Verbose; `{}` for Good |
| Variant | `{"UaType":6,"Value":[1,2,3,4],"Dimensions":[2,2]}` - a matrix is a flat array plus dimensions |
| DataValue | the Variant members plus `Status`, `SourceTimestamp`, `SourcePicoseconds`, `ServerTimestamp`, `ServerPicoseconds` |
| ExtensionObject | the structure's fields plus `"UaTypeId"` (the **DataType** NodeId); a body that is not JSON is `{"UaTypeId":..,"UaEncoding":1,"UaBody":"<base64>"}` (2 = XML) |
| Enumeration | number (Compact) or `"Running_0"` (Verbose) |
| Structure | object with the field names of the specification (`"NodeId"`, not the Go `NodeID`) |

Things worth knowing:

- **Null and empty arrays.** In a structure field a null array is omitted (or
  `null`) and an empty one is `[]`, so both survive. In a Variant both are
  written as `"Value":[]`, as open62541 does, and decode as an empty array;
  JSON cannot tell them apart there. XML can (`xsi:nil`).
- **Null DateTime.** `time.Time{}` (and anything before 1601) is written as
  `"1601-01-01T00:00:00Z"`, the exact value of binary 0, which every stack
  decodes to the same binary value. `"0001-01-01T00:00:00Z"`, the text
  Part 6 names for values below the range of a platform, is accepted on
  input but not written, because open62541 reads it as year 1 - a negative
  DateTime. Values after year 9999 are written as `"9999-12-31T23:59:59Z"`.
- **Unknown members** of a structure are ignored; missing ones keep their
  default. Duplicate members are an error.
- **Unknown structure types.** An ExtensionObject whose `UaTypeId` is not
  registered is an error if its body is a JSON object (there is nothing to
  decode it into). A binary or XML body of an unknown type is kept as
  `[]byte` / `*ua.XMLElement` and written back unchanged.
- **Masks.** `DataValue` and `DiagnosticInfo` members are written according
  to their `EncodingMask`, and the mask is rebuilt from the members present
  when decoding. Call `UpdateMask()` on values you build by hand.

## XML

`EncodeXML` writes one element named after the type, in the namespace of
`Opc.Ua.Types.xsd`:

```xml
<Argument xmlns="http://opcfoundation.org/UA/2008/02/Types.xsd">
  <Name>Speed</Name>
  <DataType><Identifier>i=11</Identifier></DataType>
  <ValueRank>-1</ValueRank>
  <Description><Text>target speed</Text></Description>
</Argument>
```

| Type | XML content |
|------|-------------|
| numbers, Boolean, String, DateTime | text; `NaN`, `INF`, `-INF` for the special floats |
| ByteString | base64 text |
| Guid | `<String>C496578A-...</String>` |
| NodeId, ExpandedNodeId | `<Identifier>ns=2;s=Name</Identifier>` |
| StatusCode | `<Code>2150891520</Code>` |
| QualifiedName | `<NamespaceIndex>2</NamespaceIndex><Name>Name</Name>` |
| LocalizedText | `<Locale>en</Locale><Text>hello</Text>` |
| Variant | `<Value><Int32>5</Int32></Value>`, `<Value><ListOfInt32>..`, or `<Value><Matrix><Dimensions>..</Dimensions><Elements>..</Elements></Matrix></Value>` |
| DataValue | `<Value>` (a Variant), `<StatusCode>`, `<SourceTimestamp>`, `<SourcePicoseconds>`, `<ServerTimestamp>`, `<ServerPicoseconds>` |
| ExtensionObject | `<TypeId><Identifier>i=297</Identifier></TypeId><Body><Argument>..</Argument></Body>` - the TypeId is the **DefaultXml encoding** NodeId |
| Enumeration | `Running_0` |
| Structure | one child element per field, in order; null fields are left out |
| Array | one child element per value, named after the element type |

`DecodeXML` matches elements by local name whatever their prefix and does not
check the name of the outermost element, so a NodeSet2 `<Value>` can be
decoded as it is:

```go
var v ua.Variant
err := ua.DecodeXML([]byte(`<Value><uax:ListOfInt32><uax:Int32>1</uax:Int32></uax:ListOfInt32></Value>`), &v)
```

An ExtensionObject of an unregistered type is kept with its body as a
`*ua.XMLElement`. `WithXMLRootName`, `WithoutXMLNamespace` and `WithIndent`
control the shape of the output.

## Namespace and server tables

NodeIds and QualifiedNames carry a namespace *index*, which only means
something together with the NamespaceArray of one server. Part 6 therefore
wants documents to carry the URI. Pass the tables and the codecs translate:

```go
ns, _ := client.NamespaceArray(ctx)
opts := []ua.CodecOption{ua.WithNamespaceArray(ns)}

doc, _ := ua.EncodeJSON(ua.NewNumericNodeID(2, 7), opts...) // "nsu=urn:my:model;i=7"

var id ua.NodeID
_ = ua.DecodeJSON(doc, &id, opts...)                        // ns=2;i=7
```

- Without `WithNamespaceArray` indexes are written as they are (`"ns=2;i=7"`).
- `WithServerArray` does the same for the ServerIndex of an ExpandedNodeId
  (`svu=<uri>;` instead of `svr=<index>;`).
- A URI that is not in the table follows Part 6 §5.4.2.10: an ExpandedNodeId
  keeps it in `NamespaceURI`; a NodeId or QualifiedName, which has no room for
  a URI, becomes a String NodeId / name in namespace 0 that holds the whole
  text, so nothing is silently mapped to the wrong namespace.
- The XML QualifiedName has a numeric `NamespaceIndex` element and is not
  translated.

## Custom structures

A structure registered with `ua.RegisterExtensionObject` works without further
setup: fields are named after the Go fields (or their `opcua:"Name"` tag) and
the body is identified by the NodeId it was registered with.

For documents other stacks should understand, tell the codecs the DataType
and encoding NodeIds, which JSON and XML use instead of the binary encoding
NodeId:

```go
type Motor struct {
    Speed float64
    Label string `opcua:"DisplayLabel"`
}

func init() {
    ua.RegisterExtensionObject(ua.NewNumericNodeID(2, 5001), new(Motor)) // Default Binary
    ua.RegisterDataTypeInfo(new(Motor), ua.DataTypeInfo{
        Name:          "MotorType",                   // XML element name
        DataTypeID:    ua.NewNumericNodeID(2, 3001),  // JSON UaTypeId
        XMLEncodingID: ua.NewNumericNodeID(2, 5002),  // XML TypeId
    })
}
```

When decoding, any of the type's NodeIds is accepted and the ExtensionObject
gets the binary encoding NodeId back, so the value can go straight onto the
wire.

## Limits and hostile input

Both decoders are meant to be usable on untrusted input:

- nesting is limited to `ua.DefaultCodecMaxDepth` (100) levels, checked while
  parsing, before anything is built for the nested value (`WithMaxDepth`);
- a Variant array is limited to `ua.MaxVariantArrayLength` elements, like in
  the binary decoder (`WithMaxArrayLength`), and matrix dimensions must match
  the number of elements;
- numbers outside of the range of their type, values of the wrong JSON type
  and malformed NodeIds, Guids, DateTimes or base64 are errors;
- XML DTDs are not processed, only the five predefined entities are known and
  only UTF-8 is accepted;
- memory use is linear in the size of the document.

Every error wraps a `ua.StatusCode` (`StatusBadDecodingError`,
`StatusBadEncodingLimitsExceeded`, `StatusBadEncodingError`) for `errors.Is`.
`FuzzDecodeJSON` and `FuzzDecodeXML` in `ua/codec_fuzz_test.go` fuzz both.

## Interoperability with open62541

The codecs are checked against open62541 v1.5.9 with a recorded corpus
(`ua/testdata/open62541_corpus.json`, 146 values covering every built-in type
as scalar and array, matrices, DataValues and structures; see
`ua/testdata/open62541/README.md` for how it is produced). The binary
encoding is the reference in both directions.

- go-opcua decodes **every** document open62541 emits to the same value, with
  two exceptions that are losses on the open62541 side (it writes `-0.0` as
  `0.0`, and a carriage return unescaped in XML).
- open62541 decodes what go-opcua emits for all built-in types, arrays,
  matrices, DataValues and plain structures in JSON, and for the built-in
  types and arrays in XML.

Where open62541 1.5.9 does not follow or does not implement the
specification, go-opcua writes what Part 6 says and accepts what open62541
writes:

| open62541 1.5.9 | go-opcua |
|-----------------|----------|
| XML: cannot encode structures, enumerations, DataValue, DiagnosticInfo, matrices, a null Variant; cannot decode DataValue, DiagnosticInfo, XmlElement | implements all of them |
| XML: reads enumerations as numbers only | writes `Name_Value` (Part 6 §5.3.4), reads both |
| XML: writes a null ByteString as the text `null`, ignores `xsi:nil` | writes `xsi:nil="true"` |
| JSON: cannot decode a structure encoded in place in an ExtensionObject - the 1.05 form it writes itself - only the non-standard `{"UaTypeId":..,"UaBody":{..}}` | writes the 1.05 form, reads both |
| JSON: cannot decode a DataValue without a value (which it writes itself) | reads and writes it |
| JSON: rejects unknown structure members | ignores them |
| JSON: always writes every structure field and the StatusCode symbol | Compact omits defaults and the symbol; Verbose writes them |

The complete list, with one test case per finding, is `corpusDivergences` in
`ua/open62541_corpus_test.go`.

The interop suite also exchanges encoded values live with the adapters of
open62541, Eclipse Milo 1.1.8 and UA-.NETStandard 2.0.1, in both directions
(go-opcua encodes and the peer decodes, and the reverse; ledger rows
`encoding.json.*` and `encoding.xml.*`, see [INTEROP.md](../INTEROP.md)):

| Peer | JSON Variant | JSON DataValue | XML Variant | XML DataValue |
|------|:---:|:---:|:---:|:---:|
| open62541 1.5.9 | ✅ | ✅ | ✅ | — open62541 has no XML DataValue |
| Eclipse Milo 1.1.8 | ✅ | go-opcua → Milo: — ¹ | ✅ | ✅ |
| UA-.NETStandard 2.0.1 | ✅ | ✅ | ✅ | ✅ |

¹ Milo decodes a JSON DataValue only in its own form, with the Variant nested
in `"Value"`; Part 6 1.05 inlines the Variant members. go-opcua reads Milo's
form.

The UA-.NETStandard `XmlDecoder` reads namespace-qualified elements only: do
not use `ua.WithoutXMLNamespace` with .NET peers. async-opcua and node-opcua
offer no Part 6 JSON or XML codec in their adapters.
