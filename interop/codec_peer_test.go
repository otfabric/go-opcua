//go:build interop

// SPDX-License-Identifier: MIT

// JSON and XML DataEncoding evidence against open62541 and Eclipse Milo
// (Part 6 §5.4, §5.3).
// COVERAGE.md: encoding / encoding.json.variant, encoding.json.datavalue,
// encoding.xml.variant, encoding.xml.datavalue, encoding.json-verbose.variant,
// encoding.json-verbose.datavalue
//
// The Verbose form (OPC UA 1.05.04, --json-mode verbose; Milo and dotnet) is
// run on the JSON half of the same tests. For the fixture's values Milo 1.1.8
// and UA-.NETStandard 2.0.1 write exactly their compact documents (no
// StatusCode Symbol either, also not for an Uncertain status), so the
// go-opcua → peer direction adds a Bad StatusCode and an Uncertain DataValue,
// which go-opcua's Verbose form writes with their Symbol.
//
// The transport in these tests is still OPC UA TCP with the binary encoding:
// values are read over the wire in binary by both stacks, and each stack's
// JSON / XML encoding of that value is then handed to the other stack's
// decoder. The binary value is the reference in both directions.
//
// The tests need the adapter operation "codec" and the client features
// "codec-json" / "codec-xml" (print-capabilities). The contract they rely on
// (opcua-interop docs/CLIENT_CONTRACT.md, "codec"):
//
//	client codec --endpoint <url> --node <nodeId> [--node ...]
//
// reads the Value attribute of every node and reports, next to the fields of
// "read" (nodeId, statusCode, dataType, builtInType, value):
//
//	"json" / "xml"                    the Variant documents
//	"dataValueJson" / "dataValueXml"  the DataValue documents
//
// each null when the stack cannot produce the document (open62541 1.5.9 has
// no XML matrix and no XML DataValue).
//
//	client codec --decode <json|xml> --type <Variant|DataValue>   (document on stdin)
//
// decodes one document and reports dataType, builtInType and value in the
// canonical value encoding of the client contract (§7) - the same form "read"
// reports - plus "binary", the OPC UA Binary encoding of what was decoded.
//
// The two peers differ in what they emit (contract, "Stack limits"): JSON
// DataValue with the Variant members flattened (open62541) or nested (Milo),
// XML without namespace (open62541) or with the uax: prefix (Milo). go-opcua
// has to decode all of it, and both have to decode what go-opcua emits.
//
// The unit tests in ua/ hold the same evidence for all built-in types against
// a recorded corpus (ua/testdata/open62541_corpus.json); these tests add the
// live path through the adapter images.

package interop

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
)

// codecFixtureNodes are the static baseline fixture variables: every scalar
// built-in type the fixture defines, the arrays and the matrix.
var codecFixtureNodes = []string{
	"Scalar.Boolean", "Scalar.SByte", "Scalar.Byte", "Scalar.Int16", "Scalar.UInt16",
	"Scalar.Int32", "Scalar.UInt32", "Scalar.Int64", "Scalar.UInt64", "Scalar.Float",
	"Scalar.Double", "Scalar.String", "Scalar.DateTime", "Scalar.Guid", "Scalar.ByteString",
	"Scalar.XmlElement", "Scalar.NodeId", "Scalar.QualifiedName", "Scalar.LocalizedText",
	"Scalar.StatusCode",
	"Array.Empty", "Array.OneElement", "Array.Int32", "Array.String", "Array.ByteString",
	"Array.Boolean", "Array.Double", "Array.Matrix2D",
	"DataValues.GoodWithTimestamps",
}

// codecPeer is one adapter and what its stack is known not to do.
type codecPeer struct {
	name         string
	imageEnv     string
	defaultImage string
	run          adapterRun
	// encodeGaps: "<node>/<document>" (document: xml, dataValueJson,
	// dataValueXml) the peer cannot produce. A gap that is listed but no
	// longer there fails the test, as does a missing document not listed.
	encodeGaps map[string]string
	// decodeGaps: "<node>/<format>" the peer cannot decode although the
	// document is valid.
	decodeGaps map[string]string
	// dataValueDecodeGaps: format -> why the peer cannot decode the
	// DataValue document go-opcua emits.
	dataValueDecodeGaps map[string]string
	// xmlMillisecondDateTime: the peer's XML decoder keeps a DateTime to the
	// millisecond only.
	xmlMillisecondDateTime bool
	// jsonMode "verbose" runs the JSON half of the tests in the Verbose form
	// of OPC UA 1.05.04 (adapter flag --json-mode verbose, client feature
	// codec-json-verbose; go-opcua ua.JSONVerbose); empty is the compact
	// form, together with XML.
	jsonMode string
}

// verbose reports whether p runs the JSON Verbose form (and no XML).
func (p codecPeer) verbose() bool { return p.jsonMode == "verbose" }

// jsonModeArgs are the adapter flags that select p's JSON form.
func (p codecPeer) jsonModeArgs() []string {
	if p.jsonMode == "" {
		return nil
	}
	return []string{"--json-mode", p.jsonMode}
}

var codecOpen62541 = codecPeer{
	name: "open62541", imageEnv: "OPEN62541_IMAGE", defaultImage: defaultOpen62541Image,
	run: runOpen62541Client,
	encodeGaps: map[string]string{
		"Array.Matrix2D/xml": "open62541 1.5.9 does not implement encoding of a matrix to XML",
		"*/dataValueXml":     "open62541 1.5.9 does not implement DataValue in XML",
	},
	// See corpusDivergences in ua/open62541_corpus_test.go for the same
	// finding against the recorded corpus.
	decodeGaps: map[string]string{
		"Scalar.XmlElement/xml": "open62541 1.5.9 does not implement decoding of XmlElement from XML",
	},
	dataValueDecodeGaps: map[string]string{
		"xml": "open62541 1.5.9 does not implement DataValue in XML",
	},
}

var codecMilo = codecPeer{
	name: "milo", imageEnv: "MILO_IMAGE", defaultImage: defaultMiloImage,
	run:        runMiloClient,
	encodeGaps: map[string]string{},
	decodeGaps: map[string]string{},
	dataValueDecodeGaps: map[string]string{
		// Part 6 (1.05) §5.4.2.18 puts the members of the Variant (UaType,
		// Value, Dimensions) directly into the DataValue object, which is
		// what go-opcua and open62541 emit. Milo nests the Variant in a
		// "Value" object and decodes only that; go-opcua decodes both
		// (TestCodec_MiloEncodes_GoDecodes).
		"json": "Eclipse Milo 1.1.8 does not decode a JSON DataValue with the Variant members inlined (the 1.05 form)",
	},
	// Milo's XML decoder parses a DateTime to the millisecond (its JSON
	// decoder keeps the full 100 ns resolution).
	xmlMillisecondDateTime: true,
}

func (p codecPeer) gap(gaps map[string]string, node, doc string) (string, bool) {
	if r, ok := gaps[node+"/"+doc]; ok {
		return r, true
	}
	r, ok := gaps["*/"+doc]
	return r, ok
}

func (p codecPeer) require(t *testing.T) {
	t.Helper()
	requireAdapterOp(t, p.imageEnv, p.defaultImage, "codec")
	requireAdapterClientFeature(t, p.imageEnv, p.defaultImage, "codec-json")
	if p.verbose() {
		requireAdapterClientFeature(t, p.imageEnv, p.defaultImage, "codec-json-verbose")
		return
	}
	requireAdapterClientFeature(t, p.imageEnv, p.defaultImage, "codec-xml")
}

// codecResult is one element of the results of "client codec" (short form)
// or of "client codec --decode".
type codecResult struct {
	NodeID        string          `json:"nodeId"`
	StatusCode    statusCodeObj   `json:"statusCode"`
	DataType      string          `json:"dataType"`
	BuiltInType   int             `json:"builtInType"`
	Value         json.RawMessage `json:"value"`
	JSON          *string         `json:"json"`
	XML           *string         `json:"xml"`
	DataValueJSON *string         `json:"dataValueJson"`
	DataValueXML  *string         `json:"dataValueXml"`
	Binary        string          `json:"binary"`
}

func codecNodeArg(name string) string {
	return "nsu=" + interopNamespaceURI + ";s=" + name
}

// codecReference reads the fixture values with the Go client, over the
// binary encoding.
func codecReference(t *testing.T, endpoint string) (map[string]*ua.DataValue, []string) {
	t.Helper()
	c := dialClient(t, endpoint)
	ctx, nsIdx := findNS(t, c)
	ref := map[string]*ua.DataValue{}
	var names []string
	for _, name := range codecFixtureNodes {
		v, err := c.ReadValue(ctx, ua.NewStringNodeID(nsIdx, name))
		if err != nil || v == nil || v.Value == nil || v.Status != ua.StatusOK {
			t.Fatalf("fixture node %s is not readable on the Go reference server: %v", name, err)
		}
		ref[name] = v
		names = append(names, name)
	}
	return ref, names
}

// variantHex is the binary encoding of v, the form values are compared in.
// A NodeId is first brought to its shortest encoding: the binary encoding
// has several forms for the same NodeId (i=85 as TwoByte or Numeric) and
// only the identity can survive a text encoding.
func variantHex(t *testing.T, v *ua.Variant) string {
	t.Helper()
	if id, ok := v.Value().(*ua.NodeID); ok && id != nil {
		short, err := ua.ParseNodeID(id.String())
		if err != nil {
			t.Fatalf("normalise NodeId %s: %v", id, err)
		}
		v = ua.MustVariant(short)
	}
	b, err := v.Encode()
	if err != nil {
		t.Fatalf("binary encode: %v", err)
	}
	return hex.EncodeToString(b)
}

// assertPeerEncodesGoDecodes: the peer reads every fixture value from a
// go-opcua server and encodes it to JSON and XML; go-opcua must decode those
// documents to the value it reads itself.
func assertPeerEncodesGoDecodes(t *testing.T, p codecPeer) {
	p.require(t)
	endpoint := startGoServer(t)
	ref, names := codecReference(t, endpoint)

	args := p.jsonModeArgs()
	for _, name := range names {
		args = append(args, "--node", codecNodeArg(name))
	}
	result := p.run(t, endpoint, "codec", args...)
	if !result.Success {
		t.Fatalf("codec failed: serviceResult=%s error=%s", result.ServiceResult, result.Error)
	}
	var items []codecResult
	if err := json.Unmarshal(result.Results, &items); err != nil {
		t.Fatalf("parse codec results: %v; raw: %s", err, result.Results)
	}
	if len(items) != len(names) {
		t.Fatalf("codec returned %d results for %d nodes", len(items), len(names))
	}

	// document returns the peer's document, or nil for a listed gap. A
	// missing document that is not listed fails, and so does a listed gap
	// that is not there (the list has to stay true).
	document := func(t *testing.T, name, kind string, doc *string) []byte {
		t.Helper()
		reason, listed := p.gap(p.encodeGaps, name, kind)
		switch {
		case doc == nil && listed:
			t.Logf("%s: no %s document: %s", name, kind, reason)
			return nil
		case doc == nil:
			t.Errorf("%s: the peer produced no %s document", name, kind)
			return nil
		case listed:
			t.Errorf("%s: %s is listed as a gap (%s) but the peer produced %s", name, kind, reason, *doc)
		}
		return []byte(*doc)
	}

	docs := map[string]int{}
	for i, name := range names {
		item, want := items[i], variantHex(t, ref[name].Value)
		t.Run(name, func(t *testing.T) {
			type variantDoc struct {
				kind   string
				doc    *string
				decode func([]byte, interface{}, ...ua.CodecOption) error
			}
			for _, d := range []variantDoc{{"json", item.JSON, ua.DecodeJSON}, {"xml", item.XML, ua.DecodeXML}} {
				if p.verbose() && d.kind == "xml" {
					continue
				}
				doc := document(t, name, d.kind, d.doc)
				if doc == nil {
					continue
				}
				var v ua.Variant
				if err := d.decode(doc, &v); err != nil {
					t.Errorf("decode %s %s: %v", d.kind, doc, err)
					continue
				}
				if got := variantHex(t, &v); got != want {
					t.Errorf("%s %s decoded to a different value\n want %s\n got  %s", d.kind, doc, want, got)
					continue
				}
				docs[d.kind]++
			}
			for _, d := range []variantDoc{{"dataValueJson", item.DataValueJSON, ua.DecodeJSON}, {"dataValueXml", item.DataValueXML, ua.DecodeXML}} {
				if p.verbose() && d.kind == "dataValueXml" {
					continue
				}
				doc := document(t, name, d.kind, d.doc)
				if doc == nil {
					continue
				}
				var dv ua.DataValue
				if err := d.decode(doc, &dv); err != nil {
					t.Errorf("decode %s %s: %v", d.kind, doc, err)
					continue
				}
				if dv.Value == nil {
					t.Errorf("%s %s decoded without a value", d.kind, doc)
					continue
				}
				if got := variantHex(t, dv.Value); got != want {
					t.Errorf("%s %s decoded to a different value\n want %s\n got  %s", d.kind, doc, want, got)
					continue
				}
				// The peer read with TimestampsToReturn=Both from a server
				// that stamps every value.
				if dv.SourceTimestamp.IsZero() && dv.ServerTimestamp.IsZero() {
					t.Errorf("%s %s decoded without a timestamp", d.kind, doc)
					continue
				}
				docs[d.kind]++
			}
		})
	}
	t.Logf("%s documents decoded by go-opcua: %v of %d nodes", p.name, docs, len(names))
	if docs["json"] != len(names) {
		t.Errorf("%d of %d JSON documents were verified", docs["json"], len(names))
	}
	if p.verbose() && docs["dataValueJson"] != len(names) {
		t.Errorf("%d of %d JSON DataValue documents were verified", docs["dataValueJson"], len(names))
	}
}

// Values the JSON Verbose tests add to the fixture's (go-opcua encodes, the
// peer decodes): a Bad StatusCode and a DataValue with an Uncertain status.
const (
	verboseBadStatus = "Verbose.BadStatusCode"
	verboseUncertain = "Verbose.UncertainDataValue"
)

// requireVerboseSymbol: the Verbose form writes a StatusCode other than Good
// with its Symbol, which the compact form leaves out. It makes sure the
// values meant to tell the forms apart do.
func requireVerboseSymbol(t *testing.T, p codecPeer, name string, doc []byte) {
	t.Helper()
	if p.verbose() && (name == verboseBadStatus || name == verboseUncertain) && !bytes.Contains(doc, []byte(`"Symbol"`)) {
		t.Fatalf("the verbose document of %s has no Symbol: %s", name, doc)
	}
}

// runCodecDecode hands a document to the adapter on stdin.
func runCodecDecode(t *testing.T, p codecPeer, format, typ string, doc []byte) (adapterResult, []byte) {
	t.Helper()
	image := getEnvOr(p.imageEnv, p.defaultImage)
	ctx, cancel := context.WithTimeout(context.Background(), clientTimeout)
	defer cancel()
	args := []string{"run", "--rm", "-i", image, "client", "codec", "--decode", format, "--type", typ}
	if format == "json" {
		args = append(args, p.jsonModeArgs()...)
	}
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdin = bytes.NewReader(doc)
	if p.name != "milo" { // the JVM warns about netty on every start
		cmd.Stderr = os.Stderr
	}
	raw, _ := cmd.Output() // a rejected document exits non-zero but still reports
	result, err := parseAdapterOutput(raw)
	if err != nil {
		t.Fatalf("parse codec --decode %s output: %v\ndoc: %s\nraw: %s", format, err, doc, raw)
	}
	return result, raw
}

// decodedVariantHex returns variantHex of the Variant whose binary encoding
// the peer reports for what it decoded. Reading the peer's binary back with
// go-opcua brings it to the same form as the reference: go-opcua has no null
// String (an empty string is the null String in its binary encoding and ""
// in its JSON and XML encodings, so a peer that decodes "" encodes a
// zero-length String where go-opcua encodes null; the same finding as
// "string/empty" in corpusDivergences, ua/open62541_corpus_test.go). For
// every other type this is a comparison of the binary encodings.
func decodedVariantHex(t *testing.T, b64 string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) == 0 {
		t.Fatalf("binary of the decoded value %q: %v", b64, err)
	}
	var v ua.Variant
	if n, err := v.Decode(raw); err != nil || n != len(raw) {
		t.Fatalf("the peer's binary encoding %x of the decoded value is not a Variant (%d of %d bytes): %v", raw, n, len(raw), err)
	}
	return variantHex(t, &v)
}

// assertGoEncodesPeerDecodes: go-opcua encodes every fixture value to JSON
// and XML and the peer decodes the documents. The peer reports the binary
// encoding of what it decoded, which must be the value go-opcua encoded.
func assertGoEncodesPeerDecodes(t *testing.T, p codecPeer) {
	p.require(t)
	endpoint := startGoServer(t)
	ref, names := codecReference(t, endpoint)

	type encoder struct {
		format string
		encode func(interface{}, ...ua.CodecOption) ([]byte, error)
	}
	encoders := []encoder{{"json", ua.EncodeJSON}, {"xml", ua.EncodeXML}}
	dataValueNames := []string{"Scalar.Int32", "Scalar.Double", "Scalar.LocalizedText", "Array.Double", "Array.Matrix2D", "DataValues.GoodWithTimestamps"}
	if p.verbose() {
		// The fixture's values encode the same in both forms (their
		// StatusCodes are Good). These two carry a StatusCode that the
		// Verbose form writes with its Symbol.
		now := time.Now().UTC().Truncate(time.Millisecond)
		ref[verboseBadStatus] = &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(ua.StatusBadNodeIDUnknown)}
		names = append(names, verboseBadStatus)
		ref[verboseUncertain] = &ua.DataValue{
			EncodingMask:    ua.DataValueValue | ua.DataValueStatusCode | ua.DataValueSourceTimestamp | ua.DataValueServerTimestamp,
			Value:           ua.MustVariant(int32(7)),
			Status:          ua.StatusUncertainInitialValue,
			SourceTimestamp: now, ServerTimestamp: now,
		}
		dataValueNames = append(dataValueNames, verboseUncertain)
		encoders = []encoder{{"json", func(v interface{}, opts ...ua.CodecOption) ([]byte, error) {
			return ua.EncodeJSON(v, append(opts, ua.WithJSONForm(ua.JSONVerbose))...)
		}}}
	}

	// The adapter runs are independent of each other and of the server:
	// run them in parallel (a Milo run is a JVM start).
	t.Run("variant", func(t *testing.T) {
		for _, name := range names {
			for _, enc := range encoders {
				value := ref[name].Value
				t.Run(name+"/"+enc.format, func(t *testing.T) {
					t.Parallel()
					doc, err := enc.encode(value)
					if err != nil {
						t.Fatalf("encode: %v", err)
					}
					requireVerboseSymbol(t, p, name, doc)
					result, raw := runCodecDecode(t, p, enc.format, "Variant", doc)
					if reason, gap := p.gap(p.decodeGaps, name, enc.format); gap {
						if result.Success {
							t.Errorf("listed as a known gap (%s) but %s decoded %s", reason, p.name, doc)
						}
						t.Logf("known gap: %s", reason)
						return
					}
					if !result.Success {
						t.Fatalf("%s rejected %s\nraw: %s", p.name, doc, raw)
					}
					var got []codecResult
					if err := json.Unmarshal(result.Results, &got); err != nil || len(got) != 1 {
						t.Fatalf("parse codec results: %v; raw: %s", err, result.Results)
					}
					if got[0].BuiltInType != int(value.Type()) {
						t.Errorf("%s decoded as built-in type %d, want %d", doc, got[0].BuiltInType, value.Type())
					}
					if got, want := decodedVariantHex(t, got[0].Binary), variantHex(t, value); got != want {
						t.Errorf("%s decoded %s to a different value\n want %s\n got  %s\n result: %s", p.name, doc, want, got, result.Results)
					}
				})
			}
		}
	})

	// DataValue: value and both timestamps survive. The binary encoding of
	// what the peer decoded must be the binary encoding of the DataValue
	// go-opcua encoded.
	t.Run("datavalue", func(t *testing.T) {
		for _, name := range dataValueNames {
			for _, enc := range encoders {
				dv := *ref[name]
				if enc.format == "xml" && p.xmlMillisecondDateTime {
					dv.SourceTimestamp = dv.SourceTimestamp.Truncate(time.Millisecond)
					dv.ServerTimestamp = dv.ServerTimestamp.Truncate(time.Millisecond)
				}
				t.Run(name+"/"+enc.format, func(t *testing.T) {
					t.Parallel()
					if dv.SourceTimestamp.IsZero() || dv.ServerTimestamp.IsZero() {
						t.Fatalf("reference DataValue has no timestamps: %+v", dv)
					}
					doc, err := enc.encode(&dv)
					if err != nil {
						t.Fatalf("encode: %v", err)
					}
					requireVerboseSymbol(t, p, name, doc)
					result, raw := runCodecDecode(t, p, enc.format, "DataValue", doc)
					if reason, gap := p.dataValueDecodeGaps[enc.format]; gap {
						if result.Success {
							t.Errorf("listed as a known gap (%s) but %s decoded %s", reason, p.name, doc)
						}
						t.Logf("known gap: %s (%s)", reason, result.ServiceResult)
						return
					}
					if !result.Success {
						t.Fatalf("%s rejected %s\nraw: %s", p.name, doc, raw)
					}
					var got []codecResult
					if err := json.Unmarshal(result.Results, &got); err != nil || len(got) != 1 {
						t.Fatalf("parse codec results: %v; raw: %s", err, result.Results)
					}
					wantBin, err := ua.Encode(&dv)
					if err != nil {
						t.Fatalf("binary encode: %v", err)
					}
					gotBin, err := base64.StdEncoding.DecodeString(got[0].Binary)
					if err != nil {
						t.Fatalf("binary of the decoded DataValue: %v", err)
					}
					if !bytes.Equal(gotBin, wantBin) {
						t.Errorf("%s decoded %s to a different DataValue\n want %x\n got  %x", p.name, doc, wantBin, gotBin)
					}
				})
			}
		}
	})
}

func TestCodec_Open62541Encodes_GoDecodes(t *testing.T) {
	assertPeerEncodesGoDecodes(t, codecOpen62541)
}
func TestCodec_GoEncodes_Open62541Decodes(t *testing.T) {
	assertGoEncodesPeerDecodes(t, codecOpen62541)
}
func TestCodec_MiloEncodes_GoDecodes(t *testing.T) { assertPeerEncodesGoDecodes(t, codecMilo) }
func TestCodec_GoEncodes_MiloDecodes(t *testing.T) { assertGoEncodesPeerDecodes(t, codecMilo) }

// codecMiloVerbose: Milo's encoder and decoder in the JSON Verbose form.
var codecMiloVerbose = func() codecPeer {
	p := codecMilo
	p.jsonMode = "verbose"
	return p
}()

func TestCodec_MiloEncodesVerbose_GoDecodes(t *testing.T) {
	assertPeerEncodesGoDecodes(t, codecMiloVerbose)
}
func TestCodec_GoEncodesVerbose_MiloDecodes(t *testing.T) {
	assertGoEncodesPeerDecodes(t, codecMiloVerbose)
}
