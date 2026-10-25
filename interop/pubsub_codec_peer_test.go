//go:build interop

// SPDX-License-Identifier: MIT

// PubSub (Part 14) message mapping evidence against open62541: UADP and JSON
// NetworkMessages encoded by one stack and decoded by the other, without a
// transport.
// COVERAGE.md: pubsub / pubsub.uadp.codec, pubsub.json.codec,
// pubsub.uadp.delta-frame, pubsub.uadp.keepalive-message
//
// The adapter operations (opcua-interop docs/CLIENT_CONTRACT.md §14.9):
//
//	client codec pubsub-uadp-encode | pubsub-json-encode   description → NetworkMessage
//	client codec pubsub-uadp-decode | pubsub-json-decode   NetworkMessage → description
//
// run open62541's UA_NetworkMessage_encodeBinary / _decodeBinary /
// _encodeJson / _decodeJson. A decode also reports open62541's re-encoding of
// what it decoded.
//
// go-opcua → open62541: go-opcua encodes a NetworkMessage of the matrix, open62541
// decodes it; its description must be the message go-opcua encoded, and for
// UADP open62541's re-encoding must be byte for byte the go-opcua encoding.
//
// open62541 → go-opcua: open62541 encodes the description of the same
// message; for UADP the bytes must be go-opcua's encoding, and go-opcua must
// decode them (and, for JSON, the text) to the same message.

package interop

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/pubsub/jsonmsg"
	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/pubsub/uadp"
	"github.com/otfabric/go-opcua/ua"
)

// requirePubSubCodec gates on the codec-pubsub client feature of the
// open62541 adapter (opcua-interop v0.8.0).
func requirePubSubCodec(t *testing.T) {
	t.Helper()
	psOpen62541.requireCodec(t)
}

// requireCodec gates on the codec-pubsub client feature of the peer.
func (p *psPeer) requireCodec(t *testing.T) {
	t.Helper()
	requireAdapterOp(t, p.env, p.image, "codec")
	requireAdapterClientFeature(t, p.env, p.image, "codec-pubsub")
}

// pubsubCodecResult is the result of a codec pubsub-* operation.
type pubsubCodecResult struct {
	Action             string          `json:"action"`
	Mapping            string          `json:"mapping"`
	StatusCode         statusCodeObj   `json:"statusCode"`
	Encoded            json.RawMessage `json:"encoded"`
	NetworkMessage     *psDesc         `json:"networkMessage"`
	Reencoded          *string         `json:"reencoded"`
	ReencodeStatusCode statusCodeObj   `json:"reencodeStatusCode"`
}

// runPubSubCodec runs a codec pubsub-* operation of open62541 with input on
// stdin.
func runPubSubCodec(t *testing.T, op string, input []byte, metadata string) pubsubCodecResult {
	t.Helper()
	return psOpen62541.runCodec(t, op, input, metadata)
}

// runCodec runs a codec pubsub-* operation of the peer with input on stdin.
func (p *psPeer) runCodec(t *testing.T, op string, input []byte, metadata string) pubsubCodecResult {
	t.Helper()
	image := getEnvOr(p.env, p.image)
	ctx, cancel := context.WithTimeout(context.Background(), clientTimeout)
	defer cancel()
	args := []string{"run", "--rm", "-i", image, "client", "codec", op}
	if metadata != "" {
		args = append(args, "--metadata", metadata)
	}
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdin = bytes.NewReader(input)
	cmd.Stderr = os.Stderr
	raw, _ := cmd.Output() // a failed encode / decode exits 4 but reports
	result, err := parseAdapterOutput(raw)
	if err != nil {
		t.Fatalf("codec %s: %v\ninput: %s\nraw: %s", op, err, input, raw)
	}
	if !result.Success {
		t.Fatalf("codec %s failed: %s %s\ninput: %s", op, result.ServiceResult, result.Error, input)
	}
	var items []pubsubCodecResult
	if err := json.Unmarshal(result.Results, &items); err != nil || len(items) != 1 {
		t.Fatalf("codec %s results: %v\nraw: %s", op, err, result.Results)
	}
	return items[0]
}

// ---------------------------------------------------------------------------
// The matrix
// ---------------------------------------------------------------------------

var (
	psTS     = time.Date(2026, 10, 23, 10, 0, 0, 123456700, time.UTC)  // 100 ns resolution
	psTSms   = time.Date(2026, 10, 23, 9, 59, 59, 500000000, time.UTC) // field DateTimes: ms (contract §7)
	psClass  = ua.NewGUID("72962B91-FA75-4AE6-8D28-B404DC7DAF63")
	psFGUID  = ua.NewGUID("01234567-89AB-CDEF-0123-456789ABCDEF")
	psNodeID = ua.NewStringNodeID(1, "PubSub.Int32")
)

func psDV(v any) *ua.DataValue {
	return &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)}
}

func psFields(vals ...any) []*message.Field {
	out := make([]*message.Field, len(vals))
	for i, v := range vals {
		out[i] = &message.Field{Index: uint16(i), Value: psDV(v)}
	}
	return out
}

// psAllTypes is one value of every built-in type of the matrix, scalars,
// arrays and a matrix.
func psAllTypes() []any {
	return []any{
		true, int8(-100), uint8(200), int16(-12345), uint16(54321),
		int32(-123456789), uint32(3234567890), int64(-1234567890123456789), uint64(18446744073709551615),
		float32(12.5), float64(-12345.6789), "OPC UA – 兼容性 – Δ", psTSms, psFGUID,
		[]byte("opcua-compat"), psNodeID, ua.StatusCode(0x80340000),
		&ua.QualifiedName{NamespaceIndex: 1, Name: "Q"}, ua.NewLocalizedTextWithLocale("text", "en"),
		[]int32{0, 1, -1, 2147483647, -2147483648}, []string{"alpha", "β", "Δ"},
		[]float64{0, 1.5, -1.5, 3.141592653589793}, [][]byte{{1, 2, 3}, {4, 5, 6}},
		[]bool{true, false}, [][]int32{{1, 2, 3}, {4, 5, 6}},
	}
}

func psMeta(name string, fields ...*ua.FieldMetaData) *ua.DataSetMetaDataType {
	return &ua.DataSetMetaDataType{Name: name, Fields: fields}
}

func psFieldMeta(name string, typ uint32, valueRank int32) *ua.FieldMetaData {
	return &ua.FieldMetaData{Name: name, BuiltInType: uint8(typ), DataType: ua.NewNumericNodeID(0, typ), ValueRank: valueRank}
}

func psLookup(md *ua.DataSetMetaDataType) message.MetaDataLookup {
	if md == nil {
		return nil
	}
	return func(message.PublisherID, uint16, uint16) *ua.DataSetMetaDataType { return md }
}

type psCodecCase struct {
	name string
	nm   *message.NetworkMessage
	md   *ua.DataSetMetaDataType
}

const (
	psMaskGroup = ua.UADPNetworkMessageContentMaskGroupHeader | ua.UADPNetworkMessageContentMaskWriterGroupID |
		ua.UADPNetworkMessageContentMaskSequenceNumber
	psMaskDSMAll = ua.UADPDataSetMessageContentMaskTimestamp | ua.UADPDataSetMessageContentMaskPicoSeconds |
		ua.UADPDataSetMessageContentMaskStatus | ua.UADPDataSetMessageContentMaskMajorVersion |
		ua.UADPDataSetMessageContentMaskMinorVersion | ua.UADPDataSetMessageContentMaskSequenceNumber
)

func psKeyFrame(writer uint16, enc message.FieldEncoding, fields ...*message.Field) *message.DataSetMessage {
	return &message.DataSetMessage{DataSetWriterID: writer, Type: message.DataSetMessageKeyFrame, Valid: true,
		FieldEncoding: enc, Fields: fields}
}

func uadpCodecCases() []psCodecCase {
	pub := func(p message.PublisherID) *message.NetworkMessage {
		return &message.NetworkMessage{
			UADPMask:    ua.UADPNetworkMessageContentMaskPublisherID | ua.UADPNetworkMessageContentMaskPayloadHeader,
			PublisherID: p,
			Messages:    []*message.DataSetMessage{psKeyFrame(1, message.FieldEncodingVariant, psFields(int32(27))...)},
		}
	}
	var cases []psCodecCase
	add := func(name string, nm *message.NetworkMessage, md *ua.DataSetMetaDataType) {
		cases = append(cases, psCodecCase{name: name, nm: nm, md: md})
	}

	add("publisher-id-byte", pub(message.NewPublisherID(message.PublisherIDByte, 7)), nil)
	add("publisher-id-uint16", pub(message.NewPublisherID(message.PublisherIDUInt16, 2234)), nil)
	add("publisher-id-uint32", pub(message.NewPublisherID(message.PublisherIDUInt32, 3234567890)), nil)
	add("publisher-id-uint64", pub(message.NewPublisherID(message.PublisherIDUInt64, 18446744073709551615)), nil)
	add("publisher-id-string", pub(message.StringPublisherID("pub-α-1")), nil)

	// Every NetworkMessage header field.
	full := pub(message.NewPublisherID(message.PublisherIDUInt16, 2234))
	full.UADPMask |= ua.UADPNetworkMessageContentMaskGroupHeader | ua.UADPNetworkMessageContentMaskWriterGroupID |
		ua.UADPNetworkMessageContentMaskGroupVersion | ua.UADPNetworkMessageContentMaskNetworkMessageNumber |
		ua.UADPNetworkMessageContentMaskSequenceNumber | ua.UADPNetworkMessageContentMaskTimestamp |
		ua.UADPNetworkMessageContentMaskPicoSeconds | ua.UADPNetworkMessageContentMaskDataSetClassID |
		ua.UADPNetworkMessageContentMaskPromotedFields
	full.GroupHeader = message.GroupHeader{WriterGroupID: 100, GroupVersion: 0x01020304, NetworkMessageNumber: 1, SequenceNumber: 65535}
	full.Timestamp = psTS
	full.PicoSeconds = 999
	full.DataSetClassID = psClass
	full.PromotedFields = []*ua.Variant{ua.MustVariant(int32(42)), ua.MustVariant("promoted"), ua.MustVariant(1.5)}
	add("network-message-header-all-fields", full, nil)

	// The group header fields one at a time.
	for _, g := range []struct {
		name string
		mask ua.UADPNetworkMessageContentMask
	}{
		{"writer-group-id", ua.UADPNetworkMessageContentMaskWriterGroupID},
		{"group-version", ua.UADPNetworkMessageContentMaskGroupVersion},
		{"network-message-number", ua.UADPNetworkMessageContentMaskNetworkMessageNumber},
		{"sequence-number", ua.UADPNetworkMessageContentMaskSequenceNumber},
	} {
		m := pub(message.NewPublisherID(message.PublisherIDUInt16, 1))
		m.UADPMask |= ua.UADPNetworkMessageContentMaskGroupHeader | g.mask
		m.GroupHeader = message.GroupHeader{WriterGroupID: 7, GroupVersion: 99, NetworkMessageNumber: 3, SequenceNumber: 4711}
		add("group-header-"+g.name, m, nil)
	}

	// Without PublisherId, without payload header (the DataSetMessage
	// count comes from the metadata on the open62541 side).
	noPH := &message.NetworkMessage{
		UADPMask: ua.UADPNetworkMessageContentMaskGroupHeader | ua.UADPNetworkMessageContentMaskWriterGroupID,
		Messages: []*message.DataSetMessage{psKeyFrame(0, message.FieldEncodingVariant, psFields(int32(-5), "hi")...)},
	}
	noPH.GroupHeader.WriterGroupID = 100
	add("no-payload-header", noPH, psMeta("ds", psFieldMeta("a", id.Int32, -1), psFieldMeta("b", id.String, -1)))

	// Every DataSetMessage header field.
	dsmAll := pub(message.NewPublisherID(message.PublisherIDUInt16, 2234))
	d := dsmAll.Messages[0]
	d.UADPMask = psMaskDSMAll
	d.SequenceNumber = 65000
	d.Timestamp = psTS
	d.PicoSeconds = 12
	d.Status = 0x80340000
	d.MetaDataVersion = ua.ConfigurationVersionDataType{MajorVersion: 2369083044, MinorVersion: 7}
	add("dataset-message-header-all-fields", dsmAll, nil)

	// Valid = false.
	invalid := pub(message.NewPublisherID(message.PublisherIDByte, 1))
	invalid.Messages[0].Valid = false
	add("dataset-message-invalid", invalid, nil)

	// Field encodings.
	variant := pub(message.NewPublisherID(message.PublisherIDUInt16, 2234))
	variant.Messages[0].Fields = psFields(psAllTypes()...)
	add("variant-all-types", variant, nil)

	dv := pub(message.NewPublisherID(message.PublisherIDUInt16, 2234))
	dv.Messages[0].FieldEncoding = message.FieldEncodingDataValue
	dv.Messages[0].Fields = []*message.Field{
		{Index: 0, Value: psDV(int32(1))},
		{Index: 1, Value: &ua.DataValue{EncodingMask: ua.DataValueValue | ua.DataValueStatusCode, Value: ua.MustVariant(2.5), Status: ua.StatusCode(0x40920000)}},
		{Index: 2, Value: &ua.DataValue{EncodingMask: ua.DataValueValue | ua.DataValueSourceTimestamp | ua.DataValueServerTimestamp,
			Value: ua.MustVariant("ts"), SourceTimestamp: psTS, ServerTimestamp: psTS.Add(time.Second)}},
		{Index: 3, Value: &ua.DataValue{EncodingMask: ua.DataValueValue | ua.DataValueSourceTimestamp | ua.DataValueSourcePicoseconds |
			ua.DataValueServerTimestamp | ua.DataValueServerPicoseconds | ua.DataValueStatusCode,
			Value: ua.MustVariant([]int32{1, 2, 3}), Status: ua.StatusBadInternalError, SourceTimestamp: psTS, SourcePicoseconds: 7,
			ServerTimestamp: psTS, ServerPicoseconds: 9}},
		{Index: 4, Value: &ua.DataValue{EncodingMask: ua.DataValueStatusCode, Status: ua.StatusBadNoData}},
	}
	add("datavalue", dv, nil)

	rawMeta := psMeta("raw",
		psFieldMeta("Boolean", id.Boolean, -1), psFieldMeta("SByte", id.SByte, -1), psFieldMeta("Int16", id.Int16, -1),
		psFieldMeta("UInt32", id.UInt32, -1), psFieldMeta("Int64", id.Int64, -1), psFieldMeta("UInt64", id.UInt64, -1),
		psFieldMeta("Float", id.Float, -1), psFieldMeta("Double", id.Double, -1), psFieldMeta("String", id.String, -1),
		psFieldMeta("DateTime", id.DateTime, -1), psFieldMeta("Guid", id.GUID, -1), psFieldMeta("ByteString", id.ByteString, -1),
		psFieldMeta("StatusCode", id.StatusCode, -1))
	raw := pub(message.NewPublisherID(message.PublisherIDUInt16, 2234))
	raw.Messages[0].FieldEncoding = message.FieldEncodingRawData
	raw.Messages[0].Fields = psFields(true, int8(-1), int16(-300), uint32(4000000000), int64(-1), uint64(1<<63+5),
		float32(-0.25), 1e300, "raw-Δ", psTSms, psFGUID, []byte{0, 1, 2, 255}, ua.StatusCode(0x80340000))
	add("rawdata", raw, rawMeta)

	// The empty String: go-opcua has no null String and encodes "" as the
	// null String (length -1); a peer may encode a zero-length String
	// (psPeer.byteDivergences).
	empty := pub(message.NewPublisherID(message.PublisherIDUInt16, 2234))
	empty.Messages[0].Fields = psFields("", []string{"", "x"})
	add("empty-string", empty, nil)

	// KeepAlive, multiple DataSetMessages, delta frames.
	keepAlive := pub(message.NewPublisherID(message.PublisherIDUInt16, 2234))
	keepAlive.Messages[0] = &message.DataSetMessage{DataSetWriterID: 1, Type: message.DataSetMessageKeepAlive, Valid: true,
		UADPMask: ua.UADPDataSetMessageContentMaskSequenceNumber, SequenceNumber: 77}
	add("keep-alive", keepAlive, nil)

	multi := pub(message.NewPublisherID(message.PublisherIDUInt16, 2234))
	multi.UADPMask |= psMaskGroup
	multi.GroupHeader = message.GroupHeader{WriterGroupID: 100, SequenceNumber: 8}
	multi.Messages = []*message.DataSetMessage{
		psKeyFrame(1, message.FieldEncodingVariant, psFields(int32(1), "one")...),
		{DataSetWriterID: 2, Type: message.DataSetMessageKeepAlive, Valid: true, UADPMask: ua.UADPDataSetMessageContentMaskSequenceNumber, SequenceNumber: 3},
		psKeyFrame(3, message.FieldEncodingDataValue, &message.Field{Value: &ua.DataValue{EncodingMask: ua.DataValueValue | ua.DataValueStatusCode,
			Value: ua.MustVariant(uint64(3)), Status: ua.StatusUncertain}}),
		psKeyFrame(65535, message.FieldEncodingVariant, psFields([]float64{1, 2})...),
	}
	multi.Messages[0].UADPMask = ua.UADPDataSetMessageContentMaskSequenceNumber
	multi.Messages[0].SequenceNumber = 10
	add("multiple-dataset-messages", multi, nil)

	deltaMeta := psMeta("delta", psFieldMeta("a", id.Int32, -1), psFieldMeta("b", id.String, -1),
		psFieldMeta("c", id.Double, -1), psFieldMeta("d", id.Boolean, -1))
	delta := pub(message.NewPublisherID(message.PublisherIDUInt16, 2234))
	delta.Messages[0] = &message.DataSetMessage{DataSetWriterID: 1, Type: message.DataSetMessageDeltaFrame, Valid: true,
		FieldEncoding: message.FieldEncodingVariant, UADPMask: ua.UADPDataSetMessageContentMaskSequenceNumber, SequenceNumber: 5,
		Fields: []*message.Field{{Index: 1, Value: psDV("changed")}, {Index: 3, Value: psDV(true)}}}
	add("delta-frame-variant", delta, deltaMeta)

	deltaDV := pub(message.NewPublisherID(message.PublisherIDUInt16, 2234))
	deltaDV.Messages[0] = &message.DataSetMessage{DataSetWriterID: 1, Type: message.DataSetMessageDeltaFrame, Valid: true,
		FieldEncoding: message.FieldEncodingDataValue,
		Fields: []*message.Field{{Index: 2, Value: &ua.DataValue{EncodingMask: ua.DataValueValue | ua.DataValueSourceTimestamp,
			Value: ua.MustVariant(-0.5), SourceTimestamp: psTS}}}}
	add("delta-frame-datavalue", deltaDV, deltaMeta)
	return cases
}

// TestPubSubCodec_GoEncodesUADP_Open62541Decodes: go-opcua encodes, open62541
// decodes; the description and open62541's re-encoding must match.
func TestPubSubCodec_GoEncodesUADP_Open62541Decodes(t *testing.T) {
	requirePubSubCodec(t)
	psGoEncodesUADP(t, psOpen62541)
}

// psSkipUnsupported skips a codec case the peer cannot handle.
func psSkipUnsupported(t *testing.T, p *psPeer, name string) {
	t.Helper()
	if why, ok := p.codecUnsupported[name]; ok {
		t.Skipf("%s: %s", p.name, why)
	}
}

// psGoEncodesUADP: go-opcua encodes every UADP case, the peer decodes it;
// its description must be the message and its re-encoding the same bytes.
func psGoEncodesUADP(t *testing.T, p *psPeer) {
	for _, c := range uadpCodecCases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			psSkipUnsupported(t, p, c.name)
			md := psLookup(c.md)
			b, err := uadp.Encode(c.nm, &uadp.EncodeOptions{MetaData: md})
			if err != nil {
				t.Fatalf("uadp.Encode: %v", err)
			}
			meta := ""
			if c.md != nil {
				meta = metaJSON(t, c.md)
			}
			r := p.runCodec(t, "pubsub-uadp-decode", []byte(base64.StdEncoding.EncodeToString(b)), meta)
			if r.NetworkMessage == nil {
				t.Fatalf("no description: %+v", r)
			}
			assertSameDesc(t, p.name+"'s decoding of the go-opcua message", describeUADP(t, c.nm, md), *r.NetworkMessage)
			if r.Reencoded == nil {
				t.Fatalf("%s could not re-encode what it decoded: %s", p.name, r.ReencodeStatusCode)
			}
			if re, _ := base64.StdEncoding.DecodeString(*r.Reencoded); !bytes.Equal(re, b) {
				t.Errorf("%s re-encodes the message differently\n go-opcua %s\n %s %s", p.name, hex.EncodeToString(b), p.name, hex.EncodeToString(re))
			}
		})
	}
}

// TestPubSubCodec_Open62541EncodesUADP_GoDecodes: open62541 encodes the
// description, go-opcua decodes it; the bytes must be go-opcua's encoding.
func TestPubSubCodec_Open62541EncodesUADP_GoDecodes(t *testing.T) {
	requirePubSubCodec(t)
	psPeerEncodesUADP(t, psOpen62541)
}

// psPeerEncodesUADP: the peer encodes the description of every UADP case,
// go-opcua decodes it; the bytes must be go-opcua's encoding.
func psPeerEncodesUADP(t *testing.T, p *psPeer) {
	for _, c := range uadpCodecCases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			psSkipUnsupported(t, p, c.name)
			md := psLookup(c.md)
			want := describeUADP(t, c.nm, md)
			doc, err := json.Marshal(want)
			if err != nil {
				t.Fatal(err)
			}
			meta := ""
			if c.md != nil {
				meta = metaJSON(t, c.md)
			}
			r := p.runCodec(t, "pubsub-uadp-encode", doc, meta)
			var b64 string
			if err := json.Unmarshal(r.Encoded, &b64); err != nil {
				t.Fatalf("encoded %s: %v", r.Encoded, err)
			}
			b, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				t.Fatalf("encoded %s: %v", b64, err)
			}
			got, err := uadp.Decode(b, &uadp.DecodeOptions{MetaData: md})
			if err != nil {
				t.Fatalf("uadp.Decode of %s's %x: %v", p.name, b, err)
			}
			// Part 14 (DataSetFlags1 bit 0): the content of an invalid DataSetMessage
			// is to be ignored; go-opcua's decoder skips its fields.
			wantDecoded := want
			wantDecoded.Messages = append([]psDSM(nil), want.Messages...)
			for i := range wantDecoded.Messages {
				if v := wantDecoded.Messages[i].Valid; v != nil && !*v {
					wantDecoded.Messages[i].Fields = nil
				}
			}
			assertSameDesc(t, "go-opcua's decoding of the "+p.name+" message", wantDecoded, describeUADP(t, got, md))
			ours, err := uadp.Encode(c.nm, &uadp.EncodeOptions{MetaData: md})
			why, known := p.byteDivergences[c.name]
			switch {
			case err != nil:
				t.Fatalf("uadp.Encode: %v", err)
			case known && bytes.Equal(ours, b):
				t.Errorf("listed as a known divergence (%s) but the encodings are equal", why)
			case known:
				t.Logf("known divergence: %s\n go-opcua %x\n %s %x", why, ours, p.name, b)
			case !bytes.Equal(ours, b):
				t.Errorf("the encodings differ\n go-opcua %x\n %s %x", ours, p.name, b)
			}
		})
	}
}

// TestPubSubCodec_UADPSecurityHeader: the security header of a signed
// go-opcua message (PubSub-Aes256-CTR) as open62541 reads it. The codec has
// no keys (contract §14.9), so this is the header layout only; signatures
// and encryption are verified on the live path (pubsub_live_peer_test.go).
func TestPubSubCodec_UADPSecurityHeader(t *testing.T) {
	requirePubSubCodec(t)
	nm := uadpCodecCases()[1].nm // publisher-id-uint16
	keys := staticKeyRing(t, security.Aes256CTR(), 4711, psStaticKey256)
	b, err := uadp.Encode(nm, &uadp.EncodeOptions{SecurityMode: ua.MessageSecurityModeSign, Keys: keys, NonceSequence: 9})
	if err != nil {
		t.Fatalf("uadp.Encode: %v", err)
	}
	dec, err := uadp.Decode(b, &uadp.DecodeOptions{Security: func(*message.NetworkMessage) (ua.MessageSecurityMode, security.KeySource, error) {
		return ua.MessageSecurityModeSign, keys, nil
	}})
	if err != nil || dec.Security == nil {
		t.Fatalf("go-opcua cannot read its own signed message: %v", err)
	}
	// The signature (32 bytes) follows the payload: open62541's
	// standalone decoder does not know the policy, so hand it the message
	// without the signature.
	r := runPubSubCodec(t, "pubsub-uadp-decode", []byte(base64.StdEncoding.EncodeToString(b[:len(b)-32])), "")
	s := r.NetworkMessage.Security
	if s == nil {
		t.Fatalf("open62541 found no security header: %+v", r.NetworkMessage)
	}
	if !s.Signed || s.Encrypted || s.SecurityTokenID != 4711 || s.Nonce != base64.StdEncoding.EncodeToString(dec.Security.MessageNonce) {
		t.Errorf("security header: open62541 %+v, go-opcua %+v", *s, *dec.Security)
	}
	r.NetworkMessage.Security = nil
	assertSameDesc(t, "payload of the signed message", describeUADP(t, nm, nil), *r.NetworkMessage)
}

// TestPubSubCodec_Open62541UADPSecurityHeader_GoDecodes: the security header
// of a message open62541 encodes, as go-opcua reads it. The codec has no keys
// (contract §14.9): open62541 writes the header fields and no signature, so
// go-opcua stops after the header (DecodeOptions.Accept), before it would
// verify the message.
func TestPubSubCodec_Open62541UADPSecurityHeader_GoDecodes(t *testing.T) {
	requirePubSubCodec(t)
	nm := uadpCodecCases()[1].nm // publisher-id-uint16
	nonce := []byte{1, 2, 3, 4, 0, 0, 0, 9}
	desc := describeUADP(t, nm, nil)
	desc.Security = &psSecurity{Signed: true, SecurityTokenID: 4711, Nonce: base64.StdEncoding.EncodeToString(nonce)}
	doc, err := json.Marshal(desc)
	if err != nil {
		t.Fatal(err)
	}
	r := psOpen62541.runCodec(t, "pubsub-uadp-encode", doc, "")
	var b64 string
	if err := json.Unmarshal(r.Encoded, &b64); err != nil {
		t.Fatalf("encoded %s: %v", r.Encoded, err)
	}
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("encoded %s: %v", b64, err)
	}
	var hdr *message.NetworkMessage
	_, err = uadp.Decode(b, &uadp.DecodeOptions{Accept: func(h *message.NetworkMessage) bool {
		hdr = h
		return false
	}})
	if !errors.Is(err, uadp.ErrFiltered) || hdr == nil {
		t.Fatalf("uadp.Decode of open62541's %x: %v", b, err)
	}
	s := hdr.Security
	if s == nil {
		t.Fatalf("go-opcua found no security header in open62541's %x", b)
	}
	if !s.Signed || s.Encrypted || s.ForceKeyReset || s.SecurityTokenID != 4711 || !bytes.Equal(s.MessageNonce, nonce) {
		t.Errorf("security header: go-opcua read %+v from open62541's %x", *s, b)
	}
	if !hdr.PublisherID.Equal(nm.PublisherID) {
		t.Errorf("publisher id: go-opcua read %v, open62541 was given %v", hdr.PublisherID, nm.PublisherID)
	}
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

func jsonCodecCases() []psCodecCase {
	hdr := ua.JSONDataSetMessageContentMaskDataSetWriterID | ua.JSONDataSetMessageContentMaskMetaDataVersion |
		ua.JSONDataSetMessageContentMaskSequenceNumber | ua.JSONDataSetMessageContentMaskTimestamp |
		ua.JSONDataSetMessageContentMaskStatus | ua.JSONDataSetMessageContentMaskMessageType
	nmHdr := ua.JSONNetworkMessageContentMaskNetworkMessageHeader | ua.JSONNetworkMessageContentMaskDataSetMessageHeader |
		ua.JSONNetworkMessageContentMaskPublisherID
	dsm := func(writer uint16, fcm ua.DataSetFieldContentMask, fields ...*message.Field) *message.DataSetMessage {
		return &message.DataSetMessage{DataSetWriterID: writer, Type: message.DataSetMessageKeyFrame, Valid: true,
			JSONMask: hdr, FieldContentMask: fcm, SequenceNumber: 4711, Timestamp: psTS, Status: 0,
			MetaDataVersion: ua.ConfigurationVersionDataType{MajorVersion: 1, MinorVersion: 2}, Fields: fields}
	}
	named := func(vals ...any) []*message.Field {
		fs := psFields(vals...)
		for i, f := range fs {
			f.Name = "F" + string(rune('a'+i))
		}
		return fs
	}
	var cases []psCodecCase
	add := func(name string, nm *message.NetworkMessage) { cases = append(cases, psCodecCase{name: name, nm: nm}) }

	str := &message.NetworkMessage{JSONMask: nmHdr | ua.JSONNetworkMessageContentMaskDataSetClassID, MessageID: "m-1",
		PublisherID: message.StringPublisherID("pub-a"), DataSetClassID: psClass,
		Messages: []*message.DataSetMessage{dsm(7, 0, named(true, int32(-5), int64(-9007199254740993), uint64(18446744073709551615),
			1.25, "JSON – Δ", psTSms, []byte("bytes"), psFGUID, []int32{1, 2, 3}, []string{"x", "y"})...)}}
	add("string-publisher-id-variant-fields", str)

	num := &message.NetworkMessage{JSONMask: nmHdr, MessageID: "m-2", PublisherID: message.NewPublisherID(message.PublisherIDUInt16, 2234),
		Messages: []*message.DataSetMessage{dsm(1, 0, named(int32(1))...)}}
	num.Messages[0].Status = 12345
	add("numeric-publisher-id-status", num)

	dvm := &message.NetworkMessage{JSONMask: nmHdr, MessageID: "m-3", PublisherID: message.NewPublisherID(message.PublisherIDUInt32, 3234567890),
		Messages: []*message.DataSetMessage{dsm(2, ua.DataSetFieldContentMaskStatusCode|ua.DataSetFieldContentMaskSourceTimestamp|ua.DataSetFieldContentMaskServerTimestamp,
			&message.Field{Name: "Temp", Value: &ua.DataValue{EncodingMask: ua.DataValueValue | ua.DataValueSourceTimestamp | ua.DataValueServerTimestamp,
				Value: ua.MustVariant(21.5), SourceTimestamp: psTS, ServerTimestamp: psTS.Add(time.Millisecond)}},
			&message.Field{Name: "Bad", Value: &ua.DataValue{EncodingMask: ua.DataValueValue | ua.DataValueStatusCode,
				Value: ua.MustVariant(int32(0)), Status: ua.StatusCode(0x80340000)}})}}
	add("datavalue-fields", dvm)

	multi := &message.NetworkMessage{JSONMask: nmHdr, MessageID: "m-4", PublisherID: message.StringPublisherID("multi"),
		Messages: []*message.DataSetMessage{dsm(1, 0, named(int32(1))...), dsm(2, 0, named("two", 2.0)...), dsm(3, 0, named([]bool{true})...)}}
	add("multiple-dataset-messages", multi)
	return cases
}

// jsonCaseMetaData is the DataSetMetaData of every DataSetMessage of nm
// (by DataSetWriterId): its fields with their names, types and ranks.
func jsonCaseMetaData(nm *message.NetworkMessage) map[uint16]*ua.DataSetMetaDataType {
	out := map[uint16]*ua.DataSetMetaDataType{}
	for _, d := range nm.Messages {
		md := &ua.DataSetMetaDataType{Name: "ds"}
		for _, f := range d.Fields {
			typ := uint32(f.Value.Value.Type())
			rank := int32(-1)
			if f.Value.Value.IsArray() {
				rank = 1
			}
			md.Fields = append(md.Fields, psFieldMeta(f.Name, typ, rank))
		}
		out[d.DataSetWriterID] = md
	}
	return out
}

// jsonCaseLookup is jsonCaseMetaData as a MetaDataLookup.
func jsonCaseLookup(nm *message.NetworkMessage) message.MetaDataLookup {
	mds := jsonCaseMetaData(nm)
	return func(_ message.PublisherID, _, w uint16) *ua.DataSetMetaDataType { return mds[w] }
}

// jsonCaseMeta is jsonCaseMetaData as the --metadata argument of the codec.
func jsonCaseMeta(t *testing.T, nm *message.NetworkMessage) string {
	t.Helper()
	type entry struct {
		DataSetWriterID uint16          `json:"dataSetWriterId"`
		MetaData        json.RawMessage `json:"metaData"`
	}
	var out []entry
	mds := jsonCaseMetaData(nm)
	for _, d := range nm.Messages {
		out = append(out, entry{d.DataSetWriterID, json.RawMessage(metaJSON(t, mds[d.DataSetWriterID]))})
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// TestPubSubCodec_GoEncodesJSON_Open62541Decodes: go-opcua's JSON
// NetworkMessages decoded by open62541.
func TestPubSubCodec_GoEncodesJSON_Open62541Decodes(t *testing.T) {
	requirePubSubCodec(t)
	psGoEncodesJSON(t, psOpen62541)
}

// psGoEncodesJSON: go-opcua's JSON NetworkMessages decoded by the peer; its
// description must be the message, and go-opcua must decode its re-encoding
// to the same message.
func psGoEncodesJSON(t *testing.T, p *psPeer) {
	for _, c := range jsonCodecCases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			psSkipUnsupported(t, p, "json/"+c.name)
			b, err := jsonmsg.Encode(c.nm, nil)
			if err != nil {
				t.Fatalf("jsonmsg.Encode: %v", err)
			}
			r := p.runCodec(t, "pubsub-json-decode", b, jsonCaseMeta(t, c.nm))
			if r.NetworkMessage == nil {
				t.Fatalf("no description")
			}
			assertSameDesc(t, p.name+"'s decoding of "+string(b), describeJSON(t, c.nm), *r.NetworkMessage)
			if r.Reencoded == nil {
				t.Fatalf("%s could not re-encode: %s", p.name, r.ReencodeStatusCode)
			}
			// The peer has the DataSetMetaData (--metadata), so may leave
			// out what it implies (UaType): decode with it too.
			back, err := jsonmsg.Decode([]byte(*r.Reencoded), &jsonmsg.DecodeOptions{MetaData: jsonCaseLookup(c.nm)})
			if gap, known := p.goDecodeGaps["json/"+c.name]; known {
				if err == nil {
					t.Errorf("listed as a go-opcua gap (%s) but go-opcua decodes %s", gap, *r.Reencoded)
				} else {
					t.Logf("known go-opcua gap: %s: %v", gap, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("jsonmsg.Decode of %s's re-encoding %s: %v", p.name, *r.Reencoded, err)
			}
			assertSameDesc(t, "go-opcua's decoding of "+p.name+"'s re-encoding "+*r.Reencoded, describeJSON(t, c.nm), describeJSON(t, back))
		})
	}
}

// TestPubSubCodec_Open62541EncodesJSON_GoDecodes: open62541's JSON
// NetworkMessages decoded by go-opcua.
func TestPubSubCodec_Open62541EncodesJSON_GoDecodes(t *testing.T) {
	requirePubSubCodec(t)
	psPeerEncodesJSON(t, psOpen62541)
}

// psPeerEncodesJSON: the peer encodes the description of every JSON case,
// go-opcua decodes it to the same message.
func psPeerEncodesJSON(t *testing.T, p *psPeer) {
	for _, c := range jsonCodecCases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			psSkipUnsupported(t, p, "json/"+c.name)
			want := describeJSON(t, c.nm)
			in := want
			in.Messages = append([]psDSM(nil), want.Messages...)
			// The description selects the field encoding per message.
			for i, d := range c.nm.Messages {
				if d.FieldContentMask == 0 {
					in.Messages[i].FieldEncoding = "Variant"
				}
			}
			// The publisher id keeps its width on encode.
			in.PublisherID = psPublisherIDOf(c.nm.PublisherID)
			doc, err := json.Marshal(in)
			if err != nil {
				t.Fatal(err)
			}
			r := p.runCodec(t, "pubsub-json-encode", doc, "")
			var text string
			if err := json.Unmarshal(r.Encoded, &text); err != nil {
				t.Fatalf("encoded %s: %v", r.Encoded, err)
			}
			got, err := jsonmsg.Decode([]byte(text), nil)
			if err != nil {
				t.Fatalf("jsonmsg.Decode of %s's %s: %v", p.name, text, err)
			}
			assertSameDesc(t, "go-opcua's decoding of "+p.name+"'s "+text, want, describeJSON(t, got))
		})
	}
}
