//go:build interop

// SPDX-License-Identifier: MIT

// The NetworkMessage description of the opcua-interop codec operations
// (docs/CLIENT_CONTRACT.md §14.9) and its conversion from and to the
// go-opcua model (pubsub/message). Not ledger evidence by itself.
//
// The description is what the open62541 adapter prints for a NetworkMessage
// it decoded ("pubsub-uadp-decode", "pubsub-json-decode") and what it builds
// a NetworkMessage from ("pubsub-uadp-encode", "pubsub-json-encode"). Field
// values use the canonical value encoding of the client contract (§7).

package interop

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/ua"
)

type psDesc struct {
	Mapping        string         `json:"mapping,omitempty"`
	Version        *int           `json:"version,omitempty"`
	MessageID      *string        `json:"messageId,omitempty"`
	PublisherID    *psPublisherID `json:"publisherId,omitempty"`
	DataSetClassID *string        `json:"dataSetClassId,omitempty"`
	GroupHeader    *psGroupHeader `json:"groupHeader,omitempty"`
	PayloadHeader  *bool          `json:"payloadHeader,omitempty"`
	Timestamp      *string        `json:"timestamp,omitempty"`
	Picoseconds    *uint16        `json:"picoseconds,omitempty"`
	PromotedFields []psField      `json:"promotedFields,omitempty"`
	Security       *psSecurity    `json:"security,omitempty"`
	Chunk          *bool          `json:"chunk,omitempty"`
	Messages       []psDSM        `json:"messages"`
}

type psPublisherID struct {
	Type  string          `json:"type"`
	Value json.RawMessage `json:"value"`
}

type psGroupHeader struct {
	WriterGroupID        *uint16 `json:"writerGroupId,omitempty"`
	GroupVersion         *uint32 `json:"groupVersion,omitempty"`
	NetworkMessageNumber *uint16 `json:"networkMessageNumber,omitempty"`
	SequenceNumber       *uint16 `json:"sequenceNumber,omitempty"`
}

type psSecurity struct {
	Signed             bool    `json:"signed"`
	Encrypted          bool    `json:"encrypted"`
	ForceKeyReset      bool    `json:"forceKeyReset"`
	SecurityTokenID    uint32  `json:"securityTokenId"`
	Nonce              string  `json:"nonce"`
	SecurityFooterSize *uint16 `json:"securityFooterSize,omitempty"`
}

type psConfigVersion struct {
	MajorVersion *uint32 `json:"majorVersion,omitempty"`
	MinorVersion *uint32 `json:"minorVersion,omitempty"`
}

type psDSM struct {
	DataSetWriterID *uint16          `json:"dataSetWriterId,omitempty"`
	MessageType     string           `json:"messageType"`
	FieldEncoding   string           `json:"fieldEncoding"`
	Valid           *bool            `json:"valid,omitempty"`
	SequenceNumber  *uint32          `json:"sequenceNumber,omitempty"`
	Timestamp       *string          `json:"timestamp,omitempty"`
	Picoseconds     *uint16          `json:"picoseconds,omitempty"`
	Status          *uint32          `json:"status,omitempty"`
	ConfigVersion   *psConfigVersion `json:"configVersion,omitempty"`
	Fields          []psField        `json:"fields,omitempty"`
}

type psStatus struct {
	Code uint32 `json:"code"`
}

type psField struct {
	Name              string          `json:"name,omitempty"`
	Index             *uint16         `json:"index,omitempty"`
	DataType          string          `json:"dataType"`
	BuiltInType       int             `json:"builtInType,omitempty"`
	ArrayDimensions   []uint32        `json:"arrayDimensions,omitempty"`
	Value             json.RawMessage `json:"value"`
	StatusCode        *psStatus       `json:"statusCode,omitempty"`
	SourceTimestamp   *string         `json:"sourceTimestamp,omitempty"`
	SourcePicoseconds *uint16         `json:"sourcePicoseconds,omitempty"`
	ServerTimestamp   *string         `json:"serverTimestamp,omitempty"`
	ServerPicoseconds *uint16         `json:"serverPicoseconds,omitempty"`
}

func ptr[T any](v T) *T { return &v }

// psTime formats a time as the description does: RFC 3339 UTC with 7
// fractional digits.
func psTime(t time.Time) string {
	t = t.UTC()
	return t.Format("2006-01-02T15:04:05") + fmt.Sprintf(".%07dZ", t.Nanosecond()/100)
}

func psParseTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("description timestamp %q: %v", s, err)
	}
	return v.UTC()
}

func psPublisherIDOf(p message.PublisherID) *psPublisherID {
	switch p.Type {
	case message.PublisherIDString:
		b, _ := json.Marshal(p.Str)
		return &psPublisherID{Type: "String", Value: b}
	case message.PublisherIDUInt64:
		return &psPublisherID{Type: "UInt64", Value: json.RawMessage(strconv.Quote(strconv.FormatUint(p.Num, 10)))}
	default:
		return &psPublisherID{Type: p.Type.String(), Value: json.RawMessage(strconv.FormatUint(p.Num, 10))}
	}
}

func (p *psPublisherID) model(t *testing.T) message.PublisherID {
	t.Helper()
	if p.Type == "String" {
		var s string
		if err := json.Unmarshal(p.Value, &s); err != nil {
			t.Fatalf("publisherId %s: %v", p.Value, err)
		}
		return message.StringPublisherID(s)
	}
	n, err := strconv.ParseUint(strings.Trim(string(p.Value), `"`), 10, 64)
	if err != nil {
		t.Fatalf("publisherId %s: %v", p.Value, err)
	}
	types := map[string]message.PublisherIDType{
		"Byte": message.PublisherIDByte, "UInt16": message.PublisherIDUInt16,
		"UInt32": message.PublisherIDUInt32, "UInt64": message.PublisherIDUInt64,
	}
	typ, ok := types[p.Type]
	if !ok {
		t.Fatalf("publisherId type %q", p.Type)
	}
	return message.NewPublisherID(typ, n)
}

// ---------------------------------------------------------------------------
// Values: ua.Variant <-> canonical value encoding (contract §7)
// ---------------------------------------------------------------------------

var psTypeNames = map[ua.TypeID]string{
	ua.TypeIDBoolean: "Boolean", ua.TypeIDSByte: "SByte", ua.TypeIDByte: "Byte",
	ua.TypeIDInt16: "Int16", ua.TypeIDUint16: "UInt16", ua.TypeIDInt32: "Int32",
	ua.TypeIDUint32: "UInt32", ua.TypeIDInt64: "Int64", ua.TypeIDUint64: "UInt64",
	ua.TypeIDFloat: "Float", ua.TypeIDDouble: "Double", ua.TypeIDString: "String",
	ua.TypeIDDateTime: "DateTime", ua.TypeIDGUID: "Guid", ua.TypeIDByteString: "ByteString",
	ua.TypeIDNodeID: "NodeId", ua.TypeIDStatusCode: "StatusCode",
	ua.TypeIDQualifiedName: "QualifiedName", ua.TypeIDLocalizedText: "LocalizedText",
}

func psTypeByName(name string) (ua.TypeID, bool) {
	for id, n := range psTypeNames {
		if n == name {
			return id, true
		}
	}
	return 0, false
}

// canonScalar encodes one scalar value.
func canonScalar(t *testing.T, v any) any {
	t.Helper()
	switch x := v.(type) {
	case int64:
		return strconv.FormatInt(x, 10)
	case uint64:
		return strconv.FormatUint(x, 10)
	case float32:
		if math.IsNaN(float64(x)) || math.IsInf(float64(x), 0) {
			return nil
		}
		return x
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return nil
		}
		return x
	case time.Time:
		return x.UTC().Format("2006-01-02T15:04:05.000Z")
	case *ua.GUID:
		return strings.ToLower(x.String())
	case []byte:
		return base64.StdEncoding.EncodeToString(x)
	case *ua.NodeID:
		return x.String()
	case ua.StatusCode:
		return map[string]any{"code": uint32(x)}
	case *ua.QualifiedName:
		return map[string]any{"ns": x.NamespaceIndex, "name": x.Name}
	case *ua.LocalizedText:
		return map[string]any{"locale": x.Locale, "text": x.Text}
	case bool, int8, uint8, int16, uint16, int32, uint32, string:
		return x
	}
	t.Fatalf("canonScalar: unsupported value %T", v)
	return nil
}

// toCanon returns the dataType, the value and the array dimensions (only
// for a matrix) of a Variant in the description.
func toCanon(t *testing.T, v *ua.Variant) (string, json.RawMessage, []uint32) {
	t.Helper()
	if v == nil || v.Value() == nil {
		return "Null", json.RawMessage("null"), nil
	}
	name, ok := psTypeNames[v.Type()]
	if !ok {
		t.Fatalf("toCanon: unsupported type %v", v.Type())
	}
	var out any
	var dims []uint32
	rv := reflect.ValueOf(v.Value())
	if v.Type() != ua.TypeIDByteString && rv.Kind() == reflect.Slice || v.Type() == ua.TypeIDByteString && rv.Kind() == reflect.Slice && rv.Type().Elem().Kind() == reflect.Slice {
		var flat []any
		var walk func(r reflect.Value, depth int)
		walk = func(r reflect.Value, depth int) {
			if len(dims) <= depth {
				dims = append(dims, uint32(r.Len()))
			}
			for i := 0; i < r.Len(); i++ {
				e := r.Index(i)
				if e.Kind() == reflect.Slice && (v.Type() != ua.TypeIDByteString || e.Type().Elem().Kind() != reflect.Uint8) {
					walk(e, depth+1)
					continue
				}
				flat = append(flat, canonScalar(t, e.Interface()))
			}
		}
		walk(rv, 0)
		if flat == nil {
			flat = []any{}
		}
		out = flat
		if len(dims) < 2 {
			dims = nil
		}
	} else {
		out = canonScalar(t, v.Value())
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("toCanon: %v", err)
	}
	return name, b, dims
}

func fromCanonScalar(t *testing.T, typ ua.TypeID, raw json.RawMessage) any {
	t.Helper()
	var err error
	str := func() string {
		var s string
		if err = json.Unmarshal(raw, &s); err != nil {
			t.Fatalf("value %s: want a string: %v", raw, err)
		}
		return s
	}
	num := func() float64 {
		if string(raw) == "null" {
			return math.NaN()
		}
		var f float64
		if err = json.Unmarshal(raw, &f); err != nil {
			t.Fatalf("value %s: want a number: %v", raw, err)
		}
		return f
	}
	switch typ {
	case ua.TypeIDBoolean:
		var b bool
		if err := json.Unmarshal(raw, &b); err != nil {
			t.Fatalf("value %s: %v", raw, err)
		}
		return b
	case ua.TypeIDSByte:
		return int8(num())
	case ua.TypeIDByte:
		return uint8(num())
	case ua.TypeIDInt16:
		return int16(num())
	case ua.TypeIDUint16:
		return uint16(num())
	case ua.TypeIDInt32:
		return int32(num())
	case ua.TypeIDUint32:
		return uint32(num())
	case ua.TypeIDInt64:
		n, err := strconv.ParseInt(str(), 10, 64)
		if err != nil {
			t.Fatalf("Int64 %s: %v", raw, err)
		}
		return n
	case ua.TypeIDUint64:
		n, err := strconv.ParseUint(str(), 10, 64)
		if err != nil {
			t.Fatalf("UInt64 %s: %v", raw, err)
		}
		return n
	case ua.TypeIDFloat:
		return float32(num())
	case ua.TypeIDDouble:
		return num()
	case ua.TypeIDString:
		return str()
	case ua.TypeIDDateTime:
		return psParseTime(t, str())
	case ua.TypeIDGUID:
		return ua.NewGUID(str())
	case ua.TypeIDByteString:
		b, err := base64.StdEncoding.DecodeString(str())
		if err != nil {
			t.Fatalf("ByteString %s: %v", raw, err)
		}
		return b
	case ua.TypeIDNodeID:
		id, err := ua.ParseNodeID(str())
		if err != nil {
			t.Fatalf("NodeId %s: %v", raw, err)
		}
		return id
	case ua.TypeIDStatusCode:
		var s psStatus
		if err := json.Unmarshal(raw, &s); err != nil {
			t.Fatalf("StatusCode %s: %v", raw, err)
		}
		return ua.StatusCode(s.Code)
	case ua.TypeIDQualifiedName:
		var q struct {
			NS   uint16 `json:"ns"`
			Name string `json:"name"`
		}
		if err := json.Unmarshal(raw, &q); err != nil {
			t.Fatalf("QualifiedName %s: %v", raw, err)
		}
		return &ua.QualifiedName{NamespaceIndex: q.NS, Name: q.Name}
	case ua.TypeIDLocalizedText:
		var l struct {
			Locale string `json:"locale"`
			Text   string `json:"text"`
		}
		if err := json.Unmarshal(raw, &l); err != nil {
			t.Fatalf("LocalizedText %s: %v", raw, err)
		}
		return ua.NewLocalizedTextWithLocale(l.Text, l.Locale)
	default:
	}
	t.Fatalf("fromCanonScalar: unsupported type %v", typ)
	return nil
}

// fromCanon builds the Variant of a description value.
func fromCanon(t *testing.T, dataType string, raw json.RawMessage, dims []uint32) *ua.Variant {
	t.Helper()
	if dataType == "Null" {
		return nil
	}
	typ, ok := psTypeByName(dataType)
	if !ok {
		t.Fatalf("fromCanon: unsupported dataType %q", dataType)
	}
	var arr []json.RawMessage
	if len(raw) > 0 && raw[0] == '[' {
		if err := json.Unmarshal(raw, &arr); err != nil {
			t.Fatalf("array value %s: %v", raw, err)
		}
		sample := reflect.TypeOf(fromCanonScalar(t, typ, zeroCanon(typ)))
		elems := make([]reflect.Value, len(arr))
		for i, e := range arr {
			elems[i] = reflect.ValueOf(fromCanonScalar(t, typ, e))
		}
		if len(dims) == 2 {
			outer := reflect.MakeSlice(reflect.SliceOf(reflect.SliceOf(sample)), int(dims[0]), int(dims[0]))
			for r := 0; r < int(dims[0]); r++ {
				row := reflect.MakeSlice(reflect.SliceOf(sample), int(dims[1]), int(dims[1]))
				for c := 0; c < int(dims[1]); c++ {
					row.Index(c).Set(elems[r*int(dims[1])+c])
				}
				outer.Index(r).Set(row)
			}
			return ua.MustVariant(outer.Interface())
		}
		s := reflect.MakeSlice(reflect.SliceOf(sample), len(elems), len(elems))
		for i, e := range elems {
			s.Index(i).Set(e)
		}
		return ua.MustVariant(s.Interface())
	}
	return ua.MustVariant(fromCanonScalar(t, typ, raw))
}

// zeroCanon is a canonical value of the type, used to find the Go type of
// array elements.
func zeroCanon(typ ua.TypeID) json.RawMessage {
	switch typ {
	case ua.TypeIDBoolean:
		return json.RawMessage("false")
	case ua.TypeIDInt64, ua.TypeIDUint64:
		return json.RawMessage(`"0"`)
	case ua.TypeIDString, ua.TypeIDByteString:
		return json.RawMessage(`""`)
	case ua.TypeIDDateTime:
		return json.RawMessage(`"2000-01-01T00:00:00Z"`)
	case ua.TypeIDGUID:
		return json.RawMessage(`"00000000-0000-0000-0000-000000000000"`)
	case ua.TypeIDNodeID:
		return json.RawMessage(`"i=0"`)
	case ua.TypeIDStatusCode:
		return json.RawMessage(`{"code":0}`)
	case ua.TypeIDQualifiedName:
		return json.RawMessage(`{"ns":0,"name":""}`)
	case ua.TypeIDLocalizedText:
		return json.RawMessage(`{"locale":"","text":""}`)
	default:
	}
	return json.RawMessage("0")
}

// variantKey is the comparison form of a value: its binary encoding.
func variantKey(t *testing.T, v *ua.Variant) string {
	t.Helper()
	if v == nil || v.Value() == nil {
		return "null"
	}
	if id, ok := v.Value().(*ua.NodeID); ok {
		short, err := ua.ParseNodeID(id.String())
		if err != nil {
			t.Fatalf("NodeId %s: %v", id, err)
		}
		v = ua.MustVariant(short)
	}
	b, err := v.Encode()
	if err != nil {
		t.Fatalf("encode %v: %v", v, err)
	}
	return hex.EncodeToString(b)
}

// ---------------------------------------------------------------------------
// Model -> description
// ---------------------------------------------------------------------------

var psMessageTypes = map[message.DataSetMessageType]string{
	message.DataSetMessageKeyFrame: "KeyFrame", message.DataSetMessageDeltaFrame: "DeltaFrame",
	message.DataSetMessageEvent: "Event", message.DataSetMessageKeepAlive: "KeepAlive",
}

var psFieldEncodings = map[message.FieldEncoding]string{
	message.FieldEncodingVariant: "Variant", message.FieldEncodingRawData: "RawData",
	message.FieldEncodingDataValue: "DataValue",
}

// psFieldOf describes one field. withDV adds the DataValue members.
func psFieldOf(t *testing.T, f *message.Field, name string, index *uint16, withDV bool) psField {
	t.Helper()
	var v *ua.Variant
	if f.Value != nil {
		v = f.Value.Value
	}
	dt, raw, dims := toCanon(t, v)
	pf := psField{Name: name, Index: index, DataType: dt, Value: raw, ArrayDimensions: dims}
	if withDV && f.Value != nil {
		dv := f.Value
		if dv.Has(ua.DataValueStatusCode) {
			pf.StatusCode = &psStatus{Code: uint32(dv.Status)}
		}
		if dv.Has(ua.DataValueSourceTimestamp) {
			pf.SourceTimestamp = ptr(psTime(dv.SourceTimestamp))
		}
		if dv.Has(ua.DataValueSourcePicoseconds) {
			pf.SourcePicoseconds = ptr(dv.SourcePicoseconds)
		}
		if dv.Has(ua.DataValueServerTimestamp) {
			pf.ServerTimestamp = ptr(psTime(dv.ServerTimestamp))
		}
		if dv.Has(ua.DataValueServerPicoseconds) {
			pf.ServerPicoseconds = ptr(dv.ServerPicoseconds)
		}
	}
	return pf
}

// psMetaNames returns the field names of a writer's metadata.
func psMetaNames(md message.MetaDataLookup, p message.PublisherID, wg, w uint16) []string {
	if md == nil {
		return nil
	}
	m := md(p, wg, w)
	if m == nil {
		return nil
	}
	var names []string
	for _, f := range m.Fields {
		names = append(names, f.Name)
	}
	return names
}

// describeUADP is the description of a UADP NetworkMessage as the adapter
// prints it after decoding (names from md, if given).
func describeUADP(t *testing.T, nm *message.NetworkMessage, md message.MetaDataLookup) psDesc {
	t.Helper()
	m := nm.UADPMask
	d := psDesc{Mapping: "uadp", Version: ptr(1), Chunk: ptr(false)}
	if m&ua.UADPNetworkMessageContentMaskPublisherID != 0 {
		d.PublisherID = psPublisherIDOf(nm.PublisherID)
	}
	if m&ua.UADPNetworkMessageContentMaskDataSetClassID != 0 {
		d.DataSetClassID = ptr(strings.ToLower(nm.DataSetClassID.String()))
	}
	if m&ua.UADPNetworkMessageContentMaskGroupHeader != 0 {
		g := &psGroupHeader{}
		if m&ua.UADPNetworkMessageContentMaskWriterGroupID != 0 {
			g.WriterGroupID = ptr(nm.GroupHeader.WriterGroupID)
		}
		if m&ua.UADPNetworkMessageContentMaskGroupVersion != 0 {
			g.GroupVersion = ptr(nm.GroupHeader.GroupVersion)
		}
		if m&ua.UADPNetworkMessageContentMaskNetworkMessageNumber != 0 {
			g.NetworkMessageNumber = ptr(nm.GroupHeader.NetworkMessageNumber)
		}
		if m&ua.UADPNetworkMessageContentMaskSequenceNumber != 0 {
			g.SequenceNumber = ptr(nm.GroupHeader.SequenceNumber)
		}
		d.GroupHeader = g
	}
	payloadHeader := m&ua.UADPNetworkMessageContentMaskPayloadHeader != 0
	d.PayloadHeader = ptr(payloadHeader)
	if m&ua.UADPNetworkMessageContentMaskTimestamp != 0 {
		d.Timestamp = ptr(psTime(nm.Timestamp))
	}
	if m&ua.UADPNetworkMessageContentMaskPicoSeconds != 0 {
		d.Picoseconds = ptr(nm.PicoSeconds)
	}
	if m&ua.UADPNetworkMessageContentMaskPromotedFields != 0 {
		for _, v := range nm.PromotedFields {
			d.PromotedFields = append(d.PromotedFields, psFieldOf(t, &message.Field{Value: &ua.DataValue{Value: v}}, "", nil, false))
		}
	}
	if s := nm.Security; s != nil {
		d.Security = &psSecurity{Signed: s.Signed, Encrypted: s.Encrypted, ForceKeyReset: s.ForceKeyReset,
			SecurityTokenID: s.SecurityTokenID, Nonce: base64.StdEncoding.EncodeToString(s.MessageNonce)}
		if s.FooterSize > 0 {
			d.Security.SecurityFooterSize = ptr(s.FooterSize)
		}
	}
	d.Messages = []psDSM{}
	for _, dsm := range nm.Messages {
		var names []string
		if payloadHeader {
			names = psMetaNames(md, nm.PublisherID, nm.GroupHeader.WriterGroupID, dsm.DataSetWriterID)
		} else {
			names = psMetaNames(md, nm.PublisherID, nm.GroupHeader.WriterGroupID, 0)
		}
		pd := psDSM{MessageType: psMessageTypes[dsm.Type], FieldEncoding: psFieldEncodings[dsm.FieldEncoding], Valid: ptr(dsm.Valid)}
		if payloadHeader {
			pd.DataSetWriterID = ptr(dsm.DataSetWriterID)
		}
		dm := dsm.UADPMask
		if dm&ua.UADPDataSetMessageContentMaskSequenceNumber != 0 {
			pd.SequenceNumber = ptr(dsm.SequenceNumber & 0xFFFF)
		}
		if dm&ua.UADPDataSetMessageContentMaskTimestamp != 0 {
			pd.Timestamp = ptr(psTime(dsm.Timestamp))
		}
		if dm&ua.UADPDataSetMessageContentMaskPicoSeconds != 0 {
			pd.Picoseconds = ptr(dsm.PicoSeconds)
		}
		if dm&ua.UADPDataSetMessageContentMaskStatus != 0 {
			pd.Status = ptr(uint32(dsm.Status) >> 16)
		}
		if dm&(ua.UADPDataSetMessageContentMaskMajorVersion|ua.UADPDataSetMessageContentMaskMinorVersion) != 0 {
			cv := &psConfigVersion{}
			if dm&ua.UADPDataSetMessageContentMaskMajorVersion != 0 {
				cv.MajorVersion = ptr(dsm.MetaDataVersion.MajorVersion)
			}
			if dm&ua.UADPDataSetMessageContentMaskMinorVersion != 0 {
				cv.MinorVersion = ptr(dsm.MetaDataVersion.MinorVersion)
			}
			pd.ConfigVersion = cv
		}
		withDV := dsm.FieldEncoding == message.FieldEncodingDataValue
		for i, f := range dsm.Fields {
			switch dsm.Type {
			case message.DataSetMessageKeyFrame:
				name := ""
				if i < len(names) {
					name = names[i]
				}
				pd.Fields = append(pd.Fields, psFieldOf(t, f, name, nil, withDV))
			case message.DataSetMessageDeltaFrame:
				name := ""
				if int(f.Index) < len(names) {
					name = names[f.Index]
				}
				pd.Fields = append(pd.Fields, psFieldOf(t, f, name, ptr(f.Index), withDV))
			default: // KeepAlive and Event: no fields in the description
			}
		}
		d.Messages = append(d.Messages, pd)
	}
	return d
}

// describeJSON is the description of a JSON NetworkMessage as the adapter
// prints it after decoding: numeric PublisherIds as UInt64 (JSON has no
// width), DataSetWriterIds always, every field encoding as DataValue.
func describeJSON(t *testing.T, nm *message.NetworkMessage) psDesc {
	t.Helper()
	d := psDesc{Mapping: "json", Messages: []psDSM{}}
	if nm.MessageID != "" {
		d.MessageID = ptr(nm.MessageID)
	}
	if nm.JSONMask&ua.JSONNetworkMessageContentMaskPublisherID != 0 {
		p := nm.PublisherID
		if p.Type != message.PublisherIDString {
			p = message.NewPublisherID(message.PublisherIDUInt64, p.Num)
		}
		d.PublisherID = psPublisherIDOf(p)
	}
	if nm.JSONMask&ua.JSONNetworkMessageContentMaskDataSetClassID != 0 {
		d.DataSetClassID = ptr(strings.ToLower(nm.DataSetClassID.String()))
	}
	for _, dsm := range nm.Messages {
		pd := psDSM{DataSetWriterID: ptr(dsm.DataSetWriterID), MessageType: psMessageTypes[dsm.Type],
			FieldEncoding: "DataValue", Valid: ptr(true)}
		jm := dsm.JSONMask
		if jm&ua.JSONDataSetMessageContentMaskSequenceNumber != 0 {
			pd.SequenceNumber = ptr(dsm.SequenceNumber)
		}
		if jm&ua.JSONDataSetMessageContentMaskTimestamp != 0 {
			pd.Timestamp = ptr(psTime(dsm.Timestamp))
		}
		if jm&ua.JSONDataSetMessageContentMaskStatus != 0 {
			pd.Status = ptr(uint32(dsm.Status))
		}
		if jm&ua.JSONDataSetMessageContentMaskMetaDataVersion != 0 {
			pd.ConfigVersion = &psConfigVersion{MajorVersion: ptr(dsm.MetaDataVersion.MajorVersion), MinorVersion: ptr(dsm.MetaDataVersion.MinorVersion)}
		}
		withDV := dsm.FieldContentMask&ua.DataSetFieldContentMaskRawData == 0
		for _, f := range dsm.Fields {
			pd.Fields = append(pd.Fields, psFieldOf(t, f, f.Name, nil, withDV))
		}
		d.Messages = append(d.Messages, pd)
	}
	return d
}

// psComparable replaces every value of a description by the binary
// encoding of the Variant it denotes, so that descriptions compare by
// value (0.1 is 0.10000000000000001 in open62541's %.17g).
func psComparable(t *testing.T, d psDesc) string {
	t.Helper()
	conv := func(fs []psField) []psField {
		out := make([]psField, len(fs))
		for i, f := range fs {
			key := variantKey(t, fromCanon(t, f.DataType, f.Value, f.ArrayDimensions))
			f.Value = json.RawMessage(strconv.Quote(key))
			f.BuiltInType = 0
			if len(f.ArrayDimensions) < 2 {
				f.ArrayDimensions = nil
			}
			out[i] = f
		}
		return out
	}
	d.PromotedFields = conv(d.PromotedFields)
	msgs := make([]psDSM, len(d.Messages))
	for i, m := range d.Messages {
		m.Fields = conv(m.Fields)
		msgs[i] = m
	}
	d.Messages = msgs
	b, err := json.MarshalIndent(d, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// assertSameDesc fails when two descriptions differ in any member or value.
func assertSameDesc(t *testing.T, what string, want, got psDesc) {
	t.Helper()
	w, g := psComparable(t, want), psComparable(t, got)
	if w != g {
		t.Errorf("%s: descriptions differ\nwant %s\ngot  %s", what, w, g)
	}
}

// metaJSON is the DataSetMetaDataType of fields in the OPC UA JSON encoding
// the codec's --metadata takes.
func metaJSON(t *testing.T, md *ua.DataSetMetaDataType) string {
	t.Helper()
	type field struct {
		Name            string   `json:"Name"`
		BuiltInType     uint8    `json:"BuiltInType"`
		DataType        string   `json:"DataType"`
		ValueRank       int32    `json:"ValueRank"`
		ArrayDimensions []uint32 `json:"ArrayDimensions,omitempty"`
		MaxStringLength uint32   `json:"MaxStringLength,omitempty"`
	}
	out := struct {
		Name   string  `json:"Name"`
		Fields []field `json:"Fields"`
	}{Name: md.Name}
	for _, f := range md.Fields {
		out.Fields = append(out.Fields, field{Name: f.Name, BuiltInType: f.BuiltInType, DataType: f.DataType.String(),
			ValueRank: f.ValueRank, ArrayDimensions: f.ArrayDimensions, MaxStringLength: f.MaxStringLength})
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
