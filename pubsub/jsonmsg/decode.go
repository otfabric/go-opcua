// SPDX-License-Identifier: MIT

package jsonmsg

import (
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/ua"
)

// Decode decodes a "ua-data" JSON NetworkMessage, or the content of its
// Messages member when the publisher omitted the network message header: an
// array of DataSetMessages, a single DataSetMessage, or a bare Payload object.
//
// The masks of the result report what was found: nm.JSONMask has the
// NetworkMessageHeader bit if the header was present, the
// DataSetMessageHeader bit if the DataSetMessages had a header, the
// SingleDataSetMessage bit if Messages was an object; each DataSetMessage's
// JSONMask has the bits of its header members and FieldContentMask the
// encoding of its fields (no bit for Variant fields, the DataValue bits found,
// RawData for bare values).
//
// With opts.MetaData the fields of a DataSetMessage are matched to the
// DataSetMetaData of its writer by name: Field.Index is the position in the
// metadata, the fields are sorted by it, RawData fields get the type of the
// metadata, and a field the metadata does not know is an error. Without
// metadata Field.Index is the position in the Payload and RawData fields are
// typed after their JSON form (Boolean, Int64, Double, String or arrays of
// these; other values are kept as their JSON text in a String).
//
// A well-formed message of another type returns an
// [*UnsupportedMessageTypeError]; malformed input returns an error wrapping
// [ErrDecode]. Decode never panics.
func Decode(b []byte, opts *DecodeOptions) (*message.NetworkMessage, error) {
	if opts == nil {
		opts = &DecodeOptions{}
	}
	if len(b) > opts.maxMessageSize() {
		return nil, errorf("message of %d bytes exceeds the limit of %d", len(b), opts.maxMessageSize())
	}
	if !json.Valid(b) {
		return nil, errorf("invalid JSON")
	}
	d := &decoder{opts: opts, co: opts.codecOptions()}
	nm := &message.NetworkMessage{Type: message.NetworkMessageDataSet}
	if opts.PublisherID != nil {
		nm.PublisherID = *opts.PublisherID
	}
	switch kind(b) {
	case '[':
		return nm, d.messages(nm, b)
	case '{':
	default:
		return nil, errorf("a NetworkMessage must be a JSON object or array")
	}
	ms, err := objectMembers(b, math.MaxInt32)
	if err != nil {
		return nil, err
	}
	if raw, ok := lookup(ms, "MessageType"); ok {
		t, err := stringValue(raw, "MessageType")
		if err != nil {
			return nil, err
		}
		switch t {
		case MessageTypeData:
			return nm, d.networkMessage(nm, ms)
		case MessageTypeKeyFrame, MessageTypeDeltaFrame, MessageTypeEvent, MessageTypeKeepAlive:
			// A DataSetMessage without the network message header.
			nm.JSONMask |= ua.JSONNetworkMessageContentMaskSingleDataSetMessage
			return nm, d.messages(nm, b)
		case "":
		default:
			return nil, &UnsupportedMessageTypeError{MessageType: t}
		}
	}
	if _, ok := lookup(ms, "Messages"); ok {
		return nm, d.networkMessage(nm, ms)
	}
	nm.JSONMask |= ua.JSONNetworkMessageContentMaskSingleDataSetMessage
	return nm, d.messages(nm, b)
}

type decoder struct {
	opts *DecodeOptions
	co   []ua.CodecOption
}

func (d *decoder) networkMessage(nm *message.NetworkMessage, ms []member) error {
	nm.JSONMask |= ua.JSONNetworkMessageContentMaskNetworkMessageHeader
	var messages json.RawMessage
	for _, m := range ms {
		var err error
		switch m.key {
		case "MessageId":
			nm.MessageID, err = stringValue(m.val, "MessageId")
		case "PublisherId":
			if isNull(m.val) {
				continue
			}
			nm.PublisherID, err = publisherIDValue(m.val)
			nm.JSONMask |= ua.JSONNetworkMessageContentMaskPublisherID
		case "WriterGroupName":
			nm.WriterGroupName, err = stringValue(m.val, "WriterGroupName")
			nm.JSONMask |= ua.JSONNetworkMessageContentMaskWriterGroupName
		case "DataSetClassId":
			if isNull(m.val) {
				continue
			}
			var g ua.GUID
			if err = ua.DecodeJSON(m.val, &g); err != nil {
				return errorf("DataSetClassId: %v", err)
			}
			nm.DataSetClassID = &g
			nm.JSONMask |= ua.JSONNetworkMessageContentMaskDataSetClassID
		case "ReplyTo":
			nm.ReplyTo, err = stringValue(m.val, "ReplyTo")
			nm.JSONMask |= ua.JSONNetworkMessageContentMaskReplyTo
		case "Messages":
			messages = m.val
		}
		if err != nil {
			return err
		}
	}
	if messages == nil || isNull(messages) {
		return nil
	}
	if kind(messages) == '{' {
		nm.JSONMask |= ua.JSONNetworkMessageContentMaskSingleDataSetMessage
	}
	return d.messages(nm, messages)
}

// messages decodes the content of Messages: an array of DataSetMessages or a
// single one.
func (d *decoder) messages(nm *message.NetworkMessage, raw json.RawMessage) error {
	var elems []json.RawMessage
	switch kind(raw) {
	case '[':
		var err error
		if elems, err = arrayElements(raw, d.opts.maxDataSetMessages()); err != nil {
			return err
		}
	case '{':
		elems = []json.RawMessage{raw}
	default:
		return errorf("Messages must be an array or an object")
	}
	nm.Messages = make([]*message.DataSetMessage, 0, len(elems))
	for _, e := range elems {
		if kind(e) != '{' {
			return errorf("a DataSetMessage must be a JSON object")
		}
		ms, err := objectMembers(e, d.opts.maxFields()+16)
		if err != nil {
			return err
		}
		var dsm *message.DataSetMessage
		if isDataSetMessage(ms) {
			nm.JSONMask |= ua.JSONNetworkMessageContentMaskDataSetMessageHeader
			dsm, err = d.dataSetMessage(nm, ms)
		} else {
			dsm = d.newDataSetMessage()
			err = d.payload(nm, dsm, ms)
		}
		if err != nil {
			return err
		}
		nm.Messages = append(nm.Messages, dsm)
	}
	return nil
}

// dsmHeaderKeys are the members of a DataSetMessage other than Payload.
var dsmHeaderKeys = map[string]bool{
	"DataSetWriterId": true, "DataSetWriterName": true, "PublisherId": true,
	"WriterGroupName": true, "SequenceNumber": true, "MetaDataVersion": true,
	"MinorVersion": true, "Timestamp": true, "Status": true, "MessageType": true,
}

// isDataSetMessage tells a DataSetMessage with header from a bare Payload.
func isDataSetMessage(ms []member) bool {
	if _, ok := lookup(ms, "Payload"); ok {
		return true
	}
	if raw, ok := lookup(ms, "MessageType"); ok {
		if s, err := stringValue(raw, ""); err == nil && strings.HasPrefix(s, "ua-") {
			return true
		}
	}
	if _, ok := lookup(ms, "DataSetWriterId"); !ok {
		return false
	}
	for _, m := range ms {
		if !dsmHeaderKeys[m.key] {
			return false
		}
	}
	return true
}

func (d *decoder) newDataSetMessage() *message.DataSetMessage {
	return &message.DataSetMessage{
		DataSetWriterID: d.opts.DataSetWriterID,
		Type:            message.DataSetMessageKeyFrame,
		Valid:           true,
	}
}

func (d *decoder) dataSetMessage(nm *message.NetworkMessage, ms []member) (*message.DataSetMessage, error) {
	dsm := d.newDataSetMessage()
	var payload json.RawMessage
	for _, m := range ms {
		var (
			err error
			n   uint64
		)
		switch m.key {
		case "DataSetWriterId":
			n, err = uintValue(m.val, "DataSetWriterId", math.MaxUint16)
			dsm.DataSetWriterID = uint16(n)
			dsm.JSONMask |= ua.JSONDataSetMessageContentMaskDataSetWriterID
		case "DataSetWriterName":
			dsm.DataSetWriterName, err = stringValue(m.val, "DataSetWriterName")
			dsm.JSONMask |= ua.JSONDataSetMessageContentMaskDataSetWriterName
		case "PublisherId":
			if isNull(m.val) {
				continue
			}
			var p message.PublisherID
			p, err = publisherIDValue(m.val)
			dsm.PublisherID = &p
			dsm.JSONMask |= ua.JSONDataSetMessageContentMaskPublisherID
		case "WriterGroupName":
			dsm.WriterGroupName, err = stringValue(m.val, "WriterGroupName")
			dsm.JSONMask |= ua.JSONDataSetMessageContentMaskWriterGroupName
		case "SequenceNumber":
			n, err = uintValue(m.val, "SequenceNumber", math.MaxUint32)
			dsm.SequenceNumber = uint32(n)
			dsm.JSONMask |= ua.JSONDataSetMessageContentMaskSequenceNumber
		case "MetaDataVersion":
			var v ua.ConfigurationVersionDataType
			if err = ua.DecodeJSON(m.val, &v); err != nil {
				return nil, errorf("MetaDataVersion: %v", err)
			}
			dsm.MetaDataVersion = v
			dsm.JSONMask |= ua.JSONDataSetMessageContentMaskMetaDataVersion
		case "MinorVersion":
			n, err = uintValue(m.val, "MinorVersion", math.MaxUint32)
			if dsm.JSONMask&ua.JSONDataSetMessageContentMaskMetaDataVersion == 0 {
				dsm.MetaDataVersion.MinorVersion = uint32(n)
			}
			dsm.JSONMask |= ua.JSONDataSetMessageContentMaskMinorVersion
		case "Timestamp":
			dsm.Timestamp, err = timeValue(m.val, "Timestamp", d.co)
			dsm.JSONMask |= ua.JSONDataSetMessageContentMaskTimestamp
		case "Status":
			dsm.Status, err = statusValue(m.val, "Status")
			dsm.JSONMask |= ua.JSONDataSetMessageContentMaskStatus
		case "MessageType":
			var t string
			if t, err = stringValue(m.val, "MessageType"); err != nil {
				return nil, err
			}
			switch t {
			case MessageTypeKeyFrame, "":
				dsm.Type = message.DataSetMessageKeyFrame
			case MessageTypeDeltaFrame:
				dsm.Type = message.DataSetMessageDeltaFrame
			case MessageTypeEvent:
				dsm.Type = message.DataSetMessageEvent
			case MessageTypeKeepAlive:
				dsm.Type = message.DataSetMessageKeepAlive
			default:
				return nil, &UnsupportedMessageTypeError{MessageType: t}
			}
			dsm.JSONMask |= ua.JSONDataSetMessageContentMaskMessageType
		case "Payload":
			payload = m.val
		}
		if err != nil {
			return nil, err
		}
	}
	if payload == nil || isNull(payload) {
		return dsm, nil
	}
	if kind(payload) != '{' {
		return nil, errorf("Payload must be a JSON object")
	}
	pms, err := objectMembers(payload, d.opts.maxFields())
	if err != nil {
		return nil, err
	}
	return dsm, d.payload(nm, dsm, pms)
}

// payload decodes the fields of a DataSetMessage.
func (d *decoder) payload(nm *message.NetworkMessage, dsm *message.DataSetMessage, ms []member) error {
	if len(ms) > d.opts.maxFields() {
		return errorf("more than %d fields", d.opts.maxFields())
	}
	var md *ua.DataSetMetaDataType
	if d.opts.MetaData != nil {
		p := nm.PublisherID
		if dsm.PublisherID != nil {
			p = *dsm.PublisherID
		}
		md = d.opts.MetaData(p, 0, dsm.DataSetWriterID)
	}
	var byName map[string]int
	if md != nil {
		byName = make(map[string]int, len(md.Fields))
		for i, f := range md.Fields {
			if f != nil {
				byName[f.Name] = i
			}
		}
	}
	dsm.Fields = make([]*message.Field, 0, len(ms))
	for i, m := range ms {
		f := &message.Field{Index: uint16(i), Name: m.key}
		var fmd *ua.FieldMetaData
		if md != nil {
			idx, ok := byName[m.key]
			if !ok {
				return errorf("field %q is not in the DataSetMetaData of writer %d", m.key, dsm.DataSetWriterID)
			}
			if idx > math.MaxUint16 {
				return errorf("field %q has index %d", m.key, idx)
			}
			f.Index = uint16(idx)
			fmd = md.Fields[idx]
		}
		dv, fm, err := d.field(m.val, fmd)
		if err != nil {
			return errorf("field %q: %v", m.key, err)
		}
		f.Value = dv
		dsm.FieldContentMask |= fm
		dsm.Fields = append(dsm.Fields, f)
	}
	if md != nil {
		sort.SliceStable(dsm.Fields, func(i, j int) bool { return dsm.Fields[i].Index < dsm.Fields[j].Index })
	}
	return nil
}

// dataValueKeys are the members of a DataValue or Variant in the 1.05 and
// 1.04 encodings.
var dataValueKeys = map[string]bool{
	"UaType": true, "Value": true, "Dimensions": true, "Status": true,
	"SourceTimestamp": true, "SourcePicoseconds": true,
	"ServerTimestamp": true, "ServerPicoseconds": true,
	"Type": true, "Body": true,
}

// field decodes one field value and reports its encoding.
func (d *decoder) field(raw json.RawMessage, fmd *ua.FieldMetaData) (*ua.DataValue, ua.DataSetFieldContentMask, error) {
	if isNull(raw) {
		return &ua.DataValue{}, 0, nil
	}
	if kind(raw) == '{' {
		ms, err := objectMembers(raw, 64)
		structure := fmd != nil && fmd.BuiltInType == byte(ua.TypeIDExtensionObject)
		if err == nil && isDataValueShape(ms) && (len(ms) > 0 || !structure) {
			return d.dataValue(raw, ms)
		}
	}
	v, err := d.rawValue(raw, fmd)
	if err != nil {
		return nil, 0, err
	}
	return &ua.DataValue{EncodingMask: ua.DataValueValue, Value: v}, ua.DataSetFieldContentMaskRawData, nil
}

func isDataValueShape(ms []member) bool {
	for _, m := range ms {
		if !dataValueKeys[m.key] {
			return false
		}
	}
	return true
}

func (d *decoder) dataValue(raw json.RawMessage, ms []member) (*ua.DataValue, ua.DataSetFieldContentMask, error) {
	// The 1.04 reversible Variant {"Type":..,"Body":..} at the top level.
	if _, ok := lookup(ms, "Type"); ok {
		var v ua.Variant
		if err := ua.DecodeJSON(raw, &v, d.co...); err != nil {
			return nil, 0, err
		}
		return &ua.DataValue{EncodingMask: ua.DataValueValue, Value: &v}, 0, nil
	}
	var dv ua.DataValue
	if err := ua.DecodeJSON(raw, &dv, d.co...); err != nil {
		return nil, 0, err
	}
	var fm ua.DataSetFieldContentMask
	if dv.Has(ua.DataValueStatusCode) {
		fm |= ua.DataSetFieldContentMaskStatusCode
	}
	if dv.Has(ua.DataValueSourceTimestamp) {
		fm |= ua.DataSetFieldContentMaskSourceTimestamp
	}
	if dv.Has(ua.DataValueServerTimestamp) {
		fm |= ua.DataSetFieldContentMaskServerTimestamp
	}
	if dv.Has(ua.DataValueSourcePicoseconds) {
		fm |= ua.DataSetFieldContentMaskSourcePicoSeconds
	}
	if dv.Has(ua.DataValueServerPicoseconds) {
		fm |= ua.DataSetFieldContentMaskServerPicoSeconds
	}
	return &dv, fm, nil
}

// rawValue decodes a RawData field: with metadata as its declared type,
// without by its JSON form.
func (d *decoder) rawValue(raw json.RawMessage, fmd *ua.FieldMetaData) (*ua.Variant, error) {
	bt := byte(0)
	if fmd != nil {
		bt = fmd.BuiltInType
	}
	switch {
	case bt == byte(ua.TypeIDVariant):
		// BaseDataType: a Variant if it is one, else typed by its form.
		var v ua.Variant
		if kind(raw) == '{' && ua.DecodeJSON(raw, &v, d.co...) == nil && v.Value() != nil {
			return &v, nil
		}
	case bt > 0 && bt <= byte(ua.TypeIDDiagnosticInfo):
		value := raw
		if bt == byte(ua.TypeIDExtensionObject) && kind(raw) == '{' && fmd.DataType != nil {
			// The structure without its UaTypeId: add the DataType.
			if ms, err := objectMembers(raw, math.MaxInt32); err == nil {
				if _, ok := lookup(ms, "UaTypeId"); !ok {
					id, err := ua.EncodeJSON(fmd.DataType, d.co...)
					if err != nil {
						return nil, err
					}
					value = append(append(append([]byte(`{"UaTypeId":`), id...), ','), raw[1:]...)
					if len(ms) == 0 {
						value = append(append([]byte(`{"UaTypeId":`), id...), '}')
					}
				}
			}
		}
		doc := make([]byte, 0, len(value)+32)
		doc = append(doc, `{"UaType":`...)
		doc = strconv.AppendUint(doc, uint64(bt), 10)
		doc = append(doc, `,"Value":`...)
		doc = append(doc, value...)
		doc = append(doc, '}')
		var v ua.Variant
		if err := ua.DecodeJSON(doc, &v, d.co...); err != nil {
			return nil, err
		}
		return &v, nil
	}
	return inferValue(raw)
}

// inferValue types a RawData value without metadata.
func inferValue(raw json.RawMessage) (*ua.Variant, error) {
	var x interface{}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&x); err != nil {
		return nil, err
	}
	switch v := x.(type) {
	case bool:
		return ua.NewVariant(v)
	case string:
		return ua.NewVariant(v)
	case json.Number:
		return ua.NewVariant(number(v))
	case []interface{}:
		if arr := inferArray(v); arr != nil {
			return ua.NewVariant(arr)
		}
	}
	return ua.NewVariant(string(raw))
}

func number(n json.Number) interface{} {
	if i, err := n.Int64(); err == nil {
		return i
	}
	f, _ := n.Float64()
	return f
}

// inferArray returns a typed slice for an array whose elements share one
// JSON type, nil otherwise.
func inferArray(v []interface{}) interface{} {
	if len(v) == 0 {
		return nil
	}
	switch v[0].(type) {
	case bool:
		out := make([]bool, len(v))
		for i, e := range v {
			b, ok := e.(bool)
			if !ok {
				return nil
			}
			out[i] = b
		}
		return out
	case string:
		out := make([]string, len(v))
		for i, e := range v {
			s, ok := e.(string)
			if !ok {
				return nil
			}
			out[i] = s
		}
		return out
	case json.Number:
		ints := make([]int64, len(v))
		floats := make([]float64, len(v))
		allInt := true
		for i, e := range v {
			n, ok := e.(json.Number)
			if !ok {
				return nil
			}
			if iv, err := n.Int64(); err == nil {
				ints[i] = iv
			} else {
				allInt = false
			}
			floats[i], _ = n.Float64()
		}
		if allInt {
			return ints
		}
		return floats
	}
	return nil
}

// publisherIDValue decodes a PublisherId: a string (Part 14 1.05, open62541)
// or a number (1.04 implementations).
func publisherIDValue(raw json.RawMessage) (message.PublisherID, error) {
	if kind(raw) == '"' {
		s, err := stringValue(raw, "PublisherId")
		if err != nil {
			return message.PublisherID{}, err
		}
		if isDecimal(s) {
			if n, err := strconv.ParseUint(s, 10, 64); err == nil {
				return message.NewPublisherID(message.PublisherIDUInt64, n), nil
			}
		}
		return message.StringPublisherID(s), nil
	}
	n, err := uintValue(raw, "PublisherId", math.MaxUint64)
	if err != nil {
		return message.PublisherID{}, err
	}
	return message.NewPublisherID(message.PublisherIDUInt64, n), nil
}

func isDecimal(s string) bool {
	if s == "" || len(s) > 20 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
