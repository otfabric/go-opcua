// SPDX-License-Identifier: MIT

package jsonmsg

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/google/uuid"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/ua"
)

// Encode encodes a NetworkMessage of type NetworkMessageDataSet as a
// "ua-data" JSON message, following nm.JSONMask and the JSONMask and
// FieldContentMask of each DataSetMessage, or, with nm.Action set, as a
// "ua-action-request" or "ua-action-response" message (see Actions in the
// package documentation).
//
// With the NetworkMessageHeader bit a missing MessageID is generated (it is
// mandatory). Without the NetworkMessageHeader bit the result is the array of
// DataSetMessages, or the single DataSetMessage with the SingleDataSetMessage
// bit. The SingleDataSetMessage bit requires exactly one DataSetMessage.
func Encode(nm *message.NetworkMessage, opts *EncodeOptions) ([]byte, error) {
	if nm == nil {
		return nil, errors.New("pubsub/jsonmsg: nil NetworkMessage")
	}
	if nm.Type != message.NetworkMessageDataSet {
		return nil, fmt.Errorf("pubsub/jsonmsg: cannot encode a NetworkMessage of type %d as JSON", nm.Type)
	}
	if opts == nil {
		opts = &EncodeOptions{}
	}
	if nm.Action != nil {
		e := &encoder{opts: opts, nm: nm}
		return e.encodeAction()
	}
	mask := nm.JSONMask
	single := mask&ua.JSONNetworkMessageContentMaskSingleDataSetMessage != 0
	if single && len(nm.Messages) != 1 {
		return nil, fmt.Errorf("pubsub/jsonmsg: SingleDataSetMessage needs exactly one DataSetMessage, have %d", len(nm.Messages))
	}
	e := &encoder{opts: opts, nm: nm}
	if mask&ua.JSONNetworkMessageContentMaskNetworkMessageHeader != 0 {
		o := e.object()
		id := nm.MessageID
		if id == "" {
			id = uuid.NewString()
		}
		o.key("MessageId")
		e.str(id)
		o.key("MessageType")
		e.str(MessageTypeData)
		if mask&ua.JSONNetworkMessageContentMaskPublisherID != 0 {
			o.key("PublisherId")
			e.publisherID(nm.PublisherID)
		}
		if mask&ua.JSONNetworkMessageContentMaskWriterGroupName != 0 {
			o.key("WriterGroupName")
			e.str(nm.WriterGroupName)
		}
		if mask&ua.JSONNetworkMessageContentMaskDataSetClassID != 0 && nm.DataSetClassID != nil {
			o.key("DataSetClassId")
			if err := e.value(nm.DataSetClassID); err != nil {
				return nil, err
			}
		}
		if mask&ua.JSONNetworkMessageContentMaskReplyTo != 0 && nm.ReplyTo != "" {
			o.key("ReplyTo")
			e.str(nm.ReplyTo)
		}
		o.key("Messages")
		if err := e.messages(single); err != nil {
			return nil, err
		}
		o.end()
	} else if err := e.messages(single); err != nil {
		return nil, err
	}
	return e.buf.Bytes(), nil
}

type encoder struct {
	buf  bytes.Buffer
	opts *EncodeOptions
	nm   *message.NetworkMessage
}

type object struct {
	e     *encoder
	first bool
}

func (e *encoder) object() *object {
	e.buf.WriteByte('{')
	return &object{e: e, first: true}
}

func (o *object) key(k string) {
	if !o.first {
		o.e.buf.WriteByte(',')
	}
	o.first = false
	o.e.str(k)
	o.e.buf.WriteByte(':')
}

func (o *object) end() { o.e.buf.WriteByte('}') }

func (e *encoder) str(s string) {
	b, _ := ua.EncodeJSON(s) // never fails for a string
	e.buf.Write(b)
}

func (e *encoder) uint(n uint64) { e.buf.WriteString(strconv.FormatUint(n, 10)) }

func (e *encoder) codecOptions(verbose bool) []ua.CodecOption {
	var co []ua.CodecOption
	if e.opts.NamespaceArray != nil {
		co = append(co, ua.WithNamespaceArray(e.opts.NamespaceArray))
	}
	if verbose {
		co = append(co, ua.WithJSONForm(ua.JSONVerbose))
	}
	return co
}

func (e *encoder) value(v interface{}) error {
	b, err := ua.EncodeJSON(v, e.codecOptions(false)...)
	if err != nil {
		return fmt.Errorf("pubsub/jsonmsg: %w", err)
	}
	e.buf.Write(b)
	return nil
}

func (e *encoder) publisherID(p message.PublisherID) {
	if p.Type != message.PublisherIDString && e.opts.NumericPublisherID {
		e.uint(p.Num)
		return
	}
	e.str(p.String())
}

func (e *encoder) messages(single bool) error {
	if single {
		return e.dataSetMessage(e.nm.Messages[0])
	}
	e.buf.WriteByte('[')
	for i, m := range e.nm.Messages {
		if i > 0 {
			e.buf.WriteByte(',')
		}
		if err := e.dataSetMessage(m); err != nil {
			return err
		}
	}
	e.buf.WriteByte(']')
	return nil
}

func dataSetMessageTypeName(t message.DataSetMessageType) (string, error) {
	switch t {
	case message.DataSetMessageKeyFrame:
		return MessageTypeKeyFrame, nil
	case message.DataSetMessageDeltaFrame:
		return MessageTypeDeltaFrame, nil
	case message.DataSetMessageEvent:
		return MessageTypeEvent, nil
	case message.DataSetMessageKeepAlive:
		return MessageTypeKeepAlive, nil
	}
	return "", fmt.Errorf("pubsub/jsonmsg: unknown DataSetMessage type %d", t)
}

func (e *encoder) dataSetMessage(m *message.DataSetMessage) error {
	if m == nil {
		return errors.New("pubsub/jsonmsg: nil DataSetMessage")
	}
	typeName, err := dataSetMessageTypeName(m.Type)
	if err != nil {
		return err
	}
	if e.nm.JSONMask&ua.JSONNetworkMessageContentMaskDataSetMessageHeader == 0 {
		if m.Type == message.DataSetMessageKeepAlive {
			return errors.New("pubsub/jsonmsg: a keep-alive DataSetMessage needs the DataSetMessageHeader")
		}
		return e.payload(m)
	}
	mask := m.JSONMask
	o := e.object()
	if mask&ua.JSONDataSetMessageContentMaskDataSetWriterID != 0 {
		o.key("DataSetWriterId")
		e.uint(uint64(m.DataSetWriterID))
	}
	if mask&ua.JSONDataSetMessageContentMaskDataSetWriterName != 0 {
		o.key("DataSetWriterName")
		e.str(m.DataSetWriterName)
	}
	if mask&ua.JSONDataSetMessageContentMaskPublisherID != 0 {
		o.key("PublisherId")
		p := e.nm.PublisherID
		if m.PublisherID != nil {
			p = *m.PublisherID
		}
		e.publisherID(p)
	}
	if mask&ua.JSONDataSetMessageContentMaskWriterGroupName != 0 {
		o.key("WriterGroupName")
		name := m.WriterGroupName
		if name == "" {
			name = e.nm.WriterGroupName
		}
		e.str(name)
	}
	if mask&ua.JSONDataSetMessageContentMaskSequenceNumber != 0 {
		o.key("SequenceNumber")
		e.uint(uint64(m.SequenceNumber))
	}
	if mask&ua.JSONDataSetMessageContentMaskMetaDataVersion != 0 {
		o.key("MetaDataVersion")
		// Both members are always written: a missing member reads as 0,
		// but some decoders want them.
		o2 := e.object()
		o2.key("MajorVersion")
		e.uint(uint64(m.MetaDataVersion.MajorVersion))
		o2.key("MinorVersion")
		e.uint(uint64(m.MetaDataVersion.MinorVersion))
		o2.end()
	} else if mask&ua.JSONDataSetMessageContentMaskMinorVersion != 0 {
		o.key("MinorVersion")
		e.uint(uint64(m.MetaDataVersion.MinorVersion))
	}
	if mask&ua.JSONDataSetMessageContentMaskTimestamp != 0 {
		o.key("Timestamp")
		if err := e.value(m.Timestamp); err != nil {
			return err
		}
	}
	if mask&ua.JSONDataSetMessageContentMaskStatus != 0 {
		o.key("Status")
		// The StatusCode object; Good is written as {"Code":0} rather than
		// the {} of the Compact encoding, which some decoders reject.
		o2 := e.object()
		o2.key("Code")
		e.uint(uint64(m.Status))
		o2.end()
	}
	if mask&ua.JSONDataSetMessageContentMaskMessageType != 0 {
		o.key("MessageType")
		e.str(typeName)
	}
	if m.Type != message.DataSetMessageKeepAlive {
		o.key("Payload")
		if err := e.payload(m); err != nil {
			return err
		}
	}
	o.end()
	return nil
}

func (e *encoder) fieldName(m *message.DataSetMessage, f *message.Field) (string, error) {
	if f.Name != "" {
		return f.Name, nil
	}
	if e.opts.MetaData != nil {
		p := e.nm.PublisherID
		if m.PublisherID != nil {
			p = *m.PublisherID
		}
		if md := e.opts.MetaData(p, e.nm.GroupHeader.WriterGroupID, m.DataSetWriterID); md != nil &&
			int(f.Index) < len(md.Fields) && md.Fields[f.Index] != nil && md.Fields[f.Index].Name != "" {
			return md.Fields[f.Index].Name, nil
		}
	}
	return "", fmt.Errorf("pubsub/jsonmsg: field %d of DataSetWriter %d has no name", f.Index, m.DataSetWriterID)
}

func (e *encoder) payload(m *message.DataSetMessage) error {
	verbose := m.JSONMask&ua.JSONDataSetMessageContentMaskFieldEncoding2 != 0
	co := e.codecOptions(verbose)
	o := e.object()
	seen := make(map[string]struct{}, len(m.Fields))
	for _, f := range m.Fields {
		if f == nil {
			return fmt.Errorf("pubsub/jsonmsg: nil field in DataSetMessage of writer %d", m.DataSetWriterID)
		}
		name, err := e.fieldName(m, f)
		if err != nil {
			return err
		}
		if _, dup := seen[name]; dup {
			return fmt.Errorf("pubsub/jsonmsg: duplicate field name %q", name)
		}
		seen[name] = struct{}{}
		o.key(name)
		if err := e.field(f.Value, m.FieldContentMask, co); err != nil {
			return fmt.Errorf("pubsub/jsonmsg: field %q: %w", name, err)
		}
	}
	o.end()
	return nil
}

// field writes one field value in the encoding the field content mask selects.
func (e *encoder) field(dv *ua.DataValue, fm ua.DataSetFieldContentMask, co []ua.CodecOption) error {
	var v *ua.Variant
	if dv != nil && dv.Has(ua.DataValueValue) {
		v = dv.Value
	} else if dv != nil && dv.EncodingMask == 0 && dv.Value != nil {
		v = dv.Value // a DataValue built without its mask
	}
	switch {
	case fm&ua.DataSetFieldContentMaskRawData != 0:
		return e.raw(v, co)
	case fm&(ua.DataSetFieldContentMaskStatusCode|ua.DataSetFieldContentMaskSourceTimestamp|
		ua.DataSetFieldContentMaskServerTimestamp|ua.DataSetFieldContentMaskSourcePicoSeconds|
		ua.DataSetFieldContentMaskServerPicoSeconds) != 0:
		out := &ua.DataValue{}
		if v != nil {
			out.EncodingMask |= ua.DataValueValue
			out.Value = v
		}
		if dv != nil {
			if fm&ua.DataSetFieldContentMaskStatusCode != 0 && dv.Status != ua.StatusGood {
				out.EncodingMask |= ua.DataValueStatusCode
				out.Status = dv.Status
			}
			if fm&ua.DataSetFieldContentMaskSourceTimestamp != 0 && !dv.SourceTimestamp.IsZero() {
				out.EncodingMask |= ua.DataValueSourceTimestamp
				out.SourceTimestamp = dv.SourceTimestamp
				if fm&ua.DataSetFieldContentMaskSourcePicoSeconds != 0 && dv.SourcePicoseconds != 0 {
					out.EncodingMask |= ua.DataValueSourcePicoseconds
					out.SourcePicoseconds = dv.SourcePicoseconds
				}
			}
			if fm&ua.DataSetFieldContentMaskServerTimestamp != 0 && !dv.ServerTimestamp.IsZero() {
				out.EncodingMask |= ua.DataValueServerTimestamp
				out.ServerTimestamp = dv.ServerTimestamp
				if fm&ua.DataSetFieldContentMaskServerPicoSeconds != 0 && dv.ServerPicoseconds != 0 {
					out.EncodingMask |= ua.DataValueServerPicoseconds
					out.ServerPicoseconds = dv.ServerPicoseconds
				}
			}
		}
		return e.encodeValue(out, co)
	default:
		if v == nil {
			v = &ua.Variant{}
		}
		return e.encodeValue(v, co)
	}
}

func (e *encoder) encodeValue(v interface{}, co []ua.CodecOption) error {
	b, err := ua.EncodeJSON(v, co...)
	if err != nil {
		return err
	}
	e.buf.Write(b)
	return nil
}

// raw writes the value of a Variant without the Variant wrapper: the "Value"
// member of its JSON encoding.
func (e *encoder) raw(v *ua.Variant, co []ua.CodecOption) error {
	if v == nil || v.Value() == nil {
		e.buf.WriteString("null")
		return nil
	}
	b, err := ua.EncodeJSON(v, co...)
	if err != nil {
		return err
	}
	var members struct {
		Value json.RawMessage
	}
	if err := json.Unmarshal(b, &members); err != nil {
		return err
	}
	if members.Value == nil {
		e.buf.WriteString("null")
		return nil
	}
	e.buf.Write(members.Value)
	return nil
}
