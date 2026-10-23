// SPDX-License-Identifier: MIT

package jsonmsg

import (
	"encoding/json"
	"errors"
	"math"

	"github.com/google/uuid"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/ua"
)

// EncodeMetaData encodes a "ua-metadata" message:
//
//	{"MessageId":"..","MessageType":"ua-metadata","PublisherId":"..",
//	 "DataSetWriterId":1,"WriterGroupName":"..","DataSetWriterName":"..",
//	 "Timestamp":"..","MetaData":{..}}
//
// The names and the Timestamp are omitted when empty; MetaData is encoded
// with the Compact encoding.
func EncodeMetaData(m *MetaDataMessage, opts *EncodeOptions) ([]byte, error) {
	if m == nil || m.MetaData == nil {
		return nil, errors.New("pubsub/jsonmsg: metadata message without MetaData")
	}
	if opts == nil {
		opts = &EncodeOptions{}
	}
	e := &encoder{opts: opts}
	o := e.header(m.MessageID, MessageTypeMetaData, m.PublisherID)
	o.key("DataSetWriterId")
	e.uint(uint64(m.DataSetWriterID))
	if m.WriterGroupName != "" {
		o.key("WriterGroupName")
		e.str(m.WriterGroupName)
	}
	if m.DataSetWriterName != "" {
		o.key("DataSetWriterName")
		e.str(m.DataSetWriterName)
	}
	if !m.Timestamp.IsZero() {
		o.key("Timestamp")
		if err := e.value(m.Timestamp); err != nil {
			return nil, err
		}
	}
	o.key("MetaData")
	if err := e.value(m.MetaData); err != nil {
		return nil, err
	}
	o.end()
	return e.buf.Bytes(), nil
}

// header opens a message object with MessageId, MessageType and PublisherId.
func (e *encoder) header(id, typ string, p message.PublisherID) *object {
	if id == "" {
		id = uuid.NewString()
	}
	o := e.object()
	o.key("MessageId")
	e.str(id)
	o.key("MessageType")
	e.str(typ)
	o.key("PublisherId")
	e.publisherID(p)
	return o
}

// DecodeMetaData decodes a "ua-metadata" message. The PublisherId may be a
// string or a number (see the package documentation).
func DecodeMetaData(b []byte, opts *DecodeOptions) (*MetaDataMessage, error) {
	ms, err := topLevel(b, opts, MessageTypeMetaData)
	if err != nil {
		return nil, err
	}
	d := &decoder{opts: opts, co: opts.codecOptions()}
	out := &MetaDataMessage{}
	if opts != nil && opts.PublisherID != nil {
		out.PublisherID = *opts.PublisherID
	}
	for _, m := range ms {
		var n uint64
		switch m.key {
		case "MessageId":
			out.MessageID, err = stringValue(m.val, "MessageId")
		case "PublisherId":
			if !isNull(m.val) {
				out.PublisherID, err = publisherIDValue(m.val)
			}
		case "DataSetWriterId":
			n, err = uintValue(m.val, "DataSetWriterId", math.MaxUint16)
			out.DataSetWriterID = uint16(n)
		case "WriterGroupName":
			out.WriterGroupName, err = stringValue(m.val, "WriterGroupName")
		case "DataSetWriterName":
			out.DataSetWriterName, err = stringValue(m.val, "DataSetWriterName")
		case "Timestamp":
			out.Timestamp, err = timeValue(m.val, "Timestamp", d.co)
		case "MetaData":
			if isNull(m.val) {
				continue
			}
			md := new(ua.DataSetMetaDataType)
			if derr := ua.DecodeJSON(m.val, md, d.co...); derr != nil {
				return nil, errorf("MetaData: %v", derr)
			}
			out.MetaData = md
		}
		if err != nil {
			return nil, err
		}
	}
	if out.MetaData == nil {
		return nil, errorf("ua-metadata message without MetaData")
	}
	return out, nil
}

// EncodeStatus encodes a "ua-status" message:
//
//	{"MessageId":"..","MessageType":"ua-status","PublisherId":"..",
//	 "Timestamp":"..","IsCyclic":true,"Status":2,"NextReportTime":".."}
//
// The timestamps are omitted when zero.
func EncodeStatus(m *StatusMessage, opts *EncodeOptions) ([]byte, error) {
	if m == nil {
		return nil, errors.New("pubsub/jsonmsg: nil status message")
	}
	if opts == nil {
		opts = &EncodeOptions{}
	}
	e := &encoder{opts: opts}
	o := e.header(m.MessageID, MessageTypeStatus, m.PublisherID)
	if !m.Timestamp.IsZero() {
		o.key("Timestamp")
		if err := e.value(m.Timestamp); err != nil {
			return nil, err
		}
	}
	o.key("IsCyclic")
	if m.IsCyclic {
		e.buf.WriteString("true")
	} else {
		e.buf.WriteString("false")
	}
	o.key("Status")
	e.uint(uint64(m.Status))
	if !m.NextReportTime.IsZero() {
		o.key("NextReportTime")
		if err := e.value(m.NextReportTime); err != nil {
			return nil, err
		}
	}
	o.end()
	return e.buf.Bytes(), nil
}

// DecodeStatus decodes a "ua-status" message.
func DecodeStatus(b []byte, opts *DecodeOptions) (*StatusMessage, error) {
	ms, err := topLevel(b, opts, MessageTypeStatus)
	if err != nil {
		return nil, err
	}
	d := &decoder{opts: opts, co: opts.codecOptions()}
	out := &StatusMessage{}
	if opts != nil && opts.PublisherID != nil {
		out.PublisherID = *opts.PublisherID
	}
	for _, m := range ms {
		switch m.key {
		case "MessageId":
			out.MessageID, err = stringValue(m.val, "MessageId")
		case "PublisherId":
			if !isNull(m.val) {
				out.PublisherID, err = publisherIDValue(m.val)
			}
		case "Timestamp":
			out.Timestamp, err = timeValue(m.val, "Timestamp", d.co)
		case "NextReportTime":
			out.NextReportTime, err = timeValue(m.val, "NextReportTime", d.co)
		case "IsCyclic":
			if err = json.Unmarshal(m.val, &out.IsCyclic); err != nil {
				err = errorf("IsCyclic: expected a boolean")
			}
		case "Status":
			var s ua.PubSubState
			if derr := ua.DecodeJSON(m.val, &s); derr != nil {
				return nil, errorf("Status: %v", derr)
			}
			out.Status = s
		}
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// topLevel checks the size of a message, splits its object and checks its
// MessageType.
func topLevel(b []byte, opts *DecodeOptions, want string) ([]member, error) {
	if len(b) > opts.maxMessageSize() {
		return nil, errorf("message of %d bytes exceeds the limit of %d", len(b), opts.maxMessageSize())
	}
	if kind(b) != '{' {
		return nil, errorf("expected a JSON object")
	}
	ms, err := objectMembers(b, math.MaxInt32)
	if err != nil {
		return nil, err
	}
	raw, ok := lookup(ms, "MessageType")
	if !ok {
		return nil, errorf("no MessageType")
	}
	t, err := stringValue(raw, "MessageType")
	if err != nil {
		return nil, err
	}
	if t != want {
		return nil, &UnsupportedMessageTypeError{MessageType: t}
	}
	return ms, nil
}

// MessageType returns the MessageType of a JSON message: "ua-data",
// "ua-metadata", ..., or for a message without network message header the
// DataSetMessage type ("ua-keyframe", ...) or "" if it has none.
func MessageType(b []byte) (string, error) {
	switch kind(b) {
	case '[':
		return "", nil
	case '{':
	default:
		return "", errorf("expected a JSON object or array")
	}
	var m struct {
		MessageType json.RawMessage
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return "", errorf("%v", err)
	}
	if m.MessageType == nil {
		return "", nil
	}
	return stringValue(m.MessageType, "MessageType")
}

// DecodeAny decodes a JSON PubSub message of any supported type: it returns
// a *message.NetworkMessage for "ua-data" (and messages without network
// message header), a *MetaDataMessage for "ua-metadata" and a
// *StatusMessage for "ua-status". Other types return an
// [*UnsupportedMessageTypeError].
func DecodeAny(b []byte, opts *DecodeOptions) (interface{}, error) {
	if len(b) > opts.maxMessageSize() {
		return nil, errorf("message of %d bytes exceeds the limit of %d", len(b), opts.maxMessageSize())
	}
	t, err := MessageType(b)
	if err != nil {
		return nil, err
	}
	switch t {
	case MessageTypeMetaData:
		return DecodeMetaData(b, opts)
	case MessageTypeStatus:
		return DecodeStatus(b, opts)
	}
	return Decode(b, opts)
}
