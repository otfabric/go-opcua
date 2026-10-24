// SPDX-License-Identifier: MIT

package jsonmsg

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/ua"
)

// The JSON messages of PubSub Actions (Part 14 §7.2.5.6 in 1.05); the
// layout is described in the package documentation.

// maxCorrelationData bounds the CorrelationData the decoder accepts.
const maxCorrelationData = 4096

// actionTypeName is the MessageType of the action DataSetMessages of type t,
// empty for other types.
func actionTypeName(t message.DataSetMessageType) string {
	switch t {
	case message.DataSetMessageActionRequest:
		return MessageTypeActionRequest
	case message.DataSetMessageActionResponse:
		return MessageTypeActionResponse
	}
	return ""
}

// encodeAction encodes an action NetworkMessage. A missing MessageID is
// generated and a zero Timestamp is the current time: both are mandatory.
func (e *encoder) encodeAction() ([]byte, error) {
	nm := e.nm
	a := nm.Action
	want := message.DataSetMessageActionRequest
	switch a.Type {
	case message.ActionRequest:
	case message.ActionResponse:
		want = message.DataSetMessageActionResponse
	default:
		return nil, fmt.Errorf("pubsub/jsonmsg: action message type %d", a.Type)
	}
	if len(nm.Messages) == 0 {
		return nil, errors.New("pubsub/jsonmsg: an action NetworkMessage needs a DataSetMessage")
	}
	if math.IsNaN(a.TimeoutHint) || math.IsInf(a.TimeoutHint, 0) {
		return nil, fmt.Errorf("pubsub/jsonmsg: TimeoutHint %v", a.TimeoutHint)
	}
	o := e.object()
	id := nm.MessageID
	if id == "" {
		id = uuid.NewString()
	}
	o.key("MessageId")
	e.str(id)
	o.key("MessageType")
	e.str(actionTypeName(want))
	o.key("PublisherId")
	e.publisherID(nm.PublisherID)
	ts := nm.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	o.key("Timestamp")
	if err := e.value(ts); err != nil {
		return nil, err
	}
	req := a.Type == message.ActionRequest
	if req && a.ResponseAddress != "" {
		o.key("ResponseAddress")
		e.str(a.ResponseAddress)
	}
	if a.CorrelationData != nil {
		o.key("CorrelationData")
		e.str(base64.StdEncoding.EncodeToString(a.CorrelationData))
	}
	if a.RequestorID != nil {
		o.key("RequestorId")
		e.publisherID(*a.RequestorID)
	}
	if req && a.TimeoutHint > 0 {
		o.key("TimeoutHint")
		e.buf.WriteString(strconv.FormatFloat(a.TimeoutHint, 'g', -1, 64))
	}
	o.key("Messages")
	e.buf.WriteByte('[')
	for i, m := range nm.Messages {
		if i > 0 {
			e.buf.WriteByte(',')
		}
		if m == nil {
			return nil, errors.New("pubsub/jsonmsg: nil DataSetMessage")
		}
		if m.Type != want {
			return nil, fmt.Errorf("pubsub/jsonmsg: DataSetMessage %d of type %v in an %v", i, m.Type, a.Type)
		}
		if err := e.actionDataSetMessage(m); err != nil {
			return nil, err
		}
	}
	e.buf.WriteByte(']')
	o.end()
	return e.buf.Bytes(), nil
}

// actionDataSetMessage writes an ActionRequest or ActionResponse
// DataSetMessage (Part 14 §7.2.5.6.2 and §7.2.5.6.3).
func (e *encoder) actionDataSetMessage(m *message.DataSetMessage) error {
	if m.ActionState > ua.ActionStateDone {
		return fmt.Errorf("pubsub/jsonmsg: ActionState %d", m.ActionState)
	}
	const dataValueBits = ua.DataSetFieldContentMaskStatusCode | ua.DataSetFieldContentMaskSourceTimestamp |
		ua.DataSetFieldContentMaskServerTimestamp | ua.DataSetFieldContentMaskSourcePicoSeconds |
		ua.DataSetFieldContentMaskServerPicoSeconds
	mask := m.JSONMask
	o := e.object()
	o.key("DataSetWriterId")
	e.uint(uint64(m.DataSetWriterID))
	o.key("ActionTargetId")
	e.uint(uint64(m.ActionTargetID))
	if mask&ua.JSONDataSetMessageContentMaskDataSetWriterName != 0 {
		o.key("DataSetWriterName")
		e.str(m.DataSetWriterName)
	}
	if mask&ua.JSONDataSetMessageContentMaskWriterGroupName != 0 {
		o.key("WriterGroupName")
		e.str(m.WriterGroupName)
	}
	if mask&ua.JSONDataSetMessageContentMaskMetaDataVersion != 0 {
		o.key("MetaDataVersion")
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
	if m.Type == message.DataSetMessageActionResponse {
		o.key("Status")
		o2 := e.object()
		o2.key("Code")
		e.uint(uint64(m.Status))
		o2.end()
	}
	if mask&ua.JSONDataSetMessageContentMaskMessageType != 0 {
		o.key("MessageType")
		e.str(actionTypeName(m.Type))
	}
	o.key("RequestId")
	e.uint(uint64(m.RequestID))
	o.key("ActionState")
	e.uint(uint64(m.ActionState))
	o.key("Payload")
	// The DataValue encoding is not allowed: such fields are Variants.
	saved := m.FieldContentMask
	if saved&dataValueBits != 0 && saved&ua.DataSetFieldContentMaskRawData == 0 {
		cp := *m
		cp.FieldContentMask = 0
		m = &cp
	}
	if err := e.payload(m); err != nil {
		return err
	}
	o.end()
	return nil
}

// actionNetworkMessage decodes the members of an action NetworkMessage of
// MessageType t.
func (d *decoder) actionNetworkMessage(nm *message.NetworkMessage, ms []member, t string) error {
	a := &message.ActionHeader{Type: message.ActionRequest}
	d.action = message.DataSetMessageActionRequest
	if t == MessageTypeActionResponse {
		a.Type = message.ActionResponse
		d.action = message.DataSetMessageActionResponse
	}
	nm.Action = a
	nm.JSONMask |= ua.JSONNetworkMessageContentMaskNetworkMessageHeader | ua.JSONNetworkMessageContentMaskDataSetMessageHeader
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
		case "Timestamp":
			nm.Timestamp, err = timeValue(m.val, "Timestamp", d.co)
		case "ResponseAddress":
			a.ResponseAddress, err = stringValue(m.val, "ResponseAddress")
		case "CorrelationData":
			a.CorrelationData, err = correlationValue(m.val)
		case "RequestorId":
			if isNull(m.val) {
				continue
			}
			var p message.PublisherID
			p, err = publisherIDValue(m.val)
			a.RequestorID = &p
		case "TimeoutHint":
			a.TimeoutHint, err = durationValue(m.val, "TimeoutHint")
		case "Messages":
			messages = m.val
		}
		if err != nil {
			return err
		}
	}
	if a.Type == message.ActionResponse {
		// Not used in responses (Part 14 Table 195).
		a.ResponseAddress, a.TimeoutHint = "", 0
	}
	var elems []json.RawMessage
	switch kind(messages) {
	case '[':
		var err error
		if elems, err = arrayElements(messages, d.opts.maxDataSetMessages()); err != nil {
			return err
		}
	case '{':
		elems = []json.RawMessage{messages}
	default:
		return errorf("an action NetworkMessage needs Messages")
	}
	if len(elems) == 0 {
		return errorf("an action NetworkMessage needs a DataSetMessage")
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
		dsm, err := d.dataSetMessage(nm, ms)
		if err != nil {
			return err
		}
		if dsm.JSONMask&ua.JSONDataSetMessageContentMaskMessageType == 0 {
			dsm.Type = d.action
		}
		if dsm.Type != d.action {
			return errorf("a %v DataSetMessage in a %s message", dsm.Type, t)
		}
		if dsm.FieldContentMask&^ua.DataSetFieldContentMaskRawData != 0 {
			return errorf("the fields of an action message are Variants or RawData, not DataValues")
		}
		nm.Messages = append(nm.Messages, dsm)
	}
	return nil
}

// actionMember decodes a member of an action DataSetMessage that a data
// DataSetMessage does not have.
func (d *decoder) actionMember(dsm *message.DataSetMessage, m member) error {
	var n uint64
	var err error
	switch m.key {
	case "ActionTargetId":
		n, err = uintValue(m.val, "ActionTargetId", math.MaxUint16)
		dsm.ActionTargetID = uint16(n)
	case "RequestId":
		n, err = uintValue(m.val, "RequestId", math.MaxUint16)
		dsm.RequestID = uint16(n)
	case "ActionState":
		dsm.ActionState, err = actionStateValue(m.val)
	}
	return err
}

// actionStateValue decodes an ActionState: the number of the Compact
// encoding, the "Name_Value" string of the Verbose encoding, or the name.
func actionStateValue(raw json.RawMessage) (ua.ActionState, error) {
	if kind(raw) == '"' {
		s, err := stringValue(raw, "ActionState")
		if err != nil {
			return 0, err
		}
		name, num, hasNum := strings.Cut(s, "_")
		for st, n := range []string{"Idle", "Executing", "Done"} {
			if name == n && (!hasNum || num == strconv.Itoa(st)) {
				return ua.ActionState(st), nil
			}
		}
		return 0, errorf("ActionState: unknown value %.40q", s)
	}
	n, err := uintValue(raw, "ActionState", uint64(ua.ActionStateDone))
	return ua.ActionState(n), err
}

// correlationValue decodes the base64 ByteString of CorrelationData.
func correlationValue(raw json.RawMessage) ([]byte, error) {
	if isNull(raw) {
		return nil, nil
	}
	s, err := stringValue(raw, "CorrelationData")
	if err != nil {
		return nil, err
	}
	if base64.StdEncoding.DecodedLen(len(s)) > maxCorrelationData {
		return nil, errorf("CorrelationData of more than %d bytes", maxCorrelationData)
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, errorf("CorrelationData: %v", err)
	}
	return b, nil
}

// durationValue decodes a Duration: a finite, non-negative JSON number.
func durationValue(raw json.RawMessage, name string) (float64, error) {
	var f float64
	if err := json.Unmarshal(raw, &f); err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 {
		return 0, errorf("%s: expected a non-negative number", name)
	}
	return f, nil
}
