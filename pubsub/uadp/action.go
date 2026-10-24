// SPDX-License-Identifier: MIT

package uadp

import (
	"math"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/ua"
)

// PubSub Actions (Part 14 §6.2.11.2 in 1.05): an ActionRequest or
// ActionResponse NetworkMessage is a DataSet NetworkMessage (type 000) with
// bit 5 of ExtendedFlags2 set and the ActionHeader of Table 154 after the
// security header. Its DataSetMessages are of type ActionRequest (0101) or
// ActionResponse (0110), whose body (Tables 166 and 167) is
//
//	ActionTargetId UInt16 | RequestId UInt16 | ActionState Byte
//	FieldCount UInt16 | DataSetFields
//
// with the fields encoded as Variant or RawData. The Status of a response is
// the Status of the DataSetMessage header.
//
// Decisions where Part 14 1.05 leaves the encoding open:
//
//   - The RequestorId (BaseDataType) is encoded as a Variant, the encoding
//     of a BaseDataType structure field (Part 6 §5.2.2.16), holding the
//     PublisherId of the Requestor (Byte, UInt16, UInt32, UInt64 or String).
//   - The ActionHeader follows the security header, so it is part of the
//     encrypted range of a SignAndEncrypt message, like the payload.
//   - The FieldCount is written for RawData fields too: Tables 166 and 167
//     do not omit it as the key frame does.
//   - Chunked action messages are not supported.

// maxActionString bounds the ResponseAddress and a String RequestorId.
const maxActionString = 4096

// checkAction validates an action NetworkMessage for Encode.
func checkAction(nm *message.NetworkMessage) error {
	a := nm.Action
	if nm.Type != message.NetworkMessageDataSet {
		return malformed("an ActionHeader in a NetworkMessage of type %d", nm.Type)
	}
	want := message.DataSetMessageActionRequest
	switch a.Type {
	case message.ActionRequest:
	case message.ActionResponse:
		want = message.DataSetMessageActionResponse
	default:
		return malformed("action message type %d", a.Type)
	}
	switch n := len(nm.Messages); {
	case n == 0:
		return malformed("an action NetworkMessage needs a DataSetMessage")
	case n > maxMessages:
		return malformed("%d DataSetMessages, at most %d fit into a NetworkMessage", n, maxMessages)
	case n > 1 && nm.UADPMask&ua.UADPNetworkMessageContentMaskPayloadHeader == 0:
		return malformed("%d DataSetMessages need the PayloadHeader", n)
	}
	for i, m := range nm.Messages {
		if m == nil {
			return malformed("nil DataSetMessage")
		}
		if m.Type != want {
			return malformed("DataSetMessage %d of type %v in an %v", i, m.Type, a.Type)
		}
	}
	if len(a.ResponseAddress) > maxActionString {
		return malformed("ResponseAddress of %d bytes", len(a.ResponseAddress))
	}
	if r := a.RequestorID; r != nil && (r.Type > message.PublisherIDString || len(r.Str) > maxActionString) {
		return malformed("RequestorId %v", r)
	}
	if math.IsNaN(a.TimeoutHint) || math.IsInf(a.TimeoutHint, 0) {
		return malformed("TimeoutHint %v", a.TimeoutHint)
	}
	return nil
}

// writeActionHeader writes the ActionHeader. A response carries neither
// ResponseAddress nor TimeoutHint.
func writeActionHeader(b *ua.Buffer, a *message.ActionHeader) error {
	req := a.Type == message.ActionRequest
	var flags byte
	if req {
		flags |= actRequest
		if a.ResponseAddress != "" {
			flags |= actResponseAddress
		}
		if a.TimeoutHint > 0 {
			flags |= actTimeoutHint
		}
	}
	if a.CorrelationData != nil {
		flags |= actCorrelationData
	}
	if a.RequestorID != nil {
		flags |= actRequestorID
	}
	b.WriteUint8(flags)
	if flags&actResponseAddress != 0 {
		b.WriteString(a.ResponseAddress)
	}
	if flags&actCorrelationData != 0 {
		b.WriteByteString(a.CorrelationData)
	}
	if flags&actRequestorID != 0 {
		b.WriteStruct(a.RequestorID.Variant())
	}
	if flags&actTimeoutHint != 0 {
		b.WriteFloat64(a.TimeoutHint)
	}
	if b.Error() != nil {
		return malformed("action header: %v", b.Error())
	}
	return nil
}

// decodeActionHeader decodes the ActionHeader at the start of body and
// returns the number of bytes it took.
func decodeActionHeader(body []byte) (*message.ActionHeader, int, error) {
	b := ua.NewBuffer(body)
	flags := b.ReadUint8()
	if b.Error() != nil {
		return nil, 0, malformed("truncated action header")
	}
	if flags&^actKnown != 0 {
		return nil, 0, malformed("reserved ActionFlags 0x%02x", flags)
	}
	a := &message.ActionHeader{Type: message.ActionResponse}
	if flags&actRequest != 0 {
		a.Type = message.ActionRequest
	} else if flags&(actResponseAddress|actTimeoutHint) != 0 {
		return nil, 0, malformed("ResponseAddress or TimeoutHint in an ActionResponse")
	}
	if flags&actResponseAddress != 0 {
		a.ResponseAddress = b.ReadString()
		if len(a.ResponseAddress) > maxActionString {
			return nil, 0, malformed("ResponseAddress of %d bytes", len(a.ResponseAddress))
		}
	}
	if flags&actCorrelationData != 0 {
		// A present but empty ByteString stays distinguishable from an
		// absent one.
		a.CorrelationData = append([]byte{}, b.ReadBytes()...)
	}
	if flags&actRequestorID != 0 {
		v := new(ua.Variant)
		b.ReadStruct(v)
		if b.Error() != nil {
			return nil, 0, malformed("RequestorId: %v", b.Error())
		}
		id, err := message.PublisherIDFromVariant(v)
		if err != nil {
			return nil, 0, malformed("RequestorId: %v", err)
		}
		if len(id.Str) > maxActionString {
			return nil, 0, malformed("RequestorId of %d bytes", len(id.Str))
		}
		a.RequestorID = &id
	}
	if flags&actTimeoutHint != 0 {
		a.TimeoutHint = b.ReadFloat64()
		if math.IsNaN(a.TimeoutHint) || math.IsInf(a.TimeoutHint, 0) {
			return nil, 0, malformed("TimeoutHint %v", a.TimeoutHint)
		}
	}
	if b.Error() != nil {
		return nil, 0, malformed("truncated action header")
	}
	return a, b.Pos(), nil
}

// checkActionMessages checks that the DataSetMessages of a decoded
// NetworkMessage match its ActionHeader: all of the action type of the
// header with one, none of an action type without.
func checkActionMessages(nm *message.NetworkMessage) error {
	want := message.DataSetMessageType(0xff)
	if a := nm.Action; a != nil {
		want = message.DataSetMessageActionRequest
		if a.Type == message.ActionResponse {
			want = message.DataSetMessageActionResponse
		}
	}
	for i, m := range nm.Messages {
		isAction := m.Type == message.DataSetMessageActionRequest || m.Type == message.DataSetMessageActionResponse
		switch {
		case nm.Action == nil && isAction:
			return malformed("DataSetMessage %d: an %v without ActionHeader", i, m.Type)
		case nm.Action != nil && m.Valid && m.Type != want:
			return malformed("DataSetMessage %d: an %v in an %v", i, m.Type, nm.Action.Type)
		}
	}
	return nil
}

// encodeAction writes the body of an ActionRequest or ActionResponse
// DataSetMessage (Part 14 Tables 166 and 167 in 1.05).
func (e *encoder) encodeAction(b *ua.Buffer, m *message.DataSetMessage) error {
	if m.FieldEncoding == message.FieldEncodingDataValue {
		return malformed("the fields of an %v are Variant or RawData, not DataValue", m.Type)
	}
	if m.ActionState > ua.ActionStateDone {
		return malformed("ActionState %d", m.ActionState)
	}
	if len(m.Fields) > math.MaxUint16 {
		return malformed("%d fields", len(m.Fields))
	}
	b.WriteUint16(m.ActionTargetID)
	b.WriteUint16(m.RequestID)
	b.WriteUint8(uint8(m.ActionState))
	b.WriteUint16(uint16(len(m.Fields)))
	if m.FieldEncoding == message.FieldEncodingVariant {
		for _, f := range m.Fields {
			writeField(b, m.FieldEncoding, f)
		}
		return nil
	}
	md := e.metaData(m)
	if md != nil && len(md.Fields) != len(m.Fields) && len(m.Fields) > 0 {
		return malformed("RawData %v with %d fields, the DataSetMetaData has %d", m.Type, len(m.Fields), len(md.Fields))
	}
	for i, f := range m.Fields {
		if err := writeRawField(b, md, i, fieldVariant(f)); err != nil {
			return err
		}
	}
	return nil
}

// decodeAction decodes the body of an ActionRequest or ActionResponse
// DataSetMessage. A RawData message carries either no field or all fields
// of its DataSetMetaData.
func decodeAction(b *ua.Buffer, m *message.DataSetMessage, md *ua.DataSetMetaDataType) error {
	if m.FieldEncoding == message.FieldEncodingDataValue {
		return malformed("the fields of an %v are Variant or RawData, not DataValue", m.Type)
	}
	m.ActionTargetID = b.ReadUint16()
	m.RequestID = b.ReadUint16()
	m.ActionState = ua.ActionState(b.ReadUint8())
	n := int(b.ReadUint16())
	if b.Error() != nil {
		return malformed("truncated %v", m.Type)
	}
	if m.ActionState > ua.ActionStateDone {
		return malformed("ActionState %d", m.ActionState)
	}
	// Every field takes at least one byte.
	if n > b.Len() {
		return malformed("%d fields in %d bytes", n, b.Len())
	}
	if n == 0 {
		return nil
	}
	if m.FieldEncoding == message.FieldEncodingRawData {
		if md == nil {
			return ErrNoMetaData
		}
		if n != len(md.Fields) {
			return malformed("RawData %v with %d fields, the DataSetMetaData has %d", m.Type, n, len(md.Fields))
		}
	}
	m.Fields = make([]*message.Field, n)
	for i := range m.Fields {
		var dv *ua.DataValue
		if m.FieldEncoding == message.FieldEncodingRawData {
			v, err := readRawField(b, md, i)
			if err != nil {
				return wrapField(i, err)
			}
			dv = &ua.DataValue{EncodingMask: ua.DataValueValue, Value: v}
		} else {
			var err error
			if dv, err = readField(b, m.FieldEncoding); err != nil {
				return wrapField(i, err)
			}
		}
		m.Fields[i] = &message.Field{Index: uint16(i), Value: dv}
	}
	return nil
}

// PeekAction reports whether an encoded UADP NetworkMessage is an action
// message (bit 5 of ExtendedFlags2), without decoding it.
func PeekAction(b []byte) bool {
	return len(b) >= 3 && b[0]&flagsVersionMask == UADPVersion && b[0]&flagsExtended1 != 0 &&
		b[1]&ext1Extended2 != 0 && b[2]&ext2Action != 0
}
