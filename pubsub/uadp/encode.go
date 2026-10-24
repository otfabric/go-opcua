// SPDX-License-Identifier: MIT

package uadp

import (
	"math"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/ua"
)

type encoder struct {
	nm   *message.NetworkMessage
	opts *EncodeOptions
	sec  *encodeSecurity
}

func (e *encoder) has(m ua.UADPNetworkMessageContentMask) bool {
	return e.nm.UADPMask&m != 0
}

// check validates the type and the body of the NetworkMessage.
func (e *encoder) check() error {
	nm := e.nm
	if nm.Chunk != nil {
		if nm.Action != nil {
			if err := checkActionChunk(nm); err != nil {
				return err
			}
		}
		switch nm.Type {
		case message.NetworkMessageDataSet:
			if e.has(ua.UADPNetworkMessageContentMaskPayloadHeader) && (len(nm.Messages) != 1 || nm.Messages[0] == nil) {
				return malformed("a chunk with PayloadHeader needs the one DataSetMessage it is a piece of")
			}
		case message.NetworkMessageDiscoveryResponse:
		default:
			return malformed("chunk of a NetworkMessage of type %d", nm.Type)
		}
		return nil
	}
	if nm.Action != nil {
		return checkAction(nm)
	}
	for _, m := range nm.Messages {
		if m != nil && (m.Type == message.DataSetMessageActionRequest || m.Type == message.DataSetMessageActionResponse) {
			return malformed("an %v DataSetMessage needs the ActionHeader", m.Type)
		}
	}
	switch nm.Type {
	case message.NetworkMessageDataSet:
		switch n := len(nm.Messages); {
		case n == 0:
			return malformed("a DataSet NetworkMessage needs a DataSetMessage")
		case n > maxMessages:
			return malformed("%d DataSetMessages, at most %d fit into a NetworkMessage", n, maxMessages)
		case n > 1 && !e.has(ua.UADPNetworkMessageContentMaskPayloadHeader):
			return malformed("%d DataSetMessages need the PayloadHeader", n)
		}
	case message.NetworkMessageDiscoveryResponse:
		if nm.Discovery == nil {
			return malformed("discovery announcement without body")
		}
	case message.NetworkMessageDiscoveryRequest:
		if nm.Request == nil {
			return malformed("discovery probe without body")
		}
	default:
		return malformed("NetworkMessage type %d", nm.Type)
	}
	return nil
}

func (e *encoder) encode() ([]byte, error) {
	nm := e.nm
	if err := e.check(); err != nil {
		return nil, err
	}
	payloadHeader := nm.Type == message.NetworkMessageDataSet && e.has(ua.UADPNetworkMessageContentMaskPayloadHeader)

	b := ua.NewBuffer(make([]byte, 0, 256))
	if err := e.writeHeader(b, payloadHeader); err != nil {
		return nil, err
	}
	if e.sec != nil {
		e.sec.writeHeader(b)
	}
	if b.Error() != nil {
		return nil, malformed("header: %v", b.Error())
	}
	// The ActionHeader follows the security header: it is encrypted with
	// the payload.
	payloadStart := b.Len()
	if nm.Action != nil {
		if err := writeActionHeader(b, nm.Action); err != nil {
			return nil, err
		}
	}

	var err error
	switch {
	case nm.Chunk != nil:
		writeChunk(b, nm.Chunk)
	case nm.Type == message.NetworkMessageDataSet:
		err = e.encodePayload(b, payloadHeader)
	case nm.Type == message.NetworkMessageDiscoveryResponse:
		err = encodeDiscovery(b, nm.Discovery)
	default:
		err = encodeDiscoveryRequest(b, nm.Request)
	}
	if err != nil {
		return nil, err
	}
	if b.Error() != nil {
		return nil, malformed("payload: %v", b.Error())
	}

	out := b.Bytes()
	if e.sec != nil {
		return e.sec.protect(out, payloadStart)
	}
	return out, nil
}

// writeHeader writes the NetworkMessage header up to the PromotedFields, the
// security header excluded.
func (e *encoder) writeHeader(b *ua.Buffer, payloadHeader bool) error {
	nm := e.nm
	// Flags. ExtendedFlags1 and 2 are written only if a bit of them is set
	// (open62541: UA_NetworkMessage_ExtendedFlags1Enabled).
	ext2 := byte(nm.Type) << ext2TypeShift
	if e.has(ua.UADPNetworkMessageContentMaskPromotedFields) {
		ext2 |= ext2PromotedFields
	}
	if nm.Chunk != nil {
		ext2 |= ext2Chunk
	}
	if nm.Action != nil {
		ext2 |= ext2Action
	}
	var ext1 byte
	if e.has(ua.UADPNetworkMessageContentMaskPublisherID) {
		if nm.PublisherID.Type > message.PublisherIDString {
			return malformed("PublisherId type %d", nm.PublisherID.Type)
		}
		ext1 = byte(nm.PublisherID.Type)
	}
	if e.has(ua.UADPNetworkMessageContentMaskDataSetClassID) {
		ext1 |= ext1DataSetClassID
	}
	if e.sec != nil {
		ext1 |= ext1Security
	}
	if e.has(ua.UADPNetworkMessageContentMaskTimestamp) {
		ext1 |= ext1Timestamp
	}
	if e.has(ua.UADPNetworkMessageContentMaskPicoSeconds) {
		ext1 |= ext1PicoSeconds
	}
	if ext2 != 0 {
		ext1 |= ext1Extended2
	}
	flags := byte(UADPVersion)
	if e.has(ua.UADPNetworkMessageContentMaskPublisherID) {
		flags |= flagsPublisherID
	}
	if e.has(ua.UADPNetworkMessageContentMaskGroupHeader) {
		flags |= flagsGroupHeader
	}
	if payloadHeader {
		flags |= flagsPayloadHeader
	}
	if ext1 != 0 {
		flags |= flagsExtended1
	}

	b.WriteUint8(flags)
	if ext1 != 0 {
		b.WriteUint8(ext1)
		if ext2 != 0 {
			b.WriteUint8(ext2)
		}
	}
	if flags&flagsPublisherID != 0 {
		writePublisherID(b, nm.PublisherID)
	}
	if ext1&ext1DataSetClassID != 0 {
		b.WriteStruct(nm.DataSetClassID)
	}

	if flags&flagsGroupHeader != 0 {
		var gf byte
		for _, f := range groupFields {
			if e.has(f.mask) {
				gf |= f.flag
			}
		}
		b.WriteUint8(gf)
		for _, f := range groupFields {
			if gf&f.flag != 0 {
				f.enc(b, &nm.GroupHeader)
			}
		}
	}

	switch {
	case !payloadHeader:
	case nm.Chunk != nil:
		// The PayloadHeader of a chunk is the DataSetWriterId of the
		// DataSetMessage it is a piece of (Part 14 Table 158 in 1.05).
		b.WriteUint16(nm.Messages[0].DataSetWriterID)
	default:
		b.WriteUint8(uint8(len(nm.Messages)))
		for _, m := range nm.Messages {
			if m == nil {
				return malformed("nil DataSetMessage")
			}
			b.WriteUint16(m.DataSetWriterID)
		}
	}

	if ext1&ext1Timestamp != 0 {
		b.WriteTime(nm.Timestamp)
	}
	if ext1&ext1PicoSeconds != 0 {
		b.WriteUint16(nm.PicoSeconds)
	}
	if ext2&ext2PromotedFields != 0 {
		pf := ua.NewBuffer(nil)
		for _, v := range nm.PromotedFields {
			pf.WriteStruct(v)
		}
		if pf.Error() != nil {
			return malformed("promoted fields: %v", pf.Error())
		}
		if pf.Len() > math.MaxUint16 {
			return malformed("promoted fields of %d bytes", pf.Len())
		}
		b.WriteUint16(uint16(pf.Len()))
		b.Write(pf.Bytes())
	}
	return nil
}

func writePublisherID(b *ua.Buffer, p message.PublisherID) {
	switch p.Type {
	case message.PublisherIDByte:
		b.WriteUint8(uint8(p.Num))
	case message.PublisherIDUInt16:
		b.WriteUint16(uint16(p.Num))
	case message.PublisherIDUInt32:
		b.WriteUint32(uint32(p.Num))
	case message.PublisherIDUInt64:
		b.WriteUint64(p.Num)
	default:
		b.WriteString(p.Str)
	}
}

// encodePayload writes the Sizes (if there is more than one DataSetMessage)
// and the DataSetMessages.
func (e *encoder) encodePayload(b *ua.Buffer, payloadHeader bool) error {
	msgs := e.nm.Messages
	if len(msgs) == 1 {
		return e.encodeDataSetMessage(b, msgs[0])
	}
	bodies := make([][]byte, len(msgs))
	for i, m := range msgs {
		mb := ua.NewBuffer(nil)
		if err := e.encodeDataSetMessage(mb, m); err != nil {
			return err
		}
		// Part 14: a DataSetMessage that does not fit into the UInt16
		// size belongs into a NetworkMessage of its own.
		if mb.Len() > math.MaxUint16 {
			return malformed("DataSetMessage %d has %d bytes, more than its UInt16 size", i, mb.Len())
		}
		bodies[i] = mb.Bytes()
	}
	if payloadHeader {
		for _, body := range bodies {
			b.WriteUint16(uint16(len(body)))
		}
	}
	for _, body := range bodies {
		b.Write(body)
	}
	return nil
}

func (e *encoder) metaData(m *message.DataSetMessage) *ua.DataSetMetaDataType {
	if e.opts.MetaData == nil {
		return nil
	}
	return e.opts.MetaData(e.nm.PublisherID, e.nm.GroupHeader.WriterGroupID, m.DataSetWriterID)
}

func (e *encoder) encodeDataSetMessage(b *ua.Buffer, m *message.DataSetMessage) error {
	if m == nil {
		return malformed("nil DataSetMessage")
	}
	if m.FieldEncoding > message.FieldEncodingDataValue {
		return malformed("field encoding %d", m.FieldEncoding)
	}
	if m.Type > message.DataSetMessageKeepAlive && m.Type != message.DataSetMessageActionRequest && m.Type != message.DataSetMessageActionResponse {
		return malformed("DataSetMessage type %d", m.Type)
	}

	f1 := byte(m.FieldEncoding) << dsf1EncodingShift
	if m.Valid {
		f1 |= dsf1Valid
	}
	f2 := byte(m.Type)
	for _, f := range dsmFields {
		switch {
		case m.UADPMask&f.mask == 0:
		case f.flags2:
			f2 |= f.flag
		default:
			f1 |= f.flag
		}
	}
	// DataSetFlags2 is written only when needed (open62541:
	// UA_DataSetMessageHeader_DataSetFlags2Enabled).
	if f2 != 0 {
		f1 |= dsf1Flags2
	}
	b.WriteUint8(f1)
	if f2 != 0 {
		b.WriteUint8(f2)
	}
	for _, f := range dsmFields {
		if m.UADPMask&f.mask != 0 {
			f.enc(b, m)
		}
	}

	switch m.Type {
	case message.DataSetMessageKeyFrame, message.DataSetMessageEvent:
		return e.encodeKeyFrame(b, m)
	case message.DataSetMessageDeltaFrame:
		return e.encodeDeltaFrame(b, m)
	case message.DataSetMessageActionRequest, message.DataSetMessageActionResponse:
		return e.encodeAction(b, m)
	default: // keep-alive: no payload
		return nil
	}
}

// encodeKeyFrame writes the fields of a key frame or an event: the field
// count (not for RawData, Part 14: "The FieldCount shall be omitted if
// RawData field encoding is set") and the field values.
func (e *encoder) encodeKeyFrame(b *ua.Buffer, m *message.DataSetMessage) error {
	if m.FieldEncoding == message.FieldEncodingRawData {
		// A RawData key frame without fields is a heartbeat: open62541
		// writes only the header.
		if len(m.Fields) == 0 {
			return nil
		}
		md := e.metaData(m)
		if md != nil && len(md.Fields) != len(m.Fields) {
			return malformed("RawData key frame with %d fields, the DataSetMetaData has %d", len(m.Fields), len(md.Fields))
		}
		for i, f := range m.Fields {
			if err := writeRawField(b, md, i, fieldVariant(f)); err != nil {
				return err
			}
		}
		return nil
	}
	if len(m.Fields) > math.MaxUint16 {
		return malformed("%d fields", len(m.Fields))
	}
	b.WriteUint16(uint16(len(m.Fields)))
	for _, f := range m.Fields {
		writeField(b, m.FieldEncoding, f)
	}
	return nil
}

func (e *encoder) encodeDeltaFrame(b *ua.Buffer, m *message.DataSetMessage) error {
	if len(m.Fields) > math.MaxUint16 {
		return malformed("%d fields", len(m.Fields))
	}
	var md *ua.DataSetMetaDataType
	if m.FieldEncoding == message.FieldEncodingRawData {
		md = e.metaData(m)
	}
	b.WriteUint16(uint16(len(m.Fields)))
	for _, f := range m.Fields {
		if f == nil {
			return malformed("nil field in delta frame")
		}
		b.WriteUint16(f.Index)
		if m.FieldEncoding == message.FieldEncodingRawData {
			if err := writeRawField(b, md, int(f.Index), fieldVariant(f)); err != nil {
				return err
			}
			continue
		}
		writeField(b, m.FieldEncoding, f)
	}
	return nil
}

func writeField(b *ua.Buffer, enc message.FieldEncoding, f *message.Field) {
	if enc == message.FieldEncodingVariant {
		b.WriteStruct(fieldVariant(f))
		return
	}
	var dv ua.DataValue
	if f != nil && f.Value != nil {
		dv = *f.Value
		if dv.EncodingMask == 0 {
			dv.UpdateMask()
		}
	}
	b.WriteStruct(&dv)
}

func fieldVariant(f *message.Field) *ua.Variant {
	if f == nil || f.Value == nil {
		return nil
	}
	return f.Value.Value
}
