// SPDX-License-Identifier: MIT

package uadp

import (
	"fmt"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/ua"
)

type decoder struct {
	// b is a private copy of the message: decryption works in place and
	// decoded values (ByteStrings, Guids) may alias it.
	b    []byte
	opts *DecodeOptions
}

func (d *decoder) decode() (*message.NetworkMessage, error) {
	nm, hdrEnd, err := decodeHeaders(d.b)
	if err != nil {
		return nil, err
	}
	if d.opts.Accept != nil && !d.opts.Accept(nm) {
		return nil, ErrFiltered
	}
	body, err := d.unprotect(nm, hdrEnd)
	if err != nil {
		return nil, err
	}
	if nm.Security != nil && nm.Security.FooterSize > 0 {
		n := int(nm.Security.FooterSize)
		if n > len(body) {
			return nil, malformed("security footer of %d bytes, %d left", n, len(body))
		}
		body = body[:len(body)-n]
	}
	if nm.Action != nil {
		a, n, err := decodeActionHeader(body)
		if err != nil {
			return nil, err
		}
		nm.Action = a
		body = body[n:]
	}
	switch {
	case nm.Chunk != nil:
		nm.Chunk, err = decodeChunk(body)
	case nm.Type == message.NetworkMessageDiscoveryResponse:
		nm.Discovery, err = decodeDiscovery(body)
	case nm.Type == message.NetworkMessageDiscoveryRequest:
		nm.Request, err = decodeDiscoveryRequest(body)
	default:
		if err = d.decodePayload(nm, body); err == nil {
			err = checkActionMessages(nm)
		}
	}
	if err != nil {
		return nil, err
	}
	return nm, nil
}

// PeekType returns the NetworkMessage type of an encoded UADP NetworkMessage
// from its flags, without decoding it, and whether it is a chunk.
func PeekType(b []byte) (t message.NetworkMessageType, chunk bool, err error) {
	if len(b) == 0 || b[0]&flagsVersionMask != UADPVersion {
		return 0, false, malformed("not a UADP NetworkMessage")
	}
	if b[0]&flagsExtended1 == 0 || len(b) < 2 || b[1]&ext1Extended2 == 0 {
		return message.NetworkMessageDataSet, false, nil
	}
	if len(b) < 3 {
		return 0, false, malformed("truncated ExtendedFlags2")
	}
	return message.NetworkMessageType((b[2] & ext2TypeMask) >> ext2TypeShift), b[2]&ext2Chunk != 0, nil
}

// decodeHeaders decodes everything up to and including the security header.
// It returns the offset of the payload.
func decodeHeaders(data []byte) (*message.NetworkMessage, int, error) {
	b := ua.NewBuffer(data)
	nm := &message.NetworkMessage{}

	flags := b.ReadUint8()
	if b.Error() != nil {
		return nil, 0, malformed("empty message")
	}
	if v := flags & flagsVersionMask; v != UADPVersion {
		return nil, 0, malformed("UADP version %d", v)
	}
	var ext1, ext2 byte
	if flags&flagsExtended1 != 0 {
		ext1 = b.ReadUint8()
		if ext1&ext1Extended2 != 0 {
			ext2 = b.ReadUint8()
		}
	}
	switch t := message.NetworkMessageType((ext2 & ext2TypeMask) >> ext2TypeShift); t {
	case message.NetworkMessageDataSet, message.NetworkMessageDiscoveryResponse, message.NetworkMessageDiscoveryRequest:
		nm.Type = t
	default:
		return nil, 0, malformed("NetworkMessage type %d", t)
	}
	if ext2&ext2Chunk != 0 {
		// A chunk of a DataSetMessage or of an announcement (Part 14
		// §7.2.4.4.4 in 1.05); its payload is decoded after the security.
		if nm.Type == message.NetworkMessageDiscoveryRequest {
			return nil, 0, malformed("chunk of a discovery probe")
		}
		nm.Chunk = &message.Chunk{}
	}
	if ext2&ext2Action != 0 {
		// The ActionHeader follows the security header; it is decoded
		// with the payload (decodeActionHeader).
		if nm.Type != message.NetworkMessageDataSet {
			return nil, 0, malformed("ActionHeader in a NetworkMessage of type %d", nm.Type)
		}
		if nm.Chunk != nil {
			return nil, 0, unsupported("chunked action messages")
		}
		nm.Action = &message.ActionHeader{}
	}

	mask := ua.UADPNetworkMessageContentMaskNone
	if flags&flagsPublisherID != 0 {
		mask |= ua.UADPNetworkMessageContentMaskPublisherID
		nm.PublisherID.Type = message.PublisherIDType(ext1 & ext1PublisherIDTypeMask)
		switch nm.PublisherID.Type {
		case message.PublisherIDByte:
			nm.PublisherID.Num = uint64(b.ReadUint8())
		case message.PublisherIDUInt16:
			nm.PublisherID.Num = uint64(b.ReadUint16())
		case message.PublisherIDUInt32:
			nm.PublisherID.Num = uint64(b.ReadUint32())
		case message.PublisherIDUInt64:
			nm.PublisherID.Num = b.ReadUint64()
		case message.PublisherIDString:
			nm.PublisherID.Str = b.ReadString()
		default:
			return nil, 0, malformed("PublisherId type %d", nm.PublisherID.Type)
		}
	}
	if ext1&ext1DataSetClassID != 0 {
		mask |= ua.UADPNetworkMessageContentMaskDataSetClassID
		nm.DataSetClassID = new(ua.GUID)
		b.ReadStruct(nm.DataSetClassID)
	}

	if flags&flagsGroupHeader != 0 {
		mask |= ua.UADPNetworkMessageContentMaskGroupHeader
		gf := b.ReadUint8()
		for _, f := range groupFields {
			if gf&f.flag != 0 {
				mask |= f.mask
				f.dec(b, &nm.GroupHeader)
			}
		}
	}

	if flags&flagsPayloadHeader != 0 {
		if nm.Type != message.NetworkMessageDataSet {
			return nil, 0, malformed("PayloadHeader in a discovery message")
		}
		mask |= ua.UADPNetworkMessageContentMaskPayloadHeader
		if nm.Chunk != nil {
			// The PayloadHeader of a chunk is the DataSetWriterId
			// (Part 14 Table 158 in 1.05).
			nm.Messages = []*message.DataSetMessage{{DataSetWriterID: b.ReadUint16()}}
		} else {
			n := int(b.ReadUint8())
			if b.Error() == nil && n == 0 {
				return nil, 0, malformed("PayloadHeader without DataSetMessages")
			}
			ids := b.ReadN(2 * n)
			if b.Error() == nil {
				nm.Messages = make([]*message.DataSetMessage, n)
				for i := range nm.Messages {
					nm.Messages[i] = &message.DataSetMessage{DataSetWriterID: uint16(ids[2*i]) | uint16(ids[2*i+1])<<8}
				}
			}
		}
	} else if nm.Type == message.NetworkMessageDataSet {
		// Without PayloadHeader there is one DataSetMessage of an
		// unknown writer (open62541 assumes one unless configured).
		nm.Messages = []*message.DataSetMessage{{}}
	}

	if ext1&ext1Timestamp != 0 {
		mask |= ua.UADPNetworkMessageContentMaskTimestamp
		nm.Timestamp = b.ReadTime()
	}
	if ext1&ext1PicoSeconds != 0 {
		mask |= ua.UADPNetworkMessageContentMaskPicoSeconds
		nm.PicoSeconds = b.ReadUint16()
	}
	if ext2&ext2PromotedFields != 0 {
		mask |= ua.UADPNetworkMessageContentMaskPromotedFields
		// The PromotedFields are confined to their declared size
		// (Part 14 §7.2.4.4.2 in 1.05).
		pf := ua.NewBuffer(b.ReadN(int(b.ReadUint16())))
		for b.Error() == nil && pf.Len() > 0 {
			v := new(ua.Variant)
			pf.ReadStruct(v)
			if pf.Error() != nil {
				return nil, 0, malformed("promoted field %d: %v", len(nm.PromotedFields), pf.Error())
			}
			nm.PromotedFields = append(nm.PromotedFields, v)
		}
	}
	nm.UADPMask = mask

	if ext1&ext1Security != 0 {
		if b.Error() != nil {
			return nil, 0, malformed("truncated header")
		}
		h, err := decodeSecurityHeader(b)
		if err != nil {
			return nil, 0, err
		}
		nm.Security = h
	}
	if b.Error() != nil {
		return nil, 0, malformed("truncated header")
	}
	return nm, b.Pos(), nil
}

// decodePayload decodes the Sizes and the DataSetMessages. With Sizes, every
// DataSetMessage is confined to its size and the next one starts at the
// declared offset, however far the decoding of the previous one got
// (Part 14 §7.2.4.5.3 in 1.05, as open62541).
func (d *decoder) decodePayload(nm *message.NetworkMessage, payload []byte) error {
	n := len(nm.Messages)
	spans := [][]byte{payload}
	if n > 1 {
		if len(payload) < 2*n {
			return malformed("truncated payload sizes")
		}
		spans = make([][]byte, n)
		off := 2 * n
		for i := range spans {
			size := int(payload[2*i]) | int(payload[2*i+1])<<8
			if size == 0 || off+size > len(payload) {
				return malformed("DataSetMessage %d of %d bytes, %d left", i, size, len(payload)-off)
			}
			spans[i] = payload[off : off+size]
			off += size
		}
	}
	for i, m := range nm.Messages {
		if err := d.decodeDataSetMessage(nm, m, spans[i]); err != nil {
			return wrapIndex(i, err)
		}
	}
	return nil
}

func (d *decoder) metaData(nm *message.NetworkMessage, m *message.DataSetMessage) *ua.DataSetMetaDataType {
	if d.opts.MetaData == nil {
		return nil
	}
	return d.opts.MetaData(nm.PublisherID, nm.GroupHeader.WriterGroupID, m.DataSetWriterID)
}

func (d *decoder) decodeDataSetMessage(nm *message.NetworkMessage, m *message.DataSetMessage, data []byte) error {
	b := ua.NewBuffer(data)
	f1 := b.ReadUint8()
	m.Valid = f1&dsf1Valid != 0
	m.FieldEncoding = message.FieldEncoding((f1 & dsf1EncodingMask) >> dsf1EncodingShift)
	if m.FieldEncoding > message.FieldEncodingDataValue {
		return malformed("reserved field encoding %d", m.FieldEncoding)
	}
	var f2 byte
	if f1&dsf1Flags2 != 0 {
		f2 = b.ReadUint8()
	}
	m.Type = message.DataSetMessageType(f2 & dsf2TypeMask)
	isAction := m.Type == message.DataSetMessageActionRequest || m.Type == message.DataSetMessageActionResponse
	if m.Type > message.DataSetMessageKeepAlive && !isAction {
		return unsupported("DataSetMessage type %d", m.Type)
	}
	for _, f := range dsmFields {
		flags := f1
		if f.flags2 {
			flags = f2
		}
		if flags&f.flag != 0 {
			m.UADPMask |= f.mask
			f.dec(b, m)
		}
	}
	if b.Error() != nil {
		return malformed("truncated DataSetMessage header")
	}
	// The content of an invalid DataSetMessage is to be ignored; its
	// size (or the end of the payload) says where the next one starts.
	if !m.Valid {
		return nil
	}

	var md *ua.DataSetMetaDataType
	if m.FieldEncoding == message.FieldEncodingRawData || d.opts.MetaData != nil {
		md = d.metaData(nm, m)
	}
	var err error
	switch m.Type {
	case message.DataSetMessageKeyFrame, message.DataSetMessageEvent:
		err = decodeKeyFrame(b, m, md)
	case message.DataSetMessageDeltaFrame:
		err = decodeDeltaFrame(b, m, md)
	case message.DataSetMessageActionRequest, message.DataSetMessageActionResponse:
		err = decodeAction(b, m, md)
	default: // keep-alive: no payload
	}
	if err != nil {
		return err
	}
	if md != nil {
		for _, f := range m.Fields {
			if int(f.Index) < len(md.Fields) && md.Fields[f.Index] != nil {
				f.Name = md.Fields[f.Index].Name
			}
		}
	}
	return nil
}

func decodeKeyFrame(b *ua.Buffer, m *message.DataSetMessage, md *ua.DataSetMetaDataType) error {
	if m.FieldEncoding == message.FieldEncodingRawData {
		// No FieldCount: the fields are those of the DataSetMetaData.
		// Nothing after the header is a heartbeat.
		if b.Len() == 0 {
			return nil
		}
		if md == nil {
			return ErrNoMetaData
		}
		m.Fields = make([]*message.Field, len(md.Fields))
		for i := range md.Fields {
			v, err := readRawField(b, md, i)
			if err != nil {
				return err
			}
			m.Fields[i] = &message.Field{Index: uint16(i), Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: v}}
		}
		return nil
	}
	n := int(b.ReadUint16())
	if b.Error() != nil {
		return malformed("truncated field count")
	}
	// Every field takes at least one byte.
	if n > b.Len() {
		return malformed("%d fields in %d bytes", n, b.Len())
	}
	m.Fields = make([]*message.Field, n)
	for i := range m.Fields {
		dv, err := readField(b, m.FieldEncoding)
		if err != nil {
			return wrapField(i, err)
		}
		m.Fields[i] = &message.Field{Index: uint16(i), Value: dv}
	}
	return nil
}

func decodeDeltaFrame(b *ua.Buffer, m *message.DataSetMessage, md *ua.DataSetMetaDataType) error {
	n := int(b.ReadUint16())
	if b.Error() != nil {
		return malformed("truncated field count")
	}
	// Every field takes its index and at least one byte.
	if 3*n > b.Len() {
		return malformed("%d delta fields in %d bytes", n, b.Len())
	}
	if m.FieldEncoding == message.FieldEncodingRawData && md == nil {
		return ErrNoMetaData
	}
	m.Fields = make([]*message.Field, n)
	for i := range m.Fields {
		idx := b.ReadUint16()
		var dv *ua.DataValue
		var err error
		if m.FieldEncoding == message.FieldEncodingRawData {
			var v *ua.Variant
			if v, err = readRawField(b, md, int(idx)); err == nil {
				dv = &ua.DataValue{EncodingMask: ua.DataValueValue, Value: v}
			}
		} else {
			dv, err = readField(b, m.FieldEncoding)
		}
		if err != nil {
			return wrapField(i, err)
		}
		m.Fields[i] = &message.Field{Index: idx, Value: dv}
	}
	return nil
}

func readField(b *ua.Buffer, enc message.FieldEncoding) (*ua.DataValue, error) {
	if enc == message.FieldEncodingVariant {
		v := new(ua.Variant)
		b.ReadStruct(v)
		if b.Error() != nil {
			return nil, malformed("%v", b.Error())
		}
		return &ua.DataValue{EncodingMask: ua.DataValueValue, Value: v}, nil
	}
	dv := new(ua.DataValue)
	b.ReadStruct(dv)
	if b.Error() != nil {
		return nil, malformed("%v", b.Error())
	}
	return dv, nil
}

func wrapIndex(i int, err error) error {
	return fmt.Errorf("DataSetMessage %d: %w", i, err)
}

func wrapField(i int, err error) error {
	return fmt.Errorf("field %d: %w", i, err)
}
