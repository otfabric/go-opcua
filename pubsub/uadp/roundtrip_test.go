// SPDX-License-Identifier: MIT

package uadp

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/ua"
)

var nmMaskBits = []ua.UADPNetworkMessageContentMask{
	ua.UADPNetworkMessageContentMaskPublisherID,
	ua.UADPNetworkMessageContentMaskGroupHeader,
	ua.UADPNetworkMessageContentMaskWriterGroupID,
	ua.UADPNetworkMessageContentMaskGroupVersion,
	ua.UADPNetworkMessageContentMaskNetworkMessageNumber,
	ua.UADPNetworkMessageContentMaskSequenceNumber,
	ua.UADPNetworkMessageContentMaskPayloadHeader,
	ua.UADPNetworkMessageContentMaskTimestamp,
	ua.UADPNetworkMessageContentMaskPicoSeconds,
	ua.UADPNetworkMessageContentMaskDataSetClassID,
	ua.UADPNetworkMessageContentMaskPromotedFields,
}

const groupSubMask = ua.UADPNetworkMessageContentMaskWriterGroupID | ua.UADPNetworkMessageContentMaskGroupVersion |
	ua.UADPNetworkMessageContentMaskNetworkMessageNumber | ua.UADPNetworkMessageContentMaskSequenceNumber

// fullNetworkMessage returns a message with every header field set and the
// mask m. expected is what a decoder returns: the fields the mask does not
// select are zero.
func fullNetworkMessage(m ua.UADPNetworkMessageContentMask, pub message.PublisherID, msgs []*message.DataSetMessage) (in, expected *message.NetworkMessage) {
	in = &message.NetworkMessage{
		UADPMask:       m,
		PublisherID:    pub,
		DataSetClassID: &ua.GUID{Data1: 1, Data2: 2, Data3: 3, Data4: []byte{4, 5, 6, 7, 8, 9, 10, 11}},
		GroupHeader:    message.GroupHeader{WriterGroupID: 1, GroupVersion: 2, NetworkMessageNumber: 3, SequenceNumber: 4},
		Timestamp:      ts,
		PicoSeconds:    5,
		PromotedFields: []*ua.Variant{ua.MustVariant(int32(1)), ua.MustVariant("two")},
		Messages:       msgs,
	}
	e := *in
	has := func(b ua.UADPNetworkMessageContentMask) bool { return m&b != 0 }
	if !has(ua.UADPNetworkMessageContentMaskGroupHeader) {
		e.UADPMask &^= groupSubMask
	}
	g := e.GroupHeader
	e.GroupHeader = message.GroupHeader{}
	if e.UADPMask&ua.UADPNetworkMessageContentMaskWriterGroupID != 0 {
		e.GroupHeader.WriterGroupID = g.WriterGroupID
	}
	if e.UADPMask&ua.UADPNetworkMessageContentMaskGroupVersion != 0 {
		e.GroupHeader.GroupVersion = g.GroupVersion
	}
	if e.UADPMask&ua.UADPNetworkMessageContentMaskNetworkMessageNumber != 0 {
		e.GroupHeader.NetworkMessageNumber = g.NetworkMessageNumber
	}
	if e.UADPMask&ua.UADPNetworkMessageContentMaskSequenceNumber != 0 {
		e.GroupHeader.SequenceNumber = g.SequenceNumber
	}
	if !has(ua.UADPNetworkMessageContentMaskPublisherID) {
		e.PublisherID = message.PublisherID{}
	}
	if !has(ua.UADPNetworkMessageContentMaskDataSetClassID) {
		e.DataSetClassID = nil
	}
	if !has(ua.UADPNetworkMessageContentMaskTimestamp) {
		e.Timestamp = time.Time{}
	}
	if !has(ua.UADPNetworkMessageContentMaskPicoSeconds) {
		e.PicoSeconds = 0
	}
	if !has(ua.UADPNetworkMessageContentMaskPromotedFields) {
		e.PromotedFields = nil
	}
	if !has(ua.UADPNetworkMessageContentMaskPayloadHeader) {
		e.Messages = nil
		for _, dm := range msgs {
			c := *dm
			c.DataSetWriterID = 0
			e.Messages = append(e.Messages, &c)
		}
	}
	return in, &e
}

// TestRoundTripNetworkMessageMasks encodes every combination of the network
// message content mask with every PublisherId type, unsecured, signed and
// encrypted.
func TestRoundTripNetworkMessageMasks(t *testing.T) {
	pubs := []message.PublisherID{
		message.NewPublisherID(message.PublisherIDByte, 0xfe),
		message.NewPublisherID(message.PublisherIDUInt16, 0xfedc),
		message.NewPublisherID(message.PublisherIDUInt32, 0xfedcba98),
		message.NewPublisherID(message.PublisherIDUInt64, 0xfedcba9876543210),
		message.StringPublisherID("publisher"),
	}
	ks := zeroKeys(testPolicy{nonceRandom: [4]byte{1, 2, 3, 4}})
	modes := []ua.MessageSecurityMode{ua.MessageSecurityModeNone, ua.MessageSecurityModeSign, ua.MessageSecurityModeSignAndEncrypt}
	for bits := range 1 << len(nmMaskBits) {
		var m ua.UADPNetworkMessageContentMask
		for i, b := range nmMaskBits {
			if bits&(1<<i) != 0 {
				m |= b
			}
		}
		pub := pubs[bits%len(pubs)]
		mode := modes[bits%len(modes)]
		msg := keyFrame(message.FieldEncodingVariant, vf(0, int32(bits)))
		msg.DataSetWriterID = 9
		in, want := fullNetworkMessage(m, pub, []*message.DataSetMessage{msg})
		b, err := Encode(in, &EncodeOptions{SecurityMode: mode, Keys: ks, NonceSequence: uint32(bits)})
		require.NoError(t, err, "mask %v", m)
		got, err := Decode(b, &DecodeOptions{Security: requireSecurity(mode, ks)})
		require.NoError(t, err, "mask %v", m)
		if mode != ua.MessageSecurityModeNone {
			require.NotNil(t, got.Security)
			require.Equal(t, mode == ua.MessageSecurityModeSignAndEncrypt, got.Security.Encrypted)
			got.Security = nil
		}
		require.Equal(t, want, got, "mask %v", m)
	}
}

// TestRoundTripDataSetMessages encodes every combination of the DataSetMessage
// content mask with every message type and field encoding.
func TestRoundTripDataSetMessages(t *testing.T) {
	md := &ua.DataSetMetaDataType{Fields: []*ua.FieldMetaData{
		{Name: "i", BuiltInType: uint8(ua.TypeIDInt32), ValueRank: -1},
		{Name: "s", BuiltInType: uint8(ua.TypeIDString), ValueRank: -1},
		{Name: "d", BuiltInType: uint8(ua.TypeIDDouble), ValueRank: 1},
	}}
	fieldsFor := func(enc message.FieldEncoding, typ message.DataSetMessageType) []*message.Field {
		var fs []*message.Field
		switch typ {
		case message.DataSetMessageKeepAlive:
			return nil
		case message.DataSetMessageDeltaFrame:
			fs = []*message.Field{vf(2, []float64{1.5, 2.5}), vf(0, int32(-3))}
		default:
			fs = []*message.Field{vf(0, int32(-3)), vf(1, "x"), vf(2, []float64{1.5})}
		}
		for _, f := range fs {
			f.Name = md.Fields[f.Index].Name
			if enc == message.FieldEncodingDataValue {
				f.Value.EncodingMask |= ua.DataValueSourceTimestamp
				f.Value.SourceTimestamp = ts
			}
		}
		return fs
	}
	all := ua.UADPDataSetMessageContentMaskTimestamp | ua.UADPDataSetMessageContentMaskPicoSeconds |
		ua.UADPDataSetMessageContentMaskStatus | ua.UADPDataSetMessageContentMaskMajorVersion |
		ua.UADPDataSetMessageContentMaskMinorVersion | ua.UADPDataSetMessageContentMaskSequenceNumber
	for mask := ua.UADPDataSetMessageContentMask(0); mask <= all; mask++ {
		for typ := message.DataSetMessageKeyFrame; typ <= message.DataSetMessageKeepAlive; typ++ {
			for enc := message.FieldEncodingVariant; enc <= message.FieldEncodingDataValue; enc++ {
				name := fmt.Sprintf("mask %v type %v encoding %v", mask, typ, enc)
				in := &message.DataSetMessage{
					DataSetWriterID: 1, Type: typ, Valid: true, FieldEncoding: enc, UADPMask: mask,
					SequenceNumber: 0xbeef, Timestamp: ts, PicoSeconds: 7, Status: ua.StatusUncertain,
					MetaDataVersion: ua.ConfigurationVersionDataType{MajorVersion: 1, MinorVersion: 2},
					Fields:          fieldsFor(enc, typ),
				}
				want := *in
				if mask&ua.UADPDataSetMessageContentMaskSequenceNumber == 0 {
					want.SequenceNumber = 0
				}
				if mask&ua.UADPDataSetMessageContentMaskTimestamp == 0 {
					want.Timestamp = time.Time{}
				}
				if mask&ua.UADPDataSetMessageContentMaskPicoSeconds == 0 {
					want.PicoSeconds = 0
				}
				if mask&ua.UADPDataSetMessageContentMaskStatus == 0 {
					want.Status = 0
				}
				if mask&ua.UADPDataSetMessageContentMaskMajorVersion == 0 {
					want.MetaDataVersion.MajorVersion = 0
				}
				if mask&ua.UADPDataSetMessageContentMaskMinorVersion == 0 {
					want.MetaDataVersion.MinorVersion = 0
				}
				// Two messages: the second one is the same with
				// another writer id, so the Sizes are exercised.
				in2 := *in
				in2.DataSetWriterID = 2
				want2 := want
				want2.DataSetWriterID = 2
				nm := &message.NetworkMessage{UADPMask: ua.UADPNetworkMessageContentMaskPayloadHeader, Messages: []*message.DataSetMessage{in, &in2}}
				b, err := Encode(nm, &EncodeOptions{MetaData: metaLookup(md)})
				require.NoError(t, err, name)
				got, err := Decode(b, &DecodeOptions{MetaData: metaLookup(md)})
				require.NoError(t, err, name)
				require.Equal(t, []*message.DataSetMessage{&want, &want2}, got.Messages, name)
			}
		}
	}
}

// TestRawDataTypes round-trips every built-in type through RawData, as
// scalar and as array.
func TestRawDataTypes(t *testing.T) {
	values := []any{
		true, int8(-1), byte(2), int16(-3), uint16(4), int32(-5), uint32(6), int64(-7), uint64(8),
		float32(9.5), float64(10.5), "eleven", ts,
		&ua.GUID{Data1: 1, Data2: 2, Data3: 3, Data4: []byte{1, 2, 3, 4, 5, 6, 7, 8}},
		[]byte{0xb, 0xc},
		ua.XMLElement("<x/>"),
		ua.NewNumericNodeID(1, 17), ua.NewNumericExpandedNodeID(2, 18), ua.StatusBadInternalError,
		&ua.QualifiedName{NamespaceIndex: 1, Name: "q"}, ua.NewLocalizedText("l"),
		&ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int32(23))},
		ua.MustVariant("variant"),
		&ua.DiagnosticInfo{},
	}
	for _, v := range values {
		variant := ua.MustVariant(v)
		fmdScalar := &ua.FieldMetaData{Name: "s", BuiltInType: uint8(variant.Type()), ValueRank: -1}
		fmdArray := &ua.FieldMetaData{Name: "a", BuiltInType: uint8(variant.Type()), ValueRank: 1}
		md := &ua.DataSetMetaDataType{Fields: []*ua.FieldMetaData{fmdScalar, fmdArray}}
		arr := arrayOf(v)
		msg := keyFrame(message.FieldEncodingRawData, vf(0, v), vf(1, arr))
		msg.Fields[0].Name, msg.Fields[1].Name = "s", "a"
		nm := &message.NetworkMessage{Messages: []*message.DataSetMessage{msg}}
		b, err := Encode(nm, &EncodeOptions{MetaData: metaLookup(md)})
		require.NoError(t, err, "%T", v)
		got, err := Decode(b, &DecodeOptions{MetaData: metaLookup(md)})
		require.NoError(t, err, "%T", v)
		require.Equal(t, nm, got, "%T", v)

		// Without metadata, the encoder writes the same bytes.
		b2, err := Encode(nm, nil)
		require.NoError(t, err, "%T", v)
		require.Equal(t, b, b2, "%T", v)
	}
}

// arrayOf returns a Variant array of two v.
func arrayOf(v any) any {
	if b, ok := v.(byte); ok {
		return ua.ByteArray{b, b}
	}
	a := reflect.MakeSlice(reflect.SliceOf(reflect.TypeOf(v)), 2, 2)
	a.Index(0).Set(reflect.ValueOf(v))
	a.Index(1).Set(reflect.ValueOf(v))
	return a.Interface()
}
