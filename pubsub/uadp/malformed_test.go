// SPDX-License-Identifier: MIT

package uadp

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/ua"
)

// Byte vectors of open62541 v1.5.9 tests/pubsub/check_pubsub_encoding.c.
func TestOpen62541DecodeVectors(t *testing.T) {
	// UA_PubSub_Decode_DataSetMessageStartsAtDeclaredOffset: the first
	// DataSetMessage declares 5 bytes and fills 3; the second starts at
	// the declared offset and is not valid.
	nm, err := Decode([]byte{0x41, 0x02, 0x01, 0x00, 0x02, 0x00,
		0x05, 0x00, 0x03, 0x00,
		0x01, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x00}, nil)
	require.NoError(t, err)
	require.Len(t, nm.Messages, 2)
	require.True(t, nm.Messages[0].Valid)
	require.Empty(t, nm.Messages[0].Fields)
	require.False(t, nm.Messages[1].Valid)
	require.Equal(t, uint16(2), nm.Messages[1].DataSetWriterID)

	for name, raw := range map[string][]byte{
		// UA_PubSub_Decode_InvalidVersionReturnsError
		"invalid version": {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		// UA_PubSub_Decode_PayloadHeaderCountZeroReturnsBadDecodingError
		"payload header count zero": {0x41, 0x00},
		// UA_PubSub_Decode_MultiDsmZeroSizeReturnsBadDecodingError
		"zero size": {0x41, 0x02, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00},
		// UA_PubSub_Decode_InvalidPublisherIdTypeReturnsBadInternalError
		"publisher id type 5": {0x91, 0x05},
		// UA_PubSub_Decode_PromotedFieldTruncatedVariant
		"promoted field truncated": {0x81, 0x80, 0x02, 0x01, 0x00, 0x06, 0x2a, 0x00},
		// UA_PubSub_Decode_PromotedFieldsExceedDeclaredSize
		"promoted fields exceed size": {0x81, 0x80, 0x02, 0x01, 0x00, 0x06, 0x2a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00},
		// UA_PubSub_Decode_KeyFrameFieldCountMustFitBuffer (as payload)
		"key frame count": {0x01, 0x01, 0xff, 0xff},
		// UA_PubSub_Decode_DeltaFrameFieldCountMustFitBuffer
		"delta frame count": {0x01, 0x81, 0x01, 0xff, 0xff},
	} {
		_, err := Decode(raw, nil)
		require.ErrorIs(t, err, ErrMalformed, name)
	}

	// UA_PubSub_Decode_RawDataSizeMustFitBuffer: one Byte field.
	md := &ua.DataSetMetaDataType{Fields: []*ua.FieldMetaData{{BuiltInType: uint8(ua.TypeIDByte), DataType: ua.NewNumericNodeID(0, id.Byte), ValueRank: -1}}}
	nm, err = Decode([]byte{0x01, 0x03, 0xaa}, &DecodeOptions{MetaData: metaLookup(md)})
	require.NoError(t, err)
	require.Equal(t, byte(0xaa), nm.Messages[0].Fields[0].Value.Value.Value())
	// A RawData field must fit into its DataSetMessage. (A RawData key
	// frame with nothing after the header is a heartbeat, which open62541
	// writes but its decoder rejects; this decoder accepts it.)
	md.Fields[0].BuiltInType = uint8(ua.TypeIDUint16)
	_, err = Decode([]byte{0x41, 0x02, 0x01, 0x00, 0x02, 0x00, 0x02, 0x00, 0x03, 0x00, 0x03, 0xaa, 0x03, 0xaa, 0xbb}, &DecodeOptions{MetaData: metaLookup(md)})
	require.ErrorIs(t, err, ErrMalformed)
}

func TestDecodeMalformed(t *testing.T) {
	md := &ua.DataSetMetaDataType{Fields: []*ua.FieldMetaData{
		{BuiltInType: uint8(ua.TypeIDString), ValueRank: -1, MaxStringLength: 4},
		{BuiltInType: uint8(ua.TypeIDInt16), ValueRank: 2, ArrayDimensions: []uint32{2, 0}},
	}}
	opts := &DecodeOptions{MetaData: metaLookup(md)}
	for _, tc := range []struct {
		name string
		hex  string
		err  error
	}{
		{"empty", "", ErrMalformed},
		{"version 0", "00", ErrMalformed},
		{"truncated ext1", "81", ErrMalformed},
		{"truncated ext2", "81 80", ErrMalformed},
		{"chunk", "81 80 01", ErrMalformed},
		{"chunk of a probe", "81 80 05", ErrMalformed},
		{"reserved type", "81 80 0c", ErrMalformed},
		{"truncated publisher", "91 02 0102", ErrMalformed},
		{"truncated class id", "81 08 0102", ErrMalformed},
		{"truncated group header", "21 01 01", ErrMalformed},
		{"truncated payload header", "41 02 0100", ErrMalformed},
		{"truncated timestamp", "81 20 0102", ErrMalformed},
		{"truncated promoted size", "81 80 02 01", ErrMalformed},
		{"truncated security", "81 10 01", ErrMalformed},
		{"no payload", "01", ErrMalformed},
		{"truncated sizes", "41 02 0100 0200 05", ErrMalformed},
		{"size beyond payload", "41 02 0100 0200 0500 0100 01", ErrMalformed},
		{"reserved field encoding", "01 07", ErrMalformed},
		{"reserved message type", "01 81 04", ErrUnsupported},
		{"truncated dsm header", "01 89 00", ErrMalformed},
		{"truncated field count", "01 01 01", ErrMalformed},
		{"bad variant", "01 01 0100 3f", ErrMalformed},
		{"truncated datavalue", "01 05 0100 01", ErrMalformed},
		{"truncated delta count", "01 81 01 00", ErrMalformed},
		{"truncated delta value", "01 81 01 0100 0000 06 01", ErrMalformed},
		{"raw string too long", "01 03 05000000 6162636465", ErrMalformed},
		{"raw string padding missing", "01 03 01000000 61 00", ErrMalformed},
		{"raw string truncated", "01 03 09000000 61", ErrMalformed},
		{"raw dimension above bound", "01 03 00000000 00000000 03000000 01000000", ErrMalformed},
		{"raw truncated dimensions", "01 03 00000000 00000000 02000000", ErrMalformed},
		{"raw array larger than message", "01 03 00000000 00000000 02000000 ffff0000", ErrMalformed},
		{"raw zero dimension", "01 03 00000000 00000000 00000000 00000000", ErrMalformed},
		{"raw delta index", "01 83 01 0100 0500 00", ErrMalformed},
	} {
		_, err := Decode(h(t, tc.hex), opts)
		require.ErrorIs(t, err, tc.err, tc.name)
	}

	// RawData without metadata.
	_, err := Decode(h(t, "01 03 aa"), nil)
	require.ErrorIs(t, err, ErrNoMetaData)
	_, err = Decode(h(t, "01 83 01 0100 0000 aa"), nil)
	require.ErrorIs(t, err, ErrNoMetaData)
}

func TestRawDataMetaDataErrors(t *testing.T) {
	cases := []struct {
		name string
		f    *ua.FieldMetaData
		err  error
	}{
		{"no type", &ua.FieldMetaData{ValueRank: -1}, ErrUnsupported},
		{"type 26", &ua.FieldMetaData{BuiltInType: 26, ValueRank: -1}, ErrUnsupported},
		{"value rank any", &ua.FieldMetaData{BuiltInType: 6, ValueRank: -2}, ErrUnsupported},
		{"value rank mismatch", &ua.FieldMetaData{BuiltInType: 6, ValueRank: 1, ArrayDimensions: []uint32{1, 2}}, ErrMalformed},
		{"too many dimensions", &ua.FieldMetaData{BuiltInType: 6, ValueRank: 33}, ErrMalformed},
		{"unknown structure", &ua.FieldMetaData{BuiltInType: 22, DataType: ua.NewNumericNodeID(5, 5), ValueRank: -1}, ErrUnsupported},
		{"structure without type", &ua.FieldMetaData{BuiltInType: 22, ValueRank: -1}, ErrUnsupported},
	}
	for _, tc := range cases {
		md := &ua.DataSetMetaDataType{Fields: []*ua.FieldMetaData{tc.f}}
		_, err := Decode(h(t, "01 03 0100000000000000"), &DecodeOptions{MetaData: metaLookup(md)})
		require.ErrorIs(t, err, tc.err, tc.name)
	}
	_, err := Decode(h(t, "01 03 01"), &DecodeOptions{MetaData: metaLookup(&ua.DataSetMetaDataType{Fields: []*ua.FieldMetaData{nil}})})
	require.ErrorIs(t, err, ErrMalformed)
}

func TestEncodeErrors(t *testing.T) {
	kf := func(fs ...*message.Field) *message.DataSetMessage {
		return keyFrame(message.FieldEncodingVariant, fs...)
	}
	many := make([]*message.DataSetMessage, 256)
	for i := range many {
		many[i] = kf()
	}
	big := make([]*message.Field, 70000)
	bigString := string(make([]byte, 70000))
	md := &ua.DataSetMetaDataType{Fields: []*ua.FieldMetaData{
		{BuiltInType: uint8(ua.TypeIDString), ValueRank: -1, MaxStringLength: 2},
		{BuiltInType: uint8(ua.TypeIDInt32), ValueRank: 1, ArrayDimensions: []uint32{1}},
	}}
	ph := ua.UADPNetworkMessageContentMaskPayloadHeader
	for _, tc := range []struct {
		name string
		nm   *message.NetworkMessage
		md   *ua.DataSetMetaDataType
	}{
		{"nil", nil, nil},
		{"no messages", &message.NetworkMessage{}, nil},
		{"two messages without payload header", &message.NetworkMessage{Messages: []*message.DataSetMessage{kf(), kf()}}, nil},
		{"256 messages", &message.NetworkMessage{UADPMask: ph, Messages: many}, nil},
		{"bad type", &message.NetworkMessage{Type: 7}, nil},
		{"bad publisher type", &message.NetworkMessage{UADPMask: ua.UADPNetworkMessageContentMaskPublisherID, PublisherID: message.PublisherID{Type: 9}, Messages: []*message.DataSetMessage{kf()}}, nil},
		{"nil message", &message.NetworkMessage{Messages: []*message.DataSetMessage{nil}}, nil},
		{"nil message in payload header", &message.NetworkMessage{UADPMask: ph, Messages: []*message.DataSetMessage{kf(), nil}}, nil},
		{"field encoding", &message.NetworkMessage{Messages: []*message.DataSetMessage{{FieldEncoding: 3}}}, nil},
		{"message type", &message.NetworkMessage{Messages: []*message.DataSetMessage{{Type: 4}}}, nil},
		{"too many fields", &message.NetworkMessage{Messages: []*message.DataSetMessage{kf(big...)}}, nil},
		{"too many delta fields", &message.NetworkMessage{Messages: []*message.DataSetMessage{{Type: message.DataSetMessageDeltaFrame, Fields: big}}}, nil},
		{"nil delta field", &message.NetworkMessage{Messages: []*message.DataSetMessage{{Type: message.DataSetMessageDeltaFrame, Fields: []*message.Field{nil}}}}, nil},
		{"oversized message in a group", &message.NetworkMessage{UADPMask: ph, Messages: []*message.DataSetMessage{kf(vf(0, bigString)), kf()}}, nil},
		{"oversized promoted fields", &message.NetworkMessage{UADPMask: ua.UADPNetworkMessageContentMaskPromotedFields, PromotedFields: []*ua.Variant{ua.MustVariant(bigString)}, Messages: []*message.DataSetMessage{kf()}}, nil},
		{"raw field count", &message.NetworkMessage{Messages: []*message.DataSetMessage{keyFrame(message.FieldEncodingRawData, vf(0, "a"))}}, md},
		{"raw string too long", &message.NetworkMessage{Messages: []*message.DataSetMessage{keyFrame(message.FieldEncodingRawData, vf(0, "abc"), vf(1, []int32{1}))}}, md},
		{"raw null", &message.NetworkMessage{Messages: []*message.DataSetMessage{keyFrame(message.FieldEncodingRawData, &message.Field{}, vf(1, []int32{1}))}}, md},
		{"raw type mismatch", &message.NetworkMessage{Messages: []*message.DataSetMessage{keyFrame(message.FieldEncodingRawData, vf(0, int32(1)), vf(1, []int32{1}))}}, md},
		{"raw array for scalar", &message.NetworkMessage{Messages: []*message.DataSetMessage{keyFrame(message.FieldEncodingRawData, vf(0, []string{"a"}), vf(1, []int32{1}))}}, md},
		{"raw scalar for array", &message.NetworkMessage{Messages: []*message.DataSetMessage{keyFrame(message.FieldEncodingRawData, vf(0, "a"), vf(1, int32(1)))}}, md},
		{"raw array too long", &message.NetworkMessage{Messages: []*message.DataSetMessage{keyFrame(message.FieldEncodingRawData, vf(0, "a"), vf(1, []int32{1, 2}))}}, md},
		{"raw dimensions", &message.NetworkMessage{Messages: []*message.DataSetMessage{keyFrame(message.FieldEncodingRawData, vf(0, "a"), vf(1, [][]int32{{1}}))}}, md},
		{"raw null array", &message.NetworkMessage{Messages: []*message.DataSetMessage{keyFrame(message.FieldEncodingRawData, vf(0, "a"), vf(1, []int32(nil)))}}, md},
		{"raw delta index", &message.NetworkMessage{Messages: []*message.DataSetMessage{{Type: message.DataSetMessageDeltaFrame, FieldEncoding: message.FieldEncodingRawData, Fields: []*message.Field{vf(5, "a")}}}}, md},
		{"raw structure without value", &message.NetworkMessage{Messages: []*message.DataSetMessage{keyFrame(message.FieldEncodingRawData, vf(0, &ua.ExtensionObject{}))}}, nil},
	} {
		_, err := Encode(tc.nm, &EncodeOptions{MetaData: metaLookup(tc.md)})
		require.ErrorIs(t, err, ErrMalformed, tc.name)
	}
}

// Fields that the model leaves nil encode as null values.
func TestEncodeNilFields(t *testing.T) {
	nm := &message.NetworkMessage{Messages: []*message.DataSetMessage{
		keyFrame(message.FieldEncodingDataValue, nil, &message.Field{}, &message.Field{Value: &ua.DataValue{Value: ua.MustVariant(int32(1)), Status: ua.StatusBad}}),
	}}
	b, err := Encode(nm, nil)
	require.NoError(t, err)
	require.Equal(t, h(t, "01 05 0300 00 00 03 0601000000 00000080"), b)

	nm.Messages[0].FieldEncoding = message.FieldEncodingVariant
	b, err = Encode(nm, nil)
	require.NoError(t, err)
	require.Equal(t, h(t, "01 01 0300 00 00 0601000000"), b)
}

// RawData structures: a registered structure by its DataType NodeId, or by
// the DefaultEncodingId of the StructureDataTypes; opaque bodies are written
// as they are.
func TestRawDataStructures(t *testing.T) {
	custom := ua.NewNumericNodeID(3, 1000)
	md := &ua.DataSetMetaDataType{
		StructureDataTypes: []*ua.StructureDescription{{
			DataTypeID:          custom,
			StructureDefinition: &ua.StructureDefinition{DefaultEncodingID: ua.NewNumericNodeID(0, id.RangeEncodingDefaultBinary)},
		}},
		Fields: []*ua.FieldMetaData{
			{Name: "r", BuiltInType: uint8(ua.TypeIDExtensionObject), DataType: custom, ValueRank: 1, ArrayDimensions: []uint32{2}},
		},
	}
	r := []*ua.ExtensionObject{ua.NewExtensionObject(&ua.Range{Low: 1, High: 2}), ua.NewExtensionObject(&ua.Range{Low: 3, High: 4})}
	nm := &message.NetworkMessage{Messages: []*message.DataSetMessage{keyFrame(message.FieldEncodingRawData, vf(0, r))}}
	nm.Messages[0].Fields[0].Name = "r"
	b, err := Encode(nm, &EncodeOptions{MetaData: metaLookup(md)})
	require.NoError(t, err)
	require.Equal(t, h(t, "01 03 02000000 000000000000f03f 0000000000000040 0000000000000840 0000000000001040"), b)
	got, err := Decode(b, &DecodeOptions{MetaData: metaLookup(md)})
	require.NoError(t, err)
	require.Equal(t, nm, got)

	// An opaque body.
	opaque := &ua.ExtensionObject{EncodingMask: ua.ExtensionObjectBinary, TypeID: ua.NewFourByteExpandedNodeID(3, 1001), Value: []byte{1, 2, 3}}
	b, err = Encode(&message.NetworkMessage{Messages: []*message.DataSetMessage{keyFrame(message.FieldEncodingRawData, vf(0, opaque))}}, nil)
	require.NoError(t, err)
	require.Equal(t, h(t, "01 03 010203"), b)

	// A field of DataType BaseDataType (built-in type Variant) is a
	// Variant, also in RawData.
	mdv := &ua.DataSetMetaDataType{Fields: []*ua.FieldMetaData{{Name: "v", BuiltInType: uint8(ua.TypeIDVariant), ValueRank: -1}}}
	nm = &message.NetworkMessage{Messages: []*message.DataSetMessage{keyFrame(message.FieldEncodingRawData, vf(0, int32(7)))}}
	nm.Messages[0].Fields[0].Name = "v"
	b, err = Encode(nm, &EncodeOptions{MetaData: metaLookup(mdv)})
	require.NoError(t, err)
	require.Equal(t, h(t, "01 03 0607000000"), b)
	got, err = Decode(b, &DecodeOptions{MetaData: metaLookup(mdv)})
	require.NoError(t, err)
	require.Equal(t, nm, got)
	_, err = Decode(h(t, "01 03 3f"), &DecodeOptions{MetaData: metaLookup(mdv)})
	require.ErrorIs(t, err, ErrMalformed)
}

func TestPeekType(t *testing.T) {
	for _, tc := range []struct {
		hex   string
		typ   message.NetworkMessageType
		chunk bool
		err   bool
	}{
		{"", 0, false, true},
		{"02", 0, false, true},
		{"01", message.NetworkMessageDataSet, false, false},
		{"81", message.NetworkMessageDataSet, false, false},
		{"81 01", message.NetworkMessageDataSet, false, false},
		{"81 80", 0, false, true},
		{"91 80 04", message.NetworkMessageDiscoveryRequest, false, false},
		{"91 80 09", message.NetworkMessageDiscoveryResponse, true, false},
	} {
		typ, chunk, err := PeekType(h(t, tc.hex))
		if tc.err {
			require.ErrorIs(t, err, ErrMalformed, tc.hex)
			continue
		}
		require.NoError(t, err, tc.hex)
		require.Equal(t, tc.typ, typ, tc.hex)
		require.Equal(t, tc.chunk, chunk, tc.hex)
	}
}
