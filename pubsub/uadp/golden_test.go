// SPDX-License-Identifier: MIT

package uadp

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/ua"
)

// ts is the DateTime 0x01d73a9f94c25410 of open62541's decryption vector.
var ts = time.Unix(0x01d73a9f94c25410/10_000_000-11644473600, (0x01d73a9f94c25410%10_000_000)*100).UTC()

// vf is a field with the Variant v.
func vf(i int, v any) *message.Field {
	return &message.Field{Index: uint16(i), Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)}}
}

func keyFrame(enc message.FieldEncoding, fields ...*message.Field) *message.DataSetMessage {
	return &message.DataSetMessage{Valid: true, FieldEncoding: enc, Fields: fields}
}

// h strips the spaces of a readable hex string.
func h(t testing.TB, s string) []byte {
	return unhex(t, strings.ReplaceAll(s, " ", ""))
}

type golden struct {
	name string
	nm   *message.NetworkMessage
	hex  string
	md   *ua.DataSetMetaDataType
}

func metaLookup(md *ua.DataSetMetaDataType) message.MetaDataLookup {
	if md == nil {
		return nil
	}
	return func(message.PublisherID, uint16, uint16) *ua.DataSetMetaDataType { return md }
}

func goldenVectors() []golden {
	nm := func(mask ua.UADPNetworkMessageContentMask, msgs ...*message.DataSetMessage) *message.NetworkMessage {
		return &message.NetworkMessage{UADPMask: mask, Messages: msgs}
	}
	withPub := func(p message.PublisherID) *message.NetworkMessage {
		m := nm(ua.UADPNetworkMessageContentMaskPublisherID, keyFrame(message.FieldEncodingVariant, vf(0, int32(27))))
		m.PublisherID = p
		return m
	}

	full := nm(ua.UADPNetworkMessageContentMaskPublisherID|ua.UADPNetworkMessageContentMaskGroupHeader|
		ua.UADPNetworkMessageContentMaskWriterGroupID|ua.UADPNetworkMessageContentMaskGroupVersion|
		ua.UADPNetworkMessageContentMaskNetworkMessageNumber|ua.UADPNetworkMessageContentMaskSequenceNumber|
		ua.UADPNetworkMessageContentMaskPayloadHeader|ua.UADPNetworkMessageContentMaskTimestamp|
		ua.UADPNetworkMessageContentMaskPicoSeconds|ua.UADPNetworkMessageContentMaskDataSetClassID|
		ua.UADPNetworkMessageContentMaskPromotedFields,
		keyFrame(message.FieldEncodingVariant, vf(0, true)),
		&message.DataSetMessage{Valid: true, Type: message.DataSetMessageKeepAlive,
			UADPMask: ua.UADPDataSetMessageContentMaskSequenceNumber, SequenceNumber: 0x0203})
	full.PublisherID = message.NewPublisherID(message.PublisherIDByte, 7)
	full.DataSetClassID = &ua.GUID{Data1: 0x12345678, Data2: 0xabcd, Data3: 0xef01, Data4: []byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80}}
	full.GroupHeader = message.GroupHeader{WriterGroupID: 0x0102, GroupVersion: 0x01020304, NetworkMessageNumber: 5, SequenceNumber: 6}
	full.Messages[0].DataSetWriterID = 10
	full.Messages[1].DataSetWriterID = 11
	full.Timestamp = ts
	full.PicoSeconds = 0x0102
	full.PromotedFields = []*ua.Variant{ua.MustVariant(int32(42))}

	delta := &message.DataSetMessage{
		Valid: true, Type: message.DataSetMessageDeltaFrame, FieldEncoding: message.FieldEncodingDataValue,
		UADPMask: ua.UADPDataSetMessageContentMaskSequenceNumber | ua.UADPDataSetMessageContentMaskTimestamp |
			ua.UADPDataSetMessageContentMaskPicoSeconds | ua.UADPDataSetMessageContentMaskStatus |
			ua.UADPDataSetMessageContentMaskMajorVersion | ua.UADPDataSetMessageContentMaskMinorVersion,
		SequenceNumber: 0x0102, Timestamp: ts, PicoSeconds: 0x0304, Status: ua.StatusBadNodeIDUnknown,
		MetaDataVersion: ua.ConfigurationVersionDataType{MajorVersion: 10, MinorVersion: 11},
		Fields: []*message.Field{
			{Index: 3, Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(uint16(7))}},
			{Index: 5, Value: &ua.DataValue{EncodingMask: ua.DataValueValue | ua.DataValueStatusCode, Value: ua.MustVariant(int32(-1)), Status: ua.StatusBad}},
		},
	}

	rawMD := &ua.DataSetMetaDataType{Fields: []*ua.FieldMetaData{
		{Name: "b", BuiltInType: uint8(ua.TypeIDByte), ValueRank: -1},
		{Name: "s", BuiltInType: uint8(ua.TypeIDString), ValueRank: -1, MaxStringLength: 8},
		{Name: "a", BuiltInType: uint8(ua.TypeIDUint32), ValueRank: 1, ArrayDimensions: []uint32{2}},
		{Name: "m", DataType: ua.NewNumericNodeID(0, id.Int16), ValueRank: 2, ArrayDimensions: []uint32{2, 2}},
		{Name: "r", BuiltInType: uint8(ua.TypeIDExtensionObject), DataType: ua.NewNumericNodeID(0, id.Range), ValueRank: -1},
	}}
	raw := keyFrame(message.FieldEncodingRawData,
		vf(0, byte(0xaa)), vf(1, "abc"), vf(2, []uint32{1, 2}), vf(3, [][]int16{{1, 2}, {3, 4}}),
		vf(4, ua.NewExtensionObject(&ua.Range{Low: 1, High: 2})))
	for i, f := range raw.Fields {
		f.Name = rawMD.Fields[i].Name
	}

	event := &message.DataSetMessage{Valid: true, Type: message.DataSetMessageEvent, Fields: []*message.Field{vf(0, "x")}}

	return []golden{
		// open62541 UA_PubSub_EnDecode_ShallWorkOn1DS1ValueVariantKeyFrame.
		{"minimal", nm(0, keyFrame(message.FieldEncodingVariant, vf(0, int32(27)))), "01 01 0100 061b000000", nil},
		{"publisher byte", withPub(message.NewPublisherID(message.PublisherIDByte, 5)), "11 05 01 0100 061b000000", nil},
		{"publisher uint16", withPub(message.NewPublisherID(message.PublisherIDUInt16, 0x1234)), "91 01 3412 01 0100 061b000000", nil},
		{"publisher uint32", withPub(message.NewPublisherID(message.PublisherIDUInt32, 0x12345678)), "91 02 78563412 01 0100 061b000000", nil},
		{"publisher uint64", withPub(message.NewPublisherID(message.PublisherIDUInt64, 0x0102030405060708)), "91 03 0807060504030201 01 0100 061b000000", nil},
		{"publisher string", withPub(message.StringPublisherID("ab")), "91 04 02000000 6162 01 0100 061b000000", nil},
		{"all network message headers", full,
			"f1 e8 02 07 78563412 cdab 01ef 1020304050607080" + // flags, ext1, ext2, publisher, class id
				"0f 0201 04030201 0500 0600" + // group header
				"02 0a00 0b00" + // payload header
				"1054c2949f3ad701 0201" + // timestamp, picoseconds
				"0500 062a000000" + // promoted fields
				"0500 0400" + // sizes
				"01 0100 0101" + // key frame: Boolean true
				"89 03 0302", // keep-alive with sequence number
			nil},
		{"all dataset message headers, delta frame, DataValue", nm(0, delta),
			"01 fd 31 0201 1054c2949f3ad701 0403 3480 0a000000 0b000000" +
				"0200 0300 01050700 0500 0306ffffffff00000080", nil},
		{"event", nm(0, event), "01 81 02 0100 0c0100000078", nil},
		{"invalid heartbeat", nm(0, &message.DataSetMessage{}), "01 00 0000", nil},
		{"raw data", nm(0, raw),
			"01 03 aa" +
				"03000000 616263 0000000000" + // String padded to MaxStringLength 8
				"02000000 01000000 02000000" + // UInt32[2]
				"02000000 02000000 0100 0200 0300 0400" + // Int16[2][2]
				"000000000000f03f 0000000000000040", // Range body
			rawMD},
		{"raw data heartbeat", nm(0, keyFrame(message.FieldEncodingRawData)), "01 03", rawMD},
	}
}

func TestGoldenVectors(t *testing.T) {
	for _, g := range goldenVectors() {
		t.Run(g.name, func(t *testing.T) {
			want := h(t, g.hex)
			got, err := Encode(g.nm, &EncodeOptions{MetaData: metaLookup(g.md)})
			require.NoError(t, err)
			require.Equal(t, hex.EncodeToString(want), hex.EncodeToString(got))

			dec, err := Decode(want, &DecodeOptions{MetaData: metaLookup(g.md)})
			require.NoError(t, err)
			require.Equal(t, g.nm, dec)
		})
	}
}

func TestDiscoveryMetaData(t *testing.T) {
	md := &ua.DataSetMetaDataType{
		Name: "DS",
		Fields: []*ua.FieldMetaData{{
			Name: "f", BuiltInType: uint8(ua.TypeIDInt32), DataType: ua.NewNumericNodeID(0, id.Int32), ValueRank: -1,
		}},
		ConfigurationVersion: &ua.ConfigurationVersionDataType{MajorVersion: 1, MinorVersion: 2},
	}
	nm := &message.NetworkMessage{
		Type:        message.NetworkMessageDiscoveryResponse,
		UADPMask:    ua.UADPNetworkMessageContentMaskPublisherID,
		PublisherID: message.NewPublisherID(message.PublisherIDByte, 1),
		Discovery: &message.Discovery{
			Type: message.DiscoveryDataSetMetaData, SequenceNumber: 5, DataSetWriterID: 10,
			MetaData: md, StatusCode: ua.StatusOK,
		},
	}
	mdBytes, err := ua.Encode(md)
	require.NoError(t, err)
	want := append(h(t, "91 80 08 01 02 0500 0a00"), mdBytes...)
	want = append(want, 0, 0, 0, 0)

	got, err := Encode(nm, nil)
	require.NoError(t, err)
	require.Equal(t, want, got)

	dec, err := Decode(got, nil)
	require.NoError(t, err)
	require.Equal(t, nm.Discovery.Type, dec.Discovery.Type)
	require.Equal(t, nm.Discovery.SequenceNumber, dec.Discovery.SequenceNumber)
	require.Equal(t, nm.Discovery.DataSetWriterID, dec.Discovery.DataSetWriterID)
	require.Equal(t, "DS", dec.Discovery.MetaData.Name)
	require.Equal(t, md.Fields[0].Name, dec.Discovery.MetaData.Fields[0].Name)
	require.Equal(t, md.ConfigurationVersion, dec.Discovery.MetaData.ConfigurationVersion)
	require.Equal(t, nm.PublisherID, dec.PublisherID)
	require.Empty(t, dec.Messages)

	// A signed and encrypted announcement.
	ks := zeroKeys(testPolicy{})
	sec, err := Encode(nm, &EncodeOptions{SecurityMode: ua.MessageSecurityModeSignAndEncrypt, Keys: ks})
	require.NoError(t, err)
	dec2, err := Decode(sec, &DecodeOptions{Security: requireSecurity(ua.MessageSecurityModeSignAndEncrypt, ks)})
	require.NoError(t, err)
	require.Equal(t, dec.Discovery, dec2.Discovery)

	// Errors.
	_, err = Encode(&message.NetworkMessage{Type: message.NetworkMessageDiscoveryResponse}, nil)
	require.ErrorIs(t, err, ErrMalformed)
	_, err = Encode(&message.NetworkMessage{Type: message.NetworkMessageDiscoveryResponse, Discovery: &message.Discovery{Type: message.DiscoveryDataSetMetaData}}, nil)
	require.ErrorIs(t, err, ErrMalformed)
	_, err = Encode(&message.NetworkMessage{Type: message.NetworkMessageDiscoveryResponse, Discovery: &message.Discovery{Type: message.DiscoveryPublisherEndpoints}}, nil)
	require.ErrorIs(t, err, ErrUnsupported)
	_, err = Encode(&message.NetworkMessage{Type: message.NetworkMessageDiscoveryRequest}, nil)
	require.ErrorIs(t, err, ErrUnsupported)
	for _, raw := range []string{
		"81 80 08",                 // no body
		"81 80 08 01",              // publisher endpoints
		"81 80 08 02 0500",         // truncated
		"c1 80 08 01 0100 02 0500", // payload header in a discovery message
	} {
		_, err := Decode(h(t, raw), nil)
		require.Error(t, err, raw)
	}
	_, err = Decode(h(t, "81 80 08 01"), nil)
	require.ErrorIs(t, err, ErrUnsupported)
	_, err = Decode(h(t, "81 80 04 01"), nil)
	require.ErrorIs(t, err, ErrUnsupported, "discovery request")
}
