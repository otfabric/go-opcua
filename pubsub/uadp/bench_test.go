// SPDX-License-Identifier: MIT

package uadp

import (
	"testing"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/ua"
)

// benchMessage is a typical NetworkMessage: publisher, group header and
// payload header, one key frame of ten fields with sequence number and
// timestamp.
func benchMessage(enc message.FieldEncoding) (*message.NetworkMessage, *ua.DataSetMetaDataType) {
	md := &ua.DataSetMetaDataType{}
	dsm := &message.DataSetMessage{
		DataSetWriterID: 1, Valid: true, FieldEncoding: enc,
		UADPMask:       ua.UADPDataSetMessageContentMaskSequenceNumber | ua.UADPDataSetMessageContentMaskTimestamp,
		SequenceNumber: 42, Timestamp: ts,
	}
	for i := range 10 {
		var v any
		switch i % 4 {
		case 0:
			v = int32(i)
		case 1:
			v = float64(i) + 0.5
		case 2:
			v = i%3 == 0
		default:
			v = ts
		}
		f := vf(i, v)
		dsm.Fields = append(dsm.Fields, f)
		md.Fields = append(md.Fields, &ua.FieldMetaData{BuiltInType: uint8(f.Value.Value.Type()), ValueRank: -1})
	}
	nm := &message.NetworkMessage{
		UADPMask: ua.UADPNetworkMessageContentMaskPublisherID | ua.UADPNetworkMessageContentMaskGroupHeader |
			ua.UADPNetworkMessageContentMaskWriterGroupID | ua.UADPNetworkMessageContentMaskSequenceNumber |
			ua.UADPNetworkMessageContentMaskPayloadHeader,
		PublisherID: message.NewPublisherID(message.PublisherIDUInt16, 1000),
		GroupHeader: message.GroupHeader{WriterGroupID: 100, SequenceNumber: 7},
		Messages:    []*message.DataSetMessage{dsm},
	}
	return nm, md
}

func benchmarkEncode(b *testing.B, enc message.FieldEncoding, mode ua.MessageSecurityMode) {
	nm, md := benchMessage(enc)
	opts := &EncodeOptions{MetaData: metaLookup(md), SecurityMode: mode, Keys: zeroKeys(testPolicy{})}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Encode(nm, opts); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkDecode(b *testing.B, enc message.FieldEncoding, mode ua.MessageSecurityMode) {
	nm, md := benchMessage(enc)
	ks := zeroKeys(testPolicy{})
	data, err := Encode(nm, &EncodeOptions{MetaData: metaLookup(md), SecurityMode: mode, Keys: ks})
	if err != nil {
		b.Fatal(err)
	}
	opts := &DecodeOptions{MetaData: metaLookup(md), Security: requireSecurity(mode, ks)}
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Decode(data, opts); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncodeKeyFrameVariant(b *testing.B) {
	benchmarkEncode(b, message.FieldEncodingVariant, ua.MessageSecurityModeNone)
}
func BenchmarkEncodeKeyFrameRawData(b *testing.B) {
	benchmarkEncode(b, message.FieldEncodingRawData, ua.MessageSecurityModeNone)
}
func BenchmarkEncodeKeyFrameSignAndEncrypt(b *testing.B) {
	benchmarkEncode(b, message.FieldEncodingVariant, ua.MessageSecurityModeSignAndEncrypt)
}
func BenchmarkDecodeKeyFrameVariant(b *testing.B) {
	benchmarkDecode(b, message.FieldEncodingVariant, ua.MessageSecurityModeNone)
}
func BenchmarkDecodeKeyFrameRawData(b *testing.B) {
	benchmarkDecode(b, message.FieldEncodingRawData, ua.MessageSecurityModeNone)
}
func BenchmarkDecodeKeyFrameSignAndEncrypt(b *testing.B) {
	benchmarkDecode(b, message.FieldEncodingVariant, ua.MessageSecurityModeSignAndEncrypt)
}
