// SPDX-License-Identifier: MIT

package jsonmsg

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/ua"
)

// The golden messages of this file come from open62541 v1.5.9,
// tests/pubsub/check_pubsub_encoding_json.c.

// ticks converts an OPC UA DateTime (100 ns since 1601) to a time.Time.
func ticks(n int64) time.Time {
	return time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(n) * 100)
}

func metaLookup(fields ...string) message.MetaDataLookup {
	return metaLookupTyped(nil, fields...)
}

func metaLookupTyped(types []byte, fields ...string) message.MetaDataLookup {
	md := &ua.DataSetMetaDataType{}
	for i, f := range fields {
		fm := &ua.FieldMetaData{Name: f, ValueRank: -1}
		if i < len(types) {
			fm.BuiltInType = types[i]
			fm.DataType = ua.NewNumericNodeID(0, uint32(types[i]))
		}
		md.Fields = append(md.Fields, fm)
	}
	return func(message.PublisherID, uint16, uint16) *ua.DataSetMetaDataType { return md }
}

// UA_PubSub_EncodeAllOptionalFields.
func TestOpen62541EncodeAllOptionalFields(t *testing.T) {
	classID := ua.NewGUID("00000001-0002-0003-0000-000000000000")
	nm := &message.NetworkMessage{
		Type: message.NetworkMessageDataSet,
		JSONMask: ua.JSONNetworkMessageContentMaskNetworkMessageHeader |
			ua.JSONNetworkMessageContentMaskDataSetMessageHeader |
			ua.JSONNetworkMessageContentMaskPublisherID |
			ua.JSONNetworkMessageContentMaskDataSetClassID,
		MessageID:      "ABCDEFGH",
		PublisherID:    message.NewPublisherID(message.PublisherIDUInt16, 65535),
		DataSetClassID: classID,
		Messages: []*message.DataSetMessage{{
			DataSetWriterID: 12345,
			Type:            message.DataSetMessageKeyFrame,
			Valid:           true,
			JSONMask: ua.JSONDataSetMessageContentMaskDataSetWriterID |
				ua.JSONDataSetMessageContentMaskSequenceNumber |
				ua.JSONDataSetMessageContentMaskMetaDataVersion |
				ua.JSONDataSetMessageContentMaskTimestamp |
				ua.JSONDataSetMessageContentMaskStatus |
				ua.JSONDataSetMessageContentMaskMessageType,
			SequenceNumber:  4711,
			MetaDataVersion: ua.ConfigurationVersionDataType{MajorVersion: 42, MinorVersion: 7},
			Timestamp:       ticks(11111111111111),
			Status:          12345,
			Fields: []*message.Field{{
				Name:  "Field1",
				Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(uint32(27))},
			}},
		}},
	}
	got, err := Encode(nm, nil)
	require.NoError(t, err)

	golden := `{"MessageId":"ABCDEFGH","MessageType":"ua-data","PublisherId":"65535","DataSetClassId":"00000001-0002-0003-0000-000000000000","Messages":[{"DataSetWriterId":12345,"SequenceNumber":4711,"MetaDataVersion":{"MajorVersion":42,"MinorVersion":7},"Timestamp":"1601-01-13T20:38:31.1111111Z","Status":{"Code":12345,"Symbol":"Good"},"MessageType":"ua-keyframe","Payload":{"Field1":{"UaType":7,"Value":27}}}]}`
	// open62541 adds the symbol of the StatusCode (and calls 12345 "Good",
	// as it names a code by its high 16 bits); the Compact encoding has no
	// symbol.
	want := strings.Replace(golden, `{"Code":12345,"Symbol":"Good"}`, `{"Code":12345}`, 1)
	require.Equal(t, want, string(got))

	// And open62541's own output decodes to the same message.
	dec, err := Decode([]byte(golden), &DecodeOptions{MetaData: metaLookup("Field1")})
	require.NoError(t, err)
	require.Equal(t, "ABCDEFGH", dec.MessageID)
	require.Equal(t, "65535", dec.PublisherID.String())
	require.Equal(t, classID.String(), dec.DataSetClassID.String())
	require.Equal(t, nm.JSONMask, dec.JSONMask)
	d := dec.Messages[0]
	require.Equal(t, nm.Messages[0].JSONMask, d.JSONMask)
	require.Equal(t, uint16(12345), d.DataSetWriterID)
	require.Equal(t, uint32(4711), d.SequenceNumber)
	require.Equal(t, nm.Messages[0].MetaDataVersion, d.MetaDataVersion)
	require.True(t, d.Timestamp.Equal(nm.Messages[0].Timestamp))
	require.Equal(t, ua.StatusCode(12345), d.Status)
	require.Equal(t, uint32(27), d.Fields[0].Value.Value.Value())
	require.Zero(t, d.FieldContentMask)
}

// UA_NetworkMessage_oneMessage_twoFields_json_decode.
func TestOpen62541DecodeTwoFields(t *testing.T) {
	in := `{"MessageId":"5ED82C10-50BB-CD07-0120-22521081E8EE","MessageType":"ua-data","Messages":[{"DataSetWriterId":62541,"MetaDataVersion":{"MajorVersion":1478393530,"MinorVersion":12345},"SequenceNumber":4711,"Payload":{"Test":{"UaType":5,"Value":42},"Server localtime":{"UaType":13,"Value":"2018-06-05T05:58:36.000Z"}}}]}`
	nm, err := Decode([]byte(in), &DecodeOptions{MetaData: metaLookup("Test", "Server localtime")})
	require.NoError(t, err)
	require.Equal(t, ua.JSONNetworkMessageContentMaskNetworkMessageHeader|ua.JSONNetworkMessageContentMaskDataSetMessageHeader, nm.JSONMask)
	require.Len(t, nm.Messages, 1)
	d := nm.Messages[0]
	require.Equal(t, uint16(62541), d.DataSetWriterID)
	require.Equal(t, uint32(4711), d.SequenceNumber)
	require.Equal(t, uint32(1478393530), d.MetaDataVersion.MajorVersion)
	require.Equal(t, uint32(12345), d.MetaDataVersion.MinorVersion)
	require.Equal(t, message.DataSetMessageKeyFrame, d.Type)
	require.Len(t, d.Fields, 2)
	require.Equal(t, uint16(42), d.Fields[0].Value.Value.Value())
	require.Equal(t, time.Date(2018, 6, 5, 5, 58, 36, 0, time.UTC), d.Fields[1].Value.Value.Value())
	require.Equal(t, uint16(1), d.Fields[1].Index)
}

// UA_NetworkMessage_json_decode: no metadata, extra 1.05 members.
func TestOpen62541DecodeWithoutMetaData(t *testing.T) {
	in := `{"MessageId":"5ED82C10-50BB-CD07-0120-22521081E8EE","MessageType":"ua-data","WriterGroupName":"wg","Messages":[{"MetaDataVersion":{"MajorVersion": 47, "MinorVersion": 47},"DataSetWriterId":62541,"DataSetWriterName":"dsw","MinorVersion":2,"Status":22,"SequenceNumber":4711,"Payload":{"Test":{"UaType":5,"Value":42},"Server localtime":{"UaType":1,"Value":true}}}]}`
	nm, err := Decode([]byte(in), nil)
	require.NoError(t, err)
	require.Equal(t, "wg", nm.WriterGroupName)
	d := nm.Messages[0]
	require.Equal(t, "dsw", d.DataSetWriterName)
	require.Equal(t, ua.StatusCode(22), d.Status)
	require.Equal(t, uint32(47), d.MetaDataVersion.MajorVersion)
	require.Equal(t, uint32(47), d.MetaDataVersion.MinorVersion, "MetaDataVersion wins over MinorVersion")
	require.Equal(t, "Test", d.Fields[0].Name)
	require.Equal(t, uint16(0), d.Fields[0].Index)
	require.Equal(t, uint16(42), d.Fields[0].Value.Value.Value())
	require.Equal(t, "Server localtime", d.Fields[1].Name)
	require.Equal(t, true, d.Fields[1].Value.Value.Value())
}

// UA_NetworkMessage_json_decode_messageObject.
func TestOpen62541DecodeMessageObject(t *testing.T) {
	in := `{"MessageId":"5ED82C10-50BB-CD07-0120-22521081E8EE","MessageType":"ua-data","Messages":{"MetaDataVersion":{"MajorVersion": 47, "MinorVersion": 47},"DataSetWriterId":62541,"Status":22,"SequenceNumber":4711,"Payload":{"Test":{"UaType":5,"Value":42},"Server localtime":{"UaType":1,"Value":true}}}}`
	nm, err := Decode([]byte(in), nil)
	require.NoError(t, err)
	require.NotZero(t, nm.JSONMask&ua.JSONNetworkMessageContentMaskSingleDataSetMessage)
	require.Len(t, nm.Messages, 1)
	require.Len(t, nm.Messages[0].Fields, 2)
}

// UA_Networkmessage_DataSetFieldsNull_json_decode.
func TestOpen62541DecodeNullPayload(t *testing.T) {
	in := "{ \"MessageId\": \"32235546-05d9-4fd7-97df-ea3ff3408574\",  " +
		"\"MessageType\": \"ua-data\",  \"PublisherId\": \"MQTT-Localhost\",  " +
		"\"DataSetClassId\": \"00000005-cab9-4470-8f8a-2c1ead207e0e\",  \"Messages\": " +
		"[    {      \"DataSetWriterId\": 1,      \"SequenceNumber\": 224,     \"MetaDataVersion\": " +
		"{        \"MajorVersion\": 1,        \"MinorVersion\": 1      },\"Payload\":null}]}"
	nm, err := Decode([]byte(in), nil)
	require.NoError(t, err)
	require.Equal(t, message.StringPublisherID("MQTT-Localhost"), nm.PublisherID)
	require.Equal(t, "00000005-CAB9-4470-8F8A-2C1EAD207E0E", strings.ToUpper(nm.DataSetClassID.String()))
	require.Equal(t, uint32(224), nm.Messages[0].SequenceNumber)
	require.Empty(t, nm.Messages[0].Fields)
}

// UA_Networkmessage_metaData_oob: open62541 rejects a field whose metadata
// index is beyond the number of fields in the message (a limitation of its
// array layout); here the field simply gets its metadata index.
func TestOpen62541DecodeMetaDataIndex(t *testing.T) {
	in := `{"MessageType":"ua-data","Messages":[{"DataSetWriterId":1,"Payload":{"Energy":null}}]}`
	md := metaLookup("Temperature", "Pressure", "Humidity", "Vibration", "Voltage", "Current", "Status", "Energy")
	nm, err := Decode([]byte(in), &DecodeOptions{MetaData: md})
	require.NoError(t, err)
	f := nm.Messages[0].Fields[0]
	require.Equal(t, uint16(7), f.Index)
	require.Equal(t, "Energy", f.Name)
	require.Nil(t, f.Value.Value)

	// A name the metadata does not know is an error.
	_, err = Decode([]byte(`{"MessageType":"ua-data","Messages":[{"DataSetWriterId":1,"Payload":{"Nope":null}}]}`), &DecodeOptions{MetaData: md})
	require.ErrorIs(t, err, ErrDecode)
}

// UA_Networkmessage_json_uint32_and_datavalue_roundtrip.
func TestOpen62541DataValueRoundTrip(t *testing.T) {
	md := metaLookup("Field")
	for _, seq := range []uint32{0, 4711, 65535, 65536, 1 << 31} {
		in := fmt.Sprintf(`{"MessageType":"ua-data","Messages":[{`+
			`"DataSetWriterId":1,"SequenceNumber":%d,`+
			`"Status":12345,"Payload":{"Field":{`+
			`"UaType":7,"Value":27,`+
			`"Status":{"Code":1073741824},`+
			`"SourceTimestamp":"1970-01-15T06:56:07Z",`+
			`"ServerTimestamp":"1970-01-15T06:56:08Z"}}}]}`, seq)
		nm, err := Decode([]byte(in), &DecodeOptions{MetaData: md})
		require.NoError(t, err)
		d := nm.Messages[0]
		require.Equal(t, seq, d.SequenceNumber)
		require.Equal(t, ua.StatusCode(12345), d.Status)
		require.Equal(t, ua.DataSetFieldContentMaskStatusCode|ua.DataSetFieldContentMaskSourceTimestamp|ua.DataSetFieldContentMaskServerTimestamp, d.FieldContentMask)
		dv := d.Fields[0].Value
		require.Equal(t, ua.StatusCode(0x40000000), dv.Status)
		require.Equal(t, time.Date(1970, 1, 15, 6, 56, 7, 0, time.UTC), dv.SourceTimestamp)
		require.Equal(t, time.Date(1970, 1, 15, 6, 56, 8, 0, time.UTC), dv.ServerTimestamp)

		b, err := Encode(nm, nil)
		require.NoError(t, err)
		nm2, err := Decode(b, &DecodeOptions{MetaData: md})
		require.NoError(t, err)
		require.Equal(t, seq, nm2.Messages[0].SequenceNumber)
		require.Equal(t, dv.Status, nm2.Messages[0].Fields[0].Value.Status)
		require.Equal(t, dv.SourceTimestamp, nm2.Messages[0].Fields[0].Value.SourceTimestamp)
		require.Equal(t, dv.ServerTimestamp, nm2.Messages[0].Fields[0].Value.ServerTimestamp)
	}
}

// UA_Networkmessage_json_publisherid_roundtrip: numeric PublisherIds travel
// as strings and come back as UInt64; strings stay strings.
func TestOpen62541PublisherID(t *testing.T) {
	for _, p := range []message.PublisherID{
		message.NewPublisherID(message.PublisherIDByte, 17),
		message.NewPublisherID(message.PublisherIDUInt16, 65000),
		message.NewPublisherID(message.PublisherIDUInt32, 4000000000),
		message.NewPublisherID(message.PublisherIDUInt64, 1<<64-1),
		message.StringPublisherID("publisher-alpha"),
	} {
		nm := &message.NetworkMessage{
			JSONMask: ua.JSONNetworkMessageContentMaskNetworkMessageHeader |
				ua.JSONNetworkMessageContentMaskDataSetMessageHeader |
				ua.JSONNetworkMessageContentMaskPublisherID,
			PublisherID: p,
			Messages:    []*message.DataSetMessage{{DataSetWriterID: 1, JSONMask: ua.JSONDataSetMessageContentMaskDataSetWriterID}},
		}
		b, err := Encode(nm, nil)
		require.NoError(t, err)
		require.Contains(t, string(b), `"PublisherId":"`+p.String()+`"`)
		dec, err := Decode(b, nil)
		require.NoError(t, err)
		require.Equal(t, p.String(), dec.PublisherID.String())
		if p.Type == message.PublisherIDString {
			require.Equal(t, p, dec.PublisherID)
		} else {
			require.Equal(t, message.PublisherIDUInt64, dec.PublisherID.Type)
		}

		b, err = Encode(nm, &EncodeOptions{NumericPublisherID: true})
		require.NoError(t, err)
		if p.Type != message.PublisherIDString {
			require.Contains(t, string(b), `"PublisherId":`+p.String()+`,`)
		}
		dec, err = Decode(b, nil)
		require.NoError(t, err)
		require.Equal(t, p.String(), dec.PublisherID.String())
	}
}

// What open62541's publisher sends (sendNetworkMessageJson): no MessageId
// (written as null), PublisherId as a string, Messages as an array.
func TestOpen62541PublisherShape(t *testing.T) {
	in := `{"MessageId":null,"MessageType":"ua-data","PublisherId":"2234","Messages":[{"DataSetWriterId":62541,"SequenceNumber":3,"MessageType":"ua-keyframe","Payload":{"Server localtime":{"UaType":13,"Value":"2024-01-01T00:00:00Z"}}}]}`
	nm, err := Decode([]byte(in), nil)
	require.NoError(t, err)
	require.Empty(t, nm.MessageID)
	require.Equal(t, "2234", nm.PublisherID.String())
	require.Equal(t, uint32(3), nm.Messages[0].SequenceNumber)
}
