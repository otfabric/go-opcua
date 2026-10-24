// SPDX-License-Identifier: MIT

package jsonmsg

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/ua"
)

const (
	nmHeader  = ua.JSONNetworkMessageContentMaskNetworkMessageHeader
	dsmHeader = ua.JSONNetworkMessageContentMaskDataSetMessageHeader
	single    = ua.JSONNetworkMessageContentMaskSingleDataSetMessage

	allDSM = ua.JSONDataSetMessageContentMaskDataSetWriterID |
		ua.JSONDataSetMessageContentMaskMetaDataVersion |
		ua.JSONDataSetMessageContentMaskSequenceNumber |
		ua.JSONDataSetMessageContentMaskTimestamp |
		ua.JSONDataSetMessageContentMaskStatus |
		ua.JSONDataSetMessageContentMaskMessageType |
		ua.JSONDataSetMessageContentMaskDataSetWriterName |
		ua.JSONDataSetMessageContentMaskPublisherID |
		ua.JSONDataSetMessageContentMaskWriterGroupName

	dvMask = ua.DataSetFieldContentMaskStatusCode | ua.DataSetFieldContentMaskSourceTimestamp |
		ua.DataSetFieldContentMaskServerTimestamp | ua.DataSetFieldContentMaskSourcePicoSeconds |
		ua.DataSetFieldContentMaskServerPicoSeconds
)

var (
	ts1 = time.Date(2024, 5, 6, 7, 8, 9, 123456700, time.UTC)
	ts2 = time.Date(2024, 5, 6, 7, 8, 10, 0, time.UTC)
)

var fieldNames = []string{"Bool", "Int32", "Double", "String", "Ints", "Time", "Node"}
var fieldTypes = []byte{1, 6, 11, 12, 6, 13, 17}

func fieldValues() []*ua.DataValue {
	vals := []interface{}{true, int32(-5), 3.25, "hello \"world\"", []int32{1, 2, 3}, ts1, ua.NewNumericNodeID(2, 70000)}
	out := make([]*ua.DataValue, len(vals))
	for i, v := range vals {
		out[i] = &ua.DataValue{
			EncodingMask: ua.DataValueValue | ua.DataValueStatusCode | ua.DataValueSourceTimestamp |
				ua.DataValueServerTimestamp | ua.DataValueSourcePicoseconds | ua.DataValueServerPicoseconds,
			Value:             ua.MustVariant(v),
			Status:            ua.StatusUncertain,
			SourceTimestamp:   ts1,
			ServerTimestamp:   ts2,
			SourcePicoseconds: 10,
			ServerPicoseconds: 20,
		}
	}
	return out
}

func testMessage(nmMask ua.JSONNetworkMessageContentMask, dsmMask ua.JSONDataSetMessageContentMask,
	fm ua.DataSetFieldContentMask, typ message.DataSetMessageType, count int) *message.NetworkMessage {
	nm := &message.NetworkMessage{
		Type:            message.NetworkMessageDataSet,
		JSONMask:        nmMask,
		MessageID:       "msg-1",
		PublisherID:     message.StringPublisherID("pub"),
		WriterGroupName: "wg",
		ReplyTo:         "reply",
		DataSetClassID:  ua.NewGUID("72962B91-FA75-4AE6-8D28-B404DC7DAF63"),
	}
	for w := 0; w < count; w++ {
		dsm := &message.DataSetMessage{
			DataSetWriterID:   uint16(10 + w),
			Type:              typ,
			Valid:             true,
			JSONMask:          dsmMask,
			FieldContentMask:  fm,
			SequenceNumber:    100000 + uint32(w),
			Timestamp:         ts1,
			Status:            ua.StatusBadInternalError,
			MetaDataVersion:   ua.ConfigurationVersionDataType{MajorVersion: 7, MinorVersion: 8},
			DataSetWriterName: fmt.Sprintf("writer-%d", w),
			WriterGroupName:   "wg",
		}
		if typ != message.DataSetMessageKeepAlive {
			for i, v := range fieldValues() {
				if typ == message.DataSetMessageDeltaFrame && i%2 == 0 {
					continue
				}
				dsm.Fields = append(dsm.Fields, &message.Field{Index: uint16(i), Name: fieldNames[i], Value: v})
			}
		}
		nm.Messages = append(nm.Messages, dsm)
	}
	return nm
}

// expectField is what a field looks like after a round trip with the given
// field content mask.
func expectField(dv *ua.DataValue, fm ua.DataSetFieldContentMask) *ua.DataValue {
	out := &ua.DataValue{EncodingMask: ua.DataValueValue, Value: dv.Value}
	if fm&ua.DataSetFieldContentMaskRawData != 0 {
		return out
	}
	if fm&ua.DataSetFieldContentMaskStatusCode != 0 {
		out.EncodingMask |= ua.DataValueStatusCode
		out.Status = dv.Status
	}
	if fm&ua.DataSetFieldContentMaskSourceTimestamp != 0 {
		out.EncodingMask |= ua.DataValueSourceTimestamp
		out.SourceTimestamp = dv.SourceTimestamp
		if fm&ua.DataSetFieldContentMaskSourcePicoSeconds != 0 {
			out.EncodingMask |= ua.DataValueSourcePicoseconds
			out.SourcePicoseconds = dv.SourcePicoseconds
		}
	}
	if fm&ua.DataSetFieldContentMaskServerTimestamp != 0 {
		out.EncodingMask |= ua.DataValueServerTimestamp
		out.ServerTimestamp = dv.ServerTimestamp
		if fm&ua.DataSetFieldContentMaskServerPicoSeconds != 0 {
			out.EncodingMask |= ua.DataValueServerPicoseconds
			out.ServerPicoseconds = dv.ServerPicoseconds
		}
	}
	return out
}

func TestRoundTrip(t *testing.T) {
	nmMasks := []ua.JSONNetworkMessageContentMask{
		nmHeader | dsmHeader | ua.JSONNetworkMessageContentMaskPublisherID |
			ua.JSONNetworkMessageContentMaskDataSetClassID | ua.JSONNetworkMessageContentMaskWriterGroupName |
			ua.JSONNetworkMessageContentMaskReplyTo,
		nmHeader | dsmHeader,
		nmHeader | dsmHeader | single,
		nmHeader,
		dsmHeader,
		dsmHeader | single,
		single,
		0,
	}
	dsmMasks := []ua.JSONDataSetMessageContentMask{
		allDSM,
		ua.JSONDataSetMessageContentMaskDataSetWriterID | ua.JSONDataSetMessageContentMaskMessageType,
		ua.JSONDataSetMessageContentMaskDataSetWriterID | ua.JSONDataSetMessageContentMaskMinorVersion | ua.JSONDataSetMessageContentMaskMessageType,
		allDSM | ua.JSONDataSetMessageContentMaskFieldEncoding2,
		allDSM | ua.JSONDataSetMessageContentMaskFieldEncoding1,
	}
	fieldMasks := []ua.DataSetFieldContentMask{
		0,
		ua.DataSetFieldContentMaskStatusCode,
		ua.DataSetFieldContentMaskSourceTimestamp,
		dvMask,
		ua.DataSetFieldContentMaskServerTimestamp | ua.DataSetFieldContentMaskServerPicoSeconds,
		ua.DataSetFieldContentMaskRawData,
	}
	types := []message.DataSetMessageType{
		message.DataSetMessageKeyFrame, message.DataSetMessageDeltaFrame,
		message.DataSetMessageEvent, message.DataSetMessageKeepAlive,
	}
	md := metaLookupTyped(fieldTypes, fieldNames...)
	n := 0
	for _, nmMask := range nmMasks {
		for _, dsmMask := range dsmMasks {
			for _, fm := range fieldMasks {
				for _, typ := range types {
					count := 3
					if nmMask&single != 0 {
						count = 1
					}
					hasDSMHeader := nmMask&dsmHeader != 0
					if typ == message.DataSetMessageKeepAlive && !hasDSMHeader {
						continue
					}
					if typ != message.DataSetMessageKeyFrame && dsmMask&ua.JSONDataSetMessageContentMaskMessageType == 0 {
						continue // the type cannot travel
					}
					name := fmt.Sprintf("nm=%d/dsm=%d/fm=%d/%s", nmMask, dsmMask, fm, typ)
					n++
					t.Run(name, func(t *testing.T) {
						in := testMessage(nmMask, dsmMask, fm, typ, count)
						b, err := Encode(in, nil)
						require.NoError(t, err)
						require.True(t, json.Valid(b), "%s", b)
						out, err := Decode(b, &DecodeOptions{MetaData: md, DataSetWriterID: 10})
						require.NoError(t, err, "%s", b)
						checkRoundTrip(t, in, out, b)
					})
				}
			}
		}
	}
	require.Greater(t, n, 300)
}

func checkRoundTrip(t *testing.T, in, out *message.NetworkMessage, b []byte) {
	t.Helper()
	wantMask := in.JSONMask
	if wantMask&nmHeader == 0 {
		wantMask &= nmHeader | dsmHeader | single
	}
	require.Equal(t, wantMask, out.JSONMask, "%s", b)
	if in.JSONMask&nmHeader != 0 {
		require.Equal(t, in.MessageID, out.MessageID)
		if in.JSONMask&ua.JSONNetworkMessageContentMaskPublisherID != 0 {
			require.Equal(t, in.PublisherID, out.PublisherID)
		}
		if in.JSONMask&ua.JSONNetworkMessageContentMaskWriterGroupName != 0 {
			require.Equal(t, in.WriterGroupName, out.WriterGroupName)
		}
		if in.JSONMask&ua.JSONNetworkMessageContentMaskReplyTo != 0 {
			require.Equal(t, in.ReplyTo, out.ReplyTo)
		}
		if in.JSONMask&ua.JSONNetworkMessageContentMaskDataSetClassID != 0 {
			require.Equal(t, in.DataSetClassID.String(), out.DataSetClassID.String())
		}
	}
	require.Len(t, out.Messages, len(in.Messages))
	for i, im := range in.Messages {
		om := out.Messages[i]
		require.True(t, om.Valid)
		if in.JSONMask&dsmHeader == 0 {
			require.Zero(t, om.JSONMask)
			require.Equal(t, message.DataSetMessageKeyFrame, om.Type)
			require.Equal(t, uint16(10), om.DataSetWriterID) // from the options
		} else {
			wantDSM := im.JSONMask &^ (ua.JSONDataSetMessageContentMaskFieldEncoding1 | ua.JSONDataSetMessageContentMaskFieldEncoding2)
			require.Equal(t, wantDSM, om.JSONMask)
			require.Equal(t, im.Type, om.Type)
			m := im.JSONMask
			if m&ua.JSONDataSetMessageContentMaskDataSetWriterID != 0 {
				require.Equal(t, im.DataSetWriterID, om.DataSetWriterID)
			}
			if m&ua.JSONDataSetMessageContentMaskDataSetWriterName != 0 {
				require.Equal(t, im.DataSetWriterName, om.DataSetWriterName)
			}
			if m&ua.JSONDataSetMessageContentMaskPublisherID != 0 {
				require.Equal(t, in.PublisherID, *om.PublisherID)
			}
			if m&ua.JSONDataSetMessageContentMaskWriterGroupName != 0 {
				require.Equal(t, im.WriterGroupName, om.WriterGroupName)
			}
			if m&ua.JSONDataSetMessageContentMaskSequenceNumber != 0 {
				require.Equal(t, im.SequenceNumber, om.SequenceNumber)
			}
			if m&ua.JSONDataSetMessageContentMaskMetaDataVersion != 0 {
				require.Equal(t, im.MetaDataVersion, om.MetaDataVersion)
			} else if m&ua.JSONDataSetMessageContentMaskMinorVersion != 0 {
				require.Equal(t, im.MetaDataVersion.MinorVersion, om.MetaDataVersion.MinorVersion)
			}
			if m&ua.JSONDataSetMessageContentMaskTimestamp != 0 {
				require.Equal(t, im.Timestamp, om.Timestamp)
			}
			if m&ua.JSONDataSetMessageContentMaskStatus != 0 {
				require.Equal(t, im.Status, om.Status)
			}
		}
		if im.Type == message.DataSetMessageKeepAlive {
			require.Empty(t, om.Fields)
			continue
		}
		require.Equal(t, im.FieldContentMask&(dvMask|ua.DataSetFieldContentMaskRawData), om.FieldContentMask&(dvMask|ua.DataSetFieldContentMaskRawData))
		require.Len(t, om.Fields, len(im.Fields))
		for j, f := range im.Fields {
			g := om.Fields[j]
			require.Equal(t, f.Name, g.Name)
			require.Equal(t, f.Index, g.Index)
			require.Equal(t, expectField(f.Value, im.FieldContentMask), g.Value, "field %s in %s", f.Name, b)
		}
	}
}

func TestEncodeVerboseFieldEncoding(t *testing.T) {
	nm := testMessage(dsmHeader, ua.JSONDataSetMessageContentMaskFieldEncoding2, ua.DataSetFieldContentMaskStatusCode, message.DataSetMessageKeyFrame, 1)
	nm.Messages[0].Fields[0].Value.Status = ua.StatusBadInternalError
	b, err := Encode(nm, nil)
	require.NoError(t, err)
	require.Contains(t, string(b), `"Symbol":"BadInternalError"`)
}

func TestEncodeNamespaceArray(t *testing.T) {
	nm := testMessage(dsmHeader|single, 0, 0, message.DataSetMessageKeyFrame, 1)
	ns := []string{"http://opcfoundation.org/UA/", "urn:a", "urn:b"}
	b, err := Encode(nm, &EncodeOptions{NamespaceArray: ns})
	require.NoError(t, err)
	require.Contains(t, string(b), "nsu=urn:b;i=70000")
	out, err := Decode(b, &DecodeOptions{NamespaceArray: ns})
	require.NoError(t, err)
	require.Equal(t, ua.NewNumericNodeID(2, 70000), out.Messages[0].Fields[6].Value.Value.Value())
}

func TestEncodeShapes(t *testing.T) {
	f := func(nmMask ua.JSONNetworkMessageContentMask, count int) string {
		nm := testMessage(nmMask, ua.JSONDataSetMessageContentMaskDataSetWriterID, 0, message.DataSetMessageKeyFrame, count)
		for _, m := range nm.Messages {
			m.Fields = m.Fields[1:2]
		}
		b, err := Encode(nm, nil)
		require.NoError(t, err)
		return string(b)
	}
	require.Equal(t, `{"Int32":{"UaType":6,"Value":-5}}`, f(single, 1))
	require.Equal(t, `[{"Int32":{"UaType":6,"Value":-5}},{"Int32":{"UaType":6,"Value":-5}}]`, f(0, 2))
	require.Equal(t, `{"DataSetWriterId":10,"Payload":{"Int32":{"UaType":6,"Value":-5}}}`, f(dsmHeader|single, 1))
	require.Equal(t, `{"MessageId":"msg-1","MessageType":"ua-data","Messages":{"DataSetWriterId":10,"Payload":{"Int32":{"UaType":6,"Value":-5}}}}`, f(nmHeader|dsmHeader|single, 1))
}

func TestEncodeRawData(t *testing.T) {
	nm := testMessage(single, 0, ua.DataSetFieldContentMaskRawData, message.DataSetMessageKeyFrame, 1)
	b, err := Encode(nm, nil)
	require.NoError(t, err)
	require.Equal(t, `{"Bool":true,"Int32":-5,"Double":3.25,"String":"hello \"world\"","Ints":[1,2,3],"Time":"2024-05-06T07:08:09.1234567Z","Node":"ns=2;i=70000"}`, string(b))

	// Without metadata the values are typed after their JSON form.
	out, err := Decode(b, nil)
	require.NoError(t, err)
	got := map[string]interface{}{}
	for _, f := range out.Messages[0].Fields {
		got[f.Name] = f.Value.Value.Value()
	}
	require.Equal(t, map[string]interface{}{
		"Bool": true, "Int32": int64(-5), "Double": 3.25, "String": `hello "world"`,
		"Ints": []int64{1, 2, 3}, "Time": "2024-05-06T07:08:09.1234567Z", "Node": "ns=2;i=70000",
	}, got)
}

func TestRawDataWithoutMetaData(t *testing.T) {
	out, err := Decode([]byte(`{"a":[1.5,2],"b":["x","y"],"c":[true,false],"d":{"x":1},"e":[1,"x"],"f":[],"g":1e400,"h":18446744073709551615}`), nil)
	require.NoError(t, err)
	got := map[string]interface{}{}
	for _, f := range out.Messages[0].Fields {
		got[f.Name] = f.Value.Value.Value()
	}
	require.Equal(t, []float64{1.5, 2}, got["a"])
	require.Equal(t, []string{"x", "y"}, got["b"])
	require.Equal(t, []bool{true, false}, got["c"])
	require.Equal(t, `{"x":1}`, got["d"])
	require.Equal(t, `[1,"x"]`, got["e"])
	require.Equal(t, `[]`, got["f"])
	require.Equal(t, 18446744073709551615.0, got["h"])
}

func TestRawDataStructure(t *testing.T) {
	// A registered structure as RawData: written without the Variant
	// wrapper, read back with the DataType of the metadata.
	v := &ua.ExtensionObject{Value: &ua.ConfigurationVersionDataType{MajorVersion: 1, MinorVersion: 2}}
	v.TypeID = ua.NewFourByteExpandedNodeID(0, 14593)
	nm := &message.NetworkMessage{JSONMask: single, Messages: []*message.DataSetMessage{{
		FieldContentMask: ua.DataSetFieldContentMaskRawData,
		Fields: []*message.Field{
			{Name: "S", Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)}},
			{Name: "V", Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int16(3))}},
			{Name: "N", Value: &ua.DataValue{}},
		},
	}}}
	b, err := Encode(nm, nil)
	require.NoError(t, err)
	md := &ua.DataSetMetaDataType{Fields: []*ua.FieldMetaData{
		{Name: "S", BuiltInType: 22, DataType: ua.NewNumericNodeID(0, 14593), ValueRank: -1},
		{Name: "V", BuiltInType: 24, ValueRank: -1},
		{Name: "N", BuiltInType: 6, ValueRank: -1},
	}}
	lookup := func(message.PublisherID, uint16, uint16) *ua.DataSetMetaDataType { return md }
	out, err := Decode(b, &DecodeOptions{MetaData: lookup})
	require.NoError(t, err, "%s", b)
	eo, ok := out.Messages[0].Fields[0].Value.Value.Value().(*ua.ExtensionObject)
	require.True(t, ok)
	require.Equal(t, &ua.ConfigurationVersionDataType{MajorVersion: 1, MinorVersion: 2}, eo.Value)
	require.Equal(t, int64(3), out.Messages[0].Fields[1].Value.Value.Value(), "a BaseDataType field is typed after its JSON form")
	require.Nil(t, out.Messages[0].Fields[2].Value.Value)

	// The same structure without UaTypeId, as other stacks write it.
	for _, in := range []string{`{"S":{"MajorVersion":1,"MinorVersion":2}}`, `{"S":{ }}`} {
		out, err = Decode([]byte(in), &DecodeOptions{MetaData: lookup})
		require.NoError(t, err)
		eo, ok = out.Messages[0].Fields[0].Value.Value.Value().(*ua.ExtensionObject)
		require.True(t, ok)
		require.IsType(t, &ua.ConfigurationVersionDataType{}, eo.Value)
	}
	// A Variant in a BaseDataType field.
	out, err = Decode([]byte(`{"V":{"UaType":4,"Value":3}}`), &DecodeOptions{MetaData: lookup})
	require.NoError(t, err)
	require.Equal(t, int16(3), out.Messages[0].Fields[0].Value.Value.Value())
	out, err = Decode([]byte(`{"V":{"x":3}}`), &DecodeOptions{MetaData: lookup})
	require.NoError(t, err)
	require.Equal(t, `{"x":3}`, out.Messages[0].Fields[0].Value.Value.Value())
	_, err = Decode([]byte(`{"N":"x"}`), &DecodeOptions{MetaData: lookup})
	require.ErrorIs(t, err, ErrDecode)
}

func TestDecodeLegacyForms(t *testing.T) {
	// The 1.04 reversible Variant and DataValue.
	in := `{"MessageId":"1","MessageType":"ua-data","PublisherId":42,"Messages":[{"DataSetWriterId":"3","Status":2147483648,"Payload":{"a":{"Type":6,"Body":5},"b":{"Value":{"Type":11,"Body":1.5},"SourceTimestamp":"2024-01-01T00:00:00Z"}}}]}`
	nm, err := Decode([]byte(in), nil)
	require.NoError(t, err)
	require.Equal(t, message.NewPublisherID(message.PublisherIDUInt64, 42), nm.PublisherID)
	d := nm.Messages[0]
	require.Equal(t, uint16(3), d.DataSetWriterID)
	require.Equal(t, ua.StatusCode(0x80000000), d.Status)
	require.Equal(t, int32(5), d.Fields[0].Value.Value.Value())
	require.Equal(t, 1.5, d.Fields[1].Value.Value.Value())
	require.Equal(t, ua.DataSetFieldContentMaskSourceTimestamp, d.FieldContentMask)
}

func TestDecodeBareDataSetMessage(t *testing.T) {
	pid := message.StringPublisherID("p")
	nm, err := Decode([]byte(`{"DataSetWriterId":5,"MessageType":"ua-keepalive","SequenceNumber":9}`), &DecodeOptions{PublisherID: &pid})
	require.NoError(t, err)
	require.Equal(t, single|dsmHeader, nm.JSONMask)
	require.Equal(t, pid, nm.PublisherID)
	require.Equal(t, message.DataSetMessageKeepAlive, nm.Messages[0].Type)

	// Header members only, no MessageType: a DataSetMessage, not a payload.
	nm, err = Decode([]byte(`[{"DataSetWriterId":5,"SequenceNumber":9},{"x":1}]`), nil)
	require.NoError(t, err)
	require.Equal(t, dsmHeader, nm.JSONMask)
	require.Equal(t, uint16(5), nm.Messages[0].DataSetWriterID)
	require.Empty(t, nm.Messages[0].Fields)
	require.Equal(t, "x", nm.Messages[1].Fields[0].Name)

	// An empty array is a NetworkMessage without DataSetMessages.
	nm, err = Decode([]byte(`[]`), nil)
	require.NoError(t, err)
	require.Empty(t, nm.Messages)

	// A network message header without Messages.
	nm, err = Decode([]byte(`{"MessageId":"1","MessageType":"ua-data"}`), nil)
	require.NoError(t, err)
	require.Empty(t, nm.Messages)
	nm, err = Decode([]byte(`{"MessageType":"ua-data","Messages":null,"PublisherId":null,"DataSetClassId":null}`), nil)
	require.NoError(t, err)
	require.Empty(t, nm.Messages)
	// Messages without MessageType.
	nm, err = Decode([]byte(`{"Messages":[{"Payload":{}}]}`), nil)
	require.NoError(t, err)
	require.Len(t, nm.Messages, 1)
	// The DataSetMessage-level PublisherId selects the metadata.
	var seen message.PublisherID
	lookup := func(p message.PublisherID, _, _ uint16) *ua.DataSetMetaDataType { seen = p; return nil }
	_, err = Decode([]byte(`{"PublisherId":"x","MessageType":"ua-deltaframe","Payload":{"a":null},"WriterGroupName":"g","DataSetWriterName":"n","PublisherId2":1}`), &DecodeOptions{MetaData: lookup})
	require.NoError(t, err)
	require.Equal(t, message.StringPublisherID("x"), seen)
}

func TestDecodeErrors(t *testing.T) {
	cases := map[string]string{
		"not json":         `{`,
		"scalar":           `42`,
		"string":           `"ua-data"`,
		"messages scalar":  `{"MessageType":"ua-data","Messages":3}`,
		"messages element": `{"MessageType":"ua-data","Messages":[3]}`,
		"dup key":          `{"MessageType":"ua-data","MessageType":"ua-data"}`,
		"bad type":         `{"MessageType":7}`,
		"bad id":           `{"MessageType":"ua-data","MessageId":7}`,
		"bad pub":          `{"MessageType":"ua-data","PublisherId":true}`,
		"bad pub neg":      `{"MessageType":"ua-data","PublisherId":-1}`,
		"bad wgn":          `{"MessageType":"ua-data","WriterGroupName":1}`,
		"bad class":        `{"MessageType":"ua-data","DataSetClassId":"zz"}`,
		"bad replyto":      `{"MessageType":"ua-data","ReplyTo":1}`,
		"writer range":     `[{"DataSetWriterId":65536,"Payload":{}}]`,
		"writer frac":      `[{"DataSetWriterId":1.5,"Payload":{}}]`,
		"writer string":    `[{"DataSetWriterId":"x","Payload":{}}]`,
		"seq range":        `[{"SequenceNumber":4294967296,"Payload":{}}]`,
		"minor":            `[{"MinorVersion":"x","Payload":{}}]`,
		"mdv":              `[{"MetaDataVersion":3,"Payload":{}}]`,
		"timestamp":        `[{"Timestamp":"yesterday","Payload":{}}]`,
		"status":           `[{"Status":"bad","Payload":{}}]`,
		"dsm pub":          `[{"PublisherId":{},"Payload":{}}]`,
		"dsm name":         `[{"DataSetWriterName":1,"Payload":{}}]`,
		"dsm wgn":          `[{"WriterGroupName":1,"Payload":{}}]`,
		"dsm type":         `[{"MessageType":1,"Payload":{}}]`,
		"payload":          `[{"Payload":[]}]`,
		"payload dup":      `[{"Payload":{"a":1,"a":2}}]`,
		"field value":      `[{"Payload":{"a":{"UaType":6,"Value":"x"}}}]`,
		"field variant":    `[{"Payload":{"a":{"Type":6,"Body":"x"}}}]`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Decode([]byte(in), nil)
			require.ErrorIs(t, err, ErrDecode)
		})
	}

	var ute *UnsupportedMessageTypeError
	for _, typ := range []string{"ua-metadata", "ua-status", "ua-application", "ua-endpoints", "ua-connection", "ua-action-request"} {
		_, err := Decode([]byte(`{"MessageType":"`+typ+`"}`), nil)
		require.ErrorAs(t, err, &ute)
		require.Equal(t, typ, ute.MessageType)
		require.Contains(t, err.Error(), typ)
	}
	_, err := Decode([]byte(`[{"MessageType":"ua-weird","Payload":{}}]`), nil)
	require.ErrorAs(t, err, &ute)

	// Limits.
	_, err = Decode([]byte(`[{},{},{}]`), &DecodeOptions{MaxDataSetMessages: 2})
	require.ErrorIs(t, err, ErrDecode)
	_, err = Decode([]byte(`{"a":1,"b":2,"c":3}`), &DecodeOptions{MaxFields: 2})
	require.ErrorIs(t, err, ErrDecode)
	_, err = Decode([]byte(`[{"Payload":{"a":1,"b":2,"c":3}}]`), &DecodeOptions{MaxFields: 2})
	require.ErrorIs(t, err, ErrDecode)
	_, err = Decode([]byte(`[{}]`), &DecodeOptions{MaxMessageSize: 3})
	require.ErrorIs(t, err, ErrDecode)
	deep := strings.Repeat("[", 200) + strings.Repeat("]", 200)
	_, err = Decode([]byte(`{"a":{"UaType":6,"Value":`+deep+`}}`), nil)
	require.ErrorIs(t, err, ErrDecode)
}

func TestEncodeErrors(t *testing.T) {
	_, err := Encode(nil, nil)
	require.Error(t, err)
	_, err = Encode(&message.NetworkMessage{Type: message.NetworkMessageDiscoveryResponse}, nil)
	require.Error(t, err)
	_, err = Encode(&message.NetworkMessage{JSONMask: single}, nil)
	require.Error(t, err)
	_, err = Encode(&message.NetworkMessage{Messages: []*message.DataSetMessage{nil}}, nil)
	require.Error(t, err)
	_, err = Encode(&message.NetworkMessage{Messages: []*message.DataSetMessage{{Type: 9}}}, nil)
	require.Error(t, err)
	_, err = Encode(&message.NetworkMessage{Messages: []*message.DataSetMessage{{Type: message.DataSetMessageKeepAlive}}}, nil)
	require.Error(t, err)
	_, err = Encode(&message.NetworkMessage{Messages: []*message.DataSetMessage{{Fields: []*message.Field{nil}}}}, nil)
	require.Error(t, err)
	_, err = Encode(&message.NetworkMessage{Messages: []*message.DataSetMessage{{Fields: []*message.Field{{Index: 3}}}}}, nil)
	require.Error(t, err)
	_, err = Encode(&message.NetworkMessage{Messages: []*message.DataSetMessage{{Fields: []*message.Field{{Name: "a"}, {Name: "a"}}}}}, nil)
	require.Error(t, err)
	bad := &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(&ua.ExtensionObject{Value: make(chan int)})}
	for _, fm := range []ua.DataSetFieldContentMask{0, ua.DataSetFieldContentMaskRawData} {
		_, err = Encode(&message.NetworkMessage{Messages: []*message.DataSetMessage{{FieldContentMask: fm, Fields: []*message.Field{{Name: "a", Value: bad}}}}}, nil)
		require.Error(t, err)
	}
}

func TestEncodeNamesFromMetaData(t *testing.T) {
	nm := &message.NetworkMessage{JSONMask: single, Messages: []*message.DataSetMessage{{
		DataSetWriterID: 1,
		Fields: []*message.Field{
			{Index: 1, Value: &ua.DataValue{Value: ua.MustVariant(int32(1))}},
			{Index: 0},
		},
	}}}
	b, err := Encode(nm, &EncodeOptions{MetaData: metaLookup("first", "second")})
	require.NoError(t, err)
	require.Equal(t, `{"second":{"UaType":6,"Value":1},"first":null}`, string(b))
	// Fields without value in every encoding.
	nm.Messages[0].FieldContentMask = ua.DataSetFieldContentMaskRawData
	b, err = Encode(nm, &EncodeOptions{MetaData: metaLookup("first", "second")})
	require.NoError(t, err)
	require.Equal(t, `{"second":1,"first":null}`, string(b))
	nm.Messages[0].FieldContentMask = ua.DataSetFieldContentMaskStatusCode
	b, err = Encode(nm, &EncodeOptions{MetaData: metaLookup("first", "second")})
	require.NoError(t, err)
	require.Equal(t, `{"second":{"UaType":6,"Value":1},"first":{}}`, string(b))
}

func TestMetaDataMessage(t *testing.T) {
	md := &ua.DataSetMetaDataType{
		Name: "ds",
		Fields: []*ua.FieldMetaData{
			{Name: "a", BuiltInType: 6, DataType: ua.NewTwoByteNodeID(6), ValueRank: -1},
			{Name: "b", BuiltInType: 12, DataType: ua.NewTwoByteNodeID(12), ValueRank: 1, ArrayDimensions: []uint32{0}},
		},
		ConfigurationVersion: &ua.ConfigurationVersionDataType{MajorVersion: 3, MinorVersion: 4},
	}
	in := &MetaDataMessage{
		MessageID:         "m1",
		PublisherID:       message.NewPublisherID(message.PublisherIDUInt32, 7),
		DataSetWriterID:   9,
		WriterGroupName:   "wg",
		DataSetWriterName: "w",
		Timestamp:         ts1,
		MetaData:          md,
	}
	b, err := EncodeMetaData(in, nil)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(string(b), `{"MessageId":"m1","MessageType":"ua-metadata","PublisherId":"7","DataSetWriterId":9,"WriterGroupName":"wg","DataSetWriterName":"w","Timestamp":"2024-05-06T07:08:09.1234567Z","MetaData":{"Name":"ds"`), "%s", b)
	typ, err := MessageType(b)
	require.NoError(t, err)
	require.Equal(t, MessageTypeMetaData, typ)

	out, err := DecodeMetaData(b, nil)
	require.NoError(t, err)
	require.Equal(t, "7", out.PublisherID.String())
	in.PublisherID = out.PublisherID
	require.Equal(t, in, out)

	any, err := DecodeAny(b, nil)
	require.NoError(t, err)
	require.IsType(t, &MetaDataMessage{}, any)

	// Generated MessageId, minimal form.
	b, err = EncodeMetaData(&MetaDataMessage{MetaData: &ua.DataSetMetaDataType{}}, nil)
	require.NoError(t, err)
	out, err = DecodeMetaData(b, nil)
	require.NoError(t, err)
	require.Len(t, out.MessageID, 36)

	_, err = EncodeMetaData(&MetaDataMessage{}, nil)
	require.Error(t, err)
	_, err = EncodeMetaData(nil, nil)
	require.Error(t, err)

	pid := message.StringPublisherID("d")
	out, err = DecodeMetaData([]byte(`{"MessageType":"ua-metadata","PublisherId":null,"MetaData":{}}`), &DecodeOptions{PublisherID: &pid})
	require.NoError(t, err)
	require.Equal(t, pid, out.PublisherID)

	var ute *UnsupportedMessageTypeError
	_, err = DecodeMetaData([]byte(`{"MessageType":"ua-data"}`), nil)
	require.ErrorAs(t, err, &ute)
	for _, bad := range []string{
		`[]`, `{`, `{}`, `{"MessageType":1}`,
		`{"MessageType":"ua-metadata"}`,
		`{"MessageType":"ua-metadata","MetaData":null}`,
		`{"MessageType":"ua-metadata","MetaData":3}`,
		`{"MessageType":"ua-metadata","MessageId":3,"MetaData":{}}`,
		`{"MessageType":"ua-metadata","PublisherId":[],"MetaData":{}}`,
		`{"MessageType":"ua-metadata","DataSetWriterId":-1,"MetaData":{}}`,
		`{"MessageType":"ua-metadata","WriterGroupName":1,"MetaData":{}}`,
		`{"MessageType":"ua-metadata","DataSetWriterName":1,"MetaData":{}}`,
		`{"MessageType":"ua-metadata","Timestamp":1,"MetaData":{}}`,
	} {
		_, err = DecodeMetaData([]byte(bad), nil)
		require.ErrorIs(t, err, ErrDecode, bad)
	}
}

func TestStatusMessage(t *testing.T) {
	in := &StatusMessage{
		MessageID:      "s1",
		PublisherID:    message.StringPublisherID("pub"),
		Timestamp:      ts1,
		IsCyclic:       true,
		Status:         ua.PubSubStateOperational,
		NextReportTime: ts2,
	}
	b, err := EncodeStatus(in, nil)
	require.NoError(t, err)
	require.Equal(t, `{"MessageId":"s1","MessageType":"ua-status","PublisherId":"pub","Timestamp":"2024-05-06T07:08:09.1234567Z","IsCyclic":true,"Status":2,"NextReportTime":"2024-05-06T07:08:10Z"}`, string(b))
	out, err := DecodeStatus(b, nil)
	require.NoError(t, err)
	require.Equal(t, in, out)
	any, err := DecodeAny(b, nil)
	require.NoError(t, err)
	require.Equal(t, in, any)

	b, err = EncodeStatus(&StatusMessage{Status: ua.PubSubStateError}, nil)
	require.NoError(t, err)
	require.Contains(t, string(b), `"IsCyclic":false,"Status":3}`)
	_, err = EncodeStatus(nil, nil)
	require.Error(t, err)

	// The Verbose enumeration form.
	pid := message.StringPublisherID("d")
	out, err = DecodeStatus([]byte(`{"MessageType":"ua-status","PublisherId":null,"Status":"Paused_1"}`), &DecodeOptions{PublisherID: &pid})
	require.NoError(t, err)
	require.Equal(t, ua.PubSubStatePaused, out.Status)
	require.Equal(t, pid, out.PublisherID)
	for _, bad := range []string{
		`{"MessageType":"ua-status","IsCyclic":1}`,
		`{"MessageType":"ua-status","Status":{}}`,
		`{"MessageType":"ua-status","Timestamp":1}`,
		`{"MessageType":"ua-status","NextReportTime":1}`,
		`{"MessageType":"ua-status","MessageId":1}`,
		`{"MessageType":"ua-status","PublisherId":true}`,
	} {
		_, err = DecodeStatus([]byte(bad), nil)
		require.ErrorIs(t, err, ErrDecode, bad)
	}
}

func TestDecodeAny(t *testing.T) {
	nm := testMessage(nmHeader|dsmHeader, allDSM, 0, message.DataSetMessageKeyFrame, 1)
	b, err := Encode(nm, nil)
	require.NoError(t, err)
	v, err := DecodeAny(b, nil)
	require.NoError(t, err)
	require.IsType(t, &message.NetworkMessage{}, v)

	v, err = DecodeAny([]byte(`[]`), nil)
	require.NoError(t, err)
	require.IsType(t, &message.NetworkMessage{}, v)

	_, err = DecodeAny([]byte(`7`), nil)
	require.ErrorIs(t, err, ErrDecode)
	_, err = DecodeAny([]byte(`{"MessageType":`), nil)
	require.ErrorIs(t, err, ErrDecode)
	_, err = DecodeAny([]byte(`{}`), &DecodeOptions{MaxMessageSize: 1})
	require.ErrorIs(t, err, ErrDecode)
	var ute *UnsupportedMessageTypeError
	_, err = DecodeAny([]byte(`{"MessageType":"ua-endpoints"}`), nil)
	require.True(t, errors.As(err, &ute))
	typ, err := MessageType([]byte(`{"a":1}`))
	require.NoError(t, err)
	require.Empty(t, typ)
	_, err = MessageType([]byte(`{"MessageType":1}`))
	require.Error(t, err)
	_, err = DecodeStatus([]byte(`{}`), &DecodeOptions{MaxMessageSize: 1})
	require.ErrorIs(t, err, ErrDecode)
}

func TestParseHelpers(t *testing.T) {
	_, err := objectMembers([]byte(`{"a":1} x`), 10)
	require.ErrorIs(t, err, ErrDecode)
	_, err = objectMembers([]byte(`[1]`), 10)
	require.ErrorIs(t, err, ErrDecode)
	_, err = objectMembers([]byte(``), 10)
	require.ErrorIs(t, err, ErrDecode)
	_, err = objectMembers([]byte(`{"a":}`), 10)
	require.ErrorIs(t, err, ErrDecode)
	_, err = objectMembers([]byte(`{"a":1`), 10)
	require.ErrorIs(t, err, ErrDecode)
	_, err = arrayElements([]byte(`{}`), 10)
	require.ErrorIs(t, err, ErrDecode)
	_, err = arrayElements([]byte(`[1] 2`), 10)
	require.ErrorIs(t, err, ErrDecode)
	_, err = arrayElements([]byte(``), 10)
	require.ErrorIs(t, err, ErrDecode)
	_, err = arrayElements([]byte(`[1,]`), 10)
	require.ErrorIs(t, err, ErrDecode)
	_, err = arrayElements([]byte(`[1`), 10)
	require.ErrorIs(t, err, ErrDecode)
	n, err := uintValue([]byte(`1e3`), "x", 5000)
	require.NoError(t, err)
	require.Equal(t, uint64(1000), n)
	_, err = uintValue([]byte(`"1`), "x", 5000)
	require.ErrorIs(t, err, ErrDecode)
	require.Equal(t, byte(0), kind([]byte("  ")))
	_, err = inferValue([]byte(`{`))
	require.Error(t, err)
	require.False(t, isDecimal("123456789012345678901"))
}
