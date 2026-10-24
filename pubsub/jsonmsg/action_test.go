// SPDX-License-Identifier: MIT

package jsonmsg

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/ua"
)

func actionField(name string, v any) *message.Field {
	return &message.Field{Name: name, Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)}}
}

func actionRequest() *message.NetworkMessage {
	requestor := message.StringPublisherID("requestor")
	return &message.NetworkMessage{
		Type:        message.NetworkMessageDataSet,
		PublisherID: message.NewPublisherID(message.PublisherIDUInt16, 7),
		MessageID:   "m1",
		Timestamp:   time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC),
		Action: &message.ActionHeader{
			Type:            message.ActionRequest,
			ResponseAddress: "prefix/json/action-response/7/wg",
			CorrelationData: []byte{1, 2, 3},
			RequestorID:     &requestor,
			TimeoutHint:     2500,
		},
		Messages: []*message.DataSetMessage{{
			DataSetWriterID: 3, Type: message.DataSetMessageActionRequest, Valid: true,
			JSONMask: ua.JSONDataSetMessageContentMaskDataSetWriterName | ua.JSONDataSetMessageContentMaskWriterGroupName |
				ua.JSONDataSetMessageContentMaskMetaDataVersion | ua.JSONDataSetMessageContentMaskTimestamp |
				ua.JSONDataSetMessageContentMaskMessageType,
			DataSetWriterName: "w", WriterGroupName: "wg",
			MetaDataVersion: ua.ConfigurationVersionDataType{MajorVersion: 1, MinorVersion: 2},
			Timestamp:       time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC),
			ActionTargetID:  9, RequestID: 41, ActionState: ua.ActionStateExecuting,
			Fields: []*message.Field{actionField("a", int32(5)), actionField("b", "x")},
		}},
	}
}

func TestActionJSONRoundTrip(t *testing.T) {
	in := actionRequest()
	b, err := Encode(in, nil)
	require.NoError(t, err)
	var raw map[string]any
	require.NoError(t, json.Unmarshal(b, &raw))
	require.Equal(t, "ua-action-request", raw["MessageType"])
	require.Equal(t, "7", raw["PublisherId"])
	require.Equal(t, "requestor", raw["RequestorId"])
	require.Equal(t, "AQID", raw["CorrelationData"])
	require.Equal(t, 2500.0, raw["TimeoutHint"])
	dsm := raw["Messages"].([]any)[0].(map[string]any)
	require.Equal(t, 9.0, dsm["ActionTargetId"])
	require.Equal(t, 41.0, dsm["RequestId"])
	require.Equal(t, 1.0, dsm["ActionState"])
	require.Equal(t, "ua-action-request", dsm["MessageType"])
	require.NotContains(t, dsm, "Status", "a request carries no Status")

	out, err := Decode(b, nil)
	require.NoError(t, err)
	require.Equal(t, in.Action.Type, out.Action.Type)
	require.Equal(t, in.Action.ResponseAddress, out.Action.ResponseAddress)
	require.Equal(t, in.Action.CorrelationData, out.Action.CorrelationData)
	require.Equal(t, "requestor", out.Action.RequestorID.String())
	require.Equal(t, 2500.0, out.Action.TimeoutHint)
	require.Equal(t, in.Timestamp, out.Timestamp)
	require.Equal(t, "m1", out.MessageID)
	require.Equal(t, "7", out.PublisherID.String())
	m := out.Messages[0]
	require.Equal(t, message.DataSetMessageActionRequest, m.Type)
	require.Equal(t, uint16(3), m.DataSetWriterID)
	require.Equal(t, uint16(9), m.ActionTargetID)
	require.Equal(t, uint16(41), m.RequestID)
	require.Equal(t, ua.ActionStateExecuting, m.ActionState)
	require.Equal(t, "w", m.DataSetWriterName)
	require.Equal(t, "wg", m.WriterGroupName)
	require.Equal(t, uint32(2), m.MetaDataVersion.MinorVersion)
	require.Len(t, m.Fields, 2)
	require.Equal(t, int32(5), m.Fields[0].Value.Value.Value())
	require.Equal(t, "b", m.Fields[1].Name)

	// DecodeAny returns the NetworkMessage.
	v, err := DecodeAny(b, nil)
	require.NoError(t, err)
	require.IsType(t, &message.NetworkMessage{}, v)
}

func TestActionJSONResponse(t *testing.T) {
	requestor := message.NewPublisherID(message.PublisherIDUInt32, 99)
	md := &ua.DataSetMetaDataType{Fields: []*ua.FieldMetaData{{Name: "out", BuiltInType: uint8(ua.TypeIDDouble), ValueRank: -1}}}
	in := &message.NetworkMessage{
		Type:        message.NetworkMessageDataSet,
		PublisherID: message.StringPublisherID("responder"),
		Action:      &message.ActionHeader{Type: message.ActionResponse, ResponseAddress: "ignored", TimeoutHint: 9, RequestorID: &requestor},
		Messages: []*message.DataSetMessage{{
			DataSetWriterID: 3, Type: message.DataSetMessageActionResponse, Valid: true,
			// DataValue bits are written as Variants.
			FieldContentMask: ua.DataSetFieldContentMaskStatusCode,
			Status:           ua.StatusUncertain, ActionTargetID: 2, RequestID: 5, ActionState: ua.ActionStateDone,
			Fields: []*message.Field{{Index: 0, Value: &ua.DataValue{EncodingMask: ua.DataValueValue | ua.DataValueStatusCode, Value: ua.MustVariant(1.5), Status: ua.StatusBadInternalError}}},
		}},
	}
	lookup := func(message.PublisherID, uint16, uint16) *ua.DataSetMetaDataType { return md }
	b, err := Encode(in, &EncodeOptions{MetaData: lookup})
	require.NoError(t, err)
	s := string(b)
	require.Contains(t, s, `"MessageType":"ua-action-response"`)
	require.NotContains(t, s, "ResponseAddress")
	require.NotContains(t, s, "TimeoutHint")
	require.NotContains(t, s, "MessageId\":\"\"")
	require.Contains(t, s, `"Status":{"Code":1073741824}`)
	require.NotContains(t, s, "SourceTimestamp")

	out, err := Decode(b, &DecodeOptions{MetaData: lookup})
	require.NoError(t, err)
	require.Equal(t, message.ActionResponse, out.Action.Type)
	require.Equal(t, "99", out.Action.RequestorID.String())
	require.Nil(t, out.Action.CorrelationData)
	m := out.Messages[0]
	require.Equal(t, message.DataSetMessageActionResponse, m.Type)
	require.Equal(t, ua.StatusUncertain, m.Status)
	require.Equal(t, ua.ActionStateDone, m.ActionState)
	require.Equal(t, 1.5, m.Fields[0].Value.Value.Value())
	require.Equal(t, "out", m.Fields[0].Name)

	// RawData fields are bare values.
	in.Messages[0].FieldContentMask = ua.DataSetFieldContentMaskRawData
	b, err = Encode(in, &EncodeOptions{MetaData: lookup})
	require.NoError(t, err)
	require.Contains(t, string(b), `"Payload":{"out":1.5}`)
	out, err = Decode(b, &DecodeOptions{MetaData: lookup})
	require.NoError(t, err)
	require.Equal(t, 1.5, out.Messages[0].Fields[0].Value.Value.Value())

	// Responses ignore a ResponseAddress and a TimeoutHint; ActionState in
	// its Verbose and name forms; Messages as an object.
	b = []byte(`{"MessageType":"ua-action-response","PublisherId":"1","ResponseAddress":"x","TimeoutHint":5,
		"Messages":{"DataSetWriterId":1,"ActionTargetId":1,"RequestId":1,"ActionState":"Executing_1","Payload":{}}}`)
	out, err = Decode(b, nil)
	require.NoError(t, err)
	require.Empty(t, out.Action.ResponseAddress)
	require.Zero(t, out.Action.TimeoutHint)
	require.Equal(t, ua.ActionStateExecuting, out.Messages[0].ActionState)
	require.Equal(t, message.DataSetMessageActionResponse, out.Messages[0].Type)
	out, err = Decode([]byte(strings.Replace(string(b), "Executing_1", "Done", 1)), nil)
	require.NoError(t, err)
	require.Equal(t, ua.ActionStateDone, out.Messages[0].ActionState)
}

func TestActionJSONEncodeErrors(t *testing.T) {
	for name, mod := range map[string]func(nm *message.NetworkMessage){
		"no type":     func(nm *message.NetworkMessage) { nm.Action.Type = 0 },
		"no messages": func(nm *message.NetworkMessage) { nm.Messages = nil },
		"nil message": func(nm *message.NetworkMessage) { nm.Messages[0] = nil },
		"wrong type":  func(nm *message.NetworkMessage) { nm.Messages[0].Type = message.DataSetMessageActionResponse },
		"state":       func(nm *message.NetworkMessage) { nm.Messages[0].ActionState = 7 },
		"timeout":     func(nm *message.NetworkMessage) { z := 0.0; nm.Action.TimeoutHint = z / z },
		"no name":     func(nm *message.NetworkMessage) { nm.Messages[0].Fields[0].Name = "" },
	} {
		nm := actionRequest()
		mod(nm)
		_, err := Encode(nm, nil)
		require.Error(t, err, name)
	}
	// Without MessageId and Timestamp both are generated.
	nm := actionRequest()
	nm.MessageID, nm.Timestamp = "", time.Time{}
	b, err := Encode(nm, nil)
	require.NoError(t, err)
	out, err := Decode(b, nil)
	require.NoError(t, err)
	require.NotEmpty(t, out.MessageID)
	require.WithinDuration(t, time.Now(), out.Timestamp, time.Minute)
}

func TestActionJSONMalformed(t *testing.T) {
	const head = `{"MessageType":"ua-action-request","PublisherId":"1",`
	dsm := func(members string) string {
		return head + `"Messages":[{"DataSetWriterId":1,"ActionTargetId":1,"RequestId":1,"ActionState":1` + members + `,"Payload":{}}]}`
	}
	for name, in := range map[string]string{
		"no messages":          head + `"TimeoutHint":1}`,
		"empty messages":       head + `"Messages":[]}`,
		"messages string":      head + `"Messages":"x"}`,
		"message not object":   head + `"Messages":[1]}`,
		"duplicate member":     head + `"Messages":[{"RequestId":1,"RequestId":2}]}`,
		"bad correlation":      head + `"CorrelationData":"!!","Messages":[{}]}`,
		"correlation number":   head + `"CorrelationData":5,"Messages":[{}]}`,
		"long correlation":     head + `"CorrelationData":"` + strings.Repeat("A", 8000) + `","Messages":[{}]}`,
		"negative timeout":     head + `"TimeoutHint":-1,"Messages":[{}]}`,
		"timeout string":       head + `"TimeoutHint":"1","Messages":[{}]}`,
		"requestor object":     head + `"RequestorId":{},"Messages":[{}]}`,
		"address number":       head + `"ResponseAddress":1,"Messages":[{}]}`,
		"message id number":    head + `"MessageId":1,"Messages":[{}]}`,
		"publisher object":     `{"MessageType":"ua-action-request","PublisherId":{},"Messages":[{}]}`,
		"bad timestamp":        head + `"Timestamp":"x","Messages":[{}]}`,
		"state 3":              dsm(`,"ActionState":3`),
		"state name":           strings.Replace(dsm(""), `"ActionState":1`, `"ActionState":"Running"`, 1),
		"state verbose number": strings.Replace(dsm(""), `"ActionState":1`, `"ActionState":"Done_1"`, 1),
		"state object":         strings.Replace(dsm(""), `"ActionState":1`, `"ActionState":{}`, 1),
		"target range":         strings.Replace(dsm(""), `"ActionTargetId":1`, `"ActionTargetId":70000`, 1),
		"request id range":     strings.Replace(dsm(""), `"RequestId":1`, `"RequestId":-1`, 1),
		"wrong message type":   dsm(`,"MessageType":"ua-action-response"`),
		"datavalue field":      strings.Replace(dsm(""), `"Payload":{}`, `"Payload":{"a":{"UaType":6,"Value":1,"Status":{"Code":2147483648}}}`, 1),
		"payload array":        strings.Replace(dsm(""), `"Payload":{}`, `"Payload":[]`, 1),
	} {
		_, err := Decode([]byte(in), nil)
		if name == "duplicate member" || name == "state 3" || name == "wrong message type" {
			require.Error(t, err, name)
			continue
		}
		require.ErrorIs(t, err, ErrDecode, name)
	}
	// A ua-keyframe DataSetMessage in an action message.
	_, err := Decode([]byte(dsm(`,"MessageType":"ua-keyframe"`)), nil)
	require.ErrorIs(t, err, ErrDecode)
	// An action DataSetMessage in a ua-data message.
	var ute *UnsupportedMessageTypeError
	_, err = Decode([]byte(`{"MessageType":"ua-data","Messages":[{"DataSetWriterId":1,"MessageType":"ua-action-request","Payload":{}}]}`), nil)
	require.ErrorAs(t, err, &ute)
	// Too many DataSetMessages.
	_, err = Decode([]byte(head+`"Messages":[{},{},{}]}`), &DecodeOptions{MaxDataSetMessages: 2})
	require.ErrorIs(t, err, ErrDecode)
	// A null RequestorId and CorrelationData are absent.
	out, err := Decode([]byte(`{"MessageType":"ua-action-request","RequestorId":null,"CorrelationData":null,"PublisherId":null,"Messages":[{}]}`), nil)
	require.NoError(t, err)
	require.Nil(t, out.Action.RequestorID)
	require.Nil(t, out.Action.CorrelationData)
}
