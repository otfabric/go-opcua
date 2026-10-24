// SPDX-License-Identifier: MIT

package uadp

import (
	"math/rand/v2"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/ua"
)

func actionDSM(t message.DataSetMessageType, writer, target, req uint16, st ua.ActionState, fields ...*message.Field) *message.DataSetMessage {
	return &message.DataSetMessage{DataSetWriterID: writer, Type: t, Valid: true,
		ActionTargetID: target, RequestID: req, ActionState: st, Fields: fields}
}

func actionRequestNM() *message.NetworkMessage {
	requestor := message.StringPublisherID("requestor")
	return &message.NetworkMessage{
		Type:        message.NetworkMessageDataSet,
		UADPMask:    ua.UADPNetworkMessageContentMaskPublisherID | ua.UADPNetworkMessageContentMaskPayloadHeader,
		PublisherID: message.NewPublisherID(message.PublisherIDUInt16, 7),
		Action: &message.ActionHeader{
			Type:            message.ActionRequest,
			ResponseAddress: "opc.udp://127.0.0.1:4841",
			CorrelationData: []byte{1, 2, 3, 4},
			RequestorID:     &requestor,
			TimeoutHint:     1500,
		},
		Messages: []*message.DataSetMessage{
			actionDSM(message.DataSetMessageActionRequest, 3, 9, 41, ua.ActionStateExecuting, vf(0, int32(5)), vf(1, "x")),
			actionDSM(message.DataSetMessageActionRequest, 4, 1, 42, ua.ActionStateIdle),
		},
	}
}

func TestActionRoundTrip(t *testing.T) {
	in := actionRequestNM()
	b, err := Encode(in, nil)
	require.NoError(t, err)
	require.True(t, PeekAction(b))
	typ, chunk, err := PeekType(b)
	require.NoError(t, err)
	require.Equal(t, message.NetworkMessageDataSet, typ)
	require.False(t, chunk)

	out, err := Decode(b, nil)
	require.NoError(t, err)
	require.Equal(t, in.Action, out.Action)
	require.Equal(t, in.PublisherID, out.PublisherID)
	require.Len(t, out.Messages, 2)
	for i, m := range out.Messages {
		require.Equal(t, in.Messages[i].DataSetWriterID, m.DataSetWriterID)
		require.Equal(t, message.DataSetMessageActionRequest, m.Type)
		require.Equal(t, in.Messages[i].ActionTargetID, m.ActionTargetID)
		require.Equal(t, in.Messages[i].RequestID, m.RequestID)
		require.Equal(t, in.Messages[i].ActionState, m.ActionState)
		require.Len(t, m.Fields, len(in.Messages[i].Fields))
	}
	require.Equal(t, int32(5), out.Messages[0].Fields[0].Value.Value.Value())
	require.Equal(t, "x", out.Messages[0].Fields[1].Value.Value.Value())

	// A response: Status in the DataSetMessage header, no ResponseAddress
	// and TimeoutHint even if set, an empty CorrelationData kept.
	resp := &message.NetworkMessage{
		Type:        message.NetworkMessageDataSet,
		UADPMask:    ua.UADPNetworkMessageContentMaskPublisherID,
		PublisherID: message.NewPublisherID(message.PublisherIDByte, 1),
		Action:      &message.ActionHeader{Type: message.ActionResponse, ResponseAddress: "x", TimeoutHint: 5, CorrelationData: []byte{}},
		Messages: []*message.DataSetMessage{{Type: message.DataSetMessageActionResponse, Valid: true,
			UADPMask: ua.UADPDataSetMessageContentMaskStatus, Status: ua.StatusBadTimeout,
			ActionTargetID: 2, RequestID: 3, ActionState: ua.ActionStateDone, Fields: []*message.Field{vf(0, 1.5)}}},
	}
	b, err = Encode(resp, nil)
	require.NoError(t, err)
	out, err = Decode(b, nil)
	require.NoError(t, err)
	require.Equal(t, &message.ActionHeader{Type: message.ActionResponse, CorrelationData: []byte{}}, out.Action)
	m := out.Messages[0]
	require.Equal(t, ua.StatusBadTimeout, m.Status)
	require.Equal(t, ua.ActionStateDone, m.ActionState)
	require.Equal(t, 1.5, m.Fields[0].Value.Value.Value())

	// Without optional members.
	resp.Action = &message.ActionHeader{Type: message.ActionResponse}
	b, err = Encode(resp, nil)
	require.NoError(t, err)
	out, err = Decode(b, nil)
	require.NoError(t, err)
	require.Equal(t, resp.Action, out.Action)

	// Every RequestorId type.
	for _, r := range []message.PublisherID{
		message.NewPublisherID(message.PublisherIDByte, 3), message.NewPublisherID(message.PublisherIDUInt16, 300),
		message.NewPublisherID(message.PublisherIDUInt32, 70000), message.NewPublisherID(message.PublisherIDUInt64, 1<<40),
	} {
		in := actionRequestNM()
		in.Action.RequestorID = &r
		b, err := Encode(in, nil)
		require.NoError(t, err)
		out, err := Decode(b, nil)
		require.NoError(t, err)
		require.Equal(t, r, *out.Action.RequestorID)
	}
}

func TestActionRawData(t *testing.T) {
	md := &ua.DataSetMetaDataType{Fields: []*ua.FieldMetaData{
		{Name: "a", BuiltInType: uint8(ua.TypeIDInt32), DataType: ua.NewNumericNodeID(0, id.Int32), ValueRank: -1},
		{Name: "b", BuiltInType: uint8(ua.TypeIDUint16), DataType: ua.NewNumericNodeID(0, id.UInt16), ValueRank: -1},
	}}
	in := actionRequestNM()
	in.Messages = in.Messages[:1]
	in.Messages[0].FieldEncoding = message.FieldEncodingRawData
	in.Messages[0].Fields = []*message.Field{vf(0, int32(-2)), vf(1, uint16(9))}
	b, err := Encode(in, &EncodeOptions{MetaData: metaLookup(md)})
	require.NoError(t, err)
	out, err := Decode(b, &DecodeOptions{MetaData: metaLookup(md)})
	require.NoError(t, err)
	m := out.Messages[0]
	require.Equal(t, message.FieldEncodingRawData, m.FieldEncoding)
	require.Equal(t, int32(-2), m.Fields[0].Value.Value.Value())
	require.Equal(t, uint16(9), m.Fields[1].Value.Value.Value())
	require.Equal(t, "a", m.Fields[0].Name)

	_, err = Decode(b, nil)
	require.ErrorIs(t, err, ErrNoMetaData)
	short := &ua.DataSetMetaDataType{Fields: md.Fields[:1]}
	_, err = Decode(b, &DecodeOptions{MetaData: metaLookup(short)})
	require.ErrorIs(t, err, ErrMalformed)
	_, err = Encode(in, &EncodeOptions{MetaData: metaLookup(short)})
	require.ErrorIs(t, err, ErrMalformed)

	// An empty RawData message (an Executing response) needs no metadata.
	in.Messages[0].Fields = nil
	b, err = Encode(in, nil)
	require.NoError(t, err)
	out, err = Decode(b, nil)
	require.NoError(t, err)
	require.Empty(t, out.Messages[0].Fields)
}

func TestActionSecured(t *testing.T) {
	ks := zeroKeys(testPolicy{})
	for _, mode := range []ua.MessageSecurityMode{ua.MessageSecurityModeSign, ua.MessageSecurityModeSignAndEncrypt} {
		in := actionRequestNM()
		b, err := Encode(in, &EncodeOptions{SecurityMode: mode, Keys: ks, NonceSequence: 1})
		require.NoError(t, err)
		require.True(t, PeekAction(b))
		var hdr *message.NetworkMessage
		out, err := Decode(b, &DecodeOptions{
			Accept:   func(h *message.NetworkMessage) bool { hdr = h; return true },
			Security: requireSecurity(mode, ks),
		})
		require.NoError(t, err)
		require.NotNil(t, hdr.Action, "the header announces the action message")
		require.Equal(t, in.Action, out.Action)
		require.Equal(t, mode == ua.MessageSecurityModeSignAndEncrypt, out.Security.Encrypted)
		require.Equal(t, "x", out.Messages[0].Fields[1].Value.Value.Value())

		if mode == ua.MessageSecurityModeSignAndEncrypt {
			// The ActionHeader is encrypted: the ResponseAddress does
			// not appear in the message.
			require.NotContains(t, string(b), in.Action.ResponseAddress)
		}
		// A modified ActionHeader fails the signature.
		bad := append([]byte(nil), b...)
		bad[len(bad)-40] ^= 0xff
		_, err = Decode(bad, &DecodeOptions{Security: requireSecurity(mode, ks)})
		require.ErrorIs(t, err, ErrSecurityChecksFailed)
		// An unsecured action message is rejected where security is
		// required.
		plain, err := Encode(in, nil)
		require.NoError(t, err)
		_, err = Decode(plain, &DecodeOptions{Security: requireSecurity(mode, ks)})
		require.ErrorIs(t, err, ErrSecurityMode)
	}
}

func TestActionEncodeErrors(t *testing.T) {
	cases := map[string]func(nm *message.NetworkMessage){
		"no type":           func(nm *message.NetworkMessage) { nm.Action.Type = 0 },
		"discovery type":    func(nm *message.NetworkMessage) { nm.Type = message.NetworkMessageDiscoveryResponse },
		"no messages":       func(nm *message.NetworkMessage) { nm.Messages = nil },
		"no payload header": func(nm *message.NetworkMessage) { nm.UADPMask = ua.UADPNetworkMessageContentMaskPublisherID },
		"nil message":       func(nm *message.NetworkMessage) { nm.Messages[1] = nil },
		"wrong dsm type":    func(nm *message.NetworkMessage) { nm.Messages[0].Type = message.DataSetMessageActionResponse },
		"key frame":         func(nm *message.NetworkMessage) { nm.Messages[0].Type = message.DataSetMessageKeyFrame },
		"long address":      func(nm *message.NetworkMessage) { nm.Action.ResponseAddress = string(make([]byte, maxActionString+1)) },
		"requestor type": func(nm *message.NetworkMessage) {
			nm.Action.RequestorID = &message.PublisherID{Type: 7}
		},
		"nan timeout":  func(nm *message.NetworkMessage) { nm.Action.TimeoutHint = nan() },
		"state":        func(nm *message.NetworkMessage) { nm.Messages[0].ActionState = 3 },
		"datavalue":    func(nm *message.NetworkMessage) { nm.Messages[0].FieldEncoding = message.FieldEncodingDataValue },
		"too many dsm": func(nm *message.NetworkMessage) { nm.Messages = make([]*message.DataSetMessage, maxMessages+1) },
		"too many fields": func(nm *message.NetworkMessage) {
			nm.Messages[0].Fields = make([]*message.Field, 1<<16)
		},
	}
	for name, mod := range cases {
		nm := actionRequestNM()
		mod(nm)
		_, err := Encode(nm, nil)
		require.ErrorIs(t, err, ErrMalformed, name)
	}
	// An action DataSetMessage needs the ActionHeader.
	nm := actionRequestNM()
	nm.Action = nil
	_, err := Encode(nm, nil)
	require.ErrorIs(t, err, ErrMalformed)
	// A chunk carries one action DataSetMessage, and its ActionHeader is
	// checked like that of a whole message.
	nm = actionRequestNM()
	_, err = EncodeChunks(nm, nil, 40)
	require.ErrorIs(t, err, ErrMalformed)
	nm.Messages = nm.Messages[:1]
	nm.Messages[0].Type = message.DataSetMessageKeyFrame
	_, err = EncodeChunks(nm, nil, 40)
	require.ErrorIs(t, err, ErrMalformed)
	for name, mod := range map[string]func(a *message.ActionHeader){
		"no type":        func(a *message.ActionHeader) { a.Type = 0 },
		"long address":   func(a *message.ActionHeader) { a.ResponseAddress = string(make([]byte, maxActionString+1)) },
		"requestor type": func(a *message.ActionHeader) { a.RequestorID = &message.PublisherID{Type: 7} },
		"nan timeout":    func(a *message.ActionHeader) { a.TimeoutHint = nan() },
	} {
		nm = actionRequestNM()
		nm.Messages = nm.Messages[:1]
		nm.Chunk = &message.Chunk{TotalSize: 10, Data: []byte{1}}
		mod(nm.Action)
		_, err = Encode(nm, nil)
		require.ErrorIs(t, err, ErrMalformed, name)
	}
}

// TestActionChunks: an ActionRequest and an ActionResponse larger than the
// NetworkMessage size are sent as chunks (Part 14 §7.2.4.4.4) that carry
// the ActionHeader, unsecured and secured, and are reassembled in any
// order.
func TestActionChunks(t *testing.T) {
	big := string(make([]byte, 3000))
	for _, mode := range []ua.MessageSecurityMode{ua.MessageSecurityModeNone, ua.MessageSecurityModeSign, ua.MessageSecurityModeSignAndEncrypt} {
		for _, typ := range []message.ActionMessageType{message.ActionRequest, message.ActionResponse} {
			t.Run(mode.String()+"/"+typ.String(), func(t *testing.T) {
				ks := zeroKeys(testPolicy{})
				nm := actionRequestNM()
				nm.Messages = nm.Messages[:1]
				nm.Messages[0].SequenceNumber = 7
				nm.Messages[0].Fields = append(nm.Messages[0].Fields, vf(2, big))
				if typ == message.ActionResponse {
					nm.Action.Type, nm.Action.ResponseAddress, nm.Action.TimeoutHint = message.ActionResponse, "", 0
					nm.Messages[0].Type = message.DataSetMessageActionResponse
					nm.Messages[0].ActionState = ua.ActionStateDone
				}
				opts := &EncodeOptions{}
				dopts := &DecodeOptions{}
				if mode > ua.MessageSecurityModeNone {
					opts = &EncodeOptions{SecurityMode: mode, Keys: ks, NonceSequence: 1}
					dopts = &DecodeOptions{Security: requireSecurity(mode, ks)}
				}
				chunks, err := EncodeChunks(nm, opts, 500)
				require.NoError(t, err)
				require.Greater(t, len(chunks), 5)
				r := NewReassembler(nil)
				var payload []byte
				var last *message.NetworkMessage
				for n, i := range rand.New(rand.NewPCG(3, 4)).Perm(len(chunks)) {
					require.LessOrEqual(t, len(chunks[i]), 500)
					require.True(t, PeekAction(chunks[i]))
					c, err := Decode(chunks[i], dopts)
					require.NoError(t, err)
					require.NotNil(t, c.Chunk)
					require.Equal(t, nm.Action, c.Action, "every chunk carries the ActionHeader")
					require.Equal(t, uint16(7), c.Chunk.MessageSequenceNumber)
					p, _, err := r.Add(c, time.Unix(1, 0))
					require.NoError(t, err)
					if n < len(chunks)-1 {
						require.Nil(t, p)
					}
					payload, last = p, c
				}
				out, err := DecodeReassembled(last, payload, nil)
				require.NoError(t, err)
				require.Equal(t, nm.Action, out.Action)
				require.Len(t, out.Messages, 1)
				m := out.Messages[0]
				require.Equal(t, nm.Messages[0].Type, m.Type)
				require.Equal(t, uint16(9), m.ActionTargetID)
				require.Equal(t, uint16(41), m.RequestID)
				require.Equal(t, big, m.Fields[2].Value.Value.Value())
			})
		}
	}

	// A reassembled payload that is not an action DataSetMessage of the
	// type of the ActionHeader is rejected.
	nm := actionRequestNM()
	nm.Messages = nm.Messages[:1]
	chunks, err := EncodeChunks(nm, nil, 100)
	require.NoError(t, err)
	r := NewReassembler(nil)
	var payload []byte
	var last *message.NetworkMessage
	for _, b := range chunks {
		c, err := Decode(b, nil)
		require.NoError(t, err)
		payload, _, err = r.Add(c, time.Unix(1, 0))
		require.NoError(t, err)
		last = c
	}
	last.Action.Type = message.ActionResponse
	_, err = DecodeReassembled(last, payload, nil)
	require.ErrorIs(t, err, ErrMalformed)
}

func nan() float64 {
	z := 0.0
	return z / z
}

func TestActionDecodeMalformed(t *testing.T) {
	good, err := Encode(actionRequestNM(), nil)
	require.NoError(t, err)
	for n := range good {
		_, err := Decode(good[:n], nil)
		require.Error(t, err, "truncated to %d bytes", n)
	}

	// UADPFlags 0x91 (PublisherId, ExtendedFlags1), ExtendedFlags1 0x80
	// (Byte PublisherId, ExtendedFlags2), ExtendedFlags2 0x20 (action),
	// PublisherId 5, then the ActionHeader and one DataSetMessage.
	hdr := []byte{0x91, 0x80, 0x20, 0x05}
	dsm := func(t byte, state byte) []byte {
		// DataSetFlags1 valid + flags2, DataSetFlags2 type, target 1,
		// request 2, state, no fields.
		return []byte{0x81, t, 0x01, 0x00, 0x02, 0x00, state, 0x00, 0x00}
	}
	ok := cat(hdr, []byte{0x01}, dsm(0x05, 1))
	_, err = Decode(ok, nil)
	require.NoError(t, err)

	for name, raw := range map[string][]byte{
		"reserved action flags":    cat(hdr, []byte{0x21}, dsm(0x05, 1)),
		"response with address":    cat(hdr, []byte{0x02, 0x01, 0x00, 0x00, 0x00, 'a'}, dsm(0x06, 2)),
		"response with timeout":    cat(hdr, []byte{0x10, 0, 0, 0, 0, 0, 0, 0xf0, 0x3f}, dsm(0x06, 2)),
		"request dsm in response":  cat(hdr, []byte{0x00}, dsm(0x05, 1)),
		"response dsm in request":  cat(hdr, []byte{0x01}, dsm(0x06, 1)),
		"key frame in request":     cat(hdr, []byte{0x01}, []byte{0x01, 0x00, 0x00}),
		"action dsm without flag":  cat([]byte{0x91, 0x00, 0x05}, dsm(0x05, 1)),
		"state 3":                  cat(hdr, []byte{0x01}, dsm(0x05, 3)),
		"field count":              cat(hdr, []byte{0x01}, []byte{0x81, 0x05, 1, 0, 2, 0, 1, 0xff, 0xff, 0x00}),
		"datavalue":                cat(hdr, []byte{0x01}, []byte{0x85, 0x05, 1, 0, 2, 0, 1, 0, 0}),
		"truncated field":          cat(hdr, []byte{0x01}, []byte{0x81, 0x05, 1, 0, 2, 0, 1, 1, 0, 0x06}),
		"nan timeout":              cat(hdr, []byte{0x11, 0, 0, 0, 0, 0, 0, 0xf8, 0x7f}, dsm(0x05, 1)),
		"requestor double":         cat(hdr, []byte{0x09, 0x0b, 0, 0, 0, 0, 0, 0, 0xf0, 0x3f}, dsm(0x05, 1)),
		"requestor truncated":      cat(hdr, []byte{0x09, 0x06, 0x01}, dsm(0x05, 1)),
		"long address":             cat(hdr, []byte{0x03, 0x01, 0x10, 0x00, 0x00}, make([]byte, 4097), dsm(0x05, 1)),
		"action in discovery":      {0x91, 0x80, 0x28, 0x05, 0x01},
		"truncated action header":  hdr,
		"truncated correlation":    cat(hdr, []byte{0x05, 0xff, 0xff, 0x00, 0x00}),
		"truncated action message": cat(hdr, []byte{0x01}, []byte{0x81, 0x05, 0x01}),
	} {
		_, err := Decode(raw, nil)
		require.ErrorIs(t, err, ErrMalformed, name)
	}
	// A truncated chunk with an ActionHeader.
	_, err = Decode([]byte{0x91, 0x80, 0x21, 0x05}, nil)
	require.ErrorIs(t, err, ErrMalformed)
	// An invalid DataSetMessage of another type is tolerated.
	_, err = Decode(cat(hdr, []byte{0x01}, []byte{0x00}), nil)
	require.NoError(t, err)

	require.False(t, PeekAction(nil))
	require.False(t, PeekAction([]byte{0x91, 0x80, 0x00}))
	require.False(t, PeekAction([]byte{0x11, 0x80, 0x20}))
}

func TestActionLargeString(t *testing.T) {
	long := message.StringPublisherID(string(make([]byte, maxActionString+1)))
	b := ua.NewBuffer(nil)
	b.WriteUint8(actRequestorID | actRequest)
	b.WriteStruct(long.Variant())
	_, _, err := decodeActionHeader(b.Bytes())
	require.ErrorIs(t, err, ErrMalformed)
}

// FuzzDecodeAction feeds arbitrary bytes, seeded with action messages
// (plain, RawData and secured), to Decode and encodes whatever it accepts
// again. Neither may panic, and an accepted message must be consistent.
func FuzzDecodeAction(f *testing.F) {
	md := &ua.DataSetMetaDataType{Fields: []*ua.FieldMetaData{
		{Name: "a", BuiltInType: uint8(ua.TypeIDInt32), DataType: ua.NewNumericNodeID(0, id.Int32), ValueRank: -1},
	}}
	ks := zeroKeys(testPolicy{})
	in := actionRequestNM()
	for _, opts := range []*EncodeOptions{nil, {SecurityMode: ua.MessageSecurityModeSignAndEncrypt, Keys: ks, NonceSequence: 3}} {
		b, err := Encode(in, opts)
		require.NoError(f, err)
		f.Add(b)
	}
	raw := actionRequestNM()
	raw.Messages = raw.Messages[:1]
	raw.Messages[0].FieldEncoding = message.FieldEncodingRawData
	raw.Messages[0].Fields = []*message.Field{vf(0, int32(1))}
	b, err := Encode(raw, &EncodeOptions{MetaData: metaLookup(md)})
	require.NoError(f, err)
	f.Add(b)
	f.Add([]byte{0x91, 0x80, 0x20, 0x05, 0x01, 0x81, 0x05, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00})

	opts := &DecodeOptions{MetaData: metaLookup(md), Security: requireSecurity(ua.MessageSecurityModeNone, ks)}
	f.Fuzz(func(t *testing.T, b []byte) {
		nm, err := Decode(b, opts)
		if err != nil {
			return
		}
		if nm.Action != nil {
			require.NotZero(t, nm.Action.Type)
			if nm.Action.Type == message.ActionResponse {
				require.Empty(t, nm.Action.ResponseAddress)
			}
		}
		for _, m := range nm.Messages {
			require.LessOrEqual(t, m.ActionState, ua.ActionStateDone)
		}
		_, _ = Encode(nm, &EncodeOptions{MetaData: metaLookup(md)})
	})
}
