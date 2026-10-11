// SPDX-License-Identifier: MIT

package uasc

import (
	"bytes"
	stderrors "errors"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func newReadMessage(msgType string, nodes int) *Message {
	req := &ua.ReadRequest{
		RequestHeader: &ua.RequestHeader{
			AuthenticationToken: ua.NewTwoByteNodeID(0),
			Timestamp:           time.Date(2024, time.January, 2, 3, 4, 5, 0, time.UTC),
			RequestHandle:       9,
			AdditionalHeader:    ua.NewExtensionObject(nil),
		},
		TimestampsToReturn: ua.TimestampsToReturnBoth,
	}
	for i := 0; i < nodes; i++ {
		req.NodesToRead = append(req.NodesToRead, &ua.ReadValueID{
			NodeID:       ua.NewNumericNodeID(2, uint32(100000+i)),
			AttributeID:  ua.AttributeIDValue,
			DataEncoding: &ua.QualifiedName{},
		})
	}
	return &Message{
		MessageHeader: &MessageHeader{
			Header:                  NewHeader(msgType, ChunkTypeFinal, 77),
			SymmetricSecurityHeader: NewSymmetricSecurityHeader(5),
			SequenceHeader:          NewSequenceHeader(11, 22),
		},
		TypeID:  ua.NewFourByteExpandedNodeID(0, id.ReadRequestEncodingDefaultBinary),
		Service: req,
	}
}

func TestMessage_EncodeChunksSplitsBody(t *testing.T) {
	whole, err := newReadMessage("MSG", 40).Encode()
	require.NoError(t, err)
	const headerLen = 24 // header + symmetric security header + sequence header
	body := whole[headerLen:]

	const maxBody = 64
	m := newReadMessage("MSG", 40)
	chunks, err := m.EncodeChunks(maxBody)
	require.NoError(t, err)
	require.Len(t, chunks, len(body)/maxBody+1)
	require.Greater(t, len(chunks), 2)

	var joined []byte
	for i, c := range chunks {
		var h MessageChunk
		_, err := h.Decode(c)
		require.NoError(t, err)
		require.Equal(t, "MSG", h.MessageType)
		require.Equal(t, uint32(77), h.SecureChannelID)
		require.Equal(t, uint32(5), h.TokenID)
		require.Equal(t, uint32(len(c)), h.MessageSize, "chunk %d declares its own size", i)
		if i < len(chunks)-1 {
			require.Equal(t, byte(ChunkTypeIntermediate), h.ChunkType)
			require.Len(t, c, headerLen+maxBody)
		} else {
			require.Equal(t, byte(ChunkTypeFinal), h.ChunkType)
		}
		// h.Data starts at the sequence header (which may be encrypted on the wire).
		var seq SequenceHeader
		n, err := seq.Decode(h.Data)
		require.NoError(t, err)
		require.Equal(t, uint32(22), seq.RequestID)
		joined = append(joined, h.Data[n:]...)
	}
	require.True(t, bytes.Equal(body, joined), "the chunk bodies must reassemble to the unchunked body")

	// The reassembled message decodes back to the original request.
	var got Message
	_, err = got.Decode(append(append([]byte{}, whole[:headerLen]...), joined...))
	require.NoError(t, err)
	req, ok := got.Service.(*ua.ReadRequest)
	require.True(t, ok)
	require.Len(t, req.NodesToRead, 40)
	require.Equal(t, uint32(100039), req.NodesToRead[39].NodeID.IntID())
}

func TestMessage_EncodeChunksZeroBodySizeUsesDefault(t *testing.T) {
	// 4096 is the fallback: a body below it stays in one chunk, a larger one is split.
	chunks, err := newReadMessage("MSG", 2).EncodeChunks(0)
	require.NoError(t, err)
	require.Len(t, chunks, 1)

	big, err := newReadMessage("MSG", 600).Encode()
	require.NoError(t, err)
	require.Greater(t, len(big)-24, 4096)
	chunks, err = newReadMessage("MSG", 600).EncodeChunks(0)
	require.NoError(t, err)
	require.Len(t, chunks, (len(big)-24)/4096+1)
	require.Len(t, chunks[0], 24+4096)
}

func TestMessage_EncodeErrors(t *testing.T) {
	m := newReadMessage("XXX", 1)
	chunks, err := m.EncodeChunks(1024)
	require.True(t, stderrors.Is(err, errors.ErrInvalidMessageType))
	require.Nil(t, chunks)

	b, err := m.Encode()
	require.True(t, stderrors.Is(err, errors.ErrInvalidMessageType))
	require.Nil(t, b)

	// A service body that cannot be serialized.
	m = newReadMessage("MSG", 1)
	m.Service = make(chan int)
	chunks, err = m.EncodeChunks(1024)
	require.Error(t, err)
	require.Nil(t, chunks)
}

func TestMessage_DecodeErrors(t *testing.T) {
	good, err := newReadMessage("MSG", 1).Encode()
	require.NoError(t, err)

	t.Run("unknown message type", func(t *testing.T) {
		bad := append([]byte("XYZ"), good[3:]...)

		var h MessageHeader
		_, err := h.Decode(bad)
		require.True(t, stderrors.Is(err, errors.ErrInvalidMessageType))

		var c MessageChunk
		_, err = c.Decode(bad)
		require.True(t, stderrors.Is(err, errors.ErrInvalidMessageType))
		require.Nil(t, c.Data)

		var m Message
		_, err = m.Decode(bad)
		require.True(t, stderrors.Is(err, errors.ErrInvalidMessageType))
		require.Nil(t, m.Service)
	})

	t.Run("truncated sequence header", func(t *testing.T) {
		var m Message
		_, err := m.Decode(good[:18]) // header (12) + token id (4) + half a sequence header
		require.Error(t, err)
		require.Nil(t, m.Service)
	})

	t.Run("truncated header", func(t *testing.T) {
		var m Message
		_, err := m.Decode(good[:6])
		require.Error(t, err)
	})

	t.Run("unknown service", func(t *testing.T) {
		var m Message
		// Replace the service type id (four byte node id at offset 24) by i=1.
		bad := append([]byte{}, good...)
		bad[26], bad[27] = 0x01, 0x00
		_, err := m.Decode(bad)
		require.Equal(t, ua.StatusBadServiceUnsupported, err)
	})
}
