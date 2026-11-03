// SPDX-License-Identifier: MIT

package uasc

import (
	"bytes"
	stderrors "errors"
	"math"
	"strconv"
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

// TestMessageSize covers the bound on the UInt32 MessageSize of a chunk
// (Part 6 §6.7.2.2) without allocating a body of 4 GiB.
func TestMessageSize(t *testing.T) {
	t.Parallel()
	if strconv.IntSize < 64 {
		t.Skip("a body of 4 GiB has no int length here")
	}
	// Kept out of constant expressions so that the file builds where int
	// has 32 bits.
	maxU32 := uint64(math.MaxUint32)
	got, err := messageSize(symmetricChunkHeaderSize, 100)
	require.NoError(t, err)
	require.EqualValues(t, 124, got)

	got, err = messageSize(symmetricChunkHeaderSize, int(maxU32-symmetricChunkHeaderSize))
	require.NoError(t, err)
	require.EqualValues(t, uint32(math.MaxUint32), got)

	for _, tc := range []struct{ header, body int }{
		{symmetricChunkHeaderSize, int(maxU32 - symmetricChunkHeaderSize + 1)},
		{12 + 100, int(maxU32)},
		{symmetricChunkHeaderSize, -1},
	} {
		_, err := messageSize(tc.header, tc.body)
		require.ErrorIs(t, err, errors.ErrMessageTooLarge, "header %d body %d", tc.header, tc.body)
	}
}

// TestTimeoutHint: the TimeoutHint is a UInt32 of milliseconds (Part 4
// §7.33); timeouts outside it are clamped, not wrapped.
func TestTimeoutHint(t *testing.T) {
	t.Parallel()
	require.EqualValues(t, 1500, timeoutHint(1500*time.Millisecond))
	require.EqualValues(t, 0, timeoutHint(-time.Second))
	require.EqualValues(t, uint32(math.MaxUint32), timeoutHint(50*24*time.Hour))
	require.EqualValues(t, uint32(math.MaxUint32), timeoutHint(math.MaxUint32*time.Millisecond))
}

// TestCheckPeerLimits: a message over the MaxMessageSize or MaxChunkCount the
// peer announced is refused; zero is no limit (Part 6 §7.1.2.3, §7.1.2.4).
func TestCheckPeerLimits(t *testing.T) {
	t.Parallel()
	require.NoError(t, checkPeerLimits(1000, 3, 0, 0))
	require.NoError(t, checkPeerLimits(1000, 3, 1000, 3))
	require.ErrorIs(t, checkPeerLimits(1001, 1, 1000, 0), errors.ErrMessageTooLarge)
	require.ErrorIs(t, checkPeerLimits(10, 4, 0, 3), errors.ErrMessageTooLarge)
	require.NoError(t, checkPeerLimits(math.MaxInt32, 1, math.MaxUint32, 0), "limits above MaxInt32 work on 32-bit platforms")
}

// TestAbortChunks_Bounded: a peer that never finishes the messages it had
// refused cannot make the set of their request ids grow.
func TestAbortChunks_Bounded(t *testing.T) {
	t.Parallel()
	s := &SecureChannel{chunks: make(map[uint32][]*MessageChunk)}
	for id := uint32(0); id < 10*maxAbortedChunks; id++ {
		s.chunks[id] = []*MessageChunk{{}}
		s.abortChunks(id)
		require.NotContains(t, s.chunks, id)
		require.Contains(t, s.chunksAborted, id)
	}
	require.Len(t, s.chunksAborted, maxAbortedChunks)
}
