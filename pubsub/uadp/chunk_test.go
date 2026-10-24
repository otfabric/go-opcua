// SPDX-License-Identifier: MIT

package uadp

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/ua"
)

const chunkMask = ua.UADPNetworkMessageContentMaskPublisherID | ua.UADPNetworkMessageContentMaskGroupHeader |
	ua.UADPNetworkMessageContentMaskWriterGroupID | ua.UADPNetworkMessageContentMaskSequenceNumber |
	ua.UADPNetworkMessageContentMaskPayloadHeader

// chunkNM is a NetworkMessage with one DataSetMessage of writer 0x14,
// sequence number 5, and one Int32 field: 10 bytes of DataSetMessage.
func chunkNM() *message.NetworkMessage {
	m := keyFrame(message.FieldEncodingVariant, vf(0, int32(0x11223344)))
	m.DataSetWriterID = 0x14
	m.SequenceNumber = 5
	m.UADPMask = ua.UADPDataSetMessageContentMaskSequenceNumber
	return &message.NetworkMessage{
		UADPMask:    chunkMask,
		PublisherID: message.NewPublisherID(message.PublisherIDByte, 1),
		GroupHeader: message.GroupHeader{WriterGroupID: 0x0a, SequenceNumber: 7},
		Messages:    []*message.DataSetMessage{m},
	}
}

// TestChunkGolden checks the layout of chunk NetworkMessages (Part 14
// §7.2.4.4.4 in 1.05). The bytes follow the .NET stack 2.x
// (UadpChunker.TrySplitNetworkMessage) for the same message and size: the
// header of the message with the chunk bit, the DataSetWriterId as the
// PayloadHeader, the GroupHeader SequenceNumber advanced per chunk, and chunk
// data of maxSize minus the 25 bytes of headers.
func TestChunkGolden(t *testing.T) {
	nm := chunkNM()
	whole, err := Encode(nm, nil)
	require.NoError(t, err)
	require.Equal(t, h(t, "71 01 09 0a00 0700 01 1400 09 0500 0100 06 44332211"), whole)

	chunks, err := EncodeChunks(nm, nil, 29)
	require.NoError(t, err)
	want := []string{
		"f1 80 01 01 09 0a00 0700 1400 0500 00000000 0a000000 04000000 09050001",
		"f1 80 01 01 09 0a00 0800 1400 0500 04000000 0a000000 04000000 00064433",
		"f1 80 01 01 09 0a00 0900 1400 0500 08000000 0a000000 02000000 2211",
	}
	require.Len(t, chunks, len(want))
	for i, w := range want {
		require.Equal(t, h(t, w), chunks[i], "chunk %d", i)
		require.LessOrEqual(t, len(chunks[i]), 29)
	}

	// Decode and reassemble in reverse order.
	r := NewReassembler(nil)
	now := time.Unix(1000, 0)
	var payload []byte
	var last *message.NetworkMessage
	for i := len(chunks) - 1; i >= 0; i-- {
		c, err := Decode(chunks[i], nil)
		require.NoError(t, err)
		require.NotNil(t, c.Chunk)
		require.Equal(t, uint16(0x14), c.Messages[0].DataSetWriterID)
		require.Equal(t, uint16(7+i), c.GroupHeader.SequenceNumber)
		require.Equal(t, chunkMask, c.UADPMask)
		p, dropped, err := r.Add(c, now)
		require.NoError(t, err)
		require.Zero(t, dropped)
		if i > 0 {
			require.Nil(t, p)
		}
		payload, last = p, c
	}
	require.Equal(t, h(t, "09 0500 0100 06 44332211"), payload)
	dec, err := DecodeReassembled(last, payload, nil)
	require.NoError(t, err)
	require.Nil(t, dec.Chunk)
	require.Len(t, dec.Messages, 1)
	m := dec.Messages[0]
	require.Equal(t, uint16(0x14), m.DataSetWriterID)
	require.Equal(t, uint32(5), m.SequenceNumber)
	require.Equal(t, int32(0x11223344), m.Fields[0].Value.Value.Value())
	st := r.Stats()
	require.Equal(t, uint64(1), st.Completed)
	require.Zero(t, st.Pending)
	require.Zero(t, st.PendingBytes)
}

func TestChunkGoldenWithoutPayloadHeader(t *testing.T) {
	nm := chunkNM()
	nm.UADPMask &^= ua.UADPNetworkMessageContentMaskPayloadHeader | ua.UADPNetworkMessageContentMaskGroupHeader
	chunks, err := EncodeChunks(nm, nil, 24)
	require.NoError(t, err)
	// 4 bytes of flags and PublisherId, 14 of chunk fields: 6 bytes of data.
	require.Equal(t, []string{
		"91 80 01 01 0500 00000000 0a000000 06000000 090500010006",
		"91 80 01 01 0500 06000000 0a000000 04000000 44332211",
	}, hexes(chunks))
	c, err := Decode(chunks[0], nil)
	require.NoError(t, err)
	require.Len(t, c.Messages, 1, "one DataSetMessage of an unknown writer")
	require.Zero(t, c.Messages[0].DataSetWriterID)
}

func hexes(bs [][]byte) []string {
	var out []string
	for _, b := range bs {
		out = append(out, spaced(b))
	}
	return out
}

// spaced formats a chunk as the vectors above: flags and PublisherId, chunk
// fields, data.
func spaced(b []byte) string {
	f := func(b []byte) string { return fmt.Sprintf("%x", b) }
	return f(b[:1]) + " " + f(b[1:2]) + " " + f(b[2:3]) + " " + f(b[3:4]) + " " + f(b[4:6]) + " " + f(b[6:10]) + " " + f(b[10:14]) + " " + f(b[14:18]) + " " + f(b[18:])
}

func TestChunkRoundTripSecured(t *testing.T) {
	for _, mode := range []ua.MessageSecurityMode{ua.MessageSecurityModeSign, ua.MessageSecurityModeSignAndEncrypt} {
		t.Run(mode.String(), func(t *testing.T) {
			ks := zeroKeys(testPolicy{})
			nm := chunkNM()
			var fields []*message.Field
			for i := range 200 {
				fields = append(fields, vf(i, fmt.Sprintf("value %d", i)))
			}
			nm.Messages[0].Fields = fields
			nm.UADPMask |= ua.UADPNetworkMessageContentMaskTimestamp | ua.UADPNetworkMessageContentMaskPromotedFields
			nm.Timestamp = ts
			nm.PromotedFields = []*ua.Variant{ua.MustVariant(int32(9))}
			seq := uint32(100)
			opts := &EncodeOptions{SecurityMode: mode, Keys: ks, NextNonceSequence: func() uint32 { seq++; return seq }}
			chunks, err := EncodeChunks(nm, opts, 300)
			require.NoError(t, err)
			require.Greater(t, len(chunks), 5)
			require.Equal(t, uint32(100+len(chunks)), seq, "one nonce per chunk")
			nonces := map[string]bool{}
			r := NewReassembler(nil)
			var payload []byte
			var last *message.NetworkMessage
			// Shuffled order.
			order := rand.New(rand.NewPCG(1, 2)).Perm(len(chunks))
			for n, i := range order {
				require.LessOrEqual(t, len(chunks[i]), 300)
				c, err := Decode(chunks[i], &DecodeOptions{Security: requireSecurity(mode, ks)})
				require.NoError(t, err)
				require.Equal(t, mode == ua.MessageSecurityModeSignAndEncrypt, c.Security.Encrypted)
				require.False(t, nonces[string(c.Security.MessageNonce)], "nonce reuse")
				nonces[string(c.Security.MessageNonce)] = true
				require.Equal(t, ts, c.Timestamp)
				require.Equal(t, int32(9), c.PromotedFields[0].Value())
				p, _, err := r.Add(c, time.Unix(1, 0))
				require.NoError(t, err)
				if n < len(order)-1 {
					require.Nil(t, p)
				}
				payload, last = p, c
			}
			dec, err := DecodeReassembled(last, payload, nil)
			require.NoError(t, err)
			require.Len(t, dec.Messages[0].Fields, 200)
			require.Equal(t, "value 199", dec.Messages[0].Fields[199].Value.Value.Value())
			require.NotNil(t, dec.Security)

			// A tampered chunk fails its own verification.
			bad := bytes.Clone(chunks[0])
			bad[len(bad)-40] ^= 1
			_, err = Decode(bad, &DecodeOptions{Security: requireSecurity(mode, ks)})
			require.ErrorIs(t, err, ErrSecurityChecksFailed)
		})
	}

	// Without NextNonceSequence the chunks take NonceSequence plus their
	// index.
	ks := zeroKeys(testPolicy{})
	nm := chunkNM()
	chunks, err := EncodeChunks(nm, &EncodeOptions{SecurityMode: ua.MessageSecurityModeSign, Keys: ks, NonceSequence: 40}, 25+6+8+32+4)
	require.NoError(t, err)
	require.Len(t, chunks, 3)
	for i, c := range chunks {
		d, err := Decode(c, &DecodeOptions{Security: requireSecurity(ua.MessageSecurityModeSign, ks)})
		require.NoError(t, err)
		require.Equal(t, []byte{byte(40 + i), 0, 0, 0}, d.Security.MessageNonce[4:])
	}
}

func TestChunkDiscovery(t *testing.T) {
	md := &ua.DataSetMetaDataType{Name: "a long DataSetMetaData name to need several chunks"}
	nm := &message.NetworkMessage{
		Type:        message.NetworkMessageDiscoveryResponse,
		UADPMask:    ua.UADPNetworkMessageContentMaskPublisherID,
		PublisherID: message.StringPublisherID("pub"),
		Discovery:   &message.Discovery{Type: message.DiscoveryDataSetMetaData, SequenceNumber: 3, DataSetWriterID: 2, MetaData: md},
	}
	chunks, err := EncodeChunks(nm, nil, 40)
	require.NoError(t, err)
	require.Greater(t, len(chunks), 3)
	r := NewReassembler(nil)
	var payload []byte
	var last *message.NetworkMessage
	for _, b := range chunks {
		c, err := Decode(b, nil)
		require.NoError(t, err)
		require.Equal(t, uint16(3), c.Chunk.MessageSequenceNumber)
		require.Empty(t, c.Messages)
		payload, _, err = r.Add(c, time.Time{})
		require.NoError(t, err)
		last = c
	}
	dec, err := DecodeReassembled(last, payload, nil)
	require.NoError(t, err)
	require.Equal(t, md.Name, dec.Discovery.MetaData.Name)
	require.Equal(t, message.PublisherIDString, dec.PublisherID.Type)
}

func TestChunkEncodeErrors(t *testing.T) {
	_, err := EncodeChunks(nil, nil, 100)
	require.ErrorIs(t, err, ErrMalformed)
	nm := chunkNM()
	nm.Messages = append(nm.Messages, nm.Messages[0])
	_, err = EncodeChunks(nm, nil, 100)
	require.ErrorIs(t, err, ErrMalformed, "two DataSetMessages")
	_, err = EncodeChunks(chunkNM(), nil, 25)
	require.ErrorIs(t, err, ErrMalformed, "no room for data")
	_, err = EncodeChunks(&message.NetworkMessage{Type: message.NetworkMessageDiscoveryRequest, Request: &message.DiscoveryRequest{}}, nil, 100)
	require.ErrorIs(t, err, ErrMalformed, "probes are not chunked")
	_, err = EncodeChunks(&message.NetworkMessage{Type: message.NetworkMessageDiscoveryResponse}, nil, 100)
	require.ErrorIs(t, err, ErrMalformed)
	_, err = EncodeChunks(&message.NetworkMessage{Type: message.NetworkMessageDiscoveryResponse, Discovery: &message.Discovery{Type: 9}}, nil, 100)
	require.ErrorIs(t, err, ErrUnsupported)
	c := chunkNM()
	c.Chunk = &message.Chunk{}
	_, err = EncodeChunks(c, nil, 100)
	require.ErrorIs(t, err, ErrMalformed, "already a chunk")
	bad := chunkNM()
	bad.Messages[0].FieldEncoding = 7
	_, err = EncodeChunks(bad, nil, 100)
	require.ErrorIs(t, err, ErrMalformed)
	_, err = EncodeChunks(chunkNM(), &EncodeOptions{SecurityMode: ua.MessageSecurityModeSign}, 100)
	require.ErrorIs(t, err, ErrSecurityChecksFailed)
	_, err = EncodeChunks(chunkNM(), &EncodeOptions{SecurityMode: ua.MessageSecurityModeSign, Keys: &testKeys{}}, 100)
	require.ErrorIs(t, err, ErrSecurityChecksFailed)
	pf := chunkNM()
	pf.UADPMask |= ua.UADPNetworkMessageContentMaskPromotedFields
	pf.PromotedFields = []*ua.Variant{{}}
	pf.PublisherID.Type = 9
	_, err = EncodeChunks(pf, nil, 100)
	require.ErrorIs(t, err, ErrMalformed)

	// Encode of a single chunk.
	c = chunkNM()
	c.Chunk = &message.Chunk{TotalSize: 1, Data: []byte{1}}
	c.Messages = nil
	_, err = Encode(c, nil)
	require.ErrorIs(t, err, ErrMalformed, "chunk with PayloadHeader without writer")
	c.Type = message.NetworkMessageDiscoveryRequest
	_, err = Encode(c, nil)
	require.ErrorIs(t, err, ErrMalformed, "chunk of a probe")
	c.Type = message.NetworkMessageDiscoveryResponse
	_, err = Encode(c, nil)
	require.NoError(t, err)

	_, err = DecodeReassembled(nil, nil, nil)
	require.ErrorIs(t, err, ErrMalformed)
	_, err = DecodeReassembled(&message.NetworkMessage{Type: message.NetworkMessageDiscoveryRequest, Chunk: &message.Chunk{}}, nil, nil)
	require.ErrorIs(t, err, ErrMalformed)
	_, err = DecodeReassembled(&message.NetworkMessage{Chunk: &message.Chunk{}}, []byte{0x01, 0x07}, nil)
	require.ErrorIs(t, err, ErrMalformed)
	_, err = DecodeReassembled(&message.NetworkMessage{Type: message.NetworkMessageDiscoveryResponse, Chunk: &message.Chunk{}}, []byte{2}, nil)
	require.ErrorIs(t, err, ErrMalformed)
}

func TestChunkDecodeMalformed(t *testing.T) {
	const hdr = "91 80 01 01 "
	for _, tc := range []struct{ name, hex string }{
		{"truncated", hdr + "0500 00000000"},
		{"no data", hdr + "0500 00000000 0a000000 00000000"},
		{"null data", hdr + "0500 00000000 0a000000 ffffffff"},
		{"data beyond the message", hdr + "0500 00000000 0a000000 05000000 0102"},
		{"trailing bytes", hdr + "0500 00000000 0a000000 01000000 0102"},
		{"total size 0", hdr + "0500 00000000 00000000 01000000 01"},
		{"beyond the total size", hdr + "0500 0a000000 0a000000 01000000 01"},
		{"offset overflow", hdr + "0500 ffffffff ffffffff 02000000 0102"},
		{"truncated chunk writer id", "f1 80 01 01 09 0a00 0700 14"},
	} {
		_, err := Decode(h(t, tc.hex), nil)
		require.ErrorIs(t, err, ErrMalformed, tc.name)
	}
	nm, err := Decode(h(t, hdr+"0500 09000000 0a000000 01000000 01"), nil)
	require.NoError(t, err)
	require.Equal(t, &message.Chunk{MessageSequenceNumber: 5, ChunkOffset: 9, TotalSize: 10, Data: []byte{1}}, nm.Chunk)
}

// chunk returns a decoded chunk NetworkMessage of publisher pub.
func chunk(pub uint64, seq uint16, off, total uint32, data []byte) *message.NetworkMessage {
	return &message.NetworkMessage{
		UADPMask:    chunkMask,
		PublisherID: message.NewPublisherID(message.PublisherIDUInt16, pub),
		GroupHeader: message.GroupHeader{WriterGroupID: 1},
		Messages:    []*message.DataSetMessage{{DataSetWriterID: 2}},
		Chunk:       &message.Chunk{MessageSequenceNumber: seq, ChunkOffset: off, TotalSize: total, Data: data},
	}
}

func TestReassemblerLayout(t *testing.T) {
	now := time.Unix(100, 0)
	data := []byte("0123456789")
	add := func(r *Reassembler, off, n int) ([]byte, error) {
		p, _, err := r.Add(chunk(1, 1, uint32(off), 10, data[off:off+n]), now)
		return p, err
	}

	t.Run("single chunk", func(t *testing.T) {
		r := NewReassembler(nil)
		p, err := add(r, 0, 10)
		require.NoError(t, err)
		require.Equal(t, data, p)
		require.Zero(t, r.Stats().Pending)
	})
	t.Run("in order and interleaved", func(t *testing.T) {
		r := NewReassembler(nil)
		for i := 0; i < 8; i += 4 {
			p, err := add(r, i, 4)
			require.NoError(t, err)
			require.Nil(t, p)
			// Another message of the same writer in between.
			_, _, err = r.Add(chunk(1, 2, uint32(i), 10, data[i:i+4]), now)
			require.NoError(t, err)
		}
		p, err := add(r, 8, 2)
		require.NoError(t, err)
		require.Equal(t, data, p)
		require.Equal(t, 1, r.Stats().Pending)
	})
	t.Run("last chunk first", func(t *testing.T) {
		r := NewReassembler(nil)
		_, err := add(r, 8, 2)
		require.NoError(t, err)
		_, err = add(r, 8, 2)
		require.ErrorIs(t, err, ErrChunkRejected, "duplicate last chunk")
		_, err = add(r, 0, 3)
		require.ErrorIs(t, err, ErrChunkRejected, "does not fit the last chunk")
		_, err = add(r, 4, 4)
		require.NoError(t, err)
		p, err := add(r, 0, 4)
		require.NoError(t, err)
		require.Equal(t, data, p)
	})
	t.Run("rejections", func(t *testing.T) {
		r := NewReassembler(&ReassemblerOptions{MaxChunks: 4})
		_, err := add(r, 0, 4)
		require.NoError(t, err)
		for name, c := range map[string][2]int{
			"duplicate":           {0, 4},
			"overlap":             {2, 4},
			"other size":          {4, 3},
			"last at wrong place": {7, 3},
		} {
			_, err := add(r, c[0], c[1])
			require.ErrorIs(t, err, ErrChunkRejected, name)
		}
		_, _, err = r.Add(chunk(1, 1, 4, 11, data[:4]), now)
		require.ErrorIs(t, err, ErrChunkRejected, "other total size")
		_, _, err = r.Add(chunk(1, 9, 0, 10, data[:1]), now)
		require.ErrorIs(t, err, ErrChunkRejected, "too many chunks")
		_, _, err = r.Add(chunk(1, 9, 1, 10, data[:2]), now)
		require.ErrorIs(t, err, ErrChunkRejected, "misaligned")
		_, _, err = r.Add(chunk(1, 9, 0, 10, nil), now)
		require.ErrorIs(t, err, ErrChunkRejected, "empty")
		_, _, err = r.Add(chunk(1, 9, 0, 0, data), now)
		require.ErrorIs(t, err, ErrChunkRejected, "total 0")
		_, _, err = r.Add(chunk(1, 9, 8, 10, data[:4]), now)
		require.ErrorIs(t, err, ErrChunkRejected, "beyond the total")
		_, _, err = r.Add(chunk(1, 9, 0, DefaultMaxReassembledSize+1, data[:4]), now)
		require.ErrorIs(t, err, ErrChunkRejected, "too large")
		_, _, err = r.Add(&message.NetworkMessage{}, now)
		require.ErrorIs(t, err, ErrChunkRejected, "no chunk")
		_, _, err = r.Add(nil, now)
		require.ErrorIs(t, err, ErrChunkRejected)
		st := r.Stats()
		require.Equal(t, uint64(13), st.Rejected)
		require.Equal(t, 1, st.Pending)
		require.Equal(t, 4+chunkOverhead, st.PendingBytes)
		// The pending message completes despite the rejections.
		_, err = add(r, 4, 4)
		require.NoError(t, err)
		p, err := add(r, 8, 2)
		require.NoError(t, err)
		require.Equal(t, data, p)
	})
}

func TestReassemblerKeys(t *testing.T) {
	r := NewReassembler(nil)
	now := time.Time{}
	base := chunk(1, 1, 0, 2, []byte{1})
	variants := []func(*message.NetworkMessage){
		func(*message.NetworkMessage) {},
		func(m *message.NetworkMessage) { m.PublisherID.Num = 2 },
		func(m *message.NetworkMessage) { m.PublisherID.Type = message.PublisherIDUInt32 },
		func(m *message.NetworkMessage) { m.GroupHeader.WriterGroupID = 2 },
		func(m *message.NetworkMessage) { m.Messages[0].DataSetWriterID = 3 },
		func(m *message.NetworkMessage) { m.Chunk.MessageSequenceNumber = 2 },
		func(m *message.NetworkMessage) { m.Type = message.NetworkMessageDiscoveryResponse },
		func(m *message.NetworkMessage) { m.Security = &message.SecurityHeader{Signed: true} },
		func(m *message.NetworkMessage) { m.UADPMask &^= ua.UADPNetworkMessageContentMaskPublisherID },
		// Action messages: the requests of two Requestors to one writer,
		// and the responses to them, do not mix.
		func(m *message.NetworkMessage) { m.Action = &message.ActionHeader{Type: message.ActionRequest} },
		func(m *message.NetworkMessage) { m.Action = &message.ActionHeader{Type: message.ActionResponse} },
		func(m *message.NetworkMessage) {
			m.Action = &message.ActionHeader{Type: message.ActionRequest, CorrelationData: []byte{1}}
		},
		func(m *message.NetworkMessage) {
			r := message.StringPublisherID("r")
			m.Action = &message.ActionHeader{Type: message.ActionRequest, RequestorID: &r}
		},
	}
	for _, v := range variants {
		m := *base
		m.Messages = []*message.DataSetMessage{{DataSetWriterID: 2}}
		c := *base.Chunk
		m.Chunk = &c
		v(&m)
		_, _, err := r.Add(&m, now)
		require.NoError(t, err)
	}
	require.Equal(t, len(variants), r.Stats().Pending, "every variant is a message of its own")
	r.Reset()
	require.Zero(t, r.Stats().Pending)
	require.Zero(t, r.Stats().PendingBytes)
}

func TestReassemblerLimits(t *testing.T) {
	t0 := time.Unix(100, 0)
	t.Run("timeout", func(t *testing.T) {
		r := NewReassembler(&ReassemblerOptions{Timeout: time.Second})
		_, _, err := r.Add(chunk(1, 1, 0, 4, []byte{1, 2}), t0)
		require.NoError(t, err)
		_, _, err = r.Add(chunk(1, 2, 0, 4, []byte{1, 2}), t0.Add(500*time.Millisecond))
		require.NoError(t, err)
		// The first one expires, the second is still waiting.
		_, dropped, err := r.Add(chunk(1, 3, 0, 4, []byte{1, 2}), t0.Add(time.Second))
		require.NoError(t, err)
		require.Equal(t, 1, dropped)
		// Its last chunk starts a new message.
		_, _, err = r.Add(chunk(1, 1, 2, 4, []byte{3, 4}), t0.Add(time.Second))
		require.NoError(t, err)
		require.Equal(t, 1, r.Expire(t0.Add(1600*time.Millisecond)))
		require.Equal(t, 0, r.Expire(t0.Add(1600*time.Millisecond)))
		st := r.Stats()
		require.Equal(t, uint64(2), st.Expired)
		require.Equal(t, uint64(2), st.Dropped)
		require.Equal(t, 2, st.Pending)
		require.Equal(t, 2, r.Expire(t0.Add(time.Hour)))
		require.Zero(t, r.Stats().PendingBytes)
	})
	t.Run("per publisher", func(t *testing.T) {
		r := NewReassembler(&ReassemblerOptions{MaxMessageSize: 100, MaxChunks: 10, MaxPublisherMessages: 2})
		for seq := range uint16(3) {
			_, _, err := r.Add(chunk(1, seq, 0, 100, make([]byte, 10)), t0.Add(time.Duration(seq)))
			require.NoError(t, err)
		}
		// A third message of publisher 1 evicted its oldest one, other
		// publishers are not affected.
		_, _, err := r.Add(chunk(2, 0, 0, 100, make([]byte, 10)), t0)
		require.NoError(t, err)
		st := r.Stats()
		require.Equal(t, 3, st.Pending)
		require.Equal(t, uint64(1), st.Evicted)
		_, _, err = r.Add(chunk(1, 0, 10, 100, make([]byte, 10)), t0)
		require.NoError(t, err, "a new message")
		require.Equal(t, uint64(2), r.Stats().Evicted)
	})
	t.Run("publisher bytes", func(t *testing.T) {
		// 9 chunks of 10 bytes are charged 9*(10+64) = 666 bytes: two
		// incomplete messages fit, the first chunk of a third does not.
		r := NewReassembler(&ReassemblerOptions{MaxMessageSize: 100, MaxChunks: 10, MaxPublisherBytes: 1400})
		for off := uint32(0); off < 90; off += 10 {
			_, _, err := r.Add(chunk(1, 1, off, 100, make([]byte, 10)), t0)
			require.NoError(t, err)
		}
		_, dropped, err := r.Add(chunk(1, 2, 0, 100, make([]byte, 10)), t0)
		require.NoError(t, err)
		require.Zero(t, dropped, "both fit")
		for off := uint32(10); off < 90; off += 10 {
			_, _, err := r.Add(chunk(1, 2, off, 100, make([]byte, 10)), t0)
			require.NoError(t, err)
		}
		_, dropped, err = r.Add(chunk(1, 3, 0, 100, make([]byte, 10)), t0)
		require.NoError(t, err)
		require.Equal(t, 9, dropped, "the oldest message made room")
		require.Equal(t, 2, r.Stats().Pending)
	})
	t.Run("global", func(t *testing.T) {
		r := NewReassembler(&ReassemblerOptions{MaxMessageSize: 100, MaxChunks: 10, MaxPendingMessages: 3, MaxPublisherMessages: 3})
		for pub := range uint64(10) {
			_, _, err := r.Add(chunk(pub, 1, 0, 100, make([]byte, 10)), t0.Add(time.Duration(pub)))
			require.NoError(t, err)
		}
		st := r.Stats()
		require.Equal(t, 3, st.Pending)
		require.Equal(t, uint64(7), st.Evicted)
		// The newest ones survived.
		_, _, err := r.Add(chunk(9, 1, 10, 100, make([]byte, 10)), t0)
		require.NoError(t, err)
		require.Equal(t, uint64(7), r.Stats().Evicted)
	})
	t.Run("no room", func(t *testing.T) {
		// A single message larger than the limits cannot be made room
		// for: the limits are raised to fit one.
		o := (&ReassemblerOptions{MaxMessageSize: 100, MaxChunks: 10, MaxPendingBytes: 1, MaxPublisherBytes: 1}).normalize()
		require.Equal(t, 100+10*chunkOverhead, o.MaxPublisherBytes)
		require.Equal(t, o.MaxPublisherBytes, o.MaxPendingBytes)
		r := NewReassembler(&ReassemblerOptions{MaxMessageSize: 100, MaxChunks: 100, MaxPublisherBytes: 1})
		for off := uint32(0); off < 99; off++ {
			_, _, err := r.Add(chunk(1, 1, off, 100, []byte{1}), t0)
			require.NoError(t, err)
		}
		p, _, err := r.Add(chunk(1, 1, 99, 100, []byte{1}), t0)
		require.NoError(t, err)
		require.Len(t, p, 100)
		// A message of a publisher at its limit with nothing to evict.
		r = NewReassembler(&ReassemblerOptions{MaxMessageSize: 4, MaxChunks: 4, MaxPublisherMessages: 1, MaxPendingMessages: 1})
		_, _, err = r.Add(chunk(1, 1, 0, 4, []byte{1}), t0)
		require.NoError(t, err)
		require.Equal(t, 1, r.opts.MaxPendingMessages)
	})
}

func TestReassemblerConcurrent(t *testing.T) {
	r := NewReassembler(nil)
	payload := bytes.Repeat([]byte("abcdefgh"), 64)
	var wg sync.WaitGroup
	for w := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for seq := range uint16(20) {
				var got []byte
				for off := 0; off < len(payload); off += 50 {
					end := min(off+50, len(payload))
					p, _, err := r.Add(chunk(uint64(w), seq, uint32(off), uint32(len(payload)), payload[off:end]), time.Time{})
					if err != nil {
						t.Error(err)
						return
					}
					if p != nil {
						got = p
					}
				}
				if !bytes.Equal(got, payload) {
					t.Error("payload mismatch")
					return
				}
			}
		}()
	}
	wg.Wait()
	st := r.Stats()
	require.Equal(t, uint64(160), st.Completed)
	require.Zero(t, st.Pending)
}
