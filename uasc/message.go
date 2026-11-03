// SPDX-License-Identifier: MIT

package uasc

import (
	"fmt"
	"log/slog"
	"math"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
)

type MessageHeader struct {
	*Header
	*AsymmetricSecurityHeader
	*SymmetricSecurityHeader
	*SequenceHeader
}

func (m *MessageHeader) Decode(b []byte) (int, error) {
	buf := ua.NewBuffer(b)

	m.Header = new(Header)
	buf.ReadStruct(m.Header)

	switch m.MessageType {
	case "OPN":
		m.AsymmetricSecurityHeader = new(AsymmetricSecurityHeader)
		buf.ReadStruct(m.AsymmetricSecurityHeader)

	case "MSG", "CLO":
		m.SymmetricSecurityHeader = new(SymmetricSecurityHeader)
		buf.ReadStruct(m.SymmetricSecurityHeader)

	default:
		return buf.Pos(), fmt.Errorf("%w: %q", errors.ErrInvalidMessageType, m.MessageType)
	}

	// Sequence header could be encrypted, defer decoding until after decryption
	m.SequenceHeader = new(SequenceHeader)
	//buf.ReadStruct(m.SequenceHeader)

	return buf.Pos(), buf.Error()
}

type MessageChunk struct {
	*MessageHeader
	Data []byte
}

func (m *MessageChunk) Decode(b []byte) (int, error) {
	m.MessageHeader = new(MessageHeader)
	n, err := m.MessageHeader.Decode(b)
	if err != nil {
		return n, err
	}
	m.Data = b[n:]
	return len(b), nil
}

// MessageAbort represents a non-terminal OPC UA Secure Channel error.
//
// Specification: Part6, 7.3.
type MessageAbort struct {
	ErrorCode uint32
	Reason    string
}

func (m *MessageAbort) Decode(b []byte) (int, error) {
	buf := ua.NewBuffer(b)
	m.ErrorCode = buf.ReadUint32()
	m.Reason = buf.ReadString()
	return buf.Pos(), buf.Error()
}

func (m *MessageAbort) Encode() ([]byte, error) {
	buf := ua.NewBuffer(nil)
	buf.WriteUint32(m.ErrorCode)
	buf.WriteString(m.Reason)
	return buf.Bytes(), buf.Error()
}

func (m *MessageAbort) MessageAbort() string {
	return ua.StatusCode(m.ErrorCode).Error()
}

// encodeAbort returns the abort chunk of m (Part 6 §6.7.3): a final chunk of
// type 'A' that tells the receiver to discard the message, with code and
// reason as its body. m keeps its headers and sequence number.
func (m *Message) encodeAbort(code ua.StatusCode, reason string) ([]byte, error) {
	body, err := (&MessageAbort{ErrorCode: uint32(code), Reason: reason}).Encode()
	if err != nil {
		return nil, err
	}
	size, err := messageSize(symmetricChunkHeaderSize, len(body))
	if err != nil {
		return nil, err
	}
	m.MessageSize = size
	m.ChunkType = ChunkTypeError
	chunk := ua.NewBuffer(nil)
	chunk.WriteStruct(m.Header)
	chunk.WriteStruct(m.SymmetricSecurityHeader)
	chunk.WriteStruct(m.SequenceHeader)
	chunk.Write(body)
	return chunk.Bytes(), chunk.Error()
}

// Message represents a OPC UA Secure Conversation message.
type Message struct {
	*MessageHeader
	TypeID  *ua.ExpandedNodeID
	Service interface{}
}

func (m *Message) Decode(b []byte) (int, error) {
	m.MessageHeader = new(MessageHeader)
	var pos int
	n, err := m.MessageHeader.Decode(b)
	if err != nil {
		return n, err
	}
	pos += n

	m.SequenceHeader = new(SequenceHeader)
	n, err = m.SequenceHeader.Decode(b[pos:])
	if err != nil {
		return n, err
	}
	pos += n

	m.TypeID, m.Service, err = ua.DecodeService(b[pos:])
	return len(b), err
}

func (m *Message) Encode() ([]byte, error) {
	chunks, err := m.EncodeChunks(math.MaxUint32)
	if err != nil {
		return nil, err
	}
	return chunks[0], nil
}

// symmetricChunkHeaderSize is the size of the message header, the symmetric
// security header and the sequence header of a MSG or CLO chunk (Part 6
// §6.7.2.2 to §6.7.2.4).
const symmetricChunkHeaderSize = 24

// messageSize returns the MessageSize of a chunk with headerSize bytes of
// headers and bodySize bytes of body. The MessageSize field is a UInt32
// (Part 6 §6.7.2.2): a chunk that does not fit in it cannot be sent.
func messageSize(headerSize, bodySize int) (uint32, error) {
	if headerSize < 0 || bodySize < 0 || uint64(headerSize)+uint64(bodySize) > math.MaxUint32 {
		return 0, fmt.Errorf("%w: %d bytes of body", errors.ErrMessageTooLarge, bodySize)
	}
	return uint32(headerSize + bodySize), nil
}

// checkPeerLimits returns ErrMessageTooLarge if a message body of bodySize
// bytes in chunks chunks exceeds the MaxMessageSize or MaxChunkCount the
// peer announced (Part 6 §7.1.2.3, §7.1.2.4). The size is that of the
// unencrypted body; zero means no limit.
func checkPeerLimits(bodySize int, chunks, maxMessageSize, maxChunkCount uint32) error {
	if maxMessageSize > 0 && int64(bodySize) > int64(maxMessageSize) {
		return fmt.Errorf("%w: %d bytes > %d the peer accepts", errors.ErrMessageTooLarge, bodySize, maxMessageSize)
	}
	if maxChunkCount > 0 && chunks > maxChunkCount {
		return fmt.Errorf("%w: %d chunks > %d the peer accepts", errors.ErrMessageTooLarge, chunks, maxChunkCount)
	}
	return nil
}

func (m *Message) EncodeChunks(maxBodySize uint32) ([][]byte, error) {
	return m.encodeChunks(maxBodySize, 0, 0)
}

// encodeChunks is EncodeChunks for a peer that accepts messages of at most
// maxMessageSize bytes in at most maxChunkCount chunks; zero means no limit.
// The limits apply to MSG and CLO messages: an OPN is a single chunk.
func (m *Message) encodeChunks(maxBodySize, maxMessageSize, maxChunkCount uint32) ([][]byte, error) {
	dataBody := ua.NewBuffer(nil)
	dataBody.WriteStruct(m.TypeID)
	dataBody.WriteStruct(m.Service)

	if dataBody.Error() != nil {
		return nil, dataBody.Error()
	}

	// maxBodySize can be 0 if the channel instance is not yet fully negotiated
	// (e.g. during OPN exchange). Default to 4096 to avoid division by zero.
	if maxBodySize == 0 {
		slog.Default().Warn("maxBodySize == 0, defaulting to 4096")
		maxBodySize = 1 << 12
	}

	// The final chunk carries the 24 bytes of the message, symmetric
	// security and sequence headers; the asymmetric header of an OPN is
	// checked below.
	bodySize, err := messageSize(symmetricChunkHeaderSize, dataBody.Len())
	if err != nil {
		return nil, err
	}
	nrChunks := (bodySize-symmetricChunkHeaderSize)/maxBodySize + 1
	chunks := make([][]byte, nrChunks)

	switch m.MessageType {
	case "OPN":
		partialHeader := ua.NewBuffer(nil)
		partialHeader.WriteStruct(m.AsymmetricSecurityHeader)
		partialHeader.WriteStruct(m.SequenceHeader)

		if partialHeader.Error() != nil {
			return nil, partialHeader.Error()
		}

		size, err := messageSize(12+partialHeader.Len(), dataBody.Len())
		if err != nil {
			return nil, err
		}
		m.MessageSize = size
		buf := ua.NewBuffer(nil)
		buf.WriteStruct(m.Header)
		buf.Write(partialHeader.Bytes())
		buf.Write(dataBody.Bytes())

		return [][]byte{buf.Bytes()}, buf.Error()

	case "CLO", "MSG":
		if err := checkPeerLimits(dataBody.Len(), nrChunks, maxMessageSize, maxChunkCount); err != nil {
			return nil, err
		}

		for i := uint32(0); i < nrChunks-1; i++ {
			m.MessageSize = maxBodySize + 24
			m.ChunkType = ChunkTypeIntermediate
			chunk := ua.NewBuffer(nil)
			chunk.WriteStruct(m.Header)
			chunk.WriteStruct(m.SymmetricSecurityHeader)
			chunk.WriteStruct(m.SequenceHeader)
			chunk.Write(dataBody.ReadN(int(maxBodySize)))
			if chunk.Error() != nil {
				return nil, chunk.Error()
			}

			chunks[i] = chunk.Bytes()
		}

		m.ChunkType = ChunkTypeFinal
		size, err := messageSize(symmetricChunkHeaderSize, dataBody.Len())
		if err != nil {
			return nil, err
		}
		m.MessageSize = size
		chunk := ua.NewBuffer(nil)
		chunk.WriteStruct(m.Header)
		chunk.WriteStruct(m.SymmetricSecurityHeader)
		chunk.WriteStruct(m.SequenceHeader)
		chunk.Write(dataBody.Bytes())
		if chunk.Error() != nil {
			return nil, chunk.Error()
		}

		chunks[nrChunks-1] = chunk.Bytes()
		return chunks, nil
	default:
		return nil, fmt.Errorf("%w: %q", errors.ErrInvalidMessageType, m.MessageType)
	}
}
