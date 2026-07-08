// SPDX-License-Identifier: MIT

package uasc

import (
	"fmt"

	"github.com/otfabric/go-opcua/ua"
)

// SequenceHeader represents a Sequence Header in OPC UA Secure Conversation.
type SequenceHeader struct {
	SequenceNumber uint32
	RequestID      uint32
}

// NewSequenceHeader creates a new OPC UA Secure Conversation Sequence Header.
func NewSequenceHeader(seq, req uint32) *SequenceHeader {
	return &SequenceHeader{
		SequenceNumber: seq,
		RequestID:      req,
	}
}

func (h *SequenceHeader) Decode(b []byte) (int, error) {
	buf := ua.NewBuffer(b)
	h.SequenceNumber = buf.ReadUint32()
	h.RequestID = buf.ReadUint32()
	return buf.Pos(), buf.Error()
}

func (h *SequenceHeader) Encode() ([]byte, error) {
	buf := ua.NewBuffer(nil)
	buf.WriteUint32(h.SequenceNumber)
	buf.WriteUint32(h.RequestID)
	return buf.Bytes(), buf.Error()
}

// String returns Header in string.
func (h *SequenceHeader) String() string {
	return fmt.Sprintf(
		"SequenceNumber: %d, RequestID: %d",
		h.SequenceNumber,
		h.RequestID,
	)
}
