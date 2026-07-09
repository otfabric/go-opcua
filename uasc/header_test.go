// SPDX-License-Identifier: MIT

package uasc

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHeader(t *testing.T) {
	cases := []CodecTestCase{
		{
			Name: "normal",
			Struct: &Header{
				MessageType:     MessageTypeMessage,
				ChunkType:       ChunkTypeFinal,
				MessageSize:     12,
				SecureChannelID: 0,
			},
			Bytes: []byte{ // Message message
				// MessageType: MSG
				0x4d, 0x53, 0x47,
				// Chunk Type: Final
				0x46,
				// MessageSize: 12
				0x0c, 0x00, 0x00, 0x00,
				// SecureChannelID: 0
				0x00, 0x00, 0x00, 0x00,
			},
		},
	}
	RunCodecTest(t, cases)
}

func TestHeaderString(t *testing.T) {
	h := NewHeader(MessageTypeMessage, ChunkTypeFinal, 42)
	require.Contains(t, h.String(), "MSG")
	require.Contains(t, h.String(), "SecureChannelID: 42")
}
