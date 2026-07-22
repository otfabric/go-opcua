// SPDX-License-Identifier: MIT

package uacp

import (
	"testing"
)

func FuzzHeaderDecode(f *testing.F) {
	f.Add([]byte{'H', 'E', 'L', 'F', 0x08, 0x00, 0x00, 0x00})
	f.Add([]byte{'A', 'C', 'K', 'F', 0x1c, 0x00, 0x00, 0x00})
	f.Add([]byte{'E', 'R', 'R', 'F'})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		h := new(Header)
		n, err := h.Decode(data)
		if err != nil {
			return
		}
		if n > len(data) {
			t.Fatalf("Header.Decode consumed %d bytes but input was %d", n, len(data))
		}
	})
}

func FuzzHelloDecode(f *testing.F) {
	f.Add([]byte{
		0x00, 0x00, 0x00, 0x00, // Version
		0x00, 0x00, 0x01, 0x00, // ReceiveBufSize
		0x00, 0x00, 0x01, 0x00, // SendBufSize
		0x00, 0x00, 0x00, 0x00, // MaxMessageSize
		0x00, 0x00, 0x00, 0x00, // MaxChunkCount
		0x00, 0x00, 0x00, 0x00, // EndpointURL length 0
	})
	f.Add([]byte{0xff, 0xff, 0xff, 0x7f})
	f.Fuzz(func(t *testing.T, data []byte) {
		h := new(Hello)
		n, err := h.Decode(data)
		if err != nil {
			return
		}
		if n > len(data) {
			t.Fatalf("Hello.Decode consumed %d bytes but input was %d", n, len(data))
		}
	})
}
