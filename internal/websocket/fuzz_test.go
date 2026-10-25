// SPDX-License-Identifier: MIT

package websocket

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

// FuzzRead feeds arbitrary bytes to the frame reader of a server. It must
// never panic, never return more bytes than the frames carry and always end
// with an error once the input is exhausted.
func FuzzRead(f *testing.F) {
	f.Add(frame(0x80|opBinary, []byte("hello"), key))
	f.Add(append(frame(opBinary, []byte("a"), key), frame(0x80|opContinuation, []byte("b"), key)...))
	f.Add(frame(0x80|opPing, []byte("p"), key))
	f.Add(frame(0x80|opClose, binary.BigEndian.AppendUint16(nil, 1000), key))
	f.Add(frame(0x80|opBinary, bytes.Repeat([]byte{1}, 300), key))
	f.Add([]byte{0x82, 0xff, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		c, _ := serverReading(data, 1<<16)
		got, _ := io.ReadAll(c)
		if len(got) > len(data) {
			t.Fatalf("read %d bytes from %d bytes of input", len(got), len(data))
		}
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Fatal("read after the end of the input succeeded")
		}
	})
}

// FuzzAccept feeds arbitrary bytes to the server side of the opening
// handshake.
func FuzzAccept(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: AQIDBAUGBwgJCgsMDQ4PEA==\r\nSec-WebSocket-Protocol: opcua+uacp\r\n\r\n"))
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Add([]byte("\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		mc := &memConn{r: bytes.NewReader(data)}
		c, _, err := Accept(mc, ServerOptions{Subprotocols: []string{"opcua+uacp"}})
		if err != nil {
			return
		}
		if c.Subprotocol() != "opcua+uacp" {
			t.Fatalf("accepted sub-protocol %q", c.Subprotocol())
		}
		_, _ = io.ReadAll(c)
	})
}

// FuzzReadMessage feeds arbitrary bytes to the message reader of a server
// (the opcua+uajson sub-protocol). It must never panic, never return a
// message larger than the limit or than the input, and always end with an
// error once the input is exhausted.
func FuzzReadMessage(f *testing.F) {
	f.Add(frame(0x80|opText, []byte(`{"UaTypeId":"i=631"}`), key))
	f.Add(append(frame(opText, []byte("a"), key), frame(0x80|opContinuation, []byte("b"), key)...))
	f.Add(frame(0x80|opText, []byte{0xff}, key))
	f.Add(frame(0x80|opBinary, bytes.Repeat([]byte{1}, 300), key))
	f.Add(frame(0x80|opClose, binary.BigEndian.AppendUint16(nil, 1000), key))
	f.Add([]byte{})
	const limit = 1 << 12
	f.Fuzz(func(t *testing.T, data []byte) {
		c, _ := serverReading(data, 1<<16)
		total := 0
		for {
			msg, err := c.ReadMessage(limit)
			if err != nil {
				break
			}
			if len(msg) > limit {
				t.Fatalf("message of %d bytes, limit %d", len(msg), limit)
			}
			total += len(msg)
			if total > len(data) {
				t.Fatalf("read %d bytes from %d bytes of input", total, len(data))
			}
		}
		if _, err := c.ReadMessage(limit); err == nil {
			t.Fatal("read after the end of the input succeeded")
		}
	})
}
