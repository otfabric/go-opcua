// SPDX-License-Identifier: MIT

package websocket

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadMessage(t *testing.T) {
	var in []byte
	in = append(in, frame(0x80|opText, []byte(`{"a":1}`), key)...)
	// A fragmented binary message with a ping in between.
	in = append(in, frame(opBinary, []byte("ab"), key)...)
	in = append(in, frame(0x80|opPing, []byte("p"), key)...)
	in = append(in, frame(opContinuation, nil, key)...)
	in = append(in, frame(0x80|opContinuation, []byte("cd"), key)...)
	// An empty text message.
	in = append(in, frame(0x80|opText, nil, key)...)
	in = append(in, frame(0x80|opClose, binary.BigEndian.AppendUint16(nil, CloseNormal), key)...)
	c, mc := serverReading(in, 0)

	msg, err := c.ReadMessage(1 << 10)
	require.NoError(t, err)
	require.Equal(t, `{"a":1}`, string(msg))
	msg, err = c.ReadMessage(1 << 10)
	require.NoError(t, err)
	require.Equal(t, "abcd", string(msg))
	msg, err = c.ReadMessage(1 << 10)
	require.NoError(t, err)
	require.Empty(t, msg)
	_, err = c.ReadMessage(1 << 10)
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, CloseNormal, c.CloseCode())
	_, err = c.ReadMessage(1 << 10)
	require.ErrorIs(t, err, io.EOF, "the end is sticky")

	// The ping was answered, the Close frame too.
	w := mc.written()
	require.Equal(t, byte(0x80|opPong), w[0])
	require.Equal(t, CloseNormal, closeCode(t, w[3:]))
}

func TestReadMessageTooLarge(t *testing.T) {
	for name, in := range map[string][]byte{
		"one frame": frame(0x80|opText, bytes.Repeat([]byte("x"), 11), key),
		"fragments": append(frame(opText, bytes.Repeat([]byte("x"), 6), key), frame(0x80|opContinuation, bytes.Repeat([]byte("x"), 6), key)...),
	} {
		t.Run(name, func(t *testing.T) {
			c, mc := serverReading(in, 0)
			_, err := c.ReadMessage(10)
			require.ErrorIs(t, err, ErrMessageTooLarge)
			require.Equal(t, CloseMessageTooBig, closeCode(t, mc.written()))
			_, err = c.ReadMessage(10)
			require.ErrorIs(t, err, ErrMessageTooLarge)
		})
	}
}

func TestReadMessageInvalid(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		err  error
		code int
	}{
		{"invalid UTF-8", frame(0x80|opText, []byte{0xff, 0xfe}, key), ErrInvalidUTF8, CloseInvalidPayload},
		{"text inside binary", append(frame(opBinary, []byte("a"), key), frame(0x80|opText, []byte("b"), key)...), ErrProtocol, CloseProtocolError},
		{"unmasked", frame(0x80|opText, []byte("a"), nil), ErrProtocol, CloseProtocolError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, mc := serverReading(tt.in, 0)
			_, err := c.ReadMessage(1 << 10)
			require.ErrorIs(t, err, tt.err)
			require.Equal(t, tt.code, closeCode(t, mc.written()))
		})
	}
}

func TestReadMessageTruncated(t *testing.T) {
	in := frame(0x80|opText, []byte("hello"), key)
	c, _ := serverReading(in[:len(in)-2], 0)
	_, err := c.ReadMessage(1 << 10)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestReadRejectsTextStillWithoutMessages(t *testing.T) {
	c, mc := serverReading(frame(0x80|opText, []byte("a"), key), 0)
	_, err := c.Read(make([]byte, 4))
	require.ErrorIs(t, err, ErrUnsupportedData)
	require.Equal(t, CloseUnsupportedData, closeCode(t, mc.written()))
}

func TestWriteText(t *testing.T) {
	mc := &memConn{r: bytes.NewReader(nil)}
	c := newConn(mc, bufio.NewReader(mc), true, "opcua+uajson", 0)
	require.NoError(t, c.WriteText([]byte(`{"x":true}`)))

	// The server side reads it back.
	s, _ := serverReading(mc.written(), 0)
	msg, err := s.ReadMessage(1 << 10)
	require.NoError(t, err)
	require.Equal(t, `{"x":true}`, string(msg))
	require.True(t, s.text)

	require.NoError(t, c.Close())
	require.ErrorIs(t, c.WriteText([]byte("late")), net.ErrClosed)
}
