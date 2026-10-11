// SPDX-License-Identifier: MIT

package uacp

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// TestHandshake_AcknowledgeCannotRaiseBufferSizes: a server answers the Hello
// with buffer sizes above the ones the client offered and then sends a
// message of that size.
//
// Regression (found by chaos TestChaosMonkeyCorruption, where a bit flip did
// this to the Acknowledge): the client adopted the sizes as they were. Its
// receive buffers have the size it offered, so Receive sliced beyond the
// buffer and the panic, in the goroutine that reads the connection, took the
// whole application down.
func TestHandshake_AcknowledgeCannotRaiseBufferSizes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	const claimed = 1 << 20
	const sent = 131136 // above the 65535 the client offers, below what the server claims
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		hdr := make([]byte, 8)
		if _, err := io.ReadFull(c, hdr); err != nil {
			return
		}
		if _, err := io.CopyN(io.Discard, c, int64(binary.LittleEndian.Uint32(hdr[4:]))-8); err != nil {
			return
		}
		body, err := ua.Encode(&Acknowledge{
			ReceiveBufSize: claimed,
			SendBufSize:    claimed,
			MaxMessageSize: 0,
			MaxChunkCount:  0,
		})
		if err != nil {
			return
		}
		ack := append([]byte("ACKF\x00\x00\x00\x00"), body...)
		binary.LittleEndian.PutUint32(ack[4:], uint32(len(ack)))
		msg := make([]byte, sent)
		copy(msg, "MSGF")
		binary.LittleEndian.PutUint32(msg[4:], sent)
		_, _ = c.Write(append(ack, msg...))
		time.Sleep(time.Second)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := Dial(ctx, "opc.tcp://"+ln.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	require.Equal(t, uint32(DefaultReceiveBufSize), conn.ReceiveBufSize(), "the Acknowledge cannot raise what the Hello offered")
	require.Equal(t, uint32(DefaultSendBufSize), conn.SendBufSize())

	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	_, err = conn.Receive()
	require.ErrorIs(t, err, errors.ErrMessageTooLarge)
}
