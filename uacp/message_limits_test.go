// SPDX-License-Identifier: MIT

package uacp

import (
	"context"
	"encoding/binary"
	"io"
	"math"
	"net"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// ackServer accepts one connection on a loopback port, reads the Hello and
// answers with ack. It returns the endpoint to dial.
func ackServer(t *testing.T, ack *Acknowledge) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
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
		body, err := ua.Encode(ack)
		if err != nil {
			return
		}
		b := append([]byte("ACKF\x00\x00\x00\x00"), body...)
		binary.LittleEndian.PutUint32(b[4:], uint32(len(b)))
		_, _ = c.Write(b)
		_, _ = io.Copy(io.Discard, c)
	}()
	return "opc.tcp://" + ln.Addr().String()
}

// TestHandshake_ClientCapsServerLimits: the limits of the Acknowledge bound
// what the client sends (Part 6 §7.1.2.4) and, capped at the client's own
// configured limits, what it accepts. A server announcing no limit gets the
// client's own, or the defaults when the client has none either.
func TestHandshake_ClientCapsServerLimits(t *testing.T) {
	const huge = math.MaxUint32
	tests := []struct {
		name                     string
		ownSize, ownChunks       uint32 // the client's Hello
		srvSize, srvChunks       uint32 // the server's Acknowledge
		wantSize, wantChunks     uint32 // what the client accepts
		wantPeerSize, wantPeerCC uint32 // what the client may send
	}{
		{"defaults, server without limits", 0, 0, 0, 0, DefaultMaxMessageSize, DefaultMaxChunkCount, 0, 0},
		{"defaults, server limits", 0, 0, 16 * MB, 2000, 16 * MB, 2000, 16 * MB, 2000},
		{"own limits, server without limits", 1 * MB, 100, 0, 0, 1 * MB, 100, 0, 0},
		{"own limits, larger server limits", 1 * MB, 100, huge, huge, 1 * MB, 100, huge, huge},
		{"own limits, smaller server limits", 4 * MB, 100, 1 * MB, 10, 1 * MB, 10, 1 * MB, 10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoint := ackServer(t, &Acknowledge{
				ReceiveBufSize: DefaultReceiveBufSize,
				SendBufSize:    DefaultSendBufSize,
				MaxMessageSize: tt.srvSize,
				MaxChunkCount:  tt.srvChunks,
			})
			own := *DefaultClientACK
			own.MaxMessageSize, own.MaxChunkCount = tt.ownSize, tt.ownChunks
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn, err := (&Dialer{ClientACK: &own}).Dial(ctx, endpoint)
			require.NoError(t, err)
			defer func() { _ = conn.Close() }()

			require.Equal(t, tt.wantSize, conn.MaxMessageSize(), "accepted message size")
			require.Equal(t, tt.wantChunks, conn.MaxChunkCount(), "accepted chunk count")
			require.Equal(t, tt.wantPeerSize, conn.PeerMaxMessageSize(), "message size the server accepts")
			require.Equal(t, tt.wantPeerCC, conn.PeerMaxChunkCount(), "chunk count the server accepts")
		})
	}
}

// TestHandshake_ServerTakesClientLimits: the limits of the Hello bound what
// the server sends (Part 6 §7.1.2.3).
func TestHandshake_ServerTakesClientLimits(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ln, err := Listen(ctx, "opc.tcp://127.0.0.1:0", nil)
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	accepted := make(chan *Conn, 1)
	go func() {
		c, err := ln.Accept(ctx)
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()

	own := *DefaultClientACK
	own.MaxMessageSize, own.MaxChunkCount = 1*MB, 10
	cc, err := (&Dialer{ClientACK: &own}).Dial(ctx, "opc.tcp://"+ln.Addr().String())
	require.NoError(t, err)
	defer func() { _ = cc.Close() }()

	sc := <-accepted
	require.NotNil(t, sc)
	defer func() { _ = sc.Close() }()
	require.EqualValues(t, 1*MB, sc.PeerMaxMessageSize())
	require.EqualValues(t, 10, sc.PeerMaxChunkCount())

	// A client without limits leaves the server's sends unbounded.
	go func() {
		c, err := ln.Accept(ctx)
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()
	cc2, err := Dial(ctx, "opc.tcp://"+ln.Addr().String())
	require.NoError(t, err)
	defer func() { _ = cc2.Close() }()
	sc2 := <-accepted
	require.NotNil(t, sc2)
	defer func() { _ = sc2.Close() }()
	require.Zero(t, sc2.PeerMaxMessageSize())
	require.Zero(t, sc2.PeerMaxChunkCount())
}
