// SPDX-License-Identifier: MIT

package uasc

import (
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/stretchr/testify/require"
)

// waitSrvDone waits for the server's receive loop to end.
func (p *covPair) waitSrvDone(t *testing.T) {
	t.Helper()
	select {
	case <-p.srvDone:
	case <-time.After(covWait):
		t.Fatal("the server's receive loop did not end")
	}
}

// TestReceive_PartialMessagesBounded covers the bound on the partial
// messages buffered on one channel: a few interleaved messages are
// collected, more request IDs or more bytes than the channel accepts end the
// connection with Bad_TcpMessageTooLarge and free what was buffered.
func TestReceive_PartialMessagesBounded(t *testing.T) {
	t.Run("interleaved messages", func(t *testing.T) {
		p := newCovPair(t, covNone, covOpts{})
		for id := uint32(1); id <= maxOpenMessages; id++ {
			p.sendRaw(t, 0x1000+id, ChunkTypeIntermediate, 100)
		}
		p.read(t, 2) // read in order after the chunks: all were collected
		p.server.chunksMu.Lock()
		require.Len(t, p.server.chunks, maxOpenMessages)
		require.EqualValues(t, maxOpenMessages*100, p.server.chunksTotal)
		p.server.chunksMu.Unlock()
		p.requireNoSrvErr(t, 0)
	})
	t.Run("request IDs", func(t *testing.T) {
		p := newCovPair(t, covNone, covOpts{})
		for id := uint32(1); id <= maxOpenMessages+1; id++ {
			p.sendRaw(t, 0x2000+id, ChunkTypeIntermediate, 100)
		}
		msg := p.waitSrvErr(t, ua.StatusBadTCPMessageTooLarge)
		require.Zero(t, msg.RequestID, "a channel error")
		p.waitSrvDone(t)
		p.server.chunksMu.Lock()
		require.Empty(t, p.server.chunks)
		require.Empty(t, p.server.chunkBytes)
		require.Zero(t, p.server.chunksTotal)
		p.server.chunksMu.Unlock()
	})
	t.Run("bytes", func(t *testing.T) {
		ack := *uacp.DefaultServerACK
		ack.MaxMessageSize = 64 * 1024
		p := newCovPair(t, covNone, covOpts{serverACK: &ack})
		require.EqualValues(t, 128*1024, p.server.partialBytesLimit())
		// Every message is within MaxMessageSize, together they are not.
		for id := uint32(1); id <= 4; id++ {
			p.sendRaw(t, 0x3000+id, ChunkTypeIntermediate, 40000)
		}
		msg := p.waitSrvErr(t, ua.StatusBadTCPMessageTooLarge)
		require.Zero(t, msg.RequestID)
		require.ErrorContains(t, msg.Err, "bytes in partial messages")
		p.waitSrvDone(t)
		p.server.chunksMu.Lock()
		require.Empty(t, p.server.chunks)
		require.Zero(t, p.server.chunksTotal)
		p.server.chunksMu.Unlock()
	})
	t.Run("completed messages are released", func(t *testing.T) {
		ack := *uacp.DefaultServerACK
		ack.MaxMessageSize = 64 * 1024
		p := newCovPair(t, covNone, covOpts{serverACK: &ack})
		// Many more bytes than the limit over time, never at once.
		for id := uint32(1); id <= 8; id++ {
			p.sendRaw(t, 0x4000+id, ChunkTypeIntermediate, 40000, ChunkTypeFinal, 100)
		}
		p.read(t, 2)
		p.server.chunksMu.Lock()
		require.Empty(t, p.server.chunks)
		require.Zero(t, p.server.chunksTotal)
		p.server.chunksMu.Unlock()
	})
	t.Run("no limits", func(t *testing.T) {
		ack := *uacp.DefaultServerACK
		ack.MaxChunkCount, ack.MaxMessageSize = 0, 0
		p := newCovPair(t, covNone, covOpts{serverACK: &ack})
		require.Zero(t, p.server.partialBytesLimit())
	})
}
