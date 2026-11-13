// SPDX-License-Identifier: MIT

package uasc

import (
	"context"
	"encoding/binary"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// TestVerifyAndDecrypt_PaddingSize checks that a signed and encrypted chunk
// whose PaddingSize does not fit in its plaintext is refused.
func TestVerifyAndDecrypt_PaddingSize(t *testing.T) {
	client, server := aeadPair(t, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)
	require.False(t, client.algo.AEAD())
	sigLen := client.algo.SignatureLength()
	require.EqualValues(t, 32, sigLen)

	_, plains := sendChunks(t, client, readRequest(1), 0x2f1)
	const headerLength = 16
	header := append([]byte(nil), plains[0][:headerLength]...)
	header[3] = byte(ChunkTypeFinal)

	for _, tc := range []struct {
		name    string
		padding byte
		ok      bool
	}{
		{"padding fits", 14, true}, // 15 bytes of padding and its size, 1 byte of body
		{"padding of the whole body", 15, true},
		{"padding longer than the body", 16, false},
		{"largest padding size", 0xff, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// 16 bytes of plaintext and 32 of signature: three cipher blocks.
			payload := make([]byte, 16)
			payload[15] = tc.padding
			binary.LittleEndian.PutUint32(header[4:], uint32(headerLength+48))
			sig, err := client.algo.Signature(append(append([]byte(nil), header...), payload...))
			require.NoError(t, err)
			ct, err := client.algo.Encrypt(append(append([]byte(nil), payload...), sig...))
			require.NoError(t, err)
			wire := append(append([]byte(nil), header...), ct...)

			chunk := new(MessageChunk)
			_, err = chunk.Decode(wire)
			require.NoError(t, err)
			require.NotPanics(t, func() {
				out, err := server.verifyAndDecrypt(chunk, wire)
				if tc.ok {
					require.NoError(t, err)
					require.Len(t, out, 15-int(tc.padding))
				} else {
					require.ErrorIs(t, err, ua.StatusBadSecurityChecksFailed)
				}
			})
		})
	}
}

// panicHandler is a slog handler that panics on the record "recv" once
// armed: it stands in for a fault while a client channel receives.
type panicHandler struct{ armed *atomic.Bool }

func (h panicHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h panicHandler) Handle(_ context.Context, r slog.Record) error {
	if r.Message == "recv" && h.armed.Load() {
		panic("fault while receiving")
	}
	return nil
}
func (h panicHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h panicHandler) WithGroup(string) slog.Handler      { return h }

// TestDispatcher_PanicEndsChannel checks that a panic on the client's
// receive goroutine fails the waiting requests and ends the channel instead
// of the process.
func TestDispatcher_PanicEndsChannel(t *testing.T) {
	var armed atomic.Bool
	p := newCovPair(t, covNone, covOpts{tweakClient: func(c *Config) {
		c.Logger = slog.New(panicHandler{&armed})
	}})
	p.read(t, 1)

	armed.Store(true)
	err := p.tryRead(context.Background(), 1)
	require.ErrorIs(t, err, ua.StatusBadInternalError)

	select {
	case err := <-p.clientErrs:
		require.ErrorIs(t, err, ua.StatusBadInternalError)
	case <-time.After(covWait):
		t.Fatal("the channel error was not reported")
	}
	select {
	case <-p.client.disconnected:
	case <-time.After(covWait):
		t.Fatal("the dispatcher did not end")
	}
}
