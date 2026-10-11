// SPDX-License-Identifier: MIT

package uasc

import (
	"context"
	"encoding/binary"
	"io"
	"math"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/stretchr/testify/require"
)

// TestCheckSequenceNumber covers the rule a receiver applies to the chunks of
// a secured channel: each one follows the one before it.
//
// Regression: the sequence numbers of received chunks were not verified at
// all. A chunk that was repeated on the wire passed the signature check of
// the policies without authenticated encryption, so a request could be
// replayed and was executed again, and a multi-chunk message with a chunk
// missing or out of order was put together from what arrived.
func TestCheckSequenceNumber(t *testing.T) {
	const (
		rsa = ua.SecurityPolicyURIBasic256Sha256
		ecc = ua.SecurityPolicyURIECCNistP256
	)
	tests := []struct {
		name   string
		policy string
		mode   ua.MessageSecurityMode
		first  bool
		last   uint32
		got    uint32
		ok     bool
	}{
		{name: "next", policy: rsa, mode: ua.MessageSecurityModeSignAndEncrypt, last: 7, got: 8, ok: true},
		{name: "next, sign only", policy: rsa, mode: ua.MessageSecurityModeSign, last: 7, got: 8, ok: true},
		{name: "replayed", policy: rsa, mode: ua.MessageSecurityModeSignAndEncrypt, last: 7, got: 7},
		{name: "replayed, sign only", policy: rsa, mode: ua.MessageSecurityModeSign, last: 7, got: 7},
		{name: "older", policy: rsa, mode: ua.MessageSecurityModeSignAndEncrypt, last: 7, got: 3},
		{name: "gap", policy: rsa, mode: ua.MessageSecurityModeSignAndEncrypt, last: 7, got: 9},
		{name: "first chunk starts anywhere", policy: rsa, mode: ua.MessageSecurityModeSignAndEncrypt, first: true, got: 512, ok: true},
		{name: "legacy wrap", policy: rsa, mode: ua.MessageSecurityModeSignAndEncrypt, last: math.MaxUint32 - 1023, got: 1, ok: true},
		{name: "legacy wrap to 0", policy: rsa, mode: ua.MessageSecurityModeSignAndEncrypt, last: math.MaxUint32 - 1024, got: 0, ok: true},
		{name: "legacy wrap too early", policy: rsa, mode: ua.MessageSecurityModeSignAndEncrypt, last: math.MaxUint32 - 1025, got: 1},
		{name: "legacy wrap too far", policy: rsa, mode: ua.MessageSecurityModeSignAndEncrypt, last: math.MaxUint32 - 1023, got: 1024},
		{name: "legacy runs to the end", policy: rsa, mode: ua.MessageSecurityModeSignAndEncrypt, last: math.MaxUint32 - 1, got: math.MaxUint32, ok: true},
		{name: "ecc next", policy: ecc, mode: ua.MessageSecurityModeSignAndEncrypt, last: 0, got: 1, ok: true},
		{name: "ecc replayed", policy: ecc, mode: ua.MessageSecurityModeSign, last: 4, got: 4},
		{name: "ecc gap", policy: ecc, mode: ua.MessageSecurityModeSignAndEncrypt, last: 4, got: 6},
		{name: "ecc wraps at the end only", policy: ecc, mode: ua.MessageSecurityModeSignAndEncrypt, last: math.MaxUint32, got: 0, ok: true},
		{name: "ecc does not wrap early", policy: ecc, mode: ua.MessageSecurityModeSignAndEncrypt, last: math.MaxUint32 - 1000, got: 1},
		{name: "no security, not verified", policy: ua.SecurityPolicyURINone, mode: ua.MessageSecurityModeNone, last: 7, got: 7, ok: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &SecureChannel{cfg: &Config{SecurityPolicyURI: tt.policy, SecurityMode: tt.mode, Logger: testLogger}}
			s.receivedAny = !tt.first
			s.lastReceivedSequenceNumber.Store(tt.last)
			err := s.checkSequenceNumber(tt.got)
			if tt.ok {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, ua.StatusBadSequenceNumberInvalid)
		})
	}
}

// TestReadChunk_RejectsReplayedChunk plays chunks of a signed channel to the
// receiving end the way they come off the wire: in order they are accepted;
// a repeated one, one that skips a number and one from before are refused,
// and refusing them does not move the expected number.
func TestReadChunk_RejectsReplayedChunk(t *testing.T) {
	for _, uri := range []string{ua.SecurityPolicyURIBasic256Sha256, ua.SecurityPolicyURIECCNistP256} {
		for _, mode := range secureModes {
			t.Run(uri+"/"+mode.String(), func(t *testing.T) {
				sender, receiver := symmetricPair(t, uri, mode)
				sender.SetMaximumBodySize(8192)

				// The receiving channel reads from a connection the test
				// writes the secured chunks to.
				ln, err := uacp.Listen(context.Background(), "opc.tcp://127.0.0.1:0", nil)
				require.NoError(t, err)
				defer func() { _ = ln.Close() }()
				peerCh := make(chan *uacp.Conn, 1)
				go func() {
					if c, err := ln.Accept(context.Background()); err == nil {
						peerCh <- c
					}
				}()
				wire, err := uacp.Dial(context.Background(), "opc.tcp://"+ln.Addr().String())
				require.NoError(t, err)
				defer func() { _ = wire.Close() }()
				conn := <-peerCh
				defer func() { _ = conn.Close() }()

				s := receiver.sc
				s.c = conn
				s.kind = server
				s.instances = map[uint32][]*channelInstance{receiver.secureChannelID: {receiver}}
				s.activeInstance = receiver

				var chunks [][]byte
				for i := 0; i < 5; i++ {
					w, _ := sendChunks(t, sender, readRequest(1), 631)
					require.Len(t, w, 1)
					chunks = append(chunks, w[0])
				}
				read := func(chunk []byte) (*MessageChunk, error) {
					_, err := wire.Write(chunk)
					require.NoError(t, err)
					return s.readChunk()
				}
				seq := func(chunk []byte) uint32 {
					m, err := read(chunk)
					require.NoError(t, err)
					return m.SequenceNumber
				}

				first := seq(chunks[0])
				require.Equal(t, first+1, seq(chunks[1]))

				_, err = read(chunks[1]) // replayed at once
				require.ErrorIs(t, err, ua.StatusBadSequenceNumberInvalid)
				_, err = read(chunks[0]) // replayed later
				require.ErrorIs(t, err, ua.StatusBadSequenceNumberInvalid)
				_, err = read(chunks[3]) // chunk 2 lost
				require.ErrorIs(t, err, ua.StatusBadSequenceNumberInvalid)

				// None of them moved the receiver: the chunk that is due is
				// still accepted.
				require.Equal(t, first+2, seq(chunks[2]))
				require.Equal(t, first+3, seq(chunks[3]))
				require.Equal(t, first+4, seq(chunks[4]))
			})
		}
	}
}

// TestOpen_UnsolicitedOpenMessageDuringOpen has a peer that answers an
// OpenSecureChannel request with a stream of OpenSecureChannel messages
// nobody asked for and never with the response. open() gives up while the
// dispatcher is still looking at those messages.
//
// Regression (run with -race): the dispatcher read the opening instance of
// the channel without synchronisation while open() cleared it.
func TestOpen_UnsolicitedOpenMessageDuringOpen(t *testing.T) {
	ln, err := uacp.Listen(context.Background(), "opc.tcp://127.0.0.1:0", nil)
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	served := make(chan struct{})
	go func() {
		defer close(served)
		peer, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		defer func() { _ = peer.Close() }()
		// The client's own request, sent back again and again: a well-formed
		// OpenSecureChannel message that is not the response.
		hdr := make([]byte, 8)
		if _, err := io.ReadFull(peer, hdr); err != nil {
			return
		}
		msg := make([]byte, binary.LittleEndian.Uint32(hdr[4:]))
		copy(msg, hdr)
		if _, err := io.ReadFull(peer, msg[8:]); err != nil {
			return
		}
		// Under another request id, so that it is nobody's answer: the id
		// follows the headers (12 bytes), the asymmetric security header
		// (policy URI, no certificate, no thumbprint) and the sequence
		// number.
		reqID := 12 + 4 + len(ua.SecurityPolicyURINone) + 4 + 4 + 4
		binary.LittleEndian.PutUint32(msg[reqID:], 0xDEAD)
		for {
			if _, err := peer.Write(msg); err != nil {
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()

	conn, err := uacp.Dial(context.Background(), "opc.tcp://"+ln.Addr().String())
	require.NoError(t, err)
	cfg := &Config{
		SecurityPolicyURI: ua.SecurityPolicyURINone,
		SecurityMode:      ua.MessageSecurityModeNone,
		RequestTimeout:    10 * time.Second,
		Lifetime:          60_000,
		Logger:            testLogger,
	}
	s, err := NewSecureChannel("opc.tcp://"+ln.Addr().String(), conn, cfg, make(chan error, 1))
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err = s.Open(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Nil(t, s.opening(), "nothing is being opened any more")
	require.Nil(t, s.openWait(1), "no dispatcher has to wait for an open() that is gone")

	// The dispatcher goes on reading the unsolicited messages for a while.
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, conn.Close())
	<-served
}
