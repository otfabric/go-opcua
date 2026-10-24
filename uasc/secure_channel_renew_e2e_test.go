// SPDX-License-Identifier: MIT

package uasc

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/internal/testutil/leakcheck"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// This file covers SecurityToken renewals between real client and server
// channels (see secure_channel_e2e_test.go).

// tokenIDs returns the ids of the tokens a channel verifies incoming
// messages with.
func tokenIDs(s *SecureChannel) []uint32 {
	s.instancesMu.Lock()
	defer s.instancesMu.Unlock()
	var ids []uint32
	for _, inst := range s.instances[7] {
		ids = append(ids, inst.securityTokenID)
	}
	return ids
}

func hasToken(s *SecureChannel, tokenID uint32) bool {
	for _, id := range tokenIDs(s) {
		if id == tokenID {
			return true
		}
	}
	return false
}

// TestRenewal_Automatic opens channels with a short token lifetime: the
// client renews the token before it expires, again and again, while
// requests go on, and both ends retire the tokens that were superseded.
func TestRenewal_Automatic(t *testing.T) {
	for _, pol := range []covPolicy{covRSA, covAEAD} {
		t.Run(pol.name, func(t *testing.T) {
			p := newCovPair(t, pol, covOpts{tweakClient: func(c *Config) { c.Lifetime = 400 }})
			require.Equal(t, 400*time.Millisecond, p.server.activeInstanceOrNil().revisedLifetime)

			const renewals = 3
			for deadline := time.Now().Add(30 * time.Second); ; {
				p.read(t, 2)
				if _, tok := token(p.client); tok >= 9+renewals {
					break
				}
				require.True(t, time.Now().Before(deadline), "the token was not renewed")
			}
			require.Eventually(t, func() bool {
				return !hasToken(p.client, 9) && !hasToken(p.server, 9)
			}, 30*time.Second, 10*time.Millisecond, "the first token is retired on both ends")
			p.read(t, 2)

			select {
			case err := <-p.clientErrs:
				t.Fatalf("unexpected client error: %v", err)
			default:
			}
		})
	}
}

// TestRenewal_RefusedTokenExpires has the server refuse to renew the token
// (the client's certificate was revoked in the meantime). The client reports
// that the renewal failed, and the server closes the channel when the token
// it could not replace expires.
func TestRenewal_RefusedTokenExpires(t *testing.T) {
	var opens atomic.Int32
	p := newCovPair(t, covRSA, covOpts{
		tweakClient: func(c *Config) { c.Lifetime = 300 },
		tweakServer: func(c *Config) {
			c.ClientCertificateValidator = func([]byte) error {
				if opens.Add(1) > 1 {
					return ua.StatusBadCertificateRevoked
				}
				return nil
			}
		},
	})

	timeout := time.After(covWait)
	for renewalFailed := false; !renewalFailed; {
		select {
		case err := <-p.clientErrs:
			if strings.Contains(err.Error(), "renewal failed") {
				require.ErrorIs(t, err, ua.StatusBadCertificateRevoked)
				renewalFailed = true
			}
		case <-timeout:
			t.Fatal("the failed renewal was not reported")
		}
	}

	select {
	case <-p.srvDone: // the server closed the connection
	case <-time.After(covWait):
		t.Fatal("the server kept a channel with an expired token")
	}
	select {
	case <-p.client.disconnected:
	case <-time.After(covWait):
		t.Fatal("the client did not notice that the channel was closed")
	}
	require.Error(t, p.tryRead(context.Background(), 1))
}

// TestRenewal_ConcurrentRequests renews the token while several goroutines
// keep sending requests and the server answers them from goroutines of its
// own, as the server's channel writer does: no request fails, and every
// response is secured with a token the client knows.
func TestRenewal_ConcurrentRequests(t *testing.T) {
	for _, pol := range []covPolicy{covRSA, covAEAD, covECC} {
		t.Run(pol.name, func(t *testing.T) {
			var answering sync.WaitGroup
			p := newCovPair(t, pol, covOpts{handle: func(p *covPair, msg *MessageBody) bool {
				req, ok := msg.Request().(*ua.ReadRequest)
				if !ok {
					return false
				}
				answering.Add(1)
				go func() {
					defer answering.Done()
					_ = p.server.SendResponseWithContext(context.Background(), msg.RequestID, readResponse(req))
				}()
				return true
			}})
			t.Cleanup(answering.Wait)

			const workers, reads, renewals = 4, 15, 4
			var wg sync.WaitGroup
			errs := make(chan error, workers*reads)
			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func(nodes int) {
					defer wg.Done()
					for i := 0; i < reads; i++ {
						if err := p.tryRead(context.Background(), nodes); err != nil {
							errs <- err
						}
					}
				}(1 + w*1500) // some of them need several chunks
			}
			for i := 0; i < renewals; i++ {
				require.NoError(t, p.client.Renew(context.Background()))
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Error(err)
			}
			_, tok := token(p.client)
			require.EqualValues(t, 9+renewals, tok)
		})
	}
}

// waitBlocked waits until a goroutine running fn waits for a mutex.
func waitBlocked(t *testing.T, fn string) {
	t.Helper()
	require.Eventually(t, func() bool {
		for _, g := range strings.Split(leakcheck.AllStacks(), "\n\n") {
			if strings.Contains(g, fn) && strings.Contains(g, "sync.(*Mutex).") {
				return true
			}
		}
		return false
	}, covWait, time.Millisecond)
}

// TestResponse_TokenReplacedWhileWaiting sends a response while the server
// hands over to a new token: the response waits for the outgoing token, and
// once that is released it is secured with the new one, not the one it
// waited for.
func TestResponse_TokenReplacedWhileWaiting(t *testing.T) {
	for _, pol := range []covPolicy{covNone, covRSA} {
		t.Run(pol.name, func(t *testing.T) {
			ids := make(chan uint32, 1)
			p := newCovPair(t, pol, covOpts{handle: holdRequests(ids)})
			pending := p.asyncRead(context.Background(), 1)
			reqID := recv(t, ids)

			// The hand-over, as handleOpenSecureChannelRequest does it: the
			// outgoing token is locked while the new one is installed.
			old := p.server.activeInstanceOrNil()
			old.Lock()
			sent := make(chan error, 1)
			go func() {
				sent <- p.server.SendResponseWithContext(context.Background(), reqID, readResponse(covReadRequest(1)))
			}()
			waitBlocked(t, ".sendResponseWithContext(")

			next := newChannelInstance(p.server)
			next.state = channelActive
			next.secureChannelID = old.secureChannelID
			next.securityTokenID = old.securityTokenID // the keys stay the same
			next.algo = old.algo
			next.maxBodySize = old.maxBodySize
			next.sequenceNumber, next.seqStarted, next.zeroBasedSeq = old.sequenceNumber, old.seqStarted, old.zeroBasedSeq
			before := atomic.LoadUint32(&old.messagesSent)
			p.server.instancesMu.Lock()
			p.server.instances[7] = append(p.server.instances[7], next)
			p.server.activeInstance = next
			p.server.instancesMu.Unlock()
			old.Unlock()

			require.NoError(t, result(t, sent))
			require.NoError(t, result(t, pending))
			require.EqualValues(t, 1, atomic.LoadUint32(&next.messagesSent), "sent with the new token")
			require.Equal(t, before, atomic.LoadUint32(&old.messagesSent))
		})
	}
}

// serverChunk secures a response with the server's active token, the way the
// server does, but names tokenID in its header.
func (p *covPair) serverChunk(t *testing.T, reqID uint32, svc any, tokenID uint32) []byte {
	t.Helper()
	inst := p.server.activeInstanceOrNil()
	inst.Lock()
	defer inst.Unlock()
	m := inst.newMessage(svc, ua.ServiceTypeID(svc), reqID)
	m.TokenID = tokenID
	chunks, err := m.EncodeChunks(inst.maxBodySize)
	require.NoError(t, err)
	require.Len(t, chunks, 1)
	b, err := inst.signAndEncrypt(m, chunks[0])
	require.NoError(t, err)
	return b
}

// TestVerify_Tokens covers how a client picks the token to verify a chunk
// with after a renewal, when it knows two: the one named in the chunk first,
// then the others, for peers that do not name the token they used. A chunk
// none of them verifies is refused.
func TestVerify_Tokens(t *testing.T) {
	for _, pol := range []covPolicy{covRSA, covAEAD} {
		t.Run(pol.name, func(t *testing.T) {
			ids := make(chan uint32, 4)
			p := newCovPair(t, pol, covOpts{handle: holdRequests(ids)})
			require.NoError(t, p.client.Renew(context.Background()))
			require.Eventually(t, func() bool {
				_, tok := token(p.server)
				return tok == 10
			}, covWait, time.Millisecond)
			require.Equal(t, []uint32{9, 10}, tokenIDs(p.client))

			for _, tokenID := range []uint32{10, 9, 4242} {
				pending := p.asyncRead(context.Background(), 1)
				reqID := recv(t, ids)
				_, err := p.serverConn.Write(p.serverChunk(t, reqID, readResponse(covReadRequest(1)), tokenID))
				require.NoError(t, err)
				require.NoError(t, result(t, pending), "token %d", tokenID)
			}

			pending := p.asyncRead(context.Background(), 1)
			reqID := recv(t, ids)
			chunk := p.serverChunk(t, reqID, readResponse(covReadRequest(1)), 10)
			chunk[len(chunk)-1] ^= 0xff
			_, err := p.serverConn.Write(chunk)
			require.NoError(t, err)
			require.ErrorIs(t, result(t, pending), ua.StatusBadSecurityChecksFailed)
		})
	}
}

// TestOPN_ResponseNotSent covers a server that cannot send its
// OpenSecureChannel response: no token is issued.
func TestOPN_ResponseNotSent(t *testing.T) {
	p := newCovPair(t, covNone, covOpts{noOpen: true})
	require.NoError(t, p.serverConn.SetWriteDeadline(time.Now().Add(-time.Second)))
	ctx, cancel := context.WithCancel(context.Background())
	opened := make(chan error, 1)
	go func() { opened <- p.client.Open(ctx) }()
	p.waitSrvErr(t, nil)
	cancel()
	require.ErrorIs(t, result(t, opened), context.Canceled)
	c, _ := token(p.server)
	require.Zero(t, c)
}

// TestScheduleServerTokenExpiry_NoLifetime: a token without a lifetime is not
// retired.
func TestScheduleServerTokenExpiry_NoLifetime(t *testing.T) {
	s := NewCryptoChannel(&Config{Logger: testLogger})
	inst := &channelInstance{sc: s}
	s.scheduleServerTokenExpiry(inst)
	require.Nil(t, inst.expiry)
}

// TestConstructors_Errors covers the constructors' refusals.
func TestConstructors_Errors(t *testing.T) {
	require.PanicsWithValue(t, "uasc: NewCryptoChannel: cfg is nil", func() { NewCryptoChannel(nil) })
	_, err := NewServerSecureChannel("opc.tcp://localhost:4840", nil, &Config{}, make(chan error), 1, 1, 1)
	require.ErrorIs(t, err, errors.ErrNotConnected)
}

// TestClientToken_NoLifetime: a token the server gave no lifetime has no
// expiry timer, and stays known after it was superseded.
func TestClientToken_NoLifetime(t *testing.T) {
	s := newExpiryTestChannel()
	first := s.testInstall(1, 0, time.Now())
	require.Nil(t, first.expiry)
	s.testInstall(2, time.Minute, time.Now())
	defer s.ReleaseTokens()
	require.Equal(t, []uint32{1, 2}, s.testTokens())
}

// TestRenewal_SupersededTokenNotRenewed: a token replaced by Renew before its
// own scheduled renewal fires is not renewed again. Its renewal would open
// from the sequence number of the superseded token, a number already used on
// the channel, and peers that check sequence numbers (Part 6 §6.7.2.4; the
// go-opcua server, opcua-asyncio) close the channel. The successor schedules
// its own renewal.
func TestRenewal_SupersededTokenNotRenewed(t *testing.T) {
	for _, pol := range []covPolicy{covRSA, covAEAD} {
		t.Run(pol.name, func(t *testing.T) {
			// A lifetime that outlasts the test: only explicit renewals.
			p := newCovPair(t, pol, covOpts{tweakClient: func(c *Config) { c.Lifetime = 3_600_000 }})
			first := p.client.activeInstanceOrNil()
			require.NotNil(t, first)
			p.read(t, 2)

			require.NoError(t, p.client.Renew(context.Background()))
			p.read(t, 2)
			_, renewed := token(p.client)
			require.NotEqual(t, first.securityTokenID, renewed)

			// What the scheduled renewal of the first token does when it fires.
			require.NoError(t, p.client.renew(first))
			_, tok := token(p.client)
			require.Equal(t, renewed, tok, "the superseded token was renewed again")
			p.read(t, 2)

			select {
			case err := <-p.clientErrs:
				t.Fatalf("unexpected client error: %v", err)
			case msg := <-p.srvErrs:
				t.Fatalf("unexpected server error: %v", msg.Err)
			default:
			}
		})
	}
}
