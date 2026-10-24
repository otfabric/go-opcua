// SPDX-License-Identifier: MIT

package uasc

import (
	"context"
	"crypto"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/otfabric/go-opcua/uapolicy"
	"github.com/stretchr/testify/require"
)

// This file feeds real client and server SecureChannels (see
// secure_channel_e2e_test.go) with what a faulty or hostile peer sends.

const covWait = 10 * time.Second

// covRawChunk returns a symmetric chunk of a channel without security.
func covRawChunk(msgType string, chunkType byte, channelID, tokenID, seq, reqID uint32, body []byte) []byte {
	b := make([]byte, 24, 24+len(body))
	copy(b, msgType)
	b[3] = chunkType
	binary.LittleEndian.PutUint32(b[4:], uint32(24+len(body)))
	binary.LittleEndian.PutUint32(b[8:], channelID)
	binary.LittleEndian.PutUint32(b[12:], tokenID)
	binary.LittleEndian.PutUint32(b[16:], seq)
	binary.LittleEndian.PutUint32(b[20:], reqID)
	return append(b, body...)
}

// covEncodeService encodes a service with its type id, as the body of a
// message.
func covEncodeService(t *testing.T, svc any) []byte {
	t.Helper()
	buf := ua.NewBuffer(nil)
	buf.WriteStruct(ua.NewFourByteExpandedNodeID(0, ua.ServiceTypeID(svc)))
	buf.WriteStruct(svc)
	require.NoError(t, buf.Error())
	return buf.Bytes()
}

// covReqHeader is the header of a request that is put together by hand.
func covReqHeader(handle uint32) *ua.RequestHeader {
	return &ua.RequestHeader{
		AuthenticationToken: ua.NewTwoByteNodeID(0),
		Timestamp:           time.Now(),
		RequestHandle:       handle,
		AdditionalHeader:    ua.NewExtensionObject(nil),
	}
}

// waitFor waits for an error from ch that matches target.
func waitFor(t *testing.T, ch <-chan error, target error) {
	t.Helper()
	timeout := time.After(covWait)
	for {
		select {
		case err := <-ch:
			if errors.Is(err, target) {
				return
			}
		case <-timeout:
			t.Fatalf("no %v", target)
		}
	}
}

// waitSrvErr returns the first error the server's receive loop saw that
// matches target, or the first one if target is nil.
func (p *covPair) waitSrvErr(t *testing.T, target error) *MessageBody {
	t.Helper()
	timeout := time.After(covWait)
	for {
		select {
		case msg := <-p.srvErrs:
			if target == nil || errors.Is(msg.Err, target) {
				return msg
			}
		case <-timeout:
			t.Fatalf("the server did not fail with %v", target)
			return nil
		}
	}
}

// asyncRead sends a ReadRequest in the background.
func (p *covPair) asyncRead(ctx context.Context, nodes int) <-chan error {
	ch := make(chan error, 1)
	go func() { ch <- p.tryRead(ctx, nodes) }()
	return ch
}

func result(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(covWait):
		t.Fatal("no result")
		return nil
	}
}

// holdRequests is a server request handler that answers nothing and reports
// the request ids of the ReadRequests it got.
func holdRequests(ids chan<- uint32) func(*covPair, *MessageBody) bool {
	return func(_ *covPair, msg *MessageBody) bool {
		if _, ok := msg.Request().(*ua.ReadRequest); ok {
			ids <- msg.RequestID
			return true
		}
		return false
	}
}

func recv(t *testing.T, ch <-chan uint32) uint32 {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(covWait):
		t.Fatal("nothing received")
		return 0
	}
}

func (p *covPair) handlerCount() int {
	p.client.handlersMu.Lock()
	defer p.client.handlersMu.Unlock()
	return len(p.client.handlers)
}

// TestDispatcher_PeerFaults sends the client chunks of a channel without
// security that are damaged or out of place, while a request waits for its
// response. Each fault ends up with the waiting request (if it can be
// attributed to it, or if it ends the connection) and the channel goes on
// working where the stream allows it.
func TestDispatcher_PeerFaults(t *testing.T) {
	read := &ua.ReadResponse{ResponseHeader: covRespHeader(ua.StatusOK), Results: []*ua.DataValue{}}
	tests := []struct {
		name string
		// chunks returns what the server sends while the request with id
		// reqID waits.
		chunks func(t *testing.T, reqID uint32) [][]byte
		want   error
		// decoding is set if the fault is a decoding error of some kind.
		decoding bool
		// usable is set if the channel still works after the fault.
		usable bool
	}{
		{
			name: "abort",
			chunks: func(t *testing.T, reqID uint32) [][]byte {
				abort, err := (&MessageAbort{ErrorCode: uint32(ua.StatusBadResponseTooLarge), Reason: "too large"}).Encode()
				require.NoError(t, err)
				return [][]byte{
					covRawChunk("MSG", ChunkTypeIntermediate, 7, 9, 1, reqID, []byte("half a response")),
					covRawChunk("MSG", ChunkTypeError, 7, 9, 2, reqID, abort),
				}
			},
			want:   ua.StatusBadResponseTooLarge,
			usable: true,
		},
		{
			name: "malformed abort",
			chunks: func(t *testing.T, reqID uint32) [][]byte {
				return [][]byte{covRawChunk("MSG", ChunkTypeError, 7, 9, 1, reqID, []byte{1, 2})}
			},
			want:   ua.StatusBadDecodingError,
			usable: true,
		},
		{
			name: "undecodable body",
			chunks: func(t *testing.T, reqID uint32) [][]byte {
				return [][]byte{covRawChunk("MSG", ChunkTypeFinal, 7, 9, 1, reqID, []byte{0xff, 0xff, 0xff})}
			},
			decoding: true,
			usable:   true,
		},
		{
			name: "a request sent to the client",
			chunks: func(t *testing.T, reqID uint32) [][]byte {
				body := covEncodeService(t, &ua.OpenSecureChannelRequest{RequestHeader: covReqHeader(reqID)})
				return [][]byte{covRawChunk("MSG", ChunkTypeFinal, 7, 9, 1, reqID, body)}
			},
			want:   ua.StatusBadServiceUnsupported,
			usable: true,
		},
		{
			name: "response under a token the client does not know",
			chunks: func(t *testing.T, reqID uint32) [][]byte {
				// Peers that do not rotate token ids are tolerated: the
				// chunk is verified with the tokens that are known.
				return [][]byte{covRawChunk("MSG", ChunkTypeFinal, 7, 1234, 1, reqID, covEncodeService(t, readResponse(covReadRequest(1))))}
			},
			usable: true,
		},
		{
			name: "unknown secure channel",
			chunks: func(t *testing.T, reqID uint32) [][]byte {
				return [][]byte{covRawChunk("MSG", ChunkTypeFinal, 99, 9, 1, reqID, covEncodeService(t, read))}
			},
			want:   errors.ErrInvalidState,
			usable: true,
		},
		{
			name: "unknown message type",
			chunks: func(t *testing.T, reqID uint32) [][]byte {
				return [][]byte{covRawChunk("XYZ", ChunkTypeFinal, 7, 9, 1, reqID, covEncodeService(t, read))}
			},
			want:   errors.ErrInvalidMessageType,
			usable: true,
		},
		{
			name: "chunk shorter than its header",
			chunks: func(t *testing.T, reqID uint32) [][]byte {
				c := covRawChunk("MSG", ChunkTypeFinal, 7, 9, 1, reqID, nil)[:10]
				binary.LittleEndian.PutUint32(c[4:], 10)
				return [][]byte{c}
			},
			want:   ua.StatusBadDecodingError,
			usable: true,
		},
		{
			name: "no sequence header",
			chunks: func(t *testing.T, reqID uint32) [][]byte {
				c := covRawChunk("MSG", ChunkTypeFinal, 7, 9, 1, reqID, nil)[:20]
				binary.LittleEndian.PutUint32(c[4:], 20)
				return [][]byte{c}
			},
			decoding: true,
			usable:   true,
		},
		{
			name: "unsolicited OpenSecureChannel response",
			chunks: func(t *testing.T, reqID uint32) [][]byte {
				return [][]byte{covOPNChunk(t, ua.SecurityPolicyURINone, reqID, &ua.OpenSecureChannelResponse{
					ResponseHeader: covRespHeader(ua.StatusOK), SecurityToken: &ua.ChannelSecurityToken{},
				})}
			},
			want:   errors.ErrInvalidState, // nothing is being opened
			usable: true,
		},
		{
			name: "close",
			chunks: func(t *testing.T, reqID uint32) [][]byte {
				return [][]byte{covRawChunk("CLO", ChunkTypeFinal, 7, 9, 1, reqID, nil)}
			},
			want: io.EOF,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ids := make(chan uint32, 4)
			p := newCovPair(t, covNone, covOpts{handle: holdRequests(ids)})
			pending := p.asyncRead(context.Background(), 1)
			reqID := recv(t, ids)
			for _, c := range tt.chunks(t, reqID) {
				_, err := p.serverConn.Write(c)
				require.NoError(t, err)
			}
			err := result(t, pending)
			switch {
			case tt.want == nil && !tt.decoding:
				require.NoError(t, err)
			case tt.decoding:
				require.Error(t, err)
			default:
				require.ErrorIs(t, err, tt.want)
			}
			require.Zero(t, p.handlerCount(), "no handler is left behind")
			if err != nil {
				// Faults that are not a status of a service reach the
				// connection monitor.
				waitFor(t, p.clientErrs, err)
			}
			if !tt.usable {
				return
			}
			// The channel still works: answer the next request.
			pending = p.asyncRead(context.Background(), 2)
			reqID = recv(t, ids)
			_, err = p.serverConn.Write(covRawChunk("MSG", ChunkTypeFinal, 7, 9, 10, reqID, covEncodeService(t, readResponse(covReadRequest(2)))))
			require.NoError(t, err)
			require.NoError(t, result(t, pending))
		})
	}
}

// covOPNChunk returns an OpenSecureChannel message of a channel without
// security.
func covOPNChunk(t *testing.T, uri string, reqID uint32, svc any) []byte {
	t.Helper()
	inst := &channelInstance{sc: &SecureChannel{cfg: &Config{SecurityPolicyURI: uri, SecurityMode: ua.MessageSecurityModeNone, Logger: testLogger}}}
	m := opnMessage(inst, uri, nil, nil, svc, ua.ServiceTypeID(svc))
	m.SecureChannelID = 7
	m.RequestID = reqID
	b, err := m.Encode()
	require.NoError(t, err)
	return b
}

// TestDispatcher_ConnectionErrorReachesAllRequests has the server answer with
// an Error message while two requests wait: both get its status code, and
// so does the connection monitor.
func TestDispatcher_ConnectionErrorReachesAllRequests(t *testing.T) {
	ids := make(chan uint32, 4)
	p := newCovPair(t, covNone, covOpts{handle: holdRequests(ids)})
	first := p.asyncRead(context.Background(), 1)
	second := p.asyncRead(context.Background(), 1)
	recv(t, ids)
	recv(t, ids)

	p.serverConn.SendError(ua.StatusBadTCPInternalError)
	require.ErrorIs(t, result(t, first), ua.StatusBadTCPInternalError)
	require.ErrorIs(t, result(t, second), ua.StatusBadTCPInternalError)
	waitFor(t, p.clientErrs, ua.StatusBadTCPInternalError)
	require.Zero(t, p.handlerCount())
}

// TestDispatcher_ServiceFaults covers responses with a bad service result:
// the caller gets the status code (and its handler the response); only the
// ones that mean the channel or session has to be recreated reach the
// connection monitor.
func TestDispatcher_ServiceFaults(t *testing.T) {
	for _, tt := range []struct {
		status    ua.StatusCode
		reconnect bool
	}{
		{ua.StatusBadTooManyOperations, false},
		{ua.StatusBadSessionIDInvalid, true},
	} {
		t.Run(tt.status.Error(), func(t *testing.T) {
			var fault atomic.Bool
			fault.Store(true)
			p := newCovPair(t, covNone, covOpts{handle: func(p *covPair, msg *MessageBody) bool {
				if !fault.Load() {
					return false
				}
				_ = p.server.SendResponseWithContext(context.Background(), msg.RequestID, &ua.ServiceFault{ResponseHeader: covRespHeader(tt.status)})
				return true
			}})
			var handled ua.Response
			err := p.client.SendRequest(context.Background(), covReadRequest(1), nil, func(r ua.Response) error {
				handled = r
				return nil
			})
			require.ErrorIs(t, err, tt.status)
			require.IsType(t, &ua.ServiceFault{}, handled, "the handler sees the fault")
			if tt.reconnect {
				waitFor(t, p.clientErrs, tt.status)
				return
			}
			// The next request is answered; no fault reached the monitor.
			fault.Store(false)
			p.read(t, 1)
			select {
			case err := <-p.clientErrs:
				t.Fatalf("operation-level fault reached the monitor: %v", err)
			default:
			}
		})
	}
}

// TestDispatcher_UnsolicitedResponse sends the client a response nobody asked
// for, and the response to a request whose caller gave up: both are dropped.
func TestDispatcher_UnsolicitedResponse(t *testing.T) {
	ids := make(chan uint32, 4)
	var hold atomic.Bool
	hold.Store(true)
	p := newCovPair(t, covNone, covOpts{handle: func(p *covPair, msg *MessageBody) bool {
		return hold.Load() && holdRequests(ids)(p, msg)
	}})

	ctx, cancel := context.WithCancel(context.Background())
	pending := p.asyncRead(ctx, 1)
	reqID := recv(t, ids)
	cancel()
	require.ErrorIs(t, result(t, pending), context.Canceled)
	require.Zero(t, p.handlerCount())

	hold.Store(false)
	// The late response, and one for a request that was never made.
	require.NoError(t, p.server.SendResponseWithContext(context.Background(), reqID, readResponse(covReadRequest(1))))
	unsolicited := readResponse(covReadRequest(1))
	unsolicited.Results[0].Value = ua.MustVariant("CurrentTime")
	require.NoError(t, p.server.SendResponseWithContext(context.Background(), 0xBEEF, unsolicited))
	p.read(t, 3)
}

// TestReceive_ChunkLimits covers the limits a connection has agreed on: more
// chunks or a larger message than that is refused, for the request it
// belongs to, on both ends.
func TestReceive_ChunkLimits(t *testing.T) {
	big := func(p *covPair, msg *MessageBody) bool {
		req := msg.Request().(*ua.ReadRequest)
		if len(req.NodesToRead) == 1 {
			_ = p.server.SendResponseWithContext(context.Background(), msg.RequestID, readResponse(covReadRequest(16000)))
			return true
		}
		return false
	}
	t.Run("chunk count", func(t *testing.T) {
		ack := *uacp.DefaultServerACK
		ack.MaxChunkCount = 2
		p := newCovPair(t, covNone, covOpts{serverACK: &ack, handle: big})
		require.EqualValues(t, 2, p.clientConn.MaxChunkCount())

		// A response of five chunks.
		require.ErrorIs(t, p.tryRead(context.Background(), 1), errors.ErrTooManyChunks)
		p.read(t, 2) // the channel still works
		// A request of five chunks.
		require.NoError(t, p.client.SendRequest(context.Background(), covReadRequest(16000), nil, nil))
		msg := p.waitSrvErr(t, errors.ErrTooManyChunks)
		require.NotZero(t, msg.RequestID, "the error belongs to the request")
	})
	t.Run("message size", func(t *testing.T) {
		ack := *uacp.DefaultServerACK
		ack.MaxMessageSize = 64 * 1024
		p := newCovPair(t, covNone, covOpts{serverACK: &ack, handle: big})
		require.ErrorIs(t, p.tryRead(context.Background(), 1), errors.ErrMessageTooLarge)
		p.read(t, 2) // the channel still works
	})
}

// TestReceive_ContextDone does not read once the context is done.
func TestReceive_ContextDone(t *testing.T) {
	p := newCovPair(t, covNone, covOpts{noOpen: true, noServe: true})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	msg := p.server.Receive(ctx)
	require.ErrorIs(t, msg.Err, context.Canceled)
}

// covSideOPN is an OpenSecureChannel request that is sent to the server over
// the client's connection without the client channel knowing.
type covSideOPN struct {
	uri       string
	mode      ua.MessageSecurityMode
	cert      []byte
	key       crypto.PrivateKey
	remote    crypto.PublicKey
	channelID uint32
	req       *ua.OpenSecureChannelRequest
}

func (p *covPair) sendSideOPN(t *testing.T, o covSideOPN) {
	t.Helper()
	inst := &channelInstance{
		sc:              &SecureChannel{cfg: &Config{SecurityPolicyURI: o.uri, SecurityMode: o.mode, Certificate: o.cert, Logger: testLogger}},
		secureChannelID: o.channelID,
		zeroBasedSeq:    !uapolicy.LegacySequenceNumbers(o.uri),
	}
	if o.mode != ua.MessageSecurityModeNone {
		var err error
		inst.algo, err = uapolicy.AsymmetricKeys(o.uri, o.key, o.remote)
		require.NoError(t, err)
	}
	// Continue the client's sequence numbers, as a renewal does.
	if act := p.client.activeInstanceOrNil(); act != nil {
		act.Lock()
		inst.sequenceNumber, inst.seqStarted = act.sequenceNumber, act.seqStarted
		act.sequenceNumber++
		act.Unlock()
	}
	o.req.RequestHeader = covReqHeader(77)
	m := inst.newMessage(o.req, id.OpenSecureChannelRequestEncodingDefaultBinary, 77)
	b, err := m.Encode()
	require.NoError(t, err)
	b, err = inst.signAndEncrypt(m, b)
	require.NoError(t, err)
	_, err = p.clientConn.Write(b)
	require.NoError(t, err)
}

// TestServerOPN_Refused sends an open server channel OpenSecureChannel
// requests it has to refuse.
func TestServerOPN_Refused(t *testing.T) {
	pki, err := testpki.Get()
	require.NoError(t, err)
	none := func(channelID uint32, req *ua.OpenSecureChannelRequest) covSideOPN {
		return covSideOPN{uri: ua.SecurityPolicyURINone, mode: ua.MessageSecurityModeNone, channelID: channelID, req: req}
	}
	renew := func() *ua.OpenSecureChannelRequest {
		return &ua.OpenSecureChannelRequest{RequestType: ua.SecurityTokenRequestTypeRenew, SecurityMode: ua.MessageSecurityModeNone}
	}
	tests := []struct {
		name    string
		pol     covPolicy
		opn     covSideOPN
		want    error
		errorTo bool // the server answers with an Error message
	}{
		{
			name: "another secure channel",
			pol:  covNone,
			opn:  none(8, renew()),
			want: ua.StatusBadSecureChannelIDInvalid,
		},
		{
			name: "another policy",
			pol:  covNone,
			opn: covSideOPN{uri: ua.SecurityPolicyURIBasic256Sha256, mode: ua.MessageSecurityModeNone,
				cert: pki.ClientCert, channelID: 7, req: renew()},
			want: ua.StatusBadSecurityPolicyRejected,
		},
		{
			name: "another certificate",
			pol:  covRSA,
			opn: covSideOPN{uri: ua.SecurityPolicyURIBasic256Sha256, mode: ua.MessageSecurityModeNone,
				cert: pki.StrangerCert, channelID: 7, req: renew()},
			want: ua.StatusBadSecurityChecksFailed,
		},
		{
			name: "another protocol version",
			pol:  covNone,
			opn:  none(7, &ua.OpenSecureChannelRequest{ClientProtocolVersion: 1, RequestType: ua.SecurityTokenRequestTypeRenew}),
			want: ua.StatusBadProtocolVersionUnsupported,
		},
		{
			name:    "another security mode",
			pol:     covNone,
			opn:     none(7, &ua.OpenSecureChannelRequest{RequestType: ua.SecurityTokenRequestTypeRenew, SecurityMode: ua.MessageSecurityModeSign}),
			want:    ua.StatusBadSecurityModeRejected,
			errorTo: true,
		},
		{
			name: "no client nonce",
			pol:  covRSA,
			opn: covSideOPN{uri: ua.SecurityPolicyURIBasic256Sha256, mode: ua.MessageSecurityModeSignAndEncrypt,
				cert: pki.ClientCert, key: pki.ClientKey, remote: &pki.ServerKey.PublicKey, channelID: 7,
				req: &ua.OpenSecureChannelRequest{RequestType: ua.SecurityTokenRequestTypeRenew, SecurityMode: ua.MessageSecurityModeSignAndEncrypt}},
			want:    ua.StatusBadNonceInvalid,
			errorTo: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newCovPair(t, tt.pol, covOpts{})
			channelID, tokenID := token(p.server)
			p.sendSideOPN(t, tt.opn)
			p.waitSrvErr(t, tt.want)
			if tt.errorTo {
				waitFor(t, p.clientErrs, tt.want)
			}
			c, tok := token(p.server)
			require.Equal(t, channelID, c)
			require.Equal(t, tokenID, tok, "no token was issued")
		})
	}
}

// TestServerOPN_OpenRefused covers the reasons a server refuses to open a
// channel: the client's certificate is not trusted, the server has no
// certificate for the policy, or the client's certificate cannot be used.
func TestServerOPN_OpenRefused(t *testing.T) {
	pki, err := testpki.Get()
	require.NoError(t, err)

	t.Run("untrusted certificate", func(t *testing.T) {
		for _, tt := range []struct {
			verdict error
			want    ua.StatusCode
		}{
			{ua.StatusBadCertificateRevoked, ua.StatusBadCertificateRevoked},
			{fmt.Errorf("not in the trust list"), ua.StatusBadCertificateUntrusted},
		} {
			seen := make(chan []byte, 1)
			p := newCovPair(t, covRSA, covOpts{noOpen: true, tweakServer: func(c *Config) {
				c.ClientCertificateValidator = func(der []byte) error {
					seen <- der
					return tt.verdict
				}
			}})
			require.ErrorIs(t, p.client.Open(context.Background()), tt.want)
			require.Equal(t, pki.ClientCert, <-seen)
			c, _ := token(p.server)
			require.Zero(t, c, "the server channel is not open")
		}
	})

	t.Run("trusted certificate", func(t *testing.T) {
		var calls atomic.Int32
		p := newCovPair(t, covRSA, covOpts{tweakServer: func(c *Config) {
			c.ClientCertificateValidator = func([]byte) error { calls.Add(1); return nil }
		}})
		p.read(t, 1)
		require.EqualValues(t, 1, calls.Load())
	})

	t.Run("no certificate for the policy", func(t *testing.T) {
		p := newCovPair(t, covECC, covOpts{noOpen: true, tweakServer: func(c *Config) {
			c.LocalIdentity = func(string) ([]byte, crypto.Signer, error) { return nil, nil, fmt.Errorf("no ECC certificate") }
		}})
		require.ErrorIs(t, p.client.Open(context.Background()), ua.StatusBadSecurityPolicyRejected)
	})

	for _, tt := range []struct {
		name string
		pol  covPolicy
		cert []byte
	}{
		{"unparsable client certificate", covRSA, []byte("not a certificate")},
		{"RSA certificate on an ECC policy", covECC, pki.ClientCert},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := newCovPair(t, tt.pol, covOpts{noOpen: true, tweakClient: func(c *Config) { c.Certificate = tt.cert }})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			opened := make(chan error, 1)
			go func() { opened <- p.client.Open(ctx) }()
			// The server cannot verify the request and does not answer it.
			msg := p.waitSrvErr(t, nil)
			require.Error(t, msg.Err)
			cancel()
			require.ErrorIs(t, <-opened, context.Canceled)
			require.Nil(t, p.client.opening())
		})
	}
}

// TestClientOpen_LocalErrors covers what keeps a client from sending an
// OpenSecureChannel request at all.
func TestClientOpen_LocalErrors(t *testing.T) {
	pki, err := testpki.Get()
	require.NoError(t, err)

	t.Run("unparsable server certificate", func(t *testing.T) {
		p := newCovPair(t, covRSA, covOpts{noOpen: true, tweakClient: func(c *Config) { c.RemoteCertificate = []byte("junk") }})
		require.Error(t, p.client.Open(context.Background()))
	})
	t.Run("server certificate of the wrong key type", func(t *testing.T) {
		p := newCovPair(t, covECC, covOpts{noOpen: true, tweakClient: func(c *Config) { c.RemoteCertificate = pki.ServerCert }})
		require.Error(t, p.client.Open(context.Background()))
	})
	t.Run("connection closed", func(t *testing.T) {
		p := newCovPair(t, covNone, covOpts{noOpen: true})
		require.NoError(t, p.clientConn.Close())
		require.ErrorIs(t, p.client.Open(context.Background()), net.ErrClosed)
		require.Zero(t, p.handlerCount())
		require.Nil(t, p.client.opening())
	})
	t.Run("server channel", func(t *testing.T) {
		p := newCovPair(t, covNone, covOpts{noOpen: true, noServe: true})
		require.ErrorIs(t, p.server.Open(context.Background()), errors.ErrInvalidState)
	})
	t.Run("not open", func(t *testing.T) {
		p := newCovPair(t, covNone, covOpts{noOpen: true, noServe: true})
		require.ErrorIs(t, p.client.Renew(context.Background()), errors.ErrSecureChannelClosed)
		require.ErrorIs(t, p.client.SendRequest(context.Background(), covReadRequest(1), nil, nil), errors.ErrSecureChannelClosed)
		require.ErrorIs(t, p.server.SendResponseWithContext(context.Background(), 1, readResponse(covReadRequest(1))), errors.ErrSecureChannelClosed)
		require.ErrorIs(t, p.server.SendMsgWithContext(context.Background(), nil, 1, readResponse(covReadRequest(1))), errors.ErrSecureChannelClosed)
	})
}

// covServerOPN returns an OpenSecureChannel response for the client's first
// request, secured by the server of the policy.
func covServerOPN(t *testing.T, pol covPolicy, resp *ua.OpenSecureChannelResponse, tamper bool) []byte {
	t.Helper()
	if pol.mode == ua.MessageSecurityModeNone {
		return covOPNChunk(t, pol.uri, 1, resp)
	}
	cid, sid := covIdentities(t, pol)
	algo, err := uapolicy.AsymmetricKeys(pol.uri, sid.key, cid.key.Public())
	require.NoError(t, err)
	inst := &channelInstance{
		sc:   &SecureChannel{cfg: &Config{SecurityPolicyURI: pol.uri, SecurityMode: pol.mode, Logger: testLogger}},
		algo: algo,
	}
	m := opnMessage(inst, pol.uri, sid.cert, cid.cert, resp, id.OpenSecureChannelResponseEncodingDefaultBinary)
	m.SecureChannelID = 7
	b, err := m.Encode()
	require.NoError(t, err)
	b, err = inst.signAndEncrypt(m, b)
	require.NoError(t, err)
	if tamper {
		b[len(b)-1] ^= 0xff
	}
	return b
}

// TestClientOpen_Responses answers the client's OpenSecureChannel request
// with responses it has to refuse, and with one it has to correct.
func TestClientOpen_Responses(t *testing.T) {
	good := func(lifetime uint32, nonce []byte) *ua.OpenSecureChannelResponse {
		return &ua.OpenSecureChannelResponse{
			ResponseHeader: covRespHeader(ua.StatusOK),
			SecurityToken:  &ua.ChannelSecurityToken{ChannelID: 7, TokenID: 3, CreatedAt: time.Now(), RevisedLifetime: lifetime},
			ServerNonce:    nonce,
		}
	}
	nonce := make([]byte, 32)
	tests := []struct {
		name  string
		pol   covPolicy
		reply func(t *testing.T) []byte
		want  error
	}{
		{
			name: "another policy",
			pol:  covNone,
			reply: func(t *testing.T) []byte {
				return covOPNChunk(t, ua.SecurityPolicyURIBasic256Sha256, 1, good(60_000, nil))
			},
			want: ua.StatusBadSecurityPolicyRejected,
		},
		{
			name: "not an OpenSecureChannel response",
			pol:  covNone,
			reply: func(t *testing.T) []byte {
				return covOPNChunk(t, ua.SecurityPolicyURINone, 1, readResponse(covReadRequest(1)))
			},
			want: errors.ErrInvalidResponseType,
		},
		{
			name:  "no server nonce",
			pol:   covRSA,
			reply: func(t *testing.T) []byte { return covServerOPN(t, covRSA, good(60_000, nil), false) },
			want:  ua.StatusBadNonceInvalid,
		},
		{
			name:  "bad signature",
			pol:   covRSASign,
			reply: func(t *testing.T) []byte { return covServerOPN(t, covRSASign, good(60_000, nonce), true) },
			want:  ua.StatusBadSecurityChecksFailed,
		},
		{
			name:  "signed by the server",
			pol:   covRSASign,
			reply: func(t *testing.T) []byte { return covServerOPN(t, covRSASign, good(60_000, nonce), false) },
		},
		{
			name: "longer lifetime than asked for",
			pol:  covNone,
			reply: func(t *testing.T) []byte {
				return covServerOPN(t, covNone, good(3_600_000, nil), false)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newCovPair(t, tt.pol, covOpts{noOpen: true, noServe: true})
			opened := make(chan error, 1)
			go func() { opened <- p.client.Open(context.Background()) }()
			_, err := p.serverConn.Receive() // the request
			require.NoError(t, err)
			_, err = p.serverConn.Write(tt.reply(t))
			require.NoError(t, err)
			err = result(t, opened)
			if tt.want != nil {
				require.ErrorIs(t, err, tt.want)
				c, _ := token(p.client)
				require.Zero(t, c, "the channel is not open")
				return
			}
			require.NoError(t, err)
			c, tok := token(p.client)
			require.EqualValues(t, 7, c)
			require.EqualValues(t, 3, tok)
			act := p.client.activeInstanceOrNil()
			require.Equal(t, 60*time.Second, act.revisedLifetime, "the client keeps to the lifetime it asked for")
		})
	}
}

// TestRequest_SendFailures covers requests that cannot be sent. None of them
// may leave a handler behind or use up a sequence number: on a secured
// channel the server refuses every chunk after a gap.
func TestRequest_SendFailures(t *testing.T) {
	unencodable := &ua.AddNodesRequest{NodesToAdd: []*ua.AddNodesItem{{}}} // nil ExpandedNodeIDs
	for _, pol := range []covPolicy{covRSA, covAEAD} {
		t.Run(pol.name, func(t *testing.T) {
			p := newCovPair(t, pol, covOpts{})
			ignore := func(ua.Response) error { return nil }

			err := p.client.SendRequest(context.Background(), &covUnknownRequest{}, nil, ignore)
			require.ErrorIs(t, err, errors.ErrUnknownService)
			p.read(t, 1)

			err = p.client.SendRequest(context.Background(), unencodable, nil, ignore)
			require.Error(t, err)
			p.read(t, 1) // no sequence number is missing
			require.Zero(t, p.handlerCount())

			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			require.ErrorIs(t, p.tryRead(ctx, 1), context.Canceled)
			require.Zero(t, p.handlerCount())
			p.read(t, 1)

			// Cancelled after the first of several chunks.
			require.ErrorIs(t, p.tryRead(&cancelAfter{Context: context.Background(), after: 1}, 8000), context.Canceled)
			require.Zero(t, p.handlerCount())
			p.read(t, 1)

			// Two requests with the same id.
			act := p.client.activeInstanceOrNil()
			reqID := p.client.nextRequestID()
			ch, err := p.client.sendAsyncWithTimeout(context.Background(), covReadRequest(1), reqID, act, nil, true, time.Minute)
			require.NoError(t, err)
			_, err = p.client.sendAsyncWithTimeout(context.Background(), covReadRequest(1), reqID, act, nil, true, time.Minute)
			require.ErrorIs(t, err, errors.ErrDuplicateHandler)
			select {
			case msg := <-ch:
				require.NoError(t, msg.Err)
				require.IsType(t, &ua.ReadResponse{}, msg.Response())
			case <-time.After(covWait):
				t.Fatal("no response to the first request")
			}
			p.read(t, 1)

			// No response wanted.
			require.NoError(t, p.client.SendRequest(context.Background(), covReadRequest(1), nil, nil))
			p.read(t, 1)
		})
	}
}

// TestRequest_ConnectionClosed sends a request over a connection that is gone.
func TestRequest_ConnectionClosed(t *testing.T) {
	p := newCovPair(t, covNone, covOpts{})
	require.NoError(t, p.clientConn.Close())
	require.ErrorIs(t, p.tryRead(context.Background(), 1), net.ErrClosed)
	require.Zero(t, p.handlerCount())
}

// TestRequest_Timeout waits for a response that does not come.
func TestRequest_Timeout(t *testing.T) {
	ids := make(chan uint32, 1)
	p := newCovPair(t, covNone, covOpts{handle: holdRequests(ids)})
	err := p.client.SendRequestWithTimeout(context.Background(), covReadRequest(1), nil, time.Millisecond, func(ua.Response) error { return nil })
	require.ErrorIs(t, err, ua.StatusBadTimeout)
	recv(t, ids)
	require.Zero(t, p.handlerCount())
}

// covUnknownRequest is a request of a type no service is registered for.
type covUnknownRequest struct{ ua.ReadRequest }

// covUnknownResponse is a response of a type no service is registered for.
type covUnknownResponse struct{ ua.ReadResponse }

// cancelAfter is a context that is done after its Done method has been
// called a number of times: it ends while a message is being sent.
type cancelAfter struct {
	context.Context
	after, calls int
}

var closedCh = func() chan struct{} { c := make(chan struct{}); close(c); return c }()

func (c *cancelAfter) Done() <-chan struct{} {
	c.calls++
	if c.calls > c.after {
		return closedCh
	}
	return nil
}

func (c *cancelAfter) Err() error {
	if c.calls > c.after {
		return context.Canceled
	}
	return nil
}

// TestResponse_SendFailures covers responses a server channel cannot send.
// Like requests, they must not use up a sequence number.
func TestResponse_SendFailures(t *testing.T) {
	ids := make(chan uint32, 8)
	p := newCovPair(t, covRSA, covOpts{handle: holdRequests(ids)})
	bad := &ua.BrowseResponse{ResponseHeader: covRespHeader(ua.StatusOK), Results: []*ua.BrowseResult{{
		References: []*ua.ReferenceDescription{{ReferenceTypeID: ua.NewNumericNodeID(0, 1), BrowseName: &ua.QualifiedName{}, DisplayName: &ua.LocalizedText{}}},
	}}}
	answer := func(send func(reqID uint32) error) {
		t.Helper()
		pending := p.asyncRead(context.Background(), 1)
		require.NoError(t, send(recv(t, ids)))
		require.NoError(t, result(t, pending))
	}
	resp := readResponse(covReadRequest(1))
	ctx := context.Background()

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	require.ErrorIs(t, p.server.SendResponseWithContext(cancelled, 1, resp), context.Canceled)
	require.ErrorIs(t, p.server.SendResponseWithContext(ctx, 1, &covUnknownResponse{}), errors.ErrUnknownService)
	require.ErrorIs(t, p.server.SendMsgWithContext(ctx, nil, 1, &covUnknownResponse{}), errors.ErrUnknownService)
	require.Error(t, p.server.SendResponseWithContext(ctx, 1, bad))
	require.Error(t, p.server.SendMsgWithContext(ctx, nil, 1, bad))
	answer(func(reqID uint32) error { return p.server.SendResponseWithContext(ctx, reqID, resp) })

	// With a deadline for the write.
	deadline, cancelDeadline := context.WithTimeout(ctx, time.Minute)
	defer cancelDeadline()
	answer(func(reqID uint32) error { return p.server.SendResponseWithContext(deadline, reqID, resp) })

	// Through SendMsgWithContext.
	answer(func(reqID uint32) error { return p.server.SendMsgWithContext(ctx, nil, reqID, resp) })

	// Cancelled after the first of several chunks: the client never gets
	// the rest, and the sequence numbers go on from the chunk that was sent.
	err := p.server.SendResponseWithContext(&cancelAfter{Context: ctx, after: 2}, 0xABC, readResponse(covReadRequest(8000)))
	require.ErrorIs(t, err, context.Canceled)
	answer(func(reqID uint32) error { return p.server.SendResponseWithContext(ctx, reqID, resp) })

	// The connection is gone.
	require.NoError(t, p.serverConn.Close())
	require.ErrorIs(t, p.server.SendResponseWithContext(ctx, 1, resp), net.ErrClosed)
	require.ErrorIs(t, p.server.SendMsgWithContext(ctx, nil, 1, resp), net.ErrClosed)
}

// TestClose_AfterPeerClosed closes a channel whose connection the server has
// closed already: there is nothing left to send.
func TestClose_AfterPeerClosed(t *testing.T) {
	p := newCovPair(t, covNone, covOpts{})
	require.NoError(t, p.serverConn.Close())
	select {
	case <-p.client.disconnected:
	case <-time.After(covWait):
		t.Fatal("the client did not notice")
	}
	waitFor(t, p.clientErrs, io.EOF)
	require.ErrorIs(t, p.client.Close(), io.EOF)
	require.ErrorIs(t, p.client.Close(), io.EOF, "closing twice")
}

// TestClose_DuringRenewal closes a channel while a token renewal waits for the
// server: Close does not wait for the renewal, and the renewal fails.
func TestClose_DuringRenewal(t *testing.T) {
	release := make(chan struct{})
	ids := make(chan uint32, 1)
	p := newCovPair(t, covNone, covOpts{handle: func(_ *covPair, msg *MessageBody) bool {
		ids <- msg.RequestID
		<-release // the server stops reading
		return true
	}})
	defer close(release)
	require.NoError(t, p.client.SendRequest(context.Background(), covReadRequest(1), nil, nil))
	recv(t, ids)

	renewed := make(chan error, 1)
	go func() { renewed <- p.client.Renew(context.Background()) }()
	require.Eventually(t, func() bool {
		if p.client.sendGate.TryRLock() {
			p.client.sendGate.RUnlock()
			return false
		}
		return true
	}, covWait, time.Millisecond, "the renewal holds the gate")

	require.ErrorIs(t, p.client.Close(), io.EOF)
	require.Error(t, result(t, renewed))
}
