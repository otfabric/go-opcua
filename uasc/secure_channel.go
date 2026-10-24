// SPDX-License-Identifier: MIT

package uasc

import (
	"context"
	"crypto"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/otfabric/go-opcua/uapolicy"
)

const (
	timeoutLeniency = 250 * time.Millisecond
	MaxTimeout      = math.MaxUint32 * time.Millisecond
)

type channelKind int

const (
	client channelKind = iota
	server
)

// ResponseHandler handles the response of a service request and
// is used by the client.
type ResponseHandler func(ua.Response) error

// MessageBody is the content of a secure channel message sent
// between a client and a server and represents a service
// request or response.
type MessageBody struct {
	RequestID       uint32
	SecureChannelID uint32
	Err             error

	body any
}

func (b MessageBody) Request() ua.Request {
	if x, ok := b.body.(ua.Request); ok {
		return x
	}
	return nil
}

func (b MessageBody) Response() ua.Response {
	if x, ok := b.body.(ua.Response); ok {
		return x
	}
	return nil
}

type SecureChannel struct {
	endpointURL string

	// c is the uacp connection
	c *uacp.Conn

	// cfg is the configuration for the secure channel.
	cfg *Config

	// time returns the current time. When not set it defaults to time.Now().
	time func() time.Time

	// closing is channel used to indicate to go routines that the secure channel is closing
	closing      chan struct{}
	disconnected chan struct{}

	// startDispatcher ensures only one dispatcher is running
	startDispatcher sync.Once

	// requestID is a "global" counter shared between multiple channels and tokens
	requestID   uint32
	requestIDMu sync.Mutex

	// instances maps secure channel IDs to a list to channel states
	instances      map[uint32][]*channelInstance
	activeInstance *channelInstance
	instancesMu    sync.Mutex

	// maxLifetime is the longest SecurityToken lifetime (ms) a server channel
	// grants; captured from the configured lifetime on the first open.
	maxLifetime uint32

	// sendGate keeps requests and token renewal apart: every request holds
	// the read side while it is written to the connection and a renewal
	// holds the write side. A renewal therefore starts only when no request
	// is half-way out, and no request picks a channel instance while the
	// token is being replaced.
	sendGate sync.RWMutex

	// openWaitCh is closed by the open() call that sent request openWaitID
	// when it returns. The dispatcher waits for it after forwarding the
	// OpenSecureChannelResponse to that request, so that no new messages
	// are read while the channel's crypto state is being updated. It is
	// nil while no open() is waiting for a response.
	//
	// The wait belongs to one request: an open() that ended without a
	// response (timeout, cancellation) must not release the dispatcher
	// early when the response of a later open() arrives.
	openWaitMu sync.Mutex
	openWaitID uint32
	openWaitCh chan struct{}

	// handlers maps request ids to the requests waiting for their response
	handlers   map[uint32]pendingRequest
	handlersMu sync.Mutex

	// chunks maintains a temporary list of chunks for a given request ID
	chunks   map[uint32][]*MessageChunk
	chunksMu sync.Mutex

	// openingInstance is a temporary var that allows the dispatcher know how to handle a open channel request
	// note: we only allow a single "open" request in flight at any point in time. The mutex is held for the entire
	// duration of the "open" request.
	//
	// On a client open() sets and clears it while the dispatcher looks at
	// it for every OpenSecureChannel message it receives, solicited or
	// not: both go through opening() and setOpening().
	openingInstance   *channelInstance
	openingMu         sync.Mutex
	openingInstanceMu sync.Mutex

	// errorCh receive dispatcher errors
	errch chan<- error

	// required for the server channel

	// // secureChannelID is a unique identifier for the SecureChannel assigned by the Server.
	// // If a Server receives a SecureChannelId which it does not recognize it shall return an
	// // appropriate transport layer error.
	// //
	// // When a Server starts the first SecureChannelId used should be a value that is likely to
	// // be unique after each restart. This ensures that a Server restart does not cause
	// // previously connected Clients to accidentally ‘reuse’ SecureChannels that did not belong
	// // to them.
	// secureChannelID uint32

	// // sequenceNumber is a monotonically increasing sequence number assigned by the sender to each
	// // MessageChunk sent over the SecureChannel.
	// sequenceNumber uint32

	// // securityTokenID is a unique identifier for the SecureChannel SecurityToken used to secure the Message.
	// // This identifier is returned by the Server in an OpenSecureChannel response Message.
	// // If a Server receives a TokenId which it does not recognize it shall return an appropriate
	// // transport layer error.
	// securityTokenID uint32

	// kind indicates whether this is a server or a client channel.
	kind channelKind

	// peerCert is the certificate a client opened this (server) channel
	// with. It is kept apart from cfg so that it can be read while the
	// channel is in use.
	peerCert atomic.Pointer[[]byte]

	// lastReceivedSequenceNumber is the sequence number of the chunk that
	// was received last. The policies with authenticated encryption need it
	// to open the next chunk.
	lastReceivedSequenceNumber atomic.Uint32

	// receivedAny is set once the first chunk has been received: from then
	// on the sequence numbers of a secured channel have to be contiguous.
	// Only the goroutine that reads the chunks uses it.
	receivedAny bool

	// binding and keyChain are the state of the SecureChannelEnhancements
	// of OPC UA 1.05.07 (see channel_binding.go). keyChain is the key
	// material the next renewal is chained to; only the goroutine that
	// handles OpenSecureChannel messages uses it.
	binding  channelBinding
	keyChain []byte

	closeOnce sync.Once
}

func NewSecureChannel(endpoint string, c *uacp.Conn, cfg *Config, errCh chan<- error) (*SecureChannel, error) {
	return newSecureChannel(endpoint, c, cfg, client, errCh)
}

// NewCryptoChannel returns a SecureChannel that can exercise the session and
// user-token cryptographic helpers without an underlying UACP connection.
// It must not be used for Open/SendRequest.
func NewCryptoChannel(cfg *Config) *SecureChannel {
	if cfg == nil {
		panic("uasc: NewCryptoChannel: cfg is nil")
	}
	return &SecureChannel{cfg: cfg}
}

func NewServerSecureChannel(endpoint string, c *uacp.Conn, cfg *Config, errCh chan<- error, secureChannelID, sequenceNumber, securityTokenID uint32) (*SecureChannel, error) {
	s, err := newSecureChannel(endpoint, c, cfg, server, errCh)
	if err != nil {
		return nil, err
	}

	s.openingInstance = newChannelInstance(s)
	s.openingInstance.secureChannelID = secureChannelID
	s.openingInstance.sequenceNumber = sequenceNumber
	s.openingInstance.securityTokenID = securityTokenID

	return s, nil
}

func newSecureChannel(endpoint string, c *uacp.Conn, cfg *Config, kind channelKind, errCh chan<- error) (*SecureChannel, error) {
	if c == nil {
		return nil, errors.ErrNotConnected
	}

	if cfg == nil {
		return nil, fmt.Errorf("%w: no secure channel config", errors.ErrInvalidSecurityConfig)
	}

	if errCh == nil {
		return nil, fmt.Errorf("%w: no error channel", errors.ErrInvalidState)
	}

	switch {
	case cfg.SecurityPolicyURI == ua.SecurityPolicyURINone && cfg.SecurityMode != ua.MessageSecurityModeNone:
		return nil, fmt.Errorf("%w: policy '%s' cannot be used with '%s'", errors.ErrInvalidSecurityConfig, cfg.SecurityPolicyURI, cfg.SecurityMode)
	case cfg.SecurityPolicyURI != ua.SecurityPolicyURINone && (cfg.SecurityMode != ua.MessageSecurityModeSignAndEncrypt && cfg.SecurityMode != ua.MessageSecurityModeSign):
		return nil, fmt.Errorf("%w: policy '%s' can only be used with '%s' or '%s'", errors.ErrInvalidSecurityConfig, cfg.SecurityPolicyURI, ua.MessageSecurityModeSign, ua.MessageSecurityModeSignAndEncrypt)
	case cfg.SecurityPolicyURI != ua.SecurityPolicyURINone && cfg.localKey() == nil:
		return nil, fmt.Errorf("%w: policy '%s' requires a private key", errors.ErrInvalidSecurityConfig, cfg.SecurityPolicyURI)
	}
	// A client names its policy up front. Refuse one that is not implemented
	// here, by name: otherwise the first thing to fail is whatever the policy
	// needs and this library cannot do, such as parsing a server certificate
	// with a brainpool or Ed448 key ("x509: unsupported elliptic curve").
	if kind == client && !uapolicy.IsSupported(cfg.SecurityPolicyURI) {
		return nil, fmt.Errorf("%w: %s", errors.ErrUnsupportedSecurityPolicy, cfg.SecurityPolicyURI)
	}

	s := &SecureChannel{
		endpointURL:  endpoint,
		c:            c,
		cfg:          cfg,
		requestID:    cfg.RequestIDSeed,
		kind:         kind,
		errch:        errCh,
		closing:      make(chan struct{}),
		disconnected: make(chan struct{}),
		instances:    make(map[uint32][]*channelInstance),
		chunks:       make(map[uint32][]*MessageChunk),
		handlers:     make(map[uint32]pendingRequest),
	}

	return s, nil
}

func (s *SecureChannel) RemoteAddr() net.Addr {
	return s.c.RemoteAddr()
}

// SecurityMode returns the message security mode configured for this channel.
func (s *SecureChannel) SecurityMode() ua.MessageSecurityMode {
	return s.cfg.SecurityMode
}

// RemoteCertificate returns the DER encoded application instance certificate
// of the peer: on a server channel the certificate the client opened the
// channel with, on a client channel the configured server certificate. It is
// nil for a channel without security.
func (s *SecureChannel) RemoteCertificate() []byte {
	if p := s.peerCert.Load(); p != nil {
		return *p
	}
	return s.cfg.RemoteCertificate
}

// SecurityPolicyURI returns the security policy URI configured for this channel.
func (s *SecureChannel) SecurityPolicyURI() string {
	return s.cfg.SecurityPolicyURI
}

func (s *SecureChannel) getActiveChannelInstance() (*channelInstance, error) {
	s.instancesMu.Lock()
	defer s.instancesMu.Unlock()
	if s.activeInstance == nil {
		return nil, errors.ErrSecureChannelClosed
	}
	return s.activeInstance, nil
}

func (s *SecureChannel) dispatcher() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	defer func() {
		close(s.disconnected)
	}()

	for {
		select {
		case <-s.closing:
			return
		default:
			msg := s.Receive(ctx)
			if msg.Err != nil && s.notifyMonitor(msg) {
				select {
				case <-s.closing:
					return
				default:
					select {
					case s.errch <- s.monitorError(msg):
					default:
					}
				}
			}

			if msg.Err == io.EOF {
				return
			}

			if msg.Err != nil {
				s.cfg.Logger.Debug("error", "channel_id", s.c.ID(), "request_id", msg.RequestID, "error", msg.Err)

				ch, ok := s.popHandler(msg.RequestID)
				if !ok && msg.RequestID == 0 {
					// Connection-level error (e.g. OPC UA ERR message from the server)
					// carries no request ID. Broadcast it to all pending handlers so
					// callers receive the specific OPC UA status code rather than bare
					// io.EOF when the disconnected channel fires on the next loop.
					s.handlersMu.Lock()
					pending := make(map[uint32]chan *MessageBody, len(s.handlers))
					for id, h := range s.handlers {
						pending[id] = h.ch
						delete(s.handlers, id)
					}
					s.handlersMu.Unlock()
					for _, hch := range pending {
						select {
						case hch <- msg:
						default:
						}
					}
				} else if ok {
					select {
					case ch <- msg:
					default:
					}
				}
				continue
			} else {
				s.cfg.Logger.Debug("received", "channel_id", s.c.ID(), "request_id", msg.RequestID, "type", fmt.Sprintf("%T", msg.body))
			}

			ch, ok := s.popHandler(msg.RequestID)

			if !ok {
				s.cfg.Logger.Debug("no handler", "channel_id", s.c.ID(), "request_id", msg.RequestID, "type", fmt.Sprintf("%T", msg.body))
				continue
			}

			// Track whether the dispatcher needs to wait for open() to
			// finish updating the crypto state before reading the next message.
			isOpenResp := false
			if _, ok := msg.Response().(*ua.OpenSecureChannelResponse); ok {
				isOpenResp = true
			}

			s.cfg.Logger.Debug("sending to handler", "channel_id", s.c.ID(), "request_id", msg.RequestID, "type", fmt.Sprintf("%T", msg.body))
			select {
			case ch <- msg:
			default:
				// this should never happen since the chan is of size one
				s.cfg.Logger.Warn("unexpected state: channel write should always succeed", "channel_id", s.c.ID(), "request_id", msg.RequestID)
			}

			if isOpenResp {
				// Wait for the open() that sent this request to finish
				// updating the channel's crypto state. If it is gone
				// already there is nothing to wait for.
				if done := s.openWait(msg.RequestID); done != nil {
					select {
					case <-done:
					case <-s.closing:
						return
					}
				}
			}
		}
	}
}

// notifyMonitor reports whether a failed message should be forwarded to the
// connection monitor (via errch) to drive reconnection.
//
// Connection- and transport-level failures (no decoded response body, e.g.
// io.EOF, decode errors, message-abort) are always forwarded. A message that
// carries a fully decoded response is an operation-level ServiceFault: it is
// returned to the waiting caller and must NOT tear down the channel, unless the
// fault indicates that the secure channel, session, or subscriptions must be
// recreated (which only the monitor can do).
func (s *SecureChannel) notifyMonitor(msg *MessageBody) bool {
	if msg.Response() == nil {
		return true
	}
	return isReconnectTrigger(msg.Err)
}

// RequestFault is how the secure channel reports a service fault that asks
// for recovery (an invalid session or subscription) to its error channel:
// the fault, and the authentication token of the request it answers. A
// session fault is only news about the session the request was sent in; the
// receiver can tell a fault of a session it has left from one of the session
// it uses.
type RequestFault struct {
	Err error
	// AuthToken is the authentication token the request was sent with, nil
	// for a request outside a session.
	AuthToken *ua.NodeID
}

func (f *RequestFault) Error() string { return f.Err.Error() }
func (f *RequestFault) Unwrap() error { return f.Err }

// monitorError is the error the dispatcher reports for a failed msg: a
// service fault as a RequestFault, anything else as it is.
func (s *SecureChannel) monitorError(msg *MessageBody) error {
	if msg.Response() == nil {
		return msg.Err
	}
	s.handlersMu.Lock()
	h := s.handlers[msg.RequestID]
	s.handlersMu.Unlock()
	return &RequestFault{Err: msg.Err, AuthToken: h.authToken}
}

// isReconnectTrigger reports whether a service-level fault requires the secure
// channel, session, or subscriptions to be recreated. These are the status
// codes the client's connection monitor acts on; every other operation-level
// fault is delivered to the caller without disturbing the connection.
// BadNoSubscription is not one: only a Publish request gets it, and only the
// client's publish loop knows whether it is stale (a subscription was
// recreated while the request was under way).
func isReconnectTrigger(err error) bool {
	switch {
	case errors.Is(err, ua.StatusBadSecureChannelIDInvalid),
		errors.Is(err, ua.StatusBadSessionIDInvalid),
		errors.Is(err, ua.StatusBadSubscriptionIDInvalid),
		errors.Is(err, ua.StatusBadCertificateInvalid):
		return true
	default:
		return false
	}
}

// Receive receives message chunks from the secure channel, decodes and forwards
// them to the registered callback channel, if there is one. Otherwise,
// the message is dropped.
func (s *SecureChannel) Receive(ctx context.Context) *MessageBody {
	for {
		select {
		case <-ctx.Done():
			return &MessageBody{Err: ctx.Err()}

		default:
			chunk, err := s.readChunk()
			if err == io.EOF {
				s.cfg.Logger.Debug("read chunk EOF", "channel_id", s.c.ID())
				return &MessageBody{Err: err}
			}

			if err != nil {
				return &MessageBody{Err: err}
			}

			hdr := chunk.Header
			reqID := chunk.RequestID

			strdat := string(chunk.Data)
			if strings.Contains(strdat, "CurrentTime") {
				s.cfg.Logger.Debug("requested CurrentTime")
			}

			msg := &MessageBody{
				RequestID:       reqID,
				SecureChannelID: chunk.SecureChannelID,
			}

			s.cfg.Logger.Debug("recv", "channel_id", s.c.ID(), "request_id", reqID, "message_type", string(hdr.MessageType), "chunk_type", string([]byte{hdr.ChunkType}), "bytes", hdr.MessageSize)

			s.chunksMu.Lock()

			switch hdr.ChunkType {
			case 'A':
				delete(s.chunks, reqID)
				s.chunksMu.Unlock()

				msga := new(MessageAbort)
				if _, err := msga.Decode(chunk.Data); err != nil {
					s.cfg.Logger.Debug("invalid MSGA chunk", "channel_id", s.c.ID(), "request_id", reqID, "error", err)
					msg.Err = ua.StatusBadDecodingError
					return msg
				}

				return &MessageBody{RequestID: reqID, Err: ua.StatusCode(msga.ErrorCode)}

			case 'C':
				s.chunks[reqID] = append(s.chunks[reqID], chunk)
				if n := len(s.chunks[reqID]); uint32(n) > s.c.MaxChunkCount() {
					delete(s.chunks, reqID)
					s.chunksMu.Unlock()
					msg.Err = fmt.Errorf("%w: %d > %d", errors.ErrTooManyChunks, n, s.c.MaxChunkCount())
					return msg
				}
				s.chunksMu.Unlock()
				continue
			}

			// merge chunks
			all := append(s.chunks[reqID], chunk)
			delete(s.chunks, reqID)

			s.chunksMu.Unlock()

			b := mergeChunks(all)

			if uint32(len(b)) > s.c.MaxMessageSize() {
				msg.Err = fmt.Errorf("%w: %d > %d", errors.ErrMessageTooLarge, uint32(len(b)), s.c.MaxMessageSize())
				return msg
			}

			// The client dispatcher only receives responses so extracting
			// the error from the ResponseHeader is correct here. Server-side
			// request error handling lives in the server (Server.serve).
			//
			// Since we are not decoding the ResponseHeader separately
			// we need to drop every message that has an error since we
			// cannot get to the RequestHandle in the ResponseHeader.
			// To fix this we must a) decode the ResponseHeader separately
			// and subsequently remove it and the TypeID from all service
			// structs and tests. We also need to add a deadline to all
			// handlers and check them periodically to time them out.
			_, body, err := ua.DecodeService(b)
			if err != nil {
				msg.Err = err
				return msg
			}

			msg.body = body

			// Only server channels should process incoming
			// OpenSecureChannelRequests. A client receiving one is a
			// protocol error.
			if req, ok := msg.Request().(*ua.OpenSecureChannelRequest); ok {
				if s.kind != server {
					msg.Err = ua.StatusBadServiceUnsupported
					return msg
				}
				err := s.handleOpenSecureChannelRequest(reqID, req)
				if err != nil {
					s.cfg.Logger.Debug("handling failed", "channel_id", s.c.ID(), "request_id", reqID, "type", fmt.Sprintf("%T", req), "error", err)
					return &MessageBody{Err: err}
				}
				return &MessageBody{}
			}

			// If the service status is not OK then bubble
			// that error up to the caller.
			if resp := msg.Response(); resp != nil {
				if status := resp.Header().ServiceResult; status != ua.StatusOK {
					msg.Err = status
					return msg
				}
			}

			return msg
		}
	}
}

// opening returns the channel instance an OpenSecureChannel exchange is in
// progress for, or nil.
func (s *SecureChannel) opening() *channelInstance {
	s.openingInstanceMu.Lock()
	defer s.openingInstanceMu.Unlock()
	return s.openingInstance
}

func (s *SecureChannel) setOpening(instance *channelInstance) {
	s.openingInstanceMu.Lock()
	s.openingInstance = instance
	s.openingInstanceMu.Unlock()
}

// openWait returns the channel that is closed when the open() call that sent
// request reqID returns, or nil if that call is not waiting any more.
func (s *SecureChannel) openWait(reqID uint32) <-chan struct{} {
	s.openWaitMu.Lock()
	defer s.openWaitMu.Unlock()
	if s.openWaitCh == nil || s.openWaitID != reqID {
		return nil
	}
	return s.openWaitCh
}

func (s *SecureChannel) readChunk() (*MessageChunk, error) {
	// read a full message from the underlying conn.
	b, err := s.c.Receive()
	// Check for a uacp-level error (e.g. an ERR message from the server)
	// BEFORE the len(b)==0 guard. uacp.Receive returns (nil, *Error) for ERR
	// messages, so the nil slice would otherwise be misidentified as EOF.
	// do not wrap this error since it hides conn error
	var uacperr *uacp.Error
	if errors.As(err, &uacperr) {
		return nil, err
	}
	// A chunk the transport refused for its size is a protocol violation of
	// the peer, not the end of the stream: say so instead of reporting EOF.
	if errors.Is(err, errors.ErrMessageTooLarge) || errors.Is(err, errors.ErrMessageTooSmall) {
		return nil, fmt.Errorf("sechan: read chunk failed: %w", err)
	}
	if err == io.EOF || len(b) == 0 {
		return nil, io.EOF
	}
	if err != nil {
		return nil, fmt.Errorf("sechan: read header failed: %w", err)
	}

	const hdrlen = 12 // secure conversation header size
	// The transport layer only guarantees its own 8 byte header. A shorter
	// frame than the secure conversation header (a damaged size field, or a
	// hostile peer) must be rejected here: slicing it would panic and take
	// the whole process down.
	if len(b) < hdrlen {
		return nil, fmt.Errorf("sechan: chunk of %d bytes is shorter than its header: %w", len(b), ua.StatusBadDecodingError)
	}
	h := new(Header)
	if _, err := h.Decode(b[:hdrlen]); err != nil {
		return nil, fmt.Errorf("sechan: decode header failed: %w", err)
	}

	// decode the other headers
	m := new(MessageChunk)
	if _, err := m.Decode(b); err != nil {
		return nil, fmt.Errorf("sechan: decode chunk failed: %w", err)
	}

	var decryptWith *channelInstance

	switch m.MessageType {
	case "OPN":
		// Make sure we have a valid security header
		if m.AsymmetricSecurityHeader == nil {
			return nil, ua.StatusBadDecodingError // correct per Part 6 §6.7.2
		}

		opening := s.opening()
		if opening == nil {
			return nil, fmt.Errorf("%w: openingInstance is nil", errors.ErrInvalidState)
		}

		renewal := false
		if s.kind == server {
			renewing, err := s.beginServerRenewal(m)
			if err != nil {
				return nil, err
			}
			if renewing != nil {
				s.setOpening(renewing)
				opening = renewing
				renewal = true
			}
		}

		if s.kind == client {
			// A client knows which policy and server certificate it opened
			// the channel with; open() has prepared the opening instance
			// accordingly. The response must not rewrite that configuration:
			// it is shared by every later reconnect of the client, so a
			// single damaged (or forged) OpenSecureChannel response would
			// otherwise change the client's security settings for good and
			// could leave it unable to ever connect again.
			if m.SecurityPolicyURI != s.cfg.SecurityPolicyURI {
				return nil, ua.StatusBadSecurityPolicyRejected
			}
			decryptWith = opening
			break
		}

		// A renewal keeps the policy and the certificates of the channel
		// (beginServerRenewal has verified that it asks for the same). The
		// channel is in use then: the session services read its policy and
		// peer certificate from other goroutines, so they are only stored
		// when the channel is opened.
		//
		// The security policy decides how the sequence numbers of the
		// channel run. A renewal continues the numbering of the channel.
		if !renewal {
			s.cfg.SecurityPolicyURI = m.SecurityPolicyURI
			opening.zeroBasedSeq = !uapolicy.LegacySequenceNumbers(m.SecurityPolicyURI)
			opening.seqStarted = false
		}
		if m.SecurityPolicyURI != ua.SecurityPolicyURINone {
			// A server with certificates of several key types answers with
			// the one that fits the policy the client asks for.
			if !renewal && s.cfg.LocalIdentity != nil {
				cert, key, err := s.cfg.LocalIdentity(m.SecurityPolicyURI)
				if err != nil {
					s.cfg.Logger.Warn("no application instance certificate for the security policy", "channel_id", s.c.ID(), "policy", m.SecurityPolicyURI, "error", err)
					s.c.SendError(ua.StatusBadSecurityPolicyRejected)
					return nil, ua.StatusBadSecurityPolicyRejected
				}
				s.cfg.Certificate = cert
				s.cfg.LocalPrivateKey = key
			}
			if !renewal {
				s.cfg.RemoteCertificate = m.SenderCertificate
				peer := m.SenderCertificate
				s.peerCert.Store(&peer)
				// Record the client's certificate thumbprint so the OPN response we
				// send back carries a correct ReceiverCertificateThumbprint. Strict
				// clients (UaExpert, Prosys) reject encrypted channels otherwise.
				s.cfg.Thumbprint = uapolicy.Thumbprint(m.SenderCertificate)
			}
			s.cfg.Logger.Debug("setting securityPolicy", "channel_id", s.c.ID(), "policy", m.SecurityPolicyURI)

			remoteKey, err := uapolicy.CertificatePublicKey(s.cfg.RemoteCertificate)
			if err != nil {
				return nil, err
			}
			// This is also where a certificate of the wrong key type for the
			// policy is turned away: an RSA certificate on an ECC policy, or
			// a curve the policy does not permit.
			algo, err := uapolicy.AsymmetricKeys(s.cfg.SecurityPolicyURI, s.cfg.localKey(), remoteKey)
			if err != nil {
				return nil, err
			}

			opening.algo = algo
		}

		decryptWith = opening
	case "CLO":
		return nil, io.EOF
	case "MSG":
		// noop
	default:
		return nil, fmt.Errorf("%w: %s", errors.ErrInvalidMessageType, m.MessageType)
	}

	// Decrypt the block and put data back into m.Data
	m.Data, err = s.verifyAndDecrypt(m, b, decryptWith)
	if err != nil {
		return nil, err
	}

	n, err := m.SequenceHeader.Decode(m.Data)
	if err != nil {
		return nil, fmt.Errorf("sechan: decode sequence header failed: %w", err)
	}
	m.Data = m.Data[n:]
	if err := s.checkSequenceNumber(m.SequenceNumber); err != nil {
		return nil, err
	}
	s.receivedAny = true
	s.lastReceivedSequenceNumber.Store(m.SequenceNumber)

	return m, nil
}

// checkSequenceNumber verifies that a chunk which passed the security checks
// is the one that follows the chunk received before it (Part 6 §6.7.2.4).
//
// The signature of a chunk does not tell whether the chunk was seen before,
// whether one before it is missing, or whether it is out of order: without
// this check an attacker on the path can repeat a request and have it
// executed again, or take a chunk out of a multi-chunk message. The policies
// with authenticated encryption derive the nonce of a chunk from the
// sequence number expected for it, so they reject such a chunk already; for
// all other secured channels this is the check.
//
// A channel without security has no protection against any of this, and its
// sequence numbers are not verified: peers that do not keep them contiguous
// keep working.
func (s *SecureChannel) checkSequenceNumber(got uint32) error {
	if !s.receivedAny || s.cfg.SecurityMode == ua.MessageSecurityModeNone {
		return nil
	}
	last := s.lastReceivedSequenceNumber.Load()
	if got == last+1 {
		// For the ECC policies this includes the wrap from UInt32.MaxValue
		// to 0.
		return nil
	}
	// The original rules let the sender wrap anywhere in the last 1024
	// numbers, to a number below 1024.
	if uapolicy.LegacySequenceNumbers(s.cfg.SecurityPolicyURI) && last >= math.MaxUint32-1024 && got < 1024 {
		return nil
	}
	return fmt.Errorf("sechan: sequence number %d after %d: %w", got, last, ua.StatusBadSequenceNumberInvalid)
}

// verifyAndDecrypt verifies and optionally decrypts a message. if `instance` is given, then it will only use that
// state. Otherwise it will look up states by channel ID and try each.
func (s *SecureChannel) verifyAndDecrypt(m *MessageChunk, b []byte, instance *channelInstance) ([]byte, error) {
	if instance != nil {
		return instance.verifyAndDecrypt(m, b)
	}

	instances := s.getInstancesBySecureChannelID(m.SecureChannelID)
	if len(instances) == 0 {
		return nil, fmt.Errorf("%w: SecureChannelID=%d", errors.ErrInvalidState, m.SecureChannelID)
	}

	var (
		err      error
		verified []byte
	)

	// Prefer the token named in the symmetric header; fall back to the other
	// known tokens (newest first) for peers that do not rotate TokenIds.
	if m.SymmetricSecurityHeader != nil {
		for i := len(instances) - 1; i >= 0; i-- {
			if instances[i].securityTokenID != m.TokenID {
				continue
			}
			if verified, err = instances[i].verifyAndDecrypt(m, b); err == nil {
				return verified, nil
			}
		}
	}

	for i := len(instances) - 1; i >= 0; i-- {
		if m.SymmetricSecurityHeader != nil && instances[i].securityTokenID == m.TokenID {
			continue
		}
		if verified, err = instances[i].verifyAndDecrypt(m, b); err == nil {
			return verified, nil
		}
		s.cfg.Logger.Debug("attempting older channel state", "channel_id", s.c.ID())
	}

	if err == nil {
		err = ua.StatusBadSecureChannelTokenUnknown
	}
	return nil, err
}

func (s *SecureChannel) getInstancesBySecureChannelID(id uint32) []*channelInstance {
	s.instancesMu.Lock()
	defer s.instancesMu.Unlock()

	instances := s.instances[id]
	if len(instances) == 0 {
		return nil
	}

	// return a copy of the slice in case a renewal is triggered
	cpy := make([]*channelInstance, len(instances))
	copy(cpy, instances)

	return cpy
}

func (s *SecureChannel) LocalEndpoint() string {
	return s.endpointURL
}

func (s *SecureChannel) Open(ctx context.Context) error {
	return s.open(ctx, nil, ua.SecurityTokenRequestTypeIssue)
}

func (s *SecureChannel) open(ctx context.Context, instance *channelInstance, requestType ua.SecurityTokenRequestType) error {
	s.cfg.Logger.Debug("opening secure channel")

	// Tell the dispatcher that open() has finished processing the
	// OpenSecureChannelResponse, allowing it to resume reading messages.
	done := make(chan struct{})
	defer func() {
		s.openWaitMu.Lock()
		if s.openWaitCh == done {
			s.openWaitCh = nil
		}
		s.openWaitMu.Unlock()
		close(done)
	}()

	s.openingMu.Lock()
	defer s.openingMu.Unlock()

	if s.opening() != nil {
		return fmt.Errorf("%w: openingInstance must be nil when opening a new secure channel", errors.ErrInvalidState)
	}

	var (
		err       error
		localKey  crypto.PrivateKey
		remoteKey crypto.PublicKey
	)

	s.startDispatcher.Do(func() {
		go s.dispatcher()
	})

	// Set the encryption methods to Asymmetric with the appropriate
	// public keys.  OpenSecureChannel is always encrypted with the
	// asymmetric algorithms.
	// The default value of the encryption algorithm method is the
	// SecurityModeNone so no additional work is required for that case
	if s.cfg.SecurityMode != ua.MessageSecurityModeNone {
		localKey = s.cfg.localKey()
		var err error
		if remoteKey, err = uapolicy.CertificatePublicKey(s.cfg.RemoteCertificate); err != nil {
			return err
		}
	}

	algo, err := uapolicy.AsymmetricKeys(s.cfg.SecurityPolicyURI, localKey, remoteKey)
	if err != nil {
		return err
	}

	// The client's half of the key negotiation: a random nonce for the RSA
	// policies, a fresh ephemeral public key for the ECC ones. Renewals
	// negotiate from scratch.
	kx, err := uapolicy.NewKeyExchange(s.cfg.SecurityPolicyURI, uapolicy.RoleClient)
	if err != nil {
		return err
	}

	opening := newChannelInstance(s)
	opening.zeroBasedSeq = !uapolicy.LegacySequenceNumbers(s.cfg.SecurityPolicyURI)

	if requestType == ua.SecurityTokenRequestTypeRenew {
		// Safe: renew() holds the write side of sendGate, so no request is
		// being sent, and it holds instance.Lock().
		// Snapshot the current sequence number and bump the source so
		// the value is never reused if the old instance is briefly active
		// during the OpenSecureChannel round-trip.
		opening.sequenceNumber = instance.sequenceNumber
		opening.seqStarted = instance.seqStarted
		instance.sequenceNumber++
		opening.secureChannelID = instance.secureChannelID
	}
	opening.algo = algo
	opening.SetMaximumBodySize(int(s.c.SendBufSize()))
	s.setOpening(opening)

	// trigger cleanup after we are all done
	defer func() {
		if opening.state != channelActive {
			s.cfg.Logger.Warn("failed to open a new secure channel", "channel_id", s.c.ID())
		}
		s.setOpening(nil)
	}()

	reqID := s.nextRequestID()
	s.openWaitMu.Lock()
	s.openWaitID, s.openWaitCh = reqID, done
	s.openWaitMu.Unlock()

	req := &ua.OpenSecureChannelRequest{
		ClientProtocolVersion: 0,
		RequestType:           requestType,
		SecurityMode:          s.cfg.SecurityMode,
		ClientNonce:           kx.Nonce(),
		RequestedLifetime:     s.cfg.Lifetime,
	}

	return s.sendRequestWithTimeout(ctx, req, reqID, opening, nil, s.cfg.RequestTimeout, func(v ua.Response) error {
		s.cfg.Logger.Debug("handling OpenSecureChannelResponse")
		resp, ok := v.(*ua.OpenSecureChannelResponse)
		if !ok {
			return fmt.Errorf("%w: got %T", errors.ErrInvalidResponseType, v)
		}
		return s.handleOpenSecureChannelResponse(resp, kx, opening)
	})
}

func (s *SecureChannel) handleOpenSecureChannelResponse(resp *ua.OpenSecureChannelResponse, kx *uapolicy.KeyExchange, instance *channelInstance) (err error) {
	s.cfg.Logger.Debug("handling OpenSecureChannelResponse")
	instance.state = channelActive
	instance.secureChannelID = resp.SecurityToken.ChannelID
	instance.securityTokenID = resp.SecurityToken.TokenID
	instance.createdAt = resp.SecurityToken.CreatedAt
	instance.revisedLifetime = time.Millisecond * time.Duration(resp.SecurityToken.RevisedLifetime)

	// allow the client to specify a lifetime that is smaller
	if int64(s.cfg.Lifetime) < int64(instance.revisedLifetime/time.Millisecond) {
		instance.revisedLifetime = time.Millisecond * time.Duration(s.cfg.Lifetime)
	}

	// For an ECC policy this validates the server's ephemeral public key and
	// runs the key agreement.
	// A renewal on a channel with SecureChannelEnhancements chains the new
	// keys to the ones in use.
	algo, keyChain, err := kx.SymmetricChained(resp.ServerNonce, s.keyChain)
	if err != nil {
		return fmt.Errorf("%w: %w", ua.StatusBadNonceInvalid, err)
	}
	instance.algo = algo
	s.keyChain = keyChain

	instance.SetMaximumBodySize(int(s.c.SendBufSize()))

	s.instancesMu.Lock()
	defer s.instancesMu.Unlock()

	s.installClientToken(instance)

	s.cfg.Logger.Debug("received security token", "channel_id", s.c.ID(), "secure_channel_id", instance.secureChannelID, "token_id", instance.securityTokenID, "created_at", instance.createdAt.Format(time.RFC3339), "lifetime", instance.revisedLifetime)

	// A client renews its token before it expires. Retiring superseded
	// tokens is set up by installClientToken above.
	if s.kind == client {
		go s.scheduleRenewal(instance)
	}

	return
}

func (s *SecureChannel) handleOpenSecureChannelRequest(reqID uint32, svc ua.Request) error {
	s.cfg.Logger.Info("handling OpenSecureChannelRequest")

	var err error

	req, ok := svc.(*ua.OpenSecureChannelRequest)
	if !ok {
		s.cfg.Logger.Warn("expected OpenSecureChannelRequest", "got", fmt.Sprintf("%T", svc))
	}

	// Part 6 §6.7.4: ClientProtocolVersion must match the version
	// negotiated during the HELLO/ACK handshake.
	if req.ClientProtocolVersion != s.c.Version() {
		return ua.StatusBadProtocolVersionUnsupported
	}

	// Part 4 §5.5.2 says the AuthenticationToken of an OpenSecureChannel
	// request is null, but it carries no meaning for this service and
	// widely deployed stacks (open62541) send the session token along when
	// renewing. It is ignored rather than rejected: rejecting it tears down
	// the channel of an otherwise conformant client at its first renewal.

	revisedLifetime := s.reviseLifetime(req.RequestedLifetime)
	s.cfg.Lifetime = revisedLifetime
	// The security mode is chosen when the channel is opened and holds for
	// its whole life. A renewal that asks for another mode is refused: taking
	// it over would let whoever can send a renewal weaken (or change) the
	// protection of a channel that sessions are already bound to. Other
	// goroutines read the mode while they send responses, so it is written
	// only on the initial open, before the channel is in use.
	if err := s.acceptSecurityMode(req.SecurityMode); err != nil {
		s.cfg.Logger.Warn("OpenSecureChannel renewal with a different security mode refused",
			"channel_id", s.c.ID(), "mode", s.cfg.SecurityMode, "requested", req.SecurityMode)
		s.c.SendError(ua.StatusBadSecurityModeRejected)
		return err
	}

	// Reject untrusted client application certificates at channel open
	// (OPC UA application authentication), before issuing a SecurityToken.
	if s.cfg.ClientCertificateValidator != nil &&
		s.cfg.SecurityMode != ua.MessageSecurityModeNone &&
		len(s.cfg.RemoteCertificate) > 0 {
		if verr := s.cfg.ClientCertificateValidator(s.cfg.RemoteCertificate); verr != nil {
			sc := ua.StatusBadCertificateUntrusted
			if status, ok := verr.(ua.StatusCode); ok {
				sc = status
			}
			s.cfg.Logger.Warn("client certificate rejected at OpenSecureChannel", "error", verr)
			// Part 6 §6.7.2/§7.1.5: a failed OpenSecureChannel is reported with
			// a transport-level Error message, after which the connection is
			// closed. No SecurityToken has been issued yet, so a ServiceFault
			// secured with the (not yet established) symmetric keys could not
			// be decoded by the client.
			s.c.SendError(sc)
			return sc
		}
	}

	// I had to do the encryption setup in the chunk decoding logic because you have to
	// decrypt the thing before you even know you have an open message.
	// so this is redundant.
	var (
		localKey  crypto.PrivateKey
		remoteKey crypto.PublicKey
	)

	// Set the encryption methods to Asymmetric with the appropriate
	// public keys.  OpenSecureChannel is always encrypted with the
	// asymmetric algorithms.
	// The default value of the encryption algorithm method is the
	// SecurityModeNone so no additional work is required for that case
	if s.cfg.SecurityMode != ua.MessageSecurityModeNone {
		localKey = s.cfg.localKey()
		var err error
		if remoteKey, err = uapolicy.CertificatePublicKey(s.cfg.RemoteCertificate); err != nil {
			return err
		}
	}

	algo, err := uapolicy.AsymmetricKeys(s.cfg.SecurityPolicyURI, localKey, remoteKey)
	if err != nil {
		return err
	}

	// The server's half of the key negotiation. It is completed before the
	// response goes out: with an ECC policy the ClientNonce is an ephemeral
	// public key, and one that is not a valid point on the curve of the
	// policy must not get a SecurityToken.
	kx, err := uapolicy.NewKeyExchange(s.cfg.SecurityPolicyURI, uapolicy.RoleServer)
	if err != nil {
		return err
	}
	symmetric, keyChain, err := kx.SymmetricChained(req.ClientNonce, s.keyChain)
	if err != nil {
		s.cfg.Logger.Warn("OpenSecureChannel rejected: invalid client nonce", "channel_id", s.c.ID(), "error", err)
		s.c.SendError(ua.StatusBadNonceInvalid)
		return ua.StatusBadNonceInvalid
	}

	instance := s.openingInstance
	instance.algo = algo
	// The server echoes the client's RequestHandle for correlation. Under
	// requestIDMu: Close draws a request id from another goroutine.
	instance.sc.requestIDMu.Lock()
	instance.sc.requestID = req.RequestHeader.RequestHandle
	instance.sc.requestIDMu.Unlock()

	// Renewal: issue a new token on the same channel. The outgoing token's
	// send lock is held across the hand-over so sequence numbers stay
	// contiguous and nothing is secured with the old token after the renewal
	// response; senders blocked on it re-resolve the active instance once it
	// is released (see sendResponseWithContext).
	if outgoing := s.activeInstanceOrNil(); outgoing != nil && outgoing != instance {
		outgoing.Lock()
		defer outgoing.Unlock()
		instance.securityTokenID = outgoing.securityTokenID + 1
		instance.sequenceNumber = outgoing.sequenceNumber
		instance.zeroBasedSeq = outgoing.zeroBasedSeq
		instance.seqStarted = outgoing.seqStarted
	}

	nonce := kx.Nonce()
	resp := &ua.OpenSecureChannelResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          s.timeNow(),
			RequestHandle:      req.RequestHeader.RequestHandle,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		ServerProtocolVersion: s.c.Version(),
		SecurityToken: &ua.ChannelSecurityToken{
			ChannelID:       instance.secureChannelID,
			TokenID:         instance.securityTokenID,
			CreatedAt:       s.timeNow(),
			RevisedLifetime: revisedLifetime,
		},
		ServerNonce: nonce,
	}

	ctx := context.Background() // TODO(fs): thread request context from Receive path
	if err := s.sendResponseWithContext(ctx, instance, reqID, resp); err != nil {
		return err
	}

	instance.algo = symmetric
	s.keyChain = keyChain

	// Now that the symmetric algorithm is known, compute the maximum body size
	// per chunk from the negotiated send buffer so large responses (e.g. a
	// Browse of a big folder) are split into multiple chunks instead of
	// overflowing the client's receive buffer and dropping the connection.
	instance.SetMaximumBodySize(int(s.c.SendBufSize()))

	instance.state = channelActive // correct: per Part 6 §6.7.2, server considers channel open after sending response
	instance.createdAt = s.timeNow()
	instance.revisedLifetime = time.Duration(revisedLifetime) * time.Millisecond

	s.instancesMu.Lock()
	s.instances[instance.secureChannelID] = append(
		s.instances[instance.secureChannelID],
		instance,
	)
	s.activeInstance = instance
	s.scheduleServerTokenExpiry(instance)
	s.instancesMu.Unlock()

	return nil
}

func (s *SecureChannel) scheduleRenewal(instance *channelInstance) {
	// https://reference.opcfoundation.org/v104/Core/docs/Part4/5.5.2/#5.5.2.1
	// Clients should request a new SecurityToken after 75 % of its lifetime has elapsed. This should ensure that
	// clients will receive the new SecurityToken before the old one actually expire
	const renewAfter = 0.75
	// Computed on the duration itself. Rounding the lifetime down to whole
	// seconds first turns every lifetime below 1.34s into "renew now", and
	// the renewed token is renewed immediately again, in a tight loop.
	when := time.Duration(float64(instance.revisedLifetime) * renewAfter)

	s.cfg.Logger.Debug("security token refresh scheduled", "channel_id", s.c.ID(), "refresh_at", time.Now().UTC().Add(when).Format(time.RFC3339), "timeout", when, "secure_channel_id", instance.secureChannelID, "token_id", instance.securityTokenID)

	t := time.NewTimer(when)
	defer t.Stop()

	select {
	case <-s.closing:
		return
	case <-t.C:
	}

	if err := s.renew(instance); err != nil {
		// Do not block forever if nobody is listening any more (the owner
		// closed the channel, or already has an error pending).
		select {
		case s.errch <- fmt.Errorf("opcua: security token renewal failed: %w", err):
		case <-s.closing:
		}
	}
}

func (s *SecureChannel) renew(instance *channelInstance) error {
	// The write side of sendGate ensures that no one else renews at the same
	// time and that no request is in the middle of being sent.
	s.sendGate.Lock()
	defer s.sendGate.Unlock()

	// A token that was replaced in the meantime (Renew before its scheduled
	// renewal fired) is not renewed again: the renewal would open from the
	// superseded token's sequence number, one already used on the channel
	// (Part 6 §6.7.2.4), and the successor schedules a renewal of its own.
	if active := s.activeInstanceOrNil(); active != nil && active != instance {
		s.cfg.Logger.Debug("security token already renewed", "channel_id", s.c.ID(),
			"secure_channel_id", instance.secureChannelID, "token_id", instance.securityTokenID)
		return nil
	}

	instance.Lock()
	defer instance.Unlock()

	return s.open(context.Background(), instance, ua.SecurityTokenRequestTypeRenew)
}

func (s *SecureChannel) sendRequestWithTimeout(
	ctx context.Context,
	req ua.Request,
	reqID uint32,
	instance *channelInstance,
	authToken *ua.NodeID,
	timeout time.Duration,
	h ResponseHandler) error {

	respRequired := h != nil

	ch, err := s.sendAsyncWithTimeout(ctx, req, reqID, instance, authToken, respRequired, timeout)
	if err != nil {
		return err
	}

	if !respRequired {
		return nil
	}

	return s.awaitResponse(ctx, reqID, ch, timeout, h)
}

// awaitResponse waits for the response to request reqID and passes it to h.
func (s *SecureChannel) awaitResponse(ctx context.Context, reqID uint32, ch <-chan *MessageBody, timeout time.Duration, h ResponseHandler) error {

	// `+ timeoutLeniency` to give the server a chance to respond to TimeoutHint
	timer := time.NewTimer(timeout + timeoutLeniency)
	defer timer.Stop()

	deliver := func(msg *MessageBody) error {
		if msg.Err != nil {
			if msg.Response() != nil {
				_ = h(msg.Response()) // ignore result because msg.Err takes precedence
			}
			return msg.Err
		}
		return h(msg.Response())
	}
	// A response that has already been dispatched wins over the other
	// outcomes. In particular, when the peer answers with an Error message and
	// closes the connection, the dispatcher hands the error to the handler and
	// then closes s.disconnected: both cases are ready at once and select
	// would pick either, turning the peer's status code into a bare io.EOF.
	delivered := func() (error, bool) {
		select {
		case msg := <-ch:
			return deliver(msg), true
		default:
			return nil, false
		}
	}

	select {
	case msg := <-ch:
		return deliver(msg)
	case <-ctx.Done():
		if err, ok := delivered(); ok {
			return err
		}
		s.popHandler(reqID)
		return ctx.Err()
	case <-s.disconnected:
		if err, ok := delivered(); ok {
			return err
		}
		s.popHandler(reqID)
		return io.EOF
	case <-timer.C:
		if err, ok := delivered(); ok {
			return err
		}
		s.popHandler(reqID)
		return ua.StatusBadTimeout
	}
}

// pendingRequest is a request waiting for its response: the channel the
// response goes to and the authentication token the request was sent with.
type pendingRequest struct {
	ch        chan *MessageBody
	authToken *ua.NodeID
}

func (s *SecureChannel) popHandler(reqID uint32) (chan *MessageBody, bool) {
	s.handlersMu.Lock()
	defer s.handlersMu.Unlock()

	h, ok := s.handlers[reqID]
	if ok {
		delete(s.handlers, reqID)
	}
	return h.ch, ok
}

func (s *SecureChannel) Renew(ctx context.Context) error {
	instance, err := s.getActiveChannelInstance()
	if err != nil {
		return err
	}

	return s.renew(instance)
}

func (s *SecureChannel) SendRequest(ctx context.Context, req ua.Request, authToken *ua.NodeID, h ResponseHandler) error {
	// SendRequest sends the service request and calls h with the response.
	return s.SendRequestWithTimeout(ctx, req, authToken, s.cfg.RequestTimeout, h)
}

func (s *SecureChannel) SendRequestWithTimeout(ctx context.Context, req ua.Request, authToken *ua.NodeID, timeout time.Duration, h ResponseHandler) error {
	// Only the transmission is done under the gate; waiting for the response
	// must not hold up a token renewal.
	s.sendGate.RLock()
	active, err := s.getActiveChannelInstance()
	if err != nil {
		s.sendGate.RUnlock()
		return err
	}
	reqID := s.nextRequestID()
	ch, err := s.sendAsyncWithTimeout(ctx, req, reqID, active, authToken, h != nil, timeout)
	s.sendGate.RUnlock()
	if err != nil {
		return err
	}
	if h == nil {
		return nil
	}
	return s.awaitResponse(ctx, reqID, ch, timeout, h)
}

func (s *SecureChannel) sendAsyncWithTimeout(
	ctx context.Context,
	req ua.Request,
	reqID uint32,
	instance *channelInstance,
	authToken *ua.NodeID,
	respRequired bool,
	timeout time.Duration,
) (<-chan *MessageBody, error) {

	instance.Lock()
	defer instance.Unlock()

	var resp chan *MessageBody

	if respRequired {
		// register the handler if a callback was passed
		resp = make(chan *MessageBody, 1)

		s.handlersMu.Lock()

		if _, ok := s.handlers[reqID]; ok {
			s.handlersMu.Unlock()
			return nil, fmt.Errorf("%w: request id %d", errors.ErrDuplicateHandler, reqID)
		}

		s.handlers[reqID] = pendingRequest{ch: resp, authToken: authToken}
		s.handlersMu.Unlock()
	}

	// A request that is not sent must not leave its handler behind, nor use
	// up the sequence numbers of the chunks that were never written: the
	// peer refuses every chunk of a secured channel that follows a gap.
	seq, seqStarted := instance.sequenceNumber, instance.seqStarted
	fail := func(err error) (<-chan *MessageBody, error) {
		instance.sequenceNumber, instance.seqStarted = seq, seqStarted
		if respRequired {
			s.popHandler(reqID)
		}
		return nil, err
	}

	m, err := instance.newRequestMessage(req, reqID, authToken, timeout)
	if err != nil {
		return fail(err)
	}

	chunks, err := m.EncodeChunks(instance.maxBodySize)
	if err != nil {
		return fail(err)
	}

	for i, chunk := range chunks {
		select {
		case <-ctx.Done():
			return fail(ctx.Err())
		default:
		}
		if i > 0 { // fix sequence number on subsequent chunks
			number := instance.nextSequenceNumber()
			binary.LittleEndian.PutUint32(chunk[16:], uint32(number))
		}

		chunk, err = instance.signAndEncrypt(m, chunk)
		if err != nil {
			return fail(err)
		}

		// send the message
		var n int
		_ = s.c.SetWriteDeadline(time.Now().Add(timeout))
		if n, err = s.c.Write(chunk); err != nil {
			// A failed write may still have put (part of) the chunk on
			// the wire: its number is used up. Giving it back would make
			// the next chunk reuse it, which an AEAD policy cannot open.
			seq, seqStarted = instance.sequenceNumber, instance.seqStarted
			return fail(err)
		}
		_ = s.c.SetWriteDeadline(time.Time{})
		seq, seqStarted = instance.sequenceNumber, instance.seqStarted

		atomic.AddUint64(&instance.bytesSent, uint64(n))
		atomic.AddUint32(&instance.messagesSent, 1)

		s.cfg.Logger.Debug("send", "channel_id", s.c.ID(), "request_id", reqID, "type", fmt.Sprintf("%T", req), "bytes", len(chunk))
	}

	return resp, nil
}

func (s *SecureChannel) SendResponseWithContext(ctx context.Context, reqID uint32, resp ua.Response) error {
	return s.sendResponseWithContext(ctx, nil, reqID, resp)
}

func (s *SecureChannel) SendMsgWithContext(ctx context.Context, instance *channelInstance, reqID uint32, resp any) error {
	typeID := ua.ServiceTypeID(resp)
	if typeID == 0 {
		return fmt.Errorf("%w: %T", errors.ErrUnknownService, resp)
	}

	var err error
	if instance == nil {
		instance, err = s.getActiveChannelInstance()
		if err != nil {
			return err
		}
	}

	// we need to get a lock on the sequence number so we are sure to send them in the correct order.
	instance.Lock()
	defer instance.Unlock()

	// encode the message. If it cannot be encoded nothing is sent, so give
	// the sequence number back: the numbers on the wire have to stay
	// contiguous.
	prevSeq, prevStarted := instance.sequenceNumber, instance.seqStarted
	m := instance.newMessage(resp, typeID, reqID)
	b, err := m.Encode()
	if err != nil {
		instance.sequenceNumber, instance.seqStarted = prevSeq, prevStarted
		return err
	}

	// encrypt the message prior to sending it
	// if SecurityMode == None, this returns the byte stream untouched
	b, err = instance.signAndEncrypt(m, b)
	if err != nil {
		return err
	}

	// send the message
	n, err := s.c.Write(b)
	if err != nil {
		return err
	}

	// Go's net.Conn guarantees err != nil when n < len(b), so this is defense-in-depth.
	if len(b) != n {
		return fmt.Errorf("%w: %T len=%d sent=%d", errors.ErrMessageTooLarge, resp, len(b), n)
	}

	atomic.AddUint64(&instance.bytesSent, uint64(n))
	atomic.AddUint32(&instance.messagesSent, 1)

	s.cfg.Logger.Debug("send", "channel_id", s.c.ID(), "request_id", reqID, "type", fmt.Sprintf("%T", resp), "bytes", len(b))

	return nil
}

func (s *SecureChannel) sendResponseWithContext(ctx context.Context, instance *channelInstance, reqID uint32, resp ua.Response) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	typeID := ua.ServiceTypeID(resp)
	if typeID == 0 {
		return fmt.Errorf("%w: %T", errors.ErrUnknownService, resp)
	}

	// Without an explicit instance the response is secured with the active
	// token. A renewal can replace it while we wait for the send lock, in
	// which case the token we resolved is stale and must not be used.
	useActive := instance == nil
	for {
		if useActive {
			var err error
			if instance, err = s.getActiveChannelInstance(); err != nil {
				return err
			}
		}
		instance.Lock()
		if !useActive || s.isActiveInstance(instance) {
			break
		}
		instance.Unlock()
	}
	defer instance.Unlock()

	var err error

	// Encode the message into one or more chunks. maxBodySize is derived from
	// the negotiated send buffer (see SetMaximumBodySize), so large responses
	// such as a Browse of a folder with many nodes are split across multiple
	// chunks instead of overflowing the peer's receive buffer and dropping the
	// connection. Before the channel is fully negotiated (OPN exchange)
	// maxBodySize is 0; OPN responses are small and always a single chunk.
	maxBodySize := instance.maxBodySize
	if maxBodySize == 0 {
		maxBodySize = s.c.SendBufSize()
	}

	// newMessage consumes a sequence number. If the response cannot be
	// encoded nothing is sent, so give the number back: the sequence numbers
	// on the wire have to stay contiguous.
	prevSeq, prevStarted := instance.sequenceNumber, instance.seqStarted
	m := instance.newMessage(resp, typeID, reqID)
	chunks, err := m.EncodeChunks(maxBodySize)
	if err != nil {
		instance.sequenceNumber, instance.seqStarted = prevSeq, prevStarted
		s.cfg.Logger.Warn("error encoding msg", "error", err)
		return err
	}

	// Set a write deadline from the context if one is available.
	if deadline, ok := ctx.Deadline(); ok {
		_ = s.c.SetWriteDeadline(deadline)
		defer func() { _ = s.c.SetWriteDeadline(time.Time{}) }()
	}

	for i, chunk := range chunks {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if i > 0 { // fix sequence number on subsequent chunks
			number := instance.nextSequenceNumber()
			binary.LittleEndian.PutUint32(chunk[16:], uint32(number))
		}

		// encrypt the chunk prior to sending it
		// if SecurityMode == None, this returns the byte stream untouched
		chunk, err = instance.signAndEncrypt(m, chunk)
		if err != nil {
			return err
		}

		// send the chunk
		n, err := s.c.Write(chunk)
		if err != nil {
			return err
		}

		// Go's net.Conn guarantees err != nil when n < len(b), so this is defense-in-depth.
		if len(chunk) != n {
			return fmt.Errorf("%w: %T len=%d sent=%d", errors.ErrMessageTooLarge, resp, len(chunk), n)
		}

		atomic.AddUint64(&instance.bytesSent, uint64(n))
		atomic.AddUint32(&instance.messagesSent, 1)

		s.cfg.Logger.Debug("send", "channel_id", s.c.ID(), "request_id", reqID, "type", fmt.Sprintf("%T", resp), "bytes", len(chunk))
	}

	return nil
}

func (s *SecureChannel) nextRequestID() uint32 {
	s.requestIDMu.Lock()
	defer s.requestIDMu.Unlock()

	s.requestID++
	if s.requestID == 0 {
		s.requestID = 1
	}

	return s.requestID
}

// Close closes an existing secure channel.
func (s *SecureChannel) Close() (err error) {
	// https://github.com/otfabric/go-opcua/pull/470
	// guard against double close until we found the root cause
	err = io.EOF
	s.closeOnce.Do(func() { err = s.close() })
	return
}

func (s *SecureChannel) close() error {
	s.cfg.Logger.Debug("closing secure channel", "channel_id", s.c.ID())

	defer func() {
		close(s.closing)
		// no token of a closed channel needs to be retired any more
		s.ReleaseTokens()
		// Close the underlying UACP connection so that the secure channel
		// is the single owner of the connection lifecycle. This is safe
		// to call even if the connection is already closed (closeOnce).
		_ = s.c.Close()
	}()

	select {
	case <-s.disconnected:
		return io.EOF
	default:
	}

	// CloseSecureChannel is a request only a client sends (Part 6 §7.1.4).
	// A server ends the channel by closing the connection, after an Error
	// message that tells the client why (§7.1.5).
	if s.kind == server {
		s.sendCloseError()
		return io.EOF
	}

	// Best-effort: try to send CloseSecureChannelRequest but don't
	// fail the close if the connection is already dead. A token renewal in
	// progress holds the gate until the server answers or the request times
	// out; closing must not wait for that, so the request is skipped then.
	if s.sendGate.TryRLock() {
		if active, err := s.getActiveChannelInstance(); err == nil {
			_, _ = s.sendAsyncWithTimeout(context.Background(), &ua.CloseSecureChannelRequest{}, s.nextRequestID(), active, nil, false, s.cfg.RequestTimeout)
		}
		s.sendGate.RUnlock()
	}

	return io.EOF
}

// closeErrorTimeout bounds the write of the Error message a server channel
// sends when it is closed. A server channel's RequestTimeout is usually zero,
// so it cannot be used for this.
const closeErrorTimeout = 5 * time.Second

// sendCloseError tells the client of an open server channel that the channel
// is being closed. It is best-effort: the connection may be dead already. The
// lock of the active instance keeps the Error message from landing between
// the chunks of a response that is being sent.
func (s *SecureChannel) sendCloseError() {
	active, err := s.getActiveChannelInstance()
	if err != nil {
		return
	}
	active.Lock()
	defer active.Unlock()
	_ = s.c.SetWriteDeadline(time.Now().Add(closeErrorTimeout))
	s.c.SendError(ua.StatusBadSecureChannelClosed)
	_ = s.c.SetWriteDeadline(time.Time{})
}

func (s *SecureChannel) timeNow() time.Time {
	if s.time != nil {
		return s.time()
	}
	return time.Now()
}

func mergeChunks(chunks []*MessageChunk) []byte {
	if len(chunks) == 0 {
		return nil
	}
	if len(chunks) == 1 {
		return chunks[0].Data
	}

	var b []byte
	var seqnr uint32
	for _, c := range chunks {
		if c.SequenceNumber == seqnr {
			continue // duplicate chunk
		}
		seqnr = c.SequenceNumber
		b = append(b, c.Data...)
	}
	return b
}
