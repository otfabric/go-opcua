// SPDX-License-Identifier: MIT

package uasc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
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

type conditionLocker struct {
	bLock   bool
	lockMu  sync.Mutex
	lockCnd *sync.Cond
}

func newConditionLocker() *conditionLocker {
	c := &conditionLocker{}
	c.lockCnd = sync.NewCond(&c.lockMu)
	return c
}

func (c *conditionLocker) lock() {
	c.lockMu.Lock()
	c.bLock = true
	c.lockMu.Unlock()
}

func (c *conditionLocker) unlock() {
	c.lockMu.Lock()
	c.bLock = false
	c.lockMu.Unlock()
	c.lockCnd.Broadcast()
}

func (c *conditionLocker) waitIfLock() {
	c.lockMu.Lock()
	for c.bLock {
		c.lockCnd.Wait()
	}
	c.lockMu.Unlock()
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

	// prevent sending msg when secure channel renewal occurs
	reqLocker  *conditionLocker
	pendingReq sync.WaitGroup

	// openDone is signalled by open() when it finishes processing an
	// OpenSecureChannelResponse. The dispatcher waits on this channel
	// after forwarding an OpenSecureChannelResponse so that no new
	// messages are read while the channel's crypto state is being updated.
	openDone chan struct{}

	// handles maps requestIDs to response channels
	handlers   map[uint32]chan *MessageBody
	handlersMu sync.Mutex

	// chunks maintains a temporary list of chunks for a given request ID
	chunks   map[uint32][]*MessageChunk
	chunksMu sync.Mutex

	// openingInstance is a temporary var that allows the dispatcher know how to handle a open channel request
	// note: we only allow a single "open" request in flight at any point in time. The mutex is held for the entire
	// duration of the "open" request.
	openingInstance *channelInstance
	openingMu       sync.Mutex

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

	closeOnce sync.Once
}

func NewSecureChannel(endpoint string, c *uacp.Conn, cfg *Config, errCh chan<- error) (*SecureChannel, error) {
	return newSecureChannel(endpoint, c, cfg, client, errCh)
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
	case cfg.SecurityPolicyURI != ua.SecurityPolicyURINone && cfg.LocalKey == nil:
		return nil, fmt.Errorf("%w: policy '%s' requires a private key", errors.ErrInvalidSecurityConfig, cfg.SecurityPolicyURI)
	}

	s := &SecureChannel{
		endpointURL:  endpoint,
		c:            c,
		cfg:          cfg,
		requestID:    cfg.RequestIDSeed,
		kind:         kind,
		reqLocker:    newConditionLocker(),
		openDone:     make(chan struct{}, 1),
		errch:        errCh,
		closing:      make(chan struct{}),
		disconnected: make(chan struct{}),
		instances:    make(map[uint32][]*channelInstance),
		chunks:       make(map[uint32][]*MessageChunk),
		handlers:     make(map[uint32]chan *MessageBody),
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
					case s.errch <- msg.Err:
					default:
					}
				}
			}

			if msg.Err == io.EOF {
				return
			}

			if msg.Err != nil {
				s.cfg.Logger.Debug("error", "channel_id", s.c.ID(), "request_id", msg.RequestID, "error", msg.Err)
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
				// Wait for open() to signal that it has finished updating
				// the channel's crypto state. Use a timeout to avoid a
				// permanent deadlock if the handler never signals.
				select {
				case <-s.openDone:
				case <-s.closing:
					return
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

// isReconnectTrigger reports whether a service-level fault requires the secure
// channel, session, or subscriptions to be recreated. These are the status
// codes the client's connection monitor acts on; every other operation-level
// fault is delivered to the caller without disturbing the connection.
func isReconnectTrigger(err error) bool {
	switch {
	case errors.Is(err, ua.StatusBadSecureChannelIDInvalid),
		errors.Is(err, ua.StatusBadSessionIDInvalid),
		errors.Is(err, ua.StatusBadSubscriptionIDInvalid),
		errors.Is(err, ua.StatusBadNoSubscription),
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
			// request error handling lives in handleService().
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

func (s *SecureChannel) readChunk() (*MessageChunk, error) {
	// read a full message from the underlying conn.
	b, err := s.c.Receive()
	if err == io.EOF || len(b) == 0 {
		return nil, io.EOF
	}
	// do not wrap this error since it hides conn error
	var uacperr *uacp.Error
	if errors.As(err, &uacperr) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("sechan: read header failed: %w", err)
	}

	const hdrlen = 12 // secure conversation header size
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

		if s.openingInstance == nil {
			return nil, fmt.Errorf("%w: openingInstance is nil", errors.ErrInvalidState)
		}

		s.cfg.SecurityPolicyURI = m.SecurityPolicyURI
		if m.SecurityPolicyURI != ua.SecurityPolicyURINone {
			s.cfg.RemoteCertificate = m.SenderCertificate
			s.cfg.Logger.Debug("setting securityPolicy", "channel_id", s.c.ID(), "policy", m.SecurityPolicyURI)

			remoteKey, err := uapolicy.PublicKey(s.cfg.RemoteCertificate)
			if err != nil {
				return nil, err
			}
			algo, err := uapolicy.Asymmetric(s.cfg.SecurityPolicyURI, s.openingInstance.sc.cfg.LocalKey, remoteKey)
			if err != nil {
				return nil, err
			}

			s.openingInstance.algo = algo

			// For OpenSecureChannel asymmetric encryption is always used
			s.cfg.SecurityMode = ua.MessageSecurityModeSignAndEncrypt
		}

		decryptWith = s.openingInstance
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

	return m, nil
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

	for i := len(instances) - 1; i >= 0; i-- {
		if verified, err = instances[i].verifyAndDecrypt(m, b); err == nil {
			return verified, nil
		}
		s.cfg.Logger.Debug("attempting older channel state", "channel_id", s.c.ID())
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

	return instances
}

func (s *SecureChannel) LocalEndpoint() string {
	return s.endpointURL
}

func (s *SecureChannel) Open(ctx context.Context) error {
	return s.open(ctx, nil, ua.SecurityTokenRequestTypeIssue)
}

func (s *SecureChannel) open(ctx context.Context, instance *channelInstance, requestType ua.SecurityTokenRequestType) error {
	s.cfg.Logger.Debug("opening secure channel")

	// Signal the dispatcher that open() has finished processing the
	// OpenSecureChannelResponse, allowing it to resume reading messages.
	defer func() {
		select {
		case s.openDone <- struct{}{}:
		default:
		}
	}()

	s.openingMu.Lock()
	defer s.openingMu.Unlock()

	if s.openingInstance != nil {
		return fmt.Errorf("%w: openingInstance must be nil when opening a new secure channel", errors.ErrInvalidState)
	}

	var (
		err       error
		localKey  *rsa.PrivateKey
		remoteKey *rsa.PublicKey
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
		localKey = s.cfg.LocalKey
		var err error
		if remoteKey, err = uapolicy.PublicKey(s.cfg.RemoteCertificate); err != nil {
			return err
		}
	}

	algo, err := uapolicy.Asymmetric(s.cfg.SecurityPolicyURI, localKey, remoteKey)
	if err != nil {
		return err
	}

	s.openingInstance = newChannelInstance(s)
	// s.openingInstance.secureChannelID = s.secureChannelID
	// s.openingInstance.sequenceNumber = s.sequenceNumber
	// s.openingInstance.securityTokenID = s.securityTokenID

	if requestType == ua.SecurityTokenRequestTypeRenew {
		// Safe: reqLocker.lock() blocks new requests, pendingReq.Wait()
		// drains in-flight ones, and instance.Lock() is held by renew().
		// Snapshot the current sequence number and bump the source so
		// the value is never reused if the old instance is briefly active
		// during the OpenSecureChannel round-trip.
		s.openingInstance.sequenceNumber = instance.sequenceNumber
		instance.sequenceNumber++
		s.openingInstance.secureChannelID = instance.secureChannelID
	}

	// trigger cleanup after we are all done
	defer func() {
		if s.openingInstance == nil || s.openingInstance.state != channelActive {
			s.cfg.Logger.Warn("failed to open a new secure channel", "channel_id", s.c.ID())
		}
		s.openingInstance = nil
	}()

	reqID := s.nextRequestID()

	s.openingInstance.algo = algo
	s.openingInstance.SetMaximumBodySize(int(s.c.SendBufSize()))

	localNonce, err := algo.MakeNonce()
	if err != nil {
		return err
	}

	req := &ua.OpenSecureChannelRequest{
		ClientProtocolVersion: 0,
		RequestType:           requestType,
		SecurityMode:          s.cfg.SecurityMode,
		ClientNonce:           localNonce,
		RequestedLifetime:     s.cfg.Lifetime,
	}

	return s.sendRequestWithTimeout(ctx, req, reqID, s.openingInstance, nil, s.cfg.RequestTimeout, func(v ua.Response) error {
		s.cfg.Logger.Debug("handling OpenSecureChannelResponse")
		resp, ok := v.(*ua.OpenSecureChannelResponse)
		if !ok {
			return fmt.Errorf("%w: got %T", errors.ErrInvalidResponseType, v)
		}
		return s.handleOpenSecureChannelResponse(resp, localNonce, s.openingInstance)
	})
}

func (s *SecureChannel) handleOpenSecureChannelResponse(resp *ua.OpenSecureChannelResponse, localNonce []byte, instance *channelInstance) (err error) {
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

	if instance.algo, err = uapolicy.Symmetric(s.cfg.SecurityPolicyURI, localNonce, resp.ServerNonce); err != nil {
		return err
	}

	instance.SetMaximumBodySize(int(s.c.SendBufSize()))

	s.instancesMu.Lock()
	defer s.instancesMu.Unlock()

	s.instances[resp.SecurityToken.ChannelID] = append(
		s.instances[resp.SecurityToken.ChannelID],
		s.openingInstance,
	)

	s.activeInstance = instance

	s.cfg.Logger.Debug("received security token", "channel_id", s.c.ID(), "secure_channel_id", instance.secureChannelID, "token_id", instance.securityTokenID, "created_at", instance.createdAt.Format(time.RFC3339), "lifetime", instance.revisedLifetime)

	// depending on whether the channel is used in a client
	// or a server we need to trigger different behavior.
	// client channels trigger token renewals and need to cleanup old
	// channel crypto configs. server channels only need to do the
	// channel cleanup.
	switch s.kind {
	case client:
		go s.scheduleRenewal(instance)
		go s.scheduleExpiration(instance)

	case server:
		go s.scheduleExpiration(instance)
	}

	return
}

func (s *SecureChannel) handleOpenSecureChannelRequest(reqID uint32, svc ua.Request) error {
	s.cfg.Logger.Debug("handling OpenSecureChannelRequest")

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

	// Part 6.7.4: The AuthenticationToken should be nil. ???
	if req.RequestHeader.AuthenticationToken.IntID() != 0 {
		return ua.StatusBadSecureChannelTokenUnknown
	}

	s.cfg.Lifetime = req.RequestedLifetime
	s.cfg.SecurityMode = req.SecurityMode

	// I had to do the encryption setup in the chunk decoding logic because you have to
	// decrypt the thing before you even know you have an open message.
	// so this is redundant.
	var (
		localKey  *rsa.PrivateKey
		remoteKey *rsa.PublicKey
	)

	// Set the encryption methods to Asymmetric with the appropriate
	// public keys.  OpenSecureChannel is always encrypted with the
	// asymmetric algorithms.
	// The default value of the encryption algorithm method is the
	// SecurityModeNone so no additional work is required for that case
	if s.cfg.SecurityMode != ua.MessageSecurityModeNone {
		localKey = s.cfg.LocalKey
		var err error
		if remoteKey, err = uapolicy.PublicKey(s.cfg.RemoteCertificate); err != nil {
			return err
		}
	}

	algo, err := uapolicy.Asymmetric(s.cfg.SecurityPolicyURI, localKey, remoteKey)
	if err != nil {
		return err
	}

	instance := s.openingInstance
	instance.algo = algo
	instance.sc.requestID = req.RequestHeader.RequestHandle // server echoes client's RequestHandle for correlation

	nonce := make([]byte, instance.algo.NonceLength())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
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
			RevisedLifetime: req.RequestedLifetime,
		},
		ServerNonce: nonce,
	}

	ctx := context.Background() // TODO(fs): thread request context from Receive path
	if err := s.sendResponseWithContext(ctx, instance, reqID, resp); err != nil {
		return err
	}

	instance.algo, err = uapolicy.Symmetric(s.cfg.SecurityPolicyURI, nonce, req.ClientNonce)
	if err != nil {
		return err
	}

	instance.state = channelActive // correct: per Part 6 §6.7.2, server considers channel open after sending response

	s.instancesMu.Lock()
	s.instances[instance.secureChannelID] = append(
		s.instances[instance.secureChannelID],
		instance,
	)
	s.activeInstance = instance
	s.instancesMu.Unlock()

	return nil
}

func (s *SecureChannel) scheduleRenewal(instance *channelInstance) {
	// https://reference.opcfoundation.org/v104/Core/docs/Part4/5.5.2/#5.5.2.1
	// Clients should request a new SecurityToken after 75 % of its lifetime has elapsed. This should ensure that
	// clients will receive the new SecurityToken before the old one actually expire
	const renewAfter = 0.75
	when := time.Second * time.Duration(instance.revisedLifetime.Seconds()*renewAfter)

	s.cfg.Logger.Debug("security token refresh scheduled", "channel_id", s.c.ID(), "refresh_at", time.Now().UTC().Add(when).Format(time.RFC3339), "timeout", when, "secure_channel_id", instance.secureChannelID, "token_id", instance.securityTokenID)

	t := time.NewTimer(when)
	defer t.Stop()

	select {
	case <-s.closing:
		return
	case <-t.C:
	}

	if err := s.renew(instance); err != nil {
		s.errch <- fmt.Errorf("opcua: security token renewal failed: %w", err)
	}
}

func (s *SecureChannel) renew(instance *channelInstance) error {
	// lock ensure no one else renews this at the same time
	s.reqLocker.lock()
	defer s.reqLocker.unlock()
	s.pendingReq.Wait()
	instance.Lock()
	defer instance.Unlock()

	return s.open(context.Background(), instance, ua.SecurityTokenRequestTypeRenew)
}

func (s *SecureChannel) scheduleExpiration(instance *channelInstance) {
	// https://reference.opcfoundation.org/v104/Core/docs/Part4/5.5.2/#5.5.2.1
	// Clients should accept Messages secured by an expired SecurityToken for up to 25 % of the token lifetime.
	const expireAfter = 1.25
	when := instance.createdAt.Add(time.Second * time.Duration(instance.revisedLifetime.Seconds()*expireAfter))

	s.cfg.Logger.Debug("security token expiration scheduled", "channel_id", s.c.ID(), "expires_at", when.UTC().Format(time.RFC3339), "secure_channel_id", instance.secureChannelID, "token_id", instance.securityTokenID)

	t := time.NewTimer(time.Until(when))
	defer t.Stop()

	select {
	case <-s.closing:
		return
	case <-t.C:
	}

	s.instancesMu.Lock()
	defer s.instancesMu.Unlock()

	oldInstances := s.instances[instance.securityTokenID]

	s.instances[instance.securityTokenID] = []*channelInstance{}

	for _, oldInstance := range oldInstances {
		if oldInstance.secureChannelID != instance.secureChannelID {
			// something has gone horribly wrong!
			s.cfg.Logger.Warn("secureChannelID mismatch during scheduleExpiration", "channel_id", s.c.ID())
		}
		if oldInstance.securityTokenID == instance.securityTokenID {
			continue
		}
		s.instances[instance.securityTokenID] = append(
			s.instances[instance.securityTokenID],
			oldInstance,
		)
	}
}

func (s *SecureChannel) sendRequestWithTimeout(
	ctx context.Context,
	req ua.Request,
	reqID uint32,
	instance *channelInstance,
	authToken *ua.NodeID,
	timeout time.Duration,
	h ResponseHandler) error {

	s.pendingReq.Add(1)
	respRequired := h != nil

	ch, err := s.sendAsyncWithTimeout(ctx, req, reqID, instance, authToken, respRequired, timeout)
	s.pendingReq.Done()
	if err != nil {
		return err
	}

	if !respRequired {
		return nil
	}

	// `+ timeoutLeniency` to give the server a chance to respond to TimeoutHint
	timer := time.NewTimer(timeout + timeoutLeniency)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		s.popHandler(reqID)
		return ctx.Err()
	case <-s.disconnected:
		s.popHandler(reqID)
		return io.EOF
	case msg := <-ch:
		if msg.Err != nil {
			if msg.Response() != nil {
				_ = h(msg.Response()) // ignore result because msg.Err takes precedence
			}
			return msg.Err
		}
		return h(msg.Response())
	case <-timer.C:
		s.popHandler(reqID)
		return ua.StatusBadTimeout
	}
}

func (s *SecureChannel) popHandler(reqID uint32) (chan *MessageBody, bool) {
	s.handlersMu.Lock()
	defer s.handlersMu.Unlock()

	ch, ok := s.handlers[reqID]
	if ok {
		delete(s.handlers, reqID)
	}
	return ch, ok
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
	s.reqLocker.waitIfLock()
	active, err := s.getActiveChannelInstance()
	if err != nil {
		return err
	}

	return s.sendRequestWithTimeout(ctx, req, s.nextRequestID(), active, authToken, timeout, h)
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

	m, err := instance.newRequestMessage(req, reqID, authToken, timeout)
	if err != nil {
		return nil, err
	}

	var resp chan *MessageBody

	if respRequired {
		// register the handler if a callback was passed
		resp = make(chan *MessageBody, 1)

		s.handlersMu.Lock()

		if s.handlers[reqID] != nil {
			s.handlersMu.Unlock()
			return nil, fmt.Errorf("%w: request id %d", errors.ErrDuplicateHandler, reqID)
		}

		s.handlers[reqID] = resp
		s.handlersMu.Unlock()
	}

	chunks, err := m.EncodeChunks(instance.maxBodySize)
	if err != nil {
		return nil, err
	}

	for i, chunk := range chunks {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		if i > 0 { // fix sequence number on subsequent chunks
			number := instance.nextSequenceNumber()
			binary.LittleEndian.PutUint32(chunk[16:], uint32(number))
		}

		chunk, err = instance.signAndEncrypt(m, chunk)
		if err != nil {
			return nil, err
		}

		// send the message
		var n int
		_ = s.c.SetWriteDeadline(time.Now().Add(timeout))
		if n, err = s.c.Write(chunk); err != nil {
			return nil, err
		}
		_ = s.c.SetWriteDeadline(time.Time{})

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
	// encode the message
	m := instance.newMessage(resp, typeID, reqID)
	b, err := m.Encode()
	if err != nil {
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

	var err error
	if instance == nil {
		instance, err = s.getActiveChannelInstance()
		if err != nil {
			return err
		}
	}
	instance.Lock()
	defer instance.Unlock()

	// encode the message
	m := instance.newMessage(resp, typeID, reqID)
	b, err := m.Encode()
	if err != nil {
		s.cfg.Logger.Warn("error encoding msg", "error", err)
		return err
	}

	// encrypt the message prior to sending it
	// if SecurityMode == None, this returns the byte stream untouched
	b, err = instance.signAndEncrypt(m, b)
	if err != nil {
		return err
	}

	// Set a write deadline from the context if one is available.
	if deadline, ok := ctx.Deadline(); ok {
		_ = s.c.SetWriteDeadline(deadline)
		defer func() { _ = s.c.SetWriteDeadline(time.Time{}) }()
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
		// Close the underlying UACP connection so that the secure channel
		// is the single owner of the connection lifecycle. This is safe
		// to call even if the connection is already closed (closeOnce).
		_ = s.c.Close()
	}()

	s.reqLocker.unlock()

	select {
	case <-s.disconnected:
		return io.EOF
	default:
	}

	// Best-effort: try to send CloseSecureChannelRequest but don't
	// fail the close if the connection is already dead.
	_ = s.SendRequest(context.Background(), &ua.CloseSecureChannelRequest{}, nil, nil)

	return io.EOF
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
