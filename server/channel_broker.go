// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
	"log/slog"
	mrand "math/rand"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/otfabric/go-opcua/uasc"
)

// inbound is a request together with the channel it arrived on.
type inbound struct {
	msg *uasc.MessageBody
	sc  *uasc.SecureChannel
	w   *channelWriter
}

type channelBroker struct {
	endpoints   map[string]*ua.EndpointDescription
	endpointURL string

	wg sync.WaitGroup

	// mu protects concurrent modification of s, secureChannelID, and secureTokenID
	mu sync.RWMutex
	// s is a slice of all SecureChannels watched by the channelBroker
	s map[uint32]*uasc.SecureChannel

	// closed is set by Close. A connection that is registered afterwards is
	// dropped at once: nobody would ever close it.
	closed bool

	// Next Secure Channel ID to issue to a client
	secureChannelID uint32

	// Next Token ID to issue to a client
	secureTokenID uint32

	// writers holds the response writer of every registered channel.
	writers map[*uasc.SecureChannel]*channelWriter

	// writeTimeout and maxPending configure the channel writers, see
	// WithResponseWriteTimeout and WithMaxPendingResponses.
	writeTimeout time.Duration
	maxPending   int

	// msgChan is the common channel that all messages from all channels
	// get funneled into for handling
	msgChan chan inbound
	logger  *slog.Logger

	// clientCertificateValidator is copied onto each new SecureChannel Config
	// so untrusted client certs can be rejected at OpenSecureChannel.
	clientCertificateValidator ClientCertificateValidator

	// localIdentity selects the application instance certificate and key of
	// a new channel from the security policy the client opens it with. Nil
	// means every channel uses the certificate passed to RegisterConn.
	localIdentity func(securityPolicyURI string) ([]byte, crypto.Signer, error)

	// onRequest is called with the header of every request as it arrives,
	// before it waits for the request handler (session activity).
	onRequest func(*ua.RequestHeader)
}

func newChannelBroker(l *slog.Logger, endpointURL string, clientCertValidator ClientCertificateValidator) *channelBroker {
	rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	return &channelBroker{
		endpoints:                  make(map[string]*ua.EndpointDescription),
		endpointURL:                endpointURL,
		s:                          make(map[uint32]*uasc.SecureChannel),
		writers:                    make(map[*uasc.SecureChannel]*channelWriter),
		msgChan:                    make(chan inbound),
		secureChannelID:            uint32(rng.Int31()),
		secureTokenID:              uint32(rng.Int31()),
		logger:                     l,
		clientCertificateValidator: clientCertValidator,
	}
}

// sequenceNumberSeed returns the sequence number a new server channel starts
// from. The channel increments it before the first chunk, and with the
// legacy (RSA) security policies the first SequenceNumber must be below 1024
// (Part 6 §6.7.2.4), so the seed is 0..1022 and the first number 1..1023.
// The ECC policies ignore it and start at 0. intn is math/rand's Int31n.
func sequenceNumberSeed(intn func(int32) int32) uint32 {
	return uint32(intn(1023))
}

// RegisterConn connects a new UACP connection to the channel broker's list
// of connections and starts waiting for data on it.  Data is pushed onto the broker's
// Response channel
// Blocks until the context is done, the connection closes, or a critical error.
func (c *channelBroker) RegisterConn(ctx context.Context, conn *uacp.Conn, localCert []byte, localKey *rsa.PrivateKey) error {
	cfg := defaultChannelConfig()
	cfg.Certificate = localCert
	cfg.LocalKey = localKey
	cfg.LocalIdentity = c.localIdentity
	cfg.Logger = c.logger
	cfg.ClientCertificateValidator = c.clientCertificateValidator

	c.mu.Lock()
	c.secureChannelID++
	c.secureTokenID++
	secureChannelID := c.secureChannelID
	secureTokenID := c.secureTokenID
	sequenceNumber := sequenceNumberSeed(mrand.Int31n)
	c.mu.Unlock()

	errch := make(chan error, 1)
	sc, err := uasc.NewServerSecureChannel(
		c.endpointURL,
		conn,
		cfg,
		errch,
		secureChannelID,
		sequenceNumber,
		secureTokenID,
	)
	if err != nil {
		c.logger.Error("error creating secure channel for new connection", "error", err)
		return err
	}

	w := newChannelWriter(sc, conn, c.logger, c.writeTimeout, c.maxPending)

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = conn.Close()
		return io.EOF
	}
	c.s[secureChannelID] = sc
	c.writers[sc] = w
	c.logger.Info("registered new channel", "secure_channel_id", secureChannelID, "total_channels", len(c.s))
	// Add under the lock that Close holds while it collects the channels, so
	// that Close waits for exactly the channels it has seen.
	c.wg.Add(1)
	c.mu.Unlock()

	go w.run()

	c.receive(ctx, sc, w, secureChannelID)

	sc.ReleaseTokens()

	c.mu.Lock()
	delete(c.s, secureChannelID)
	delete(c.writers, sc)
	c.mu.Unlock()

	// The channel is finished, whatever the reason: release the TCP
	// connection and stop the channel's writer and timers. Without this the
	// socket of every client that disconnected (or sent garbage) stays open
	// until the server shuts down. The connection is closed first so that a
	// response still being written to an unresponsive peer cannot hold up
	// the close.
	w.close()
	<-w.exited
	_ = sc.Close()
	c.wg.Done()

	return ctx.Err()
}

// receive reads the requests of one channel and hands them to the request
// handler until the channel ends.
//
// The requests of all channels are handled by one goroutine, which can be
// busy for a while (an ActivateSession on a Brainpool policy, a large Browse
// on a loaded machine). The channel is not stalled behind it: the requests
// it has read wait for the handler in a queue of their own, fed in order to
// the handler by forward, and receive goes on reading. That matters for the
// OpenSecureChannel requests, which are answered right here: a renewal that
// the client sent in time must not sit unread in the socket behind requests
// that wait for the handler while the lifetime of the token it renews runs
// out (Part 4 §5.5.2.1). The in-flight slots still bound what a channel may
// queue, so a client that does not read its responses is held off by TCP
// back pressure as before.
func (c *channelBroker) receive(ctx context.Context, sc *uasc.SecureChannel, w *channelWriter, secureChannelID uint32) {
	queue := make(chan inbound, cap(w.slots))
	forwarded := make(chan struct{})
	go c.forward(ctx, w, queue, forwarded)
	// Whatever ends the channel, the requests read before the end are still
	// handled (a CloseSession before the CloseSecureChannel, say) before the
	// channel is torn down; forward stops early only when the writer or the
	// server is gone.
	defer func() {
		close(queue)
		<-forwarded
	}()

	// A panic while decoding a message cannot be attributed to a request
	// (it has not been decoded) and leaves the stream in an unknown state.
	// It ends this channel, not the process.
	defer func() {
		if r := recover(); r != nil {
			logPanic(c.logger, "receiving on a secure channel", r, "secure_channel_id", secureChannelID)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			c.logger.Warn("context done, closing secure channel", "secure_channel_id", secureChannelID)
			return
		case <-w.done:
			return
		default:
		}

		msg := sc.Receive(ctx)
		if msg.Err == io.EOF {
			c.logger.Warn("secure channel closed", "secure_channel_id", secureChannelID)
			return
		}
		if msg.Err != nil {
			c.logger.Info("secure channel message error", "secure_channel_id", secureChannelID, "request_id", msg.RequestID, "error", msg.Err)
			// A per-request decoding/processing error must not tear down the
			// whole channel. When the failure can be correlated to a request
			// (RequestID != 0), return a ServiceFault so the caller fails
			// fast instead of blocking until its timeout, then keep serving.
			// Only unrecoverable/connection-level errors (RequestID == 0)
			// close the channel.
			if msg.RequestID != 0 {
				c.logger.Warn("request error, returning service fault",
					"secure_channel_id", secureChannelID, "request_id", msg.RequestID, "error", msg.Err)
				fault := &ua.ServiceFault{ResponseHeader: faultHeader(msg.Err)}
				if !w.acquire(ctx) {
					return
				}
				if err := w.send(msg.RequestID, fault); err != nil {
					c.logger.Error("error sending service fault", "secure_channel_id", secureChannelID, "error", err)
					return
				}
				continue
			}
			c.logger.Error("secure channel error", "secure_channel_id", secureChannelID, "error", msg.Err)
			return
		}
		if msg.Request() == nil {
			// OpenSecureChannel is answered inside Receive, and a server has
			// no use for anything that is not a request.
			if resp := msg.Response(); resp != nil {
				c.logger.Error("server received a response", "secure_channel_id", secureChannelID, "type", fmt.Sprintf("%T", resp))
			}
			continue
		}

		if c.onRequest != nil {
			if hdr := msg.Request().Header(); hdr != nil {
				c.onRequest(hdr)
			}
		}

		// Take an in-flight slot before queueing the request. This is what
		// applies back pressure to a client that sends requests faster than
		// it reads the responses, and it keeps the queue from filling up: it
		// has room for every slot.
		if !w.acquire(ctx) {
			return
		}
		queue <- inbound{msg: msg, sc: sc, w: w}
	}
}

// forward hands the requests receive queued for a channel to the request
// handler, in the order they were read, until the queue is closed and empty
// or the channel's writer or ctx ends. It closes done when it returns.
func (c *channelBroker) forward(ctx context.Context, w *channelWriter, queue <-chan inbound, done chan<- struct{}) {
	defer close(done)
	for in := range queue {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case c.msgChan <- in:
		}
	}
}

// writer returns the response writer of a registered channel, or nil.
func (c *channelBroker) writer(sc *uasc.SecureChannel) *channelWriter {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.writers[sc]
}

// faultHeader builds a ResponseHeader for a ServiceFault returned in response
// to a request-scoped error. If the error is a ua.StatusCode it is used
// directly; otherwise the fault reports a generic decoding error.
func faultHeader(err error) *ua.ResponseHeader {
	status := ua.StatusBadDecodingError
	if sc, ok := err.(ua.StatusCode); ok {
		status = sc
	}
	return &ua.ResponseHeader{
		Timestamp:          time.Now(),
		ServiceResult:      status,
		ServiceDiagnostics: &ua.DiagnosticInfo{},
		StringTable:        []string{},
		AdditionalHeader:   ua.NewExtensionObject(nil),
	}
}

const brokerCloseTimeout = 10 * time.Second

// Close gracefully closes all secure channels.
// The provided context controls the deadline for waiting on in-flight
// goroutines. If ctx is nil or has no deadline, a default timeout is used.
func (c *channelBroker) Close(ctx context.Context) error {
	var err error
	c.mu.Lock()
	c.closed = true
	channels := make([]*uasc.SecureChannel, 0, len(c.s))
	for _, s := range c.s {
		channels = append(channels, s)
	}
	c.mu.Unlock()
	// Closing writes to the connection, so do it without holding the lock.
	for _, s := range channels {
		_ = s.Close()
	}

	// Wait for all goroutines to finish or context to expire.
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.wg.Wait()
	}()

	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, brokerCloseTimeout)
		defer cancel()
	}

	select {
	case <-done:
	case <-ctx.Done():
		c.logger.Error("CloseAll: timed out waiting for channels to exit")
	}

	return err
}

func (c *channelBroker) ReadMessage(ctx context.Context) (inbound, bool) {
	select {
	case <-ctx.Done():
		return inbound{}, false
	case in := <-c.msgChan:
		return in, true
	}
}
