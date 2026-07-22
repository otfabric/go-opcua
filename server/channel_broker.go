// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/rsa"
	"io"
	"log/slog"
	mrand "math/rand"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/otfabric/go-opcua/uasc"
)

type channelBroker struct {
	endpoints   map[string]*ua.EndpointDescription
	endpointURL string

	wg sync.WaitGroup

	// mu protects concurrent modification of s, secureChannelID, and secureTokenID
	mu sync.RWMutex
	// s is a slice of all SecureChannels watched by the channelBroker
	s map[uint32]*uasc.SecureChannel

	// Next Secure Channel ID to issue to a client
	secureChannelID uint32

	// Next Token ID to issue to a client
	secureTokenID uint32

	// msgChan is the common channel that all messages from all channels
	// get funneled into for handling
	msgChan chan *uasc.MessageBody
	logger  *slog.Logger

	// clientCertificateValidator is copied onto each new SecureChannel Config
	// so untrusted client certs can be rejected at OpenSecureChannel.
	clientCertificateValidator ClientCertificateValidator
}

func newChannelBroker(l *slog.Logger, endpointURL string, clientCertValidator ClientCertificateValidator) *channelBroker {
	rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	return &channelBroker{
		endpoints:                  make(map[string]*ua.EndpointDescription),
		endpointURL:                endpointURL,
		s:                          make(map[uint32]*uasc.SecureChannel),
		msgChan:                    make(chan *uasc.MessageBody),
		secureChannelID:            uint32(rng.Int31()),
		secureTokenID:              uint32(rng.Int31()),
		logger:                     l,
		clientCertificateValidator: clientCertValidator,
	}
}

// RegisterConn connects a new UACP connection to the channel broker's list
// of connections and starts waiting for data on it.  Data is pushed onto the broker's
// Response channel
// Blocks until the context is done, the connection closes, or a critical error.
func (c *channelBroker) RegisterConn(ctx context.Context, conn *uacp.Conn, localCert []byte, localKey *rsa.PrivateKey) error {
	cfg := defaultChannelConfig()
	cfg.Certificate = localCert
	cfg.LocalKey = localKey
	cfg.Logger = c.logger
	cfg.ClientCertificateValidator = c.clientCertificateValidator

	c.mu.Lock()
	c.secureChannelID++
	c.secureTokenID++
	secureChannelID := c.secureChannelID
	secureTokenID := c.secureTokenID
	sequenceNumber := uint32(mrand.Int31n(1023) + 1)
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

	c.mu.Lock()
	c.s[secureChannelID] = sc
	c.logger.Info("registered new channel", "secure_channel_id", secureChannelID, "total_channels", len(c.s))
	c.mu.Unlock()
	c.wg.Add(1)
outer:
	for {
		select {
		case <-ctx.Done():
			c.logger.Warn("context done, closing secure channel", "secure_channel_id", secureChannelID)
			break outer

		default:
			msg := sc.Receive(ctx)
			if msg.Err == io.EOF {
				c.logger.Warn("secure channel closed", "secure_channel_id", secureChannelID)
				break outer
			} else if msg.Err != nil {
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
					if err := sc.SendResponseWithContext(ctx, msg.RequestID, fault); err != nil {
						c.logger.Error("error sending service fault", "secure_channel_id", secureChannelID, "error", err)
						break outer
					}
					continue
				}
				c.logger.Error("secure channel error", "secure_channel_id", secureChannelID, "error", msg.Err)
				break outer
			}
			select {
			case <-ctx.Done():
				break outer
			case c.msgChan <- msg:
			}
		}
	}

	c.mu.Lock()
	delete(c.s, secureChannelID)
	c.mu.Unlock()
	c.wg.Done()

	return ctx.Err()
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
	for _, s := range c.s {
		_ = s.Close()
	}
	c.mu.Unlock()

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

func (c *channelBroker) ReadMessage(ctx context.Context) *uasc.MessageBody {
	select {
	case <-ctx.Done():
		return nil
	case msg := <-c.msgChan:
		return msg
	}
}
