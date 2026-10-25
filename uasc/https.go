// SPDX-License-Identifier: MIT

package uasc

import (
	"bytes"
	"context"
	"crypto/tls"
	stderrors "errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

// The HTTPS transport with UA Binary encoding (Part 6 §7.4, profile
// https-uabinary) has no secure conversation: each request is the body of an
// HTTP POST and its response the body of the HTTP response, encoded as the
// encoding NodeId of the service structure followed by the structure. TLS
// protects the messages. The SecurityPolicy of the endpoint, named in the
// OPCUA-SecurityPolicy header, only decides how the nonces of CreateSession
// and ActivateSession are signed (Part 6 §7.4.1); with None they are not.
const (
	// SchemeHTTPS is the URL scheme of HTTPS endpoints (Part 6 §7.4.1). The
	// transport underneath is plain https.
	SchemeHTTPS = "opc.https"

	// HTTPSContentType is the Content-Type of UA Binary messages over
	// HTTPS (Part 6 §7.4.4).
	HTTPSContentType = "application/octet-stream"

	// HTTPSContentTypeLegacy is the Content-Type of UA Binary messages that
	// older applications use; it is accepted for backward compatibility
	// (Part 6 §7.4.2).
	HTTPSContentTypeLegacy = "application/opcua+uabinary"

	// HTTPSSecurityPolicyHeader is the HTTP header that names the security
	// policy of the client (Part 6 §7.4.1). Without it the server assumes
	// None.
	HTTPSSecurityPolicyHeader = "OPCUA-SecurityPolicy"

	// MaxHTTPSMessageSize is the size limit of an HTTPS response body a
	// client accepts.
	MaxHTTPSMessageSize = 16 << 20
)

// IsHTTPSEndpoint reports whether endpoint is an opc.https or https URL.
func IsHTTPSEndpoint(endpoint string) bool {
	scheme, _, ok := strings.Cut(endpoint, "://")
	return ok && (strings.EqualFold(scheme, SchemeHTTPS) || strings.EqualFold(scheme, "https"))
}

// HTTPSURL returns the https URL that the requests to an opc.https (or
// https) endpoint are posted to.
func HTTPSURL(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errors.ErrInvalidEndpoint, err)
	}
	if !strings.EqualFold(u.Scheme, SchemeHTTPS) && !strings.EqualFold(u.Scheme, "https") {
		return "", fmt.Errorf("%w: unsupported scheme %q", errors.ErrInvalidEndpoint, u.Scheme)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("%w: missing host", errors.ErrInvalidEndpoint)
	}
	u.Scheme = "https"
	return u.String(), nil
}

// HTTPSPolicySupported reports whether a security policy can be used over
// HTTPS. A policy that binds the session to the ChannelThumbprint of a secure
// conversation (Part 6 §6.7.5, the policies with SecureChannelEnhancements)
// cannot: HTTPS has no secure conversation and so no thumbprint.
func HTTPSPolicySupported(policyURI string) bool {
	return policyURI == ua.SecurityPolicyURINone ||
		(uapolicy.IsSupported(policyURI) && !uapolicy.SecureChannelEnhancements(policyURI))
}

// NewHTTPSClient returns the HTTP client of the HTTPS transport: HTTP/1.1
// (Part 6 §7.4.4) over TLS 1.2 or later with tlsConfig, nil for the system
// roots. There is no overall request timeout: every request is bounded by
// the timeout of the service call, and a Publish request is held by the
// server until it has something to send.
func NewHTTPSClient(tlsConfig *tls.Config) *http.Client {
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}
	tlsConfig = tlsConfig.Clone()
	if tlsConfig.MinVersion < tls.VersionTLS12 {
		tlsConfig.MinVersion = tls.VersionTLS12
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSClientConfig:     tlsConfig,
			TLSHandshakeTimeout: 10 * time.Second,
			MaxIdleConnsPerHost: 8,
			IdleConnTimeout:     90 * time.Second,
			// HTTP/1.1 only: an empty map turns HTTP/2 off.
			TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
		},
		// A redirect would post the request somewhere the client was not
		// configured to talk to.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// EncodeServiceMessage encodes a service request or response as the body of
// an HTTPS message in UA Binary: the encoding NodeId of its type and the
// structure (Part 6 §7.4.4).
func EncodeServiceMessage(v any) ([]byte, error) {
	typeID := ua.ServiceTypeID(v)
	if typeID == 0 {
		return nil, fmt.Errorf("%w: %T", errors.ErrUnknownService, v)
	}
	buf := ua.NewBuffer(nil)
	buf.WriteStruct(ua.NewFourByteExpandedNodeID(0, typeID))
	buf.WriteStruct(v)
	if err := buf.Error(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// directTransport is the transport of a client channel without a secure
// conversation: HTTPS (NewHTTPSChannel, NewHTTPSJSONChannel), or WebSockets
// with the sub-protocol opcua+uajson (NewWebSocketJSONChannel). Each request
// is an encoded service message sent on its own, and the message that comes
// back is its response.
type directTransport struct {
	// client posts the requests to url over HTTPS; nil with ws.
	client *http.Client
	url    string
	// ws are the WebSockets of a wss-uajson channel.
	ws *wsPool

	// json selects the JSON encoding (Part 6 §5.4.9) over UA Binary.
	// contentType is the Content-Type of an HTTPS request.
	json        bool
	contentType string
	// namespaces is the NamespaceArray of the server, which the JSON
	// encoding uses for the NodeIds of other namespaces (SetNamespaces).
	namespaces atomic.Pointer[[]string]

	// ctx is cancelled when the channel is closed; it ends the requests in
	// flight.
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup // requests sent without waiting for the response
	mu     sync.Mutex     // guards closed and wg.Add
	closed bool
}

// goAsync runs f in the background unless the channel is closed.
func (t *directTransport) goAsync(f func()) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return false
	}
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		f()
	}()
	return true
}

// nsArray returns the NamespaceArray the JSON encoding uses.
func (t *directTransport) nsArray() []string {
	if ns := t.namespaces.Load(); ns != nil {
		return *ns
	}
	return nil
}

// encode encodes a request in the encoding of the transport.
func (t *directTransport) encode(req ua.Request) ([]byte, error) {
	if t.json {
		return EncodeServiceMessageJSON(req, t.nsArray())
	}
	return EncodeServiceMessage(req)
}

// decode decodes a response in the encoding of the transport.
func (t *directTransport) decode(b []byte) (any, error) {
	if t.json {
		return DecodeServiceMessageJSON(b, t.nsArray())
	}
	_, v, err := ua.DecodeService(b)
	return v, err
}

// lostError is the failure of a request to reach the server or to get its
// response back: the connection to the server is gone.
type lostError struct{ err error }

func (e *lostError) Error() string { return e.err.Error() }
func (e *lostError) Unwrap() error { return e.err }

// checkDirectConfig checks the security configuration of a channel without
// a secure conversation.
func checkDirectConfig(cfg *Config, errCh chan<- error) error {
	if cfg == nil {
		return fmt.Errorf("%w: no secure channel config", errors.ErrInvalidSecurityConfig)
	}
	if errCh == nil {
		return fmt.Errorf("%w: no error channel", errors.ErrInvalidState)
	}
	switch {
	case cfg.SecurityPolicyURI == ua.SecurityPolicyURINone && cfg.SecurityMode != ua.MessageSecurityModeNone:
		return fmt.Errorf("%w: policy '%s' cannot be used with '%s'", errors.ErrInvalidSecurityConfig, cfg.SecurityPolicyURI, cfg.SecurityMode)
	case cfg.SecurityPolicyURI != ua.SecurityPolicyURINone && cfg.SecurityMode != ua.MessageSecurityModeSignAndEncrypt && cfg.SecurityMode != ua.MessageSecurityModeSign:
		return fmt.Errorf("%w: policy '%s' can only be used with '%s' or '%s'", errors.ErrInvalidSecurityConfig, cfg.SecurityPolicyURI, ua.MessageSecurityModeSign, ua.MessageSecurityModeSignAndEncrypt)
	case cfg.SecurityPolicyURI != ua.SecurityPolicyURINone && cfg.localKey() == nil:
		return fmt.Errorf("%w: policy '%s' requires a private key", errors.ErrInvalidSecurityConfig, cfg.SecurityPolicyURI)
	case !HTTPSPolicySupported(cfg.SecurityPolicyURI):
		return fmt.Errorf("%w: %s over HTTPS", errors.ErrUnsupportedSecurityPolicy, cfg.SecurityPolicyURI)
	}
	return nil
}

// newDirectChannel returns a client channel with transport t.
func newDirectChannel(endpoint string, cfg *Config, errCh chan<- error, t *directTransport) *SecureChannel {
	t.ctx, t.cancel = context.WithCancel(context.Background())
	return &SecureChannel{
		endpointURL:  endpoint,
		cfg:          cfg,
		requestID:    cfg.RequestIDSeed,
		kind:         client,
		errch:        errCh,
		closing:      make(chan struct{}),
		disconnected: make(chan struct{}),
		instances:    make(map[uint32][]*channelInstance),
		chunks:       make(map[uint32][]*MessageChunk),
		handlers:     make(map[uint32]pendingRequest),
		direct:       t,
	}
}

// NewHTTPSChannel returns a client channel to an opc.https (or https)
// endpoint. It has no connection of its own: Open does nothing and every
// request is posted with httpClient, NewHTTPSClient(nil) if nil. The session
// signatures use cfg like those of a secure conversation, and cfg's
// SecurityPolicyURI is sent in the OPCUA-SecurityPolicy header.
//
// errCh receives the errors that ask for recovery, as for NewSecureChannel:
// a fault that invalidates the session, and the failure of a request to
// reach the server (wrapping io.EOF).
func NewHTTPSChannel(endpoint string, httpClient *http.Client, cfg *Config, errCh chan<- error) (*SecureChannel, error) {
	return newHTTPSChannel(endpoint, httpClient, cfg, errCh, false)
}

// NewHTTPSJSONChannel is NewHTTPSChannel for the JSON encoding (Part 6
// §7.4.5, transport profile https-uajson): the requests and responses are
// JSON messages (Part 6 §5.4.9) with the Content-Type application/json.
func NewHTTPSJSONChannel(endpoint string, httpClient *http.Client, cfg *Config, errCh chan<- error) (*SecureChannel, error) {
	return newHTTPSChannel(endpoint, httpClient, cfg, errCh, true)
}

func newHTTPSChannel(endpoint string, httpClient *http.Client, cfg *Config, errCh chan<- error, json bool) (*SecureChannel, error) {
	if err := checkDirectConfig(cfg, errCh); err != nil {
		return nil, err
	}
	target, err := HTTPSURL(endpoint)
	if err != nil {
		return nil, err
	}
	if httpClient == nil {
		httpClient = NewHTTPSClient(nil)
	}
	t := &directTransport{client: httpClient, url: target, json: json, contentType: HTTPSContentType}
	if json {
		t.contentType = HTTPSJSONContentType
	}
	return newDirectChannel(endpoint, cfg, errCh, t), nil
}

// IsHTTPS reports whether the channel is an HTTPS channel (NewHTTPSChannel,
// NewHTTPSJSONChannel).
func (s *SecureChannel) IsHTTPS() bool { return s.direct != nil && s.direct.client != nil }

// IsJSON reports whether the channel sends its messages in the JSON
// encoding (NewHTTPSJSONChannel, NewWebSocketJSONChannel).
func (s *SecureChannel) IsJSON() bool { return s.direct != nil && s.direct.json }

// SetNamespaces sets the NamespaceArray of the server. The JSON encoding
// writes the NodeIds of namespaces other than 0 with their namespace URI
// and reads them back with it (Part 6 §5.4.2.10); without the array, or for
// an index it does not have, the namespace index is used. It has no effect
// on the other channels.
func (s *SecureChannel) SetNamespaces(ns []string) {
	if s.direct != nil {
		ns = slices.Clone(ns)
		s.direct.namespaces.Store(&ns)
	}
}

// closeDirect closes a channel without a secure conversation: the requests
// in flight are cancelled.
func (s *SecureChannel) closeDirect() error {
	t := s.direct
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
	t.cancel()
	t.wg.Wait()
	if t.ws != nil {
		t.ws.close()
	}
	close(s.closing)
	close(s.disconnected)
	if t.client != nil {
		if tr, ok := t.client.Transport.(interface{ CloseIdleConnections() }); ok {
			tr.CloseIdleConnections()
		}
	}
	return nil
}

// sendDirect sends req and hands the response to h. Without h the request
// is sent in the background and its response dropped.
func (s *SecureChannel) sendDirect(ctx context.Context, req ua.Request, authToken *ua.NodeID, timeout time.Duration, h ResponseHandler) error {
	select {
	case <-s.closing:
		return errors.ErrSecureChannelClosed
	default:
	}
	reqID := s.nextRequestID()
	if _, err := s.setRequestHeader(req, reqID, authToken, timeout); err != nil {
		return err
	}
	body, err := s.direct.encode(req)
	if err != nil {
		return err
	}
	if h == nil {
		if !s.direct.goAsync(func() { _, _ = s.exchange(context.WithoutCancel(ctx), reqID, body, timeout) }) {
			return errors.ErrSecureChannelClosed
		}
		return nil
	}

	msg, err := s.exchange(ctx, reqID, body, timeout)
	if err != nil {
		return err
	}
	if msg.Err != nil && s.notifyMonitor(msg) {
		s.report(&RequestFault{Err: msg.Err, AuthToken: authToken})
	}
	if msg.Err != nil {
		_ = h(msg.Response()) // msg.Err takes precedence
		return msg.Err
	}
	return h(msg.Response())
}

// report hands err to the client's monitor unless one is pending already.
func (s *SecureChannel) report(err error) {
	select {
	case <-s.closing:
	case s.errch <- err:
	default:
	}
}

// exchange sends the encoded request reqID and decodes the response.
func (s *SecureChannel) exchange(ctx context.Context, reqID uint32, body []byte, timeout time.Duration) (*MessageBody, error) {
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(s.direct.ctx, cancel)
	defer stop()
	var expired atomic.Bool
	if timeout > 0 {
		// `+ timeoutLeniency` to give the server a chance to respond to
		// TimeoutHint, as on a secure conversation.
		t := time.AfterFunc(timeout+timeoutLeniency, func() {
			expired.Store(true)
			cancel()
		})
		defer t.Stop()
	}

	s.cfg.Logger.Debug("direct send", "request_id", reqID, "url", s.endpointURL, "bytes", len(body))
	var (
		b   []byte
		err error
	)
	if s.direct.ws != nil {
		b, err = s.exchangeWebSocket(rctx, reqID, body)
	} else {
		b, err = s.postHTTPS(rctx, body)
	}
	// A server may answer a request it saw cancelled (an empty 200 from a
	// handler that returned), and that answer can win the race with the
	// cancellation. Its failure is then the end of ctx, the timeout or the
	// closed channel.
	if end := s.directEnded(ctx, &expired); end != nil {
		return nil, end
	}
	var lost *lostError
	if stderrors.As(err, &lost) {
		// The connection to the server is gone. The monitor recovers it
		// the way it recovers a closed TCP connection. The cause is kept
		// as text only: an error that is a connection refusal would make
		// the monitor give up instead of retrying.
		err = fmt.Errorf("%w: %s: %v", io.EOF, s.directName(), lost.err)
		s.report(err)
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	v, err := s.direct.decode(b)
	if err != nil {
		return nil, err
	}
	r, ok := v.(ua.Response)
	if !ok {
		return nil, fmt.Errorf("%w: %T is not a response", ua.StatusBadUnknownResponse, v)
	}
	if hdr := r.Header(); s.direct.ws != nil && hdr != nil && hdr.RequestHandle != reqID && hdr.RequestHandle != 0 {
		// A WebSocket carries one request at a time, so this is a
		// server that answered some other request.
		return nil, fmt.Errorf("%w: response to request %d, sent %d", ua.StatusBadUnknownResponse, hdr.RequestHandle, reqID)
	}
	s.cfg.Logger.Debug("direct recv", "request_id", reqID, "type", fmt.Sprintf("%T", r), "bytes", len(b))
	msg := &MessageBody{RequestID: reqID, body: r}
	if hdr := r.Header(); hdr != nil && hdr.ServiceResult != ua.StatusOK {
		msg.Err = hdr.ServiceResult
	}
	return msg, nil
}

// directName names the transport of a channel without a secure
// conversation in errors.
func (s *SecureChannel) directName() string {
	if s.direct.ws != nil {
		return "wss"
	}
	return "https"
}

// postHTTPS posts an encoded request and returns the body of the response.
func (s *SecureChannel) postHTTPS(ctx context.Context, body []byte) ([]byte, error) {
	t := s.direct
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Content-Type", t.contentType)
	hreq.Header.Set(HTTPSSecurityPolicyHeader, s.cfg.SecurityPolicyURI)

	resp, err := t.client.Do(hreq)
	if err != nil {
		return nil, &lostError{err}
	}
	defer func() { _ = resp.Body.Close() }()

	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxHTTPSMessageSize+1))
	if err != nil {
		return nil, &lostError{err}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP status %s", ua.StatusBadCommunicationError, resp.Status)
	}
	if len(b) > MaxHTTPSMessageSize {
		return nil, fmt.Errorf("%w: response larger than %d bytes", errors.ErrMessageTooLarge, MaxHTTPSMessageSize)
	}
	return b, nil
}

// directEnded returns why a request must stop, or nil: the end of ctx, the
// closed channel or the timeout of the request.
func (s *SecureChannel) directEnded(ctx context.Context, expired *atomic.Bool) error {
	switch {
	case ctx.Err() != nil:
		return ctx.Err()
	case s.direct.ctx.Err() != nil:
		return errors.ErrSecureChannelClosed
	case expired.Load():
		return ua.StatusBadTimeout
	}
	return nil
}
