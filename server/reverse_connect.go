// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/uacp"
)

// Reverse connect (Part 6 §7.1.3): the server opens the TCP connection to a
// client that is listening for it, announces itself with a ReverseHello
// message and then serves the connection like one it had accepted. It lets a
// server behind a firewall or NAT be reached by a client it can reach itself.

const (
	// DefaultReverseConnectRetryInterval is the delay before the first retry
	// of a failed reverse connection attempt. The delay doubles with every
	// further failure.
	DefaultReverseConnectRetryInterval = 500 * time.Millisecond

	// DefaultReverseConnectMaxRetryInterval is the upper bound of the delay
	// between two reverse connection attempts.
	DefaultReverseConnectMaxRetryInterval = 15 * time.Second

	// DefaultReverseConnectMaxConnections is the default number of
	// connections one reverse connect target may have in use at a time.
	DefaultReverseConnectMaxConnections = 8
)

// ReverseConnectState is the state of a reverse connect target.
type ReverseConnectState int

const (
	// ReverseConnectConnecting: the server is opening a connection to the
	// client. This is also the state of a target whose server has not been
	// started yet.
	ReverseConnectConnecting ReverseConnectState = iota

	// ReverseConnectWaiting: a connection is open and announced with a
	// ReverseHello message; the client has not used it yet.
	ReverseConnectWaiting

	// ReverseConnectConnected: the client uses at least one connection.
	ReverseConnectConnected

	// ReverseConnectBackoff: the last attempt failed (see
	// [ReverseConnect.Err]) and the server waits before it tries again.
	ReverseConnectBackoff

	// ReverseConnectClosed: the target was removed or the server closed.
	ReverseConnectClosed
)

// String returns the name of the state.
func (s ReverseConnectState) String() string {
	switch s {
	case ReverseConnectConnecting:
		return "Connecting"
	case ReverseConnectWaiting:
		return "Waiting"
	case ReverseConnectConnected:
		return "Connected"
	case ReverseConnectBackoff:
		return "Backoff"
	case ReverseConnectClosed:
		return "Closed"
	default:
		return fmt.Sprintf("ReverseConnectState(%d)", int(s))
	}
}

// ReverseConnectOption configures a reverse connect target. See
// [WithReverseConnect] and [Server.AddReverseConnect].
type ReverseConnectOption func(*reverseConnectConfig)

type reverseConnectConfig struct {
	endpointURL    string
	retryInterval  time.Duration
	maxRetry       time.Duration
	maxConnections int
}

// ReverseConnectEndpointURL sets the EndpointUrl announced in the
// ReverseHello message: the URL of the endpoint the client is to use for the
// secure channel and the session. It defaults to the first endpoint of the
// server (see [EndPoint]).
func ReverseConnectEndpointURL(url string) ReverseConnectOption {
	return func(c *reverseConnectConfig) { c.endpointURL = url }
}

// ReverseConnectRetryInterval sets the delay before the first retry of a
// failed connection attempt and the upper bound the delay grows to as
// attempts keep failing (it doubles each time). Values that are not positive
// select the defaults, [DefaultReverseConnectRetryInterval] and
// [DefaultReverseConnectMaxRetryInterval].
func ReverseConnectRetryInterval(initial, max time.Duration) ReverseConnectOption {
	return func(c *reverseConnectConfig) {
		c.retryInterval = initial
		c.maxRetry = max
	}
}

// ReverseConnectMaxConnections limits the number of connections the client
// may have in use at a time. While the limit is reached the server does not
// open another idle connection. A value that is not positive selects
// [DefaultReverseConnectMaxConnections].
func ReverseConnectMaxConnections(n int) ReverseConnectOption {
	return func(c *reverseConnectConfig) { c.maxConnections = n }
}

func newReverseConnectConfig(opts []ReverseConnectOption) reverseConnectConfig {
	var c reverseConnectConfig
	for _, opt := range opts {
		if opt != nil {
			opt(&c)
		}
	}
	if c.retryInterval <= 0 {
		c.retryInterval = DefaultReverseConnectRetryInterval
	}
	if c.maxRetry <= 0 {
		c.maxRetry = DefaultReverseConnectMaxRetryInterval
	}
	if c.maxRetry < c.retryInterval {
		c.maxRetry = c.retryInterval
	}
	if c.maxConnections <= 0 {
		c.maxConnections = DefaultReverseConnectMaxConnections
	}
	return c
}

// reverseConnectSpec is a target configured with WithReverseConnect.
type reverseConnectSpec struct {
	clientURL string
	opts      []ReverseConnectOption
}

// WithReverseConnect makes the server open reverse connections to the client
// listening at clientURL ("opc.tcp://host:port") once it is started. See
// [Server.AddReverseConnect] for the details; the handles of the targets
// configured this way are available from [Server.ReverseConnects].
func WithReverseConnect(clientURL string, opts ...ReverseConnectOption) Option {
	return func(s *serverConfig) error {
		if _, _, err := uacp.ParseEndpoint(clientURL); err != nil {
			return fmt.Errorf("server: reverse connect: %w", err)
		}
		s.reverseConnects = append(s.reverseConnects, reverseConnectSpec{clientURL: clientURL, opts: opts})
		return nil
	}
}

// ReverseConnect is a reverse connect target: a client the server connects
// to. It is returned by [Server.AddReverseConnect].
type ReverseConnect struct {
	srv       *Server
	clientURL string
	cfg       reverseConnectConfig

	// kick wakes the connection loop when a connection ended: the client
	// may want a new one right away, and a slot became free.
	kick chan struct{}

	// done is closed when the connection loop has stopped and wg counts the
	// connections being served.
	done chan struct{}
	wg   sync.WaitGroup

	mu      sync.Mutex
	phase   ReverseConnectState
	err     error
	conns   map[*uacp.Conn]struct{}
	cancel  context.CancelFunc
	started bool
	closed  bool
}

// ClientURL returns the URL of the client the server connects to.
func (rc *ReverseConnect) ClientURL() string { return rc.clientURL }

// State returns the current state of the target.
func (rc *ReverseConnect) State() ReverseConnectState {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	switch {
	case rc.closed:
		return ReverseConnectClosed
	case len(rc.conns) > 0:
		return ReverseConnectConnected
	default:
		return rc.phase
	}
}

// Connections returns the number of connections the client currently uses.
func (rc *ReverseConnect) Connections() int {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return len(rc.conns)
}

// Err returns the reason the most recent connection attempt failed, or nil
// if it succeeded or none was made yet. A client that refuses the server
// (for example because it expects another ServerUri) shows up here.
func (rc *ReverseConnect) Err() error {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.err
}

// Close removes the target from the server: the server stops connecting to
// the client and closes the connections it opened to it, which ends the
// secure channels on them. Sessions and subscriptions are not deleted; they
// time out as after any other connection loss. Close is idempotent.
func (rc *ReverseConnect) Close() error {
	rc.srv.forgetReverseConnect(rc)
	rc.shutdown()
	return nil
}

// shutdown stops the connection loop, closes the connections and waits for
// both.
func (rc *ReverseConnect) shutdown() {
	rc.mu.Lock()
	rc.closed = true
	started := rc.started
	cancel := rc.cancel
	conns := make([]*uacp.Conn, 0, len(rc.conns))
	for c := range rc.conns {
		conns = append(conns, c)
	}
	rc.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	for _, c := range conns {
		_ = c.Close()
	}
	if started {
		<-rc.done
	}
	rc.wg.Wait()
}

// start launches the connection loop. ctx is the context of the server.
func (rc *ReverseConnect) start(ctx context.Context) {
	rc.mu.Lock()
	if rc.closed || rc.started {
		rc.mu.Unlock()
		return
	}
	rc.started = true
	ctx, rc.cancel = context.WithCancel(ctx)
	rc.mu.Unlock()

	go rc.run(ctx)
}

func (rc *ReverseConnect) setPhase(p ReverseConnectState) {
	rc.mu.Lock()
	rc.phase = p
	rc.mu.Unlock()
}

func (rc *ReverseConnect) setResult(p ReverseConnectState, err error) {
	rc.mu.Lock()
	rc.phase = p
	rc.err = err
	rc.mu.Unlock()
}

// run keeps one idle connection to the client available until ctx is done.
//
// Each round opens a connection, announces the server and waits for the
// client to use the connection. Once it does, the connection is served in
// the background and the next round provides the next idle connection, so
// that the client can open a further channel (or replace a broken one)
// without having to wait for a retry.
func (rc *ReverseConnect) run(ctx context.Context) {
	defer close(rc.done)
	// A panic in here must not end the process; the target is lost.
	defer func() {
		if r := recover(); r != nil {
			logPanic(rc.srv.cfg.logger, "running a reverse connect", r, "client", rc.clientURL)
		}
	}()

	log := rc.srv.cfg.logger
	dialer := &uacp.ReverseDialer{
		Dialer: &net.Dialer{Timeout: uacp.DefaultDialTimeout},
		Logger: log,
	}

	delay := rc.cfg.retryInterval
	for ctx.Err() == nil {
		if !rc.waitForSlot(ctx) {
			return
		}
		rc.setPhase(ReverseConnectConnecting)
		err := rc.attempt(ctx, dialer)
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			delay = rc.cfg.retryInterval
			continue
		}
		rc.setResult(ReverseConnectBackoff, err)
		log.Debug("reverse connect failed", "client", rc.clientURL, "error", err, "retry_in", delay)

		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
			delay = min(2*delay, rc.cfg.maxRetry)
		case <-rc.kick:
			// A connection ended: the client is likely to be waiting for
			// the server already, so do not sit out a long delay.
			delay = rc.cfg.retryInterval
		}
	}
}

// waitForSlot blocks while the client uses as many connections as it may.
// It reports false if ctx is done.
func (rc *ReverseConnect) waitForSlot(ctx context.Context) bool {
	for {
		rc.mu.Lock()
		n := len(rc.conns)
		rc.mu.Unlock()
		if n < rc.cfg.maxConnections {
			return ctx.Err() == nil
		}
		select {
		case <-ctx.Done():
			return false
		case <-rc.kick:
		}
	}
}

// attempt opens one connection, announces the server on it and waits for
// the client's Hello. It returns nil once the connection is being served.
func (rc *ReverseConnect) attempt(ctx context.Context, dialer *uacp.ReverseDialer) error {
	s := rc.srv
	endpoint := rc.cfg.endpointURL
	if endpoint == "" {
		endpoint = s.firstEndpointURL()
	}
	rhe := &uacp.ReverseHello{ServerURI: s.cfg.applicationURI, EndpointURL: endpoint}

	conn, err := dialer.Dial(ctx, rc.clientURL, rhe)
	if err != nil {
		return err
	}
	rc.setPhase(ReverseConnectWaiting)

	// The client answers whenever it wants to use the connection, so there
	// is no deadline. A connection whose peer is gone is detected by TCP
	// keep-alive.
	if err := conn.AcceptHello(ctx, endpoint); err != nil {
		_ = conn.Close()
		return err
	}

	rc.mu.Lock()
	if rc.closed {
		rc.mu.Unlock()
		_ = conn.Close()
		return context.Canceled
	}
	rc.conns[conn] = struct{}{}
	rc.err = nil
	rc.wg.Add(1)
	rc.mu.Unlock()
	s.cfg.logger.Info("registered reverse connection", "remote_addr", conn.RemoteAddr())

	go func() {
		defer rc.wg.Done()
		defer func() {
			rc.mu.Lock()
			delete(rc.conns, conn)
			rc.mu.Unlock()
			select {
			case rc.kick <- struct{}{}:
			default:
			}
		}()
		// The connection is served under the server's context, like an
		// accepted one: removing the target closes it explicitly.
		s.serveConn(s.serveContext(), conn)
	}()
	return nil
}

// AddReverseConnect makes the server open reverse connections to the client
// listening at clientURL ("opc.tcp://host:port").
//
// The server connects to the client, announces itself with a ReverseHello
// message (carrying its ApplicationUri and the URL of the endpoint the
// client is to use) and waits for the client to open a secure channel on the
// connection. From then on the connection is served exactly like one the
// client had opened itself, with every security policy and service the
// server offers. As soon as the client uses a connection the server opens
// the next one, so that one idle connection is always available. An attempt
// that fails, because the client is not listening or refuses the server, is
// repeated with an increasing delay; a connection that breaks is replaced at
// once.
//
// A target added before [Server.Start] becomes active when the server
// starts. Targets are removed with [ReverseConnect.Close] and when the
// server closes.
func (s *Server) AddReverseConnect(clientURL string, opts ...ReverseConnectOption) (*ReverseConnect, error) {
	if _, _, err := uacp.ParseEndpoint(clientURL); err != nil {
		return nil, fmt.Errorf("server: reverse connect: %w", err)
	}
	rc := &ReverseConnect{
		srv:       s,
		clientURL: clientURL,
		cfg:       newReverseConnectConfig(opts),
		kick:      make(chan struct{}, 1),
		done:      make(chan struct{}),
		conns:     make(map[*uacp.Conn]struct{}),
	}

	s.rcMu.Lock()
	if s.rcClosed {
		s.rcMu.Unlock()
		return nil, fmt.Errorf("server: reverse connect: server is closed")
	}
	s.reverseConnects = append(s.reverseConnects, rc)
	ctx := s.rcCtx
	s.rcMu.Unlock()

	if ctx != nil {
		rc.start(ctx)
	}
	return rc, nil
}

// ReverseConnects returns the reverse connect targets of the server, in the
// order they were added.
func (s *Server) ReverseConnects() []*ReverseConnect {
	s.rcMu.Lock()
	defer s.rcMu.Unlock()
	return append([]*ReverseConnect(nil), s.reverseConnects...)
}

func (s *Server) forgetReverseConnect(rc *ReverseConnect) {
	s.rcMu.Lock()
	defer s.rcMu.Unlock()
	for i, q := range s.reverseConnects {
		if q == rc {
			s.reverseConnects = append(s.reverseConnects[:i], s.reverseConnects[i+1:]...)
			return
		}
	}
}

// startReverseConnects activates the configured targets and those added
// before Start. ctx is the context of the running server.
func (s *Server) startReverseConnects(ctx context.Context) error {
	for _, spec := range s.cfg.reverseConnects {
		if _, err := s.AddReverseConnect(spec.clientURL, spec.opts...); err != nil {
			return err
		}
	}
	s.cfg.reverseConnects = nil

	s.rcMu.Lock()
	s.rcCtx = ctx
	targets := append([]*ReverseConnect(nil), s.reverseConnects...)
	s.rcMu.Unlock()
	for _, rc := range targets {
		rc.start(ctx)
	}
	return nil
}

// closeReverseConnects stops all targets. No target can be added afterwards.
func (s *Server) closeReverseConnects() {
	s.rcMu.Lock()
	s.rcClosed = true
	targets := s.reverseConnects
	s.reverseConnects = nil
	s.rcMu.Unlock()
	for _, rc := range targets {
		rc.shutdown()
	}
}

// serveContext returns the context connections are served under.
func (s *Server) serveContext() context.Context {
	s.rcMu.Lock()
	defer s.rcMu.Unlock()
	if s.rcCtx == nil {
		return context.Background()
	}
	return s.rcCtx
}

// firstEndpointURL returns the URL of the server's first endpoint.
func (s *Server) firstEndpointURL() string {
	if eps := s.URLs(); len(eps) > 0 {
		return eps[0]
	}
	return s.url
}
