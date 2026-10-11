// SPDX-License-Identifier: MIT

package uacp

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
)

// Reverse connect (Part 6 §7.1.3).
//
// In a reverse connection the roles of the TCP peers are swapped: the OPC UA
// server opens the socket to a listening client and announces itself with a
// ReverseHello message. From then on the connection is used exactly like one
// the client had opened: the client answers with Hello, the server with
// Acknowledge, and the client opens the secure channel.
//
// The server side is ReverseDialer plus Conn.AcceptHello, the client side is
// ReverseListener plus Dialer.AcceptReverse.

const (
	// MaxReverseHelloURILength is the largest ServerUri and EndpointUrl a
	// ReverseHello message may carry, in bytes (Part 6 §7.1.2.6).
	MaxReverseHelloURILength = 4096

	// maxReverseHelloSize is the size of the largest valid ReverseHello
	// message: the header and two length-prefixed strings.
	maxReverseHelloSize = hdrlen + 2*(4+MaxReverseHelloURILength)

	// minReverseHelloSize is the size of the smallest ReverseHello message:
	// the header and two (empty or null) strings.
	minReverseHelloSize = hdrlen + 2*4

	// DefaultReverseHelloTimeout is how long a ReverseListener waits for the
	// ReverseHello message of a connection it has accepted.
	DefaultReverseHelloTimeout = 10 * time.Second

	// DefaultMaxReverseHandshakes is the default number of accepted
	// connections a ReverseListener lets wait for their ReverseHello message
	// at the same time.
	DefaultMaxReverseHandshakes = 16

	// DefaultMaxPendingReverse is the default number of announced connections
	// a ReverseListener keeps for a client that has not asked for them yet.
	DefaultMaxPendingReverse = 16
)

// validate reports whether r respects the limits of Part 6 §7.1.2.6.
func (r *ReverseHello) validate() error {
	if len(r.ServerURI) > MaxReverseHelloURILength {
		return fmt.Errorf("%w: ReverseHello ServerUri has %d bytes, the limit is %d", errors.ErrMessageTooLarge, len(r.ServerURI), MaxReverseHelloURILength)
	}
	if len(r.EndpointURL) > MaxReverseHelloURILength {
		return fmt.Errorf("%w: ReverseHello EndpointUrl has %d bytes, the limit is %d", errors.ErrMessageTooLarge, len(r.EndpointURL), MaxReverseHelloURILength)
	}
	return nil
}

// reverseHelloError is an error of the ReverseHello exchange together with
// the status code that is reported to the peer.
type reverseHelloError struct {
	code ua.StatusCode
	err  error
}

func (e *reverseHelloError) Error() string { return e.err.Error() }
func (e *reverseHelloError) Unwrap() error { return e.err }

// readReverseHello reads one ReverseHello message from c. Nothing but the
// eight header bytes is read before the announced size has been checked
// against the limit, so a peer cannot make the listener allocate or wait for
// more than maxReverseHelloSize bytes.
func readReverseHello(c io.Reader) (*ReverseHello, error) {
	var hdr [hdrlen]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return nil, err
	}
	var h Header
	if _, err := h.Decode(hdr[:]); err != nil {
		return nil, &reverseHelloError{ua.StatusBadTCPInternalError, fmt.Errorf("uacp: header decode failed: %w", err)}
	}
	if h.MessageType != MessageTypeReverseHello || h.ChunkType != ChunkTypeFinal {
		return nil, &reverseHelloError{ua.StatusBadTCPMessageTypeInvalid,
			fmt.Errorf("%w: %q: expected ReverseHello", errors.ErrInvalidMessageType, h.MessageType+string(rune(h.ChunkType)))}
	}
	if h.MessageSize > maxReverseHelloSize {
		return nil, &reverseHelloError{ua.StatusBadTCPMessageTooLarge,
			fmt.Errorf("%w: ReverseHello of %d bytes, the limit is %d", errors.ErrMessageTooLarge, h.MessageSize, maxReverseHelloSize)}
	}
	if h.MessageSize < minReverseHelloSize {
		return nil, &reverseHelloError{ua.StatusBadTCPInternalError,
			fmt.Errorf("%w: ReverseHello of %d bytes", errors.ErrMessageTooSmall, h.MessageSize)}
	}

	body := make([]byte, h.MessageSize-hdrlen)
	if _, err := io.ReadFull(c, body); err != nil {
		return nil, err
	}
	rhe := new(ReverseHello)
	n, err := rhe.Decode(body)
	if err != nil {
		return nil, &reverseHelloError{ua.StatusBadTCPInternalError, fmt.Errorf("uacp: decode RHE failed: %w", err)}
	}
	if n != len(body) {
		return nil, &reverseHelloError{ua.StatusBadTCPInternalError,
			fmt.Errorf("uacp: decode RHE failed: %d trailing bytes", len(body)-n)}
	}
	if err := rhe.validate(); err != nil {
		return nil, &reverseHelloError{ua.StatusBadTCPMessageTooLarge, err}
	}
	return rhe, nil
}

// ReverseDialer opens reverse connections. It is the server's counterpart of
// Dialer: it connects to a listening client and announces the server with a
// ReverseHello message.
type ReverseDialer struct {
	// Dialer establishes the TCP connection. Defaults to a net.Dialer with
	// DefaultDialTimeout.
	Dialer *net.Dialer

	// ACK defines the connection limits of the server. Defaults to
	// DefaultServerACK.
	ACK *Acknowledge

	// Logger is the logger for connection-level messages.
	// If nil, logging is disabled.
	Logger *slog.Logger
}

// Dial connects to the client listening at clientURL ("opc.tcp://host:port")
// and sends the ReverseHello message rhe. The returned connection is not
// usable until the client has answered with Hello: call Conn.AcceptHello.
//
// The dial timeout covers the TCP connect and the sending of the message.
func (d *ReverseDialer) Dial(ctx context.Context, clientURL string, rhe *ReverseHello) (*Conn, error) {
	if rhe == nil {
		return nil, fmt.Errorf("uacp: no ReverseHello message")
	}
	if err := rhe.validate(); err != nil {
		return nil, err
	}
	_, raddr, err := ParseEndpoint(clientURL)
	if err != nil {
		return nil, err
	}

	dl := d.Dialer
	if dl == nil {
		dl = defaultNetDialer()
	}
	if dl.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, dl.Timeout)
		defer cancel()
	}

	c, err := dl.DialContext(ctx, "tcp", raddr.Host)
	if err != nil {
		return nil, err
	}
	ack := d.ACK
	if ack == nil {
		ack = DefaultServerACK
	}
	conn, err := NewConn(c.(*net.TCPConn), ack)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	conn.logger = d.Logger

	if t, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(t)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetWriteDeadline(time.Now()) })
	err = conn.Send(MessageTypeReverseHello+string(rune(ChunkTypeFinal)), rhe)
	if !stop() && err == nil {
		err = ctx.Err()
	}
	if err != nil {
		_ = conn.Close()
		return nil, handshakeError(ctx, err)
	}
	_ = conn.SetWriteDeadline(time.Time{})
	conn.logDebug("sent RHE", "conn_id", conn.id, "client", clientURL, "server_uri", rhe.ServerURI, "endpoint", rhe.EndpointURL)
	return conn, nil
}

// AcceptHello performs the server side of the HEL/ACK exchange on a
// connection: it waits for the Hello message of the client, checks that it
// names endpoint, and answers with Acknowledge.
//
// It is meant for reverse connections (see ReverseDialer), where the Hello
// message arrives whenever the client decides to use the connection, which
// can be long after it was opened. AcceptHello therefore waits until ctx is
// done.
func (c *Conn) AcceptHello(ctx context.Context, endpoint string) (err error) {
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Now()) })
	defer stop()

	err = func() (err error) {
		// A panic while decoding what a peer sent must end this connection,
		// not the process.
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("uacp: panic during handshake: %v\n%s", r, debug.Stack())
			}
		}()
		return c.srvhandshake(endpoint)
	}()
	if err != nil {
		return handshakeError(ctx, err)
	}
	// See Handshake: do not hand out a connection whose deadline is about to
	// be expired by the cancellation hook.
	if !stop() {
		return ctx.Err()
	}
	_ = c.SetDeadline(time.Time{})
	return nil
}

// ReverseListenerConfig configures a ReverseListener. The zero value is a
// usable configuration.
type ReverseListenerConfig struct {
	// Filter is called with every ReverseHello message that arrives. A
	// connection for which it returns an error is refused: it is answered
	// with an Error message and closed. Use it to admit only the servers
	// that are expected to connect. If nil, every server is admitted.
	//
	// Filter is called from the goroutines of the listener and must not
	// block.
	Filter func(*ReverseHello) error

	// HelloTimeout is how long an accepted connection may take to deliver
	// its ReverseHello message. Defaults to DefaultReverseHelloTimeout.
	HelloTimeout time.Duration

	// MaxHandshakes is the number of accepted connections that may be
	// waiting for their ReverseHello message at the same time. Connections
	// beyond the limit are closed at once. Defaults to
	// DefaultMaxReverseHandshakes.
	MaxHandshakes int

	// MaxPending is the number of announced connections that are kept for a
	// client that has not asked for them yet. When the limit is reached the
	// oldest pending connection is closed. Defaults to
	// DefaultMaxPendingReverse.
	MaxPending int

	// Logger is the logger for connection-level messages.
	// If nil, logging is disabled.
	Logger *slog.Logger
}

// ReverseListener accepts reverse connections: TCP connections opened by OPC
// UA servers that announce themselves with a ReverseHello message.
//
// One listener can serve any number of clients and servers. A connection
// that no client is waiting for is kept (a server keeps one idle connection
// open for exactly that purpose, see Part 6 §7.1.3) until a client asks for
// it with Accept, the server closes it, or it is displaced by a newer
// connection of the same server.
//
// Nothing a server says in its ReverseHello message is authenticated. The
// message only selects the client the connection is handed to; the server
// proves its identity in the secure channel that is opened afterwards.
type ReverseListener struct {
	l   net.Listener
	cfg ReverseListenerConfig

	closed    chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup

	mu         sync.Mutex
	handshakes map[*net.TCPConn]struct{}
	pending    []*reverseConn
	waiters    []*reverseWaiter

	// rejected counts the connections refused by the filter and lastReject
	// is the reason of the latest refusal.
	rejected   uint64
	lastReject error
}

// reverseConn is an announced connection.
type reverseConn struct {
	c   *net.TCPConn
	rhe *ReverseHello

	// A pending connection is watched for being closed by the server. done
	// is closed when the watcher has stopped and dead tells whether it found
	// the connection unusable. Both are unset for a connection that went
	// straight to a waiting client.
	claimed atomic.Bool
	done    chan struct{}
	dead    bool
}

// reverseWaiter is a client waiting in Accept.
type reverseWaiter struct {
	match func(*ReverseHello) error
	ch    chan *reverseConn
}

// ListenReverse opens a listener for reverse connections on addr, which is
// either a "host:port" address or an "opc.tcp://host:port" URL. An empty or
// unspecified host listens on all addresses, port 0 picks a free port. cfg
// may be nil.
func ListenReverse(ctx context.Context, addr string, cfg *ReverseListenerConfig) (*ReverseListener, error) {
	hostport := addr
	if strings.Contains(addr, "://") {
		_, u, err := ParseEndpoint(addr)
		if err != nil {
			return nil, err
		}
		hostport = u.Host
	}
	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", hostport)
	if err != nil {
		return nil, err
	}
	return NewReverseListener(l, cfg), nil
}

// NewReverseListener returns a ReverseListener that accepts the connections
// of l, which must be a TCP listener. The ReverseListener owns l from now on
// and closes it when it is closed. cfg may be nil.
func NewReverseListener(l net.Listener, cfg *ReverseListenerConfig) *ReverseListener {
	rl := &ReverseListener{
		l:          l,
		closed:     make(chan struct{}),
		handshakes: make(map[*net.TCPConn]struct{}),
	}
	if cfg != nil {
		rl.cfg = *cfg
	}
	if rl.cfg.HelloTimeout <= 0 {
		rl.cfg.HelloTimeout = DefaultReverseHelloTimeout
	}
	if rl.cfg.MaxHandshakes <= 0 {
		rl.cfg.MaxHandshakes = DefaultMaxReverseHandshakes
	}
	if rl.cfg.MaxPending <= 0 {
		rl.cfg.MaxPending = DefaultMaxPendingReverse
	}
	rl.wg.Add(1)
	go rl.acceptLoop()
	return rl
}

// Addr returns the listener's network address.
func (l *ReverseListener) Addr() net.Addr { return l.l.Addr() }

// Pending returns the number of announced connections no client has asked
// for yet.
func (l *ReverseListener) Pending() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.pending)
}

// Close closes the listener together with all connections that have not been
// handed to a client, and waits for the goroutines of the listener to stop.
// Connections returned by Accept are not affected.
func (l *ReverseListener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		// The lock orders this with offer and the accept loop, which start
		// goroutines only as long as the listener is not closed.
		l.mu.Lock()
		close(l.closed)
		conns := make([]*net.TCPConn, 0, len(l.handshakes)+len(l.pending))
		for c := range l.handshakes {
			conns = append(conns, c)
		}
		for _, p := range l.pending {
			conns = append(conns, p.c)
		}
		l.pending = nil
		l.mu.Unlock()

		err = l.l.Close()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	l.wg.Wait()
	return err
}

func (l *ReverseListener) isClosed() bool {
	select {
	case <-l.closed:
		return true
	default:
		return false
	}
}

func (l *ReverseListener) closedError() error {
	return &net.OpError{Op: "accept", Net: "tcp", Addr: l.l.Addr(), Err: net.ErrClosed}
}

func (l *ReverseListener) logDebug(msg string, args ...any) {
	if l.cfg.Logger != nil {
		l.cfg.Logger.Debug(msg, args...)
	}
}

func (l *ReverseListener) logWarn(msg string, args ...any) {
	if l.cfg.Logger != nil {
		l.cfg.Logger.Warn(msg, args...)
	}
}

func (l *ReverseListener) acceptLoop() {
	defer l.wg.Done()
	for {
		nc, err := l.l.Accept()
		if err != nil {
			if l.isClosed() {
				return
			}
			l.logWarn("reverse listener: accept failed", "error", err)
			// Do not spin on a persistent accept error (e.g. EMFILE).
			select {
			case <-l.closed:
				return
			case <-time.After(10 * time.Millisecond):
			}
			continue
		}
		c, ok := nc.(*net.TCPConn)
		if !ok {
			l.logWarn("reverse listener: not a TCP connection", "type", fmt.Sprintf("%T", nc))
			_ = nc.Close()
			continue
		}

		l.mu.Lock()
		if l.isClosed() || len(l.handshakes) >= l.cfg.MaxHandshakes {
			l.mu.Unlock()
			l.logWarn("reverse listener: too many unannounced connections, dropping one", "remote_addr", c.RemoteAddr())
			_ = c.Close()
			continue
		}
		l.handshakes[c] = struct{}{}
		l.wg.Add(1)
		l.mu.Unlock()
		go l.handshake(c)
	}
}

// handshake reads the ReverseHello message of an accepted connection and
// hands the connection to a waiting client or keeps it as pending.
func (l *ReverseListener) handshake(c *net.TCPConn) {
	defer l.wg.Done()

	_ = c.SetDeadline(time.Now().Add(l.cfg.HelloTimeout))
	rhe, err := func() (rhe *ReverseHello, err error) {
		// A panic while decoding what a peer sent must end this connection,
		// not the process: this goroutine belongs to the listener.
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("uacp: panic during reverse handshake: %v\n%s", r, debug.Stack())
			}
		}()
		return readReverseHello(c)
	}()
	if err == nil && l.cfg.Filter != nil {
		if ferr := l.cfg.Filter(rhe); ferr != nil {
			code := ua.StatusBadTCPEndpointURLInvalid
			var sc ua.StatusCode
			if errors.As(ferr, &sc) {
				code = sc
			}
			err = &reverseHelloError{code, ferr}
			l.mu.Lock()
			l.rejected++
			l.lastReject = ferr
			l.mu.Unlock()
		}
	}

	l.mu.Lock()
	delete(l.handshakes, c)
	l.mu.Unlock()

	if err != nil {
		l.logWarn("reverse listener: connection refused", "remote_addr", c.RemoteAddr(), "error", err)
		var rerr *reverseHelloError
		if errors.As(err, &rerr) {
			// The reason is not sent: it would tell an unauthenticated peer
			// what the client expects.
			sendError(c, rerr.code)
		}
		_ = c.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})
	l.logDebug("reverse listener: received RHE", "remote_addr", c.RemoteAddr(), "server_uri", rhe.ServerURI, "endpoint", rhe.EndpointURL)
	l.offer(&reverseConn{c: c, rhe: rhe})
}

// sendError writes an Error message with the given code to c.
func sendError(c net.Conn, code ua.StatusCode) {
	body, err := (&Error{ErrorCode: uint32(code)}).Encode()
	if err != nil {
		return
	}
	h := Header{MessageType: MessageTypeError, ChunkType: ChunkTypeFinal, MessageSize: uint32(len(body) + hdrlen)}
	hdr, err := h.Encode()
	if err != nil {
		return
	}
	_, _ = c.Write(append(hdr, body...))
}

// offer hands p to the first waiting client that wants it and keeps it as
// pending otherwise.
func (l *ReverseListener) offer(p *reverseConn) {
	l.mu.Lock()
	if l.isClosed() {
		l.mu.Unlock()
		_ = p.c.Close()
		return
	}
	for i, w := range l.waiters {
		if w.match == nil || w.match(p.rhe) == nil {
			l.waiters = append(l.waiters[:i], l.waiters[i+1:]...)
			w.ch <- p // buffered
			l.mu.Unlock()
			return
		}
	}

	// Nobody is waiting for it. A newer connection of the same server
	// displaces an older one: the older one is the more likely to be stale.
	var evict []*reverseConn
	kept := l.pending[:0]
	for _, q := range l.pending {
		if q.rhe.ServerURI == p.rhe.ServerURI && q.rhe.EndpointURL == p.rhe.EndpointURL {
			evict = append(evict, q)
			continue
		}
		kept = append(kept, q)
	}
	l.pending = kept
	for len(l.pending) >= l.cfg.MaxPending {
		evict = append(evict, l.pending[0])
		l.pending = l.pending[1:]
	}
	p.claimed.Store(false)
	p.done = make(chan struct{})
	p.dead = false
	l.pending = append(l.pending, p)
	l.wg.Add(1)
	l.mu.Unlock()

	go l.watch(p)
	for _, q := range evict {
		l.logDebug("reverse listener: dropping pending connection", "server_uri", q.rhe.ServerURI)
		_ = q.c.Close() // ends its watcher
	}
}

// watch waits for a pending connection to be closed by the server (or to
// misbehave: a server must not send anything before the client's Hello) and
// removes it then, so that clients are not handed dead connections.
func (l *ReverseListener) watch(p *reverseConn) {
	defer l.wg.Done()
	defer close(p.done)

	var b [1]byte
	_, err := p.c.Read(b[:])
	var nerr net.Error
	if p.claimed.Load() && errors.As(err, &nerr) && nerr.Timeout() {
		// interrupted by claim: the connection is alive
		return
	}
	p.dead = true
	l.mu.Lock()
	for i, q := range l.pending {
		if q == p {
			l.pending = append(l.pending[:i], l.pending[i+1:]...)
			break
		}
	}
	l.mu.Unlock()
	_ = p.c.Close()
}

// claim stops the watcher of a pending connection that was removed from the
// list and reports whether the connection is usable.
func (l *ReverseListener) claim(p *reverseConn) bool {
	if p.done == nil {
		return true
	}
	p.claimed.Store(true)
	_ = p.c.SetReadDeadline(time.Unix(1, 0))
	<-p.done
	if p.dead {
		return false
	}
	_ = p.c.SetReadDeadline(time.Time{})
	return true
}

// Accept returns a reverse connection whose ReverseHello message satisfies
// match, together with that message. It prefers the most recent pending
// connection and otherwise waits for a server to connect until ctx is done.
// A nil match accepts any server.
//
// The returned connection is a plain TCP connection on which nothing but the
// ReverseHello message was exchanged. Most callers want Dialer.AcceptReverse
// instead, which also performs the HEL/ACK handshake.
//
// match must not block and must not call methods of the listener.
func (l *ReverseListener) Accept(ctx context.Context, match func(*ReverseHello) error) (*net.TCPConn, *ReverseHello, error) {
	l.mu.Lock()
	rejected := l.rejected
	l.mu.Unlock()

	for {
		l.mu.Lock()
		if l.isClosed() {
			l.mu.Unlock()
			return nil, nil, l.closedError()
		}
		var p *reverseConn
		for i := len(l.pending) - 1; i >= 0; i-- {
			if q := l.pending[i]; match == nil || match(q.rhe) == nil {
				p = q
				l.pending = append(l.pending[:i], l.pending[i+1:]...)
				break
			}
		}
		if p != nil {
			l.mu.Unlock()
			if l.claim(p) {
				return p.c, p.rhe, nil
			}
			continue // it died while it was pending
		}
		w := &reverseWaiter{match: match, ch: make(chan *reverseConn, 1)}
		l.waiters = append(l.waiters, w)
		l.mu.Unlock()

		select {
		case p := <-w.ch:
			return p.c, p.rhe, nil
		case <-ctx.Done():
			l.abandon(w)
			return nil, nil, l.waitError(ctx.Err(), rejected)
		case <-l.closed:
			l.abandon(w)
			return nil, nil, l.closedError()
		}
	}
}

// abandon removes a waiter that gave up. A connection that was handed to it
// in the meantime is offered to the other clients.
func (l *ReverseListener) abandon(w *reverseWaiter) {
	l.mu.Lock()
	for i, q := range l.waiters {
		if q == w {
			l.waiters = append(l.waiters[:i], l.waiters[i+1:]...)
			break
		}
	}
	l.mu.Unlock()
	// Connections are handed over with the lock held, so nothing can arrive
	// on the channel any more.
	select {
	case p := <-w.ch:
		l.offer(p)
	default:
	}
}

// waitError describes why Accept gave up. It wraps cause and, if a server was
// refused by the filter while the caller was waiting, the reason of that.
func (l *ReverseListener) waitError(cause error, rejectedBefore uint64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.rejected != rejectedBefore && l.lastReject != nil {
		return fmt.Errorf("uacp: no acceptable reverse connection: %w (refused a server: %w)", cause, l.lastReject)
	}
	if n := len(l.pending); n > 0 {
		uris := make([]string, 0, n)
		for _, p := range l.pending {
			uris = append(uris, p.rhe.ServerURI)
		}
		return fmt.Errorf("uacp: no matching reverse connection: %w (pending connections of other servers: %q)", cause, uris)
	}
	return fmt.Errorf("uacp: no reverse connection: %w", cause)
}

// AcceptReverse is the reverse-connect counterpart of Dial: instead of
// connecting to the server it waits for the server to connect to l and to
// announce itself with a ReverseHello message that satisfies match (see
// ReverseListener.Accept), and then performs the HEL/ACK handshake.
//
// The Hello message names the EndpointUrl of the ReverseHello message, as
// Part 6 §7.1.3 requires; endpoint is used if the server did not send one.
// The dial timeout bounds the waiting and the handshake together. A zero
// timeout waits until ctx is done.
func (d *Dialer) AcceptReverse(ctx context.Context, l *ReverseListener, endpoint string, match func(*ReverseHello) error) (*Conn, *ReverseHello, error) {
	if l == nil {
		return nil, nil, fmt.Errorf("uacp: no reverse listener")
	}
	dl := d.Dialer
	if dl == nil {
		dl = defaultNetDialer()
	}
	if dl.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, dl.Timeout)
		defer cancel()
	}

	for {
		c, rhe, err := l.Accept(ctx, match)
		if err != nil {
			return nil, nil, err
		}
		conn, err := NewConn(c, d.ClientACK)
		if err != nil {
			_ = c.Close()
			return nil, nil, err
		}
		conn.logger = d.Logger

		url := rhe.EndpointURL
		if url == "" {
			url = endpoint
		}
		conn.logDebug("starting HEL/ACK handshake on reverse connection", "conn_id", conn.id, "server_uri", rhe.ServerURI, "endpoint", url)
		err = conn.Handshake(ctx, url)
		if err == nil {
			return conn, rhe, nil
		}
		_ = conn.Close()
		conn.logWarn("HEL/ACK handshake on reverse connection failed", "conn_id", conn.id, "error", err)

		// An Error message is the server's answer and a done context ends
		// the waiting. Anything else is a connection that broke, typically
		// one that had been pending for a while: wait for the server to
		// connect again.
		var uerr *Error
		if ctx.Err() != nil || errors.As(err, &uerr) {
			return nil, nil, err
		}
	}
}
