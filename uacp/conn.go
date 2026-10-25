// SPDX-License-Identifier: MIT

package uacp

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
)

const (
	KB = 1024
	MB = 1024 * KB

	DefaultReceiveBufSize = 0xffff
	DefaultSendBufSize    = 0xffff
	DefaultMaxChunkCount  = 512
	DefaultMaxMessageSize = 2 * MB

	// DefaultDialTimeout is the default timeout for establishing a TCP
	// connection when using the package-level Dial/DialTCP helpers or a
	// zero-value Dialer. Set Dialer.Timeout to zero for no timeout.
	DefaultDialTimeout = 10 * time.Second
)

var (
	// DefaultClientACK is the ACK handshake message sent to the server
	// for client connections.
	DefaultClientACK = &Acknowledge{
		ReceiveBufSize: DefaultReceiveBufSize,
		SendBufSize:    DefaultSendBufSize,
		MaxChunkCount:  0, // use what the server wants
		MaxMessageSize: 0, // use what the server wants
	}

	// DefaultServerACK is the ACK handshake message sent to the client
	// for server connections.
	DefaultServerACK = &Acknowledge{
		ReceiveBufSize: DefaultReceiveBufSize,
		SendBufSize:    DefaultSendBufSize,
		MaxChunkCount:  DefaultMaxChunkCount,
		MaxMessageSize: DefaultMaxMessageSize,
	}
)

// connid stores the current connection id. updated with atomic.AddUint32.
var connid uint32

// nextid returns the next connection id.
func nextid() uint32 {
	return atomic.AddUint32(&connid, 1)
}

// minNonZero returns the smaller of two limits where 0 means "no limit". If one
// value is 0 the other is returned; if both are 0 the result is 0.
func minNonZero(a, b uint32) uint32 {
	switch {
	case a == 0:
		return b
	case b == 0:
		return a
	default:
		return min(a, b)
	}
}

// defaultNetDialer returns a net.Dialer with DefaultDialTimeout when no custom
// dialer is configured.
func defaultNetDialer() *net.Dialer {
	return &net.Dialer{Timeout: DefaultDialTimeout}
}

// Dialer establishes a connection to an endpoint.
type Dialer struct {
	// Dialer establishes the TCP connection. Defaults to net.Dialer.
	Dialer *net.Dialer

	// ClientACK defines the connection parameters requested by the client.
	// Defaults to DefaultClientACK.
	ClientACK *Acknowledge

	// Logger is the logger for connection-level messages.
	// If nil, logging is disabled.
	Logger *slog.Logger

	// TLSConfig configures TLS for opc.wss endpoints: the roots the server's
	// TLS certificate is verified against (RootCAs, nil for the system
	// roots), a client TLS certificate, ServerName. The TLS certificates are
	// independent of the application instance certificates (Part 6
	// §7.5.3). TLS 1.2 is the minimum version. Ignored for opc.tcp.
	TLSConfig *tls.Config
}

// Dial connects to endpoint and performs the HEL/ACK handshake. An opc.tcp
// endpoint is reached over TCP, an opc.wss endpoint over a TLS secured
// WebSocket with the sub-protocol opcua+uacp (Part 6 §7.5).
func (d *Dialer) Dial(ctx context.Context, endpoint string) (*Conn, error) {
	if d.Logger != nil {
		d.Logger.Debug("connecting", "endpoint", endpoint)
	}

	dl := d.Dialer
	if dl == nil {
		dl = defaultNetDialer()
	}

	var (
		conn *Conn
		err  error
	)
	if IsWebSocketEndpoint(endpoint) {
		// TLS and the WebSocket upgrade are part of establishing the
		// connection: the dial timeout covers them and the HEL/ACK.
		if dl.Timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, dl.Timeout)
			defer cancel()
		}
		var nc net.Conn
		if nc, err = d.dialWebSocket(ctx, dl, endpoint); err != nil {
			return nil, err
		}
		conn = newConn(nc, d.ClientACK)
	} else {
		_, raddr, err := ParseEndpoint(endpoint)
		if err != nil {
			return nil, err
		}
		c, err := dl.DialContext(ctx, "tcp", raddr.Host)
		if err != nil {
			return nil, err
		}
		if conn, err = NewConn(c.(*net.TCPConn), d.ClientACK); err != nil {
			_ = c.Close()
			return nil, err
		}

		// The connection is only usable once the HEL/ACK exchange is done,
		// so the dial timeout covers it as well: a peer that accepts the
		// TCP connection but stays silent must not hold up the caller
		// indefinitely.
		if dl.Timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, dl.Timeout)
			defer cancel()
		}
	}
	conn.logger = d.Logger

	conn.logDebug("starting HEL/ACK handshake", "conn_id", conn.id)
	if err := conn.Handshake(ctx, endpoint); err != nil {
		conn.logWarn("HEL/ACK handshake failed", "conn_id", conn.id, "error", err)
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// Dial uses the default dialer and DefaultDialTimeout to establish a connection
// to the endpoint.
func Dial(ctx context.Context, endpoint string) (*Conn, error) {
	return DialWithTimeout(ctx, endpoint, DefaultDialTimeout)
}

// DialWithTimeout establishes a connection using the given dial timeout. A zero
// timeout means no limit (beyond any deadline on ctx).
func DialWithTimeout(ctx context.Context, endpoint string, timeout time.Duration) (*Conn, error) {
	return (&Dialer{Dialer: &net.Dialer{Timeout: timeout}}).Dial(ctx, endpoint)
}

// DialTCP establishes a TCP connection to the OPC UA endpoint address only.
// It parses the endpoint URL (e.g. opc.tcp://host:4840/path) and opens a TCP
// connection, leaving hostname resolution to net.Dialer. No OPC UA HEL/ACK or
// secure channel is performed. The caller must close the returned connection.
// Use this for TCP reachability checks (e.g. "ping" or connection diagnostics)
// without creating a session or secure channel.
func DialTCP(ctx context.Context, endpoint string) (net.Conn, error) {
	return DialTCPWithTimeout(ctx, endpoint, DefaultDialTimeout)
}

// DialTCPWithTimeout is like DialTCP but uses the given dial timeout. A zero
// timeout means no limit (beyond any deadline on ctx).
func DialTCPWithTimeout(ctx context.Context, endpoint string, timeout time.Duration) (net.Conn, error) {
	_, raddr, err := ParseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	return (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", raddr.Host)
}

// serverHandshakeTimeout bounds how long an accepted connection may take to
// complete the HEL/ACK handshake before it is dropped.
const serverHandshakeTimeout = 10 * time.Second

// Listener is a OPC UA Connection Protocol network listener.
type Listener struct {
	l        *net.TCPListener
	ack      *Acknowledge
	endpoint string

	// The TCP accept loop and the HEL/ACK handshakes run in the background
	// so that a peer which connects but does not (or only slowly) send its
	// HEL cannot keep other peers from being accepted.
	start     sync.Once
	ready     chan acceptResult
	closed    chan struct{}
	closeOnce sync.Once

	mu      sync.Mutex
	pending map[*net.TCPConn]struct{} // connections in handshake

	// upgrade turns an accepted TCP connection into the connection UACP
	// runs on, within the handshake deadline: TLS and the WebSocket opening
	// handshake for opc.wss. Nil for opc.tcp.
	upgrade func(*net.TCPConn) (net.Conn, error)
}

// acceptResult is the outcome of accepting one connection.
type acceptResult struct {
	conn *Conn
	err  error
}

// Listen acts like net.Listen for OPC UA Connection Protocol networks.
//
// Currently the endpoint can only be specified in "opc.tcp://<addr[:port]>/path" format.
//
// If the IP field of laddr is nil or an unspecified IP address, Listen listens
// on all available unicast and anycast IP addresses of the local system.
// If the Port field of laddr is 0, a port number is automatically chosen.
func Listen(ctx context.Context, endpoint string, ack *Acknowledge) (*Listener, error) {
	_, laddr, err := ParseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	return listen(ctx, laddr.Host, endpoint, ack)
}

// listen returns a Listener on the TCP address hostport for endpoint.
func listen(ctx context.Context, hostport, endpoint string, ack *Acknowledge) (*Listener, error) {
	if ack == nil {
		a := *DefaultServerACK
		ack = &a
	} else {
		// Clone so the caller can reuse/mutate their template without affecting
		// an already-running listener.
		a := *ack
		ack = &a
	}
	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", hostport)
	if err != nil {
		return nil, err
	}
	return &Listener{
		l:        l.(*net.TCPListener),
		ack:      ack,
		endpoint: endpoint,
		ready:    make(chan acceptResult),
		closed:   make(chan struct{}),
		pending:  make(map[*net.TCPConn]struct{}),
	}, nil
}

// Accept returns the next connection that completed the HEL/ACK handshake.
//
// TCP connections are accepted and handshaken in the background, each with a
// deadline, so a slow or silent peer does not delay other connections. A
// failed handshake is reported as an error; the caller should keep calling
// Accept. Accept returns ctx.Err() when ctx is done and a *net.OpError
// wrapping net.ErrClosed once the listener is closed.
func (l *Listener) Accept(ctx context.Context) (*Conn, error) {
	l.start.Do(func() { go l.acceptLoop() })

	select {
	case r := <-l.ready:
		return r.conn, r.err
	case <-l.closed:
		return nil, l.closedError()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (l *Listener) closedError() error {
	return &net.OpError{Op: "accept", Net: "tcp", Addr: l.l.Addr(), Err: net.ErrClosed}
}

// deliver hands r to a caller of Accept. It reports false if the listener
// was closed first.
func (l *Listener) deliver(r acceptResult) bool {
	select {
	case l.ready <- r:
		return true
	case <-l.closed:
		return false
	}
}

func (l *Listener) acceptLoop() {
	for {
		c, err := l.l.AcceptTCP()
		if err != nil {
			select {
			case <-l.closed:
				return
			default:
			}
			if !l.deliver(acceptResult{err: err}) {
				return
			}
			// Do not spin on a persistent accept error (e.g. EMFILE).
			select {
			case <-l.closed:
				return
			case <-time.After(10 * time.Millisecond):
			}
			continue
		}

		l.mu.Lock()
		l.pending[c] = struct{}{}
		l.mu.Unlock()
		go l.handshake(c)
	}
}

// handshake performs the server side of the HEL/ACK exchange on c and
// delivers the result to Accept.
func (l *Listener) handshake(c *net.TCPConn) {
	// Clone listener ACK; srvhandshake also clones before negotiating, but
	// the initial HEL receive must use a per-connection copy.
	_ = c.SetDeadline(time.Now().Add(serverHandshakeTimeout))
	var conn *Conn
	err := func() (err error) {
		// A panic while decoding what a peer sent must end this connection,
		// not the process: this goroutine belongs to the listener.
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("uacp: panic during handshake: %v\n%s", r, debug.Stack())
			}
		}()
		var nc net.Conn = c
		if l.upgrade != nil {
			if nc, err = l.upgrade(c); err != nil {
				return err
			}
		}
		conn = newConn(nc, l.ack)
		return conn.srvhandshake(l.endpoint)
	}()
	if err == nil {
		_ = conn.SetDeadline(time.Time{})
	}

	l.mu.Lock()
	delete(l.pending, c)
	l.mu.Unlock()

	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		_ = c.Close()
		l.deliver(acceptResult{err: err})
		return
	}
	if !l.deliver(acceptResult{conn: conn}) {
		_ = conn.Close()
	}
}

// Close closes the Listener and drops the connections whose handshake has
// not completed yet.
func (l *Listener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	err := l.l.Close()

	l.mu.Lock()
	for c := range l.pending {
		_ = c.Close()
	}
	l.mu.Unlock()
	return err
}

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr {
	return l.l.Addr()
}

// Endpoint returns the listener's EndpointURL.
func (l *Listener) Endpoint() string {
	return l.endpoint
}

// Conn is a UACP connection. It runs over TCP (opc.tcp) or over a WebSocket
// (opc.wss); all I/O goes through the methods of Conn, which use the
// transport of the connection.
type Conn struct {
	// TCPConn is the TCP connection of an opc.tcp connection. It is nil for
	// an opc.wss connection, which runs over TLS and a WebSocket.
	*net.TCPConn
	nc     net.Conn // the transport: TCPConn, or the WebSocket
	id     uint32
	ack    *Acknowledge
	logger *slog.Logger

	closeOnce sync.Once
	bufPool   sync.Pool
}

func NewConn(c *net.TCPConn, ack *Acknowledge) (*Conn, error) {
	if c == nil {
		return nil, fmt.Errorf("uacp: no connection")
	}
	if ack == nil {
		ack = DefaultClientACK
	}
	return newConn(c, ack), nil
}

// newConn returns a Conn on nc with a copy of ack, which must not be nil.
func newConn(nc net.Conn, ack *Acknowledge) *Conn {
	if ack == nil {
		ack = DefaultClientACK
	}
	// Always clone: DefaultClientACK / caller templates must not be mutated by
	// handshake negotiation or shared across concurrent connections.
	ackCopy := *ack
	conn := &Conn{nc: nc, id: nextid(), ack: &ackCopy}
	if tc, ok := nc.(*net.TCPConn); ok {
		conn.TCPConn = tc
	}
	conn.bufPool.New = func() any {
		b := make([]byte, ackCopy.ReceiveBufSize)
		return &b
	}
	return conn
}

// Read reads from the transport of the connection.
func (c *Conn) Read(b []byte) (int, error) { return c.nc.Read(b) }

// Write writes to the transport of the connection. Over a WebSocket every
// Write is one binary frame, which is why a MessageChunk is always written
// in one call (Part 6 §7.5.2).
func (c *Conn) Write(b []byte) (int, error) { return c.nc.Write(b) }

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr { return c.nc.LocalAddr() }

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr { return c.nc.RemoteAddr() }

// SetDeadline sets the read and write deadlines of the transport.
func (c *Conn) SetDeadline(t time.Time) error { return c.nc.SetDeadline(t) }

// SetReadDeadline sets the read deadline of the transport.
func (c *Conn) SetReadDeadline(t time.Time) error { return c.nc.SetReadDeadline(t) }

// SetWriteDeadline sets the write deadline of the transport.
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.nc.SetWriteDeadline(t) }

// SetLogger sets the logger for connection-level messages.
func (c *Conn) SetLogger(l *slog.Logger) {
	c.logger = l
}

func (c *Conn) logDebug(msg string, args ...any) {
	if c.logger == nil {
		return
	}
	c.logger.Debug(msg, args...)
}

func (c *Conn) logWarn(msg string, args ...any) {
	if c.logger == nil {
		return
	}
	c.logger.Warn(msg, args...)
}

func (c *Conn) ID() uint32 {
	return c.id
}

func (c *Conn) Version() uint32 {
	return c.ack.Version
}

func (c *Conn) ReceiveBufSize() uint32 {
	return c.ack.ReceiveBufSize
}

func (c *Conn) SendBufSize() uint32 {
	return c.ack.SendBufSize
}

func (c *Conn) MaxMessageSize() uint32 {
	return c.ack.MaxMessageSize
}

func (c *Conn) MaxChunkCount() uint32 {
	return c.ack.MaxChunkCount
}

func (c *Conn) Close() (err error) {
	err = io.EOF
	c.closeOnce.Do(func() { err = c.close() })
	return err
}

func (c *Conn) close() error {
	c.logDebug("closing connection", "conn_id", c.id)
	return c.nc.Close()
}

func (c *Conn) Handshake(ctx context.Context, endpoint string) error {
	hel := &Hello{
		Version:        c.ack.Version,
		ReceiveBufSize: c.ack.ReceiveBufSize,
		SendBufSize:    c.ack.SendBufSize,
		MaxMessageSize: c.ack.MaxMessageSize,
		MaxChunkCount:  c.ack.MaxChunkCount,
		EndpointURL:    endpoint,
	}

	// set a deadline if there is one
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	// Abort the exchange when ctx is cancelled: without this a peer that
	// accepts the connection but never answers the HEL blocks the caller
	// forever when ctx has no deadline.
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Now()) })
	defer stop()

	if err := c.Send("HELF", hel); err != nil {
		return handshakeError(ctx, err)
	}

	b, err := c.Receive()
	if err != nil {
		return handshakeError(ctx, err)
	}

	// From here on ctx no longer governs the connection. If the cancellation
	// hook has already fired it may still be about to expire the deadline,
	// which would poison the established connection, so give up instead.
	if !stop() {
		return ctx.Err()
	}

	// clear the deadline
	_ = c.SetDeadline(time.Time{})

	msgtyp := string(b[:4])
	switch msgtyp {
	case "ACKF":
		ack := new(Acknowledge)
		if _, err := ack.Decode(b[hdrlen:]); err != nil {
			return fmt.Errorf("uacp: decode ACK failed: %w", err)
		}
		if ack.Version != 0 {
			return fmt.Errorf("%w: version=%d", errors.ErrInvalidState, ack.Version)
		}
		if ack.MaxChunkCount == 0 {
			ack.MaxChunkCount = DefaultMaxChunkCount
			c.logDebug("server has no chunk limit, using default", "conn_id", c.id, "max_chunk_count", ack.MaxChunkCount)
		}
		if ack.MaxMessageSize == 0 {
			ack.MaxMessageSize = DefaultMaxMessageSize
			c.logDebug("server has no message size limit, using default", "conn_id", c.id, "max_message_size", ack.MaxMessageSize)
		}
		// The server revises the buffer sizes of the Hello downwards (Part 6
		// §7.1.2.4); it cannot raise them. The receive buffers of this
		// connection have the size that was offered: an Acknowledge with a
		// larger one (a faulty or hostile server, or a message damaged on
		// the way) would make Receive accept a message that does not fit
		// its buffer, and panic.
		if hel.ReceiveBufSize > 0 && ack.ReceiveBufSize > hel.ReceiveBufSize {
			ack.ReceiveBufSize = hel.ReceiveBufSize
		}
		if hel.SendBufSize > 0 && ack.SendBufSize > hel.SendBufSize {
			ack.SendBufSize = hel.SendBufSize
		}
		c.ack = ack
		c.logDebug("received ACK", "conn_id", c.id, "ack", fmt.Sprintf("%#v", ack))
		return nil

	case "ERRF":
		errf := new(Error)
		if _, err := errf.Decode(b[hdrlen:]); err != nil {
			return fmt.Errorf("uacp: decode ERR failed: %w", err)
		}
		c.logDebug("received ERRF", "conn_id", c.id, "error", errf)
		return errf

	default:
		c.SendError(ua.StatusBadTCPInternalError)
		return fmt.Errorf("%w: %q", errors.ErrInvalidMessageType, msgtyp)
	}
}

// handshakeError returns the context's error if the handshake failed because
// ctx was cancelled or timed out, and err otherwise.
func handshakeError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	// The connection's deadline is the context's deadline and may fire a
	// moment before the context itself reports it.
	var netErr net.Error
	if _, ok := ctx.Deadline(); ok && errors.As(err, &netErr) && netErr.Timeout() {
		return context.DeadlineExceeded
	}
	return err
}

func (c *Conn) srvhandshake(endpoint string) error {
	b, err := c.Receive()
	if err != nil {
		c.SendError(ua.StatusBadTCPInternalError)
		return err
	}

	msgtyp := string(b[:4])
	msg := b[hdrlen:]
	switch msgtyp {
	case "HELF":
		hel := new(Hello)
		if _, err := hel.Decode(msg); err != nil {
			c.SendError(ua.StatusBadTCPInternalError)
			return err
		}
		if !endpointMatch(hel.EndpointURL, endpoint) {
			c.SendError(ua.StatusBadTCPEndpointURLInvalid)
			return fmt.Errorf("%w: %s", errors.ErrInvalidEndpoint, hel.EndpointURL)
		}

		// Negotiate buffer sizes to the smaller of what each side supports, so
		// we never send a chunk larger than the client can receive (which would
		// otherwise cause the client to drop the connection). c.ack is shared
		// with the listener, so clone it before mutating per-connection.
		ack := *c.ack
		if hel.ReceiveBufSize > 0 {
			ack.SendBufSize = min(ack.SendBufSize, hel.ReceiveBufSize)
		}
		if hel.SendBufSize > 0 {
			ack.ReceiveBufSize = min(ack.ReceiveBufSize, hel.SendBufSize)
		}
		if hel.MaxMessageSize > 0 {
			ack.MaxMessageSize = minNonZero(ack.MaxMessageSize, hel.MaxMessageSize)
		}
		if hel.MaxChunkCount > 0 {
			ack.MaxChunkCount = minNonZero(ack.MaxChunkCount, hel.MaxChunkCount)
		}
		c.ack = &ack

		if err := c.Send("ACKF", c.ack); err != nil {
			c.SendError(ua.StatusBadTCPInternalError)
			return err
		}
		c.logDebug("received HEL", "conn_id", c.id, "hello", fmt.Sprintf("%#v", hel), "ack", fmt.Sprintf("%#v", c.ack))
		return nil

	case "RHEF":
		// A ReverseHello is only ever sent by a server, on a connection the
		// server opened itself (Part 6 §7.1.3). A server that receives one on
		// an accepted connection is talking to a confused or hostile peer.
		c.SendError(ua.StatusBadTCPMessageTypeInvalid)
		return fmt.Errorf("%w: %q: ReverseHello received by a server", errors.ErrInvalidMessageType, msgtyp)

	case "ERRF":
		errf := new(Error)
		if _, err := errf.Decode(b[hdrlen:]); err != nil {
			return fmt.Errorf("uacp: decode ERR failed: %w", err)
		}
		c.logDebug("received ERRF", "conn_id", c.id, "error", errf)
		return errf

	default:
		c.SendError(ua.StatusBadTCPInternalError)
		return fmt.Errorf("%w: %q", errors.ErrInvalidMessageType, msgtyp)
	}
}

// endpointMatch compares two OPC-UA endpoint URLs. It normalises port
// differences that arise when the server listens on ":0" (random port).
// If either URL cannot be parsed the function falls back to a plain
// string comparison.
func endpointMatch(clientURL, serverURL string) bool {
	cu, cerr := url.Parse(clientURL)
	su, serr := url.Parse(serverURL)
	if cerr != nil || serr != nil {
		return clientURL == serverURL
	}
	if !strings.EqualFold(cu.Scheme, su.Scheme) {
		return false
	}
	// An unspecified server host is a bind wildcard, not a client-reachable
	// endpoint hostname. In that case, match the client URL by scheme, path,
	// and port without requiring the hostname to equal the bind address.
	serverHost := su.Hostname()
	serverIP := net.ParseIP(serverHost)
	serverHostIsWildcard := serverIP != nil && serverIP.IsUnspecified()
	if !serverHostIsWildcard && !strings.EqualFold(cu.Hostname(), serverHost) {
		return false
	}
	// A server registered without a path (su.Path == "") accepts any client
	// path, just as an unspecified host accepts any client hostname. A server
	// that explicitly registers a path requires the client to match it.
	if su.Path != "" && cu.Path != su.Path {
		return false
	}
	// Accept any client port when the server was configured with port 0.
	cp, sp := cu.Port(), su.Port()
	if sp == "0" || sp == "" {
		return true
	}
	if cp == "" {
		cp = defaultPort
		if strings.EqualFold(cu.Scheme, SchemeWebSocket) {
			cp = defaultWebSocketPort
		}
	}
	return cp == sp
}

// hdrlen is the size of the uacp header.
const hdrlen = 8

// Receive reads a full UACP message from the underlying connection.
// The size of b must be at least ReceiveBufSize. Otherwise,
// the function returns an error.
func (c *Conn) Receive() ([]byte, error) {
	bp := c.bufPool.Get().(*[]byte)
	defer c.bufPool.Put(bp)
	b := *bp

	if _, err := io.ReadFull(c, b[:hdrlen]); err != nil {
		return nil, err // not wrapped to preserve io.EOF for errors.Is checks
	}

	var h Header
	if _, err := h.Decode(b[:hdrlen]); err != nil {
		return nil, fmt.Errorf("uacp: header decode failed: %w", err)
	}

	if h.MessageSize > c.ack.ReceiveBufSize || int64(h.MessageSize) > int64(len(b)) {
		return nil, fmt.Errorf("%w: %d > %d bytes MsgType=%s ChunkType=%c", errors.ErrMessageTooLarge, h.MessageSize, c.ack.ReceiveBufSize, h.MessageType, h.ChunkType)
	}
	if h.MessageSize < hdrlen {
		return nil, fmt.Errorf("%w: %d bytes MsgType=%s ChunkType=%c", errors.ErrMessageTooSmall, h.MessageSize, h.MessageType, h.ChunkType)
	}

	if _, err := io.ReadFull(c, b[hdrlen:h.MessageSize]); err != nil {
		return nil, err // not wrapped to preserve io.EOF for errors.Is checks
	}

	c.logDebug("received message", "conn_id", c.id, "msg_type", string(h.MessageType), "chunk_type", string(h.ChunkType), "size", h.MessageSize)

	if h.MessageType == "ERR" {
		errf := new(Error)
		if _, err := errf.Decode(b[hdrlen:h.MessageSize]); err != nil {
			return nil, fmt.Errorf("uacp: failed to decode ERRF message: %w", err)
		}
		return nil, errf
	}

	// Copy the message so the pool buffer can be reused safely.
	msg := make([]byte, h.MessageSize)
	copy(msg, b[:h.MessageSize])
	return msg, nil
}

func (c *Conn) Send(typ string, msg interface{}) error {
	if len(typ) != 4 {
		return fmt.Errorf("%w: %s", errors.ErrInvalidMessageType, typ)
	}

	body, err := ua.Encode(msg)
	if err != nil {
		return fmt.Errorf("uacp: encode msg failed: %w", err)
	}

	h := Header{
		MessageType: typ[:3],
		ChunkType:   typ[3],
		MessageSize: uint32(len(body) + hdrlen),
	}

	if h.MessageSize > c.ack.SendBufSize {
		return fmt.Errorf("%w: %d > %d bytes", errors.ErrMessageTooLarge, h.MessageSize, c.ack.SendBufSize)
	}

	hdr, err := h.Encode()
	if err != nil {
		return fmt.Errorf("uacp: encode hdr failed: %w", err)
	}

	b := append(hdr, body...)
	if _, err := c.Write(b); err != nil {
		return fmt.Errorf("uacp: write failed: %w", err)
	}
	c.logDebug("sent message", "conn_id", c.id, "msg_type", typ, "size", len(b))

	return nil
}

func (c *Conn) SendError(code ua.StatusCode) {
	// we swallow the error to silence complaints from the linter
	// since sending an error will close the connection and we
	// want to bubble a different error up.
	_ = c.Send("ERRF", &Error{ErrorCode: uint32(code)})
}
