// SPDX-License-Identifier: MIT

package uacp

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
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
}

func (d *Dialer) Dial(ctx context.Context, endpoint string) (*Conn, error) {
	if d.Logger != nil {
		d.Logger.Debug("connecting", "endpoint", endpoint)
	}

	_, raddr, err := ParseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}

	dl := d.Dialer
	if dl == nil {
		dl = defaultNetDialer()
	}

	c, err := dl.DialContext(ctx, "tcp", raddr.Host)
	if err != nil {
		return nil, err
	}

	conn, err := NewConn(c.(*net.TCPConn), d.ClientACK)
	if err != nil {
		_ = c.Close()
		return nil, err
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

// Listener is a OPC UA Connection Protocol network listener.
type Listener struct {
	l        *net.TCPListener
	ack      *Acknowledge
	endpoint string
}

// Listen acts like net.Listen for OPC UA Connection Protocol networks.
//
// Currently the endpoint can only be specified in "opc.tcp://<addr[:port]>/path" format.
//
// If the IP field of laddr is nil or an unspecified IP address, Listen listens
// on all available unicast and anycast IP addresses of the local system.
// If the Port field of laddr is 0, a port number is automatically chosen.
func Listen(ctx context.Context, endpoint string, ack *Acknowledge) (*Listener, error) {
	if ack == nil {
		ack = DefaultServerACK
	}
	_, laddr, err := ParseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}

	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", laddr.Host)
	if err != nil {
		return nil, err
	}
	return &Listener{
		l:        l.(*net.TCPListener),
		ack:      ack,
		endpoint: endpoint,
	}, nil
}

// Accept accepts the next incoming call and returns the new connection.
//
// The first param ctx is to be passed to monitor(), which monitors and handles
// incoming messages automatically in another goroutine.
func (l *Listener) Accept(ctx context.Context) (*Conn, error) {
	c, err := l.l.AcceptTCP()
	if err != nil {
		return nil, err
	}
	conn := &Conn{TCPConn: c, id: nextid(), ack: l.ack}
	conn.bufPool.New = func() any {
		b := make([]byte, l.ack.ReceiveBufSize)
		return &b
	}
	if err := conn.srvhandshake(l.endpoint); err != nil {
		_ = c.Close()
		return nil, err
	}
	return conn, nil
}

// Close closes the Listener.
func (l *Listener) Close() error {
	return l.l.Close()
}

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr {
	return l.l.Addr()
}

// Endpoint returns the listener's EndpointURL.
func (l *Listener) Endpoint() string {
	return l.endpoint
}

type Conn struct {
	*net.TCPConn
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
	conn := &Conn{TCPConn: c, id: nextid(), ack: ack}
	conn.bufPool.New = func() any {
		b := make([]byte, ack.ReceiveBufSize)
		return &b
	}
	return conn, nil
}

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
	return c.TCPConn.Close()
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

	if err := c.Send("HELF", hel); err != nil {
		return err
	}

	b, err := c.Receive()
	if err != nil {
		return err
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

func (c *Conn) srvhandshake(endpoint string) error {
	b, err := c.Receive()
	if err != nil {
		c.SendError(ua.StatusBadTCPInternalError)
		return err
	}

	// HEL or RHE?
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
		rhe := new(ReverseHello)
		if _, err := rhe.Decode(msg); err != nil {
			c.SendError(ua.StatusBadTCPInternalError)
			return err
		}
		if rhe.EndpointURL != endpoint {
			c.SendError(ua.StatusBadTCPEndpointURLInvalid)
			return fmt.Errorf("%w: %s", errors.ErrInvalidEndpoint, rhe.EndpointURL)
		}
		c.logDebug("reverse hello redirect", "conn_id", c.id, "server_uri", rhe.ServerURI)
		_ = c.Close()
		var dialer net.Dialer
		c2, err := dialer.DialContext(context.Background(), "tcp", rhe.ServerURI)
		if err != nil {
			return err
		}
		c.TCPConn = c2.(*net.TCPConn)
		c.logDebug("received RHE", "conn_id", c.id, "rhe", fmt.Sprintf("%#v", rhe))
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
	if !strings.EqualFold(cu.Hostname(), su.Hostname()) {
		return false
	}
	if cu.Path != su.Path {
		return false
	}
	// Accept any client port when the server was configured with port 0.
	cp, sp := cu.Port(), su.Port()
	if sp == "0" || sp == "" {
		return true
	}
	if cp == "" {
		cp = defaultPort
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

	if h.MessageSize > c.ack.ReceiveBufSize {
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
