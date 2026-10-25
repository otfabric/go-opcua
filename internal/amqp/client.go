// SPDX-License-Identifier: MIT

// Package amqp is a small, dependency-free AMQP 1.0 client (OASIS AMQP 1.0)
// for the AMQP transport of OPC UA PubSub (Part 14 Annex B.3).
//
// It opens one connection with one session and attaches sender and
// receiver links on it as they are needed. It supports SASL ANONYMOUS,
// PLAIN and EXTERNAL (Part 5 §5.3), TLS (amqps), the negotiation of the
// maximum frame size, idle time-outs with empty frames as heartbeats
// (Part 2 §2.4.5), session and link flow control (§2.5.6, §2.6.7),
// messages that span several transfer frames (§2.6.14), pre-settled and
// unsettled deliveries with their dispositions (§2.6.12, Part 3 §3.4) and
// automatic reconnection with exponential backoff: after a reconnect the
// client attaches its links again and sends the unsettled deliveries again
// (at least once).
//
// Everything decoded from the network is bounded: the frame size, the
// nesting depth and the counts and lengths of the values in a frame, and
// the size of a message that spans several frames.
package amqp

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	mrand "math/rand/v2"
	"net"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/otfabric/go-opcua/internal/goid"
)

// Defaults of [Options].
const (
	DefaultIdleTimeout       = 60 * time.Second
	DefaultConnectTimeout    = 10 * time.Second
	DefaultMinReconnectDelay = 100 * time.Millisecond
	DefaultMaxReconnectDelay = 30 * time.Second
	DefaultMaxFrameSize      = 64 << 10
	DefaultMaxMessageSize    = 16 << 20
	DefaultCredit            = 256
)

// DefaultSessionWindow is the incoming window of the session, in transfer
// frames (§2.5.6), unless Options.SessionWindow sets another. It is opened
// again whenever half of it is used.
const DefaultSessionWindow = 1 << 16

// maxCtrl bounds the control frames queued for the writer. A broker that
// keeps to the session window cannot make the client queue more than about
// one answer per transfer frame of the window before it reads them.
const maxCtrl = 2 * DefaultSessionWindow

// SASL mechanisms (Part 5 §5.3.3.1). NONE skips the SASL layer.
const (
	SASLAnonymous = "ANONYMOUS"
	SASLPlain     = "PLAIN"
	SASLExternal  = "EXTERNAL"
	SASLNone      = "NONE"
)

// Errors of the client.
var (
	// ErrClosed is returned after Close.
	ErrClosed = errors.New("amqp: client closed")
	// ErrNotConnected is returned by a pre-settled Send while the client
	// is reconnecting.
	ErrNotConnected = errors.New("amqp: not connected")
	// ErrMessageTooLarge is returned by Send for a message above the
	// max-message-size of the link.
	ErrMessageTooLarge = errors.New("amqp: message too large for the link")

	errConnLost = errors.New("amqp: connection lost")
)

// ConnectError is a connection the broker refused: during SASL or with a
// close frame instead of the open or begin frame.
type ConnectError struct {
	// SASLCode is the outcome code of a failed SASL exchange (SASL is
	// true).
	SASL     bool
	SASLCode uint8
	// Err is the error of the broker's close frame, if any.
	Err *Error
	// Reason describes refusals of the client itself (no common SASL
	// mechanism, ...).
	Reason string
}

func (e *ConnectError) Error() string {
	switch {
	case e.SASL:
		reasons := map[uint8]string{SASLAuth: "authentication failed", SASLSys: "system error",
			SASLSysPerm: "permanent system error", SASLSysTemp: "temporary system error"}
		r, ok := reasons[e.SASLCode]
		if !ok {
			r = "unknown code"
		}
		return fmt.Sprintf("amqp: SASL: %s (%d)", r, e.SASLCode)
	case e.Err != nil:
		return "amqp: connection refused: " + e.Err.Error()
	}
	return "amqp: connection refused: " + e.Reason
}

// fatal reports whether retrying the connection cannot help.
func (e *ConnectError) fatal() bool {
	switch {
	case e.SASL:
		return e.SASLCode == SASLAuth || e.SASLCode == SASLSysPerm
	case e.Err != nil:
		return e.Err.Condition == CondUnauthorizedAccess
	}
	return true
}

// LinkError is a link the broker refused or detached.
type LinkError struct {
	Address string
	// Err is the error of the detach, nil if the broker gave none.
	Err *Error
}

func (e *LinkError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("amqp: link %q detached by the broker", e.Address)
	}
	return fmt.Sprintf("amqp: link %q detached by the broker: %v", e.Address, e.Err)
}

// DeliveryError is an unsettled delivery the broker did not accept: its
// outcome is *Rejected, *Released or *Modified (Part 3 §3.4).
type DeliveryError struct {
	State DeliveryState
}

func (e *DeliveryError) Error() string {
	switch s := e.State.(type) {
	case *Rejected:
		if s.Error != nil {
			return "amqp: message rejected: " + s.Error.Error()
		}
		return "amqp: message rejected"
	case *Released:
		return "amqp: message released (not delivered)"
	case *Modified:
		return "amqp: message modified (not delivered)"
	}
	return fmt.Sprintf("amqp: unexpected outcome %T", e.State)
}

// Options configure a [Client].
type Options struct {
	// Server is amqp://host[:5672] or amqps://host[:5671] (Part 14 B.3.2).
	// A path is ignored: addresses are given per link.
	Server string
	// ContainerID identifies the client (§2.7.1); empty selects a random
	// one.
	ContainerID string
	// Hostname is sent in the open and sasl-init frames; empty selects the
	// host of Server. RabbitMQ selects the virtual host with "vhost:name".
	Hostname string
	// SASLMechanism is ANONYMOUS, PLAIN, EXTERNAL or NONE (no SASL layer).
	// Empty selects PLAIN with a Username, EXTERNAL with a TLS client
	// certificate (if the broker offers it) and ANONYMOUS otherwise.
	SASLMechanism string
	Username      string
	Password      string
	// TLSConfig is used for amqps. Nil selects the system defaults.
	TLSConfig *tls.Config
	// IdleTimeout: the connection is dropped when nothing arrived for this
	// long; half of it is announced to the broker as idle-time-out
	// (§2.4.5). Zero selects DefaultIdleTimeout, a negative value turns it
	// off. The client sends heartbeats as the broker's idle-time-out asks.
	IdleTimeout time.Duration
	// ConnectTimeout bounds one connection attempt (dial to begin).
	ConnectTimeout time.Duration
	// MinReconnectDelay and MaxReconnectDelay bound the exponential backoff
	// between connection attempts.
	MinReconnectDelay time.Duration
	MaxReconnectDelay time.Duration
	// MaxFrameSize is the largest frame the client accepts (at least 512).
	MaxFrameSize uint32
	// SessionWindow is the incoming window of the session in transfer
	// frames (§2.5.6), at most DefaultSessionWindow; 0 selects
	// DefaultSessionWindow.
	SessionWindow uint32
	// MaxMessageSize limits received messages; it is announced on receiver
	// links and larger messages are rejected.
	MaxMessageSize int
	// Credit is the link credit of receiver links: how many messages the
	// broker may send ahead.
	Credit uint32
	// ConnectionProperties, SessionProperties and LinkProperties are the
	// properties of the open, begin and attach frames.
	ConnectionProperties Map
	SessionProperties    Map
	LinkProperties       Map
	// SourceCapabilities are put on the source of receiver links and
	// TargetCapabilities on the target of sender links ("queue" or "topic"
	// for ActiveMQ Artemis, for example).
	SourceCapabilities []Symbol
	TargetCapabilities []Symbol
	// Dialer opens the network connection; nil uses net.Dialer (and TLS for
	// amqps). Tests use it to inject faults.
	Dialer func(ctx context.Context, network, addr string) (net.Conn, error)
	// OnConnect is called after each successful connection.
	OnConnect func()
	// OnConnectionLost is called when an established connection breaks.
	OnConnectionLost func(err error)
	Logger           *slog.Logger
}

// Handler receives messages. Handlers run on one delivery goroutine, in the
// order the messages arrived; a slow handler delays the others.
type Handler func(*Message)

type linkState int

const (
	linkDetached linkState = iota
	linkAttaching
	linkAttached
	linkDetaching
)

// link is a sender or receiver link. Its per-connection fields are valid
// while cs is the current connection; all fields are guarded by Client.mu.
type link struct {
	name    string
	address string
	role    Role // RoleSender or RoleReceiver: our end
	settled bool // pre-settled deliveries
	handler Handler
	// active: a receiver that is subscribed. confirmed: Subscribe returned
	// it, so a refusal is retried instead of reported.
	active, confirmed bool
	retry             time.Duration

	cs             *conn
	state          linkState
	handle         uint32
	remoteHandle   uint32
	credit         uint32
	deliveryCount  uint32
	maxMessageSize uint64
	peerSettled    bool // the peer sends pre-settled deliveries
	err            error
	drain          bool
	queued         int // deliveries queued or being written
	tag            uint64

	// The delivery being received.
	inDelivery bool
	curID      uint32
	curSettled bool
	partial    []byte
	size       int
	dropping   bool
}

// outDelivery is a message to send.
type outDelivery struct {
	l        *link
	payload  []byte
	settled  bool
	off      int
	id       uint32
	started  bool
	finished bool
	done     chan error
}

// finish reports the result of a delivery, once. c.mu is held.
func (d *outDelivery) finish(err error) {
	if !d.finished {
		d.finished = true
		d.done <- err
	}
}

type ctrlItem struct {
	body Body
	link *link // for a link flow: the link whose state it carries
}

// conn is one connection with its session (§2.5).
type conn struct {
	nc         net.Conn
	br         *bufio.Reader
	dead       chan struct{}
	deadOnce   sync.Once
	writerDone chan struct{}
	wake       chan struct{}

	maxFrame      uint32 // the peer's: the largest frame we may send
	remoteIdle    time.Duration
	handleMax     uint32
	remoteChannel uint16

	// Session flow control state (§2.5.6).
	nextOutgoingID       uint32
	nextDeliveryID       uint32
	remoteIncomingWindow uint32
	nextIncomingID       uint32
	incomingWindow       uint32

	handles   map[uint32]*link // ours
	remote    map[uint32]*link // by the peer's handle
	attaching map[string]*link // by name, until the peer attached
	unsettled map[uint32]*outDelivery

	ctrl  []ctrlItem
	xfers []*outDelivery
	cur   *outDelivery
}

func (cs *conn) kill() {
	cs.deadOnce.Do(func() {
		close(cs.dead)
		_ = cs.nc.Close()
	})
}

// signal wakes the writer.
func (cs *conn) signal() {
	select {
	case cs.wake <- struct{}{}:
	default:
	}
}

func (cs *conn) queue(b Body) { cs.queueLink(b, nil) }

func (cs *conn) queueLink(b Body, l *link) {
	cs.ctrl = append(cs.ctrl, ctrlItem{body: b, link: l})
	cs.signal()
}

// Client is an AMQP 1.0 client. Its methods are safe for concurrent use.
type Client struct {
	opts     Options
	addr     string
	tls      bool
	hostname string
	idle     time.Duration
	log      *slog.Logger

	done    chan struct{} // closed by Close
	deliver chan inbound
	wg      sync.WaitGroup // the goroutines but the delivery goroutine
	// deliverDone is closed when the delivery goroutine ends; deliverID is
	// its goroutine id, so a Close from a handler does not wait for itself.
	deliverDone chan struct{}
	deliverID   atomic.Uint64

	mu        sync.Mutex
	closed    bool
	cs        *conn // nil while disconnected
	changed   chan struct{}
	senders   map[senderKey]*link
	receivers map[*link]struct{}
	nextName  uint64
}

type senderKey struct {
	address string
	settled bool
}

type inbound struct {
	l *link
	m *Message
}

// Dial connects to the broker and returns the client. It retries failed
// attempts with backoff until ctx is done, except for refusals that a retry
// cannot fix (failed authentication, ...). Once connected, the client
// reconnects by itself until Close.
func Dial(ctx context.Context, opts Options) (*Client, error) {
	c, err := newClient(opts)
	if err != nil {
		return nil, err
	}
	first := make(chan error, 1)
	c.wg.Add(1)
	go c.deliverLoop()
	go c.run(ctx, first)
	select {
	case err := <-first:
		if err != nil {
			_ = c.Close()
			return nil, err
		}
		return c, nil
	case <-ctx.Done():
		_ = c.Close()
		return nil, ctx.Err()
	}
}

func newClient(opts Options) (*Client, error) {
	u, err := url.Parse(opts.Server)
	if err != nil {
		return nil, fmt.Errorf("amqp: server %q: %w", opts.Server, err)
	}
	c := &Client{
		opts:        opts,
		log:         opts.Logger,
		done:        make(chan struct{}),
		deliver:     make(chan inbound, 256),
		deliverDone: make(chan struct{}),
		changed:     make(chan struct{}),
		senders:     map[senderKey]*link{},
		receivers:   map[*link]struct{}{},
	}
	port := "5672"
	switch strings.ToLower(u.Scheme) {
	case "amqp":
	case "amqps":
		c.tls, port = true, "5671"
	default:
		return nil, fmt.Errorf("amqp: unsupported scheme %q in %q", u.Scheme, opts.Server)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("amqp: no host in %q", opts.Server)
	}
	if u.Port() != "" {
		port = u.Port()
	}
	c.addr = net.JoinHostPort(u.Hostname(), port)
	c.hostname = opts.Hostname
	if c.hostname == "" {
		c.hostname = u.Hostname()
	}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	if c.opts.ContainerID == "" {
		var b [8]byte
		_, _ = rand.Read(b[:])
		c.opts.ContainerID = "go-opcua-" + hex.EncodeToString(b[:])
	}
	switch strings.ToUpper(c.opts.SASLMechanism) {
	case "", SASLAnonymous, SASLPlain, SASLExternal, SASLNone:
		c.opts.SASLMechanism = strings.ToUpper(c.opts.SASLMechanism)
	default:
		return nil, fmt.Errorf("amqp: unsupported SASL mechanism %q", opts.SASLMechanism)
	}
	switch {
	case opts.IdleTimeout == 0:
		c.idle = DefaultIdleTimeout
	case opts.IdleTimeout > 0:
		c.idle = max(opts.IdleTimeout, 2*time.Millisecond)
	}
	if c.opts.ConnectTimeout <= 0 {
		c.opts.ConnectTimeout = DefaultConnectTimeout
	}
	if c.opts.MinReconnectDelay <= 0 {
		c.opts.MinReconnectDelay = DefaultMinReconnectDelay
	}
	if c.opts.MaxReconnectDelay <= 0 {
		c.opts.MaxReconnectDelay = DefaultMaxReconnectDelay
	}
	if c.opts.MaxReconnectDelay < c.opts.MinReconnectDelay {
		c.opts.MaxReconnectDelay = c.opts.MinReconnectDelay
	}
	if c.opts.SessionWindow == 0 || c.opts.SessionWindow > DefaultSessionWindow {
		c.opts.SessionWindow = DefaultSessionWindow
	}
	if c.opts.MaxFrameSize == 0 {
		c.opts.MaxFrameSize = DefaultMaxFrameSize
	}
	c.opts.MaxFrameSize = max(c.opts.MaxFrameSize, MinMaxFrameSize)
	if c.opts.MaxMessageSize <= 0 {
		c.opts.MaxMessageSize = DefaultMaxMessageSize
	}
	if c.opts.Credit == 0 {
		c.opts.Credit = DefaultCredit
	}
	return c, nil
}

// ContainerID returns the container identifier of the client.
func (c *Client) ContainerID() string { return c.opts.ContainerID }

// broadcast wakes everybody waiting for a state change. c.mu is held.
func (c *Client) broadcast() {
	close(c.changed)
	c.changed = make(chan struct{})
}

// waitLocked releases c.mu and waits for the next state change.
func (c *Client) waitLocked(ctx context.Context) error {
	ch := c.changed
	c.mu.Unlock()
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return ErrClosed
	}
}

// run keeps the client connected until Close.
func (c *Client) run(ctx context.Context, first chan<- error) {
	defer c.wg.Done()
	delay := c.opts.MinReconnectDelay
	connected := false
	for {
		attemptCtx := ctx
		if connected {
			attemptCtx = context.Background()
		}
		cs, err := c.connect(attemptCtx)
		if err != nil {
			var ce *ConnectError
			if !connected && (errors.As(err, &ce) && ce.fatal() || ctx.Err() != nil) {
				first <- err
				return
			}
			c.log.Debug("amqp: connect failed", "server", c.addr, "error", err, "retry_in", delay)
			if !c.sleep(ctx, connected, delay) {
				if !connected {
					first <- err
				}
				return
			}
			delay = min(delay*2, c.opts.MaxReconnectDelay)
			continue
		}
		delay = c.opts.MinReconnectDelay
		if !c.attach(cs) {
			cs.kill()
			return
		}
		if !connected {
			connected = true
			first <- nil
		}
		if c.opts.OnConnect != nil {
			c.opts.OnConnect()
		}
		err = c.serve(cs)
		c.detach(cs)
		select {
		case <-c.done:
			return
		default:
		}
		c.log.Debug("amqp: connection lost", "server", c.addr, "error", err)
		if c.opts.OnConnectionLost != nil {
			c.opts.OnConnectionLost(err)
		}
	}
}

// sleep waits for the backoff delay with jitter; false if the client was
// closed (or, before the first connection, ctx ended).
func (c *Client) sleep(ctx context.Context, connected bool, d time.Duration) bool {
	d = d*4/5 + time.Duration(mrand.Int64N(int64(d)*2/5+1))
	t := time.NewTimer(d)
	defer t.Stop()
	var ctxDone <-chan struct{}
	if !connected {
		ctxDone = ctx.Done()
	}
	select {
	case <-t.C:
		return true
	case <-c.done:
		return false
	case <-ctxDone:
		return false
	}
}

func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	dial := c.opts.Dialer
	if dial == nil {
		d := &net.Dialer{}
		dial = d.DialContext
	}
	nc, err := dial(ctx, "tcp", c.addr)
	if err != nil {
		return nil, err
	}
	if !c.tls {
		return nc, nil
	}
	cfg := c.opts.TLSConfig.Clone()
	if cfg == nil {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if cfg.ServerName == "" {
		host, _, _ := net.SplitHostPort(c.addr)
		cfg.ServerName = host
	}
	tc := tls.Client(nc, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = nc.Close()
		return nil, fmt.Errorf("amqp: TLS handshake: %w", err)
	}
	return tc, nil
}

func writeFrame(w net.Conn, f *Frame) error {
	b, err := AppendFrame(nil, f)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// readBody reads frames until one with a body (skipping heartbeats).
func (c *Client) readBody(br *bufio.Reader) (*Frame, error) {
	for {
		f, err := ReadFrame(br, c.opts.MaxFrameSize)
		if err != nil {
			return nil, err
		}
		if f.Body != nil {
			return f, nil
		}
	}
}

func readHeader(br *bufio.Reader) ([8]byte, error) {
	var h [8]byte
	_, err := io.ReadFull(br, h[:])
	return h, err
}

// connect dials the broker and opens the connection and the session: the
// protocol headers (§2.2), SASL (Part 5 §5.3), open (§2.4.1) and begin
// (§2.5.1).
func (c *Client) connect(ctx context.Context) (*conn, error) {
	ctx, cancel := context.WithTimeout(ctx, c.opts.ConnectTimeout)
	defer cancel()
	go func() { // Close aborts the attempt
		select {
		case <-c.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	nc, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = nc.SetDeadline(dl)
	}
	stopClose := context.AfterFunc(ctx, func() { _ = nc.Close() })
	defer stopClose()
	fail := func(err error) (*conn, error) {
		_ = nc.Close()
		if ctx.Err() != nil {
			return nil, fmt.Errorf("amqp: connect %s: %w (%v)", c.addr, ctx.Err(), err)
		}
		return nil, err
	}
	br := bufio.NewReaderSize(nc, 32<<10)
	if c.opts.SASLMechanism != SASLNone {
		if err := c.sasl(nc, br); err != nil {
			return fail(err)
		}
	}
	if _, err := nc.Write(HeaderAMQP[:]); err != nil {
		return fail(err)
	}
	h, err := readHeader(br)
	if err != nil {
		return fail(fmt.Errorf("amqp: no protocol header: %w", err))
	}
	if h != HeaderAMQP {
		return fail(&ConnectError{Reason: fmt.Sprintf("the broker answered protocol header %q", h[:])})
	}
	var idle uint32
	if c.idle > 0 {
		idle = uint32(min(c.idle/2/time.Millisecond, math.MaxUint32))
	}
	open := &Open{
		ContainerID:  c.opts.ContainerID,
		Hostname:     c.hostname,
		MaxFrameSize: c.opts.MaxFrameSize,
		ChannelMax:   0, // one session
		IdleTimeout:  idle,
		Properties:   c.opts.ConnectionProperties,
	}
	if err := writeFrame(nc, &Frame{Body: open}); err != nil {
		return fail(err)
	}
	f, err := c.readBody(br)
	if err != nil {
		return fail(fmt.Errorf("amqp: no open frame: %w", err))
	}
	peer, ok := f.Body.(*Open)
	if !ok || f.Type != FrameAMQP {
		return fail(protoErr("expected open, got %T", f.Body))
	}
	begin := &Begin{IncomingWindow: c.opts.SessionWindow, OutgoingWindow: math.MaxUint32, Properties: c.opts.SessionProperties}
	if err := writeFrame(nc, &Frame{Body: begin}); err != nil {
		return fail(err)
	}
	f, err = c.readBody(br)
	if err != nil {
		return fail(fmt.Errorf("amqp: no begin frame: %w", err))
	}
	var pb *Begin
	switch b := f.Body.(type) {
	case *Begin:
		pb = b
	case *Close:
		if b.Error == nil {
			b.Error = &Error{Condition: CondInternalError, Description: "closed without error"}
		}
		return fail(&ConnectError{Err: b.Error})
	default:
		return fail(protoErr("expected begin, got %T", f.Body))
	}
	if pb.RemoteChannel == nil || *pb.RemoteChannel != 0 {
		return fail(protoErr("begin does not answer channel 0"))
	}
	if !stopClose() {
		return nil, ctx.Err()
	}
	_ = nc.SetDeadline(time.Time{})
	cs := &conn{
		nc:                   nc,
		br:                   br,
		dead:                 make(chan struct{}),
		writerDone:           make(chan struct{}),
		wake:                 make(chan struct{}, 1),
		maxFrame:             max(peer.MaxFrameSize, MinMaxFrameSize),
		remoteIdle:           time.Duration(peer.IdleTimeout) * time.Millisecond,
		handleMax:            pb.HandleMax,
		remoteChannel:        f.Channel,
		remoteIncomingWindow: pb.IncomingWindow,
		nextIncomingID:       pb.NextOutgoingID,
		incomingWindow:       c.opts.SessionWindow,
		handles:              map[uint32]*link{},
		remote:               map[uint32]*link{},
		attaching:            map[string]*link{},
		unsettled:            map[uint32]*outDelivery{},
	}
	return cs, nil
}

// sasl performs the SASL exchange (Part 5 §5.3.2).
func (c *Client) sasl(nc net.Conn, br *bufio.Reader) error {
	if _, err := nc.Write(HeaderSASL[:]); err != nil {
		return err
	}
	h, err := readHeader(br)
	if err != nil {
		return fmt.Errorf("amqp: no SASL protocol header: %w", err)
	}
	if h == HeaderAMQP {
		return &ConnectError{Reason: "the broker does not use SASL (set the SASL mechanism NONE)"}
	}
	if h != HeaderSASL {
		return &ConnectError{Reason: fmt.Sprintf("the broker answered protocol header %q", h[:])}
	}
	f, err := c.readBody(br)
	if err != nil {
		return err
	}
	mechs, ok := f.Body.(*SASLMechanisms)
	if !ok || f.Type != FrameSASL {
		return protoErr("expected sasl-mechanisms, got %T", f.Body)
	}
	offered := func(m string) bool { return slices.Contains(mechs.Mechanisms, Symbol(m)) }
	mech := c.opts.SASLMechanism
	if mech == "" {
		cert := c.tls && c.opts.TLSConfig != nil && (len(c.opts.TLSConfig.Certificates) > 0 || c.opts.TLSConfig.GetClientCertificate != nil)
		switch {
		case c.opts.Username != "":
			mech = SASLPlain
		case cert && offered(SASLExternal):
			mech = SASLExternal
		default:
			mech = SASLAnonymous
		}
	}
	if !offered(mech) {
		return &ConnectError{Reason: fmt.Sprintf("SASL mechanism %s not offered (offered: %v)", mech, mechs.Mechanisms)}
	}
	init := &SASLInit{Mechanism: Symbol(mech), Hostname: c.hostname, InitialResponse: []byte{}}
	if mech == SASLPlain {
		// RFC 4616: authzid NUL authcid NUL passwd.
		init.InitialResponse = []byte("\x00" + c.opts.Username + "\x00" + c.opts.Password)
	}
	if err := writeFrame(nc, &Frame{Type: FrameSASL, Body: init}); err != nil {
		return err
	}
	for range 8 {
		f, err := c.readBody(br)
		if err != nil {
			return err
		}
		switch b := f.Body.(type) {
		case *SASLChallenge:
			// None of the mechanisms has challenges: answer empty.
			if err := writeFrame(nc, &Frame{Type: FrameSASL, Body: &SASLResponse{}}); err != nil {
				return err
			}
		case *SASLOutcome:
			if b.Code != SASLOk {
				return &ConnectError{SASL: true, SASLCode: b.Code}
			}
			return nil
		default:
			return protoErr("unexpected %T during SASL", f.Body)
		}
	}
	return protoErr("SASL exchange without outcome")
}

// attach makes cs the current connection and attaches the links again.
// False if the client was closed meanwhile.
func (c *Client) attach(cs *conn) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	c.cs = cs
	senders := make([]*link, 0, len(c.senders))
	for _, l := range c.senders {
		senders = append(senders, l)
	}
	receivers := make([]*link, 0, len(c.receivers))
	for l := range c.receivers {
		receivers = append(receivers, l)
	}
	byName := func(a, b *link) int { return strings.Compare(a.name, b.name) }
	slices.SortFunc(senders, byName)
	slices.SortFunc(receivers, byName)
	for _, l := range append(receivers, senders...) {
		c.attachLink(cs, l)
	}
	c.broadcast()
	return true
}

// detach forgets cs and fails what needs it.
func (c *Client) detach(cs *conn) {
	cs.kill()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cs == cs {
		c.cs = nil
	}
	for _, l := range cs.handles {
		c.resetLink(l)
	}
	for _, d := range cs.unsettled {
		d.finish(errConnLost)
	}
	for _, d := range cs.xfers {
		d.l.queued--
		d.finish(errConnLost)
	}
	if d := cs.cur; d != nil {
		d.l.queued--
		d.finish(errConnLost)
	}
	cs.xfers, cs.cur, cs.unsettled = nil, nil, map[uint32]*outDelivery{}
	c.broadcast()
}

func (c *Client) resetLink(l *link) {
	l.cs, l.state = nil, linkDetached
	l.inDelivery, l.partial, l.dropping = false, nil, false
}

// newLink returns a link. c.mu is held.
func (c *Client) newLink(address string, role Role, settled bool) *link {
	return &link{address: address, role: role, settled: settled, retry: c.opts.MinReconnectDelay}
}

// attachLink sends an attach for l on cs (§2.6.3). c.mu is held.
func (c *Client) attachLink(cs *conn, l *link) {
	h, ok := uint32(0), false
	for i := uint32(0); i <= cs.handleMax && i < 1<<16; i++ {
		if _, used := cs.handles[i]; !used {
			h, ok = i, true
			break
		}
	}
	c.resetLink(l)
	if !ok {
		l.cs, l.err = cs, &LinkError{Address: l.address, Err: &Error{Condition: CondResourceLimit, Description: "no free link handle"}}
		return
	}
	c.nextName++
	kind := "sender"
	if l.role == RoleReceiver {
		kind = "receiver"
	}
	l.name = fmt.Sprintf("%s-%s-%d", c.opts.ContainerID, kind, c.nextName)
	l.cs, l.state, l.handle, l.err = cs, linkAttaching, h, nil
	l.credit, l.deliveryCount, l.maxMessageSize, l.drain = 0, 0, 0, false
	cs.handles[h] = l
	cs.attaching[l.name] = l
	a := &Attach{Name: l.name, Handle: h, Role: l.role, RcvSettleMode: ReceiverSettleFirst, Properties: c.opts.LinkProperties}
	if l.settled {
		a.SndSettleMode = SenderSettleSettled
	} else {
		a.SndSettleMode = SenderSettleUnsettled
	}
	if l.role == RoleSender {
		a.Source = &Source{Address: c.opts.ContainerID}
		a.Target = &Target{Address: l.address, Capabilities: c.opts.TargetCapabilities}
	} else {
		a.Source = &Source{Address: l.address, Capabilities: c.opts.SourceCapabilities}
		a.Target = &Target{Address: c.opts.ContainerID}
		a.MaxMessageSize = uint64(c.opts.MaxMessageSize)
	}
	cs.queue(a)
}

// serve reads frames from cs until it fails. The writer goroutine sends.
func (c *Client) serve(cs *conn) error {
	c.wg.Add(1)
	go c.writer(cs)
	for {
		if c.idle > 0 {
			_ = cs.nc.SetReadDeadline(time.Now().Add(c.idle))
		}
		f, err := ReadFrame(cs.br, c.opts.MaxFrameSize)
		if err != nil {
			return err
		}
		if f.Body == nil {
			continue // heartbeat
		}
		if f.Type != FrameAMQP || f.Channel != cs.remoteChannel {
			return protoErr("frame of type %d on channel %d", f.Type, f.Channel)
		}
		c.mu.Lock()
		in, err := c.handle(cs, f)
		if err == nil && len(cs.ctrl) > maxCtrl {
			// Answers (dispositions, echoed flows) pile up: the broker
			// keeps sending and does not read.
			err = fmt.Errorf("amqp: the broker does not read: %d frames queued", len(cs.ctrl))
		}
		c.mu.Unlock()
		if err != nil {
			var pc *peerClose
			if errors.As(err, &pc) {
				c.flush(cs)
				if pc.err != nil {
					return &ConnectError{Err: pc.err}
				}
			}
			return err
		}
		if in != nil {
			select {
			case c.deliver <- *in:
			case <-c.done:
			}
		}
	}
}

// peerClose is the close (or end) of the peer, answered already.
type peerClose struct{ err *Error }

func (p *peerClose) Error() string {
	if p.err == nil {
		return "amqp: closed by the broker"
	}
	return "amqp: closed by the broker: " + p.err.Error()
}

// flush waits a moment for the writer to send what is queued (an answer
// to the peer's close) before the connection is closed.
func (c *Client) flush(cs *conn) {
	t := time.NewTimer(time.Second)
	defer t.Stop()
	select {
	case <-cs.writerDone:
	case <-t.C:
	}
}

// handle processes one frame. c.mu is held.
func (c *Client) handle(cs *conn, f *Frame) (*inbound, error) {
	switch b := f.Body.(type) {
	case *Attach:
		return nil, c.onAttach(cs, b)
	case *Flow:
		c.onFlow(cs, b)
	case *Transfer:
		return c.onTransfer(cs, b, f.Payload)
	case *Disposition:
		c.onDisposition(cs, b)
	case *Detach:
		c.onDetach(cs, b)
	case *End:
		cs.queue(&End{})
		cs.queue(&Close{})
		return nil, &peerClose{err: b.Error}
	case *Close:
		cs.queue(&Close{})
		return nil, &peerClose{err: b.Error}
	default:
		return nil, protoErr("unexpected %T", f.Body)
	}
	return nil, nil
}

func (c *Client) onAttach(cs *conn, a *Attach) error {
	l := cs.attaching[a.Name]
	if l == nil || a.Role == l.role {
		return protoErr("attach of unknown link %q", a.Name)
	}
	if _, used := cs.remote[a.Handle]; used {
		return protoErr("attach with handle %d in use", a.Handle)
	}
	delete(cs.attaching, a.Name)
	l.remoteHandle = a.Handle
	cs.remote[a.Handle] = l
	if l.state != linkAttaching {
		return nil // detaching already
	}
	// A refused link has a null terminus; the detach with the error
	// follows (§2.6.3).
	if l.role == RoleSender && a.Target == nil || l.role == RoleReceiver && a.Source == nil {
		return nil
	}
	l.state = linkAttached
	l.maxMessageSize = a.MaxMessageSize
	l.peerSettled = a.SndSettleMode == SenderSettleSettled
	l.retry = c.opts.MinReconnectDelay
	if l.role == RoleReceiver {
		l.deliveryCount = a.InitialDeliveryCount
		l.credit = c.opts.Credit
		cs.queueLink(&Flow{Handle: &l.handle}, l)
	}
	c.broadcast()
	return nil
}

// serialDiff returns a - b in serial number arithmetic (RFC 1982).
func serialDiff(a, b uint32) int64 { return int64(int32(a - b)) }

func (c *Client) onFlow(cs *conn, f *Flow) {
	if f.NextIncomingID != nil {
		cs.remoteIncomingWindow = uint32(max(0, serialDiff(*f.NextIncomingID+f.IncomingWindow, cs.nextOutgoingID)))
	} else {
		cs.remoteIncomingWindow = f.IncomingWindow
	}
	cs.signal()
	if f.Handle == nil {
		if f.Echo {
			cs.queue(&Flow{})
		}
		return
	}
	l := cs.remote[*f.Handle]
	if l == nil || l.cs != cs {
		return
	}
	if l.role == RoleSender && f.LinkCredit != nil {
		dc := uint32(0) // our initial-delivery-count
		if f.DeliveryCount != nil {
			dc = *f.DeliveryCount
		}
		// §2.6.7: link-credit = delivery-count(rcv) + link-credit(rcv) -
		// delivery-count(snd).
		l.credit = uint32(max(0, serialDiff(dc+*f.LinkCredit, l.deliveryCount)))
		l.drain = f.Drain
		c.checkDrain(cs, l)
		c.broadcast()
	}
	if f.Echo {
		cs.queueLink(&Flow{Handle: &l.handle}, l)
	}
}

// checkDrain completes a drain request (§2.6.7) once the link has nothing
// more to send: the unused credit is consumed. c.mu is held.
func (c *Client) checkDrain(cs *conn, l *link) {
	if !l.drain || l.queued > 0 || l.state != linkAttached {
		return
	}
	l.deliveryCount += l.credit
	l.credit, l.drain = 0, false
	cs.queueLink(&Flow{Handle: &l.handle}, l)
}

func (c *Client) onTransfer(cs *conn, t *Transfer, payload []byte) (*inbound, error) {
	// Session flow control (§2.5.6): every transfer frame counts.
	cs.nextIncomingID++
	if cs.incomingWindow > 0 {
		cs.incomingWindow--
	}
	if cs.incomingWindow < c.opts.SessionWindow/2 {
		cs.incomingWindow = c.opts.SessionWindow
		cs.queue(&Flow{})
	}
	l := cs.remote[t.Handle]
	if l == nil || l.role != RoleReceiver {
		return nil, protoErr("transfer on handle %d, which is not a receiver link", t.Handle)
	}
	if !l.inDelivery {
		if t.DeliveryID == nil {
			return nil, protoErr("first transfer of a delivery without delivery-id")
		}
		l.inDelivery, l.curID = true, *t.DeliveryID
		l.curSettled = l.peerSettled || t.Settled != nil && *t.Settled
		l.partial, l.size, l.dropping = nil, 0, false
		if l.credit > 0 {
			l.credit--
		}
		l.deliveryCount++
	} else if t.Settled != nil && *t.Settled {
		l.curSettled = true
	}
	if t.Aborted {
		l.inDelivery, l.partial = false, nil
		c.replenish(cs, l)
		return nil, nil
	}
	l.size += len(payload)
	switch {
	case l.dropping:
	case l.size > c.opts.MaxMessageSize:
		l.dropping, l.partial = true, nil
	case !t.More && l.partial == nil:
		l.partial = payload // a message in one frame: no copy
	default:
		l.partial = append(l.partial, payload...)
	}
	if t.More {
		return nil, nil
	}
	l.inDelivery = false
	body := l.partial
	l.partial = nil
	c.replenish(cs, l)
	var state DeliveryState = &Accepted{}
	var msg *Message
	if l.dropping {
		c.log.Warn("amqp: dropped a message above the size limit", "address", l.address, "size", l.size, "limit", c.opts.MaxMessageSize)
		state = &Rejected{Error: &Error{Condition: CondMessageSizeExceeded}}
	} else {
		msg = &Message{}
		if err := msg.UnmarshalBinary(body); err != nil {
			c.log.Warn("amqp: dropped a malformed message", "address", l.address, "error", err)
			state = &Rejected{Error: &Error{Condition: CondDecodeError, Description: err.Error()}}
			msg = nil
		}
	}
	// Settle at once (receiver settle mode first): the message is
	// accepted before the application sees it, so a Close cannot lose the
	// disposition after the handler ran. At least once all the same: if
	// the disposition does not reach the broker, it delivers again.
	if !l.curSettled {
		cs.queue(&Disposition{Role: RoleReceiver, First: l.curID, Settled: true, State: state})
	}
	if msg == nil || !l.active || l.state != linkAttached {
		return nil, nil
	}
	return &inbound{l: l, m: msg}, nil
}

// replenish gives a receiver link its credit back when half is used.
func (c *Client) replenish(cs *conn, l *link) {
	if l.active && l.state == linkAttached && l.credit <= c.opts.Credit/2 {
		l.credit = c.opts.Credit
		cs.queueLink(&Flow{Handle: &l.handle}, l)
	}
}

func inRange(id, first, last uint32) bool { return id-first <= last-first }

func (c *Client) onDisposition(cs *conn, d *Disposition) {
	if d.Role != RoleReceiver {
		return // the peer settling deliveries we received: we settled first
	}
	last := d.First
	if d.Last != nil {
		last = *d.Last
	}
	var settle []uint32
	for id, od := range cs.unsettled {
		if !inRange(id, d.First, last) {
			continue
		}
		var err error
		switch s := d.State.(type) {
		case *Accepted:
		case *Rejected, *Released, *Modified:
			err = &DeliveryError{State: s}
		default:
			if !d.Settled {
				continue // *Received or none: not decided yet
			}
		}
		delete(cs.unsettled, id)
		if !d.Settled {
			settle = append(settle, id)
		}
		od.finish(err)
	}
	slices.Sort(settle)
	for _, id := range settle {
		cs.queue(&Disposition{Role: RoleSender, First: id, Settled: true})
	}
}

func (c *Client) onDetach(cs *conn, d *Detach) {
	l := cs.remote[d.Handle]
	if l == nil {
		return
	}
	delete(cs.remote, d.Handle)
	if l.cs != cs {
		return
	}
	delete(cs.handles, l.handle)
	if l.state == linkDetaching {
		c.resetLink(l)
		c.broadcast()
		return
	}
	// Detached by the broker: answer, and fail what is under way.
	cs.queue(&Detach{Handle: l.handle, Closed: d.Closed})
	if l.role == RoleSender && l.state == linkAttached {
		// A sender that worked: the next Send attaches a new one. (A
		// refused one keeps its error for the Sends waiting for it.)
		key := senderKey{address: l.address, settled: l.settled}
		if c.senders[key] == l {
			delete(c.senders, key)
		}
	}
	c.resetLink(l)
	l.cs, l.err = cs, &LinkError{Address: l.address, Err: d.Error}
	for id, od := range cs.unsettled {
		if od.l == l {
			delete(cs.unsettled, id)
			od.finish(l.err)
		}
	}
	cs.xfers = slices.DeleteFunc(cs.xfers, func(od *outDelivery) bool {
		if od.l == l {
			l.queued--
			od.finish(l.err)
			return true
		}
		return false
	})
	if od := cs.cur; od != nil && od.l == l {
		cs.cur = nil
		l.queued--
		od.finish(l.err)
	}
	if l.role == RoleReceiver && l.active && l.confirmed {
		delay := l.retry
		l.retry = min(l.retry*2, c.opts.MaxReconnectDelay)
		c.log.Warn("amqp: broker detached a receiver link", "address", l.address, "error", d.Error, "retry_in", delay)
		c.wg.Add(1)
		go c.reattachLater(cs, l, delay)
	}
	c.broadcast()
}

// reattachLater attaches a receiver link the broker detached again after
// delay, while the subscription lasts: nobody else would, the subscriber
// believes it is subscribed.
func (c *Client) reattachLater(cs *conn, l *link, delay time.Duration) {
	defer c.wg.Done()
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-t.C:
	case <-c.done:
		return
	case <-cs.dead:
		return // the next connection attaches it
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.cs != cs || !l.active || l.state != linkDetached {
		return
	}
	c.attachLink(cs, l)
}

// writer sends the frames of cs: control frames first, then the transfer
// frames of one delivery after the other, as the link credit and the
// session window allow, and empty frames when the connection would be
// idle for longer than half the broker's idle-time-out.
func (c *Client) writer(cs *conn) {
	defer c.wg.Done()
	defer close(cs.writerDone)
	var heartbeat <-chan time.Time
	var timer *time.Timer
	if cs.remoteIdle > 0 {
		timer = time.NewTimer(cs.remoteIdle / 2)
		defer timer.Stop()
		heartbeat = timer.C
	}
	var buf []byte
	for {
		c.mu.Lock()
		f, d, last := c.nextFrame(cs)
		c.mu.Unlock()
		if f == nil {
			select {
			case <-cs.wake:
				continue
			case <-cs.dead:
				return
			case <-heartbeat:
				f = &Frame{}
			}
		}
		var err error
		buf, err = AppendFrame(buf[:0], f)
		if err == nil {
			_ = cs.nc.SetWriteDeadline(time.Now().Add(max(c.idle, 10*time.Second)))
			_, err = cs.nc.Write(buf)
		}
		if d != nil && last && d.settled {
			// The last frame of a pre-settled delivery: it is done (and
			// in no list the connection loss would fail).
			c.mu.Lock()
			if err != nil {
				d.finish(errConnLost)
			} else {
				d.finish(nil)
			}
			c.mu.Unlock()
		}
		if err != nil {
			c.log.Debug("amqp: write failed", "error", err)
			cs.kill()
			return
		}
		if timer != nil {
			timer.Reset(cs.remoteIdle / 2)
		}
		if _, ok := f.Body.(*Close); ok {
			return // nothing may follow a close
		}
	}
}

// nextFrame returns the next frame to write, nil if there is none. For a
// transfer frame it returns the delivery and whether the frame is its
// last. c.mu is held.
func (c *Client) nextFrame(cs *conn) (*Frame, *outDelivery, bool) {
	for len(cs.ctrl) > 0 {
		it := cs.ctrl[0]
		cs.ctrl[0] = ctrlItem{}
		cs.ctrl = cs.ctrl[1:]
		if f, ok := it.body.(*Flow); ok && !c.fillFlow(cs, f, it.link) {
			continue
		}
		return &Frame{Body: it.body}, nil, false
	}
	if cs.cur == nil {
		for i, d := range cs.xfers {
			if d.l.credit > 0 && d.l.cs == cs && d.l.state == linkAttached {
				cs.cur = d
				cs.xfers = slices.Delete(cs.xfers, i, i+1)
				break
			}
		}
	}
	d := cs.cur
	if d == nil || cs.remoteIncomingWindow == 0 {
		return nil, nil, false
	}
	l := d.l
	t := &Transfer{Handle: l.handle, More: true}
	if !d.started {
		d.started = true
		d.id = cs.nextDeliveryID
		cs.nextDeliveryID++
		l.tag++
		tag := binary.BigEndian.AppendUint64(nil, l.tag)
		format := uint32(0)
		settled := d.settled
		t.DeliveryID, t.DeliveryTag, t.MessageFormat, t.Settled = &d.id, tag, &format, &settled
		l.deliveryCount++
		l.credit--
		if !d.settled {
			cs.unsettled[d.id] = d
		}
	}
	hdr, err := AppendFrame(nil, &Frame{Body: t})
	if err != nil { // cannot happen: a transfer always encodes
		cs.cur = nil
		l.queued--
		delete(cs.unsettled, d.id)
		d.finish(err)
		return nil, nil, false
	}
	chunk := min(int(cs.maxFrame)-len(hdr), len(d.payload)-d.off)
	last := d.off+chunk == len(d.payload)
	if last {
		t.More = false
		cs.cur = nil
		l.queued--
		c.checkDrain(cs, l)
	}
	f := &Frame{Body: t, Payload: d.payload[d.off : d.off+chunk]}
	d.off += chunk
	cs.nextOutgoingID++
	cs.remoteIncomingWindow--
	return f, d, last
}

// fillFlow completes a flow frame with the current session state and, for
// a link flow, the state of the link; false if the link is gone.
func (c *Client) fillFlow(cs *conn, f *Flow, l *link) bool {
	nii := cs.nextIncomingID
	f.NextIncomingID, f.IncomingWindow = &nii, cs.incomingWindow
	f.NextOutgoingID, f.OutgoingWindow = cs.nextOutgoingID, math.MaxUint32
	if l == nil {
		return true
	}
	if l.cs != cs || l.state != linkAttached {
		return false
	}
	h, dc, lc := l.handle, l.deliveryCount, l.credit
	f.Handle, f.DeliveryCount, f.LinkCredit = &h, &dc, &lc
	return true
}

func (c *Client) deliverLoop() {
	defer close(c.deliverDone)
	c.deliverID.Store(goid.ID())
	for {
		var in inbound
		select {
		case in = <-c.deliver:
		case <-c.done:
			return
		}
		select {
		case <-c.done:
			return // closed: no handler runs any more
		default:
		}
		c.mu.Lock()
		active, h := in.l.active, in.l.handler
		c.mu.Unlock()
		if active {
			h(in.m)
		}
	}
}

// IsConnected reports whether the client is connected right now.
func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cs != nil
}

// Send sends a message to address on a sender link of its own (attached
// on first use and again after a reconnect). A settled (pre-settled, at
// most once) message returns once it is written, or ErrNotConnected while
// the client reconnects. An unsettled one (at least once) returns when the
// broker accepted it, with a *DeliveryError if it rejected or released it;
// while the client reconnects it waits and is sent on the next connection,
// and it is sent again if the connection broke before the outcome came.
// If ctx ends first the message is abandoned (it may still be delivered).
// A link the broker refuses returns a *LinkError.
func (c *Client) Send(ctx context.Context, address string, m *Message, settled bool) error {
	b, err := m.MarshalBinary()
	if err != nil {
		return err
	}
	key := senderKey{address: address, settled: settled}
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return ErrClosed
		}
		cs := c.cs
		if cs == nil {
			if settled {
				c.mu.Unlock()
				return ErrNotConnected
			}
			if err := c.waitLocked(ctx); err != nil {
				return err
			}
			continue
		}
		l := c.senders[key]
		if l == nil {
			l = c.newLink(address, RoleSender, settled)
			c.senders[key] = l
			c.attachLink(cs, l)
		}
		switch {
		case l.err != nil && l.cs == cs:
			err := l.err
			delete(c.senders, key)
			c.mu.Unlock()
			return err
		case l.cs != cs:
			c.attachLink(cs, l)
		case l.state == linkAttached:
			if l.maxMessageSize > 0 && uint64(len(b)) > l.maxMessageSize {
				c.mu.Unlock()
				return fmt.Errorf("%w: %d bytes, limit %d", ErrMessageTooLarge, len(b), l.maxMessageSize)
			}
			d := &outDelivery{l: l, payload: b, settled: settled, done: make(chan error, 1)}
			cs.xfers = append(cs.xfers, d)
			l.queued++
			cs.signal()
			c.mu.Unlock()
			select {
			case err := <-d.done:
				if errors.Is(err, errConnLost) {
					if settled {
						return ErrNotConnected
					}
					continue // send it again on the next connection
				}
				return err
			case <-ctx.Done():
				c.abandon(cs, d)
				return ctx.Err()
			case <-c.done:
				return ErrClosed
			}
		}
		if err := c.waitLocked(ctx); err != nil {
			return err
		}
	}
}

// abandon forgets a delivery whose sender gave up.
func (c *Client) abandon(cs *conn, d *outDelivery) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if d.finished {
		return
	}
	d.finished = true
	if i := slices.Index(cs.xfers, d); i >= 0 {
		cs.xfers = slices.Delete(cs.xfers, i, i+1)
		d.l.queued--
		c.checkDrain(cs, d.l)
		return
	}
	if cs.unsettled[d.id] == d {
		delete(cs.unsettled, d.id) // the outcome no longer matters
	}
}

// Subscription is an active receiver link.
type Subscription struct {
	c    *Client
	l    *link
	once sync.Once
}

// Subscribe attaches a receiver link to address and delivers its messages
// to h. With settled the broker is asked to send pre-settled messages (at
// most once); otherwise the client accepts each message (at least once).
// It waits for the broker's attach; while the client is reconnecting the
// subscription is registered and attached on the next connection. A link
// the broker refuses returns a *LinkError; refusals after a reconnect are
// retried with backoff.
func (c *Client) Subscribe(ctx context.Context, address string, settled bool, h Handler) (*Subscription, error) {
	if h == nil {
		return nil, errors.New("amqp: nil handler")
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrClosed
	}
	l := c.newLink(address, RoleReceiver, settled)
	l.handler, l.active = h, true
	c.receivers[l] = struct{}{}
	sub := &Subscription{c: c, l: l}
	cs := c.cs
	if cs == nil {
		l.confirmed = true
		c.mu.Unlock()
		return sub, nil
	}
	c.attachLink(cs, l)
	for {
		switch {
		case l.cs == cs && l.err != nil:
			err := l.err
			l.active = false
			delete(c.receivers, l)
			c.mu.Unlock()
			return nil, err
		case l.cs != cs || l.state == linkAttached:
			// Attached, or the connection was lost: the next one attaches
			// it.
			l.confirmed = true
			c.mu.Unlock()
			return sub, nil
		}
		if err := c.waitLocked(ctx); err != nil {
			// Detach the half-attached link without waiting for the
			// broker (ctx has ended): its late attach and detach are
			// handled as those of a link being detached.
			_ = sub.Unsubscribe(ctx)
			return nil, err
		}
		c.mu.Lock()
	}
}

// Address returns the address of the subscription.
func (s *Subscription) Address() string { return s.l.address }

// Unsubscribe detaches the link (closing it, §2.6.6) and waits for the
// broker's detach. It is idempotent.
func (s *Subscription) Unsubscribe(ctx context.Context) error {
	var err error
	s.once.Do(func() {
		c, l := s.c, s.l
		c.mu.Lock()
		l.active = false
		delete(c.receivers, l)
		cs := l.cs
		if c.closed || cs == nil || c.cs != cs || l.state == linkDetached {
			c.mu.Unlock()
			return
		}
		l.state = linkDetaching
		cs.queue(&Detach{Handle: l.handle, Closed: true})
		for l.cs == cs && l.state == linkDetaching && c.cs == cs {
			if err = c.waitLocked(ctx); err != nil {
				if errors.Is(err, ErrClosed) {
					err = nil
				}
				return
			}
			c.mu.Lock()
		}
		c.mu.Unlock()
	})
	return err
}

// Close closes the connection (sending close, §2.4.3) and stops the client.
// Pending calls return ErrClosed. It waits for a handler that is running,
// unless it is called from that handler.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	cs := c.cs
	if cs != nil {
		cs.queue(&Close{})
	}
	c.mu.Unlock()
	if cs != nil {
		c.flush(cs)
	}
	close(c.done)
	if cs != nil {
		cs.kill()
	}
	c.wg.Wait()
	if goid.ID() != c.deliverID.Load() {
		<-c.deliverDone
	}
	return nil
}
