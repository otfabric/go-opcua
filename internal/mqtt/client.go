// SPDX-License-Identifier: MIT

// Package mqtt is a small, dependency-free MQTT 3.1.1 and MQTT 5.0 client
// for the MQTT transport of OPC UA PubSub.
//
// It supports publishing and receiving at QoS 0, 1 and 2 (exactly once with
// the PUBREC/PUBREL/PUBCOMP flow), retained messages, wildcard
// subscriptions, user name and password, TLS, keep-alive with
// PINGREQ/PINGRESP and automatic reconnection with exponential backoff:
// after a reconnect the client subscribes again (unless the broker kept the
// session) and retransmits unacknowledged publications with the DUP flag,
// or the PUBREL of a QoS 2 publication the broker already received.
//
// MQTT 3.1.1 is the default; [Options].ProtocolVersion selects MQTT 5.0 or
// the best version the broker accepts. With MQTT 5.0 the client sends and
// receives properties (content type, payload format, message expiry,
// response topic, correlation data, user properties), reports the reason
// codes of refusals as errors, honours the broker's Receive Maximum,
// Maximum Packet Size, Maximum QoS, Retain Available, Wildcard Subscription
// Available and Server Keep Alive, announces its own Receive Maximum and
// Maximum Packet Size, never accepts topic aliases (Topic Alias Maximum 0),
// supports the subscription options No Local, Retain As Published and
// Retain Handling, and reports a DISCONNECT of the broker with its reason.
// Enhanced authentication (AUTH) and topic aliases are not supported.
package mqtt

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/otfabric/go-opcua/internal/goid"
)

// Defaults of [Options].
const (
	DefaultKeepAlive         = 60 * time.Second
	DefaultConnectTimeout    = 10 * time.Second
	DefaultMinReconnectDelay = 100 * time.Millisecond
	DefaultMaxReconnectDelay = 30 * time.Second
	DefaultMaxPacketSize     = 16 << 20
)

// VersionBestAvailable is the [Options].ProtocolVersion that tries MQTT 5.0
// and falls back to 3.1.1 when the broker refuses the protocol version.
const VersionBestAvailable byte = 0xff

// noQuota is the send quota of a connection without flow control (3.1.1):
// more than there are packet identifiers.
const noQuota = 1 << 20

// Errors of the client.
var (
	// ErrClosed is returned after Close.
	ErrClosed = errors.New("mqtt: client closed")
	// ErrNotConnected is returned by a QoS 0 Publish while the client is
	// reconnecting.
	ErrNotConnected = errors.New("mqtt: not connected")
	// ErrSubscriptionRefused is returned by Subscribe when the broker
	// refuses the subscription.
	ErrSubscriptionRefused = errors.New("mqtt: subscription refused by the broker")
	// ErrPublishRefused is returned by Publish when an MQTT 5.0 broker
	// acknowledges a publication with a failure reason code.
	ErrPublishRefused = errors.New("mqtt: publication refused by the broker")
	// ErrUnsubscribeRefused is returned by Unsubscribe when an MQTT 5.0
	// broker refuses to remove the subscription.
	ErrUnsubscribeRefused = errors.New("mqtt: unsubscribe refused by the broker")
	// ErrNotSupported is returned when the broker announced (MQTT 5.0
	// CONNACK) that it does not support what is asked: retained messages,
	// wildcard subscriptions or a packet of that size.
	ErrNotSupported = errors.New("mqtt: not supported by the broker")
)

// ConnectError is a CONNACK with a return code (3.1.1) or reason code
// (5.0) other than 0.
type ConnectError struct {
	ReturnCode byte
	// Version is the protocol level of the CONNECT that was refused.
	Version byte
	// ReasonString and ServerReference are the MQTT 5.0 properties of the
	// CONNACK, if the broker sent them.
	ReasonString    string
	ServerReference string
}

func (e *ConnectError) v5() bool { return e.Version >= Version5 && e.ReturnCode >= 0x80 }

func (e *ConnectError) Error() string {
	var r string
	if e.v5() {
		r = ReasonText(e.ReturnCode)
	} else {
		reasons := map[byte]string{
			ConnRefusedProtocolVersion:    "unacceptable protocol version",
			ConnRefusedIdentifierRejected: "client identifier rejected",
			ConnRefusedServerUnavailable:  "server unavailable",
			ConnRefusedBadCredentials:     "bad user name or password",
			ConnRefusedNotAuthorized:      "not authorized",
		}
		var ok bool
		if r, ok = reasons[e.ReturnCode]; !ok {
			r = "unknown reason"
		}
	}
	s := fmt.Sprintf("mqtt: connection refused: %s (%d)", r, e.ReturnCode)
	if e.ReasonString != "" {
		s += ": " + e.ReasonString
	}
	if e.ServerReference != "" {
		s += " (server reference " + e.ServerReference + ")"
	}
	return s
}

// fatal reports whether retrying the connection cannot help.
func (e *ConnectError) fatal() bool {
	if e.v5() {
		switch e.ReturnCode {
		case ReasonUnspecifiedError, ReasonImplementationSpecific, ReasonServerUnavailable,
			ReasonServerBusy, ReasonQuotaExceeded, ReasonConnectionRateExceeded:
			return false
		}
		return true
	}
	return e.ReturnCode != ConnRefusedServerUnavailable
}

// versionRefused reports whether the broker refused the protocol version.
func (e *ConnectError) versionRefused() bool {
	return e.ReturnCode == ConnRefusedProtocolVersion || e.ReturnCode == ReasonUnsupportedProtocolVersion
}

// DisconnectError is a DISCONNECT an MQTT 5.0 broker sent (§3.14), passed
// to OnConnectionLost.
type DisconnectError struct {
	ReasonCode      byte
	ReasonString    string
	ServerReference string
}

func (e *DisconnectError) Error() string {
	s := fmt.Sprintf("mqtt: disconnected by the broker: %s (%#02x)", ReasonText(e.ReasonCode), e.ReasonCode)
	if e.ReasonString != "" {
		s += ": " + e.ReasonString
	}
	if e.ServerReference != "" {
		s += " (server reference " + e.ServerReference + ")"
	}
	return s
}

// ReasonError is a failure reason code of an MQTT 5.0 PUBACK, PUBREC,
// SUBACK or UNSUBACK. It wraps ErrPublishRefused, ErrSubscriptionRefused or
// ErrUnsubscribeRefused.
type ReasonError struct {
	// Topic is the topic name or topic filter.
	Topic        string
	ReasonCode   byte
	ReasonString string
	err          error
}

func (e *ReasonError) Error() string {
	s := fmt.Sprintf("%v: %q: %s (%#02x)", e.err, e.Topic, ReasonText(e.ReasonCode), e.ReasonCode)
	if e.ReasonString != "" {
		s += ": " + e.ReasonString
	}
	return s
}

func (e *ReasonError) Unwrap() error { return e.err }

func reasonErr(sentinel error, topic string, code byte, p *Properties) error {
	e := &ReasonError{Topic: topic, ReasonCode: code, err: sentinel}
	if p != nil && p.ReasonString != nil {
		e.ReasonString = *p.ReasonString
	}
	return e
}

// Options configure a [Client].
type Options struct {
	// Server is mqtt://host[:1883] or mqtts://host[:8883] (also tcp://,
	// ssl:// and tls://).
	Server string
	// ProtocolVersion is Version311 (the default, also for 0), Version5 or
	// VersionBestAvailable.
	ProtocolVersion byte
	// ClientID may be empty with a clean session: the broker assigns one.
	ClientID string
	// Username and Password are sent if Username is not empty.
	Username string
	Password string
	// PersistentSession asks the broker to keep the session (clean session
	// off; with MQTT 5.0 Clean Start off and a Session Expiry Interval). It
	// needs a ClientID. Exactly once (QoS 2) across reconnects needs it.
	PersistentSession bool
	// SessionExpiry is the MQTT 5.0 Session Expiry Interval (seconds) of a
	// persistent session; 0 selects 0xFFFFFFFF, a session that does not
	// expire (as in 3.1.1). Without PersistentSession the session ends with
	// the connection.
	SessionExpiry uint32
	// ReceiveMaximum is the MQTT 5.0 Receive Maximum: how many QoS 1 and 2
	// publications the broker may send before they are acknowledged. 0
	// selects 65535. A broker that sends more is disconnected.
	ReceiveMaximum uint16
	// RequestResponseInformation and RequestProblemInformation are the
	// MQTT 5.0 CONNECT properties of the same name. A nil
	// RequestProblemInformation leaves the default (true).
	RequestResponseInformation bool
	RequestProblemInformation  *bool
	// UserProperties are the MQTT 5.0 User Properties of the CONNECT.
	UserProperties []UserProperty
	// KeepAlive is the keep-alive interval, rounded up to whole seconds.
	// Zero selects DefaultKeepAlive, a negative value turns it off. An
	// MQTT 5.0 broker may replace it (Server Keep Alive).
	KeepAlive time.Duration
	// TLSConfig is used for mqtts. Nil selects the system defaults.
	TLSConfig *tls.Config
	// ConnectTimeout bounds one connection attempt (dial and CONNACK).
	ConnectTimeout time.Duration
	// MinReconnectDelay and MaxReconnectDelay bound the exponential backoff
	// between connection attempts.
	MinReconnectDelay time.Duration
	MaxReconnectDelay time.Duration
	// MaxPacketSize limits received packets (the remaining length); larger
	// ones are dropped. With MQTT 5.0 it is announced to the broker as the
	// Maximum Packet Size, and a broker that still sends a larger packet is
	// disconnected.
	MaxPacketSize int
	// Will is the will message.
	Will *Will
	// Dialer opens the network connection; nil uses net.Dialer (and TLS for
	// mqtts). Tests use it to inject faults.
	Dialer func(ctx context.Context, network, addr string) (net.Conn, error)
	// DefaultHandler, if set, receives the messages that match no
	// subscription of this client, such as the messages a broker delivers
	// for a persistent session before Subscribe was called again.
	DefaultHandler Handler
	// OnConnect is called after each successful connection.
	OnConnect func(sessionPresent bool)
	// OnConnectionLost is called when an established connection breaks;
	// a DISCONNECT of an MQTT 5.0 broker is a [*DisconnectError].
	OnConnectionLost func(err error)
	Logger           *slog.Logger
}

// Message is a received PUBLISH.
type Message struct {
	Topic     string
	Payload   []byte
	QoS       byte
	Retain    bool
	Duplicate bool
	// Props are the MQTT 5.0 properties of the PUBLISH (content type,
	// user properties, ...); empty with 3.1.1.
	Props Properties
}

// Handler receives messages. Handlers run on one delivery goroutine, in the
// order the messages arrived; a slow handler delays the others.
type Handler func(*Message)

// Client is an MQTT client. Its methods are safe for concurrent use.
type Client struct {
	opts      Options
	network   string
	addr      string
	tls       bool
	keepAlive time.Duration
	recvMax   int
	log       *slog.Logger

	done    chan struct{} // closed by Close
	deliver chan *Message
	wg      sync.WaitGroup // the goroutines but the delivery goroutine
	// deliverDone is closed when the delivery goroutine ends; deliverID is
	// its goroutine id, so a Close from a handler does not wait for itself.
	deliverDone chan struct{}
	deliverID   atomic.Uint64

	writeMu sync.Mutex

	mu        sync.Mutex
	closed    bool
	conn      *link // nil while disconnected
	connGen   uint64
	version   byte // of the last connection, 0 before the first
	connack   Properties
	nextID    uint16
	seq       uint64
	inflight  map[uint16]*pending
	queue     []*pending // waiting for send quota on c.conn, in order
	acks      map[uint16]chan Packet
	subs      map[string]*subEntry
	nextSubID uint64
	qos2      map[uint16]bool // received QoS 2 packet ids awaiting PUBREL

	lastSent atomic.Int64 // unix nanos
	lastRecv atomic.Int64
	pingSent atomic.Int64 // 0: no ping outstanding
}

// link is one network connection and what the broker announced for it.
type link struct {
	conn      net.Conn
	version   byte
	keepAlive time.Duration
	maxOut    int  // the broker's Maximum Packet Size, 0: no limit
	maxQoS    byte // the broker's Maximum QoS
	noRetain  bool // Retain Available 0
	noWild    bool // Wildcard Subscription Available 0
	quota     int  // send quota (MQTT 5.0 §4.9); c.mu
}

type pending struct {
	seq     uint64
	pkt     *Publish
	done    chan error // buffered: the waiter may be gone
	sent    bool       // written on the current link: holds a quota slot
	written bool       // written at least once
	rel     bool       // QoS 2: PUBREC received, PUBREL sent
}

type subEntry struct {
	tf       TopicFilter
	handlers map[uint64]Handler
}

// Dial connects to the broker and returns the client. It retries failed
// attempts with backoff until ctx is done, except for refusals that a retry
// cannot fix (bad credentials, not authorized, ...). Once connected, the
// client reconnects by itself until Close.
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
		return nil, fmt.Errorf("mqtt: server %q: %w", opts.Server, err)
	}
	c := &Client{
		opts:        opts,
		network:     "tcp",
		log:         opts.Logger,
		done:        make(chan struct{}),
		deliver:     make(chan *Message, 256),
		deliverDone: make(chan struct{}),
		inflight:    map[uint16]*pending{},
		acks:        map[uint16]chan Packet{},
		subs:        map[string]*subEntry{},
		qos2:        map[uint16]bool{},
	}
	port := "1883"
	switch strings.ToLower(u.Scheme) {
	case "mqtt", "tcp":
	case "mqtts", "ssl", "tls":
		c.tls, port = true, "8883"
	default:
		return nil, fmt.Errorf("mqtt: unsupported scheme %q in %q", u.Scheme, opts.Server)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("mqtt: no host in %q", opts.Server)
	}
	if u.Port() != "" {
		port = u.Port()
	}
	c.addr = net.JoinHostPort(u.Hostname(), port)
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	switch opts.ProtocolVersion {
	case 0:
		c.opts.ProtocolVersion = Version311
	case Version311, Version5, VersionBestAvailable:
	default:
		return nil, fmt.Errorf("mqtt: unsupported protocol version %d", opts.ProtocolVersion)
	}
	switch {
	case opts.KeepAlive == 0:
		c.keepAlive = DefaultKeepAlive
	case opts.KeepAlive > 0:
		c.keepAlive = (opts.KeepAlive + time.Second - 1).Truncate(time.Second)
		if c.keepAlive > 65535*time.Second {
			c.keepAlive = 65535 * time.Second
		}
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
	if c.opts.MaxPacketSize <= 0 || c.opts.MaxPacketSize > MaxRemainingLength {
		c.opts.MaxPacketSize = DefaultMaxPacketSize
	}
	c.recvMax = int(opts.ReceiveMaximum)
	if c.recvMax == 0 {
		c.recvMax = 65535
	}
	if opts.PersistentSession && opts.ClientID == "" {
		return nil, errors.New("mqtt: a persistent session needs a client identifier")
	}
	if _, err := appendProps(nil, TypeConnect, &Properties{User: opts.UserProperties}); err != nil {
		return nil, fmt.Errorf("mqtt: connect user properties: %w", err)
	}
	if w := opts.Will; w != nil {
		if !ValidTopicName(w.Topic) || w.QoS > 2 {
			return nil, fmt.Errorf("mqtt: invalid will topic %q or QoS %d", w.Topic, w.QoS)
		}
		if _, err := appendProps(nil, typeWill, &w.Props); err != nil {
			return nil, fmt.Errorf("mqtt: will properties: %w", err)
		}
	}
	return c, nil
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
		l, br, sp, err := c.connectBest(attemptCtx)
		if err != nil {
			var ce *ConnectError
			if !connected && (errors.As(err, &ce) && ce.fatal() || ctx.Err() != nil) {
				first <- err
				return
			}
			c.log.Debug("mqtt: connect failed", "server", c.addr, "error", err, "retry_in", delay)
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
		if !c.attach(l, sp) {
			_ = l.conn.Close()
			return
		}
		if !connected {
			connected = true
			first <- nil
		}
		if c.opts.OnConnect != nil {
			c.opts.OnConnect(sp)
		}
		err = c.serve(l, br)
		c.detach(l)
		select {
		case <-c.done:
			return
		default:
		}
		c.log.Debug("mqtt: connection lost", "server", c.addr, "error", err)
		if c.opts.OnConnectionLost != nil {
			c.opts.OnConnectionLost(err)
		}
	}
}

// sleep waits for the backoff delay with jitter; false if the client was
// closed (or, before the first connection, ctx ended).
func (c *Client) sleep(ctx context.Context, connected bool, d time.Duration) bool {
	d = d*4/5 + time.Duration(rand.Int64N(int64(d)*2/5+1))
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

// connectBest connects with the configured protocol version; with
// VersionBestAvailable it tries 5.0 first (or the version that worked
// last) and 3.1.1 if the broker refuses the protocol version.
func (c *Client) connectBest(ctx context.Context) (*link, *bufio.Reader, bool, error) {
	v := c.opts.ProtocolVersion
	if v != VersionBestAvailable {
		return c.connect(ctx, v)
	}
	c.mu.Lock()
	v = c.version
	c.mu.Unlock()
	if v == 0 {
		v = Version5
	}
	l, br, sp, err := c.connect(ctx, v)
	var ce *ConnectError
	if v == Version5 && errors.As(err, &ce) && ce.versionRefused() {
		c.log.Debug("mqtt: the broker refused MQTT 5.0, trying 3.1.1", "server", c.addr)
		return c.connect(ctx, Version311)
	}
	return l, br, sp, err
}

// connect dials the broker and performs the CONNECT/CONNACK handshake.
func (c *Client) connect(ctx context.Context, version byte) (*link, *bufio.Reader, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, c.opts.ConnectTimeout)
	defer cancel()
	go func() { // Close aborts the attempt
		select {
		case <-c.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, nil, false, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()
	pkt := c.connectPacket(version)
	b, err := Encode(pkt)
	if err == nil {
		_, err = conn.Write(b)
	}
	if err != nil {
		_ = conn.Close()
		return nil, nil, false, err
	}
	br := bufio.NewReader(conn)
	limit := 16
	if version >= Version5 {
		limit = c.opts.MaxPacketSize
	}
	p, err := ReadPacketVersion(br, limit, version)
	if err != nil {
		_ = conn.Close()
		if ctx.Err() != nil {
			return nil, nil, false, fmt.Errorf("mqtt: no CONNACK: %w", ctx.Err())
		}
		return nil, nil, false, fmt.Errorf("mqtt: no CONNACK: %w", err)
	}
	ack, ok := p.(*Connack)
	if !ok {
		_ = conn.Close()
		return nil, nil, false, protoErr("expected CONNACK, got packet type %d", p.Type())
	}
	if ack.ReturnCode != ConnAccepted {
		_ = conn.Close()
		ce := &ConnectError{ReturnCode: ack.ReturnCode, Version: version}
		if s := ack.Props.ReasonString; s != nil {
			ce.ReasonString = *s
		}
		if s := ack.Props.ServerReference; s != nil {
			ce.ServerReference = *s
		}
		return nil, nil, false, ce
	}
	if !stopClose() {
		return nil, nil, false, ctx.Err()
	}
	_ = conn.SetDeadline(time.Time{})
	l := &link{conn: conn, version: version, keepAlive: c.keepAlive, maxQoS: 2, quota: noQuota}
	if version >= Version5 {
		pr := &ack.Props
		l.quota = 65535
		if pr.ReceiveMaximum != nil {
			l.quota = int(*pr.ReceiveMaximum)
		}
		if pr.MaximumPacketSize != nil && uint64(*pr.MaximumPacketSize) < MaxRemainingLength+5 {
			l.maxOut = int(*pr.MaximumPacketSize)
		}
		if pr.ServerKeepAlive != nil {
			l.keepAlive = time.Duration(*pr.ServerKeepAlive) * time.Second
		}
		if pr.MaximumQoS != nil {
			l.maxQoS = *pr.MaximumQoS
		}
		l.noRetain = pr.RetainAvailable != nil && *pr.RetainAvailable == 0
		l.noWild = pr.WildcardSubAvailable != nil && *pr.WildcardSubAvailable == 0
	}
	c.mu.Lock()
	c.version = version
	c.connack = ack.Props
	c.mu.Unlock()
	return l, br, ack.SessionPresent, nil
}

// connectPacket is the CONNECT of a protocol version.
func (c *Client) connectPacket(version byte) *Connect {
	pkt := &Connect{
		ProtocolName:  "MQTT",
		ProtocolLevel: version,
		CleanSession:  !c.opts.PersistentSession,
		KeepAlive:     uint16(c.keepAlive / time.Second),
		ClientID:      c.opts.ClientID,
		Will:          c.opts.Will,
	}
	if c.opts.Username != "" {
		u := c.opts.Username
		pkt.Username = &u
		if c.opts.Password != "" {
			pkt.Password = []byte(c.opts.Password)
		}
	}
	if version >= Version5 {
		pr := &pkt.Props
		if c.opts.PersistentSession {
			exp := c.opts.SessionExpiry
			if exp == 0 {
				exp = 0xffffffff
			}
			pr.SessionExpiry = &exp
		}
		if c.recvMax < 65535 {
			pr.ReceiveMaximum = Ptr(uint16(c.recvMax))
		}
		pr.MaximumPacketSize = Ptr(uint32(c.opts.MaxPacketSize))
		if c.opts.RequestResponseInformation {
			pr.RequestResponseInfo = Ptr(byte(1))
		}
		if rp := c.opts.RequestProblemInformation; rp != nil && !*rp {
			pr.RequestProblemInfo = Ptr(byte(0))
		}
		pr.User = c.opts.UserProperties
		// No Topic Alias Maximum: 0, the broker must not use aliases.
	}
	return pkt
}

func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	dial := c.opts.Dialer
	if dial == nil {
		d := &net.Dialer{}
		dial = d.DialContext
	}
	conn, err := dial(ctx, c.network, c.addr)
	if err != nil {
		return nil, err
	}
	if !c.tls {
		return conn, nil
	}
	cfg := c.opts.TLSConfig.Clone()
	if cfg == nil {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if cfg.ServerName == "" {
		host, _, _ := net.SplitHostPort(c.addr)
		cfg.ServerName = host
	}
	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("mqtt: TLS handshake: %w", err)
	}
	return tc, nil
}

// attach makes l the current connection, subscribes again if the session
// is new and retransmits unacknowledged publications (as far as the
// broker's Receive Maximum allows). False if the client was closed
// meanwhile.
func (c *Client) attach(l *link, sessionPresent bool) bool {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return false
	}
	c.conn = l
	c.connGen++
	gen := c.connGen
	now := time.Now().UnixNano()
	c.lastSent.Store(now)
	c.lastRecv.Store(now)
	c.pingSent.Store(0)
	var resub []TopicFilter
	if !sessionPresent {
		// A new session: the broker forgot the subscriptions and the QoS 2
		// exchanges in both directions.
		clear(c.qos2)
		for _, e := range c.subs {
			resub = append(resub, c.filterFor(l, e.tf))
		}
		sort.Slice(resub, func(i, j int) bool { return resub[i].Filter < resub[j].Filter })
	}
	var all []*pending
	for _, p := range c.inflight {
		all = append(all, p)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].seq < all[j].seq })
	var resend []resent
	var qos0 []*Publish
	c.queue = c.queue[:0]
	for _, p := range all {
		p.sent = false
		if !p.written && p.pkt.QoS > l.maxQoS {
			// Queued while disconnected, for a broker with a lower
			// Maximum QoS (§3.2.2.3.4).
			if l.maxQoS == 0 {
				cp := *p.pkt
				cp.QoS, cp.PacketID = 0, 0
				qos0 = append(qos0, &cp)
				c.complete(p, nil)
				continue
			}
			p.pkt.QoS = l.maxQoS
		}
		switch {
		case p.rel && !sessionPresent:
			// The broker had the message (PUBREC) and has no session to
			// release it from: it is delivered.
			c.complete(p, nil)
		case !p.rel && !p.written && c.refuse(l, p.pkt) != nil:
			c.complete(p, c.refuse(l, p.pkt))
		case l.quota > 0:
			l.quota--
			resend = append(resend, resent{p, p.written})
			p.sent, p.written = true, true
		default:
			c.queue = append(c.queue, p)
		}
	}
	var subID uint16
	var subAck chan Packet
	if len(resub) > 0 {
		subID = c.allocID()
		subAck = make(chan Packet, 1)
		c.acks[subID] = subAck
	}
	c.mu.Unlock()

	if len(resub) > 0 {
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			c.resubscribe(l, gen, resub, subID, subAck)
		}()
	}
	for _, r := range resend {
		c.retransmit(l, r.p, r.dup)
	}
	for _, p := range qos0 {
		_ = c.write(l, p)
	}
	return true
}

type resent struct {
	p   *pending
	dup bool
}

// retransmit sends a pending publication: its PUBREL if the broker already
// received it, else the PUBLISH, with DUP if it was sent before.
func (c *Client) retransmit(l *link, p *pending, dup bool) {
	c.mu.Lock()
	rel, pkt := p.rel, *p.pkt
	c.mu.Unlock()
	if rel {
		_ = c.write(l, &Ack{Kind: TypePubrel, PacketID: pkt.PacketID})
		return
	}
	pkt.Dup = dup
	c.sendPending(l, p, &pkt)
}

// sendPending writes a publication that holds a quota slot. One the broker
// cannot take (too large) fails and frees its slot.
func (c *Client) sendPending(l *link, p *pending, pkt *Publish) {
	err := c.write(l, pkt)
	if errors.Is(err, ErrNotSupported) {
		c.mu.Lock()
		if c.inflight[pkt.PacketID] == p {
			c.complete(p, err)
			next := c.release(l)
			c.mu.Unlock()
			c.sendNext(l, next)
			return
		}
		c.mu.Unlock()
	}
}

// filterFor drops the MQTT 5.0 subscription options for an older link.
func (c *Client) filterFor(l *link, tf TopicFilter) TopicFilter {
	if l.version < Version5 {
		return TopicFilter{Filter: tf.Filter, QoS: tf.QoS}
	}
	return tf
}

// refuse returns why a publication cannot be sent on l: what the MQTT 5.0
// broker announced it does not support.
func (c *Client) refuse(l *link, p *Publish) error {
	if p.Retain && l.noRetain {
		return fmt.Errorf("%w: retained messages (Retain Available 0)", ErrNotSupported)
	}
	return nil
}

// complete ends a pending publication. c.mu is held.
func (c *Client) complete(p *pending, err error) {
	delete(c.inflight, p.pkt.PacketID)
	select {
	case p.done <- err:
	default:
	}
}

// release returns the quota slot of an acknowledged publication and takes
// the next queued one, if any, which the caller sends. c.mu is held.
func (c *Client) release(l *link) *pending {
	if c.conn != l {
		return nil
	}
	l.quota++
	for len(c.queue) > 0 {
		p := c.queue[0]
		c.queue = c.queue[1:]
		if c.inflight[p.pkt.PacketID] != p || p.sent {
			continue
		}
		if err := c.refuse(l, p.pkt); err != nil && !p.written {
			c.complete(p, err)
			continue
		}
		l.quota--
		p.sent = true
		return p
	}
	return nil
}

// sendNext sends a publication release returned.
func (c *Client) sendNext(l *link, p *pending) {
	if p == nil {
		return
	}
	c.mu.Lock()
	dup := p.written
	p.written = true
	c.mu.Unlock()
	c.retransmit(l, p, dup)
}

// resubscribe makes the subscriptions of the client again on a new
// connection. The filters the broker refuses are asked for again, with
// backoff, for as long as the connection lasts and they have handlers:
// nobody else would, the subscribers believe they are subscribed.
func (c *Client) resubscribe(l *link, gen uint64, filters []TopicFilter, id uint16, ack chan Packet) {
	delay := c.opts.MinReconnectDelay
	for {
		_ = c.write(l, &Subscribe{PacketID: id, Topics: filters})
		var refused []string
		select {
		case p, ok := <-ack:
			if !ok {
				return // connection lost: the next one subscribes again
			}
			s, _ := p.(*Suback)
			if s == nil {
				return
			}
			for i, rc := range s.ReturnCodes {
				if rc >= SubackFailure && i < len(filters) {
					c.log.Warn("mqtt: broker refused subscription after reconnect", "filter", filters[i].Filter,
						"reason", ReasonText(rc), "retry_in", delay)
					refused = append(refused, filters[i].Filter)
				}
			}
		case <-c.done:
			c.dropAck(id)
			return
		}
		if len(refused) == 0 {
			return
		}
		t := time.NewTimer(delay)
		select {
		case <-t.C:
		case <-c.done:
			t.Stop()
			return
		}
		delay = min(delay*2, c.opts.MaxReconnectDelay)
		c.mu.Lock()
		if c.closed || c.conn != l || c.connGen != gen {
			c.mu.Unlock()
			return
		}
		filters = filters[:0]
		for _, f := range refused {
			if e := c.subs[f]; e != nil {
				filters = append(filters, c.filterFor(l, e.tf))
			}
		}
		if len(filters) == 0 {
			c.mu.Unlock()
			return
		}
		id = c.allocID()
		ack = make(chan Packet, 1)
		c.acks[id] = ack
		c.mu.Unlock()
	}
}

// detach forgets l and fails the waiters that need it.
func (c *Client) detach(l *link) {
	_ = l.conn.Close()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == l {
		c.conn = nil
		c.queue = c.queue[:0]
	}
	for id, ch := range c.acks {
		close(ch) // waiters treat a closed channel as "connection lost"
		delete(c.acks, id)
	}
}

// allocID returns a packet identifier that is not in use. c.mu is held.
func (c *Client) allocID() uint16 {
	for {
		c.nextID++
		if c.nextID == 0 {
			c.nextID = 1
		}
		if _, ok := c.inflight[c.nextID]; ok {
			continue
		}
		if _, ok := c.acks[c.nextID]; ok {
			continue
		}
		return c.nextID
	}
}

// write sends a packet on l. A packet above the broker's Maximum Packet
// Size is not sent (ErrNotSupported) and the connection stays up.
func (c *Client) write(l *link, p Packet) error {
	b, err := EncodeVersion(p, l.version)
	if err != nil {
		return err
	}
	if l.maxOut > 0 && len(b) > l.maxOut {
		return fmt.Errorf("%w: packet of %d bytes, the broker's Maximum Packet Size is %d", ErrNotSupported, len(b), l.maxOut)
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	timeout := max(c.keepAlive, l.keepAlive, 10*time.Second)
	_ = l.conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err = l.conn.Write(b)
	if err != nil {
		_ = l.conn.Close() // the reader notices and the client reconnects
		return err
	}
	c.lastSent.Store(time.Now().UnixNano())
	return nil
}

// protocolError is a violation of the protocol by the broker; an MQTT 5.0
// client names it in a DISCONNECT before it closes the connection
// (§4.13).
type protocolError struct {
	reason byte
	err    error
}

func (e *protocolError) Error() string { return e.err.Error() }
func (e *protocolError) Unwrap() error { return e.err }

func violation(reason byte, format string, args ...any) error {
	return &protocolError{reason: reason, err: protoErr(format, args...)}
}

// serve reads packets from l until it fails, and keeps it alive.
func (c *Client) serve(l *link, br *bufio.Reader) error {
	stop := make(chan struct{})
	var kwg sync.WaitGroup
	if l.keepAlive > 0 {
		kwg.Add(1)
		go func() {
			defer kwg.Done()
			c.keepAliveLoop(l, stop)
		}()
	}
	defer func() {
		close(stop)
		kwg.Wait()
	}()
	for {
		p, err := ReadPacketVersion(br, c.opts.MaxPacketSize, l.version)
		if errors.Is(err, ErrTooLarge) {
			if l.version >= Version5 {
				// The broker ignored our Maximum Packet Size (§3.1.2.11.4).
				err = &protocolError{reason: ReasonPacketTooLarge, err: err}
			} else {
				c.log.Warn("mqtt: dropped a packet above the size limit", "error", err)
				continue
			}
		} else if errors.Is(err, ErrProtocol) {
			err = &protocolError{reason: ReasonMalformedPacket, err: err}
		}
		if err == nil {
			c.lastRecv.Store(time.Now().UnixNano())
			err = c.handle(l, p)
		}
		if err != nil {
			var pe *protocolError
			if errors.As(err, &pe) && l.version >= Version5 {
				c.log.Warn("mqtt: disconnecting from a broker that violated the protocol", "error", err)
				_ = c.write(l, &Disconnect{ReasonCode: pe.reason})
			}
			_ = l.conn.Close()
			return err
		}
	}
}

func (c *Client) keepAliveLoop(l *link, stop <-chan struct{}) {
	ka := l.keepAlive
	interval := max(ka/4, 10*time.Millisecond)
	t := time.NewTicker(interval)
	defer t.Stop()
	idle := ka * 3 / 4
	for {
		select {
		case <-stop:
			return
		case <-c.done:
			return
		case <-t.C:
		}
		now := time.Now()
		if ps := c.pingSent.Load(); ps != 0 {
			if now.Sub(time.Unix(0, ps)) > ka {
				c.log.Debug("mqtt: keep-alive timeout", "server", c.addr)
				_ = l.conn.Close()
				return
			}
			continue
		}
		if now.Sub(time.Unix(0, c.lastSent.Load())) >= idle || now.Sub(time.Unix(0, c.lastRecv.Load())) >= idle {
			c.pingSent.Store(now.UnixNano())
			_ = c.write(l, &Simple{Kind: TypePingreq})
		}
	}
}

func (c *Client) handle(l *link, p Packet) error {
	switch p := p.(type) {
	case *Publish:
		return c.handlePublish(l, p)
	case *Ack:
		switch p.Kind {
		case TypePuback:
			c.mu.Lock()
			pd := c.inflight[p.PacketID]
			if pd == nil || pd.pkt.QoS != 1 {
				c.mu.Unlock()
				return nil
			}
			var err error
			if p.ReasonCode >= 0x80 {
				err = reasonErr(ErrPublishRefused, pd.pkt.Topic, p.ReasonCode, &p.Props)
			}
			c.complete(pd, err)
			var next *pending
			if pd.sent {
				next = c.release(l)
			}
			c.mu.Unlock()
			c.sendNext(l, next)
		case TypePubrec:
			c.mu.Lock()
			pd := c.inflight[p.PacketID]
			if pd != nil && pd.pkt.QoS != 2 {
				c.mu.Unlock()
				return nil
			}
			if pd != nil && p.ReasonCode >= 0x80 {
				// Refused: the exchange ends here (§4.3.3).
				c.complete(pd, reasonErr(ErrPublishRefused, pd.pkt.Topic, p.ReasonCode, &p.Props))
				var next *pending
				if pd.sent {
					next = c.release(l)
				}
				c.mu.Unlock()
				c.sendNext(l, next)
				return nil
			}
			if pd != nil {
				pd.rel = true
			}
			c.mu.Unlock()
			rel := &Ack{Kind: TypePubrel, PacketID: p.PacketID}
			if pd == nil {
				if p.ReasonCode >= 0x80 {
					return nil
				}
				// Not ours (any more): let the broker finish it.
				rel.ReasonCode = ReasonPacketIdentifierNotFound
			}
			return c.write(l, rel)
		case TypePubrel:
			c.mu.Lock()
			known := c.qos2[p.PacketID]
			delete(c.qos2, p.PacketID)
			c.mu.Unlock()
			comp := &Ack{Kind: TypePubcomp, PacketID: p.PacketID}
			if !known {
				comp.ReasonCode = ReasonPacketIdentifierNotFound
			}
			return c.write(l, comp)
		case TypePubcomp:
			c.mu.Lock()
			pd := c.inflight[p.PacketID]
			if pd == nil || pd.pkt.QoS != 2 || !pd.rel {
				c.mu.Unlock()
				return nil
			}
			// A failure here (Packet Identifier not found) still means the
			// broker had the message: it was delivered.
			c.complete(pd, nil)
			var next *pending
			if pd.sent {
				next = c.release(l)
			}
			c.mu.Unlock()
			c.sendNext(l, next)
		case TypeUnsuback:
			c.ack(p.PacketID, p)
		}
	case *Suback:
		c.ack(p.PacketID, p)
	case *Simple:
		if p.Kind == TypePingresp {
			c.pingSent.Store(0)
			return nil
		}
		return violation(ReasonProtocolError, "unexpected packet type %d from the broker", p.Kind)
	case *Disconnect:
		if l.version < Version5 {
			return violation(ReasonProtocolError, "unexpected DISCONNECT from the broker")
		}
		e := &DisconnectError{ReasonCode: p.ReasonCode}
		if s := p.Props.ReasonString; s != nil {
			e.ReasonString = *s
		}
		if s := p.Props.ServerReference; s != nil {
			e.ServerReference = *s
		}
		c.log.Info("mqtt: the broker closed the connection", "server", c.addr, "reason", ReasonText(p.ReasonCode), "reason_string", e.ReasonString)
		return e
	default:
		return violation(ReasonProtocolError, "unexpected packet type %d from the broker", p.Type())
	}
	return nil
}

func (c *Client) handlePublish(l *link, p *Publish) error {
	if p.Props.TopicAlias != nil {
		// Topic Alias Maximum 0: the broker must not send aliases
		// (§3.1.2.11.5).
		return violation(ReasonTopicAliasInvalid, "PUBLISH with topic alias %d, none was allowed", *p.Props.TopicAlias)
	}
	msg := &Message{Topic: p.Topic, Payload: p.Payload, QoS: p.QoS, Retain: p.Retain, Duplicate: p.Dup, Props: p.Props}
	switch p.QoS {
	case 0:
		c.enqueue(msg)
	case 1:
		// Acknowledge before the application sees the message: once it has
		// seen it, a Close must not lose the PUBACK and make the broker
		// deliver the message again. If the write fails the connection is
		// gone and the broker redelivers anyway (at least once), so the
		// message is delivered all the same.
		err := c.write(l, &Ack{Kind: TypePuback, PacketID: p.PacketID})
		c.enqueue(msg)
		return err
	case 2:
		c.mu.Lock()
		seen := c.qos2[p.PacketID]
		if !seen && l.version >= Version5 && len(c.qos2) >= c.recvMax {
			c.mu.Unlock()
			return violation(ReasonReceiveMaximumExceeded, "more than %d unacknowledged QoS 2 publications", c.recvMax)
		}
		c.qos2[p.PacketID] = true
		c.mu.Unlock()
		err := c.write(l, &Ack{Kind: TypePubrec, PacketID: p.PacketID})
		if !seen {
			c.enqueue(msg)
		}
		return err
	}
	return nil
}

func (c *Client) ack(id uint16, p Packet) {
	c.mu.Lock()
	ch := c.acks[id]
	delete(c.acks, id)
	c.mu.Unlock()
	if ch != nil {
		ch <- p
	}
}

func (c *Client) enqueue(m *Message) {
	select {
	case c.deliver <- m:
	case <-c.done:
	}
}

func (c *Client) deliverLoop() {
	defer close(c.deliverDone)
	c.deliverID.Store(goid.ID())
	var hs []Handler
	for {
		var m *Message
		select {
		case m = <-c.deliver:
		case <-c.done:
			return
		}
		select {
		case <-c.done:
			return // closed: no handler runs any more
		default:
		}
		c.mu.Lock()
		hs = hs[:0]
		filters := make([]string, 0, len(c.subs))
		for f := range c.subs {
			filters = append(filters, f)
		}
		sort.Strings(filters)
		for _, f := range filters {
			if !MatchTopic(f, m.Topic) {
				continue
			}
			e := c.subs[f]
			ids := make([]uint64, 0, len(e.handlers))
			for id := range e.handlers {
				ids = append(ids, id)
			}
			sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
			for _, id := range ids {
				hs = append(hs, e.handlers[id])
			}
		}
		c.mu.Unlock()
		if len(hs) == 0 && c.opts.DefaultHandler != nil {
			hs = append(hs, c.opts.DefaultHandler)
		}
		// Every handler owns its payload and properties.
		msgs := make([]*Message, len(hs))
		for i := range hs {
			msgs[i] = m
			if i > 0 {
				cp := *m
				cp.Payload = append([]byte(nil), m.Payload...)
				cp.Props.User = append([]UserProperty(nil), m.Props.User...)
				cp.Props.SubscriptionIDs = append([]uint32(nil), m.Props.SubscriptionIDs...)
				if m.Props.CorrelationData != nil {
					cp.Props.CorrelationData = append([]byte{}, m.Props.CorrelationData...)
				}
				msgs[i] = &cp
			}
		}
		for i, h := range hs {
			h(msgs[i])
		}
	}
}

// IsConnected reports whether the client is connected right now.
func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil
}

// ProtocolVersion returns the protocol level of the current (or last)
// connection: Version311 or Version5; 0 before the first connection.
func (c *Client) ProtocolVersion() byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.version
}

// ServerProperties returns the MQTT 5.0 properties of the last CONNACK
// (Assigned Client Identifier, Receive Maximum, Response Information, ...).
func (c *Client) ServerProperties() Properties {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.connack
	p.User = append([]UserProperty(nil), p.User...)
	return p
}

// PublishOptions are the options of [Client.PublishWith].
type PublishOptions struct {
	// QoS is 0 (at most once), 1 (at least once) or 2 (exactly once). An
	// MQTT 5.0 broker with a lower Maximum QoS gets that.
	QoS    byte
	Retain bool
	// Props are the MQTT 5.0 properties of the PUBLISH: payload format,
	// message expiry, content type, response topic, correlation data and
	// user properties. They are not sent over 3.1.1. Topic aliases and
	// subscription identifiers are not allowed.
	Props Properties
}

// Publish sends a message with PublishWith.
func (c *Client) Publish(ctx context.Context, topic string, payload []byte, qos byte, retain bool) error {
	return c.PublishWith(ctx, topic, payload, PublishOptions{QoS: qos, Retain: retain})
}

// PublishWith sends a message. QoS 0 returns once the message is written
// (or ErrNotConnected while reconnecting). QoS 1 returns when the broker
// acknowledged it (PUBACK) and QoS 2 when the exchange is complete
// (PUBCOMP); while the client reconnects, or the broker's Receive Maximum
// is reached, the message waits and is sent when it can. If ctx ends first
// the call returns; a message not yet sent is dropped, one already sent is
// still completed with the broker (it may have been delivered).
func (c *Client) PublishWith(ctx context.Context, topic string, payload []byte, opts PublishOptions) error {
	if !ValidTopicName(topic) {
		return fmt.Errorf("mqtt: invalid topic name %q", topic)
	}
	if opts.QoS > 2 {
		return fmt.Errorf("mqtt: QoS %d", opts.QoS)
	}
	if opts.Props.TopicAlias != nil || len(opts.Props.SubscriptionIDs) > 0 {
		return errors.New("mqtt: PUBLISH with a topic alias or subscription identifier")
	}
	pb, err := appendProps(nil, TypePublish, &opts.Props)
	if err != nil {
		return fmt.Errorf("mqtt: publish properties: %w", err)
	}
	if len(payload)+len(topic)+len(pb)+4 > MaxRemainingLength {
		return fmt.Errorf("mqtt: payload of %d bytes is too large", len(payload))
	}
	pkt := &Publish{Topic: topic, Payload: payload, QoS: opts.QoS, Retain: opts.Retain, Props: opts.Props}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrClosed
	}
	l := c.conn
	if l != nil {
		if err := c.refuse(l, pkt); err != nil {
			c.mu.Unlock()
			return err
		}
		if pkt.QoS > l.maxQoS {
			c.log.Debug("mqtt: QoS above the broker's Maximum QoS, downgraded", "qos", pkt.QoS, "maximum", l.maxQoS)
			pkt.QoS = l.maxQoS
		}
	}
	if pkt.QoS == 0 {
		c.mu.Unlock()
		if l == nil {
			return ErrNotConnected
		}
		return c.write(l, pkt)
	}
	pkt.PacketID = c.allocID()
	c.seq++
	pd := &pending{seq: c.seq, pkt: pkt, done: make(chan error, 1)}
	c.inflight[pkt.PacketID] = pd
	var send *Publish
	if l != nil {
		if l.quota > 0 {
			l.quota--
			pd.sent, pd.written = true, true
			cp := *pkt
			send = &cp
		} else {
			c.queue = append(c.queue, pd)
		}
	}
	c.mu.Unlock()
	if send != nil {
		c.sendPending(l, pd, send) // on a write failure it is resent after the reconnect
	}
	select {
	case err := <-pd.done:
		return err
	case <-ctx.Done():
		c.forget(pkt.PacketID, pd)
		return ctx.Err()
	case <-c.done:
		return ErrClosed
	}
}

// forget drops a publication whose caller gave up, unless it was sent: the
// broker may have it, and its exchange (and packet identifier) must be
// completed.
func (c *Client) forget(id uint16, pd *pending) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inflight[id] == pd && !pd.written {
		delete(c.inflight, id)
	}
}

// Subscription is an active subscription of a handler.
type Subscription struct {
	c      *Client
	filter string
	id     uint64
	once   sync.Once
}

// SubscribeOptions are the options of [Client.SubscribeWith].
type SubscribeOptions struct {
	// QoS is the maximum QoS of the messages the broker delivers.
	QoS byte
	// NoLocal, RetainAsPublished and RetainHandling are the MQTT 5.0
	// subscription options (§3.8.3.1); 3.1.1 ignores them.
	NoLocal           bool
	RetainAsPublished bool
	RetainHandling    byte
	// UserProperties are sent with the SUBSCRIBE (MQTT 5.0).
	UserProperties []UserProperty
}

// Subscribe subscribes h with SubscribeWith.
func (c *Client) Subscribe(ctx context.Context, filter string, qos byte, h Handler) (*Subscription, error) {
	return c.SubscribeWith(ctx, filter, SubscribeOptions{QoS: qos}, h)
}

// SubscribeWith subscribes h to a topic filter (with + and # wildcards).
// It waits for the broker's SUBACK; while the client is reconnecting the
// subscription is registered and made on the next connection. Several
// handlers may subscribe to the same filter: the broker gets the highest
// QoS and the options of the latest call.
func (c *Client) SubscribeWith(ctx context.Context, filter string, opts SubscribeOptions, h Handler) (*Subscription, error) {
	if !ValidTopicFilter(filter) {
		return nil, fmt.Errorf("mqtt: invalid topic filter %q", filter)
	}
	if h == nil {
		return nil, errors.New("mqtt: nil handler")
	}
	if opts.RetainHandling > RetainDoNotSend {
		return nil, fmt.Errorf("mqtt: retain handling %d", opts.RetainHandling)
	}
	if _, err := appendProps(nil, TypeSubscribe, &Properties{User: opts.UserProperties}); err != nil {
		return nil, fmt.Errorf("mqtt: subscribe properties: %w", err)
	}
	qos := min(opts.QoS, 2)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrClosed
	}
	l := c.conn
	if l != nil && l.noWild && strings.ContainsAny(filter, "+#") {
		c.mu.Unlock()
		return nil, fmt.Errorf("%w: wildcard subscriptions (%q)", ErrNotSupported, filter)
	}
	e := c.subs[filter]
	if e == nil {
		e = &subEntry{tf: TopicFilter{Filter: filter, QoS: qos}, handlers: map[uint64]Handler{}}
		c.subs[filter] = e
	}
	e.tf = TopicFilter{Filter: filter, QoS: max(e.tf.QoS, qos), NoLocal: opts.NoLocal,
		RetainAsPublished: opts.RetainAsPublished, RetainHandling: opts.RetainHandling}
	c.nextSubID++
	sub := &Subscription{c: c, filter: filter, id: c.nextSubID}
	e.handlers[sub.id] = h
	if l == nil {
		c.mu.Unlock()
		return sub, nil
	}
	tf := c.filterFor(l, e.tf)
	id := c.allocID()
	ch := make(chan Packet, 1)
	c.acks[id] = ch
	c.mu.Unlock()

	_ = c.write(l, &Subscribe{PacketID: id, Topics: []TopicFilter{tf}, Props: Properties{User: opts.UserProperties}})
	select {
	case p, ok := <-ch:
		if !ok {
			return sub, nil // connection lost: subscribed again on reconnect
		}
		s, _ := p.(*Suback)
		if s == nil || len(s.ReturnCodes) != 1 {
			sub.remove()
			return nil, fmt.Errorf("%w: %q", ErrSubscriptionRefused, filter)
		}
		if rc := s.ReturnCodes[0]; rc >= SubackFailure {
			sub.remove()
			if l.version >= Version5 {
				return nil, reasonErr(ErrSubscriptionRefused, filter, rc, &s.Props)
			}
			return nil, fmt.Errorf("%w: %q", ErrSubscriptionRefused, filter)
		}
		return sub, nil
	case <-ctx.Done():
		c.dropAck(id)
		sub.remove()
		return nil, ctx.Err()
	case <-c.done:
		return nil, ErrClosed
	}
}

func (c *Client) dropAck(id uint16) {
	c.mu.Lock()
	delete(c.acks, id)
	c.mu.Unlock()
}

// remove unregisters the handler; it reports whether the filter has no
// handlers left (and was removed).
func (s *Subscription) remove() (last bool) {
	c := s.c
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.subs[s.filter]
	if e == nil {
		return false
	}
	delete(e.handlers, s.id)
	if len(e.handlers) == 0 {
		delete(c.subs, s.filter)
		return true
	}
	return false
}

// Unsubscribe removes the handler. When it was the last handler of its
// filter the client unsubscribes from the broker and waits for UNSUBACK;
// an MQTT 5.0 refusal is returned as a [*ReasonError]. It is idempotent.
func (s *Subscription) Unsubscribe(ctx context.Context) error {
	var err error
	s.once.Do(func() {
		if !s.remove() {
			return
		}
		c := s.c
		c.mu.Lock()
		l := c.conn
		if l == nil || c.closed {
			c.mu.Unlock()
			return
		}
		id := c.allocID()
		ch := make(chan Packet, 1)
		c.acks[id] = ch
		c.mu.Unlock()
		if err = c.write(l, &Unsubscribe{PacketID: id, Filters: []string{s.filter}}); err != nil {
			c.dropAck(id)
			err = nil // the next session starts without the subscription
			return
		}
		select {
		case p, ok := <-ch:
			if a, _ := p.(*Ack); ok && a != nil && len(a.ReasonCodes) > 0 && a.ReasonCodes[0] >= 0x80 {
				err = reasonErr(ErrUnsubscribeRefused, s.filter, a.ReasonCodes[0], &a.Props)
			}
		case <-ctx.Done():
			c.dropAck(id)
			err = ctx.Err()
		case <-c.done:
		}
	})
	return err
}

// Close disconnects from the broker (sending DISCONNECT, with MQTT 5.0
// reason Normal disconnection: the will is not published) and stops the
// client. Pending calls return ErrClosed. It waits for a handler that is
// running, unless it is called from that handler.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	l := c.conn
	close(c.done)
	c.mu.Unlock()
	if l != nil {
		_ = c.write(l, &Disconnect{})
		_ = l.conn.Close()
	}
	c.wg.Wait()
	if goid.ID() != c.deliverID.Load() {
		<-c.deliverDone
	}
	return nil
}
