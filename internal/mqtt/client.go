// SPDX-License-Identifier: MIT

// Package mqtt is a small, dependency-free MQTT 3.1.1 client for the MQTT
// transport of OPC UA PubSub.
//
// It supports QoS 0 and 1 publishing (QoS 2 is downgraded to 1), receiving
// at QoS 0, 1 and 2, retained messages, wildcard subscriptions, user name
// and password, TLS, keep-alive with PINGREQ/PINGRESP and automatic
// reconnection with exponential backoff: after a reconnect the client
// subscribes again (unless the broker kept the session) and retransmits
// unacknowledged QoS 1 publications with the DUP flag.
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
)

// Defaults of [Options].
const (
	DefaultKeepAlive         = 60 * time.Second
	DefaultConnectTimeout    = 10 * time.Second
	DefaultMinReconnectDelay = 100 * time.Millisecond
	DefaultMaxReconnectDelay = 30 * time.Second
	DefaultMaxPacketSize     = 16 << 20
)

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
)

// ConnectError is a CONNACK with a return code other than 0.
type ConnectError struct {
	ReturnCode byte
}

func (e *ConnectError) Error() string {
	reasons := map[byte]string{
		ConnRefusedProtocolVersion:    "unacceptable protocol version",
		ConnRefusedIdentifierRejected: "client identifier rejected",
		ConnRefusedServerUnavailable:  "server unavailable",
		ConnRefusedBadCredentials:     "bad user name or password",
		ConnRefusedNotAuthorized:      "not authorized",
	}
	r, ok := reasons[e.ReturnCode]
	if !ok {
		r = "unknown reason"
	}
	return fmt.Sprintf("mqtt: connection refused: %s (%d)", r, e.ReturnCode)
}

// fatal reports whether retrying the connection cannot help.
func (e *ConnectError) fatal() bool { return e.ReturnCode != ConnRefusedServerUnavailable }

// Options configure a [Client].
type Options struct {
	// Server is mqtt://host[:1883] or mqtts://host[:8883] (also tcp://,
	// ssl:// and tls://).
	Server string
	// ClientID may be empty with a clean session: the broker assigns one.
	ClientID string
	// Username and Password are sent if Username is not empty.
	Username string
	Password string
	// PersistentSession asks the broker to keep the session (clean session
	// off). It needs a ClientID.
	PersistentSession bool
	// KeepAlive is the keep-alive interval, rounded up to whole seconds.
	// Zero selects DefaultKeepAlive, a negative value turns it off.
	KeepAlive time.Duration
	// TLSConfig is used for mqtts. Nil selects the system defaults.
	TLSConfig *tls.Config
	// ConnectTimeout bounds one connection attempt (dial and CONNACK).
	ConnectTimeout time.Duration
	// MinReconnectDelay and MaxReconnectDelay bound the exponential backoff
	// between connection attempts.
	MinReconnectDelay time.Duration
	MaxReconnectDelay time.Duration
	// MaxPacketSize limits received packets; larger ones are dropped.
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
	// OnConnectionLost is called when an established connection breaks.
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
}

// Handler receives messages. Handlers run on one delivery goroutine, in the
// order the messages arrived; a slow handler delays the others.
type Handler func(*Message)

// Client is an MQTT 3.1.1 client. Its methods are safe for concurrent use.
type Client struct {
	opts      Options
	network   string
	addr      string
	tls       bool
	keepAlive time.Duration
	log       *slog.Logger

	done    chan struct{} // closed by Close
	deliver chan *Message
	wg      sync.WaitGroup

	writeMu sync.Mutex

	mu        sync.Mutex
	closed    bool
	conn      net.Conn // nil while disconnected
	connGen   uint64
	nextID    uint16
	seq       uint64
	inflight  map[uint16]*pending
	acks      map[uint16]chan Packet
	subs      map[string]*subEntry
	nextSubID uint64
	qos2      map[uint16]bool // received QoS 2 packet ids awaiting PUBREL

	lastSent atomic.Int64 // unix nanos
	lastRecv atomic.Int64
	pingSent atomic.Int64 // 0: no ping outstanding
}

type pending struct {
	seq  uint64
	pkt  *Publish
	done chan error
}

type subEntry struct {
	qos      byte
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
	c.wg.Add(2)
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
		opts:     opts,
		network:  "tcp",
		log:      opts.Logger,
		done:     make(chan struct{}),
		deliver:  make(chan *Message, 256),
		inflight: map[uint16]*pending{},
		acks:     map[uint16]chan Packet{},
		subs:     map[string]*subEntry{},
		qos2:     map[uint16]bool{},
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
	if c.opts.MaxPacketSize <= 0 {
		c.opts.MaxPacketSize = DefaultMaxPacketSize
	}
	if opts.PersistentSession && opts.ClientID == "" {
		return nil, errors.New("mqtt: a persistent session needs a client identifier")
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
		conn, br, sp, err := c.connect(attemptCtx)
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
		if !c.attach(conn, sp) {
			_ = conn.Close()
			return
		}
		if !connected {
			connected = true
			first <- nil
		}
		if c.opts.OnConnect != nil {
			c.opts.OnConnect(sp)
		}
		err = c.serve(conn, br)
		c.detach(conn)
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

// connect dials the broker and performs the CONNECT/CONNACK handshake.
func (c *Client) connect(ctx context.Context) (net.Conn, *bufio.Reader, bool, error) {
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
	pkt := &Connect{
		CleanSession: !c.opts.PersistentSession,
		KeepAlive:    uint16(c.keepAlive / time.Second),
		ClientID:     c.opts.ClientID,
		Will:         c.opts.Will,
	}
	if c.opts.Username != "" {
		u := c.opts.Username
		pkt.Username = &u
		if c.opts.Password != "" {
			pkt.Password = []byte(c.opts.Password)
		}
	}
	b, err := Encode(pkt)
	if err == nil {
		_, err = conn.Write(b)
	}
	if err != nil {
		_ = conn.Close()
		return nil, nil, false, err
	}
	br := bufio.NewReader(conn)
	p, err := ReadPacket(br, 16)
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
		return nil, nil, false, &ConnectError{ReturnCode: ack.ReturnCode}
	}
	if !stopClose() {
		return nil, nil, false, ctx.Err()
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, br, ack.SessionPresent, nil
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

// attach makes conn the current connection, subscribes again if the
// session is new and retransmits unacknowledged publications. False if the
// client was closed meanwhile.
func (c *Client) attach(conn net.Conn, sessionPresent bool) bool {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return false
	}
	c.conn = conn
	c.connGen++
	gen := c.connGen
	now := time.Now().UnixNano()
	c.lastSent.Store(now)
	c.lastRecv.Store(now)
	c.pingSent.Store(0)
	var resub []TopicFilter
	if !sessionPresent {
		for f, e := range c.subs {
			resub = append(resub, TopicFilter{Filter: f, QoS: e.qos})
		}
		sort.Slice(resub, func(i, j int) bool { return resub[i].Filter < resub[j].Filter })
	}
	var resend []*pending
	for _, p := range c.inflight {
		resend = append(resend, p)
	}
	sort.Slice(resend, func(i, j int) bool { return resend[i].seq < resend[j].seq })
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
			c.resubscribe(conn, gen, resub, subID, subAck)
		}()
	}
	for _, p := range resend {
		pkt := *p.pkt
		pkt.Dup = true
		_ = c.write(conn, &pkt)
	}
	return true
}

// resubscribe makes the subscriptions of the client again on a new
// connection. The filters the broker refuses are asked for again, with
// backoff, for as long as the connection lasts and they have handlers:
// nobody else would, the subscribers believe they are subscribed.
func (c *Client) resubscribe(conn net.Conn, gen uint64, filters []TopicFilter, id uint16, ack chan Packet) {
	delay := c.opts.MinReconnectDelay
	for {
		_ = c.write(conn, &Subscribe{PacketID: id, Topics: filters})
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
				if rc == SubackFailure && i < len(filters) {
					c.log.Warn("mqtt: broker refused subscription after reconnect", "filter", filters[i].Filter, "retry_in", delay)
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
		if c.closed || c.conn != conn || c.connGen != gen {
			c.mu.Unlock()
			return
		}
		filters = filters[:0]
		for _, f := range refused {
			if e := c.subs[f]; e != nil {
				filters = append(filters, TopicFilter{Filter: f, QoS: e.qos})
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

// detach forgets conn and fails the waiters that need it.
func (c *Client) detach(conn net.Conn) {
	_ = conn.Close()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == conn {
		c.conn = nil
	}
	for id, ch := range c.acks {
		close(ch) // waiters treat a closed channel as "connection lost"
		delete(c.acks, id)
	}
	clear(c.qos2)
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

func (c *Client) write(conn net.Conn, p Packet) error {
	b, err := Encode(p)
	if err != nil {
		return err
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	timeout := max(c.keepAlive, 10*time.Second)
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err = conn.Write(b)
	if err != nil {
		_ = conn.Close() // the reader notices and the client reconnects
		return err
	}
	c.lastSent.Store(time.Now().UnixNano())
	return nil
}

// serve reads packets from conn until it fails, and keeps it alive.
func (c *Client) serve(conn net.Conn, br *bufio.Reader) error {
	stop := make(chan struct{})
	var kwg sync.WaitGroup
	if c.keepAlive > 0 {
		kwg.Add(1)
		go func() {
			defer kwg.Done()
			c.keepAliveLoop(conn, stop)
		}()
	}
	defer func() {
		close(stop)
		kwg.Wait()
	}()
	for {
		p, err := ReadPacket(br, c.opts.MaxPacketSize)
		if errors.Is(err, ErrTooLarge) {
			c.log.Warn("mqtt: dropped a packet above the size limit", "error", err)
			continue
		}
		if err != nil {
			_ = conn.Close()
			return err
		}
		c.lastRecv.Store(time.Now().UnixNano())
		if err := c.handle(conn, p); err != nil {
			_ = conn.Close()
			return err
		}
	}
}

func (c *Client) keepAliveLoop(conn net.Conn, stop <-chan struct{}) {
	interval := max(c.keepAlive/4, 10*time.Millisecond)
	t := time.NewTicker(interval)
	defer t.Stop()
	idle := c.keepAlive * 3 / 4
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
			if now.Sub(time.Unix(0, ps)) > c.keepAlive {
				c.log.Debug("mqtt: keep-alive timeout", "server", c.addr)
				_ = conn.Close()
				return
			}
			continue
		}
		if now.Sub(time.Unix(0, c.lastSent.Load())) >= idle || now.Sub(time.Unix(0, c.lastRecv.Load())) >= idle {
			c.pingSent.Store(now.UnixNano())
			_ = c.write(conn, &Simple{Kind: TypePingreq})
		}
	}
}

func (c *Client) handle(conn net.Conn, p Packet) error {
	switch p := p.(type) {
	case *Publish:
		msg := &Message{Topic: p.Topic, Payload: p.Payload, QoS: p.QoS, Retain: p.Retain, Duplicate: p.Dup}
		switch p.QoS {
		case 0:
			c.enqueue(msg)
		case 1:
			// Acknowledge before the application sees the message: once it
			// has seen it, a Close must not lose the PUBACK and make the
			// broker deliver the message again. If the write fails the
			// connection is gone and the broker redelivers anyway (at least
			// once), so the message is delivered all the same.
			err := c.write(conn, &Ack{Kind: TypePuback, PacketID: p.PacketID})
			c.enqueue(msg)
			return err
		case 2:
			c.mu.Lock()
			seen := c.qos2[p.PacketID]
			c.qos2[p.PacketID] = true
			c.mu.Unlock()
			err := c.write(conn, &Ack{Kind: TypePubrec, PacketID: p.PacketID})
			if !seen {
				c.enqueue(msg)
			}
			return err
		}
	case *Ack:
		switch p.Kind {
		case TypePuback:
			c.mu.Lock()
			pd := c.inflight[p.PacketID]
			delete(c.inflight, p.PacketID)
			c.mu.Unlock()
			if pd != nil {
				pd.done <- nil
			}
		case TypePubrel:
			c.mu.Lock()
			delete(c.qos2, p.PacketID)
			c.mu.Unlock()
			return c.write(conn, &Ack{Kind: TypePubcomp, PacketID: p.PacketID})
		case TypeUnsuback:
			c.ack(p.PacketID, p)
		case TypePubrec, TypePubcomp:
			// Only for QoS 2 publications, which this client does not send.
		}
	case *Suback:
		c.ack(p.PacketID, p)
	case *Simple:
		if p.Kind == TypePingresp {
			c.pingSent.Store(0)
			return nil
		}
		return protoErr("unexpected packet type %d from the broker", p.Kind)
	default:
		return protoErr("unexpected packet type %d from the broker", p.Type())
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
	defer c.wg.Done()
	var hs []Handler
	for {
		var m *Message
		select {
		case m = <-c.deliver:
		case <-c.done:
			return
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
		// Every handler owns its payload.
		msgs := make([]*Message, len(hs))
		for i := range hs {
			msgs[i] = m
			if i > 0 {
				cp := *m
				cp.Payload = append([]byte(nil), m.Payload...)
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

// Publish sends a message. QoS 0 returns once the message is written (or
// ErrNotConnected while reconnecting). QoS 1 (and 2, downgraded to 1)
// returns when the broker acknowledged it; while the client reconnects the
// message waits and is sent on the next connection. If ctx ends first the
// message is abandoned (it may still have been delivered).
func (c *Client) Publish(ctx context.Context, topic string, payload []byte, qos byte, retain bool) error {
	if !ValidTopicName(topic) {
		return fmt.Errorf("mqtt: invalid topic name %q", topic)
	}
	if len(payload)+len(topic)+4 > MaxRemainingLength {
		return fmt.Errorf("mqtt: payload of %d bytes is too large", len(payload))
	}
	if qos > 1 {
		qos = 1
	}
	pkt := &Publish{Topic: topic, Payload: payload, QoS: qos, Retain: retain}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrClosed
	}
	conn := c.conn
	if qos == 0 {
		c.mu.Unlock()
		if conn == nil {
			return ErrNotConnected
		}
		return c.write(conn, pkt)
	}
	pkt.PacketID = c.allocID()
	c.seq++
	pd := &pending{seq: c.seq, pkt: pkt, done: make(chan error, 1)}
	c.inflight[pkt.PacketID] = pd
	c.mu.Unlock()
	if conn != nil {
		_ = c.write(conn, pkt) // on failure it is resent after the reconnect
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

func (c *Client) forget(id uint16, pd *pending) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inflight[id] == pd {
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

// Subscribe subscribes h to a topic filter (with + and # wildcards). It
// waits for the broker's SUBACK; while the client is reconnecting the
// subscription is registered and made on the next connection. Several
// handlers may subscribe to the same filter.
func (c *Client) Subscribe(ctx context.Context, filter string, qos byte, h Handler) (*Subscription, error) {
	if !ValidTopicFilter(filter) {
		return nil, fmt.Errorf("mqtt: invalid topic filter %q", filter)
	}
	if h == nil {
		return nil, errors.New("mqtt: nil handler")
	}
	if qos > 2 {
		qos = 2
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrClosed
	}
	e := c.subs[filter]
	if e == nil {
		e = &subEntry{qos: qos, handlers: map[uint64]Handler{}}
		c.subs[filter] = e
	}
	e.qos = max(e.qos, qos)
	c.nextSubID++
	sub := &Subscription{c: c, filter: filter, id: c.nextSubID}
	e.handlers[sub.id] = h
	conn := c.conn
	if conn == nil {
		c.mu.Unlock()
		return sub, nil
	}
	id := c.allocID()
	ch := make(chan Packet, 1)
	c.acks[id] = ch
	c.mu.Unlock()

	_ = c.write(conn, &Subscribe{PacketID: id, Topics: []TopicFilter{{Filter: filter, QoS: e.qos}}})
	select {
	case p, ok := <-ch:
		if !ok {
			return sub, nil // connection lost: subscribed again on reconnect
		}
		if s, _ := p.(*Suback); s == nil || len(s.ReturnCodes) != 1 || s.ReturnCodes[0] == SubackFailure {
			sub.remove()
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
// filter the client unsubscribes from the broker and waits for UNSUBACK.
// It is idempotent.
func (s *Subscription) Unsubscribe(ctx context.Context) error {
	var err error
	s.once.Do(func() {
		if !s.remove() {
			return
		}
		c := s.c
		c.mu.Lock()
		conn := c.conn
		if conn == nil || c.closed {
			c.mu.Unlock()
			return
		}
		id := c.allocID()
		ch := make(chan Packet, 1)
		c.acks[id] = ch
		c.mu.Unlock()
		if err = c.write(conn, &Unsubscribe{PacketID: id, Filters: []string{s.filter}}); err != nil {
			c.dropAck(id)
			err = nil // the next session starts without the subscription
			return
		}
		select {
		case <-ch:
		case <-ctx.Done():
			c.dropAck(id)
			err = ctx.Err()
		case <-c.done:
		}
	})
	return err
}

// Close disconnects from the broker (sending DISCONNECT) and stops the
// client. Pending calls return ErrClosed.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	conn := c.conn
	close(c.done)
	c.mu.Unlock()
	if conn != nil {
		_ = c.write(conn, &Simple{Kind: TypeDisconnect})
		_ = conn.Close()
	}
	c.wg.Wait()
	return nil
}
