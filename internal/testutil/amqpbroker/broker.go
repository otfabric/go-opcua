// SPDX-License-Identifier: MIT

// Package amqpbroker is a small in-process AMQP 1.0 broker for tests.
//
// It speaks SASL (ANONYMOUS, PLAIN with user name and password checks,
// EXTERNAL with a TLS client certificate) and TLS, opens any number of
// sessions per connection, and routes messages by address:
//
//   - a queue address (by default one starting with "/queues/", like
//     RabbitMQ's, or "queue://") keeps its messages until a consumer takes
//     them; consumers compete, round-robin;
//   - any other address is a topic: every receiver link attached to it
//     gets a copy, and nothing is kept for later.
//
// It grants link credit to senders, honours the credit of receivers and the
// session windows, splits and joins multi-frame transfers, settles
// unsettled deliveries with a disposition and redelivers the unaccepted
// messages of a queue when a consumer goes away. It sends empty frames as
// the client's idle-time-out asks and drops clients that stay silent for
// longer than its own.
//
// For chaos tests the broker can be stopped and started again on the same
// address (Stop keeps the queues, like a broker with persistence; Reset
// forgets them), drop all connections, close them with an error, detach
// the links of an address, withhold its dispositions and stop sending
// heartbeats.
package amqpbroker

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/otfabric/go-opcua/internal/amqp"
)

// Options configure a Broker.
type Options struct {
	// TLSConfig, if set, makes the broker speak TLS (amqps). Set ClientAuth
	// to accept SASL EXTERNAL with client certificates.
	TLSConfig *tls.Config
	// Users, if set, are the accepted PLAIN user names and passwords;
	// ANONYMOUS is refused then.
	Users map[string]string
	// Mechanisms overrides the offered SASL mechanisms.
	Mechanisms []string
	// RequireSASL refuses clients that skip the SASL layer.
	RequireSASL bool
	// MaxFrameSize is the largest frame the broker accepts (default 64 KiB).
	MaxFrameSize uint32
	// MaxMessageSize is announced on the links (0: no limit).
	MaxMessageSize uint64
	// IdleTimeout: clients silent for this long are dropped; half of it is
	// announced (0: none).
	IdleTimeout time.Duration
	// Credit is the link credit given to senders (default 100).
	Credit uint32
	// MaxQueued bounds the messages kept per queue and per subscriber
	// (default 10000).
	MaxQueued int
	// IsQueue tells the queue addresses from the topic addresses.
	IsQueue func(address string) bool
	// RefuseAddress, if set, refuses the links to the addresses it returns
	// true for (amqp:not-found).
	RefuseAddress func(address string) bool
	// RefuseOpen, if set, answers an open with a close carrying the error
	// it returns (nil: accept).
	RefuseOpen func(*amqp.Open) *amqp.Error
	// Outcome, if set, decides the outcome of the unsettled messages
	// clients send (nil result: accepted). Only accepted messages are
	// routed.
	Outcome func(address string, m *amqp.Message) amqp.DeliveryState
	// OnOpen, OnAttach and OnMessage see the client's open and attach
	// frames and every message it sends (before routing).
	OnOpen    func(*amqp.Open)
	OnAttach  func(*amqp.Attach)
	OnMessage func(address string, m *amqp.Message, settled bool)
	Logger    *slog.Logger
}

// Broker is an in-process AMQP 1.0 broker.
type Broker struct {
	opts Options
	log  *slog.Logger

	mu        sync.Mutex
	ln        net.Listener
	addr      string
	running   bool
	clients   map[*client]struct{}
	queues    map[string]*queue
	topics    map[string]map[*blink]struct{}
	acceptWG  sync.WaitGroup
	clientsWG sync.WaitGroup

	silent   atomic.Bool
	withhold atomic.Bool
	received atomic.Int64
}

type stored struct {
	payload []byte
}

type queue struct {
	msgs      []*stored
	consumers []*blink
	next      int
}

type client struct {
	b    *Broker
	conn net.Conn
	out  chan []byte
	done chan struct{}
	once sync.Once

	maxFrame   uint32       // the client's
	remoteIdle atomic.Int64 // the client's idle-time-out
	sessions   map[uint16]*session
	closing    bool // the broker ended the connection: it sends nothing more
	lastSent   atomic.Int64
	unwritten  atomic.Int64 // frames queued, not written yet
}

type session struct {
	c                    *client
	channel              uint16
	links                map[uint32]*blink // by the client's handle
	nextOutgoingID       uint32
	nextDeliveryID       uint32
	nextIncomingID       uint32
	incomingWindow       uint32
	remoteIncomingWindow uint32
	unacked              map[uint32]*unacked
}

type unacked struct {
	l   *blink
	msg *stored
}

// blink is a link of the broker: role is the broker's end.
type blink struct {
	s             *session
	handle        uint32 // the broker's, equal to the client's
	role          amqp.Role
	address       string
	queue         bool
	settled       bool // the broker sends pre-settled deliveries
	credit        uint32
	deliveryCount uint32
	backlog       []*stored
	tag           uint64

	inDelivery bool
	curID      uint32
	curSettled bool
	partial    []byte
}

const sessionWindow = 1 << 20

// New returns a stopped broker.
func New(opts Options) *Broker {
	if opts.MaxQueued <= 0 {
		opts.MaxQueued = 10000
	}
	if opts.Credit == 0 {
		opts.Credit = 100
	}
	if opts.MaxFrameSize == 0 {
		opts.MaxFrameSize = 64 << 10
	}
	if opts.IsQueue == nil {
		opts.IsQueue = func(a string) bool { return strings.HasPrefix(a, "/queues/") || strings.HasPrefix(a, "queue://") }
	}
	b := &Broker{
		opts:    opts,
		log:     opts.Logger,
		clients: map[*client]struct{}{},
		queues:  map[string]*queue{},
		topics:  map[string]map[*blink]struct{}{},
	}
	if b.log == nil {
		b.log = slog.New(slog.DiscardHandler)
	}
	return b
}

// Start listens on 127.0.0.1 (a free port the first time, the same port
// after a Stop) and serves clients.
func (b *Broker) Start() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.running {
		return errors.New("amqpbroker: already running")
	}
	addr := b.addr
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	var ln net.Listener
	var err error
	// The port of a stopped broker may need a moment to be free again.
	for range 50 {
		if ln, err = net.Listen("tcp", addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		return fmt.Errorf("amqpbroker: listen: %w", err)
	}
	if b.opts.TLSConfig != nil {
		ln = tls.NewListener(ln, b.opts.TLSConfig)
	}
	b.ln = ln
	b.addr = ln.Addr().String()
	b.running = true
	b.acceptWG.Add(1)
	go b.accept(ln)
	return nil
}

// Addr returns the host:port the broker listens on.
func (b *Broker) Addr() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.addr
}

// URL returns amqp://addr or amqps://addr.
func (b *Broker) URL() string {
	if b.opts.TLSConfig != nil {
		return "amqps://" + b.Addr()
	}
	return "amqp://" + b.Addr()
}

// Stop closes the listener and all connections. Queues are kept for the
// next Start.
func (b *Broker) Stop() {
	b.mu.Lock()
	if !b.running {
		b.mu.Unlock()
		return
	}
	b.running = false
	ln := b.ln
	b.mu.Unlock()
	_ = ln.Close()
	b.acceptWG.Wait()
	b.DropConnections()
	b.clientsWG.Wait()
}

// Restart stops and starts the broker.
func (b *Broker) Restart() error {
	b.Stop()
	return b.Start()
}

// Close stops the broker for good.
func (b *Broker) Close() { b.Stop() }

// Reset forgets all queued messages.
func (b *Broker) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, q := range b.queues {
		q.msgs = nil
	}
}

// DropConnections closes all client connections without a protocol
// goodbye; the broker keeps listening.
func (b *Broker) DropConnections() {
	b.mu.Lock()
	cs := make([]*client, 0, len(b.clients))
	for c := range b.clients {
		c.shutdown()
		cs = append(cs, c)
	}
	b.mu.Unlock()
	// Closed outside b.mu: closing a TLS connection writes.
	for _, c := range cs {
		c.close()
	}
}

// CloseConnections closes all client connections with a close frame
// carrying e.
func (b *Broker) CloseConnections(e *amqp.Error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for c := range b.clients {
		if c.sessions != nil && !c.closing {
			c.send(0, &amqp.Close{Error: e}, nil)
			c.shutdown()
		}
	}
}

// DetachLinks detaches (closes) all links to address with error e.
func (b *Broker) DetachLinks(address string, e *amqp.Error) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for c := range b.clients {
		for _, s := range c.sessions {
			for h, l := range s.links {
				if l.address == address {
					c.send(s.channel, &amqp.Detach{Handle: l.handle, Closed: true, Error: e}, nil)
					b.dropLink(l)
					delete(s.links, h)
					n++
				}
			}
		}
	}
	return n
}

// SetSilent makes the broker stop (or resume) sending heartbeats.
func (b *Broker) SetSilent(silent bool) { b.silent.Store(silent) }

// SetWithholdDispositions makes the broker stop (or resume) settling the
// unsettled messages clients send: the messages are routed, but the
// clients never learn it.
func (b *Broker) SetWithholdDispositions(w bool) { b.withhold.Store(w) }

// ClientCount returns the number of open connections.
func (b *Broker) ClientCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for c := range b.clients {
		if c.sessions != nil {
			n++
		}
	}
	return n
}

// LinkCount returns the number of links attached to address.
func (b *Broker) LinkCount(address string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for c := range b.clients {
		for _, s := range c.sessions {
			for _, l := range s.links {
				if l.address == address {
					n++
				}
			}
		}
	}
	return n
}

// Received returns the number of messages clients sent.
func (b *Broker) Received() int64 { return b.received.Load() }

// Queued returns the number of messages waiting in a queue.
func (b *Broker) Queued(address string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if q := b.queues[address]; q != nil {
		return len(q.msgs)
	}
	return 0
}

func (b *Broker) accept(ln net.Listener) {
	defer b.acceptWG.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		c := &client{b: b, conn: conn, out: make(chan []byte, 4096), done: make(chan struct{})}
		b.mu.Lock()
		if !b.running {
			b.mu.Unlock()
			_ = conn.Close()
			return
		}
		b.clients[c] = struct{}{}
		b.clientsWG.Add(2)
		b.mu.Unlock()
		go c.writeLoop()
		go c.serve()
	}
}

// close ends the connection; serve cleans up.
func (c *client) close() {
	c.once.Do(func() {
		close(c.done)
		_ = c.conn.Close()
	})
}

// sendRaw queues bytes; a client that cannot keep up is disconnected.
func (c *client) sendRaw(buf []byte) {
	c.unwritten.Add(1)
	select {
	case c.out <- buf:
	case <-c.done:
		c.unwritten.Add(-1)
	default:
		c.unwritten.Add(-1)
		c.b.log.Warn("amqpbroker: slow client disconnected")
		c.close()
	}
}

func (c *client) send(channel uint16, body amqp.Body, payload []byte) {
	c.sendType(amqp.FrameAMQP, channel, body, payload)
}

func (c *client) sendType(typ byte, channel uint16, body amqp.Body, payload []byte) {
	buf, err := amqp.AppendFrame(nil, &amqp.Frame{Type: typ, Channel: channel, Body: body, Payload: payload})
	if err != nil {
		c.b.log.Error("amqpbroker: encode", "error", err)
		return
	}
	c.sendRaw(buf)
}

func (c *client) writeLoop() {
	defer c.b.clientsWG.Done()
	var tick <-chan time.Time
	for {
		select {
		case buf := <-c.out:
			_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			_, err := c.conn.Write(buf)
			c.unwritten.Add(-1)
			if err != nil {
				c.close()
				return
			}
			c.lastSent.Store(time.Now().UnixNano())
			if idle := time.Duration(c.remoteIdle.Load()); tick == nil && idle > 0 {
				t := time.NewTicker(idle / 4)
				defer t.Stop()
				tick = t.C
			}
		case <-tick:
			idle := time.Duration(c.remoteIdle.Load())
			if !c.b.silent.Load() && time.Since(time.Unix(0, c.lastSent.Load())) >= idle/2 {
				// An empty frame (§2.4.5).
				c.sendRaw([]byte{0, 0, 0, 8, 2, 0, 0, 0})
			}
		case <-c.done:
			return
		}
	}
}

func (c *client) serve() {
	b := c.b
	defer b.clientsWG.Done()
	defer c.cleanup()
	br := bufio.NewReader(c.conn)
	// Whatever ends the connection, the frames queued before (a close, a
	// SASL outcome) get a moment to go out.
	defer c.flushSoon()
	_ = c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if !c.handshake(br) {
		return
	}
	for {
		if b.opts.IdleTimeout > 0 {
			_ = c.conn.SetReadDeadline(time.Now().Add(b.opts.IdleTimeout))
		} else {
			_ = c.conn.SetReadDeadline(time.Time{})
		}
		f, err := amqp.ReadFrame(br, b.opts.MaxFrameSize)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				b.log.Debug("amqpbroker: read", "error", err)
			}
			return
		}
		if f.Body == nil {
			continue
		}
		b.mu.Lock()
		ok := c.handle(f)
		if !ok {
			c.shutdown()
		}
		b.mu.Unlock()
		if !ok {
			return
		}
	}
}

func readHeader(r io.Reader) ([8]byte, error) {
	var h [8]byte
	_, err := io.ReadFull(r, h[:])
	return h, err
}

// handshakeFrame sends a frame of the handshake, on channel 0.
func (c *client) handshakeFrame(typ byte, body amqp.Body) {
	c.sendType(typ, 0, body, nil)
}

// handshake runs the protocol header and SASL exchange and the open.
func (c *client) handshake(br *bufio.Reader) bool {
	b := c.b
	h, err := readHeader(br)
	if err != nil {
		return false
	}
	switch h {
	case amqp.HeaderSASL:
		c.sendRaw(amqp.HeaderSASL[:])
		if !c.sasl(br) {
			return false
		}
		if h, err = readHeader(br); err != nil || h != amqp.HeaderAMQP {
			return false
		}
		c.sendRaw(amqp.HeaderAMQP[:])
	case amqp.HeaderAMQP:
		if b.opts.RequireSASL || b.opts.Users != nil {
			c.sendRaw(amqp.HeaderSASL[:])
			return false
		}
		c.sendRaw(amqp.HeaderAMQP[:])
	default:
		c.sendRaw(amqp.HeaderAMQP[:])
		return false
	}
	f, err := amqp.ReadFrame(br, b.opts.MaxFrameSize)
	if err != nil {
		return false
	}
	open, ok := f.Body.(*amqp.Open)
	if !ok {
		return false
	}
	if b.opts.OnOpen != nil {
		b.opts.OnOpen(open)
	}
	var idle uint32
	if b.opts.IdleTimeout > 0 {
		idle = uint32(b.opts.IdleTimeout / 2 / time.Millisecond)
	}
	c.handshakeFrame(amqp.FrameAMQP, &amqp.Open{ContainerID: "amqpbroker", MaxFrameSize: b.opts.MaxFrameSize, ChannelMax: math.MaxUint16, IdleTimeout: idle})
	if b.opts.RefuseOpen != nil {
		if e := b.opts.RefuseOpen(open); e != nil {
			c.handshakeFrame(amqp.FrameAMQP, &amqp.Close{Error: e})
			return false
		}
	}
	b.mu.Lock()
	if c.closing {
		b.mu.Unlock()
		return false
	}
	c.maxFrame = max(open.MaxFrameSize, amqp.MinMaxFrameSize)
	c.remoteIdle.Store(int64(time.Duration(open.IdleTimeout) * time.Millisecond))
	c.sessions = map[uint16]*session{}
	b.mu.Unlock()
	return true
}

func (c *client) mechanisms() []amqp.Symbol {
	b := c.b
	if b.opts.Mechanisms != nil {
		out := make([]amqp.Symbol, len(b.opts.Mechanisms))
		for i, m := range b.opts.Mechanisms {
			out[i] = amqp.Symbol(m)
		}
		return out
	}
	m := []amqp.Symbol{"PLAIN"}
	if b.opts.Users == nil {
		m = append(m, "ANONYMOUS")
	}
	if b.opts.TLSConfig != nil {
		m = append(m, "EXTERNAL")
	}
	return m
}

func (c *client) sasl(br *bufio.Reader) bool {
	b := c.b
	mechs := c.mechanisms()
	c.handshakeFrame(amqp.FrameSASL, &amqp.SASLMechanisms{Mechanisms: mechs})
	f, err := amqp.ReadFrame(br, b.opts.MaxFrameSize)
	if err != nil {
		return false
	}
	init, ok := f.Body.(*amqp.SASLInit)
	if !ok {
		return false
	}
	code := amqp.SASLAuth
	if slices.Contains(mechs, init.Mechanism) {
		switch string(init.Mechanism) {
		case "ANONYMOUS":
			if b.opts.Users == nil {
				code = amqp.SASLOk
			}
		case "PLAIN":
			parts := bytes.SplitN(init.InitialResponse, []byte{0}, 3)
			if len(parts) == 3 {
				if b.opts.Users == nil {
					code = amqp.SASLOk
				} else if pw, ok := b.opts.Users[string(parts[1])]; ok && pw == string(parts[2]) {
					code = amqp.SASLOk
				}
			}
		case "EXTERNAL":
			if tc, ok := c.conn.(*tls.Conn); ok && len(tc.ConnectionState().PeerCertificates) > 0 {
				code = amqp.SASLOk
			}
		}
	}
	c.handshakeFrame(amqp.FrameSASL, &amqp.SASLOutcome{Code: code})
	return code == amqp.SASLOk
}

// handle processes a frame; false closes the connection. b.mu is held.
func (c *client) handle(f *amqp.Frame) bool {
	if f.Type != amqp.FrameAMQP {
		return false
	}
	if _, ok := f.Body.(*amqp.Close); ok {
		if !c.closing {
			c.send(0, &amqp.Close{}, nil)
		}
		return false
	}
	if c.closing {
		return true // after its close the broker only waits for the client's
	}
	if begin, ok := f.Body.(*amqp.Begin); ok {
		if _, used := c.sessions[f.Channel]; used {
			return false
		}
		s := &session{c: c, channel: f.Channel, links: map[uint32]*blink{}, nextIncomingID: begin.NextOutgoingID,
			incomingWindow: sessionWindow, remoteIncomingWindow: begin.IncomingWindow, unacked: map[uint32]*unacked{}}
		c.sessions[f.Channel] = s
		ch := f.Channel
		c.send(f.Channel, &amqp.Begin{RemoteChannel: &ch, IncomingWindow: sessionWindow, OutgoingWindow: math.MaxUint32, HandleMax: 1023}, nil)
		return true
	}
	s := c.sessions[f.Channel]
	if s == nil {
		return false
	}
	switch p := f.Body.(type) {
	case *amqp.Attach:
		return s.attach(p)
	case *amqp.Flow:
		s.flow(p)
	case *amqp.Transfer:
		return s.transfer(p, f.Payload)
	case *amqp.Disposition:
		s.disposition(p)
	case *amqp.Detach:
		l := s.links[p.Handle]
		if l == nil {
			return true // the answer to a detach of the broker
		}
		delete(s.links, p.Handle)
		c.b.dropLink(l)
		c.send(s.channel, &amqp.Detach{Handle: l.handle, Closed: p.Closed}, nil)
	case *amqp.End:
		for h, l := range s.links {
			c.b.dropLink(l)
			delete(s.links, h)
		}
		delete(c.sessions, s.channel)
		c.send(s.channel, &amqp.End{}, nil)
	default:
		return false
	}
	return true
}

// flushSoon gives the write loop a moment before the connection closes.
func (c *client) flushSoon() {
	deadline := time.Now().Add(time.Second)
	for c.unwritten.Load() > 0 && time.Now().Before(deadline) {
		select {
		case <-c.done:
			return
		case <-time.After(time.Millisecond):
		}
	}
}

func (s *session) attach(a *amqp.Attach) bool {
	c, b := s.c, s.c.b
	if _, used := s.links[a.Handle]; used {
		return false
	}
	if b.opts.OnAttach != nil {
		b.opts.OnAttach(a)
	}
	l := &blink{s: s, handle: a.Handle, role: amqp.RoleReceiver}
	if a.Role == amqp.RoleReceiver {
		l.role = amqp.RoleSender
	}
	reply := &amqp.Attach{Name: a.Name, Handle: a.Handle, Role: l.role, SndSettleMode: a.SndSettleMode,
		RcvSettleMode: amqp.ReceiverSettleFirst, MaxMessageSize: b.opts.MaxMessageSize}
	if a.Role == amqp.RoleSender {
		if a.Target != nil {
			l.address = a.Target.Address
		}
		reply.Source, reply.Target = a.Source, a.Target
	} else {
		if a.Source != nil {
			l.address = a.Source.Address
		}
		l.settled = a.SndSettleMode == amqp.SenderSettleSettled
		reply.Source, reply.Target = a.Source, a.Target
		reply.InitialDeliveryCount = 0
	}
	refused := a.Role == amqp.RoleSender && a.Target == nil || a.Role == amqp.RoleReceiver && (a.Source == nil || l.address == "") ||
		b.opts.RefuseAddress != nil && b.opts.RefuseAddress(l.address)
	if refused {
		if a.Role == amqp.RoleSender {
			reply.Target = nil
		} else {
			reply.Source = nil
		}
		c.send(s.channel, reply, nil)
		c.send(s.channel, &amqp.Detach{Handle: a.Handle, Closed: true, Error: &amqp.Error{Condition: amqp.CondNotFound, Description: "no node " + l.address}}, nil)
		return true
	}
	l.queue = l.address != "" && b.opts.IsQueue(l.address)
	s.links[a.Handle] = l
	c.send(s.channel, reply, nil)
	if l.role == amqp.RoleReceiver {
		l.credit = b.opts.Credit
		s.sendFlow(l)
		return true
	}
	l.deliveryCount = 0
	if l.queue {
		q := b.queue(l.address)
		q.consumers = append(q.consumers, l)
	} else {
		subs := b.topics[l.address]
		if subs == nil {
			subs = map[*blink]struct{}{}
			b.topics[l.address] = subs
		}
		subs[l] = struct{}{}
	}
	return true
}

func (b *Broker) queue(address string) *queue {
	q := b.queues[address]
	if q == nil {
		q = &queue{}
		b.queues[address] = q
	}
	return q
}

// dropLink forgets a link; the unaccepted messages of a queue consumer go
// back to the queue. b.mu is held.
func (b *Broker) dropLink(l *blink) {
	if l.role != amqp.RoleSender {
		return
	}
	s := l.s
	var back []*stored
	ids := make([]uint32, 0)
	for id, u := range s.unacked {
		if u.l == l {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	for _, id := range ids {
		back = append(back, s.unacked[id].msg)
		delete(s.unacked, id)
	}
	if l.queue {
		q := b.queue(l.address)
		q.consumers = slices.DeleteFunc(q.consumers, func(x *blink) bool { return x == l })
		q.msgs = append(append(back, l.backlog...), q.msgs...)
		l.backlog = nil
		b.dispatch(q)
		return
	}
	if subs := b.topics[l.address]; subs != nil {
		delete(subs, l)
		if len(subs) == 0 {
			delete(b.topics, l.address)
		}
	}
}

func (s *session) sendFlow(l *blink) {
	nii := s.nextIncomingID
	f := &amqp.Flow{NextIncomingID: &nii, IncomingWindow: s.incomingWindow, NextOutgoingID: s.nextOutgoingID, OutgoingWindow: math.MaxUint32}
	if l != nil {
		h, dc, lc := l.handle, l.deliveryCount, l.credit
		f.Handle, f.DeliveryCount, f.LinkCredit = &h, &dc, &lc
	}
	s.c.send(s.channel, f, nil)
}

func (s *session) flow(f *amqp.Flow) {
	if f.NextIncomingID != nil {
		w := int64(int32(*f.NextIncomingID + f.IncomingWindow - s.nextOutgoingID))
		s.remoteIncomingWindow = uint32(max(0, w))
	} else {
		s.remoteIncomingWindow = f.IncomingWindow
	}
	var l *blink
	if f.Handle != nil {
		l = s.links[*f.Handle]
	}
	if l != nil && l.role == amqp.RoleSender && f.LinkCredit != nil {
		dc := uint32(0)
		if f.DeliveryCount != nil {
			dc = *f.DeliveryCount
		}
		l.credit = uint32(max(0, int64(int32(dc+*f.LinkCredit-l.deliveryCount))))
	}
	s.c.b.pumpSession(s)
	if l != nil && l.role == amqp.RoleSender && f.Drain {
		l.deliveryCount += l.credit
		l.credit = 0
		s.sendFlow(l)
	} else if f.Echo {
		s.sendFlow(l)
	}
}

// pumpSession sends what the links of s may send now. b.mu is held.
func (b *Broker) pumpSession(s *session) {
	for _, l := range s.links {
		if l.role != amqp.RoleSender {
			continue
		}
		if l.queue {
			b.dispatch(b.queue(l.address))
		}
		b.pump(l)
	}
}

// dispatch moves the messages of a queue to consumers with credit,
// round-robin. b.mu is held.
func (b *Broker) dispatch(q *queue) {
	for len(q.msgs) > 0 {
		var to *blink
		for range q.consumers {
			q.next = (q.next + 1) % len(q.consumers)
			if cand := q.consumers[q.next]; !cand.s.c.closing && cand.credit > uint32(len(cand.backlog)) {
				to = cand
				break
			}
		}
		if to == nil {
			return
		}
		to.backlog = append(to.backlog, q.msgs[0])
		q.msgs = q.msgs[1:]
		b.pump(to)
	}
}

// pump sends the backlog of a link as its credit and the session window
// allow, splitting messages into frames of the client's size. b.mu is
// held.
func (b *Broker) pump(l *blink) {
	s := l.s
	c := s.c
	for len(l.backlog) > 0 && l.credit > 0 {
		m := l.backlog[0]
		chunk := int(c.maxFrame) - 64 // room for the transfer performative
		frames := uint32((len(m.payload) + chunk - 1) / chunk)
		if s.remoteIncomingWindow < frames {
			return
		}
		l.backlog = l.backlog[1:]
		id := s.nextDeliveryID
		s.nextDeliveryID++
		l.tag++
		tag := []byte(fmt.Sprintf("%d", l.tag))
		format := uint32(0)
		settled := l.settled
		// All frames of the delivery in one write.
		var buf []byte
		for off := 0; off < len(m.payload); off += chunk {
			end := min(off+chunk, len(m.payload))
			t := &amqp.Transfer{Handle: l.handle, More: end < len(m.payload)}
			if off == 0 {
				t.DeliveryID, t.DeliveryTag, t.MessageFormat, t.Settled = &id, tag, &format, &settled
			}
			buf, _ = amqp.AppendFrame(buf, &amqp.Frame{Channel: s.channel, Body: t, Payload: m.payload[off:end]})
			s.nextOutgoingID++
			s.remoteIncomingWindow--
		}
		c.sendRaw(buf)
		l.deliveryCount++
		l.credit--
		if !settled {
			s.unacked[id] = &unacked{l: l, msg: m}
		}
	}
}

func (s *session) transfer(t *amqp.Transfer, payload []byte) bool {
	c, b := s.c, s.c.b
	s.nextIncomingID++
	s.incomingWindow--
	if s.incomingWindow < sessionWindow/2 {
		s.incomingWindow = sessionWindow
		s.sendFlow(nil)
	}
	l := s.links[t.Handle]
	if l == nil || l.role != amqp.RoleReceiver {
		return false
	}
	if !l.inDelivery {
		if t.DeliveryID == nil {
			return false
		}
		l.inDelivery, l.curID, l.partial = true, *t.DeliveryID, nil
		l.curSettled = t.Settled != nil && *t.Settled
	} else if t.Settled != nil && *t.Settled {
		l.curSettled = true
	}
	if t.Aborted {
		l.inDelivery, l.partial = false, nil
		return true
	}
	l.partial = append(l.partial, payload...)
	if len(l.partial) > 64<<20 {
		return false
	}
	if t.More {
		return true
	}
	l.inDelivery = false
	body := l.partial
	l.partial = nil
	l.deliveryCount++
	if l.credit > 0 {
		l.credit--
	}
	if l.credit < b.opts.Credit/2 {
		l.credit = b.opts.Credit
		s.sendFlow(l)
	}
	b.received.Add(1)
	// Read before the message is routed: a consumer can have it before
	// the disposition is decided, and a message received while
	// dispositions are withheld is never settled, also when the
	// withholding ends meanwhile.
	withhold := b.withhold.Load()
	m := &amqp.Message{}
	var state amqp.DeliveryState = &amqp.Accepted{}
	address := l.address
	if err := m.UnmarshalBinary(body); err != nil {
		state = &amqp.Rejected{Error: &amqp.Error{Condition: amqp.CondDecodeError, Description: err.Error()}}
	} else {
		if address == "" && m.Properties != nil {
			address = m.Properties.To // an anonymous sender: the to field
		}
		if b.opts.OnMessage != nil {
			b.opts.OnMessage(address, m, l.curSettled)
		}
		if b.opts.Outcome != nil && !l.curSettled {
			if st := b.opts.Outcome(address, m); st != nil {
				state = st
			}
		}
	}
	if _, ok := state.(*amqp.Accepted); ok {
		b.route(address, &stored{payload: body})
	}
	if !l.curSettled && !withhold {
		c.send(s.channel, &amqp.Disposition{Role: amqp.RoleReceiver, First: l.curID, Settled: true, State: state}, nil)
	}
	return true
}

// route stores a message in its queue or hands it to the subscribers of
// its topic. b.mu is held.
func (b *Broker) route(address string, m *stored) {
	if address == "" {
		return
	}
	if b.opts.IsQueue(address) {
		q := b.queue(address)
		if len(q.msgs) >= b.opts.MaxQueued {
			b.log.Warn("amqpbroker: queue full, dropping message", "address", address)
			return
		}
		q.msgs = append(q.msgs, m)
		b.dispatch(q)
		return
	}
	for l := range b.topics[address] {
		if len(l.backlog) >= b.opts.MaxQueued {
			continue
		}
		l.backlog = append(l.backlog, m)
		b.pump(l)
	}
}

func (s *session) disposition(d *amqp.Disposition) {
	if d.Role != amqp.RoleReceiver {
		return
	}
	last := d.First
	if d.Last != nil {
		last = *d.Last
	}
	b := s.c.b
	for id, u := range s.unacked {
		if id-d.First > last-d.First {
			continue
		}
		switch d.State.(type) {
		case *amqp.Released, *amqp.Modified:
			if u.l.queue {
				q := b.queue(u.l.address)
				q.msgs = append([]*stored{u.msg}, q.msgs...)
				defer b.dispatch(q)
			}
		case nil:
			if !d.Settled {
				continue
			}
		}
		delete(s.unacked, id)
	}
}

func (c *client) cleanup() {
	b := c.b
	c.close()
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.clients, c)
	c.shutdown()
}

// shutdown ends a connection for the broker: nothing more is sent on it,
// its links go away and the unsettled messages of its queue consumers go
// back to their queues. It runs when the connection ends, in the same
// critical section as what ends it (a drop, a close, a frame that fails),
// not later when its goroutines wind down: until then the queue would keep
// dispatching to the dead consumer, and a client that reconnected
// meanwhile would get the messages after it in the queue first, the ones
// sent to the dead link only when they went back (and a subscriber
// discards those older ones by their sequence numbers). b.mu is held.
func (c *client) shutdown() {
	c.closing = true
	for _, s := range c.sessions {
		for h, l := range s.links {
			c.b.dropLink(l)
			delete(s.links, h)
		}
	}
	c.sessions = nil
}
