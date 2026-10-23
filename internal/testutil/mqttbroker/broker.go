// SPDX-License-Identifier: MIT

// Package mqttbroker is a small in-process MQTT 3.1.1 broker for tests.
//
// It routes QoS 0 and 1 messages (QoS 2 publications are accepted with the
// full PUBREC/PUBREL/PUBCOMP flow and delivered at QoS 1 at most), supports
// + and # wildcards, retained messages, clean and persistent sessions
// (subscriptions and unacknowledged QoS 1 messages survive a disconnect),
// will messages, session takeover, keep-alive enforcement, user name and
// password checks and TLS.
//
// For chaos tests the broker can be stopped and started again on the same
// address (Stop keeps the sessions and retained messages, like a broker with
// persistence; Reset forgets them), drop all connections, and stop
// answering PINGREQ.
package mqttbroker

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/otfabric/go-opcua/internal/mqtt"
)

// Options configure a Broker.
type Options struct {
	// TLSConfig, if set, makes the broker speak TLS (mqtts).
	TLSConfig *tls.Config
	// Users, if set, are the accepted user names and passwords; clients
	// without valid credentials are refused.
	Users map[string]string
	// MaxQueued bounds the QoS 1 messages kept per session (default 1000).
	MaxQueued int
	// OnPublish, if set, sees every PUBLISH a client sends (before routing).
	OnPublish func(clientID string, p *mqtt.Publish)
	// RefuseFilter, if set, makes SUBSCRIBE fail (0x80) for the filters it
	// returns true for.
	RefuseFilter func(filter string) bool
	Logger       *slog.Logger
}

// Broker is an in-process MQTT broker.
type Broker struct {
	opts Options
	log  *slog.Logger

	mu        sync.Mutex
	ln        net.Listener
	addr      string
	sessions  map[string]*session
	retained  map[string]*mqtt.Publish
	clients   map[*client]struct{}
	autoID    int
	running   bool
	acceptWG  sync.WaitGroup
	clientsWG sync.WaitGroup

	ignorePings atomic.Bool
	published   atomic.Int64
}

type session struct {
	id       string
	clean    bool
	subs     map[string]byte
	client   *client
	nextID   uint16
	seq      uint64
	inflight map[uint16]*queued // QoS 1 sent (or to send), awaiting PUBACK
}

type queued struct {
	seq uint64
	pkt *mqtt.Publish
}

type client struct {
	b     *Broker
	conn  net.Conn
	out   chan []byte
	done  chan struct{}
	once  sync.Once
	sess  *session
	will  *mqtt.Will
	qos2  map[uint16]bool
	clean bool // the client sent DISCONNECT
}

// New returns a stopped broker.
func New(opts Options) *Broker {
	if opts.MaxQueued <= 0 {
		opts.MaxQueued = 1000
	}
	b := &Broker{
		opts:     opts,
		log:      opts.Logger,
		sessions: map[string]*session{},
		retained: map[string]*mqtt.Publish{},
		clients:  map[*client]struct{}{},
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
		return errors.New("mqttbroker: already running")
	}
	addr := b.addr
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	var ln net.Listener
	var err error
	// The port of a stopped broker may need a moment to be free again.
	for i := 0; i < 50; i++ {
		if ln, err = net.Listen("tcp", addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		return fmt.Errorf("mqttbroker: listen: %w", err)
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

// URL returns mqtt://addr or mqtts://addr.
func (b *Broker) URL() string {
	if b.opts.TLSConfig != nil {
		return "mqtts://" + b.Addr()
	}
	return "mqtt://" + b.Addr()
}

// Stop closes the listener and all connections. Sessions and retained
// messages are kept for the next Start.
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

// Reset forgets all sessions and retained messages.
func (b *Broker) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for id, s := range b.sessions {
		if s.client == nil {
			delete(b.sessions, id)
		}
	}
	b.retained = map[string]*mqtt.Publish{}
}

// DropConnections closes all client connections without a protocol
// goodbye; the broker keeps listening.
func (b *Broker) DropConnections() {
	b.mu.Lock()
	cs := make([]*client, 0, len(b.clients))
	for c := range b.clients {
		cs = append(cs, c)
	}
	b.mu.Unlock()
	for _, c := range cs {
		c.close()
	}
}

// SetIgnorePings makes the broker stop (or resume) answering PINGREQ.
func (b *Broker) SetIgnorePings(ignore bool) { b.ignorePings.Store(ignore) }

// ClientCount returns the number of connected clients.
func (b *Broker) ClientCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for c := range b.clients {
		if c.sess != nil {
			n++
		}
	}
	return n
}

// Published returns the number of PUBLISH packets the broker received.
func (b *Broker) Published() int64 { return b.published.Load() }

// Retained returns the retained message of a topic, nil if there is none.
func (b *Broker) Retained(topic string) []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	if p := b.retained[topic]; p != nil {
		return append([]byte(nil), p.Payload...)
	}
	return nil
}

func (b *Broker) accept(ln net.Listener) {
	defer b.acceptWG.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		c := &client{b: b, conn: conn, out: make(chan []byte, 1024), done: make(chan struct{}), qos2: map[uint16]bool{}}
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

// send queues a packet; a client that cannot keep up is disconnected.
func (c *client) send(p mqtt.Packet) {
	buf, err := mqtt.Encode(p)
	if err != nil {
		c.b.log.Error("mqttbroker: encode", "error", err)
		return
	}
	select {
	case c.out <- buf:
	case <-c.done:
	default:
		c.b.log.Warn("mqttbroker: slow client disconnected")
		c.close()
	}
}

func (c *client) writeLoop() {
	defer c.b.clientsWG.Done()
	for {
		select {
		case buf := <-c.out:
			_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := c.conn.Write(buf); err != nil {
				c.close()
				return
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
	_ = c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	p, err := mqtt.ReadPacket(br, 0)
	if err != nil {
		return
	}
	conn, ok := p.(*mqtt.Connect)
	if !ok {
		return
	}
	if !c.connect(conn) {
		return
	}
	keepAlive := time.Duration(conn.KeepAlive) * time.Second
	for {
		if keepAlive > 0 {
			_ = c.conn.SetReadDeadline(time.Now().Add(keepAlive * 3 / 2))
		} else {
			_ = c.conn.SetReadDeadline(time.Time{})
		}
		p, err := mqtt.ReadPacket(br, 0)
		if err != nil {
			return
		}
		if !c.handle(p) {
			return
		}
	}
}

func (c *client) connect(p *mqtt.Connect) bool {
	b := c.b
	refuse := func(code byte) bool {
		// Written directly: the connection closes right after.
		buf, _ := mqtt.Encode(&mqtt.Connack{ReturnCode: code})
		_ = c.conn.SetWriteDeadline(time.Now().Add(time.Second))
		_, _ = c.conn.Write(buf)
		return false
	}
	v311 := p.ProtocolName == "MQTT" && p.ProtocolLevel == 4
	v31 := p.ProtocolName == "MQIsdp" && p.ProtocolLevel == 3
	if !v311 && !v31 {
		return refuse(mqtt.ConnRefusedProtocolVersion)
	}
	if b.opts.Users != nil {
		if p.Username == nil {
			return refuse(mqtt.ConnRefusedNotAuthorized)
		}
		if pw, ok := b.opts.Users[*p.Username]; !ok || pw != string(p.Password) {
			return refuse(mqtt.ConnRefusedBadCredentials)
		}
	}
	b.mu.Lock()
	id := p.ClientID
	if id == "" {
		if !p.CleanSession {
			b.mu.Unlock()
			return refuse(mqtt.ConnRefusedIdentifierRejected)
		}
		b.autoID++
		id = "auto-" + strconv.Itoa(b.autoID)
	}
	s := b.sessions[id]
	var old *client
	if s != nil {
		old = s.client
		s.client = nil
	}
	present := s != nil && !p.CleanSession && !s.clean
	if !present {
		s = &session{id: id, subs: map[string]byte{}, inflight: map[uint16]*queued{}}
		b.sessions[id] = s
	}
	s.clean = p.CleanSession
	s.client = c
	c.sess = s
	c.will = p.Will
	var resend []*queued
	for _, q := range s.inflight {
		resend = append(resend, q)
	}
	b.mu.Unlock()
	if old != nil {
		old.close() // session takeover
	}
	c.send(&mqtt.Connack{SessionPresent: present})
	sort.Slice(resend, func(i, j int) bool { return resend[i].seq < resend[j].seq })
	for _, q := range resend {
		pkt := *q.pkt // Dup is set if it was sent before
		c.send(&pkt)
		q.pkt.Dup = true
	}
	return true
}

func (c *client) handle(p mqtt.Packet) bool {
	b := c.b
	switch p := p.(type) {
	case *mqtt.Publish:
		b.published.Add(1)
		if b.opts.OnPublish != nil {
			b.opts.OnPublish(c.sess.id, p)
		}
		switch p.QoS {
		case 0:
			b.route(p)
		case 1:
			b.route(p)
			c.send(&mqtt.Ack{Kind: mqtt.TypePuback, PacketID: p.PacketID})
		case 2:
			if !c.qos2[p.PacketID] {
				c.qos2[p.PacketID] = true
				b.route(p)
			}
			c.send(&mqtt.Ack{Kind: mqtt.TypePubrec, PacketID: p.PacketID})
		}
	case *mqtt.Ack:
		switch p.Kind {
		case mqtt.TypePuback:
			b.mu.Lock()
			delete(c.sess.inflight, p.PacketID)
			b.mu.Unlock()
		case mqtt.TypePubrel:
			delete(c.qos2, p.PacketID)
			c.send(&mqtt.Ack{Kind: mqtt.TypePubcomp, PacketID: p.PacketID})
		case mqtt.TypePubrec, mqtt.TypePubcomp:
			// The broker never sends QoS 2.
		default:
			return false
		}
	case *mqtt.Subscribe:
		codes := make([]byte, len(p.Topics))
		b.mu.Lock()
		for i, s := range p.Topics {
			if b.opts.RefuseFilter != nil && b.opts.RefuseFilter(s.Filter) {
				codes[i] = mqtt.SubackFailure
				continue
			}
			codes[i] = min(s.QoS, 1)
			c.sess.subs[s.Filter] = codes[i]
		}
		b.mu.Unlock()
		c.send(&mqtt.Suback{PacketID: p.PacketID, ReturnCodes: codes})
		for i, s := range p.Topics {
			if codes[i] != mqtt.SubackFailure {
				b.sendRetained(c, s.Filter, codes[i])
			}
		}
	case *mqtt.Unsubscribe:
		b.mu.Lock()
		for _, f := range p.Filters {
			delete(c.sess.subs, f)
		}
		b.mu.Unlock()
		c.send(&mqtt.Ack{Kind: mqtt.TypeUnsuback, PacketID: p.PacketID})
	case *mqtt.Simple:
		switch p.Kind {
		case mqtt.TypePingreq:
			if !b.ignorePings.Load() {
				c.send(&mqtt.Simple{Kind: mqtt.TypePingresp})
			}
		case mqtt.TypeDisconnect:
			c.clean = true
			return false
		default:
			return false
		}
	default:
		return false // a second CONNECT or a server-to-client packet
	}
	return true
}

func (c *client) cleanup() {
	b := c.b
	c.close()
	b.mu.Lock()
	delete(b.clients, c)
	s := c.sess
	if s != nil && s.client == c {
		s.client = nil
		if s.clean {
			delete(b.sessions, s.id)
		}
	}
	will := c.will
	b.mu.Unlock()
	if will != nil && !c.clean && s != nil {
		b.route(&mqtt.Publish{Topic: will.Topic, Payload: will.Payload, QoS: will.QoS, Retain: will.Retain})
	}
}

// route stores a retained message and forwards a message to the matching
// sessions.
func (b *Broker) route(p *mqtt.Publish) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if p.Retain {
		if len(p.Payload) == 0 {
			delete(b.retained, p.Topic)
		} else {
			r := *p
			r.Payload = append([]byte(nil), p.Payload...)
			r.Dup = false
			b.retained[p.Topic] = &r
		}
	}
	for _, s := range b.sessions {
		granted, ok := byte(0), false
		for f, q := range s.subs {
			if mqtt.MatchTopic(f, p.Topic) {
				granted, ok = max(granted, q), true
			}
		}
		if ok {
			b.deliver(s, p.Topic, p.Payload, min(p.QoS, granted), false)
		}
	}
}

// deliver sends a message to a session. b.mu is held.
func (b *Broker) deliver(s *session, topic string, payload []byte, qos byte, retain bool) {
	pkt := &mqtt.Publish{Topic: topic, Payload: append([]byte(nil), payload...), QoS: qos, Retain: retain}
	if qos == 0 {
		if s.client != nil {
			s.client.send(pkt)
		}
		return
	}
	if s.client == nil && s.clean {
		return
	}
	if len(s.inflight) >= b.opts.MaxQueued {
		b.log.Warn("mqttbroker: queue full, dropping message", "client", s.id)
		return
	}
	for {
		s.nextID++
		if s.nextID == 0 {
			s.nextID = 1
		}
		if _, used := s.inflight[s.nextID]; !used {
			break
		}
	}
	pkt.PacketID = s.nextID
	s.seq++
	s.inflight[pkt.PacketID] = &queued{seq: s.seq, pkt: pkt}
	if s.client != nil {
		cp := *pkt
		s.client.send(&cp)
		pkt.Dup = true // a resend is a duplicate
	}
}

func (b *Broker) sendRetained(c *client, filter string, granted byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	topics := make([]string, 0, len(b.retained))
	for t := range b.retained {
		if mqtt.MatchTopic(filter, t) {
			topics = append(topics, t)
		}
	}
	sort.Strings(topics)
	for _, t := range topics {
		r := b.retained[t]
		if c.sess.client == c {
			b.deliver(c.sess, t, r.Payload, min(r.QoS, granted), true)
		}
	}
}
