// SPDX-License-Identifier: MIT

// Package mqttbroker is a small in-process MQTT 3.1.1 and MQTT 5.0 broker
// for tests.
//
// It routes QoS 0, 1 and 2 messages (with the full PUBREC/PUBREL/PUBCOMP
// flow in both directions), supports + and # wildcards, retained messages,
// clean and persistent sessions (subscriptions and unacknowledged QoS 1 and
// 2 messages survive a disconnect), will messages, session takeover,
// keep-alive enforcement, user name and password checks and TLS.
//
// MQTT 5.0 clients get reason codes (refusals, PUBACK "no matching
// subscribers", SUBACK and UNSUBACK), the CONNACK properties of the options
// (Receive Maximum, Maximum Packet Size, Maximum QoS, Retain Available,
// Wildcard Subscription Available, Server Keep Alive, Assigned Client
// Identifier; Topic Alias Maximum 0, no subscription identifiers, no shared
// subscriptions), the PUBLISH properties of the sender (payload format,
// content type, response topic, correlation data, user properties, the
// message expiry minus the time the message waited), flow control with
// their Receive Maximum, their Maximum Packet Size, the subscription options
// No Local, Retain As Published and Retain Handling, the Session Expiry
// Interval (checked when the client connects again) and a DISCONNECT with a
// reason on session takeover and [Broker.Disconnect]. Enhanced
// authentication, topic aliases and the will delay are not supported.
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
	"strings"
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
	// MaxQueued bounds the QoS 1 and 2 messages kept per session (default
	// 1000).
	MaxQueued int
	// OnConnect, if set, sees every CONNECT (before it is checked).
	OnConnect func(p *mqtt.Connect)
	// OnPublish, if set, sees every PUBLISH a client sends (before routing).
	OnPublish func(clientID string, p *mqtt.Publish)
	// RefuseFilter, if set, makes SUBSCRIBE fail (0x80, with MQTT 5.0 Not
	// authorized) for the filters it returns true for.
	RefuseFilter func(filter string) bool
	// RefusePublish, if set, returns the reason code (0x80 or above) with
	// which a QoS 1 or 2 publication of an MQTT 5.0 client is refused, or 0.
	// A refused publication is not routed.
	RefusePublish func(clientID, topic string) byte
	// DisableV5 makes the broker refuse MQTT 5.0 clients, as a 3.1.1 broker
	// does (CONNACK return code 1).
	DisableV5 bool
	// The CONNACK properties for MQTT 5.0 clients: ReceiveMaximum (0: not
	// sent, 65535) and MaxPacketSize (0: not sent, no limit) are enforced;
	// MaximumQoS (nil: 2), NoRetain, NoWildcard and ServerKeepAlive are
	// announced and enforced. MaximumQoS also caps the QoS granted to 3.1.1
	// subscriptions.
	ReceiveMaximum  uint16
	MaxPacketSize   uint32
	MaximumQoS      *byte
	NoRetain        bool
	NoWildcard      bool
	ServerKeepAlive *uint16
	Logger          *slog.Logger
}

// Broker is an in-process MQTT broker.
type Broker struct {
	opts   Options
	log    *slog.Logger
	maxQoS byte

	mu        sync.Mutex
	ln        net.Listener
	addr      string
	sessions  map[string]*session
	retained  map[string]*retainedMsg
	clients   map[*client]struct{}
	autoID    int
	running   bool
	acceptWG  sync.WaitGroup
	clientsWG sync.WaitGroup

	ignorePings atomic.Bool
	published   atomic.Int64
}

type retainedMsg struct {
	pkt *mqtt.Publish
	at  time.Time
}

type subOpts struct {
	qos     byte
	noLocal bool
	rap     bool // retain as published
}

type session struct {
	id     string
	expiry uint32 // session expiry interval: 0 ends with the connection
	gone   time.Time
	subs   map[string]subOpts
	// qos2 are the QoS 2 packet identifiers received from the client
	// awaiting PUBREL: a resent PUBLISH is not routed again.
	qos2   map[uint16]bool
	client *client
	nextID uint16
	seq    uint64
	// inflight are the QoS 1 and 2 messages sent (or to send) to the
	// client, awaiting PUBACK or PUBCOMP.
	inflight map[uint16]*queued
}

type queued struct {
	seq  uint64
	pkt  *mqtt.Publish // Dup is set once it was sent
	at   time.Time     // when the broker received it (message expiry)
	sent bool          // sent on the current connection: holds a quota slot
	rel  bool          // QoS 2: PUBREC received, PUBREL sent
}

type client struct {
	b       *Broker
	conn    net.Conn
	out     chan []byte
	done    chan struct{}
	once    sync.Once
	sess    *session
	will    *mqtt.Will
	clean   bool // the client sent DISCONNECT without will
	version byte
	quota   int // send quota for the client's Receive Maximum; b.mu
	maxOut  int // the client's Maximum Packet Size, 0: no limit
	noInfo  bool
}

// New returns a stopped broker.
func New(opts Options) *Broker {
	if opts.MaxQueued <= 0 {
		opts.MaxQueued = 1000
	}
	b := &Broker{
		opts:     opts,
		log:      opts.Logger,
		maxQoS:   2,
		sessions: map[string]*session{},
		retained: map[string]*retainedMsg{},
		clients:  map[*client]struct{}{},
	}
	if opts.MaximumQoS != nil {
		b.maxQoS = min(*opts.MaximumQoS, 2)
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
	b.retained = map[string]*retainedMsg{}
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

// Disconnect closes the connection of a client: with a DISCONNECT with
// the reason code and reason string for an MQTT 5.0 client, without a
// goodbye for older ones. It reports whether the client was connected.
func (b *Broker) Disconnect(clientID string, reason byte, reasonString string) bool {
	b.mu.Lock()
	s := b.sessions[clientID]
	var c *client
	if s != nil {
		c = s.client
	}
	b.mu.Unlock()
	if c == nil {
		return false
	}
	c.disconnect(reason, reasonString)
	return true
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
	if r := b.retained[topic]; r != nil {
		return append([]byte(nil), r.pkt.Payload...)
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
		c := &client{b: b, conn: conn, out: make(chan []byte, 1024), done: make(chan struct{})}
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

// disconnect sends an MQTT 5.0 client a DISCONNECT and closes the
// connection.
func (c *client) disconnect(reason byte, reasonString string) {
	if c.version >= mqtt.Version5 {
		d := &mqtt.Disconnect{ReasonCode: reason}
		if reasonString != "" {
			d.Props.ReasonString = &reasonString
		}
		c.writeNow(d)
	}
	c.close()
}

// writeNow writes a packet directly, for the last packet of a connection.
func (c *client) writeNow(p mqtt.Packet) {
	buf, err := mqtt.EncodeVersion(p, c.version)
	if err != nil {
		return
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(time.Second))
	_, _ = c.conn.Write(buf)
}

// send queues a packet; a client that cannot keep up is disconnected.
func (c *client) send(p mqtt.Packet) {
	buf, err := mqtt.EncodeVersion(p, c.version)
	if err != nil {
		c.b.log.Error("mqttbroker: encode", "error", err)
		return
	}
	c.sendBuf(buf)
}

func (c *client) sendBuf(buf []byte) {
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
	p, err := mqtt.ReadPacket(br, int(b.opts.MaxPacketSize))
	if err != nil {
		return
	}
	conn, ok := p.(*mqtt.Connect)
	if !ok {
		return
	}
	if b.opts.OnConnect != nil {
		b.opts.OnConnect(conn)
	}
	keepAlive, ok := c.connect(conn)
	if !ok {
		return
	}
	for {
		if keepAlive > 0 {
			_ = c.conn.SetReadDeadline(time.Now().Add(keepAlive * 3 / 2))
		} else {
			_ = c.conn.SetReadDeadline(time.Time{})
		}
		p, err := mqtt.ReadPacketVersion(br, int(b.opts.MaxPacketSize), c.version)
		switch {
		case errors.Is(err, mqtt.ErrTooLarge):
			c.disconnect(mqtt.ReasonPacketTooLarge, err.Error())
			return
		case errors.Is(err, mqtt.ErrProtocol):
			c.disconnect(mqtt.ReasonMalformedPacket, err.Error())
			return
		case err != nil:
			return
		}
		if !c.handle(p) {
			return
		}
	}
}

func (c *client) connect(p *mqtt.Connect) (time.Duration, bool) {
	b := c.b
	v5 := p.ProtocolName == "MQTT" && p.ProtocolLevel == mqtt.Version5
	refuse := func(code, code5 byte, reason string) (time.Duration, bool) {
		// Written directly: the connection closes right after.
		ack := &mqtt.Connack{ReturnCode: code}
		if v5 && code5 != 0 {
			ack.ReturnCode = code5
			ack.Props.ReasonString = &reason
		}
		c.writeNow(ack)
		return 0, false
	}
	v311 := p.ProtocolName == "MQTT" && p.ProtocolLevel == mqtt.Version311
	v31 := p.ProtocolName == "MQIsdp" && p.ProtocolLevel == mqtt.Version31
	if v5 && b.opts.DisableV5 {
		v5 = false // answered as a 3.1.1 broker would
	}
	if !v311 && !v31 && !v5 {
		return refuse(mqtt.ConnRefusedProtocolVersion, 0, "")
	}
	if v5 {
		c.version = mqtt.Version5
	} else {
		c.version = mqtt.Version311
	}
	if p.Props.AuthMethod != nil {
		return refuse(0, mqtt.ReasonBadAuthenticationMethod, "enhanced authentication is not supported")
	}
	if b.opts.Users != nil {
		if p.Username == nil {
			return refuse(mqtt.ConnRefusedNotAuthorized, mqtt.ReasonNotAuthorized, "a user name is required")
		}
		if pw, ok := b.opts.Users[*p.Username]; !ok || pw != string(p.Password) {
			return refuse(mqtt.ConnRefusedBadCredentials, mqtt.ReasonBadUserNameOrPassword, "wrong user name or password")
		}
	}
	c.noInfo = p.Props.RequestProblemInfo != nil && *p.Props.RequestProblemInfo == 0
	if v := p.Props.MaximumPacketSize; v != nil {
		c.maxOut = int(min(*v, mqtt.MaxRemainingLength+5))
	}
	c.quota = 1 << 20
	if v5 {
		c.quota = 65535
		if v := p.Props.ReceiveMaximum; v != nil {
			c.quota = int(*v)
		}
	}
	// 3.1.1: a clean session ends with the connection, a persistent one
	// never expires. 5.0: the Session Expiry Interval decides.
	expiry := uint32(0)
	if !v5 && !p.CleanSession {
		expiry = 0xffffffff
	}
	if v := p.Props.SessionExpiry; v5 && v != nil {
		expiry = *v
	}
	ack := &mqtt.Connack{}
	b.mu.Lock()
	id := p.ClientID
	if id == "" {
		if !p.CleanSession && !v5 {
			b.mu.Unlock()
			return refuse(mqtt.ConnRefusedIdentifierRejected, 0, "")
		}
		b.autoID++
		id = "auto-" + strconv.Itoa(b.autoID)
		if v5 {
			ack.Props.AssignedClientID = &id
		}
	}
	s := b.sessions[id]
	var old *client
	if s != nil {
		old = s.client
		s.client = nil
	}
	expired := s != nil && old == nil && s.expiry != 0xffffffff &&
		time.Since(s.gone) > time.Duration(s.expiry)*time.Second
	present := s != nil && !p.CleanSession && s.expiry != 0 && !expired
	if !present {
		s = &session{id: id, subs: map[string]subOpts{}, qos2: map[uint16]bool{}, inflight: map[uint16]*queued{}}
		b.sessions[id] = s
	}
	s.expiry = expiry
	s.client = c
	c.sess = s
	c.will = p.Will
	b.mu.Unlock()
	if old != nil {
		old.disconnect(mqtt.ReasonSessionTakenOver, "another connection took over the session") // session takeover
	}
	ack.SessionPresent = present
	if v5 {
		pr := &ack.Props
		if b.opts.ReceiveMaximum > 0 {
			pr.ReceiveMaximum = mqtt.Ptr(b.opts.ReceiveMaximum)
		}
		if b.opts.MaxPacketSize > 0 {
			pr.MaximumPacketSize = mqtt.Ptr(b.opts.MaxPacketSize)
		}
		if b.maxQoS < 2 {
			pr.MaximumQoS = mqtt.Ptr(b.maxQoS)
		}
		if b.opts.NoRetain {
			pr.RetainAvailable = mqtt.Ptr(byte(0))
		}
		if b.opts.NoWildcard {
			pr.WildcardSubAvailable = mqtt.Ptr(byte(0))
		}
		pr.ServerKeepAlive = b.opts.ServerKeepAlive
		pr.SubIDAvailable = mqtt.Ptr(byte(0))
		pr.SharedSubAvailable = mqtt.Ptr(byte(0))
	}
	c.send(ack)
	keepAlive := time.Duration(p.KeepAlive) * time.Second
	if v := b.opts.ServerKeepAlive; v5 && v != nil {
		keepAlive = time.Duration(*v) * time.Second
	}

	// Retransmit what the session had in flight.
	b.mu.Lock()
	var all []*queued
	for _, q := range s.inflight {
		q.sent = false
		all = append(all, q)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].seq < all[j].seq })
	for _, q := range all {
		if c.quota <= 0 {
			break
		}
		c.transmit(q)
	}
	b.mu.Unlock()
	return keepAlive, true
}

// transmit sends an in-flight message (or its PUBREL) and takes a quota
// slot. A message too large for the client is dropped as if it had been
// delivered (MQTT 5.0 §3.1.2.11.4); an expired one is dropped. b.mu is
// held.
func (c *client) transmit(q *queued) {
	s := c.sess
	if q.rel {
		c.quota--
		q.sent = true
		c.send(&mqtt.Ack{Kind: mqtt.TypePubrel, PacketID: q.pkt.PacketID})
		return
	}
	pkt := *q.pkt
	if !pkt.Dup && !expire(&pkt, q.at) {
		delete(s.inflight, pkt.PacketID)
		return
	}
	buf, err := mqtt.EncodeVersion(&pkt, c.version)
	if err != nil || c.maxOut > 0 && len(buf) > c.maxOut {
		delete(s.inflight, pkt.PacketID)
		return
	}
	c.quota--
	q.sent = true
	q.pkt.Dup = true // a resend is a duplicate
	c.sendBuf(buf)
}

// expire lowers the Message Expiry Interval of p by the time since at; false
// if the message has expired (MQTT 5.0 §3.3.2.3.3).
func expire(p *mqtt.Publish, at time.Time) bool {
	e := p.Props.MessageExpiry
	if e == nil {
		return true
	}
	waited := uint32(time.Since(at) / time.Second)
	if waited >= *e {
		return false
	}
	p.Props.MessageExpiry = mqtt.Ptr(*e - waited)
	return true
}

// pump sends queued messages while the client has quota. b.mu is held.
func (c *client) pump() {
	s := c.sess
	if s == nil || s.client != c || c.quota <= 0 {
		return
	}
	var wait []*queued
	for _, q := range s.inflight {
		if !q.sent {
			wait = append(wait, q)
		}
	}
	sort.Slice(wait, func(i, j int) bool { return wait[i].seq < wait[j].seq })
	for _, q := range wait {
		if c.quota <= 0 {
			return
		}
		c.transmit(q)
	}
}

// ack builds an acknowledgement with a reason code (MQTT 5.0).
func (c *client) ack(kind byte, id uint16, reason byte, reasonString string) *mqtt.Ack {
	a := &mqtt.Ack{Kind: kind, PacketID: id, ReasonCode: reason}
	if reasonString != "" && !c.noInfo {
		a.Props.ReasonString = &reasonString
	}
	return a
}

func (c *client) handle(p mqtt.Packet) bool {
	b := c.b
	v5 := c.version >= mqtt.Version5
	switch p := p.(type) {
	case *mqtt.Publish:
		b.published.Add(1)
		if b.opts.OnPublish != nil {
			b.opts.OnPublish(c.sess.id, p)
		}
		if v5 {
			switch {
			case p.Props.TopicAlias != nil:
				c.disconnect(mqtt.ReasonTopicAliasInvalid, "Topic Alias Maximum is 0")
				return false
			case len(p.Props.SubscriptionIDs) > 0:
				c.disconnect(mqtt.ReasonProtocolError, "a client must not send subscription identifiers")
				return false
			case p.Retain && b.opts.NoRetain:
				c.disconnect(mqtt.ReasonRetainNotSupported, "retain is not available")
				return false
			case p.QoS > b.maxQoS:
				c.disconnect(mqtt.ReasonQoSNotSupported, "QoS above the Maximum QoS")
				return false
			}
		}
		refused := byte(0)
		if v5 && p.QoS > 0 && b.opts.RefusePublish != nil {
			refused = b.opts.RefusePublish(c.sess.id, p.Topic)
		}
		switch p.QoS {
		case 0:
			b.route(p, c.sess)
		case 1:
			reason := refused
			if refused == 0 && b.route(p, c.sess) == 0 && v5 {
				reason = mqtt.ReasonNoMatchingSubscribers
			}
			c.send(c.ack(mqtt.TypePuback, p.PacketID, reason, reasonText(refused)))
		case 2:
			reason := refused
			b.mu.Lock()
			s := c.sess
			fresh := !s.qos2[p.PacketID] && refused == 0
			if fresh && v5 && b.opts.ReceiveMaximum > 0 && len(s.qos2) >= int(b.opts.ReceiveMaximum) {
				b.mu.Unlock()
				c.disconnect(mqtt.ReasonReceiveMaximumExceeded, "too many unacknowledged QoS 2 publications")
				return false
			}
			if fresh {
				s.qos2[p.PacketID] = true
			}
			b.mu.Unlock()
			if fresh {
				if b.route(p, c.sess) == 0 && v5 {
					reason = mqtt.ReasonNoMatchingSubscribers
				}
			}
			c.send(c.ack(mqtt.TypePubrec, p.PacketID, reason, reasonText(refused)))
		}
	case *mqtt.Ack:
		switch p.Kind {
		case mqtt.TypePuback:
			b.mu.Lock()
			if q := c.sess.inflight[p.PacketID]; q != nil && q.pkt.QoS == 1 {
				delete(c.sess.inflight, p.PacketID)
				if q.sent {
					c.quota++
					c.pump()
				}
			}
			b.mu.Unlock()
		case mqtt.TypePubrec:
			b.mu.Lock()
			q := c.sess.inflight[p.PacketID]
			switch {
			case q == nil || q.pkt.QoS != 2:
				c.send(c.ack(mqtt.TypePubrel, p.PacketID, mqtt.ReasonPacketIdentifierNotFound, ""))
			case p.ReasonCode >= 0x80:
				delete(c.sess.inflight, p.PacketID)
				if q.sent {
					c.quota++
					c.pump()
				}
			default:
				q.rel = true
				c.send(&mqtt.Ack{Kind: mqtt.TypePubrel, PacketID: p.PacketID})
			}
			b.mu.Unlock()
		case mqtt.TypePubcomp:
			b.mu.Lock()
			if q := c.sess.inflight[p.PacketID]; q != nil && q.rel {
				delete(c.sess.inflight, p.PacketID)
				if q.sent {
					c.quota++
					c.pump()
				}
			}
			b.mu.Unlock()
		case mqtt.TypePubrel:
			reason := byte(0)
			b.mu.Lock()
			if !c.sess.qos2[p.PacketID] {
				reason = mqtt.ReasonPacketIdentifierNotFound
			}
			delete(c.sess.qos2, p.PacketID)
			b.mu.Unlock()
			c.send(c.ack(mqtt.TypePubcomp, p.PacketID, reason, ""))
		default:
			c.disconnect(mqtt.ReasonProtocolError, "unexpected UNSUBACK")
			return false
		}
	case *mqtt.Subscribe:
		if v5 && len(p.Props.SubscriptionIDs) > 0 {
			c.disconnect(mqtt.ReasonSubscriptionIDsNotSupported, "subscription identifiers are not supported")
			return false
		}
		codes := make([]byte, len(p.Topics))
		isNew := make([]bool, len(p.Topics))
		var reason string
		b.mu.Lock()
		for i, s := range p.Topics {
			switch {
			case b.opts.RefuseFilter != nil && b.opts.RefuseFilter(s.Filter):
				codes[i] = mqtt.SubackFailure
				if v5 {
					codes[i], reason = mqtt.ReasonNotAuthorized, "refused by the test"
				}
				continue
			case v5 && b.opts.NoWildcard && strings.ContainsAny(s.Filter, "+#"):
				codes[i], reason = mqtt.ReasonWildcardSubsNotSupported, "wildcard subscriptions are not available"
				continue
			case v5 && s.NoLocal && strings.HasPrefix(s.Filter, "$share/"):
				c.disconnect(mqtt.ReasonProtocolError, "No Local on a shared subscription")
				b.mu.Unlock()
				return false
			}
			codes[i] = min(s.QoS, b.maxQoS)
			_, had := c.sess.subs[s.Filter]
			isNew[i] = !had
			c.sess.subs[s.Filter] = subOpts{qos: codes[i], noLocal: s.NoLocal, rap: s.RetainAsPublished}
		}
		b.mu.Unlock()
		ack := &mqtt.Suback{PacketID: p.PacketID, ReturnCodes: codes}
		if reason != "" && !c.noInfo {
			ack.Props.ReasonString = &reason
		}
		c.send(ack)
		for i, s := range p.Topics {
			if codes[i] >= mqtt.SubackFailure {
				continue
			}
			// Retain Handling (MQTT 5.0 §3.8.3.1); always 0 for 3.1.1.
			if s.RetainHandling == mqtt.RetainDoNotSend || s.RetainHandling == mqtt.RetainSendIfNew && !isNew[i] {
				continue
			}
			b.sendRetained(c, s.Filter, codes[i])
		}
	case *mqtt.Unsubscribe:
		codes := make([]byte, len(p.Filters))
		b.mu.Lock()
		for i, f := range p.Filters {
			if _, ok := c.sess.subs[f]; !ok {
				codes[i] = mqtt.ReasonNoSubscriptionExisted
			}
			delete(c.sess.subs, f)
		}
		b.mu.Unlock()
		a := &mqtt.Ack{Kind: mqtt.TypeUnsuback, PacketID: p.PacketID}
		if v5 {
			a.ReasonCodes = codes
		}
		c.send(a)
	case *mqtt.Simple:
		switch p.Kind {
		case mqtt.TypePingreq:
			if !b.ignorePings.Load() {
				c.send(&mqtt.Simple{Kind: mqtt.TypePingresp})
			}
		default:
			c.disconnect(mqtt.ReasonProtocolError, "unexpected PINGRESP")
			return false
		}
	case *mqtt.Disconnect:
		// Disconnect with Will Message (0x04) publishes the will.
		c.clean = p.ReasonCode != mqtt.ReasonDisconnectWithWill
		if v := p.Props.SessionExpiry; v5 && v != nil {
			b.mu.Lock()
			if c.sess.expiry == 0 && *v != 0 {
				b.mu.Unlock()
				c.disconnect(mqtt.ReasonProtocolError, "session expiry set on DISCONNECT after 0 on CONNECT")
				return false
			}
			c.sess.expiry = *v
			b.mu.Unlock()
		}
		return false
	default:
		// A second CONNECT, AUTH or a server-to-client packet.
		c.disconnect(mqtt.ReasonProtocolError, fmt.Sprintf("unexpected packet type %d", p.Type()))
		return false
	}
	return true
}

func reasonText(code byte) string {
	if code == 0 {
		return ""
	}
	return "refused by the test"
}

func (c *client) cleanup() {
	b := c.b
	c.close()
	b.mu.Lock()
	delete(b.clients, c)
	s := c.sess
	if s != nil && s.client == c {
		s.client = nil
		s.gone = time.Now()
		if s.expiry == 0 {
			delete(b.sessions, s.id)
		}
	}
	will := c.will
	b.mu.Unlock()
	if will != nil && !c.clean && s != nil {
		b.route(&mqtt.Publish{Topic: will.Topic, Payload: will.Payload, QoS: min(will.QoS, b.maxQoS), Retain: will.Retain, Props: will.Props}, nil)
	}
}

// route stores a retained message and forwards a message to the matching
// sessions (not to from, for a No Local subscription). It returns the
// number of sessions it went to.
func (b *Broker) route(p *mqtt.Publish, from *session) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	if p.Retain {
		if len(p.Payload) == 0 {
			delete(b.retained, p.Topic)
		} else {
			r := *p
			r.Payload = append([]byte(nil), p.Payload...)
			r.Dup = false
			b.retained[p.Topic] = &retainedMsg{pkt: &r, at: now}
		}
	}
	n := 0
	for _, s := range b.sessions {
		var opts subOpts
		ok := false
		for f, o := range s.subs {
			if !mqtt.MatchTopic(f, p.Topic) || o.noLocal && s == from {
				continue
			}
			if !ok || o.qos > opts.qos {
				opts.qos = o.qos
			}
			opts.rap = opts.rap || o.rap
			ok = true
		}
		if ok {
			n++
			b.deliver(s, p, min(p.QoS, opts.qos), p.Retain && opts.rap, now)
		}
	}
	return n
}

// forwardProps are the properties of a PUBLISH the broker forwards
// (MQTT 5.0 §3.3.2.3): not the topic alias and subscription identifiers.
func forwardProps(p *mqtt.Properties) mqtt.Properties {
	return mqtt.Properties{
		PayloadFormat:   p.PayloadFormat,
		MessageExpiry:   p.MessageExpiry,
		ContentType:     p.ContentType,
		ResponseTopic:   p.ResponseTopic,
		CorrelationData: append([]byte(nil), p.CorrelationData...),
		User:            append([]mqtt.UserProperty(nil), p.User...),
	}
}

// deliver sends a message to a session. b.mu is held.
func (b *Broker) deliver(s *session, src *mqtt.Publish, qos byte, retain bool, at time.Time) {
	pkt := &mqtt.Publish{Topic: src.Topic, Payload: append([]byte(nil), src.Payload...), QoS: qos, Retain: retain,
		Props: forwardProps(&src.Props)}
	if src.Props.CorrelationData == nil {
		pkt.Props.CorrelationData = nil
	}
	if qos == 0 {
		if c := s.client; c != nil && expire(pkt, at) {
			buf, err := mqtt.EncodeVersion(pkt, c.version)
			if err == nil && (c.maxOut == 0 || len(buf) <= c.maxOut) {
				c.sendBuf(buf)
			}
		}
		return
	}
	if s.client == nil && s.expiry == 0 {
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
	q := &queued{seq: s.seq, pkt: pkt, at: at}
	s.inflight[pkt.PacketID] = q
	if c := s.client; c != nil && c.quota > 0 {
		c.transmit(q)
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
		probe := *r.pkt
		if !expire(&probe, r.at) {
			delete(b.retained, t)
			continue
		}
		if c.sess.client == c {
			b.deliver(c.sess, r.pkt, min(r.pkt.QoS, granted), true, r.at)
		}
	}
}
