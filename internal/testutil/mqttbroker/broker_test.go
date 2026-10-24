// SPDX-License-Identifier: MIT

package mqttbroker

import (
	"bufio"
	"crypto/tls"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/mqtt"
)

// raw is a hand-driven protocol client.
type raw struct {
	t    *testing.T
	conn net.Conn
	br   *bufio.Reader
	v    byte // protocol level, 0: 3.1.1
}

func rawDial(t *testing.T, b *Broker) *raw {
	t.Helper()
	conn, err := net.Dial("tcp", b.Addr())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return &raw{t: t, conn: conn, br: bufio.NewReader(conn)}
}

func (r *raw) send(p mqtt.Packet) {
	r.t.Helper()
	b, err := mqtt.EncodeVersion(p, r.level())
	require.NoError(r.t, err)
	_, err = r.conn.Write(b)
	require.NoError(r.t, err)
}

func (r *raw) read() mqtt.Packet {
	r.t.Helper()
	_ = r.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	p, err := mqtt.ReadPacketVersion(r.br, 0, r.level())
	require.NoError(r.t, err)
	return p
}

func (r *raw) level() byte {
	if r.v == 0 {
		return mqtt.Version311
	}
	return r.v
}

// closed reports whether the broker closed the connection.
func (r *raw) closed() bool {
	_ = r.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		p, err := mqtt.ReadPacketVersion(r.br, 0, r.level())
		if err != nil {
			return true
		}
		if _, ok := p.(*mqtt.Disconnect); !ok {
			return false
		}
	}
}

func (r *raw) quiet(d time.Duration) {
	r.t.Helper()
	_ = r.conn.SetReadDeadline(time.Now().Add(d))
	p, err := mqtt.ReadPacketVersion(r.br, 0, r.level())
	require.Error(r.t, err, "unexpected %#v", p)
}

func (r *raw) connect(c *mqtt.Connect) *mqtt.Connack {
	r.t.Helper()
	if c.ProtocolName == "" {
		c.ProtocolName, c.ProtocolLevel = "MQTT", r.level()
	}
	r.send(c)
	ack, ok := r.read().(*mqtt.Connack)
	require.True(r.t, ok)
	return ack
}

func (r *raw) subscribe(id uint16, filter string, qos byte) []byte {
	r.t.Helper()
	r.send(&mqtt.Subscribe{PacketID: id, Topics: []mqtt.TopicFilter{{Filter: filter, QoS: qos}}})
	for {
		p := r.read()
		if s, ok := p.(*mqtt.Suback); ok {
			require.Equal(r.t, id, s.PacketID)
			return s.ReturnCodes
		}
	}
}

func start(t *testing.T, opts Options) *Broker {
	t.Helper()
	b := New(opts)
	require.NoError(t, b.Start())
	t.Cleanup(b.Close)
	return b
}

func TestConnectRefusals(t *testing.T) {
	b := start(t, Options{Users: map[string]string{"u": "p"}})
	require.Error(t, b.Start(), "already running")
	u, bad := "u", "x"
	cases := []struct {
		c    *mqtt.Connect
		code byte
	}{
		{&mqtt.Connect{ProtocolName: "MQTT", ProtocolLevel: 6, CleanSession: true}, mqtt.ConnRefusedProtocolVersion},
		{&mqtt.Connect{ProtocolName: "XX", ProtocolLevel: 4, CleanSession: true}, mqtt.ConnRefusedProtocolVersion},
		{&mqtt.Connect{CleanSession: true}, mqtt.ConnRefusedNotAuthorized},
		{&mqtt.Connect{CleanSession: true, Username: &bad, Password: []byte("p")}, mqtt.ConnRefusedBadCredentials},
		{&mqtt.Connect{CleanSession: true, Username: &u, Password: []byte("x")}, mqtt.ConnRefusedBadCredentials},
		{&mqtt.Connect{Username: &u, Password: []byte("p")}, mqtt.ConnRefusedIdentifierRejected},
		{&mqtt.Connect{ProtocolName: "MQIsdp", ProtocolLevel: 3, ClientID: "old", Username: &u, Password: []byte("p")}, mqtt.ConnAccepted},
	}
	for _, tc := range cases {
		r := rawDial(t, b)
		ack := r.connect(tc.c)
		require.Equal(t, tc.code, ack.ReturnCode, "%+v", tc.c)
		if tc.code != mqtt.ConnAccepted {
			require.True(t, r.closed())
		}
	}

	// The first packet must be CONNECT.
	r := rawDial(t, b)
	r.send(&mqtt.Simple{Kind: mqtt.TypePingreq})
	require.True(t, r.closed())
}

func TestRoutingQoSAndRetain(t *testing.T) {
	b := start(t, Options{})
	sub := rawDial(t, b)
	sub.connect(&mqtt.Connect{ClientID: "sub", CleanSession: true})
	require.Equal(t, []byte{2}, sub.subscribe(1, "a/+", 2))
	require.Equal(t, []byte{0}, sub.subscribe(2, "a/#", 0))

	pub := rawDial(t, b)
	pub.connect(&mqtt.Connect{CleanSession: true})
	require.Equal(t, 2, b.ClientCount())

	// QoS 1 publication: PUBACK, delivered once at the highest granted QoS.
	pub.send(&mqtt.Publish{Topic: "a/b", QoS: 1, PacketID: 10, Payload: []byte("one")})
	require.Equal(t, &mqtt.Ack{Kind: mqtt.TypePuback, PacketID: 10}, pub.read())
	m := sub.read().(*mqtt.Publish)
	require.Equal(t, "one", string(m.Payload))
	require.Equal(t, byte(1), m.QoS)
	sub.send(&mqtt.Ack{Kind: mqtt.TypePuback, PacketID: m.PacketID})

	// QoS 2 publication: PUBREC, PUBREL, PUBCOMP; the duplicate is not
	// routed twice.
	pub.send(&mqtt.Publish{Topic: "a/b/c", QoS: 2, PacketID: 11, Payload: []byte("two")})
	require.Equal(t, &mqtt.Ack{Kind: mqtt.TypePubrec, PacketID: 11}, pub.read())
	pub.send(&mqtt.Publish{Topic: "a/b/c", QoS: 2, PacketID: 11, Payload: []byte("two"), Dup: true})
	require.Equal(t, &mqtt.Ack{Kind: mqtt.TypePubrec, PacketID: 11}, pub.read())
	pub.send(&mqtt.Ack{Kind: mqtt.TypePubrel, PacketID: 11})
	require.Equal(t, &mqtt.Ack{Kind: mqtt.TypePubcomp, PacketID: 11}, pub.read())
	m = sub.read().(*mqtt.Publish)
	require.Equal(t, "two", string(m.Payload))
	require.Equal(t, byte(0), m.QoS, "only a/# (QoS 0) matches")
	sub.quiet(100 * time.Millisecond)
	require.Equal(t, int64(3), b.Published())

	// Retained messages.
	pub.send(&mqtt.Publish{Topic: "r/1", Retain: true, Payload: []byte("keep"), QoS: 1, PacketID: 12})
	pub.read()
	require.Equal(t, []byte("keep"), b.Retained("r/1"))
	require.Equal(t, []byte{1}, sub.subscribe(3, "r/#", 1))
	m = sub.read().(*mqtt.Publish)
	require.True(t, m.Retain)
	sub.send(&mqtt.Ack{Kind: mqtt.TypePuback, PacketID: m.PacketID})
	pub.send(&mqtt.Publish{Topic: "r/1", Retain: true})
	m = sub.read().(*mqtt.Publish)
	require.False(t, m.Retain)
	require.Nil(t, b.Retained("r/1"))

	// Unsubscribe.
	sub.send(&mqtt.Unsubscribe{PacketID: 4, Filters: []string{"a/+", "a/#", "r/#"}})
	require.Equal(t, &mqtt.Ack{Kind: mqtt.TypeUnsuback, PacketID: 4}, sub.read())
	pub.send(&mqtt.Publish{Topic: "a/b", Payload: []byte("gone")})
	sub.quiet(100 * time.Millisecond)

	// Ping and an orderly disconnect.
	sub.send(&mqtt.Simple{Kind: mqtt.TypePingreq})
	require.Equal(t, mqtt.TypePingresp, sub.read().Type())
	sub.send(&mqtt.Simple{Kind: mqtt.TypeDisconnect})
	require.True(t, sub.closed())
	require.Eventually(t, func() bool { return b.ClientCount() == 1 }, 5*time.Second, 5*time.Millisecond)
}

func TestRefuseFilterAndHooks(t *testing.T) {
	var seen []string
	b := start(t, Options{
		RefuseFilter: func(f string) bool { return f == "no" },
		OnPublish:    func(id string, p *mqtt.Publish) { seen = append(seen, id+":"+p.Topic) },
	})
	r := rawDial(t, b)
	r.connect(&mqtt.Connect{ClientID: "c", CleanSession: true})
	r.send(&mqtt.Subscribe{PacketID: 1, Topics: []mqtt.TopicFilter{{Filter: "no"}, {Filter: "yes", QoS: 1}}})
	require.Equal(t, &mqtt.Suback{PacketID: 1, ReturnCodes: []byte{mqtt.SubackFailure, 1}}, r.read())
	r.send(&mqtt.Publish{Topic: "no"})
	r.send(&mqtt.Publish{Topic: "yes"})
	require.Equal(t, "yes", r.read().(*mqtt.Publish).Topic)
	require.Equal(t, []string{"c:no", "c:yes"}, seen)
}

func TestPersistentSessionAndTakeover(t *testing.T) {
	b := start(t, Options{MaxQueued: 2})
	s1 := rawDial(t, b)
	require.False(t, s1.connect(&mqtt.Connect{ClientID: "p"}).SessionPresent)
	s1.subscribe(1, "q", 1)

	pub := rawDial(t, b)
	pub.connect(&mqtt.Connect{ClientID: "pub", CleanSession: true})
	pub.send(&mqtt.Publish{Topic: "q", QoS: 1, PacketID: 1, Payload: []byte("1")})
	pub.read()
	m := s1.read().(*mqtt.Publish)
	require.False(t, m.Dup)
	// No PUBACK: the message stays in flight.

	// Takeover: the second connection with the same id wins.
	s2 := rawDial(t, b)
	require.True(t, s2.connect(&mqtt.Connect{ClientID: "p"}).SessionPresent)
	require.True(t, s1.closed())
	m = s2.read().(*mqtt.Publish)
	require.True(t, m.Dup)
	require.Equal(t, "1", string(m.Payload))
	s2.send(&mqtt.Ack{Kind: mqtt.TypePuback, PacketID: m.PacketID})

	// Offline: QoS 1 is queued (up to MaxQueued), QoS 0 dropped.
	require.NoError(t, s2.conn.Close())
	require.Eventually(t, func() bool { return b.ClientCount() == 1 }, 5*time.Second, 5*time.Millisecond)
	for i, payload := range []string{"a", "b", "c"} {
		pub.send(&mqtt.Publish{Topic: "q", QoS: 1, PacketID: uint16(10 + i), Payload: []byte(payload)})
		pub.read()
	}
	pub.send(&mqtt.Publish{Topic: "q", Payload: []byte("zero")})
	// QoS 0 has no acknowledgement: make sure the broker has handled "zero"
	// (while "p" is offline) before "p" comes back. It handles the packets of
	// a connection in order, so the PUBACK of a later QoS 1 message on an
	// unsubscribed topic proves it.
	pub.send(&mqtt.Publish{Topic: "sync", QoS: 1, PacketID: 20, Payload: []byte("sync")})
	require.Equal(t, uint16(20), pub.read().(*mqtt.Ack).PacketID)
	s3 := rawDial(t, b)
	require.True(t, s3.connect(&mqtt.Connect{ClientID: "p"}).SessionPresent)
	require.Equal(t, "a", string(s3.read().(*mqtt.Publish).Payload))
	require.Equal(t, "b", string(s3.read().(*mqtt.Publish).Payload))
	s3.quiet(100 * time.Millisecond)

	// A clean connection discards the session.
	require.NoError(t, s3.conn.Close())
	s4 := rawDial(t, b)
	require.False(t, s4.connect(&mqtt.Connect{ClientID: "p", CleanSession: true}).SessionPresent)
	s4.quiet(100 * time.Millisecond)
}

func TestWillAndKeepAlive(t *testing.T) {
	b := start(t, Options{})
	watcher := rawDial(t, b)
	watcher.connect(&mqtt.Connect{ClientID: "w", CleanSession: true})
	watcher.subscribe(1, "will/#", 0)

	// Abnormal end: the will is published.
	c := rawDial(t, b)
	c.connect(&mqtt.Connect{ClientID: "c", CleanSession: true, KeepAlive: 1, Will: &mqtt.Will{Topic: "will/c", Payload: []byte("dead")}})
	start := time.Now()
	require.True(t, c.closed(), "keep-alive enforced")
	require.Less(t, time.Since(start), 3*time.Second)
	require.Equal(t, "dead", string(watcher.read().(*mqtt.Publish).Payload))

	// Orderly end: no will.
	d := rawDial(t, b)
	d.connect(&mqtt.Connect{ClientID: "d", CleanSession: true, Will: &mqtt.Will{Topic: "will/d", Payload: []byte("x")}})
	d.send(&mqtt.Simple{Kind: mqtt.TypeDisconnect})
	require.True(t, d.closed())
	watcher.quiet(100 * time.Millisecond)

	// A protocol violation (second CONNECT) closes the connection.
	e := rawDial(t, b)
	e.connect(&mqtt.Connect{ClientID: "e", CleanSession: true})
	e.send(&mqtt.Connect{ProtocolName: "MQTT", ProtocolLevel: 4, ClientID: "e"})
	require.True(t, e.closed())
	f := rawDial(t, b)
	f.connect(&mqtt.Connect{ClientID: "f", CleanSession: true})
	f.send(&mqtt.Ack{Kind: mqtt.TypeUnsuback, PacketID: 1})
	require.True(t, f.closed())
	g := rawDial(t, b)
	g.connect(&mqtt.Connect{ClientID: "g", CleanSession: true})
	g.send(&mqtt.Simple{Kind: mqtt.TypePingresp})
	require.True(t, g.closed())
}

func TestIgnorePingsAndChaos(t *testing.T) {
	b := start(t, Options{})
	r := rawDial(t, b)
	r.connect(&mqtt.Connect{ClientID: "c", CleanSession: true})
	b.SetIgnorePings(true)
	r.send(&mqtt.Simple{Kind: mqtt.TypePingreq})
	r.quiet(100 * time.Millisecond)
	b.SetIgnorePings(false)
	r.send(&mqtt.Simple{Kind: mqtt.TypePingreq})
	require.Equal(t, mqtt.TypePingresp, r.read().Type())

	b.DropConnections()
	require.True(t, r.closed())

	// Stop keeps state, the address stays the same.
	addr := b.Addr()
	r2 := rawDial(t, b)
	r2.connect(&mqtt.Connect{ClientID: "keep"})
	r2.subscribe(1, "x", 1)
	r2.send(&mqtt.Publish{Topic: "ret", Retain: true, Payload: []byte("v")})
	require.Eventually(t, func() bool { return b.Retained("ret") != nil }, 5*time.Second, 5*time.Millisecond)
	require.NoError(t, b.Restart())
	require.Equal(t, addr, b.Addr())
	require.True(t, r2.closed())
	r3 := rawDial(t, b)
	require.True(t, r3.connect(&mqtt.Connect{ClientID: "keep"}).SessionPresent)
	require.Equal(t, []byte("v"), b.Retained("ret"))

	// Reset forgets offline sessions and retained messages.
	require.NoError(t, r3.conn.Close())
	require.Eventually(t, func() bool { return b.ClientCount() == 0 }, 5*time.Second, 5*time.Millisecond)
	b.Reset()
	require.Nil(t, b.Retained("ret"))
	r4 := rawDial(t, b)
	require.False(t, r4.connect(&mqtt.Connect{ClientID: "keep"}).SessionPresent)

	b.Stop()
	b.Stop()
	_, err := net.DialTimeout("tcp", addr, time.Second)
	require.Error(t, err)
}

func TestTLSBroker(t *testing.T) {
	srv, cli, err := SelfSignedTLS()
	require.NoError(t, err)
	b := start(t, Options{TLSConfig: srv})
	require.Equal(t, "mqtts://"+b.Addr(), b.URL())
	conn, err := tls.Dial("tcp", b.Addr(), cli)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	r := &raw{t: t, conn: conn, br: bufio.NewReader(conn)}
	require.Equal(t, mqtt.ConnAccepted, r.connect(&mqtt.Connect{CleanSession: true}).ReturnCode)
}

func TestSlowClient(t *testing.T) {
	b := start(t, Options{})
	slow := rawDial(t, b)
	slow.connect(&mqtt.Connect{ClientID: "slow", CleanSession: true})
	slow.subscribe(1, "flood", 0)
	pub := rawDial(t, b)
	pub.connect(&mqtt.Connect{ClientID: "pub", CleanSession: true})
	payload := make([]byte, 64<<10)
	// The slow client never reads: its queue overflows and it is dropped.
	go func() {
		for i := 0; i < 4000; i++ {
			b, _ := mqtt.Encode(&mqtt.Publish{Topic: "flood", Payload: payload})
			if _, err := pub.conn.Write(b); err != nil {
				return
			}
		}
	}()
	require.Eventually(t, func() bool { return b.ClientCount() == 1 }, 20*time.Second, 10*time.Millisecond)
	require.Equal(t, "mqtt://"+b.Addr(), b.URL())
}

// TestResumedSessionKeepsOrder: a client that resumes its session gets the
// QoS 1 messages queued for it before the ones published while it connects
// (MQTT 3.1.1 §4.6).
func TestResumedSessionKeepsOrder(t *testing.T) {
	for range 10 {
		b := start(t, Options{MaxQueued: 1000})
		sub := rawDial(t, b)
		sub.connect(&mqtt.Connect{ClientID: "s"})
		sub.subscribe(1, "q", 1)
		require.NoError(t, sub.conn.Close())
		require.Eventually(t, func() bool { return b.ClientCount() == 0 }, 5*time.Second, time.Millisecond)

		pub := rawDial(t, b)
		pub.connect(&mqtt.Connect{ClientID: "pub", CleanSession: true})
		n := 0
		publish := func() {
			n++
			pub.send(&mqtt.Publish{Topic: "q", QoS: 1, PacketID: uint16(n), Payload: []byte(strconv.Itoa(n))})
			pub.read()
		}
		for range 200 {
			publish() // queued for the offline session
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			for range 200 {
				publish() // routed while the session resumes
			}
		}()
		s := rawDial(t, b)
		require.True(t, s.connect(&mqtt.Connect{ClientID: "s"}).SessionPresent)
		<-done
		for want := 1; want <= 400; want++ {
			m, ok := s.read().(*mqtt.Publish)
			require.True(t, ok)
			got, _ := strconv.Atoi(string(m.Payload))
			require.Equal(t, want, got, "messages out of order")
			s.send(&mqtt.Ack{Kind: mqtt.TypePuback, PacketID: m.PacketID})
		}
		b.Close()
	}
}
