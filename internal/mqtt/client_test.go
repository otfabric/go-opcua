// SPDX-License-Identifier: MIT

package mqtt_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/internal/testutil/testport"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/mqtt"
	"github.com/otfabric/go-opcua/internal/testutil/mqttbroker"
)

func startBroker(t *testing.T, opts mqttbroker.Options) *mqttbroker.Broker {
	t.Helper()
	b := mqttbroker.New(opts)
	require.NoError(t, b.Start())
	t.Cleanup(b.Close)
	return b
}

func dial(t *testing.T, opts mqtt.Options) *mqtt.Client {
	t.Helper()
	if opts.MinReconnectDelay == 0 {
		opts.MinReconnectDelay = 10 * time.Millisecond
		opts.MaxReconnectDelay = 100 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := mqtt.Dial(ctx, opts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

type inbox struct {
	ch chan *mqtt.Message
}

func newInbox() *inbox { return &inbox{ch: make(chan *mqtt.Message, 1000)} }

func (i *inbox) handle(m *mqtt.Message) { i.ch <- m }

func (i *inbox) next(t *testing.T) *mqtt.Message {
	t.Helper()
	select {
	case m := <-i.ch:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("no message")
		return nil
	}
}

func (i *inbox) none(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case m := <-i.ch:
		t.Fatalf("unexpected message on %s: %q", m.Topic, m.Payload)
	case <-time.After(d):
	}
}

var bg = context.Background()

func TestPublishSubscribe(t *testing.T) {
	b := startBroker(t, mqttbroker.Options{})
	sub := dial(t, mqtt.Options{Server: b.URL(), ClientID: "sub"})
	pub := dial(t, mqtt.Options{Server: b.URL()}) // the broker assigns an id
	require.True(t, pub.IsConnected())

	all, plus, exact := newInbox(), newInbox(), newInbox()
	_, err := sub.Subscribe(bg, "opcua/#", 1, all.handle)
	require.NoError(t, err)
	_, err = sub.Subscribe(bg, "opcua/+/data", 0, plus.handle)
	require.NoError(t, err)
	exactSub, err := sub.Subscribe(bg, "opcua/json/data", 1, exact.handle)
	require.NoError(t, err)

	require.NoError(t, pub.Publish(bg, "opcua/json/data", []byte("q0"), 0, false))
	require.NoError(t, pub.Publish(bg, "opcua/json/data", []byte("q1"), 1, false))
	require.NoError(t, pub.Publish(bg, "opcua/json/meta", []byte("meta"), 2, false)) // downgraded to 1

	for _, in := range []*inbox{all, plus, exact} {
		m := in.next(t)
		require.Equal(t, "q0", string(m.Payload))
		require.Equal(t, byte(0), m.QoS)
		m = in.next(t)
		require.Equal(t, "q1", string(m.Payload))
	}
	m := all.next(t)
	require.Equal(t, "opcua/json/meta", m.Topic)
	require.Equal(t, byte(1), m.QoS)
	require.False(t, m.Retain)
	plus.none(t, 100*time.Millisecond)

	// Unsubscribing one handler leaves the others.
	require.NoError(t, exactSub.Unsubscribe(bg))
	require.NoError(t, exactSub.Unsubscribe(bg))
	require.NoError(t, pub.Publish(bg, "opcua/json/data", []byte("after"), 1, false))
	require.Equal(t, "after", string(all.next(t).Payload))
	require.Equal(t, "after", string(plus.next(t).Payload))
	exact.none(t, 100*time.Millisecond)
}

func TestSameFilterTwoHandlers(t *testing.T) {
	b := startBroker(t, mqttbroker.Options{})
	c := dial(t, mqtt.Options{Server: b.URL(), ClientID: "c"})
	a1, a2 := newInbox(), newInbox()
	s1, err := c.Subscribe(bg, "t", 1, func(m *mqtt.Message) { m.Payload[0] = 'X'; a1.handle(m) })
	require.NoError(t, err)
	_, err = c.Subscribe(bg, "t", 1, a2.handle)
	require.NoError(t, err)
	require.NoError(t, c.Publish(bg, "t", []byte("hi"), 1, false))
	require.Equal(t, "Xi", string(a1.next(t).Payload))
	require.Equal(t, "hi", string(a2.next(t).Payload), "handlers own their payload")
	// Removing one handler keeps the broker subscription.
	require.NoError(t, s1.Unsubscribe(bg))
	require.NoError(t, c.Publish(bg, "t", []byte("2"), 1, false))
	require.Equal(t, "2", string(a2.next(t).Payload))
}

func TestRetained(t *testing.T) {
	b := startBroker(t, mqttbroker.Options{})
	pub := dial(t, mqtt.Options{Server: b.URL(), ClientID: "pub"})
	require.NoError(t, pub.Publish(bg, "meta/1", []byte("v1"), 1, true))
	require.NoError(t, pub.Publish(bg, "meta/1", []byte("v2"), 1, true))
	require.NoError(t, pub.Publish(bg, "meta/2", []byte("w"), 0, true))
	require.Equal(t, []byte("v2"), b.Retained("meta/1"))

	sub := dial(t, mqtt.Options{Server: b.URL(), ClientID: "sub"})
	in := newInbox()
	_, err := sub.Subscribe(bg, "meta/+", 1, in.handle)
	require.NoError(t, err)
	m := in.next(t)
	require.Equal(t, "meta/1", m.Topic)
	require.Equal(t, "v2", string(m.Payload))
	require.True(t, m.Retain)
	require.Equal(t, byte(1), m.QoS)
	m = in.next(t)
	require.Equal(t, "meta/2", m.Topic)
	require.Equal(t, byte(0), m.QoS)

	// Live messages are not flagged as retained.
	require.NoError(t, pub.Publish(bg, "meta/1", []byte("v3"), 1, true))
	m = in.next(t)
	require.False(t, m.Retain)

	// An empty retained message deletes it.
	require.NoError(t, pub.Publish(bg, "meta/1", nil, 1, true))
	require.Nil(t, b.Retained("meta/1"))
	in.next(t)
	sub2 := dial(t, mqtt.Options{Server: b.URL(), ClientID: "sub2"})
	in2 := newInbox()
	_, err = sub2.Subscribe(bg, "meta/1", 1, in2.handle)
	require.NoError(t, err)
	in2.none(t, 100*time.Millisecond)
}

func TestReconnectAfterBrokerRestart(t *testing.T) {
	b := startBroker(t, mqttbroker.Options{})
	var connects, losts atomic.Int32
	sub := dial(t, mqtt.Options{
		Server:           b.URL(),
		ClientID:         "sub",
		OnConnect:        func(bool) { connects.Add(1) },
		OnConnectionLost: func(error) { losts.Add(1) },
	})
	pub := dial(t, mqtt.Options{Server: b.URL(), ClientID: "pub"})
	in := newInbox()
	_, err := sub.Subscribe(bg, "data/#", 1, in.handle)
	require.NoError(t, err)
	require.NoError(t, pub.Publish(bg, "data/x", []byte("before"), 1, false))
	require.Equal(t, "before", string(in.next(t).Payload))

	b.Stop()
	require.Eventually(t, func() bool { return !sub.IsConnected() && !pub.IsConnected() }, 5*time.Second, 5*time.Millisecond)
	require.ErrorIs(t, pub.Publish(bg, "data/x", []byte("lost"), 0, false), mqtt.ErrNotConnected)
	b.Reset() // a broker without persistence: the subscription is gone
	require.NoError(t, b.Start())
	require.Eventually(t, func() bool { return sub.IsConnected() && pub.IsConnected() }, 5*time.Second, 5*time.Millisecond)
	require.Eventually(t, func() bool { return connects.Load() == 2 }, 5*time.Second, time.Millisecond)
	require.Equal(t, int32(1), losts.Load())

	// The client subscribed again: QoS 1 messages arrive. Retry until the
	// resubscription is in place.
	require.Eventually(t, func() bool {
		require.NoError(t, pub.Publish(bg, "data/x", []byte("after"), 1, false))
		select {
		case m := <-in.ch:
			return string(m.Payload) == "after"
		case <-time.After(50 * time.Millisecond):
			return false
		}
	}, 5*time.Second, time.Millisecond)

	// And again after the broker dropped all connections.
	b.DropConnections()
	require.Eventually(t, func() bool { return b.ClientCount() == 2 && sub.IsConnected() }, 5*time.Second, 5*time.Millisecond)
	require.Eventually(t, func() bool {
		require.NoError(t, pub.Publish(bg, "data/y", []byte("again"), 1, false))
		select {
		case m := <-in.ch:
			return string(m.Payload) == "again"
		case <-time.After(50 * time.Millisecond):
			return false
		}
	}, 5*time.Second, time.Millisecond)
}

func TestQoS1RetransmitAfterReconnect(t *testing.T) {
	var dups atomic.Int32
	b := startBroker(t, mqttbroker.Options{
		OnPublish: func(_ string, p *mqtt.Publish) {
			if p.Dup {
				dups.Add(1)
			}
		},
	})
	// A persistent subscriber: the broker keeps its subscription and
	// queues QoS 1 messages while it is away.
	var present atomic.Bool
	sub := dial(t, mqtt.Options{Server: b.URL(), ClientID: "sub", PersistentSession: true,
		OnConnect: func(sp bool) { present.Store(sp) }})
	in := newInbox()
	_, err := sub.Subscribe(bg, "q/#", 1, in.handle)
	require.NoError(t, err)

	// The publisher's connection swallows PUBLISH packets once: the
	// message is never acknowledged and must be sent again (DUP) after
	// the reconnect.
	var swallow atomic.Bool
	swallow.Store(true)
	pub := dial(t, mqtt.Options{Server: b.URL(), ClientID: "pub", Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &dropConn{Conn: c, drop: &swallow}, nil
	}})
	done := make(chan error, 1)
	go func() { done <- pub.Publish(bg, "q/1", []byte("once"), 1, false) }()
	select {
	case err := <-done:
		t.Fatalf("publish returned before the PUBACK: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	swallow.Store(false)
	b.Stop()
	require.NoError(t, b.Start())
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("publish did not complete after the reconnect")
	}
	require.Equal(t, int32(1), dups.Load())
	m := in.next(t)
	require.Equal(t, "once", string(m.Payload))
	require.True(t, present.Load(), "the broker kept the subscriber's session")

	// A QoS 1 publish while disconnected waits for the connection.
	b.Stop()
	require.Eventually(t, func() bool { return !pub.IsConnected() }, 5*time.Second, 5*time.Millisecond)
	go func() { done <- pub.Publish(bg, "q/2", []byte("queued"), 1, false) }()
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, b.Start())
	require.NoError(t, <-done)
	m = in.next(t)
	if string(m.Payload) == "once" {
		// At least once: the broker may resend what it had not seen
		// acknowledged when it stopped.
		require.True(t, m.Duplicate)
		m = in.next(t)
	}
	require.Equal(t, "queued", string(m.Payload))

	// The subscriber was away while a message was published: the broker
	// delivers it on reconnect.
	require.NoError(t, sub.Close())
	// Wait until the broker has handled the subscriber's DISCONNECT, and
	// with it the PUBACK of "queued" written before it: otherwise the
	// session may legitimately get "queued" again on reconnect.
	require.Eventually(t, func() bool { return b.ClientCount() == 1 }, 5*time.Second, time.Millisecond)
	require.NoError(t, pub.Publish(bg, "q/3", []byte("offline"), 1, false))
	in2 := newInbox()
	dial(t, mqtt.Options{Server: b.URL(), ClientID: "sub", PersistentSession: true, DefaultHandler: in2.handle})
	m = in2.next(t)
	require.Equal(t, "offline", string(m.Payload))
	require.Equal(t, "q/3", m.Topic)
}

// dropConn drops the PUBLISH packets written while drop is set.
type dropConn struct {
	net.Conn
	drop *atomic.Bool
}

func (c *dropConn) Write(b []byte) (int, error) {
	if c.drop.Load() && len(b) > 0 && b[0]>>4 == mqtt.TypePublish {
		return len(b), nil
	}
	return c.Conn.Write(b)
}

func TestKeepAliveTimeout(t *testing.T) {
	b := startBroker(t, mqttbroker.Options{})
	lost := make(chan error, 10)
	c := dial(t, mqtt.Options{Server: b.URL(), ClientID: "ka", KeepAlive: time.Second,
		OnConnectionLost: func(err error) { lost <- err }})
	// The pings are answered: no connection loss.
	select {
	case err := <-lost:
		t.Fatalf("lost the connection: %v", err)
	case <-time.After(1500 * time.Millisecond):
	}
	b.SetIgnorePings(true)
	start := time.Now()
	select {
	case err := <-lost:
		t.Logf("connection lost after %v: %v", time.Since(start), err)
		require.Less(t, time.Since(start), 4*time.Second)
	case <-time.After(5 * time.Second):
		t.Fatal("keep-alive timeout not detected")
	}
	b.SetIgnorePings(false)
	require.Eventually(t, c.IsConnected, 5*time.Second, 5*time.Millisecond)
}

func TestTLS(t *testing.T) {
	srv, cli, err := mqttbroker.SelfSignedTLS()
	require.NoError(t, err)
	b := startBroker(t, mqttbroker.Options{TLSConfig: srv})
	require.Contains(t, b.URL(), "mqtts://")
	c := dial(t, mqtt.Options{Server: b.URL(), ClientID: "tls", TLSConfig: cli})
	in := newInbox()
	_, err = c.Subscribe(bg, "s", 1, in.handle)
	require.NoError(t, err)
	require.NoError(t, c.Publish(bg, "s", []byte("secret"), 1, false))
	require.Equal(t, "secret", string(in.next(t).Payload))

	// An untrusted certificate fails (and is retried until ctx ends).
	ctx, cancel := context.WithTimeout(bg, 300*time.Millisecond)
	defer cancel()
	_, err = mqtt.Dial(ctx, mqtt.Options{Server: b.URL(), MinReconnectDelay: 10 * time.Millisecond})
	require.Error(t, err)
}

func TestCredentials(t *testing.T) {
	b := startBroker(t, mqttbroker.Options{Users: map[string]string{"alice": "secret"}})
	dial(t, mqtt.Options{Server: b.URL(), Username: "alice", Password: "secret"})

	var ce *mqtt.ConnectError
	start := time.Now()
	_, err := mqtt.Dial(bg, mqtt.Options{Server: b.URL(), Username: "alice", Password: "wrong"})
	require.ErrorAs(t, err, &ce)
	require.Equal(t, mqtt.ConnRefusedBadCredentials, ce.ReturnCode)
	require.Less(t, time.Since(start), 2*time.Second, "a refusal is not retried")
	_, err = mqtt.Dial(bg, mqtt.Options{Server: b.URL()})
	require.ErrorAs(t, err, &ce)
	require.Equal(t, mqtt.ConnRefusedNotAuthorized, ce.ReturnCode)
}

func TestSubscriptionRefused(t *testing.T) {
	b := startBroker(t, mqttbroker.Options{RefuseFilter: func(f string) bool { return f == "forbidden/#" }})
	c := dial(t, mqtt.Options{Server: b.URL()})
	_, err := c.Subscribe(bg, "forbidden/#", 1, func(*mqtt.Message) {})
	require.ErrorIs(t, err, mqtt.ErrSubscriptionRefused)
	_, err = c.Subscribe(bg, "a+", 1, func(*mqtt.Message) {})
	require.Error(t, err)
	_, err = c.Subscribe(bg, "a", 1, nil)
	require.Error(t, err)
	require.Error(t, c.Publish(bg, "a/+", nil, 0, false))
	require.Error(t, c.Publish(bg, "a", make([]byte, mqtt.MaxRemainingLength), 0, false))
}

func TestDialErrors(t *testing.T) {
	for _, s := range []string{"http://x", "mqtt://", "::", "mqtt://[::1"} {
		_, err := mqtt.Dial(bg, mqtt.Options{Server: s})
		require.Error(t, err, s)
	}
	_, err := mqtt.Dial(bg, mqtt.Options{Server: "mqtt://127.0.0.1:1", PersistentSession: true})
	require.Error(t, err)

	// Nothing listens: retried until the context ends.
	addr := fmt.Sprintf("127.0.0.1:%d", testport.TCP(t))
	ctx, cancel := context.WithTimeout(bg, 200*time.Millisecond)
	defer cancel()
	_, err = mqtt.Dial(ctx, mqtt.Options{Server: "tcp://" + addr, MinReconnectDelay: 10 * time.Millisecond})
	require.Error(t, err)

	// A server that never answers CONNECT.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			defer func() { _ = c.Close() }()
		}
	}()
	ctx, cancel = context.WithTimeout(bg, time.Second)
	defer cancel()
	_, err = mqtt.Dial(ctx, mqtt.Options{Server: "mqtt://" + l.Addr().String(), ConnectTimeout: 100 * time.Millisecond})
	require.Error(t, err)

	// A server that answers with something else than CONNACK.
	l2, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = l2.Close() }()
	go func() {
		c, err := l2.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		b, _ := mqtt.Encode(&mqtt.Simple{Kind: mqtt.TypePingresp})
		_, _ = c.Write(b)
		time.Sleep(time.Second)
	}()
	ctx, cancel = context.WithTimeout(bg, 300*time.Millisecond)
	defer cancel()
	_, err = mqtt.Dial(ctx, mqtt.Options{Server: "mqtt://" + l2.Addr().String()})
	require.Error(t, err)
}

func TestCloseSemantics(t *testing.T) {
	b := startBroker(t, mqttbroker.Options{})
	c := dial(t, mqtt.Options{Server: b.URL(), KeepAlive: -1})
	b.Stop()
	require.Eventually(t, func() bool { return !c.IsConnected() }, 5*time.Second, 5*time.Millisecond)
	// Subscribe while reconnecting registers the subscription.
	sub, err := c.Subscribe(bg, "x", 1, func(*mqtt.Message) {})
	require.NoError(t, err)
	require.NoError(t, sub.Unsubscribe(bg))
	pending := make(chan error, 1)
	go func() { pending <- c.Publish(bg, "x", []byte("p"), 1, false) }()
	time.Sleep(20 * time.Millisecond)
	require.NoError(t, c.Close())
	require.NoError(t, c.Close())
	require.ErrorIs(t, <-pending, mqtt.ErrClosed)
	require.ErrorIs(t, c.Publish(bg, "x", nil, 0, false), mqtt.ErrClosed)
	_, err = c.Subscribe(bg, "x", 0, func(*mqtt.Message) {})
	require.ErrorIs(t, err, mqtt.ErrClosed)
}

func TestContextCancel(t *testing.T) {
	b := startBroker(t, mqttbroker.Options{})
	c := dial(t, mqtt.Options{Server: b.URL()})
	b.Stop()
	require.Eventually(t, func() bool { return !c.IsConnected() }, 5*time.Second, 5*time.Millisecond)
	ctx, cancel := context.WithTimeout(bg, 50*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, c.Publish(ctx, "x", nil, 1, false), context.DeadlineExceeded)
	require.NoError(t, b.Start())
	require.Eventually(t, c.IsConnected, 5*time.Second, 5*time.Millisecond)
	canceled, cancel2 := context.WithCancel(bg)
	cancel2()
	_, err := c.Subscribe(canceled, "y", 1, func(*mqtt.Message) {})
	if err != nil { // the SUBACK may win the race
		require.ErrorIs(t, err, context.Canceled)
	}
}

func TestMaxPacketSize(t *testing.T) {
	b := startBroker(t, mqttbroker.Options{})
	c := dial(t, mqtt.Options{Server: b.URL(), MaxPacketSize: 1000})
	in := newInbox()
	_, err := c.Subscribe(bg, "big", 0, in.handle)
	require.NoError(t, err)
	require.NoError(t, c.Publish(bg, "big", make([]byte, 5000), 1, false))
	require.NoError(t, c.Publish(bg, "big", []byte("small"), 1, false))
	require.Equal(t, "small", string(in.next(t).Payload))
	require.True(t, c.IsConnected())
}

func TestConcurrentUse(t *testing.T) {
	b := startBroker(t, mqttbroker.Options{})
	sub := dial(t, mqtt.Options{Server: b.URL(), ClientID: "sub"})
	pub := dial(t, mqtt.Options{Server: b.URL(), ClientID: "pub"})
	var got atomic.Int64
	_, err := sub.Subscribe(bg, "c/#", 1, func(*mqtt.Message) { got.Add(1) })
	require.NoError(t, err)
	const workers, per = 8, 50
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				topic := fmt.Sprintf("c/%d", w)
				if err := pub.Publish(bg, topic, []byte("m"), byte(i%2), false); err != nil {
					t.Error(err)
					return
				}
				if i%10 == 0 {
					s, err := sub.Subscribe(bg, topic+"/x", 0, func(*mqtt.Message) {})
					if err == nil {
						_ = s.Unsubscribe(bg)
					}
				}
			}
		}()
	}
	wg.Wait()
	require.Eventually(t, func() bool { return got.Load() == workers*per }, 5*time.Second, 5*time.Millisecond)
}

func TestHandlerMayPublish(t *testing.T) {
	b := startBroker(t, mqttbroker.Options{})
	c := dial(t, mqtt.Options{Server: b.URL()})
	in := newInbox()
	_, err := c.Subscribe(bg, "reply", 1, in.handle)
	require.NoError(t, err)
	_, err = c.Subscribe(bg, "request", 1, func(m *mqtt.Message) {
		// QoS 1 from inside a handler does not deadlock: PUBACKs are read
		// by another goroutine.
		if err := c.Publish(bg, "reply", m.Payload, 1, false); err != nil {
			t.Error(err)
		}
	})
	require.NoError(t, err)
	require.NoError(t, c.Publish(bg, "request", []byte("ping"), 1, false))
	require.Equal(t, "ping", string(in.next(t).Payload))
}

func TestQoS2Receive(t *testing.T) {
	// A hand-written broker that sends a QoS 2 message twice.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	result := make(chan []byte, 4)
	go fakeBroker(t, l, func(conn net.Conn, read func() mqtt.Packet, write func(mqtt.Packet)) {
		sub := read().(*mqtt.Subscribe)
		write(&mqtt.Suback{PacketID: sub.PacketID, ReturnCodes: []byte{2}})
		write(&mqtt.Publish{Topic: "t", QoS: 2, PacketID: 5, Payload: []byte("x")})
		write(&mqtt.Publish{Topic: "t", QoS: 2, PacketID: 5, Payload: []byte("x"), Dup: true})
		for i := 0; i < 2; i++ {
			if a, ok := read().(*mqtt.Ack); ok {
				result <- []byte{a.Kind}
			}
		}
		write(&mqtt.Ack{Kind: mqtt.TypePubrel, PacketID: 5})
		if a, ok := read().(*mqtt.Ack); ok {
			result <- []byte{a.Kind}
		}
		// Acks the client does not expect are ignored.
		write(&mqtt.Ack{Kind: mqtt.TypePubcomp, PacketID: 9})
		write(&mqtt.Ack{Kind: mqtt.TypePuback, PacketID: 9})
		write(&mqtt.Suback{PacketID: 77})
		// A CONNACK now is a protocol error: the client drops the connection.
		write(&mqtt.Connack{})
		time.Sleep(100 * time.Millisecond)
	})
	c := dial(t, mqtt.Options{Server: "mqtt://" + l.Addr().String()})
	in := newInbox()
	_, err = c.Subscribe(bg, "t", 2, in.handle)
	require.NoError(t, err)
	m := in.next(t)
	require.Equal(t, byte(2), m.QoS)
	in.none(t, 100*time.Millisecond)
	require.Equal(t, []byte{mqtt.TypePubrec}, <-result)
	require.Equal(t, []byte{mqtt.TypePubrec}, <-result)
	require.Equal(t, []byte{mqtt.TypePubcomp}, <-result)
}

// fakeBroker accepts connections, answers CONNECT and runs script on the
// first connection.
func fakeBroker(t *testing.T, l net.Listener, script func(net.Conn, func() mqtt.Packet, func(mqtt.Packet))) {
	first := true
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn, first bool) {
			defer func() { _ = conn.Close() }()
			r := newPacketReader(conn)
			if _, ok := r().(*mqtt.Connect); !ok {
				return
			}
			write := func(p mqtt.Packet) {
				b, err := mqtt.Encode(p)
				if err == nil {
					_, _ = conn.Write(b)
				}
			}
			write(&mqtt.Connack{})
			if first {
				script(conn, r, write)
				return
			}
			for r() != nil {
			}
		}(conn, first)
		first = false
	}
}

func newPacketReader(conn net.Conn) func() mqtt.Packet {
	br := bufioReader(conn)
	return func() mqtt.Packet {
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		p, err := mqtt.ReadPacket(br, 0)
		if err != nil {
			return nil
		}
		return p
	}
}

func TestErrorsAreDistinct(t *testing.T) {
	require.False(t, errors.Is(mqtt.ErrClosed, mqtt.ErrNotConnected))
}
