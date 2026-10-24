// SPDX-License-Identifier: MIT

package mqtt_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/mqtt"
	"github.com/otfabric/go-opcua/internal/testutil/mqttbroker"
)

func dial5(t *testing.T, opts mqtt.Options) *mqtt.Client {
	t.Helper()
	opts.ProtocolVersion = mqtt.Version5
	return dial(t, opts)
}

func TestV5PublishSubscribeProperties(t *testing.T) {
	b := startBroker(t, mqttbroker.Options{})
	sub := dial5(t, mqtt.Options{Server: b.URL(), ClientID: "sub"})
	old := dial(t, mqtt.Options{Server: b.URL(), ClientID: "old"})
	pub := dial5(t, mqtt.Options{Server: b.URL(), UserProperties: []mqtt.UserProperty{{Key: "app", Value: "test"}}})
	require.Equal(t, mqtt.Version5, pub.ProtocolVersion())
	require.Equal(t, mqtt.Version311, old.ProtocolVersion())
	sp := pub.ServerProperties()
	require.NotNil(t, sp.AssignedClientID, "the broker assigned the empty client identifier")

	in, in2, in3 := newInbox(), newInbox(), newInbox()
	_, err := sub.Subscribe(bg, "p/#", 2, in.handle)
	require.NoError(t, err)
	_, err = sub.Subscribe(bg, "p/+", 1, in2.handle)
	require.NoError(t, err)
	_, err = old.Subscribe(bg, "p/#", 1, in3.handle)
	require.NoError(t, err)

	props := mqtt.Properties{
		PayloadFormat:   mqtt.Ptr(byte(1)),
		MessageExpiry:   mqtt.Ptr(uint32(600)),
		ContentType:     mqtt.Ptr("application/json"),
		ResponseTopic:   mqtt.Ptr("p/reply"),
		CorrelationData: []byte("id-1"),
		User:            []mqtt.UserProperty{{Key: "UAMessageType", Value: "ua-data"}, {Key: "x", Value: "1"}},
	}
	for _, qos := range []byte{0, 1, 2} {
		require.NoError(t, pub.PublishWith(bg, "p/data", []byte(`{"q":1}`), mqtt.PublishOptions{QoS: qos, Props: props}))
		m := in.next(t)
		require.Equal(t, qos, m.QoS)
		require.Equal(t, "application/json", *m.Props.ContentType)
		require.Equal(t, props.User, m.Props.User)
		require.Equal(t, "p/reply", *m.Props.ResponseTopic)
		require.Equal(t, []byte("id-1"), m.Props.CorrelationData)
		require.Equal(t, byte(1), *m.Props.PayloadFormat)
		require.LessOrEqual(t, *m.Props.MessageExpiry, uint32(600))
		// The second handler gets its own copy.
		m2 := in2.next(t)
		m2.Props.User[0].Value = "changed"
		m2.Props.CorrelationData[0] = 'X'
		require.Equal(t, "ua-data", m.Props.User[0].Value)
		require.Equal(t, byte('i'), m.Props.CorrelationData[0])
		// 3.1.1 subscribers get the message without properties.
		m3 := in3.next(t)
		require.Equal(t, `{"q":1}`, string(m3.Payload))
		require.Equal(t, mqtt.Properties{}, m3.Props)
	}

	// Properties a client must not send.
	require.Error(t, pub.PublishWith(bg, "p/x", nil, mqtt.PublishOptions{Props: mqtt.Properties{TopicAlias: mqtt.Ptr(uint16(1))}}))
	require.Error(t, pub.PublishWith(bg, "p/x", nil, mqtt.PublishOptions{Props: mqtt.Properties{SessionExpiry: mqtt.Ptr(uint32(1))}}))
	require.Error(t, pub.PublishWith(bg, "p/x", nil, mqtt.PublishOptions{QoS: 3}))
	// Over 3.1.1 the properties are dropped.
	require.NoError(t, old.PublishWith(bg, "p/y", []byte("v3"), mqtt.PublishOptions{QoS: 1, Props: props}))
	m := in.next(t)
	require.Equal(t, "v3", string(m.Payload))
	require.Nil(t, m.Props.ContentType)
}

func TestV5QoS2ExactlyOnce(t *testing.T) {
	for _, v := range []byte{mqtt.Version311, mqtt.Version5} {
		t.Run(map[byte]string{4: "3.1.1", 5: "5.0"}[v], func(t *testing.T) {
			var pubrels atomic.Int32
			b := startBroker(t, mqttbroker.Options{})
			sub := dial(t, mqtt.Options{Server: b.URL(), ClientID: "sub", ProtocolVersion: v, PersistentSession: true})
			in := newInbox()
			_, err := sub.Subscribe(bg, "eo", 2, in.handle)
			require.NoError(t, err)

			// The connection drops PUBREL once: the publication waits, and
			// after the reconnect (the broker kept the session) the client
			// sends the PUBREL again instead of the message.
			var swallow atomic.Bool
			pub := dial(t, mqtt.Options{Server: b.URL(), ClientID: "pub", ProtocolVersion: v, PersistentSession: true,
				Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
					c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
					if err != nil {
						return nil, err
					}
					return &typeDropConn{Conn: c, kind: mqtt.TypePubrel, drop: &swallow, seen: &pubrels}, nil
				}})
			require.NoError(t, pub.Publish(bg, "eo", []byte("one"), 2, false))
			m := in.next(t)
			require.Equal(t, byte(2), m.QoS)
			require.Equal(t, "one", string(m.Payload))

			swallow.Store(true)
			done := make(chan error, 1)
			go func() { done <- pub.Publish(bg, "eo", []byte("two"), 2, false) }()
			require.Eventually(t, func() bool { return pubrels.Load() >= 2 }, 5*time.Second, time.Millisecond)
			swallow.Store(false)
			b.DropConnections()
			select {
			case err := <-done:
				require.NoError(t, err)
			case <-time.After(10 * time.Second):
				t.Fatal("QoS 2 publication not completed after the reconnect")
			}
			require.Equal(t, "two", string(in.next(t).Payload))
			in.none(t, 100*time.Millisecond)
		})
	}
}

// typeDropConn drops the packets of one type written while drop is set
// and counts the packets of that type.
type typeDropConn struct {
	net.Conn
	kind byte
	drop *atomic.Bool
	seen *atomic.Int32
}

func (c *typeDropConn) Write(b []byte) (int, error) {
	if len(b) > 0 && b[0]>>4 == c.kind {
		c.seen.Add(1)
		if c.drop.Load() {
			return len(b), nil
		}
	}
	return c.Conn.Write(b)
}

func TestV5QoS2RetransmitPublish(t *testing.T) {
	var dups atomic.Int32
	b := startBroker(t, mqttbroker.Options{OnPublish: func(_ string, p *mqtt.Publish) {
		if p.Dup {
			dups.Add(1)
		}
	}})
	sub := dial5(t, mqtt.Options{Server: b.URL(), ClientID: "sub", PersistentSession: true})
	in := newInbox()
	_, err := sub.Subscribe(bg, "r", 2, in.handle)
	require.NoError(t, err)
	var swallow atomic.Bool
	var seen atomic.Int32
	swallow.Store(true)
	pub := dial5(t, mqtt.Options{Server: b.URL(), ClientID: "pub", PersistentSession: true, SessionExpiry: 60,
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return &typeDropConn{Conn: c, kind: mqtt.TypePublish, drop: &swallow, seen: &seen}, nil
		}})
	done := make(chan error, 1)
	go func() { done <- pub.Publish(bg, "r", []byte("again"), 2, false) }()
	require.Eventually(t, func() bool { return seen.Load() == 1 }, 5*time.Second, time.Millisecond)
	swallow.Store(false)
	b.DropConnections()
	require.NoError(t, <-done)
	require.Equal(t, int32(1), dups.Load())
	require.Equal(t, "again", string(in.next(t).Payload))
}

func TestV5BestAvailable(t *testing.T) {
	b := startBroker(t, mqttbroker.Options{DisableV5: true})
	c := dial(t, mqtt.Options{Server: b.URL(), ProtocolVersion: mqtt.VersionBestAvailable})
	require.Equal(t, mqtt.Version311, c.ProtocolVersion())
	// It stays on 3.1.1 after a reconnect.
	b.DropConnections()
	require.Eventually(t, func() bool { return b.ClientCount() == 1 && c.IsConnected() }, 5*time.Second, time.Millisecond)
	require.Equal(t, mqtt.Version311, c.ProtocolVersion())

	b5 := startBroker(t, mqttbroker.Options{})
	c5 := dial(t, mqtt.Options{Server: b5.URL(), ProtocolVersion: mqtt.VersionBestAvailable})
	require.Equal(t, mqtt.Version5, c5.ProtocolVersion())

	// Version5 alone does not fall back.
	_, err := mqtt.Dial(bg, mqtt.Options{Server: b.URL(), ProtocolVersion: mqtt.Version5})
	var ce *mqtt.ConnectError
	require.ErrorAs(t, err, &ce)
	require.Equal(t, mqtt.ConnRefusedProtocolVersion, ce.ReturnCode)
	_, err = mqtt.Dial(bg, mqtt.Options{Server: b.URL(), ProtocolVersion: 7})
	require.Error(t, err)
}

func TestV5ConnectRefused(t *testing.T) {
	b := startBroker(t, mqttbroker.Options{Users: map[string]string{"alice": "secret"}})
	start := time.Now()
	_, err := mqtt.Dial(bg, mqtt.Options{Server: b.URL(), ProtocolVersion: mqtt.Version5, Username: "alice", Password: "wrong"})
	var ce *mqtt.ConnectError
	require.ErrorAs(t, err, &ce)
	require.Equal(t, mqtt.ReasonBadUserNameOrPassword, ce.ReturnCode)
	require.Equal(t, mqtt.Version5, ce.Version)
	require.NotEmpty(t, ce.ReasonString)
	require.Contains(t, err.Error(), "bad user name or password")
	require.Less(t, time.Since(start), 2*time.Second, "a refusal is not retried")

	for code, fatal := range map[byte]bool{
		mqtt.ReasonServerBusy: false, mqtt.ReasonServerUnavailable: false, mqtt.ReasonQuotaExceeded: false,
		mqtt.ReasonNotAuthorized: true, mqtt.ReasonBanned: true, mqtt.ReasonUseAnotherServer: true,
	} {
		e := &mqtt.ConnectError{ReturnCode: code, Version: mqtt.Version5, ReasonString: "r", ServerReference: "s"}
		require.Contains(t, e.Error(), "server reference s")
		require.Equal(t, fatal, mqtt.ConnectErrorFatal(e), "%#x", code)
	}
}

func TestV5BrokerLimits(t *testing.T) {
	b := startBroker(t, mqttbroker.Options{MaxPacketSize: 300, MaximumQoS: mqtt.Ptr(byte(1)), NoRetain: true, NoWildcard: true})
	c := dial5(t, mqtt.Options{Server: b.URL(), ClientID: "c", PersistentSession: true})
	in := newInbox()
	_, err := c.Subscribe(bg, "lim", 2, in.handle)
	require.NoError(t, err)

	// Maximum QoS 1: QoS 2 is downgraded.
	require.NoError(t, c.Publish(bg, "lim", []byte("q2"), 2, false))
	require.Equal(t, byte(1), in.next(t).QoS)
	// Retain Available 0.
	require.ErrorIs(t, c.Publish(bg, "lim", []byte("r"), 1, true), mqtt.ErrNotSupported)
	// Maximum Packet Size: not sent, the connection stays.
	require.ErrorIs(t, c.Publish(bg, "lim", make([]byte, 400), 0, false), mqtt.ErrNotSupported)
	require.ErrorIs(t, c.Publish(bg, "lim", make([]byte, 400), 1, false), mqtt.ErrNotSupported)
	require.True(t, c.IsConnected())
	require.NoError(t, c.Publish(bg, "lim", []byte("small"), 1, false))
	require.Equal(t, "small", string(in.next(t).Payload))
	// Wildcard Subscription Available 0.
	_, err = c.Subscribe(bg, "lim/#", 1, in.handle)
	require.ErrorIs(t, err, mqtt.ErrNotSupported)

	// Queued while disconnected: downgraded or refused on the next connection.
	b.Stop()
	require.Eventually(t, func() bool { return !c.IsConnected() }, 5*time.Second, time.Millisecond)
	q2 := make(chan error, 1)
	ret := make(chan error, 1)
	go func() { q2 <- c.Publish(bg, "lim", []byte("queued"), 2, false) }()
	go func() { ret <- c.Publish(bg, "lim", []byte("queued"), 1, true) }()
	require.Eventually(t, func() bool { return mqtt.InflightCount(c) == 2 }, 5*time.Second, time.Millisecond)
	require.NoError(t, b.Start())
	require.NoError(t, <-q2)
	require.ErrorIs(t, <-ret, mqtt.ErrNotSupported)
	m := in.next(t)
	for string(m.Payload) != "queued" {
		// At least once: the broker may resend what it had not seen
		// acknowledged when it stopped.
		require.True(t, m.Duplicate)
		m = in.next(t)
	}
	require.Equal(t, byte(1), m.QoS)
}

func TestV5MaximumQoS0Queued(t *testing.T) {
	seen := make(chan *mqtt.Publish, 10)
	b := startBroker(t, mqttbroker.Options{MaximumQoS: mqtt.Ptr(byte(0)), OnPublish: func(_ string, p *mqtt.Publish) { seen <- p }})
	c := dial5(t, mqtt.Options{Server: b.URL(), ClientID: "c"})
	require.NoError(t, c.Publish(bg, "z", []byte("now"), 1, false)) // sent at QoS 0
	require.Equal(t, byte(0), (<-seen).QoS)
	b.Stop()
	require.Eventually(t, func() bool { return !c.IsConnected() }, 5*time.Second, time.Millisecond)
	done := make(chan error, 1)
	go func() { done <- c.Publish(bg, "z", []byte("later"), 1, false) }()
	require.Eventually(t, func() bool { return mqtt.InflightCount(c) == 1 }, 5*time.Second, time.Millisecond)
	require.NoError(t, b.Start())
	require.NoError(t, <-done)
	p := <-seen
	require.Equal(t, "later", string(p.Payload))
	require.Equal(t, byte(0), p.QoS)
}

func TestV5ReasonErrors(t *testing.T) {
	b := startBroker(t, mqttbroker.Options{
		RefuseFilter:  func(f string) bool { return f == "secret" },
		RefusePublish: func(_, topic string) byte { return map[string]byte{"deny": mqtt.ReasonNotAuthorized}[topic] },
	})
	c := dial5(t, mqtt.Options{Server: b.URL()})
	var re *mqtt.ReasonError
	err := c.Publish(bg, "deny", []byte("x"), 1, false)
	require.ErrorIs(t, err, mqtt.ErrPublishRefused)
	require.ErrorAs(t, err, &re)
	require.Equal(t, mqtt.ReasonNotAuthorized, re.ReasonCode)
	require.Equal(t, "deny", re.Topic)
	require.Contains(t, err.Error(), "not authorized")
	err = c.Publish(bg, "deny", []byte("x"), 2, false)
	require.ErrorIs(t, err, mqtt.ErrPublishRefused)
	// "No matching subscribers" is a success.
	require.NoError(t, c.Publish(bg, "nobody", []byte("x"), 1, false))
	require.NoError(t, c.Publish(bg, "nobody", []byte("x"), 2, false))

	_, err = c.Subscribe(bg, "secret", 1, func(*mqtt.Message) {})
	require.ErrorIs(t, err, mqtt.ErrSubscriptionRefused)
	require.ErrorAs(t, err, &re)
	require.Equal(t, mqtt.ReasonNotAuthorized, re.ReasonCode)
	require.NotEmpty(t, re.ReasonString)
}

func TestV5SubscribeOptions(t *testing.T) {
	b := startBroker(t, mqttbroker.Options{})
	c := dial5(t, mqtt.Options{Server: b.URL(), ClientID: "c"})
	in := newInbox()
	_, err := c.SubscribeWith(bg, "own", mqtt.SubscribeOptions{QoS: 1, NoLocal: true,
		UserProperties: []mqtt.UserProperty{{Key: "k", Value: "v"}}}, in.handle)
	require.NoError(t, err)
	_, err = c.SubscribeWith(bg, "kept", mqtt.SubscribeOptions{QoS: 1, RetainAsPublished: true}, in.handle)
	require.NoError(t, err)
	require.NoError(t, c.Publish(bg, "own", []byte("mine"), 1, false))
	require.NoError(t, c.Publish(bg, "kept", []byte("r"), 1, true))
	m := in.next(t)
	require.Equal(t, "r", string(m.Payload), "No Local")
	require.True(t, m.Retain, "Retain As Published")

	none := newInbox()
	_, err = c.SubscribeWith(bg, "kept", mqtt.SubscribeOptions{QoS: 1, RetainHandling: mqtt.RetainDoNotSend}, none.handle)
	require.NoError(t, err)
	none.none(t, 100*time.Millisecond)
	_, err = c.SubscribeWith(bg, "x", mqtt.SubscribeOptions{RetainHandling: 3}, none.handle)
	require.Error(t, err)
	_, err = c.SubscribeWith(bg, "x", mqtt.SubscribeOptions{UserProperties: []mqtt.UserProperty{{Key: "\x00"}}}, none.handle)
	require.Error(t, err)

	// The options survive a reconnect without session.
	b.DropConnections()
	require.Eventually(t, func() bool { return b.ClientCount() == 1 && c.IsConnected() }, 5*time.Second, time.Millisecond)
	require.Eventually(t, func() bool {
		require.NoError(t, c.Publish(bg, "own", []byte("mine"), 1, false))
		require.NoError(t, c.Publish(bg, "kept", []byte("live"), 1, false))
		select {
		case m := <-in.ch:
			return string(m.Payload) == "live"
		case <-time.After(50 * time.Millisecond):
			return false
		}
	}, 5*time.Second, time.Millisecond)
	for {
		select {
		case m := <-in.ch:
			require.NotEqual(t, "mine", string(m.Payload))
			continue
		case <-time.After(100 * time.Millisecond):
		}
		break
	}

	// Over 3.1.1 the options are dropped.
	old := dial(t, mqtt.Options{Server: b.URL(), ClientID: "old"})
	in3 := newInbox()
	_, err = old.SubscribeWith(bg, "own3", mqtt.SubscribeOptions{QoS: 1, NoLocal: true}, in3.handle)
	require.NoError(t, err)
	require.NoError(t, old.Publish(bg, "own3", []byte("back"), 1, false))
	require.Equal(t, "back", string(in3.next(t).Payload))
}

func TestV5ServerDisconnect(t *testing.T) {
	b := startBroker(t, mqttbroker.Options{})
	lost := make(chan error, 10)
	c := dial5(t, mqtt.Options{Server: b.URL(), ClientID: "c", OnConnectionLost: func(err error) { lost <- err }})
	require.True(t, b.Disconnect("c", mqtt.ReasonAdministrativeAction, "kicked"))
	var err error
	select {
	case err = <-lost:
	case <-time.After(5 * time.Second):
		t.Fatal("no connection loss")
	}
	var de *mqtt.DisconnectError
	require.ErrorAs(t, err, &de)
	require.Equal(t, mqtt.ReasonAdministrativeAction, de.ReasonCode)
	require.Equal(t, "kicked", de.ReasonString)
	require.Contains(t, err.Error(), "administrative action")
	require.Contains(t, (&mqtt.DisconnectError{ReasonCode: 0x9c, ServerReference: "b2"}).Error(), "b2")
	require.Eventually(t, c.IsConnected, 5*time.Second, time.Millisecond, "reconnects")
}

// TestV5SessionTakeover: a second client with the same ClientID takes the
// session over; the first one learns why. The first client does not
// reconnect, or it would take the session back while the second dials.
func TestV5SessionTakeover(t *testing.T) {
	b := startBroker(t, mqttbroker.Options{})
	lost := make(chan error, 10)
	dial5(t, mqtt.Options{Server: b.URL(), ClientID: "c", MinReconnectDelay: time.Hour, MaxReconnectDelay: time.Hour,
		OnConnectionLost: func(err error) { lost <- err }})
	dial5(t, mqtt.Options{Server: b.URL(), ClientID: "c", MinReconnectDelay: time.Hour, MaxReconnectDelay: time.Hour})
	var err error
	var de *mqtt.DisconnectError
	select {
	case err = <-lost:
		require.ErrorAs(t, err, &de)
		require.Equal(t, mqtt.ReasonSessionTakenOver, de.ReasonCode)
	case <-time.After(5 * time.Second):
		t.Fatal("no connection loss")
	}
}

// TestV5NoReconnectAfterTakeover: a client whose session was taken over
// waits its backoff before it reconnects instead of taking the session back
// at once.
func TestV5NoReconnectAfterTakeover(t *testing.T) {
	var connects atomic.Int32
	b := startBroker(t, mqttbroker.Options{OnConnect: func(p *mqtt.Connect) {
		if p.ClientID == "c" {
			connects.Add(1)
		}
	}})
	lost := make(chan error, 10)
	dial5(t, mqtt.Options{Server: b.URL(), ClientID: "c", MinReconnectDelay: time.Hour, MaxReconnectDelay: time.Hour,
		OnConnectionLost: func(err error) { lost <- err }})
	second := dial5(t, mqtt.Options{Server: b.URL(), ClientID: "c", MinReconnectDelay: time.Hour, MaxReconnectDelay: time.Hour})
	select {
	case <-lost:
	case <-time.After(5 * time.Second):
		t.Fatal("no connection loss")
	}
	time.Sleep(300 * time.Millisecond) // time for a reconnect that should not come
	require.Equal(t, int32(2), connects.Load(), "the first client connected again")
	require.True(t, second.IsConnected())
}

func TestV5ServerKeepAliveAndSession(t *testing.T) {
	one := uint16(1)
	b := startBroker(t, mqttbroker.Options{ServerKeepAlive: &one})
	lost := make(chan error, 10)
	var present atomic.Bool
	c := dial5(t, mqtt.Options{Server: b.URL(), ClientID: "ka", KeepAlive: time.Hour, PersistentSession: true,
		OnConnect: func(sp bool) { present.Store(sp) }, OnConnectionLost: func(err error) { lost <- err }})
	b.SetIgnorePings(true)
	select {
	case err := <-lost: // the broker's 1 s keep-alive applies, not the hour asked for
		require.Error(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("keep-alive timeout not detected")
	}
	b.SetIgnorePings(false)
	require.Eventually(t, func() bool { return c.IsConnected() && present.Load() }, 5*time.Second, time.Millisecond, "the session never expires")
}

func TestV5ReceiveMaximum(t *testing.T) {
	// The broker allows two unacknowledged publications.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	got := make(chan *mqtt.Publish, 10)
	release := make(chan uint16, 10)
	go fakeBroker5(t, l, &mqtt.Connack{Props: mqtt.Properties{ReceiveMaximum: mqtt.Ptr(uint16(2))}},
		func(read func() mqtt.Packet, write func(mqtt.Packet)) {
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				for id := range release {
					write(&mqtt.Ack{Kind: mqtt.TypePuback, PacketID: id})
				}
			}()
			for {
				p := read()
				if p == nil {
					close(release)
					wg.Wait()
					return
				}
				if pub, ok := p.(*mqtt.Publish); ok {
					got <- pub
				}
			}
		})
	c := dial5(t, mqtt.Options{Server: "mqtt://" + l.Addr().String()})
	done := make(chan error, 3)
	for i := 0; i < 3; i++ {
		go func() { done <- c.Publish(bg, "t", []byte{byte(i)}, 1, false) }()
	}
	p1, p2 := <-got, <-got
	select {
	case p := <-got:
		t.Fatalf("a third publication beyond the Receive Maximum: %v", p.PacketID)
	case <-time.After(150 * time.Millisecond):
	}
	release <- p1.PacketID
	p3 := <-got
	require.False(t, p3.Dup)
	release <- p2.PacketID
	release <- p3.PacketID
	for i := 0; i < 3; i++ {
		require.NoError(t, <-done)
	}
}

func TestV5ClientEnforcesLimits(t *testing.T) {
	cases := []struct {
		name   string
		script func(write func(mqtt.Packet))
		reason byte
	}{
		{"receive maximum", func(write func(mqtt.Packet)) {
			for i := 1; i <= 3; i++ {
				write(&mqtt.Publish{Topic: "t", QoS: 2, PacketID: uint16(i)})
			}
		}, mqtt.ReasonReceiveMaximumExceeded},
		{"topic alias", func(write func(mqtt.Packet)) {
			write(&mqtt.Publish{Topic: "t", Props: mqtt.Properties{TopicAlias: mqtt.Ptr(uint16(1))}})
		}, mqtt.ReasonTopicAliasInvalid},
		{"too large", func(write func(mqtt.Packet)) {
			write(&mqtt.Publish{Topic: "t", Payload: make([]byte, 2000)})
		}, mqtt.ReasonPacketTooLarge},
		{"auth", func(write func(mqtt.Packet)) {
			write(&mqtt.Auth{ReasonCode: mqtt.ReasonReAuthenticate})
		}, mqtt.ReasonProtocolError},
		{"connack", func(write func(mqtt.Packet)) {
			write(&mqtt.Connack{})
		}, mqtt.ReasonProtocolError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer func() { _ = l.Close() }()
			reason := make(chan byte, 1)
			go fakeBroker5(t, l, &mqtt.Connack{}, func(read func() mqtt.Packet, write func(mqtt.Packet)) {
				tc.script(write)
				for {
					p := read()
					if p == nil {
						return
					}
					if d, ok := p.(*mqtt.Disconnect); ok {
						reason <- d.ReasonCode
						return
					}
				}
			})
			dial5(t, mqtt.Options{Server: "mqtt://" + l.Addr().String(), ReceiveMaximum: 2, MaxPacketSize: 1000})
			select {
			case r := <-reason:
				require.Equal(t, tc.reason, r)
			case <-time.After(5 * time.Second):
				t.Fatal("no DISCONNECT")
			}
		})
	}

	// A malformed packet: DISCONNECT Malformed Packet.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	reason := make(chan byte, 1)
	go fakeBroker5(t, l, &mqtt.Connack{}, func(read func() mqtt.Packet, write func(mqtt.Packet)) {
		write(rawPacket{0x40, 4, 0, 1, 0, 9}) // PUBACK with a property length beyond the packet
		for {
			p := read()
			if p == nil {
				return
			}
			if d, ok := p.(*mqtt.Disconnect); ok {
				reason <- d.ReasonCode
				return
			}
		}
	})
	dial5(t, mqtt.Options{Server: "mqtt://" + l.Addr().String()})
	require.Equal(t, mqtt.ReasonMalformedPacket, <-reason)
}

// rawPacket is written as is by fakeBroker5.
type rawPacket []byte

func (rawPacket) Type() byte { return 0 }

func TestV5UnknownIdentifiers(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	acks := make(chan *mqtt.Ack, 10)
	unsub := make(chan struct{})
	go fakeBroker5(t, l, &mqtt.Connack{}, func(read func() mqtt.Packet, write func(mqtt.Packet)) {
		write(&mqtt.Ack{Kind: mqtt.TypePubrec, PacketID: 40})
		write(&mqtt.Ack{Kind: mqtt.TypePubrec, PacketID: 41, ReasonCode: mqtt.ReasonUnspecifiedError})
		write(&mqtt.Ack{Kind: mqtt.TypePubrel, PacketID: 42})
		write(&mqtt.Ack{Kind: mqtt.TypePubcomp, PacketID: 43})
		write(&mqtt.Ack{Kind: mqtt.TypePuback, PacketID: 44, ReasonCode: mqtt.ReasonUnspecifiedError})
		for {
			switch p := read().(type) {
			case nil:
				return
			case *mqtt.Ack:
				acks <- p
			case *mqtt.Subscribe:
				write(&mqtt.Suback{PacketID: p.PacketID, ReturnCodes: []byte{1}})
			case *mqtt.Unsubscribe:
				<-unsub
				write(&mqtt.Ack{Kind: mqtt.TypeUnsuback, PacketID: p.PacketID, ReasonCodes: []byte{mqtt.ReasonNotAuthorized},
					Props: mqtt.Properties{ReasonString: mqtt.Ptr("no")}})
			}
		}
	})
	c := dial5(t, mqtt.Options{Server: "mqtt://" + l.Addr().String()})
	a := <-acks
	require.Equal(t, mqtt.TypePubrel, a.Kind)
	require.Equal(t, mqtt.ReasonPacketIdentifierNotFound, a.ReasonCode)
	a = <-acks
	require.Equal(t, mqtt.TypePubcomp, a.Kind)
	require.Equal(t, mqtt.ReasonPacketIdentifierNotFound, a.ReasonCode)

	s, err := c.Subscribe(bg, "u", 1, func(*mqtt.Message) {})
	require.NoError(t, err)
	close(unsub)
	err = s.Unsubscribe(bg)
	require.ErrorIs(t, err, mqtt.ErrUnsubscribeRefused)
	var re *mqtt.ReasonError
	require.ErrorAs(t, err, &re)
	require.Equal(t, "no", re.ReasonString)
	require.True(t, c.IsConnected())
}

func TestV5AbandonedPublicationCompletes(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	pubs := make(chan *mqtt.Publish, 10)
	ack := make(chan uint16, 1)
	go fakeBroker5(t, l, &mqtt.Connack{Props: mqtt.Properties{ReceiveMaximum: mqtt.Ptr(uint16(1))}},
		func(read func() mqtt.Packet, write func(mqtt.Packet)) {
			go func() {
				for id := range ack {
					write(&mqtt.Ack{Kind: mqtt.TypePuback, PacketID: id})
				}
			}()
			for {
				p := read()
				if p == nil {
					close(ack)
					return
				}
				if pub, ok := p.(*mqtt.Publish); ok {
					pubs <- pub
				}
			}
		})
	c := dial5(t, mqtt.Options{Server: "mqtt://" + l.Addr().String()})
	ctx, cancel := context.WithCancel(bg)
	done := make(chan error, 1)
	go func() { done <- c.Publish(ctx, "t", []byte("first"), 1, false) }()
	p := <-pubs
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
	// The written publication keeps its quota slot until the broker
	// acknowledges it.
	done2 := make(chan error, 1)
	go func() { done2 <- c.Publish(bg, "t", []byte("second"), 1, false) }()
	select {
	case p := <-pubs:
		t.Fatalf("sent beyond the Receive Maximum: %q", p.Payload)
	case <-time.After(100 * time.Millisecond):
	}
	ack <- p.PacketID
	p2 := <-pubs
	require.Equal(t, "second", string(p2.Payload))
	ack <- p2.PacketID
	require.NoError(t, <-done2)
	require.Equal(t, 0, mqtt.InflightCount(c))
}

func TestV5OptionsValidation(t *testing.T) {
	for _, o := range []mqtt.Options{
		{Server: "mqtt://127.0.0.1:1", UserProperties: []mqtt.UserProperty{{Key: "\x00"}}},
		{Server: "mqtt://127.0.0.1:1", Will: &mqtt.Will{Topic: "a/#"}},
		{Server: "mqtt://127.0.0.1:1", Will: &mqtt.Will{Topic: "w", Props: mqtt.Properties{TopicAlias: mqtt.Ptr(uint16(1))}}},
	} {
		_, err := mqtt.Dial(bg, o)
		require.Error(t, err)
	}

	// Will properties and the connect options.
	b := startBroker(t, mqttbroker.Options{})
	w := dial5(t, mqtt.Options{Server: b.URL(), ClientID: "w"})
	in := newInbox()
	_, err := w.Subscribe(bg, "will", 1, in.handle)
	require.NoError(t, err)
	no := false
	c := dial5(t, mqtt.Options{Server: b.URL(), ClientID: "dies", RequestResponseInformation: true, RequestProblemInformation: &no,
		ReceiveMaximum: 5, Will: &mqtt.Will{Topic: "will", Payload: []byte("gone"), QoS: 1,
			Props: mqtt.Properties{ContentType: mqtt.Ptr("text/plain"), WillDelay: mqtt.Ptr(uint32(0))}}})
	require.True(t, c.IsConnected())
	b.Disconnect("dies", mqtt.ReasonAdministrativeAction, "")
	m := in.next(t)
	require.Equal(t, "gone", string(m.Payload))
	require.Equal(t, "text/plain", *m.Props.ContentType)
}

// fakeBroker5 accepts MQTT 5.0 connections, answers CONNECT with connack
// and runs script on the first connection.
func fakeBroker5(t *testing.T, l net.Listener, connack *mqtt.Connack, script func(read func() mqtt.Packet, write func(mqtt.Packet))) {
	first := true
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn, first bool) {
			defer func() { _ = conn.Close() }()
			br := bufioReader(conn)
			read := func() mqtt.Packet {
				_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				p, err := mqtt.ReadPacketVersion(br, 0, mqtt.Version5)
				if err != nil {
					return nil
				}
				return p
			}
			var wmu sync.Mutex
			write := func(p mqtt.Packet) {
				wmu.Lock()
				defer wmu.Unlock()
				if r, ok := p.(rawPacket); ok {
					_, _ = conn.Write(r)
					return
				}
				b, err := mqtt.EncodeVersion(p, mqtt.Version5)
				if err == nil {
					_, _ = conn.Write(b)
				}
			}
			if _, ok := read().(*mqtt.Connect); !ok {
				return
			}
			write(connack)
			if first {
				script(read, write)
				return
			}
			for read() != nil {
			}
		}(conn, first)
		first = false
	}
}

func TestV5ErrorsAreDistinct(t *testing.T) {
	require.False(t, errors.Is(mqtt.ErrPublishRefused, mqtt.ErrSubscriptionRefused))
}
