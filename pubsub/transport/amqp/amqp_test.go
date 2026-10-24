// SPDX-License-Identifier: MIT

package amqp

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	iamqp "github.com/otfabric/go-opcua/internal/amqp"
	"github.com/otfabric/go-opcua/internal/testutil/amqpbroker"
	"github.com/otfabric/go-opcua/pubsub/transport"
)

var bg = context.Background()

func startBroker(t *testing.T, opts amqpbroker.Options) *amqpbroker.Broker {
	t.Helper()
	b := amqpbroker.New(opts)
	require.NoError(t, b.Start())
	t.Cleanup(b.Close)
	return b
}

func open(t *testing.T, cfg transport.Config) *Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(bg, 10*time.Second)
	defer cancel()
	c, err := Open(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

type inbox chan *transport.Message

func (in inbox) handle(m *transport.Message) { in <- m }

func (in inbox) next(t *testing.T) *transport.Message {
	t.Helper()
	select {
	case m := <-in:
		return m
	case <-time.After(10 * time.Second):
		t.Fatal("no message")
		return nil
	}
}

// recorder keeps the messages the broker received.
type recorder struct {
	mu   sync.Mutex
	msgs []*iamqp.Message
	sets []bool
}

func (r *recorder) on(_ string, m *iamqp.Message, settled bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.msgs = append(r.msgs, m)
	r.sets = append(r.sets, settled)
}

func (r *recorder) last(t *testing.T) (*iamqp.Message, bool) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	require.NotEmpty(t, r.msgs)
	return r.msgs[len(r.msgs)-1], r.sets[len(r.sets)-1]
}

func TestSendSubscribe(t *testing.T) {
	rec := &recorder{}
	b := startBroker(t, amqpbroker.Options{OnMessage: rec.on})
	require.Contains(t, transport.Schemes(), "amqp")
	require.Contains(t, transport.Schemes(), "amqps")

	sub := open(t, transport.Config{URL: b.URL(), ProfileURI: transport.ProfileAMQPJSON})
	tc, err := transport.Open(bg, transport.Config{URL: b.URL(), ProfileURI: transport.ProfileAMQPJSON})
	require.NoError(t, err)
	defer func() { _ = tc.Close() }()
	pub := tc.(*Conn)
	require.Equal(t, DefaultMaxMessageSize, pub.MaxMessageSize())
	require.True(t, sub.Connected())

	in := make(inbox, 100)
	cancel, err := sub.Subscribe(bg, "/exchanges/amq.topic/data", 1, in.handle)
	require.NoError(t, err)

	for _, qos := range []byte{0, 1, 2} {
		require.NoError(t, pub.Send(bg, []byte{'m', '0' + qos}, transport.PublishOptions{Topic: "/exchanges/amq.topic/data", QoS: qos}))
		m := in.next(t)
		require.Equal(t, "/exchanges/amq.topic/data", m.Topic)
		require.Equal(t, []byte{'m', '0' + qos}, m.Payload)
		require.WithinDuration(t, time.Now(), m.Received, 10*time.Second)
		am, settled := rec.last(t)
		require.Equal(t, qos == 0, settled)
		require.Equal(t, SubjectData, am.Properties.Subject)
		require.Equal(t, iamqp.Symbol(ContentTypeJSON), am.Properties.ContentType)
		require.IsType(t, iamqp.UUID{}, am.Properties.MessageID)
		require.Equal(t, qos > 0, am.Header != nil && am.Header.Durable)
	}
	// Message ids are unique.
	rec.mu.Lock()
	require.NotEqual(t, rec.msgs[0].Properties.MessageID, rec.msgs[1].Properties.MessageID)
	rec.mu.Unlock()

	// Metadata, an explicit content type and the properties of Table B.2.
	require.NoError(t, pub.Send(bg, []byte("meta"), transport.PublishOptions{
		Topic: "/exchanges/amq.topic/data", QoS: 1, Retain: true, MessageType: transport.MessageTypeMetaData, ContentType: ContentTypeUADP,
		Properties: map[string]any{
			"message-to": "dest", "message-reply-to": "back", "message-correlation-id": "corr",
			"message-group-id": "g", "message-reply-to-group-id": "rg", "message-content-encoding": "gzip",
			"message-user-id": "user", "message-absolute-expiry-time": float64(60000), "message-creation-time": true,
			"site": "plant", "line": 3, "ratio": 0.5, "odd": []int{1},
		},
	}))
	require.Equal(t, []byte("meta"), in.next(t).Payload)
	am, _ := rec.last(t)
	p := am.Properties
	require.Equal(t, SubjectMetaData, p.Subject)
	require.Equal(t, iamqp.Symbol(ContentTypeUADP), p.ContentType)
	require.Equal(t, "dest", p.To)
	require.Equal(t, "back", p.ReplyTo)
	require.Equal(t, "corr", p.CorrelationID)
	require.Equal(t, "g", p.GroupID)
	require.Equal(t, "rg", p.ReplyToGroupID)
	require.Equal(t, iamqp.Symbol("gzip"), p.ContentEncoding)
	require.Equal(t, []byte("user"), p.UserID)
	require.WithinDuration(t, time.Now().Add(time.Minute), p.AbsoluteExpiryTime, 10*time.Second)
	require.WithinDuration(t, time.Now(), p.CreationTime, 10*time.Second)
	require.Equal(t, map[string]any{"site": "plant", "line": int64(3), "ratio": 0.5, "odd": "[1]"}, am.ApplicationProperties)

	require.NoError(t, cancel())
	require.NoError(t, pub.Send(bg, []byte("x"), transport.PublishOptions{Topic: "/exchanges/amq.topic/data", QoS: 1}))
	select {
	case m := <-in:
		t.Fatalf("message after unsubscribe: %q", m.Payload)
	default:
	}
}

func TestSendErrors(t *testing.T) {
	b := startBroker(t, amqpbroker.Options{RefuseAddress: func(a string) bool { return a == "forbidden" }})
	c := open(t, transport.Config{URL: b.URL(), MaxMessageSize: 10})
	require.Equal(t, 10, c.MaxMessageSize())
	require.ErrorContains(t, c.Send(bg, []byte("x"), transport.PublishOptions{}), "needs a topic")
	require.ErrorIs(t, c.Send(bg, make([]byte, 11), transport.PublishOptions{Topic: "a"}), transport.ErrMessageTooLarge)
	var le *iamqp.LinkError
	require.ErrorAs(t, c.Send(bg, []byte("x"), transport.PublishOptions{Topic: "forbidden", QoS: 1}), &le)
	_, err := c.Subscribe(bg, "", 0, func(*transport.Message) {})
	require.ErrorContains(t, err, "needs a topic")
	_, err = c.Subscribe(bg, "a", 0, nil)
	require.ErrorContains(t, err, "nil handler")
	_, err = c.Subscribe(bg, "forbidden", 0, func(*transport.Message) {})
	require.ErrorAs(t, err, &le)

	require.NoError(t, c.Close())
	require.NoError(t, c.Close())
	require.ErrorIs(t, c.Send(bg, []byte("x"), transport.PublishOptions{Topic: "a"}), transport.ErrClosed)
	_, err = c.Subscribe(bg, "a", 0, func(*transport.Message) {})
	require.ErrorIs(t, err, transport.ErrClosed)
}

func TestReceiveLimits(t *testing.T) {
	b := startBroker(t, amqpbroker.Options{})
	sub := open(t, transport.Config{URL: b.URL(), MaxMessageSize: 4})
	pub := open(t, transport.Config{URL: b.URL()})
	in := make(inbox, 10)
	_, err := sub.Subscribe(bg, "/queues/q", 0, in.handle)
	require.NoError(t, err)
	// Too large for the subscriber, then a message without bytes (sent
	// with the client directly), then one that fits.
	require.NoError(t, pub.Send(bg, []byte("too large"), transport.PublishOptions{Topic: "/queues/q", QoS: 1}))
	require.NoError(t, pub.client.Send(bg, "/queues/q", &iamqp.Message{Value: int32(1), HasValue: true}, false))
	require.NoError(t, pub.Send(bg, []byte("ok"), transport.PublishOptions{Topic: "/queues/q", QoS: 1}))
	require.Equal(t, []byte("ok"), in.next(t).Payload)
}

func TestReconnect(t *testing.T) {
	b := startBroker(t, amqpbroker.Options{})
	sub := open(t, transport.Config{URL: b.URL()})
	pub := open(t, transport.Config{URL: b.URL()})
	in := make(inbox, 100)
	_, err := sub.Subscribe(bg, "/queues/r", 1, in.handle)
	require.NoError(t, err)
	b.DropConnections()
	// At least once waits for the connection and arrives (perhaps twice).
	require.NoError(t, pub.Send(bg, []byte("after"), transport.PublishOptions{Topic: "/queues/r", QoS: 1}))
	require.Equal(t, []byte("after"), in.next(t).Payload)
	require.Eventually(t, func() bool { return sub.Connected() && pub.Connected() }, 10*time.Second, 5*time.Millisecond)
	// At most once fails while reconnecting, or is sent.
	b.Stop()
	require.Eventually(t, func() bool { return !pub.Connected() }, 10*time.Second, 5*time.Millisecond)
	require.ErrorIs(t, pub.Send(bg, []byte("lost"), transport.PublishOptions{Topic: "/queues/r"}), ErrNotConnected)
	require.NoError(t, b.Restart())
	require.Eventually(t, func() bool { return sub.Connected() && pub.Connected() }, 10*time.Second, 5*time.Millisecond)
}

func TestOptions(t *testing.T) {
	opts, err := options(transport.Config{URL: "amqp://h", KeepAlive: time.Second, Properties: map[string]string{
		"container-id": "cid", "username": "u", "password": "p", "sasl-mechanism": "plain",
		"connection-hostname": "vhost:x", "connection-max-frame-size": "4096", "link-max-message-size": "1000",
		"credit": "7", "source-capabilities": "queue, topic", "target-capabilities": "topic",
		"connection-product": "test", "session-s": "1", "link-l": "2", "connection-": "dropped", "other": "x",
	}})
	require.NoError(t, err)
	require.Equal(t, "cid", opts.ContainerID)
	require.Equal(t, "u", opts.Username)
	require.Equal(t, "p", opts.Password)
	require.Equal(t, "PLAIN", opts.SASLMechanism)
	require.Equal(t, "vhost:x", opts.Hostname)
	require.Equal(t, uint32(4096), opts.MaxFrameSize)
	require.Equal(t, 1000, opts.MaxMessageSize)
	require.Equal(t, uint32(7), opts.Credit)
	require.Equal(t, time.Second, opts.IdleTimeout)
	require.Equal(t, []iamqp.Symbol{"queue", "topic"}, opts.SourceCapabilities)
	require.Equal(t, []iamqp.Symbol{"topic"}, opts.TargetCapabilities)
	require.Equal(t, iamqp.Map{{Key: iamqp.Symbol("product"), Value: "test"}}, opts.ConnectionProperties)
	require.Equal(t, iamqp.Map{{Key: iamqp.Symbol("s"), Value: "1"}}, opts.SessionProperties)
	require.Equal(t, iamqp.Map{{Key: iamqp.Symbol("l"), Value: "2"}}, opts.LinkProperties)

	// Config fields win over properties.
	opts, err = options(transport.Config{ClientID: "c", Username: "cu", Properties: map[string]string{
		"container-id": "cid", "username": "u", "idle-timeout": "30",
	}})
	require.NoError(t, err)
	require.Equal(t, "c", opts.ContainerID)
	require.Equal(t, "cu", opts.Username)
	require.Equal(t, 30*time.Second, opts.IdleTimeout)
	opts, err = options(transport.Config{Properties: map[string]string{"connection-idle-time-out": "5000"}})
	require.NoError(t, err)
	require.Equal(t, 10*time.Second, opts.IdleTimeout)

	for _, name := range []string{"idle-timeout", "connection-idle-time-out", "connection-max-frame-size", "link-max-message-size", "credit"} {
		_, err := options(transport.Config{Properties: map[string]string{name: "x"}})
		require.ErrorContains(t, err, name)
		_, err = Open(bg, transport.Config{URL: "amqp://h", Properties: map[string]string{name: "-1"}})
		require.ErrorContains(t, err, name)
	}
}

func TestOpenFails(t *testing.T) {
	b := startBroker(t, amqpbroker.Options{Users: map[string]string{"u": "p"}})
	_, err := Open(bg, transport.Config{URL: b.URL(), Username: "u", Password: "wrong"})
	var ce *iamqp.ConnectError
	require.ErrorAs(t, err, &ce)
	c := open(t, transport.Config{URL: b.URL(), Properties: map[string]string{"username": "u", "password": "p"}})
	require.True(t, c.Connected())
}

func TestTLS(t *testing.T) {
	srv, cli, err := amqpbroker.TestTLS(false)
	require.NoError(t, err)
	b := startBroker(t, amqpbroker.Options{TLSConfig: srv})
	c := open(t, transport.Config{URL: "amqps://" + b.Addr(), TLSConfig: cli})
	in := make(inbox, 1)
	_, err = c.Subscribe(bg, "t", 0, in.handle)
	require.NoError(t, err)
	require.NoError(t, c.Send(bg, []byte("s"), transport.PublishOptions{Topic: "t", QoS: 1}))
	require.Equal(t, []byte("s"), in.next(t).Payload)
}

func TestMessageMapping(t *testing.T) {
	c := &Conn{contentType: ContentTypeUADP}
	now := time.Now()
	m := c.message([]byte("p"), transport.PublishOptions{Properties: map[string]any{
		"message-correlation-id":       []byte{1},
		"message-absolute-expiry-time": "nope",
		"message-creation-time":        false,
		"message-to":                   nil,
		"message-reply-to":             7,
	}}, now)
	require.Nil(t, m.Header)
	require.Equal(t, iamqp.Symbol(ContentTypeUADP), m.Properties.ContentType)
	require.Equal(t, []byte{1}, m.Properties.CorrelationID)
	require.True(t, m.Properties.AbsoluteExpiryTime.IsZero())
	require.True(t, m.Properties.CreationTime.IsZero())
	require.Empty(t, m.Properties.To)
	require.Equal(t, "7", m.Properties.ReplyTo)
	require.Nil(t, m.ApplicationProperties)
	id := m.Properties.MessageID.(iamqp.UUID)
	require.Equal(t, byte(0x40), id[6]&0xf0)

	m = c.message(nil, transport.PublishOptions{Properties: map[string]any{
		"message-correlation-id":       uint64(9),
		"message-absolute-expiry-time": int32(1000),
	}}, now)
	require.Equal(t, uint64(9), m.Properties.CorrelationID)
	require.Equal(t, now.Add(time.Second), m.Properties.AbsoluteExpiryTime)
	m = c.message(nil, transport.PublishOptions{Properties: map[string]any{
		"message-correlation-id":       "",
		"message-absolute-expiry-time": float32(-1),
	}}, now)
	require.Nil(t, m.Properties.CorrelationID)
	require.True(t, m.Properties.AbsoluteExpiryTime.IsZero())
	m = c.message(nil, transport.PublishOptions{Properties: map[string]any{"message-absolute-expiry-time": "2000"}}, now)
	require.Equal(t, now.Add(2*time.Second), m.Properties.AbsoluteExpiryTime)

	require.Equal(t, int64(1), appValue(1))
	require.Equal(t, "{}", appValue(struct{}{}))
	require.Nil(t, appValue(nil))
	require.Nil(t, mapErr(nil))
	e := errors.New("e")
	require.Equal(t, e, mapErr(e))
}
