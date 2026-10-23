// SPDX-License-Identifier: MIT

package mqtt

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	imqtt "github.com/otfabric/go-opcua/internal/mqtt"
	"github.com/otfabric/go-opcua/internal/testutil/mqttbroker"
	"github.com/otfabric/go-opcua/pubsub/transport"
)

var bg = context.Background()

func startBroker(t *testing.T, opts mqttbroker.Options) *mqttbroker.Broker {
	t.Helper()
	b := mqttbroker.New(opts)
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
	case <-time.After(5 * time.Second):
		t.Fatal("no message")
		return nil
	}
}

func TestSendSubscribe(t *testing.T) {
	b := startBroker(t, mqttbroker.Options{})
	require.Contains(t, transport.Schemes(), "mqtt")
	require.Contains(t, transport.Schemes(), "mqtts")

	sub := open(t, transport.Config{URL: b.URL(), ProfileURI: transport.ProfileMQTTJSON})
	pub, err := transport.Open(bg, transport.Config{URL: b.URL()})
	require.NoError(t, err)
	defer func() { _ = pub.Close() }()
	require.Equal(t, DefaultMaxMessageSize, pub.MaxMessageSize())
	require.True(t, sub.Connected())

	in := make(inbox, 100)
	cancel, err := sub.Subscribe(bg, "opcua/json/data/+/#", 1, in.handle)
	require.NoError(t, err)

	for _, qos := range []byte{0, 1, 2} {
		require.NoError(t, pub.Send(bg, []byte{'m', '0' + qos}, transport.PublishOptions{Topic: "opcua/json/data/pub/wg", QoS: qos}))
		m := in.next(t)
		require.Equal(t, "opcua/json/data/pub/wg", m.Topic)
		require.Equal(t, []byte{'m', '0' + qos}, m.Payload)
		require.Nil(t, m.Source)
		require.WithinDuration(t, time.Now(), m.Received, 5*time.Second)
	}

	// Retained metadata reaches a late subscriber.
	require.NoError(t, pub.Send(bg, []byte("meta"), transport.PublishOptions{Topic: "opcua/json/metadata/pub/wg/w", QoS: 1, Retain: true}))
	late := open(t, transport.Config{URL: b.URL()})
	in2 := make(inbox, 10)
	_, err = late.Subscribe(bg, "opcua/json/metadata/#", 1, in2.handle)
	require.NoError(t, err)
	require.Equal(t, "meta", string(in2.next(t).Payload))

	require.NoError(t, cancel())
	require.NoError(t, cancel())
	require.NoError(t, pub.Send(bg, []byte("x"), transport.PublishOptions{Topic: "opcua/json/data/pub/wg", QoS: 1}))
	select {
	case m := <-in:
		t.Fatalf("message after cancel: %q", m.Payload)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestReconnect(t *testing.T) {
	b := startBroker(t, mqttbroker.Options{})
	sub := open(t, transport.Config{URL: b.URL()})
	pub := open(t, transport.Config{URL: b.URL()})
	in := make(inbox, 100)
	_, err := sub.Subscribe(bg, "t", 1, in.handle)
	require.NoError(t, err)

	b.Stop()
	require.Eventually(t, func() bool { return !pub.Connected() }, 5*time.Second, 5*time.Millisecond)
	require.ErrorIs(t, pub.Send(bg, []byte("x"), transport.PublishOptions{Topic: "t"}), ErrNotConnected)
	b.Reset()
	require.NoError(t, b.Start())
	require.Eventually(t, func() bool {
		require.NoError(t, pub.Send(bg, []byte("back"), transport.PublishOptions{Topic: "t", QoS: 1}))
		select {
		case m := <-in:
			return string(m.Payload) == "back"
		case <-time.After(50 * time.Millisecond):
			return false
		}
	}, 10*time.Second, time.Millisecond)
}

func TestTLSAndCredentials(t *testing.T) {
	srv, cli, err := mqttbroker.SelfSignedTLS()
	require.NoError(t, err)
	b := startBroker(t, mqttbroker.Options{TLSConfig: srv, Users: map[string]string{"u": "p"}})
	c := open(t, transport.Config{URL: b.URL(), TLSConfig: cli, Username: "u", Password: "p", KeepAlive: 5 * time.Second})
	in := make(inbox, 1)
	_, err = c.Subscribe(bg, "s", 0, in.handle)
	require.NoError(t, err)
	require.NoError(t, c.Send(bg, []byte("tls"), transport.PublishOptions{Topic: "s"}))
	require.Equal(t, "tls", string(in.next(t).Payload))

	// Credentials and the client id from the connection properties.
	c2 := open(t, transport.Config{URL: b.URL(), TLSConfig: cli, Properties: map[string]string{
		"username": "u", "password": "p", "client-id": "from-props", "keep-alive": "30",
	}})
	require.True(t, c2.Connected())

	var ce *imqtt.ConnectError
	_, err = Open(bg, transport.Config{URL: b.URL(), TLSConfig: cli, Username: "u", Password: "bad"})
	require.ErrorAs(t, err, &ce)
	_, err = Open(bg, transport.Config{URL: b.URL(), Properties: map[string]string{"keep-alive": "x"}})
	require.Error(t, err)
}

func TestLimitsAndClose(t *testing.T) {
	b := startBroker(t, mqttbroker.Options{RefuseFilter: func(f string) bool { return f == "no" }})
	c := open(t, transport.Config{URL: b.URL(), MaxMessageSize: 100})
	require.Equal(t, 100, c.MaxMessageSize())
	require.ErrorIs(t, c.Send(bg, make([]byte, 101), transport.PublishOptions{Topic: "t"}), transport.ErrMessageTooLarge)
	require.Error(t, c.Send(bg, []byte("x"), transport.PublishOptions{}))
	_, err := c.Subscribe(bg, "t", 0, nil)
	require.Error(t, err)
	_, err = c.Subscribe(bg, "no", 0, func(*transport.Message) {})
	require.ErrorIs(t, err, imqtt.ErrSubscriptionRefused)

	// Received messages above the limit are dropped.
	in := make(inbox, 10)
	_, err = c.Subscribe(bg, "big", 0, in.handle)
	require.NoError(t, err)
	other := open(t, transport.Config{URL: b.URL()})
	require.NoError(t, other.Send(bg, make([]byte, 500), transport.PublishOptions{Topic: "big", QoS: 1}))
	require.NoError(t, other.Send(bg, []byte("ok"), transport.PublishOptions{Topic: "big", QoS: 1}))
	require.Equal(t, "ok", string(in.next(t).Payload))

	require.NoError(t, c.Close())
	require.NoError(t, c.Close())
	require.ErrorIs(t, c.Send(bg, []byte("x"), transport.PublishOptions{Topic: "t"}), transport.ErrClosed)
	_, err = c.Subscribe(bg, "t", 0, func(*transport.Message) {})
	require.ErrorIs(t, err, transport.ErrClosed)

	ctx, cancel := context.WithTimeout(bg, 100*time.Millisecond)
	defer cancel()
	_, err = Open(ctx, transport.Config{URL: "mqtt://127.0.0.1:1"})
	require.Error(t, err)
}
