// SPDX-License-Identifier: MIT

// Package mqtt is the MQTT transport of OPC UA PubSub (Part 14 §7.3.5):
// NetworkMessages (UADP or JSON) as MQTT 3.1.1 messages on a broker.
//
// Importing the package registers the "mqtt" and "mqtts" schemes with
// [transport.Register].
//
// The URL is mqtt://host[:1883] or mqtts://host[:8883]. Send publishes to
// PublishOptions.Topic (the QueueName of the writer group, or the
// MetaDataQueueName of a writer) with its QoS (0 or 1; 2 is downgraded to 1)
// and Retain flag; Subscribe subscribes a topic filter, MQTT wildcards
// allowed. The connection reconnects by itself with exponential backoff,
// subscribes again and retransmits unacknowledged QoS 1 messages; QoS 0
// messages sent while it is reconnecting fail with [ErrNotConnected].
//
// open62541 1.5 connects with MQTT 3.1.1, an empty client identifier and a
// clean session, publishes and subscribes at QoS 0 without retain, and uses
// a keep-alive of 400 s; this transport talks to the same brokers.
//
// Besides the Config fields the connection properties "client-id",
// "username", "password" and "keep-alive" (seconds) are honoured where the
// corresponding Config field is empty.
package mqtt

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	imqtt "github.com/otfabric/go-opcua/internal/mqtt"
	"github.com/otfabric/go-opcua/pubsub/transport"
)

// DefaultMaxMessageSize is the default limit of a NetworkMessage.
const DefaultMaxMessageSize = 1 << 20

// ErrNotConnected is returned by a QoS 0 Send while the connection is
// re-established.
var ErrNotConnected = imqtt.ErrNotConnected

func init() {
	open := func(ctx context.Context, cfg transport.Config) (transport.Connection, error) {
		return Open(ctx, cfg)
	}
	transport.Register("mqtt", open)
	transport.Register("mqtts", open)
}

// Conn is an MQTT PubSub connection.
type Conn struct {
	client  *imqtt.Client
	maxSize int
	log     *slog.Logger

	mu     sync.Mutex
	closed bool
}

var _ transport.Connection = (*Conn)(nil)

// Open connects to the broker of cfg.URL. Failed attempts are retried with
// backoff until ctx ends, except refusals a retry cannot fix (bad
// credentials, ...), so ctx should carry a deadline.
func Open(ctx context.Context, cfg transport.Config) (*Conn, error) {
	prop := func(name string) string { return cfg.Properties[name] }
	opts := imqtt.Options{
		Server:    cfg.URL,
		ClientID:  cfg.ClientID,
		Username:  cfg.Username,
		Password:  cfg.Password,
		KeepAlive: cfg.KeepAlive,
		TLSConfig: cfg.TLSConfig,
		Logger:    cfg.Logger,
	}
	if opts.ClientID == "" {
		opts.ClientID = prop("client-id")
	}
	if opts.ClientID == "" {
		var b [6]byte
		_, _ = rand.Read(b[:])
		opts.ClientID = "opcua-pubsub-" + hex.EncodeToString(b[:])
	}
	if opts.Username == "" {
		opts.Username = prop("username")
	}
	if opts.Password == "" {
		opts.Password = prop("password")
	}
	if opts.KeepAlive == 0 && prop("keep-alive") != "" {
		s, err := strconv.ParseUint(prop("keep-alive"), 10, 16)
		if err != nil {
			return nil, fmt.Errorf("pubsub/transport/mqtt: keep-alive property %q: %w", prop("keep-alive"), err)
		}
		opts.KeepAlive = time.Duration(s) * time.Second
	}
	c := &Conn{maxSize: cfg.MaxMessageSize, log: cfg.Logger}
	if c.maxSize <= 0 {
		c.maxSize = DefaultMaxMessageSize
	}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	// Room for the topic and the packet header.
	opts.MaxPacketSize = c.maxSize + 65536 + 16
	client, err := imqtt.Dial(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("pubsub/transport/mqtt: connect %s: %w", cfg.URL, err)
	}
	c.client = client
	return c, nil
}

func mapErr(err error) error {
	if errors.Is(err, imqtt.ErrClosed) {
		return transport.ErrClosed
	}
	return err
}

// Send publishes payload to opts.Topic. QoS 1 waits for the broker's
// acknowledgement (and, while reconnecting, for the connection).
func (c *Conn) Send(ctx context.Context, payload []byte, opts transport.PublishOptions) error {
	if opts.Topic == "" {
		return errors.New("pubsub/transport/mqtt: Send needs a topic (queue name)")
	}
	if len(payload) > c.maxSize {
		return fmt.Errorf("%w: %d bytes, limit %d", transport.ErrMessageTooLarge, len(payload), c.maxSize)
	}
	return mapErr(c.client.Publish(ctx, opts.Topic, payload, opts.QoS, opts.Retain))
}

// Subscribe subscribes h to a topic filter. The returned function
// unsubscribes.
func (c *Conn) Subscribe(ctx context.Context, topic string, qos byte, h transport.Handler) (func() error, error) {
	if h == nil {
		return nil, errors.New("pubsub/transport/mqtt: nil handler")
	}
	maxSize := c.maxSize
	sub, err := c.client.Subscribe(ctx, topic, qos, func(m *imqtt.Message) {
		if len(m.Payload) > maxSize {
			c.log.Debug("pubsub/transport/mqtt: dropping oversized message", "topic", m.Topic, "size", len(m.Payload))
			return
		}
		h(&transport.Message{Payload: m.Payload, Topic: m.Topic, Received: time.Now()})
	})
	if err != nil {
		return nil, fmt.Errorf("pubsub/transport/mqtt: subscribe %q: %w", topic, mapErr(err))
	}
	return func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return mapErr(sub.Unsubscribe(ctx))
	}, nil
}

// MaxMessageSize is the largest payload Send accepts.
func (c *Conn) MaxMessageSize() int { return c.maxSize }

// Connected reports whether the connection to the broker is up right now.
func (c *Conn) Connected() bool { return c.client.IsConnected() }

// Close disconnects from the broker.
func (c *Conn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	return c.client.Close()
}
