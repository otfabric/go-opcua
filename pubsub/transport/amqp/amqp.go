// SPDX-License-Identifier: MIT

// Package amqp is the AMQP transport of OPC UA PubSub (Part 14 §7.3.4 and
// Annex B.3): NetworkMessages (UADP or JSON) as AMQP 1.0 messages on a
// broker.
//
// Importing the package registers the "amqp" and "amqps" schemes with
// [transport.Register].
//
// The URL is amqp://host[:5672] or amqps://host[:5671] (B.3.2); a path is
// ignored. Queue names (QueueName, MetaDataQueueName) are AMQP addresses:
// Send sends to the target address PublishOptions.Topic and Subscribe
// receives from the source address topic, without wildcards. How an
// address is resolved is up to the broker:
//
//   - RabbitMQ 4 (native AMQP 1.0, address format v2): "/queues/<queue>"
//     sends to and receives from a declared queue; "/exchanges/<exchange>/<key>"
//     sends to an exchange with a routing key, for example
//     "/exchanges/amq.topic/opcua.data". Subscribers receive from a queue
//     bound to the exchange.
//   - ActiveMQ Artemis: a plain address, "opcua/data". It is created on
//     first use; the routing type follows the broker's defaults or the
//     "source-capabilities" / "target-capabilities" connection properties
//     ("queue" for anycast, "topic" for multicast). The "queue://" and
//     "topic://" prefixes work as well when the acceptor allows them.
//
// Delivery guarantees (B.3.5): best effort and at most once (QoS 0) send
// pre-settled messages and receive on links the broker settles (a message
// can be lost); at least once (QoS 1) sends unsettled messages and Send
// returns when the broker accepted it (it is sent again after a reconnect,
// so it can arrive twice); exactly once is downgraded to at least once.
// DataSetMetaData is sent at least once. AMQP has no retained messages:
// PublishOptions.Retain is ignored, so a subscriber that starts late waits
// for the next metadata the publisher sends (MetaDataUpdateTime).
//
// The message mapping follows B.3.7 and B.3.8: the body is one data
// section with the NetworkMessage, the properties carry a random UUID as
// message-id, the subject "ua-data" or "ua-metadata" and the content-type
// "application/opcua+uadp" or "application/json". The WriterGroupProperties
// and DataSetWriterProperties named in Table B.2 ("message-to",
// "message-reply-to", "message-correlation-id", "message-group-id",
// "message-reply-to-group-id", "message-content-encoding",
// "message-user-id", "message-absolute-expiry-time" (a Duration in
// milliseconds), "message-creation-time" (a Boolean)) set the message
// properties; the other properties become application-properties. Received
// messages may have any body that carries bytes (data sections, or an
// amqp-value or amqp-sequence holding binary).
//
// The connection reconnects by itself with exponential backoff, attaches
// its links again and sends unsettled messages again; QoS 0 messages sent
// while it is reconnecting fail with [ErrNotConnected].
//
// Connection properties (KeyValuePairs of the PubSubConnection, B.3.4):
// "connection-hostname", "connection-max-frame-size" and
// "connection-idle-time-out" (milliseconds) set those fields of the open
// frame, "link-max-message-size" the limit of received messages; other
// names with the prefix "connection-", "session-" or "link-" are sent as
// properties of the open, begin and attach frames. Besides, "container-id",
// "username", "password", "sasl-mechanism" (ANONYMOUS, PLAIN, EXTERNAL or
// NONE), "source-capabilities" and "target-capabilities" (comma
// separated), "credit" (link credit of receivers) and "idle-timeout"
// (seconds) are honoured where the corresponding Config field is empty.
package amqp

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	iamqp "github.com/otfabric/go-opcua/internal/amqp"
	"github.com/otfabric/go-opcua/pubsub/transport"
)

// DefaultMaxMessageSize is the default limit of a NetworkMessage.
const DefaultMaxMessageSize = 1 << 20

// Subjects of Part 14 Table B.1.
const (
	SubjectData     = "ua-data"
	SubjectMetaData = "ua-metadata"
)

// Content types of Part 14 B.3.8.
const (
	ContentTypeUADP = transport.ContentTypeUADP
	ContentTypeJSON = transport.ContentTypeJSON
)

// ErrNotConnected is returned by a QoS 0 Send while the connection is
// re-established.
var ErrNotConnected = iamqp.ErrNotConnected

func init() {
	open := func(ctx context.Context, cfg transport.Config) (transport.Connection, error) {
		return Open(ctx, cfg)
	}
	transport.Register("amqp", open)
	transport.Register("amqps", open)
}

// Conn is an AMQP PubSub connection.
type Conn struct {
	client      *iamqp.Client
	maxSize     int
	contentType string
	log         *slog.Logger

	mu     sync.Mutex
	closed bool
}

var _ transport.Connection = (*Conn)(nil)

// Open connects to the broker of cfg.URL. Failed attempts are retried with
// backoff until ctx ends, except refusals a retry cannot fix (bad
// credentials, ...), so ctx should carry a deadline.
func Open(ctx context.Context, cfg transport.Config) (*Conn, error) {
	opts, err := options(cfg)
	if err != nil {
		return nil, fmt.Errorf("pubsub/transport/amqp: %w", err)
	}
	c := &Conn{maxSize: cfg.MaxMessageSize, log: cfg.Logger, contentType: ContentTypeUADP}
	if cfg.ProfileURI == transport.ProfileAMQPJSON {
		c.contentType = ContentTypeJSON
	}
	if c.maxSize <= 0 {
		c.maxSize = DefaultMaxMessageSize
	}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	if opts.MaxMessageSize == 0 {
		// Room for the sections around the NetworkMessage.
		opts.MaxMessageSize = c.maxSize + 64<<10
	}
	client, err := iamqp.Dial(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("pubsub/transport/amqp: connect %s: %w", cfg.URL, err)
	}
	c.client = client
	return c, nil
}

// options maps the transport configuration and the connection properties
// (B.3.4) to the client options.
func options(cfg transport.Config) (iamqp.Options, error) {
	opts := iamqp.Options{
		Server:      cfg.URL,
		ContainerID: cfg.ClientID,
		Username:    cfg.Username,
		Password:    cfg.Password,
		TLSConfig:   cfg.TLSConfig,
		IdleTimeout: cfg.KeepAlive,
		Logger:      cfg.Logger,
	}
	set := func(s *string, name string) {
		if *s == "" {
			*s = cfg.Properties[name]
		}
	}
	set(&opts.ContainerID, "container-id")
	set(&opts.Username, "username")
	set(&opts.Password, "password")
	set(&opts.SASLMechanism, "sasl-mechanism")
	opts.SASLMechanism = strings.ToUpper(opts.SASLMechanism)
	uintProp := func(name string, bits int) (uint64, bool, error) {
		s, ok := cfg.Properties[name]
		if !ok {
			return 0, false, nil
		}
		n, err := strconv.ParseUint(strings.TrimSpace(s), 10, bits)
		if err != nil {
			return 0, false, fmt.Errorf("connection property %s %q: %w", name, s, err)
		}
		return n, true, nil
	}
	if opts.IdleTimeout == 0 {
		if n, ok, err := uintProp("idle-timeout", 32); err != nil {
			return opts, err
		} else if ok {
			opts.IdleTimeout = time.Duration(n) * time.Second
		}
		// idle-time-out of the open frame (§2.7.1) is what the client
		// announces: half of its own time-out.
		if n, ok, err := uintProp("connection-idle-time-out", 32); err != nil {
			return opts, err
		} else if ok {
			opts.IdleTimeout = 2 * time.Duration(n) * time.Millisecond
		}
	}
	if n, ok, err := uintProp("connection-max-frame-size", 32); err != nil {
		return opts, err
	} else if ok {
		opts.MaxFrameSize = uint32(n)
	}
	if n, ok, err := uintProp("link-max-message-size", 31); err != nil {
		return opts, err
	} else if ok {
		opts.MaxMessageSize = int(n)
	}
	if n, ok, err := uintProp("credit", 32); err != nil {
		return opts, err
	} else if ok {
		opts.Credit = uint32(n)
	}
	opts.Hostname = cfg.Properties["connection-hostname"]
	opts.SourceCapabilities = symbols(cfg.Properties["source-capabilities"])
	opts.TargetCapabilities = symbols(cfg.Properties["target-capabilities"])
	for name, v := range cfg.Properties {
		var m *iamqp.Map
		var key string
		switch {
		case name == "connection-hostname" || name == "connection-max-frame-size" ||
			name == "connection-idle-time-out" || name == "link-max-message-size":
			continue
		case strings.HasPrefix(name, "connection-"):
			m, key = &opts.ConnectionProperties, strings.TrimPrefix(name, "connection-")
		case strings.HasPrefix(name, "session-"):
			m, key = &opts.SessionProperties, strings.TrimPrefix(name, "session-")
		case strings.HasPrefix(name, "link-"):
			m, key = &opts.LinkProperties, strings.TrimPrefix(name, "link-")
		default:
			continue
		}
		if key != "" {
			*m = append(*m, iamqp.KV{Key: iamqp.Symbol(key), Value: v})
		}
	}
	return opts, nil
}

// symbols splits a comma separated list.
func symbols(s string) []iamqp.Symbol {
	var out []iamqp.Symbol
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, iamqp.Symbol(f))
		}
	}
	return out
}

func mapErr(err error) error {
	if errors.Is(err, iamqp.ErrClosed) {
		return transport.ErrClosed
	}
	return err
}

// Send sends payload to the address opts.Topic. QoS 0 sends it pre-settled,
// QoS 1 and 2 wait until the broker accepted it (and, while reconnecting,
// for the connection).
func (c *Conn) Send(ctx context.Context, payload []byte, opts transport.PublishOptions) error {
	if opts.Topic == "" {
		return errors.New("pubsub/transport/amqp: Send needs a topic (address)")
	}
	if len(payload) > c.maxSize {
		return fmt.Errorf("%w: %d bytes, limit %d", transport.ErrMessageTooLarge, len(payload), c.maxSize)
	}
	m := c.message(payload, opts, time.Now())
	return mapErr(c.client.Send(ctx, opts.Topic, m, opts.QoS == 0))
}

// message builds the AMQP message of a NetworkMessage (B.3.7, B.3.8).
func (c *Conn) message(payload []byte, opts transport.PublishOptions, now time.Time) *iamqp.Message {
	var id iamqp.UUID
	_, _ = rand.Read(id[:])
	id[6] = id[6]&0x0f | 0x40 // version 4 (RFC 9562)
	id[8] = id[8]&0x3f | 0x80
	p := &iamqp.Properties{MessageID: id, Subject: SubjectData, ContentType: iamqp.Symbol(c.contentType)}
	if opts.MessageType == transport.MessageTypeMetaData {
		p.Subject = SubjectMetaData
	}
	if opts.ContentType != "" {
		p.ContentType = iamqp.Symbol(opts.ContentType)
	}
	m := &iamqp.Message{Properties: p, Data: [][]byte{payload}}
	if opts.QoS > 0 {
		m.Header = &iamqp.Header{Durable: true, Priority: 4}
	}
	for name, v := range opts.Properties {
		if !messageProperty(p, name, v, now) {
			if m.ApplicationProperties == nil {
				m.ApplicationProperties = map[string]any{}
			}
			m.ApplicationProperties[name] = appValue(v)
		}
	}
	return m
}

// messageProperty sets the message property of a "message-" name of Part 14
// Table B.2 and reports whether name is one.
func messageProperty(p *iamqp.Properties, name string, v any, now time.Time) bool {
	str := func() string {
		switch v := v.(type) {
		case string:
			return v
		case []byte:
			return string(v)
		case nil:
			return ""
		}
		return fmt.Sprint(v)
	}
	switch name {
	case "message-to":
		p.To = str()
	case "message-user-id":
		p.UserID = []byte(str())
	case "message-reply-to":
		p.ReplyTo = str()
	case "message-correlation-id":
		switch v := v.(type) {
		case []byte, uint64:
			p.CorrelationID = v
		default:
			if s := str(); s != "" {
				p.CorrelationID = s
			}
		}
	case "message-group-id":
		p.GroupID = str()
	case "message-reply-to-group-id":
		p.ReplyToGroupID = str()
	case "message-content-encoding":
		p.ContentEncoding = iamqp.Symbol(str())
	case "message-absolute-expiry-time":
		// A Duration (milliseconds) from now.
		if ms, ok := number(v); ok && ms > 0 && ms < math.MaxInt64/float64(time.Millisecond) {
			p.AbsoluteExpiryTime = now.Add(time.Duration(ms * float64(time.Millisecond)))
		}
	case "message-creation-time":
		if b, ok := v.(bool); ok && b {
			p.CreationTime = now
		}
	default:
		return false
	}
	return true
}

// number converts a numeric value.
func number(v any) (float64, bool) {
	switch v := v.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int8, int16, int32, int64, int, uint8, uint16, uint32, uint64:
		f, err := strconv.ParseFloat(fmt.Sprint(v), 64)
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(v, 64)
		return f, err == nil
	}
	return 0, false
}

// appValue converts a property value to a simple AMQP type, which is all
// application-properties may hold (Part 3 §3.2.5); other values are sent as
// their string form.
func appValue(v any) any {
	switch v := v.(type) {
	case nil, bool, string, []byte, time.Time,
		int8, int16, int32, int64, uint8, uint16, uint32, uint64, float32, float64:
		return v
	case int:
		return int64(v)
	}
	return fmt.Sprint(v)
}

// Subscribe receives the messages of the source address topic. QoS 0
// receives on a link the broker settles, QoS 1 and 2 on one the client
// settles. The returned function detaches the link.
func (c *Conn) Subscribe(ctx context.Context, topic string, qos byte, h transport.Handler) (func() error, error) {
	if h == nil {
		return nil, errors.New("pubsub/transport/amqp: nil handler")
	}
	if topic == "" {
		return nil, errors.New("pubsub/transport/amqp: Subscribe needs a topic (address)")
	}
	maxSize := c.maxSize
	sub, err := c.client.Subscribe(ctx, topic, qos == 0, func(m *iamqp.Message) {
		payload := m.Payload()
		if payload == nil {
			c.log.Debug("pubsub/transport/amqp: dropping a message without a binary body", "address", topic)
			return
		}
		if len(payload) > maxSize {
			c.log.Debug("pubsub/transport/amqp: dropping oversized message", "address", topic, "size", len(payload))
			return
		}
		h(&transport.Message{Payload: payload, Topic: topic, Received: time.Now()})
	})
	if err != nil {
		return nil, fmt.Errorf("pubsub/transport/amqp: subscribe %q: %w", topic, mapErr(err))
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

// Close closes the connection.
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
