// SPDX-License-Identifier: MIT

// Package mqtt is the MQTT transport of OPC UA PubSub (Part 14 §7.3.4 in
// 1.05.06, §7.3.5 in earlier 1.05 editions): NetworkMessages (UADP or JSON)
// as MQTT 3.1.1 or MQTT 5.0 messages on a broker.
//
// Importing the package registers the "mqtt" and "mqtts" schemes with
// [transport.Register].
//
// The URL is mqtt://host[:1883] or mqtts://host[:8883]. Send publishes to
// PublishOptions.Topic (the QueueName of the writer group, or the
// MetaDataQueueName of a writer) with its QoS (0, 1 or 2: at most, at least
// and exactly once, §7.3.4.5) and Retain flag; Subscribe subscribes a topic
// filter, MQTT wildcards allowed. The connection reconnects by itself with
// exponential backoff, subscribes again and retransmits unacknowledged QoS
// 1 and 2 messages; QoS 0 messages sent while it is reconnecting fail with
// [ErrNotConnected].
//
// # MQTT version
//
// The version is Config.MQTTVersion or else the connection property
// MqttVersion (§7.3.4.4, Table 201): "3.1.1", "5.0" or "BestAvailable"
// (5.0 if the broker accepts it, else 3.1.1). Part 14 makes BestAvailable
// the default; go-opcua keeps 3.1.1 as the default, the version every
// PubSub peer speaks (open62541 1.5 has no 5.0).
//
// With MQTT 5.0 every message carries the Content Type of its encoding,
// "application/opcua+uadp" or "application/json" (§7.3.4.9.1, §7.3.4.9.2;
// for metadata too: the body is a UADP discovery response or a JSON
// ua-metadata message), and the User Property UAMessageType ("ua-data",
// "ua-metadata", §7.3.4.8 Table 207). Received messages expose their
// Content Type and User Properties on [transport.Message]. The standard
// connection properties of Table 202 set the CONNECT: "connection-ClientID",
// "connection-Receive Maximum", "connection-Maximum Packet Size" (the lower
// of it and the message size limit), "connection-Session Expiry Interval"
// (a value above 0 keeps the session on the broker for that many seconds),
// "connection-Request Response Information" and "connection-Request
// Problem Information"; "connection-Topic Alias Maximum" is ignored, the
// transport never accepts topic aliases. Every other connection property
// that is not one of go-opcua's ("client-id", "username", "password",
// "keep-alive") or MqttTopicPrefix becomes a User Property of the CONNECT.
// Over 3.1.1 these settings are silently discarded, as Part 14 asks.
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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	imqtt "github.com/otfabric/go-opcua/internal/mqtt"
	"github.com/otfabric/go-opcua/pubsub/transport"
)

// DefaultMaxMessageSize is the default limit of a NetworkMessage.
const DefaultMaxMessageSize = 1 << 20

// Values of the MqttVersion connection property (Part 14 §7.3.4.4).
const (
	Version311           = "3.1.1"
	Version5             = "5.0"
	VersionBestAvailable = "BestAvailable"
)

// Names of the connection properties of Part 14 §7.3.4.4 (Tables 201 and
// 202). The namespace index of the keys is 0.
const (
	PropMqttVersion                = "MqttVersion"
	PropMqttTopicPrefix            = "MqttTopicPrefix"
	PropClientID                   = "connection-ClientID"
	PropReceiveMaximum             = "connection-Receive Maximum"
	PropMaximumPacketSize          = "connection-Maximum Packet Size"
	PropSessionExpiryInterval      = "connection-Session Expiry Interval"
	PropTopicAliasMaximum          = "connection-Topic Alias Maximum"
	PropRequestResponseInformation = "connection-Request Response Information"
	PropRequestProblemInformation  = "connection-Request Problem Information"
)

// ownProps are the connection properties that are not User Properties:
// those of Part 14 and those of go-opcua.
var ownProps = map[string]bool{
	PropMqttVersion: true, PropMqttTopicPrefix: true, PropClientID: true, PropReceiveMaximum: true,
	PropMaximumPacketSize: true, PropSessionExpiryInterval: true, PropTopicAliasMaximum: true,
	PropRequestResponseInformation: true, PropRequestProblemInformation: true,
	"client-id": true, "username": true, "password": true, "keep-alive": true,
}

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
	client      *imqtt.Client
	maxSize     int
	contentType string
	log         *slog.Logger

	mu     sync.Mutex
	closed bool
}

var _ transport.Connection = (*Conn)(nil)

// ParseVersion maps a value of the MqttVersion connection property to the
// protocol version of the client ("": 3.1.1).
func ParseVersion(s string) (byte, error) {
	switch strings.TrimSpace(s) {
	case "", Version311:
		return imqtt.Version311, nil
	case Version5, "5":
		return imqtt.Version5, nil
	case VersionBestAvailable:
		return imqtt.VersionBestAvailable, nil
	}
	return 0, fmt.Errorf("pubsub/transport/mqtt: MqttVersion %q is not %q, %q or %q", s, Version311, Version5, VersionBestAvailable)
}

// ContentTypeOf returns the Content Type of the NetworkMessages of a
// transport profile, "" if the profile has none.
func ContentTypeOf(profileURI string) string {
	switch profileURI {
	case transport.ProfileMQTTUADP:
		return transport.ContentTypeUADP
	case transport.ProfileMQTTJSON:
		return transport.ContentTypeJSON
	}
	return ""
}

// CheckProperties checks the values of the MQTT connection properties of
// Part 14 §7.3.4.4: the version, and numbers and Booleans where Table 202
// asks for them.
func CheckProperties(props map[string]string) error {
	if _, err := ParseVersion(props[PropMqttVersion]); err != nil {
		return err
	}
	for name, bits := range map[string]int{PropReceiveMaximum: 16, PropMaximumPacketSize: 32,
		PropSessionExpiryInterval: 32, PropTopicAliasMaximum: 16, "keep-alive": 16} {
		if v, ok := props[name]; ok {
			n, err := strconv.ParseUint(strings.TrimSpace(v), 10, bits)
			if err != nil {
				return fmt.Errorf("pubsub/transport/mqtt: connection property %q: %q is not a UInt%d", name, v, bits)
			}
			if n == 0 && (name == PropReceiveMaximum || name == PropMaximumPacketSize) {
				return fmt.Errorf("pubsub/transport/mqtt: connection property %q must not be 0", name)
			}
		}
	}
	for _, name := range []string{PropRequestResponseInformation, PropRequestProblemInformation} {
		if v, ok := props[name]; ok {
			if _, err := strconv.ParseBool(strings.TrimSpace(v)); err != nil {
				return fmt.Errorf("pubsub/transport/mqtt: connection property %q: %q is not a Boolean", name, v)
			}
		}
	}
	return nil
}

// Open connects to the broker of cfg.URL. Failed attempts are retried with
// backoff until ctx ends, except refusals a retry cannot fix (bad
// credentials, ...), so ctx should carry a deadline.
func Open(ctx context.Context, cfg transport.Config) (*Conn, error) {
	prop := func(name string) string { return strings.TrimSpace(cfg.Properties[name]) }
	if err := CheckProperties(cfg.Properties); err != nil {
		return nil, err
	}
	version := cfg.MQTTVersion
	if version == "" {
		version = prop(PropMqttVersion)
	}
	v, err := ParseVersion(version)
	if err != nil {
		return nil, err
	}
	opts := imqtt.Options{
		Server:          cfg.URL,
		ProtocolVersion: v,
		ClientID:        cfg.ClientID,
		Username:        cfg.Username,
		Password:        cfg.Password,
		KeepAlive:       cfg.KeepAlive,
		TLSConfig:       cfg.TLSConfig,
		Logger:          cfg.Logger,
	}
	for _, name := range []string{PropClientID, "client-id"} {
		if opts.ClientID == "" {
			opts.ClientID = prop(name)
		}
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
		s, _ := strconv.ParseUint(prop("keep-alive"), 10, 16) // checked
		opts.KeepAlive = time.Duration(s) * time.Second
	}
	c := &Conn{maxSize: cfg.MaxMessageSize, log: cfg.Logger, contentType: ContentTypeOf(cfg.ProfileURI)}
	if c.maxSize <= 0 {
		c.maxSize = DefaultMaxMessageSize
	}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	// Room for the topic, the properties and the packet header.
	opts.MaxPacketSize = c.maxSize + 2*65536 + 16
	if v != imqtt.Version311 {
		mqtt5Options(&opts, cfg.Properties)
	}
	client, err := imqtt.Dial(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("pubsub/transport/mqtt: connect %s: %w", cfg.URL, err)
	}
	c.client = client
	return c, nil
}

// mqtt5Options applies the connection properties of Part 14 §7.3.4.4 Table
// 202 and the User Properties (checked by CheckProperties) for MQTT 5.0
// and BestAvailable. The client sends them only with MQTT 5.0; a
// BestAvailable connection that falls back to 3.1.1 keeps the session
// (without expiry) if a Session Expiry Interval was set.
func mqtt5Options(opts *imqtt.Options, props map[string]string) {
	num := func(name string) (uint64, bool) {
		v, ok := props[name]
		if !ok {
			return 0, false
		}
		n, _ := strconv.ParseUint(strings.TrimSpace(v), 10, 32)
		return n, true
	}
	flag := func(name string) (bool, bool) {
		v, ok := props[name]
		if !ok {
			return false, false
		}
		b, _ := strconv.ParseBool(strings.TrimSpace(v))
		return b, true
	}
	if n, ok := num(PropReceiveMaximum); ok {
		opts.ReceiveMaximum = uint16(n)
	}
	if n, ok := num(PropMaximumPacketSize); ok && int(n) < opts.MaxPacketSize {
		opts.MaxPacketSize = int(n)
	}
	if n, ok := num(PropSessionExpiryInterval); ok && n > 0 {
		opts.PersistentSession = true
		opts.SessionExpiry = uint32(n)
	}
	if b, ok := flag(PropRequestResponseInformation); ok {
		opts.RequestResponseInformation = b
	}
	if b, ok := flag(PropRequestProblemInformation); ok {
		opts.RequestProblemInformation = &b
	}
	names := make([]string, 0, len(props))
	for name := range props {
		if !ownProps[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		opts.UserProperties = append(opts.UserProperties, imqtt.UserProperty{Key: name, Value: props[name]})
	}
}

func mapErr(err error) error {
	if errors.Is(err, imqtt.ErrClosed) {
		return transport.ErrClosed
	}
	return err
}

// Send publishes payload to opts.Topic. QoS 1 waits for the broker's
// acknowledgement and QoS 2 for the end of the exactly once exchange (and,
// while reconnecting, for the connection).
func (c *Conn) Send(ctx context.Context, payload []byte, opts transport.PublishOptions) error {
	if opts.Topic == "" {
		return errors.New("pubsub/transport/mqtt: Send needs a topic (queue name)")
	}
	if len(payload) > c.maxSize {
		return fmt.Errorf("%w: %d bytes, limit %d", transport.ErrMessageTooLarge, len(payload), c.maxSize)
	}
	po := imqtt.PublishOptions{QoS: opts.QoS, Retain: opts.Retain}
	ct := opts.ContentType
	if ct == "" {
		ct = c.contentType
	}
	if ct != "" {
		po.Props.ContentType = &ct
	}
	if opts.MessageType != "" {
		po.Props.User = append(po.Props.User, imqtt.UserProperty{Key: transport.UAMessageTypeProperty, Value: opts.MessageType})
	}
	for _, p := range opts.UserProperties {
		po.Props.User = append(po.Props.User, imqtt.UserProperty{Key: p.Name, Value: p.Value})
	}
	if opts.MessageExpiry > 0 {
		s := (opts.MessageExpiry + time.Second - 1) / time.Second
		po.Props.MessageExpiry = imqtt.Ptr(uint32(min(s, 0xffffffff)))
	}
	return mapErr(c.client.PublishWith(ctx, opts.Topic, payload, po))
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
		tm := &transport.Message{Payload: m.Payload, Topic: m.Topic, Received: time.Now()}
		if ct := m.Props.ContentType; ct != nil {
			tm.ContentType = *ct
		}
		for _, u := range m.Props.User {
			tm.UserProperties = append(tm.UserProperties, transport.Property{Name: u.Key, Value: u.Value})
		}
		h(tm)
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

// Version returns the MQTT version of the connection: Version311 or
// Version5.
func (c *Conn) Version() string {
	if c.client.ProtocolVersion() == imqtt.Version5 {
		return Version5
	}
	return Version311
}

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
