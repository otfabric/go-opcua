// SPDX-License-Identifier: MIT

// Package transport is the transport layer of OPC UA PubSub (Part 14 §7.3):
// it moves encoded NetworkMessages between publishers and subscribers.
//
// A [Connection] is opened for a PubSubConnection from its transport profile
// and network address. The UDP (opc.udp://, unicast and multicast),
// Ethernet (opc.eth://) and MQTT (mqtt://, mqtts://) transports are
// implemented by the sub-packages and register themselves with [Register];
// import them for their side effect or use
// [github.com/otfabric/go-opcua/pubsub], which imports all of them.
package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"sync"
	"time"
)

// Transport profile URIs of Part 14 / Part 7.
const (
	ProfileUDPUADP  = "http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp"
	ProfileMQTTUADP = "http://opcfoundation.org/UA-Profile/Transport/pubsub-mqtt-uadp"
	ProfileMQTTJSON = "http://opcfoundation.org/UA-Profile/Transport/pubsub-mqtt-json"
	ProfileEthUADP  = "http://opcfoundation.org/UA-Profile/Transport/pubsub-eth-uadp"
)

// Message is one received NetworkMessage, still encoded.
type Message struct {
	// Payload is the encoded NetworkMessage. It belongs to the receiver.
	Payload []byte
	// Topic is the broker topic (queue name) it arrived on; empty for UDP.
	Topic string
	// Source is the sender's address for datagram transports, if known.
	Source net.Addr
	// Received is when the transport received the message.
	Received time.Time
	// ContentType is the MIME type of the payload, if the transport carries
	// one: the MQTT 5.0 Content Type ("application/opcua+uadp",
	// "application/json", Part 14 §7.3.4.9). Empty otherwise.
	ContentType string
	// UserProperties are the MQTT 5.0 User Properties of the message, in
	// order (UAMessageType, promoted fields, ...; Part 14 §7.3.4.8).
	UserProperties []Property
}

// Property is a name and value pair of a message header, such as an MQTT
// 5.0 User Property. A name may occur more than once.
type Property struct {
	Name, Value string
}

// UserProperty returns the value of the first user property called name,
// and whether there is one.
func (m *Message) UserProperty(name string) (string, bool) {
	for _, p := range m.UserProperties {
		if p.Name == name {
			return p.Value, true
		}
	}
	return "", false
}

// MIME types of NetworkMessages (Part 14 §7.3.4.9.1 and §7.3.4.9.2), sent
// as the MQTT 5.0 Content Type.
const (
	ContentTypeUADP     = "application/opcua+uadp"
	ContentTypeJSON     = "application/json"
	ContentTypeJSONGzip = "application/json+gzip"
)

// MQTT message types (Part 14 §7.3.4.7.2), sent as the MQTT 5.0 User
// Property UAMessageType (§7.3.4.8, Table 207).
const (
	UAMessageTypeProperty = "UAMessageType"
	MessageTypeData       = "ua-data"
	MessageTypeMetaData   = "ua-metadata"
	MessageTypeStatus     = "ua-status"
)

// Handler receives messages. It is called from the transport's receive
// goroutine and must not block for long.
type Handler func(*Message)

// PublishOptions are the per-message settings of broker transports
// (BrokerWriterGroupTransportDataType / BrokerDataSetWriterTransportDataType).
// Datagram transports ignore them.
type PublishOptions struct {
	// Topic is the queue name. Datagram transports ignore it.
	Topic string
	// QoS is the MQTT quality of service: 0 (at most once), 1 (at least
	// once) or 2 (exactly once).
	QoS byte
	// Retain asks the broker to keep the message for late subscribers
	// (used for metadata).
	Retain bool
	// ContentType is the MIME type of the payload (ContentTypeUADP,
	// ContentTypeJSON); empty selects the one of the transport profile.
	// MQTT 5.0 sends it as Content Type, 3.1.1 cannot.
	ContentType string
	// MessageType is the UAMessageType of the message (MessageTypeData,
	// MessageTypeMetaData, ...); MQTT 5.0 sends it as a User Property.
	MessageType string
	// MessageExpiry, if positive, is the MQTT 5.0 Message Expiry Interval
	// (rounded up to whole seconds).
	MessageExpiry time.Duration
	// UserProperties are further MQTT 5.0 User Properties.
	UserProperties []Property
}

// Connection is an open PubSub transport connection.
type Connection interface {
	// Send transmits one encoded NetworkMessage.
	Send(ctx context.Context, payload []byte, opts PublishOptions) error
	// Subscribe delivers received messages to h. For broker transports
	// topic selects the queue (MQTT wildcards are allowed); datagram
	// transports deliver everything received on the connection's address
	// and ignore topic. The returned function cancels the subscription.
	Subscribe(ctx context.Context, topic string, qos byte, h Handler) (cancel func() error, err error)
	// MaxMessageSize is the largest payload Send accepts (0: unlimited).
	MaxMessageSize() int
	// Close closes the connection and stops all subscriptions.
	Close() error
}

// Config describes the connection to open.
type Config struct {
	// ProfileURI is the TransportProfileUri of the PubSubConnection.
	ProfileURI string
	// URL is the address: opc.udp://host:port for UDP (a multicast group
	// joins the group), opc.eth://MAC[:VID[.PCP]] for Ethernet,
	// mqtt://host:port or mqtts://host:port for MQTT.
	URL string
	// Interface is the network interface (NetworkInterface of
	// NetworkAddressDataType): for UDP multicast, empty selects the system
	// default; Ethernet requires it.
	Interface string

	// MQTT settings. MQTTVersion is "3.1.1", "5.0" or "BestAvailable"
	// (the values of the MqttVersion connection property, Part 14
	// §7.3.4.4); empty uses the MqttVersion connection property and, without
	// it, 3.1.1.
	MQTTVersion string
	ClientID    string
	Username    string
	Password    string
	TLSConfig   *tls.Config
	KeepAlive   time.Duration

	// UDP settings: the TTL of multicast datagrams (default 1) and whether
	// this host receives its own multicast datagrams (default true).
	// Ethernet uses MulticastLoopback for the frames this host sends.
	MulticastTTL      int
	MulticastLoopback *bool
	// ListenAddress overrides the local address a UDP subscriber binds;
	// by default it binds the port of URL (and joins the group if URL is
	// multicast).
	ListenAddress string

	// Properties are the connection properties (KeyValuePairs) of the
	// PubSubConnection, by name, for transport specific options.
	Properties map[string]string

	// MaxMessageSize limits the size of the NetworkMessages the connection
	// sends and receives. Zero selects the transport default: the largest
	// UDP payload (65507 bytes over IPv4, 65527 over IPv6) for UDP, the
	// payload of one frame (1500 bytes or the smaller MTU) for Ethernet,
	// 1 MiB for MQTT. Ethernet does not go above the frame payload.
	MaxMessageSize int

	Logger *slog.Logger
}

// Errors shared by the transports.
var (
	// ErrClosed is returned by the methods of a closed Connection.
	ErrClosed = errors.New("pubsub/transport: connection closed")
	// ErrMessageTooLarge is returned by Send for a payload above
	// MaxMessageSize.
	ErrMessageTooLarge = errors.New("pubsub/transport: message too large")
)

// Opener opens a Connection for one transport.
type Opener func(ctx context.Context, cfg Config) (Connection, error)

var (
	mu      sync.RWMutex
	openers = map[string]Opener{}
)

// Register makes a transport available for a URL scheme ("opc.udp",
// "opc.eth", "mqtt", "mqtts"). It panics if the scheme is registered twice.
func Register(scheme string, open Opener) {
	mu.Lock()
	defer mu.Unlock()
	if _, ok := openers[scheme]; ok {
		panic("pubsub/transport: scheme registered twice: " + scheme)
	}
	openers[scheme] = open
}

// Schemes returns the registered URL schemes.
func Schemes() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(openers))
	for s := range openers {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// Open opens a connection with the transport registered for the scheme of
// cfg.URL.
func Open(ctx context.Context, cfg Config) (Connection, error) {
	scheme, err := Scheme(cfg.URL)
	if err != nil {
		return nil, err
	}
	mu.RLock()
	open := openers[scheme]
	mu.RUnlock()
	if open == nil {
		return nil, fmt.Errorf("pubsub/transport: no transport for %q (registered: %v)", scheme, Schemes())
	}
	return open(ctx, cfg)
}

// Scheme returns the scheme of a transport URL.
func Scheme(url string) (string, error) {
	for i := 0; i < len(url); i++ {
		if url[i] == ':' {
			if i == 0 {
				break
			}
			return url[:i], nil
		}
	}
	return "", fmt.Errorf("pubsub/transport: %q has no scheme", url)
}
