// SPDX-License-Identifier: MIT

// Package transport is the transport layer of OPC UA PubSub (Part 14 §7.3):
// it moves encoded NetworkMessages between publishers and subscribers.
//
// A [Connection] is opened for a PubSubConnection from its transport profile
// and network address. The UDP (opc.udp://, unicast and multicast), MQTT
// (mqtt://, mqtts://) and AMQP (amqp://, amqps://) transports are
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
	ProfileAMQPUADP = "http://opcfoundation.org/UA-Profile/Transport/pubsub-amqp-uadp"
	ProfileAMQPJSON = "http://opcfoundation.org/UA-Profile/Transport/pubsub-amqp-json"
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
}

// Handler receives messages. It is called from the transport's receive
// goroutine and must not block for long.
type Handler func(*Message)

// PublishOptions are the per-message settings of broker transports
// (BrokerWriterGroupTransportDataType / BrokerDataSetWriterTransportDataType).
// Datagram transports ignore them.
type PublishOptions struct {
	// Topic is the queue name. Datagram transports ignore it.
	Topic string
	// QoS is the requested delivery guarantee: 0 at most once (best
	// effort), 1 at least once, 2 exactly once (downgraded to 1).
	QoS byte
	// Retain asks the broker to keep the message for late subscribers
	// (used for metadata). AMQP has no retained messages and ignores it.
	Retain bool
	// ContentType is the MIME type of the message mapping,
	// "application/opcua+uadp" or "application/json" (AMQP content-type,
	// Part 14 B.3.8). Empty: the transport derives it from the profile.
	ContentType string
	// MetaData marks a DataSetMetaData message (AMQP sends it with the
	// subject "ua-metadata", Part 14 Table B.1).
	MetaData bool
	// Properties are the transport settings of the writer group and the
	// dataset writer (WriterGroupProperties, DataSetWriterProperties) that
	// apply to the message, writer before group. AMQP maps the names of
	// Part 14 Table B.2 ("message-to", ...) to message properties and sends
	// the others as application properties; MQTT ignores them.
	Properties map[string]any
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
	// joins the group), mqtt://host:port or mqtts://host:port for MQTT,
	// amqp://host:port or amqps://host:port for AMQP.
	URL string
	// Interface is the network interface for UDP multicast (NetworkInterface
	// of NetworkAddressDataType); empty selects the system default.
	Interface string

	// Broker settings (MQTT and AMQP). ClientID is the AMQP container-id.
	ClientID  string
	Username  string
	Password  string
	TLSConfig *tls.Config
	KeepAlive time.Duration

	// UDP settings: the TTL of multicast datagrams (default 1) and whether
	// this host receives its own multicast datagrams (default true).
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
	// UDP payload (65507 bytes over IPv4, 65527 over IPv6) for UDP, 1 MiB
	// for MQTT and AMQP.
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
// "mqtt", "mqtts", "amqp", "amqps"). It panics if the scheme is registered twice.
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
