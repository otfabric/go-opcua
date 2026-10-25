// SPDX-License-Identifier: MIT

package uacp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/internal/websocket"
)

// The WebSocket transport of the OPC UA Connection Protocol (Part 6 §7.5):
// the UACP messages and the secure conversation on top of them travel in
// binary WebSocket frames over TLS, one MessageChunk per frame. The HEL/ACK
// handshake runs after the WebSocket opening handshake, as on TCP.
//
// The sub-protocol opcua+uajson (transport profile wss-uajson) carries no
// UACP: each WebSocket message is one service request or response in the
// JSON encoding (Part 6 §7.5.2, §5.4.9), there is neither a HEL/ACK nor a
// secure conversation, and TLS alone protects the messages. Such connections
// are MessageConns.
const (
	// SchemeWebSocket is the URL scheme of WebSocket endpoints.
	SchemeWebSocket = "opc.wss"

	// WebSocketSubprotocol is the WebSocket sub-protocol that carries UACP
	// (Part 6 §7.5.2).
	WebSocketSubprotocol = "opcua+uacp"

	// WebSocketJSONSubprotocol is the WebSocket sub-protocol that carries
	// service messages in the JSON encoding (Part 6 §7.5.2).
	WebSocketJSONSubprotocol = "opcua+uajson"

	// defaultWebSocketPort is the port of an opc.wss URL without one: the
	// HTTPS port, since the connection starts as an HTTPS request.
	defaultWebSocketPort = "443"
)

// IsWebSocketEndpoint reports whether endpoint is an opc.wss URL.
func IsWebSocketEndpoint(endpoint string) bool {
	scheme, _, ok := strings.Cut(endpoint, "://")
	return ok && strings.EqualFold(scheme, SchemeWebSocket)
}

// ParseWebSocketEndpoint parses and validates an opc.wss endpoint URL like
// ParseEndpoint does for opc.tcp. The Host of the returned URL is in
// host:port form; the port defaults to 443.
func ParseWebSocketEndpoint(endpoint string) (*url.URL, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errors.ErrInvalidEndpoint, err)
	}
	if !strings.EqualFold(u.Scheme, SchemeWebSocket) {
		return nil, fmt.Errorf("%w: unsupported scheme %q", errors.ErrInvalidEndpoint, u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("%w: missing host", errors.ErrInvalidEndpoint)
	}
	port := u.Port()
	if port == "" {
		port = defaultWebSocketPort
	} else if err := validatePort(port); err != nil {
		return nil, err
	}
	u.Host = net.JoinHostPort(host, port)
	return u, nil
}

// transportTLS returns a copy of cfg for the WebSocket transport: at least
// TLS 1.2 and HTTP/1.1, the protocol the WebSocket upgrade is made in.
func transportTLS(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		cfg = &tls.Config{}
	}
	cfg = cfg.Clone()
	if cfg.MinVersion < tls.VersionTLS12 {
		cfg.MinVersion = tls.VersionTLS12
	}
	cfg.NextProtos = []string{"http/1.1"}
	return cfg
}

// MessageConn is a WebSocket connection with the sub-protocol opcua+uajson,
// which carries whole messages instead of a byte stream.
type MessageConn interface {
	// ReadMessage reads the next message. A message larger than maxSize
	// bytes ends the connection with WebSocket status 1009 (Part 6 §7.5.2).
	// It must not be called from two goroutines at once.
	ReadMessage(maxSize int64) ([]byte, error)
	// WriteMessage sends p as one text message. It may be called
	// concurrently.
	WriteMessage(p []byte) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	RemoteAddr() net.Addr
	Close() error
}

// messageConn is the MessageConn of a WebSocket.
type messageConn struct{ *websocket.Conn }

func (c messageConn) WriteMessage(p []byte) error { return c.WriteText(p) }

// DialWebSocketJSON opens a TLS secured WebSocket with the sub-protocol
// opcua+uajson to an opc.wss endpoint (Part 6 §7.5.2), with the TLS
// configuration and the dial timeout of d, which covers TLS and the
// WebSocket upgrade. There is no HEL/ACK on such a connection.
func (d *Dialer) DialWebSocketJSON(ctx context.Context, endpoint string) (MessageConn, error) {
	dl := d.Dialer
	if dl == nil {
		dl = defaultNetDialer()
	}
	if dl.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, dl.Timeout)
		defer cancel()
	}
	ws, err := d.dialWebSocket(ctx, dl, endpoint, WebSocketJSONSubprotocol)
	if err != nil {
		return nil, err
	}
	return messageConn{ws}, nil
}

// dialWebSocket opens the TLS connection to the host of an opc.wss endpoint
// and upgrades it to a WebSocket with the sub-protocol subprotocol.
func (d *Dialer) dialWebSocket(ctx context.Context, dl *net.Dialer, endpoint, subprotocol string) (*websocket.Conn, error) {
	u, err := ParseWebSocketEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	raw, err := dl.DialContext(ctx, "tcp", u.Host)
	if err != nil {
		return nil, err
	}
	cfg := transportTLS(d.TLSConfig)
	if cfg.ServerName == "" {
		cfg.ServerName = u.Hostname()
	}
	tc := tls.Client(raw, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("uacp: TLS handshake with %s: %w", u.Host, err)
	}
	ws, err := websocket.Client(ctx, tc, u, websocket.ClientOptions{Subprotocols: []string{subprotocol}})
	if err != nil {
		_ = tc.Close()
		return nil, fmt.Errorf("uacp: WebSocket upgrade at %s: %w", endpoint, err)
	}
	return ws, nil
}

// ListenWebSocket listens for OPC UA WebSocket connections (Part 6 §7.5) on
// the host and port of an opc.wss endpoint URL. Each accepted connection is
// secured with TLS using tlsConfig, which must hold the server's TLS
// certificate (it may differ from the application instance certificate,
// Part 6 §7.5.3), upgraded to a WebSocket with the sub-protocol opcua+uacp
// and then goes through the HEL/ACK handshake. Accept returns connections
// that completed all three. TLS 1.2 is the minimum version; set ClientAuth
// and ClientCAs in tlsConfig to require client TLS certificates. With
// ServeWebSocketJSON the listener also accepts the sub-protocol opcua+uajson.
func ListenWebSocket(ctx context.Context, endpoint string, tlsConfig *tls.Config, ack *Acknowledge) (*Listener, error) {
	u, err := ParseWebSocketEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	if tlsConfig == nil || (len(tlsConfig.Certificates) == 0 && tlsConfig.GetCertificate == nil && tlsConfig.GetConfigForClient == nil) {
		return nil, fmt.Errorf("%w: a WebSocket listener needs a TLS certificate", errors.ErrInvalidSecurityConfig)
	}
	l, err := listen(ctx, u.Host, endpoint, ack)
	if err != nil {
		return nil, err
	}
	cfg := transportTLS(tlsConfig)
	l.upgrade = func(c *net.TCPConn) (net.Conn, error) {
		tc := tls.Server(c, cfg)
		if err := tc.Handshake(); err != nil {
			return nil, fmt.Errorf("uacp: TLS handshake: %w", err)
		}
		protocols := []string{WebSocketSubprotocol}
		if l.jsonHandler.Load() != nil {
			protocols = append(protocols, WebSocketJSONSubprotocol)
		}
		ws, _, err := websocket.Accept(tc, websocket.ServerOptions{Subprotocols: protocols})
		if err != nil {
			return nil, fmt.Errorf("uacp: WebSocket upgrade: %w", err)
		}
		return ws, nil
	}
	return l, nil
}

// ServeWebSocketJSON makes a WebSocket listener accept the sub-protocol
// opcua+uajson next to opcua+uacp (Part 6 §7.5.2): a connection that
// selects it skips the HEL/ACK handshake and is handed to h in a goroutine
// of its own instead of being returned by Accept. h owns the connection and
// closes it. Call it before the first Accept; it has no effect on an opc.tcp
// listener.
func (l *Listener) ServeWebSocketJSON(h func(MessageConn)) {
	l.jsonHandler.Store(&h)
}

// handOver hands nc to the opcua+uajson handler if it is a WebSocket with
// that sub-protocol, and reports whether it did.
func (l *Listener) handOver(nc net.Conn) bool {
	ws, ok := nc.(*websocket.Conn)
	if !ok || ws.Subprotocol() != WebSocketJSONSubprotocol {
		return false
	}
	h := l.jsonHandler.Load()
	if h == nil {
		return false
	}
	// The handshake deadline ends here: h sets its own.
	_ = ws.SetDeadline(time.Time{})
	go (*h)(messageConn{ws})
	return true
}
