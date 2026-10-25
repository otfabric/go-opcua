// SPDX-License-Identifier: MIT

package uacp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/internal/websocket"
)

// The WebSocket transport of the OPC UA Connection Protocol (Part 6 §7.5):
// the UACP messages and the secure conversation on top of them travel in
// binary WebSocket frames over TLS, one MessageChunk per frame. The HEL/ACK
// handshake runs after the WebSocket opening handshake, as on TCP.
const (
	// SchemeWebSocket is the URL scheme of WebSocket endpoints.
	SchemeWebSocket = "opc.wss"

	// WebSocketSubprotocol is the WebSocket sub-protocol that carries UACP
	// (Part 6 §7.5.2).
	WebSocketSubprotocol = "opcua+uacp"

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

// dialWebSocket opens the TLS connection to the host of an opc.wss endpoint
// and upgrades it to a WebSocket with the sub-protocol opcua+uacp.
func (d *Dialer) dialWebSocket(ctx context.Context, dl *net.Dialer, endpoint string) (net.Conn, error) {
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
	ws, err := websocket.Client(ctx, tc, u, websocket.ClientOptions{Subprotocols: []string{WebSocketSubprotocol}})
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
// and ClientCAs in tlsConfig to require client TLS certificates.
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
		ws, _, err := websocket.Accept(tc, websocket.ServerOptions{Subprotocols: []string{WebSocketSubprotocol}})
		if err != nil {
			return nil, fmt.Errorf("uacp: WebSocket upgrade: %w", err)
		}
		return ws, nil
	}
	return l, nil
}
