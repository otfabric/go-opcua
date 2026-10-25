// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/otfabric/go-opcua/uasc"
)

// transportConfig holds the endpoints of the WebSocket or HTTPS transport.
type transportConfig struct {
	endpoints []string // advertised endpoint URLs
	listen    string   // bind address host:port, "" for that of endpoints[0]
}

// bindAddr returns the TCP address the transport listens on, "" if it has
// no endpoints.
func (t *transportConfig) bindAddr() (string, error) {
	if t.listen != "" {
		return t.listen, nil
	}
	if len(t.endpoints) == 0 {
		return "", nil
	}
	u, err := url.Parse(t.endpoints[0])
	if err != nil {
		return "", fmt.Errorf("%w: %v", errors.ErrInvalidEndpoint, err)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(u.Hostname(), port), nil
}

// applyPort rewrites the endpoint URLs without a concrete port to the port
// the transport is bound to.
func (t *transportConfig) applyPort(addr net.Addr) {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		return
	}
	for i, ep := range t.endpoints {
		t.endpoints[i] = rewriteOPCURLPort(ep, tcp.Port)
	}
}

// WebSocketEndPoint adds an opc.wss endpoint at host and port: OPC UA
// Secure Conversation and UA Binary over a TLS secured WebSocket with the
// sub-protocol opcua+uacp (Part 6 §7.5, transport profile wss-uasc-uabinary).
// The server listens for WebSocket connections on the first one, next to the
// opc.tcp listener, unless ListenWebSocketOn says otherwise. Port 0 picks a
// free port. All the security policies and modes enabled on the server are
// offered, as on opc.tcp. The TLS certificate is set with TLSConfig.
func WebSocketEndPoint(host string, port int) Option {
	return func(s *serverConfig) error {
		s.wss.endpoints = append(s.wss.endpoints, endpointURL(uacp.SchemeWebSocket, host, port))
		return nil
	}
}

// ListenWebSocketOn sets the TCP address the WebSocket transport binds to
// (e.g. "0.0.0.0:4843"), as ListenOn does for opc.tcp.
func ListenWebSocketOn(addr string) Option {
	return func(s *serverConfig) error {
		s.wss.listen = addr
		return nil
	}
}

// HTTPSEndPoint adds an opc.https endpoint at host and port: UA Binary over
// HTTPS (Part 6 §7.4, transport profile https-uabinary). Every request is an
// HTTP POST; there is no secure conversation, TLS protects the messages and
// the security policy only decides how the session nonces are signed. It
// offers each enabled security policy that does not need a secure
// conversation (see uasc.HTTPSPolicySupported) with the modes enabled for
// it. The server listens on the first HTTPS endpoint unless ListenHTTPSOn
// says otherwise; port 0 picks a free port. The TLS certificate is set with
// TLSConfig.
func HTTPSEndPoint(host string, port int) Option {
	return func(s *serverConfig) error {
		s.https.endpoints = append(s.https.endpoints, endpointURL(uasc.SchemeHTTPS, host, port))
		return nil
	}
}

// ListenHTTPSOn sets the TCP address the HTTPS transport binds to (e.g.
// "0.0.0.0:4843"), as ListenOn does for opc.tcp.
func ListenHTTPSOn(addr string) Option {
	return func(s *serverConfig) error {
		s.https.listen = addr
		return nil
	}
}

// EnableUAJSON makes the opc.wss and opc.https endpoints serve the UA JSON
// mappings of their transports as well:
//
//   - https-uajson (Part 6 §7.4.5): an HTTPS request with the Content-Type
//     application/json (or application/opcua+uajson, which UA-.NETStandard
//     sends) is a JSON message (Part 6 §5.4.9), answered by one, and may be
//     gzip compressed. The security policies are those of https-uabinary.
//   - wss-uajson (Part 6 §7.5.2): a WebSocket with the sub-protocol
//     opcua+uajson carries one JSON message per WebSocket message, with no
//     HEL/ACK and no secure conversation. Its requests are served
//     concurrently and answered as they complete; a client correlates them
//     by RequestHandle. A WebSocket cannot name a security policy, so it is
//     only offered when None with the mode None is enabled (or no security
//     is configured at all), and TLS alone protects the messages.
//
// The JSON endpoints are advertised next to the binary ones, at the same
// URLs, with the transport profiles ua.TransportProfileHTTPSJSON and
// ua.TransportProfileWSSJSON. Responses are written in the compact JSON
// form; requests may use the compact or the verbose form.
func EnableUAJSON() Option {
	return func(s *serverConfig) error {
		s.uajson = true
		return nil
	}
}

// TLSConfig sets the TLS configuration of the opc.wss and opc.https
// endpoints: the server's TLS certificate (Certificates or GetCertificate)
// and, to require client TLS certificates, ClientAuth and ClientCAs. The TLS
// certificate may differ from the application instance certificate (Part 6
// §7.5.3); without this option the RSA application instance certificate and
// its key are used. TLS 1.2 is the minimum version whatever cfg says.
func TLSConfig(cfg *tls.Config) Option {
	return func(s *serverConfig) error {
		s.tlsConfig = cfg
		return nil
	}
}

// transportTLS returns the TLS configuration of the WebSocket and HTTPS
// listeners.
func (s *serverConfig) transportTLS() (*tls.Config, error) {
	if s.tlsConfig != nil {
		cfg := s.tlsConfig.Clone()
		if cfg.MinVersion < tls.VersionTLS12 {
			cfg.MinVersion = tls.VersionTLS12
		}
		return cfg, nil
	}
	if len(s.certificate) == 0 || s.privateKey == nil {
		return nil, fmt.Errorf("%w: opc.wss and opc.https endpoints need a TLS certificate (TLSConfig) or an application instance certificate", errors.ErrInvalidSecurityConfig)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{s.certificate}, PrivateKey: s.privateKey}},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// listenTransports opens the listeners of the WebSocket and HTTPS
// transports and rewrites their endpoint URLs to the bound ports. Serving
// starts with serveTransports.
func (s *Server) listenTransports(ctx context.Context) error {
	if len(s.cfg.wss.endpoints) == 0 && len(s.cfg.https.endpoints) == 0 {
		return nil
	}
	var cfg *tls.Config
	if m := s.push; m != nil && m.https.Load() != nil {
		// The certificate of the DefaultHttpsGroup, which ApplyChanges can
		// replace.
		base := s.cfg.tlsConfig
		if base == nil {
			base = &tls.Config{}
		}
		cfg = m.tlsConfig(base)
		if cfg.MinVersion < tls.VersionTLS12 {
			cfg.MinVersion = tls.VersionTLS12
		}
	} else {
		var err error
		if cfg, err = s.cfg.transportTLS(); err != nil {
			return err
		}
		if m := s.push; m != nil {
			cfg = m.tlsConfig(cfg)
		}
	}
	if addr, err := s.cfg.wss.bindAddr(); err != nil {
		return err
	} else if addr != "" {
		if s.wl, err = uacp.ListenWebSocket(ctx, uacp.SchemeWebSocket+"://"+addr, cfg, nil); err != nil {
			return err
		}
		s.cfg.wss.applyPort(s.wl.Addr())
		if s.wssJSONEnabled() {
			s.wj = newWSSJSONServer(s)
		}
	}
	if addr, err := s.cfg.https.bindAddr(); err != nil {
		s.closeTransports()
		return err
	} else if addr != "" {
		if s.hs, err = newHTTPSServer(ctx, s, addr, cfg); err != nil {
			s.closeTransports()
			return err
		}
		s.cfg.https.applyPort(s.hs.ln.Addr())
	}
	return nil
}

// serveTransports starts serving the WebSocket and HTTPS listeners.
func (s *Server) serveTransports(ctx context.Context) {
	if s.wj != nil {
		s.wj.start()
		s.wl.ServeWebSocketJSON(s.wj.serve)
	}
	if s.wl != nil {
		go s.acceptAndRegister(ctx, s.wl)
	}
	if s.hs != nil {
		s.hs.start()
	}
}

// closeTransports closes the WebSocket and HTTPS listeners. The HTTPS
// requests in flight are ended and waited for.
func (s *Server) closeTransports() {
	if s.wl != nil {
		_ = s.wl.Close()
	}
	if s.wj != nil {
		s.wj.close()
	}
	if s.hs != nil {
		s.hs.close()
	}
}

// transportURLs are the endpoint URLs of a transport profile.
type transportURLs struct {
	urls    []string
	profile string
}

// transportEndpoints returns the endpoint URLs of each transport with their
// transport profile.
func (s *Server) transportEndpoints() []transportURLs {
	t := []transportURLs{
		{s.cfg.endpoints, ua.TransportProfileUATCP},
		{s.cfg.wss.endpoints, ua.TransportProfileWSS},
		{s.cfg.https.endpoints, ua.TransportProfileHTTPS},
	}
	if s.cfg.uajson {
		// The JSON twins, at the same URLs.
		if s.wssJSONEnabled() {
			t = append(t, transportURLs{s.cfg.wss.endpoints, ua.TransportProfileWSSJSON})
		}
		t = append(t, transportURLs{s.cfg.https.endpoints, ua.TransportProfileHTTPSJSON})
	}
	return t
}

// wssJSONEnabled reports whether the opc.wss endpoints serve wss-uajson:
// EnableUAJSON, and the security policy None with the mode None, the only
// security opcua+uajson has (or no security configured at all).
func (s *Server) wssJSONEnabled() bool {
	if !s.cfg.uajson || len(s.cfg.wss.endpoints) == 0 {
		return false
	}
	if len(s.cfg.enabledSec) == 0 {
		return true
	}
	for _, sec := range s.cfg.enabledSec {
		if sec.secPolicy == ua.SecurityPolicyURINone && sec.secMode == ua.MessageSecurityModeNone {
			return true
		}
	}
	return false
}

// tlsOnly reports whether a transport profile has no secure conversation:
// TLS alone protects its messages.
func tlsOnly(profile string) bool {
	switch profile {
	case ua.TransportProfileHTTPS, ua.TransportProfileHTTPSJSON, ua.TransportProfileWSSJSON:
		return true
	}
	return false
}

// WebSocketAddr returns the address the opc.wss listener is bound to, nil
// before Start or without a WebSocket endpoint.
func (s *Server) WebSocketAddr() net.Addr {
	if s == nil || s.wl == nil {
		return nil
	}
	return s.wl.Addr()
}

// HTTPSAddr returns the address the opc.https listener is bound to, nil
// before Start or without an HTTPS endpoint.
func (s *Server) HTTPSAddr() net.Addr {
	if s == nil || s.hs == nil {
		return nil
	}
	return s.hs.ln.Addr()
}
