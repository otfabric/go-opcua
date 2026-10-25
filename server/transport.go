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
		s.wss.endpoints = append(s.wss.endpoints, fmt.Sprintf("%s://%s", uacp.SchemeWebSocket, net.JoinHostPort(host, fmt.Sprint(port))))
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
		s.https.endpoints = append(s.https.endpoints, fmt.Sprintf("%s://%s", uasc.SchemeHTTPS, net.JoinHostPort(host, fmt.Sprint(port))))
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
	cfg, err := s.cfg.transportTLS()
	if err != nil {
		return err
	}
	if addr, err := s.cfg.wss.bindAddr(); err != nil {
		return err
	} else if addr != "" {
		if s.wl, err = uacp.ListenWebSocket(ctx, uacp.SchemeWebSocket+"://"+addr, cfg, nil); err != nil {
			return err
		}
		s.cfg.wss.applyPort(s.wl.Addr())
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
	if s.hs != nil {
		s.hs.close()
	}
}

// transportEndpoints returns the endpoint URLs of each transport with their
// transport profile.
func (s *Server) transportEndpoints() []struct {
	urls    []string
	profile string
} {
	return []struct {
		urls    []string
		profile string
	}{
		{s.cfg.endpoints, ua.TransportProfileUATCP},
		{s.cfg.wss.endpoints, ua.TransportProfileWSS},
		{s.cfg.https.endpoints, ua.TransportProfileHTTPS},
	}
}
