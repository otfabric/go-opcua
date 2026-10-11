// SPDX-License-Identifier: MIT

package opcua

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
)

// reverseConfig is the reverse connect configuration of a client.
type reverseConfig struct {
	// listenAddr is the address of the listener the client opens for
	// itself. It is unused when listener is set.
	listenAddr string

	// listener is a listener supplied by the caller, which the client uses
	// but does not own.
	listener *uacp.ReverseListener

	// serverURI is the ServerUri the server must announce. Empty accepts any.
	serverURI string
}

// ReverseConnectOption configures the reverse connect behaviour of a client.
// See [ReverseConnect] and [ReverseConnectListener].
type ReverseConnectOption func(*reverseConfig)

// ReverseServerURI makes the client accept a reverse connection only from
// the server that announces uri as its ServerUri, which is the server's
// ApplicationUri.
//
// It is required to tell servers apart when several of them connect to the
// same listener (see [ReverseConnectListener]) and recommended otherwise.
// Note that the announcement alone proves nothing: see [ReverseConnect].
func ReverseServerURI(uri string) ReverseConnectOption {
	return func(rc *reverseConfig) { rc.serverURI = uri }
}

// ReverseConnect makes the client wait for the server to connect to it
// instead of connecting to the server (OPC UA reverse connect, Part 6
// §7.1.3). It is meant for servers the client cannot reach, for example
// because they sit behind a firewall or NAT, but which can reach the client.
//
// The client listens on listenAddr, a "host:port" address or an
// "opc.tcp://host:port" URL, from the first [Client.Connect] (or
// [Client.Dial]) until [Client.Close]. The server must be configured with the
// address the client is reachable at; see server.WithReverseConnect for a
// server of this module.
//
// The server announces itself with a ReverseHello message that carries its
// ServerUri and the EndpointUrl the client is to use. The client refuses the
// connection, and keeps waiting, unless
//
//   - the ServerUri is the one set with [ReverseServerURI], if any, and
//   - the EndpointUrl denotes the endpoint URL the client was created with
//     (see [NewClient]). A client created with an empty endpoint URL accepts
//     any EndpointUrl and uses it.
//
// A ReverseHello message is not authenticated: anyone who can reach the
// listener can send one with any content. The server is authenticated, as
// always, by its certificate when the secure channel is opened, so use a
// security mode other than None and validate the server certificate. The
// client then also requires the ServerUri to be the ApplicationUri of the
// certificate it is configured with (unless [InsecureSkipVerify] is set).
//
// The time the client waits for the server is bounded by the context passed
// to Connect and by [DialTimeout]. Servers typically retry a reverse
// connection only every few seconds, so the timeout must be long enough to
// cover one such interval. With [AutoReconnect] the client goes back to
// waiting for the server after a connection loss and restores the session
// and the subscriptions as usual.
//
// The discovery helpers [GetEndpoints], [FindServers] and
// [FindServersOnNetwork] accept the option as well. To serve several servers
// or clients with one listener use [ReverseConnectListener].
func ReverseConnect(listenAddr string, opts ...ReverseConnectOption) Option {
	return func(cfg *Config) error {
		if listenAddr == "" {
			return fmt.Errorf("opcua: reverse connect: empty listen address")
		}
		if strings.Contains(listenAddr, "://") {
			if _, _, err := uacp.ParseEndpoint(listenAddr); err != nil {
				return fmt.Errorf("opcua: reverse connect: %w", err)
			}
		} else if _, _, err := net.SplitHostPort(listenAddr); err != nil {
			return fmt.Errorf("opcua: reverse connect: invalid listen address: %w", err)
		}
		rc := &reverseConfig{listenAddr: listenAddr}
		for _, opt := range opts {
			if opt != nil {
				opt(rc)
			}
		}
		cfg.reverse = rc
		return nil
	}
}

// ReverseConnectListener is like [ReverseConnect] but makes the client take
// its reverse connection from l instead of opening a listener of its own.
//
// One listener can be shared by any number of clients, which is how several
// servers are served on a single port: give every client the ServerUri of
// its server with [ReverseServerURI]. The listener hands each incoming
// connection to the client that expects it and keeps a connection nobody is
// waiting for until a client asks for it.
//
// Create the listener with uacp.ListenReverse or, for a net.Listener of your
// own, uacp.NewReverseListener; its configuration bounds the number of
// pending connections and can restrict the servers that are admitted at all.
// The listener is not closed by [Client.Close]: close it yourself once all
// its clients are closed.
func ReverseConnectListener(l *uacp.ReverseListener, opts ...ReverseConnectOption) Option {
	return func(cfg *Config) error {
		if l == nil {
			return fmt.Errorf("opcua: reverse connect: no listener")
		}
		rc := &reverseConfig{listener: l}
		for _, opt := range opts {
			if opt != nil {
				opt(rc)
			}
		}
		cfg.reverse = rc
		return nil
	}
}

// endpoint returns the endpoint URL the client uses for the secure channel
// and the session. It differs from the URL the client was created with only
// for a reverse connection of a client created without one: then it is the
// EndpointUrl the server announced.
func (c *Client) endpoint() string {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	if c.activeEndpoint != "" {
		return c.activeEndpoint
	}
	return c.endpointURL
}

// reverseListener returns the listener the client takes its reverse
// connections from. A client that was not given one opens it on first use.
func (c *Client) reverseListener(ctx context.Context) (*uacp.ReverseListener, error) {
	rc := c.cfg.reverse
	if rc.listener != nil {
		return rc.listener, nil
	}

	c.connMu.Lock()
	defer c.connMu.Unlock()
	if c.ownListener != nil {
		return c.ownListener, nil
	}
	// Close has released the listener and nothing would close a new one.
	if c.mctx.Err() != nil {
		return nil, ua.StatusBadConnectionClosed
	}
	l, err := uacp.ListenReverse(ctx, rc.listenAddr, &uacp.ReverseListenerConfig{
		// The listener serves this client only, so a server the client
		// does not expect is turned away instead of being kept.
		Filter: c.matchReverseHello,
		Logger: c.cfg.logger,
	})
	if err != nil {
		return nil, fmt.Errorf("opcua: reverse connect: %w", err)
	}
	c.ownListener = l
	return l, nil
}

// closeReverseListener closes the listener the client opened for itself.
func (c *Client) closeReverseListener() {
	c.connMu.Lock()
	l := c.ownListener
	c.ownListener = nil
	c.connMu.Unlock()
	if l != nil {
		_ = l.Close()
	}
}

// matchReverseHello reports whether the client accepts a reverse connection
// that was announced with rhe. It only looks at configuration that never
// changes: it is called from the goroutines of the listener.
func (c *Client) matchReverseHello(rhe *uacp.ReverseHello) error {
	if want := c.cfg.reverse.serverURI; want != "" && rhe.ServerURI != want {
		return fmt.Errorf("%w: ServerUri is %q, expected %q: %w",
			errors.ErrReverseHelloRejected, rhe.ServerURI, want, ua.StatusBadServerURIInvalid)
	}
	if want := c.endpointURL; want != "" && rhe.EndpointURL != "" && !sameEndpointURL(rhe.EndpointURL, want) {
		return fmt.Errorf("%w: EndpointUrl is %q, expected %q: %w",
			errors.ErrReverseHelloRejected, rhe.EndpointURL, want, ua.StatusBadTCPEndpointURLInvalid)
	}
	return nil
}

// acceptReverse waits for the server to connect and returns the connection
// together with the endpoint URL to use on it.
func (c *Client) acceptReverse(ctx context.Context) (*uacp.Conn, string, error) {
	l, err := c.reverseListener(ctx)
	if err != nil {
		return nil, "", err
	}

	// Closing the client ends the waiting, also on a listener that is not
	// the client's own and therefore stays open.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(c.mctx, cancel)
	defer stop()

	conn, rhe, err := c.cfg.dialer.AcceptReverse(ctx, l, c.endpointURL, c.matchReverseHello)
	if err != nil {
		if c.mctx.Err() != nil && ctx.Err() != nil {
			return nil, "", ua.StatusBadConnectionClosed
		}
		return nil, "", err
	}
	if err := c.checkReverseServerCertificate(rhe); err != nil {
		_ = conn.Close()
		return nil, "", err
	}

	endpoint := c.endpointURL
	if endpoint == "" {
		endpoint = rhe.EndpointURL
	}
	c.cfg.logger.Debug("reverse connection accepted", "server_uri", rhe.ServerURI, "endpoint", endpoint)
	return conn, endpoint, nil
}

// checkReverseServerCertificate verifies that the server which announced
// itself with rhe claims to be the application the client's server
// certificate was issued to.
//
// The ServerUri of a ReverseHello message is an unauthenticated claim. With
// security the server proves, when the secure channel is opened, that it
// owns the private key of the certificate the client is configured with.
// Requiring the announced ServerUri to be the ApplicationUri of that
// certificate ties the two together, so that a connection announced by one
// application cannot end up being used as the connection to another.
func (c *Client) checkReverseServerCertificate(rhe *uacp.ReverseHello) error {
	sc := c.cfg.sechan
	if sc.SecurityMode == ua.MessageSecurityModeNone || sc.SecurityMode == ua.MessageSecurityModeInvalid {
		return nil
	}
	if c.cfg.certValidator.insecureSkipVerify || len(sc.RemoteCertificate) == 0 {
		return nil
	}
	certs, err := x509.ParseCertificates(sc.RemoteCertificate)
	if err != nil {
		return fmt.Errorf("opcua: reverse connect: server certificate: %w", err)
	}
	if len(certs) == 0 {
		return nil
	}
	for _, u := range certs[0].URIs {
		if u.String() == rhe.ServerURI {
			return nil
		}
	}
	return fmt.Errorf("%w: ServerUri %q is not the ApplicationUri of the server certificate %v",
		errors.ErrReverseHelloRejected, rhe.ServerURI, certs[0].URIs)
}

// reverseOptions returns the options that make another client use the same
// reverse connect configuration as c, sharing its listener.
func (c *Client) reverseOptions(ctx context.Context) ([]Option, error) {
	rc := c.cfg.reverse
	if rc == nil {
		return nil, nil
	}
	l, err := c.reverseListener(ctx)
	if err != nil {
		return nil, err
	}
	opts := []Option{ReverseConnectListener(l, ReverseServerURI(rc.serverURI))}
	if d := c.cfg.dialer.Dialer; d != nil {
		opts = append(opts, DialTimeout(d.Timeout))
	}
	return opts, nil
}

// sameEndpointURL reports whether two endpoint URLs denote the same
// endpoint: the same scheme, host (ignoring case), port (4840 if absent)
// and path (ignoring a trailing slash). URLs that cannot be parsed are
// compared as strings.
func sameEndpointURL(a, b string) bool {
	if a == b {
		return true
	}
	x, errA := url.Parse(a)
	y, errB := url.Parse(b)
	if errA != nil || errB != nil {
		return false
	}
	port := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			return p
		}
		return "4840"
	}
	return strings.EqualFold(x.Scheme, y.Scheme) &&
		strings.EqualFold(x.Hostname(), y.Hostname()) &&
		port(x) == port(y) &&
		strings.TrimSuffix(x.Path, "/") == strings.TrimSuffix(y.Path, "/")
}
