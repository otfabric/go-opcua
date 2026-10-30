// SPDX-License-Identifier: MIT

package transport

import (
	"context"
	"crypto/tls"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/stretchr/testify/require"
)

// transportServer starts a server with the fixture and an opc.tcp, an
// opc.wss and an opc.https endpoint on ports of their own. It returns the URL
// of each.
func transportServer(t *testing.T, opts ...server.Option) (*testutil.Fixture, *server.Server, map[string]string) {
	t.Helper()
	parallel(t)
	srv, err := server.New(append([]server.Option{
		server.EndPoint("localhost", 0),
		server.WebSocketEndPoint("localhost", 0),
		server.HTTPSEndPoint("localhost", 0),
		server.TLSConfig(testutil.TLS(t).ServerConfig()),
		server.InsecureNoSecurity(),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
	}, opts...)...)
	require.NoError(t, err)
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })
	f := testutil.AddFixture(t, srv)

	urls := map[string]string{}
	for _, u := range srv.URLs() {
		urls[ua.TransportProfileForURL(u)] = u
	}
	require.Len(t, urls, 3, "%v", srv.URLs())
	for _, u := range urls {
		require.NotContains(t, u, ":0", "advertised URLs carry the bound port")
	}
	return f, srv, urls
}

// tlsClient returns the client option that trusts the test TLS CA.
func tlsClient(t *testing.T) opcua.Option {
	t.Helper()
	return opcua.TLSConfig(testutil.TLS(t).ClientConfig())
}

// hostPort returns the host:port of an endpoint URL.
func hostPort(t *testing.T, endpoint string) string {
	t.Helper()
	u, err := url.Parse(endpoint)
	require.NoError(t, err)
	return u.Host
}

// exerciseSession reads, writes, browses, reads a value large enough for
// several chunks and calls a method.
func exerciseSession(t *testing.T, c *opcua.Client, f *testutil.Fixture, tag string) {
	t.Helper()
	ctx := context.Background()
	st, err := c.WriteNodeValue(ctx, f.String, tag)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, st)
	dv, err := c.ReadValue(ctx, f.String)
	require.NoError(t, err)
	require.Equal(t, tag, dv.Value.Value())

	ids := make([]*ua.NodeID, 600)
	for i := range ids {
		ids[i] = f.Int32Array
	}
	dvs, err := c.ReadValues(ctx, ids...)
	require.NoError(t, err)
	require.Len(t, dvs, len(ids))

	refs, err := c.Node(ua.NewNumericNodeID(0, 85)).ReferencedNodes(ctx, 33, ua.BrowseDirectionForward, ua.NodeClassAll, true)
	require.NoError(t, err)
	require.NotEmpty(t, refs)

	res, err := c.CallMethod(ctx, f.MethodObject, f.SquareMethod, int32(12))
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, res.StatusCode)
	require.Equal(t, int32(144), res.OutputArguments[0].Value())
}

// TestTransportWSS_EndpointsAdvertised checks that every enabled policy and
// mode is offered over opc.wss with the WebSocket transport profile, and that
// the endpoints of a transport are found by their profile.
func TestTransportWSS_EndpointsAdvertised(t *testing.T) {
	_, _, urls := transportServer(t, secureServerOpts(t)...)
	ctx := context.Background()

	eps, err := opcua.GetEndpoints(ctx, urls[ua.TransportProfileWSS], tlsClient(t))
	require.NoError(t, err)
	// The request URL matches the opc.wss endpoints: only they are returned.
	require.Len(t, eps, 1+len(securePolicies)*len(secureModes))
	for _, ep := range eps {
		require.Equal(t, ua.TransportProfileWSS, ep.TransportProfileURI)
		require.Equal(t, urls[ua.TransportProfileWSS], ep.EndpointURL)
	}

	// A GetEndpoints request whose URL matches nothing returns the endpoints
	// of all transports; SelectEndpoint keeps to opc.tcp and
	// SelectEndpointForTransport picks the asked transport.
	c := newClient(t, urls[ua.TransportProfileUATCP])
	var resp *ua.GetEndpointsResponse
	err = c.Send(ctx, &ua.GetEndpointsRequest{EndpointURL: "opc.tcp://other-name:4840"}, func(r ua.Response) error {
		resp = r.(*ua.GetEndpointsResponse)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, resp.Endpoints, 3+2*len(securePolicies)*len(secureModes)+len(securePolicies))

	ep, err := opcua.SelectEndpoint(resp.Endpoints, "None", ua.MessageSecurityModeNone, nil)
	require.NoError(t, err)
	require.Equal(t, ua.TransportProfileUATCP, ep.TransportProfileURI)
	for _, profile := range []string{ua.TransportProfileWSS, ua.TransportProfileHTTPS} {
		ep, err = opcua.SelectEndpointForTransport(resp.Endpoints, profile, "None", ua.MessageSecurityModeNone, nil)
		require.NoError(t, err)
		require.Equal(t, profile, ep.TransportProfileURI)
		require.Equal(t, urls[profile], ep.EndpointURL)
	}
	_, err = opcua.SelectEndpointForTransport(resp.Endpoints, "urn:no-such-profile", "", ua.MessageSecurityModeInvalid, nil)
	require.Error(t, err)
}

// TestTransportWSS_PolicyModeMatrix runs a session with every security
// policy and mode over opc.wss: the secure conversation is the same as on
// opc.tcp, inside TLS.
func TestTransportWSS_PolicyModeMatrix(t *testing.T) {
	f, _, urls := transportServer(t, secureServerOpts(t)...)
	wss := urls[ua.TransportProfileWSS]

	exerciseSession(t, newClient(t, wss, tlsClient(t)), f, "wss-None")
	for _, pol := range securePolicies {
		for _, mode := range secureModes {
			t.Run(shortPolicy(pol)+"/"+mode.String(), func(t *testing.T) {
				ep := endpointForTLS(t, wss, pol, mode)
				c := newClient(t, wss, append(secureClientOpts(t, ep, ua.UserTokenTypeAnonymous), tlsClient(t))...)
				require.Equal(t, pol, c.SecurityPolicy())
				require.Equal(t, mode, c.SecurityMode())
				exerciseSession(t, c, f, "wss-"+shortPolicy(pol)+"-"+mode.String())
			})
		}
	}
}

// endpointForTLS is endpointFor for an opc.wss or opc.https URL.
func endpointForTLS(t *testing.T, endpoint, policyURI string, mode ua.MessageSecurityMode) *ua.EndpointDescription {
	t.Helper()
	eps, err := opcua.GetEndpoints(context.Background(), endpoint, tlsClient(t))
	require.NoError(t, err)
	for _, ep := range eps {
		if ep.SecurityPolicyURI == policyURI && ep.SecurityMode == mode {
			return ep
		}
	}
	t.Fatalf("%s does not advertise %s / %s", endpoint, policyURI, mode)
	return nil
}

// TestTransportWSS_Subscription checks Publish over a WebSocket.
func TestTransportWSS_Subscription(t *testing.T) {
	f, _, urls := transportServer(t)
	ctx := context.Background()
	c := newClient(t, urls[ua.TransportProfileWSS], tlsClient(t))

	sub, ch, err := c.NewSubscription().Interval(fastInterval).Monitor(f.Int32).Start(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(ctx) })
	awaitValue(t, ch, 0, int32(42))
	writeInt32(t, c, f.Int32, 4711)
	awaitValue(t, ch, 0, int32(4711))
}

// TestTransportWSS_TLSTrust checks the TLS layer: the server's TLS
// certificate is verified against the configured roots, and a server that
// requires client TLS certificates refuses clients without one.
func TestTransportWSS_TLSTrust(t *testing.T) {
	pkiTLS := testutil.TLS(t)
	strict := pkiTLS.ServerConfig()
	strict.ClientAuth = tls.RequireAndVerifyClientCert
	strict.ClientCAs = pkiTLS.Roots
	_, _, urls := transportServer(t, server.TLSConfig(strict))
	wss := urls[ua.TransportProfileWSS]

	// The system roots do not know the test CA.
	_, err := dialClient(t, wss)
	require.ErrorContains(t, err, "TLS handshake")

	// Trusted server, but no client certificate.
	_, err = dialClient(t, wss, tlsClient(t))
	require.Error(t, err)

	withCert := pkiTLS.ClientConfig()
	withCert.Certificates = []tls.Certificate{pkiTLS.Client}
	c := newClient(t, wss, opcua.TLSConfig(withCert))
	_, err = c.ReadValue(context.Background(), ua.NewNumericNodeID(0, 2258))
	require.NoError(t, err)

	// A client TLS certificate the server does not trust.
	stranger := pkiTLS.ClientConfig()
	stranger.Certificates = []tls.Certificate{pkiTLS.Stranger}
	_, err = dialClient(t, wss, opcua.TLSConfig(stranger))
	require.Error(t, err)

	// A Dialer with a TLS configuration of its own keeps it.
	d := &uacp.Dialer{TLSConfig: withCert}
	newClient(t, wss, opcua.Dialer(d), opcua.TLSConfig(stranger))
}

// TestTransportWSS_Reconnect drops the WebSocket connection under a running
// subscription: the client reconnects and the subscription delivers again.
func TestTransportWSS_Reconnect(t *testing.T) {
	f, _, urls := transportServer(t)
	ctx := context.Background()
	proxy := testutil.NewChaosProxy(t, hostPort(t, urls[ua.TransportProfileWSS]), 1)
	via := strings.Replace(urls[ua.TransportProfileWSS], hostPort(t, urls[ua.TransportProfileWSS]), proxy.Addr(), 1)
	via = strings.Replace(via, "127.0.0.1", "localhost", 1)

	states := make(chan opcua.ConnState, 32)
	c := newClient(t, via, tlsClient(t), opcua.AutoReconnect(true), opcua.ReconnectInterval(50*time.Millisecond),
		opcua.WithConnStateChan(states))
	sub, ch, err := c.NewSubscription().Interval(fastInterval).Monitor(f.Int32).Start(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(ctx) })
	awaitValue(t, ch, 0, int32(42))

	proxy.DropAll()
	awaitState(t, states, opcua.Reconnecting)
	awaitState(t, states, opcua.Connected)

	writer := newClient(t, urls[ua.TransportProfileUATCP])
	writeInt32(t, writer, f.Int32, 99)
	awaitValue(t, ch, 0, int32(99))
}

// awaitState waits until the client reports state.
func awaitState(t *testing.T, states <-chan opcua.ConnState, want opcua.ConnState) {
	t.Helper()
	deadline := time.After(waitTimeout)
	for {
		select {
		case s := <-states:
			if s == want {
				return
			}
		case <-deadline:
			t.Fatalf("client did not reach state %s", want)
		}
	}
}

// TestTransportWSS_ServerStartErrors checks the configuration errors of the
// WebSocket and HTTPS listeners.
func TestTransportWSS_ServerStartErrors(t *testing.T) {
	parallel(t)
	// No TLS certificate and no application instance certificate.
	srv, err := server.New(server.InsecureNoSecurity(), server.EndPoint("localhost", 0), server.WebSocketEndPoint("localhost", 0))
	require.NoError(t, err)
	require.Error(t, srv.Start(context.Background()))

	// Without TLSConfig the application instance certificate serves TLS.
	p := pki(t)
	srv, err = server.New(server.EndPoint("localhost", 0), server.HTTPSEndPoint("localhost", 0),
		server.Certificate(p.ServerCert), server.PrivateKey(p.ServerKey),
		server.InsecureNoSecurity(), server.EnableAuthMode(ua.UserTokenTypeAnonymous))
	require.NoError(t, err)
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })
	var httpsURL string
	for _, u := range srv.URLs() {
		if ua.TransportProfileForURL(u) == ua.TransportProfileHTTPS {
			httpsURL = u
		}
	}
	require.NotEmpty(t, httpsURL)
	_, err = dialClient(t, httpsURL, opcua.TLSConfig(&tls.Config{RootCAs: certPool(p.ServerCertX509)}))
	require.NoError(t, err)

	// A bind address that is in use.
	busy, err := server.New(server.InsecureNoSecurity(), server.EndPoint("localhost", 0), server.ListenWebSocketOn(hostPort(t, httpsURL)),
		server.WebSocketEndPoint("localhost", 1), server.TLSConfig(testutil.TLS(t).ServerConfig()))
	require.NoError(t, err)
	require.Error(t, busy.Start(context.Background()))
	busy, err = server.New(server.InsecureNoSecurity(), server.EndPoint("localhost", 0), server.ListenHTTPSOn(hostPort(t, httpsURL)),
		server.HTTPSEndPoint("localhost", 1), server.TLSConfig(testutil.TLS(t).ServerConfig()))
	require.NoError(t, err)
	require.Error(t, busy.Start(context.Background()))
}
