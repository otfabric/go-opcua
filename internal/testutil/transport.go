// SPDX-License-Identifier: MIT

package testutil

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// TransportURLs are the endpoint URLs of a server started with
// NewTransportTestServer, one per transport.
type TransportURLs struct {
	TCP, WSS, HTTPS string
}

// JSONTransportTestClient connects a client to the UA JSON mapping
// (ua.TransportProfileHTTPSJSON or ua.TransportProfileWSSJSON) of url with
// security None, trusting the TLS CA of the test PKI.
func JSONTransportTestClient(t *testing.T, url, profile string, opts ...opcua.Option) *opcua.Client {
	t.Helper()
	return NewTransportTestClient(t, url, append([]opcua.Option{opcua.TransportProfile(profile)}, opts...)...)
}

// TLS returns the TLS PKI of the test binary.
func TLS(t *testing.T) *testpki.TLSPKI {
	t.Helper()
	p, err := testpki.TLS()
	if err != nil {
		t.Fatalf("testutil: TLS PKI: %v", err)
	}
	return p
}

// NewTransportTestServer starts a server with an opc.tcp, an opc.wss and an
// opc.https endpoint on localhost, each on a port of its own, with the TLS
// server certificate of the test PKI. Without options it offers None and
// anonymous access only.
func NewTransportTestServer(t *testing.T, opts ...server.Option) (*server.Server, TransportURLs) {
	t.Helper()
	defaults := []server.Option{
		server.EndPoint("localhost", 0),
		server.WebSocketEndPoint("localhost", 0),
		server.HTTPSEndPoint("localhost", 0),
		server.TLSConfig(TLS(t).ServerConfig()),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
	}
	srv, err := server.New(append(defaults, opts...)...)
	if err != nil {
		t.Fatalf("testutil: new server: %v", err)
	}
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("testutil: start server: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	var urls TransportURLs
	for _, u := range srv.URLs() {
		switch ua.TransportProfileForURL(u) {
		case ua.TransportProfileUATCP:
			urls.TCP = u
		case ua.TransportProfileWSS:
			urls.WSS = u
		case ua.TransportProfileHTTPS:
			urls.HTTPS = u
		}
	}
	return srv, urls
}

// NewTransportTestClient connects a client to url (any transport) with
// security None, trusting the TLS CA of the test PKI.
func NewTransportTestClient(t *testing.T, url string, opts ...opcua.Option) *opcua.Client {
	t.Helper()
	defaults := []opcua.Option{
		opcua.SecurityMode(ua.MessageSecurityModeNone),
		opcua.TLSConfig(TLS(t).ClientConfig()),
		opcua.DialTimeout(30 * time.Second),
		opcua.RequestTimeout(30 * time.Second),
	}
	c, err := opcua.NewClient(url, append(defaults, opts...)...)
	if err != nil {
		t.Fatalf("testutil: new client: %v", err)
	}
	ctx := context.Background()
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("testutil: connect %s: %v", url, err)
	}
	t.Cleanup(func() { _ = c.Close(ctx) })
	return c
}
