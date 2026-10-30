//go:build interop

// SPDX-License-Identifier: MIT

// Tests in this file cover the UA JSON mappings of the opc.https (Part 6
// §7.4.5, https-uajson) and opc.wss (Part 6 §7.5.2, wss-uajson) transports
// against the UA-.NETStandard adapter server: go-opcua dials the JSON twins
// that UA-.NETStandard advertises next to its binary endpoints with the
// security mode None (HttpsServiceHost). The adapter client never selects
// these endpoints (CLIENT_CONTRACT.md), so there is no reverse direction.
//
// UA-.NETStandard dispatches an HTTPS POST to its JSON decoder only for the
// Content-Type application/opcua+uajson, not for the application/json of
// Part 6 §7.4.2 Table 80 that go-opcua sends; the HTTPS test makes the
// client send the former through an HTTP client of its own.

package interop

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

// dialJSONTransportClient connects a go-opcua client to the endpoint of the
// UA JSON profile at url, with security None and the test CA trusted for
// TLS. Over HTTPS it authenticates with a user name, as dialTransportClient
// does.
func dialJSONTransportClient(t *testing.T, url, profile string, user bool, opts ...opcua.Option) *opcua.Client {
	t.Helper()
	tlsCfg := &tls.Config{RootCAs: testCAPool(t), MinVersion: tls.VersionTLS12}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	eps, err := opcua.GetEndpoints(ctx, url, opcua.TLSConfig(tlsCfg))
	if err != nil {
		t.Fatalf("GetEndpoints(%s): %v", url, err)
	}
	ep, err := opcua.SelectEndpointForTransport(eps, profile, ua.SecurityPolicyURINone, ua.MessageSecurityModeNone, nil)
	if err != nil {
		t.Fatalf("%s: no None endpoint of transport %s in %d endpoints: %v", url, profile, len(eps), err)
	}
	ep.EndpointURL = url
	opts = append(opts, opcua.TLSConfig(tlsCfg), opcua.DialTimeout(dialTimeout), opcua.RequestTimeout(10*time.Second))
	if user {
		opts = append(opts, opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeUserName), opcua.AuthUsername("test-user", "test-password"))
	} else {
		opts = append(opts, opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous), opcua.AuthAnonymous())
	}
	c, err := opcua.NewClient(url, append([]opcua.Option{opcua.InsecureNoSecurity()}, opts...)...)
	if err != nil {
		t.Fatalf("NewClient(%s, opcua.InsecureNoSecurity()): %v", url, err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel2()
	if err := c.Connect(ctx2); err != nil {
		t.Fatalf("Connect(%s, %s): %v", url, profile, err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = c.Close(ctx)
	})
	return c
}

// TestDotnetServer_Transport_WSSJSON: go-opcua client → dotnet server over
// opc.wss with the sub-protocol opcua+uajson.
func TestDotnetServer_Transport_WSSJSON(t *testing.T) {
	h := startDotnetTransportServer(t)
	exerciseTransport(t, dialJSONTransportClient(t, h.wss, ua.TransportProfileWSSJSON, false))
}

// TestDotnetServer_Transport_HTTPSJSON: go-opcua client → dotnet server over
// opc.https with JSON bodies; Publish is a long-polled POST.
func TestDotnetServer_Transport_HTTPSJSON(t *testing.T) {
	h := startDotnetTransportServer(t)
	// UA-.NETStandard takes JSON over HTTPS only as application/opcua+uajson.
	exerciseTransport(t, dialJSONTransportClient(t, h.https, ua.TransportProfileHTTPSJSON, true,
		opcua.HTTPSJSONContentType(uasc.HTTPSJSONContentTypeLegacy)))
}
