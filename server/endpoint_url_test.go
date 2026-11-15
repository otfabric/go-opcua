// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// TestEndpointURLKey: two endpoint URLs are the same when they differ only
// in the letter case of the scheme or the host, or by a trailing slash.
func TestEndpointURLKey(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		a, b string
		same bool
	}{
		{"opc.tcp://localhost:4840", "opc.tcp://localhost:4840", true},
		{"opc.tcp://localhost:4840", "opc.tcp://localhost:4840/", true},
		{"opc.tcp://localhost:4840", "opc.tcp://LocalHost:4840", true},
		{"opc.tcp://localhost:4840", "OPC.TCP://LOCALHOST:4840/", true},
		{"opc.tcp://plant-a:4840/UA/Server", "opc.tcp://Plant-A:4840/UA/Server/", true},
		{"opc.tcp://[fe80::1%25eth0]:4840", "opc.tcp://[FE80::1%25eth0]:4840", true},
		{"opc.wss://localhost:4843", "OPC.WSS://localhost:4843/", true},
		{"", "/", true},
		// Only one trailing slash, and only the scheme and the host.
		{"opc.tcp://localhost:4840", "opc.tcp://localhost:4840//", false},
		{"opc.tcp://plant-a:4840/UA/Server", "opc.tcp://plant-a:4840/ua/server", false},
		{"opc.tcp://user@plant-a:4840", "opc.tcp://USER@plant-a:4840", false},
		{"opc.tcp://localhost:4840", "opc.tcp://localhost:4841", false},
		{"opc.tcp://localhost:4840", "opc.tcp://127.0.0.1:4840", false},
		{"opc.tcp://localhost:4840", "opc.wss://localhost:4840", false},
		{"opc.tcp://localhost:4840", "opc.tcp://localhost", false},
		{"opc.tcp://localhost:4840/?a", "opc.tcp://localhost:4840/?A", false},
		{"localhost:4840", "LOCALHOST:4840", false},
	} {
		require.Equal(t, tc.same, endpointURLKey(tc.a) == endpointURLKey(tc.b), "%q and %q: %q, %q",
			tc.a, tc.b, endpointURLKey(tc.a), endpointURLKey(tc.b))
	}
}

// TestGetEndpointsAndCreateSessionAgree: GetEndpoints (Part 4 §5.4.4) and
// CreateSession (§5.6.2) answer each URL with the same endpoints: those of
// the URL, compared as endpointURLKey writes it, or all of them when none
// matches.
func TestGetEndpointsAndCreateSessionAgree(t *testing.T) {
	srv := newTestServer()
	tcp := &ua.EndpointDescription{EndpointURL: "opc.tcp://localhost:4840", SecurityMode: ua.MessageSecurityModeNone,
		TransportProfileURI: ua.TransportProfileUATCP}
	tcpSigned := &ua.EndpointDescription{EndpointURL: "opc.tcp://localhost:4840", SecurityMode: ua.MessageSecurityModeSign,
		TransportProfileURI: ua.TransportProfileUATCP}
	wss := &ua.EndpointDescription{EndpointURL: "opc.wss://localhost:4843", SecurityMode: ua.MessageSecurityModeNone,
		TransportProfileURI: ua.TransportProfileWSS}
	https := &ua.EndpointDescription{EndpointURL: "opc.https://localhost:4844", SecurityMode: ua.MessageSecurityModeSign,
		TransportProfileURI: ua.TransportProfileHTTPS}
	plant := &ua.EndpointDescription{EndpointURL: "opc.tcp://Plant-A:4840/UA/Server/", SecurityMode: ua.MessageSecurityModeNone,
		TransportProfileURI: ua.TransportProfileUATCP}
	all := []*ua.EndpointDescription{tcp, tcpSigned, wss, https, plant}
	srv.endpoints = all
	discovery := &DiscoveryService{srv: srv}
	sessions := &SessionService{srv: srv}

	for _, tc := range []struct {
		url  string
		want []*ua.EndpointDescription
	}{
		{"opc.tcp://localhost:4840", []*ua.EndpointDescription{tcp, tcpSigned}},
		{"opc.tcp://localhost:4840/", []*ua.EndpointDescription{tcp, tcpSigned}},
		{"opc.tcp://LOCALHOST:4840", []*ua.EndpointDescription{tcp, tcpSigned}},
		{"OPC.TCP://LocalHost:4840/", []*ua.EndpointDescription{tcp, tcpSigned}},
		{"opc.wss://localhost:4843/", []*ua.EndpointDescription{wss}},
		{"opc.https://LOCALHOST:4844", []*ua.EndpointDescription{https}},
		{"opc.tcp://plant-a:4840/UA/Server", []*ua.EndpointDescription{plant}},
		// No endpoint has this URL: all of them.
		{"opc.tcp://plant-a:4840/ua/server", all},
		{"opc.tcp://host.docker.internal:4840", all},
		{"opc.tcp://localhost:4841", all},
		{"opc.tcp://localhost:4840//", all},
		{"", all},
	} {
		t.Run(tc.url, func(t *testing.T) {
			resp, err := discovery.GetEndpoints(context.Background(), nil, &ua.GetEndpointsRequest{
				RequestHeader: reqHeader(),
				EndpointURL:   tc.url,
			}, 1)
			require.NoError(t, err)
			require.Equal(t, tc.want, resp.(*ua.GetEndpointsResponse).Endpoints, "GetEndpoints")

			resp, err = sessions.CreateSession(context.Background(), scNone(), &ua.CreateSessionRequest{
				RequestHeader:           reqHeader(),
				EndpointURL:             tc.url,
				RequestedSessionTimeout: 5000,
				ClientNonce:             []byte("n"),
			}, 1)
			require.NoError(t, err)
			require.Equal(t, tc.want, resp.(*ua.CreateSessionResponse).ServerEndpoints, "CreateSession")
		})
	}
	require.Equal(t, all, srv.endpoints, "the server's list is not changed")
}
