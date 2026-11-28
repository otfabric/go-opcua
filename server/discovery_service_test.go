// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestDiscoveryService_FindServers(t *testing.T) {
	srv := discoveryTestServer(t)
	svc := &DiscoveryService{srv: srv}

	resp, err := svc.FindServers(context.Background(), nil, &ua.FindServersRequest{
		RequestHeader: reqHeader(),
	}, 1)
	require.NoError(t, err)
	fs := resp.(*ua.FindServersResponse)
	require.Equal(t, ua.StatusOK, fs.ResponseHeader.ServiceResult)
	require.NotEmpty(t, fs.Servers)
}

func TestDiscoveryService_GetEndpoints(t *testing.T) {
	srv := discoveryTestServer(t)
	svc := &DiscoveryService{srv: srv}

	resp, err := svc.GetEndpoints(context.Background(), nil, &ua.GetEndpointsRequest{
		RequestHeader: reqHeader(),
		EndpointURL:   srv.Endpoints()[0].EndpointURL,
	}, 1)
	require.NoError(t, err)
	ge := resp.(*ua.GetEndpointsResponse)
	require.Equal(t, ua.StatusOK, ge.ResponseHeader.ServiceResult)
	require.NotEmpty(t, ge.Endpoints)
}

// TestDiscoveryService_GetEndpointsProfileURIs: GetEndpoints returns the
// Endpoints of the requested Transport Profiles, all of them for an empty
// list and none when none matches (Part 4 §5.5.4).
func TestDiscoveryService_GetEndpointsProfileURIs(t *testing.T) {
	srv := discoveryTestServer(t)
	svc := &DiscoveryService{srv: srv}
	get := func(profiles ...string) []*ua.EndpointDescription {
		t.Helper()
		resp, err := svc.GetEndpoints(context.Background(), nil, &ua.GetEndpointsRequest{
			RequestHeader: reqHeader(),
			EndpointURL:   srv.Endpoints()[0].EndpointURL,
			ProfileURIs:   profiles,
		}, 1)
		require.NoError(t, err)
		ge := resp.(*ua.GetEndpointsResponse)
		require.Equal(t, ua.StatusOK, ge.ResponseHeader.ServiceResult)
		return ge.Endpoints
	}
	all := get()
	require.NotEmpty(t, all)
	require.Equal(t, all, get(ua.TransportProfileUATCP), "every endpoint of the test server is opc.tcp")
	require.Equal(t, all, get(ua.TransportProfileHTTPS, ua.TransportProfileUATCP))
	require.Empty(t, get(ua.TransportProfileHTTPS), "an empty list if no Endpoints match")
	require.Empty(t, get(ua.TransportProfileUATCP+"?x=1"), "compared as they are")

	tcp := &ua.EndpointDescription{TransportProfileURI: ua.TransportProfileUATCP}
	wss := &ua.EndpointDescription{TransportProfileURI: ua.TransportProfileWSS}
	https := &ua.EndpointDescription{TransportProfileURI: ua.TransportProfileHTTPS}
	eps := []*ua.EndpointDescription{tcp, wss, https}
	require.Equal(t, eps, endpointsForProfiles(eps, nil))
	require.Equal(t, []*ua.EndpointDescription{tcp, https}, endpointsForProfiles(eps, []string{ua.TransportProfileHTTPS, ua.TransportProfileUATCP}), "in the order of the endpoints")
	require.Equal(t, []*ua.EndpointDescription{wss}, endpointsForProfiles(eps, []string{ua.TransportProfileWSS}))
}

func TestDiscoveryService_FindServersOnNetworkUnsupported(t *testing.T) {
	srv := newTestServer()
	svc := &DiscoveryService{srv: srv}

	resp, err := svc.FindServersOnNetwork(context.Background(), nil, &ua.FindServersOnNetworkRequest{
		RequestHeader: reqHeader(),
	}, 1)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadServiceUnsupported, resp.Header().ServiceResult)
}

func TestDiscoveryService_RegisterServerUnsupported(t *testing.T) {
	srv := newTestServer()
	svc := &DiscoveryService{srv: srv}

	resp, err := svc.RegisterServer(context.Background(), nil, &ua.RegisterServerRequest{
		RequestHeader: reqHeader(),
	}, 1)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadServiceUnsupported, resp.Header().ServiceResult)
}

func TestDiscoveryService_RegisterServer2Unsupported(t *testing.T) {
	srv := newTestServer()
	svc := &DiscoveryService{srv: srv}

	resp, err := svc.RegisterServer2(context.Background(), nil, &ua.RegisterServer2Request{
		RequestHeader: reqHeader(),
	}, 1)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadServiceUnsupported, resp.Header().ServiceResult)
}

func discoveryTestServer(t *testing.T) *Server {
	t.Helper()
	srv, err := New(
		EndPoint("localhost", 4840),
		InsecureNoSecurity(),
		EnableAuthMode(ua.UserTokenTypeAnonymous),
	)
	require.NoError(t, err)
	srv.SubscriptionService = &SubscriptionService{
		srv:  srv,
		Subs: make(map[uint32]*Subscription),
	}
	srv.MonitoredItemService = &MonitoredItemService{
		SubService: srv.SubscriptionService,
		Items:      make(map[uint32]*MonitoredItem),
		Nodes:      make(map[string][]*MonitoredItem),
		Subs:       make(map[uint32][]*MonitoredItem),
	}
	srv.initEndpoints()
	require.NotEmpty(t, srv.Endpoints())
	return srv
}
