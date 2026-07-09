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
		EnableSecurity(ua.SecurityPolicyURINone, ua.MessageSecurityModeNone),
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
