package server

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscoveryService_FindServers(t *testing.T) {
	srv, err := New(
		EndPoint("localhost", 4840),
		EnableSecurity("None", ua.MessageSecurityModeNone),
		EnableAuthMode(ua.UserTokenTypeAnonymous),
	)
	require.NoError(t, err)
	srv.initEndpoints()
	svc := &DiscoveryService{srv: srv}

	t.Run("returns server application description", func(t *testing.T) {
		req := &ua.FindServersRequest{RequestHeader: reqHeader()}
		resp, err := svc.FindServers(context.Background(), nil, req, 1)
		require.NoError(t, err)

		fsResp := resp.(*ua.FindServersResponse)
		require.Len(t, fsResp.Servers, 1)
		assert.Equal(t, ua.ApplicationTypeServer, fsResp.Servers[0].ApplicationType)
	})

	t.Run("wrong request type", func(t *testing.T) {
		_, err := svc.FindServers(context.Background(), nil, &ua.ReadRequest{RequestHeader: reqHeader()}, 1)
		assert.Error(t, err)
	})
}

func TestDiscoveryService_GetEndpoints(t *testing.T) {
	srv, err := New(
		EndPoint("localhost", 4840),
		EnableSecurity("None", ua.MessageSecurityModeNone),
		EnableAuthMode(ua.UserTokenTypeAnonymous),
	)
	require.NoError(t, err)
	srv.initEndpoints()
	svc := &DiscoveryService{srv: srv}

	t.Run("matching URL returns endpoints", func(t *testing.T) {
		url := srv.endpoints[0].EndpointURL
		req := &ua.GetEndpointsRequest{
			RequestHeader: reqHeader(),
			EndpointURL:   url,
		}
		resp, err := svc.GetEndpoints(context.Background(), nil, req, 1)
		require.NoError(t, err)

		epResp := resp.(*ua.GetEndpointsResponse)
		assert.NotEmpty(t, epResp.Endpoints)
		for _, ep := range epResp.Endpoints {
			assert.Equal(t, url, ep.EndpointURL)
		}
	})

	t.Run("case insensitive URL match", func(t *testing.T) {
		url := srv.endpoints[0].EndpointURL
		req := &ua.GetEndpointsRequest{
			RequestHeader: reqHeader(),
			EndpointURL:   "OPC.TCP://LOCALHOST:4840",
		}
		resp, err := svc.GetEndpoints(context.Background(), nil, req, 1)
		require.NoError(t, err)

		epResp := resp.(*ua.GetEndpointsResponse)
		// If the URLs differ in case, they should still match
		if url == "opc.tcp://localhost:4840" {
			assert.NotEmpty(t, epResp.Endpoints)
		}
	})

	t.Run("non-matching URL returns empty", func(t *testing.T) {
		req := &ua.GetEndpointsRequest{
			RequestHeader: reqHeader(),
			EndpointURL:   "opc.tcp://unknown:9999",
		}
		resp, err := svc.GetEndpoints(context.Background(), nil, req, 1)
		require.NoError(t, err)

		epResp := resp.(*ua.GetEndpointsResponse)
		assert.Empty(t, epResp.Endpoints)
	})
}

func TestDiscoveryService_UnsupportedMethods(t *testing.T) {
	srv := newTestServer()
	svc := &DiscoveryService{srv: srv}

	tests := []struct {
		name    string
		handler func(req ua.Request) (ua.Response, error)
	}{
		{"FindServersOnNetwork", func(r ua.Request) (ua.Response, error) {
			return svc.FindServersOnNetwork(context.Background(), nil, r, 1)
		}},
		{"RegisterServer", func(r ua.Request) (ua.Response, error) { return svc.RegisterServer(context.Background(), nil, r, 1) }},
		{"RegisterServer2", func(r ua.Request) (ua.Response, error) { return svc.RegisterServer2(context.Background(), nil, r, 1) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resp ua.Response
			var err error
			switch tt.name {
			case "FindServersOnNetwork":
				resp, err = svc.FindServersOnNetwork(context.Background(), nil, &ua.FindServersOnNetworkRequest{RequestHeader: reqHeader()}, 1)
			case "RegisterServer":
				resp, err = svc.RegisterServer(context.Background(), nil, &ua.RegisterServerRequest{RequestHeader: reqHeader()}, 1)
			case "RegisterServer2":
				resp, err = svc.RegisterServer2(context.Background(), nil, &ua.RegisterServer2Request{RequestHeader: reqHeader()}, 1)
			}
			require.NoError(t, err)
			fault := resp.(*ua.ServiceFault)
			assert.Equal(t, ua.StatusBadServiceUnsupported, fault.ResponseHeader.ServiceResult)
		})
	}
}
