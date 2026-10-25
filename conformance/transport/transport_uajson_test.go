// SPDX-License-Identifier: MIT

package transport

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/otfabric/go-opcua/uasc"
	"github.com/stretchr/testify/require"
)

// jsonServer is transportServer with the UA JSON mappings enabled.
func jsonServer(t *testing.T, opts ...server.Option) (*testutil.Fixture, *server.Server, map[string]string) {
	t.Helper()
	return transportServer(t, append([]server.Option{server.EnableUAJSON()}, opts...)...)
}

// jsonClient connects a client to the UA JSON mapping of an endpoint.
func jsonClient(t *testing.T, endpoint, profile string, opts ...opcua.Option) *opcua.Client {
	t.Helper()
	c := newClient(t, endpoint, append([]opcua.Option{tlsClient(t), opcua.TransportProfile(profile)}, opts...)...)
	require.True(t, c.SecureChannel().IsJSON())
	return c
}

// jsonEndpointFor returns the endpoint of an opc.https or opc.wss URL with
// a JSON transport profile, policy and mode.
func jsonEndpointFor(t *testing.T, endpoint, profile, policy string, mode ua.MessageSecurityMode) *ua.EndpointDescription {
	t.Helper()
	eps, err := opcua.GetEndpoints(context.Background(), endpoint, tlsClient(t), opcua.TransportProfile(profile))
	require.NoError(t, err)
	ep, err := opcua.SelectEndpointForTransport(eps, profile, policy, mode, nil)
	if policy != ua.SecurityPolicyURINone {
		ep, err = opcua.SelectEndpointForTransport(eps, profile, policy, mode, pki(t).ClientCert)
	}
	require.NoError(t, err)
	return ep
}

// TestTransportUAJSON_EndpointsAdvertised checks the JSON twins of the
// opc.https and opc.wss endpoints: the same URLs, the transport profiles
// https-uajson and wss-uajson of Part 7, the HTTPS policies for
// https-uajson and None only for wss-uajson.
func TestTransportUAJSON_EndpointsAdvertised(t *testing.T) {
	_, _, urls := jsonServer(t, secureServerOpts(t)...)
	eps, err := opcua.GetEndpoints(context.Background(), urls[ua.TransportProfileHTTPS], tlsClient(t))
	require.NoError(t, err)
	byProfile := map[string][]*ua.EndpointDescription{}
	for _, ep := range eps {
		byProfile[ep.TransportProfileURI] = append(byProfile[ep.TransportProfileURI], ep)
	}
	require.Len(t, byProfile[ua.TransportProfileHTTPSJSON], len(byProfile[ua.TransportProfileHTTPS]))
	for _, ep := range byProfile[ua.TransportProfileHTTPSJSON] {
		require.Equal(t, urls[ua.TransportProfileHTTPS], ep.EndpointURL)
	}
	require.Empty(t, byProfile[ua.TransportProfileWSSJSON], "the endpoints of the URL asked for")

	eps, err = opcua.GetEndpoints(context.Background(), urls[ua.TransportProfileWSS], tlsClient(t))
	require.NoError(t, err)
	byProfile = map[string][]*ua.EndpointDescription{}
	for _, ep := range eps {
		byProfile[ep.TransportProfileURI] = append(byProfile[ep.TransportProfileURI], ep)
	}
	require.Len(t, byProfile[ua.TransportProfileWSSJSON], 1)
	wss := byProfile[ua.TransportProfileWSSJSON][0]
	require.Equal(t, urls[ua.TransportProfileWSS], wss.EndpointURL)
	require.Equal(t, ua.SecurityPolicyURINone, wss.SecurityPolicyURI)
	require.Equal(t, ua.MessageSecurityModeNone, wss.SecurityMode)

	// SelectEndpoint prefers UA Binary: JSON is chosen explicitly.
	ep, err := opcua.SelectEndpoint(eps, "", ua.MessageSecurityModeInvalid, nil)
	require.NoError(t, err)
	require.Equal(t, ua.TransportProfileWSS, ep.TransportProfileURI)
}

// TestTransportUAJSON_Sessions runs sessions over both JSON mappings: read,
// write, browse, a value of several hundred elements and a method call.
func TestTransportUAJSON_Sessions(t *testing.T) {
	f, _, urls := jsonServer(t)
	for _, tc := range []struct{ url, profile string }{
		{urls[ua.TransportProfileHTTPS], ua.TransportProfileHTTPSJSON},
		{urls[ua.TransportProfileWSS], ua.TransportProfileWSSJSON},
	} {
		c := jsonClient(t, tc.url, tc.profile)
		exerciseSession(t, c, f, tc.profile)
	}
}

// TestTransportUAJSON_PolicyMatrix runs https-uajson sessions with every
// policy: the session signatures of CreateSession and ActivateSession are
// fields of JSON messages, signed with the policy named in the
// OPCUA-SecurityPolicy header (Part 6 §7.4.1).
func TestTransportUAJSON_PolicyMatrix(t *testing.T) {
	f, _, urls := jsonServer(t, secureServerOpts(t)...)
	addr := urls[ua.TransportProfileHTTPS]
	for _, pol := range securePolicies {
		t.Run(shortPolicy(pol), func(t *testing.T) {
			ep := jsonEndpointFor(t, addr, ua.TransportProfileHTTPSJSON, pol, ua.MessageSecurityModeSignAndEncrypt)
			c := newClient(t, addr, append(secureClientOpts(t, ep, ua.UserTokenTypeAnonymous), tlsClient(t))...)
			require.True(t, c.SecureChannel().IsJSON())
			require.Equal(t, pol, c.SecurityPolicy())
			exerciseSession(t, c, f, "https-uajson-"+shortPolicy(pol))
		})
	}
}

// TestTransportUAJSON_Username checks user name tokens over the JSON
// mappings: in clear text on the None endpoints, which TLS protects.
func TestTransportUAJSON_Username(t *testing.T) {
	f, _, urls := jsonServer(t,
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.WithUsernameValidator(userValidator))
	ctx := context.Background()
	for _, tc := range []struct{ url, profile string }{
		{urls[ua.TransportProfileHTTPS], ua.TransportProfileHTTPSJSON},
		{urls[ua.TransportProfileWSS], ua.TransportProfileWSSJSON},
	} {
		ep := jsonEndpointFor(t, tc.url, tc.profile, ua.SecurityPolicyURINone, ua.MessageSecurityModeNone)
		c := newClient(t, tc.url, tlsClient(t), opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeUserName), opcua.AuthUsername("alice", "wonderland"))
		require.True(t, c.SecureChannel().IsJSON())
		_, err := c.ReadValue(ctx, f.Int32)
		require.NoError(t, err)

		_, err = dialClient(t, tc.url, tlsClient(t), opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeUserName), opcua.AuthUsername("alice", "wrong"))
		require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
	}
}

// TestTransportUAJSON_Subscription checks Publish over both JSON mappings.
func TestTransportUAJSON_Subscription(t *testing.T) {
	f, _, urls := jsonServer(t)
	ctx := context.Background()
	for i, tc := range []struct{ url, profile string }{
		{urls[ua.TransportProfileHTTPS], ua.TransportProfileHTTPSJSON},
		{urls[ua.TransportProfileWSS], ua.TransportProfileWSSJSON},
	} {
		c := jsonClient(t, tc.url, tc.profile)
		sub, ch, err := c.NewSubscription().Interval(fastInterval).Monitor(f.Int32).Start(ctx)
		require.NoError(t, err)
		t.Cleanup(func() { _ = sub.Cancel(ctx) })
		writeInt32(t, c, f.Int32, int32(4700+i))
		awaitValue(t, ch, 0, int32(4700+i))
	}
}

// TestTransportUAJSON_Protocol checks the HTTP mapping of Part 6 §7.4.5:
// the JSON content types, the content type of the response and the faults
// for requests that cannot be served.
func TestTransportUAJSON_Protocol(t *testing.T) {
	f, _, urls := jsonServer(t)
	addr := urls[ua.TransportProfileHTTPS]
	getEndpoints := []byte(`{"UaTypeId":"i=426","RequestHeader":{"RequestHandle":7}}`)

	decode := func(t *testing.T, b []byte) ua.Response {
		t.Helper()
		v, err := uasc.DecodeServiceMessageJSON(b, nil)
		require.NoError(t, err, string(b))
		return v.(ua.Response)
	}
	t.Run("content types", func(t *testing.T) {
		for _, ct := range []string{uasc.HTTPSJSONContentType, uasc.HTTPSJSONContentTypeLegacy} {
			resp, b := post(t, addr, http.MethodPost, ct, "", getEndpoints)
			require.Equal(t, http.StatusOK, resp.StatusCode, ct)
			require.Equal(t, ct, resp.Header.Get("Content-Type"))
			require.Equal(t, uint32(7), decode(t, b).Header().RequestHandle)
		}
	})
	t.Run("legacy client", func(t *testing.T) {
		c := jsonClient(t, addr, ua.TransportProfileHTTPSJSON, opcua.HTTPSJSONContentType(uasc.HTTPSJSONContentTypeLegacy))
		exerciseSession(t, c, f, "legacy")
	})
	fault := func(t *testing.T, policy, body string, want ua.StatusCode) {
		t.Helper()
		resp, b := post(t, addr, http.MethodPost, uasc.HTTPSJSONContentType, policy, []byte(body))
		require.Equal(t, http.StatusOK, resp.StatusCode)
		r := decode(t, b)
		require.Equal(t, want, r.Header().ServiceResult, "%T", r)
	}
	t.Run("garbage", func(t *testing.T) {
		fault(t, "", "", ua.StatusBadDecodingError)
		fault(t, "", "{", ua.StatusBadDecodingError)
		fault(t, "", `{"UaTypeId":"i=631","NodesToRead":"x"}`, ua.StatusBadDecodingError)
	})
	t.Run("not a request", func(t *testing.T) {
		fault(t, "", `{"UaTypeId":"i=429"}`, ua.StatusBadServiceUnsupported)
		// A request without anything is a request with default values.
		fault(t, "", `{"UaTypeId":"i=631"}`, ua.StatusBadSessionIDInvalid)
	})
	t.Run("policy not offered", func(t *testing.T) {
		fault(t, ua.SecurityPolicyURIBasic256Sha256, string(getEndpoints), ua.StatusBadSecurityPolicyRejected)
	})
	t.Run("no secure conversation", func(t *testing.T) {
		fault(t, "", `{"UaTypeId":"i=446","RequestHeader":{}}`, ua.StatusBadServiceUnsupported)
	})
	t.Run("no session", func(t *testing.T) {
		fault(t, "", `{"UaTypeId":"i=631","RequestHeader":{},"NodesToRead":[{"NodeId":"i=2258","AttributeId":13}]}`, ua.StatusBadSessionIDInvalid)
	})
}

// TestTransportUAJSON_SubProtocols checks that one opc.wss listener serves
// both sub-protocols, and that a server without EnableUAJSON refuses
// opcua+uajson (Part 6 §7.5.2: the client then reports an error).
func TestTransportUAJSON_SubProtocols(t *testing.T) {
	f, _, urls := jsonServer(t)
	addr := urls[ua.TransportProfileWSS]
	exerciseSession(t, newClient(t, addr, tlsClient(t)), f, "binary")
	exerciseSession(t, jsonClient(t, addr, ua.TransportProfileWSSJSON), f, "json")

	_, _, plain := transportServer(t)
	d := &uacp.Dialer{TLSConfig: testutil.TLS(t).ClientConfig()}
	_, err := d.DialWebSocketJSON(context.Background(), plain[ua.TransportProfileWSS])
	require.Error(t, err)
}

// TestTransportUAJSON_Reconnect cuts the WebSockets of a wss-uajson client
// under a running subscription: the client recovers and the subscription
// delivers again.
func TestTransportUAJSON_Reconnect(t *testing.T) {
	f, _, urls := jsonServer(t)
	ctx := context.Background()
	addr := urls[ua.TransportProfileWSS]
	proxy := testutil.NewChaosProxy(t, hostPort(t, addr), 3)
	via := strings.Replace(addr, hostPort(t, addr), proxy.Addr(), 1)
	via = strings.Replace(via, "127.0.0.1", "localhost", 1)

	states := make(chan opcua.ConnState, 32)
	c := jsonClient(t, via, ua.TransportProfileWSSJSON, opcua.AutoReconnect(true), opcua.ReconnectInterval(50*time.Millisecond),
		opcua.WithConnStateChan(states))
	sub, ch, err := c.NewSubscription().Interval(fastInterval).Monitor(f.Int32).Start(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(ctx) })
	awaitValue(t, ch, 0, int32(42))

	writer := newClient(t, urls[ua.TransportProfileUATCP])
	proxy.SetRefuse(true)
	proxy.DropAll()
	awaitState(t, states, opcua.Reconnecting)
	proxy.SetRefuse(false)
	awaitState(t, states, opcua.Connected)

	writeInt32(t, writer, f.Int32, 99)
	awaitValue(t, ch, 0, int32(99))
}
