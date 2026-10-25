// SPDX-License-Identifier: MIT

package conformance

import (
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
	"github.com/stretchr/testify/require"
)

func certPool(certs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c)
	}
	return p
}

// TestTransportHTTPS_EndpointsAdvertised checks the opc.https endpoints:
// the HTTPS transport profile, and each enabled policy once, with the
// strongest mode enabled for it (Part 6 §7.4.1: only the policy matters).
func TestTransportHTTPS_EndpointsAdvertised(t *testing.T) {
	_, _, urls := transportServer(t, secureServerOpts(t)...)
	eps, err := opcua.GetEndpoints(context.Background(), urls[ua.TransportProfileHTTPS], tlsClient(t))
	require.NoError(t, err)
	require.Len(t, eps, 1+len(securePolicies))
	seen := map[string]bool{}
	for _, ep := range eps {
		require.Equal(t, ua.TransportProfileHTTPS, ep.TransportProfileURI)
		require.Equal(t, urls[ua.TransportProfileHTTPS], ep.EndpointURL)
		require.True(t, strings.HasPrefix(ep.EndpointURL, "opc.https://"))
		if ep.SecurityPolicyURI == ua.SecurityPolicyURINone {
			require.Equal(t, ua.MessageSecurityModeNone, ep.SecurityMode)
		} else {
			require.Equal(t, ua.MessageSecurityModeSignAndEncrypt, ep.SecurityMode)
			require.NotEmpty(t, ep.ServerCertificate)
		}
		require.False(t, seen[ep.SecurityPolicyURI], "policy %s offered twice", ep.SecurityPolicyURI)
		seen[ep.SecurityPolicyURI] = true
	}
}

// TestTransportHTTPS_PolicyMatrix runs a session over opc.https with every
// policy: the nonces of CreateSession and ActivateSession are signed with
// the policy; TLS protects the messages.
func TestTransportHTTPS_PolicyMatrix(t *testing.T) {
	f, _, urls := transportServer(t, secureServerOpts(t)...)
	addr := urls[ua.TransportProfileHTTPS]

	c := newClient(t, addr, tlsClient(t))
	require.True(t, c.SecureChannel().IsHTTPS())
	exerciseSession(t, c, f, "https-None")
	for _, pol := range securePolicies {
		t.Run(shortPolicy(pol), func(t *testing.T) {
			ep := endpointForTLS(t, addr, pol, ua.MessageSecurityModeSignAndEncrypt)
			c := newClient(t, addr, append(secureClientOpts(t, ep, ua.UserTokenTypeAnonymous), tlsClient(t))...)
			require.Equal(t, pol, c.SecurityPolicy())
			exerciseSession(t, c, f, "https-"+shortPolicy(pol))
		})
	}

	// The https scheme is accepted for the same endpoint.
	plain := "https" + strings.TrimPrefix(addr, "opc.https")
	exerciseSession(t, newClient(t, plain, tlsClient(t)), f, "https-plain")
}

// TestTransportHTTPS_Username checks user name tokens over HTTPS: in clear
// text on the None endpoint, where TLS protects them, and encrypted with the
// server certificate on a secured one.
func TestTransportHTTPS_Username(t *testing.T) {
	f, _, urls := transportServer(t, secureServerOpts(t,
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.WithUsernameValidator(userValidator))...)
	addr := urls[ua.TransportProfileHTTPS]
	ctx := context.Background()

	none := endpointForTLS(t, addr, ua.SecurityPolicyURINone, ua.MessageSecurityModeNone)
	var hasUser bool
	for _, tok := range none.UserIdentityTokens {
		hasUser = hasUser || tok.TokenType == ua.UserTokenTypeUserName
	}
	require.True(t, hasUser, "the HTTPS None endpoint offers user names: TLS protects them")

	c := newClient(t, addr, tlsClient(t), opcua.SecurityFromEndpoint(none, ua.UserTokenTypeUserName), opcua.AuthUsername("alice", "wonderland"))
	_, err := c.ReadValue(ctx, f.Int32)
	require.NoError(t, err)

	ep := endpointForTLS(t, addr, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)
	c = newClient(t, addr, append(secureClientOpts(t, ep, ua.UserTokenTypeUserName), tlsClient(t), opcua.AuthUsername("alice", "wonderland"))...)
	_, err = c.ReadValue(ctx, f.Int32)
	require.NoError(t, err)

	_, err = dialClient(t, addr, append(secureClientOpts(t, ep, ua.UserTokenTypeUserName), tlsClient(t), opcua.AuthUsername("alice", "wrong"))...)
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
}

// TestTransportHTTPS_Subscription checks Publish over HTTPS: the server
// holds the POST of a Publish request until a notification is due.
func TestTransportHTTPS_Subscription(t *testing.T) {
	f, _, urls := transportServer(t)
	ctx := context.Background()
	c := newClient(t, urls[ua.TransportProfileHTTPS], tlsClient(t))

	sub, ch, err := c.NewSubscription().Interval(fastInterval).Monitor(f.Int32).Start(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(ctx) })
	awaitValue(t, ch, 0, int32(42))
	writeInt32(t, c, f.Int32, 4711)
	awaitValue(t, ch, 0, int32(4711))
}

// post sends body to an HTTPS endpoint the way a client does and returns the
// HTTP response with its body.
func post(t *testing.T, endpoint, method, contentType, policy string, body []byte) (*http.Response, []byte) {
	t.Helper()
	target, err := uasc.HTTPSURL(endpoint)
	require.NoError(t, err)
	req, err := http.NewRequest(method, target, bytes.NewReader(body))
	require.NoError(t, err)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if policy != "" {
		req.Header.Set(uasc.HTTPSSecurityPolicyHeader, policy)
	}
	resp, err := uasc.NewHTTPSClient(testutil.TLS(t).ClientConfig()).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, b
}

// decodeResponse decodes the body of an HTTPS response.
func decodeResponse(t *testing.T, b []byte) ua.Response {
	t.Helper()
	_, v, err := ua.DecodeService(b)
	require.NoError(t, err)
	r, ok := v.(ua.Response)
	require.True(t, ok, "%T", v)
	return r
}

func encodeRequest(t *testing.T, req ua.Request) []byte {
	t.Helper()
	if req.Header() == nil {
		req.SetHeader(&ua.RequestHeader{AuthenticationToken: ua.NewTwoByteNodeID(0), RequestHandle: 7, Timestamp: time.Now()})
	}
	b, err := uasc.EncodeServiceMessage(req)
	require.NoError(t, err)
	return b
}

// TestTransportHTTPS_Protocol checks the HTTP mapping of Part 6 §7.4.4:
// POST only, the UA Binary content type, the OPCUA-SecurityPolicy header,
// size limits and the faults for requests that cannot be served.
func TestTransportHTTPS_Protocol(t *testing.T) {
	_, _, urls := transportServer(t)
	addr := urls[ua.TransportProfileHTTPS]
	getEndpoints := encodeRequest(t, &ua.GetEndpointsRequest{EndpointURL: addr})

	t.Run("binary", func(t *testing.T) {
		for _, ct := range []string{uasc.HTTPSContentType, uasc.HTTPSContentTypeLegacy, uasc.HTTPSContentType + "; charset=binary"} {
			resp, b := post(t, addr, http.MethodPost, ct, "", getEndpoints)
			require.Equal(t, http.StatusOK, resp.StatusCode, ct)
			require.Equal(t, uasc.HTTPSContentType, resp.Header.Get("Content-Type"))
			r := decodeResponse(t, b).(*ua.GetEndpointsResponse)
			require.Equal(t, uint32(7), r.ResponseHeader.RequestHandle)
			require.NotEmpty(t, r.Endpoints)
		}
	})
	t.Run("explicit None", func(t *testing.T) {
		resp, b := post(t, addr, http.MethodPost, uasc.HTTPSContentType, ua.SecurityPolicyURINone, getEndpoints)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.IsType(t, &ua.GetEndpointsResponse{}, decodeResponse(t, b))
	})
	t.Run("method", func(t *testing.T) {
		resp, _ := post(t, addr, http.MethodGet, "", "", nil)
		require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
		require.Equal(t, http.MethodPost, resp.Header.Get("Allow"))
	})
	t.Run("content type", func(t *testing.T) {
		for _, ct := range []string{"", "application/json", "text/plain", ";;"} {
			resp, _ := post(t, addr, http.MethodPost, ct, "", getEndpoints)
			require.Equal(t, http.StatusUnsupportedMediaType, resp.StatusCode, ct)
		}
	})
	t.Run("too large", func(t *testing.T) {
		resp, _ := post(t, addr, http.MethodPost, uasc.HTTPSContentType, "", make([]byte, 3<<20))
		require.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
	})
	fault := func(t *testing.T, policy string, body []byte, want ua.StatusCode) {
		t.Helper()
		resp, b := post(t, addr, http.MethodPost, uasc.HTTPSContentType, policy, body)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		r := decodeResponse(t, b)
		require.Equal(t, want, r.Header().ServiceResult, "%T", r)
	}
	t.Run("garbage", func(t *testing.T) {
		fault(t, "", []byte{1, 2, 3}, ua.StatusBadDecodingError)
		fault(t, "", nil, ua.StatusBadDecodingError)
		fault(t, "", append(getEndpoints[:6:6], 0xff), ua.StatusBadDecodingError)
	})
	t.Run("unknown service", func(t *testing.T) {
		fault(t, "", []byte{0x01, 0x00, 0x39, 0x30}, ua.StatusBadServiceUnsupported)
	})
	t.Run("not a request", func(t *testing.T) {
		b, err := uasc.EncodeServiceMessage(&ua.GetEndpointsResponse{ResponseHeader: &ua.ResponseHeader{}})
		require.NoError(t, err)
		fault(t, "", b, ua.StatusBadServiceUnsupported)
	})
	t.Run("policy not offered", func(t *testing.T) {
		fault(t, ua.SecurityPolicyURIBasic256Sha256, getEndpoints, ua.StatusBadSecurityPolicyRejected)
		fault(t, "urn:nonsense", getEndpoints, ua.StatusBadSecurityPolicyRejected)
	})
	t.Run("no secure conversation", func(t *testing.T) {
		fault(t, "", encodeRequest(t, &ua.OpenSecureChannelRequest{}), ua.StatusBadServiceUnsupported)
	})
	t.Run("no session", func(t *testing.T) {
		fault(t, "", encodeRequest(t, &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{{NodeID: ua.NewNumericNodeID(0, 2258), AttributeID: ua.AttributeIDValue}}}), ua.StatusBadSessionIDInvalid)
	})
}

// TestTransportHTTPS_TLSTrust checks the verification of the server's TLS
// certificate and the HTTPClient option.
func TestTransportHTTPS_TLSTrust(t *testing.T) {
	_, _, urls := transportServer(t)
	addr := urls[ua.TransportProfileHTTPS]

	_, err := dialClient(t, addr)
	require.ErrorContains(t, err, "certificate")

	c := newClient(t, addr, opcua.HTTPClient(uasc.NewHTTPSClient(testutil.TLS(t).ClientConfig())))
	_, err = c.ReadValue(context.Background(), ua.NewNumericNodeID(0, 2258))
	require.NoError(t, err)
}

// TestTransportHTTPS_Reconnect cuts the connections under a running
// subscription, a Publish request among them: the client reactivates its
// session and the subscription delivers again.
func TestTransportHTTPS_Reconnect(t *testing.T) {
	f, _, urls := transportServer(t)
	ctx := context.Background()
	addr := urls[ua.TransportProfileHTTPS]
	proxy := testutil.NewChaosProxy(t, hostPort(t, addr), 2)
	via := strings.Replace(addr, hostPort(t, addr), proxy.Addr(), 1)
	via = strings.Replace(via, "127.0.0.1", "localhost", 1)

	states := make(chan opcua.ConnState, 32)
	c := newClient(t, via, tlsClient(t), opcua.AutoReconnect(true), opcua.ReconnectInterval(50*time.Millisecond),
		opcua.WithConnStateChan(states))
	sub, ch, err := c.NewSubscription().Interval(fastInterval).Monitor(f.Int32).Start(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(ctx) })
	awaitValue(t, ch, 0, int32(42))

	writer := newClient(t, urls[ua.TransportProfileUATCP])

	// Cut connections: HTTPS has no connection the session depends on. A
	// request that was under way fails (and the client recovers), the next
	// one opens a new connection; the subscription goes on either way.
	proxy.DropAll()
	writeInt32(t, writer, f.Int32, 98)
	awaitValue(t, ch, 0, int32(98))

	// The server cannot be reached: the requests fail, the client reports
	// the connection lost and recovers once the server is back.
	proxy.SetRefuse(true)
	proxy.DropAll()
	awaitState(t, states, opcua.Reconnecting)
	proxy.SetRefuse(false)
	awaitState(t, states, opcua.Connected)

	writeInt32(t, writer, f.Int32, 99)
	awaitValue(t, ch, 0, int32(99))
}
