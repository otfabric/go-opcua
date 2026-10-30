// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/otfabric/go-opcua/uasc"
	"github.com/stretchr/testify/require"
)

// startUAJSONServer starts a server with opc.https and opc.wss endpoints
// that serve UA JSON. It returns the server, the https URL to post to, an
// HTTP client and the opc.wss URL.
func startUAJSONServer(tb testing.TB, opts ...Option) (*Server, string, *http.Client, string) {
	tb.Helper()
	pki, err := testpki.TLS()
	require.NoError(tb, err)
	defaults := []Option{
		EndPoint("localhost", 0),
		ListenOn("127.0.0.1:0"),
		HTTPSEndPoint("localhost", 0),
		ListenHTTPSOn("127.0.0.1:0"),
		WebSocketEndPoint("localhost", 0),
		TLSConfig(pki.ServerConfig()),
		EnableUAJSON(),
		EnableAuthMode(ua.UserTokenTypeAnonymous),
	}
	s, err := New(append(defaults, opts...)...)
	require.NoError(tb, err)
	require.NoError(tb, s.Start(context.Background()))
	tb.Cleanup(func() { _ = s.Close() })
	c := uasc.NewHTTPSClient(pki.ClientConfig())
	tb.Cleanup(c.CloseIdleConnections)
	return s, "https://" + s.hs.ln.Addr().String() + "/", c, "opc.wss://" + s.wl.Addr().String()
}

// postJSON posts body with the content type and encoding and returns the
// HTTP response with its body.
func postJSON(tb testing.TB, c *http.Client, url, contentType, encoding string, body []byte) (*http.Response, []byte) {
	tb.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	require.NoError(tb, err)
	req.Header.Set("Content-Type", contentType)
	if encoding != "" {
		req.Header.Set("Content-Encoding", encoding)
	}
	resp, err := c.Do(req)
	require.NoError(tb, err)
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	require.NoError(tb, err)
	return resp, b
}

func decodeJSONResponse(t *testing.T, b []byte) ua.Response {
	t.Helper()
	v, err := uasc.DecodeServiceMessageJSON(b, nil)
	require.NoError(t, err, string(b))
	return v.(ua.Response)
}

func TestHTTPSJSON(t *testing.T) {
	_, url, c, _ := startUAJSONServer(t, InsecureNoSecurity())
	getEndpoints := []byte(`{"UaTypeId":"i=426","RequestHeader":{"RequestHandle":9}}`)

	for _, ct := range []string{uasc.HTTPSJSONContentType, uasc.HTTPSJSONContentTypeLegacy, "application/json; charset=utf-8"} {
		resp, b := postJSON(t, c, url, ct, "", getEndpoints)
		require.Equal(t, http.StatusOK, resp.StatusCode, ct)
		mt := strings.Split(ct, ";")[0]
		require.Equal(t, mt, resp.Header.Get("Content-Type"), "the media type of the request")
		r := decodeJSONResponse(t, b).(*ua.GetEndpointsResponse)
		require.Equal(t, uint32(9), r.ResponseHeader.RequestHandle)
		var profiles []string
		for _, ep := range r.Endpoints {
			profiles = append(profiles, ep.TransportProfileURI)
		}
		require.Contains(t, profiles, ua.TransportProfileHTTPSJSON)
		require.Contains(t, profiles, ua.TransportProfileWSSJSON)
	}

	// A gzip compressed message (Part 6 §7.4.5).
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	_, _ = zw.Write(getEndpoints)
	require.NoError(t, zw.Close())
	resp, b := postJSON(t, c, url, uasc.HTTPSJSONContentType, "gzip", z.Bytes())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, uint32(9), decodeJSONResponse(t, b).Header().RequestHandle)

	// What cannot be decoded is answered with a fault that carries the
	// RequestHandle if it can be found.
	for doc, want := range map[string]struct {
		status ua.StatusCode
		handle uint32
	}{
		`{"UaTypeId":"i=631","RequestHeader":{"RequestHandle":4},"NodesToRead":7}`:        {ua.StatusBadDecodingError, 4},
		`{"TypeId":{"Id":631},"Body":{"RequestHeader":{"RequestHandle":5},"MaxAge":"x"}}`: {ua.StatusBadDecodingError, 5},
		`{"UaTypeId":"i=884","Low":1}`:                              {ua.StatusBadServiceUnsupported, 0},
		`{"UaTypeId":"i=634","ResponseHeader":{"RequestHandle":3}}`: {ua.StatusBadServiceUnsupported, 0},
		`{`: {ua.StatusBadDecodingError, 0},
	} {
		resp, b := postJSON(t, c, url, uasc.HTTPSJSONContentType, "", []byte(doc))
		require.Equal(t, http.StatusOK, resp.StatusCode, doc)
		f := decodeJSONResponse(t, b).(*ua.ServiceFault)
		require.Equal(t, want.status, f.ResponseHeader.ServiceResult, doc)
		require.Equal(t, want.handle, f.ResponseHeader.RequestHandle, doc)
	}

	// HTTP errors.
	resp, _ = postJSON(t, c, url, uasc.HTTPSJSONContentType, "gzip", []byte("not gzip"))
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp, _ = postJSON(t, c, url, uasc.HTTPSJSONContentType, "br", getEndpoints)
	require.Equal(t, http.StatusUnsupportedMediaType, resp.StatusCode)
	resp, _ = postJSON(t, c, url, uasc.HTTPSContentType, "gzip", getEndpoints)
	require.Equal(t, http.StatusUnsupportedMediaType, resp.StatusCode, "binary bodies are not compressed")
	resp, _ = postJSON(t, c, url, "text/plain", "", getEndpoints)
	require.Equal(t, http.StatusUnsupportedMediaType, resp.StatusCode)
	z.Reset()
	zw = gzip.NewWriter(&z)
	_, _ = zw.Write(bytes.Repeat([]byte(" "), httpsMaxRequestSize+1))
	require.NoError(t, zw.Close())
	resp, _ = postJSON(t, c, url, uasc.HTTPSJSONContentType, "gzip", z.Bytes())
	require.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode, "the limit applies decompressed")
}

func TestHTTPSJSONDisabled(t *testing.T) {
	_, url, c := startHTTPSServer(t)
	resp, b := postJSON(t, c, url, uasc.HTTPSJSONContentType, "", []byte(`{"UaTypeId":"i=426"}`))
	require.Equal(t, http.StatusUnsupportedMediaType, resp.StatusCode)
	require.NotContains(t, string(b), "application/json")
}

func TestJSONRequestHandle(t *testing.T) {
	require.Equal(t, uint32(0), jsonRequestHandle([]byte(`[`)))
	require.Equal(t, uint32(0), jsonRequestHandle([]byte(`{}`)))
	require.Equal(t, uint32(3), jsonRequestHandle([]byte(`{"RequestHeader":{"RequestHandle":3}}`)))
	require.Equal(t, uint32(4), jsonRequestHandle([]byte(`{"Body":{"RequestHeader":{"RequestHandle":4}}}`)))
}

func TestEncodeDirectResponseFallback(t *testing.T) {
	s, _, _, _ := startUAJSONServer(t, InsecureNoSecurity())
	// A Variant of an unsupported Go type cannot be encoded: a fault with
	// BadEncodingError goes out instead.
	resp := &ua.ReadResponse{ResponseHeader: &ua.ResponseHeader{RequestHandle: 2}, Results: []*ua.DataValue{{EncodingMask: ua.DataValueValue, Value: &ua.Variant{}}}}
	for _, isJSON := range []bool{true, false} {
		b, err := s.encodeDirectResponse(resp, isJSON)
		require.NoError(t, err)
		require.NotEmpty(t, b)
	}
	require.NotEmpty(t, s.namespaceURIs())
	require.Nil(t, (&Server{}).namespaceURIs())
}

func TestUAJSONEndpoints(t *testing.T) {
	pki, err := testpki.Get()
	require.NoError(t, err)
	tests := []struct {
		name      string
		opts      []Option
		wssJSON   bool
		httpsJSON int // number of https-uajson endpoints
	}{
		{"none", []Option{InsecureNoSecurity()}, true, 1},
		{"signed only", []Option{
			EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSign),
			PrivateKey(pki.ServerKey), Certificate(pki.ServerCert),
		}, false, 1},
		{"both", []Option{
			InsecureNoSecurity(),
			EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
			PrivateKey(pki.ServerKey), Certificate(pki.ServerCert),
		}, true, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, _, _, _ := startUAJSONServer(t, tt.opts...)
			require.Equal(t, tt.wssJSON, s.wj != nil)
			var wss, https int
			for _, ep := range s.Endpoints() {
				switch ep.TransportProfileURI {
				case ua.TransportProfileWSSJSON:
					wss++
					require.Equal(t, ua.SecurityPolicyURINone, ep.SecurityPolicyURI)
					require.Equal(t, ua.MessageSecurityModeNone, ep.SecurityMode)
				case ua.TransportProfileHTTPSJSON:
					https++
				}
			}
			if tt.wssJSON && len(tt.opts) > 0 {
				require.Equal(t, 1, wss)
			}
			if !tt.wssJSON {
				require.Zero(t, wss)
			}
			require.Equal(t, tt.httpsJSON, https)
		})
	}
}

func TestUAJSONUserTokenOnNone(t *testing.T) {
	// TLS protects the user token on the JSON endpoints, as on HTTPS.
	s, _, _, _ := startUAJSONServer(t,
		InsecureNoSecurity(),
		EnableAuthMode(ua.UserTokenTypeUserName))
	for _, ep := range s.Endpoints() {
		var hasUser bool
		for _, tok := range ep.UserIdentityTokens {
			hasUser = hasUser || tok.TokenType == ua.UserTokenTypeUserName
		}
		require.Equal(t, tlsOnly(ep.TransportProfileURI), hasUser, ep.TransportProfileURI)
	}
}

// wssJSONClient opens an opcua+uajson WebSocket to url.
func wssJSONClient(t *testing.T, url string) uacp.MessageConn {
	t.Helper()
	pki, err := testpki.TLS()
	require.NoError(t, err)
	c, err := (&uacp.Dialer{TLSConfig: pki.ClientConfig()}).DialWebSocketJSON(context.Background(), url)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	require.NoError(t, c.SetReadDeadline(time.Now().Add(30*time.Second)))
	return c
}

func roundTrip(t *testing.T, c uacp.MessageConn, req string) ua.Response {
	t.Helper()
	require.NoError(t, c.WriteMessage([]byte(req)))
	b, err := c.ReadMessage(1 << 24)
	require.NoError(t, err)
	return decodeJSONResponse(t, b)
}

func TestWSSJSON(t *testing.T) {
	_, _, _, url := startUAJSONServer(t, InsecureNoSecurity())
	c := wssJSONClient(t, url)

	r := roundTrip(t, c, `{"UaTypeId":"i=426","RequestHeader":{"RequestHandle":11}}`)
	require.Equal(t, uint32(11), r.Header().RequestHandle)
	require.NotEmpty(t, r.(*ua.GetEndpointsResponse).Endpoints)

	// A request that cannot be decoded is answered with a fault; the
	// connection stays usable.
	f := roundTrip(t, c, `{"UaTypeId":"i=631","RequestHeader":{"RequestHandle":12},"NodesToRead":1}`).(*ua.ServiceFault)
	require.Equal(t, ua.StatusBadDecodingError, f.ResponseHeader.ServiceResult)
	require.Equal(t, uint32(12), f.ResponseHeader.RequestHandle)
	f = roundTrip(t, c, `{"UaTypeId":"i=631","RequestHeader":{"RequestHandle":13}}`).(*ua.ServiceFault)
	require.Equal(t, ua.StatusBadSessionIDInvalid, f.ResponseHeader.ServiceResult)
}

func TestWSSJSONConcurrentRequests(t *testing.T) {
	_, _, _, url := startUAJSONServer(t, InsecureNoSecurity())
	c := wssJSONClient(t, url)

	// Several requests in flight at once on one connection are all
	// answered, each with its RequestHandle.
	const n = 10
	for i := range n {
		require.NoError(t, c.WriteMessage([]byte(`{"UaTypeId":"i=426","RequestHeader":{"RequestHandle":`+strconv.Itoa(100+i)+`}}`)))
	}
	seen := make(map[uint32]bool)
	for range n {
		b, err := c.ReadMessage(1 << 24)
		require.NoError(t, err)
		seen[decodeJSONResponse(t, b).Header().RequestHandle] = true
	}
	for i := range n {
		require.True(t, seen[uint32(100+i)], "handle %d", 100+i)
	}
}

func TestWSSJSONTooLarge(t *testing.T) {
	_, _, _, url := startUAJSONServer(t, InsecureNoSecurity())
	c := wssJSONClient(t, url)
	// The server ends the connection (with status 1009, Part 6 §7.5.2) as
	// soon as it sees the length of the message, so the write may fail.
	_ = c.WriteMessage(make([]byte, httpsMaxRequestSize+1))
	_, err := c.ReadMessage(1 << 24)
	require.Error(t, err)
}

func TestWSSJSONClose(t *testing.T) {
	s, _, _, url := startUAJSONServer(t, InsecureNoSecurity())
	c := wssJSONClient(t, url)
	_ = roundTrip(t, c, `{"UaTypeId":"i=426"}`)

	// Closing the server closes the connection.
	require.NoError(t, s.Close())
	_, err := c.ReadMessage(1 << 24)
	require.Error(t, err)

	// A connection handed over after the close is closed at once.
	w := newWSSJSONServer(s)
	w.close()
	fc := &closedConn{}
	w.serve(fc)
	require.True(t, fc.closed)
}

// closedConn is a MessageConn that records Close.
type closedConn struct {
	uacp.MessageConn
	mu     sync.Mutex
	closed bool
}

func (c *closedConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func TestWSSJSONConnDeadlines(t *testing.T) {
	dc := &deadlineConn{}
	cc := &wssJSONConn{c: dc}
	cc.begin()
	require.True(t, dc.last().IsZero(), "no idle timeout while a request is in flight")
	cc.begin()
	cc.end()
	require.True(t, dc.last().IsZero())
	cc.end()
	require.False(t, dc.last().IsZero(), "idle again")
}

// deadlineConn is a MessageConn that records its read deadline.
type deadlineConn struct {
	uacp.MessageConn
	mu sync.Mutex
	dl time.Time
}

func (c *deadlineConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dl = t
	return nil
}

func (c *deadlineConn) last() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dl
}

// FuzzHTTPSJSONBody posts arbitrary JSON request bodies. The server must
// answer each with an HTTP response and stay healthy.
func FuzzHTTPSJSONBody(f *testing.F) {
	_, url, c, _ := startUAJSONServer(f, InsecureNoSecurity())
	for _, req := range []any{
		&ua.ReadRequest{RequestHeader: &ua.RequestHeader{}, NodesToRead: []*ua.ReadValueID{{NodeID: ua.NewStringNodeID(1, "x")}}},
		&ua.GetEndpointsRequest{RequestHeader: &ua.RequestHeader{}},
		&ua.CreateSessionRequest{RequestHeader: &ua.RequestHeader{}},
		&ua.PublishRequest{RequestHeader: &ua.RequestHeader{}},
		&ua.ReadResponse{ResponseHeader: &ua.ResponseHeader{}},
	} {
		b, err := uasc.EncodeServiceMessageJSON(req, nil)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte(`{"TypeId":{"Id":631},"Body":{}}`))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, body []byte) {
		resp, b := postJSON(t, c, url, uasc.HTTPSJSONContentType, "", body)
		require.Contains(t, []int{http.StatusOK, http.StatusRequestEntityTooLarge}, resp.StatusCode)
		if resp.StatusCode == http.StatusOK {
			_ = decodeJSONResponse(t, b)
		}
	})
}
