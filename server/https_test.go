// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
	"github.com/stretchr/testify/require"
)

func TestTransportConfig(t *testing.T) {
	var tc transportConfig
	addr, err := tc.bindAddr()
	require.NoError(t, err)
	require.Empty(t, addr, "no endpoints, no listener")

	tc.endpoints = []string{"opc.https://host"}
	addr, err = tc.bindAddr()
	require.NoError(t, err)
	require.Equal(t, "host:443", addr)

	tc.listen = "0.0.0.0:1"
	addr, err = tc.bindAddr()
	require.NoError(t, err)
	require.Equal(t, "0.0.0.0:1", addr)

	bad := transportConfig{endpoints: []string{"%zz://h"}}
	_, err = bad.bindAddr()
	require.ErrorIs(t, err, errors.ErrInvalidEndpoint)

	tc = transportConfig{endpoints: []string{"opc.wss://h:0", "opc.wss://h:7"}}
	tc.applyPort(&net.UnixAddr{Name: "x"})
	require.Equal(t, "opc.wss://h:0", tc.endpoints[0], "only a TCP address has a port")
	tc.applyPort(&net.TCPAddr{Port: 4843})
	require.Equal(t, []string{"opc.wss://h:4843", "opc.wss://h:7"}, tc.endpoints)
}

func TestTransportTLS(t *testing.T) {
	var cfg serverConfig
	_, err := cfg.transportTLS()
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)

	cfg.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS10}
	tc, err := cfg.transportTLS()
	require.NoError(t, err)
	require.Equal(t, uint16(tls.VersionTLS12), tc.MinVersion)
	require.Equal(t, uint16(tls.VersionTLS10), cfg.tlsConfig.MinVersion, "the caller's config is not changed")

	_, err = New(EndPoint("localhost", 0), HTTPSEndPoint("localhost", 0))
	require.NoError(t, err)
	s, err := New(EndPoint("localhost", 0), ListenOn("127.0.0.1:0"), HTTPSEndPoint("localhost", 0))
	require.NoError(t, err)
	require.ErrorIs(t, s.Start(context.Background()), errors.ErrInvalidSecurityConfig, "no certificate for TLS")
	require.NoError(t, s.Close())
}

func TestRequestHandleOf(t *testing.T) {
	require.Equal(t, uint32(0), requestHandleOf(&ua.ReadResponse{}))
	require.Equal(t, uint32(5), requestHandleOf(&ua.ReadResponse{ResponseHeader: &ua.ResponseHeader{RequestHandle: 5}}))
}

// startHTTPSServer starts a server with an HTTPS endpoint and returns it with
// the base URL to post to.
func startHTTPSServer(tb testing.TB) (*Server, string, *http.Client) {
	tb.Helper()
	pki, err := testpki.TLS()
	require.NoError(tb, err)
	s, err := New(
		EndPoint("localhost", 0),
		ListenOn("127.0.0.1:0"),
		HTTPSEndPoint("localhost", 0),
		ListenHTTPSOn("127.0.0.1:0"),
		TLSConfig(pki.ServerConfig()),
		EnableSecurity("None", ua.MessageSecurityModeNone),
		EnableAuthMode(ua.UserTokenTypeAnonymous),
	)
	require.NoError(tb, err)
	require.NoError(tb, s.Start(context.Background()))
	tb.Cleanup(func() { _ = s.Close() })
	c := uasc.NewHTTPSClient(pki.ClientConfig())
	tb.Cleanup(c.CloseIdleConnections)
	return s, "https://" + s.hs.ln.Addr().String() + "/", c
}

// postBody posts body and returns the HTTP status.
func postBody(tb testing.TB, c *http.Client, url string, body []byte) int {
	tb.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	require.NoError(tb, err)
	req.Header.Set("Content-Type", uasc.HTTPSContentType)
	resp, err := c.Do(req)
	require.NoError(tb, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestHTTPSServerClosing(t *testing.T) {
	s, url, c := startHTTPSServer(t)

	// A request without a session is answered at once with a fault.
	body, err := uasc.EncodeServiceMessage(&ua.ReadRequest{RequestHeader: &ua.RequestHeader{Timestamp: time.Now()}})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, postBody(t, c, url, body))

	ch := s.hs.vc.channels[ua.SecurityPolicyURINone]
	require.NotNil(t, ch)

	// A request whose client went away gives no response.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.Nil(t, s.hs.handle(ctx, "", body, false))

	require.NoError(t, s.Close())
	require.Nil(t, s.hs.handle(context.Background(), "", body, false), "the server has closed")

	rec := &recorder{header: http.Header{}}
	s.hs.ServeHTTP(rec, &http.Request{Method: http.MethodPost})
	require.Equal(t, http.StatusServiceUnavailable, rec.status)
}

// recorder is a minimal http.ResponseWriter.
type recorder struct {
	header http.Header
	status int
	body   strings.Builder
}

func (r *recorder) Header() http.Header         { return r.header }
func (r *recorder) Write(b []byte) (int, error) { return r.body.Write(b) }
func (r *recorder) WriteHeader(code int)        { r.status = code }

// FuzzHTTPSBody posts arbitrary request bodies. The server must answer each
// with an HTTP response and stay healthy.
func FuzzHTTPSBody(f *testing.F) {
	_, url, c := startHTTPSServer(f)
	for _, req := range []any{
		&ua.ReadRequest{RequestHeader: &ua.RequestHeader{}},
		&ua.GetEndpointsRequest{RequestHeader: &ua.RequestHeader{}},
		&ua.CreateSessionRequest{RequestHeader: &ua.RequestHeader{}},
		&ua.PublishRequest{RequestHeader: &ua.RequestHeader{}},
		&ua.ReadResponse{ResponseHeader: &ua.ResponseHeader{}},
	} {
		b, err := uasc.EncodeServiceMessage(req)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte{})
	f.Add([]byte{1, 0, 0x77, 0x02})
	f.Fuzz(func(t *testing.T, body []byte) {
		status := postBody(t, c, url, body)
		require.Contains(t, []int{http.StatusOK, http.StatusRequestEntityTooLarge}, status)
	})
}
