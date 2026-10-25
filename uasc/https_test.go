// SPDX-License-Identifier: MIT

package uasc

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// httpsPeer is an HTTPS server that answers each request with what respond
// returns for it.
type httpsPeer struct {
	*httptest.Server
	requests atomic.Int32
	lastReq  atomic.Pointer[http.Request]
	lastBody atomic.Value // []byte
}

func newHTTPSPeer(t *testing.T, respond func(w http.ResponseWriter, r *http.Request, req ua.Request)) *httpsPeer {
	t.Helper()
	return newRawHTTPSPeer(t, func(w http.ResponseWriter, r *http.Request, b []byte) {
		var req ua.Request
		if _, v, err := ua.DecodeService(b); err == nil {
			req, _ = v.(ua.Request)
		}
		respond(w, r, req)
	})
}

// newRawHTTPSPeer is newHTTPSPeer for respond functions that decode the
// body of the request themselves.
func newRawHTTPSPeer(t *testing.T, respond func(w http.ResponseWriter, r *http.Request, body []byte)) *httpsPeer {
	t.Helper()
	p := &httpsPeer{}
	p.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.requests.Add(1)
		p.lastReq.Store(r)
		b, _ := io.ReadAll(r.Body)
		p.lastBody.Store(b)
		respond(w, r, b)
	}))
	t.Cleanup(p.Close)
	return p
}

func (p *httpsPeer) endpoint() string {
	return "opc.https://" + strings.TrimPrefix(p.URL, "https://") + "/ua"
}

// writeResponse writes resp as the body of an HTTPS response.
func writeResponse(t *testing.T, w http.ResponseWriter, resp any) {
	b, err := EncodeServiceMessage(resp)
	if err != nil {
		t.Error(err)
		return
	}
	w.Header().Set("Content-Type", HTTPSContentType)
	_, _ = w.Write(b)
}

func okHeader(req ua.Request, status ua.StatusCode) *ua.ResponseHeader {
	return &ua.ResponseHeader{RequestHandle: req.Header().RequestHandle, ServiceResult: status, Timestamp: time.Now(), ServiceDiagnostics: &ua.DiagnosticInfo{}, AdditionalHeader: ua.NewExtensionObject(nil)}
}

func noneConfig() *Config {
	return &Config{SecurityPolicyURI: ua.SecurityPolicyURINone, SecurityMode: ua.MessageSecurityModeNone, RequestTimeout: 5 * time.Second, Logger: testLogger}
}

func newHTTPSTestChannel(t *testing.T, p *httpsPeer) (*SecureChannel, chan error) {
	t.Helper()
	errCh := make(chan error, 1)
	sc, err := NewHTTPSChannel(p.endpoint(), p.Client(), noneConfig(), errCh)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sc.Close() })
	return sc, errCh
}

func TestHTTPSHelpers(t *testing.T) {
	require.True(t, IsHTTPSEndpoint("opc.https://h/"))
	require.True(t, IsHTTPSEndpoint("HTTPS://h"))
	require.False(t, IsHTTPSEndpoint("opc.tcp://h"))
	require.False(t, IsHTTPSEndpoint("https"))

	u, err := HTTPSURL("opc.https://h:4843/ua?x=1")
	require.NoError(t, err)
	require.Equal(t, "https://h:4843/ua?x=1", u)
	for _, bad := range []string{"%zz://h", "opc.tcp://h", "opc.https:///x"} {
		_, err := HTTPSURL(bad)
		require.ErrorIs(t, err, errors.ErrInvalidEndpoint, bad)
	}

	require.True(t, HTTPSPolicySupported(ua.SecurityPolicyURINone))
	require.True(t, HTTPSPolicySupported(ua.SecurityPolicyURIBasic256Sha256))
	require.True(t, HTTPSPolicySupported(ua.SecurityPolicyURIECCNistP256))
	require.False(t, HTTPSPolicySupported(ua.SecurityPolicyURIECCNistP256AesGcm), "bound to a ChannelThumbprint")
	require.False(t, HTTPSPolicySupported("urn:unknown"))

	c := NewHTTPSClient(&tls.Config{MinVersion: tls.VersionTLS10})
	require.Equal(t, uint16(tls.VersionTLS12), c.Transport.(*http.Transport).TLSClientConfig.MinVersion)
	require.NotNil(t, NewHTTPSClient(nil))

	_, err = EncodeServiceMessage(struct{}{})
	require.ErrorIs(t, err, errors.ErrUnknownService)
}

func TestNewHTTPSChannelErrors(t *testing.T) {
	errCh := make(chan error, 1)
	ep := "opc.https://localhost:1"
	_, err := NewHTTPSChannel(ep, nil, nil, errCh)
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	_, err = NewHTTPSChannel(ep, nil, noneConfig(), nil)
	require.ErrorIs(t, err, errors.ErrInvalidState)
	_, err = NewHTTPSChannel("opc.tcp://h", nil, noneConfig(), errCh)
	require.ErrorIs(t, err, errors.ErrInvalidEndpoint)

	cases := []*Config{
		{SecurityPolicyURI: ua.SecurityPolicyURINone, SecurityMode: ua.MessageSecurityModeSign},
		{SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256, SecurityMode: ua.MessageSecurityModeNone},
		{SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256, SecurityMode: ua.MessageSecurityModeSign},
	}
	for _, cfg := range cases {
		_, err := NewHTTPSChannel(ep, nil, cfg, errCh)
		require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig, "%s %s", cfg.SecurityPolicyURI, cfg.SecurityMode)
	}

	p, err := testpki.Get()
	require.NoError(t, err)
	_, err = NewHTTPSChannel(ep, nil, &Config{SecurityPolicyURI: ua.SecurityPolicyURIECCNistP256AesGcm, SecurityMode: ua.MessageSecurityModeSign, LocalPrivateKey: p.ECC.Client[testpki.CurveP256].Key}, errCh)
	require.ErrorIs(t, err, errors.ErrUnsupportedSecurityPolicy)

	sc, err := NewHTTPSChannel(ep, nil, &Config{SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256, SecurityMode: ua.MessageSecurityModeSignAndEncrypt, LocalKey: p.ClientKey, Logger: testLogger}, errCh)
	require.NoError(t, err)
	require.True(t, sc.IsHTTPS())
	require.NoError(t, sc.Close())
}

func TestHTTPSRoundTrip(t *testing.T) {
	peer := newHTTPSPeer(t, func(w http.ResponseWriter, r *http.Request, req ua.Request) {
		writeResponse(t, w, &ua.GetEndpointsResponse{ResponseHeader: okHeader(req, ua.StatusOK), Endpoints: []*ua.EndpointDescription{{EndpointURL: "x"}}})
	})
	sc, _ := newHTTPSTestChannel(t, peer)
	ctx := context.Background()

	require.NoError(t, sc.Open(ctx), "nothing to open")
	require.NoError(t, sc.Renew(ctx), "nothing to renew")
	require.Nil(t, sc.RemoteAddr())

	var got *ua.GetEndpointsResponse
	err := sc.SendRequest(ctx, &ua.GetEndpointsRequest{}, ua.NewNumericNodeID(0, 7), func(r ua.Response) error {
		got = r.(*ua.GetEndpointsResponse)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, got.Endpoints, 1)

	hr := peer.lastReq.Load()
	require.Equal(t, http.MethodPost, hr.Method)
	require.Equal(t, "/ua", hr.URL.Path)
	require.Equal(t, HTTPSContentType, hr.Header.Get("Content-Type"))
	require.Equal(t, ua.SecurityPolicyURINone, hr.Header.Get(HTTPSSecurityPolicyHeader))

	// Without a handler the request is sent in the background.
	before := peer.requests.Load()
	require.NoError(t, sc.SendRequest(ctx, &ua.GetEndpointsRequest{}, nil, nil))
	require.Eventually(t, func() bool { return peer.requests.Load() == before+1 }, time.Minute, time.Millisecond)
	require.NoError(t, sc.Close())

	require.ErrorIs(t, sc.SendRequest(ctx, &ua.GetEndpointsRequest{}, nil, nil), errors.ErrSecureChannelClosed)
	require.ErrorIs(t, sc.SendRequest(ctx, &ua.GetEndpointsRequest{}, nil, func(ua.Response) error { return nil }), errors.ErrSecureChannelClosed)
	select {
	case <-sc.Disconnected():
	default:
		t.Fatal("a closed channel is disconnected")
	}
	require.Equal(t, io.EOF, sc.Close())
}

func TestHTTPSAsyncAfterClose(t *testing.T) {
	tr := &directTransport{closed: true}
	require.False(t, tr.goAsync(func() { t.Error("must not run") }))
}

func TestHTTPSFaults(t *testing.T) {
	var status atomic.Uint32
	peer := newHTTPSPeer(t, func(w http.ResponseWriter, r *http.Request, req ua.Request) {
		writeResponse(t, w, &ua.ServiceFault{ResponseHeader: okHeader(req, ua.StatusCode(status.Load()))})
	})
	sc, errCh := newHTTPSTestChannel(t, peer)
	ctx := context.Background()
	called := false
	h := func(ua.Response) error { called = true; return nil }

	// An ordinary fault goes to the caller only.
	status.Store(uint32(ua.StatusBadNodeIDUnknown))
	require.ErrorIs(t, sc.SendRequest(ctx, &ua.ReadRequest{}, nil, h), ua.StatusBadNodeIDUnknown)
	require.True(t, called, "the handler sees the fault")
	require.Empty(t, errCh)

	// A fault that asks for recovery goes to the monitor too.
	token := ua.NewNumericNodeID(0, 99)
	status.Store(uint32(ua.StatusBadSessionIDInvalid))
	require.ErrorIs(t, sc.SendRequest(ctx, &ua.ReadRequest{}, token, h), ua.StatusBadSessionIDInvalid)
	err := <-errCh
	var fault *RequestFault
	require.ErrorAs(t, err, &fault)
	require.True(t, fault.AuthToken.Equal(token))
}

func TestHTTPSBadResponses(t *testing.T) {
	var mode atomic.Int32
	peer := newHTTPSPeer(t, func(w http.ResponseWriter, r *http.Request, req ua.Request) {
		switch mode.Load() {
		case 0:
			http.Error(w, "nope", http.StatusForbidden)
		case 1:
			_, _ = w.Write([]byte{1, 2, 3})
		case 2:
			writeResponse(t, w, req) // a request, not a response
		case 3:
			_, _ = w.Write(make([]byte, MaxHTTPSMessageSize+1))
		case 4:
			// announce more than is sent, then cut the connection
			w.Header().Set("Content-Length", "1000")
			_, _ = w.Write([]byte{1})
			hj, _ := w.(http.Hijacker)
			c, _, _ := hj.Hijack()
			_ = c.Close()
		}
	})
	sc, errCh := newHTTPSTestChannel(t, peer)
	ctx := context.Background()
	h := func(ua.Response) error { return nil }

	mode.Store(0)
	require.ErrorIs(t, sc.SendRequest(ctx, &ua.ReadRequest{}, nil, h), ua.StatusBadCommunicationError)
	mode.Store(1)
	require.Error(t, sc.SendRequest(ctx, &ua.ReadRequest{}, nil, h))
	mode.Store(2)
	require.ErrorIs(t, sc.SendRequest(ctx, &ua.ReadRequest{}, nil, h), ua.StatusBadUnknownResponse)
	mode.Store(3)
	require.ErrorIs(t, sc.SendRequest(ctx, &ua.ReadRequest{}, nil, h), errors.ErrMessageTooLarge)
	require.Empty(t, errCh, "none of these is a lost connection")

	mode.Store(4)
	err := sc.SendRequest(ctx, &ua.ReadRequest{}, nil, h)
	require.ErrorIs(t, err, io.EOF, "a response cut short is a lost connection")
	require.ErrorIs(t, <-errCh, io.EOF)

	// A request this library does not know cannot be sent.
	require.ErrorIs(t, sc.SendRequest(ctx, &unknownRequest{}, nil, h), errors.ErrUnknownService)
}

// unknownRequest is a request type that is not registered.
type unknownRequest struct{ ua.ReadRequest }

func TestHTTPSTimeoutAndCancel(t *testing.T) {
	release := make(chan struct{})
	peer := newHTTPSPeer(t, func(w http.ResponseWriter, r *http.Request, req ua.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	defer close(release)
	sc, errCh := newHTTPSTestChannel(t, peer)
	h := func(ua.Response) error { return nil }

	err := sc.SendRequestWithTimeout(context.Background(), &ua.ReadRequest{}, nil, time.Millisecond, h)
	require.ErrorIs(t, err, ua.StatusBadTimeout)

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- sc.SendRequestWithTimeout(ctx, &ua.ReadRequest{}, nil, time.Minute, h) }()
	for peer.requests.Load() < 2 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	require.ErrorIs(t, <-errc, context.Canceled)

	// Closing the channel ends a request that waits.
	go func() {
		errc <- sc.SendRequestWithTimeout(context.Background(), &ua.ReadRequest{}, nil, time.Minute, h)
	}()
	for peer.requests.Load() < 3 {
		time.Sleep(time.Millisecond)
	}
	require.NoError(t, sc.Close())
	require.ErrorIs(t, <-errc, errors.ErrSecureChannelClosed)
	require.Empty(t, errCh)
}

// lateAnswer is an http.RoundTripper that answers a request only once it is
// cancelled, with an empty 200: the answer of a server handler that returned
// when it saw the cancellation, winning the race with it.
type lateAnswer struct{ started chan struct{} }

func (l lateAnswer) RoundTrip(r *http.Request) (*http.Response, error) {
	l.started <- struct{}{}
	<-r.Context().Done()
	return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
}

// A response that arrives after the request was cancelled reports why it was
// cancelled, not that it cannot be decoded.
//
// Regression (TestHTTPSTimeoutAndCancel on CI): closing the channel under a
// waiting request returned "unexpected EOF" when the server's empty answer
// won the race with the cancellation.
func TestHTTPSLateAnswerAfterCancel(t *testing.T) {
	started := make(chan struct{}, 1)
	errCh := make(chan error, 1)
	sc, err := NewHTTPSChannel("opc.https://localhost:1/ua", &http.Client{Transport: lateAnswer{started}}, noneConfig(), errCh)
	require.NoError(t, err)
	h := func(ua.Response) error { return nil }

	err = sc.SendRequestWithTimeout(context.Background(), &ua.ReadRequest{}, nil, time.Millisecond, h)
	require.ErrorIs(t, err, ua.StatusBadTimeout)
	<-started

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- sc.SendRequestWithTimeout(ctx, &ua.ReadRequest{}, nil, time.Minute, h) }()
	<-started
	cancel()
	require.ErrorIs(t, <-errc, context.Canceled)

	go func() {
		errc <- sc.SendRequestWithTimeout(context.Background(), &ua.ReadRequest{}, nil, time.Minute, h)
	}()
	<-started
	require.NoError(t, sc.Close())
	require.ErrorIs(t, <-errc, errors.ErrSecureChannelClosed)
	require.Empty(t, errCh, "none of these is a lost connection")
}

func TestHTTPSUnreachable(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	_ = l.Close()

	errCh := make(chan error, 1)
	sc, err := NewHTTPSChannel("opc.https://"+addr, nil, noneConfig(), errCh)
	require.NoError(t, err)
	defer func() { _ = sc.Close() }()
	err = sc.SendRequest(context.Background(), &ua.ReadRequest{}, nil, func(ua.Response) error { return nil })
	require.ErrorIs(t, err, io.EOF)
	require.NotErrorIs(t, err, syscall.ECONNREFUSED, "the monitor gives up on a refusal; a lost HTTPS connection is retried")
	require.ErrorIs(t, <-errCh, io.EOF)

	// A second loss while one is pending is not queued.
	err = sc.SendRequest(context.Background(), &ua.ReadRequest{}, nil, func(ua.Response) error { return nil })
	require.ErrorIs(t, err, io.EOF)
}
