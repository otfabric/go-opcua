// SPDX-License-Identifier: MIT

package uasc

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/stretchr/testify/require"
)

var testNamespaces = []string{"http://opcfoundation.org/UA/", "urn:one", "urn:two"}

func TestServiceMessageJSON(t *testing.T) {
	req := &ua.ReadRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 7, AuthenticationToken: ua.NewByteStringNodeID(0, []byte{1, 2})},
		NodesToRead:   []*ua.ReadValueID{{NodeID: ua.NewStringNodeID(2, "x"), AttributeID: ua.AttributeIDValue}},
	}
	b, err := EncodeServiceMessageJSON(req, testNamespaces)
	require.NoError(t, err)
	s := string(b)
	// Part 6 §5.4.9 and §5.4.2.16: the UaTypeId of the DataType first, the
	// fields in place, no UaEncoding or UaBody; compact (no MaxAge: 0).
	require.True(t, strings.HasPrefix(s, `{"UaTypeId":"i=629",`), s)
	require.NotContains(t, s, "UaBody")
	require.NotContains(t, s, "MaxAge")
	// Part 6 §5.4.2.10: other namespaces by their URI.
	require.Contains(t, s, `"NodeId":"nsu=urn:two;s=x"`)

	v, err := DecodeServiceMessageJSON(b, testNamespaces)
	require.NoError(t, err)
	got := v.(*ua.ReadRequest)
	require.Equal(t, uint32(7), got.RequestHeader.RequestHandle)
	require.Equal(t, "ns=2;s=x", got.NodesToRead[0].NodeID.String())

	// The verbose form, the binary encoding id and the 1.04 form decode
	// too.
	for _, doc := range []string{
		`{"UaTypeId":"i=631","RequestHeader":{"RequestHandle":3},"MaxAge":0,"TimestampsToReturn":"Both_2","NodesToRead":[]}`,
		`{"TypeId":{"Id":631},"Body":{"RequestHeader":{"RequestHandle":3}}}`,
	} {
		v, err := DecodeServiceMessageJSON([]byte(doc), nil)
		require.NoError(t, err, doc)
		require.Equal(t, uint32(3), v.(*ua.ReadRequest).RequestHeader.RequestHandle)
	}

	// What the compact form leaves out is filled in as by the binary
	// decoder.
	v, err = DecodeServiceMessageJSON([]byte(`{"UaTypeId":"i=631","NodesToRead":[{}]}`), nil)
	require.NoError(t, err)
	got = v.(*ua.ReadRequest)
	require.NotNil(t, got.RequestHeader)
	require.NotNil(t, got.RequestHeader.AuthenticationToken)
	require.NotNil(t, got.NodesToRead[0].NodeID)
	require.NotNil(t, got.NodesToRead[0].DataEncoding)

	// A fault encodes like any other response.
	b, err = EncodeServiceMessageJSON(&ua.ServiceFault{ResponseHeader: &ua.ResponseHeader{RequestHandle: 1, ServiceResult: ua.StatusBadDecodingError}}, nil)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(string(b), `{"UaTypeId":"i=395",`), string(b))
}

func TestServiceMessageJSONErrors(t *testing.T) {
	_, err := EncodeServiceMessageJSON(struct{}{}, nil)
	require.ErrorIs(t, err, errors.ErrUnknownService)

	for doc, want := range map[string]error{
		`null`:                           ua.StatusBadDecodingError,
		`{}`:                             ua.StatusBadDecodingError,
		`[1]`:                            ua.StatusBadDecodingError,
		`{"UaTypeId":"i=631"`:            ua.StatusBadDecodingError,
		`{"UaTypeId":"i=999999"}`:        ua.StatusBadDecodingError,
		`{"UaTypeId":"i=884","Low":1.5}`: ua.StatusBadServiceUnsupported, // a Range
	} {
		_, err := DecodeServiceMessageJSON([]byte(doc), nil)
		require.ErrorIs(t, err, want, doc)
	}
}

// jsonPeer is an HTTPS server that decodes JSON requests and answers each
// with what respond returns for it.
func newHTTPSJSONPeer(t *testing.T, respond func(req ua.Request) any) *httpsPeer {
	t.Helper()
	return newRawHTTPSPeer(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
		v, err := DecodeServiceMessageJSON(body, testNamespaces)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		b, err := EncodeServiceMessageJSON(respond(v.(ua.Request)), testNamespaces)
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", HTTPSJSONContentType)
		_, _ = w.Write(b)
	})
}

func TestHTTPSJSONRoundTrip(t *testing.T) {
	peer := newHTTPSJSONPeer(t, func(req ua.Request) any {
		r := req.(*ua.ReadRequest)
		return &ua.ReadResponse{ResponseHeader: okHeader(req, ua.StatusOK), Results: []*ua.DataValue{{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(r.NodesToRead[0].NodeID)}}}
	})
	errCh := make(chan error, 1)
	sc, err := NewHTTPSJSONChannel(peer.endpoint(), peer.Client(), noneConfig(), errCh)
	require.NoError(t, err)
	defer func() { _ = sc.Close() }()
	require.True(t, sc.IsHTTPS())
	require.True(t, sc.IsJSON())
	require.False(t, sc.IsWebSocketJSON())
	sc.SetNamespaces(testNamespaces)

	var got *ua.ReadResponse
	err = sc.SendRequest(context.Background(), &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{{NodeID: ua.NewStringNodeID(1, "a")}}}, nil, func(r ua.Response) error {
		got = r.(*ua.ReadResponse)
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, "ns=1;s=a", got.Results[0].Value.Value().(*ua.NodeID).String())
	hr := peer.lastReq.Load()
	require.Equal(t, HTTPSJSONContentType, hr.Header.Get("Content-Type"))
	require.Equal(t, ua.SecurityPolicyURINone, hr.Header.Get(HTTPSSecurityPolicyHeader))
	require.Contains(t, string(peer.lastBody.Load().([]byte)), `"nsu=urn:one;s=a"`)

	// An undecodable response is an error of the request, not a lost
	// connection.
	bad := newRawHTTPSPeer(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) { _, _ = io.WriteString(w, "{") })
	sc2, err := NewHTTPSJSONChannel(bad.endpoint(), bad.Client(), noneConfig(), errCh)
	require.NoError(t, err)
	defer func() { _ = sc2.Close() }()
	err = sc2.SendRequest(context.Background(), &ua.ReadRequest{}, nil, func(ua.Response) error { return nil })
	require.ErrorIs(t, err, ua.StatusBadDecodingError)
	// A request is not a response.
	req := newRawHTTPSPeer(t, func(w http.ResponseWriter, _ *http.Request, body []byte) { _, _ = w.Write(body) })
	sc3, err := NewHTTPSJSONChannel(req.endpoint(), req.Client(), noneConfig(), errCh)
	require.NoError(t, err)
	defer func() { _ = sc3.Close() }()
	err = sc3.SendRequest(context.Background(), &ua.ReadRequest{}, nil, func(ua.Response) error { return nil })
	require.ErrorIs(t, err, ua.StatusBadUnknownResponse)
	require.Empty(t, errCh)
}

func TestSetNamespacesOnSecureConversation(t *testing.T) {
	sc := &SecureChannel{}
	sc.SetNamespaces(testNamespaces) // no effect, no panic
	require.False(t, sc.IsJSON())
	require.False(t, sc.IsHTTPS())
	require.False(t, sc.IsWebSocketJSON())
}

// wssJSONPeer is a WebSocket server with the sub-protocol opcua+uajson.
// serve handles each connection.
type wssJSONPeer struct {
	l     *uacp.Listener
	url   string
	conns atomic.Int32
	wg    sync.WaitGroup
}

func newWSSJSONPeer(t *testing.T, serve func(c uacp.MessageConn)) *wssJSONPeer {
	t.Helper()
	pki, err := testpki.TLS()
	require.NoError(t, err)
	l, err := uacp.ListenWebSocket(context.Background(), "opc.wss://localhost:0/ua", pki.ServerConfig(), nil)
	require.NoError(t, err)
	p := &wssJSONPeer{l: l, url: fmt.Sprintf("opc.wss://localhost:%d/ua", l.Addr().(*net.TCPAddr).Port)}
	l.ServeWebSocketJSON(func(c uacp.MessageConn) {
		p.conns.Add(1)
		p.wg.Add(1)
		defer p.wg.Done()
		defer func() { _ = c.Close() }()
		serve(c)
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			if _, err := l.Accept(ctx); err != nil && strings.Contains(err.Error(), "closed") {
				return
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = l.Close()
		<-done
		p.wg.Wait()
	})
	return p
}

// answer serves requests one after the other with respond.
func answer(respond func(req ua.Request) any) func(c uacp.MessageConn) {
	return func(c uacp.MessageConn) {
		for {
			b, err := c.ReadMessage(1 << 20)
			if err != nil {
				return
			}
			v, err := DecodeServiceMessageJSON(b, testNamespaces)
			if err != nil {
				return
			}
			resp := respond(v.(ua.Request))
			if resp == nil {
				return
			}
			out, err := EncodeServiceMessageJSON(resp, testNamespaces)
			if err != nil {
				return
			}
			if err := c.WriteMessage(out); err != nil {
				return
			}
		}
	}
}

func (p *wssJSONPeer) channel(t *testing.T) (*SecureChannel, chan error) {
	t.Helper()
	pki, err := testpki.TLS()
	require.NoError(t, err)
	errCh := make(chan error, 1)
	sc, err := NewWebSocketJSONChannel(p.url, &uacp.Dialer{TLSConfig: pki.ClientConfig()}, noneConfig(), errCh)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sc.Close() })
	return sc, errCh
}

func TestWebSocketJSONRoundTrip(t *testing.T) {
	peer := newWSSJSONPeer(t, answer(func(req ua.Request) any {
		return &ua.GetEndpointsResponse{ResponseHeader: okHeader(req, ua.StatusOK), Endpoints: []*ua.EndpointDescription{{EndpointURL: "x"}}}
	}))
	sc, errCh := peer.channel(t)
	ctx := context.Background()
	require.True(t, sc.IsWebSocketJSON())
	require.True(t, sc.IsJSON())
	require.False(t, sc.IsHTTPS())
	require.NoError(t, sc.Open(ctx), "nothing to open")
	require.NoError(t, sc.Renew(ctx), "nothing to renew")

	for range 3 {
		var got *ua.GetEndpointsResponse
		err := sc.SendRequest(ctx, &ua.GetEndpointsRequest{}, nil, func(r ua.Response) error {
			got = r.(*ua.GetEndpointsResponse)
			return nil
		})
		require.NoError(t, err)
		require.Len(t, got.Endpoints, 1)
	}
	require.Equal(t, int32(1), peer.conns.Load(), "sequential requests share a WebSocket")

	// Without a handler the request is sent in the background.
	require.NoError(t, sc.SendRequest(ctx, &ua.GetEndpointsRequest{}, nil, nil))
	require.NoError(t, sc.Close())
	require.ErrorIs(t, sc.SendRequest(ctx, &ua.GetEndpointsRequest{}, nil, nil), errors.ErrSecureChannelClosed)
	require.Empty(t, errCh)
}

func TestWebSocketJSONConcurrent(t *testing.T) {
	// The peer serves the requests of a WebSocket one after the other and
	// holds the Publish requests until released.
	release := make(chan struct{})
	peer := newWSSJSONPeer(t, answer(func(req ua.Request) any {
		if _, ok := req.(*ua.PublishRequest); ok {
			<-release
		}
		return &ua.ServiceFault{ResponseHeader: okHeader(req, ua.StatusOK)}
	}))
	sc, _ := peer.channel(t)
	ctx := context.Background()
	h := func(ua.Response) error { return nil }

	const parked = 3
	errc := make(chan error, parked)
	for range parked {
		go func() { errc <- sc.SendRequest(ctx, &ua.PublishRequest{}, nil, h) }()
	}
	require.Eventually(t, func() bool { return peer.conns.Load() == parked }, time.Minute, time.Millisecond)
	// A Read is not held up behind the Publish requests.
	require.NoError(t, sc.SendRequest(ctx, &ua.ReadRequest{}, nil, h))
	close(release)
	for range parked {
		require.NoError(t, <-errc)
	}
}

func TestWebSocketJSONTimeoutAndCancel(t *testing.T) {
	block := make(chan struct{})
	peer := newWSSJSONPeer(t, answer(func(req ua.Request) any {
		<-block
		return nil
	}))
	t.Cleanup(func() { close(block) }) // before the peer's cleanup
	sc, errCh := peer.channel(t)
	h := func(ua.Response) error { return nil }

	err := sc.SendRequestWithTimeout(context.Background(), &ua.ReadRequest{}, nil, time.Millisecond, h)
	require.ErrorIs(t, err, ua.StatusBadTimeout)

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- sc.SendRequestWithTimeout(ctx, &ua.ReadRequest{}, nil, time.Minute, h) }()
	require.Eventually(t, func() bool { return peer.conns.Load() == 2 }, time.Minute, time.Millisecond)
	cancel()
	require.ErrorIs(t, <-errc, context.Canceled)

	go func() { errc <- sc.SendRequestWithTimeout(context.Background(), &ua.ReadRequest{}, nil, time.Minute, h) }()
	require.Eventually(t, func() bool { return peer.conns.Load() == 3 }, time.Minute, time.Millisecond)
	require.NoError(t, sc.Close())
	require.ErrorIs(t, <-errc, errors.ErrSecureChannelClosed)
	require.Empty(t, errCh, "none of these is a lost connection")
}

func TestWebSocketJSONBadResponses(t *testing.T) {
	tests := []struct {
		name  string
		serve func(c uacp.MessageConn)
		want  error
		lost  bool
	}{
		{"other request", answer(func(req ua.Request) any {
			return &ua.ReadResponse{ResponseHeader: &ua.ResponseHeader{RequestHandle: req.Header().RequestHandle + 1}}
		}), ua.StatusBadUnknownResponse, false},
		{"undecodable", func(c uacp.MessageConn) {
			_, _ = c.ReadMessage(1 << 20)
			_ = c.WriteMessage([]byte("{"))
		}, ua.StatusBadDecodingError, false},
		{"too large", func(c uacp.MessageConn) {
			_, _ = c.ReadMessage(1 << 20)
			_ = c.WriteMessage(make([]byte, MaxWebSocketJSONMessageSize+1))
			_, _ = c.ReadMessage(1 << 20) // the close frame
		}, errors.ErrMessageTooLarge, false},
		{"closed", func(c uacp.MessageConn) {
			_, _ = c.ReadMessage(1 << 20)
		}, io.EOF, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peer := newWSSJSONPeer(t, tt.serve)
			sc, errCh := peer.channel(t)
			err := sc.SendRequest(context.Background(), &ua.ReadRequest{}, nil, func(ua.Response) error { return nil })
			require.ErrorIs(t, err, tt.want)
			if tt.lost {
				require.ErrorIs(t, <-errCh, io.EOF)
			} else {
				require.Empty(t, errCh)
			}
		})
	}
}

func TestWebSocketJSONUnreachable(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	_ = l.Close()

	errCh := make(chan error, 1)
	sc, err := NewWebSocketJSONChannel("opc.wss://"+addr, nil, noneConfig(), errCh)
	require.NoError(t, err)
	defer func() { _ = sc.Close() }()
	err = sc.SendRequest(context.Background(), &ua.ReadRequest{}, nil, func(ua.Response) error { return nil })
	require.ErrorIs(t, err, io.EOF)
	require.ErrorIs(t, <-errCh, io.EOF)
}

func TestNewWebSocketJSONChannelErrors(t *testing.T) {
	errCh := make(chan error, 1)
	ep := "opc.wss://localhost:1"
	_, err := NewWebSocketJSONChannel(ep, nil, nil, errCh)
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	_, err = NewWebSocketJSONChannel(ep, nil, noneConfig(), nil)
	require.ErrorIs(t, err, errors.ErrInvalidState)
	_, err = NewWebSocketJSONChannel("opc.https://h", nil, noneConfig(), errCh)
	require.ErrorIs(t, err, errors.ErrInvalidEndpoint)

	p, err := testpki.Get()
	require.NoError(t, err)
	_, err = NewWebSocketJSONChannel(ep, nil, &Config{SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256, SecurityMode: ua.MessageSecurityModeSign, LocalKey: p.ClientKey}, errCh)
	require.ErrorIs(t, err, errors.ErrUnsupportedSecurityPolicy)
}

// fakeConn is a MessageConn that only records that it was closed.
type fakeConn struct {
	uacp.MessageConn
	closed atomic.Bool
}

func (c *fakeConn) Close() error { c.closed.Store(true); return nil }

func TestWebSocketPool(t *testing.T) {
	var dialed atomic.Int32
	p := &wsPool{
		dial: func(context.Context) (uacp.MessageConn, error) {
			dialed.Add(1)
			return &fakeConn{}, nil
		},
		conns: make(map[uacp.MessageConn]struct{}),
	}
	ctx := context.Background()

	// Idle WebSockets are reused, up to maxIdleWebSockets are kept.
	var busy []uacp.MessageConn
	for range maxIdleWebSockets + 1 {
		c, err := p.get(ctx)
		require.NoError(t, err)
		busy = append(busy, c)
	}
	for _, c := range busy {
		p.put(c)
	}
	require.Len(t, p.idle, maxIdleWebSockets)
	require.True(t, busy[maxIdleWebSockets].(*fakeConn).closed.Load())
	c, err := p.get(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(maxIdleWebSockets+1), dialed.Load())
	p.put(c)

	// A WebSocket idle for too long is closed instead of reused.
	for i := range p.idle {
		p.idle[i].since = time.Now().Add(-webSocketIdleTimeout)
	}
	stale := p.idle[0].c.(*fakeConn)
	c, err = p.get(ctx)
	require.NoError(t, err)
	require.True(t, stale.closed.Load())
	require.Empty(t, p.idle)
	require.Len(t, p.conns, 1)

	// After close nothing is handed out, and what comes back is closed.
	p.close()
	require.True(t, c.(*fakeConn).closed.Load())
	_, err = p.get(ctx)
	require.ErrorIs(t, err, errors.ErrSecureChannelClosed)
	late := &fakeConn{}
	p.put(late)
	require.True(t, late.closed.Load())

	// A WebSocket dialed while the channel closed is closed.
	q := &wsPool{conns: make(map[uacp.MessageConn]struct{})}
	dialing := &fakeConn{}
	q.dial = func(context.Context) (uacp.MessageConn, error) { q.close(); return dialing, nil }
	_, err = q.get(ctx)
	require.ErrorIs(t, err, errors.ErrSecureChannelClosed)
	require.True(t, dialing.closed.Load())
}
