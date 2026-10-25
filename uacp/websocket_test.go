// SPDX-License-Identifier: MIT

package uacp

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func tlsPKI(t *testing.T) *testpki.TLSPKI {
	t.Helper()
	p, err := testpki.TLS()
	require.NoError(t, err)
	return p
}

// wsListener starts a WebSocket listener on a free port and returns it with
// the URL to dial.
func wsListener(t *testing.T, path string) (*Listener, string) {
	t.Helper()
	l, err := ListenWebSocket(context.Background(), "opc.wss://localhost:0"+path, tlsPKI(t).ServerConfig(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	return l, fmt.Sprintf("opc.wss://localhost:%d%s", l.Addr().(*net.TCPAddr).Port, path)
}

func TestWebSocketDialAndExchange(t *testing.T) {
	l, url := wsListener(t, "/ua")
	ctx := context.Background()

	accepted := make(chan *Conn, 1)
	go func() {
		c, err := l.Accept(ctx)
		if err == nil {
			accepted <- c
		}
		close(accepted)
	}()

	d := &Dialer{TLSConfig: tlsPKI(t).ClientConfig()}
	c, err := d.Dial(ctx, url)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	s := <-accepted
	require.NotNil(t, s)
	defer func() { _ = s.Close() }()

	require.Nil(t, c.TCPConn, "a WebSocket connection has no TCP connection of its own")
	require.NotNil(t, c.LocalAddr())
	require.NotNil(t, s.RemoteAddr())
	require.Equal(t, DefaultServerACK.MaxChunkCount, c.MaxChunkCount())

	// UACP messages travel both ways, one frame each.
	require.NoError(t, c.Send("MSGF", &Hello{EndpointURL: "x"}))
	b, err := s.Receive()
	require.NoError(t, err)
	require.Equal(t, "MSGF", string(b[:4]))
	require.NoError(t, s.Send("MSGF", &Acknowledge{ReceiveBufSize: 7}))
	b, err = c.Receive()
	require.NoError(t, err)
	require.Equal(t, "MSGF", string(b[:4]))

	// A closing peer ends the stream with io.EOF, as on TCP.
	require.NoError(t, c.Close())
	_, err = s.Receive()
	require.ErrorIs(t, err, io.EOF)
}

func TestWebSocketDialFailures(t *testing.T) {
	l, url := wsListener(t, "/")
	ctx := context.Background()
	// The listener only handshakes while somebody accepts.
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for {
			if _, err := l.Accept(ctx); errors.Is(err, net.ErrClosed) {
				return
			}
		}
	}()
	t.Cleanup(func() { _ = l.Close(); <-drained })

	t.Run("untrusted server", func(t *testing.T) {
		_, err := (&Dialer{}).Dial(ctx, url) // system roots do not know the test CA
		require.ErrorContains(t, err, "TLS handshake")
	})
	t.Run("wrong name", func(t *testing.T) {
		cfg := tlsPKI(t).ClientConfig()
		cfg.ServerName = "example.com"
		_, err := (&Dialer{TLSConfig: cfg}).Dial(ctx, url)
		require.ErrorContains(t, err, "TLS handshake")
	})
	t.Run("invalid url", func(t *testing.T) {
		for _, u := range []string{"opc.wss://", "opc.wss://h:x", "opc.wss://h:99999", "opc.wss://%zz"} {
			_, err := (&Dialer{}).Dial(ctx, u)
			require.ErrorIs(t, err, errors.ErrInvalidEndpoint, u)
		}
	})
	t.Run("refused", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		addr := l.Addr().String()
		_ = l.Close()
		_, err = (&Dialer{}).Dial(ctx, "opc.wss://"+addr)
		require.Error(t, err)
	})
	t.Run("not a websocket server", func(t *testing.T) {
		// A TLS server that answers the upgrade with 404.
		ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsPKI(t).ServerConfig())
		require.NoError(t, err)
		defer func() { _ = ln.Close() }()
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer func() { _ = c.Close() }()
			if _, err := http.ReadRequest(bufio.NewReader(c)); err == nil {
				_, _ = io.WriteString(c, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
			}
		}()
		_, err = (&Dialer{TLSConfig: tlsPKI(t).ClientConfig()}).Dial(ctx, "opc.wss://localhost:"+fmt.Sprint(ln.Addr().(*net.TCPAddr).Port))
		require.ErrorContains(t, err, "WebSocket upgrade")
	})
	t.Run("timeout", func(t *testing.T) {
		// A TCP server that never answers the TLS handshake.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer func() { _ = ln.Close() }()
		go func() {
			c, err := ln.Accept()
			if err == nil {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(io.Discard, c)
			}
		}()
		d := &Dialer{Dialer: &net.Dialer{Timeout: 50 * time.Millisecond}, TLSConfig: tlsPKI(t).ClientConfig()}
		_, err = d.Dial(ctx, "opc.wss://"+ln.Addr().String())
		require.Error(t, err)
	})
}

func TestWebSocketListenerRejects(t *testing.T) {
	l, url := wsListener(t, "/")
	ctx := context.Background()
	addr := l.Addr().String()

	accept := func() error {
		_, err := l.Accept(ctx)
		return err
	}

	t.Run("plain tcp", func(t *testing.T) {
		c, err := net.Dial("tcp", addr)
		require.NoError(t, err)
		_, _ = c.Write([]byte("HELF\x20\x00\x00\x00"))
		require.ErrorContains(t, accept(), "TLS handshake")
		_ = c.Close()
	})
	t.Run("tls without upgrade", func(t *testing.T) {
		c, err := tls.Dial("tcp", addr, tlsPKI(t).ClientConfig())
		require.NoError(t, err)
		_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
		require.ErrorContains(t, accept(), "WebSocket upgrade")
		_ = c.Close()
	})
	t.Run("wrong endpoint in HEL", func(t *testing.T) {
		errc := make(chan error, 1)
		go func() { errc <- accept() }()
		u := url[:len(url)-1] + "/other"
		_, err := (&Dialer{TLSConfig: tlsPKI(t).ClientConfig()}).Dial(ctx, u)
		require.ErrorIs(t, err, ua.StatusBadTCPEndpointURLInvalid)
		require.ErrorIs(t, <-errc, errors.ErrInvalidEndpoint)
	})
}

func TestListenWebSocketErrors(t *testing.T) {
	ctx := context.Background()
	_, err := ListenWebSocket(ctx, "opc.tcp://127.0.0.1:0", tlsPKI(t).ServerConfig(), nil)
	require.ErrorIs(t, err, errors.ErrInvalidEndpoint)
	_, err = ListenWebSocket(ctx, "opc.wss://127.0.0.1:0", nil, nil)
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	_, err = ListenWebSocket(ctx, "opc.wss://127.0.0.1:0", &tls.Config{}, nil)
	require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	_, err = ListenWebSocket(ctx, "opc.wss://256.0.0.1:0", tlsPKI(t).ServerConfig(), nil)
	require.Error(t, err)
}

func TestWebSocketEndpointHelpers(t *testing.T) {
	require.True(t, IsWebSocketEndpoint("opc.wss://h:1/"))
	require.True(t, IsWebSocketEndpoint("OPC.WSS://h"))
	require.False(t, IsWebSocketEndpoint("opc.tcp://h"))
	require.False(t, IsWebSocketEndpoint("opc.wss"))

	u, err := ParseWebSocketEndpoint("opc.wss://example.com/ua")
	require.NoError(t, err)
	require.Equal(t, "example.com:443", u.Host)
	_, err = ParseWebSocketEndpoint("opc.wss://example.com:0x1")
	require.Error(t, err)

	require.True(t, endpointMatch("opc.wss://h/ua", "opc.wss://h:443/ua"))
	require.False(t, endpointMatch("opc.wss://h/ua", "opc.wss://h:4840/ua"))
	require.False(t, endpointMatch("opc.tcp://h:443/ua", "opc.wss://h:443/ua"))

	cfg := transportTLS(&tls.Config{MinVersion: tls.VersionTLS10, NextProtos: []string{"h2"}})
	require.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
	require.Equal(t, []string{"http/1.1"}, cfg.NextProtos)
	cfg = transportTLS(&tls.Config{MinVersion: tls.VersionTLS13})
	require.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
}
