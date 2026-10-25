// SPDX-License-Identifier: MIT

package uacp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/internal/websocket"
	"github.com/stretchr/testify/require"
)

func TestWebSocketJSONDialAndHandOver(t *testing.T) {
	l, url := wsListener(t, "/ua")
	served := make(chan MessageConn, 1)
	l.ServeWebSocketJSON(func(c MessageConn) { served <- c })
	ctx := context.Background()

	// A binary client is still accepted on the same listener.
	accepted := make(chan *Conn, 1)
	go func() {
		c, err := l.Accept(ctx)
		if err == nil {
			accepted <- c
		}
		close(accepted)
	}()
	d := &Dialer{TLSConfig: tlsPKI(t).ClientConfig()}
	bc, err := d.Dial(ctx, url)
	require.NoError(t, err)
	s := <-accepted
	require.NotNil(t, s)
	_ = s.Close()
	_ = bc.Close()

	c, err := d.DialWebSocketJSON(ctx, url)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	var sc MessageConn
	select {
	case sc = <-served:
	case <-time.After(10 * time.Second):
		t.Fatal("the JSON connection was not handed over")
	}
	defer func() { _ = sc.Close() }()
	require.NotNil(t, sc.RemoteAddr())

	// The handshake deadline no longer applies to the handed over
	// connection: it is cleared, and the handler sets its own.
	require.NoError(t, sc.SetReadDeadline(time.Now().Add(10*time.Second)))
	require.NoError(t, c.SetWriteDeadline(time.Now().Add(10*time.Second)))
	require.NoError(t, c.WriteMessage([]byte(`{"UaTypeId":"i=631"}`)))
	msg, err := sc.ReadMessage(1 << 10)
	require.NoError(t, err)
	require.Equal(t, `{"UaTypeId":"i=631"}`, string(msg))
	require.NoError(t, sc.WriteMessage([]byte(`{}`)))
	msg, err = c.ReadMessage(1 << 10)
	require.NoError(t, err)
	require.Equal(t, `{}`, string(msg))

	// A message over the limit ends the connection with 1009.
	require.NoError(t, c.WriteMessage(make([]byte, 20)))
	_, err = sc.ReadMessage(10)
	require.ErrorIs(t, err, websocket.ErrMessageTooLarge)
	_, err = c.ReadMessage(1 << 10)
	require.Error(t, err)
	require.Equal(t, websocket.CloseMessageTooBig, c.(messageConn).CloseCode())
}

func TestWebSocketJSONNotServed(t *testing.T) {
	// Without ServeWebSocketJSON the sub-protocol is refused.
	l, url := wsListener(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			_, _ = l.Accept(ctx) // the failed upgrade
		}
	}()
	defer func() { cancel(); <-done }()
	d := &Dialer{TLSConfig: tlsPKI(t).ClientConfig(), Dialer: &net.Dialer{Timeout: 10 * time.Second}}
	_, err := d.DialWebSocketJSON(context.Background(), url)
	require.ErrorIs(t, err, websocket.ErrHandshake)

	_, err = d.DialWebSocketJSON(context.Background(), "opc.tcp://localhost:1")
	require.Error(t, err)
}

func TestWebSocketJSONHandOverOnlyJSON(t *testing.T) {
	l := &Listener{}
	require.False(t, l.handOver(&net.TCPConn{}), "not a WebSocket")
}
