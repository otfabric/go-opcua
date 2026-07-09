// SPDX-License-Identifier: MIT

package uacp

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/stretchr/testify/require"
)

func TestListenerAddrAndEndpoint(t *testing.T) {
	ep := "opc.tcp://127.0.0.1:4840/foo"
	ln, err := Listen(context.Background(), ep, nil)
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	require.NotNil(t, ln.Addr())
	require.Equal(t, ep, ln.Endpoint())
}

func TestConn(t *testing.T) {
	t.Run("server exists ", func(t *testing.T) {
		ep := "opc.tcp://127.0.0.1:4840/foo/bar"
		ln, err := Listen(context.Background(), ep, nil)
		require.NoError(t, err)
		defer func() { _ = ln.Close() }()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		done := make(chan struct{})
		acceptErr := make(chan error, 1)
		go func() {
			c, err := ln.Accept(ctx)
			if err != nil {
				acceptErr <- err
				return
			}
			defer func() { _ = c.Close() }()
			close(done)
		}()

		if _, err = Dial(ctx, ep); err != nil {
			t.Error(err)
		}

		select {
		case <-done:
		case err := <-acceptErr:
			require.Fail(t, "accept fail: %v", err)
		case <-time.After(time.Second):
			require.Fail(t, "timed out")
		}
	})

	t.Run("Address resolves, but does not implement a opcua-server", func(t *testing.T) {
		ep := "opc.tcp://example.com:56789"

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, err := Dial(ctx, ep)
		var operr *net.OpError
		if errors.As(err, &operr) && !operr.Timeout() {
			t.Error(err)
		}
	})
}

func TestClientWrite(t *testing.T) {
	ep := "opc.tcp://127.0.0.1:4840/foo/bar"
	ln, err := Listen(context.Background(), ep, nil)
	require.NoError(t, err, "Listen failed")
	defer func() { _ = ln.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var srvConn *Conn
	done := make(chan int)
	acceptErr := make(chan error, 1)
	go func() {
		defer func() { _ = ln.Close() }()
		var err error
		srvConn, err = ln.Accept(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		done <- 0
	}()

	cliConn, err := Dial(ctx, ep)
	require.NoError(t, err, "Dial failed")

	for {
		select {
		case _, ok := <-done:
			require.True(t, ok, "failed to setup secure channel")
			goto NEXT
		case err := <-acceptErr:
			require.Fail(t, "accept fail: %v", err)
		case <-time.After(time.Second):
			require.Fail(t, "timed out")
		}
	}

NEXT:
	msg := &Message{Data: []byte{0xde, 0xad, 0xbe, 0xef}}
	err = cliConn.Send("MSGF", msg)
	require.NoError(t, err, "Send failed")

	got, err := srvConn.Receive()
	require.NoError(t, err, "Receive failed")

	got = got[hdrlen:]

	want, err := msg.Encode()
	require.NoError(t, err, "Encode failed")

	require.Equal(t, want, got)
}

func TestServerWrite(t *testing.T) {
	ep := "opc.tcp://127.0.0.1:4840/foo/bar"
	ln, err := Listen(context.Background(), ep, nil)
	require.NoError(t, err, "Listen failed")
	defer func() { _ = ln.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var srvConn *Conn
	done := make(chan int)
	acceptErr := make(chan error, 1)
	go func() {
		defer func() { _ = ln.Close() }()
		var err error
		srvConn, err = ln.Accept(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		done <- 0
	}()

	cliConn, err := Dial(ctx, ep)
	require.NoError(t, err, "Dial failed")

	for {
		select {
		case _, ok := <-done:
			require.True(t, ok, "failed to setup secure channel")
			goto NEXT
		case err := <-acceptErr:
			require.Fail(t, "accept fail: %v", err)
		case <-time.After(time.Second):
			require.Fail(t, "timed out")
		}
	}

NEXT:
	want := []byte{0xde, 0xad, 0xbe, 0xef}
	_, err = srvConn.Write(want)
	require.NoError(t, err, "Write failed")

	got := make([]byte, cliConn.ReceiveBufSize())
	n, err := cliConn.Read(got)
	require.NoError(t, err, "Read failed")

	got = got[:n]
	require.Equal(t, want, got)
}

func TestMinNonZero(t *testing.T) {
	tests := []struct {
		a, b uint32
		want uint32
	}{
		{0, 0, 0},
		{0, 5, 5},
		{5, 0, 5},
		{3, 7, 3},
		{7, 3, 3},
	}
	for _, tt := range tests {
		got := minNonZero(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("minNonZero(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestDefaultNetDialer(t *testing.T) {
	d := defaultNetDialer()
	if d == nil {
		t.Fatal("defaultNetDialer() returned nil")
	}
	if d.Timeout != DefaultDialTimeout {
		t.Errorf("Timeout = %v, want %v", d.Timeout, DefaultDialTimeout)
	}
}

func TestConnAccessors(t *testing.T) {
	ep := "opc.tcp://127.0.0.1:4841/test"
	ln, err := Listen(context.Background(), ep, nil)
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	doneCh := make(chan *Conn, 1)
	go func() {
		c, err := ln.Accept(context.Background())
		if err == nil {
			doneCh <- c
		}
	}()

	clientConn, err := Dial(context.Background(), ep)
	require.NoError(t, err)
	defer func() { _ = clientConn.Close() }()

	serverConn := <-doneCh
	defer func() { _ = serverConn.Close() }()

	// Exercise the accessor methods on a live connection
	_ = clientConn.ID()
	_ = clientConn.Version()
	_ = clientConn.SendBufSize()
	_ = clientConn.MaxMessageSize()
	_ = clientConn.MaxChunkCount()
	clientConn.SetLogger(slog.Default())
}
