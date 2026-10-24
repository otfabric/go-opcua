// SPDX-License-Identifier: MIT

package uacp

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"

	"github.com/otfabric/go-opcua/errors"
	"github.com/stretchr/testify/require"
)

// TestReverseDialer_ReverseHelloDoesNotFit: a ReverseHello larger than the
// send buffer is not sent and the connection is closed.
func TestReverseDialer_ReverseHelloDoesNotFit(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()

	d := &ReverseDialer{Dialer: &net.Dialer{Timeout: testWait}, ACK: &Acknowledge{ReceiveBufSize: 8192, SendBufSize: 16}}
	conn, err := d.Dial(context.Background(), "opc.tcp://"+ln.Addr().String(), &ReverseHello{ServerURI: "urn:server", EndpointURL: "opc.tcp://server:4840"})
	require.Nil(t, conn)
	require.ErrorIs(t, err, errors.ErrMessageTooLarge)

	c, ok := <-accepted
	require.True(t, ok)
	defer func() { _ = c.Close() }()
	requireClosed(t, c)
}

// TestReverseListener_AnnouncedAfterClose: a connection whose ReverseHello
// was accepted while the listener was being closed is not kept.
func TestReverseListener_AnnouncedAfterClose(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	l, addr := testReverseListener(t, &ReverseListenerConfig{Filter: func(*ReverseHello) error {
		once.Do(func() { close(entered) })
		<-release
		return nil
	}})

	c := announce(t, addr, "urn:server", "")
	<-entered // the ReverseHello was read; the connection is about to be offered

	closed := make(chan error, 1)
	go func() { closed <- l.Close() }()
	waitFor(t, l.isClosed, "Close has begun")
	close(release)

	require.NoError(t, <-closed)
	require.Zero(t, l.Pending())
	requireClosed(t, c)
	_, _, err := l.Accept(context.Background(), nil)
	require.ErrorIs(t, err, net.ErrClosed)
}

// TestReverseListener_SkipsConnectionFoundDead: a pending connection that
// turns out to be dead when a client claims it is skipped, and the client
// keeps waiting for a usable one.
func TestReverseListener_SkipsConnectionFoundDead(t *testing.T) {
	l, _ := testReverseListener(t, nil)
	a, b := tcpPair(t)

	// A pending connection whose watcher has already stopped and found it
	// dead, but which is still in the list.
	dead := &reverseConn{c: a, rhe: &ReverseHello{ServerURI: "urn:dead"}, done: make(chan struct{}), dead: true}
	close(dead.done)
	l.mu.Lock()
	l.pending = append(l.pending, dead)
	l.mu.Unlock()
	require.False(t, l.claim(dead))

	l.mu.Lock()
	l.pending = append(l.pending, dead)
	l.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c, rhe, err := l.Accept(ctx, nil)
	require.Nil(t, c)
	require.Nil(t, rhe)
	require.ErrorIs(t, err, context.Canceled)
	require.ErrorContains(t, err, "uacp: no reverse connection", "the dead connection is not reported as pending")
	require.Zero(t, l.Pending())
	_ = b.Close()
}

func TestAcceptReverseSince_NoListener(t *testing.T) {
	_, _, err := testDialer().AcceptReverseSince(context.Background(), nil, "", nil, 0)
	require.ErrorContains(t, err, "no reverse listener")
}

// blockingFailListener fails its first Accept and blocks in the following
// ones until it is closed.
type blockingFailListener struct {
	pipeListener
	mu     sync.Mutex
	failed bool
	first  chan struct{}
}

func (f *blockingFailListener) Accept() (net.Conn, error) {
	f.mu.Lock()
	if !f.failed {
		f.failed = true
		f.mu.Unlock()
		close(f.first)
		return nil, fmt.Errorf("accept: too many open files")
	}
	f.mu.Unlock()
	return f.pipeListener.Accept()
}

// TestReverseListener_CloseDuringAcceptBackoff: Close ends the accept loop
// while it waits after an accept error.
func TestReverseListener_CloseDuringAcceptBackoff(t *testing.T) {
	f := &blockingFailListener{pipeListener: pipeListener{conns: make(chan net.Conn), closed: make(chan struct{})}, first: make(chan struct{})}
	l := NewReverseListener(f, &ReverseListenerConfig{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	<-f.first
	require.NoError(t, l.Close())
	_, _, err := l.Accept(context.Background(), nil)
	require.ErrorIs(t, err, net.ErrClosed)
}
