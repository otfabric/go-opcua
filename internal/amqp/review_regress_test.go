// SPDX-License-Identifier: MIT

package amqp_test

import (
	"bytes"
	"context"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/amqp"
	"github.com/otfabric/go-opcua/internal/testutil/amqpbroker"
)

// Regression: Close waited for the delivery goroutine, so a handler that
// closed the client waited for itself forever.
func TestCloseFromHandler(t *testing.T) {
	b := startBroker(t, amqpbroker.Options{})
	c := dial(t, amqp.Options{Server: b.URL()})
	closed := make(chan error, 1)
	_, err := c.Subscribe(bg, "close/me", true, func(*amqp.Message) { closed <- c.Close() })
	require.NoError(t, err)
	require.NoError(t, c.Send(bg, "close/me", dataMsg("x"), true))
	select {
	case err := <-closed:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Close called from a handler did not return")
	}
	require.ErrorIs(t, c.Send(bg, "close/me", dataMsg("x"), true), amqp.ErrClosed)
}

// Close from another goroutine still waits for a running handler.
func TestCloseWaitsForHandler(t *testing.T) {
	b := startBroker(t, amqpbroker.Options{})
	c := dial(t, amqp.Options{Server: b.URL()})
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	_, err := c.Subscribe(bg, "slow", true, func(*amqp.Message) {
		close(entered)
		<-release
		close(finished)
	})
	require.NoError(t, err)
	require.NoError(t, c.Send(bg, "slow", dataMsg("x"), true))
	<-entered
	done := make(chan struct{})
	go func() { _ = c.Close(); close(done) }()
	select {
	case <-done:
		t.Fatal("Close returned while a handler was running")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	<-done
	select {
	case <-finished:
	default:
		t.Fatal("Close returned before the handler")
	}
}

// Regression: every echo flow (and every unsettled transfer) of the broker
// queued an answer for the writer, without limit: a broker that sent and
// did not read made the client queue answers until the write deadline.
//
// The broker's not reading is modelled by the client's connection, whose
// writes block (until their deadline) once the flood starts: with a real
// peer that does not read, how much the socket buffers absorb before the
// client's writes block depends on the host, and on Linux the full receive
// queue of the peer can stall the connection in both directions before the
// client has queued enough to notice.
func TestBrokerThatDoesNotReadIsDropped(t *testing.T) {
	p := newPeer(t)
	lost := make(chan error, 1)
	var stalled atomic.Bool
	dialPeer(t, p, amqp.Options{
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			c, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return newStallConn(c, &stalled), nil
		},
		OnConnectionLost: func(err error) {
			select {
			case lost <- err:
			default:
			}
		},
	})
	frame, err := amqp.AppendFrame(nil, &amqp.Frame{Body: &amqp.Flow{IncomingWindow: 1000, OutgoingWindow: 1000, Echo: true}})
	require.NoError(t, err)
	stalled.Store(true)
	chunk := bytes.Repeat(frame, 10_000)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := p.conn.Write(chunk); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		close(stop)
		_ = p.conn.SetWriteDeadline(time.Now())
		<-done
	})
	select {
	case err := <-lost:
		require.ErrorContains(t, err, "does not read")
	case <-time.After(30 * time.Second):
		t.Fatal("the client kept queueing answers")
	}
}

// stallConn is a connection whose writes block, once stalled is set, until
// their deadline or Close: a peer that does not read.
type stallConn struct {
	net.Conn
	stalled *atomic.Bool
	mu      sync.Mutex
	dl      time.Time
	closed  chan struct{}
	once    sync.Once
}

func newStallConn(c net.Conn, stalled *atomic.Bool) *stallConn {
	return &stallConn{Conn: c, stalled: stalled, closed: make(chan struct{})}
}

func (c *stallConn) Write(b []byte) (int, error) {
	if !c.stalled.Load() {
		return c.Conn.Write(b)
	}
	c.mu.Lock()
	dl := c.dl
	c.mu.Unlock()
	var timeout <-chan time.Time
	if !dl.IsZero() {
		tm := time.NewTimer(time.Until(dl))
		defer tm.Stop()
		timeout = tm.C
	}
	select {
	case <-timeout:
		return 0, os.ErrDeadlineExceeded
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *stallConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.dl = t
	c.mu.Unlock()
	return c.Conn.SetWriteDeadline(t)
}

func (c *stallConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.dl = t
	c.mu.Unlock()
	return c.Conn.SetDeadline(t)
}

func (c *stallConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}
