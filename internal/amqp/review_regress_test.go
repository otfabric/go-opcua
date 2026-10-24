// SPDX-License-Identifier: MIT

package amqp_test

import (
	"bytes"
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
func TestBrokerThatDoesNotReadIsDropped(t *testing.T) {
	p := newPeer(t)
	lost := make(chan error, 1)
	dialPeer(t, p, amqp.Options{OnConnectionLost: func(err error) {
		select {
		case lost <- err:
		default:
		}
	}})
	frame, err := amqp.AppendFrame(nil, &amqp.Frame{Body: &amqp.Flow{IncomingWindow: 1000, OutgoingWindow: 1000, Echo: true}})
	require.NoError(t, err)
	flood := bytes.Repeat(frame, 600_000)
	go func() { _, _ = p.conn.Write(flood) }() // and never read
	select {
	case err := <-lost:
		require.ErrorContains(t, err, "does not read")
	case <-time.After(15 * time.Second):
		t.Fatal("the client kept queueing answers")
	}
}
