// SPDX-License-Identifier: MIT

package amqp_test

import (
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
