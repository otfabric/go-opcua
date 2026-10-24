// SPDX-License-Identifier: MIT

package mqtt_test

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/mqtt"
	"github.com/otfabric/go-opcua/internal/testutil/mqttbroker"
)

// Regression: Close waited for the delivery goroutine, so a handler that
// closed the client waited for itself forever.
func TestCloseFromHandler(t *testing.T) {
	b := startBroker(t, mqttbroker.Options{})
	c := dial(t, mqtt.Options{Server: b.URL()})
	closed := make(chan error, 1)
	_, err := c.Subscribe(bg, "close/me", 0, func(*mqtt.Message) { closed <- c.Close() })
	require.NoError(t, err)
	require.NoError(t, c.Publish(bg, "close/me", []byte("x"), 0, false))
	select {
	case err := <-closed:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Close called from a handler did not return")
	}
	require.ErrorIs(t, c.Publish(bg, "close/me", []byte("x"), 0, false), mqtt.ErrClosed)
}

// Close from another goroutine still waits for a running handler.
func TestCloseWaitsForHandler(t *testing.T) {
	b := startBroker(t, mqttbroker.Options{})
	c := dial(t, mqtt.Options{Server: b.URL()})
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	_, err := c.Subscribe(bg, "slow", 0, func(*mqtt.Message) {
		close(entered)
		<-release
		close(finished)
	})
	require.NoError(t, err)
	require.NoError(t, c.Publish(bg, "slow", []byte("x"), 0, false))
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

// Regression: with every packet identifier taken by publications the
// broker never acknowledged, allocID looped forever holding the client's
// mutex: Publish, Subscribe and even Close hung.
func TestPacketIdentifiersExhausted(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	go fakeBroker(t, l, func(_ net.Conn, read func() mqtt.Packet, _ func(mqtt.Packet)) {
		for read() != nil { // never acknowledges
		}
	})
	c := dial(t, mqtt.Options{Server: "mqtt://" + l.Addr().String()})
	gone, cancel := context.WithCancel(bg)
	cancel()
	// Written publications keep their identifiers until the broker
	// acknowledges them, after their callers gave up.
	for i := 0; ; i++ {
		err := c.Publish(gone, "t", []byte("x"), 1, false)
		if errors.Is(err, mqtt.ErrNoPacketID) {
			require.Greater(t, i, 60000)
			break
		}
		require.ErrorIs(t, err, context.Canceled)
		require.Less(t, i, 1<<16, "no limit")
	}
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(bg, time.Second)
		defer cancel()
		_, err := c.Subscribe(ctx, "s", 1, func(*mqtt.Message) {})
		done <- err
	}()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.DeadlineExceeded) // the broker does not answer
	case <-time.After(5 * time.Second):
		t.Fatal("Subscribe hung")
	}
	closed := make(chan struct{})
	go func() { _ = c.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close hung")
	}
}

// Regression: Close sent DISCONNECT under the write lock, so with a broker
// that stopped reading it waited for a blocked write's deadline: the
// keep-alive (or the broker's Server Keep Alive, up to 18 hours).
func TestCloseWithStalledBroker(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	stop := make(chan struct{})
	defer close(stop)
	go fakeBroker(t, l, func(net.Conn, func() mqtt.Packet, func(mqtt.Packet)) { <-stop }) // reads nothing
	c, err := mqtt.Dial(bg, mqtt.Options{Server: "mqtt://" + l.Addr().String(), KeepAlive: 300 * time.Second})
	require.NoError(t, err)
	var written atomic.Int64
	go func() {
		payload := make([]byte, 256<<10)
		for c.Publish(bg, "t", payload, 0, false) == nil {
			written.Add(1)
		}
	}()
	// Wait until a write blocks: the socket buffers are full.
	last := int64(-1)
	require.Eventually(t, func() bool {
		n := written.Load()
		stalled := n > 0 && n == last
		last = n
		return stalled
	}, 10*time.Second, 200*time.Millisecond)
	closed := make(chan struct{})
	go func() { _ = c.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("Close waited for the blocked write")
	}
}
