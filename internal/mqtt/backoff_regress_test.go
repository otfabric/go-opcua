// SPDX-License-Identifier: MIT

package mqtt_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/mqtt"
	"github.com/otfabric/go-opcua/internal/testutil/mqttbroker"
)

// reconnectAfter makes the broker end the connection of client "c" with
// a DISCONNECT and returns how long the client took to connect again.
func reconnectAfter(t *testing.T, b *mqttbroker.Broker, connected <-chan struct{}) time.Duration {
	t.Helper()
	start := time.Now()
	require.True(t, b.Disconnect("c", mqtt.ReasonServerBusy, "test"))
	select {
	case <-connected:
		return time.Since(start)
	case <-time.After(10 * time.Second):
		t.Fatal("the client did not connect again")
		return 0
	}
}

func connectSignal() (chan struct{}, func(bool)) {
	ch := make(chan struct{}, 16)
	return ch, func(bool) { ch <- struct{}{} }
}

// Regression (chaos/pubsub TestChaosMQTT5NoLoss): the backoff only started
// over after a connection that lasted MaxReconnectDelay (30 s by default).
// Under repeated faults no connection lasted that long, the backoff grew to
// its maximum, and one DISCONNECT then kept a subscriber away for up to 36 s
// while its persistent session filled up on the broker. The wait after a
// DISCONNECT now starts over after a connection that lasted longer than it.
func TestRegressionBackoffStartsOverAfterStableConnection(t *testing.T) {
	b := startBroker(t, mqttbroker.Options{})
	connected, onConnect := connectSignal()
	dial5(t, mqtt.Options{Server: b.URL(), ClientID: "c", MinReconnectDelay: 20 * time.Millisecond,
		MaxReconnectDelay: time.Hour, OnConnect: onConnect})
	<-connected
	// Without the fix the eighth wait is 20 ms * 2^7 = 2.56 s (+-20 %).
	for i := range 8 {
		time.Sleep(300 * time.Millisecond) // longer than the 40 ms wait
		d := reconnectAfter(t, b, connected)
		require.Less(t, d, time.Second, "reconnect %d took %v", i+1, d)
	}
}

// Regression (chaos/pubsub TestChaosMQTT5NoLoss): the failed attempts of a
// broker outage left the client with their long backoff after it had
// connected again, so a second short outage kept it away for that long.
// A connection now starts the backoff of the connection attempts over.
func TestRegressionBackoffAfterOutageStartsOver(t *testing.T) {
	b := startBroker(t, mqttbroker.Options{})
	connected, onConnect := connectSignal()
	dial5(t, mqtt.Options{Server: b.URL(), ClientID: "c", MinReconnectDelay: 10 * time.Millisecond,
		MaxReconnectDelay: time.Hour, OnConnect: onConnect})
	<-connected
	outage := func(d time.Duration) time.Duration {
		b.Stop()
		time.Sleep(d)
		require.NoError(t, b.Start())
		start := time.Now()
		select {
		case <-connected:
		case <-time.After(10 * time.Second):
			t.Fatal("the client did not connect again after the outage")
		}
		return time.Since(start)
	}
	outage(600 * time.Millisecond) // failed attempts: the backoff reaches 640 ms or more
	d := outage(50 * time.Millisecond)
	// Without the fix the client waits out the backoff of the first outage
	// (at least 512 ms); with it the attempts start at 10 ms again.
	require.Less(t, d, 300*time.Millisecond)
}

// A connection the broker ends right after it was made is no reason to
// start over: the backoff keeps growing, so that two clients with one
// client identifier do not take the session from each other in a tight
// loop.
func TestBackoffGrowsWhileConnectionsAreShort(t *testing.T) {
	b := startBroker(t, mqttbroker.Options{})
	connected, onConnect := connectSignal()
	dial5(t, mqtt.Options{Server: b.URL(), ClientID: "c", MinReconnectDelay: 20 * time.Millisecond,
		MaxReconnectDelay: time.Hour, OnConnect: onConnect})
	<-connected
	var last time.Duration
	for range 6 {
		last = reconnectAfter(t, b, connected)
	}
	// The sixth wait is 20 ms * 2^5 = 640 ms (+-20 %).
	require.Greater(t, last, 400*time.Millisecond)
}
