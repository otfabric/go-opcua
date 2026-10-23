// SPDX-License-Identifier: MIT

package mqtt_test

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/mqtt"
	"github.com/otfabric/go-opcua/internal/testutil/mqttbroker"
)

// Regression (chaos/pubsub): when the broker refused a subscription that
// the client made again after a reconnect, the client only logged it. The
// subscriber still believed it was subscribed and never got a message
// again, also after the broker accepted the filter again. The client now
// asks again, with backoff, while the connection lasts.
func TestRegressionResubscriptionRefusedAfterReconnect(t *testing.T) {
	var refuse atomic.Bool
	b := startBroker(t, mqttbroker.Options{RefuseFilter: func(string) bool { return refuse.Load() }})
	sub := dial(t, mqtt.Options{Server: b.URL()})
	pub := dial(t, mqtt.Options{Server: b.URL()})
	in := newInbox()
	_, err := sub.Subscribe(bg, "data/#", 1, in.handle)
	require.NoError(t, err)
	require.NoError(t, pub.Publish(bg, "data/x", []byte("before"), 1, false))
	require.Equal(t, "before", string(in.next(t).Payload))

	refuse.Store(true)
	b.DropConnections()
	require.Eventually(t, func() bool { return b.ClientCount() == 2 && sub.IsConnected() }, 5*time.Second, 5*time.Millisecond)
	time.Sleep(200 * time.Millisecond) // refused, and refused again
	refuse.Store(false)
	require.Eventually(t, func() bool {
		require.NoError(t, pub.Publish(bg, "data/x", []byte("after"), 1, false))
		select {
		case m := <-in.ch:
			return string(m.Payload) == "after"
		case <-time.After(50 * time.Millisecond):
			return false
		}
	}, 5*time.Second, time.Millisecond, "the refused resubscription was never made again")
}
