// SPDX-License-Identifier: MIT

package mqtt_test

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/internal/mqtt"
	"github.com/otfabric/go-opcua/internal/testutil/mqttbroker"
	"github.com/stretchr/testify/require"
)

// Regression: a QoS 1 message was handed to the application before its
// PUBACK was written, so a client closed right after it saw the message
// could leave the PUBACK unsent and the broker delivered the message again
// to the next connection of the persistent session.
func TestCloseAfterDeliveryDoesNotLoseAck(t *testing.T) {
	b := startBroker(t, mqttbroker.Options{})
	bg := context.Background()
	pub := dial(t, mqtt.Options{Server: b.URL(), ClientID: "pub"})

	for i := 0; i < 20; i++ {
		in := newInbox()
		sub, err := mqtt.Dial(bg, mqtt.Options{Server: b.URL(), ClientID: "sub", PersistentSession: true, DefaultHandler: in.handle})
		require.NoError(t, err)
		if i == 0 {
			_, err = sub.Subscribe(bg, "ack/#", 1, in.handle)
			require.NoError(t, err)
		}
		require.NoError(t, pub.Publish(bg, "ack/x", []byte{byte(i)}, 1, false))
		m := in.next(t)
		require.Equal(t, []byte{byte(i)}, m.Payload, "round %d: a redelivered message", i)
		require.NoError(t, sub.Close()) // right after the message was seen
	}

	// Nothing is left for the session.
	in := newInbox()
	sub := dial(t, mqtt.Options{Server: b.URL(), ClientID: "sub", PersistentSession: true, DefaultHandler: in.handle})
	_ = sub
	in.none(t, 200*time.Millisecond)
}
