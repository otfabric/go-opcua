// SPDX-License-Identifier: MIT

package pubsub

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/ua"
)

// TestRegressionProfileSchemeMismatch: a connection whose Address belongs to
// a built-in transport of another TransportProfileUri (an amqp:// URL with
// the MQTT profile, ...) was accepted, by Validate and by AddConnection
// (also through the AddConnection method of the information model), and
// ran the transport of the URL under the profile of the configuration.
// Found by conformance/pubsub_brokers_test.go.
func TestRegressionProfileSchemeMismatch(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		profile, url string
	}{
		{transport.ProfileMQTTUADP, "amqp://127.0.0.1:5672"},
		{transport.ProfileMQTTJSON, "opc.udp://127.0.0.1:4840"},
		{transport.ProfileAMQPJSON, "mqtts://127.0.0.1:8883"},
		{transport.ProfileAMQPUADP, "opc.udp://127.0.0.1:4840"},
		{transport.ProfileUDPUADP, "mqtt://127.0.0.1:1883"},
		{transport.ProfileUDPUADP, "AMQP://127.0.0.1:5672"},
		{transport.ProfileUDPUADP, "opc.eth://01-00-5e-00-00-01"},
	} {
		conn := UDPConnection("c", c.url, uint16(1))
		conn.TransportProfileURI = c.profile
		require.ErrorContains(t, Validate(NewConfiguration(nil, conn)), "does not fit the TransportProfileUri", c.url)
		rt, err := New(nil)
		require.NoError(t, err)
		_, err = rt.AddConnection(conn)
		require.Error(t, err, c.url)
		require.ErrorIs(t, err, ua.StatusBadConfigurationError)
		require.NoError(t, rt.Close())
	}
	// The matching ones, and schemes of transports the application
	// registers, which take any profile.
	for _, c := range []struct {
		profile, url string
	}{
		{transport.ProfileMQTTUADP, "mqtts://127.0.0.1:8883"},
		{transport.ProfileAMQPJSON, "amqps://127.0.0.1:5671"},
		{transport.ProfileUDPUADP, "opc.udp://127.0.0.1:4840"},
		{transport.ProfileUDPUADP, "custom://segment"},
	} {
		conn := UDPConnection("c", c.url, uint16(1))
		conn.TransportProfileURI = c.profile
		require.NoError(t, Validate(NewConfiguration(nil, conn)), c.url)
	}
}
