// SPDX-License-Identifier: MIT

// Importing package pubsub registers the "opc.udp", "mqtt", "mqtts", "amqp"
// and "amqps" transports.

package pubsub

import (
	_ "github.com/otfabric/go-opcua/pubsub/transport/amqp" // registers amqp, amqps
	_ "github.com/otfabric/go-opcua/pubsub/transport/mqtt" // registers mqtt, mqtts
	_ "github.com/otfabric/go-opcua/pubsub/transport/udp"  // registers opc.udp
)
