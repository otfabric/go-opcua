// SPDX-License-Identifier: MIT


// Importing package pubsub registers the "opc.udp", "mqtt" and "mqtts"
// transports.

package pubsub

import (
	_ "github.com/otfabric/go-opcua/pubsub/transport/mqtt" // registers mqtt, mqtts
	_ "github.com/otfabric/go-opcua/pubsub/transport/udp"  // registers opc.udp
)
