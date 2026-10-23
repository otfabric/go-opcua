// SPDX-License-Identifier: MIT

//go:build pubsub_transports

// The UDP and MQTT transports are built in a parallel branch. Once they are
// merged, drop the build constraint above so that importing package pubsub
// registers the "opc.udp", "mqtt" and "mqtts" schemes.

package pubsub

import (
	_ "github.com/otfabric/go-opcua/pubsub/transport/mqtt" // registers mqtt, mqtts
	_ "github.com/otfabric/go-opcua/pubsub/transport/udp"  // registers opc.udp
)
