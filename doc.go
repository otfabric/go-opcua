// SPDX-License-Identifier: MIT

// Package opcua provides a high-level OPC-UA client and server implementation in pure Go.
//
// The root package contains the [Client] for connecting to OPC-UA servers and
// performing read, write, browse, subscribe, and method call operations.
//
// # Client Usage
//
// Create a client and connect:
//
//	c, err := opcua.NewClient("opc.tcp://localhost:4840")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if err := c.Connect(ctx); err != nil {
//	    log.Fatal(err)
//	}
//	defer c.Close(ctx)
//
// Read a value:
//
//	dv, err := c.ReadValue(ctx, ua.NewNumericNodeID(0, 2258))
//
// Subscribe to changes:
//
//	sub, ch, err := c.NewSubscription().
//	    Interval(100 * time.Millisecond).
//	    Monitor(nodeID).
//	    Start(ctx)
//
// # Sub-packages
//
// The server package provides the OPC-UA server implementation.
// The ua package defines all OPC-UA data types and service messages.
// The uasc package implements the Secure Conversation layer.
// The uacp package implements the Connection Protocol (TCP transport).
// The uapolicy package implements the security policies.
package opcua
