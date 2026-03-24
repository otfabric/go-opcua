// Copyright 2018-2024 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

// Example reconnect demonstrates the OPC-UA client's automatic reconnection
// feature. It connects to a server with auto-reconnect enabled and monitors
// the connection state. If the server goes down, the client will automatically
// attempt to reconnect at the configured interval.
//
// This example also shows how to handle reads during reconnection — the client
// returns errors while disconnected, and operations resume once reconnected.
//
// Usage:
//
//	go run reconnect.go -endpoint opc.tcp://localhost:4840 -node "ns=2;s=Temperature"
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
)

func main() {
	var (
		endpoint = flag.String("endpoint", "opc.tcp://localhost:4840", "OPC UA Endpoint URL")
		nodeID   = flag.String("node", "ns=0;i=2258", "NodeID to read (default: Server CurrentTime)")
		interval = flag.Duration("reconnect-interval", 2*time.Second, "Interval between reconnect attempts")
	)
	var debugMode bool
	flag.BoolVar(&debugMode, "debug", false, "enable debug logging")

	flag.Parse()
	if debugMode {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}
	log.SetFlags(0)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Create a client with auto-reconnect enabled.
	// The WithConnStateHandler option lets us monitor state transitions.
	c, err := opcua.NewClient(*endpoint,
		opcua.SecurityMode(ua.MessageSecurityModeNone),
		opcua.AutoReconnect(true),
		opcua.ReconnectInterval(*interval),
		opcua.WithConnStateHandler(func(state opcua.ConnState) {
			// This callback fires on every state transition.
			// Use it for monitoring, alerting, or coordinating application behavior.
			switch state {
			case opcua.Connecting:
				log.Println("[STATE] Connecting...")
			case opcua.Connected:
				log.Println("[STATE] Connected — operations will succeed")
			case opcua.Disconnected:
				log.Println("[STATE] Disconnected — operations will fail until reconnected")
			case opcua.Reconnecting:
				log.Println("[STATE] Reconnecting...")
			case opcua.Closed:
				log.Println("[STATE] Closed — client shut down")
			}
		}),
	)
	if err != nil {
		log.Fatal(err)
	}

	if err := c.Connect(ctx); err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Close(ctx) }()

	id, err := ua.ParseNodeID(*nodeID)
	if err != nil {
		log.Fatalf("invalid node id: %v", err)
	}

	// Periodically read the node value. During a disconnection, reads will
	// return errors. Once the client reconnects, reads will succeed again.
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			dv, err := c.ReadValue(ctx, id)
			if err != nil {
				// During reconnection, reads return errors. This is expected.
				// The auto-reconnect logic handles recovery in the background.
				log.Printf("[READ] Error: %v (state: %s)", err, c.State())
				continue
			}
			if dv.Status != ua.StatusOK {
				log.Printf("[READ] Bad status: %s", dv.Status)
				continue
			}
			fmt.Printf("[READ] %s = %v\n", *nodeID, dv.Value.Value())
		}
	}
}
