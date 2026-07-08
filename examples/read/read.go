// SPDX-License-Identifier: MIT

// Example read demonstrates reading a node value from an OPC-UA server.
//
// It shows the high-level ReadValue / ReadValues helpers as well as the
// low-level Read service with proper error handling, including retry logic
// for transient errors that occur during reconnection.
//
// Usage:
//
//	go run read.go -endpoint opc.tcp://localhost:4840 -node "ns=2;s=Temperature"
//	go run read.go -endpoint opc.tcp://localhost:4840 -node "ns=2;s=Temperature" -node2 "ns=0;i=2258"
package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"log"
	"log/slog"
	"os"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
)

func main() {
	var (
		endpoint = flag.String("endpoint", "opc.tcp://localhost:4840", "OPC UA Endpoint URL")
		nodeID   = flag.String("node", "", "NodeID to read")
		nodeID2  = flag.String("node2", "", "optional second NodeID for the ReadValues demo")
	)
	var debugMode bool
	flag.BoolVar(&debugMode, "debug", false, "enable debug logging")

	flag.Parse()
	if debugMode {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}
	log.SetFlags(0)

	ctx := context.Background()

	c, err := opcua.NewClient(*endpoint, opcua.SecurityMode(ua.MessageSecurityModeNone))
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

	// High-level: ReadValue reads a single node's Value attribute and returns
	// the DataValue directly, without building a ReadRequest.
	dv, err := c.ReadValue(ctx, id)
	if err != nil {
		log.Fatalf("ReadValue failed: %s", err)
	}
	log.Printf("ReadValue: %v", dv.Value.Value())

	// High-level: ReadValues reads several nodes' Value attributes in one
	// round-trip and returns the results in order.
	ids := []*ua.NodeID{id}
	if *nodeID2 != "" {
		id2, err := ua.ParseNodeID(*nodeID2)
		if err != nil {
			log.Fatalf("invalid node2 id: %v", err)
		}
		ids = append(ids, id2)
	}
	dvs, err := c.ReadValues(ctx, ids...)
	if err != nil {
		log.Fatalf("ReadValues failed: %s", err)
	}
	for i, v := range dvs {
		log.Printf("ReadValues[%d] (%s): %v", i, ids[i], v.Value.Value())
	}

	// Low-level: for full control (MaxAge, timestamps, index ranges, ...) build
	// a ReadRequest and call Read. The retry loop below shows how to handle the
	// transient errors that can occur during reconnection.
	req := &ua.ReadRequest{
		MaxAge: 2000,
		NodesToRead: []*ua.ReadValueID{
			{NodeID: id},
		},
		TimestampsToReturn: ua.TimestampsToReturnBoth,
	}

	var resp *ua.ReadResponse
	for {
		resp, err = c.Read(ctx, req)
		if err == nil {
			break
		}

		// Following switch contains known errors that can be retried by the user.
		// Best practice is to do it on read operations.
		switch {
		case err == io.EOF && c.State() != opcua.Closed:
			// has to be retried unless user closed the connection
			time.After(1 * time.Second)
			continue

		case errors.Is(err, ua.StatusBadSessionIDInvalid):
			// Session is not activated has to be retried. Session will be recreated internally.
			time.After(1 * time.Second)
			continue

		case errors.Is(err, ua.StatusBadSessionNotActivated):
			// Session is invalid has to be retried. Session will be recreated internally.
			time.After(1 * time.Second)
			continue

		case errors.Is(err, ua.StatusBadSecureChannelIDInvalid):
			// secure channel will be recreated internally.
			time.After(1 * time.Second)
			continue

		default:
			log.Fatalf("Read failed: %s", err)
		}
	}

	if resp != nil && resp.Results[0].Status != ua.StatusOK {
		log.Fatalf("Status not OK: %v", resp.Results[0].Status)
	}

	log.Printf("%#v", resp.Results[0].Value.Value())
}
