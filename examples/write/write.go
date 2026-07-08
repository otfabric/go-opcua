// SPDX-License-Identifier: MIT

// Example write demonstrates writing a value to an OPC-UA node.
//
// It shows the high-level WriteNodeValue helper (which wraps any Go value in a
// DataValue automatically) as well as the low-level Write service.
//
// Usage:
//
//	go run write.go -endpoint opc.tcp://localhost:4840 -node "ns=2;s=Temperature" -value 42
package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"os"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
)

func main() {
	var (
		endpoint = flag.String("endpoint", "opc.tcp://localhost:4840", "OPC UA Endpoint URL")
		nodeID   = flag.String("node", "", "NodeID to read")
		value    = flag.String("value", "", "value")
	)
	var debugMode bool
	flag.BoolVar(&debugMode, "debug", false, "enable debug logging")

	flag.Parse()
	if debugMode {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}
	log.SetFlags(0)

	ctx := context.Background()

	c, err := opcua.NewClient(*endpoint)
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

	// High-level: WriteNodeValue wraps a plain Go value in a DataValue using
	// NewVariant (auto-detecting the OPC-UA type) and writes the Value attribute.
	status, err := c.WriteNodeValue(ctx, id, *value)
	if err != nil {
		log.Fatalf("WriteNodeValue failed: %s", err)
	}
	log.Printf("WriteNodeValue status: %v", status)

	// Low-level: for full control over the DataValue (timestamps, encoding mask,
	// specific Variant type, ...) build a WriteRequest and call Write.
	v, err := ua.NewVariant(*value)
	if err != nil {
		log.Fatalf("invalid value: %v", err)
	}

	req := &ua.WriteRequest{
		NodesToWrite: []*ua.WriteValue{
			{
				NodeID:      id,
				AttributeID: ua.AttributeIDValue,
				Value: &ua.DataValue{
					EncodingMask: ua.DataValueValue,
					Value:        v,
				},
			},
		},
	}

	resp, err := c.Write(ctx, req)
	if err != nil {
		log.Fatalf("Write failed: %s", err)
	}
	log.Printf("%v", resp.Results[0])
}
