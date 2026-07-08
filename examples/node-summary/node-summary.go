// SPDX-License-Identifier: MIT

// Example node-summary demonstrates Node.Summary, which reads all of a node's
// common attributes (NodeClass, BrowseName, DisplayName, Description, DataType,
// Value, AccessLevel, UserAccessLevel) in a single Read call and follows the
// HasTypeDefinition reference. This is the most efficient way to gather
// display-relevant information about a node.
//
// Usage:
//
//	go run node-summary.go -endpoint opc.tcp://localhost:4840 -node "ns=0;i=2258"
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
		nodeID   = flag.String("node", "ns=0;i=2258", "NodeID to summarize (default: Server CurrentTime)")
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

	s, err := c.Node(id).Summary(ctx)
	if err != nil {
		log.Fatalf("Summary failed: %v", err)
	}

	log.Printf("NodeID:          %s", s.NodeID)
	log.Printf("NodeClass:       %s", s.NodeClass)
	if s.BrowseName != nil {
		log.Printf("BrowseName:      %s", s.BrowseName.Name)
	}
	if s.DisplayName != nil {
		log.Printf("DisplayName:     %s", s.DisplayName.Text)
	}
	if s.Description != nil {
		log.Printf("Description:     %s", s.Description.Text)
	}
	if s.DataType != nil {
		log.Printf("DataType:        %s", s.DataType)
	}
	if s.Value != nil && s.Value.Value != nil {
		log.Printf("Value:           %v", s.Value.Value.Value())
	}
	log.Printf("AccessLevel:     %s", s.AccessLevel)
	log.Printf("UserAccessLevel: %s", s.UserAccessLevel)
	if s.TypeDefinition != nil {
		log.Printf("TypeDefinition:  %s", s.TypeDefinition)
	}
}
