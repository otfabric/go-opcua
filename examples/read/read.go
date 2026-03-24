// Copyright 2018-2020 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

// Example read demonstrates reading a node value from an OPC-UA server.
//
// It shows the low-level Read service with proper error handling, including
// retry logic for transient errors that occur during reconnection.
//
// Usage:
//
//	go run read.go -endpoint opc.tcp://localhost:4840 -node "ns=2;s=Temperature"
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
