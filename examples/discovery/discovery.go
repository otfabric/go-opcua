// Copyright 2018-2020 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

// Example discovery demonstrates the OPC-UA discovery services:
// FindServers and GetEndpoints. These are used to discover available
// servers and their supported security configurations.
//
// Usage:
//
//	go run discovery.go -endpoint opc.tcp://localhost:4840
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/otfabric/go-opcua"
)

func main() {
	endpoint := flag.String("endpoint", "opc.tcp://localhost:4840", "OPC UA Endpoint URL")
	var debugMode bool
	flag.BoolVar(&debugMode, "debug", false, "enable debug logging")

	flag.Parse()
	if debugMode {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}
	log.SetFlags(0)

	ctx := context.Background()

	if err := findServersOnNetwork(ctx, *endpoint); err != nil {
		log.Print(err)
	}

	if err := findServers(ctx, *endpoint); err != nil {
		log.Fatal(err)
	}
}

func findServersOnNetwork(ctx context.Context, endpoint string) error {
	log.Println("Finding servers on network")
	servers, err := opcua.FindServersOnNetwork(ctx, endpoint)
	if err != nil {
		return err
	}
	for i, server := range servers {
		fmt.Printf("%d Server on network:\n", i)
		fmt.Printf("  -- RecordID: %v\n", server.RecordID)
		fmt.Printf("  -- ServerName: %v\n", server.ServerName)
		fmt.Printf("  -- DiscoveryURL: %v\n", server.DiscoveryURL)
		fmt.Printf("  -- ServerCapabilities: %v\n", server.ServerCapabilities)
	}
	return nil
}

func findServers(ctx context.Context, endpoint string) error {
	log.Println("Finding servers")
	servers, err := opcua.FindServers(ctx, endpoint)
	if err != nil {
		return err
	}
	for i, server := range servers {
		fmt.Printf("%dth Server:\n", i+1)
		fmt.Printf("  -- ApplicationURI: %v\n", server.ApplicationURI)
		fmt.Printf("  -- ProductURI: %v\n", server.ProductURI)
		fmt.Printf("  -- ApplicationName: %v\n", server.ApplicationName)
		fmt.Printf("  -- ApplicationType: %v\n", server.ApplicationType)
		fmt.Printf("  -- GatewayServerURI: %v\n", server.GatewayServerURI)
		fmt.Printf("  -- DiscoveryProfileURI: %v\n", server.DiscoveryProfileURI)
		fmt.Printf("  -- DiscoveryURLs: %v\n", server.DiscoveryURLs)
	}
	return nil
}
