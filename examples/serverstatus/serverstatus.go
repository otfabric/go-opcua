// SPDX-License-Identifier: MIT

// Example serverstatus demonstrates server introspection helpers:
// ServerStatus (the ServerStatusDataType from node i=2256), NamespaceArray
// (the server's namespace table), and FindNamespace (resolve a namespace URI
// to its index).
//
// Usage:
//
//	go run serverstatus.go -endpoint opc.tcp://localhost:4840
//	go run serverstatus.go -endpoint opc.tcp://localhost:4840 -find "http://opcfoundation.org/UA/"
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
		find     = flag.String("find", "", "namespace URI to resolve to an index")
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

	// ServerStatus reads the ServerStatusDataType (node i=2256).
	status, err := c.ServerStatus(ctx)
	if err != nil {
		log.Fatalf("ServerStatus failed: %v", err)
	}
	log.Printf("State:       %v", status.State)
	log.Printf("StartTime:   %v", status.StartTime)
	log.Printf("CurrentTime: %v", status.CurrentTime)
	if status.BuildInfo != nil {
		log.Printf("Product:     %s %s", status.BuildInfo.ProductName, status.BuildInfo.SoftwareVersion)
		log.Printf("Manufacturer:%s", status.BuildInfo.ManufacturerName)
	}

	// NamespaceArray returns the server's namespace table (index = position).
	nss, err := c.NamespaceArray(ctx)
	if err != nil {
		log.Fatalf("NamespaceArray failed: %v", err)
	}
	log.Printf("Namespaces (%d):", len(nss))
	for i, uri := range nss {
		log.Printf("  [%d] %s", i, uri)
	}

	// FindNamespace resolves a namespace URI to its index.
	if *find != "" {
		idx, err := c.FindNamespace(ctx, *find)
		if err != nil {
			log.Fatalf("FindNamespace(%q) failed: %v", *find, err)
		}
		log.Printf("FindNamespace(%q) = %d", *find, idx)
	}
}
