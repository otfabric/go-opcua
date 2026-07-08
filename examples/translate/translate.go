// SPDX-License-Identifier: MIT

// Example translate demonstrates resolving a browse-name path to a NodeID
// using the TranslateBrowsePathsToNodeIDs service.
//
// It shows the three high-level client helpers plus the low-level Node method:
//
//   - Client.NodeFromPath              path from Objects folder, all segments ns=0
//   - Client.NodeFromPathInNamespace   path from Objects folder, all segments in one ns
//   - Client.NodeFromQualifiedPath     path from Objects folder, per-segment "ns:name"
//   - Node.TranslateBrowsePathInNamespaceToNodeID  path from any starting node
//
// Usage:
//
//	# Resolve from the Objects folder using -path and -namespace
//	go run translate.go -endpoint opc.tcp://localhost:4840 -path "Server.ServerStatus" -namespace 0
//
//	# Resolve a namespace-qualified path (per-segment "ns:name")
//	go run translate.go -endpoint opc.tcp://localhost:4840 -qualified "0:Server.0:ServerStatus"
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

func main() {
	endpoint := flag.String("endpoint", "opc.tcp://localhost:4840", "OPC UA Endpoint URL")
	nodePath := flag.String("path", "Server.ServerStatus", "dot-separated browse-name path from the Objects folder")
	ns := flag.Int("namespace", 0, "namespace index applied to every segment of -path")
	qualified := flag.String("qualified", "", "namespace-qualified path, per-segment \"ns:name\" (e.g. 0:Server.0:ServerStatus)")
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

	// If a qualified path was supplied, resolve it with NodeFromQualifiedPath,
	// where each segment carries its own namespace index ("ns:name").
	if *qualified != "" {
		node, err := c.NodeFromQualifiedPath(ctx, *qualified)
		if err != nil {
			log.Fatalf("NodeFromQualifiedPath(%q): %v", *qualified, err)
		}
		fmt.Printf("NodeFromQualifiedPath(%q) = %s\n", *qualified, node.ID)
		return
	}

	// NodeFromPath resolves a dot-separated path from the Objects folder with
	// every segment in namespace 0. Use this for standard-namespace paths.
	if *ns == 0 {
		node, err := c.NodeFromPath(ctx, *nodePath)
		if err != nil {
			log.Fatalf("NodeFromPath(%q): %v", *nodePath, err)
		}
		fmt.Printf("NodeFromPath(%q) = %s\n", *nodePath, node.ID)
		return
	}

	// NodeFromPathInNamespace resolves a dot-separated path from the Objects
	// folder with every segment in the given namespace index.
	node, err := c.NodeFromPathInNamespace(ctx, uint16(*ns), *nodePath)
	if err != nil {
		log.Fatalf("NodeFromPathInNamespace(%d, %q): %v", *ns, *nodePath, err)
	}
	fmt.Printf("NodeFromPathInNamespace(%d, %q) = %s\n", *ns, *nodePath, node.ID)

	// For a path that starts from a custom node (not the Objects folder), use
	// Node.TranslateBrowsePathInNamespaceToNodeID. Here we start from the same
	// Objects folder to show the equivalent lower-level call.
	root := c.Node(ua.NewTwoByteNodeID(id.ObjectsFolder))
	nodeID, err := root.TranslateBrowsePathInNamespaceToNodeID(ctx, uint16(*ns), *nodePath)
	if err != nil {
		log.Fatalf("TranslateBrowsePathInNamespaceToNodeID: %v", err)
	}
	fmt.Printf("root.TranslateBrowsePathInNamespaceToNodeID(%d, %q) = %s\n", *ns, *nodePath, nodeID)
}
