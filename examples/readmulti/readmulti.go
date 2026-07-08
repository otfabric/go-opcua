// SPDX-License-Identifier: MIT

// Example readmulti demonstrates batch reading many nodes with Client.ReadMulti.
//
// It first walks a subtree (Node.WalkLimit) to collect Variable node IDs, then
// reads all of their Value attributes in a single call. ReadMulti chunks the
// request automatically (DefaultReadMultiChunkSize = 32, or override with
// ReadMultiWithChunkSize) so it stays under typical server MaxNodesPerRead
// limits. This is the efficient way to export a whole subtree.
//
// Usage:
//
//	go run readmulti.go -endpoint opc.tcp://localhost:4840
//	go run readmulti.go -endpoint opc.tcp://localhost:4840 -node "ns=0;i=85" -depth 3 -chunk 16
package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"os"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

func main() {
	var (
		endpoint = flag.String("endpoint", "opc.tcp://localhost:4840", "OPC UA Endpoint URL")
		nodeID   = flag.String("node", "", "root NodeID of the subtree to read (default: Objects folder i=85)")
		depth    = flag.Int("depth", 3, "maximum browse depth")
		chunk    = flag.Int("chunk", 0, "max items per Read request (0 = default 32)")
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

	root := c.Node(ua.NewTwoByteNodeID(id.ObjectsFolder))
	if *nodeID != "" {
		nid, err := ua.ParseNodeID(*nodeID)
		if err != nil {
			log.Fatalf("invalid node id: %v", err)
		}
		root = c.Node(nid)
	}

	// 1. Walk the subtree and collect every Variable node as a ReadItem.
	var items []opcua.ReadItem
	for wr, err := range root.WalkLimit(ctx, *depth) {
		if err != nil {
			log.Fatalf("walk failed: %v", err)
		}
		if wr.Ref == nil || wr.Ref.NodeClass != ua.NodeClassVariable {
			continue
		}
		node := c.NodeFromExpandedNodeID(wr.Ref.NodeID)
		items = append(items, opcua.ReadItem{
			NodeID:      node.ID,
			AttributeID: ua.AttributeIDValue,
		})
	}
	log.Printf("collected %d variable node(s)", len(items))

	// 2. Batch read all values. Optionally override the per-request chunk size.
	var opts []opcua.ReadMultiOption
	if *chunk > 0 {
		opts = append(opts, opcua.ReadMultiWithChunkSize(uint32(*chunk)))
	}
	results, err := c.ReadMulti(ctx, items, opts...)
	if err != nil {
		log.Fatalf("ReadMulti failed: %v", err)
	}

	// 3. Results are in the same order as items; each carries a per-item status.
	for i, r := range results {
		if r.StatusCode != ua.StatusOK {
			log.Printf("%s: %s", items[i].NodeID, r.StatusCode)
			continue
		}
		var val any
		if r.DataValue != nil && r.DataValue.Value != nil {
			val = r.DataValue.Value.Value()
		}
		log.Printf("%s = %v", items[i].NodeID, val)
	}
}
