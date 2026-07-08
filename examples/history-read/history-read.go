// SPDX-License-Identifier: MIT

// Example history-read demonstrates reading historical data with
// HistoryReadRawModified and manual continuation-point handling.
//
// For a simpler approach that pages through all values automatically, see the
// history-read-simple example, which uses the Client.ReadHistoryAll iterator.
//
// Usage:
//
//	go run history-read.go -endpoint opc.tcp://localhost:4840 -node "ns=2;s=Temperature"
package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"os"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
)

func main() {
	endpoint := flag.String("endpoint", "opc.tcp://localhost:4840", "OPC UA Endpoint URL")
	nodeID := flag.String("node", "", "NodeID to read")
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

	// HistoryRead with ContinuationPoint use
	nodesToRequest := []*ua.HistoryReadValueID{
		{
			NodeID:       id,
			DataEncoding: &ua.QualifiedName{},
		},
	}

	for len(nodesToRequest) > 0 {
		// For ContinuationPoint usage
		// Get current nodes
		nodes := nodesToRequest
		// Reset old nodes
		nodesToRequest = make([]*ua.HistoryReadValueID, 0)

		data, err := c.HistoryReadRawModified(ctx, nodes, &ua.ReadRawModifiedDetails{
			IsReadModified: false,
			StartTime:      time.Now().UTC().AddDate(0, -1, 0),
			EndTime:        time.Now().UTC().AddDate(0, 1, 0),
		})
		if err != nil {
			log.Printf("HistoryReadRequest error: %s", err)
			break
		}

		if data == nil || len(data.Results) == 0 {
			break
		}

		for nodeNum, result := range data.Results {
			if result.StatusCode != ua.StatusOK {
				log.Printf("result.StatusCode not StatusOK: %d", result.StatusCode)
				continue
			}

			// If this is not the end of the data - continue requesting
			if len(result.ContinuationPoint) > 0 {
				nodeNew := nodes[nodeNum]
				nodeNew.ContinuationPoint = result.ContinuationPoint
				nodesToRequest = append(nodesToRequest, nodeNew)
			}

			if result.HistoryData == nil || result.HistoryData.Value == nil {
				continue
			}

			historyData, ok := result.HistoryData.Value.(*ua.HistoryData)
			if !ok || historyData == nil || len(historyData.DataValues) == 0 {
				continue
			}

			for _, value := range historyData.DataValues {
				log.Printf(
					"%s - %s - %v \n",
					nodes[nodeNum].NodeID.String(),
					value.SourceTimestamp.Format(time.RFC3339),
					value.Value.Value(),
				)
			}
		}
	}
}
