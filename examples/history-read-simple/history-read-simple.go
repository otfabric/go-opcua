// SPDX-License-Identifier: MIT

// Example history-read-simple demonstrates reading historical data with the
// Client.ReadHistoryAll iterator (Go 1.23 range-over-func), and historical
// events with the Client.ReadEventHistoryAll iterator.
//
// Unlike the history-read example, which drives HistoryReadRawModified and
// manages continuation points by hand, the iterators page through the time
// range automatically and yield one value or event at a time. Stopping early
// (-limit) releases the continuation point the server still holds.
//
// Usage:
//
//	go run history-read-simple.go -endpoint opc.tcp://localhost:4840 -node "ns=2;s=Temperature"
//	go run history-read-simple.go -endpoint opc.tcp://localhost:4840 -node "ns=2;s=Temperature" \
//	    -start 2026-01-01T00:00:00Z -end 2026-02-01T00:00:00Z
//	go run history-read-simple.go -endpoint opc.tcp://localhost:4840 -node "i=2253" -events -limit 20
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
	var (
		endpoint = flag.String("endpoint", "opc.tcp://localhost:4840", "OPC UA Endpoint URL")
		nodeID   = flag.String("node", "", "NodeID to read history for")
		startStr = flag.String("start", "", "range start (RFC3339, default: 24h ago)")
		endStr   = flag.String("end", "", "range end (RFC3339, default: now)")
		events   = flag.Bool("events", false, "read the event history of a notifier instead of values")
		limit    = flag.Int("limit", 0, "stop after this many values or events (0: all)")
	)
	var debugMode bool
	flag.BoolVar(&debugMode, "debug", false, "enable debug logging")

	flag.Parse()
	if debugMode {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}
	log.SetFlags(0)

	start := time.Now().Add(-24 * time.Hour)
	if *startStr != "" {
		t, err := time.Parse(time.RFC3339, *startStr)
		if err != nil {
			log.Fatalf("invalid -start: %v", err)
		}
		start = t
	}
	end := time.Now()
	if *endStr != "" {
		t, err := time.Parse(time.RFC3339, *endStr)
		if err != nil {
			log.Fatalf("invalid -end: %v", err)
		}
		end = t
	}

	ctx := context.Background()

	c, err := opcua.NewClient(*endpoint, opcua.InsecureNoSecurity())
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

	if *events {
		readEvents(ctx, c, id, start, end, *limit)
		return
	}

	// ReadHistoryAll returns an iterator that pages through every historical
	// value in [start, end], handling continuation points internally.
	count := 0
	for dv, err := range c.ReadHistoryAll(ctx, id, start, end) {
		if err != nil {
			log.Fatalf("history read failed: %v", err)
		}
		var val any
		if dv.Value != nil {
			val = dv.Value.Value()
		}
		log.Printf("%s  %v", dv.SourceTimestamp.Format(time.RFC3339), val)
		count++
		if count == *limit {
			break // releases the continuation point
		}
	}
	log.Printf("read %d historical value(s)", count)
}

// readEvents prints the historical events of a notifier, newest first when
// start is after end (Part 11 §6.5.2).
func readEvents(ctx context.Context, c *opcua.Client, notifier *ua.NodeID, start, end time.Time, limit int) {
	filter := ua.NewEventFilter().Select("Time", "Severity", "Message").Build()
	count := 0
	for ev, err := range c.ReadEventHistoryAll(ctx, notifier, start, end, filter, 100) {
		if err != nil {
			log.Fatalf("event history read failed: %v", err)
		}
		f := ev.EventFields
		t, _ := f[0].Value().(time.Time)
		log.Printf("%s  severity %v  %v", t.Format(time.RFC3339), f[1].Value(), f[2].Value())
		count++
		if count == limit {
			break // releases the continuation point
		}
	}
	log.Printf("read %d historical event(s)", count)
}
