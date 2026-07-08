// SPDX-License-Identifier: MIT

// Example metrics demonstrates production observability wiring: a ClientMetrics
// implementation attached via WithMetrics for per-service instrumentation, and
// an exponential back-off RetryPolicy attached via WithRetryPolicy.
//
// The metrics callbacks fire for every OPC-UA service call (Read, Write,
// Browse, Call, CreateSubscription, ...). Real implementations would forward
// these to Prometheus, OpenTelemetry, statsd, etc.; here they log with slog.
//
// Usage:
//
//	go run metrics.go -endpoint opc.tcp://localhost:4840 -node "ns=0;i=2258"
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

// logMetrics is a minimal ClientMetrics implementation that logs each event.
// Callbacks must be non-blocking; logging here is for demonstration only.
type logMetrics struct{}

func (logMetrics) OnRequest(service string) {
	slog.Info("request", "service", service)
}

func (logMetrics) OnResponse(service string, d time.Duration) {
	slog.Info("response", "service", service, "duration", d)
}

func (logMetrics) OnError(service string, d time.Duration, err error) {
	slog.Error("error", "service", service, "duration", d, "err", err)
}

func (logMetrics) OnTimeout(service string, d time.Duration) {
	slog.Warn("timeout", "service", service, "duration", d)
}

func main() {
	var (
		endpoint = flag.String("endpoint", "opc.tcp://localhost:4840", "OPC UA Endpoint URL")
		nodeID   = flag.String("node", "ns=0;i=2258", "NodeID to read (default: Server CurrentTime)")
	)
	flag.Parse()
	log.SetFlags(0)
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	ctx := context.Background()

	// WithMetrics attaches instrumentation; WithRetryPolicy retries failed
	// requests with exponential back-off (base 100ms, cap 10s, up to 5 attempts).
	c, err := opcua.NewClient(*endpoint,
		opcua.SecurityMode(ua.MessageSecurityModeNone),
		opcua.WithMetrics(logMetrics{}),
		opcua.WithRetryPolicy(opcua.ExponentialBackoff(100*time.Millisecond, 10*time.Second, 5)),
	)
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

	// Each of these calls triggers the metrics callbacks above.
	dv, err := c.ReadValue(ctx, id)
	if err != nil {
		log.Fatalf("read failed: %v", err)
	}
	log.Printf("value: %v", dv.Value.Value())
}
