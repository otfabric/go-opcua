// SPDX-License-Identifier: MIT

// Example method demonstrates calling a method on an OPC-UA server object.
//
// It shows the high-level CallMethod helper (which wraps Go values into
// Variants automatically) and MethodArguments (which reports a method's
// declared input/output arguments), as well as the low-level Call service.
//
// Usage:
//
//	go run method.go -endpoint opc.tcp://localhost:4840
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

	objectID := ua.NewStringNodeID(2, "main")
	methodID := ua.NewStringNodeID(2, "even")
	in := int64(12)

	// MethodArguments reports a method's declared input/output arguments, which
	// is handy for discovering the signature before calling. Servers that do not
	// expose Input/OutputArguments properties return empty slices.
	inputs, outputs, err := c.MethodArguments(ctx, objectID, methodID)
	if err != nil {
		log.Printf("MethodArguments unavailable: %v", err)
	} else {
		for _, a := range inputs {
			log.Printf("input  arg: %s", a.Name)
		}
		for _, a := range outputs {
			log.Printf("output arg: %s", a.Name)
		}
	}

	// High-level: CallMethod wraps each Go argument in a Variant automatically.
	result, err := c.CallMethod(ctx, objectID, methodID, in)
	if err != nil {
		log.Fatal(err)
	}
	if result.StatusCode != ua.StatusOK {
		log.Fatalf("CallMethod status: %v", result.StatusCode)
	}
	log.Printf("CallMethod: %d is even: %v", in, result.OutputArguments[0].Value())

	// Low-level: for full control, build a CallMethodRequest and call Call.
	req := &ua.CallMethodRequest{
		ObjectID:       objectID,
		MethodID:       methodID,
		InputArguments: []*ua.Variant{ua.MustVariant(in)},
	}

	resp, err := c.Call(ctx, req)
	if err != nil {
		log.Fatal(err)
	}
	if got, want := resp.StatusCode, ua.StatusOK; got != want {
		log.Fatalf("got status %v want %v", got, want)
	}
	out := resp.OutputArguments[0].Value()
	log.Printf("Call: %d is even: %v", in, out)
}
