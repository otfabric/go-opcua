// Copyright 2018-2020 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

// Example method demonstrates calling a method on an OPC-UA server object.
// It shows how to pass input arguments and receive output arguments using
// the Call service.
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

	in := int64(12)
	req := &ua.CallMethodRequest{
		ObjectID:       ua.NewStringNodeID(2, "main"),
		MethodID:       ua.NewStringNodeID(2, "even"),
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
	log.Printf("%d is even: %v", in, out)
}
