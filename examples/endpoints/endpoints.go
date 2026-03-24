// Copyright 2018-2020 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

// Package main provides an example to query the available endpoints of a server.
package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"os"

	"github.com/otfabric/go-opcua"
)

func main() {
	var endpoint = flag.String("endpoint", "opc.tcp://localhost:4840", "OPC UA Endpoint URL")
	var debugMode bool
	flag.BoolVar(&debugMode, "debug", false, "enable debug logging")

	flag.Parse()
	if debugMode {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}
	log.SetFlags(0)

	eps, err := opcua.GetEndpoints(context.Background(), *endpoint)
	if err != nil {
		log.Fatal(err)
	}

	for _, ep := range eps {
		log.Println(ep.EndpointURL, ep.SecurityPolicyURI, ep.SecurityMode)
	}
}
