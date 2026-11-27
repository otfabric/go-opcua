// SPDX-License-Identifier: MIT

// Example uafx/inspect connects to a server and prints its OPC UA FX
// information model (OPC 10000-81) with uafx.Inspect: the UAFX namespaces,
// the AutomationComponents with their Assets, FunctionalEntities and
// ConnectionEndpoints, the ConnectionManager, and the deviations from
// Part 81 the address space shows.
//
// Usage:
//
//	go run ./examples/uafx/server &
//	go run ./examples/uafx/inspect -endpoint opc.tcp://localhost:4855
//	go run ./examples/uafx/inspect -endpoint opc.tcp://localhost:4855 -json
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

func main() {
	endpoint := flag.String("endpoint", "opc.tcp://localhost:4855", "OPC UA endpoint URL")
	asJSON := flag.Bool("json", false, "print the report as JSON")
	timeout := flag.Duration("timeout", 30*time.Second, "time limit of the inspection")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if err := run(ctx, *endpoint, *asJSON, os.Stdout); err != nil {
		log.Fatal(err)
	}
}

// run inspects the server at endpoint and writes the report to w.
func run(ctx context.Context, endpoint string, asJSON bool, w io.Writer) error {
	c, err := opcua.NewClient(endpoint,
		opcua.SecurityMode(ua.MessageSecurityModeNone),
		opcua.InsecureNoSecurity(), // the example server has no security
	)
	if err != nil {
		return err
	}
	if err := c.Connect(ctx); err != nil {
		return err
	}
	defer func() { _ = c.Close(context.Background()) }()

	r, err := uafx.Inspect(ctx, c, uafx.Limits{})
	if err != nil {
		return err
	}
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}
	return print(w, r)
}

// printer writes to w and keeps the first error.
type printer struct {
	w   io.Writer
	err error
}

func (p *printer) printf(format string, args ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.w, format, args...)
	}
}

// print writes the report r for a reader.
func print(w io.Writer, r *uafx.Report) error {
	p := &printer{w: w}
	p.printf("UAFX server: %v\n", r.IsFXServer())
	for _, n := range r.Namespaces {
		if n.Present {
			p.printf("  ns=%d %s %s\n", n.Index, n.URI, n.Version)
		} else {
			p.printf("  -    %s (absent)\n", n.URI)
		}
	}
	if len(r.ServerCapabilities) > 0 {
		p.printf("Server capabilities: %s\n", strings.Join(r.ServerCapabilities, ", "))
	}
	for _, ac := range r.AutomationComponents {
		p.printf("\nAutomationComponent %s (%v)\n", ac.BrowseName.Name, ac.NodeID)
		if ac.ConformanceName != "" {
			p.printf("  conformance: %s\n", ac.ConformanceName)
		}
		if h := ac.AggregatedHealth; h != nil {
			p.printf("  health: device %v, operational %v\n", h.AggregatedDeviceHealth, h.AggregatedOperationalHealth)
		}
		p.printf("  supports persistence: %v\n", ac.Capabilities.Persistence())
		for _, a := range ac.Assets {
			p.printf("  asset %s: %s %s, serial %s, hardware %s, software %s\n",
				a.BrowseName.Name, a.Manufacturer, a.Model, a.SerialNumber, a.HardwareRevision, a.SoftwareRevision)
		}
		for _, fe := range ac.FunctionalEntities {
			printEntity(p, fe, "  ")
		}
		for _, d := range ac.Descriptors {
			p.printf("  descriptor %s\n", d.BrowseName.Name)
		}
	}
	for _, cm := range r.ConnectionManagers {
		p.printf("\nConnectionManager %s (%v): %d connection configuration sets\n",
			cm.BrowseName.Name, cm.NodeID, len(cm.ConnectionConfigurationSets))
	}
	if len(r.Findings) > 0 {
		p.printf("\nFindings:\n")
		for _, f := range r.Findings {
			p.printf("  %s\n", f)
		}
	}
	if r.Truncated {
		p.printf("\nThe server holds more than the limits of the inspection: the report is incomplete.\n")
	}
	return p.err
}

func printEntity(p *printer, fe uafx.FunctionalEntity, indent string) {
	p.printf("%sfunctional entity %s", indent, fe.BrowseName.Name)
	if fe.AuthorAssignedIdentifier != "" {
		p.printf(" %s", fe.AuthorAssignedIdentifier)
	}
	if fe.AuthorAssignedVersion != nil {
		p.printf(" v%s", fe.AuthorAssignedVersion)
	}
	if fe.OperationalHealth != nil {
		p.printf(", health %v", *fe.OperationalHealth)
	}
	p.printf("\n")
	for _, ep := range fe.ConnectionEndpoints {
		status := "unknown"
		if ep.Status != nil {
			status = ep.Status.String()
		}
		cleanup := "unknown"
		switch ms := ep.CleanupTimeoutMs; {
		case ms != nil && *ms < 0:
			cleanup = "never"
		case ms != nil:
			cleanup = ep.CleanupTimeout.String()
		}
		p.printf("%s  endpoint %s: %s, persistent %v, cleanup timeout %s",
			indent, ep.BrowseName.Name, status, ep.IsPersistent, cleanup)
		if !ep.CreationTime.IsZero() {
			p.printf(", created %s, modified %s", ep.CreationTime.UTC().Format(time.RFC3339), ep.ModificationTime.UTC().Format(time.RFC3339))
		}
		p.printf("\n")
	}
	for _, sub := range fe.SubFunctionalEntities {
		printEntity(p, sub, indent+"  ")
	}
}
