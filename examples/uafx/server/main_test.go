// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/uafx"
)

func TestServer(t *testing.T) {
	ctx := context.Background()
	srv, err := newServer("localhost", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	c := testutil.NewTestClient(t, fmt.Sprintf("opc.tcp://localhost:%d", srv.Port()))

	r, err := uafx.Inspect(ctx, c, uafx.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsFXServer() || len(r.Findings) != 0 || r.Truncated {
		t.Fatalf("FX %v, findings %v, truncated %v", r.IsFXServer(), r.Findings, r.Truncated)
	}
	if len(r.AutomationComponents) != 1 || len(r.ConnectionManagers) != 1 {
		t.Fatalf("%d components, %d connection managers", len(r.AutomationComponents), len(r.ConnectionManagers))
	}
	ac := r.AutomationComponents[0]
	if ac.BrowseName.Name != "Controller" || len(ac.Assets) != 1 || len(ac.FunctionalEntities) != 1 {
		t.Fatalf("component %+v", ac)
	}
	fe := ac.FunctionalEntities[0]
	if len(fe.ConnectionEndpoints) != 1 || len(fe.SubFunctionalEntities) != 1 || fe.AuthorAssignedVersion == nil {
		t.Fatalf("functional entity %+v", fe)
	}

	// Every value of the sequence reaches a client.
	for _, h := range healthSequence {
		if err := setHealth(srv, h); err != nil {
			t.Fatal(err)
		}
		r, err := uafx.Inspect(ctx, c, uafx.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		got := r.AutomationComponents[0].AggregatedHealth
		if got == nil || uint16(got.AggregatedDeviceHealth) != h.Device || uint32(got.AggregatedOperationalHealth) != h.Operational {
			t.Fatalf("health %+v, want %+v", got, h)
		}
	}
}
