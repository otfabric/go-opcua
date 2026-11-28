// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/cleanup"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxacid"
)

func TestServer(t *testing.T) {
	ctx := context.Background()
	a, err := newApp("localhost", 0)
	if err != nil {
		t.Fatal(err)
	}
	srv := a.srv
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	cleanup.Register(t, a.close)
	c := testutil.NewTestClient(t, fmt.Sprintf("opc.tcp://localhost:%d", srv.Port()))

	arr, err := c.NamespaceArray(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if arr[1] != applicationURI {
		t.Fatalf("namespace 1 is %s, want %s (Part 81 §14.2)", arr[1], applicationURI)
	}

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

	// Every value of the sequence reaches a client. ToLine references no
	// DataSetReader or DataSetWriter yet: it is Initial, which the
	// connections report as CommInitial in bit 0 (Part 81 §10.9, §10.34).
	for _, h := range healthSequence {
		if err := a.setHealth(h); err != nil {
			t.Fatal(err)
		}
		r, err := uafx.Inspect(ctx, c, uafx.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		got := r.AutomationComponents[0].AggregatedHealth
		if got == nil || uint16(got.AggregatedDeviceHealth) != h.Device || uint32(got.AggregatedOperationalHealth) != h.Operational|1 {
			t.Fatalf("health %+v, want %+v", got, h)
		}
	}

	// A client creates a ConnectionEndpoint, writes ConfigurationData and
	// removes the endpoint again.
	ctl, _ := index(srv, controllerNS)
	acNS, _ := index(srv, fxacid.NamespaceURI)
	id := func(n uint32) *ua.NodeID { return ua.NewNumericNodeID(ctl, n) }
	res, err := uafx.EstablishConnections(ctx, c, id(1000), &uafx.EstablishConnectionsRequest{
		CommandMask: uafx.CreateConnectionEndpointCmd | uafx.SetConfigurationDataCmd,
		ConnectionEndpointConfigurations: []*uafx.ConnectionEndpointConfiguration{{
			FunctionalEntityNode: id(1200),
			ConnectionEndpoint: &uafx.ConnectionEndpointDefinition{Parameter: &uafx.PubSubConnectionEndpointParameter{
				Name:                     "FromLine",
				ConnectionEndpointTypeID: ua.NewNumericNodeID(acNS, fxacid.PubSubConnectionEndpointType),
				InputVariableIDs:         []*ua.NodeID{id(1221)},
				CleanupTimeout:           -1,
				RelatedEndpoint:          &uafx.RelatedEndpoint{Address: "opc.tcp://line:4840", ConnectionEndpointName: "ToController"},
				Mode:                     uafx.PubSubSubscriber,
			}},
			ConfigurationData: []*uafx.NodeIDValuePair{{Key: &uafx.NodeIDArray{Node: id(1241)}, Value: ua.MustVariant(20.0)}},
		}},
	})
	if err != nil || res.Status != ua.StatusOK {
		t.Fatalf("EstablishConnections: %v %+v", err, res)
	}
	ep := res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointID
	if v := srv.Node(id(1241)).Value().Value.Value(); v != 20.0 {
		t.Fatalf("MaxAcceleration %v", v)
	}
	sc, results, err := uafx.CloseConnections(ctx, c, id(1000), []*ua.NodeID{ep}, true)
	if err != nil || sc != ua.StatusOK || len(results) != 1 || results[0] != ua.StatusOK {
		t.Fatalf("CloseConnections: %v %v %v", err, sc, results)
	}
	if srv.Node(ep) != nil {
		t.Fatal("the endpoint stays")
	}
}
