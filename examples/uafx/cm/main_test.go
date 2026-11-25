// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxcm"
)

// demoSet is a set with one Connection between two AutomationComponents
// that are not running.
func demoSet() *uafx.ConnectionConfigurationSetConf {
	addr := func(name string, port int) *uafx.ServerAddressConf {
		return &uafx.ServerAddressConf{BrowseName: name, Address: fmt.Sprintf("opc.tcp://127.0.0.1:%d", port),
			SecurityMode: ua.MessageSecurityModeNone, ServerURI: "urn:example:" + name,
			Namespaces: []string{"http://opcfoundation.org/UA/", "urn:example:uafx:controller", fxacid.NamespaceURI}}
	}
	node := func(id uint32) *uafx.NodeIdentifier { return &uafx.NodeIdentifier{Node: ua.NewNumericNodeID(1, id)} }
	endpoint := func(ac int32, name string) *uafx.ConnectionEndpointConfigurationConf {
		e := &uafx.ConnectionEndpointConfigurationConf{
			FunctionalEntityNode: node(1200), Name: name, AutomationComponentIndex: ac,
			ConnectionEndpointTypeID: ua.NewNumericNodeID(2, fxacid.PubSubConnectionEndpointType),
		}
		if ac == 0 {
			out := int32(0)
			e.OutputVariableIDs, e.OutboundFlowIndex = []*uafx.NodeIdentifier{node(1201)}, &out
		} else {
			e.InputVariableIDs, e.InboundFlowIndex = []*uafx.NodeIdentifier{node(1202)}, []int32{0, 0}
		}
		return e
	}
	return &uafx.ConnectionConfigurationSetConf{
		BrowseName:      "Line",
		ServerAddresses: []*uafx.ServerAddressConf{addr("PLC1", 1), addr("PLC2", 2)},
		AutomationComponentConfigurations: []*uafx.AutomationComponentConfigurationConf{
			{BrowseName: "AC1", AutomationComponentNode: node(1000), ServerAddressIndex: 0},
			{BrowseName: "AC2", AutomationComponentNode: node(1000), ServerAddressIndex: 1},
		},
		CommunicationFlows: []uafx.CommunicationFlowConfigurationConf{&uafx.PubSubCommunicationFlowConfigurationConf{
			BrowseName:               "Flow",
			Address:                  &uafx.AddressSelection{Address: ua.NewExtensionObject(&ua.NetworkAddressURLDataType{URL: "opc.udp://239.0.0.1:4840"})},
			SubscriberConfigurations: []*uafx.SubscriberConfigurationConf{{BrowseName: "Sub", MessageReceiveTimeout: 100}},
		}},
		Connections: []*uafx.ConnectionConfigurationConf{{BrowseName: "C1", Endpoint1: endpoint(0, "Out"), Endpoint2: endpoint(1, "In")}},
	}
}

func TestConnectionManager(t *testing.T) {
	ctx := context.Background()
	body, err := fxcm.EncodeFile([]*uafx.ConnectionConfigurationSetConf{demoSet()})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "sets.bin")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := newApp("localhost", 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.close)
	if err := a.load(path); err != nil {
		t.Fatal(err)
	}
	if err := a.load(filepath.Join(t.TempDir(), "none")); err == nil {
		t.Fatal("a missing file loaded")
	}
	if err := a.srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	c := testutil.NewTestClient(t, fmt.Sprintf("opc.tcp://localhost:%d", a.srv.Port()))

	set, ok := a.cm.SetNode(fxcm.SetKey{Name: "Line"})
	if !ok {
		t.Fatal("the set is not on the server")
	}
	sc, rs, err := uafx.EditConnectionConfigurationSets(ctx, c, uafx.StartEditing, []*ua.NodeID{set})
	if err != nil || sc != ua.StatusGood || rs[0] != ua.StatusGood {
		t.Fatalf("StartEditing: %v %v %v", sc, rs, err)
	}
	if _, _, err := uafx.EditConnectionConfigurationSets(ctx, c, uafx.DiscardUpdates, []*ua.NodeID{set}); err != nil {
		t.Fatal(err)
	}

	// The AutomationComponents are not running: the run ends in Error.
	sc, rs, err = uafx.ProcessConnectionConfigurationSets(ctx, c, uafx.ActionEstablishConnectionsEnabled, []*ua.NodeID{set})
	if err != nil || sc != ua.StatusGood || rs[0] != ua.StatusGood {
		t.Fatalf("Process: %v %v %v", sc, rs, err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		st, _ := a.m.Status(fxcm.SetKey{Name: "Line"})
		if st.State == fxcm.StateError {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("state %v", st.State)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
