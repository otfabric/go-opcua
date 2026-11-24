// SPDX-License-Identifier: MIT

package fxcm

import (
	"errors"
	"reflect"
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

func TestNewConfigValid(t *testing.T) {
	conf := validConf()
	conf.Version = 7
	c, err := NewConfig(conf)
	if err != nil {
		t.Fatal(err)
	}
	if c.Version() != 1 {
		t.Errorf("Version %d, want 1 (§6.8.2: a set that is added has Version 1)", c.Version())
	}
	if k := c.Key(); !k.Equal(SetKey{Folder: []string{"Plant", "Hall"}, Name: "Line1"}) {
		t.Errorf("Key %v", k)
	}
	if !c.RollbackOnError() {
		t.Error("RollbackOnError lost")
	}
	if got := c.Connections(); !reflect.DeepEqual(got, []string{"C1", "C2"}) {
		t.Errorf("Connections %v", got)
	}

	// The Config is a copy: changing the input or the result of Conf
	// changes nothing.
	conf.BrowseName = "changed"
	conf.Connections[0].BrowseName = "changed"
	cp := c.Conf()
	if cp.BrowseName != "Line1" || cp.Connections[0].BrowseName != "C1" || cp.Version != 1 {
		t.Errorf("Conf %q %q %d", cp.BrowseName, cp.Connections[0].BrowseName, cp.Version)
	}
	cp.Connections[0].BrowseName = "again"
	if c.Conf().Connections[0].BrowseName != "C1" {
		t.Error("Conf returned the private copy")
	}
	k := c.Key()
	k.Folder[0] = "x"
	if c.Key().Folder[0] != "Plant" {
		t.Error("Key returned the private Folder")
	}

	// The graph resolves the indexes (F.1.2.1).
	e1 := c.conns[0].endpoints[0]
	e2 := c.conns[0].endpoints[1]
	if e1.ac != c.acs[0] || e1.ac.server != c.servers[0] || e1.outbound != c.flows[0] || e1.inbound != nil {
		t.Errorf("C1.Endpoint1 not resolved: %+v", e1)
	}
	if e2.ac != c.acs[1] || e2.inbound == nil || e2.inbound.flow != c.flows[0] || e2.inbound.subscriber != c.flows[0].conf.SubscriberConfigurations[0] {
		t.Errorf("C1.Endpoint2 not resolved: %+v", e2)
	}
	if m := c.flows[0].multicast; m == nil || !*m {
		t.Error("Flow1 not multicast")
	}
	if m := c.flows[1].multicast; m == nil || *m {
		t.Error("Flow2 not unicast")
	}
	if c.conns[1].endpoints[1].outbound != nil {
		t.Error("a negative OutboundFlowIndex is no flow (F.1.2.1)")
	}
}

func TestNewConfigNil(t *testing.T) {
	_, err := NewConfig(nil)
	var ce *ConfigError
	if !errors.As(err, &ce) || len(ce.Findings) != 1 {
		t.Fatalf("err %v", err)
	}
}

func TestNewConfigNotEncodable(t *testing.T) {
	conf := validConf()
	conf.ConnectionConfigurationSetProperties = []*ua.KeyValuePair{{Key: &ua.QualifiedName{Name: "k"}, Value: ua.MustVariant(ua.NewExtensionObject(struct{ X chan int }{}))}}
	_, err := NewConfig(conf)
	var ce *ConfigError
	if !errors.As(err, &ce) || ce.Findings[0].Clause != "F.2" {
		t.Fatalf("err %v", err)
	}
}

func TestNamespaceScope(t *testing.T) {
	s := namespaceScope{"", "urn:a", ""}
	for _, tc := range []struct {
		idx uint16
		uri string
		ok  bool
	}{
		{0, uaNamespace, true},
		{1, "urn:a", true},
		{2, "", false},
		{3, "", false},
	} {
		if u, ok := s.uri(tc.idx); u != tc.uri || ok != tc.ok {
			t.Errorf("uri(%d) = %q, %v", tc.idx, u, ok)
		}
	}
	if u, ok := namespaceScope(nil).uri(0); !ok || u != uaNamespace {
		t.Error("index 0 without Namespaces")
	}
}

func TestMulticastAddress(t *testing.T) {
	tr, fa := true, false
	for _, tc := range []struct {
		eo   *ua.ExtensionObject
		want *bool
	}{
		{nil, nil},
		{urlAddress("opc.udp://239.0.0.1:4840"), &tr},
		{urlAddress("opc.udp://[ff02::1]:4840"), &tr},
		{urlAddress("opc.udp://192.168.0.1:4840"), &fa},
		{urlAddress("opc.udp://plc:4840"), nil},
		{urlAddress("://bad"), nil},
		{ua.NewExtensionObject(&ua.NetworkAddressDataType{NetworkInterface: "eth0"}), nil},
		{ua.NewExtensionObject((*ua.NetworkAddressURLDataType)(nil)), nil},
	} {
		got := multicastAddress(tc.eo)
		if (got == nil) != (tc.want == nil) || got != nil && *got != *tc.want {
			t.Errorf("%v: %v, want %v", tc.eo, got, tc.want)
		}
	}
}

// pubsubFlow returns flow i of conf.
func pubsubFlow(c *uafx.ConnectionConfigurationSetConf, i int) *uafx.PubSubCommunicationFlowConfigurationConf {
	return c.CommunicationFlows[i].(*uafx.PubSubCommunicationFlowConfigurationConf)
}
