// SPDX-License-Identifier: MIT

package fxcm_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/testutil/fxtest"
	"github.com/otfabric/go-opcua/internal/testutil/testport"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/pubsub/transport/udp"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxcm"
	"github.com/otfabric/go-opcua/uafx/fxdataid"
	"github.com/otfabric/go-opcua/uafx/fxserver"
)

// The environment of the multicast end-to-end test.
//
//   - GO_OPCUA_MULTICAST_IFACE names the interface to send and join the
//     group on; empty tries the system default, the loopback interface and
//     two others, and takes the first on which a datagram sent to the group
//     comes back to this host.
//   - GO_OPCUA_MULTICAST_REQUIRE=1 turns the skip into a failure when no
//     interface carries multicast (CI must not pass by skipping it).
const (
	multicastIfaceEnv   = "GO_OPCUA_MULTICAST_IFACE"
	multicastRequireEnv = "GO_OPCUA_MULTICAST_REQUIRE"
)

// multicastGroup is the administratively scoped group of the test (RFC
// 2365).
const multicastGroup = "239.255.81.13"

func skipMulticast(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv(multicastRequireEnv) != "" {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}

// multicastIface returns an interface on which a datagram sent to
// multicastGroup reaches a subscriber of the group on this host.
func multicastIface(t *testing.T) string {
	t.Helper()
	cands := []string{os.Getenv(multicastIfaceEnv)}
	if cands[0] == "" {
		ifs, _ := net.Interfaces()
		var rest []string
		for _, ifi := range ifs {
			switch {
			case ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagMulticast == 0:
			case ifi.Flags&net.FlagLoopback != 0:
				cands = append(cands, ifi.Name)
			default:
				rest = append(rest, ifi.Name)
			}
		}
		cands = append(cands, rest[:min(2, len(rest))]...)
	}
	for _, ifName := range cands {
		if probeMulticast(t, ifName) {
			return ifName
		}
	}
	skipMulticast(t, "no interface carries UDP multicast to %s on this host (tried %q)", multicastGroup, cands)
	return ""
}

func probeMulticast(t *testing.T, ifName string) bool {
	t.Helper()
	ctx := context.Background()
	cfg := transport.Config{URL: fmt.Sprintf("opc.udp://%s:%d", multicastGroup, testport.UDP(t)), Interface: ifName}
	sub, err := udp.Open(ctx, cfg)
	if err != nil {
		t.Logf("interface %q: %v", ifName, err)
		return false
	}
	defer func() { _ = sub.Close() }()
	got := make(chan struct{}, 1)
	if _, err := sub.Subscribe(ctx, "", 0, func(*transport.Message) {
		select {
		case got <- struct{}{}:
		default:
		}
	}); err != nil {
		t.Logf("interface %q: %v", ifName, err)
		return false
	}
	pub, err := udp.Open(ctx, cfg)
	if err != nil {
		t.Logf("interface %q: %v", ifName, err)
		return false
	}
	defer func() { _ = pub.Close() }()
	for range 3 {
		if err := pub.Send(ctx, []byte("probe"), transport.PublishOptions{}); err != nil {
			t.Logf("interface %q: %v", ifName, err)
			return false
		}
		select {
		case <-got:
			return true
		case <-time.After(200 * time.Millisecond):
		}
	}
	t.Logf("interface %q: no multicast loopback", ifName)
	return false
}

// multicastAddr is the Address of a PubSubConnection or flow on the group.
func multicastAddr(url, ifName string) *ua.ExtensionObject {
	return ua.NewExtensionObject(&ua.NetworkAddressURLDataType{NetworkInterface: ifName, URL: url})
}

// multicastModel is the PubSubConfiguration of an AC of multicastConf:
// the publisher sends Actual to the group, a subscriber writes what it
// reads to Setpoint. The ids are left to the ConnectionManager (E.2.2).
func multicastModel(url, ifName string, publisher bool) *uafx.PubSubCommunicationModelConfiguration {
	add := ua.PubSubConfigurationRefMaskElementAdd
	match := ua.PubSubConfigurationRefMaskElementMatch
	ref := func(m ua.PubSubConfigurationRefMask) *ua.PubSubConfigurationRefDataType {
		return &ua.PubSubConfigurationRefDataType{ConfigurationMask: add | m}
	}
	conn := pubsub.UDPConnection("Group", url, nil)
	conn.Address = multicastAddr(url, ifName)
	if publisher {
		pds := pubsub.PublishedDataItems("PDS", pubsub.Var("x", ua.NewNumericNodeID(e2eTest, fxtest.ConnActual), ua.TypeIDDouble))
		wg := pubsub.WriterGroup("", 0, 10*time.Millisecond, pubsub.DataSetWriter("W", 0, "PDS"))
		return &uafx.PubSubCommunicationModelConfiguration{
			PubSubConfiguration: &ua.PubSubConfiguration2DataType{
				PublishedDataSets: []*ua.PublishedDataSetDataType{pds},
				Connections:       []*ua.PubSubConnectionDataType{pubsub.AttachWriterGroups(conn, wg)},
				Enabled:           true,
			},
			ConfigurationReferences: []*ua.PubSubConfigurationRefDataType{
				ref(ua.PubSubConfigurationRefMaskReferencePubDataset),
				ref(ua.PubSubConfigurationRefMaskReferenceConnection | match),
				ref(ua.PubSubConfigurationRefMaskReferenceWriterGroup),
				ref(ua.PubSubConfigurationRefMaskReferenceWriter),
			},
		}
	}
	md := pubsub.MetaData("m", pubsub.Field{Name: "x", Type: ua.TypeIDDouble})
	r := pubsub.SetTargetVariables(pubsub.DataSetReader("R", nil, 0, 0, md), pubsub.Target(ua.NewNumericNodeID(e2eTest, fxtest.ConnSetpoint)))
	return &uafx.PubSubCommunicationModelConfiguration{
		PubSubConfiguration: &ua.PubSubConfiguration2DataType{
			Connections: []*ua.PubSubConnectionDataType{pubsub.AttachReaderGroups(conn, pubsub.ReaderGroup("RG", r))},
			Enabled:     true,
		},
		ConfigurationReferences: []*ua.PubSubConfigurationRefDataType{
			ref(ua.PubSubConfigurationRefMaskReferenceConnection | match),
			ref(ua.PubSubConfigurationRefMaskReferenceReaderGroup | match),
			ref(ua.PubSubConfigurationRefMaskReferenceReader),
		},
	}
}

// multicastConf is a set with one multicast flow (§6.13.3.2) that pub
// publishes and subs subscribe to, each with its own
// SubscriberConfiguration: a unidirectional Connection from pub to the
// first subscriber and an autonomous subscriber Connection (§5.5.1) for
// each other one.
func multicastConf(t *testing.T, name, url, ifName string, pub *ac, subs ...*ac) *uafx.ConnectionConfigurationSetConf {
	t.Helper()
	links := func(publisher bool) *ua.ExtensionObject {
		l := &uafx.PubSubCommunicationLinkConfiguration{}
		if publisher {
			l.DataSetWriterRef = &ua.PubSubConfigurationRefDataType{ConfigurationMask: ua.PubSubConfigurationRefMaskReferenceWriter}
		} else {
			l.DataSetReaderRef = &ua.PubSubConfigurationRefDataType{ConfigurationMask: ua.PubSubConfigurationRefMaskReferenceReader}
		}
		eo, err := uafx.EncodeStructure(l, uafx.NamespaceIndexes{Data: e2eData, AC: e2eAC})
		require.NoError(t, err)
		return eo
	}
	c := &uafx.ConnectionConfigurationSetConf{BrowseName: name, RollbackOnError: true}
	flow := &uafx.PubSubCommunicationFlowConfigurationConf{BrowseName: "Group", Address: &uafx.AddressSelection{Address: multicastAddr(url, ifName)}}
	c.CommunicationFlows = []uafx.CommunicationFlowConfigurationConf{flow}
	for i, x := range append([]*ac{pub}, subs...) {
		c.ServerAddresses = append(c.ServerAddresses, &uafx.ServerAddressConf{
			BrowseName: x.uri, Address: x.url, SecurityMode: ua.MessageSecurityModeNone, ServerURI: x.uri,
			Namespaces: []string{uaNamespace, fxtest.ConnNS, fxacid.NamespaceURI, fxdataid.NamespaceURI},
		})
		c.AutomationComponentConfigurations = append(c.AutomationComponentConfigurations, &uafx.AutomationComponentConfigurationConf{
			BrowseName: fmt.Sprintf("AC%d", i+1), AutomationComponentNode: n(fxtest.ConnCtl), ServerAddressIndex: int32(i),
			CommunicationModelConfig: multicastModel(url, ifName, i == 0),
		})
	}
	endpoint := func(acIdx int32, name string) *uafx.ConnectionEndpointConfigurationConf {
		e := &uafx.ConnectionEndpointConfigurationConf{
			FunctionalEntityNode:     n(fxtest.ConnMotion),
			Name:                     name,
			ConnectionEndpointTypeID: ua.NewNumericNodeID(e2eAC, fxacid.PubSubConnectionEndpointType),
			CleanupTimeout:           -1,
			AutomationComponentIndex: acIdx,
			CommunicationLinks:       links(acIdx == 0),
		}
		if acIdx == 0 {
			e.OutputVariableIDs = []*uafx.NodeIdentifier{n(fxtest.ConnActual)}
			e.OutboundFlowIndex = ptr[int32](0)
		} else {
			e.InputVariableIDs = []*uafx.NodeIdentifier{n(fxtest.ConnSetpoint)}
			e.InboundFlowIndex = []int32{0, acIdx - 1}
			e.OutboundFlowIndex = ptr[int32](-1)
		}
		return e
	}
	for i := range subs {
		flow.SubscriberConfigurations = append(flow.SubscriberConfigurations,
			&uafx.SubscriberConfigurationConf{BrowseName: fmt.Sprintf("S%d", i+2), MessageReceiveTimeout: 1000})
		cn := &uafx.ConnectionConfigurationConf{BrowseName: fmt.Sprintf("To%d", i+2), Endpoint1: endpoint(int32(i+1), "FromPub")}
		if i == 0 {
			cn.Endpoint1, cn.Endpoint2 = endpoint(0, "Pub"), cn.Endpoint1
		}
		c.Connections = append(c.Connections, cn)
	}
	return c
}

// TestConnectionManagerMulticast is the multicast scenario of design §7.1
// on a real network interface: AC1 publishes to a UDP multicast group, AC2
// and AC3 subscribe, a ConnectionManager server (four servers) establishes
// and removes the set through its Methods. One WriterGroup and
// DataSetWriter on AC1 serve both subscribers (§5.2, E.2.2.2).
func TestConnectionManagerMulticast(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ifName := multicastIface(t)
	t.Logf("multicast %s on interface %q", multicastGroup, ifName)
	url := fmt.Sprintf("opc.udp://%s:%d", multicastGroup, testport.UDP(t))
	a := newAC(t, "mc-a", fxserver.ConnectionOptions{})
	b := newAC(t, "mc-b", fxserver.ConnectionOptions{})
	c := newAC(t, "mc-c", fxserver.ConnectionOptions{})
	require.NoError(t, fxtest.SetValue(a.srv, a.id(fxtest.ConnActual), 33.0))

	m := newManager(t, fxcm.Options{})
	_, err := m.Add(multicastConf(t, "Multicast", url, ifName, a, b, c))
	require.NoError(t, err)
	s := newCMServer(t, m)
	k := fxcm.SetKey{Name: "Multicast"}
	set, ok := s.cm.SetNode(k)
	require.True(t, ok)
	process := func(action uafx.FxProcess) {
		t.Helper()
		sc, rs, err := uafx.ProcessConnectionConfigurationSets(ctx, s.c, action, []*ua.NodeID{set})
		require.NoError(t, err)
		require.Equal(t, ua.StatusGood, sc)
		require.Equal(t, []ua.StatusCode{ua.StatusGood}, rs)
		require.Eventually(t, func() bool {
			st, _ := m.Status(k)
			return st.State != fxcm.StateProcessing && st.Last != nil && st.Last.Action() == action
		}, 30*time.Second, 10*time.Millisecond)
		st, _ := m.Status(k)
		require.Equal(t, fxcm.StateReady, st.State, "%v: %+v", action, st.Last)
	}

	process(uafx.ActionEstablishConnectionsEnabled)
	assert.Equal(t, []string{"Pub"}, a.endpoints())
	assert.Equal(t, []string{"FromPub"}, b.endpoints())
	assert.Equal(t, []string{"FromPub"}, c.endpoints())
	assert.Equal(t, 1, countWritersReaders(a), "one DataSetWriter serves both subscribers")
	for _, x := range []*ac{b, c} {
		require.Eventually(t, func() bool { return x.value(t, fxtest.ConnSetpoint) == 33.0 }, 10*time.Second, 10*time.Millisecond, x.uri)
	}
	require.NoError(t, fxtest.SetValue(a.srv, a.id(fxtest.ConnActual), 34.0))
	for _, x := range []*ac{b, c} {
		require.Eventually(t, func() bool { return x.value(t, fxtest.ConnSetpoint) == 34.0 }, 10*time.Second, 10*time.Millisecond, x.uri)
	}

	process(uafx.ActionRemoveConnections)
	for _, x := range []*ac{a, b, c} {
		assert.Empty(t, x.endpoints(), x.uri)
		assert.Zero(t, countWritersReaders(x), x.uri)
	}
}
