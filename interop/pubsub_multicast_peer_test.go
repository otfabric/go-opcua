//go:build interop

// SPDX-License-Identifier: MIT

// UADP over UDP multicast between go-opcua and open62541 (Part 14 §7.3.2).
// COVERAGE.md: pubsub / pubsub.uadp.udp-multicast
//
// Multicast does not cross Docker Desktop's VM (macOS, Windows) or a Docker
// bridge, so these tests run the adapter in the host's network namespace
// (--network host), which only Linux provides; elsewhere they skip. The CI
// runners are Linux.

package interop

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/internal/testutil/testport"
	"github.com/otfabric/go-opcua/pubsub"
)

func requireHostNetwork(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("multicast between the host and a container needs --network host (Linux)")
	}
}

// psMulticastURL returns a multicast group address of the administratively
// scoped range with a port of its own, so parallel tests do not see each
// other's traffic.
func psMulticastURL(t *testing.T) string {
	t.Helper()
	p := testport.UDP(t)
	return fmt.Sprintf("opc.udp://239.255.%d.%d:%d", 64+p%64, 1+p%250, p)
}

// TestPubSubMulticast_Open62541Publishes_GoSubscribes: the open62541
// publisher sends UADP to a multicast group, the go-opcua runtime joins it.
func TestPubSubMulticast_Open62541Publishes_GoSubscribes(t *testing.T) {
	requirePubSubServer(t)
	requireHostNetwork(t)
	c := psRuntimeCase{psLiveCase: psLiveCase{name: "multicast", vars: psVars}}
	group := psMulticastURL(t)

	rec := newPSDataSets()
	startRuntime(t, pubsub.NewConfiguration(nil, pubsub.AttachReaderGroups(
		pubsub.UDPConnection("InteropSubscriber", group, nil), psRuntimeReader(c, "", 0))),
		pubsub.WithDataSetHandler(rec.handle))
	pub := startPubSubServer(t, pubsubServerOpts{hostNetwork: true,
		config: psPublisherConfig(c.psLiveCase, psProfileUDP, group, nil, false)})

	values := psValues(c.vars, psFresh())
	writePubSubVars(t, pub.endpoint, c.vars, values)
	ds := rec.wait(t, c.vars, values, psReceiveTimeout)
	if ds.DataSetWriterID != psWriterID {
		t.Errorf("DataSet from writer %d", ds.DataSetWriterID)
	}
}

// TestPubSubMulticast_GoPublishes_Open62541Subscribes: a go-opcua server
// publishes its PubSub.* variables to a multicast group; the open62541
// subscriber joins it and writes them into its TargetVariables.
func TestPubSubMulticast_GoPublishes_Open62541Subscribes(t *testing.T) {
	requirePubSubServer(t)
	requireHostNetwork(t)
	c := psRuntimeCase{psLiveCase: psLiveCase{name: "multicast", vars: psVars}}
	group := psMulticastURL(t)

	sub := startPubSubServer(t, pubsubServerOpts{hostNetwork: true,
		config: psSubscriberConfig(c.psLiveCase, psProfileUDP, group, nil, false)})
	pub := startGoPubSubServer(t, goPubSubOpts{}, func(p *pubsub.PubSub, ns uint16) {
		mustOK[pubsub.ComponentID](t)(p.AddPublishedDataSet(psRuntimeDataSet(c.vars, ns, c.maxStrLn)))
		w := pubsub.DataSetWriter("InteropWriter", psWriterID, "InteropDataSet")
		wg := pubsub.WriterGroup("InteropWriterGroup", psWriterGroupID, 100*time.Millisecond, w)
		mustOK[pubsub.ComponentID](t)(p.AddConnection(pubsub.AttachWriterGroups(
			pubsub.UDPConnection("InteropPublisher", group, uint16(psPubID)), wg)))
	})
	values := psValues(c.vars, psFresh())
	writePubSubVars(t, pub.endpoint, c.vars, values)
	waitPubSubVars(t, sub.endpoint, c.vars, values, psReceiveTimeout)
}
