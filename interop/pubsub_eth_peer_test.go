//go:build interop

// SPDX-License-Identifier: MIT

// UADP over Ethernet between go-opcua and open62541 (Part 14 §7.3.3,
// profile pubsub-eth-uadp).
// COVERAGE.md: pubsub / pubsub.uadp.eth
//
// The adapter runs on a user-defined Docker bridge network whose bridge
// interface has a known name; go-opcua sends and receives raw frames on that
// interface of the host, which the bridge forwards to and from the
// container's eth0. Raw sockets need root (or CAP_NET_RAW) and a Linux host:
// Docker Desktop's VM (macOS, Windows) keeps the bridge out of reach. The
// tests skip elsewhere unless GO_OPCUA_ETH_REQUIRE is set, which makes a skip
// a failure (the CI job that runs them as root sets it).

package interop

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/internal/testutil/testport"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/ua"
)

const psProfileEth = "http://opcfoundation.org/UA-Profile/Transport/pubsub-eth-uadp"

// psEthGroup is the multicast MAC address of the open62541 Ethernet
// examples.
const psEthGroup = "opc.eth://01-00-5e-00-00-01"

func requireEthInterop(t *testing.T) {
	t.Helper()
	skip := func(format string, args ...any) {
		t.Helper()
		if os.Getenv("GO_OPCUA_ETH_REQUIRE") != "" {
			t.Fatalf(format, args...)
		}
		t.Skipf(format, args...)
	}
	if runtime.GOOS != "linux" {
		skip("raw Ethernet between the host and a container needs a Linux Docker host")
	}
	if os.Geteuid() != 0 {
		skip("raw Ethernet sockets need root")
	}
}

// ethNetwork creates a Docker bridge network whose bridge interface is named
// after the test and returns the network and the interface name.
func ethNetwork(t *testing.T) (network, bridge string) {
	t.Helper()
	bridge = fmt.Sprintf("uaeth%d", testport.UDP(t)%100000) // at most 15 bytes
	network = strings.ToLower(dockerContainerName(t)) + "-eth"
	out, err := exec.Command("docker", "network", "create",
		"-o", "com.docker.network.bridge.name="+bridge, network).CombinedOutput()
	if err != nil {
		t.Fatalf("docker network create: %v\n%s", err, out)
	}
	t.Cleanup(func() { exec.Command("docker", "network", "rm", network).Run() }) //nolint:errcheck
	return network, bridge
}

// psEthAddress sets the address of the first connection of an adapter
// configuration to url on the container's eth0.
func psEthAddress(cfg jobj, url string) jobj {
	conn := cfg["configuration"].(jobj)["Connections"].([]jobj)[0]
	conn["Address"] = eo("i=15510", jobj{"NetworkInterface": "eth0", "Url": url})
	return cfg
}

// psEthCases are the unsecured and the SignAndEncrypt (Aes256-CTR) case of
// the UDP tests.
func psEthCases() []psRuntimeCase {
	var out []psRuntimeCase
	for _, c := range psUDPCases() {
		if c.name == "variant" || c.name == "sign-and-encrypt-aes256-ctr" {
			out = append(out, psRuntimeCase{psLiveCase: c})
		}
	}
	return out
}

// psKeyOptions passes the static keys of a secured case to the runtime.
func psKeyOptions(t *testing.T, c psRuntimeCase) []pubsub.Option {
	t.Helper()
	if keys := c.keys(t); keys != nil {
		return []pubsub.Option{pubsub.WithKeySource("InteropGroup", keys)}
	}
	return nil
}

// TestPubSubEth_GoPublishes_Open62541Subscribes: a go-opcua server publishes
// its PubSub.* variables in Ethernet frames to a multicast MAC address; the
// open62541 subscriber receives them on its eth0 and writes them into its
// TargetVariables.
func TestPubSubEth_GoPublishes_Open62541Subscribes(t *testing.T) {
	requirePubSubServer(t)
	requireEthInterop(t)
	network, bridge := ethNetwork(t)
	for _, c := range psEthCases() {
		t.Run(c.name, func(t *testing.T) {
			sub := startPubSubServer(t, pubsubServerOpts{network: network, root: true,
				config: psEthAddress(psSubscriberConfig(c.psLiveCase, psProfileEth, psEthGroup, nil, false), psEthGroup)})
			pub := startGoPubSubServer(t, goPubSubOpts{pubsubOpts: psKeyOptions(t, c)}, func(p *pubsub.PubSub, ns uint16) {
				mustOK[pubsub.ComponentID](t)(p.AddPublishedDataSet(psRuntimeDataSet(c.vars, ns, c.maxStrLn)))
				w := pubsub.DataSetWriter("InteropWriter", psWriterID, "InteropDataSet")
				wg := pubsub.WriterGroup("InteropWriterGroup", psWriterGroupID, 100*time.Millisecond, w)
				if c.mode > ua.MessageSecurityModeNone {
					wg = pubsub.Secure(wg, c.mode, "InteropGroup")
				}
				mustOK[pubsub.ComponentID](t)(p.AddConnection(pubsub.AttachWriterGroups(
					pubsub.EthernetConnection("InteropPublisher", psEthGroup, bridge, uint16(psPubID)), wg)))
			})
			values := psValues(c.vars, psFresh())
			writePubSubVars(t, pub.endpoint, c.vars, values)
			waitPubSubVars(t, sub.endpoint, c.vars, values, psReceiveTimeout)
		})
	}
}

// TestPubSubEth_Open62541Publishes_GoSubscribes: the open62541 publisher
// sends UADP in Ethernet frames to a multicast MAC address from its eth0;
// the go-opcua runtime joins the group on the bridge interface.
func TestPubSubEth_Open62541Publishes_GoSubscribes(t *testing.T) {
	requirePubSubServer(t)
	requireEthInterop(t)
	network, bridge := ethNetwork(t)
	for _, c := range psEthCases() {
		t.Run(c.name, func(t *testing.T) {
			rec := newPSDataSets()
			startRuntime(t, pubsub.NewConfiguration(nil, pubsub.AttachReaderGroups(
				pubsub.EthernetConnection("InteropSubscriber", psEthGroup, bridge, nil), psRuntimeReader(c, "", 0))),
				append(psKeyOptions(t, c), pubsub.WithDataSetHandler(rec.handle))...)
			pub := startPubSubServer(t, pubsubServerOpts{network: network, root: true,
				config: psEthAddress(psPublisherConfig(c.psLiveCase, psProfileEth, psEthGroup, nil, false), psEthGroup)})

			values := psValues(c.vars, psFresh())
			writePubSubVars(t, pub.endpoint, c.vars, values)
			ds := rec.wait(t, c.vars, values, psReceiveTimeout)
			if ds.DataSetWriterID != psWriterID {
				t.Errorf("DataSet from writer %d", ds.DataSetWriterID)
			}
		})
	}
}
