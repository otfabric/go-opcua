//go:build interop

// SPDX-License-Identifier: MIT

// PubSub (Part 14) against UA-.NETStandard 2.0.1 (Opc.Ua.PubSub): the
// opcua-interop dotnet adapter as publisher and subscriber (server
// --pubsub-config), its codec pubsub-* operations and its UADP discovery
// (client pubsub-discover); opcua-interop docs/CLIENT_CONTRACT.md §14.13.
// Ledger: testdata/ledger-dotnet.json, profile pubsub.
//
// The transport, codec and runtime tests are those of open62541
// (pubsub_*_peer_test.go) run with the dotnet peer. Chunked NetworkMessages
// and discovery, which open62541 1.5.9 does not implement, are here:
//
//   - chunks: the dotnet publisher's WriterGroup has a MaxNetworkMessageSize
//     far below its NetworkMessages, go-opcua reassembles the chunks
//     (uadp.Reassembler); go-opcua sends uadp.EncodeChunks to the dotnet
//     subscriber, which reassembles them into its TargetVariables. Both
//     unsecured and SignAndEncrypt (every chunk secured on its own).
//   - discovery (the .NET byte layout, message.DiscoveryLayoutDotNet):
//     go-opcua probes the dotnet publisher from a UDP socket and decodes the
//     announcements; the dotnet client probes a go-opcua server with
//     WithPubSub, whose runtime answers.
//
// Networking as in pubsub_helpers_test.go. The dotnet adapter has PubSub
// since opcua-interop v0.10.0.

package interop

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/pubsub/uadp"
	"github.com/otfabric/go-opcua/ua"
)

// psDotnet is the dotnet adapter as PubSub peer.
var psDotnet = &psPeer{name: "dotnet", env: dotnetEnv, image: defaultDotnetImage, mqttVersionMember: true,
	// Opc.Ua.PubSub.Mqtt sets the MQTT 5 ContentType on every publication,
	// which MQTTnet refuses on a 3.1.1 connection (contract §14.13).
	mqtt5Publisher: true,
	byteDivergences: map[string]string{
		// UadpEncoder writes "" as a zero-length String (0c 00000000),
		// go-opcua as the null String (0c ffffffff); a null String it
		// decodes stays null on re-encoding.
		"empty-string": "go-opcua encodes the empty String as the null String (length -1), Opc.Ua.PubSub as a zero-length String",
	},
	codecUnsupported: map[string]string{
		// go-opcua 51 01 01 01 00 00 01 00 06 1b000000 (DataSetFlags1 0x00,
		// MessageIsValid clear) is decoded to no DataSetMessage at all and
		// re-encoded as 51 01 00 (Part 14 §7.2.4.5.4: the content of an
		// invalid DataSetMessage is to be ignored); UadpEncoder always sets
		// MessageIsValid, so the adapter refuses valid=false (BadNotImplemented).
		"dataset-message-invalid": "Opc.Ua.PubSub drops a DataSetMessage without MessageIsValid when decoding and cannot encode one (contract §14.13)",
	},
}

// ---------------------------------------------------------------------------
// Codec
// ---------------------------------------------------------------------------

// TestPubSubCodec_GoEncodesUADP_DotnetDecodes: go-opcua encodes the UADP
// matrix, Opc.Ua.PubSub's UadpDecoder decodes it and UadpEncoder re-encodes
// it byte for byte.
func TestPubSubCodec_GoEncodesUADP_DotnetDecodes(t *testing.T) {
	psDotnet.requireCodec(t)
	psGoEncodesUADP(t, psDotnet)
}

// TestPubSubCodec_DotnetEncodesUADP_GoDecodes: UadpEncoder encodes the
// descriptions of the matrix; the bytes must be go-opcua's encoding.
func TestPubSubCodec_DotnetEncodesUADP_GoDecodes(t *testing.T) {
	psDotnet.requireCodec(t)
	psPeerEncodesUADP(t, psDotnet)
}

// TestPubSubCodec_GoEncodesJSON_DotnetDecodes: go-opcua's JSON
// NetworkMessages decoded by Opc.Ua.PubSub's JsonDecoder.
func TestPubSubCodec_GoEncodesJSON_DotnetDecodes(t *testing.T) {
	psDotnet.requireCodec(t)
	psGoEncodesJSON(t, psDotnet)
}

// TestPubSubCodec_DotnetEncodesJSON_GoDecodes: Opc.Ua.PubSub's JsonEncoder
// output decoded by go-opcua.
func TestPubSubCodec_DotnetEncodesJSON_GoDecodes(t *testing.T) {
	psDotnet.requireCodec(t)
	psPeerEncodesJSON(t, psDotnet)
}

// ---------------------------------------------------------------------------
// UDP, MQTT, security, runtime
// ---------------------------------------------------------------------------

// TestPubSubUDP_DotnetPublishes_GoReceives: the dotnet publisher sends UADP
// over UDP unicast (Variant, DataValue, RawData, Sign, SignAndEncrypt);
// go-opcua decodes, verifies and decrypts.
func TestPubSubUDP_DotnetPublishes_GoReceives(t *testing.T) {
	psPeerPublishesUDP(t, psDotnet)
}

// TestPubSubUDP_GoPublishes_DotnetSubscribes: go-opcua sends UADP over UDP
// unicast; the dotnet subscriber writes its TargetVariables.
func TestPubSubUDP_GoPublishes_DotnetSubscribes(t *testing.T) {
	psGoPublishesUDP(t, psDotnet)
}

// TestPubSubUDP_DotnetSubscriber_RejectsInsecure: a SignAndEncrypt dotnet
// reader group drops unsecured go-opcua messages and those under another key.
func TestPubSubUDP_DotnetSubscriber_RejectsInsecure(t *testing.T) {
	psPeerSubscriberRejectsInsecure(t, psDotnet)
}

// TestPubSubMQTT_DotnetPublishes_GoReceives: the dotnet publisher (MQTT
// 3.1.1, mqtt.protocolVersion) sends UADP and JSON through Mosquitto.
func TestPubSubMQTT_DotnetPublishes_GoReceives(t *testing.T) {
	psPeerPublishesMQTT(t, psDotnet)
}

// TestPubSubMQTT_GoPublishes_DotnetSubscribes: go-opcua publishes UADP and
// JSON through Mosquitto; the dotnet subscriber (MQTT 3.1.1) writes its
// TargetVariables.
func TestPubSubMQTT_GoPublishes_DotnetSubscribes(t *testing.T) {
	psGoPublishesMQTT(t, psDotnet)
}

// TestPubSubMQTT5_GoPublishes_DotnetSubscribes: go-opcua publishes over MQTT
// 5.0 with QoS 2; the dotnet subscriber speaks MQTT 5.0 (its default).
func TestPubSubMQTT5_GoPublishes_DotnetSubscribes(t *testing.T) {
	psMQTT5GoPublishes(t, psDotnet)
}

// TestPubSubMQTT5_DotnetPublishes_GoSubscribes: the dotnet publisher speaks
// MQTT 5.0; a go-opcua runtime subscribed over MQTT 5.0 receives the DataSets.
func TestPubSubMQTT5_DotnetPublishes_GoSubscribes(t *testing.T) {
	psMQTT5PeerPublishes(t, psDotnet)
}

// TestPubSubRuntime_GoPublishes_DotnetSubscribes: a go-opcua server with
// WithPubSub publishes over UDP and MQTT; the dotnet subscriber writes its
// TargetVariables.
func TestPubSubRuntime_GoPublishes_DotnetSubscribes(t *testing.T) {
	psRuntimeGoPublishes(t, psDotnet)
}

// TestPubSubRuntime_DotnetPublishes_GoSubscribes: a go-opcua runtime
// receives the DataSets of the dotnet publisher.
func TestPubSubRuntime_DotnetPublishes_GoSubscribes(t *testing.T) {
	psRuntimePeerPublishes(t, psDotnet)
}

// TestPubSubRuntime_DotnetPublishes_GoTargetVariables: a go-opcua server
// with WithPubSub writes the DataSet of the dotnet publisher into its
// PubSub.* variables (TargetVariables).
func TestPubSubRuntime_DotnetPublishes_GoTargetVariables(t *testing.T) {
	psRuntimePeerPublishesTargetVariables(t, psDotnet)
}

// TestPubSubMulticast_DotnetPublishes_GoSubscribes: the dotnet publisher
// sends UADP to a multicast group, the go-opcua runtime joins it. Host
// networking (Linux only), see pubsub_multicast_peer_test.go.
//
// UA-.NETStandard 2.0.1 turns IP_MULTICAST_LOOP off by default
// (UdpTransportOptions.MulticastLoopback), so its multicast does not reach a
// subscriber on the same host; the adapter turns it on from opcua-interop
// v0.15.0 (serverFeatures "pubsub-multicast-loopback").
func TestPubSubMulticast_DotnetPublishes_GoSubscribes(t *testing.T) {
	psDotnet.requireServer(t)
	requireHostNetwork(t)
	requireAdapterFeature(t, psDotnet.env, psDotnet.image, "serverFeatures", "pubsub-multicast-loopback")
	psMulticastPeerPublishes(t, psDotnet)
}

// TestPubSubMulticast_GoPublishes_DotnetSubscribes: a go-opcua server
// publishes to a multicast group; the dotnet subscriber joins it and writes
// its TargetVariables. Host networking (Linux only).
func TestPubSubMulticast_GoPublishes_DotnetSubscribes(t *testing.T) {
	psMulticastGoPublishes(t, psDotnet)
}

// ---------------------------------------------------------------------------
// Keep-alive and MessageReceiveTimeout
// ---------------------------------------------------------------------------

// psDotnetRuntimeReader starts a go-opcua runtime whose reader of the dotnet
// writer has MessageReceiveTimeout 1 s and the dotnet publisher of cfg (a
// psUDPPublisherConfig to the runtime's port, adjusted by edit), and returns
// the publisher, the runtime and its reader.
func psDotnetRuntimeReader(t *testing.T, edit func(cfg jobj)) (*pubsubServer, *pubsub.PubSub, pubsub.ComponentID) {
	t.Helper()
	psDotnet.requireServer(t)
	c := psRuntimeCase{psLiveCase: psLiveCase{name: "runtime-reader", vars: psVars}}
	var p *pubsub.PubSub
	port := psBindRuntimeUDP(t, psRuntimeSubscriber(t, func(url string) *ua.PubSubConfigurationDataType {
		return pubsub.NewConfiguration(nil, pubsub.AttachReaderGroups(psRuntimeSubConnection(c, url), psRuntimeReader(c, "", time.Second)))
	}, &p))
	cfg := psUDPPublisherConfig(c.psLiveCase, port)
	edit(cfg)
	pub := startPubSubServer(t, pubsubServerOpts{peer: psDotnet, config: cfg})
	conn, _ := p.Lookup(pubsub.KindConnection, pubsub.Root, "InteropSubscriber")
	rg, _ := p.Lookup(pubsub.KindReaderGroup, conn, "InteropReaderGroup")
	reader, ok := p.Lookup(pubsub.KindDataSetReader, rg, "InteropReader")
	if !ok {
		t.Fatal("no reader")
	}
	return pub, p, reader
}

// TestPubSubRuntime_KeepAlive_DotnetPublishes: the dotnet WriterGroup
// (PublishingInterval 100 ms, KeepAliveTime 300 ms) has a writer with
// DeltaFrames ("deltaFrames": true, KeyFrameCount 1000, contract §14.13)
// over the unchanging PubSub.* variables: after its first KeyFrame
// Opc.Ua.PubSub builds no DataSetMessage (an empty delta) and sends a
// KeepAlive DataSetMessage once nothing was sent for KeepAliveTime
// (Groups/WriterGroup.cs). The go-opcua reader (MessageReceiveTimeout 1 s)
// counts them, receives no data meanwhile and stays Operational: the
// keep-alive messages refresh its MessageReceiveTimeout.
func TestPubSubRuntime_KeepAlive_DotnetPublishes(t *testing.T) {
	_, p, reader := psDotnetRuntimeReader(t, func(cfg jobj) {
		cfg["deltaFrames"] = true
		wg := psWriterGroupJSON(cfg)
		wg["KeepAliveTime"] = 300
		wg["DataSetWriters"].([]jobj)[0]["KeyFrameCount"] = 1000
	})
	status := func() pubsub.Status { return mustOK[pubsub.Status](t)(p.Status(reader)) }
	state := func() ua.PubSubState { return mustOK[ua.PubSubState](t)(p.State(reader)) }

	// The first KeyFrame, then keep-alive messages only.
	deadline := time.Now().Add(psReceiveTimeout)
	for st := status(); st.Counters.DataSetMessagesReceived == 0 || st.Counters.KeepAlivesReceived == 0; st = status() {
		if time.Now().After(deadline) {
			t.Fatalf("no KeyFrame followed by keep-alive messages within %v: %+v", psReceiveTimeout, st.Counters)
		}
		time.Sleep(100 * time.Millisecond)
	}
	waitState(t, "go-opcua reader receiving keep-alive messages", ua.PubSubStateOperational, 5*time.Second, state)
	before := status().Counters

	// Eight keep-alive periods (2.4 s, more than twice the
	// MessageReceiveTimeout) with keep-alive messages only.
	deadline = time.Now().Add(15 * time.Second)
	for status().Counters.KeepAlivesReceived < before.KeepAlivesReceived+8 {
		if time.Now().After(deadline) {
			t.Fatalf("keep-alive messages stopped: %+v, before %+v", status().Counters, before)
		}
		time.Sleep(100 * time.Millisecond)
	}
	after := status().Counters
	if after.DataSetMessagesReceived != before.DataSetMessagesReceived {
		t.Errorf("%d data DataSetMessages between the keep-alive messages, want none", after.DataSetMessagesReceived-before.DataSetMessagesReceived)
	}
	// (A timeout before the publisher started is not one of them.)
	if after.Timeouts != before.Timeouts {
		t.Errorf("the reader timed out %d times while keep-alive messages arrived", after.Timeouts-before.Timeouts)
	}
	if got := state(); got != ua.PubSubStateOperational {
		t.Errorf("go-opcua reader on keep-alive messages: %v, want Operational", got)
	}
}

// TestPubSubRuntime_ReceiveTimeout_DotnetPublisher: the go-opcua reader
// (MessageReceiveTimeout 1 s) is Operational while the dotnet publisher
// sends KeyFrames every 100 ms, goes to Error when the publisher's container
// is paused (docker pause: the dotnet adapter has no PublishSubscribe
// information model to disable its WriterGroup through, contract §14.13) and
// recovers when it is unpaused.
func TestPubSubRuntime_ReceiveTimeout_DotnetPublisher(t *testing.T) {
	pub, p, reader := psDotnetRuntimeReader(t, func(jobj) {})
	state := func() ua.PubSubState { return mustOK[ua.PubSubState](t)(p.State(reader)) }
	waitState(t, "go-opcua reader while data arrives", ua.PubSubStateOperational, psReceiveTimeout, state)

	if out, err := exec.Command("docker", "pause", pub.name).CombinedOutput(); err != nil {
		t.Fatalf("docker pause: %v: %s", err, out)
	}
	paused := true
	unpause := func() {
		if paused {
			paused = false
			if out, err := exec.Command("docker", "unpause", pub.name).CombinedOutput(); err != nil {
				t.Errorf("docker unpause: %v: %s", err, out)
			}
		}
	}
	t.Cleanup(unpause)
	waitState(t, "go-opcua reader after the publisher stopped", ua.PubSubStateError, 10*time.Second, state)
	if st, err := p.Status(reader); err != nil || st.Counters.Timeouts == 0 {
		t.Errorf("reader status %+v (%v): no timeout counted", st, err)
	}

	unpause()
	waitState(t, "go-opcua reader after the publisher resumed", ua.PubSubStateOperational, 10*time.Second, state)
}

// ---------------------------------------------------------------------------
// Chunked NetworkMessages (Part 14 §7.2.4.4.4)
// ---------------------------------------------------------------------------

// psChunkSize is the MaxNetworkMessageSize of the chunk tests of case c:
// the NetworkMessage of psVars is about 160 bytes unsecured, 210 secured,
// and a chunk secured with PubSub-Aes256-CTR has 80 bytes of headers and
// signature.
func psChunkSize(c psLiveCase) int {
	if c.mode > ua.MessageSecurityModeNone {
		return 128
	}
	return 80
}

// psChunkCases are the security modes of the chunk tests.
func psChunkCases() []psLiveCase {
	return []psLiveCase{
		{name: "variant", vars: psVars},
		{name: "sign-and-encrypt-aes256-ctr", mode: ua.MessageSecurityModeSignAndEncrypt, policy: security.Aes256CTR(), key: psStaticKey256, tokenID: 1, vars: psVars},
	}
}

// psWriterGroupJSON returns the first WriterGroup of a configuration document.
func psWriterGroupJSON(cfg jobj) jobj {
	return cfg["configuration"].(jobj)["Connections"].([]jobj)[0]["WriterGroups"].([]jobj)[0]
}

// TestPubSubChunk_DotnetPublishes_GoReassembles: the dotnet WriterGroup has
// MaxNetworkMessageSize psChunkSize(c); every datagram must fit, at least two chunks
// make up a message, and go-opcua reassembles them to the DataSet.
func TestPubSubChunk_DotnetPublishes_GoReassembles(t *testing.T) {
	for _, c := range psChunkCases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			size := psChunkSize(c)
			port, ch := psListenUDP(t)
			cfg := psUDPPublisherConfig(c, port)
			psWriterGroupJSON(cfg)["MaxNetworkMessageSize"] = size
			pub := startPubSubServer(t, pubsubServerOpts{peer: psDotnet, config: cfg})
			values := psValues(c.vars, psFresh())
			writePubSubVars(t, pub.endpoint, c.vars, values)

			keys := c.keys(t)
			md := psLookup(psMetaData(c.vars, 0))
			opts := &uadp.DecodeOptions{MetaData: md, Security: func(*message.NetworkMessage) (ua.MessageSecurityMode, security.KeySource, error) {
				if keys == nil {
					return ua.MessageSecurityModeNone, nil, nil
				}
				return c.mode, keys, nil
			}}
			r := uadp.NewReassembler(nil)
			chunks := map[uint16]int{} // chunks per MessageSequenceNumber
			nm := psReceive(t, ch, func(b []byte) (*message.NetworkMessage, error) {
				if tp, _, err := uadp.PeekType(b); err == nil && tp != message.NetworkMessageDataSet {
					// A discovery announcement (the DataSetMetaData the
					// publisher sends on start): only DataSetMessages are
					// chunked (Part 14 §7.2.4.4.4).
					return &message.NetworkMessage{}, nil
				}
				if len(b) > size {
					t.Errorf("a datagram of %d bytes, MaxNetworkMessageSize is %d", len(b), size)
				}
				m, err := uadp.Decode(b, opts)
				if err != nil {
					return nil, err
				}
				if m.Chunk == nil {
					return nil, fmt.Errorf("a NetworkMessage of %d bytes that is not a chunk", len(b))
				}
				if (m.Security != nil) != (c.mode > ua.MessageSecurityModeNone) {
					return nil, fmt.Errorf("chunk security header %+v, mode %v", m.Security, c.mode)
				}
				chunks[m.Chunk.MessageSequenceNumber]++
				payload, _, err := r.Add(m, time.Now())
				if err != nil {
					return nil, err
				}
				if payload == nil {
					return &message.NetworkMessage{}, nil // incomplete: no DataSetMessage yet
				}
				full, err := uadp.DecodeReassembled(m, payload, opts)
				if err != nil {
					return nil, err
				}
				if n := chunks[m.Chunk.MessageSequenceNumber]; n < 2 {
					return nil, fmt.Errorf("a message of %d chunk(s)", n)
				}
				return full, nil
			}, values, psReceiveTimeout)
			assertPublisherHeaders(t, c, nm)
		})
	}
}

// TestPubSubChunk_GoPublishes_DotnetReassembles: go-opcua sends every
// NetworkMessage as chunks of at most psChunkSize(c) bytes (uadp.EncodeChunks); the
// dotnet subscriber reassembles them into its TargetVariables.
func TestPubSubChunk_GoPublishes_DotnetReassembles(t *testing.T) {
	psDotnet.requireServer(t)
	for _, c := range psChunkCases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			size := psChunkSize(c)
			port := freeUDPPort(t)
			sub := startPubSubServer(t, pubsubServerOpts{peer: psDotnet,
				config:   psSubscriberConfig(c, psProfileUDP, fmt.Sprintf("opc.udp://0.0.0.0:%d", port), nil, false),
				udpPorts: []int{port},
			})
			values := psValues(c.vars, psFresh())
			conn := psDial(t, transport.Config{ProfileURI: psProfileUDP, URL: fmt.Sprintf("opc.udp://127.0.0.1:%d", sub.udpPort(t, port))})
			keys := c.keys(t)
			md := psLookup(psMetaData(c.vars, 0))
			if b, err := uadp.Encode(psGoMessage(c, 1, values), &uadp.EncodeOptions{SecurityMode: c.mode, Keys: keys, MetaData: md}); err != nil {
				t.Fatalf("uadp.Encode: %v", err)
			} else if len(b) <= size {
				t.Fatalf("the NetworkMessage has %d bytes: too small to be chunked at %d", len(b), size)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			t.Cleanup(func() { cancel(); <-done })
			go func() {
				defer close(done)
				seq, nonce := uint16(1), uint32(1)
				for {
					// The DataSetMessage sequence number (the chunks'
					// MessageSequenceNumber) advances by one per message,
					// the GroupHeader SequenceNumber per chunk.
					nm := psGoMessage(c, seq, values)
					nm.Messages[0].SequenceNumber = uint32(seq)
					chunks, err := uadp.EncodeChunks(nm, &uadp.EncodeOptions{SecurityMode: c.mode, Keys: keys, NonceSequence: nonce, MetaData: md}, size)
					if err != nil {
						t.Errorf("uadp.EncodeChunks: %v", err)
						return
					}
					for _, b := range chunks {
						if len(b) > size {
							t.Errorf("a chunk of %d bytes", len(b))
						}
						_ = conn.Send(ctx, b, transport.PublishOptions{})
					}
					seq += uint16(len(chunks))
					nonce += uint32(len(chunks))
					select {
					case <-ctx.Done():
						return
					case <-time.After(100 * time.Millisecond):
					}
				}
			}()
			waitPubSubVars(t, sub.endpoint, c.vars, values, psReceiveTimeout)
		})
	}
}

// ---------------------------------------------------------------------------
// Discovery (Part 14 §7.2.4.6, the .NET layout)
// ---------------------------------------------------------------------------

// TestPubSubDiscovery_GoProbes_DotnetAnswers: go-opcua sends DataSetMetaData
// and DataSetWriterConfiguration probes in the .NET layout to the dotnet
// publisher's connection (opc.udp://0.0.0.0:<port>) and decodes the
// announcements it answers with.
func TestPubSubDiscovery_GoProbes_DotnetAnswers(t *testing.T) {
	psDotnet.requireServer(t)
	c := psLiveCase{name: "discovery", vars: psVars}
	port := freeUDPPort(t)
	pub := startPubSubServer(t, pubsubServerOpts{peer: psDotnet, udpPorts: []int{port},
		config: psPublisherConfig(c, psProfileUDP, fmt.Sprintf("opc.udp://0.0.0.0:%d", port), nil, false)})

	sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sock.Close() })
	dest := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: pub.udpPort(t, port)}

	// probe sends req until an announcement of want arrives.
	probe := func(req *message.DiscoveryRequest, want message.DiscoveryType) *message.Discovery {
		t.Helper()
		b, err := uadp.Encode(&message.NetworkMessage{Type: message.NetworkMessageDiscoveryRequest, Request: req}, nil)
		if err != nil {
			t.Fatalf("encode the probe: %v", err)
		}
		deadline := time.Now().Add(psReceiveTimeout)
		buf := make([]byte, 65536)
		var seen []string
		for time.Now().Before(deadline) {
			if _, err := sock.WriteToUDP(b, dest); err != nil {
				t.Fatalf("send the probe: %v", err)
			}
			_ = sock.SetReadDeadline(time.Now().Add(time.Second))
			for {
				n, _, err := sock.ReadFromUDP(buf)
				if err != nil {
					break // time to probe again
				}
				tp, chunk, err := uadp.PeekType(buf[:n])
				if err != nil || chunk || tp != message.NetworkMessageDiscoveryResponse {
					continue // a DataSetMessage: the publisher sends to its last peer
				}
				nm, err := uadp.Decode(buf[:n], nil)
				if err != nil {
					t.Fatalf("decode the announcement %x: %v", buf[:n], err)
				}
				d := nm.Discovery
				seen = append(seen, fmt.Sprintf("%v (layout %d)", d.Type, d.Layout))
				if d.Type != want {
					continue
				}
				if d.Layout != message.DiscoveryLayoutDotNet {
					t.Errorf("announcement layout %d, want the .NET layout", d.Layout)
				}
				if !nm.PublisherID.Equal(message.NewPublisherID(message.PublisherIDUInt16, psPubID)) {
					t.Errorf("announcement PublisherId %v (%v), want UInt16 %d", nm.PublisherID, nm.PublisherID.Type, psPubID)
				}
				return d
			}
		}
		t.Fatalf("no %v announcement within %v (announcements seen: %v)", want, psReceiveTimeout, seen)
		return nil
	}

	t.Run("dataset-metadata", func(t *testing.T) {
		d := probe(&message.DiscoveryRequest{ProbeType: message.ProbePublisherInformation, InformationType: message.InformationDataSetMetaData,
			DataSetWriterIDs: []uint16{psWriterID}, Layout: message.DiscoveryLayoutDotNet}, message.DiscoveryDataSetMetaData)
		if d.DataSetWriterID != psWriterID || d.StatusCode != ua.StatusOK || d.MetaData == nil {
			t.Fatalf("DataSetMetaData announcement: writer %d status %v metadata %v", d.DataSetWriterID, d.StatusCode, d.MetaData)
		}
		if d.MetaData.Name != "InteropDataSet" || len(d.MetaData.Fields) != len(psVars) {
			t.Fatalf("DataSetMetaData %q with %d fields, want InteropDataSet with %d", d.MetaData.Name, len(d.MetaData.Fields), len(psVars))
		}
		for i, v := range psVars {
			f := d.MetaData.Fields[i]
			if f.Name != v.name || uint32(f.BuiltInType) != v.typ || f.ValueRank != v.rank {
				t.Errorf("field %d: %s BuiltInType %d ValueRank %d, want %s %d %d", i, f.Name, f.BuiltInType, f.ValueRank, v.name, v.typ, v.rank)
			}
		}
	})
	t.Run("dataset-writer-configuration", func(t *testing.T) {
		d := probe(&message.DiscoveryRequest{ProbeType: message.ProbePublisherInformation, InformationType: message.InformationDataSetWriterConfig,
			DataSetWriterIDs: []uint16{psWriterID}, Layout: message.DiscoveryLayoutDotNet}, message.DiscoveryDataSetWriterConfig)
		g := d.WriterGroup
		if g == nil || g.WriterGroupID != psWriterGroupID || len(g.DataSetWriters) != 1 || g.DataSetWriters[0].DataSetWriterID != psWriterID {
			t.Fatalf("DataSetWriter configuration announcement: %+v", g)
		}
		if g.DataSetWriters[0].DataSetName != "InteropDataSet" || !slices.Equal(d.DataSetWriterIDs, []uint16{psWriterID}) {
			t.Errorf("writer %q, DataSetWriterIds %v", g.DataSetWriters[0].DataSetName, d.DataSetWriterIDs)
		}
		for i, sc := range d.StatusCodes {
			if sc != ua.StatusOK {
				t.Errorf("StatusCodes[%d] = %v", i, sc)
			}
		}
	})
}

// psDiscoverResult is the result of client pubsub-discover.
type psDiscoverResult struct {
	DataSetMetaData []struct {
		PublisherID     psPublisherID `json:"publisherId"`
		DataSetWriterID uint16        `json:"dataSetWriterId"`
		StatusCode      statusCodeObj `json:"statusCode"`
		MetaData        *struct {
			Name   string `json:"name"`
			Fields []struct {
				Name        string `json:"name"`
				BuiltInType uint32 `json:"builtInType"`
				ValueRank   int32  `json:"valueRank"`
			} `json:"fields"`
		} `json:"metaData"`
	} `json:"dataSetMetaData"`
	WriterConfigurations []struct {
		PublisherID      psPublisherID `json:"publisherId"`
		DataSetWriterIDs []uint16      `json:"dataSetWriterIds"`
		WriterGroup      *struct {
			Name           string `json:"name"`
			WriterGroupID  uint16 `json:"writerGroupId"`
			DataSetWriters []struct {
				Name            string `json:"name"`
				DataSetWriterID uint16 `json:"dataSetWriterId"`
				DataSetName     string `json:"dataSetName"`
			} `json:"dataSetWriters"`
		} `json:"writerGroup"`
	} `json:"writerConfigurations"`
}

// runDotnetDiscover runs client pubsub-discover (container name: name) with
// the container port probePort published on the host port hostPort: the
// probe goes to host.docker.internal:probePort, the answers come back to
// hostPort. ok is false when no announcement arrived within the client's
// --timeout-ms (BadTimeout); taken is true when Docker could not publish
// hostPort.
func runDotnetDiscover(t *testing.T, name string, probePort, hostPort int, args ...string) (r psDiscoverResult, ok, taken bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), clientTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", append([]string{"run", "--rm", "--name", name,
		"--add-host=host.docker.internal:host-gateway", "-p", fmt.Sprintf("%d:%d/udp", hostPort, probePort),
		getEnvOr(psDotnet.env, psDotnet.image), "client", "pubsub-discover",
		"--url", fmt.Sprintf("opc.udp://host.docker.internal:%d", probePort)}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = io.MultiWriter(os.Stderr, &stderr)
	raw, _ := cmd.Output()
	if ctx.Err() != nil {
		dockerStop(name) // the CLI was killed, the container may still run
	}
	if dockerPortTaken(stderr.String()) {
		return r, false, true
	}
	res, err := parseAdapterOutput(raw)
	if err != nil {
		t.Fatalf("pubsub-discover: %v\nraw: %s", err, raw)
	}
	if !res.Success {
		if statusCodeIs(res.ServiceResult, ua.StatusBadTimeout) {
			return r, false, false
		}
		t.Fatalf("pubsub-discover %v failed: %s %s", args, res.ServiceResult, res.Error)
	}
	var items []psDiscoverResult
	if err := json.Unmarshal(res.Results, &items); err != nil || len(items) != 1 {
		t.Fatalf("pubsub-discover results: %v\n%s", err, res.Results)
	}
	return items[0], true, false
}

// psDiscoveryAttempts bounds the probes of dotnetDiscover.
const psDiscoveryAttempts = 3

// dotnetDiscover runs client pubsub-discover with args against a go-opcua
// publisher of its own (startGoDiscoveryPublisher) and returns the
// announcements.
//
// The client sends a single probe and waits --timeout-ms for answers; it has
// no option to repeat the probe. UDP may lose the probe or the answer, and a
// subscriber is to probe again when no announcement arrives (Part 14
// §7.2.4.6.12.2): so does this, up to psDiscoveryAttempts times. Every
// attempt has a new publisher on new ports, so no datagram flow of an
// earlier client container (Docker's conntrack or proxy state for
// 127.0.0.1:<host port>) carries over.
func dotnetDiscover(t *testing.T, args ...string) psDiscoverResult {
	t.Helper()
	var tried []string
	for attempt, run := 1, 1; attempt <= psDiscoveryAttempts; run++ {
		pub := startGoDiscoveryPublisher(t)
		r, ok, taken := runDotnetDiscover(t, fmt.Sprintf("%s-%d", dockerContainerName(t), run), pub.probePort, pub.hostPort, args...)
		st := mustOK[pubsub.Status](t)(pub.p.Status(pub.conn))
		pub.stop()
		if ok {
			return r
		}
		if taken {
			// The client never ran: not an attempt.
			if run >= 10 {
				t.Fatalf("Docker could not publish a UDP port in %d runs", run)
			}
			t.Logf("Docker could not publish UDP port %d: another one", pub.hostPort)
			continue
		}
		// The counters include the ping probes of startGoDiscoveryPublisher,
		// received and ignored: the client's probe arrived if more probes
		// were received than ignored.
		c := st.Counters
		tried = append(tried, fmt.Sprintf("attempt %d: probes received %d, ignored %d, announcements sent %d (last error %v)",
			attempt, c.DiscoveryRequestsReceived, c.DiscoveryRequestsIgnored, c.DiscoveryResponsesSent, st.LastError))
		t.Logf("pubsub-discover %v: no announcement (%s)", args, tried[len(tried)-1])
		attempt++
	}
	t.Fatalf("pubsub-discover %v: no announcement in %d attempts:\n%s", args, psDiscoveryAttempts, strings.Join(tried, "\n"))
	return psDiscoverResult{}
}

// goDiscoveryPublisher is a go-opcua server whose runtime publishes
// InteropDataSet to 127.0.0.1:hostPort and listens for probes on
// opc.udp://0.0.0.0:probePort (its DiscoveryAddress).
type goDiscoveryPublisher struct {
	hostPort, probePort int
	p                   *pubsub.PubSub
	conn                pubsub.ComponentID
	stop                func()
}

// startGoDiscoveryPublisher starts a goDiscoveryPublisher on new ports and
// returns it once its runtime receives probes on probePort, so that the
// client container is only started on a port the runtime holds. A probe for
// a DataSetWriter it does not have (psPingPublisherID) is counted and
// answered with nothing. When the runtime does not receive (the port was
// taken; the runtime only logs that) it is started again on other ports.
func startGoDiscoveryPublisher(t *testing.T) *goDiscoveryPublisher {
	t.Helper()
	ping, err := uadp.Encode(&message.NetworkMessage{Type: message.NetworkMessageDiscoveryRequest, Request: &message.DiscoveryRequest{
		ProbeType: message.ProbePublisherInformation, InformationType: message.InformationDataSetMetaData,
		DataSetWriterIDs: []uint16{psPingPublisherID}, Layout: message.DiscoveryLayoutDotNet}}, nil)
	if err != nil {
		t.Fatalf("encode the ping probe: %v", err)
	}
	snd, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = snd.Close() }()
	for range 10 {
		d := &goDiscoveryPublisher{hostPort: freeUDPPort(t), probePort: freeUDPPort(t)}
		srv := startGoPubSubServer(t, goPubSubOpts{}, func(p *pubsub.PubSub, ns uint16) {
			mustOK[pubsub.ComponentID](t)(p.AddPublishedDataSet(psRuntimeDataSet(psVars, ns, 0)))
			conn := pubsub.UDPConnection("InteropPublisher", fmt.Sprintf("opc.udp://127.0.0.1:%d", d.hostPort), uint16(psPubID))
			conn.TransportSettings = ua.NewExtensionObject(&ua.DatagramConnectionTransport2DataType{
				DiscoveryAddress: ua.NewExtensionObject(&ua.NetworkAddressURLDataType{URL: fmt.Sprintf("opc.udp://0.0.0.0:%d", d.probePort)}),
			})
			wg := pubsub.WriterGroup("InteropWriterGroup", psWriterGroupID, time.Second,
				pubsub.DataSetWriter("InteropWriter", psWriterID, "InteropDataSet"))
			d.conn = mustOK[pubsub.ComponentID](t)(p.AddConnection(pubsub.AttachWriterGroups(conn, wg)))
		})
		d.p, d.stop = srv.srv.PubSub(), srv.close
		dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: d.probePort}
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if st := mustOK[pubsub.Status](t)(d.p.Status(d.conn)); st.Counters.DiscoveryRequestsReceived > 0 {
				return d
			}
			_, _ = snd.WriteToUDP(ping, dst)
			time.Sleep(100 * time.Millisecond)
		}
		t.Logf("the go-opcua runtime does not receive probes on UDP port %d: other ports", d.probePort)
		d.stop()
	}
	t.Fatal("no UDP port the go-opcua runtime could receive probes on")
	return nil
}

// TestPubSubDiscovery_DotnetProbes_GoAnswers: the dotnet client probes a
// go-opcua server with WithPubSub for DataSetMetaData and DataSetWriter
// configuration; the go-opcua runtime answers in the .NET layout.
//
// The go-opcua connection publishes to 127.0.0.1:<host port>, published to
// the container port the dotnet client listens on, and its DiscoveryAddress
// opc.udp://0.0.0.0:<probe port> receives the probes the client sends to
// host.docker.internal:<probe port>. The DataSetMetaData and DataSetWriter
// configuration announcements go to the connection address (§7.2.4.6.12).
//
// Each probe has a publisher and ports of its own (dotnetDiscover): with
// one publisher for both, the second client container was answered from
// the same socket to the same 127.0.0.1:<host port> as the first, removed
// one, and its answers were lost (CI, opcua-interop v0.14.0 images).
func TestPubSubDiscovery_DotnetProbes_GoAnswers(t *testing.T) {
	psDotnet.requireServer(t)
	requireAdapterOp(t, psDotnet.env, psDotnet.image, "pubsub-discover")

	t.Run("dataset-metadata", func(t *testing.T) {
		r := dotnetDiscover(t, "--type", "DataSetMetaData", "--writer-ids", fmt.Sprint(psWriterID), "--timeout-ms", "5000")
		if len(r.DataSetMetaData) == 0 {
			t.Fatalf("no DataSetMetaData announcement: %+v", r)
		}
		a := r.DataSetMetaData[0]
		if a.DataSetWriterID != psWriterID || a.StatusCode.Code != 0 || a.MetaData == nil || a.MetaData.Name != "InteropDataSet" {
			t.Fatalf("announcement %+v", a)
		}
		if a.PublisherID.Type != "UInt16" || string(a.PublisherID.Value) != fmt.Sprint(psPubID) {
			t.Errorf("PublisherId %s %s, want UInt16 %d", a.PublisherID.Type, a.PublisherID.Value, psPubID)
		}
		if len(a.MetaData.Fields) != len(psVars) {
			t.Fatalf("%d fields, want %d", len(a.MetaData.Fields), len(psVars))
		}
		for i, v := range psVars {
			f := a.MetaData.Fields[i]
			if f.Name != v.name || f.BuiltInType != v.typ || f.ValueRank != v.rank {
				t.Errorf("field %d: %+v, want %s %d %d", i, f, v.name, v.typ, v.rank)
			}
		}
	})
	t.Run("dataset-writer-configuration", func(t *testing.T) {
		r := dotnetDiscover(t, "--type", "DataSetWriterConfiguration", "--writer-ids", fmt.Sprint(psWriterID), "--timeout-ms", "5000")
		if len(r.WriterConfigurations) == 0 || r.WriterConfigurations[0].WriterGroup == nil {
			t.Fatalf("no DataSetWriter configuration announcement: %+v", r)
		}
		a := r.WriterConfigurations[0]
		g := a.WriterGroup
		if g.WriterGroupID != psWriterGroupID || g.Name != "InteropWriterGroup" || len(g.DataSetWriters) != 1 ||
			g.DataSetWriters[0].DataSetWriterID != psWriterID || g.DataSetWriters[0].DataSetName != "InteropDataSet" {
			t.Fatalf("WriterGroup %+v", *g)
		}
		if !slices.Equal(a.DataSetWriterIDs, []uint16{psWriterID}) {
			t.Errorf("DataSetWriterIds %v", a.DataSetWriterIDs)
		}
	})
}
