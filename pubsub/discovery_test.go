// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/pubsub/uadp"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// Runtime tests of the UADP chunks and discovery, with the real codec.

func testRing(t *testing.T) *security.KeyRing {
	t.Helper()
	policy := security.Aes256CTR()
	ring := security.NewKeyRing("sg", policy)
	key := make([]byte, policy.KeyLength())
	_, err := rand.Read(key)
	require.NoError(t, err)
	require.NoError(t, ring.SetKeys(policy.URI(), 1, [][]byte{key}, time.Hour, time.Hour))
	return ring
}

// withDiscoveryAddress sets the DatagramConnectionTransport2DataType of a
// connection.
func withDiscoveryAddress(c *ua.PubSubConnectionDataType, url string, announce, maxSize uint32) *ua.PubSubConnectionDataType {
	ts := &ua.DatagramConnectionTransport2DataType{DiscoveryAnnounceRate: announce, DiscoveryMaxMessageSize: maxSize}
	if url != "" {
		ts.DiscoveryAddress = ua.NewExtensionObject(&ua.NetworkAddressURLDataType{URL: url})
	}
	c.TransportSettings = ua.NewExtensionObject(ts)
	return c
}

func newRuntime(t *testing.T, cfg *ua.PubSubConfigurationDataType, opts ...Option) *PubSub {
	t.Helper()
	p, err := New(cfg, opts...)
	require.NoError(t, err)
	require.NoError(t, p.Start(context.Background()))
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func counters(t *testing.T, p *PubSub) Counters {
	t.Helper()
	st, err := p.Status(Root)
	require.NoError(t, err)
	return st.Counters
}

// waitValue waits for a complete DataSet with field b.
func waitValue(t *testing.T, rec *recorder, b string) {
	t.Helper()
	require.Eventually(t, func() bool {
		for _, d := range rec.dataSets() {
			if d.Complete && d.Field("b") != nil && d.Field("b").Value.Value() == b {
				return true
			}
		}
		return false
	}, 10*time.Second, 2*time.Millisecond)
}

func TestChunkedUDP(t *testing.T) {
	t.Parallel()
	for _, mode := range []ua.MessageSecurityMode{ua.MessageSecurityModeNone, ua.MessageSecurityModeSign, ua.MessageSecurityModeSignAndEncrypt} {
		t.Run(mode.String(), func(t *testing.T) {
			t.Parallel()
			ds, pds := e2eData(t)
			big := strings.Repeat("chunk", 2000)
			require.NoError(t, ds.Set(nodeB, big))
			url := fmt.Sprintf("opc.udp://127.0.0.1:%d", freeUDPPort(t))
			wg := WriterGroup("wg", 1, 20*time.Millisecond, DataSetWriter("w", 1, "pds"))
			wg.MaxNetworkMessageSize = 700
			rg := ReaderGroup("rg", DataSetReader("r", uint16(5), 1, 1, DataSetMetaDataOf(pds)))
			if mode > ua.MessageSecurityModeNone {
				Secure(wg, mode, "sg")
				Secure(rg, mode, "sg")
			}
			ring := testRing(t)
			rec := &recorder{}
			sub := newRuntime(t, NewConfiguration(nil, AttachReaderGroups(UDPConnection("sub", url, nil), rg)),
				WithDataSetHandler(rec.handler), WithKeySource("sg", ring))
			pub := newRuntime(t, NewConfiguration([]*ua.PublishedDataSetDataType{pds}, AttachWriterGroups(UDPConnection("pub", url, uint16(5)), wg)),
				WithDataSource(ds), WithKeySource("sg", ring))
			waitValue(t, rec, big)
			// The publisher counts its chunks once the send returned,
			// which can be after the subscriber took the message.
			require.Eventually(t, func() bool { return counters(t, pub).ChunksSent > 0 }, 5*time.Second, time.Millisecond)
			pc, sc := counters(t, pub), counters(t, sub)
			require.Zero(t, pc.EncodeErrors, errString(pub))
			require.NotZero(t, sc.ChunksReceived)
			require.NotZero(t, sc.ChunkedMessagesReceived)
			require.Zero(t, sc.DecodeErrors, errString(sub))
		})
	}
}

// TestChunkedTooSmall: a MaxNetworkMessageSize that leaves no room for
// chunk data is an encoding error.
func TestChunkedTooSmall(t *testing.T) {
	t.Parallel()
	ds, pds := e2eData(t)
	wg := WriterGroup("wg", 1, 5*time.Millisecond, DataSetWriter("w", 1, "pds"))
	wg.MaxNetworkMessageSize = 20
	pub := newRuntime(t, NewConfiguration([]*ua.PublishedDataSetDataType{pds}, AttachWriterGroups(memConnection("pub", memURL(t), uint16(5)), wg)), WithDataSource(ds))
	require.Eventually(t, func() bool {
		return counters(t, pub).EncodeErrors > 0 && strings.Contains(errString(pub), "MaxNetworkMessageSize")
	}, 5*time.Second, 2*time.Millisecond)
}

// TestReassemblyCounters injects chunks into a subscriber: complete,
// duplicate and malformed ones.
func TestReassemblyCounters(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	_, pds := e2eData(t)
	rec := &recorder{}
	sub := newRuntime(t, NewConfiguration(nil, AttachReaderGroups(memConnection("sub", url, nil),
		ReaderGroup("rg", DataSetReader("r", uint16(5), 1, 1, DataSetMetaDataOf(pds))))),
		WithDataSetHandler(rec.handler), WithChunkReassembly(uadp.ReassemblerOptions{MaxMessageSize: 1 << 16}))
	require.Eventually(t, func() bool { return bus.subscribers(url) > 0 }, 5*time.Second, time.Millisecond)

	pub := message.NewPublisherID(message.PublisherIDUInt16, 5)
	nm := &message.NetworkMessage{
		Type:        message.NetworkMessageDataSet,
		UADPMask:    DefaultUADPNetworkMessageContentMask,
		PublisherID: pub,
		GroupHeader: message.GroupHeader{WriterGroupID: 1, SequenceNumber: 1},
		Messages: []*message.DataSetMessage{{
			DataSetWriterID: 1,
			Valid:           true,
			UADPMask:        ua.UADPDataSetMessageContentMaskSequenceNumber,
			SequenceNumber:  7,
			FieldEncoding:   message.FieldEncodingVariant,
			Fields: []*message.Field{
				{Value: &ua.DataValue{Value: ua.MustVariant(int32(11))}},
				{Value: &ua.DataValue{Value: ua.MustVariant(strings.Repeat("r", 300))}},
			},
		}},
	}
	chunks, err := uadp.EncodeChunks(nm, nil, 80)
	require.NoError(t, err)
	require.Greater(t, len(chunks), 3)
	// The chunks backwards, the second one twice.
	bus.inject(url, "", chunks[1])
	for i := len(chunks) - 1; i >= 0; i-- {
		bus.inject(url, "", chunks[i])
	}
	waitValue(t, rec, strings.Repeat("r", 300))
	require.Eventually(t, func() bool {
		c := counters(t, sub)
		return c.ChunksReceived == uint64(len(chunks)+1) && c.ChunksDiscarded == 1 && c.ChunkedMessagesReceived == 1
	}, 5*time.Second, time.Millisecond)

	// A chunk beyond the size limit and a truncated one.
	bad := append([]byte(nil), chunks[0]...)
	bad[len(bad)-1] ^= 0xff
	nm.GroupHeader.SequenceNumber = 2
	nm.Messages[0].SequenceNumber = 8
	nm.Messages[0].Fields[1].Value = &ua.DataValue{Value: ua.MustVariant(strings.Repeat("r", 1<<16))}
	huge, err := uadp.EncodeChunks(nm, nil, 1000)
	require.NoError(t, err)
	bus.inject(url, "", huge[0])
	bus.inject(url, "", chunks[0][:len(chunks[0])-3])
	require.Eventually(t, func() bool {
		c := counters(t, sub)
		return c.ChunksDiscarded == 2 && c.DecodeErrors == 1
	}, 5*time.Second, time.Millisecond)
}

// discoveryPair runs a publisher and a subscriber whose reader has no
// DataSetMetaData.
func discoveryPair(t *testing.T, adjust func(pub, sub *ua.PubSubConfigurationDataType), pubOpts, subOpts []Option) (pub, sub *PubSub, rec *recorder) {
	t.Helper()
	url := memURL(t)
	ds, pds := e2eData(t)
	pubCfg := NewConfiguration([]*ua.PublishedDataSetDataType{pds},
		AttachWriterGroups(memConnection("pub", url, uint16(5)), WriterGroup("wg", 1, 10*time.Millisecond, DataSetWriter("w", 1, "pds"))))
	subCfg := NewConfiguration(nil, AttachReaderGroups(memConnection("sub", url, nil),
		ReaderGroup("rg", DataSetReader("r", uint16(5), 1, 1, nil))))
	if adjust != nil {
		adjust(pubCfg, subCfg)
	}
	rec = &recorder{}
	sub = newRuntime(t, subCfg, append([]Option{WithDataSetHandler(rec.handler)}, subOpts...)...)
	pub = newRuntime(t, pubCfg, append([]Option{WithDataSource(ds)}, pubOpts...)...)
	return pub, sub, rec
}

func TestDiscoveryMetaData(t *testing.T) {
	t.Parallel()
	for name, layout := range map[string]message.DiscoveryLayout{"spec": message.DiscoveryLayoutSpec, "dotnet": message.DiscoveryLayoutDotNet} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			pub, sub, rec := discoveryPair(t, nil, nil, []Option{WithDiscovery(DiscoveryOptions{Layout: layout})})
			waitValue(t, rec, "text")
			// The publisher counts a response once the send returned,
			// which can be after the subscriber took it.
			require.Eventually(t, func() bool { return counters(t, pub).DiscoveryResponsesSent > 0 }, 5*time.Second, time.Millisecond)
			sc, pc := counters(t, sub), counters(t, pub)
			require.NotZero(t, sc.DiscoveryRequestsSent)
			require.NotZero(t, sc.DiscoveryResponsesReceived)
			require.NotZero(t, pc.DiscoveryRequestsReceived)
			require.Zero(t, sc.DecodeErrors, errString(sub))
			require.Zero(t, pc.DecodeErrors, errString(pub))
			id := mustID(t, sub, KindDataSetReader, mustID(t, sub, KindReaderGroup, mustID(t, sub, KindConnection, Root, "sub"), "rg"), "r")
			cfg, err := sub.DataSetReaderConfig(id)
			require.NoError(t, err)
			require.Len(t, cfg.DataSetMetaData.Fields, 2)
		})
	}
}

func TestDiscoverySecured(t *testing.T) {
	t.Parallel()
	ring := testRing(t)
	// The announcement is larger than the DiscoveryMaxMessageSize: it is
	// chunked, every chunk signed.
	_, sub, rec := discoveryPair(t, func(pub, sub *ua.PubSubConfigurationDataType) {
		Secure(pub.Connections[0].WriterGroups[0], ua.MessageSecurityModeSign, "sg")
		Secure(sub.Connections[0].ReaderGroups[0], ua.MessageSecurityModeSign, "sg")
		withDiscoveryAddress(pub.Connections[0], "", 0, 120)
	}, []Option{WithKeySource("sg", ring)}, []Option{WithKeySource("sg", ring)})
	waitValue(t, rec, "text")
	c := counters(t, sub)
	require.NotZero(t, c.ChunkedMessagesReceived)
	require.Zero(t, c.DecodeErrors, errString(sub))
}

// TestDiscoveryUDP: the subscriber probes on the DiscoveryAddress, the
// publisher answers on the connection address, chunked.
func TestDiscoveryUDP(t *testing.T) {
	t.Parallel()
	url := fmt.Sprintf("opc.udp://127.0.0.1:%d", freeUDPPort(t))
	disc := fmt.Sprintf("opc.udp://127.0.0.1:%d", freeUDPPort(t))
	_, sub, rec := discoveryPair(t, func(pub, sub *ua.PubSubConfigurationDataType) {
		pub.Connections[0] = withDiscoveryAddress(UDPConnection("pub", url, uint16(5)), disc, 0, 100)
		pub.Connections[0].WriterGroups = []*ua.WriterGroupDataType{WriterGroup("wg", 1, 10*time.Millisecond, DataSetWriter("w", 1, "pds"))}
		rgs := sub.Connections[0].ReaderGroups
		sub.Connections[0] = withDiscoveryAddress(UDPConnection("sub", url, nil), disc, 0, 0)
		sub.Connections[0].ReaderGroups = rgs
	}, nil, nil)
	waitValue(t, rec, "text")
	c := counters(t, sub)
	require.NotZero(t, c.DiscoveryRequestsSent)
	require.NotZero(t, c.ChunkedMessagesReceived)
}

// TestDiscoveryAnnounceRate: the publisher announces the DataSetMetaData
// cyclically, the subscriber does not probe.
func TestDiscoveryAnnounceRate(t *testing.T) {
	t.Parallel()
	for name, settings := range map[string]func(*ua.PubSubConnectionDataType){
		"group": func(c *ua.PubSubConnectionDataType) {
			c.WriterGroups[0].TransportSettings = ua.NewExtensionObject(&ua.DatagramWriterGroupTransport2DataType{DiscoveryAnnounceRate: 1})
		},
		// Chunked above the DiscoveryMaxMessageSize.
		"connection": func(c *ua.PubSubConnectionDataType) { withDiscoveryAddress(c, "", 1, 120) },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			pub, sub, rec := discoveryPair(t, func(pub, _ *ua.PubSubConfigurationDataType) {
				settings(pub.Connections[0])
			}, nil, []Option{WithDiscovery(DiscoveryOptions{Disabled: true})})
			waitValue(t, rec, "text")
			require.Zero(t, counters(t, sub).DiscoveryRequestsSent)
			// Counted once the send returned, which can be after the
			// subscriber took the announcement.
			require.Eventually(t, func() bool { return counters(t, pub).DiscoveryResponsesSent > 0 }, 5*time.Second, time.Millisecond)
		})
	}
}

// TestDiscoveryVersionMismatch: a reader with DataSetMetaData of another
// MajorVersion probes for the current one.
func TestDiscoveryVersionMismatch(t *testing.T) {
	t.Parallel()
	_, sub, rec := discoveryPair(t, func(pub, sub *ua.PubSubConfigurationDataType) {
		md := DataSetMetaDataOf(pub.PublishedDataSets[0])
		md.ConfigurationVersion = &ua.ConfigurationVersionDataType{MajorVersion: 1, MinorVersion: 1}
		sub.Connections[0].ReaderGroups[0].DataSetReaders[0].DataSetMetaData = md
	}, nil, nil)
	waitValue(t, rec, "text")
	c := counters(t, sub)
	require.NotZero(t, c.VersionMismatches)
	require.NotZero(t, c.DiscoveryRequestsSent)
}

// probeBytes encodes a probe for the publisher 5.
func probeBytes(t *testing.T, req *message.DiscoveryRequest, pub uint64) []byte {
	t.Helper()
	b, err := uadp.Encode(&message.NetworkMessage{
		Type:        message.NetworkMessageDiscoveryRequest,
		UADPMask:    ua.UADPNetworkMessageContentMaskPublisherID,
		PublisherID: message.NewPublisherID(message.PublisherIDUInt16, pub),
		Request:     req,
	}, nil)
	require.NoError(t, err)
	return b
}

// announcements returns the discovery announcements sent on a bus address.
func announcements(t *testing.T, url string) []*message.Discovery {
	t.Helper()
	var out []*message.Discovery
	for _, s := range bus.sentTo(url) {
		if tp, chunk, err := uadp.PeekType(s.Payload); err != nil || chunk || tp != message.NetworkMessageDiscoveryResponse {
			continue
		}
		nm, err := uadp.Decode(s.Payload, nil)
		require.NoError(t, err)
		out = append(out, nm.Discovery)
	}
	return out
}

func announcer(t *testing.T, opts ...Option) (*PubSub, string) {
	t.Helper()
	url := memURL(t)
	ds, pds := e2eData(t)
	pub := newRuntime(t, NewConfiguration([]*ua.PublishedDataSetDataType{pds},
		AttachWriterGroups(memConnection("pub", url, uint16(5)), WriterGroup("wg", 7, time.Hour, DataSetWriter("w", 1, "pds"), DataSetWriter("w2", 2, "pds")))),
		append([]Option{WithDataSource(ds)}, opts...)...)
	require.Eventually(t, func() bool { return bus.subscribers(url) > 0 }, 5*time.Second, time.Millisecond)
	return pub, url
}

func TestDiscoveryProbes(t *testing.T) {
	t.Parallel()
	app := &ua.ApplicationDescription{ApplicationURI: "urn:test"}
	pub, url := announcer(t, WithDiscovery(DiscoveryOptions{
		Endpoints:    func() []*ua.EndpointDescription { return []*ua.EndpointDescription{{EndpointURL: "opc.tcp://x:4840"}} },
		Application:  func() *ua.ApplicationDescription { return app },
		Capabilities: []string{"LDS"},
	}))
	probes := []*message.DiscoveryRequest{
		{ProbeType: message.ProbePublisherInformation, InformationType: message.InformationPublisherEndpoints},
		{ProbeType: message.ProbePublisherInformation, InformationType: message.InformationDataSetMetaData},
		{ProbeType: message.ProbePublisherInformation, InformationType: message.InformationDataSetWriterConfig, DataSetWriterIDs: []uint16{2, 9}},
		{ProbeType: message.ProbePublisherInformation, InformationType: message.InformationWriterGroupConfig, WriterGroupID: 7, IncludeDataSetWriters: true},
		{ProbeType: message.ProbePublisherInformation, InformationType: message.InformationPubSubConnections, IncludeWriterGroups: true, IncludeDataSetWriters: true},
		{ProbeType: message.ProbePublisherInformation, InformationType: message.InformationPubSubConnections, TransportProfileURIs: []string{"other"}},
		{ProbeType: message.ProbeFindApplications},
	}
	for _, p := range probes {
		bus.inject(url, "", probeBytes(t, p, 5))
	}
	// For another publisher.
	bus.inject(url, "", probeBytes(t, probes[1], 6))
	// A probe is counted as received before it is decoded and answered:
	// wait for the answers and the ignored ones.
	var got []*message.Discovery
	require.Eventually(t, func() bool {
		got = announcements(t, url)
		c := counters(t, pub)
		return c.DiscoveryRequestsReceived == uint64(len(probes)+1) && c.DiscoveryRequestsIgnored == 2 && len(got) >= 7
	}, 5*time.Second, time.Millisecond)
	require.Len(t, got, 7)
	byType := map[message.DiscoveryType][]*message.Discovery{}
	for _, d := range got {
		byType[d.Type] = append(byType[d.Type], d)
	}
	require.Equal(t, "opc.tcp://x:4840", byType[message.DiscoveryPublisherEndpoints][0].Endpoints[0].EndpointURL)
	require.Len(t, byType[message.DiscoveryDataSetMetaData], 2)
	wc := byType[message.DiscoveryDataSetWriterConfig]
	require.Len(t, wc, 2)
	require.Equal(t, []uint16{2}, wc[0].DataSetWriterIDs)
	require.Len(t, wc[0].WriterGroup.DataSetWriters, 1)
	require.Len(t, wc[1].WriterGroup.DataSetWriters, 2)
	conn := byType[message.DiscoveryPubSubConnection][0].Connections[0]
	require.Equal(t, "pub", conn.Name)
	require.Len(t, conn.WriterGroups, 1)
	require.Nil(t, conn.ReaderGroups)
	ai := byType[message.DiscoveryApplicationInformation][0].Application
	require.Equal(t, "urn:test", ai.Description.ApplicationURI)
	require.Equal(t, []string{"LDS"}, ai.Capabilities)
}

func TestDiscoveryProbeDefaults(t *testing.T) {
	t.Parallel()
	pub, url := announcer(t)
	bus.inject(url, "", probeBytes(t, &message.DiscoveryRequest{ProbeType: message.ProbePublisherInformation, InformationType: message.InformationPublisherEndpoints}, 5))
	bus.inject(url, "", probeBytes(t, &message.DiscoveryRequest{ProbeType: message.ProbeFindApplications}, 5))
	// A malformed probe.
	bus.inject(url, "", []byte{0x91, 0x80, 0x04, 0x01, 0x01, 0x02, 0xff})
	require.Eventually(t, func() bool { return len(announcements(t, url)) == 2 && counters(t, pub).DecodeErrors == 1 }, 5*time.Second, time.Millisecond)
	for _, d := range announcements(t, url) {
		switch d.Type {
		case message.DiscoveryPublisherEndpoints:
			require.Equal(t, ua.StatusBadNotSupported, d.StatusCode)
		default:
			require.Equal(t, message.ApplicationInformationStatus, d.Application.Type)
			require.Equal(t, ua.PubSubStateOperational, d.Application.Status)
		}
	}
}

// TestDiscoveryFlood: a flood of probes makes the publisher send a bounded
// number of announcements.
func TestDiscoveryFlood(t *testing.T) {
	t.Parallel()
	const rate, burst = 2, 3
	pub, url := announcer(t, WithDiscovery(DiscoveryOptions{Rate: rate, Burst: burst}))
	same := probeBytes(t, &message.DiscoveryRequest{ProbeType: message.ProbePublisherInformation, InformationType: message.InformationDataSetMetaData, DataSetWriterIDs: []uint16{1}}, 5)
	var all [][]byte
	for i := range 5 {
		all = append(all, probeBytes(t, &message.DiscoveryRequest{ProbeType: message.ProbePublisherInformation, InformationType: message.InformationType(1 + i)}, 5))
	}
	const n = 400
	start := time.Now()
	for i := range n {
		bus.inject(url, "", same)
		bus.inject(url, "", all[i%len(all)])
	}
	require.Eventually(t, func() bool { return counters(t, pub).DiscoveryRequestsReceived == 2*n }, 10*time.Second, time.Millisecond)
	elapsed := time.Since(start)
	c := counters(t, pub)
	// Upper bounds only: the token bucket and the per announcement
	// interval.
	limit := uint64(burst + rate*elapsed.Seconds() + 1)
	require.LessOrEqual(t, c.DiscoveryResponsesSent, limit)
	require.LessOrEqual(t, uint64(len(announcements(t, url))), limit)
	require.GreaterOrEqual(t, c.DiscoveryRequestsIgnored, uint64(2*n)-limit)
}

func TestDiscoveryDisabled(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	ds, pds := e2eData(t)
	newRuntime(t, NewConfiguration([]*ua.PublishedDataSetDataType{pds},
		AttachWriterGroups(memConnection("pub", url, uint16(5)), WriterGroup("wg", 7, time.Hour, DataSetWriter("w", 1, "pds")))),
		WithDataSource(ds), WithDiscovery(DiscoveryOptions{Disabled: true}))
	// Once it publishes, a publisher with discovery disabled does not
	// listen.
	require.Eventually(t, func() bool { return len(bus.sentTo(url)) > 0 }, 5*time.Second, time.Millisecond)
	require.Zero(t, bus.subscribers(url))
}

func TestDiscoveryConfig(t *testing.T) {
	t.Parallel()
	base := func() *ua.PubSubConfigurationDataType {
		return NewConfiguration(nil, AttachWriterGroups(UDPConnection("c", "opc.udp://239.0.0.1:4840", uint16(1)), WriterGroup("wg", 1, time.Second)))
	}
	for name, tc := range map[string]struct {
		adjust func(*ua.PubSubConfigurationDataType)
		err    string
	}{
		"address": {func(c *ua.PubSubConfigurationDataType) {
			withDiscoveryAddress(c.Connections[0], "opc.udp://224.0.2.14:4840", 5, 1000)
		}, ""},
		"v1": {func(c *ua.PubSubConfigurationDataType) {
			c.Connections[0].TransportSettings = ua.NewExtensionObject(&ua.DatagramConnectionTransportDataType{})
		}, ""},
		"bad address type": {func(c *ua.PubSubConfigurationDataType) {
			c.Connections[0].TransportSettings = ua.NewExtensionObject(&ua.DatagramConnectionTransportDataType{DiscoveryAddress: ua.NewExtensionObject(&ua.DatagramWriterGroupTransportDataType{})})
		}, "DiscoveryAddress must be"},
		"bad scheme": {func(c *ua.PubSubConfigurationDataType) {
			withDiscoveryAddress(c.Connections[0], "nope", 0, 0)
		}, "DiscoveryAddress"},
		"broker": {func(c *ua.PubSubConfigurationDataType) {
			c.Connections[0] = withDiscoveryAddress(MQTTConnection("m", "mqtt://localhost:1883", uint16(1), MappingUADP), "", 0, 0)
		}, "on a broker connection"},
		"group transport2": {func(c *ua.PubSubConfigurationDataType) {
			c.Connections[0].WriterGroups[0].TransportSettings = ua.NewExtensionObject(&ua.DatagramWriterGroupTransport2DataType{MessageRepeatCount: 1, DiscoveryAnnounceRate: 3})
		}, ""},
		"group address": {func(c *ua.PubSubConfigurationDataType) {
			c.Connections[0].WriterGroups[0].TransportSettings = ua.NewExtensionObject(&ua.DatagramWriterGroupTransport2DataType{Address: ua.NewExtensionObject(&ua.NetworkAddressURLDataType{URL: "opc.udp://1.2.3.4:1"})})
		}, "Address of the writer group"},
		"group on broker": {func(c *ua.PubSubConfigurationDataType) {
			c.Connections[0] = AttachWriterGroups(MQTTConnection("m", "mqtt://localhost:1883", uint16(1), MappingUADP), WriterGroup("wg", 1, time.Second))
			c.Connections[0].WriterGroups[0].TransportSettings = ua.NewExtensionObject(&ua.DatagramWriterGroupTransport2DataType{})
		}, "on a broker connection"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := base()
			tc.adjust(cfg)
			err := Validate(cfg)
			if tc.err == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.err)
			}
		})
	}
}

func TestSharedAddress(t *testing.T) {
	t.Parallel()
	for url, want := range map[string]bool{
		"opc.udp://239.0.0.1:4840":      true,
		"opc.udp://[ff02::1%eth0]:4840": true,
		"opc.udp://127.0.0.1:4840":      false,
		"opc.udp://localhost:4840":      false,
		"opc.udp://239.0.0.1:4840/x":    true,
		"opc.udp://239.0.0.1":           false,
		"mem://x":                       true,
		"bogus":                         false,
	} {
		require.Equal(t, want, sharedAddress(url), url)
	}
}

func TestDiscoveryLimiter(t *testing.T) {
	t.Parallel()
	o := DiscoveryOptions{Rate: 1, Burst: 2}.normalized()
	l := newDiscoveryLimiter()
	now := time.Unix(1000, 0)
	k := discoveryKey{info: 2, id: 1}
	require.True(t, l.allow(k, now, &o))
	require.False(t, l.allow(k, now.Add(100*time.Millisecond), &o), "same announcement within MinInterval")
	require.True(t, l.allow(discoveryKey{info: 2, id: 2}, now, &o))
	require.False(t, l.allow(discoveryKey{info: 2, id: 3}, now, &o), "bucket empty")
	require.True(t, l.allow(discoveryKey{info: 2, id: 3}, now.Add(time.Second), &o))
	// The clock going back refills the bucket.
	require.True(t, l.allow(discoveryKey{info: 3}, now, &o))
	// Many keys are pruned.
	o.Rate, o.Burst = 1e9, 1e9
	for i := range maxLimiterKeys + 10 {
		require.True(t, l.allow(discoveryKey{info: 4, id: uint16(i)}, now.Add(time.Duration(i)*time.Hour), &o))
	}
	require.LessOrEqual(t, len(l.last), maxLimiterKeys)
	for i := range maxLimiterKeys + 10 {
		l.allow(discoveryKey{info: 5, id: uint16(i)}, now, &o)
	}
	require.LessOrEqual(t, len(l.last), maxLimiterKeys)
}

func TestJSONCodecNoChunks(t *testing.T) {
	t.Parallel()
	_, err := jsonCodec{}.EncodeChunks(&message.NetworkMessage{}, nil, 10)
	require.ErrorIs(t, err, errNoJSONChunks)
	_, err = jsonCodec{}.DecodeReassembled(&message.NetworkMessage{}, nil, nil)
	require.ErrorIs(t, err, errNoJSONChunks)
	_, err = uadpCodec{}.DecodeReassembled(&message.NetworkMessage{Chunk: &message.Chunk{}}, nil, nil)
	require.Error(t, err)
}
