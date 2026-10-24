// SPDX-License-Identifier: MIT

package pubsubchaos

import (
	"bytes"
	"context"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/pubsub/uadp"
	"github.com/otfabric/go-opcua/ua"
)

// Native fuzz targets for the receive path of the PubSub runtime and for
// the UADP discovery codec. Without -fuzz they run their seeds (real
// traffic of a publisher: chunks, secured chunks, RawData, probes and
// announcements in both layouts) as regression tests.

// fuzzRing returns a KeyRing with fixed keys, so that a saved crasher
// replays with the keys it was found with.
func fuzzRing(tb testing.TB) *security.KeyRing {
	tb.Helper()
	policy := security.Aes256CTR()
	ring := security.NewKeyRing("sg", policy)
	key := bytes.Repeat([]byte{0x5a}, policy.KeyLength())
	if err := ring.SetKeys(policy.URI(), 1, [][]byte{key}, time.Hour, time.Hour); err != nil {
		tb.Fatal(err)
	}
	return ring
}

// fuzzRaw is the RawData data set of the fuzz targets.
func fuzzRaw() *ua.PublishedDataSetDataType {
	return pubsub.PublishedDataItems("raw",
		pubsub.Var("n", fieldNode("raw", "n"), ua.TypeIDInt64),
		pubsub.Var("f", fieldNode("raw", "f"), ua.TypeIDDouble))
}

// fuzzSeeds returns the NetworkMessages a publisher sends that the fuzz
// subscriber has readers for: chunked (unsecured and SignAndEncrypt),
// RawData, and the discovery announcements it sends in answer to probes of
// every kind and layout, with the probes themselves.
func fuzzSeeds(tb testing.TB) [][]byte {
	tb.Helper()
	seg := mnet.segment("chaosmem://fuzz-seeds-" + tb.Name())
	var mu sync.Mutex
	var all [][]byte
	seg.setTap(func(b []byte) {
		mu.Lock()
		all = append(all, b)
		mu.Unlock()
	})
	wg1 := pubsub.WriterGroup("wg1", 1, 20*time.Millisecond, pubsub.DataSetWriter("w1", 1, "big0"))
	wg1.MaxNetworkMessageSize = 600
	wraw := pubsub.DataSetWriter("w1", 1, "raw")
	wraw.DataSetFieldContentMask = ua.DataSetFieldContentMaskRawData
	wg2 := pubsub.WriterGroup("wg2", 2, 20*time.Millisecond, wraw)
	wg4 := pubsub.Secure(pubsub.WriterGroup("wg4", 4, 20*time.Millisecond, pubsub.DataSetWriter("w1", 1, "big1")), ua.MessageSecurityModeSignAndEncrypt, "sg")
	wg4.MaxNetworkMessageSize = 600
	pub, err := pubsub.New(pubsub.NewConfiguration([]*ua.PublishedDataSetDataType{counterPDS("big0"), counterPDS("big1"), fuzzRaw()},
		pubsub.AttachWriterGroups(pubsub.UDPConnection("pub", seg.url, uint16(7)), wg1, wg2, wg4)),
		pubsub.WithDataSource(newCounterSource()), pubsub.WithKeySource("sg", fuzzRing(tb)),
		pubsub.WithDiscovery(pubsub.DiscoveryOptions{MinInterval: time.Millisecond, Rate: 1000, Burst: 1000}))
	if err != nil {
		tb.Fatal(err)
	}
	if err := pub.Start(context.Background()); err != nil {
		tb.Fatal(err)
	}
	defer func() { _ = pub.Close() }()
	rng := rand.New(rand.NewSource(1))
	deadline := time.Now().Add(10 * time.Second)
	for seg.subscribers() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	for range 40 {
		seg.injectSync(randomProbe(rng, []uint64{7}))
	}
	time.Sleep(200 * time.Millisecond)
	_ = pub.Close()

	mu.Lock()
	defer mu.Unlock()
	// One of each kind and size, at most 64.
	seen := map[[3]int]int{}
	var out [][]byte
	for _, b := range all {
		t, chunk, err := uadp.PeekType(b)
		if err != nil {
			continue
		}
		k := [3]int{int(t), map[bool]int{false: 0, true: 1}[chunk], len(b) / 100}
		if seen[k] < 2 && len(out) < 64 {
			seen[k]++
			out = append(out, b)
		}
	}
	return out
}

// FuzzRuntimeReceive delivers arbitrary NetworkMessages to a runtime with a
// publisher (that answers probes) and readers of every kind on one
// connection: Variant with metadata, RawData, without metadata (it
// probes), SignAndEncrypt, a reader of any publisher, small chunk
// reassembly limits and discovery. The runtime must not panic, not even in
// a part it recovers from (Counters.Panics), and must stay within its
// reassembly limits.
func FuzzRuntimeReceive(f *testing.F) {
	for _, b := range fuzzSeeds(f) {
		f.Add(b)
	}
	f.Add([]byte{0x91, 0x80, 0x04, 0x01, 0x01, 0x02, 0xff})
	f.Add([]byte{})

	seg := mnet.segment("chaosmem://fuzz-runtime")
	rraw := pubsub.DataSetReader("raw", uint16(7), 2, 1, pubsub.DataSetMetaDataOf(fuzzRaw()))
	rraw.DataSetFieldContentMask = ua.DataSetFieldContentMaskRawData
	conn := pubsub.AttachReaderGroups(pubsub.AttachWriterGroups(pubsub.UDPConnection("fz", seg.url, uint16(9)),
		pubsub.WriterGroup("own", 9, time.Hour, pubsub.DataSetWriter("w", 1, "own"))),
		pubsub.ReaderGroup("rg",
			pubsub.DataSetReader("big0", uint16(7), 1, 1, pubsub.DataSetMetaDataOf(counterPDS("big0"))),
			rraw,
			pubsub.DataSetReader("nomd", uint16(7), 3, 1, nil),
			pubsub.DataSetReader("any", nil, 0, 0, nil)),
		pubsub.Secure(pubsub.ReaderGroup("rgs", pubsub.DataSetReader("big1", uint16(7), 4, 1, pubsub.DataSetMetaDataOf(counterPDS("big1")))),
			ua.MessageSecurityModeSignAndEncrypt, "sg"))
	rt, err := pubsub.New(pubsub.NewConfiguration([]*ua.PublishedDataSetDataType{counterPDS("own")}, conn),
		pubsub.WithDataSource(newCounterSource()), pubsub.WithKeySource("sg", fuzzRing(f)),
		pubsub.WithDataSetHandler(func(d *pubsub.ReceivedDataSet) {
			for _, x := range d.Fields {
				if x.Value != nil && x.Value.Value != nil {
					_ = x.Value.Value.Value()
				}
			}
		}),
		pubsub.WithChunkReassembly(uadp.ReassemblerOptions{MaxMessageSize: 1 << 14, MaxChunks: 64, MaxPendingMessages: 8, MaxPublisherMessages: 4, Timeout: 100 * time.Millisecond}),
		pubsub.WithDiscovery(pubsub.DiscoveryOptions{MaxProbeInterval: time.Second}))
	if err != nil {
		f.Fatal(err)
	}
	if err := rt.Start(context.Background()); err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { _ = rt.Close() })
	deadline := time.Now().Add(10 * time.Second)
	for seg.subscribers() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if seg.subscribers() == 0 {
		f.Fatal("the runtime did not subscribe")
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		seg.injectSync(b)
		st, err := rt.Status(pubsub.Root)
		if err != nil {
			t.Fatal(err)
		}
		if st.Counters.Panics != 0 {
			t.Fatalf("the runtime recovered from %d panics", st.Counters.Panics)
		}
	})
}

// FuzzDiscoveryRoundTrip decodes arbitrary bytes as UADP discovery probes
// and announcements (both layouts) and checks that what decodes encodes
// to bytes that decode to the same message, and that the encoding is then
// stable.
func FuzzDiscoveryRoundTrip(f *testing.F) {
	for _, b := range fuzzSeeds(f) {
		if t, chunk, err := uadp.PeekType(b); err == nil && !chunk && t != message.NetworkMessageDataSet {
			f.Add(b)
		}
	}
	rng := rand.New(rand.NewSource(2))
	for range 16 {
		f.Add(randomProbe(rng, []uint64{7}))
		f.Add(forgedAnnouncement(rng, []uint64{7}, uint16(rng.Intn(100))))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		nm, err := uadp.Decode(b, nil)
		if err != nil || (nm.Discovery == nil && nm.Request == nil) || nm.Chunk != nil {
			return
		}
		out, err := uadp.Encode(nm, nil)
		if err != nil {
			t.Fatalf("decoded %v does not encode: %v", nm.Type, err)
		}
		nm2, err := uadp.Decode(out, nil)
		if err != nil {
			t.Fatalf("re-decode: %v\n% x", err, out)
		}
		// The first round may normalize: an ExtensionObject whose type has
		// no fields (e.g. the abstract DataSetWriterTransportDataType) is
		// encoded with an empty body, which decodes to no value (package
		// ua). From then on the encoding must be stable.
		out2, err := uadp.Encode(nm2, nil)
		if err != nil {
			t.Fatalf("re-encode: %v", err)
		}
		nm3, err := uadp.Decode(out2, nil)
		if err != nil {
			t.Fatalf("third decode: %v\n% x", err, out2)
		}
		out3, err := uadp.Encode(nm3, nil)
		if err != nil || !bytes.Equal(out2, out3) {
			t.Fatalf("encoding not stable (%v):\n% x\n% x", err, out2, out3)
		}
	})
}

// FuzzValidateConnection validates and creates runtimes from connection
// configurations a client could send with AddConnection: any profile,
// address, interface, MqttVersion and connection property. Validate and
// New must not panic, and New must accept what Validate accepts.
func FuzzValidateConnection(f *testing.F) {
	f.Add(uint8(0), "opc.udp://224.0.0.22:4840", "", "", "", "")
	f.Add(uint8(1), "opc.eth://01-00-5e-00-00-01:100.5", "eth0", "", "", "")
	f.Add(uint8(2), "mqtt://127.0.0.1:1883", "", "5.0", "connection-Receive Maximum", "10")
	f.Add(uint8(3), "mqtts://h:8883", "", "BestAvailable", "connection-Session Expiry Interval", "-1")
	f.Add(uint8(4), "amqp://h", "", "", "connection-max-frame-size", "512")
	f.Add(uint8(5), "amqps://h:5671", "", "", "link-max-message-size", "x")
	f.Add(uint8(2), "mqtt://h", "", "3.1.1", "connection-Maximum Packet Size", "0")
	f.Add(uint8(1), "opc.eth://ff-ff-ff-ff-ff-ff:4095.8", "lo", "", "", "")
	profiles := []string{transport.ProfileUDPUADP, transport.ProfileEthUADP, transport.ProfileMQTTUADP, transport.ProfileMQTTJSON,
		transport.ProfileAMQPUADP, transport.ProfileAMQPJSON, "", "urn:other"}
	f.Fuzz(func(t *testing.T, profile uint8, url, iface, version, prop, value string) {
		c := &ua.PubSubConnectionDataType{
			Name:                "c",
			Enabled:             false,
			PublisherID:         ua.MustVariant(uint16(1)),
			TransportProfileURI: profiles[int(profile)%len(profiles)],
			Address:             ua.NewExtensionObject(&ua.NetworkAddressURLDataType{URL: url, NetworkInterface: iface}),
		}
		if version != "" {
			pubsub.SetMQTTVersion(c, version)
		}
		if prop != "" {
			pubsub.SetConnectionProperty(c, prop, value)
		}
		cfg := pubsub.NewConfiguration(nil, c)
		verr := pubsub.Validate(cfg)
		rt, err := pubsub.New(cfg)
		if err == nil {
			_ = rt.Close()
		}
		if verr == nil && err != nil {
			t.Fatalf("Validate accepts what New refuses: %v", err)
		}
	})
}
