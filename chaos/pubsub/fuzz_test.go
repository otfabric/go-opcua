// SPDX-License-Identifier: MIT

package pubsubchaos

import (
	"context"
	"encoding/binary"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	imqtt "github.com/otfabric/go-opcua/internal/mqtt"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/internal/testutil/mqttbroker"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/ua"
)

// mutate returns a variant of b: bit flips, bytes and integers replaced by
// boundary values, cuts, extensions, splices with another message.
func mutate(rng *rand.Rand, b, other []byte) []byte {
	b = append([]byte(nil), b...)
	for range 1 + rng.Intn(3) {
		if len(b) == 0 {
			b = append(b, byte(rng.Intn(256)))
		}
		switch rng.Intn(9) {
		case 0: // bit flip
			i := rng.Intn(len(b))
			b[i] ^= 1 << rng.Intn(8)
		case 1: // random byte
			b[rng.Intn(len(b))] = byte(rng.Intn(256))
		case 2: // boundary uint16
			if len(b) >= 2 {
				i := rng.Intn(len(b) - 1)
				binary.LittleEndian.PutUint16(b[i:], []uint16{0, 1, 0x7fff, 0x8000, 0xfffe, 0xffff}[rng.Intn(6)])
			}
		case 3: // boundary uint32
			if len(b) >= 4 {
				i := rng.Intn(len(b) - 3)
				binary.LittleEndian.PutUint32(b[i:], []uint32{0, 1, 0x7fffffff, 0x80000000, 0xffffffff, 1 << 20}[rng.Intn(6)])
			}
		case 4: // cut
			b = b[:rng.Intn(len(b))]
		case 5: // extend
			for range 1 + rng.Intn(16) {
				b = append(b, byte(rng.Intn(256)))
			}
		case 6: // splice
			if len(other) > 0 {
				i, j := rng.Intn(len(b)), rng.Intn(len(other))
				b = append(b[:i:i], other[j:]...)
			}
		case 7: // duplicate a range
			i := rng.Intn(len(b))
			j := i + rng.Intn(len(b)-i)
			b = append(b[:j:j], append(append([]byte(nil), b[i:j]...), b[j:]...)...)
		default: // JSON: replace a digit or a quote
			for k := range b {
				if b[k] >= '0' && b[k] <= '9' && rng.Intn(4) == 0 {
					b[k] = "0123456789-.e\""[rng.Intn(14)]
				}
			}
		}
	}
	return b
}

func randomBytes(rng *rand.Rand) []byte {
	b := make([]byte, rng.Intn(300))
	rng.Read(b)
	if len(b) > 0 && rng.Intn(3) == 0 {
		b[0] = 0x01 | byte(rng.Intn(16))<<4 // UADP version 1 with random flags
	}
	if len(b) > 0 && rng.Intn(5) == 0 {
		b[0] = '{'
	}
	return b
}

// TestChaosFuzzThroughTransport feeds random bytes and mutated valid
// messages (UADP with the Variant, DataValue and RawData field encodings,
// key and delta frames, SignAndEncrypt, JSON data and metadata messages)
// through the real UDP and MQTT transports into subscribers with filtered,
// unfiltered, RawData and secured readers, while the publishers keep
// sending. Nothing may panic; the secured reader must never deliver
// anything but the publisher's data and must keep delivering; the runtimes
// must close.
func TestChaosFuzzThroughTransport(t *testing.T) {
	t.Parallel()
	seed := chaoskit.Seed(t)
	rng := rand.New(rand.NewSource(seed))

	ks := keyService(t, "sg", security.PolicyURIAes256CTR, time.Hour, 1, 1)
	var jsonMu sync.Mutex
	var jsonSeeds [][]byte
	broker := mqttbroker.New(mqttbroker.Options{OnPublish: func(_ string, p *imqtt.Publish) {
		if strings.HasPrefix(p.Topic, "fz/json") {
			jsonMu.Lock()
			if len(jsonSeeds) < 64 {
				jsonSeeds = append(jsonSeeds, append([]byte(nil), p.Payload...))
			}
			jsonMu.Unlock()
		}
	}})
	if err := broker.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(broker.Close)

	// The secured reader is checked strictly; the others may deliver
	// whatever a mutated unsigned message says.
	chk := newChecker()
	var others atomic.Int64
	handler := func(d *pubsub.ReceivedDataSet) {
		if d.ReaderName == "sec" {
			chk.handle(d)
			return
		}
		others.Add(1)
		for _, f := range d.Fields { // touch everything that was delivered
			if f.Value != nil && f.Value.Value != nil {
				_ = f.Value.Value.Value()
			}
		}
	}

	// Subscriber over UDP.
	subPort := freeUDPPort(t)
	rl := newRelay(t, seed, subPort)
	pdss := []*ua.PublishedDataSetDataType{counterPDS("ds0"), counterPDS("ds1"), counterPDS("ds2"), counterPDS("ds3"), counterPDS("sec"), counterPDS("js")}
	md := func(i int) *ua.DataSetMetaDataType { return pubsub.DataSetMetaDataOf(pdss[i]) }
	rDV := pubsub.DataSetReader("ds1", uint16(7), 1, 2, md(1))
	rDV.DataSetFieldContentMask = ua.DataSetFieldContentMaskStatusCode | ua.DataSetFieldContentMaskSourceTimestamp
	rRaw := pubsub.DataSetReader("ds2", uint16(7), 1, 3, md(2))
	rRaw.DataSetFieldContentMask = ua.DataSetFieldContentMaskRawData
	udpSub := pubsub.AttachReaderGroups(pubsub.UDPConnection("sub", udpURL(subPort), nil),
		pubsub.ReaderGroup("rg",
			pubsub.DataSetReader("ds0", uint16(7), 1, 1, md(0)),
			rDV, rRaw,
			pubsub.DataSetReader("ds3", uint16(7), 1, 4, md(3)),
			pubsub.DataSetReader("any", nil, 0, 0, nil),
			pubsub.DataSetReader("anyraw|md", nil, 0, 0, md(2))),
		pubsub.Secure(pubsub.ReaderGroup("rgsec", pubsub.DataSetReader("sec", uint16(8), 2, 1, md(4))), ua.MessageSecurityModeSignAndEncrypt, "sg"))
	// Subscriber over MQTT (JSON and UADP on their queues).
	mqttSub := pubsub.AttachReaderGroups(pubsub.MQTTConnection("msub", broker.URL(), nil, pubsub.MappingJSON),
		pubsub.ReaderGroup("mrg",
			pubsub.SetReaderQueue(pubsub.DataSetReader("js", uint16(9), 0, 1, nil), "fz/json", "fz/json/meta"),
			pubsub.SetReaderQueue(pubsub.DataSetReader("jsany", nil, 0, 0, nil), "fz/#", "")))
	sub := startRuntime(t, pubsub.NewConfiguration(nil, udpSub, mqttSub),
		pubsub.WithDataSetHandler(handler), pubsub.WithKeySource("sg", keySource(t, ks, "sg")))

	// Publishers.
	wDV := pubsub.DataSetWriter("w1", 2, "ds1")
	wDV.DataSetFieldContentMask = rDV.DataSetFieldContentMask
	wRaw := pubsub.DataSetWriter("w2", 3, "ds2")
	wRaw.DataSetFieldContentMask = ua.DataSetFieldContentMaskRawData
	wDelta := pubsub.DataSetWriter("w3", 4, "ds3")
	wDelta.KeyFrameCount = 4
	udpPub := pubsub.AttachWriterGroups(pubsub.UDPConnection("pub", rl.URL(), uint16(7)),
		pubsub.WriterGroup("wg", 1, 10*time.Millisecond, pubsub.DataSetWriter("w0", 1, "ds0"), wDV, wRaw, wDelta))
	secPub := pubsub.AttachWriterGroups(pubsub.UDPConnection("secpub", rl.URL(), uint16(8)),
		pubsub.Secure(pubsub.WriterGroup("wgsec", 2, 10*time.Millisecond, pubsub.DataSetWriter("ws", 1, "sec")), ua.MessageSecurityModeSignAndEncrypt, "sg"))
	jsonPub := pubsub.AttachWriterGroups(pubsub.MQTTConnection("jpub", broker.URL(), uint16(9), pubsub.MappingJSON),
		pubsub.JSONWriterGroup("jwg", 1, 10*time.Millisecond, "fz/json", pubsub.SetWriterQueue(pubsub.DataSetWriter("jw", 1, "js"), "fz/json", "fz/json/meta")))
	startRuntime(t, pubsub.NewConfiguration(pdss, udpPub, secPub, jsonPub),
		pubsub.WithDataSource(newCounterSource()), pubsub.WithKeySource("sg", keySource(t, ks, "sg")))

	chk.waitGrowth(t, 5, "sec")
	if !chaoskit.Eventually(settle, func() bool {
		jsonMu.Lock()
		defer jsonMu.Unlock()
		return len(jsonSeeds) >= 4 && len(rl.captured()) >= 32
	}) {
		t.Fatal("no seeds captured")
	}

	inj, err := imqtt.Dial(context.Background(), imqtt.Options{Server: broker.URL(), ClientID: "fuzzer"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = inj.Close() }()

	topics := []string{"fz/json", "fz/json/meta", "fz/other"}
	var sent int
	end := time.Now().Add(chaoskit.Duration(t, defaultDuration))
	for time.Now().Before(end) {
		udpSeeds := rl.captured()
		jsonMu.Lock()
		js := append([][]byte(nil), jsonSeeds...)
		jsonMu.Unlock()
		all := append(append([][]byte(nil), udpSeeds...), js...)
		for range 50 {
			var b []byte
			switch rng.Intn(10) {
			case 0:
				b = randomBytes(rng)
			case 1, 2, 3:
				b = mutate(rng, js[rng.Intn(len(js))], all[rng.Intn(len(all))])
			default:
				b = mutate(rng, udpSeeds[rng.Intn(len(udpSeeds))], all[rng.Intn(len(all))])
			}
			if rng.Intn(3) == 0 {
				_ = inj.Publish(context.Background(), topics[rng.Intn(len(topics))], b, 0, false)
			} else {
				rl.inject(b)
			}
			sent++
		}
		time.Sleep(5 * time.Millisecond)
	}
	root := status(t, sub, pubsub.Root).Counters
	t.Logf("injected %d messages; subscriber: %+v; delivered: %d secured, %d other", sent, root, chk.total.Load(), others.Load())
	if root.DecodeErrors == 0 {
		t.Error("no decode error after fuzzing")
	}

	// The secured reader still delivers (nothing unsigned was taken for
	// it and its sequence state was not disturbed).
	chk.waitGrowth(t, 10, "sec")
	waitState(t, sub, compID(t, sub, pubsub.KindDataSetReader, "sec"), ua.PubSubStateOperational)
	chk.sink.Report(t)
}
