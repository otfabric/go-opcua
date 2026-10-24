// SPDX-License-Identifier: MIT

package pubsubchaos

import (
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/uadp"
	"github.com/otfabric/go-opcua/ua"
)

// randomProbe returns a discovery probe for a random publisher (one of
// pubs or another), information and layout.
func randomProbe(rng *rand.Rand, pubs []uint64) []byte {
	req := &message.DiscoveryRequest{ProbeType: message.ProbePublisherInformation, InformationType: message.InformationType(1 + rng.Intn(5))}
	switch rng.Intn(6) {
	case 0:
		req = &message.DiscoveryRequest{ProbeType: message.ProbeFindApplications}
	case 1:
		req.Layout = message.DiscoveryLayoutDotNet
		req.InformationType = message.InformationType(1 + rng.Intn(3))
	}
	for range rng.Intn(4) {
		req.DataSetWriterIDs = append(req.DataSetWriterIDs, uint16(rng.Intn(8)))
	}
	req.WriterGroupID = uint16(rng.Intn(3))
	req.IncludeDataSetWriters = rng.Intn(2) == 0
	req.IncludeWriterGroups = rng.Intn(2) == 0
	pub := uint64(rng.Intn(1000))
	if rng.Intn(2) == 0 {
		pub = pubs[rng.Intn(len(pubs))]
	}
	b, err := uadp.Encode(&message.NetworkMessage{
		Type:        message.NetworkMessageDiscoveryRequest,
		UADPMask:    ua.UADPNetworkMessageContentMaskPublisherID,
		PublisherID: message.NewPublisherID(message.PublisherIDUInt16, pub),
		Request:     req,
	}, nil)
	if err != nil {
		panic(err)
	}
	return b
}

// forgedAnnouncement returns a DataSetMetaData announcement that a
// subscriber must ignore: a bad StatusCode for a real writer, or one of a
// publisher that does not exist.
func forgedAnnouncement(rng *rand.Rand, pubs []uint64, seq uint16) []byte {
	pub := pubs[rng.Intn(len(pubs))]
	status := ua.StatusBadNotFound
	if rng.Intn(3) == 0 {
		pub, status = uint64(1000+rng.Intn(1000)), ua.StatusGood
	}
	md := pubsub.MetaData("forged", pubsub.Field{Name: "x", Type: ua.TypeIDString})
	md.ConfigurationVersion = &ua.ConfigurationVersionDataType{MajorVersion: rng.Uint32(), MinorVersion: rng.Uint32()}
	b, err := uadp.Encode(&message.NetworkMessage{
		Type:        message.NetworkMessageDiscoveryResponse,
		UADPMask:    ua.UADPNetworkMessageContentMaskPublisherID,
		PublisherID: message.NewPublisherID(message.PublisherIDUInt16, pub),
		Discovery: &message.Discovery{
			Type:            message.DiscoveryDataSetMetaData,
			SequenceNumber:  seq,
			DataSetWriterID: uint16(1 + rng.Intn(2)),
			MetaData:        md,
			StatusCode:      status,
		},
	}, nil)
	if err != nil {
		panic(err)
	}
	return b
}

// TestChaosDiscovery runs three publishers and three subscribers on one
// lossy in-memory segment (a multicast group). The readers of the
// subscribers have no DataSetMetaData and learn it through UADP discovery
// (Part 14 §7.2.4.6) while an attacker floods the segment with probes of
// every kind and layout, for the real publishers and for others, with
// forged announcements (bad StatusCodes, unknown publishers) and with
// garbage. Each publisher must stay within its announcement rate limit, the
// subscribers must ignore the forged announcements and never deliver a
// corrupt data set, and every reader must learn its DataSetMetaData and
// deliver data sets with field names once the network is clean again.
func TestChaosDiscovery(t *testing.T) {
	t.Parallel()
	seed := chaoskit.Seed(t)
	rng := rand.New(rand.NewSource(seed))
	seg := mnet.segment(memURL(t))
	seg.seed(seed)
	const rate, burst = 10, 10
	disc := pubsub.WithDiscovery(pubsub.DiscoveryOptions{Rate: rate, Burst: burst, MaxProbeInterval: time.Second})
	pubIDs := []uint64{7, 8, 9}

	start := time.Now()
	var pubs []*pubsub.PubSub
	for _, id := range pubIDs {
		var pdss []*ua.PublishedDataSetDataType
		var ws []*ua.DataSetWriterDataType
		for w := range 2 {
			ds := fmt.Sprintf("p%dw%d", id, w+1)
			pdss = append(pdss, counterPDS(ds))
			ws = append(ws, pubsub.DataSetWriter("w"+ds, uint16(w+1), ds))
		}
		pubs = append(pubs, startRuntime(t, pubsub.NewConfiguration(pdss, pubsub.AttachWriterGroups(
			pubsub.UDPConnection("pub", seg.url, uint16(id)), pubsub.WriterGroup("wg", 1, 20*time.Millisecond, ws...))),
			pubsub.WithDataSource(newCounterSource()), disc))
	}
	type subRT struct {
		rt  *pubsub.PubSub
		chk *checker
	}
	var subs []subRT
	var readers []string
	for s := range 3 {
		var rs []*ua.DataSetReaderDataType
		for _, id := range pubIDs {
			for w := range 2 {
				ds := fmt.Sprintf("p%dw%d", id, w+1)
				rs = append(rs, pubsub.DataSetReader(ds, uint16(id), 1, uint16(w+1), nil))
				if s == 0 {
					readers = append(readers, ds)
				}
			}
		}
		chk := newChecker()
		rt := startRuntime(t, pubsub.NewConfiguration(nil, pubsub.AttachReaderGroups(pubsub.UDPConnection("sub", seg.url, nil), pubsub.ReaderGroup("rg", rs...))),
			pubsub.WithDataSetHandler(chk.handle), disc)
		subs = append(subs, subRT{rt, chk})
	}

	// The attacker.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var probes, forged, garbage atomic.Int64
	wg.Add(1)
	go func() {
		defer wg.Done()
		arng := rand.New(rand.NewSource(seed + 1))
		tk := time.NewTicker(time.Millisecond)
		defer tk.Stop()
		var seq uint16
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
			}
			for range 2 {
				seg.inject(randomProbe(arng, pubIDs))
				probes.Add(1)
			}
			if arng.Intn(4) == 0 {
				seq++
				seg.inject(forgedAnnouncement(arng, pubIDs, seq))
				forged.Add(1)
			}
			if arng.Intn(8) == 0 {
				b := randomProbe(arng, pubIDs)
				b[arng.Intn(len(b))] ^= byte(1 + arng.Intn(255))
				seg.inject(b[:arng.Intn(len(b))+1])
				garbage.Add(1)
			}
		}
	}()

	end := time.Now().Add(chaoskit.Duration(t, defaultDuration))
	for time.Now().Before(end) {
		f := faults{}
		switch rng.Intn(4) {
		case 1:
			f.drop = 0.1 + rng.Float64()*0.3
		case 2:
			f.dup, f.reorder = rng.Float64()*0.3, rng.Float64()*0.3
		case 3:
			f.delay = time.Duration(1+rng.Intn(5)) * time.Millisecond
		}
		seg.set(f)
		time.Sleep(time.Duration(100+rng.Intn(300)) * time.Millisecond)
	}
	seg.set(faults{})
	close(stop)
	wg.Wait()
	elapsed := time.Since(start)

	// Every reader learns its DataSetMetaData and then delivers data sets
	// with the field names.
	for _, s := range subs {
		for _, r := range readers {
			rid := compID(t, s.rt, pubsub.KindDataSetReader, r)
			if !chaoskit.Eventually(settle, func() bool {
				cfg, err := s.rt.DataSetReaderConfig(rid)
				return err == nil && cfg.DataSetMetaData != nil && len(cfg.DataSetMetaData.Fields) == 3 && cfg.DataSetMetaData.Name == dsOfReader(r)
			}) {
				cfg, _ := s.rt.DataSetReaderConfig(rid)
				t.Fatalf("reader %s did not learn its DataSetMetaData: %+v", r, cfg.DataSetMetaData)
			}
		}
		s.chk.waitGrowth(t, 5, readers...)
		s.chk.sink.Report(t)
	}
	t.Logf("attacker: %d probes, %d forged announcements, %d garbage", probes.Load(), forged.Load(), garbage.Load())
	for i, p := range pubs {
		c := status(t, p, pubsub.Root).Counters
		t.Logf("publisher %d: requests %d ignored %d responses %d", pubIDs[i], c.DiscoveryRequestsReceived, c.DiscoveryRequestsIgnored, c.DiscoveryResponsesSent)
		// The token bucket bounds the answers to probes.
		if limit := uint64(burst + rate*elapsed.Seconds() + 1); c.DiscoveryResponsesSent > limit {
			t.Errorf("publisher %d sent %d announcements in %v, limit %d", pubIDs[i], c.DiscoveryResponsesSent, elapsed, limit)
		}
		if c.DiscoveryRequestsIgnored == 0 {
			t.Errorf("publisher %d ignored no probe", pubIDs[i])
		}
		if c.EncodeErrors != 0 || c.SendErrors != 0 {
			t.Errorf("publisher %d: %d encode errors, %d send errors", pubIDs[i], c.EncodeErrors, c.SendErrors)
		}
	}
	for i, s := range subs {
		c := status(t, s.rt, pubsub.Root).Counters
		t.Logf("subscriber %d: probes sent %d, announcements received %d, decode errors %d", i, c.DiscoveryRequestsSent, c.DiscoveryResponsesReceived, c.DecodeErrors)
	}

	// After the flood, a new subscriber probes for itself: the rate limits
	// of the publishers have recovered.
	chk := newChecker()
	late := startRuntime(t, pubsub.NewConfiguration(nil, pubsub.AttachReaderGroups(pubsub.UDPConnection("late", seg.url, nil),
		pubsub.ReaderGroup("rg", pubsub.DataSetReader("p8w2", uint16(8), 1, 2, nil)))), pubsub.WithDataSetHandler(chk.handle), disc)
	rid := compID(t, late, pubsub.KindDataSetReader, "p8w2")
	if !chaoskit.Eventually(settle, func() bool {
		cfg, err := late.DataSetReaderConfig(rid)
		return err == nil && cfg.DataSetMetaData != nil && len(cfg.DataSetMetaData.Fields) == 3
	}) {
		t.Fatal("the late subscriber did not learn the DataSetMetaData")
	}
	if c := status(t, late, pubsub.Root).Counters; c.DiscoveryRequestsSent == 0 {
		t.Errorf("the late subscriber learned the DataSetMetaData without a probe: %+v", c)
	}
	chk.waitGrowth(t, 5, "p8w2")
	chk.sink.Report(t)
}

// TestChaosDiscoveryProbeFlood floods a publisher with probes from many
// goroutines at once: the announcements stay within the rate limit and the
// publisher keeps publishing its data at the configured rate.
func TestChaosDiscoveryProbeFlood(t *testing.T) {
	t.Parallel()
	seed := chaoskit.Seed(t)
	seg := mnet.segment(memURL(t))
	pub := startRuntime(t, pubsub.NewConfiguration([]*ua.PublishedDataSetDataType{counterPDS("ds0")}, pubsub.AttachWriterGroups(
		pubsub.UDPConnection("pub", seg.url, uint16(7)), pubsub.WriterGroup("wg", 1, 10*time.Millisecond, pubsub.DataSetWriter("w", 1, "ds0")))),
		pubsub.WithDataSource(newCounterSource()))
	chk := newChecker()
	startRuntime(t, pubsub.NewConfiguration(nil, pubsub.AttachReaderGroups(pubsub.UDPConnection("sub", seg.url, nil),
		pubsub.ReaderGroup("rg", pubsub.DataSetReader("ds0", uint16(7), 1, 1, pubsub.DataSetMetaDataOf(counterPDS("ds0")))))),
		pubsub.WithDataSetHandler(chk.handle), pubsub.WithDiscovery(pubsub.DiscoveryOptions{Disabled: true}))
	chk.waitGrowth(t, 3, "ds0")

	start := time.Now()
	before := status(t, pub, pubsub.Root).Counters
	var wg sync.WaitGroup
	const workers, each = 8, 1500
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed + int64(w)))
			for range each {
				seg.injectSync(randomProbe(rng, []uint64{7}))
			}
		}()
	}
	if !chaoskit.WaitGroupTimeout(&wg, chaoskit.OpLimit) {
		t.Fatalf("DEADLOCK: probe flood did not finish\n%s", chaoskit.AllStacks())
	}
	elapsed := time.Since(start)
	c := status(t, pub, pubsub.Root).Counters
	got := c.DiscoveryResponsesSent - before.DiscoveryResponsesSent
	// Default limits: 20 per second in bursts of 20.
	if limit := uint64(20 + 20*elapsed.Seconds() + 1); got > limit {
		t.Errorf("%d announcements in %v, limit %d", got, elapsed, limit)
	}
	if n := c.DiscoveryRequestsReceived - before.DiscoveryRequestsReceived; n != workers*each {
		t.Errorf("%d probes received, want %d", n, workers*each)
	}
	t.Logf("%d probes in %v: %d announcements, %d ignored", workers*each, elapsed, got, c.DiscoveryRequestsIgnored-before.DiscoveryRequestsIgnored)
	chk.waitGrowth(t, 10, "ds0")
	chk.sink.Report(t)
}
