// SPDX-License-Identifier: MIT

package pubsubchaos

import (
	"context"
	"fmt"
	"math/rand"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/ua"
)

// udpPair is a publisher and a subscriber runtime over UDP with a fault
// relay between them. The publisher has one writer group (WriterGroupId 1,
// PublisherId 7) with a writer per data set ds0, ds1, ...; the subscriber
// has a reader per data set.
type udpPair struct {
	pub, sub *pubsub.PubSub
	relay    *relay
	chk      *checker
	states   *stateLog
	readers  []string
	subPort  int
}

type pairOpts struct {
	writers  int
	interval time.Duration
	timeout  time.Duration
	mode     ua.MessageSecurityMode
	// pubKeys and subKeys are the key sources of the SecurityGroup "sg".
	pubKeys, subKeys security.KeySource
	// subMode overrides the security mode of the reader group.
	subMode ua.MessageSecurityMode
	// keyFrameCount of the writers (default 1: key frames only).
	keyFrameCount uint32
	// fieldMask is the DataSetFieldContentMask of the writers and readers.
	fieldMask ua.DataSetFieldContentMask
}

func newUDPPair(t *testing.T, seed int64, o pairOpts) *udpPair {
	t.Helper()
	if o.writers == 0 {
		o.writers = 1
	}
	if o.interval == 0 {
		o.interval = 10 * time.Millisecond
	}
	if o.subMode == 0 {
		o.subMode = o.mode
	}
	p := &udpPair{chk: newChecker(), subPort: freeUDPPort(t)}
	p.states = newStateLog(p.chk.sink)
	p.relay = newRelay(t, seed, p.subPort)

	var pdss []*ua.PublishedDataSetDataType
	var writers []*ua.DataSetWriterDataType
	var readers []*ua.DataSetReaderDataType
	for i := range o.writers {
		ds := fmt.Sprintf("ds%d", i)
		pds := counterPDS(ds)
		pdss = append(pdss, pds)
		w := pubsub.DataSetWriter("w"+ds, uint16(i+1), ds)
		if o.keyFrameCount > 0 {
			w.KeyFrameCount = o.keyFrameCount
		}
		w.DataSetFieldContentMask = o.fieldMask
		writers = append(writers, w)
		r := pubsub.DataSetReader(ds, uint16(7), 1, uint16(i+1), pubsub.DataSetMetaDataOf(pds))
		r.MessageReceiveTimeout = float64(o.timeout) / float64(time.Millisecond)
		r.DataSetFieldContentMask = o.fieldMask
		readers = append(readers, r)
		p.readers = append(p.readers, ds)
	}
	wg := pubsub.WriterGroup("wg", 1, o.interval, writers...)
	rg := pubsub.ReaderGroup("rg", readers...)
	var pubOpts, subOpts []pubsub.Option
	if o.mode > ua.MessageSecurityModeNone {
		pubsub.Secure(wg, o.mode, "sg")
		pubOpts = append(pubOpts, pubsub.WithKeySource("sg", o.pubKeys))
	}
	if o.subMode > ua.MessageSecurityModeNone {
		pubsub.Secure(rg, o.subMode, "sg")
		subOpts = append(subOpts, pubsub.WithKeySource("sg", o.subKeys))
	}
	subOpts = append(subOpts, pubsub.WithDataSetHandler(p.chk.handle), pubsub.WithEventHandler(p.states.handle))
	p.sub = startRuntime(t, pubsub.NewConfiguration(nil, pubsub.AttachReaderGroups(pubsub.UDPConnection("sub", udpURL(p.subPort), nil), rg)), subOpts...)
	pubOpts = append(pubOpts, pubsub.WithDataSource(newCounterSource()))
	p.pub = startRuntime(t, pubsub.NewConfiguration(pdss, pubsub.AttachWriterGroups(pubsub.UDPConnection("pub", p.relay.URL(), uint16(7)), wg)), pubOpts...)
	return p
}

// stopChecking ends the transition checks before the runtimes are closed.
func (p *udpPair) stopChecking() {
	p.states.mu.Lock()
	p.states.stop = true
	p.states.mu.Unlock()
}

// randomFaults picks the next fault of the monkey. secured enables the
// faults that change the contents of a datagram, which only a signature
// can detect.
func randomFaults(rng *rand.Rand, secured bool, timeout time.Duration) (faults, time.Duration) {
	hold := time.Duration(50+rng.Intn(250)) * time.Millisecond
	p := func() float64 { return 0.1 + rng.Float64()*0.5 }
	switch rng.Intn(9) {
	case 0:
		return faults{}, hold
	case 1:
		return faults{drop: p()}, hold
	case 2:
		return faults{dup: p()}, hold
	case 3:
		return faults{reorder: p()}, hold
	case 4:
		return faults{delay: time.Duration(5+rng.Intn(25)) * time.Millisecond}, hold
	case 5:
		return faults{blackhole: true}, timeout*2 + time.Duration(rng.Intn(200))*time.Millisecond
	case 6:
		return faults{truncate: p()}, hold
	case 7:
		if secured {
			return faults{corrupt: p()}, hold
		}
		return faults{drop: p(), dup: p()}, hold
	default:
		f := faults{drop: p() / 2, dup: p() / 2, reorder: p() / 2, truncate: p() / 3}
		if rng.Intn(2) == 0 {
			f.delay = time.Duration(1+rng.Intn(10)) * time.Millisecond
		}
		if secured {
			f.corrupt = p() / 2
		}
		return f, hold
	}
}

// TestChaosUDPNetworkFaults puts a fault relay between a publisher and a
// subscriber that dro, duplicates, reorders, delays, truncates and (with
// message security) corrupts datagrams, and blackholes the path for longer
// than the MessageReceiveTimeout. The subscriber must never deliver a
// corrupt, duplicate or stale data set, its readers must go to Error on a
// timeout and back to Operational, its counters must show the discarded
// and undecodable messages, and it must deliver again once the faults stop.
func TestChaosUDPNetworkFaults(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		mode   ua.MessageSecurityMode
		policy string
	}{
		{"None", ua.MessageSecurityModeNone, ""},
		{"Sign-Aes128", ua.MessageSecurityModeSign, security.PolicyURIAes128CTR},
		{"SignAndEncrypt-Aes256", ua.MessageSecurityModeSignAndEncrypt, security.PolicyURIAes256CTR},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			seed := chaoskit.Seed(t)
			rng := rand.New(rand.NewSource(seed))
			const timeout = 150 * time.Millisecond
			o := pairOpts{writers: 3, timeout: timeout, mode: tc.mode}
			if tc.mode > ua.MessageSecurityModeNone {
				ks := keyService(t, "sg", tc.policy, time.Hour, 2, 2)
				o.pubKeys, o.subKeys = keySource(t, ks, "sg"), keySource(t, ks, "sg")
			}
			p := newUDPPair(t, seed, o)
			p.chk.waitGrowth(t, 5, p.readers...)

			secured := tc.mode > ua.MessageSecurityModeNone
			blackholes := 0
			end := time.Now().Add(chaoskit.Duration(t, defaultDuration))
			for time.Now().Before(end) {
				f, hold := randomFaults(rng, secured, timeout)
				if f.blackhole {
					blackholes++
				}
				t.Logf("%s: %v for %v", time.Now().Format("15:04:05.000"), f, hold)
				p.relay.set(f)
				time.Sleep(hold)
			}
			// A last blackhole that lasts until every reader is in Error:
			// one of a random length may have ended before a reader whose
			// timer was held up by a loaded machine noticed it (or there
			// was none), and the checks below need a timeout.
			t.Logf("%s: blackhole until the readers time out", time.Now().Format("15:04:05.000"))
			p.relay.set(faults{blackhole: true})
			for _, r := range p.readers {
				waitState(t, p.sub, compID(t, p.sub, pubsub.KindDataSetReader, r), ua.PubSubStateError)
			}
			blackholes++
			p.relay.set(faults{})

			// Recovery: every reader delivers again and is Operational.
			p.chk.waitGrowth(t, 10, p.readers...)
			for _, r := range p.readers {
				waitState(t, p.sub, compID(t, p.sub, pubsub.KindDataSetReader, r), ua.PubSubStateOperational)
				if n := p.states.count(r, ua.PubSubStateError); n == 0 {
					t.Errorf("reader %s never went to Error, although the path was blackholed %d times", r, blackholes)
				}
			}
			delivered := p.chk.total.Load()
			root := status(t, p.sub, pubsub.Root).Counters
			t.Logf("relay: forwarded %d dropped %d duplicated %d reordered %d corrupted %d truncated %d",
				p.relay.forwarded.Load(), p.relay.dropped.Load(), p.relay.duplicated.Load(), p.relay.reordered.Load(), p.relay.corrupted.Load(), p.relay.truncated.Load())
			t.Logf("subscriber: %+v", root)
			if p.relay.duplicated.Load() > 10 && root.SequenceDiscards == 0 {
				t.Errorf("%d datagrams were duplicated but no DataSetMessage was discarded", p.relay.duplicated.Load())
			}
			if p.relay.corrupted.Load()+p.relay.truncated.Load() > 10 && root.DecodeErrors == 0 {
				t.Errorf("%d datagrams were corrupted or truncated but there was no decode error", p.relay.corrupted.Load()+p.relay.truncated.Load())
			}
			if root.Timeouts == 0 {
				t.Error("no MessageReceiveTimeout was counted")
			}
			if root.DataSetMessagesReceived < uint64(delivered) {
				t.Errorf("DataSetMessagesReceived %d < %d data sets delivered", root.DataSetMessagesReceived, delivered)
			}
			p.stopChecking()
			p.chk.sink.Report(t)
		})
	}
}

// TestChaosPublisherRestart restarts the publisher process (a new runtime
// whose sequence numbers start again at 1) under a subscriber whose readers
// remember the sequence numbers of the previous one. The readers must take
// the new publisher's messages at the latest after their
// MessageReceiveTimeout.
//
// Each publisher counts from a base of its own. A busy subscriber may still
// be working through datagrams of the previous publisher when the next one
// starts; those are told apart by their counter and kept out of the next
// run's checks, instead of waiting a fixed time for them to arrive.
func TestChaosPublisherRestart(t *testing.T) {
	t.Parallel()
	const timeout = 200 * time.Millisecond
	const runBase = 1 << 32 // counters of run r are r*runBase+1, ...
	stalls := chaoskit.WatchStalls(t)
	port := freeUDPPort(t)
	type run struct {
		chk  *checker
		base int64
	}
	var cur atomic.Pointer[run]
	cur.Store(&run{chk: newChecker()})
	var stale atomic.Int64
	handle := func(d *pubsub.ReceivedDataSet) {
		r := cur.Load()
		if nv := d.Field("n"); nv != nil && nv.Value != nil {
			if n, ok := nv.Value.Value().(int64); ok && n <= r.base {
				stale.Add(1) // a data set of an earlier publisher
				return
			}
		}
		r.chk.handle(d)
	}
	r := pubsub.DataSetReader("ds0", uint16(7), 1, 1, pubsub.DataSetMetaDataOf(counterPDS("ds0")))
	r.MessageReceiveTimeout = float64(timeout / time.Millisecond)
	sub := startRuntime(t, pubsub.NewConfiguration(nil, pubsub.AttachReaderGroups(pubsub.UDPConnection("sub", udpURL(port), nil), pubsub.ReaderGroup("rg", r))),
		pubsub.WithDataSetHandler(handle))
	rid := compID(t, sub, pubsub.KindDataSetReader, "ds0")
	for round := range 3 {
		// Far less than the MessageReceiveTimeout: the reader still has
		// the sequence numbers of the previous run.
		time.Sleep(30 * time.Millisecond)
		chk := newChecker()
		base := int64(round) * runBase
		cur.Store(&run{chk: chk, base: base})
		pub, err := pubsub.New(pubsub.NewConfiguration([]*ua.PublishedDataSetDataType{counterPDS("ds0")},
			pubsub.AttachWriterGroups(pubsub.UDPConnection("pub", udpURL(port), uint16(7)), pubsub.WriterGroup("wg", 1, 10*time.Millisecond, pubsub.DataSetWriter("w", 1, "ds0")))),
			pubsub.WithDataSource(newCounterSourceFrom(base)))
		if err != nil {
			t.Fatal(err)
		}
		begin := time.Now()
		if err := pub.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		if !chaoskit.Eventually(settle, func() bool { return chk.count("ds0") > 0 }) {
			t.Fatalf("round %d: nothing from the restarted publisher", round)
		}
		if d := time.Since(begin); round > 0 && d > timeout+time.Second {
			stalls.SkipIfStalled(t, 500*time.Millisecond, "the first message after a restart is bounded by MessageReceiveTimeout + 1 s")
			t.Errorf("round %d: the first message of the restarted publisher was delivered after %v (MessageReceiveTimeout %v)", round, d, timeout)
		}
		t.Logf("round %d: first data set after %v (%d data sets of earlier publishers delivered so far)", round, time.Since(begin), stale.Load())
		time.Sleep(1500 * time.Millisecond) // the sequence numbers get ahead of the next run's
		closeRuntime(t, pub)
		chk.sink.Report(t)
	}
	waitState(t, sub, rid, ua.PubSubStateError)
}
