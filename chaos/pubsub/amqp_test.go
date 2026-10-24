// SPDX-License-Identifier: MIT

package pubsubchaos

import (
	"fmt"
	"math/rand"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	iamqp "github.com/otfabric/go-opcua/internal/amqp"
	"github.com/otfabric/go-opcua/internal/testutil/amqpbroker"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/pubsub/uadp"
	"github.com/otfabric/go-opcua/ua"
)

func startAMQPBroker(t *testing.T, opts amqpbroker.Options) *amqpbroker.Broker {
	t.Helper()
	opts.Logger = chaoskit.Logger()
	b := amqpbroker.New(opts)
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return b
}

// amqpIdle makes the AMQP connections of a runtime ask the broker for
// heartbeats every half second, so that a silent broker is noticed.
func amqpIdle(c *ua.PubSubConnectionDataType) *ua.PubSubConnectionDataType {
	return pubsub.SetConnectionProperty(c, "connection-idle-time-out", uint32(1000))
}

// amqpFault applies one random broker fault and returns its name.
func amqpFault(t *testing.T, rng *rand.Rand, b *amqpbroker.Broker, addresses []string) string {
	t.Helper()
	switch rng.Intn(7) {
	case 0:
		if err := b.Restart(); err != nil {
			t.Fatal(err)
		}
		return "restart"
	case 1:
		d := time.Duration(100+rng.Intn(400)) * time.Millisecond
		b.Stop()
		time.Sleep(d)
		if err := b.Start(); err != nil {
			t.Fatal(err)
		}
		return "down for " + d.String()
	case 2:
		b.DropConnections()
		return "drop connections"
	case 3:
		b.CloseConnections(&iamqp.Error{Condition: "amqp:internal-error", Description: "chaos"})
		return "close connections"
	case 4:
		a := addresses[rng.Intn(len(addresses))]
		n := b.DetachLinks(a, &iamqp.Error{Condition: "amqp:link:detach-forced", Description: "chaos"})
		return fmt.Sprintf("detach %d links of %s", n, a)
	case 5:
		d := time.Duration(200+rng.Intn(600)) * time.Millisecond
		b.SetWithholdDispositions(true)
		time.Sleep(d)
		b.SetWithholdDispositions(false)
		return "withhold dispositions for " + d.String()
	default:
		b.SetSilent(true)
		time.Sleep(1500 * time.Millisecond)
		b.SetSilent(false)
		return "silent"
	}
}

// TestChaosAMQPBroker runs a publisher and a subscriber over the in-process
// AMQP 1.0 broker (UADP, UADP with SignAndEncrypt and JSON, at least once,
// the subscriber learning the DataSetMetaData from a metadata queue) while
// the broker restarts, goes down for a while, drops and closes the
// connections, detaches links, withholds its dispositions and stops
// sending heartbeats. The runtimes must reconnect and attach their links
// again; the subscriber must never deliver a corrupt, duplicate (resent
// after a reconnect) or stale data set and must deliver again once the
// faults stop.
func TestChaosAMQPBroker(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		mapping pubsub.MessageMapping
		mode    ua.MessageSecurityMode
	}{
		{"UADP", pubsub.MappingUADP, ua.MessageSecurityModeNone},
		{"UADP-SignAndEncrypt", pubsub.MappingUADP, ua.MessageSecurityModeSignAndEncrypt},
		{"JSON", pubsub.MappingJSON, ua.MessageSecurityModeNone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			seed := chaoskit.Seed(t)
			rng := rand.New(rand.NewSource(seed))
			b := startAMQPBroker(t, amqpbroker.Options{})
			chk := newChecker()
			states := newStateLog(chk.sink)

			const writers = 3
			var pdss []*ua.PublishedDataSetDataType
			var ws []*ua.DataSetWriterDataType
			var rs []*ua.DataSetReaderDataType
			var readers, addresses []string
			for i := range writers {
				ds := fmt.Sprintf("ds%d", i)
				pdss = append(pdss, counterPDS(ds))
				data := fmt.Sprintf("/exchanges/amq.topic/chaos.%s.%s", tc.name, ds)
				meta := fmt.Sprintf("/queues/chaos.%s.%s.meta", tc.name, ds)
				ws = append(ws, pubsub.SetWriterQueue(pubsub.DataSetWriter("w"+ds, uint16(i+1), ds), data, meta))
				r := pubsub.SetReaderQueue(pubsub.DataSetReader(ds, uint16(7), 0, uint16(i+1), nil), data, meta)
				r.MessageReceiveTimeout = 1500
				rs = append(rs, r)
				readers = append(readers, ds)
				addresses = append(addresses, data, meta)
			}
			var wg *ua.WriterGroupDataType
			if tc.mapping == pubsub.MappingJSON {
				wg = pubsub.JSONWriterGroup("wg", 1, 10*time.Millisecond, "/exchanges/amq.topic/chaos.json.group", ws...)
			} else {
				wg = pubsub.WriterGroup("wg", 1, 10*time.Millisecond, ws...)
			}
			rg := pubsub.ReaderGroup("rg", rs...)
			var keys []pubsub.Option
			if tc.mode > ua.MessageSecurityModeNone {
				ks := keyService(t, "sg", security.PolicyURIAes256CTR, time.Hour, 2, 2)
				pubsub.Secure(wg, tc.mode, "sg")
				pubsub.Secure(rg, tc.mode, "sg")
				keys = append(keys, pubsub.WithKeySource("sg", keySource(t, ks, "sg")))
			}
			// A MessageReceiveTimeout starts a reader over (Part 14
			// §7.2.2.3.4). A message whose outcome the broker withheld is
			// sent again after the reconnect (at least once), and a reader
			// that timed out meanwhile takes it a second time: the order is
			// not checked across a timeout.
			onEvent := func(ev pubsub.Event) {
				states.handle(ev)
				if ev.Type == pubsub.EventStateChanged && ev.Component.Kind == pubsub.KindDataSetReader && ev.Component.State == ua.PubSubStateError {
					chk.restart(func() {})
				}
			}
			sub := startRuntime(t, pubsub.NewConfiguration(nil, pubsub.AttachReaderGroups(amqpIdle(pubsub.AMQPConnection("sub", b.URL(), nil, tc.mapping)), rg)),
				append([]pubsub.Option{pubsub.WithDataSetHandler(chk.handle), pubsub.WithEventHandler(onEvent)}, keys...)...)
			pub := startRuntime(t, pubsub.NewConfiguration(pdss, pubsub.AttachWriterGroups(amqpIdle(pubsub.AMQPConnection("pub", b.URL(), uint16(7), tc.mapping)), wg)),
				append([]pubsub.Option{pubsub.WithDataSource(newCounterSource())}, keys...)...)
			chk.waitGrowth(t, 5, readers...)

			end := time.Now().Add(chaoskit.Duration(t, defaultDuration+time.Second))
			for time.Now().Before(end) {
				t.Logf("%s: %s", time.Now().Format("15:04:05.000"), amqpFault(t, rng, b, addresses))
				time.Sleep(time.Duration(100+rng.Intn(400)) * time.Millisecond)
			}

			chk.waitGrowth(t, 20, readers...)
			for _, r := range readers {
				waitState(t, sub, compID(t, sub, pubsub.KindDataSetReader, r), ua.PubSubStateOperational)
			}
			if !chaoskit.Eventually(settle, func() bool { return b.ClientCount() == 2 }) {
				t.Errorf("%d clients connected to the broker, want 2", b.ClientCount())
			}
			t.Logf("publisher: %+v", status(t, pub, pubsub.Root).Counters)
			t.Logf("subscriber: %+v", status(t, sub, pubsub.Root).Counters)
			states.mu.Lock()
			states.stop = true
			states.mu.Unlock()
			chk.sink.Report(t)
		})
	}
}

// lossLog records the counters of the data sets a broker accepted and of
// those a subscriber delivered.
type lossLog struct {
	mu        sync.Mutex
	from      int64 // first counter delivered: what came before had no subscription
	accepted  map[int64]bool
	delivered map[int64]bool
	dups      int
}

func newLossLog() *lossLog {
	return &lossLog{accepted: map[int64]bool{}, delivered: map[int64]bool{}}
}

// counterOf returns the counter n of a UADP NetworkMessage of the counter
// data set with one DataSetMessage, Variant encoded.
func counterOf(payload []byte) (int64, bool) {
	nm, err := uadp.Decode(payload, nil)
	if err != nil || len(nm.Messages) != 1 || len(nm.Messages[0].Fields) == 0 {
		return 0, false
	}
	f := nm.Messages[0].Fields[0]
	if nm.Messages[0].Type != message.DataSetMessageKeyFrame || f.Value == nil || f.Value.Value == nil {
		return 0, false
	}
	n, ok := f.Value.Value.Value().(int64)
	return n, ok
}

func (l *lossLog) accept(payload []byte) {
	n, ok := counterOf(payload)
	if !ok {
		return
	}
	l.mu.Lock()
	l.accepted[n] = true
	l.mu.Unlock()
}

func (l *lossLog) deliver(d *pubsub.ReceivedDataSet) {
	f := d.Field("n")
	if f == nil || f.Value == nil {
		return
	}
	n, _ := f.Value.Value().(int64)
	l.mu.Lock()
	if l.from == 0 {
		l.from = n
	}
	if l.delivered[n] {
		l.dups++
	}
	l.delivered[n] = true
	l.mu.Unlock()
}

// missing returns the counters accepted by the broker after the first
// delivery that the subscriber never delivered, and the number delivered.
func (l *lossLog) missing() ([]int64, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []int64
	for n := range l.accepted {
		if n > l.from && !l.delivered[n] {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out, len(l.delivered)
}

// TestChaosAMQPQueueNoLoss publishes at least once to a queue that a
// subscriber consumes at least once, while the broker (which keeps its
// queues) restarts, goes down, drops and closes connections, detaches the
// links and withholds dispositions. Every message the broker accepted must
// reach the subscriber's DataSetHandler, and none twice: the queue keeps
// what the subscriber did not settle and redelivers it, the subscriber
// settles after its handler, and the reader discards the duplicates of
// messages resent after a reconnect by their sequence numbers.
func TestChaosAMQPQueueNoLoss(t *testing.T) {
	t.Parallel()
	seed := chaoskit.Seed(t)
	rng := rand.New(rand.NewSource(seed))
	const q = "/queues/chaos.noloss"
	log := newLossLog()
	b := startAMQPBroker(t, amqpbroker.Options{OnMessage: func(address string, m *iamqp.Message, settled bool) {
		if address == q && !settled {
			log.accept(m.Payload())
		}
	}})
	chk := newChecker()
	md := pubsub.DataSetMetaDataOf(counterPDS("ds0"))
	sub := startRuntime(t, pubsub.NewConfiguration(nil, pubsub.AttachReaderGroups(amqpIdle(pubsub.AMQPConnection("sub", b.URL(), nil, pubsub.MappingUADP)),
		pubsub.ReaderGroup("rg", pubsub.SetReaderQueue(pubsub.DataSetReader("ds0", uint16(7), 0, 1, md), q, "")))),
		pubsub.WithDataSetHandler(func(d *pubsub.ReceivedDataSet) { chk.handle(d); log.deliver(d) }))
	pub := startRuntime(t, pubsub.NewConfiguration([]*ua.PublishedDataSetDataType{counterPDS("ds0")}, pubsub.AttachWriterGroups(
		amqpIdle(pubsub.AMQPConnection("pub", b.URL(), uint16(7), pubsub.MappingUADP)),
		pubsub.WriterGroup("wg", 1, 10*time.Millisecond, pubsub.SetWriterQueue(pubsub.DataSetWriter("w", 1, "ds0"), q, "")))),
		pubsub.WithDataSource(newCounterSource()))
	chk.waitGrowth(t, 5, "ds0")

	end := time.Now().Add(chaoskit.Duration(t, defaultDuration+time.Second))
	for time.Now().Before(end) {
		var f string
		switch rng.Intn(5) {
		case 0:
			if err := b.Restart(); err != nil {
				t.Fatal(err)
			}
			f = "restart"
		case 1:
			b.Stop()
			time.Sleep(time.Duration(100+rng.Intn(300)) * time.Millisecond)
			if err := b.Start(); err != nil {
				t.Fatal(err)
			}
			f = "down"
		case 2:
			b.DropConnections()
			f = "drop"
		case 3:
			n := b.DetachLinks(q, &iamqp.Error{Condition: "amqp:link:detach-forced"})
			f = fmt.Sprintf("detach %d", n)
		default:
			b.SetWithholdDispositions(true)
			time.Sleep(time.Duration(100+rng.Intn(400)) * time.Millisecond)
			b.SetWithholdDispositions(false)
			b.DropConnections() // withheld dispositions are lost: the clients resend
			f = "withhold"
		}
		t.Logf("%s: %s", time.Now().Format("15:04:05.000"), f)
		time.Sleep(time.Duration(100+rng.Intn(300)) * time.Millisecond)
	}
	chk.waitGrowth(t, 10, "ds0")

	// Stop publishing; the queue drains into the subscriber.
	closeRuntime(t, pub)
	var missing []int64
	var delivered int
	ok := chaoskit.Eventually(settle, func() bool {
		missing, delivered = log.missing()
		return len(missing) == 0 && b.Queued(q) == 0
	})
	t.Logf("broker received %d messages; %d data sets delivered, %d duplicates; subscriber %+v", b.Received(), delivered, log.dups, status(t, sub, pubsub.Root).Counters)
	if !ok {
		t.Errorf("%d messages accepted by the broker were never delivered (%d still queued): %v", len(missing), b.Queued(q), missing)
	}
	if log.dups > 0 {
		t.Errorf("%d data sets were delivered twice", log.dups)
	}
	chk.sink.Report(t)
}

// TestChaosBrokerCloseDuringReconnect closes publishers and subscribers
// while their broker connections are down and reconnecting (AMQP and MQTT
// 5.0), also while the broker comes back in the middle of the Close. Close
// must return within the bound and leave no goroutine behind.
func TestChaosBrokerCloseDuringReconnect(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"AMQP", "MQTT5"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			seed := chaoskit.Seed(t)
			rng := rand.New(rand.NewSource(seed))
			var url string
			var stop func()
			var start func() error
			switch kind {
			case "AMQP":
				b := startAMQPBroker(t, amqpbroker.Options{})
				url, stop, start = b.URL(), b.Stop, b.Start
			default:
				b := startMQTTBroker(t)
				url, stop, start = b.URL(), b.Stop, b.Start
			}
			conn := func(name string, pub any) *ua.PubSubConnectionDataType {
				if kind == "AMQP" {
					return amqpIdle(pubsub.AMQPConnection(name, url, pub, pubsub.MappingUADP))
				}
				return pubsub.SetMQTTVersion(pubsub.MQTTConnection(name, url, pub, pubsub.MappingUADP), pubsub.MQTTVersion5)
			}
			for round := range 4 {
				q := fmt.Sprintf("/queues/close.%d", round)
				chk := newChecker()
				sub, err := pubsub.New(pubsub.NewConfiguration(nil, pubsub.AttachReaderGroups(conn("sub", nil),
					pubsub.ReaderGroup("rg", pubsub.SetReaderQueue(pubsub.DataSetReader("ds0", uint16(7), 0, 1, pubsub.DataSetMetaDataOf(counterPDS("ds0"))), q, "")))),
					pubsub.WithDataSetHandler(chk.handle), pubsub.WithRetryInterval(50*time.Millisecond))
				if err != nil {
					t.Fatal(err)
				}
				pub, err := pubsub.New(pubsub.NewConfiguration([]*ua.PublishedDataSetDataType{counterPDS("ds0")}, pubsub.AttachWriterGroups(conn("pub", uint16(7)),
					pubsub.WriterGroup("wg", 1, 10*time.Millisecond, pubsub.SetWriterQueue(pubsub.DataSetWriter("w", 1, "ds0"), q, "")))),
					pubsub.WithDataSource(newCounterSource()), pubsub.WithRetryInterval(50*time.Millisecond))
				if err != nil {
					t.Fatal(err)
				}
				for _, rt := range []*pubsub.PubSub{sub, pub} {
					if err := rt.Start(t.Context()); err != nil {
						t.Fatal(err)
					}
				}
				chk.waitGrowth(t, 3, "ds0")
				stop()
				time.Sleep(time.Duration(50+rng.Intn(300)) * time.Millisecond)
				var restarted atomic.Bool
				var wg sync.WaitGroup
				if round%2 == 1 {
					// The broker comes back while the runtimes close.
					d := time.Duration(rng.Intn(20)) * time.Millisecond
					wg.Add(1)
					go func() {
						defer wg.Done()
						time.Sleep(d)
						if err := start(); err == nil {
							restarted.Store(true)
						}
					}()
				}
				for _, rt := range []*pubsub.PubSub{pub, sub} {
					wg.Add(1)
					go func() {
						defer wg.Done()
						closeRuntime(t, rt)
					}()
				}
				if !chaoskit.WaitGroupTimeout(&wg, chaoskit.OpLimit) {
					t.Fatalf("DEADLOCK: Close during reconnect\n%s", chaoskit.AllStacks())
				}
				if !restarted.Load() {
					if err := start(); err != nil {
						t.Fatal(err)
					}
				}
				chk.sink.Report(t)
			}
		})
	}
}
