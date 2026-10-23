// SPDX-License-Identifier: MIT

package pubsubchaos

import (
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	imqtt "github.com/otfabric/go-opcua/internal/mqtt"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/internal/testutil/mqttbroker"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/pubsub/uadp"
	"github.com/otfabric/go-opcua/ua"
)

// TestChaosMQTTBroker runs a publisher and a subscriber over an in-process
// MQTT broker (UADP and JSON, QoS 1, the subscriber learning the
// DataSetMetaData from the retained metadata messages) while the broker is
// restarted, stopped for a while, forgets its sessions, drops all
// connections and stops answering pings, and while the subscriber consumes
// too slowly for the broker. The runtimes must reconnect, subscribe again
// and resume publishing and receiving; the subscriber must never deliver a
// corrupt, duplicate (QoS 1 redeliveries) or stale data set.
func TestChaosMQTTBroker(t *testing.T) {
	t.Parallel()
	for _, mapping := range []pubsub.MessageMapping{pubsub.MappingUADP, pubsub.MappingJSON} {
		name := map[pubsub.MessageMapping]string{pubsub.MappingUADP: "UADP", pubsub.MappingJSON: "JSON"}[mapping]
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			seed := chaoskit.Seed(t)
			rng := rand.New(rand.NewSource(seed))
			b := mqttbroker.New(mqttbroker.Options{Logger: chaoskit.Logger()})
			if err := b.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(b.Close)

			// A one second keep-alive, so that ignored pings are noticed.
			keepAlive := pubsub.WithTransportConfig(func(_ *ua.PubSubConnectionDataType, cfg *transport.Config) {
				cfg.KeepAlive = time.Second
			})
			chk := newChecker()
			var slow atomic.Int64 // nanoseconds the handler sleeps, once
			handler := func(d *pubsub.ReceivedDataSet) {
				if ns := slow.Swap(0); ns > 0 {
					time.Sleep(time.Duration(ns))
				}
				chk.handle(d)
			}
			states := newStateLog(chk.sink)

			const writers = 3
			var pdss []*ua.PublishedDataSetDataType
			var ws []*ua.DataSetWriterDataType
			var rs []*ua.DataSetReaderDataType
			var readers []string
			for i := range writers {
				ds := fmt.Sprintf("ds%d", i)
				pdss = append(pdss, counterPDS(ds))
				q := fmt.Sprintf("chaos/%s/%s", name, ds)
				ws = append(ws, pubsub.SetWriterQueue(pubsub.DataSetWriter("w"+ds, uint16(i+1), ds), q, q+"/meta"))
				r := pubsub.SetReaderQueue(pubsub.DataSetReader(ds, uint16(7), 0, uint16(i+1), nil), q, q+"/meta")
				r.MessageReceiveTimeout = 1500
				rs = append(rs, r)
				readers = append(readers, ds)
			}
			var wg *ua.WriterGroupDataType
			if mapping == pubsub.MappingJSON {
				wg = pubsub.JSONWriterGroup("wg", 1, 10*time.Millisecond, "chaos/"+name+"/group", ws...)
			} else {
				wg = pubsub.WriterGroup("wg", 1, 10*time.Millisecond, ws...)
			}
			sub := startRuntime(t, pubsub.NewConfiguration(nil, pubsub.AttachReaderGroups(pubsub.MQTTConnection("sub", b.URL(), nil, mapping),
				pubsub.ReaderGroup("rg", rs...))), pubsub.WithDataSetHandler(handler), pubsub.WithEventHandler(states.handle), keepAlive)
			startRuntime(t, pubsub.NewConfiguration(pdss, pubsub.AttachWriterGroups(pubsub.MQTTConnection("pub", b.URL(), uint16(7), mapping), wg)),
				pubsub.WithDataSource(newCounterSource()), keepAlive)
			chk.waitGrowth(t, 5, readers...)

			end := time.Now().Add(chaoskit.Duration(t, defaultDuration+time.Second))
			for time.Now().Before(end) {
				switch rng.Intn(6) {
				case 0:
					t.Log("broker restart")
					if err := b.Restart(); err != nil {
						t.Fatal(err)
					}
				case 1:
					d := time.Duration(100+rng.Intn(400)) * time.Millisecond
					t.Logf("broker down for %v", d)
					b.Stop()
					time.Sleep(d)
					if err := b.Start(); err != nil {
						t.Fatal(err)
					}
				case 2:
					t.Log("broker drops all connections")
					b.DropConnections()
				case 3:
					t.Log("broker forgets its sessions and retained messages and restarts")
					b.Stop()
					b.Reset()
					if err := b.Start(); err != nil {
						t.Fatal(err)
					}
				case 4:
					t.Log("broker ignores pings")
					b.SetIgnorePings(true)
					time.Sleep(2500 * time.Millisecond)
					b.SetIgnorePings(false)
				case 5:
					d := time.Duration(200+rng.Intn(600)) * time.Millisecond
					t.Logf("subscriber stalls for %v", d)
					slow.Store(int64(d))
				}
				time.Sleep(time.Duration(100+rng.Intn(400)) * time.Millisecond)
			}

			// Recovery.
			chk.waitGrowth(t, 20, readers...)
			for _, r := range readers {
				waitState(t, sub, compID(t, sub, pubsub.KindDataSetReader, r), ua.PubSubStateOperational)
			}
			if !chaoskit.Eventually(settle, func() bool { return b.ClientCount() == 2 }) {
				t.Errorf("%d clients connected to the broker, want 2", b.ClientCount())
			}
			t.Logf("subscriber: %+v", status(t, sub, pubsub.Root).Counters)
			states.mu.Lock()
			states.stop = true
			states.mu.Unlock()
			chk.sink.Report(t)
		})
	}
}

// TestChaosMQTTChangeDuringOutage changes a value while the broker is down
// under a QoS 0 writer that sends delta frames (a key frame only every
// 1000 messages): the delta frame with the change cannot be sent, so the
// first data message the publisher gets through after the outage must be
// a key frame with the new value - not a keep-alive, with the change left
// for the next regular key frame 10 s later. (Whether the subscriber gets
// it depends on which client reconnects first: QoS 0 messages for a clean
// session that is not there yet are dropped by the broker.)
func TestChaosMQTTChangeDuringOutage(t *testing.T) {
	t.Parallel()
	ds := pubsub.NewMemoryDataSource()
	node := ua.NewStringNodeID(1, "v")
	if err := ds.Set(node, int32(1)); err != nil {
		t.Fatal(err)
	}
	pds := pubsub.PublishedDataItems("v", pubsub.Var("v", node, ua.TypeIDInt32))
	md := pubsub.DataSetMetaDataOf(pds)
	type seen struct {
		typ message.DataSetMessageType
		v   any
	}
	var mu sync.Mutex
	var restarted bool
	var after []seen
	b := mqttbroker.New(mqttbroker.Options{OnPublish: func(_ string, p *imqtt.Publish) {
		nm, err := uadp.Decode(p.Payload, &uadp.DecodeOptions{MetaData: func(message.PublisherID, uint16, uint16) *ua.DataSetMetaDataType { return md }})
		if err != nil || len(nm.Messages) == 0 {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if !restarted {
			return
		}
		x := seen{typ: nm.Messages[0].Type}
		if f := nm.Messages[0].Fields; len(f) > 0 && f[0].Value != nil && f[0].Value.Value != nil {
			x.v = f[0].Value.Value.Value()
		}
		after = append(after, x)
	}})
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	w := pubsub.SetWriterQueue(pubsub.DataSetWriter("w", 1, "v"), "outage/v", "")
	w.KeyFrameCount = 1000
	w.TransportSettings.Value.(*ua.BrokerDataSetWriterTransportDataType).RequestedDeliveryGuarantee = ua.BrokerTransportQoSBestEffort
	wg := pubsub.WriterGroup("wg", 1, 10*time.Millisecond, w)
	wg.KeepAliveTime = 50
	pub := startRuntime(t, pubsub.NewConfiguration([]*ua.PublishedDataSetDataType{pds},
		pubsub.AttachWriterGroups(pubsub.MQTTConnection("pub", b.URL(), uint16(7), pubsub.MappingUADP), wg)), pubsub.WithDataSource(ds))
	wgID := compID(t, pub, pubsub.KindWriterGroup, "wg")
	if !chaoskit.Eventually(settle, func() bool { return status(t, pub, wgID).Counters.NetworkMessagesSent > 5 }) {
		t.Fatal("the publisher does not send")
	}

	b.Stop()
	// The publisher notices: its keep-alives fail.
	if !chaoskit.Eventually(settle, func() bool { return status(t, pub, wgID).Counters.SendErrors > 0 }) {
		t.Fatal("no send error while the broker is down")
	}
	if err := ds.Set(node, int32(-42)); err != nil {
		t.Fatal(err)
	}
	errs := status(t, pub, wgID).Counters.SendErrors
	if !chaoskit.Eventually(settle, func() bool { return status(t, pub, wgID).Counters.SendErrors > errs+2 }) {
		t.Fatal("no send error while the broker is down")
	}
	mu.Lock()
	restarted = true
	mu.Unlock()
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	var first *seen
	chaoskit.Eventually(5*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		for i := range after {
			if after[i].typ != message.DataSetMessageKeepAlive {
				first = &after[i]
				return true
			}
		}
		return false
	})
	switch {
	case first == nil:
		t.Fatal("the change made during the broker outage was not sent after it")
	case first.typ != message.DataSetMessageKeyFrame || first.v != int32(-42):
		t.Fatalf("first data message after the outage: %v %v, want a key frame with -42", first.typ, first.v)
	}
}

// TestChaosMQTTSubscriptionRefused has the broker refuse the subscriptions
// of the subscriber for a while, also after a reconnect: the subscriber
// must subscribe again and receive once the broker accepts.
func TestChaosMQTTSubscriptionRefused(t *testing.T) {
	t.Parallel()
	var refuse atomic.Bool
	refuse.Store(true)
	b := mqttbroker.New(mqttbroker.Options{RefuseFilter: func(string) bool { return refuse.Load() }})
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	chk := newChecker()
	q := "refused/ds0"
	r := pubsub.SetReaderQueue(pubsub.DataSetReader("ds0", uint16(7), 1, 1, pubsub.DataSetMetaDataOf(counterPDS("ds0"))), q, "")
	startRuntime(t, pubsub.NewConfiguration(nil, pubsub.AttachReaderGroups(pubsub.MQTTConnection("sub", b.URL(), nil, pubsub.MappingUADP),
		pubsub.ReaderGroup("rg", r))), pubsub.WithDataSetHandler(chk.handle))
	startRuntime(t, pubsub.NewConfiguration([]*ua.PublishedDataSetDataType{counterPDS("ds0")},
		pubsub.AttachWriterGroups(pubsub.MQTTConnection("pub", b.URL(), uint16(7), pubsub.MappingUADP),
			pubsub.WriterGroup("wg", 1, 10*time.Millisecond, pubsub.SetWriterQueue(pubsub.DataSetWriter("w", 1, "ds0"), q, "")))),
		pubsub.WithDataSource(newCounterSource()))
	time.Sleep(300 * time.Millisecond)
	if n := chk.count("ds0"); n != 0 {
		t.Fatalf("%d data sets through a refused subscription", n)
	}
	b.DropConnections() // the resubscription after a reconnect is refused, too
	time.Sleep(300 * time.Millisecond)
	refuse.Store(false)
	chk.waitGrowth(t, 10, "ds0")

	// Refused after a reconnect, once the subscription was made.
	refuse.Store(true)
	b.DropConnections()
	time.Sleep(500 * time.Millisecond)
	refuse.Store(false)
	chk.waitGrowth(t, 10, "ds0")
	chk.sink.Report(t)
}
