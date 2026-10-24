// SPDX-License-Identifier: MIT

package pubsubchaos

import (
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/internal/testutil/amqpbroker"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/ua"
)

// TestParallelBrokers runs many publisher and subscriber runtimes at once
// through one AMQP 1.0 broker and one MQTT 5.0 broker (QoS 2): every
// subscriber reads the data sets of every publisher, fanned out by the
// broker, while more runtimes start and close next to them and the brokers
// drop all connections now and then. Every reader must deliver intact data
// sets in order, and deliver again after the last fault.
func TestParallelBrokers(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"AMQP", "MQTT5"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			seed := chaoskit.Seed(t)
			rng := rand.New(rand.NewSource(seed))
			var url string
			var drop func()
			if kind == "AMQP" {
				b := startAMQPBroker(t, amqpbroker.Options{})
				url, drop = b.URL(), b.DropConnections
			} else {
				b := startMQTTBroker(t)
				url, drop = b.URL(), b.DropConnections
			}
			conn := func(name string, pub any) *ua.PubSubConnectionDataType {
				if kind == "AMQP" {
					return pubsub.AMQPConnection(name, url, pub, pubsub.MappingUADP)
				}
				return pubsub.SetMQTTVersion(pubsub.MQTTConnection(name, url, pub, pubsub.MappingUADP), pubsub.MQTTVersion5)
			}
			queue := func(p, w int) string {
				if kind == "AMQP" {
					return fmt.Sprintf("/exchanges/amq.topic/par.p%d.w%d", p, w)
				}
				return fmt.Sprintf("par/p%d/w%d", p, w)
			}
			const pubs, subs, writers = 5, 5, 2
			chk := newChecker()
			readerCfg := func(s int) ([]*ua.DataSetReaderDataType, []string) {
				var rs []*ua.DataSetReaderDataType
				var names []string
				for p := range pubs {
					for w := range writers {
						ds := fmt.Sprintf("p%dw%d", p, w)
						name := fmt.Sprintf("%s|s%d", ds, s)
						rs = append(rs, brokerReader(pubsub.DataSetReader(name, uint16(100+p), 0, uint16(w+1), pubsub.DataSetMetaDataOf(counterPDS(ds))),
							queue(p, w), "", ua.BrokerTransportQoSExactlyOnce))
						names = append(names, name)
					}
				}
				return rs, names
			}
			var readers []string
			var wg sync.WaitGroup
			start := func(f func()) {
				wg.Add(1)
				go func() { defer wg.Done(); f() }()
			}
			for s := range subs {
				rs, names := readerCfg(s)
				startRuntime(t, pubsub.NewConfiguration(nil, pubsub.AttachReaderGroups(conn(fmt.Sprintf("sub%d", s), nil), pubsub.ReaderGroup("rg", rs...))),
					pubsub.WithDataSetHandler(chk.handle))
				readers = append(readers, names...)
			}
			for p := range pubs {
				var pdss []*ua.PublishedDataSetDataType
				var ws []*ua.DataSetWriterDataType
				for w := range writers {
					ds := fmt.Sprintf("p%dw%d", p, w)
					pdss = append(pdss, counterPDS(ds))
					ws = append(ws, brokerWriter(pubsub.DataSetWriter("w"+ds, uint16(w+1), ds), queue(p, w), "", ua.BrokerTransportQoSExactlyOnce))
				}
				startRuntime(t, pubsub.NewConfiguration(pdss, pubsub.AttachWriterGroups(conn(fmt.Sprintf("pub%d", p), uint16(100+p)),
					pubsub.WriterGroup("wg", 1, 20*time.Millisecond, ws...))), pubsub.WithDataSource(newCounterSource()))
			}
			chk.waitGrowth(t, 3, readers...)

			// Short-lived runtimes come and go next to the others, and the
			// broker drops everything now and then.
			stop := make(chan struct{})
			for i := range 3 {
				start(func() {
					r := rand.New(rand.NewSource(seed + int64(i)))
					for n := 0; ; n++ {
						select {
						case <-stop:
							return
						default:
						}
						rs, _ := readerCfg(100 + 10*i + n)
						rt, err := pubsub.New(pubsub.NewConfiguration(nil, pubsub.AttachReaderGroups(conn("tmp", nil), pubsub.ReaderGroup("rg", rs...))),
							pubsub.WithDataSetHandler(chk.handle))
						if err != nil {
							chk.sink.Addf("New: %v", err)
							return
						}
						if err := rt.Start(t.Context()); err != nil {
							chk.sink.Addf("Start: %v", err)
						}
						time.Sleep(time.Duration(50+r.Intn(200)) * time.Millisecond)
						closeRuntime(t, rt)
					}
				})
			}
			end := time.Now().Add(chaoskit.Duration(t, defaultDuration))
			for time.Now().Before(end) {
				time.Sleep(time.Duration(300+rng.Intn(500)) * time.Millisecond)
				drop()
			}
			close(stop)
			if !chaoskit.WaitGroupTimeout(&wg, chaoskit.OpLimit) {
				t.Fatalf("DEADLOCK: runtime churn did not stop\n%s", chaoskit.AllStacks())
			}
			chk.waitGrowth(t, 5, readers...)
			t.Logf("%d data sets delivered", chk.total.Load())
			chk.sink.Report(t)
		})
	}
}
