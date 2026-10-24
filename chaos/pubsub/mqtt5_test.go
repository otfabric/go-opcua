// SPDX-License-Identifier: MIT

package pubsubchaos

import (
	"fmt"
	"math/rand"
	"sync/atomic"
	"testing"
	"time"

	imqtt "github.com/otfabric/go-opcua/internal/mqtt"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/internal/testutil/mqttbroker"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/ua"
)

func startMQTTBroker(t *testing.T, opts ...mqttbroker.Options) *mqttbroker.Broker {
	t.Helper()
	var o mqttbroker.Options
	if len(opts) > 0 {
		o = opts[0]
	}
	o.Logger = chaoskit.Logger()
	b := mqttbroker.New(o)
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return b
}

// mqtt5Conn returns an MQTT 5.0 connection with a fixed client id and a
// session the broker keeps for a minute.
func mqtt5Conn(name, url, clientID string, pub any, mapping pubsub.MessageMapping) *ua.PubSubConnectionDataType {
	c := pubsub.SetMQTTVersion(pubsub.MQTTConnection(name, url, pub, mapping), pubsub.MQTTVersion5)
	pubsub.SetConnectionProperty(c, "client-id", clientID)
	pubsub.SetConnectionProperty(c, "connection-Session Expiry Interval", uint32(60))
	return c
}

func brokerWriter(w *ua.DataSetWriterDataType, queue, meta string, qos ua.BrokerTransportQoS) *ua.DataSetWriterDataType {
	w.TransportSettings = ua.NewExtensionObject(&ua.BrokerDataSetWriterTransportDataType{QueueName: queue, MetaDataQueueName: meta, RequestedDeliveryGuarantee: qos})
	return w
}

func brokerReader(r *ua.DataSetReaderDataType, queue, meta string, qos ua.BrokerTransportQoS) *ua.DataSetReaderDataType {
	r.TransportSettings = ua.NewExtensionObject(&ua.BrokerDataSetReaderTransportDataType{QueueName: queue, MetaDataQueueName: meta, RequestedDeliveryGuarantee: qos})
	return r
}

var mqttKeepAlive = pubsub.WithTransportConfig(func(_ *ua.PubSubConnectionDataType, cfg *transport.Config) {
	cfg.KeepAlive = time.Second
})

// mqtt5Fault applies one random fault to an MQTT broker whose clients are
// clientIDs. withReset allows the broker to forget its sessions.
func mqtt5Fault(t *testing.T, rng *rand.Rand, b *mqttbroker.Broker, refuse *atomic.Bool, withReset bool, clientIDs ...string) string {
	t.Helper()
	n := 6
	if withReset {
		n = 7
	}
	switch rng.Intn(n) {
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
		id := clientIDs[rng.Intn(len(clientIDs))]
		reason := []byte{imqtt.ReasonServerBusy, imqtt.ReasonAdministrativeAction, imqtt.ReasonServerShuttingDown, imqtt.ReasonKeepAliveTimeout}[rng.Intn(4)]
		b.Disconnect(id, reason, "chaos")
		return fmt.Sprintf("disconnect %s with 0x%02x", id, reason)
	case 4:
		b.SetIgnorePings(true)
		time.Sleep(2500 * time.Millisecond)
		b.SetIgnorePings(false)
		return "ignore pings"
	case 5:
		if refuse == nil {
			b.DropConnections()
			return "drop connections"
		}
		d := time.Duration(100+rng.Intn(300)) * time.Millisecond
		refuse.Store(true)
		time.Sleep(d)
		refuse.Store(false)
		return "refuse publications for " + d.String()
	default:
		b.Stop()
		b.Reset()
		if err := b.Start(); err != nil {
			t.Fatal(err)
		}
		return "forget sessions"
	}
}

// TestChaosMQTT5Broker runs a publisher and a subscriber over the in-process
// broker with MQTT 5.0 (persistent sessions, QoS 1 and 2, UADP and JSON, the
// subscriber learning the DataSetMetaData from the retained metadata) while
// the broker restarts, goes down, drops connections, disconnects clients
// with reason codes, stops answering pings, refuses publications with a
// reason code and forgets its sessions. The runtimes must reconnect and
// subscribe again; the subscriber must never deliver a corrupt, duplicate
// (redelivered) or stale data set.
func TestChaosMQTT5Broker(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		mapping pubsub.MessageMapping
		qos     ua.BrokerTransportQoS
	}{
		{"UADP-QoS1", pubsub.MappingUADP, ua.BrokerTransportQoSAtLeastOnce},
		{"UADP-QoS2", pubsub.MappingUADP, ua.BrokerTransportQoSExactlyOnce},
		{"JSON-QoS2", pubsub.MappingJSON, ua.BrokerTransportQoSExactlyOnce},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			seed := chaoskit.Seed(t)
			rng := rand.New(rand.NewSource(seed))
			var refuse atomic.Bool
			b := startMQTTBroker(t, mqttbroker.Options{RefusePublish: func(_, _ string) byte {
				if refuse.Load() {
					return imqtt.ReasonQuotaExceeded
				}
				return 0
			}})
			chk := newChecker()
			states := newStateLog(chk.sink)
			var pdss []*ua.PublishedDataSetDataType
			var ws []*ua.DataSetWriterDataType
			var rs []*ua.DataSetReaderDataType
			var readers []string
			for i := range 3 {
				ds := fmt.Sprintf("ds%d", i)
				pdss = append(pdss, counterPDS(ds))
				q := fmt.Sprintf("chaos5/%s/%s", tc.name, ds)
				ws = append(ws, brokerWriter(pubsub.DataSetWriter("w"+ds, uint16(i+1), ds), q, q+"/meta", tc.qos))
				r := brokerReader(pubsub.DataSetReader(ds, uint16(7), 0, uint16(i+1), nil), q, q+"/meta", tc.qos)
				r.MessageReceiveTimeout = 1500
				rs = append(rs, r)
				readers = append(readers, ds)
			}
			var wg *ua.WriterGroupDataType
			if tc.mapping == pubsub.MappingJSON {
				wg = pubsub.JSONWriterGroup("wg", 1, 10*time.Millisecond, "chaos5/"+tc.name+"/group", ws...)
			} else {
				wg = pubsub.WriterGroup("wg", 1, 10*time.Millisecond, ws...)
			}
			sub := startRuntime(t, pubsub.NewConfiguration(nil, pubsub.AttachReaderGroups(mqtt5Conn("sub", b.URL(), "chaos-sub", nil, tc.mapping),
				pubsub.ReaderGroup("rg", rs...))), pubsub.WithDataSetHandler(chk.handle), pubsub.WithEventHandler(states.handle), mqttKeepAlive)
			pub := startRuntime(t, pubsub.NewConfiguration(pdss, pubsub.AttachWriterGroups(mqtt5Conn("pub", b.URL(), "chaos-pub", uint16(7), tc.mapping), wg)),
				pubsub.WithDataSource(newCounterSource()), mqttKeepAlive)
			chk.waitGrowth(t, 5, readers...)

			end := time.Now().Add(chaoskit.Duration(t, defaultDuration+time.Second))
			for time.Now().Before(end) {
				t.Logf("%s: %s", time.Now().Format("15:04:05.000"), mqtt5Fault(t, rng, b, &refuse, true, "chaos-sub", "chaos-pub"))
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

// TestChaosMQTT5NoLoss publishes with QoS 1 and 2 to a subscriber with a
// persistent MQTT 5.0 session while the broker (which keeps the sessions)
// restarts, goes down, drops connections and disconnects the clients. Every
// publication the broker took must reach the subscriber's DataSetHandler,
// and none twice: the broker keeps them for the session and sends the
// unacknowledged ones again, and the reader discards the redeliveries of
// QoS 1 by their sequence numbers.
func TestChaosMQTT5NoLoss(t *testing.T) {
	t.Parallel()
	for _, qos := range []ua.BrokerTransportQoS{ua.BrokerTransportQoSAtLeastOnce, ua.BrokerTransportQoSExactlyOnce} {
		t.Run(qos.String(), func(t *testing.T) {
			t.Parallel()
			seed := chaoskit.Seed(t)
			rng := rand.New(rand.NewSource(seed))
			q := "chaos5/noloss/" + qos.String()
			log := newLossLog()
			b := startMQTTBroker(t, mqttbroker.Options{OnPublish: func(_ string, p *imqtt.Publish) {
				if p.Topic == q && p.QoS > 0 {
					log.accept(p.Payload)
				}
			}})
			chk := newChecker()
			md := pubsub.DataSetMetaDataOf(counterPDS("ds0"))
			sub := startRuntime(t, pubsub.NewConfiguration(nil, pubsub.AttachReaderGroups(mqtt5Conn("sub", b.URL(), "noloss-sub", nil, pubsub.MappingUADP),
				pubsub.ReaderGroup("rg", brokerReader(pubsub.DataSetReader("ds0", uint16(7), 0, 1, md), q, "", qos)))),
				pubsub.WithDataSetHandler(func(d *pubsub.ReceivedDataSet) { chk.handle(d); log.deliver(d) }), mqttKeepAlive)
			// The subscription exists before anything is published.
			if !chaoskit.Eventually(settle, func() bool { return b.ClientCount() == 1 }) {
				t.Fatal("the subscriber did not connect")
			}
			time.Sleep(100 * time.Millisecond)
			pub := startRuntime(t, pubsub.NewConfiguration([]*ua.PublishedDataSetDataType{counterPDS("ds0")}, pubsub.AttachWriterGroups(
				mqtt5Conn("pub", b.URL(), "noloss-pub", uint16(7), pubsub.MappingUADP),
				pubsub.WriterGroup("wg", 1, 10*time.Millisecond, brokerWriter(pubsub.DataSetWriter("w", 1, "ds0"), q, "", qos)))),
				pubsub.WithDataSource(newCounterSource()), mqttKeepAlive)
			chk.waitGrowth(t, 5, "ds0")

			end := time.Now().Add(chaoskit.Duration(t, defaultDuration+time.Second))
			for time.Now().Before(end) {
				t.Logf("%s: %s", time.Now().Format("15:04:05.000"), mqtt5Fault(t, rng, b, nil, false, "noloss-sub", "noloss-pub"))
				time.Sleep(time.Duration(100+rng.Intn(300)) * time.Millisecond)
			}
			chk.waitGrowth(t, 10, "ds0")

			closeRuntime(t, pub)
			var missing []int64
			var delivered int
			ok := chaoskit.Eventually(settle, func() bool {
				missing, delivered = log.missing()
				return len(missing) == 0
			})
			t.Logf("broker took %d publications; %d data sets delivered, %d duplicates; subscriber %+v", b.Published(), delivered, log.dups, status(t, sub, pubsub.Root).Counters)
			if !ok {
				t.Errorf("%d publications the broker took were never delivered: %v", len(missing), missing)
			}
			if log.dups > 0 {
				t.Errorf("%d data sets were delivered twice", log.dups)
			}
			chk.sink.Report(t)
		})
	}
}
