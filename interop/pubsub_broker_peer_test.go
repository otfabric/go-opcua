//go:build interop

// SPDX-License-Identifier: MIT

// PubSub through real brokers (Part 14 §7.3.4, Annex B.3).
// COVERAGE.md: pubsub / pubsub.mqtt5, pubsub.amqp
//
// MQTT 5.0: go-opcua speaks MQTT 5.0 to Eclipse Mosquitto while the
// open62541 adapter speaks 3.1.1 to the same broker, in both directions.
// The go-opcua messages carry the content type of their mapping and the
// UAMessageType user property (§7.3.4.8, §7.3.4.9), checked by a second
// MQTT 5.0 listener; open62541's 3.1.1 messages carry neither and go-opcua
// decodes them by their payload.
//
// AMQP 1.0: open62541 1.5.9 has no AMQP transport, so a go-opcua publisher
// and a go-opcua subscriber exchange UADP (unsecured and SignAndEncrypt) and
// JSON NetworkMessages and DataSetMetaData through RabbitMQ 4 and ActiveMQ
// Artemis, the brokers the transport is written for. This checks the
// addresses, SASL PLAIN, settlement and message properties against real
// brokers rather than the in-process test broker.

package interop

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	iamqp "github.com/otfabric/go-opcua/internal/amqp"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/ua"
)

const (
	// rabbitMQImage and artemisImage are the AMQP 1.0 brokers of the
	// AMQP tests, pinned by digest.
	rabbitMQImage = "rabbitmq:4.1.4-management-alpine@sha256:5cbd7145b0306399ad68422c3350b6cbd1bb95704b39f5896480e5b6d4238a04"
	artemisImage  = "apache/activemq-artemis:2.42.0-alpine@sha256:8e226a9885333ea5140cbedca49ee2db9bd5a59bee80844f8cf984f8e5173276"

	// amqpUser and amqpPassword are the broker credentials (SASL PLAIN).
	amqpUser     = "interop"
	amqpPassword = "interop-pw"
)

// ---------------------------------------------------------------------------
// MQTT 5.0
// ---------------------------------------------------------------------------

// psMQTT5Cases are the mappings of the MQTT 5.0 tests.
func psMQTT5Cases() []psRuntimeCase {
	return []psRuntimeCase{
		{psLiveCase: psLiveCase{name: "uadp", vars: psVars}, mqtt: true},
		{psLiveCase: psLiveCase{name: "json", vars: psVars}, mqtt: true, json: true},
	}
}

// TestPubSubMQTT5_GoPublishes_Open62541Subscribes: a go-opcua server
// publishes over MQTT 5.0 with ExactlyOnce (QoS 2); the open62541
// subscriber (MQTT 3.1.1) writes the values into its TargetVariables, and
// an MQTT 5.0 listener sees the content type and UAMessageType.
func TestPubSubMQTT5_GoPublishes_Open62541Subscribes(t *testing.T) {
	requirePubSubServer(t)
	broker := startMosquitto(t)
	for _, c := range psMQTT5Cases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			topic := fmt.Sprintf("go-opcua-interop/mqtt5/%s/%d", c.name, psFresh())
			connURL := fmt.Sprintf("mqtt://127.0.0.1:%d", broker)
			sub := startPubSubServer(t, pubsubServerOpts{config: psSubscriberConfig(c.psLiveCase, c.profile(),
				fmt.Sprintf("mqtt://host.docker.internal:%d", broker), eo("i=15670", jobj{"QueueName": topic}), c.json)})
			listen := psListen(t, transport.Config{ProfileURI: c.profile(), URL: connURL, MQTTVersion: pubsub.MQTTVersion5}, topic)

			pub := startGoPubSubServer(t, goPubSubOpts{}, func(p *pubsub.PubSub, ns uint16) {
				mustOK[pubsub.ComponentID](t)(p.AddPublishedDataSet(psRuntimeDataSet(c.vars, ns, 0)))
				w := pubsub.DataSetWriter("InteropWriter", psWriterID, "InteropDataSet")
				mapping := pubsub.MappingUADP
				var wg *ua.WriterGroupDataType
				if c.json {
					mapping = pubsub.MappingJSON
					wg = pubsub.JSONWriterGroup("InteropWriterGroup", psWriterGroupID, 100*time.Millisecond, topic, w)
					wg.TransportSettings.Value.(*ua.BrokerWriterGroupTransportDataType).RequestedDeliveryGuarantee = ua.BrokerTransportQoSExactlyOnce
				} else {
					w = pubsub.SetWriterQueue(w, topic, "")
					w.TransportSettings.Value.(*ua.BrokerDataSetWriterTransportDataType).RequestedDeliveryGuarantee = ua.BrokerTransportQoSExactlyOnce
					wg = pubsub.WriterGroup("InteropWriterGroup", psWriterGroupID, 100*time.Millisecond, w)
				}
				conn := pubsub.SetMQTTVersion(pubsub.MQTTConnection("InteropPublisher", connURL, uint16(psPubID), mapping), pubsub.MQTTVersion5)
				mustOK[pubsub.ComponentID](t)(p.AddConnection(pubsub.AttachWriterGroups(conn, wg)))
			})
			values := psValues(c.vars, psFresh())
			writePubSubVars(t, pub.endpoint, c.vars, values)
			waitPubSubVars(t, sub.endpoint, c.vars, values, psReceiveTimeout)

			select {
			case m := <-listen:
				want := transport.ContentTypeUADP
				if c.json {
					want = transport.ContentTypeJSON
				}
				if m.ContentType != want {
					t.Errorf("content type %q, want %q", m.ContentType, want)
				}
				if mt, _ := m.UserProperty(transport.UAMessageTypeProperty); mt != transport.MessageTypeData {
					t.Errorf("UAMessageType %q, want %q", mt, transport.MessageTypeData)
				}
			case <-time.After(psReceiveTimeout):
				t.Fatal("the MQTT 5.0 listener received nothing")
			}
		})
	}
}

// TestPubSubMQTT5_Open62541Publishes_GoSubscribes: open62541 publishes
// over MQTT 3.1.1; a go-opcua runtime subscribed over MQTT 5.0 receives the
// DataSets although the messages carry no content type.
func TestPubSubMQTT5_Open62541Publishes_GoSubscribes(t *testing.T) {
	requirePubSubServer(t)
	broker := startMosquitto(t)
	for _, c := range psMQTT5Cases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			topic := fmt.Sprintf("go-opcua-interop/mqtt5-sub/%s/%d", c.name, psFresh())
			pub, url := psStartAdapterPublisher(t, c, broker, topic)
			rec := newPSDataSets()
			conn := pubsub.SetMQTTVersion(psRuntimeSubConnection(c, url), pubsub.MQTTVersion5)
			startRuntime(t, pubsub.NewConfiguration(nil, pubsub.AttachReaderGroups(conn, psRuntimeReader(c, topic, 0))),
				pubsub.WithDataSetHandler(rec.handle))
			values := psValues(c.vars, psFresh())
			writePubSubVars(t, pub.endpoint, c.vars, values)
			rec.wait(t, c.vars, values, psReceiveTimeout)
		})
	}
}

// ---------------------------------------------------------------------------
// AMQP 1.0
// ---------------------------------------------------------------------------

// amqpBroker is a running AMQP broker: url is the amqp:// URL of the host
// port, props the connection properties a PubSubConnection needs, and
// queue turns a queue name into the broker's address of it (declaring it
// where the broker needs that).
type amqpBroker struct {
	url   string
	props map[string]string
	queue func(t *testing.T, name string) string
}

// startBrokerContainer runs image with env and the published ports and
// returns the host ports in the order of containerPorts. The container is
// stopped when the test ends and its log printed if the test failed.
func startBrokerContainer(t *testing.T, suffix, image string, env []string, containerPorts ...int) []int {
	t.Helper()
	name := dockerContainerName(t) + "-" + suffix
	args := []string{"run", "--rm", "--name", name}
	var ports []int
	for _, cp := range containerPorts {
		hp := freePort(t)
		ports = append(ports, hp)
		args = append(args, "-p", fmt.Sprintf("%d:%d", hp, cp))
	}
	for _, e := range env {
		args = append(args, "-e", e)
	}
	args = append(args, image)
	var logs bytes.Buffer
	var mu sync.Mutex
	cmd := exec.Command("docker", args...)
	cmd.Stdout = lockedWriter{&mu, &logs}
	cmd.Stderr = lockedWriter{&mu, &logs}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", suffix, err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		dockerStop(name)
		<-done
		if t.Failed() {
			mu.Lock()
			t.Logf("%s log:\n%s", suffix, logs.String())
			mu.Unlock()
		}
	})
	return ports
}

// waitAMQP waits until the broker at u completes an AMQP open with PLAIN.
func waitAMQP(t *testing.T, u string) {
	t.Helper()
	deadline := time.Now().Add(120 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		c, err := iamqp.Dial(ctx, iamqp.Options{Server: u, Username: amqpUser, Password: amqpPassword,
			ConnectTimeout: 5 * time.Second, MaxReconnectDelay: time.Second})
		cancel()
		if err == nil {
			_ = c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("AMQP broker %s not ready: %v", u, err)
		}
		time.Sleep(time.Second)
	}
}

// startRabbitMQ starts RabbitMQ 4, whose AMQP 1.0 addresses are
// /queues/<name> (v2 address format); queues are declared through the
// management API.
func startRabbitMQ(t *testing.T) *amqpBroker {
	t.Helper()
	ports := startBrokerContainer(t, "rabbitmq", rabbitMQImage,
		[]string{"RABBITMQ_DEFAULT_USER=" + amqpUser, "RABBITMQ_DEFAULT_PASS=" + amqpPassword}, 5672, 15672)
	u := fmt.Sprintf("amqp://127.0.0.1:%d", ports[0])
	waitAMQP(t, u)
	mgmt := fmt.Sprintf("http://127.0.0.1:%d", ports[1])
	return &amqpBroker{url: u, queue: func(t *testing.T, name string) string {
		t.Helper()
		deadline := time.Now().Add(60 * time.Second)
		for {
			req, err := http.NewRequest(http.MethodPut, mgmt+"/api/queues/%2F/"+url.PathEscape(name),
				strings.NewReader(`{"durable":false,"auto_delete":false}`))
			if err != nil {
				t.Fatal(err)
			}
			req.SetBasicAuth(amqpUser, amqpPassword)
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err == nil {
				_ = resp.Body.Close()
				if resp.StatusCode/100 == 2 {
					return "/queues/" + name
				}
				err = fmt.Errorf("HTTP %s", resp.Status)
			}
			if time.Now().After(deadline) {
				t.Fatalf("declare queue %s: %v", name, err)
			}
			time.Sleep(500 * time.Millisecond)
		}
	}}
}

// startArtemis starts ActiveMQ Artemis. Its addresses are created when a
// link attaches; the "queue" capability makes them anycast queues, which
// keep messages until a receiver takes them.
func startArtemis(t *testing.T) *amqpBroker {
	t.Helper()
	ports := startBrokerContainer(t, "artemis", artemisImage,
		[]string{"ARTEMIS_USER=" + amqpUser, "ARTEMIS_PASSWORD=" + amqpPassword, "ANONYMOUS_LOGIN=false"}, 5672)
	u := fmt.Sprintf("amqp://127.0.0.1:%d", ports[0])
	waitAMQP(t, u)
	return &amqpBroker{url: u,
		props: map[string]string{"source-capabilities": "queue", "target-capabilities": "queue"},
		queue: func(_ *testing.T, name string) string { return name }}
}

// amqpConnection is a PubSubConnection to b with its credentials and
// connection properties.
func (b *amqpBroker) connection(name string, publisherID any, mapping pubsub.MessageMapping) *ua.PubSubConnectionDataType {
	c := pubsub.AMQPConnection(name, b.url, publisherID, mapping)
	pubsub.SetConnectionProperty(c, "username", amqpUser)
	pubsub.SetConnectionProperty(c, "password", amqpPassword)
	for k, v := range b.props {
		pubsub.SetConnectionProperty(c, k, v)
	}
	return c
}

// psAMQPCase is one AMQP exchange: the mapping, the message security and
// whether the reader starts without DataSetMetaData and learns it from the
// metadata queue.
type psAMQPCase struct {
	name     string
	mapping  pubsub.MessageMapping
	mode     ua.MessageSecurityMode
	learnsMD bool
}

func psAMQPCases() []psAMQPCase {
	return []psAMQPCase{
		{name: "uadp", mapping: pubsub.MappingUADP},
		{name: "uadp-metadata", mapping: pubsub.MappingUADP, learnsMD: true},
		{name: "uadp-sign-and-encrypt", mapping: pubsub.MappingUADP, mode: ua.MessageSecurityModeSignAndEncrypt},
		{name: "json", mapping: pubsub.MappingJSON},
		{name: "json-metadata", mapping: pubsub.MappingJSON, learnsMD: true},
	}
}

// runAMQPCase runs a go-opcua publisher and subscriber of psVars through
// b and waits for the subscriber to receive the published values.
func runAMQPCase(t *testing.T, b *amqpBroker, c psAMQPCase) {
	t.Helper()
	n := psFresh()
	data := b.queue(t, fmt.Sprintf("go-opcua-interop.%s.%d", c.name, n))
	meta := b.queue(t, fmt.Sprintf("go-opcua-interop.%s.%d.meta", c.name, n))

	var opts []pubsub.Option
	if c.mode > ua.MessageSecurityModeNone {
		policy := security.Aes256CTR()
		ring := security.NewKeyRing("InteropGroup", policy)
		key := make([]byte, policy.KeyLength())
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		if err := ring.SetKeys(policy.URI(), 1, [][]byte{key}, time.Hour, time.Hour); err != nil {
			t.Fatal(err)
		}
		opts = append(opts, pubsub.WithKeySource("InteropGroup", ring))
	}

	md := psMetaData(psVars, 0)
	if c.learnsMD {
		md = nil
	}
	r := pubsub.SetReaderQueue(pubsub.DataSetReader("InteropReader", uint16(psPubID), psWriterGroupID, psWriterID, md), data, meta)
	rg := pubsub.ReaderGroup("InteropReaderGroup", r)
	w := pubsub.SetWriterQueue(pubsub.DataSetWriter("InteropWriter", psWriterID, "InteropDataSet"), data, meta)
	var wg *ua.WriterGroupDataType
	if c.mapping == pubsub.MappingJSON {
		wg = pubsub.JSONWriterGroup("InteropWriterGroup", psWriterGroupID, 100*time.Millisecond, data, w)
	} else {
		wg = pubsub.WriterGroup("InteropWriterGroup", psWriterGroupID, 100*time.Millisecond, w)
	}
	if c.mode > ua.MessageSecurityModeNone {
		rg = pubsub.Secure(rg, c.mode, "InteropGroup")
		wg = pubsub.Secure(wg, c.mode, "InteropGroup")
	}

	rec := newPSDataSets()
	sub := startRuntime(t, pubsub.NewConfiguration(nil, pubsub.AttachReaderGroups(b.connection("InteropSubscriber", nil, c.mapping), rg)),
		append([]pubsub.Option{pubsub.WithDataSetHandler(rec.handle)}, opts...)...)

	values := psValues(psVars, n)
	ds := pubsub.NewMemoryDataSource()
	for i, v := range psVars {
		if err := ds.Set(ua.NewStringNodeID(1, "PubSub."+v.name), values[i]); err != nil {
			t.Fatal(err)
		}
	}
	startRuntime(t, pubsub.NewConfiguration([]*ua.PublishedDataSetDataType{psRuntimeDataSet(psVars, 1, 0)},
		pubsub.AttachWriterGroups(b.connection("InteropPublisher", uint16(psPubID), c.mapping), wg)),
		append([]pubsub.Option{pubsub.WithDataSource(ds)}, opts...)...)

	rec.wait(t, psVars, values, psReceiveTimeout)
	st, err := sub.Status(pubsub.Root)
	if err != nil {
		t.Fatal(err)
	}
	if st.Counters.DecodeErrors != 0 {
		var last error
		for _, ci := range sub.Components() {
			if cs, _ := sub.Status(ci.ID); cs.LastError != nil {
				last = cs.LastError
			}
		}
		t.Errorf("%d decode errors, last: %v", st.Counters.DecodeErrors, last)
	}
}

// TestPubSubAMQP_RabbitMQ: go-opcua publishes and subscribes through
// RabbitMQ 4 (AMQP 1.0, v2 addresses /queues/<name>, SASL PLAIN).
func TestPubSubAMQP_RabbitMQ(t *testing.T) {
	b := startRabbitMQ(t)
	for _, c := range psAMQPCases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			runAMQPCase(t, b, c)
		})
	}
}

// TestPubSubAMQP_Artemis: go-opcua publishes and subscribes through
// ActiveMQ Artemis (AMQP 1.0, auto-created anycast addresses, SASL PLAIN).
func TestPubSubAMQP_Artemis(t *testing.T) {
	b := startArtemis(t)
	for _, c := range psAMQPCases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			runAMQPCase(t, b, c)
		})
	}
}
