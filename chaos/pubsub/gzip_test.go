// SPDX-License-Identifier: MIT

package pubsubchaos

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	imqtt "github.com/otfabric/go-opcua/internal/mqtt"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/ua"
)

func gzipBytes(b []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(b)
	_ = zw.Close()
	return buf.Bytes()
}

// forgedGzip returns a message for a gzip compressed JSON subscriber that
// it must reject: a decompression bomb, a truncated or corrupt stream,
// compressed garbage, or compressed broken JSON, with the content type
// application/json+gzip or one that does not fit the payload. The JSON
// inside is always broken: an MQTT 3.1.1 subscriber gets no content type
// and decompresses whatever starts like a gzip stream.
func forgedGzip(rng *rand.Rand, bomb []byte) (payload []byte, contentType string) {
	full := fmt.Sprintf(`{"MessageId":"%d","MessageType":"ua-data","PublisherId":"7","Messages":[{"DataSetWriterId":1,"SequenceNumber":%d,"Payload":{"n":{"Type":8,"Body":"%d"}}}]}`,
		rng.Int(), rng.Intn(1<<16), rng.Int63())
	msg := []byte(full[:len(full)-1-rng.Intn(len(full)/2)])
	gz := gzipBytes(msg)
	switch rng.Intn(6) {
	case 0:
		return bomb, transport.ContentTypeJSONGzip
	case 1:
		return gz[:1+rng.Intn(len(gz)-1)], transport.ContentTypeJSONGzip
	case 2:
		gz[len(gz)-1-rng.Intn(8)] ^= byte(1 + rng.Intn(255)) // CRC-32 or ISIZE
		return gz, transport.ContentTypeJSONGzip
	case 3:
		junk := make([]byte, 1+rng.Intn(512))
		rng.Read(junk)
		return gzipBytes(junk), transport.ContentTypeJSONGzip
	case 4:
		return gz, transport.ContentTypeJSONGzip
	default:
		return gz, transport.ContentTypeJSON
	}
}

// TestChaosGzipJSON runs a publisher that sends gzip compressed JSON
// (JsonCompression gzip, Part 14 §7.3.4.9.1) over MQTT 5.0 to two
// subscribers, one on MQTT 5.0 (which learns the compression from the
// content type) and one on MQTT 3.1.1 (which gets no content type and
// recognises the gzip header), while an attacker floods the data queues
// with decompression bombs, truncated and corrupt gzip streams, compressed
// garbage and content types that do not fit the payload, and the broker
// restarts, drops connections and disconnects the clients. The subscribers
// must never deliver a corrupt, duplicate or stale data set, must keep
// delivering, and must count what they rejected as decode errors, without
// decompressing more than their limit.
func TestChaosGzipJSON(t *testing.T) {
	t.Parallel()
	seed := chaoskit.Seed(t)
	rng := rand.New(rand.NewSource(seed))
	b := startMQTTBroker(t)
	const limit = 64 << 10

	var pdss []*ua.PublishedDataSetDataType
	var ws []*ua.DataSetWriterDataType
	var rs []*ua.DataSetReaderDataType
	var readers, queues []string
	for i := range 3 {
		ds := fmt.Sprintf("gz%d", i)
		pdss = append(pdss, counterPDS(ds))
		q := "chaosgz/" + ds
		queues = append(queues, q)
		ws = append(ws, brokerWriter(pubsub.DataSetWriter("w"+ds, uint16(i+1), ds), q, q+"/meta", ua.BrokerTransportQoSAtLeastOnce))
		r := brokerReader(pubsub.DataSetReader(ds, uint16(7), 0, uint16(i+1), nil), q, q+"/meta", ua.BrokerTransportQoSAtLeastOnce)
		r.MessageReceiveTimeout = 1500
		rs = append(rs, r)
		readers = append(readers, ds)
	}
	// One checker per subscriber: both receive every data set.
	var subs []*pubsub.PubSub
	var chks []*checker
	for _, v := range []string{pubsub.MQTTVersion5, pubsub.MQTTVersion311} {
		c := pubsub.SetMQTTVersion(pubsub.MQTTConnection("sub", b.URL(), nil, pubsub.MappingJSON), v)
		pubsub.SetConnectionProperty(c, "client-id", "chaos-gz-sub-"+v)
		pubsub.SetConnectionProperty(c, "connection-Session Expiry Interval", uint32(60))
		chk := newChecker()
		chks = append(chks, chk)
		subs = append(subs, startRuntime(t, pubsub.NewConfiguration(nil, pubsub.AttachReaderGroups(c,
			pubsub.ReaderGroup("rg", rs...))), pubsub.WithDataSetHandler(chk.handle), pubsub.WithJSONDecompressionLimit(limit), mqttKeepAlive))
	}
	pubConn := pubsub.SetJSONCompression(mqtt5Conn("pub", b.URL(), "chaos-gz-pub", uint16(7), pubsub.MappingJSON), "gzip")
	pub := startRuntime(t, pubsub.NewConfiguration(pdss, pubsub.AttachWriterGroups(pubConn,
		pubsub.JSONWriterGroup("wg", 1, 10*time.Millisecond, "chaosgz/group", ws...))),
		pubsub.WithDataSource(newCounterSource()), mqttKeepAlive)
	for _, chk := range chks {
		chk.waitGrowth(t, 5, readers...)
	}

	// The attacker reconnects on its own after a broker fault.
	att, err := imqtt.Dial(context.Background(), imqtt.Options{Server: b.URL(), ProtocolVersion: imqtt.Version5, ClientID: "chaos-gz-attacker"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = att.Close() })
	bomb := gzipBytes(bytes.Repeat([]byte(" "), 32<<20))
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var forged int
	wg.Add(1)
	go func() {
		defer wg.Done()
		arng := rand.New(rand.NewSource(seed + 1))
		for {
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Millisecond):
			}
			payload, ct := forgedGzip(arng, bomb)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			if att.PublishWith(ctx, queues[arng.Intn(len(queues))], payload, imqtt.PublishOptions{Props: imqtt.Properties{ContentType: &ct}}) == nil {
				forged++
			}
			cancel()
		}
	}()

	end := time.Now().Add(chaoskit.Duration(t, defaultDuration))
	for time.Now().Before(end) {
		t.Logf("%s: %s", time.Now().Format("15:04:05.000"), mqtt5Fault(t, rng, b, nil, false, "chaos-gz-sub-5.0", "chaos-gz-sub-3.1.1", "chaos-gz-pub"))
		time.Sleep(time.Duration(100+rng.Intn(400)) * time.Millisecond)
	}
	close(stop)
	wg.Wait()

	for _, chk := range chks {
		chk.waitGrowth(t, 20, readers...)
	}
	for _, sub := range subs {
		for _, r := range readers {
			waitState(t, sub, compID(t, sub, pubsub.KindDataSetReader, r), ua.PubSubStateOperational)
		}
	}
	pc := status(t, pub, pubsub.Root).Counters
	t.Logf("attacker: %d forged messages; publisher: %+v", forged, pc)
	if pc.EncodeErrors != 0 {
		t.Errorf("publisher: %d encode errors", pc.EncodeErrors)
	}
	for i, sub := range subs {
		c := status(t, sub, pubsub.Root).Counters
		t.Logf("subscriber %d: %+v", i, c)
		if forged > 100 && c.DecodeErrors == 0 {
			t.Errorf("subscriber %d counted no decode errors for %d forged messages", i, forged)
		}
	}
	for _, chk := range chks {
		chk.sink.Report(t)
	}
}
