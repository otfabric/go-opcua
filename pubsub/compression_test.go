// SPDX-License-Identifier: MIT

package pubsub

import (
	"bytes"
	"compress/gzip"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	imqtt "github.com/otfabric/go-opcua/internal/mqtt"
	"github.com/otfabric/go-opcua/internal/testutil/mqttbroker"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/ua"
)

func gzipped(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write(b)
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// wireMessage is a PUBLISH as the broker received it.
type wireMessage struct {
	ct      string
	payload []byte
}

// gzipPair starts a broker, a publisher of one JSON DataSet on a
// connection with the given MQTT version and JsonCompression, and a
// subscriber for each of subVersions. It returns what the broker received
// per topic and the recorders of the subscribers.
func gzipPair(t *testing.T, pubVersion, compression string, subVersions ...string) (func(topic string) (wireMessage, bool), []*recorder) {
	t.Helper()
	var mu sync.Mutex
	wire := map[string]wireMessage{}
	b := mqttbroker.New(mqttbroker.Options{OnPublish: func(_ string, p *imqtt.Publish) {
		m := wireMessage{payload: append([]byte(nil), p.Payload...)}
		if p.Props.ContentType != nil {
			m.ct = *p.Props.ContentType
		}
		mu.Lock()
		wire[p.Topic] = m
		mu.Unlock()
	}})
	require.NoError(t, b.Start())
	t.Cleanup(b.Close)

	ds := NewMemoryDataSource()
	require.NoError(t, ds.Set(nodeA, int32(7)))
	// A string that compresses well, so the compressed message is
	// visibly smaller.
	require.NoError(t, ds.Set(nodeB, strings.Repeat("compress me ", 64)))
	pds := PublishedDataItems("pds", Var("a", nodeA, ua.TypeIDInt32), Var("b", nodeB, ua.TypeIDString))
	w := SetWriterQueue(DataSetWriter("w", 1, "pds"), "gz/data", "gz/meta")
	pubConn := SetJSONCompression(SetMQTTVersion(MQTTConnection("pub", b.URL(), "pgz", MappingJSON), pubVersion), compression)
	pub, err := New(NewConfiguration([]*ua.PublishedDataSetDataType{pds},
		AttachWriterGroups(pubConn, JSONWriterGroup("wg", 1, 10*time.Millisecond, "gz/group", w))), WithDataSource(ds))
	require.NoError(t, err)
	require.NoError(t, pub.Start(context.Background()))
	t.Cleanup(func() { _ = pub.Close() })

	var recs []*recorder
	for i, v := range subVersions {
		rec := &recorder{}
		subConn := SetMQTTVersion(MQTTConnection("sub"+string(rune('0'+i)), b.URL(), nil, MappingJSON), v)
		sub, err := New(NewConfiguration(nil, AttachReaderGroups(subConn,
			ReaderGroup("rg", SetReaderQueue(DataSetReader("r", "pgz", 0, 1, nil), "gz/data", "gz/meta")))),
			WithDataSetHandler(rec.handler))
		require.NoError(t, err)
		require.NoError(t, sub.Start(context.Background()))
		t.Cleanup(func() { _ = sub.Close() })
		recs = append(recs, rec)
	}
	return func(topic string) (wireMessage, bool) {
		mu.Lock()
		defer mu.Unlock()
		m, ok := wire[topic]
		return m, ok
	}, recs
}

// waitNamed waits until rec has a complete DataSet with the field names of
// the metadata.
func waitNamed(t *testing.T, rec *recorder) {
	t.Helper()
	require.Eventually(t, func() bool {
		for _, d := range rec.dataSets() {
			if d.Complete && len(d.Fields) == 2 && d.Fields[0].Name == "a" && d.Fields[1].Name == "b" {
				return true
			}
		}
		return false
	}, 5*time.Second, time.Millisecond)
}

// TestGzipJSONEndToEnd: a connection with JsonCompression gzip on MQTT 5.0
// sends its data and metadata messages gzip compressed with the Content
// Type application/json+gzip (Part 14 §7.3.4.9.1). An MQTT 5.0 subscriber
// decompresses them by the content type, an MQTT 3.1.1 subscriber, which
// the broker gives no content type, by the gzip header.
func TestGzipJSONEndToEnd(t *testing.T) {
	t.Parallel()
	wire, recs := gzipPair(t, MQTTVersion5, "gzip", MQTTVersion5, MQTTVersion311)
	for _, rec := range recs {
		waitNamed(t, rec)
	}
	for _, topic := range []string{"gz/data", "gz/meta"} {
		var m wireMessage
		require.Eventually(t, func() bool {
			var ok bool
			m, ok = wire(topic)
			return ok
		}, 5*time.Second, time.Millisecond)
		require.Equal(t, transport.ContentTypeJSONGzip, m.ct, topic)
		require.True(t, bytes.HasPrefix(m.payload, gzipMagic), topic)
		plain, err := decompress(&transport.Message{Payload: m.payload}, DefaultJSONDecompressionLimit)
		require.NoError(t, err, topic)
		require.Less(t, len(m.payload), len(plain.Payload), topic)
		require.True(t, bytes.HasPrefix(plain.Payload, []byte("{")), topic)
	}
}

// TestGzipJSONOverMQTT311IsUncompressed: MQTT 3.1.1 cannot carry the
// content type that says that a message is compressed, so a connection
// that runs 3.1.1 sends its JSON messages uncompressed.
func TestGzipJSONOverMQTT311IsUncompressed(t *testing.T) {
	t.Parallel()
	wire, recs := gzipPair(t, MQTTVersion311, "gzip", MQTTVersion5)
	waitNamed(t, recs[0])
	var m wireMessage
	require.Eventually(t, func() bool {
		var ok bool
		m, ok = wire("gz/data")
		return ok
	}, 5*time.Second, time.Millisecond)
	require.Empty(t, m.ct)
	require.True(t, bytes.HasPrefix(m.payload, []byte("{")))
}

// TestGzipJSONNone: JsonCompression none (and no property) sends plain
// JSON.
func TestGzipJSONNone(t *testing.T) {
	t.Parallel()
	wire, recs := gzipPair(t, MQTTVersion5, "none", MQTTVersion5)
	waitNamed(t, recs[0])
	var m wireMessage
	require.Eventually(t, func() bool {
		var ok bool
		m, ok = wire("gz/data")
		return ok
	}, 5*time.Second, time.Millisecond)
	require.Equal(t, transport.ContentTypeJSON, m.ct)
}

func TestDecompress(t *testing.T) {
	t.Parallel()
	msg := []byte(`{"MessageId":"1","MessageType":"ua-data","Messages":[]}`)
	got, err := decompress(&transport.Message{Topic: "t", ContentType: transport.ContentTypeJSONGzip, Payload: gzipped(t, msg)}, 1024)
	require.NoError(t, err)
	require.Equal(t, msg, got.Payload)
	require.Equal(t, transport.ContentTypeJSON, got.ContentType)
	require.Equal(t, "t", got.Topic)

	// A message that decompresses to exactly the limit is accepted, one
	// byte more is not: a small message that inflates hugely (a
	// decompression bomb) is cut off after limit+1 bytes.
	_, err = decompress(&transport.Message{Payload: gzipped(t, msg)}, len(msg))
	require.NoError(t, err)
	_, err = decompress(&transport.Message{Payload: gzipped(t, msg)}, len(msg)-1)
	require.ErrorIs(t, err, errCompressedJSON)
	bomb := gzipped(t, make([]byte, 64<<20))
	require.Less(t, len(bomb), 256<<10)
	_, err = decompress(&transport.Message{Payload: bomb}, DefaultJSONDecompressionLimit)
	require.ErrorIs(t, err, errCompressedJSON)

	for name, payload := range map[string][]byte{
		"empty":     nil,
		"magic":     gzipMagic,
		"truncated": gzipped(t, msg)[:20],
		"not gzip":  []byte("{}"),
		"corrupt": func() []byte {
			b := gzipped(t, msg)
			b[len(b)-6] ^= 0xff // CRC-32
			return b
		}(),
	} {
		_, err := decompress(&transport.Message{Payload: payload}, 1024)
		require.ErrorIs(t, err, errCompressedJSON, name)
	}
}

func TestIsGzipped(t *testing.T) {
	t.Parallel()
	gz := []byte{0x1f, 0x8b, 0x08}
	for _, tc := range []struct {
		ct      string
		payload []byte
		want    bool
	}{
		{transport.ContentTypeJSONGzip, []byte("{"), true},
		{"Application/JSON+GZIP; x=y", nil, true},
		{"", gz, true},
		{"", []byte("{}"), false},
		{"", []byte{0xf1}, false},
		// A content type that says otherwise wins.
		{transport.ContentTypeJSON, gz, false},
		{transport.ContentTypeUADP, gz, false},
	} {
		require.Equal(t, tc.want, isGzipped(&transport.Message{ContentType: tc.ct, Payload: tc.payload}), "%q %x", tc.ct, tc.payload)
	}
}

func TestJSONCompressionValidation(t *testing.T) {
	t.Parallel()
	ok := SetJSONCompression(MQTTConnection("c", "mqtt://broker", uint16(1), MappingJSON), "gzip")
	require.NoError(t, Validate(NewConfiguration(nil, ok)))
	require.NoError(t, Validate(NewConfiguration(nil, SetJSONCompression(MQTTConnection("c", "mqtt://broker", uint16(1), MappingUADP), "none"))))
	for name, c := range map[string]*ua.PubSubConnectionDataType{
		"bad value": SetJSONCompression(MQTTConnection("c", "mqtt://broker", uint16(1), MappingJSON), "zstd"),
		"uadp":      SetJSONCompression(MQTTConnection("c", "mqtt://broker", uint16(1), MappingUADP), "gzip"),
		"amqp":      SetJSONCompression(AMQPConnection("c", "amqp://broker", uint16(1), MappingJSON), "gzip"),
		"udp":       SetJSONCompression(UDPConnection("c", "opc.udp://239.0.0.1:4840", uint16(1)), "gzip"),
	} {
		require.Error(t, Validate(NewConfiguration(nil, c)), name)
	}
}
