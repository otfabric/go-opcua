// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	imqtt "github.com/otfabric/go-opcua/internal/mqtt"
	"github.com/otfabric/go-opcua/internal/testutil/mqttbroker"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/ua"
)

// MQTT 5.0 end to end: the messages carry the content type of their
// mapping and their UAMessageType (Part 14 §7.3.4.8, §7.3.4.9), QoS 2 from
// ExactlyOnce, and the subscriber decodes them.
func TestMQTT5EndToEnd(t *testing.T) {
	t.Parallel()
	for _, mapping := range []MessageMapping{MappingJSON, MappingUADP} {
		t.Run(map[MessageMapping]string{MappingJSON: "json", MappingUADP: "uadp"}[mapping], func(t *testing.T) {
			t.Parallel()
			type seen struct {
				ct, mt string
				qos    byte
				retain bool
			}
			var mu sync.Mutex
			byTopic := map[string]seen{}
			b := mqttbroker.New(mqttbroker.Options{OnPublish: func(_ string, p *imqtt.Publish) {
				s := seen{qos: p.QoS, retain: p.Retain}
				if p.Props.ContentType != nil {
					s.ct = *p.Props.ContentType
				}
				for _, u := range p.Props.User {
					if u.Key == transport.UAMessageTypeProperty {
						s.mt = u.Value
					}
				}
				mu.Lock()
				byTopic[p.Topic] = s
				mu.Unlock()
			}})
			require.NoError(t, b.Start())
			t.Cleanup(b.Close)

			ds := NewMemoryDataSource()
			require.NoError(t, ds.Set(nodeA, int32(7)))
			pds := PublishedDataItems("pds", Var("a", nodeA, ua.TypeIDInt32))
			w := SetWriterQueue(DataSetWriter("w", 1, "pds"), "m5/data", "m5/meta")
			w.TransportSettings.Value.(*ua.BrokerDataSetWriterTransportDataType).RequestedDeliveryGuarantee = ua.BrokerTransportQoSExactlyOnce
			var wg *ua.WriterGroupDataType
			if mapping == MappingJSON {
				wg = JSONWriterGroup("wg", 1, 10*time.Millisecond, "m5/group", w)
			} else {
				wg = WriterGroup("wg", 1, 10*time.Millisecond, w)
				wg.TransportSettings = ua.NewExtensionObject(&ua.BrokerWriterGroupTransportDataType{QueueName: "m5/group"})
			}
			pubConn := SetMQTTVersion(MQTTConnection("pub", b.URL(), "p5", mapping), MQTTVersion5)
			pub, err := New(NewConfiguration([]*ua.PublishedDataSetDataType{pds}, AttachWriterGroups(pubConn, wg)), WithDataSource(ds))
			require.NoError(t, err)
			require.NoError(t, pub.Start(context.Background()))
			t.Cleanup(func() { _ = pub.Close() })

			// Reader WriterGroupId 0: a UADP metadata announcement carries
			// no WriterGroupId.
			rec := &recorder{}
			subConn := SetMQTTVersion(MQTTConnection("sub", b.URL(), nil, mapping), MQTTVersionBestAvailable)
			sub, err := New(NewConfiguration(nil, AttachReaderGroups(subConn,
				ReaderGroup("rg", SetReaderQueue(DataSetReader("r", "p5", 0, 1, nil), "m5/data", "m5/meta")))),
				WithDataSetHandler(rec.handler))
			require.NoError(t, err)
			require.NoError(t, sub.Start(context.Background()))
			t.Cleanup(func() { _ = sub.Close() })

			require.Eventually(t, func() bool {
				for _, d := range rec.dataSets() {
					if d.Complete && len(d.Fields) == 1 && d.Fields[0].Name == "a" {
						return true
					}
				}
				return false
			}, 5*time.Second, time.Millisecond)

			want := transport.ContentTypeUADP
			if mapping == MappingJSON {
				want = transport.ContentTypeJSON
			}
			// JSON data can be complete before the broker has the
			// metadata announcement: wait for both publications.
			require.Eventually(t, func() bool {
				mu.Lock()
				defer mu.Unlock()
				_, data := byTopic["m5/data"]
				_, meta := byTopic["m5/meta"]
				return data && meta
			}, 5*time.Second, time.Millisecond)
			mu.Lock()
			defer mu.Unlock()
			require.Equal(t, seen{ct: want, mt: transport.MessageTypeData, qos: 2}, byTopic["m5/data"])
			require.Equal(t, seen{ct: want, mt: transport.MessageTypeMetaData, qos: 1, retain: true}, byTopic["m5/meta"])
		})
	}
}

func TestMessageEncodingByContentType(t *testing.T) {
	t.Parallel()
	for ct, want := range map[string]encoding{
		"application/json":                encJSON,
		"Application/JSON; charset=utf-8": encJSON,
		"application/opcua+uadp":          encUADP,
	} {
		// The content type wins over what the payload looks like.
		payload := []byte("{")
		if want == encJSON {
			payload = []byte{0xf1}
		}
		got, err := messageEncoding(&transport.Message{ContentType: ct, Payload: payload})
		require.NoError(t, err)
		require.Equal(t, want, got, ct)
	}
	got, err := messageEncoding(&transport.Message{ContentType: "text/plain", Payload: []byte(" {}")})
	require.NoError(t, err)
	require.Equal(t, encJSON, got, "unknown content types: guessed from the payload")
	require.Equal(t, transport.ContentTypeJSON, encJSON.contentType())
	require.Equal(t, transport.ContentTypeUADP, encUADP.contentType())
}

// A gzip compressed JSON message that does not decompress is a decode
// error of the connection.
func TestMQTT5BrokenGzipIsADecodeError(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	sub := start(t, NewConfiguration(nil, AttachReaderGroups(brokerConnection("sub", url, nil, MappingJSON),
		ReaderGroup("rg", SetReaderQueue(DataSetReader("r", nil, 0, 0, nil), "gz", "")))))
	conn := mustID(t, sub, KindConnection, Root, "sub")
	require.Eventually(t, func() bool {
		sub.lock()
		defer sub.unlock()
		for _, c := range sub.conns {
			if c.tc != nil && c.topics != nil {
				return true
			}
		}
		return false
	}, 5*time.Second, time.Millisecond)
	sub.lock()
	var c *connection
	for _, cc := range sub.conns {
		c = cc
	}
	gen := c.gen
	sub.unlock()
	sub.receive(c, gen, &transport.Message{Topic: "gz", ContentType: transport.ContentTypeJSONGzip, Payload: []byte{0x1f, 0x8b}})
	st, err := sub.Status(conn)
	require.NoError(t, err)
	require.Equal(t, uint64(1), st.Counters.DecodeErrors)
}

func TestMQTTConnectionProperties(t *testing.T) {
	t.Parallel()
	c := MQTTConnection("c", "mqtt://broker", uint16(1), MappingJSON)
	SetMQTTVersion(c, MQTTVersion5)
	SetMQTTVersion(c, MQTTVersionBestAvailable)
	SetConnectionProperty(c, "connection-Receive Maximum", uint16(10))
	require.Len(t, c.ConnectionProperties, 2)
	require.Equal(t, MQTTVersionBestAvailable, c.ConnectionProperties[0].Value.Value())
	require.Equal(t, map[string]string{"MqttVersion": "BestAvailable", "connection-Receive Maximum": "10"},
		connectionProperties(c.ConnectionProperties))
	require.NoError(t, Validate(NewConfiguration(nil, c)))

	for _, bad := range []struct {
		name  string
		value any
	}{
		{"MqttVersion", "4.0"},
		{"connection-Receive Maximum", uint16(0)},
		{"connection-Maximum Packet Size", "big"},
		{"connection-Request Problem Information", "maybe"},
	} {
		c := SetConnectionProperty(MQTTConnection("c", "mqtt://broker", uint16(1), MappingJSON), bad.name, bad.value)
		require.ErrorContains(t, Validate(NewConfiguration(nil, c)), "ConnectionProperties", bad.name)
	}
	// UDP connections do not check them.
	u := SetMQTTVersion(UDPConnection("u", "opc.udp://224.0.0.22:4840", uint16(1)), "4.0")
	require.NoError(t, Validate(NewConfiguration(nil, u)))
}
