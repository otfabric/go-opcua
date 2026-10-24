// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	iamqp "github.com/otfabric/go-opcua/internal/amqp"
	"github.com/otfabric/go-opcua/internal/testutil/amqpbroker"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/ua"
)

// End-to-end tests of the AMQP transport (Part 14 §7.3.4) with the
// in-process broker.

// amqpMessages records what the broker received, by address.
type amqpMessages struct {
	mu   sync.Mutex
	msgs map[string][]*iamqp.Message
}

func (a *amqpMessages) on(address string, m *iamqp.Message, _ bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.msgs == nil {
		a.msgs = map[string][]*iamqp.Message{}
	}
	a.msgs[address] = append(a.msgs[address], m)
}

func (a *amqpMessages) first(address string) *iamqp.Message {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.msgs[address]) == 0 {
		return nil
	}
	return a.msgs[address][0]
}

func startAMQPBroker(t *testing.T, opts amqpbroker.Options) *amqpbroker.Broker {
	t.Helper()
	b := amqpbroker.New(opts)
	require.NoError(t, b.Start())
	t.Cleanup(b.Close)
	return b
}

// amqpPair runs a publisher and a subscriber of the data of e2eData over
// the broker at url with mapping. The writer publishes to the topic
// address data and its metadata to the queue address meta; the reader
// learns the metadata from there.
func amqpPair(t *testing.T, url string, mapping MessageMapping, data, meta string, tweak func(pub, sub *ua.PubSubConfigurationDataType), opts ...Option) (*PubSub, *recorder) {
	t.Helper()
	ds, pds := e2eData(t)
	w := SetWriterQueue(DataSetWriter("w", 1, "pds"), data, meta)
	w.DataSetWriterProperties = []*ua.KeyValuePair{{Key: &ua.QualifiedName{Name: "message-to"}, Value: ua.MustVariant("subscribers")}}
	var wg *ua.WriterGroupDataType
	if mapping == MappingJSON {
		wg = JSONWriterGroup("wg", 1, 10*time.Millisecond, data, w)
	} else {
		wg = WriterGroup("wg", 1, 10*time.Millisecond, w)
	}
	wg.GroupProperties = []*ua.KeyValuePair{{Key: &ua.QualifiedName{Name: "site"}, Value: ua.MustVariant("plant-1")}}
	pubCfg := NewConfiguration([]*ua.PublishedDataSetDataType{pds}, AttachWriterGroups(AMQPConnection("pub", url, uint16(5), mapping), wg))
	subCfg := NewConfiguration(nil, AttachReaderGroups(AMQPConnection("sub", url, nil, mapping),
		ReaderGroup("rg", SetReaderQueue(DataSetReader("r", uint16(5), 0, 1, nil), data, meta))))
	if tweak != nil {
		tweak(pubCfg, subCfg)
	}
	rec := &recorder{}
	sub, err := New(subCfg, append([]Option{WithDataSetHandler(rec.handler)}, opts...)...)
	require.NoError(t, err)
	require.NoError(t, sub.Start(context.Background()))
	t.Cleanup(func() { _ = sub.Close() })
	pub, err := New(pubCfg, append([]Option{WithDataSource(ds)}, opts...)...)
	require.NoError(t, err)
	require.NoError(t, pub.Start(context.Background()))
	t.Cleanup(func() { _ = pub.Close() })
	return sub, rec
}

func TestE2EAMQP(t *testing.T) {
	t.Parallel()
	got := &amqpMessages{}
	b := startAMQPBroker(t, amqpbroker.Options{OnMessage: got.on})
	for _, m := range []MessageMapping{MappingJSON, MappingUADP} {
		t.Run(fmt.Sprint(m), func(t *testing.T) {
			t.Parallel()
			data := fmt.Sprintf("/exchanges/amq.topic/data.%d", m)
			meta := fmt.Sprintf("/queues/meta.%d", m)
			sub, rec := amqpPair(t, b.URL(), m, data, meta, nil)
			waitData(t, rec)
			st, err := sub.Status(Root)
			require.NoError(t, err)
			require.Zero(t, st.Counters.DecodeErrors, errString(sub))
			// The metadata came from the broker.
			rid := mustID(t, sub, KindDataSetReader, mustID(t, sub, KindReaderGroup, mustID(t, sub, KindConnection, Root, "sub"), "rg"), "r")
			require.Eventually(t, func() bool {
				cfg, err := sub.DataSetReaderConfig(rid)
				require.NoError(t, err)
				return len(cfg.DataSetMetaData.Fields) == 2
			}, 5*time.Second, 2*time.Millisecond)

			// The message mapping of Part 14 B.3.7 and B.3.8.
			ct := iamqp.Symbol("application/opcua+uadp")
			if m == MappingJSON {
				ct = "application/json"
			}
			d, md := got.first(data), got.first(meta)
			require.NotNil(t, d)
			require.NotNil(t, md)
			require.Equal(t, "ua-data", d.Properties.Subject)
			require.Equal(t, "ua-metadata", md.Properties.Subject)
			require.Equal(t, ct, d.Properties.ContentType)
			require.Equal(t, ct, md.Properties.ContentType)
			require.IsType(t, iamqp.UUID{}, d.Properties.MessageID)
			// The writer has a queue of its own: its properties apply.
			require.Equal(t, "subscribers", d.Properties.To)
			require.Equal(t, "plant-1", d.ApplicationProperties["site"])
			require.Equal(t, "subscribers", md.Properties.To)
		})
	}
}

func TestE2EAMQPSecured(t *testing.T) {
	t.Parallel()
	b := startAMQPBroker(t, amqpbroker.Options{})
	for _, mode := range []ua.MessageSecurityMode{ua.MessageSecurityModeSign, ua.MessageSecurityModeSignAndEncrypt} {
		t.Run(mode.String(), func(t *testing.T) {
			t.Parallel()
			policy := security.Aes256CTR()
			ring := security.NewKeyRing("sg", policy)
			key := make([]byte, policy.KeyLength())
			_, err := rand.Read(key)
			require.NoError(t, err)
			require.NoError(t, ring.SetKeys(policy.URI(), 1, [][]byte{key}, time.Hour, time.Hour))
			q := fmt.Sprintf("/queues/secure.%d", mode)
			sub, rec := amqpPair(t, b.URL(), MappingUADP, q, q+".meta", func(pub, sub *ua.PubSubConfigurationDataType) {
				Secure(pub.Connections[0].WriterGroups[0], mode, "sg")
				Secure(sub.Connections[0].ReaderGroups[0], mode, "sg")
			}, WithKeySource("sg", ring))
			waitData(t, rec)
			st, err := sub.Status(Root)
			require.NoError(t, err)
			require.Zero(t, st.Counters.DecodeErrors, errString(sub))
		})
	}
}

func TestE2EAMQPBrokerRestart(t *testing.T) {
	t.Parallel()
	b := startAMQPBroker(t, amqpbroker.Options{})
	_, rec := amqpPair(t, b.URL(), MappingUADP, "/exchanges/amq.topic/restart", "/queues/restart.meta", nil)
	waitData(t, rec)
	b.Stop()
	require.Eventually(t, func() bool { return b.ClientCount() == 0 }, 5*time.Second, 2*time.Millisecond)
	require.NoError(t, b.Restart())
	// Both sides reconnect and attach their links again: data flows anew.
	n := len(rec.dataSets())
	require.Eventually(t, func() bool { return len(rec.dataSets()) > n+5 }, 30*time.Second, 5*time.Millisecond)
	waitData(t, rec)
}
