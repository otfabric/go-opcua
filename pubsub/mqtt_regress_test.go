// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/internal/testutil/mqttbroker"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// Regression (conformance PubSub tests): the name of a connection was its
// MQTT client identifier. Two runtimes with a connection of the same name
// on one broker - two applications that both call theirs "Connection1" -
// took over each other's session again and again: both reconnected all the
// time and lost messages.
func TestRegressionMQTTConnectionNamesShareBroker(t *testing.T) {
	t.Parallel()
	b := mqttbroker.New(mqttbroker.Options{})
	require.NoError(t, b.Start())
	t.Cleanup(b.Close)

	ds := NewMemoryDataSource()
	require.NoError(t, ds.Set(nodeA, int32(1)))
	pds := PublishedDataItems("pds", Var("a", nodeA, ua.TypeIDInt32))
	var mu sync.Mutex
	seqs := map[string][]uint32{}
	handler := func(name string) DataSetHandler {
		return func(d *ReceivedDataSet) {
			mu.Lock()
			seqs[name] = append(seqs[name], d.SequenceNumber)
			mu.Unlock()
		}
	}
	for _, name := range []string{"sub1", "sub2"} {
		sub, err := New(NewConfiguration(nil, AttachReaderGroups(MQTTConnection("Connection1", b.URL(), nil, MappingUADP),
			ReaderGroup("rg", SetReaderQueue(DataSetReader("r", uint16(1), 1, 1, DataSetMetaDataOf(pds)), "regress/q", "")))),
			WithDataSetHandler(handler(name)))
		require.NoError(t, err)
		require.NoError(t, sub.Start(context.Background()))
		t.Cleanup(func() { _ = sub.Close() })
	}
	require.Eventually(t, func() bool { return b.ClientCount() == 2 }, 5*time.Second, time.Millisecond)
	time.Sleep(100 * time.Millisecond) // the subscriptions
	pub, err := New(NewConfiguration([]*ua.PublishedDataSetDataType{pds}, AttachWriterGroups(MQTTConnection("Connection1", b.URL(), uint16(1), MappingUADP),
		WriterGroup("wg", 1, 5*time.Millisecond, SetWriterQueue(DataSetWriter("w", 1, "pds"), "regress/q", "")))), WithDataSource(ds))
	require.NoError(t, err)
	require.NoError(t, pub.Start(context.Background()))
	t.Cleanup(func() { _ = pub.Close() })

	require.Eventually(t, func() bool { return b.ClientCount() == 3 }, 5*time.Second, time.Millisecond)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		require.Equal(t, 3, b.ClientCount(), "clients with the same connection name kick each other off the broker")
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, name := range []string{"sub1", "sub2"} {
		got := seqs[name]
		require.NotEmpty(t, got, name)
		for i := 1; i < len(got); i++ {
			require.Equal(t, got[i-1]+1, got[i], "%s lost messages", name)
		}
	}
}
