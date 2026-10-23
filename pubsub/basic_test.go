// SPDX-License-Identifier: MIT

package pubsub

import (
	"testing"
	"time"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

var (
	nodeA = ua.NewStringNodeID(1, "a")
	nodeB = ua.NewStringNodeID(1, "b")
	nodeC = ua.NewStringNodeID(1, "c")
)

// pubSubPair builds a publisher of the variables a, b, c (Int32) and a
// subscriber of them on the same bus.
func pubSubPair(t *testing.T, interval time.Duration, adjust func(pub, sub *ua.PubSubConfigurationDataType)) (*PubSub, *PubSub, *MemoryDataSource, *recorder) {
	t.Helper()
	url := memURL(t)
	ds := NewMemoryDataSource()
	require.NoError(t, ds.Set(nodeA, int32(1)))
	require.NoError(t, ds.Set(nodeB, int32(2)))
	require.NoError(t, ds.Set(nodeC, int32(3)))
	pds := PublishedDataItems("pds", Var("a", nodeA, ua.TypeIDInt32), Var("b", nodeB, ua.TypeIDInt32), Var("c", nodeC, ua.TypeIDInt32))
	pubCfg := NewConfiguration([]*ua.PublishedDataSetDataType{pds},
		AttachWriterGroups(memConnection("pub", url, uint16(7)), WriterGroup("wg", 10, interval, DataSetWriter("w", 20, "pds"))))
	subCfg := NewConfiguration(nil,
		AttachReaderGroups(memConnection("sub", url, nil), ReaderGroup("rg", DataSetReader("r", uint16(7), 10, 20, DataSetMetaDataOf(pds)))))
	if adjust != nil {
		adjust(pubCfg, subCfg)
	}
	rec := &recorder{}
	sub := start(t, subCfg, WithDataSetHandler(rec.handler), WithTargetWriter(rec), WithEventHandler(rec.event))
	pub := start(t, pubCfg, WithDataSource(ds))
	return pub, sub, ds, rec
}

func TestPublishSubscribeBasic(t *testing.T) {
	t.Parallel()
	pub, sub, ds, rec := pubSubPair(t, 10*time.Millisecond, nil)
	rid := mustID(t, sub, KindDataSetReader, mustID(t, sub, KindReaderGroup, mustID(t, sub, KindConnection, Root, "sub"), "rg"), "r")
	waitState(t, sub, rid, ua.PubSubStateOperational)
	require.Eventually(t, func() bool { return len(rec.dataSets()) > 0 }, 2*time.Second, time.Millisecond)
	got := rec.dataSets()[0]
	require.Equal(t, []int32{1, 2, 3}, int32Values(got))
	require.Equal(t, "a", got.Fields[0].Name)
	require.Equal(t, uint16(7), uint16(got.PublisherID.Num))
	require.Equal(t, uint16(10), got.WriterGroupID)
	require.Equal(t, uint16(20), got.DataSetWriterID)
	require.Equal(t, message.DataSetMessageKeyFrame, got.MessageType)
	require.True(t, got.Complete)
	require.Equal(t, 1.0, float64(got.Fields[0].Value.Value.Value().(int32)))

	require.NoError(t, ds.Set(nodeB, int32(42)))
	require.Eventually(t, func() bool {
		s := rec.dataSets()
		return int32Values(s[len(s)-1])[1] == 42
	}, 2*time.Second, time.Millisecond)

	st, err := pub.Status(Root)
	require.NoError(t, err)
	require.Positive(t, st.Counters.NetworkMessagesSent)
	require.Positive(t, st.Counters.DataSetMessagesSent)
	st, err = sub.Status(Root)
	require.NoError(t, err)
	require.Positive(t, st.Counters.DataSetMessagesReceived)
}
