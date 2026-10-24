// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/uadp"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// Regression (chaos/pubsub fuzz): the field index of a delta frame sized
// the received DataSet. A delta frame of a few bytes with the index 65535
// made a reader of a one-field DataSet allocate and deliver a DataSet of
// 65536 fields, for every such message.
func TestRegressionDeltaFrameFieldIndex(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	md := MetaData("pds", Field{Name: "a", Type: ua.TypeIDInt32})
	rec := &recorder{}
	sub, err := New(NewConfiguration(nil, AttachReaderGroups(memConnection("sub", url, nil),
		ReaderGroup("rg", DataSetReader("withmd", uint16(7), 1, 1, md), DataSetReader("nomd", uint16(7), 1, 1, nil)))),
		WithDataSetHandler(rec.handler))
	require.NoError(t, err)
	require.NoError(t, sub.Start(context.Background()))
	t.Cleanup(func() { _ = sub.Close() })
	require.Eventually(t, func() bool { return bus.subscribers(url) > 0 }, 3*time.Second, time.Millisecond)

	seq := uint32(0)
	send := func(typ message.DataSetMessageType, fields ...*message.Field) {
		seq++
		b, err := uadp.Encode(&message.NetworkMessage{
			Type:        message.NetworkMessageDataSet,
			UADPMask:    DefaultUADPNetworkMessageContentMask,
			PublisherID: message.NewPublisherID(message.PublisherIDUInt16, 7),
			GroupHeader: message.GroupHeader{WriterGroupID: 1, SequenceNumber: uint16(seq)},
			Messages: []*message.DataSetMessage{{
				DataSetWriterID: 1, Type: typ, Valid: true,
				UADPMask:       ua.UADPDataSetMessageContentMaskSequenceNumber,
				SequenceNumber: seq,
				Fields:         fields,
			}},
		}, nil)
		require.NoError(t, err)
		bus.inject(url, "", b)
	}
	val := func(i uint16, v int32) *message.Field {
		return &message.Field{Index: i, Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)}}
	}
	send(message.DataSetMessageDeltaFrame, val(0xffff, 1))
	send(message.DataSetMessageKeyFrame, val(0, 2))
	send(message.DataSetMessageDeltaFrame, val(0xfffe, 3))
	send(message.DataSetMessageDeltaFrame, val(0, 4))

	require.Eventually(t, func() bool { return len(rec.dataSets()) >= 8 }, 3*time.Second, time.Millisecond)
	for _, d := range rec.dataSets() {
		require.LessOrEqual(t, len(d.Fields), 1, "reader %s: delta frame index sized the DataSet: %d fields", d.ReaderName, len(d.Fields))
	}
	last := rec.dataSets()[len(rec.dataSets())-1]
	require.Equal(t, []int32{4}, int32Values(last))
}

// Regression (chaos/pubsub): a reader discarded the messages of a
// publisher that was restarted (and so started its sequence numbers at 1
// again) as older than the last ones of its previous run, until the new
// sequence numbers caught up - forever, for a publisher that is restarted
// more often than that. After a MessageReceiveTimeout the reader now
// forgets the sequence numbers of its writers.
func TestRegressionPublisherRestartAfterTimeout(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	md := MetaData("pds", Field{Name: "a", Type: ua.TypeIDInt32})
	r := DataSetReader("r", uint16(7), 1, 1, md)
	r.MessageReceiveTimeout = 50
	rec := &recorder{}
	sub, err := New(NewConfiguration(nil, AttachReaderGroups(memConnection("sub", url, nil), ReaderGroup("rg", r))), WithDataSetHandler(rec.handler))
	require.NoError(t, err)
	require.NoError(t, sub.Start(context.Background()))
	t.Cleanup(func() { _ = sub.Close() })
	rid := mustID(t, sub, KindDataSetReader, mustID(t, sub, KindReaderGroup, mustID(t, sub, KindConnection, Root, "sub"), "rg"), "r")
	require.Eventually(t, func() bool { return bus.subscribers(url) > 0 }, 3*time.Second, time.Millisecond)

	send := func(seq uint16, v int32) {
		b, err := uadp.Encode(&message.NetworkMessage{
			Type:        message.NetworkMessageDataSet,
			UADPMask:    DefaultUADPNetworkMessageContentMask,
			PublisherID: message.NewPublisherID(message.PublisherIDUInt16, 7),
			GroupHeader: message.GroupHeader{WriterGroupID: 1, SequenceNumber: seq},
			Messages: []*message.DataSetMessage{{
				DataSetWriterID: 1, Type: message.DataSetMessageKeyFrame, Valid: true,
				UADPMask: ua.UADPDataSetMessageContentMaskSequenceNumber, SequenceNumber: uint32(seq),
				Fields: []*message.Field{{Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)}}},
			}},
		}, nil)
		require.NoError(t, err)
		bus.inject(url, "", b)
	}
	for seq := range uint16(100) {
		send(seq+1, 1)
	}
	require.Eventually(t, func() bool { return len(rec.dataSets()) == 100 }, 3*time.Second, time.Millisecond)

	// The publisher restarts: sequence numbers from 1, without a pause.
	deadline := time.Now().Add(3 * time.Second)
	for seq := uint16(1); time.Now().Before(deadline); seq++ {
		send(seq, 2)
		time.Sleep(5 * time.Millisecond)
		if ds := rec.dataSets(); int32Values(ds[len(ds)-1])[0] == 2 {
			break
		}
	}
	ds := rec.dataSets()
	require.Equal(t, []int32{2}, int32Values(ds[len(ds)-1]), "the restarted publisher's messages were discarded")
	require.Less(t, ds[100].SequenceNumber, uint32(100), "the restarted publisher's messages were discarded until its sequence numbers caught up")
	st, err := sub.Status(rid)
	require.NoError(t, err)
	require.NotZero(t, st.Counters.Timeouts)
	waitState(t, sub, rid, ua.PubSubStateOperational)
}

// Regression (chaos/pubsub network faults): a copy of the last message
// that a network delayed or duplicated past a MessageReceiveTimeout was
// delivered a second time, because the timeout made the reader forget the
// sequence numbers. The timeout now only marks them expired: the last
// message again, or one just behind it, is still discarded; a publisher
// that restarted far behind is taken.
func TestRegressionDuplicateAfterTimeout(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	md := MetaData("pds", Field{Name: "a", Type: ua.TypeIDInt32})
	r := DataSetReader("r", uint16(7), 1, 1, md)
	r.MessageReceiveTimeout = 50
	rec := &recorder{}
	sub, err := New(NewConfiguration(nil, AttachReaderGroups(memConnection("sub", url, nil), ReaderGroup("rg", r))), WithDataSetHandler(rec.handler))
	require.NoError(t, err)
	require.NoError(t, sub.Start(context.Background()))
	t.Cleanup(func() { _ = sub.Close() })
	rid := mustID(t, sub, KindDataSetReader, mustID(t, sub, KindReaderGroup, mustID(t, sub, KindConnection, Root, "sub"), "rg"), "r")
	require.Eventually(t, func() bool { return bus.subscribers(url) > 0 }, 3*time.Second, time.Millisecond)

	send := func(seq uint16, v int32) {
		b, err := uadp.Encode(&message.NetworkMessage{
			Type:        message.NetworkMessageDataSet,
			UADPMask:    DefaultUADPNetworkMessageContentMask,
			PublisherID: message.NewPublisherID(message.PublisherIDUInt16, 7),
			GroupHeader: message.GroupHeader{WriterGroupID: 1, SequenceNumber: seq},
			Messages: []*message.DataSetMessage{{
				DataSetWriterID: 1, Type: message.DataSetMessageKeyFrame, Valid: true,
				UADPMask: ua.UADPDataSetMessageContentMaskSequenceNumber, SequenceNumber: uint32(seq),
				Fields: []*message.Field{{Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)}}},
			}},
		}, nil)
		require.NoError(t, err)
		bus.inject(url, "", b)
	}
	timeouts := func() uint64 {
		st, err := sub.Status(rid)
		require.NoError(t, err)
		return st.Counters.Timeouts
	}
	for seq := uint16(181); seq <= 182; seq++ {
		send(seq, int32(seq))
	}
	require.Eventually(t, func() bool { return len(rec.dataSets()) == 2 }, 3*time.Second, time.Millisecond)
	// The messages made the reader Operational; wait for the timeout after
	// them. Counting timeouts does not tell: the reader's timer runs from
	// its start, so a slow start already timed it out once before 181.
	waitState(t, sub, rid, ua.PubSubStateError)
	require.NotZero(t, timeouts())

	// Late copies of 182 and 181 cross the timeout: both are discarded.
	send(182, 182)
	send(181, 181)
	// The publisher restarted: 1 is far behind 182 and is taken.
	send(1, 1)
	require.Eventually(t, func() bool { return len(rec.dataSets()) == 3 }, 3*time.Second, time.Millisecond)
	ds := rec.dataSets()
	require.Equal(t, []int32{1}, int32Values(ds[2]), "a late copy crossed the timeout")
	send(2, 2)
	require.Eventually(t, func() bool { return len(rec.dataSets()) == 4 }, 3*time.Second, time.Millisecond)
	require.Equal(t, []int32{2}, int32Values(rec.dataSets()[3]))
	st, err := sub.Status(rid)
	require.NoError(t, err)
	require.Equal(t, uint64(2), st.Counters.SequenceDiscards)
	require.Equal(t, uint64(1), st.Counters.SequenceResyncs)
}

// Regression (chaos/pubsub fuzz): UADP carries no field names. The decoder
// named the fields with the DataSetMetaData of the first reader that took
// the writer's messages, and every reader then placed the fields by those
// names in its own DataSet: a second reader of the same writer with other
// metadata - or one whose metadata an unsecured metadata message had
// replaced - shuffled or dropped the fields of the others, also of
// secured readers.
func TestRegressionUADPFieldsByPosition(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	ds := NewMemoryDataSource()
	require.NoError(t, ds.Set(nodeA, int32(1)))
	require.NoError(t, ds.Set(nodeB, int32(2)))
	pds := PublishedDataItems("pds", Var("a", nodeA, ua.TypeIDInt32), Var("b", nodeB, ua.TypeIDInt32))
	other := MetaData("other", Field{Name: "b", Type: ua.TypeIDInt32}, Field{Name: "a", Type: ua.TypeIDInt32})
	rec := &recorder{}
	sub, err := New(NewConfiguration(nil, AttachReaderGroups(memConnection("sub", url, nil),
		ReaderGroup("first", DataSetReader("any", nil, 0, 0, other)),
		ReaderGroup("second", DataSetReader("exact", uint16(7), 1, 1, DataSetMetaDataOf(pds))))),
		WithDataSetHandler(rec.handler))
	require.NoError(t, err)
	require.NoError(t, sub.Start(context.Background()))
	t.Cleanup(func() { _ = sub.Close() })
	pub, err := New(NewConfiguration([]*ua.PublishedDataSetDataType{pds}, AttachWriterGroups(memConnection("pub", url, uint16(7)),
		WriterGroup("wg", 1, 5*time.Millisecond, DataSetWriter("w", 1, "pds")))), WithDataSource(ds))
	require.NoError(t, err)
	require.NoError(t, pub.Start(context.Background()))
	t.Cleanup(func() { _ = pub.Close() })

	require.Eventually(t, func() bool {
		n := 0
		for _, d := range rec.dataSets() {
			if d.ReaderName == "exact" {
				n++
			}
		}
		return n >= 5
	}, 3*time.Second, time.Millisecond)
	for _, d := range rec.dataSets() {
		require.True(t, d.Complete, d.ReaderName)
		require.Equal(t, []int32{1, 2}, int32Values(d), "reader %s", d.ReaderName)
	}
}
