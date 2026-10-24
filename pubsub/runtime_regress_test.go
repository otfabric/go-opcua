// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/uadp"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// Regression: a JSON ActionRequest whose MessageType isActionMessage did
// not see (beyond its first 512 bytes, or escaped) went the way of the data
// messages, and processDSM indexed the empty fields of its stream: one
// unsecured datagram crashed the subscriber with p.mu held.
func TestRegressionJSONActionMessageToReader(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	md := MetaData("pds", Field{Name: "a", Type: ua.TypeIDInt32})
	rec := &recorder{}
	sub, err := New(NewConfiguration(nil, AttachReaderGroups(memConnection("sub", url, nil), ReaderGroup("rg", DataSetReader("r", uint16(7), 1, 1, md)))),
		WithDataSetHandler(rec.handler))
	require.NoError(t, err)
	require.NoError(t, sub.Start(context.Background()))
	t.Cleanup(func() { _ = sub.Close() })
	cid := mustID(t, sub, KindConnection, Root, "sub")
	require.Eventually(t, func() bool { return bus.subscribers(url) > 0 }, 3*time.Second, time.Millisecond)

	body := `"PublisherId":"7","Messages":[{"DataSetWriterId":1,"ActionTargetId":1,"RequestId":1,"ActionState":0,"Payload":{"a":{"Type":6,"Body":5}}}]}`
	for _, msg := range []string{
		`{"MessageId":"x","Pad":"` + strings.Repeat("p", 600) + `","MessageType":"ua-action-request",` + body,
		`{"MessageId":"y","MessageType":"ua-action-request",` + body,
		`{"MessageId":"z","MessageType":"ua-action-response",` + body,
	} {
		bus.inject(url, "", []byte(msg))
	}
	// A data message behind them is still delivered: the subscriber lives.
	bus.inject(url, "", []byte(`{"MessageId":"d","MessageType":"ua-data","PublisherId":"7","Messages":[{"DataSetWriterId":1,"Payload":{"a":{"Type":6,"Body":9}}}]}`))
	require.Eventually(t, func() bool { return len(rec.dataSets()) == 1 }, 3*time.Second, time.Millisecond)
	require.Equal(t, []int32{9}, int32Values(rec.dataSets()[0]))
	st, err := sub.Status(cid)
	require.NoError(t, err)
	require.EqualValues(t, 4, st.Counters.NetworkMessagesReceived)
}

// Regression: a chunked UADP message whose reassembled DataSetMessage is an
// ActionRequest, without ActionHeader, reached processDSM like the JSON
// messages of TestRegressionJSONActionMessageToReader.
func TestRegressionChunkedActionDataSetMessageToReader(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	md := MetaData("pds", Field{Name: "a", Type: ua.TypeIDInt32})
	rec := &recorder{}
	sub, err := New(NewConfiguration(nil, AttachReaderGroups(memConnection("sub", url, nil), ReaderGroup("rg", DataSetReader("r", uint16(7), 1, 1, md)))),
		WithDataSetHandler(rec.handler))
	require.NoError(t, err)
	require.NoError(t, sub.Start(context.Background()))
	t.Cleanup(func() { _ = sub.Close() })
	require.Eventually(t, func() bool { return bus.subscribers(url) > 0 }, 3*time.Second, time.Millisecond)

	// DataSetMessage flags: valid, Variant fields, Flags2 with the type
	// ActionRequest; ActionTargetId 1, RequestId 1, Executing, one Int32.
	dsm := []byte{0x81, 0x05, 1, 0, 1, 0, 1, 1, 0, byte(ua.TypeIDInt32), 5, 0, 0, 0}
	b, err := uadp.Encode(&message.NetworkMessage{
		Type:        message.NetworkMessageDataSet,
		UADPMask:    DefaultUADPNetworkMessageContentMask,
		PublisherID: message.NewPublisherID(message.PublisherIDUInt16, 7),
		GroupHeader: message.GroupHeader{WriterGroupID: 1},
		Messages:    []*message.DataSetMessage{{DataSetWriterID: 1}},
		Chunk:       &message.Chunk{MessageSequenceNumber: 1, TotalSize: uint32(len(dsm)), Data: dsm},
	}, nil)
	require.NoError(t, err)
	bus.inject(url, "", b)
	send := func(v int32) {
		b, err := uadp.Encode(&message.NetworkMessage{
			Type:        message.NetworkMessageDataSet,
			UADPMask:    DefaultUADPNetworkMessageContentMask,
			PublisherID: message.NewPublisherID(message.PublisherIDUInt16, 7),
			GroupHeader: message.GroupHeader{WriterGroupID: 1},
			Messages: []*message.DataSetMessage{{DataSetWriterID: 1, Type: message.DataSetMessageKeyFrame, Valid: true,
				Fields: []*message.Field{{Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)}}}}},
		}, nil)
		require.NoError(t, err)
		bus.inject(url, "", b)
	}
	send(9)
	require.Eventually(t, func() bool { return len(rec.dataSets()) == 1 }, 3*time.Second, time.Millisecond)
	require.Equal(t, []int32{9}, int32Values(rec.dataSets()[0]))
	cid := mustID(t, sub, KindConnection, Root, "sub")
	require.Eventually(t, func() bool {
		st, err := sub.Status(cid)
		return err == nil && st.Counters.ChunkedMessagesReceived == 1
	}, 3*time.Second, time.Millisecond)
}
