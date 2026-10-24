// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"fmt"
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

// Regression: an ExtensionObject whose body is a nil pointer of a known
// structure type (ua.NewExtensionObject((*T)(nil))) passed the type
// switches on eoValue as that structure, and New panicked on it.
func TestRegressionNilExtensionObjectBodies(t *testing.T) {
	t.Parallel()
	conn := func() *ua.PubSubConnectionDataType { return UDPConnection("c", "opc.udp://239.0.0.1:4840", uint16(1)) }
	var cfgs []*ua.PubSubConfigurationDataType
	for _, src := range []any{(*ua.PublishedDataItemsDataType)(nil), (*ua.PublishedEventsDataType)(nil),
		(*ua.PublishedActionDataType)(nil), (*ua.PublishedActionMethodDataType)(nil)} {
		cfgs = append(cfgs, NewConfiguration([]*ua.PublishedDataSetDataType{{Name: "x", DataSetSource: ua.NewExtensionObject(src)}}))
	}
	r := DataSetReader("r", uint16(7), 1, 1, nil)
	r.SubscribedDataSet = ua.NewExtensionObject((*ua.TargetVariablesDataType)(nil))
	cfgs = append(cfgs, NewConfiguration(nil, AttachReaderGroups(conn(), ReaderGroup("rg", r))))
	r = DataSetReader("r", uint16(7), 1, 1, nil)
	r.MessageSettings = ua.NewExtensionObject((*ua.UADPDataSetReaderMessageDataType)(nil))
	cfgs = append(cfgs, NewConfiguration(nil, AttachReaderGroups(conn(), ReaderGroup("rg", r))))
	g := WriterGroup("wg", 1, time.Second, DataSetWriter("w", 1, ""))
	g.MessageSettings = ua.NewExtensionObject((*ua.UADPWriterGroupMessageDataType)(nil))
	g.TransportSettings = ua.NewExtensionObject((*ua.DatagramWriterGroupTransport2DataType)(nil))
	cfgs = append(cfgs, NewConfiguration(nil, AttachWriterGroups(conn(), g)))
	for i, cfg := range cfgs {
		require.NotPanics(t, func() {
			p, err := New(cfg)
			if err == nil {
				require.NoError(t, p.Close())
			}
		}, "configuration %d", i)
	}
}

// Regression: a reader that does not filter on the PublisherId kept the
// state of a stream for every PublisherId it received a message from: a
// sender making up PublisherIds grew it without bound.
func TestRegressionReaderStreamsBounded(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	md := MetaData("pds", Field{Name: "a", Type: ua.TypeIDInt32})
	rec := &recorder{}
	sub, err := New(NewConfiguration(nil, AttachReaderGroups(memConnection("sub", url, nil), ReaderGroup("rg", DataSetReader("r", nil, 0, 0, md)))),
		WithDataSetHandler(rec.handler))
	require.NoError(t, err)
	require.NoError(t, sub.Start(context.Background()))
	t.Cleanup(func() { _ = sub.Close() })
	rid := mustID(t, sub, KindDataSetReader, mustID(t, sub, KindReaderGroup, mustID(t, sub, KindConnection, Root, "sub"), "rg"), "r")
	require.Eventually(t, func() bool { return bus.subscribers(url) > 0 }, 3*time.Second, time.Millisecond)

	const n = maxReaderStreams + 200
	for i := range n {
		b, err := uadp.Encode(&message.NetworkMessage{
			Type:        message.NetworkMessageDataSet,
			UADPMask:    DefaultUADPNetworkMessageContentMask,
			PublisherID: message.NewPublisherID(message.PublisherIDUInt32, uint64(i)),
			GroupHeader: message.GroupHeader{WriterGroupID: 1},
			Messages: []*message.DataSetMessage{{DataSetWriterID: 1, Type: message.DataSetMessageKeyFrame, Valid: true,
				UADPMask: ua.UADPDataSetMessageContentMaskSequenceNumber, SequenceNumber: 1,
				Fields: []*message.Field{{Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int32(i))}}}}},
		}, nil)
		require.NoError(t, err)
		bus.inject(url, "", b)
	}
	require.Eventually(t, func() bool { return len(rec.dataSets()) == n }, 5*time.Second, time.Millisecond)
	sub.lock()
	streams := len(sub.comps[rid].(*dataSetReader).streams)
	sub.unlock()
	require.LessOrEqual(t, streams, maxReaderStreams)
}

// Regression: the exchanges of an Action writer outlived the writer. A
// writer that was disabled or removed kept running its handlers until the
// TimeoutHint and its exchange timers kept sending responses for it.
func TestRegressionActionExchangesEndWithWriter(t *testing.T) {
	t.Parallel()
	for _, remove := range []bool{false, true} {
		t.Run(fmt.Sprint("remove=", remove), func(t *testing.T) {
			t.Parallel()
			url := memURL(t)
			started := make(chan struct{}, 1)
			cancelled := make(chan struct{}, 1)
			h := func(ctx context.Context, _ []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
				started <- struct{}{}
				<-ctx.Done()
				cancelled <- struct{}{}
				return nil, ua.StatusBadTimeout
			}
			resp := startReal(t, responderConfig(url, 20*time.Millisecond, ua.MessageSecurityModeNone), WithActionHandler("Calc", 1, h))
			req := startReal(t, requestorConfig(url))
			waitRunning(t, resp, "Responder")
			waitRunning(t, req, "Requestor")
			waitResponder(t, resp)
			wid := mustID(t, resp, KindDataSetWriter, mustID(t, resp, KindWriterGroup, mustID(t, resp, KindConnection, Root, "Responder"), "Actions"), "CalcWriter")

			tg := calcTarget()
			tg.Timeout = 10 * time.Second
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				defer close(done)
				_, _ = req.CallAction(ctx, tg, int32s(1, 2))
			}()
			t.Cleanup(func() { cancel(); <-done })
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("the handler did not start")
			}
			if remove {
				require.NoError(t, resp.RemoveDataSetWriter(wid))
			} else {
				require.NoError(t, resp.Disable(wid))
			}
			select {
			case <-cancelled:
			case <-time.After(2 * time.Second):
				t.Fatal("the handler of the stopped writer was not cancelled")
			}
			resp.lock()
			n := len(resp.conns[0].act.exchanges)
			resp.unlock()
			require.Zero(t, n)
		})
	}
}

// Regression: the action messages were sent with context.Background: a
// transport that waits for an acknowledgement (MQTT at QoS 1 during a
// broker outage) held CallAction beyond its timeout, until the broker came
// back or the runtime was closed.
func TestRegressionCallActionTimeoutWhileSendBlocks(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	req := startReal(t, requestorConfig(url))
	waitRunning(t, req, "Requestor")
	bus.mu.Lock()
	bus.blockSend[url] = true
	bus.mu.Unlock()
	t.Cleanup(func() {
		bus.mu.Lock()
		delete(bus.blockSend, url)
		bus.mu.Unlock()
	})
	tg := calcTarget()
	tg.Timeout = 100 * time.Millisecond
	done := make(chan error, 1)
	go func() {
		_, err := req.CallAction(context.Background(), tg, int32s(1, 2))
		done <- err
	}()
	select {
	case err := <-done:
		require.ErrorIs(t, err, ErrActionTimeout)
	case <-time.After(3 * time.Second):
		t.Fatal("CallAction did not return at its timeout")
	}
}
