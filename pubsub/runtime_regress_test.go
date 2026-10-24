// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/transport"
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

// Regression (-race): the answers to discovery probes and the probes of
// the readers were sent with p.ctx read without the lock, while Start sets
// it for a new run.
func TestRegressionDiscoveryContextRace(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	ds, pds := e2eData(t)
	pub, err := New(NewConfiguration([]*ua.PublishedDataSetDataType{pds},
		AttachWriterGroups(memConnection("pub", url, uint16(5)), WriterGroup("wg", 7, time.Hour, DataSetWriter("w", 1, "pds")))),
		WithDataSource(ds), WithRetryInterval(time.Millisecond),
		WithDiscovery(DiscoveryOptions{MinInterval: time.Nanosecond, Rate: 1e9, Burst: 1 << 20}))
	require.NoError(t, err)
	t.Cleanup(func() { _ = pub.Close() })
	probe := probeBytes(t, &message.DiscoveryRequest{ProbeType: message.ProbeFindApplications}, 5)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				bus.inject(url, "", probe)
			}
		}
	}()
	cid := mustID(t, pub, KindConnection, Root, "pub")
	for range 30 {
		ctx, cancel := context.WithCancel(context.Background())
		require.NoError(t, pub.Start(ctx))
		waitState(t, pub, cid, ua.PubSubStateOperational)
		cancel()
	}
	close(stop)
	<-done
}

// Regression: the chunks of a large DataSetMessage were sent without the
// content type and the message type the unchunked messages have (MQTT 5.0
// properties, Part 14 §7.3.4.8).
func TestRegressionChunksCarryMessageProperties(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	ds, pds := e2eData(t)
	require.NoError(t, ds.Set(nodeB, strings.Repeat("chunk", 200)))
	wg := WriterGroup("wg", 1, 20*time.Millisecond, DataSetWriter("w", 1, "pds"))
	wg.MaxNetworkMessageSize = 300
	pub := startReal(t, NewConfiguration([]*ua.PublishedDataSetDataType{pds}, AttachWriterGroups(memConnection("pub", url, uint16(5)), wg)), WithDataSource(ds))
	require.Eventually(t, func() bool {
		st, err := pub.Status(Root)
		return err == nil && st.Counters.ChunksSent >= 4
	}, 5*time.Second, time.Millisecond)
	sent := bus.sentTo(url)
	require.NotEmpty(t, sent)
	for _, m := range sent {
		require.Equal(t, transport.ContentTypeUADP, m.ContentType)
		require.Equal(t, transport.MessageTypeData, m.MessageType)
	}
}

// Regression: the incomplete chunked messages of a connection expired only
// when further chunks arrived: the chunks of a message that was never
// completed stayed in memory, uncounted, for as long as no other chunk
// came.
func TestRegressionIncompleteChunksExpire(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	md := MetaData("pds", Field{Name: "a", Type: ua.TypeIDInt32})
	sub, err := New(NewConfiguration(nil, AttachReaderGroups(memConnection("sub", url, nil), ReaderGroup("rg", DataSetReader("r", uint16(7), 1, 1, md)))),
		WithChunkReassembly(uadp.ReassemblerOptions{Timeout: 50 * time.Millisecond}))
	require.NoError(t, err)
	require.NoError(t, sub.Start(context.Background()))
	t.Cleanup(func() { _ = sub.Close() })
	require.Eventually(t, func() bool { return bus.subscribers(url) > 0 }, 3*time.Second, time.Millisecond)
	b, err := uadp.Encode(&message.NetworkMessage{
		Type:        message.NetworkMessageDataSet,
		UADPMask:    DefaultUADPNetworkMessageContentMask,
		PublisherID: message.NewPublisherID(message.PublisherIDUInt16, 7),
		GroupHeader: message.GroupHeader{WriterGroupID: 1},
		Messages:    []*message.DataSetMessage{{DataSetWriterID: 1}},
		Chunk:       &message.Chunk{MessageSequenceNumber: 1, TotalSize: 2000, Data: make([]byte, 1000)},
	}, nil)
	require.NoError(t, err)
	bus.inject(url, "", b)
	cid := mustID(t, sub, KindConnection, Root, "sub")
	require.Eventually(t, func() bool {
		st, err := sub.Status(cid)
		return err == nil && st.Counters.ChunksReceived == 1 && st.Counters.ChunksDiscarded == 1
	}, 3*time.Second, time.Millisecond)
	sub.lock()
	pending := sub.conns[0].reasm.Stats().Pending
	sub.unlock()
	require.Zero(t, pending)
}

// Regression: a Responder dropped an exchange at the end of its
// TimeoutHint even while its handler still ran. A copy of the request
// delivered late then ran the handler a second time, and a handler that
// ignores its context no longer counted toward MaxConcurrent. Ended
// exchanges are now remembered for the late copies of their requests.
func TestRegressionActionExchangeExpiry(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	var calls atomic.Int32
	release := make(chan struct{})
	h := func(ctx context.Context, in []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		if calls.Add(1) == 1 {
			<-release // ignores ctx
		}
		return addHandler(ctx, in)
	}
	resp := startReal(t, responderConfig(url, 10*time.Millisecond, ua.MessageSecurityModeNone), WithActionHandler("Calc", 1, h),
		WithActionOptions(ActionOptions{MaxTimeout: 50 * time.Millisecond, MaxConcurrent: 1}))
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	waitRunning(t, resp, "Responder")
	waitResponder(t, resp)

	// Request 1 expires while its handler runs: answered Bad_Timeout, and
	// it still takes the only slot.
	bus.inject(url, "", rawRequest(t, 1, 1, 1, ua.ActionStateExecuting, "c", 1, 2))
	require.Eventually(t, func() bool {
		for _, r := range responses(url) {
			if r.reqID == 1 && r.state == ua.ActionStateDone && r.status == ua.StatusBadTimeout {
				return true
			}
		}
		return false
	}, 3*time.Second, time.Millisecond)
	bus.inject(url, "", rawRequest(t, 1, 1, 2, ua.ActionStateExecuting, "c", 1, 2))
	require.Eventually(t, func() bool {
		for _, r := range responses(url) {
			if r.reqID == 2 && r.status == ua.StatusBadTooManyOperations {
				return true
			}
		}
		return false
	}, 3*time.Second, time.Millisecond)
	// A late copy of request 1 is answered, not executed again.
	time.Sleep(2 * actionDuplicateGuard)
	bus.inject(url, "", rawRequest(t, 1, 1, 1, ua.ActionStateExecuting, "c", 1, 2))
	require.Eventually(t, func() bool { return countResponses(url, 1, ua.ActionStateDone) >= 2 }, 3*time.Second, time.Millisecond)
	once.Do(func() { close(release) })
	require.Eventually(t, func() bool { return exchanges(resp) == 0 }, 3*time.Second, time.Millisecond)
	bus.inject(url, "", rawRequest(t, 1, 1, 1, ua.ActionStateExecuting, "c", 1, 2))

	// Request 3 completes and is acknowledged; a late copy is not
	// executed again either.
	bus.inject(url, "", rawRequest(t, 1, 1, 3, ua.ActionStateExecuting, "c", 1, 2))
	require.Eventually(t, func() bool { return countResponses(url, 3, ua.ActionStateDone) >= 1 }, 3*time.Second, time.Millisecond)
	bus.inject(url, "", rawRequest(t, 1, 1, 3, ua.ActionStateIdle, "c"))
	require.Eventually(t, func() bool { return countResponses(url, 3, ua.ActionStateIdle) == 1 }, 3*time.Second, time.Millisecond)
	bus.inject(url, "", rawRequest(t, 1, 1, 3, ua.ActionStateExecuting, "c", 1, 2))
	time.Sleep(100 * time.Millisecond)
	require.Equal(t, int32(2), calls.Load())
}

// Regression: a DataSetReader with a SecurityGroupId but no SecurityMode
// of its own (Invalid, the zero value) took the place of the security of
// its ReaderGroup with None: it accepted unsecured messages although the
// group requires signed ones.
func TestRegressionReaderSecurityGroupIDDoesNotDowngrade(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	md := MetaData("pds", Field{Name: "a", Type: ua.TypeIDInt32})
	r := DataSetReader("r", uint16(7), 1, 1, md)
	r.SecurityGroupID = "sg"
	rg := ReaderGroup("rg", r)
	Secure(rg, ua.MessageSecurityModeSign, "sg")
	rec := &recorder{}
	sub, err := New(NewConfiguration(nil, AttachReaderGroups(memConnection("sub", url, nil), rg)),
		WithDataSetHandler(rec.handler), WithKeySource("sg", testRing(t)))
	require.NoError(t, err)
	require.NoError(t, sub.Start(context.Background()))
	t.Cleanup(func() { _ = sub.Close() })
	require.Eventually(t, func() bool { return bus.subscribers(url) > 0 }, 3*time.Second, time.Millisecond)
	b, err := uadp.Encode(&message.NetworkMessage{
		Type:        message.NetworkMessageDataSet,
		UADPMask:    DefaultUADPNetworkMessageContentMask,
		PublisherID: message.NewPublisherID(message.PublisherIDUInt16, 7),
		GroupHeader: message.GroupHeader{WriterGroupID: 1},
		Messages: []*message.DataSetMessage{{DataSetWriterID: 1, Type: message.DataSetMessageKeyFrame, Valid: true,
			Fields: []*message.Field{{Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int32(1))}}}}},
	}, nil)
	require.NoError(t, err)
	bus.inject(url, "", b)
	cid := mustID(t, sub, KindConnection, Root, "sub")
	require.Eventually(t, func() bool {
		st, err := sub.Status(cid)
		return err == nil && st.Counters.DecodeErrors == 1
	}, 3*time.Second, time.Millisecond)
	require.Empty(t, rec.dataSets())
}

// Regression: a Responder's writer group (and its Action writers) became
// Operational before its connection was subscribed to the request queue:
// requests sent as soon as it was Operational were lost. The group is
// PreOperational until the subscription is in place.
func TestRegressionResponderOperationalWhenSubscribed(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	rcfg, qcfg, queue := brokerActionConfigs(url, MappingUADP)
	bus.mu.Lock()
	bus.failSub[queue] = true
	bus.mu.Unlock()
	resp := startReal(t, rcfg, WithActionHandler("Calc", 1, addHandler))
	waitRunning(t, resp, "Responder")
	gid := mustID(t, resp, KindWriterGroup, mustID(t, resp, KindConnection, Root, "Responder"), "Actions")
	wid := mustID(t, resp, KindDataSetWriter, gid, "CalcWriter")
	require.Never(t, func() bool {
		s, _ := resp.State(gid)
		w, _ := resp.State(wid)
		return s == ua.PubSubStateOperational || w == ua.PubSubStateOperational
	}, 200*time.Millisecond, 5*time.Millisecond)
	s, err := resp.State(gid)
	require.NoError(t, err)
	require.Equal(t, ua.PubSubStatePreOperational, s)

	bus.mu.Lock()
	delete(bus.failSub, queue)
	bus.mu.Unlock()
	waitState(t, resp, wid, ua.PubSubStateOperational)
	// Operational means it hears requests: the first call is answered.
	req := startReal(t, qcfg)
	waitRunning(t, req, "Requestor")
	tg := calcTarget()
	tg.RequestAddress = queue
	tg.RequestMetaData = MetaData("CalcRequest", Field{Name: "A", Type: ua.TypeIDInt32}, Field{Name: "B", Type: ua.TypeIDInt32})
	res, err := req.CallAction(context.Background(), tg, int32s(2, 3))
	require.NoError(t, err)
	require.Equal(t, int32(5), res.Outputs[0].Value())
}

// Regression: a UADP ActionRequest for a DataSetWriter the Responder does
// not have was filtered before it was counted, unlike one for an unknown
// Action target, although ActionRequestsRejected is documented to count
// both. It is counted now, and still not answered.
func TestRegressionActionRequestUnknownWriterCounted(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	resp := startReal(t, responderConfig(url, 20*time.Millisecond, ua.MessageSecurityModeNone), WithActionHandler("Calc", 1, addHandler))
	waitRunning(t, resp, "Responder")
	waitResponder(t, resp)
	cid := mustID(t, resp, KindConnection, Root, "Responder")
	rid := message.NewPublisherID(message.PublisherIDUInt16, 7)
	request := func(pub uint16, dswid uint16) []byte {
		b, err := uadp.Encode(&message.NetworkMessage{
			Type: message.NetworkMessageDataSet, PublisherID: message.NewPublisherID(message.PublisherIDUInt16, uint64(pub)),
			UADPMask: ua.UADPNetworkMessageContentMaskPublisherID | ua.UADPNetworkMessageContentMaskPayloadHeader,
			Messages: []*message.DataSetMessage{{DataSetWriterID: dswid, Type: message.DataSetMessageActionRequest, Valid: true,
				ActionTargetID: 1, RequestID: 1, ActionState: ua.ActionStateExecuting}},
			Action: &message.ActionHeader{Type: message.ActionRequest, CorrelationData: []byte("c"), RequestorID: &rid, TimeoutHint: 5000},
		}, nil)
		require.NoError(t, err)
		return b
	}
	bus.inject(url, "", request(1, 999))                                      // this Responder, an unknown writer: rejected
	bus.inject(url, "", request(2, 999))                                      // another Responder: not counted
	bus.inject(url, "", rawRequest(t, 1, 9, 2, ua.ActionStateExecuting, "c")) // an unknown target: rejected
	require.Eventually(t, func() bool { return actCounters(resp, cid).ActionRequestsRejected == 2 }, 3*time.Second, time.Millisecond)
	require.Never(t, func() bool { return actCounters(resp, cid).ActionRequestsRejected > 2 }, 100*time.Millisecond, 5*time.Millisecond)
	require.Empty(t, responses(url))
}
