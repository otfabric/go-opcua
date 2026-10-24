// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

var testMD = MetaData("ds", Field{Name: "a", Type: ua.TypeIDInt32}, Field{Name: "b", Type: ua.TypeIDInt32}, Field{Name: "c", Type: ua.TypeIDInt32})

type subFixture struct {
	t   *testing.T
	p   *PubSub
	url string
	rid ComponentID
	rec *recorder
}

// subscriberOnly starts a runtime with one reader of publisher 7, writer
// group 10, writer 20 on a fresh bus.
func subscriberOnly(t *testing.T, adjust func(r *ua.DataSetReaderDataType), opts ...Option) *subFixture {
	t.Helper()
	url := memURL(t)
	md, _ := clone(testMD)
	r := DataSetReader("r", uint16(7), 10, 20, md)
	if adjust != nil {
		adjust(r)
	}
	rec := &recorder{}
	opts = append([]Option{WithDataSetHandler(rec.handler), WithTargetWriter(rec), WithEventHandler(rec.event)}, opts...)
	p := start(t, NewConfiguration(nil, AttachReaderGroups(memConnection("sub", url, nil), ReaderGroup("rg", r))), opts...)
	rid := mustID(t, p, KindDataSetReader, mustID(t, p, KindReaderGroup, mustID(t, p, KindConnection, Root, "sub"), "rg"), "r")
	require.Eventually(t, func() bool { return bus.subscribers(url) == 1 }, 2*time.Second, time.Millisecond)
	return &subFixture{t: t, p: p, url: url, rid: rid, rec: rec}
}

// msg builds a UADP NetworkMessage of publisher 7, writer group 10 with one
// DataSetMessage of writer 20.
func msg(typ message.DataSetMessageType, seq uint32, vals ...int32) *message.NetworkMessage {
	dsm := &message.DataSetMessage{
		DataSetWriterID: 20, Type: typ, Valid: true, SequenceNumber: seq,
		UADPMask: DefaultUADPDataSetMessageContentMask, Status: ua.StatusGood,
	}
	for i, v := range vals {
		f := &message.Field{Index: uint16(i), Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)}}
		dsm.Fields = append(dsm.Fields, f)
	}
	return &message.NetworkMessage{
		Type: message.NetworkMessageDataSet, UADPMask: DefaultUADPNetworkMessageContentMask,
		PublisherID: message.NewPublisherID(message.PublisherIDUInt16, 7),
		GroupHeader: message.GroupHeader{WriterGroupID: 10}, Messages: []*message.DataSetMessage{dsm},
	}
}

func delta(seq uint32, idx uint16, v int32) *message.NetworkMessage {
	nm := msg(message.DataSetMessageDeltaFrame, seq)
	nm.Messages[0].Fields = []*message.Field{{Index: idx, Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)}}}
	return nm
}

func (f *subFixture) send(nm *message.NetworkMessage) {
	f.t.Helper()
	b, err := fakeCodecs(encUADP).Encode(nm, nil)
	require.NoError(f.t, err)
	bus.inject(f.url, "", b)
}

// sendSync sends and waits until the reader handled the message and the
// runtime called the handlers of what it delivered.
func (f *subFixture) sendSync(nm *message.NetworkMessage) {
	f.t.Helper()
	before := f.handled()
	f.send(nm)
	require.Eventually(f.t, func() bool { return f.handled() > before && bus.settled(f.url) }, 2*time.Second, time.Millisecond)
}

func (f *subFixture) handled() uint64 {
	st, err := f.p.Status(f.rid)
	require.NoError(f.t, err)
	c := st.Counters
	return c.DataSetMessagesReceived + c.KeepAlivesReceived + c.SequenceDiscards + c.VersionMismatches
}

func (f *subFixture) counters() Counters {
	st, err := f.p.Status(f.rid)
	require.NoError(f.t, err)
	return st.Counters
}

func (f *subFixture) last() *ReceivedDataSet {
	f.t.Helper()
	var ds *ReceivedDataSet
	require.Eventually(f.t, func() bool {
		s := f.rec.dataSets()
		if len(s) == 0 {
			return false
		}
		ds = s[len(s)-1]
		return true
	}, 2*time.Second, time.Millisecond)
	return ds
}

func TestDeltaMerge(t *testing.T) {
	t.Parallel()
	f := subscriberOnly(t, nil)
	// A delta before any key frame is delivered but incomplete.
	f.sendSync(delta(1, 1, 5))
	ds := f.last()
	require.False(t, ds.Complete)
	require.Nil(t, ds.Fields[0].Value)
	require.Equal(t, int32(5), ds.Fields[1].Value.Value.Value())

	f.sendSync(msg(message.DataSetMessageKeyFrame, 2, 1, 2, 3))
	ds = f.last()
	require.True(t, ds.Complete)
	require.Equal(t, []int32{1, 2, 3}, int32Values(ds))
	require.Equal(t, []int{0, 1, 2}, ds.Changed)
	require.Equal(t, message.DataSetMessageKeyFrame, ds.MessageType)

	f.sendSync(delta(3, 2, 30))
	ds = f.last()
	require.True(t, ds.Complete)
	require.Equal(t, message.DataSetMessageDeltaFrame, ds.MessageType)
	require.Equal(t, []int32{1, 2, 30}, int32Values(ds))
	require.Equal(t, []int{2}, ds.Changed)
	require.Equal(t, uint32(3), ds.SequenceNumber)
	require.NotNil(t, ds.Field("c"))
	require.Nil(t, ds.Field("nope"))
}

func TestSequenceNumbers(t *testing.T) {
	t.Parallel()
	f := subscriberOnly(t, nil)
	f.sendSync(msg(message.DataSetMessageKeyFrame, 100, 1, 1, 1))
	require.Len(t, f.rec.dataSets(), 1)

	// Duplicate and older messages are discarded.
	f.sendSync(msg(message.DataSetMessageKeyFrame, 100, 2, 2, 2))
	f.sendSync(msg(message.DataSetMessageKeyFrame, 99, 3, 3, 3))
	require.Equal(t, uint64(2), f.counters().SequenceDiscards)
	require.Len(t, f.rec.dataSets(), 1)

	// A keep-alive carries the next sequence number and does not consume
	// it.
	f.sendSync(msg(message.DataSetMessageKeepAlive, 101))
	f.sendSync(msg(message.DataSetMessageKeyFrame, 101, 4, 4, 4))
	require.Len(t, f.rec.dataSets(), 2)
	require.Equal(t, uint64(1), f.counters().KeepAlivesReceived)

	// A jump of more than a quarter of the number space resynchronises,
	// gaps below are lost messages, and the 16 bit numbers wrap around.
	f.sendSync(msg(message.DataSetMessageKeyFrame, 30000, 5, 5, 5))
	require.Equal(t, uint64(1), f.counters().SequenceResyncs)
	for _, s := range []uint32{40000, 50000, 60000} {
		f.sendSync(msg(message.DataSetMessageKeyFrame, s, 5, 5, 5))
	}
	f.sendSync(msg(message.DataSetMessageKeyFrame, 65535, 6, 6, 6))
	f.sendSync(msg(message.DataSetMessageKeyFrame, 65536+0, 7, 7, 7))
	f.sendSync(msg(message.DataSetMessageKeyFrame, 65536+2, 8, 8, 8))
	require.Equal(t, []int32{8, 8, 8}, int32Values(f.last()))
	// 65535 is now older than 2.
	f.sendSync(msg(message.DataSetMessageKeyFrame, 65535, 9, 9, 9))
	require.Equal(t, []int32{8, 8, 8}, int32Values(f.last()))
	require.Equal(t, uint64(3), f.counters().SequenceDiscards)
	require.Len(t, f.rec.dataSets(), 9)
	require.Equal(t, uint64(1), f.counters().SequenceResyncs)
}

func TestCompareSeq(t *testing.T) {
	t.Parallel()
	require.Equal(t, seqNewer, compareSeq(1, 0, true))
	require.Equal(t, seqNewer, compareSeq(0, 65535, true))
	require.Equal(t, seqDuplicate, compareSeq(5, 5, true))
	require.Equal(t, seqOlder, compareSeq(65535, 0, true))
	require.Equal(t, seqResync, compareSeq(30000, 0, true))
	require.Equal(t, seqNewer, compareSeq(0, 1<<32-1, false))
	require.Equal(t, seqOlder, compareSeq(1<<32-1, 0, false))
	require.Equal(t, seqResync, compareSeq(1<<31, 0, false))
	require.Equal(t, seqNewer, compareSeq(70000, 69999, false))
}

func TestFilters(t *testing.T) {
	t.Parallel()
	f := subscriberOnly(t, nil)
	other := msg(message.DataSetMessageKeyFrame, 1, 1, 1, 1)
	other.PublisherID = message.NewPublisherID(message.PublisherIDUInt16, 8)
	f.send(other)
	wg := msg(message.DataSetMessageKeyFrame, 2, 1, 1, 1)
	wg.GroupHeader.WriterGroupID = 11
	f.send(wg)
	w := msg(message.DataSetMessageKeyFrame, 3, 1, 1, 1)
	w.Messages[0].DataSetWriterID = 21
	f.send(w)
	noPub := msg(message.DataSetMessageKeyFrame, 4, 1, 1, 1)
	noPub.UADPMask &^= ua.UADPNetworkMessageContentMaskPublisherID
	f.send(noPub)
	f.sendSync(msg(message.DataSetMessageKeyFrame, 5, 9, 9, 9))
	sets := f.rec.dataSets()
	require.Len(t, sets, 1)
	require.Equal(t, uint32(5), sets[0].SequenceNumber)
	// Filtered messages are not decode errors.
	st, err := f.p.Status(Root)
	require.NoError(t, err)
	require.Zero(t, st.Counters.DecodeErrors)

	bus.inject(f.url, "", []byte("Ugarbage"))
	require.Eventually(t, func() bool {
		st, _ := f.p.Status(Root)
		return st.Counters.DecodeErrors == 1
	}, 2*time.Second, time.Millisecond)
}

func TestInvalidAndVersionMismatch(t *testing.T) {
	t.Parallel()
	f := subscriberOnly(t, func(r *ua.DataSetReaderDataType) {
		r.DataSetMetaData.ConfigurationVersion = &ua.ConfigurationVersionDataType{MajorVersion: 5, MinorVersion: 5}
	})
	inv := msg(message.DataSetMessageKeyFrame, 1, 1, 1, 1)
	inv.Messages[0].Valid = false
	f.send(inv)
	bad := msg(message.DataSetMessageKeyFrame, 2, 1, 1, 1)
	bad.Messages[0].MetaDataVersion = ua.ConfigurationVersionDataType{MajorVersion: 4}
	f.sendSync(bad)
	require.Equal(t, uint64(1), f.counters().VersionMismatches)
	good := msg(message.DataSetMessageKeyFrame, 3, 1, 1, 1)
	good.Messages[0].MetaDataVersion = ua.ConfigurationVersionDataType{MajorVersion: 5, MinorVersion: 9}
	f.sendSync(good)
	require.Len(t, f.rec.dataSets(), 1)
}

func TestMessageReceiveTimeout(t *testing.T) {
	t.Parallel()
	f := subscriberOnly(t, func(r *ua.DataSetReaderDataType) {
		// Well above the 25 ms between the keep-alives below, so that a
		// slow scheduler (race detector, loaded CI runner) does not time
		// the reader out while they keep it alive.
		r.MessageReceiveTimeout = 500
		SetTargetVariables(r,
			&ua.FieldTargetDataType{TargetNodeID: nodeA, AttributeID: ua.AttributeIDValue, OverrideValueHandling: ua.OverrideValueHandlingLastUsableValue},
			&ua.FieldTargetDataType{TargetNodeID: nodeB, AttributeID: ua.AttributeIDValue, OverrideValueHandling: ua.OverrideValueHandlingOverrideValue, OverrideValue: ua.MustVariant(int32(-1))},
			&ua.FieldTargetDataType{TargetNodeID: nodeC, AttributeID: ua.AttributeIDValue},
		)
	})
	// No message at all: PreOperational -> Error.
	waitState(t, f.p, f.rid, ua.PubSubStateError)
	require.Empty(t, f.rec.writes(), "no override before the reader was Operational")
	require.Equal(t, uint64(1), f.counters().Timeouts)

	f.sendSync(msg(message.DataSetMessageKeyFrame, 1, 1, 2, 3))
	waitState(t, f.p, f.rid, ua.PubSubStateOperational)
	require.Eventually(t, func() bool { return len(f.rec.writes()) == 3 }, 5*time.Second, time.Millisecond)
	f.rec.reset()

	// Messages keep the reader Operational.
	for i := range 4 {
		time.Sleep(25 * time.Millisecond)
		f.sendSync(msg(message.DataSetMessageKeepAlive, uint32(2+i)))
	}
	s, _ := f.p.State(f.rid)
	require.Equal(t, ua.PubSubStateOperational, s)

	waitState(t, f.p, f.rid, ua.PubSubStateError)
	require.Eventually(t, func() bool { return len(f.rec.writes()) == 2 }, 5*time.Second, time.Millisecond)
	w := f.rec.writes()
	require.Equal(t, nodeA, w[0].Target.TargetNodeID)
	require.Equal(t, int32(1), w[0].Value.Value.Value())
	require.Equal(t, ua.StatusUncertainLastUsableValue, w[0].Value.Status)
	require.Equal(t, int32(-1), w[1].Value.Value.Value())

	var errEv bool
	for _, ev := range f.rec.events() {
		if ev.Type == EventStateChanged && ev.Component.ID == f.rid && ev.Component.State == ua.PubSubStateError {
			errEv = true
			require.ErrorIs(t, ev.Err, ua.StatusBadTimeout)
		}
	}
	require.True(t, errEv)

	f.sendSync(msg(message.DataSetMessageKeyFrame, 9, 4, 5, 6))
	waitState(t, f.p, f.rid, ua.PubSubStateOperational)
}

func TestTargetVariablesOverride(t *testing.T) {
	t.Parallel()
	md, _ := clone(testMD)
	f := subscriberOnly(t, func(r *ua.DataSetReaderDataType) {
		r.DataSetMetaData = md
		SetTargetVariables(r,
			// Mapped by DataSetFieldId to field "c".
			&ua.FieldTargetDataType{DataSetFieldID: ua.NewGUID("11111111-2222-3333-4444-555555555555"), TargetNodeID: nodeC, AttributeID: ua.AttributeIDValue},
			&ua.FieldTargetDataType{TargetNodeID: nodeB, AttributeID: ua.AttributeIDValue, OverrideValueHandling: ua.OverrideValueHandlingLastUsableValue},
			&ua.FieldTargetDataType{TargetNodeID: nodeA, AttributeID: ua.AttributeIDValue, OverrideValueHandling: ua.OverrideValueHandlingOverrideValue, OverrideValue: ua.MustVariant(int32(77))},
		)
	})
	_ = md
	// Give field c the DataSetFieldId of the first target.
	f.p.lock()
	r := f.p.comps[f.rid].(*dataSetReader)
	r.md.Fields[2].DataSetFieldID = ua.NewGUID("11111111-2222-3333-4444-555555555555")
	f.p.unlock()

	f.sendSync(msg(message.DataSetMessageKeyFrame, 1, 1, 2, 3))
	require.Eventually(t, func() bool { return len(f.rec.writes()) == 3 }, 5*time.Second, time.Millisecond)
	w := f.rec.writes()
	require.Equal(t, nodeC, w[0].Target.TargetNodeID)
	require.Equal(t, int32(3), w[0].Value.Value.Value())
	require.Equal(t, int32(2), w[1].Value.Value.Value())
	// The third target has no DataSetFieldId: it takes field 2 by position.
	require.Equal(t, int32(3), w[2].Value.Value.Value())
	f.rec.reset()

	// Bad values: field b (Variant encoding sends the StatusCode).
	bad := msg(message.DataSetMessageDeltaFrame, 2)
	bad.Messages[0].Fields = []*message.Field{
		{Index: 1, Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(ua.StatusBadNoCommunication)}},
		{Index: 2, Value: &ua.DataValue{EncodingMask: ua.DataValueStatusCode, Status: ua.StatusBadNoCommunication}},
	}
	f.sendSync(bad)
	require.Eventually(t, func() bool { return len(f.rec.writes()) == 3 }, 5*time.Second, time.Millisecond)
	w = f.rec.writes()
	// c: Disabled -> the bad value as received.
	require.Equal(t, ua.StatusBadNoCommunication, w[0].Value.Status)
	// b: last usable value.
	require.Equal(t, int32(2), w[1].Value.Value.Value())
	require.Equal(t, ua.StatusUncertainLastUsableValue, w[1].Value.Status)
	// third target maps field index 2 by position: override value.
	require.Equal(t, int32(77), w[2].Value.Value.Value())
	ds := f.last()
	require.Equal(t, ua.StatusBadNoCommunication, ds.Fields[1].Value.Status)

	// Disabling the reader writes the overrides.
	f.rec.reset()
	require.NoError(t, f.p.Disable(f.rid))
	require.Eventually(t, func() bool { return len(f.rec.writes()) == 2 }, 5*time.Second, time.Millisecond)
}

func TestReceiverIndexRange(t *testing.T) {
	t.Parallel()
	f := subscriberOnly(t, func(r *ua.DataSetReaderDataType) {
		r.DataSetMetaData = MetaData("ds", Field{Name: "arr", Type: ua.TypeIDInt32, Array: true})
		id := ua.NewGUID("11111111-2222-3333-4444-555555555555")
		r.DataSetMetaData.Fields[0].DataSetFieldID = id
		SetTargetVariables(r,
			&ua.FieldTargetDataType{DataSetFieldID: id, TargetNodeID: nodeA, AttributeID: ua.AttributeIDValue, ReceiverIndexRange: "1:2"},
			&ua.FieldTargetDataType{DataSetFieldID: id, TargetNodeID: nodeB, AttributeID: ua.AttributeIDValue, ReceiverIndexRange: "7"},
		)
	})
	nm := msg(message.DataSetMessageKeyFrame, 1)
	nm.Messages[0].Fields = []*message.Field{{Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant([]int32{1, 2, 3, 4})}}}
	f.sendSync(nm)
	require.Eventually(t, func() bool { return len(f.rec.writes()) == 1 }, 5*time.Second, time.Millisecond)
	require.Equal(t, []int32{2, 3}, f.rec.writes()[0].Value.Value.Value())
	require.Equal(t, uint64(1), f.counters().TargetWriteErrors)
}

func TestEventMessagesReceived(t *testing.T) {
	t.Parallel()
	f := subscriberOnly(t, nil)
	f.sendSync(msg(message.DataSetMessageEvent, 1, 7, 8))
	ds := f.last()
	require.Equal(t, message.DataSetMessageEvent, ds.MessageType)
	require.True(t, ds.Complete)
	require.Equal(t, int32(7), ds.Fields[0].Value.Value.Value())
	require.Nil(t, ds.Fields[2].Value)
}

func TestTopicMatch(t *testing.T) {
	t.Parallel()
	require.True(t, topicMatch("a/b", "a/b"))
	require.True(t, topicMatch("a/+/c", "a/b/c"))
	require.True(t, topicMatch("a/#", "a/b/c"))
	require.False(t, topicMatch("a/+", "a/b/c"))
	require.False(t, topicMatch("a/b/c", "a/b"))
	require.False(t, topicMatch("a/x", "a/b"))
}

type mirrorRec struct {
	recorder
	mu sync.Mutex
	m  []*MirrorWrite
}

func (m *mirrorRec) WriteMirror(_ context.Context, w *MirrorWrite) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.m = append(m.m, w)
	if len(m.m) > 1 {
		return errors.New("mirror full")
	}
	return nil
}

func (m *mirrorRec) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.m)
}

func TestMirror(t *testing.T) {
	t.Parallel()
	mr := &mirrorRec{}
	f := subscriberOnly(t, func(r *ua.DataSetReaderDataType) { SetMirror(r, "Mirror") }, WithTargetWriter(mr))
	f.sendSync(msg(message.DataSetMessageKeyFrame, 1, 1, 2, 3))
	require.Eventually(t, func() bool { return mr.count() == 1 }, 5*time.Second, time.Millisecond)
	mr.mu.Lock()
	require.Equal(t, "Mirror", mr.m[0].Mirror.ParentNodeName)
	require.Len(t, mr.m[0].Fields, 3)
	mr.mu.Unlock()
	f.sendSync(msg(message.DataSetMessageKeyFrame, 2, 1, 2, 3))
	require.Eventually(t, func() bool { return f.counters().TargetWriteErrors == 1 }, 5*time.Second, time.Millisecond)
}

// TestSequenceNumbersAcrossMetaData: a reader that learns new DataSetMetaData
// keeps the sequence numbers of its writers. A late copy of a message
// delivered before stays stale (it was delivered again, out of order, when
// a discovery announcement arrived between the two copies).
func TestSequenceNumbersAcrossMetaData(t *testing.T) {
	t.Parallel()
	f := subscriberOnly(t, nil)
	f.sendSync(msg(message.DataSetMessageKeyFrame, 7, 1, 1, 1))

	md, _ := clone(testMD)
	md.ConfigurationVersion = &ua.ConfigurationVersionDataType{MajorVersion: md.ConfigurationVersion.MajorVersion, MinorVersion: md.ConfigurationVersion.MinorVersion + 1}
	f.send(&message.NetworkMessage{
		Type: message.NetworkMessageDiscoveryResponse, UADPMask: ua.UADPNetworkMessageContentMaskPublisherID,
		PublisherID: message.NewPublisherID(message.PublisherIDUInt16, 7),
		Discovery:   &message.Discovery{Type: message.DiscoveryDataSetMetaData, DataSetWriterID: 20, MetaData: md, StatusCode: ua.StatusGood},
	})
	require.Eventually(t, func() bool { return f.counters().MetaDataReceived == 1 && bus.settled(f.url) }, 2*time.Second, time.Millisecond)

	f.sendSync(msg(message.DataSetMessageKeyFrame, 6, 2, 2, 2))
	require.Equal(t, uint64(1), f.counters().SequenceDiscards)
	require.Len(t, f.rec.dataSets(), 1)
	f.sendSync(msg(message.DataSetMessageKeyFrame, 8, 3, 3, 3))
	require.Equal(t, []int32{3, 3, 3}, int32Values(f.last()))
}
