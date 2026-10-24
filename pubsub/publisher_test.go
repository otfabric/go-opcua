// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

type pubFixture struct {
	t   *testing.T
	p   *PubSub
	url string
	ds  *MemoryDataSource
}

func testPDS(name string) *ua.PublishedDataSetDataType {
	return PublishedDataItems(name, Var("a", nodeA, ua.TypeIDInt32), Var("b", nodeB, ua.TypeIDInt32), Var("c", nodeC, ua.TypeIDInt32))
}

// publisherOnly starts a publisher with a connection carrying the groups.
func publisherOnly(t *testing.T, conn func(url string) *ua.PubSubConnectionDataType, pds []*ua.PublishedDataSetDataType, opts ...Option) *pubFixture {
	t.Helper()
	url := memURL(t)
	ds := NewMemoryDataSource()
	require.NoError(t, ds.Set(nodeA, int32(1)))
	require.NoError(t, ds.Set(nodeB, int32(2)))
	require.NoError(t, ds.Set(nodeC, int32(3)))
	opts = append([]Option{WithDataSource(ds)}, opts...)
	p := start(t, NewConfiguration(pds, conn(url)), opts...)
	return &pubFixture{t: t, p: p, url: url, ds: ds}
}

func (f *pubFixture) sent() []*fakeNM {
	var out []*fakeNM
	for _, s := range bus.sentTo(f.url) {
		out = append(out, decodeSent(f.t, s.Payload))
	}
	return out
}

func (f *pubFixture) waitSent(n int) []*fakeNM {
	f.t.Helper()
	require.Eventually(f.t, func() bool { return len(bus.sentTo(f.url)) >= n }, 3*time.Second, time.Millisecond)
	return f.sent()
}

func dsmTypes(nms []*fakeNM) []message.DataSetMessageType {
	var out []message.DataSetMessageType
	for _, nm := range nms {
		for _, m := range nm.Msgs {
			out = append(out, m.Type)
		}
	}
	return out
}

func TestPublishingInterval(t *testing.T) {
	t.Parallel()
	f := publisherOnly(t, func(url string) *ua.PubSubConnectionDataType {
		return AttachWriterGroups(memConnection("c", url, uint16(1)), WriterGroup("wg", 1, 20*time.Millisecond, DataSetWriter("w", 1, "pds")))
	}, []*ua.PublishedDataSetDataType{testPDS("pds")})
	nms := f.waitSent(6)
	sent := bus.sentTo(f.url)
	gap := sent[5].At.Sub(sent[1].At) / 4
	// The ticker keeps the average interval; allow for a loaded machine.
	require.GreaterOrEqual(t, gap, 15*time.Millisecond)
	require.Less(t, gap, 60*time.Millisecond)
	// Network message sequence numbers count up per message.
	for i := 1; i < 6; i++ {
		require.Equal(t, nms[i-1].GH.SequenceNumber+1, nms[i].GH.SequenceNumber)
		require.Equal(t, nms[i-1].Msgs[0].Seq+1, nms[i].Msgs[0].Seq)
		require.Equal(t, uint16(1), nms[i].GH.NetworkMessageNumber)
	}
	require.Equal(t, uint16(1), nms[0].GH.WriterGroupID)
	require.NotZero(t, nms[0].GH.GroupVersion)
	require.Equal(t, DefaultUADPNetworkMessageContentMask, nms[0].UADPMask)
	require.Equal(t, DefaultUADPDataSetMessageContentMask, nms[0].Msgs[0].UADPMask)
	require.Equal(t, message.FieldEncodingVariant, nms[0].Msgs[0].FE)
	require.NotZero(t, nms[0].Msgs[0].Ver.MajorVersion)
}

func TestOffset(t *testing.T) {
	t.Parallel()
	begin := time.Now()
	f := publisherOnly(t, func(url string) *ua.PubSubConnectionDataType {
		wg := WriterGroup("wg", 1, time.Hour, DataSetWriter("w", 1, "pds"))
		wg.MessageSettings.Value.(*ua.UADPWriterGroupMessageDataType).PublishingOffset = []float64{40}
		return AttachWriterGroups(memConnection("c", url, uint16(1)), wg)
	}, []*ua.PublishedDataSetDataType{testPDS("pds")})
	f.waitSent(1)
	require.GreaterOrEqual(t, bus.sentTo(f.url)[0].At.Sub(begin), 40*time.Millisecond)
}

func TestKeyFrameCountAndKeepAlive(t *testing.T) {
	t.Parallel()
	f := publisherOnly(t, func(url string) *ua.PubSubConnectionDataType {
		w := DataSetWriter("w", 1, "pds")
		w.KeyFrameCount = 4
		wg := WriterGroup("wg", 1, 10*time.Millisecond, w)
		wg.KeepAliveTime = 25
		return AttachWriterGroups(memConnection("c", url, uint16(1)), wg)
	}, []*ua.PublishedDataSetDataType{testPDS("pds")})
	// Values do not change: a key frame every 4 intervals, keep-alives in
	// between once KeepAliveTime passed, no empty delta frames.
	nms := f.waitSent(8)
	types := dsmTypes(nms)
	require.Equal(t, message.DataSetMessageKeyFrame, types[0])
	var keys, kas int
	for _, typ := range types {
		switch typ {
		case message.DataSetMessageKeyFrame:
			keys++
		case message.DataSetMessageKeepAlive:
			kas++
		default:
			t.Fatalf("unexpected %v in %v", typ, types)
		}
	}
	require.Positive(t, kas)
	require.Positive(t, keys)
	// The keep-alive carries the next sequence number.
	for i, nm := range nms {
		if nm.Msgs[0].Type == message.DataSetMessageKeepAlive {
			require.Equal(t, nms[i-1].Msgs[0].Seq+1, nm.Msgs[0].Seq)
			break
		}
	}

	// A change is sent as a delta frame with only the changed field.
	v := int32(100)
	require.Eventually(t, func() bool {
		v++
		require.NoError(t, f.ds.Set(nodeB, v))
		for _, nm := range f.sent() {
			for _, m := range nm.Msgs {
				if m.Type == message.DataSetMessageDeltaFrame {
					return len(m.Fields) == 1 && m.Fields[0].Index == 1
				}
			}
		}
		return false
	}, 2*time.Second, time.Millisecond)
	st, err := f.p.Status(Root)
	require.NoError(t, err)
	require.Positive(t, st.Counters.KeepAlivesSent)
}

func TestHeartbeatWriter(t *testing.T) {
	t.Parallel()
	f := publisherOnly(t, func(url string) *ua.PubSubConnectionDataType {
		return AttachWriterGroups(memConnection("c", url, uint16(1)), WriterGroup("wg", 1, 10*time.Millisecond, DataSetWriter("hb", 3, "")))
	}, nil)
	nms := f.waitSent(3)
	for _, nm := range nms[:3] {
		require.Equal(t, message.DataSetMessageKeepAlive, nm.Msgs[0].Type)
		require.Equal(t, uint32(1), nm.Msgs[0].Seq)
	}
}

func TestSubstituteValueAndFieldMask(t *testing.T) {
	t.Parallel()
	pds := PublishedDataItems("pds",
		PublishedField{Field: Field{Name: "missing", Type: ua.TypeIDInt32}, NodeID: ua.NewStringNodeID(1, "missing"), Substitute: int32(-5)},
		PublishedField{Field: Field{Name: "missing2", Type: ua.TypeIDInt32}, NodeID: ua.NewStringNodeID(1, "missing2")},
		Var("a", nodeA, ua.TypeIDInt32),
	)
	f := publisherOnly(t, func(url string) *ua.PubSubConnectionDataType {
		w := DataSetWriter("w", 1, "pds")
		w.DataSetFieldContentMask = ua.DataSetFieldContentMaskStatusCode | ua.DataSetFieldContentMaskSourceTimestamp
		v := DataSetWriter("v", 2, "pds")
		return AttachWriterGroups(memConnection("c", url, uint16(1)), WriterGroup("wg", 1, 10*time.Millisecond, w, v))
	}, []*ua.PublishedDataSetDataType{pds})
	nm := f.waitSent(1)[0]
	require.Len(t, nm.Msgs, 2)
	decode := func(b []byte) *ua.DataValue {
		dv := new(ua.DataValue)
		_, err := dv.Decode(b)
		require.NoError(t, err)
		return dv
	}
	dvm := nm.Msgs[0]
	require.Equal(t, message.FieldEncodingDataValue, dvm.FE)
	sub := decode(dvm.Fields[0].DV)
	require.Equal(t, int32(-5), sub.Value.Value())
	require.Equal(t, ua.StatusUncertainSubstituteValue, sub.Status)
	require.False(t, sub.SourceTimestamp.IsZero())
	require.Equal(t, ua.StatusBadNodeIDUnknown, decode(dvm.Fields[1].DV).Status)
	good := decode(dvm.Fields[2].DV)
	require.Equal(t, int32(1), good.Value.Value())
	require.False(t, good.Has(ua.DataValueStatusCode))
	// Variant encoding: the Bad status is sent as the value.
	vm := nm.Msgs[1]
	require.Equal(t, message.FieldEncodingVariant, vm.FE)
	require.Equal(t, ua.StatusBadNodeIDUnknown, decode(vm.Fields[1].DV).Value.Value())
	require.False(t, decode(vm.Fields[2].DV).Has(ua.DataValueSourceTimestamp))
}

func TestNoDataSource(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	p := start(t, NewConfiguration([]*ua.PublishedDataSetDataType{testPDS("pds")},
		AttachWriterGroups(memConnection("c", url, uint16(1)), WriterGroup("wg", 1, 10*time.Millisecond, DataSetWriter("w", 1, "pds")))))
	_ = p
	require.Eventually(t, func() bool { return len(bus.sentTo(url)) > 0 }, 2*time.Second, time.Millisecond)
	nm := decodeSent(t, bus.sentTo(url)[0].Payload)
	dv := new(ua.DataValue)
	_, err := dv.Decode(nm.Msgs[0].Fields[0].DV)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadWaitingForInitialData, dv.Value.Value())
}

func TestOrderingSplittingAndRepeat(t *testing.T) {
	t.Parallel()
	f := publisherOnly(t, func(url string) *ua.PubSubConnectionDataType {
		wg := WriterGroup("wg", 1, time.Hour, DataSetWriter("w3", 3, "pds"), DataSetWriter("w1", 1, "pds"), DataSetWriter("w2", 2, "pds"), DataSetWriter("w4", 4, "pds"))
		wg.MessageSettings.Value.(*ua.UADPWriterGroupMessageDataType).DataSetOrdering = ua.DataSetOrderingTypeAscendingWriterID
		wg.MaxNetworkMessageSize = 1000
		wg.TransportSettings = ua.NewExtensionObject(&ua.DatagramWriterGroupTransportDataType{MessageRepeatCount: 1, MessageRepeatDelay: 1})
		return AttachWriterGroups(memConnection("c", url, uint16(1)), wg)
	}, []*ua.PublishedDataSetDataType{testPDS("pds")})
	f.waitSent(4)
	time.Sleep(20 * time.Millisecond)
	nms := f.sent()
	var ids []uint16
	var numbers []uint16
	for i, nm := range nms {
		require.LessOrEqual(t, len(bus.sentTo(f.url)[i].Payload), 1000)
		if i%2 == 1 {
			require.Equal(t, nms[i-1], nm, "repeated")
			continue
		}
		numbers = append(numbers, nm.GH.NetworkMessageNumber)
		for _, m := range nm.Msgs {
			ids = append(ids, m.WID)
		}
	}
	require.Equal(t, []uint16{1, 2, 3, 4}, ids)
	require.Greater(t, len(numbers), 1, "split into several NetworkMessages")
	for i, n := range numbers {
		require.Equal(t, uint16(i+1), n)
	}
}

func TestSingleOrderingAndOversize(t *testing.T) {
	t.Parallel()
	f := publisherOnly(t, func(url string) *ua.PubSubConnectionDataType {
		wg := WriterGroup("wg", 1, time.Hour, DataSetWriter("w2", 2, "pds"), DataSetWriter("w1", 1, "pds"))
		wg.MessageSettings.Value.(*ua.UADPWriterGroupMessageDataType).DataSetOrdering = ua.DataSetOrderingTypeAscendingWriterIDSingle
		return AttachWriterGroups(memConnection("c", url, uint16(1)), wg)
	}, []*ua.PublishedDataSetDataType{testPDS("pds")})
	nms := f.waitSent(2)
	require.Len(t, nms[0].Msgs, 1)
	require.Equal(t, uint16(1), nms[0].Msgs[0].WID)
	require.Equal(t, uint16(2), nms[1].Msgs[0].WID)

	g := publisherOnly(t, func(url string) *ua.PubSubConnectionDataType {
		wg := WriterGroup("wg", 1, 10*time.Millisecond, DataSetWriter("w", 1, "pds"))
		wg.MaxNetworkMessageSize = 50
		return AttachWriterGroups(memConnection("c", url+"x", uint16(1)), wg)
	}, []*ua.PublishedDataSetDataType{testPDS("pds")})
	require.Eventually(t, func() bool {
		st, _ := g.p.Status(Root)
		return st.Counters.EncodeErrors > 0 && strings.Contains(errString(g.p), "MaxNetworkMessageSize")
	}, 2*time.Second, time.Millisecond)
}

func errString(p *PubSub) string {
	for _, c := range p.Components() {
		if st, _ := p.Status(c.ID); st.LastError != nil {
			return st.LastError.Error()
		}
	}
	return ""
}

func TestNoPayloadHeader(t *testing.T) {
	t.Parallel()
	f := publisherOnly(t, func(url string) *ua.PubSubConnectionDataType {
		wg := WriterGroup("wg", 1, time.Hour, DataSetWriter("w1", 1, "pds"), DataSetWriter("w2", 2, "pds"))
		wg.MessageSettings.Value.(*ua.UADPWriterGroupMessageDataType).NetworkMessageContentMask &^= ua.UADPNetworkMessageContentMaskPayloadHeader
		return AttachWriterGroups(memConnection("c", url, uint16(1)), wg)
	}, []*ua.PublishedDataSetDataType{testPDS("pds")})
	nms := f.waitSent(2)
	require.Len(t, nms[0].Msgs, 1)
	require.Len(t, nms[1].Msgs, 1)
}

func TestSecuredGroup(t *testing.T) {
	t.Parallel()
	keys := newFakeKeys(3)
	keys.setFail(true)
	url := memURL(t)
	pdsCfg := testPDS("pds")
	pubCfg := NewConfiguration([]*ua.PublishedDataSetDataType{pdsCfg},
		AttachWriterGroups(memConnection("c", url, uint16(1)), Secure(WriterGroup("wg", 1, 10*time.Millisecond, DataSetWriter("w", 1, "pds")), ua.MessageSecurityModeSignAndEncrypt, "sg")))
	ds := NewMemoryDataSource()
	pub := start(t, pubCfg, WithDataSource(ds), WithKeySource("sg", keys))
	wgID := mustID(t, pub, KindWriterGroup, mustID(t, pub, KindConnection, Root, "c"), "wg")
	waitState(t, pub, wgID, ua.PubSubStatePreOperational)
	wID := mustID(t, pub, KindDataSetWriter, wgID, "w")
	s, _ := pub.State(wID)
	require.Equal(t, ua.PubSubStatePaused, s)
	time.Sleep(40 * time.Millisecond)
	require.Empty(t, bus.sentTo(url), "a secured group without keys sends nothing")

	// Subscribers: one that requires security with keys, one without keys,
	// one that does not require security but has the keys.
	rec := &recorder{}
	md := DataSetMetaDataOf(pdsCfg)
	sub := start(t, NewConfiguration(nil, AttachReaderGroups(memConnection("s", url, nil),
		Secure(ReaderGroup("secure", DataSetReader("r1", uint16(1), 1, 1, md)), ua.MessageSecurityModeSign, "sg"),
	)), WithDataSetHandler(rec.handler), WithKeySourceLookup(func(id string) security.KeySource {
		if id == "sg" {
			return keys
		}
		return nil
	}))
	noKeys := &recorder{}
	sub2 := start(t, NewConfiguration(nil, AttachReaderGroups(memConnection("s", url, nil),
		Secure(ReaderGroup("secure", DataSetReader("r1", uint16(1), 1, 1, md)), ua.MessageSecurityModeSign, "sg"),
	)), WithDataSetHandler(noKeys.handler))

	keys.setFail(false)
	waitState(t, pub, wgID, ua.PubSubStateOperational)
	waitState(t, pub, wID, ua.PubSubStateOperational)
	require.Eventually(t, func() bool { return len(rec.dataSets()) > 0 }, 2*time.Second, time.Millisecond)
	require.Eventually(t, func() bool { return len(bus.sentTo(url)) >= 2 }, 2*time.Second, time.Millisecond)
	nms := bus.sentTo(url)
	a, b := decodeSent(t, nms[0].Payload), decodeSent(t, nms[1].Payload)
	require.Equal(t, ua.MessageSecurityModeSignAndEncrypt, a.Secured)
	require.Equal(t, uint32(3), a.Token)
	require.Equal(t, a.Nonce+1, b.Nonce, "the nonce sequence increments per message")
	// sub2 receives on its own goroutine: wait for it to have refused a
	// message rather than read its counter once.
	require.Eventually(t, func() bool {
		st, _ := sub2.Status(Root)
		return st.Counters.DecodeErrors > 0
	}, 2*time.Second, time.Millisecond)
	require.Empty(t, noKeys.dataSets())

	// Keys gone: back to PreOperational.
	keys.setFail(true)
	waitState(t, pub, wgID, ua.PubSubStatePreOperational)

	// An unsecured publisher is refused by the secure reader.
	before := len(rec.dataSets())
	plainURL := url
	plain := start(t, NewConfiguration([]*ua.PublishedDataSetDataType{testPDS("pds")},
		AttachWriterGroups(memConnection("c", plainURL, uint16(1)), WriterGroup("wg", 1, 10*time.Millisecond, DataSetWriter("w", 1, "pds")))))
	_ = plain
	require.Eventually(t, func() bool {
		st, _ := sub.Status(Root)
		return st.Counters.DecodeErrors > 0
	}, 2*time.Second, time.Millisecond)
	require.Len(t, rec.dataSets(), before)

	// SetKeySource at run time.
	pub.SetKeySource("sg", newFakeKeys(9))
	waitState(t, pub, wgID, ua.PubSubStateOperational)
	pub.SetKeySource("sg", nil)
	require.Nil(t, pub.KeySource("sg"))
}

func TestEventsPublished(t *testing.T) {
	t.Parallel()
	es := &fakeEvents{}
	pds := &ua.PublishedDataSetDataType{
		Name: "events",
		DataSetSource: ua.NewExtensionObject(&ua.PublishedEventsDataType{
			EventNotifier: ua.NewNumericNodeID(0, 2253),
			SelectedFields: []*ua.SimpleAttributeOperand{
				{BrowsePath: []*ua.QualifiedName{{Name: "Message"}}, AttributeID: ua.AttributeIDValue},
				{BrowsePath: []*ua.QualifiedName{{Name: "Severity"}}, AttributeID: ua.AttributeIDValue},
			},
		}),
	}
	f := publisherOnly(t, func(url string) *ua.PubSubConnectionDataType {
		w := DataSetWriter("w", 1, "events")
		w.KeyFrameCount = 0
		return AttachWriterGroups(memConnection("c", url, uint16(1)), WriterGroup("wg", 1, 10*time.Millisecond, w))
	}, []*ua.PublishedDataSetDataType{pds}, WithEventSource(es))
	require.Eventually(t, func() bool { return es.subscribed() }, 2*time.Second, time.Millisecond)
	es.emit(ua.MustVariant("hello"), ua.MustVariant(uint16(500)))
	es.emit(ua.MustVariant("world"), ua.MustVariant(uint16(100)))
	require.Eventually(t, func() bool {
		n := 0
		for _, nm := range f.sent() {
			for _, m := range nm.Msgs {
				if m.Type == message.DataSetMessageEvent {
					n++
				}
			}
		}
		return n == 2
	}, 2*time.Second, time.Millisecond)
	cfg, err := f.p.PublishedDataSetConfig(mustID(t, f.p, KindPublishedDataSet, Root, "events"))
	require.NoError(t, err)
	require.Equal(t, "Message", cfg.DataSetMetaData.Fields[0].Name)

	// Disabling the writer cancels the event subscription.
	wID := mustID(t, f.p, KindDataSetWriter, mustID(t, f.p, KindWriterGroup, mustID(t, f.p, KindConnection, Root, "c"), "wg"), "w")
	require.NoError(t, f.p.Disable(wID))
	require.Eventually(t, func() bool { return !es.subscribed() }, 2*time.Second, time.Millisecond)
}

type fakeEvents struct {
	mu      sync.Mutex
	deliver func([]*ua.Variant)
}

func (e *fakeEvents) SubscribeEvents(_ context.Context, _ *ua.PublishedEventsDataType, deliver func([]*ua.Variant)) (func(), error) {
	e.mu.Lock()
	e.deliver = deliver
	e.mu.Unlock()
	return func() {
		e.mu.Lock()
		e.deliver = nil
		e.mu.Unlock()
	}, nil
}

func (e *fakeEvents) subscribed() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.deliver != nil
}

func (e *fakeEvents) emit(fields ...*ua.Variant) {
	e.mu.Lock()
	d := e.deliver
	e.mu.Unlock()
	d(fields)
}
