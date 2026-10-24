// SPDX-License-Identifier: MIT

package pubsub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/pubsub/jsonmsg"
	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/pubsub/uadp"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// In-memory transport, scheme "mem".

type memBus struct {
	mu       sync.Mutex
	subs     map[string][]*memSub
	retained map[string]map[string][]byte
	sent     map[string][]memSent
	maxSize  map[string]int
	failOpen map[string]int
	failSend map[string]bool
	// blockSend makes Send block until its context ends or the
	// connection is closed, like a broker transport waiting for an
	// acknowledgement during an outage.
	blockSend map[string]bool
	opened    map[string]int
}

type memSent struct {
	Topic   string
	QoS     byte
	Retain  bool
	Payload []byte
	At      time.Time
}

type memSub struct {
	url   string
	topic string
	h     transport.Handler
	ch    chan *transport.Message
	done  chan struct{}
	once  sync.Once
}

var bus = &memBus{
	subs:      map[string][]*memSub{},
	retained:  map[string]map[string][]byte{},
	sent:      map[string][]memSent{},
	maxSize:   map[string]int{},
	failOpen:  map[string]int{},
	failSend:  map[string]bool{},
	blockSend: map[string]bool{},
	opened:    map[string]int{},
}

func init() {
	transport.Register("mem", func(ctx context.Context, cfg transport.Config) (transport.Connection, error) {
		bus.mu.Lock()
		defer bus.mu.Unlock()
		if bus.failOpen[cfg.URL] > 0 {
			bus.failOpen[cfg.URL]--
			return nil, errors.New("mem: open refused")
		}
		bus.opened[cfg.URL]++
		return &memConn{url: cfg.URL, cfg: cfg}, nil
	})
}

func (b *memBus) sentTo(url string) []memSent {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]memSent(nil), b.sent[url]...)
}

func (b *memBus) subscribers(url string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subs[url])
}

// inject delivers a payload to the subscribers of url as if it was sent.
func (b *memBus) inject(url, topic string, payload []byte) {
	b.deliver(url, topic, payload)
}

func (b *memBus) deliver(url, topic string, payload []byte) {
	b.mu.Lock()
	subs := append([]*memSub(nil), b.subs[url]...)
	b.mu.Unlock()
	for _, s := range subs {
		if s.topic != "" && !topicMatch(s.topic, topic) {
			continue
		}
		m := &transport.Message{Payload: append([]byte(nil), payload...), Topic: topic, Received: time.Now()}
		select {
		case s.ch <- m:
		case <-s.done:
		}
	}
}

type memConn struct {
	url    string
	cfg    transport.Config
	mu     sync.Mutex
	closed bool
	subs   []*memSub
}

func (c *memConn) Send(ctx context.Context, payload []byte, opts transport.PublishOptions) error {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return errors.New("mem: closed")
	}
	bus.mu.Lock()
	if bus.failSend[c.url] {
		bus.mu.Unlock()
		return errors.New("mem: send refused")
	}
	if bus.blockSend[c.url] {
		bus.mu.Unlock()
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Millisecond):
			}
			c.mu.Lock()
			closed := c.closed
			c.mu.Unlock()
			if closed {
				return errors.New("mem: closed")
			}
		}
	}
	bus.sent[c.url] = append(bus.sent[c.url], memSent{Topic: opts.Topic, QoS: opts.QoS, Retain: opts.Retain, Payload: append([]byte(nil), payload...), At: time.Now()})
	if opts.Retain {
		if bus.retained[c.url] == nil {
			bus.retained[c.url] = map[string][]byte{}
		}
		bus.retained[c.url][opts.Topic] = append([]byte(nil), payload...)
	}
	bus.mu.Unlock()
	bus.deliver(c.url, opts.Topic, payload)
	return nil
}

func (c *memConn) Subscribe(ctx context.Context, topic string, qos byte, h transport.Handler) (func() error, error) {
	if strings.Contains(topic, "fail") {
		return nil, errors.New("mem: subscribe refused")
	}
	s := &memSub{url: c.url, topic: topic, h: h, ch: make(chan *transport.Message, 4096), done: make(chan struct{})}
	go func() {
		for {
			select {
			case <-s.done:
				return
			case m := <-s.ch:
				s.h(m)
			}
		}
	}()
	bus.mu.Lock()
	bus.subs[c.url] = append(bus.subs[c.url], s)
	var retained [][2]string
	for t, p := range bus.retained[c.url] {
		if topic == "" || topicMatch(topic, t) {
			retained = append(retained, [2]string{t, string(p)})
		}
	}
	bus.mu.Unlock()
	c.mu.Lock()
	c.subs = append(c.subs, s)
	c.mu.Unlock()
	for _, r := range retained {
		s.ch <- &transport.Message{Payload: []byte(r[1]), Topic: r[0], Received: time.Now()}
	}
	return func() error { c.remove(s); return nil }, nil
}

func (c *memConn) remove(s *memSub) {
	s.once.Do(func() { close(s.done) })
	bus.mu.Lock()
	defer bus.mu.Unlock()
	list := bus.subs[c.url]
	for i, x := range list {
		if x == s {
			bus.subs[c.url] = append(list[:i:i], list[i+1:]...)
			break
		}
	}
}

func (c *memConn) MaxMessageSize() int {
	bus.mu.Lock()
	defer bus.mu.Unlock()
	return bus.maxSize[c.url]
}

func (c *memConn) Close() error {
	c.mu.Lock()
	c.closed = true
	subs := c.subs
	c.subs = nil
	c.mu.Unlock()
	for _, s := range subs {
		c.remove(s)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Fake codec: JSON with the values in the OPC UA binary encoding. UADP
// payloads are prefixed with "U" (and keep only 16 bits of the sequence
// numbers), JSON payloads are plain objects.

type fakeField struct {
	Index uint16
	Name  string
	DV    []byte
}

type fakeDSM struct {
	WID      uint16
	Type     message.DataSetMessageType
	Valid    bool
	UADPMask ua.UADPDataSetMessageContentMask
	JSONMask ua.JSONDataSetMessageContentMask
	FCM      ua.DataSetFieldContentMask
	FE       message.FieldEncoding
	Seq      uint32
	TS       time.Time
	Status   uint32
	Ver      ua.ConfigurationVersionDataType
	Name     string
	WGName   string
	Pub      *message.PublisherID
	Fields   []fakeField
}

type fakeNM struct {
	Type      message.NetworkMessageType
	UADPMask  ua.UADPNetworkMessageContentMask
	JSONMask  ua.JSONNetworkMessageContentMask
	Pub       message.PublisherID
	GH        message.GroupHeader
	TS        time.Time
	Secured   ua.MessageSecurityMode
	Token     uint32
	Nonce     uint32
	MessageID string
	WGName    string
	Msgs      []fakeDSM
	DiscType  message.DiscoveryType
	DiscWID   uint16
	DiscMD    []byte
	Kind      string
}

type fakeCodec struct{ enc encoding }

func fakeCodecs(e encoding) codec { return fakeCodec{enc: e} }

func withFakeCodec() Option { return func(o *options) { o.codecs = fakeCodecs } }

func (f fakeCodec) Encode(nm *message.NetworkMessage, opts *uadp.EncodeOptions) ([]byte, error) {
	out := fakeNM{Type: nm.Type, UADPMask: nm.UADPMask, JSONMask: nm.JSONMask, Pub: nm.PublisherID, GH: nm.GroupHeader,
		TS: nm.Timestamp, MessageID: nm.MessageID, WGName: nm.WriterGroupName, Kind: "ua-data"}
	if opts != nil && opts.SecurityMode > ua.MessageSecurityModeNone {
		if opts.Keys == nil {
			return nil, errors.New("fake: no keys")
		}
		k, err := opts.Keys.CurrentKeys()
		if err != nil {
			return nil, err
		}
		out.Secured, out.Token, out.Nonce = opts.SecurityMode, k.TokenID, opts.NonceSequence
		if opts.NextNonceSequence != nil {
			out.Nonce = opts.NextNonceSequence()
		}
	}
	if f.enc == encUADP && nm.Type == message.NetworkMessageDataSet && len(nm.Messages) > 1 && nm.UADPMask&ua.UADPNetworkMessageContentMaskPayloadHeader == 0 {
		return nil, fmt.Errorf("%w: several DataSetMessages without PayloadHeader", uadp.ErrMalformed)
	}
	if nm.Discovery != nil {
		out.DiscType, out.DiscWID = nm.Discovery.Type, nm.Discovery.DataSetWriterID
		b, err := ua.Encode(nm.Discovery.MetaData)
		if err != nil {
			return nil, err
		}
		out.DiscMD = b
	}
	for _, d := range nm.Messages {
		fd := fakeDSM{WID: d.DataSetWriterID, Type: d.Type, Valid: d.Valid, UADPMask: d.UADPMask, JSONMask: d.JSONMask, FCM: d.FieldContentMask,
			FE: d.FieldEncoding, Seq: d.SequenceNumber, TS: d.Timestamp, Status: uint32(d.Status), Ver: d.MetaDataVersion, Name: d.DataSetWriterName,
			WGName: d.WriterGroupName, Pub: d.PublisherID}
		if f.enc == encUADP {
			fd.Seq &= 0xffff
		}
		for _, fl := range d.Fields {
			b, err := fl.Value.Encode()
			if err != nil {
				return nil, err
			}
			fd.Fields = append(fd.Fields, fakeField{Index: fl.Index, Name: fl.Name, DV: b})
		}
		out.Msgs = append(out.Msgs, fd)
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	if f.enc == encUADP {
		return append([]byte("U"), b...), nil
	}
	return b, nil
}

func (f fakeCodec) parse(b []byte) (*fakeNM, error) {
	b = bytes.TrimPrefix(b, []byte("U"))
	var in fakeNM
	if err := json.Unmarshal(b, &in); err != nil {
		return nil, fmt.Errorf("%w: %v", uadp.ErrMalformed, err)
	}
	return &in, nil
}

func (f fakeCodec) Decode(b []byte, opts *decodeOptions) (*message.NetworkMessage, error) {
	in, err := f.parse(b)
	if err != nil {
		return nil, err
	}
	nm := &message.NetworkMessage{Type: in.Type, UADPMask: in.UADPMask, JSONMask: in.JSONMask, PublisherID: in.Pub, GroupHeader: in.GH,
		Timestamp: in.TS, MessageID: in.MessageID, WriterGroupName: in.WGName}
	if in.Secured > ua.MessageSecurityModeNone {
		nm.Security = &message.SecurityHeader{Signed: true, Encrypted: in.Secured == ua.MessageSecurityModeSignAndEncrypt, SecurityTokenID: in.Token}
	}
	if in.DiscMD != nil {
		md := new(ua.DataSetMetaDataType)
		if _, err := ua.Decode(in.DiscMD, md); err != nil {
			return nil, err
		}
		nm.Discovery = &message.Discovery{Type: in.DiscType, DataSetWriterID: in.DiscWID, MetaData: md}
	}
	for _, d := range in.Msgs {
		nm.Messages = append(nm.Messages, &message.DataSetMessage{DataSetWriterID: d.WID})
	}
	if opts != nil && opts.Accept != nil && !opts.Accept(nm) {
		return nil, uadp.ErrFiltered
	}
	if opts != nil {
		mode := ua.MessageSecurityModeNone
		var ks security.KeySource
		if opts.Security != nil {
			mode, ks, _ = opts.Security(nm)
		}
		if in.Secured > ua.MessageSecurityModeNone {
			if ks == nil {
				return nil, fmt.Errorf("%w: secured message without keys", uadp.ErrSecurityMode)
			}
			if _, err := ks.KeysForToken(in.Token); err != nil {
				return nil, fmt.Errorf("%w: %v", uadp.ErrSecurityChecksFailed, err)
			}
		}
		if mode > securityMode(in.Secured) {
			return nil, fmt.Errorf("%w: message security %v < %v", uadp.ErrSecurityMode, in.Secured, mode)
		}
	}
	nm.Messages = nil
	for _, d := range in.Msgs {
		dsm := &message.DataSetMessage{DataSetWriterID: d.WID, Type: d.Type, Valid: d.Valid, UADPMask: d.UADPMask, JSONMask: d.JSONMask,
			FieldContentMask: d.FCM, FieldEncoding: d.FE, SequenceNumber: d.Seq, Timestamp: d.TS, Status: ua.StatusCode(d.Status), MetaDataVersion: d.Ver,
			DataSetWriterName: d.Name, WriterGroupName: d.WGName, PublisherID: d.Pub}
		var md *ua.DataSetMetaDataType
		if opts != nil && opts.MetaData != nil {
			md = opts.MetaData(in.Pub, in.GH.WriterGroupID, d.WID)
		}
		for _, fl := range d.Fields {
			dv := new(ua.DataValue)
			if _, err := dv.Decode(fl.DV); err != nil {
				return nil, err
			}
			name := fl.Name
			if f.enc == encUADP {
				name = "" // UADP does not carry names
				if md != nil && int(fl.Index) < len(md.Fields) {
					name = md.Fields[fl.Index].Name
				}
			}
			dsm.Fields = append(dsm.Fields, &message.Field{Index: fl.Index, Name: name, Value: dv})
		}
		nm.Messages = append(nm.Messages, dsm)
	}
	return nm, nil
}

func (f fakeCodec) EncodeChunks(*message.NetworkMessage, *uadp.EncodeOptions, int) ([][]byte, error) {
	return nil, errors.New("fake: no chunks")
}

func (f fakeCodec) DecodeReassembled(*message.NetworkMessage, []byte, *decodeOptions) (*message.NetworkMessage, error) {
	return nil, errors.New("fake: no chunks")
}

type fakeMeta struct {
	MessageType string
	MessageID   string
	Pub         message.PublisherID
	WID         uint16
	WGName      string
	MD          []byte
}

func (f fakeCodec) EncodeMetaData(m *jsonmsg.MetaDataMessage) ([]byte, error) {
	b, err := ua.Encode(m.MetaData)
	if err != nil {
		return nil, err
	}
	return json.Marshal(fakeMeta{MessageType: "ua-metadata", MessageID: m.MessageID, Pub: m.PublisherID, WID: m.DataSetWriterID, WGName: m.WriterGroupName, MD: b})
}

func (f fakeCodec) DecodeMetaData(b []byte, _ *decodeOptions) (*jsonmsg.MetaDataMessage, error) {
	var in fakeMeta
	if err := json.Unmarshal(b, &in); err != nil {
		return nil, err
	}
	md := new(ua.DataSetMetaDataType)
	if _, err := ua.Decode(in.MD, md); err != nil {
		return nil, err
	}
	return &jsonmsg.MetaDataMessage{MessageID: in.MessageID, PublisherID: in.Pub, DataSetWriterID: in.WID, WriterGroupName: in.WGName, MetaData: md}, nil
}

// decodeSent decodes a payload the fake codec produced, without filters.
func decodeSent(t *testing.T, b []byte) *fakeNM {
	t.Helper()
	nm, err := fakeCodec{}.parse(b)
	require.NoError(t, err)
	return nm
}

// ---------------------------------------------------------------------------
// Fake key source.

type fakeKeys struct {
	mu     sync.Mutex
	token  uint32
	fail   bool
	tokens map[uint32]bool
}

func newFakeKeys(token uint32) *fakeKeys {
	return &fakeKeys{token: token, tokens: map[uint32]bool{token: true}}
}

func (k *fakeKeys) Policy() security.Policy { return nil }

func (k *fakeKeys) CurrentKeys() (*security.Keys, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.fail {
		return nil, security.ErrNoKeys
	}
	return &security.Keys{TokenID: k.token}, nil
}

func (k *fakeKeys) KeysForToken(id uint32) (*security.Keys, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.tokens[id] {
		return nil, security.ErrNoKeys
	}
	return &security.Keys{TokenID: id}, nil
}

func (k *fakeKeys) setFail(v bool) {
	k.mu.Lock()
	k.fail = v
	k.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Recorders.

type recorder struct {
	mu   sync.Mutex
	sets []*ReceivedDataSet
	evs  []Event
	wr   []TargetWrite
}

func (r *recorder) handler(ds *ReceivedDataSet) {
	r.mu.Lock()
	r.sets = append(r.sets, ds)
	r.mu.Unlock()
}

func (r *recorder) event(ev Event) {
	r.mu.Lock()
	r.evs = append(r.evs, ev)
	r.mu.Unlock()
}

func (r *recorder) WriteTargets(_ context.Context, w []TargetWrite) []error {
	r.mu.Lock()
	r.wr = append(r.wr, w...)
	r.mu.Unlock()
	return make([]error, len(w))
}

func (r *recorder) dataSets() []*ReceivedDataSet {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*ReceivedDataSet(nil), r.sets...)
}

func (r *recorder) events() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Event(nil), r.evs...)
}

func (r *recorder) writes() []TargetWrite {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]TargetWrite(nil), r.wr...)
}

func (r *recorder) reset() {
	r.mu.Lock()
	r.sets, r.wr = nil, nil
	r.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Helpers.

// memURL returns a bus address unique to the test.
func memURL(t *testing.T) string {
	if u, ok := memURLs.Load(t); ok {
		return u.(string)
	}
	u := fmt.Sprintf("mem://%s-%d", strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()), memSeq.Add(1))
	memURLs.Store(t, u)
	return u
}

var (
	memURLs sync.Map
	memSeq  atomic.Int64
)

func memConnection(name, url string, pub any) *ua.PubSubConnectionDataType {
	c := UDPConnection(name, url, pub)
	return c
}

func brokerConnection(name, url string, pub any, m MessageMapping) *ua.PubSubConnectionDataType {
	return MQTTConnection(name, url, pub, m)
}

func start(t *testing.T, cfg *ua.PubSubConfigurationDataType, opts ...Option) *PubSub {
	t.Helper()
	opts = append([]Option{withFakeCodec(), WithRetryInterval(20 * time.Millisecond)}, opts...)
	p, err := New(cfg, opts...)
	require.NoError(t, err)
	require.NoError(t, p.Start(context.Background()))
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func waitState(t *testing.T, p *PubSub, id ComponentID, want ua.PubSubState) {
	t.Helper()
	require.Eventually(t, func() bool {
		s, err := p.State(id)
		return err == nil && s == want
	}, 3*time.Second, 2*time.Millisecond, "component %d never reached %v", id, want)
}

func mustID(t *testing.T, p *PubSub, kind ComponentKind, parent ComponentID, name string) ComponentID {
	t.Helper()
	id, ok := p.Lookup(kind, parent, name)
	require.True(t, ok, "no %v %q", kind, name)
	return id
}

func int32Values(ds *ReceivedDataSet) []int32 {
	out := make([]int32, len(ds.Fields))
	for i, f := range ds.Fields {
		if f.Value != nil && f.Value.Value != nil {
			if v, ok := f.Value.Value.Value().(int32); ok {
				out[i] = v
			}
		}
	}
	return out
}
