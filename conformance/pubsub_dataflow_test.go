// SPDX-License-Identifier: MIT

package conformance

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/internal/testutil/testport"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil/mqttbroker"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/pubsub/transport/udp"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// PubSub end to end: publishers and subscribers of this module against each
// other over real UDP sockets and an in-process MQTT broker, as servers
// (WithPubSub over their address spaces, TargetVariables) and as standalone
// runtimes (DataSetHandler).

// psInterval is the publishing interval of the PubSub tests.
const psInterval = 10 * time.Millisecond

func psUDPURL(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("opc.udp://127.0.0.1:%d", testport.UDP(t))
}

func psBroker(t *testing.T) *mqttbroker.Broker {
	t.Helper()
	b := mqttbroker.New(mqttbroker.Options{})
	require.NoError(t, b.Start())
	t.Cleanup(b.Close)
	return b
}

// psRuntime creates and starts a standalone runtime, closed at cleanup.
func psRuntime(t *testing.T, cfg *ua.PubSubConfigurationDataType, opts ...pubsub.Option) *pubsub.PubSub {
	t.Helper()
	rt, err := pubsub.New(cfg, opts...)
	require.NoError(t, err)
	require.NoError(t, rt.Start(context.Background()))
	t.Cleanup(func() { _ = rt.Close() })
	return rt
}

// psComponent returns the id of the component with the kind and name.
func psComponent(t *testing.T, rt *pubsub.PubSub, kind pubsub.ComponentKind, name string) pubsub.ComponentID {
	t.Helper()
	for _, c := range rt.Components() {
		if c.Kind == kind && c.Name == name {
			return c.ID
		}
	}
	t.Fatalf("no %v %q", kind, name)
	return 0
}

func psWaitState(t *testing.T, rt *pubsub.PubSub, cid pubsub.ComponentID, want ua.PubSubState) {
	t.Helper()
	eventually(t, func() bool {
		s, err := rt.State(cid)
		return err == nil && s == want
	}, fmt.Sprintf("component %d reaches %v", cid, want))
}

// psRecorder collects the DataSets of a runtime by reader name.
type psRecorder struct {
	mu   sync.Mutex
	sets map[string][]*pubsub.ReceivedDataSet
}

func newPSRecorder() *psRecorder { return &psRecorder{sets: map[string][]*pubsub.ReceivedDataSet{}} }

func (r *psRecorder) handle(d *pubsub.ReceivedDataSet) {
	r.mu.Lock()
	r.sets[d.ReaderName] = append(r.sets[d.ReaderName], d)
	r.mu.Unlock()
}

func (r *psRecorder) of(reader string) []*pubsub.ReceivedDataSet {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*pubsub.ReceivedDataSet(nil), r.sets[reader]...)
}

// waitFor waits for a DataSet of reader that satisfies cond and returns it.
func (r *psRecorder) waitFor(t *testing.T, reader string, cond func(*pubsub.ReceivedDataSet) bool) *pubsub.ReceivedDataSet {
	t.Helper()
	var found *pubsub.ReceivedDataSet
	eventually(t, func() bool {
		for _, d := range r.of(reader) {
			if cond(d) {
				found = d
				return true
			}
		}
		return false
	}, "reader "+reader+" receives the expected DataSet")
	return found
}

// psValues is a set of published values of several built-in types.
type psValues struct {
	I32 int32
	F64 float64
	Str string
	B   bool
	Arr []int32
}

func (v psValues) list(withArray bool) []any {
	out := []any{v.I32, v.F64, v.Str, v.B}
	if withArray {
		out = append(out, v.Arr)
	}
	return out
}

var psFieldNames = []string{"i32", "f64", "str", "b", "arr"}

var psFieldTypes = []ua.TypeID{ua.TypeIDInt32, ua.TypeIDDouble, ua.TypeIDString, ua.TypeIDBoolean, ua.TypeIDInt32}

// psFields returns the fields of the PubSub test data sets (without the
// array for RawData, which needs fixed array dimensions).
func psFields(withArray bool) []pubsub.Field {
	var out []pubsub.Field
	for i, name := range psFieldNames {
		if name == "arr" && !withArray {
			continue
		}
		out = append(out, pubsub.Field{Name: name, Type: psFieldTypes[i], Array: name == "arr"})
	}
	return out
}

// psVariant is one encoding of the end-to-end matrix.
type psVariant struct {
	name  string
	mask  ua.DataSetFieldContentMask
	delta bool
}

var psVariants = []psVariant{
	{"Variant", 0, false},
	{"DataValue", ua.DataSetFieldContentMaskStatusCode | ua.DataSetFieldContentMaskSourceTimestamp | ua.DataSetFieldContentMaskServerTimestamp, false},
	{"RawData", ua.DataSetFieldContentMaskRawData, false},
	{"VariantDelta", 0, true},
	{"DataValueDelta", ua.DataSetFieldContentMaskStatusCode | ua.DataSetFieldContentMaskSourceTimestamp, true},
	{"RawDataDelta", ua.DataSetFieldContentMaskRawData, true},
}

func (v psVariant) raw() bool { return v.mask&ua.DataSetFieldContentMaskRawData != 0 }

// TestPubSub_ServerToServerTargetVariables publishes variables of one
// server and writes them to the target variables of another, over UDP with
// the Variant, DataValue and RawData field encodings with key frames only
// and with delta frames, and over MQTT with the UADP and the JSON mapping.
// The targets must take the published values with their types, and a
// change of one variable must reach its target without touching the others.
func TestPubSub_ServerToServerTargetVariables(t *testing.T) {
	broker := psBroker(t)
	pubSrv, _ := newServer(t, server.WithPubSub(nil))
	subSrv, subURL := newServer(t, server.WithPubSub(nil))
	pubNS := server.NewNodeNameSpace(pubSrv, "urn:pubsub:pub")
	subNS := server.NewNodeNameSpace(subSrv, "urn:pubsub:sub")
	pub, sub := pubSrv.PubSub(), subSrv.PubSub()
	udpURL := psUDPURL(t)

	initial := psValues{I32: 1, F64: 0.5, Str: "first", B: true, Arr: []int32{1, 2, 3}}
	type route struct {
		name     string
		vars     map[string]*server.Node
		targets  map[string]*server.Node
		withArry bool
	}
	var routes []*route
	add := func(name string, mask ua.DataSetFieldContentMask, delta bool, conn, mqttMapping int) *route {
		r := &route{name: name, vars: map[string]*server.Node{}, targets: map[string]*server.Node{}, withArry: mask&ua.DataSetFieldContentMaskRawData == 0}
		var fields []pubsub.PublishedField
		var targets []*ua.FieldTargetDataType
		for i, v := range initial.list(r.withArry) {
			fname := psFieldNames[i]
			n := pubNS.AddNewVariableStringNode(name+"."+fname, v)
			r.vars[fname] = n
			f := pubsub.Var(fname, n.ID(), psFieldTypes[i])
			f.Array = fname == "arr"
			fields = append(fields, f)
			zero := map[string]any{"i32": int32(0), "f64": float64(0), "str": "", "b": false, "arr": []int32{0, 0, 0}}[fname]
			tn := subNS.AddNewVariableStringNode(name+"."+fname, zero)
			r.targets[fname] = tn
			targets = append(targets, pubsub.Target(tn.ID()))
		}
		pds := pubsub.PublishedDataItems(name, fields...)
		_, err := pub.AddPublishedDataSet(pds)
		require.NoError(t, err)
		gid := uint16(len(routes) + 1)
		w := pubsub.DataSetWriter("w", 1, name)
		w.DataSetFieldContentMask = mask
		if delta {
			w.KeyFrameCount = 5
		}
		rd := pubsub.SetTargetVariables(pubsub.DataSetReader("r", uint16(42), gid, 1, pubsub.DataSetMetaDataOf(pds)), targets...)
		rd.DataSetFieldContentMask = mask
		var wg *ua.WriterGroupDataType
		var pc, sc pubsub.ComponentID
		if conn == 0 {
			wg = pubsub.WriterGroup(name, gid, psInterval, w)
			pc, sc = psComponent(t, pub, pubsub.KindConnection, "udp"), psComponent(t, sub, pubsub.KindConnection, "udp")
		} else {
			q := "conformance/" + name
			pubsub.SetWriterQueue(w, q, q+"/meta")
			pubsub.SetReaderQueue(rd, q, q+"/meta")
			if mqttMapping == int(pubsub.MappingJSON) {
				wg = pubsub.JSONWriterGroup(name, gid, psInterval, q, w)
				rd.WriterGroupID = 0 // JSON NetworkMessages carry the group by name only
				pc, sc = psComponent(t, pub, pubsub.KindConnection, "mqtt-json"), psComponent(t, sub, pubsub.KindConnection, "mqtt-json")
			} else {
				wg = pubsub.WriterGroup(name, gid, psInterval, w)
				pc, sc = psComponent(t, pub, pubsub.KindConnection, "mqtt-uadp"), psComponent(t, sub, pubsub.KindConnection, "mqtt-uadp")
			}
		}
		_, err = pub.AddWriterGroup(pc, wg)
		require.NoError(t, err)
		_, err = sub.AddReaderGroup(sc, pubsub.ReaderGroup(name, rd))
		require.NoError(t, err)
		routes = append(routes, r)
		return r
	}
	for _, c := range []struct {
		name string
		rt   *pubsub.PubSub
		pid  any
	}{{"pub", pub, uint16(42)}, {"sub", sub, nil}} {
		_, err := c.rt.AddConnection(pubsub.UDPConnection("udp", udpURL, c.pid))
		require.NoError(t, err)
		_, err = c.rt.AddConnection(pubsub.MQTTConnection("mqtt-uadp", broker.URL(), c.pid, pubsub.MappingUADP))
		require.NoError(t, err)
		_, err = c.rt.AddConnection(pubsub.MQTTConnection("mqtt-json", broker.URL(), c.pid, pubsub.MappingJSON))
		require.NoError(t, err)
	}
	for _, v := range psVariants {
		add("udp-"+v.name, v.mask, v.delta, 0, 0)
	}
	add("mqtt-uadp", 0, true, 1, int(pubsub.MappingUADP))
	add("mqtt-json", 0, true, 1, int(pubsub.MappingJSON))

	c := newClient(t, subURL)
	ctx := context.Background()
	expect := func(r *route, want psValues) {
		t.Helper()
		wantVals := want.list(r.withArry)
		eventually(t, func() bool {
			for i, w := range wantVals {
				v, err := c.Node(r.targets[psFieldNames[i]].ID()).Value(ctx)
				if err != nil || v == nil {
					return false
				}
				if fmt.Sprintf("%T %v", v.Value(), v.Value()) != fmt.Sprintf("%T %v", w, w) {
					return false
				}
			}
			return true
		}, r.name+": the targets take the published values")
	}
	for _, r := range routes {
		t.Run(r.name+"/initial", func(t *testing.T) { expect(r, initial) })
	}
	// Change every variable, then only one: delta frames carry just that.
	changed := psValues{I32: -7, F64: 1e-3, Str: "zweite Ünicode ✓", B: false, Arr: []int32{9, 8, 7, 6}}
	for _, r := range routes {
		for i, v := range changed.list(r.withArry) {
			require.NoError(t, r.vars[psFieldNames[i]].SetAttribute(ua.AttributeIDValue, server.DataValueFromValue(v)))
		}
	}
	for _, r := range routes {
		t.Run(r.name+"/changed", func(t *testing.T) { expect(r, changed) })
	}
	only := changed
	only.I32 = 1 << 30
	for _, r := range routes {
		require.NoError(t, r.vars["i32"].SetAttribute(ua.AttributeIDValue, server.DataValueFromValue(only.I32)))
	}
	for _, r := range routes {
		t.Run(r.name+"/one-field", func(t *testing.T) { expect(r, only) })
	}
	for _, rd := range sub.Components() {
		if rd.Kind == pubsub.KindDataSetReader {
			st, err := sub.Status(rd.ID)
			require.NoError(t, err)
			require.Equal(t, ua.PubSubStateOperational, st.State, rd.Name)
			require.Zero(t, st.Counters.TargetWriteErrors, "reader of group %d", rd.Parent)
			require.Zero(t, st.Counters.DecodeErrors, "reader of group %d", rd.Parent)
		}
	}
}

// psStandalone runs a publisher and a subscriber runtime with a reader per
// variant over one transport and returns the subscriber's recorder.
type psStandalone struct {
	ds      *pubsub.MemoryDataSource
	nodes   map[string]*ua.NodeID
	pub     *pubsub.PubSub
	sub     *pubsub.PubSub
	rec     *psRecorder
	readers []string
}

// TestPubSub_StandaloneDataSets checks the DataSets a subscriber runtime
// delivers to its DataSetHandler for every field encoding, with key frames
// only and with delta frames, over UDP unicast, UDP multicast (where the
// host allows it) and MQTT (UADP and JSON): field names, values and types,
// the message type and the fields a delta frame carried, sequence numbers,
// PublisherId, WriterGroupId and DataSetWriterId, the MetaData version.
func TestPubSub_StandaloneDataSets(t *testing.T) {
	parallel(t)
	broker := psBroker(t)
	type tr struct {
		name    string
		conn    func(name string, pid any) *ua.PubSubConnectionDataType
		mapping pubsub.MessageMapping
		broker  bool
	}
	ucast := psUDPURL(t)
	trs := []tr{
		{"UDP", func(name string, pid any) *ua.PubSubConnectionDataType { return pubsub.UDPConnection(name, ucast, pid) }, pubsub.MappingUADP, false},
		{"MQTT-UADP", func(name string, pid any) *ua.PubSubConnectionDataType {
			return pubsub.MQTTConnection(name, broker.URL(), pid, pubsub.MappingUADP)
		}, pubsub.MappingUADP, true},
		{"MQTT-JSON", func(name string, pid any) *ua.PubSubConnectionDataType {
			return pubsub.MQTTConnection(name, broker.URL(), pid, pubsub.MappingJSON)
		}, pubsub.MappingJSON, true},
	}
	if mcast, ok := psMulticastURL(t); ok {
		trs = append(trs, tr{"UDP-multicast", func(name string, pid any) *ua.PubSubConnectionDataType { return pubsub.UDPConnection(name, mcast, pid) }, pubsub.MappingUADP, false})
	}
	for _, x := range trs {
		t.Run(x.name, func(t *testing.T) {
			t.Parallel()
			s := &psStandalone{ds: pubsub.NewMemoryDataSource(), nodes: map[string]*ua.NodeID{}, rec: newPSRecorder()}
			for i, n := range psFieldNames {
				s.nodes[n] = ua.NewStringNodeID(1, n)
				require.NoError(t, s.ds.Set(s.nodes[n], psValues{I32: 5, F64: 2.25, Str: "s", B: true, Arr: []int32{4, 5}}.list(true)[i]))
			}
			var pdss []*ua.PublishedDataSetDataType
			pubConn, subConn := x.conn("pub", "publisher-A"), x.conn("sub", nil)
			for gi, v := range psVariants {
				if x.mapping == pubsub.MappingJSON && v.raw() {
					continue // the JSON mapping has no RawData encoding
				}
				name := x.name + "-" + v.name
				var fields []pubsub.PublishedField
				for i, f := range psFields(!v.raw()) {
					pf := pubsub.Var(f.Name, s.nodes[f.Name], psFieldTypes[i])
					pf.Array = f.Array
					fields = append(fields, pf)
				}
				pds := pubsub.PublishedDataItems(name, fields...)
				pdss = append(pdss, pds)
				w := pubsub.DataSetWriter("w", uint16(10+gi), name)
				w.DataSetFieldContentMask = v.mask
				if v.delta {
					// A key frame every 5 messages: a subscriber that
					// comes late (MQTT subscribes asynchronously) is not
					// left without one for long.
					w.KeyFrameCount = 5
				}
				r := pubsub.DataSetReader(name, "publisher-A", uint16(gi+1), uint16(10+gi), pubsub.DataSetMetaDataOf(pds))
				r.DataSetFieldContentMask = v.mask
				var wg *ua.WriterGroupDataType
				if x.broker {
					q := "standalone/" + name
					pubsub.SetWriterQueue(w, q, "")
					pubsub.SetReaderQueue(r, q, "")
				}
				if x.mapping == pubsub.MappingJSON {
					wg = pubsub.JSONWriterGroup(name, uint16(gi+1), psInterval, "standalone/"+name, w)
					r.WriterGroupID = 0
				} else {
					wg = pubsub.WriterGroup(name, uint16(gi+1), psInterval, w)
				}
				pubsub.AttachWriterGroups(pubConn, wg)
				pubsub.AttachReaderGroups(subConn, pubsub.ReaderGroup(name, r))
				s.readers = append(s.readers, name)
			}
			s.sub = psRuntime(t, pubsub.NewConfiguration(nil, subConn), pubsub.WithDataSetHandler(s.rec.handle))
			s.pub = psRuntime(t, pubsub.NewConfiguration(pdss, pubConn), pubsub.WithDataSource(s.ds))

			check := func(d *pubsub.ReceivedDataSet, want psValues, raw bool) bool {
				vals := want.list(!raw)
				if !d.Complete || len(d.Fields) != len(vals) {
					return false
				}
				for i, w := range vals {
					f := d.Fields[i]
					if f.Name != psFieldNames[i] || f.Value == nil || f.Value.Value == nil ||
						fmt.Sprintf("%T %v", f.Value.Value.Value(), f.Value.Value.Value()) != fmt.Sprintf("%T %v", w, w) {
						return false
					}
				}
				return true
			}
			first := psValues{I32: 5, F64: 2.25, Str: "s", B: true, Arr: []int32{4, 5}}
			for i, name := range s.readers {
				v := psVariants[0]
				for _, pv := range psVariants {
					if x.name+"-"+pv.name == name {
						v = pv
					}
				}
				d := s.rec.waitFor(t, name, func(d *pubsub.ReceivedDataSet) bool { return check(d, first, v.raw()) })
				require.Equal(t, message.DataSetMessageKeyFrame, d.MessageType, name)
				require.Equal(t, "publisher-A", d.PublisherID.String(), name)
				require.Equal(t, uint16(10+indexOfVariant(v)), d.DataSetWriterID, name)
				if x.mapping == pubsub.MappingUADP {
					require.Equal(t, uint16(indexOfVariant(v)+1), d.WriterGroupID, name)
				}
				require.NotZero(t, d.MetaDataVersion.MajorVersion, name)
				_ = i
			}

			// One field changes: delta writers send a delta frame with
			// just that field, merged onto the last key frame. A key frame
			// may carry the change first; then change it again.
			pending := map[string]bool{}
			for _, name := range s.readers {
				pending[name] = true
			}
			for attempt := 1; len(pending) > 0; attempt++ {
				require.Less(t, attempt, 30, "no DataSet with the changed field for %v", pending)
				second := first
				second.F64 = -0.125 * float64(attempt)
				require.NoError(t, s.ds.Set(s.nodes["f64"], second.F64))
				deadline := time.Now().Add(time.Second)
				for len(pending) > 0 && time.Now().Before(deadline) {
					for name := range pending {
						v := variantOf(x.name, name)
						for _, d := range s.rec.of(name) {
							if !check(d, second, v.raw()) {
								continue
							}
							if v.delta && (d.MessageType != message.DataSetMessageDeltaFrame || len(d.Changed) != 1 || d.Changed[0] != 1) {
								continue
							}
							if !v.delta {
								require.Equal(t, message.DataSetMessageKeyFrame, d.MessageType, name)
							}
							delete(pending, name)
							break
						}
					}
					time.Sleep(5 * time.Millisecond)
				}
			}
			for _, name := range s.readers {
				// Sequence numbers grow with every DataSetMessage;
				// nothing is delivered twice.
				sets := s.rec.of(name)
				gaps := 0
				for i := 1; i < len(sets); i++ {
					d := uint16(sets[i].SequenceNumber - sets[i-1].SequenceNumber)
					require.True(t, d > 0 && d < 1<<14, "%s: sequence numbers %d, %d", name, sets[i-1].SequenceNumber, sets[i].SequenceNumber)
					if d > 1 {
						gaps++
					}
				}
				if gaps > 0 {
					t.Logf("%s: %d gaps in the sequence numbers (messages lost by the transport)", name, gaps)
				}
				st, err := s.sub.Status(psComponent(t, s.sub, pubsub.KindDataSetReader, name))
				require.NoError(t, err)
				require.Equal(t, ua.PubSubStateOperational, st.State)
				require.Zero(t, st.Counters.DecodeErrors, name)
			}
		})
	}
}

func indexOfVariant(v psVariant) int {
	for i, x := range psVariants {
		if x.name == v.name {
			return i
		}
	}
	return -1
}

func variantOf(prefix, reader string) psVariant {
	for _, v := range psVariants {
		if prefix+"-"+v.name == reader {
			return v
		}
	}
	return psVariants[0]
}

// psMulticastURL returns a multicast address that this host can send to and
// receive from, or false.
func psMulticastURL(t *testing.T) (string, bool) {
	t.Helper()
	port := testport.UDP(t)
	url := fmt.Sprintf("opc.udp://239.255.77.%d:%d", 1+port%200, port)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := udp.Open(ctx, transport.Config{URL: url})
	if err != nil {
		t.Logf("multicast unavailable: %v", err)
		return "", false
	}
	defer func() { _ = c.Close() }()
	got := make(chan struct{}, 1)
	cancelSub, err := c.Subscribe(ctx, "", 0, func(*transport.Message) {
		select {
		case got <- struct{}{}:
		default:
		}
	})
	if err != nil {
		t.Logf("multicast unavailable: %v", err)
		return "", false
	}
	defer func() { _ = cancelSub() }()
	for range 10 {
		if err := c.Send(ctx, []byte{0}, transport.PublishOptions{}); err != nil {
			t.Logf("multicast unavailable: %v", err)
			return "", false
		}
		select {
		case <-got:
			return url, true
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Log("multicast unavailable: no loopback")
	return "", false
}

// TestPubSub_KeepAliveAndReceiveTimeout checks keep-alive messages and the
// state machine of a reader around its MessageReceiveTimeout: a writer
// whose values do not change sends delta frames only when they change and
// keep-alive messages in between, which keep the reader Operational; when
// the publisher stops the reader goes to Error (counting the timeout) and
// back to Operational when it starts again; disabling the reader's group
// disables... it pauses the reader, enabling it resumes it.
func TestPubSub_KeepAliveAndReceiveTimeout(t *testing.T) {
	parallel(t)
	url := psUDPURL(t)
	ds := pubsub.NewMemoryDataSource()
	node := ua.NewStringNodeID(1, "v")
	require.NoError(t, ds.Set(node, int32(1)))
	pds := pubsub.PublishedDataItems("ka", pubsub.Var("v", node, ua.TypeIDInt32))
	w := pubsub.DataSetWriter("w", 1, "ka")
	w.KeyFrameCount = 1 << 20
	wg := pubsub.WriterGroup("wg", 1, psInterval, w)
	wg.KeepAliveTime = 50
	r := pubsub.DataSetReader("r", uint16(3), 1, 1, pubsub.DataSetMetaDataOf(pds))
	r.MessageReceiveTimeout = 300
	rec := newPSRecorder()
	var evMu sync.Mutex
	var states []ua.PubSubState
	sub := psRuntime(t, pubsub.NewConfiguration(nil, pubsub.AttachReaderGroups(pubsub.UDPConnection("sub", url, nil), pubsub.ReaderGroup("rg", r))),
		pubsub.WithDataSetHandler(rec.handle), pubsub.WithEventHandler(func(ev pubsub.Event) {
			if ev.Type == pubsub.EventStateChanged && ev.Component.Kind == pubsub.KindDataSetReader {
				evMu.Lock()
				states = append(states, ev.Component.State)
				evMu.Unlock()
			}
		}))
	rid := psComponent(t, sub, pubsub.KindDataSetReader, "r")
	rgid := psComponent(t, sub, pubsub.KindReaderGroup, "rg")
	psWaitState(t, sub, rid, ua.PubSubStatePreOperational)

	newPub := func() *pubsub.PubSub {
		p, err := pubsub.New(pubsub.NewConfiguration([]*ua.PublishedDataSetDataType{pds}, pubsub.AttachWriterGroups(pubsub.UDPConnection("pub", url, uint16(3)), wg)),
			pubsub.WithDataSource(ds))
		require.NoError(t, err)
		require.NoError(t, p.Start(context.Background()))
		return p
	}
	pub := newPub()
	rec.waitFor(t, "r", func(d *pubsub.ReceivedDataSet) bool { return d.MessageType == message.DataSetMessageKeyFrame })
	psWaitState(t, sub, rid, ua.PubSubStateOperational)

	// Nothing changes for longer than the timeout: keep-alives only.
	time.Sleep(500 * time.Millisecond)
	st, err := sub.Status(rid)
	require.NoError(t, err)
	require.Equal(t, ua.PubSubStateOperational, st.State, "keep-alives keep the reader Operational")
	require.GreaterOrEqual(t, st.Counters.KeepAlivesReceived, uint64(4))
	require.Len(t, rec.of("r"), 1, "no DataSet without a change")
	pst, err := pub.Status(psComponent(t, pub, pubsub.KindDataSetWriter, "w"))
	require.NoError(t, err)
	require.GreaterOrEqual(t, pst.Counters.KeepAlivesSent, st.Counters.KeepAlivesReceived)

	// A change: one delta frame.
	require.NoError(t, ds.Set(node, int32(2)))
	d := rec.waitFor(t, "r", func(d *pubsub.ReceivedDataSet) bool { return d.MessageType == message.DataSetMessageDeltaFrame })
	require.Equal(t, int32(2), d.Field("v").Value.Value())

	// The publisher stops: Error after the timeout; it comes back:
	// Operational.
	require.NoError(t, pub.Close())
	psWaitState(t, sub, rid, ua.PubSubStateError)
	st, err = sub.Status(rid)
	require.NoError(t, err)
	require.Equal(t, uint64(1), st.Counters.Timeouts)
	require.ErrorIs(t, st.LastError, ua.StatusBadTimeout)
	pub = newPub()
	t.Cleanup(func() { _ = pub.Close() })
	psWaitState(t, sub, rid, ua.PubSubStateOperational)

	// Disabling the group pauses the reader; enabling it resumes it.
	require.NoError(t, sub.Disable(rgid))
	psWaitState(t, sub, rgid, ua.PubSubStateDisabled)
	psWaitState(t, sub, rid, ua.PubSubStatePaused)
	require.NoError(t, sub.Enable(rgid))
	psWaitState(t, sub, rid, ua.PubSubStateOperational)
	evMu.Lock()
	got := append([]ua.PubSubState(nil), states...)
	evMu.Unlock()
	require.Equal(t, []ua.PubSubState{ua.PubSubStatePaused, ua.PubSubStatePreOperational, ua.PubSubStateOperational, ua.PubSubStateError, ua.PubSubStateOperational,
		ua.PubSubStatePaused, ua.PubSubStatePreOperational, ua.PubSubStateOperational}, got)
}

var _ = opcua.AutoReconnect
