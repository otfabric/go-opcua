// SPDX-License-Identifier: MIT

package datachange

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testhook"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
)

// ---------------------------------------------------------------------------
// nodes and values
// ---------------------------------------------------------------------------

// nodeKind is the data type and shape of a test variable.
type nodeKind int

const (
	kindDouble      nodeKind = iota // Double
	kindAnalog                      // Double with EURange [0, 200]
	kindInt32                       // Int32
	kindDoubleArray                 // Double[arrayLen]
	kindAnalogArray                 // Double[arrayLen] with EURange [0, 100]
	kindInt32Array                  // Int32[arrayLen]
	numKinds
)

// arrayLen is the length of every array variable.
const arrayLen = 6

func (k nodeKind) String() string {
	return [...]string{"Double", "Analog", "Int32", "DoubleArray", "AnalogArray", "Int32Array"}[k]
}

func (k nodeKind) isArray() bool { return k >= kindDoubleArray }

func (k nodeKind) isInt() bool { return k == kindInt32 || k == kindInt32Array }

// euRange returns the EURange of the analog kinds.
func (k nodeKind) euRange() (lo, hi float64, ok bool) {
	switch k {
	case kindAnalog:
		return 0, 200, true
	case kindAnalogArray:
		return 0, 100, true
	default:
		return 0, 0, false
	}
}

// unit is the step the deadbands and the value changes of a kind are scaled
// by: a deadband of one unit suppresses the small steps of the writers and
// lets the large ones through.
func (k nodeKind) unit() float64 {
	switch k {
	case kindAnalog:
		return 10 // 5 % of the EURange
	case kindAnalogArray:
		return 5 // 5 % of the EURange
	case kindInt32, kindInt32Array:
		return 4
	default:
		return 5
	}
}

// node is a variable of the test namespace together with the model the
// writers draw its next value from.
type node struct {
	name string
	kind nodeKind
	id   *ua.NodeID

	mu     sync.Mutex
	cur    any           // value the next step starts from
	status ua.StatusCode // status of the last server-side write
	hist   []write       // ordered server-side writes, see env.writeOrdered
}

// write is one server-side write: its sequence number and what was written.
type write struct {
	seq    int64
	value  any
	status ua.StatusCode
	source time.Time
}

// initial returns the first value of a node of kind k.
func (k nodeKind) initial() any {
	switch k {
	case kindInt32:
		return int32(100)
	case kindInt32Array:
		return []int32{100, 110, 120, 130, 140, 150}
	case kindDoubleArray, kindAnalogArray:
		return []float64{40, 45, 50, 55, 60, 65}
	default:
		return float64(50)
	}
}

// stepFloat moves v by nothing, by less than half a unit or by more than a
// unit, and keeps it inside [lo, hi].
func stepFloat(rng *rand.Rand, v, unit, lo, hi float64) float64 {
	var d float64
	switch r := rng.Float64(); {
	case r < 0.15:
		return v
	case r < 0.60:
		d = (0.05 + 0.4*rng.Float64()) * unit
	default:
		d = (1.2 + 2.8*rng.Float64()) * unit
	}
	if rng.Intn(2) == 0 {
		d = -d
	}
	if v+d < lo || v+d > hi {
		d = -d
	}
	return v + d
}

func stepInt(rng *rand.Rand, v int32) int32 {
	var d int32
	switch r := rng.Float64(); {
	case r < 0.15:
		return v
	case r < 0.60:
		d = 1
	default:
		d = int32(5 + rng.Intn(12))
	}
	if rng.Intn(2) == 0 {
		d = -d
	}
	if v+d < -10000 || v+d > 10000 {
		d = -d
	}
	return v + d
}

// bounds returns the interval the values of the node stay in.
func (n *node) bounds() (lo, hi float64) {
	if lo, hi, ok := n.kind.euRange(); ok {
		return lo, hi
	}
	return -1000, 1000
}

// step advances the model of the node and returns the new value. Arrays
// change in one or two elements only, so that an IndexRange often does not
// see the change. The caller must hold n.mu.
func (n *node) step(rng *rand.Rand) any {
	lo, hi := n.bounds()
	unit := n.kind.unit()
	switch v := n.cur.(type) {
	case float64:
		n.cur = stepFloat(rng, v, unit, lo, hi)
	case int32:
		n.cur = stepInt(rng, v)
	case []float64:
		next := append([]float64(nil), v...)
		for k := 1 + rng.Intn(2); k > 0; k-- {
			i := rng.Intn(len(next))
			next[i] = stepFloat(rng, next[i], unit, lo, hi)
		}
		n.cur = next
	case []int32:
		next := append([]int32(nil), v...)
		for k := 1 + rng.Intn(2); k > 0; k-- {
			i := rng.Intn(len(next))
			next[i] = stepInt(rng, next[i])
		}
		n.cur = next
	}
	return n.cur
}

// uniform returns a value of the node's type with every element set to (a
// value derived from) x. It is used by the scripted phases.
func (n *node) uniform(x float64) any {
	switch n.kind {
	case kindInt32:
		return int32(x)
	case kindInt32Array:
		out := make([]int32, arrayLen)
		for i := range out {
			out[i] = int32(x)
		}
		return out
	case kindDoubleArray, kindAnalogArray:
		out := make([]float64, arrayLen)
		for i := range out {
			out[i] = x
		}
		return out
	default:
		return x
	}
}

// withElement returns a copy of the array v with element i moved by d.
func withElement(v any, i int, d float64) any {
	switch x := v.(type) {
	case []float64:
		out := append([]float64(nil), x...)
		out[i] += d
		return out
	case []int32:
		out := append([]int32(nil), x...)
		out[i] += int32(d)
		return out
	}
	return v
}

// The source timestamp of every server-side write encodes the generation of
// the server instance and a sequence number that is unique for the test.
const (
	stampBaseSec    = 1_767_225_600 // 2026-01-01T00:00:00Z
	stampGenSpanSec = 100_000
)

func stamp(gen, seq int64) time.Time {
	return time.Unix(stampBaseSec+gen*stampGenSpanSec, 0).Add(time.Duration(seq) * time.Microsecond).UTC()
}

// unstamp is the inverse of stamp. ok is false for a timestamp that was not
// produced by stamp (the zero time of a value written by a client).
func unstamp(ts time.Time) (gen, seq int64, ok bool) {
	if ts.IsZero() {
		return 0, 0, false
	}
	us := ts.UnixMicro() - stampBaseSec*1_000_000
	if us < 0 {
		return 0, 0, false
	}
	span := int64(stampGenSpanSec) * 1_000_000
	return us / span, us % span, true
}

// ---------------------------------------------------------------------------
// the filter, as the test understands it
// ---------------------------------------------------------------------------

// sample is what a DataChangeFilter looks at.
type sample struct {
	status ua.StatusCode
	value  any // float64, int32, []float64, []int32 or nil
	source time.Time
}

func (s sample) String() string {
	_, seq, ok := unstamp(s.source)
	if !ok {
		return fmt.Sprintf("{%v %v unstamped}", s.value, s.status)
	}
	return fmt.Sprintf("{%v %v seq=%d}", s.value, s.status, seq)
}

// sampleOf extracts the sample of a notification. The Overflow bit says
// something about the queue, not about the value, and is reported separately.
func sampleOf(dv *ua.DataValue) (s sample, overflow bool) {
	s.status = dv.Status
	if s.status.HasOverflow() {
		overflow = true
		s.status &^= ua.StatusCodeGoodOverflow
	}
	if dv.Value != nil {
		s.value = dv.Value.Value()
	}
	s.source = dv.SourceTimestamp
	return s, overflow
}

// filter is a resolved DataChangeFilter: a percent deadband is already
// converted to the absolute change it stands for.
type filter struct {
	statusOnly  bool
	timestamp   bool
	hasDeadband bool
	deadband    float64
}

func (f filter) String() string {
	trigger := "StatusValue"
	switch {
	case f.statusOnly:
		trigger = "Status"
	case f.timestamp:
		trigger = "StatusValueTimestamp"
	}
	if !f.hasDeadband {
		return trigger
	}
	return fmt.Sprintf("%s deadband=%v", trigger, f.deadband)
}

// changed reports whether cur has to be reported when last is the value that
// was reported before (Part 4 §7.22.2, Part 8 §7.2):
//
//   - a change of status is always reported;
//   - with the Status trigger nothing else is;
//   - a value change is reported when it exceeds the deadband (any change
//     without one), for arrays when any element does or the length differs;
//   - StatusValueTimestamp also reports a change of the source timestamp,
//     unless a deadband is set.
func (f filter) changed(last, cur sample) bool {
	if last.status != cur.status {
		return true
	}
	if f.statusOnly {
		return false
	}
	deadband := 0.0
	if f.hasDeadband {
		deadband = f.deadband
	}
	if valueChanged(last.value, cur.value, deadband) {
		return true
	}
	if f.timestamp && !f.hasDeadband {
		return !last.source.Equal(cur.source)
	}
	return false
}

func valueChanged(a, b any, deadband float64) bool {
	switch x := a.(type) {
	case nil:
		return b != nil
	case float64:
		y, ok := b.(float64)
		return !ok || (x != y && math.Abs(x-y) > deadband)
	case int32:
		y, ok := b.(int32)
		return !ok || math.Abs(float64(int64(x)-int64(y))) > deadband
	case []float64:
		y, ok := b.([]float64)
		if !ok || len(x) != len(y) {
			return true
		}
		for i := range x {
			if x[i] != y[i] && math.Abs(x[i]-y[i]) > deadband {
				return true
			}
		}
		return false
	case []int32:
		y, ok := b.([]int32)
		if !ok || len(x) != len(y) {
			return true
		}
		for i := range x {
			if math.Abs(float64(int64(x[i])-int64(y[i]))) > deadband {
				return true
			}
		}
		return false
	}
	return !reflect.DeepEqual(a, b)
}

// sliceValue reduces an array to a one-dimensional index range "a" or "a:b".
// As on the server, a range that starts beyond the array has no data and one
// that ends beyond it is cut off.
func sliceValue(v any, indexRange string) (any, ua.StatusCode) {
	if indexRange == "" {
		return v, ua.StatusOK
	}
	var lo, hi int
	if n, _ := fmt.Sscanf(indexRange, "%d:%d", &lo, &hi); n < 2 {
		hi = lo
	}
	switch x := v.(type) {
	case []float64:
		if lo >= len(x) {
			return nil, ua.StatusBadIndexRangeNoData
		}
		return append([]float64(nil), x[lo:min(hi+1, len(x))]...), ua.StatusOK
	case []int32:
		if lo >= len(x) {
			return nil, ua.StatusBadIndexRangeNoData
		}
		return append([]int32(nil), x[lo:min(hi+1, len(x))]...), ua.StatusOK
	}
	return nil, ua.StatusBadIndexRangeInvalid
}

// seen returns what an item with the given index range samples when w is the
// value of its node.
func (w write) seen(indexRange string) sample {
	v, st := sliceValue(w.value, indexRange)
	if st != ua.StatusOK {
		return sample{status: st, source: w.source}
	}
	return sample{status: w.status, value: v, source: w.source}
}

// ---------------------------------------------------------------------------
// item specifications
// ---------------------------------------------------------------------------

// Sampling intervals used by the tests, in milliseconds.
const (
	samplingShortMS = 15.0
	samplingLongMS  = 300.0
	// samplingPublish asks for the publishing interval of the subscription.
	samplingPublish = -1.0
	// samplingHour is the longest interval the server grants. A sample that
	// is postponed with it never becomes due during a test.
	samplingHourMS = 3_600_000.0
)

// queueSize is the queue size of every monitored item of the suite: large
// enough that a sample is rarely discarded, and above 1 so that the server
// marks a discarded one with the Overflow bit.
const queueSize = 100

// itemSpec describes a monitored item.
type itemSpec struct {
	n          *node
	indexRange string

	// noFilter sends no filter at all, which is StatusValue without
	// deadband.
	noFilter     bool
	trigger      ua.DataChangeTrigger
	deadbandType ua.DeadbandType
	// deadband is the DeadbandValue: absolute, or a percentage of the
	// EURange.
	deadband float64

	samplingMS    float64
	discardOldest bool
}

func (s itemSpec) String() string {
	f := "no filter"
	if !s.noFilter {
		f = fmt.Sprintf("%v/%v/%v", s.trigger, s.deadbandType, s.deadband)
	}
	return fmt.Sprintf("%s[%s] %s sampling=%vms", s.n.name, s.indexRange, f, s.samplingMS)
}

// wire returns the filter to send.
func (s itemSpec) wire() *ua.ExtensionObject {
	if s.noFilter {
		return nil
	}
	return opcua.NewDataChangeFilter(s.trigger, s.deadbandType, s.deadband)
}

// resolve returns the filter the server has to apply.
func (s itemSpec) resolve() filter {
	if s.noFilter {
		return filter{}
	}
	var f filter
	switch s.trigger {
	case ua.DataChangeTriggerStatus:
		f.statusOnly = true
	case ua.DataChangeTriggerStatusValueTimestamp:
		f.timestamp = true
	case ua.DataChangeTriggerStatusValue:
	}
	switch s.deadbandType {
	case ua.DeadbandTypeAbsolute:
		f.hasDeadband, f.deadband = true, s.deadband
	case ua.DeadbandTypePercent:
		lo, hi, _ := s.n.kind.euRange()
		f.hasDeadband, f.deadband = true, s.deadband/100*(hi-lo)
	case ua.DeadbandTypeNone:
	}
	return f
}

// revisedSampling is the sampling interval the server has to grant: 0 stays
// 0, a negative request means the publishing interval, anything else is kept
// within 1 ms and 1 h.
func (s itemSpec) revisedSampling(publishingMS float64) float64 {
	switch ms := s.samplingMS; {
	case ms == 0:
		return 0
	case ms < 0:
		return publishingMS
	default:
		return math.Min(math.Max(ms, 1), samplingHourMS)
	}
}

var (
	triggers     = []ua.DataChangeTrigger{ua.DataChangeTriggerStatus, ua.DataChangeTriggerStatusValue, ua.DataChangeTriggerStatusValueTimestamp}
	samplings    = []float64{0, samplingShortMS, samplingLongMS, samplingPublish}
	indexRanges  = []string{"", "1:3", "4", "0:1"}
	deadbandMult = []float64{0.5, 1, 2}
)

// randomFilter gives s a random filter that suits its node, and a random
// sampling interval.
func (s itemSpec) randomFilter(rng *rand.Rand) itemSpec {
	s.noFilter = rng.Intn(8) == 0
	s.trigger = triggers[rng.Intn(len(triggers))]
	s.samplingMS = samplings[rng.Intn(len(samplings))]
	mult := deadbandMult[rng.Intn(len(deadbandMult))]
	_, _, analog := s.n.kind.euRange()
	switch r := rng.Intn(10); {
	case r < 4:
		s.deadbandType, s.deadband = ua.DeadbandTypeNone, 0
	case r < 7 && analog:
		// 5 % of the EURange is one unit.
		s.deadbandType, s.deadband = ua.DeadbandTypePercent, 5*mult
	default:
		s.deadbandType, s.deadband = ua.DeadbandTypeAbsolute, s.n.kind.unit()*mult
		if rng.Intn(6) == 0 {
			s.deadband = 0 // any change
		}
	}
	return s
}

// randomSpec returns a random item on n.
func randomSpec(rng *rand.Rand, n *node) itemSpec {
	s := itemSpec{n: n, discardOldest: rng.Intn(2) == 0}
	if n.kind.isArray() {
		s.indexRange = indexRanges[rng.Intn(len(indexRanges))]
	}
	return s.randomFilter(rng)
}

// ---------------------------------------------------------------------------
// environment: server behind the chaos proxy
// ---------------------------------------------------------------------------

// env is a server behind a chaos proxy. The server can be stopped and
// replaced by a fresh instance while the proxy keeps its client-facing port.
type env struct {
	t     *testing.T
	seed  int64
	proxy *testutil.ChaosProxy

	mu  sync.Mutex
	srv *server.Server
	nsp *server.NodeNameSpace
	gen int64            // generation of srv, encoded in every source timestamp
	old []*server.Server // stopped instances

	ns    uint16 // namespace index of the test nodes (the same for every instance)
	nodes []*node

	seq    atomic.Int64
	writes sync.Map // sequence number -> write
}

// newEnv starts a server with perKind variables of every kind.
func newEnv(t *testing.T, seed int64, perKind int) *env {
	t.Helper()
	e := &env{t: t, seed: seed}
	for k := nodeKind(0); k < numKinds; k++ {
		for i := 0; i < perKind; i++ {
			e.nodes = append(e.nodes, &node{name: fmt.Sprintf("%v%d", k, i), kind: k, cur: k.initial()})
		}
	}
	e.proxy = testutil.NewChaosProxy(t, "", seed)
	e.startServer()
	t.Cleanup(func() { e.stopServer() })
	return e
}

// node returns the i-th variable of kind k.
func (e *env) node(k nodeKind, i int) *node {
	for _, n := range e.nodes {
		if n.kind == k {
			if i == 0 {
				return n
			}
			i--
		}
	}
	e.t.Fatalf("no node %v #%d", k, i)
	return nil
}

func (e *env) url() string { return e.proxy.EndpointURL() }

func (e *env) server() *server.Server {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.srv
}

// startServer creates and starts a new server instance - a new generation -
// and points the proxy at it.
func (e *env) startServer() {
	e.t.Helper()
	srv, err := server.New(
		server.InsecureNoSecurity(),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.SetLogger(chaoskit.Logger()),
		server.EndPoint("localhost", e.proxy.Port()),
		server.ListenOn("localhost:0"),
	)
	if err != nil {
		e.t.Fatalf("new server: %v", err)
	}
	e.mu.Lock()
	e.gen++
	gen := e.gen
	e.mu.Unlock()
	nsp := e.populate(srv, gen)
	if err := srv.Start(context.Background()); err != nil {
		e.t.Fatalf("start server: %v", err)
	}
	e.mu.Lock()
	e.srv, e.nsp = srv, nsp
	e.mu.Unlock()
	e.proxy.SetBackend(fmt.Sprintf("localhost:%d", srv.Port()))
}

// stopServer closes the current server instance (if any).
func (e *env) stopServer() {
	e.mu.Lock()
	srv := e.srv
	e.srv, e.nsp = nil, nil
	if srv != nil {
		e.old = append(e.old, srv)
	}
	e.mu.Unlock()
	if srv != nil {
		_ = srv.Close()
	}
}

// restartServer replaces the server with a brand-new instance: all sessions,
// subscriptions and monitored items are lost, as after a process restart.
func (e *env) restartServer(downtime time.Duration) {
	e.proxy.SetRefuse(true)
	e.stopServer()
	e.proxy.DropAll()
	time.Sleep(downtime)
	e.startServer()
	e.proxy.SetRefuse(false)
}

// populate adds the test namespace to srv. Every variable starts with the
// value its model is at, stamped with the generation of srv.
func (e *env) populate(srv *server.Server, gen int64) *server.NodeNameSpace {
	e.t.Helper()
	root, err := srv.Namespace(0)
	if err != nil {
		e.t.Fatalf("namespace 0: %v", err)
	}
	ns := server.NewNodeNameSpace(srv, "http://otfabric.com/chaos/datachange")
	obj := ns.Objects()
	root.Objects().AddRef(obj, id.HasComponent, true)
	if e.ns == 0 {
		e.ns = ns.ID()
	}
	for _, n := range e.nodes {
		n.mu.Lock()
		if n.id == nil {
			n.id = ua.NewStringNodeID(e.ns, n.name)
		}
		v := ns.AddNewVariableStringNode(n.name, n.cur)
		obj.AddRef(v, id.HasComponent, true)
		if lo, hi, ok := n.kind.euRange(); ok {
			addEURange(srv, ns, v, n.name, lo, hi)
		}
		w := e.record(n, gen, n.cur, n.status)
		if sc := ns.SetAttribute(n.id, ua.AttributeIDValue, dataValue(w)); sc != ua.StatusOK {
			e.t.Fatalf("initial value of %s: %v", n.name, sc)
		}
		n.mu.Unlock()
	}
	return ns
}

// addEURange makes v an AnalogItemType variable with an EURange property
// (Part 8 §5.3.2.3).
func addEURange(srv *server.Server, ns *server.NodeNameSpace, v *server.Node, name string, lo, hi float64) {
	if typ := srv.Node(ua.NewNumericNodeID(0, id.AnalogItemType)); typ != nil {
		v.AddRef(typ, id.HasTypeDefinition, true)
	}
	rng := &ua.DataValue{
		EncodingMask: ua.DataValueValue,
		Value:        ua.MustVariant(ua.NewExtensionObject(&ua.Range{Low: lo, High: hi})),
	}
	prop := server.NewNode(
		ua.NewStringNodeID(ns.ID(), name+".EURange"),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:   server.DataValueFromValue(uint32(ua.NodeClassVariable)),
			ua.AttributeIDBrowseName:  server.DataValueFromValue(attrs.BrowseName("EURange")),
			ua.AttributeIDDisplayName: server.DataValueFromValue(attrs.DisplayName("EURange", "EURange")),
			ua.AttributeIDDataType:    server.DataValueFromValue(ua.NewNumericExpandedNodeID(0, id.Range)),
		},
		nil,
		func() *ua.DataValue { return rng },
	)
	ns.AddNode(prop)
	v.AddRef(prop, id.HasProperty, true)
}

// record registers a server-side write of n and returns it. The caller must
// hold n.mu.
func (e *env) record(n *node, gen int64, v any, status ua.StatusCode) write {
	seq := e.seq.Add(1)
	w := write{seq: seq, value: v, status: status, source: stamp(gen, seq)}
	e.writes.Store(seq, w)
	n.hist = append(n.hist, w)
	return w
}

// lookup returns the server-side write with the given sequence number.
func (e *env) lookup(seq int64) (write, bool) {
	v, ok := e.writes.Load(seq)
	if !ok {
		return write{}, false
	}
	return v.(write), true
}

// dataValue builds the DataValue of a write. It carries no server timestamp,
// so the server stamps each sample with the time it is taken.
func dataValue(w write) *ua.DataValue {
	dv := &ua.DataValue{
		EncodingMask:    ua.DataValueValue | ua.DataValueSourceTimestamp,
		Value:           ua.MustVariant(w.value),
		SourceTimestamp: w.source,
	}
	if w.status != ua.StatusOK {
		dv.EncodingMask |= ua.DataValueStatusCode
		dv.Status = w.status
	}
	return dv
}

// set writes v with the given status into the address space of the running
// server, as an application embedding the server would. Writes of one node
// through set are applied in the order of their sequence numbers. ok is false
// when no server is running.
func (e *env) set(n *node, v any, status ua.StatusCode) (w write, ok bool) {
	e.mu.Lock()
	nsp, gen := e.nsp, e.gen
	e.mu.Unlock()
	if nsp == nil {
		return write{}, false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.cur, n.status = v, status
	w = e.record(n, gen, v, status)
	if sc := nsp.SetAttribute(n.id, ua.AttributeIDValue, dataValue(w)); sc != ua.StatusOK {
		e.t.Errorf("server-side write of %s failed: %v", n.name, sc)
	}
	return w, true
}

// randomSet writes the next random value of n on the server. Now and then
// the status changes instead of, or together with, the value.
func (e *env) randomSet(n *node, rng *rand.Rand) (write, bool) {
	n.mu.Lock()
	v, status := n.step(rng), n.status
	n.mu.Unlock()
	if rng.Intn(16) == 0 {
		if status == ua.StatusOK {
			status = ua.StatusUncertainLastUsableValue
		} else {
			status = ua.StatusOK
		}
	}
	return e.set(n, v, status)
}

// clientWrite writes the next random value of n through the Write service.
// Arrays are sometimes written through an IndexRange. A client cannot write a
// status or a timestamp, so these values carry no sequence number.
func (e *env) clientWrite(ctx context.Context, c *opcua.Client, n *node, rng *rand.Rand) error {
	n.mu.Lock()
	v := n.step(rng)
	n.mu.Unlock()
	wv := &ua.WriteValue{
		NodeID:      n.id,
		AttributeID: ua.AttributeIDValue,
		Value:       &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)},
	}
	if n.kind.isArray() && rng.Intn(3) == 0 {
		part, _ := sliceValue(v, "2:3")
		wv.IndexRange = "2:3"
		wv.Value.Value = ua.MustVariant(part)
	}
	res, err := c.Write(ctx, &ua.WriteRequest{NodesToWrite: []*ua.WriteValue{wv}})
	if err != nil {
		return err
	}
	if len(res.Results) != 1 || res.Results[0] != ua.StatusOK {
		return fmt.Errorf("write %s: results %v", n.name, res.Results)
	}
	return nil
}

// between returns the ordered writes of n with from <= seq < to.
func (n *node) between(from, to int64) []write {
	n.mu.Lock()
	defer n.mu.Unlock()
	i := sort.Search(len(n.hist), func(i int) bool { return n.hist[i].seq >= from })
	j := sort.Search(len(n.hist), func(i int) bool { return n.hist[i].seq >= to })
	return append([]write(nil), n.hist[i:j]...)
}

// last returns the most recent server-side write of n.
func (n *node) last() write {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.hist[len(n.hist)-1]
}

// resources returns the per-client resources held by the current server.
func (e *env) resources() testhook.ServerResources {
	srv := e.server()
	if srv == nil {
		return testhook.ServerResources{}
	}
	return testhook.ServerResourcesOf(srv)
}

// sampler returns the state of the sampler of the current server.
func (e *env) sampler() testhook.ServerSampler {
	srv := e.server()
	if srv == nil {
		return testhook.ServerSampler{}
	}
	return testhook.ServerSamplerOf(srv)
}

// waitSamplerIdle waits until the server has taken every postponed sample.
// Together with the fact that a server-side write samples synchronously this
// is a barrier: afterwards every write made so far has been sampled by every
// item that is going to sample it.
func (e *env) waitSamplerIdle() bool {
	e.t.Helper()
	var last testhook.ServerSampler
	if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool {
		last = e.sampler()
		return last == testhook.ServerSampler{}
	}) {
		e.t.Errorf("SAMPLER STUCK: postponed samples were not taken within %v: %+v", chaoskit.SettleLimit, last)
		return false
	}
	return true
}

// requireSamplerStopped verifies that the sampler of srv holds nothing: no
// armed timer, no postponed sample, no callback in flight. A callback that
// has just fired is given time to return.
func requireSamplerStopped(t *testing.T, srv *server.Server, when string) {
	t.Helper()
	var last testhook.ServerSampler
	if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool {
		last = testhook.ServerSamplerOf(srv)
		return last == testhook.ServerSampler{}
	}) {
		t.Errorf("SAMPLER LEAK %s: %+v", when, last)
	}
}

// requireDrained waits until the current server holds no channels, sessions,
// subscriptions or monitored items, and its sampler nothing.
func (e *env) requireDrained() {
	e.t.Helper()
	var last testhook.ServerResources
	if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool {
		last = e.resources()
		return last == testhook.ServerResources{}
	}) {
		e.t.Errorf("server did not release client resources within %v: %+v", chaoskit.SettleLimit, last)
	}
	if srv := e.server(); srv != nil {
		requireSamplerStopped(e.t, srv, "after all clients are gone")
	}
}

// clientOptions returns the options of a client that talks through the proxy.
func (e *env) clientOptions(rec *chaoskit.StateRecorder, extra ...opcua.Option) []opcua.Option {
	opts := []opcua.Option{
		opcua.InsecureNoSecurity(),
		opcua.DialTimeout(10 * time.Second),
		// Fault-free tests must never fail because the machine is slow, so
		// the default request timeout only guards against a hang.
		opcua.RequestTimeout(30 * time.Second),
		opcua.ReconnectInterval(50 * time.Millisecond),
		opcua.AutoReconnect(true),
	}
	if rec != nil {
		opts = append(opts, opcua.WithConnStateHandler(rec.Handle))
	}
	if l := chaoskit.Logger(); l != nil {
		opts = append(opts, opcua.WithLogger(l.With("side", "client")))
	}
	return append(opts, extra...)
}

// connect creates and connects a client. It is closed when the test ends
// unless the test closed it earlier.
func (e *env) connect(rec *chaoskit.StateRecorder, extra ...opcua.Option) *opcua.Client {
	e.t.Helper()
	c, err := opcua.NewClient(e.url(), append([]opcua.Option{opcua.InsecureNoSecurity()}, e.clientOptions(rec, extra...)...)...)
	if err != nil {
		e.t.Fatalf("new client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		chaoskit.CloseClient(c, rec)
		e.t.Fatalf("connect: %v", err)
	}
	e.t.Cleanup(func() { chaoskit.CloseClient(c, rec) })
	return c
}

// ---------------------------------------------------------------------------
// tracker: a subscription whose notifications are judged
// ---------------------------------------------------------------------------

// spacingMin is the shortest sampling interval for which the distance of two
// consecutive samples is checked through their server timestamps. The server
// reads the clock twice per sample (once to decide, once to stamp), so the
// observed distance can be short of the real one by the time the first sample
// took; half the interval is allowed for that.
const spacingMin = 100 * time.Millisecond

// epoch is the time during which an item had one client handle, and with it
// one filter and one sampling interval. ModifyMonitoredItems starts a new
// epoch; the server switches handle, filter and interval atomically.
type epoch struct {
	it       *item
	idx      int
	handle   uint32
	flt      filter
	interval time.Duration
	// free is set when the item was disabled when this epoch began. The
	// server then has no previous value of the item, and the first sample it
	// takes from here on is reported whatever the filter.
	free bool

	// start is taken before the request that begins the epoch is sent, end
	// after the response to the request that ends it arrived. Every sample
	// of the epoch was taken in between. Guarded by item.mu.
	start, end time.Time
	count      int
}

// seenValue is one delivered notification of an item.
type seenValue struct {
	sample
	gen, seq int64
	stamped  bool
	overflow bool
	server   time.Time
	subID    uint32
}

// item is a monitored item and what the test knows about it.
type item struct {
	tr   *tracker
	spec itemSpec
	// wild items are operated on without any coordination. Only what does
	// not depend on the order of those operations is checked for them.
	wild bool

	// ctl serialises the operations that change what the item reports
	// (modify, disable, delete). id and mode are guarded by it.
	ctl  sync.Mutex
	id   uint32
	mode ua.MonitoringMode
	gone bool

	mu     sync.Mutex
	epochs []*epoch
	newest int // index of the newest epoch a notification arrived for, or -1
	has    bool
	prev   seenValue
	total  int
	// silent items are in Sampling or Disabled mode for good and must not
	// deliver anything.
	silent bool
	// log holds the notifications since startLog.
	logging bool
	log     []seenValue
}

func (it *item) String() string {
	return fmt.Sprintf("%s item %d (%v)", it.tr.name, it.id, it.spec)
}

// disabledSince reports whether the item was disabled after the last
// notification that arrived and before the epoch upTo ended: one of the
// epochs in between began disabled. The caller must hold it.mu.
func (it *item) disabledSince(upTo int) bool {
	for i := it.newest + 1; i <= upTo && i < len(it.epochs); i++ {
		if it.epochs[i].free {
			return true
		}
	}
	return false
}

// current returns the newest epoch of the item.
func (it *item) current() *epoch {
	it.mu.Lock()
	defer it.mu.Unlock()
	return it.epochs[len(it.epochs)-1]
}

// startLog starts recording the notifications of the item.
func (it *item) startLog() {
	it.mu.Lock()
	it.logging, it.log = true, nil
	it.mu.Unlock()
}

// logged returns the recorded notifications.
func (it *item) logged() []seenValue {
	it.mu.Lock()
	defer it.mu.Unlock()
	return append([]seenValue(nil), it.log...)
}

// lastSeen returns the last delivered notification.
func (it *item) lastSeen() (seenValue, bool) {
	it.mu.Lock()
	defer it.mu.Unlock()
	return it.prev, it.has
}

// tracker is a subscription with a consumer that judges every notification.
type tracker struct {
	name string
	e    *env
	sub  *opcua.Subscription
	ch   chan *opcua.PublishNotificationData
	// publishingMS is the publishing interval, which is the sampling
	// interval of items that ask for a negative one.
	publishingMS float64
	// lossy is set when faults are injected: notifications can be lost and
	// items recreated, and error notifications are expected.
	lossy bool
	sink  *chaoskit.ErrSink
	errs  chaoskit.ErrorTally

	mu         sync.Mutex
	byHandle   map[uint32]*epoch
	nextHandle uint32
	items      []*item // every item ever created

	received atomic.Int64
	stop     chan struct{}
	done     chan struct{}
}

// newTracker subscribes c and starts the consumer.
func newTracker(ctx context.Context, e *env, c *opcua.Client, name string, params *opcua.SubscriptionParameters, lossy bool, sink *chaoskit.ErrSink) (*tracker, error) {
	tr := &tracker{
		name:         name,
		e:            e,
		ch:           make(chan *opcua.PublishNotificationData, 16),
		publishingMS: float64(params.Interval / time.Millisecond),
		lossy:        lossy,
		sink:         sink,
		byHandle:     make(map[uint32]*epoch),
		stop:         make(chan struct{}),
		done:         make(chan struct{}),
	}
	go tr.consume()
	sub, err := c.Subscribe(ctx, params, tr.ch)
	if err != nil {
		tr.close()
		return nil, fmt.Errorf("subscribe %s: %w", name, err)
	}
	tr.sub = sub
	return tr, nil
}

// close stops the consumer. It must be called after the subscription was
// cancelled or the client was closed.
func (tr *tracker) close() {
	select {
	case <-tr.stop:
	default:
		close(tr.stop)
	}
	<-tr.done
}

func (tr *tracker) consume() {
	defer close(tr.done)
	for {
		select {
		case <-tr.stop:
			return
		case n := <-tr.ch:
			tr.handle(n)
		}
	}
}

func (tr *tracker) handle(n *opcua.PublishNotificationData) {
	if n.Error != nil {
		tr.errs.Add(n.Error)
		if !tr.lossy || !chaoskit.IsConnectionError(n.Error) {
			tr.sink.Addf("%s: unexpected error notification: %v", tr.name, n.Error)
		}
		return
	}
	dcn, ok := n.Value.(*ua.DataChangeNotification)
	if !ok {
		return
	}
	for _, mi := range dcn.MonitoredItems {
		if mi == nil || mi.Value == nil {
			tr.sink.Addf("%s: notification without a value: %+v", tr.name, mi)
			continue
		}
		tr.mu.Lock()
		ep := tr.byHandle[mi.ClientHandle]
		tr.mu.Unlock()
		if ep == nil {
			tr.sink.Addf("%s: notification for unknown client handle %d", tr.name, mi.ClientHandle)
			continue
		}
		tr.received.Add(1)
		ep.it.observe(ep, mi.Value, n.SubscriptionID)
	}
}

// observe judges one notification of the item.
func (it *item) observe(ep *epoch, dv *ua.DataValue, subID uint32) {
	tr := it.tr
	cur, overflow := sampleOf(dv)
	gen, seq, stamped := unstamp(cur.source)
	now := seenValue{sample: cur, gen: gen, seq: seq, stamped: stamped, overflow: overflow, server: dv.ServerTimestamp, subID: subID}

	it.mu.Lock()
	defer it.mu.Unlock()
	prev, first := it.prev, !it.has
	// Notifications arrive in the order they were queued, so the client
	// handle of an older epoch cannot follow that of a newer one. If the
	// item was disabled between the previous notification and this one (an
	// epoch that began disabled lies in between), the server compared this
	// sample with nothing.
	reordered := ep.idx < it.newest
	afterDisable := false
	if !reordered && !it.wild {
		afterDisable = it.disabledSince(ep.idx)
		it.newest = ep.idx
	}
	it.prev, it.has = now, true
	it.total++
	ep.count++
	if it.logging {
		it.log = append(it.log, now)
	}

	if it.silent {
		tr.sink.Addf("MODE LOST: %v is not in Reporting mode but delivered %v", it, cur)
		return
	}

	// The value is one that was written, reduced to the index range.
	if !it.checkShape(cur) {
		return
	}
	if stamped {
		w, ok := tr.e.lookup(seq)
		if !ok {
			tr.sink.Addf("CORRUPT VALUE: %v delivered %v, which was never written", it, cur)
			return
		}
		if want := w.seen(it.spec.indexRange); want.status != cur.status || !reflect.DeepEqual(want.value, cur.value) {
			tr.sink.Addf("CORRUPT VALUE: %v delivered %v for write %d, want %v", it, cur, seq, want)
			return
		}
	} else if tr.lossy {
		tr.sink.Addf("CORRUPT VALUE: %v delivered %v without the source timestamp of a write", it, cur)
		return
	}
	if it.wild {
		return
	}

	if reordered {
		tr.sink.Addf("REORDERED: %v delivered a notification with client handle %d after one of a later modification", it, ep.handle)
		return
	}

	// A recreated item (new subscription or new server) starts over with
	// its initial value.
	recreated := tr.lossy && !first && (subID != prev.subID || gen != prev.gen)
	if first || recreated {
		return
	}

	// At most one sample per sampling interval.
	if ep.interval >= spacingMin && !dv.ServerTimestamp.IsZero() && !prev.server.IsZero() {
		if d := dv.ServerTimestamp.Sub(prev.server); d < ep.interval/2 {
			tr.sink.Addf("SAMPLING INTERVAL VIOLATED: %v was sampled twice within %v (interval %v): %v then %v", it, d, ep.interval, prev.sample, cur)
		}
	}

	if tr.lossy {
		it.judgeLossy(ep, prev, now)
		return
	}
	// The server compared this sample with the previous one it queued. That
	// is the previous notification, unless the server had none (the item was
	// disabled) or discarded it (overflow).
	if overflow || afterDisable {
		return
	}
	if !ep.flt.changed(prev.sample, cur) {
		tr.sink.Addf("FILTER VIOLATED: %v reported %v after %v, which filter %v suppresses", it, cur, prev.sample, ep.flt)
	}
}

// checkShape verifies the type of a delivered value and, for an index range,
// its length.
func (it *item) checkShape(cur sample) bool {
	want, st := sliceValue(it.spec.n.kind.initial(), it.spec.indexRange)
	if cur.value == nil {
		if cur.status == ua.StatusOK || cur.status == ua.StatusUncertainLastUsableValue {
			it.tr.sink.Addf("CORRUPT VALUE: %v delivered no value with status %v", it, cur.status)
			return false
		}
		return true
	}
	if st != ua.StatusOK || reflect.TypeOf(want) != reflect.TypeOf(cur.value) ||
		(it.spec.n.kind.isArray() && reflect.ValueOf(want).Len() != reflect.ValueOf(cur.value).Len()) {
		it.tr.sink.Addf("CORRUPT VALUE: %v delivered %v (%T), want the shape of %v (%T)", it, cur.value, cur.value, want, want)
		return false
	}
	return true
}

// judgeLossy is the filter check that stays sound when notifications can be
// lost. The server compared now with the last sample it queued: prev, or a
// later one that never reached the client. Each of those is a server-side
// write of the node with prev.seq <= seq < now.seq. If the filter suppresses
// now relative to every one of them, nothing can justify the notification.
func (it *item) judgeLossy(ep *epoch, prev, now seenValue) {
	tr := it.tr
	if now.seq < prev.seq {
		tr.sink.Addf("REORDERED: %v delivered write %d after write %d", it, now.seq, prev.seq)
		return
	}
	for _, w := range it.spec.n.between(prev.seq, now.seq) {
		if ep.flt.changed(w.seen(it.spec.indexRange), now.sample) {
			return
		}
	}
	tr.sink.Addf("FILTER VIOLATED: %v reported %v after %v, but filter %v suppresses it relative to every value written in between",
		it, now.sample, prev.sample, ep.flt)
}

// newEpoch starts an epoch of the item and makes its client handle known to
// the consumer. It must be called before the request is sent: the first
// notification can overtake the response.
func (tr *tracker) newEpoch(it *item, spec itemSpec, free bool) *epoch {
	ep := &epoch{
		it:       it,
		flt:      spec.resolve(),
		interval: time.Duration(spec.revisedSampling(tr.publishingMS) * float64(time.Millisecond)),
		free:     free,
		start:    time.Now(),
	}
	tr.mu.Lock()
	tr.nextHandle++
	ep.handle = tr.nextHandle
	tr.byHandle[ep.handle] = ep
	tr.mu.Unlock()

	it.mu.Lock()
	ep.idx = len(it.epochs)
	it.epochs = append(it.epochs, ep)
	it.mu.Unlock()
	return ep
}

func (tr *tracker) parameters(spec itemSpec, handle uint32) *ua.MonitoringParameters {
	return &ua.MonitoringParameters{
		ClientHandle:     handle,
		SamplingInterval: spec.samplingMS,
		Filter:           spec.wire(),
		QueueSize:        queueSize,
		DiscardOldest:    spec.discardOldest,
	}
}

// create adds one monitored item per spec in the given mode. It fails when
// the server does not accept an item exactly as requested.
func (tr *tracker) create(ctx context.Context, mode ua.MonitoringMode, wild bool, specs ...itemSpec) ([]*item, error) {
	items := make([]*item, len(specs))
	reqs := make([]*ua.MonitoredItemCreateRequest, len(specs))
	for i, spec := range specs {
		it := &item{tr: tr, spec: spec, wild: wild, mode: mode, newest: -1}
		ep := tr.newEpoch(it, spec, false)
		items[i] = it
		reqs[i] = &ua.MonitoredItemCreateRequest{
			ItemToMonitor: &ua.ReadValueID{
				NodeID:       spec.n.id,
				AttributeID:  ua.AttributeIDValue,
				IndexRange:   spec.indexRange,
				DataEncoding: &ua.QualifiedName{},
			},
			MonitoringMode:      mode,
			RequestedParameters: tr.parameters(spec, ep.handle),
		}
	}
	tr.mu.Lock()
	tr.items = append(tr.items, items...)
	tr.mu.Unlock()

	res, err := tr.sub.Monitor(ctx, ua.TimestampsToReturnBoth, reqs...)
	if err != nil {
		return nil, fmt.Errorf("%s: create monitored items: %w", tr.name, err)
	}
	if len(res.Results) != len(specs) {
		return nil, fmt.Errorf("%s: create monitored items: %d results for %d items", tr.name, len(res.Results), len(specs))
	}
	for i, r := range res.Results {
		if r.StatusCode != ua.StatusOK {
			return nil, fmt.Errorf("%s: create %v: %v", tr.name, specs[i], r.StatusCode)
		}
		if want := specs[i].revisedSampling(tr.publishingMS); r.RevisedSamplingInterval != want || r.RevisedQueueSize != queueSize {
			return nil, fmt.Errorf("%s: create %v: revised sampling interval %v and queue size %d, want %v and %d",
				tr.name, specs[i], r.RevisedSamplingInterval, r.RevisedQueueSize, want, queueSize)
		}
		items[i].id = r.MonitoredItemID
	}
	return items, nil
}

// modify gives the item the filter and sampling interval of spec, and a new
// client handle. free says that the item is disabled. The caller must hold
// it.ctl.
func (tr *tracker) modify(ctx context.Context, it *item, spec itemSpec, free bool) error {
	old := it.current()
	ep := tr.newEpoch(it, spec, free)
	res, err := tr.sub.ModifyMonitoredItems(ctx, ua.TimestampsToReturnBoth, &ua.MonitoredItemModifyRequest{
		MonitoredItemID:     it.id,
		RequestedParameters: tr.parameters(spec, ep.handle),
	})
	if err != nil {
		return fmt.Errorf("modify %v: %w", it, err)
	}
	if len(res.Results) != 1 || res.Results[0].StatusCode != ua.StatusOK {
		return fmt.Errorf("modify %v to %v: results %+v", it, spec, res.Results)
	}
	if want := spec.revisedSampling(tr.publishingMS); res.Results[0].RevisedSamplingInterval != want {
		return fmt.Errorf("modify %v to %v: revised sampling interval %v, want %v", it, spec, res.Results[0].RevisedSamplingInterval, want)
	}
	it.mu.Lock()
	old.end = time.Now()
	it.spec = spec
	it.mu.Unlock()
	return nil
}

// setMode changes the monitoring mode of the item. The caller must hold
// it.ctl.
func (tr *tracker) setMode(ctx context.Context, it *item, mode ua.MonitoringMode) error {
	res, err := tr.sub.SetMonitoringMode(ctx, mode, it.id)
	if err != nil {
		return fmt.Errorf("set %v to %v: %w", it, mode, err)
	}
	if len(res.Results) != 1 || res.Results[0] != ua.StatusOK {
		return fmt.Errorf("set %v to %v: results %v", it, mode, res.Results)
	}
	it.mode = mode
	return nil
}

// remove deletes the item. The caller must hold it.ctl.
func (tr *tracker) remove(ctx context.Context, it *item) error {
	res, err := tr.sub.Unmonitor(ctx, it.id)
	if err != nil {
		return fmt.Errorf("delete %v: %w", it, err)
	}
	if len(res.Results) != 1 || res.Results[0] != ua.StatusOK {
		return fmt.Errorf("delete %v: results %v", it, res.Results)
	}
	it.gone = true
	it.mu.Lock()
	it.epochs[len(it.epochs)-1].end = time.Now()
	it.mu.Unlock()
	return nil
}

// checkRates verifies, for every epoch of every item, that the server took
// at most one sample per sampling interval: n samples that are at least one
// interval apart need (n-1) intervals.
func (tr *tracker) checkRates() {
	now := time.Now()
	tr.mu.Lock()
	items := append([]*item(nil), tr.items...)
	tr.mu.Unlock()
	for _, it := range items {
		if it.wild {
			continue
		}
		it.mu.Lock()
		for _, ep := range it.epochs {
			if ep.interval <= 0 {
				continue
			}
			end := ep.end
			if end.IsZero() {
				end = now
			}
			window := end.Sub(ep.start)
			if limit := int(window/ep.interval) + 1; ep.count > limit {
				tr.sink.Addf("SAMPLING INTERVAL VIOLATED: %v delivered %d notifications in %v with client handle %d, at most %d fit a sampling interval of %v",
					it, ep.count, window, ep.handle, limit, ep.interval)
			}
		}
		it.mu.Unlock()
	}
}
