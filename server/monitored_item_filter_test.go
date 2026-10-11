// SPDX-License-Identifier: MIT

package server

import (
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestReviseSamplingInterval(t *testing.T) {
	require.Equal(t, 0.0, reviseSamplingInterval(0, 100))
	require.Equal(t, 100.0, reviseSamplingInterval(-1, 100))
	require.Equal(t, 100.0, reviseSamplingInterval(math.NaN(), 100))
	require.Equal(t, minSamplingIntervalMS, reviseSamplingInterval(0.001, 100))
	require.Equal(t, 250.0, reviseSamplingInterval(250, 100))
	require.Equal(t, maxSamplingIntervalMS, reviseSamplingInterval(1e15, 100))
	// A negative request follows the publishing interval, clamped as well.
	require.Equal(t, minSamplingIntervalMS, reviseSamplingInterval(-1, 0.5))
}

func TestVariantChanged(t *testing.T) {
	v := ua.MustVariant
	cases := []struct {
		name     string
		a, b     *ua.Variant
		deadband float64
		want     bool
	}{
		{"both nil", nil, nil, 0, false},
		{"one nil", nil, v(int32(1)), 0, true},
		{"type change", v(int32(1)), v(int64(1)), 10, true},
		{"equal ints", v(int32(5)), v(int32(5)), 0, false},
		{"int within", v(int32(5)), v(int32(7)), 2, false},
		{"int beyond", v(int32(5)), v(int32(8)), 2, true},
		{"int64 extremes", v(int64(math.MinInt64)), v(int64(math.MaxInt64)), 1e18, true},
		{"uint within", v(uint16(5)), v(uint16(4)), 1, false},
		{"uint beyond", v(uint64(0)), v(uint64(math.MaxUint64)), 1e19, true},
		{"float within", v(float32(1)), v(float32(1.5)), 0.5, false},
		{"float beyond", v(1.0), v(1.6), 0.5, true},
		{"NaN stays NaN", v(math.NaN()), v(math.NaN()), 0, false},
		{"becomes NaN", v(1.0), v(math.NaN()), 100, true},
		{"equal infinities", v(math.Inf(-1)), v(math.Inf(-1)), 0, false},
		{"opposite infinities", v(math.Inf(-1)), v(math.Inf(1)), 1e300, true},
		{"array within", v([]float64{1, 2}), v([]float64{1.5, 2.5}), 1, false},
		{"array one beyond", v([]float64{1, 2}), v([]float64{1, 4}), 1, true},
		{"array length", v([]int32{1, 2}), v([]int32{1, 2, 3}), 100, true},
		{"scalar vs array", v(int32(1)), v([]int32{1}), 100, true},
		{"matrix within", v([][]int32{{1, 2}, {3, 4}}), v([][]int32{{2, 3}, {4, 5}}), 1, false},
		{"matrix shape", v([][]int32{{1, 2}, {3, 4}}), v([][]int32{{1}, {2}, {3}, {4}}), 100, true},
		{"strings equal", v("a"), v("a"), 0, false},
		{"strings differ", v("a"), v("b"), 0, true},
		{"bool differ", v(true), v(false), 0, true},
		{"bytestring equal", v([]byte{1, 2}), v([]byte{1, 2}), 0, false},
		{"node ids equal", v(ua.NewNumericNodeID(1, 5)), v(ua.NewNumericNodeID(1, 5)), 0, false},
	}
	for _, tc := range cases {
		require.Equal(t, tc.want, variantChanged(tc.a, tc.b, tc.deadband), tc.name)
	}

	// The fallback for kinds that are not numbers.
	require.True(t, numericChangedAny("a", "b"))
	require.False(t, numericChangedAny("a", "a"))
	require.True(t, numericChangedAny([]any{int32(1)}, []any{int32(3)}))
	require.False(t, numericChangedAny([2]int8{1, 2}, [2]int8{1, 2}))
}

func numericChangedAny(a, b any) bool {
	return numericChanged(reflect.ValueOf(a), reflect.ValueOf(b), 1)
}

func TestDataChangeFilter_Changed(t *testing.T) {
	t0 := time.Unix(100, 0)
	t1 := time.Unix(200, 0)
	base := sampleState{status: ua.StatusOK, value: ua.MustVariant(10.0), sourceTS: t0}
	with := func(mod func(*sampleState)) sampleState {
		s := base
		mod(&s)
		return s
	}
	valueChange := with(func(s *sampleState) { s.value = ua.MustVariant(12.0) })
	tsChange := with(func(s *sampleState) { s.sourceTS = t1 })
	statusChange := with(func(s *sampleState) { s.status = ua.StatusBad })

	def := defaultDataChangeFilter()
	require.False(t, def.changed(base, base))
	require.True(t, def.changed(base, valueChange))
	require.False(t, def.changed(base, tsChange))
	require.True(t, def.changed(base, statusChange))

	status := dataChangeFilter{statusOnly: true}
	require.False(t, status.changed(base, valueChange))
	require.True(t, status.changed(base, statusChange))

	ts := dataChangeFilter{timestamp: true}
	require.True(t, ts.changed(base, tsChange))
	require.False(t, ts.changed(base, base))

	band := dataChangeFilter{hasDeadband: true, deadband: 5}
	require.False(t, band.changed(base, valueChange))
	require.True(t, band.changed(base, statusChange))
	tsBand := dataChangeFilter{timestamp: true, hasDeadband: true, deadband: 5}
	require.False(t, tsBand.changed(base, tsChange), "with a deadband the timestamp is not looked at")

	require.Equal(t, sampleState{}, stateOf(nil))
}

// samplerFixture is a server with one subscription and helpers to add
// monitored items by hand, bypassing the wire.
type samplerFixture struct {
	t   *testing.T
	srv *Server
	ns  *NodeNameSpace
	sub *Subscription
	svc *MonitoredItemService
}

func newSamplerFixture(t *testing.T) *samplerFixture {
	t.Helper()
	srv := newTestServer()
	ns, _ := addTestNamespace(srv)
	sub := NewSubscription()
	sub.srv = srv.SubscriptionService
	sub.ID = 1
	return &samplerFixture{t: t, srv: srv, ns: ns, sub: sub, svc: srv.MonitoredItemService}
}

func (f *samplerFixture) node(name string) *ua.NodeID { return ua.NewStringNodeID(f.ns.ID(), name) }

func (f *samplerFixture) add(itemID uint32, node *ua.NodeID, mod func(*MonitoredItem)) *MonitoredItem {
	item := &MonitoredItem{
		ID: itemID, Sub: f.sub, Mode: ua.MonitoringModeReporting, queueSize: 10, discardOldest: true,
		Req: &ua.MonitoredItemCreateRequest{
			ItemToMonitor:       &ua.ReadValueID{NodeID: node, AttributeID: ua.AttributeIDValue},
			RequestedParameters: &ua.MonitoringParameters{ClientHandle: itemID},
		},
	}
	if mod != nil {
		mod(item)
	}
	f.svc.Mu.Lock()
	f.svc.Items[item.ID] = item
	f.svc.Nodes[node.String()] = append(f.svc.Nodes[node.String()], item)
	f.svc.Subs[f.sub.ID] = append(f.svc.Subs[f.sub.ID], item)
	f.svc.Mu.Unlock()
	return item
}

func (f *samplerFixture) set(node *ua.NodeID, v any) {
	f.t.Helper()
	require.Equal(f.t, ua.StatusOK, f.ns.SetAttribute(node, ua.AttributeIDValue, DataValueFromValue(v)))
}

func (f *samplerFixture) queued(item *MonitoredItem) []any {
	f.svc.Mu.Lock()
	defer f.svc.Mu.Unlock()
	out := make([]any, 0, len(item.queue))
	for _, n := range item.queue {
		if n.Value == nil || n.Value.Value == nil {
			out = append(out, nil)
			continue
		}
		out = append(out, n.Value.Value.Value())
	}
	return out
}

// TestSampler_DefersWithinInterval drives the sampling interval logic with
// the clock under control: a change inside the interval is postponed, and
// the sampler then takes the latest value - once.
func TestSampler_DefersWithinInterval(t *testing.T) {
	f := newSamplerFixture(t)
	node := f.node("rw_int32")
	item := f.add(1, node, func(mi *MonitoredItem) { mi.samplingInterval = time.Hour })

	// Never sampled: the first change is taken right away.
	f.set(node, int32(1))
	require.Equal(t, []any{int32(1)}, f.queued(item))

	// Inside the interval: postponed, however often the value changes.
	f.set(node, int32(2))
	f.set(node, int32(3))
	require.Equal(t, []any{int32(1)}, f.queued(item))
	f.svc.Mu.Lock()
	require.Len(t, f.svc.due, 1)
	require.False(t, item.sampleDue.IsZero())
	require.NotNil(t, f.svc.sampler)
	require.Equal(t, item.sampleDue, f.svc.samplerAt)
	f.svc.Mu.Unlock()

	// The timer firing early changes nothing and keeps the item due.
	f.svc.runSampler()
	require.Equal(t, []any{int32(1)}, f.queued(item))
	f.svc.Mu.Lock()
	require.Len(t, f.svc.due, 1)
	require.Equal(t, item.sampleDue, f.svc.samplerAt, "re-armed for the pending item")
	// Let the interval end.
	item.sampleDue = time.Now().Add(-time.Millisecond)
	f.svc.Mu.Unlock()

	f.svc.runSampler()
	require.Equal(t, []any{int32(1), int32(3)}, f.queued(item), "the latest value of the interval")
	f.svc.Mu.Lock()
	require.Empty(t, f.svc.due)
	require.True(t, item.sampleDue.IsZero())
	require.True(t, f.svc.samplerAt.IsZero())
	f.svc.Mu.Unlock()

	// A postponed sample whose value went back to the reported one is
	// dropped by the filter.
	f.set(node, int32(4))
	f.set(node, int32(3))
	f.svc.Mu.Lock()
	item.sampleDue = time.Now().Add(-time.Millisecond)
	f.svc.Mu.Unlock()
	f.svc.runSampler()
	require.Equal(t, []any{int32(1), int32(3)}, f.queued(item))

	// Once the interval has passed a change is sampled immediately again.
	f.svc.Mu.Lock()
	item.lastSampled = time.Now().Add(-2 * time.Hour)
	f.svc.Mu.Unlock()
	f.set(node, int32(5))
	require.Equal(t, []any{int32(1), int32(3), int32(5)}, f.queued(item))
}

// TestSampler_TimerFires lets the real timer do the work for a short interval.
func TestSampler_TimerFires(t *testing.T) {
	f := newSamplerFixture(t)
	node := f.node("rw_int32")
	item := f.add(1, node, func(mi *MonitoredItem) { mi.samplingInterval = 20 * time.Millisecond })
	early := f.add(2, node, func(mi *MonitoredItem) { mi.samplingInterval = time.Hour })

	f.set(node, int32(1))
	f.set(node, int32(2)) // postponed for both
	require.Eventually(t, func() bool { return len(f.queued(item)) == 2 }, 10*time.Second, 2*time.Millisecond)
	require.Equal(t, []any{int32(1), int32(2)}, f.queued(item))
	require.Equal(t, []any{int32(1)}, f.queued(early), "the long interval is still running")

	// An item becoming due earlier than the armed time pulls the timer in.
	f.svc.Mu.Lock()
	require.False(t, f.svc.samplerAt.IsZero(), "timer stays armed for the other item")
	delete(f.svc.due, early.ID)
	early.sampleDue = time.Time{}
	f.svc.deferSample(early, time.Now())
	f.svc.Mu.Unlock()
	require.Eventually(t, func() bool { return len(f.queued(early)) == 2 }, 10*time.Second, 2*time.Millisecond)
}

// TestSampler_SkipsDeletedAndDisabled verifies a postponed sample is not
// taken for an item that was deleted or disabled in the meantime.
func TestSampler_SkipsDeletedAndDisabled(t *testing.T) {
	f := newSamplerFixture(t)
	node := f.node("rw_int32")
	mod := func(mi *MonitoredItem) { mi.samplingInterval = time.Hour }
	deleted := f.add(1, node, mod)
	disabled := f.add(2, node, mod)
	sampling := f.add(3, node, func(mi *MonitoredItem) { mod(mi); mi.Mode = ua.MonitoringModeSampling })

	f.set(node, int32(1))
	f.set(node, int32(2))
	f.svc.Mu.Lock()
	require.Len(t, f.svc.due, 3)
	// Deleted behind the service's back, so that only the sampler's own
	// check stands between the item and a sample.
	delete(f.svc.Items, deleted.ID)
	disabled.Mode = ua.MonitoringModeDisabled
	for _, it := range f.svc.due {
		it.sampleDue = time.Now().Add(-time.Millisecond)
	}
	f.svc.Mu.Unlock()

	f.svc.runSampler()
	require.Equal(t, []any{int32(1)}, f.queued(deleted))
	require.Equal(t, []any{int32(1)}, f.queued(disabled))
	require.Equal(t, []any{int32(1), int32(2)}, f.queued(sampling), "Sampling mode still samples")

	// DeleteMonitoredItem forgets a postponed sample.
	f.set(node, int32(3))
	f.svc.Mu.Lock()
	require.Contains(t, f.svc.due, sampling.ID)
	f.svc.Mu.Unlock()
	f.svc.DeleteMonitoredItem(sampling.ID)
	f.svc.Mu.Lock()
	require.NotContains(t, f.svc.due, sampling.ID)
	f.svc.Mu.Unlock()
}

// TestSampler_SurvivesPanickingValueFunction verifies that application code
// that panics while a postponed or initial sample is taken does not take the
// server down.
func TestSampler_SurvivesPanickingValueFunction(t *testing.T) {
	f := newSamplerFixture(t)
	nodeID := f.node("explosive")
	n := NewVariableNode(nodeID, "explosive", func() *ua.DataValue { panic("boom") })
	f.ns.AddNode(n)
	item := f.add(1, nodeID, nil)

	f.svc.Mu.Lock()
	f.svc.deferSample(item, time.Now().Add(-time.Second))
	f.svc.Mu.Unlock()
	require.NotPanics(t, f.svc.runSampler)

	f.svc.Mu.Lock()
	require.NotPanics(t, func() { f.svc.sampleInitial(item) })
	f.svc.Mu.Unlock()
	require.Empty(t, f.queued(item))
}

// TestReadSample_Edges covers the paths of readSample that a wire test does
// not reach: an unknown namespace and a namespace that returns no value.
func TestReadSample_Edges(t *testing.T) {
	f := newSamplerFixture(t)
	gone := f.add(1, ua.NewStringNodeID(77, "nowhere"), nil)
	f.svc.Mu.Lock()
	dv := f.svc.readSample(gone)
	f.svc.Mu.Unlock()
	require.Equal(t, ua.StatusBad, dv.Status)

	// ChangeNotification for it queues that status once.
	f.svc.ChangeNotification(gone.Req.ItemToMonitor.NodeID)
	f.svc.ChangeNotification(gone.Req.ItemToMonitor.NodeID)
	require.Equal(t, []any{nil}, f.queued(gone))

	// IndexRange on something that is not an array.
	scalar := f.add(2, f.node("rw_int32"), func(mi *MonitoredItem) { mi.indexRange = "0:1" })
	f.svc.Mu.Lock()
	dv = f.svc.readSample(scalar)
	f.svc.Mu.Unlock()
	require.Nil(t, dv.Value)
	require.Equal(t, ua.StatusBadIndexRangeInvalid, dv.Status)
}

// TestParseDataChangeFilter_DataTypes covers how the Number check and the
// EURange lookup deal with the different ways a server application can
// describe a variable.
func TestParseDataChangeFilter_DataTypes(t *testing.T) {
	f := newSamplerFixture(t)
	svc := f.svc
	abs := ua.NewExtensionObject(&ua.DataChangeFilter{
		Trigger: ua.DataChangeTriggerStatusValue, DeadbandType: uint32(ua.DeadbandTypeAbsolute), DeadbandValue: 1,
	})
	pct := ua.NewExtensionObject(&ua.DataChangeFilter{
		Trigger: ua.DataChangeTriggerStatusValue, DeadbandType: uint32(ua.DeadbandTypePercent), DeadbandValue: 50,
	})
	value := func(n *ua.NodeID) *ua.ReadValueID {
		return &ua.ReadValueID{NodeID: n, AttributeID: ua.AttributeIDValue}
	}
	typed := func(name string, dataType any, v any) *Node {
		n := NewNode(f.node(name), map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:  DataValueFromValue(uint32(ua.NodeClassVariable)),
			ua.AttributeIDBrowseName: DataValueFromValue(attrs.BrowseName(name)),
		}, nil, func() *ua.DataValue { return DataValueFromValue(v) })
		if dataType != nil {
			require.NoError(t, n.SetAttribute(ua.AttributeIDDataType, DataValueFromValue(dataType)))
		}
		f.ns.AddNode(n)
		return n
	}

	// No filter, in its different spellings.
	for _, eo := range []*ua.ExtensionObject{nil, {}, ua.NewExtensionObject(nil), {Value: (*ua.DataChangeFilter)(nil)}} {
		got, st := svc.parseDataChangeFilter(value(f.node("rw_int32")), eo)
		require.Equal(t, ua.StatusOK, st)
		require.Equal(t, defaultDataChangeFilter(), got)
	}
	// A filter passed by value.
	got, st := svc.parseDataChangeFilter(value(f.node("rw_int32")),
		&ua.ExtensionObject{Value: ua.DataChangeFilter{Trigger: ua.DataChangeTriggerStatus}})
	require.Equal(t, ua.StatusOK, st)
	require.True(t, got.statusOnly)
	_, st = svc.parseDataChangeFilter(value(f.node("rw_int32")), &ua.ExtensionObject{Value: ua.EventFilter{}})
	require.Equal(t, ua.StatusBadFilterNotAllowed, st)
	_, st = svc.parseDataChangeFilter(value(f.node("rw_int32")), &ua.ExtensionObject{Value: ua.AggregateFilter{}})
	require.Equal(t, ua.StatusBadMonitoredItemFilterUnsupported, st)

	cases := []struct {
		name string
		node *Node
		want ua.StatusCode
	}{
		{"DataType NodeId Double", typed("dt_double", ua.NewNumericNodeID(0, id.Double), 1.0), ua.StatusOK},
		{"DataType ExpandedNodeId Int16", typed("dt_int16", ua.NewNumericExpandedNodeID(0, id.Int16), int16(1)), ua.StatusOK},
		{"abstract Number", typed("dt_number", ua.NewNumericNodeID(0, id.Number), 1.0), ua.StatusOK},
		{"subtype of Double", typed("dt_duration", ua.NewNumericNodeID(0, id.Duration), 1.0), ua.StatusOK},
		{"DataType String", typed("dt_string", ua.NewNumericNodeID(0, id.String), "x"), ua.StatusBadFilterNotAllowed},
		{"BaseDataType with numeric value", typed("dt_base_num", ua.NewNumericNodeID(0, id.BaseDataType), int32(1)), ua.StatusOK},
		{"BaseDataType with text value", typed("dt_base_str", ua.NewNumericNodeID(0, id.BaseDataType), "x"), ua.StatusBadFilterNotAllowed},
		{"no DataType, numeric value", typed("dt_none_num", nil, uint16(1)), ua.StatusOK},
		{"no DataType, text value", typed("dt_none_str", nil, "x"), ua.StatusBadFilterNotAllowed},
	}
	for _, tc := range cases {
		_, st := svc.parseDataChangeFilter(value(tc.node.ID()), abs)
		require.Equal(t, tc.want, st, tc.name)
	}
	_, st = svc.parseDataChangeFilter(value(ua.NewStringNodeID(77, "nowhere")), abs)
	require.Equal(t, ua.StatusBadFilterNotAllowed, st, "unknown namespace")

	// EURange in its different shapes.
	prop := func(owner *Node, name string, v any) {
		p := NewNode(f.node(owner.ID().StringID()+"."+name), map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:   DataValueFromValue(uint32(ua.NodeClassVariable)),
			ua.AttributeIDBrowseName:  DataValueFromValue(attrs.BrowseName(name)),
			ua.AttributeIDDisplayName: DataValueFromValue(attrs.DisplayName(name, name)),
		}, nil, func() *ua.DataValue {
			if v == nil {
				return &ua.DataValue{}
			}
			return &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)}
		})
		f.ns.AddNode(p)
		owner.AddRef(p, id.HasProperty, true)
	}
	analog := func(name string, eu any) *Node {
		n := typed(name, ua.NewNumericNodeID(0, id.Double), 1.0)
		prop(n, "EngineeringUnits", "ignored")
		if eu != nil {
			prop(n, "EURange", eu)
		}
		return n
	}
	euCases := []struct {
		name     string
		node     *Node
		want     ua.StatusCode
		deadband float64
	}{
		{"pointer in ExtensionObject", analog("eu_ptr", ua.NewExtensionObject(&ua.Range{Low: 0, High: 10})), ua.StatusOK, 5},
		{"value in ExtensionObject", analog("eu_val", &ua.ExtensionObject{Value: ua.Range{Low: -10, High: 10}}), ua.StatusOK, 10},
		{"inverted range", analog("eu_inv", ua.NewExtensionObject(&ua.Range{Low: 10, High: 0})), ua.StatusOK, 5},
		{"not a Range", analog("eu_str", "0..10"), ua.StatusBadMonitoredItemFilterUnsupported, 0},
		{"wrong structure", analog("eu_other", ua.NewExtensionObject(&ua.EUInformation{})), ua.StatusBadMonitoredItemFilterUnsupported, 0},
		{"no property", analog("eu_none", nil), ua.StatusBadMonitoredItemFilterUnsupported, 0},
	}
	for _, tc := range euCases {
		got, st := svc.parseDataChangeFilter(value(tc.node.ID()), pct)
		require.Equal(t, tc.want, st, tc.name)
		if st == ua.StatusOK {
			require.True(t, got.hasDeadband, tc.name)
			require.InDelta(t, tc.deadband, got.deadband, 1e-9, tc.name)
		}
	}
	// A property whose value cannot be read.
	empty := analog("eu_empty", nil)
	prop(empty, "EURange", nil)
	_, st = svc.parseDataChangeFilter(value(empty.ID()), pct)
	require.Equal(t, ua.StatusBadMonitoredItemFilterUnsupported, st)
	require.Nil(t, svc.euRange(ua.NewStringNodeID(77, "nowhere")))
}
