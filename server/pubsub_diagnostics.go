// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"strings"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
)

// The PubSub diagnostics objects (Part 14 §9.1.11): a Diagnostics object of
// type PubSubDiagnosticsRootType on PublishSubscribe (i=17409, from the
// standard nodeset) and one of the PubSubDiagnostics*Type subtypes on every
// connection, group, writer and reader, created and deleted with them. The
// values are read from pubsub.PubSub.Diagnostics on every read; nodes of
// counters and LiveValues above the DiagnosticsLevel of their object are
// kept and read Bad_OutOfService (§9.1.11.4).

// diagTypeOf returns the type of the diagnostics object of a component
// kind.
func diagTypeOf(k pubsub.ComponentKind) uint32 {
	switch k {
	case pubsub.KindConnection:
		return id.PubSubDiagnosticsConnectionType
	case pubsub.KindWriterGroup:
		return id.PubSubDiagnosticsWriterGroupType
	case pubsub.KindReaderGroup:
		return id.PubSubDiagnosticsReaderGroupType
	case pubsub.KindDataSetWriter:
		return id.PubSubDiagnosticsDataSetWriterType
	case pubsub.KindDataSetReader:
		return id.PubSubDiagnosticsDataSetReaderType
	case pubsub.KindPubSub, pubsub.KindPublishedDataSet:
	}
	return id.PubSubDiagnosticsRootType
}

// liveValueDef is a LiveValue of a diagnostics type (Part 14 Tables 316,
// 318, 322, 326, 329, 331).
type liveValueDef struct {
	name  string
	dt    uint32
	level ua.DiagnosticsLevel
	kinds []pubsub.ComponentKind
	get   func(*pubsub.DiagnosticsLiveValues) any
}

var liveValueDefs = []liveValueDef{
	{"ConfiguredDataSetWriters", id.UInt16, ua.DiagnosticsLevelBasic, []pubsub.ComponentKind{pubsub.KindPubSub, pubsub.KindWriterGroup},
		func(v *pubsub.DiagnosticsLiveValues) any { return v.ConfiguredDataSetWriters }},
	{"ConfiguredDataSetReaders", id.UInt16, ua.DiagnosticsLevelBasic, []pubsub.ComponentKind{pubsub.KindPubSub, pubsub.KindReaderGroup},
		func(v *pubsub.DiagnosticsLiveValues) any { return v.ConfiguredDataSetReaders }},
	{"OperationalDataSetWriters", id.UInt16, ua.DiagnosticsLevelBasic, []pubsub.ComponentKind{pubsub.KindPubSub, pubsub.KindWriterGroup},
		func(v *pubsub.DiagnosticsLiveValues) any { return v.OperationalDataSetWriters }},
	{"OperationalDataSetReaders", id.UInt16, ua.DiagnosticsLevelBasic, []pubsub.ComponentKind{pubsub.KindPubSub, pubsub.KindReaderGroup},
		func(v *pubsub.DiagnosticsLiveValues) any { return v.OperationalDataSetReaders }},
	{"ResolvedAddress", id.String, ua.DiagnosticsLevelBasic, []pubsub.ComponentKind{pubsub.KindConnection},
		func(v *pubsub.DiagnosticsLiveValues) any { return v.ResolvedAddress }},
	{"MessageSequenceNumber", id.UInt16, ua.DiagnosticsLevelInfo, []pubsub.ComponentKind{pubsub.KindDataSetWriter, pubsub.KindDataSetReader},
		func(v *pubsub.DiagnosticsLiveValues) any { return v.MessageSequenceNumber }},
	{"StatusCode", id.StatusCode, ua.DiagnosticsLevelInfo, []pubsub.ComponentKind{pubsub.KindDataSetWriter, pubsub.KindDataSetReader},
		func(v *pubsub.DiagnosticsLiveValues) any { return v.StatusCode }},
	{"MajorVersion", id.UInt32, ua.DiagnosticsLevelInfo, []pubsub.ComponentKind{pubsub.KindDataSetWriter, pubsub.KindDataSetReader},
		func(v *pubsub.DiagnosticsLiveValues) any { return v.MajorVersion }},
	{"MinorVersion", id.UInt32, ua.DiagnosticsLevelInfo, []pubsub.ComponentKind{pubsub.KindDataSetWriter, pubsub.KindDataSetReader},
		func(v *pubsub.DiagnosticsLiveValues) any { return v.MinorVersion }},
	{"SecurityTokenID", id.UInt32, ua.DiagnosticsLevelInfo, []pubsub.ComponentKind{pubsub.KindWriterGroup, pubsub.KindDataSetReader},
		func(v *pubsub.DiagnosticsLiveValues) any { return v.SecurityTokenID }},
	{"TimeToNextTokenID", id.Duration, ua.DiagnosticsLevelInfo, []pubsub.ComponentKind{pubsub.KindWriterGroup, pubsub.KindDataSetReader},
		func(v *pubsub.DiagnosticsLiveValues) any {
			return float64(v.TimeToNextTokenID) / float64(time.Millisecond)
		}},
}

func liveValueByName(name string) (liveValueDef, bool) {
	for _, d := range liveValueDefs {
		if d.name == name {
			return d, true
		}
	}
	return liveValueDef{}, false
}

func counterByName(name string) (pubsub.DiagnosticsCounterID, bool) {
	for _, k := range []pubsub.ComponentKind{pubsub.KindDataSetReader, pubsub.KindDataSetWriter, pubsub.KindReaderGroup, pubsub.KindWriterGroup} {
		for _, c := range pubsub.DiagnosticsCountersOf(k) {
			if c.String() == name {
				return c, true
			}
		}
	}
	return 0, false
}

func outOfService() *ua.DataValue {
	return &ua.DataValue{EncodingMask: ua.DataValueStatusCode, Status: ua.StatusBadOutOfService}
}

// diagValue returns the value of the node at path below the diagnostics
// object of a component: "DiagnosticsLevel", "TotalError/Active",
// "Counters/StateError/TimeFirstChange", "LiveValues/ResolvedAddress", ...
func (m *pubsubModel) diagValue(cid pubsub.ComponentID, path string) (ValueFunc, bool) {
	read := func(f func(d *pubsub.Diagnostics) *ua.DataValue) ValueFunc {
		return func() *ua.DataValue {
			d, err := m.rt.Diagnostics(cid)
			if err != nil {
				return badValue(ua.StatusBadNodeIDUnknown)
			}
			return f(&d)
		}
	}
	timeValue := func(t time.Time) *ua.DataValue {
		if t.IsZero() {
			return &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(time.Time{})}
		}
		return DataValueFromValue(t)
	}
	// A total is always active and at level Basic.
	total := func(class ua.PubSubDiagnosticsCounterClassification, prop string) (ValueFunc, bool) {
		pick := func(d *pubsub.Diagnostics) (uint32, time.Time) {
			if class == ua.PubSubDiagnosticsCounterClassificationError {
				return d.TotalError, d.TotalErrorFirstChange
			}
			return d.TotalInformation, d.TotalInformationFirstChange
		}
		switch prop {
		case "":
			return read(func(d *pubsub.Diagnostics) *ua.DataValue { v, _ := pick(d); return DataValueFromValue(v) }), true
		case "Active":
			return static(true), true
		case "Classification":
			return static(int32(class)), true
		case "DiagnosticsLevel":
			return static(int32(ua.DiagnosticsLevelBasic)), true
		case "TimeFirstChange":
			return read(func(d *pubsub.Diagnostics) *ua.DataValue { _, t := pick(d); return timeValue(t) }), true
		}
		return nil, false
	}
	parts := strings.Split(path, "/")
	prop := ""
	switch parts[0] {
	case "DiagnosticsLevel":
		return read(func(d *pubsub.Diagnostics) *ua.DataValue { return DataValueFromValue(int32(d.Level)) }), len(parts) == 1
	case "SubError":
		return read(func(d *pubsub.Diagnostics) *ua.DataValue { return DataValueFromValue(d.SubError) }), len(parts) == 1
	case "TotalInformation", "TotalError":
		if len(parts) > 2 {
			return nil, false
		}
		if len(parts) == 2 {
			prop = parts[1]
		}
		class := ua.PubSubDiagnosticsCounterClassificationInformation
		if parts[0] == "TotalError" {
			class = ua.PubSubDiagnosticsCounterClassificationError
		}
		return total(class, prop)
	case "Counters":
		if len(parts) < 2 || len(parts) > 3 {
			return nil, false
		}
		cnt, ok := counterByName(parts[1])
		if !ok {
			return nil, false
		}
		if len(parts) == 3 {
			prop = parts[2]
		}
		counter := func(f func(c pubsub.DiagnosticsCounter) *ua.DataValue) ValueFunc {
			return read(func(d *pubsub.Diagnostics) *ua.DataValue {
				c, ok := d.Counter(cnt)
				if !ok {
					return badValue(ua.StatusBadNodeIDUnknown)
				}
				return f(c)
			})
		}
		switch prop {
		case "":
			return counter(func(c pubsub.DiagnosticsCounter) *ua.DataValue {
				if !c.Active {
					return outOfService()
				}
				return DataValueFromValue(c.Value)
			}), true
		case "Active":
			return counter(func(c pubsub.DiagnosticsCounter) *ua.DataValue { return DataValueFromValue(c.Active) }), true
		case "Classification":
			return static(int32(cnt.Classification())), true
		case "DiagnosticsLevel":
			return static(int32(cnt.Level())), true
		case "TimeFirstChange":
			return counter(func(c pubsub.DiagnosticsCounter) *ua.DataValue { return timeValue(c.TimeFirstChange) }), true
		}
	case "LiveValues":
		if len(parts) < 2 || len(parts) > 3 {
			return nil, false
		}
		lv, ok := liveValueByName(parts[1])
		if !ok {
			return nil, false
		}
		if len(parts) == 3 {
			if parts[2] != "DiagnosticsLevel" {
				return nil, false
			}
			return static(int32(lv.level)), true
		}
		return read(func(d *pubsub.Diagnostics) *ua.DataValue {
			if lv.level > d.Level {
				return outOfService()
			}
			return DataValueFromValue(lv.get(&d.LiveValues))
		}), true
	}
	return nil, false
}

// resetMethod is the Reset method of a diagnostics object (§9.1.11.3).
func (m *pubsubModel) resetMethod(cid pubsub.ComponentID) MethodHandler {
	return m.method("Reset", func(context.Context, *ua.NodeID, []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		return nil, statusOf(m.rt.ResetDiagnostics(cid))
	})
}

// counterVar creates a variable of type PubSubDiagnosticsCounterType with
// its properties.
func (m *pubsubModel) counterVar(c *psComp, parent *Node, name, path string) {
	val, _ := m.diagValue(c.id, path)
	n := m.variableT(c, parent, id.HasComponent, 0, name, id.UInt32, -1, id.PubSubDiagnosticsCounterType, val)
	for _, p := range []struct {
		name string
		dt   uint32
	}{{"Active", id.Boolean}, {"Classification", id.PubSubDiagnosticsCounterClassification}, {"DiagnosticsLevel", id.DiagnosticsLevel}, {"TimeFirstChange", id.DateTime}} {
		pv, _ := m.diagValue(c.id, path+"/"+p.name)
		m.variable(c, n, id.HasProperty, p.name, p.dt, -1, pv)
	}
}

// diagnostics creates the diagnostics object of a component.
func (m *pubsubModel) diagnostics(c *psComp) {
	d := m.object(c, c.obj, id.HasComponent, "Diagnostics", 0, diagTypeOf(c.kind))
	val, _ := m.diagValue(c.id, "DiagnosticsLevel")
	m.variable(c, d, id.HasComponent, "DiagnosticsLevel", id.DiagnosticsLevel, -1, val)
	m.counterVar(c, d, "TotalInformation", "TotalInformation")
	m.counterVar(c, d, "TotalError", "TotalError")
	m.s.addMethodRef(d, id.PubSubDiagnosticsTypeReset)
	m.register(c, d.ID(), id.PubSubDiagnosticsTypeReset, m.resetMethod(c.id))
	val, _ = m.diagValue(c.id, "SubError")
	m.variable(c, d, id.HasComponent, "SubError", id.Boolean, -1, val)
	ctrs := m.object(c, d, id.HasComponent, "Counters", 0, id.BaseObjectType)
	for _, cnt := range pubsub.DiagnosticsCountersOf(c.kind) {
		m.counterVar(c, ctrs, cnt.String(), "Counters/"+cnt.String())
	}
	lvs := m.object(c, d, id.HasComponent, "LiveValues", 0, id.BaseObjectType)
	for _, lv := range liveValueDefs {
		if !kindIn(c.kind, lv.kinds) {
			continue
		}
		val, _ := m.diagValue(c.id, "LiveValues/"+lv.name)
		n := m.variable(c, lvs, id.HasComponent, lv.name, lv.dt, -1, val)
		m.prop(c, n, "DiagnosticsLevel", id.DiagnosticsLevel, -1, int32(lv.level))
	}
}

func kindIn(k pubsub.ComponentKind, ks []pubsub.ComponentKind) bool {
	for _, x := range ks {
		if x == k {
			return true
		}
	}
	return false
}

// bindRootDiagnostics gives the PublishSubscribe.Diagnostics object of the
// standard nodeset (i=17409) its values and its Reset method, and adds the
// optional TimeFirstChange properties of its counters, which the nodeset
// leaves out, with their standard NodeIds.
func (m *pubsubModel) bindRootDiagnostics() {
	d := m.s.ownNode(id.PublishSubscribeDiagnostics)
	if d == nil {
		return
	}
	m.s.RegisterMethod(d.ID(), ua.NewNumericNodeID(0, id.PublishSubscribeDiagnosticsReset), m.resetMethod(pubsub.Root))
	m.bindDiagChildren(d, "", "PublishSubscribe_Diagnostics")
}

func (m *pubsubModel) bindDiagChildren(parent *Node, path, name string) {
	hasTFC := false
	for _, r := range parent.refsSnapshot() {
		if r == nil || !r.IsForward || r.ReferenceTypeID == nil || r.NodeID == nil || r.NodeID.NodeID.Namespace() != 0 || r.BrowseName == nil {
			continue
		}
		if rt := r.ReferenceTypeID.IntID(); rt != id.HasComponent && rt != id.HasProperty {
			continue
		}
		child := m.s.Node(r.NodeID.NodeID)
		if child == nil {
			continue
		}
		cname := child.BrowseName().Name
		if cname == "TimeFirstChange" {
			hasTFC = true
		}
		cpath := cname
		if path != "" {
			cpath = path + "/" + cname
		}
		if child.NodeClass() == ua.NodeClassVariable {
			if val, ok := m.diagValue(pubsub.Root, cpath); ok {
				n := m.s.ownNode(child.ID().IntID())
				n.mu.Lock()
				n.val = val
				n.mu.Unlock()
				child = n
			}
		}
		if child.NodeClass() == ua.NodeClassVariable || child.NodeClass() == ua.NodeClassObject {
			m.bindDiagChildren(child, cpath, name+"_"+cname)
		}
	}
	// Counters (the totals and those below Counters) without their
	// optional TimeFirstChange.
	isCounter := path == "TotalInformation" || path == "TotalError" || (strings.HasPrefix(path, "Counters/") && strings.Count(path, "/") == 1)
	if !isCounter || hasTFC {
		return
	}
	nid, ok := id.NodeIDByName(name + "_TimeFirstChange")
	if !ok {
		return
	}
	val, _ := m.diagValue(pubsub.Root, path+"/TimeFirstChange")
	n := NewNode(ua.NewNumericNodeID(0, nid), Attributes{
		ua.AttributeIDNodeClass:       DataValueFromValue(uint32(ua.NodeClassVariable)),
		ua.AttributeIDBrowseName:      DataValueFromValue(&ua.QualifiedName{Name: "TimeFirstChange"}),
		ua.AttributeIDDisplayName:     DataValueFromValue(attrs.DisplayName("TimeFirstChange", "")),
		ua.AttributeIDDescription:     DataValueFromValue(&ua.LocalizedText{}),
		ua.AttributeIDDataType:        DataValueFromValue(ua.NewNumericExpandedNodeID(0, id.DateTime)),
		ua.AttributeIDValueRank:       DataValueFromValue(int32(-1)),
		ua.AttributeIDAccessLevel:     DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead)),
		ua.AttributeIDUserAccessLevel: DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead)),
	}, nil, val)
	m.s.namespaces[0].AddNode(n)
	m.typeDef(n, id.PropertyType)
	linkChild(parent, n, id.HasProperty)
}
