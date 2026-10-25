// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
)

// Alarm metrics (Part 9 1.05, AlarmMetricsType).
//
// An AlarmMetrics object counts the activations of the alarms of the server
// or of one alarm group since its StartTime: AlarmCount, the longest time an
// alarm was active (MaximumActiveState) and unacknowledged
// (MaximumUnAck), the most re-alarms of one activation
// (MaximumReAlarmCount) and the alarm rates (AlarmRateVariableType, alarms
// per Rate minutes): the rate of the last period (CurrentAlarmRate), the
// highest one (MaximumAlarmRate) and the average since StartTime
// (AverageAlarmRate). An activation counts when it is reported (after
// OnDelay); MaximumActiveState and MaximumUnAck count an alarm when it
// returns to normal and when it is acknowledged. The Reset method (and
// [AlarmMetrics.Reset]) starts the counting anew.

// AlarmMetricsConfig describes an AlarmMetrics object for
// [Server.AddAlarmMetrics].
type AlarmMetricsConfig struct {
	// NodeID is the NodeId of the object. Default: a new numeric NodeId in
	// Namespace.
	NodeID *ua.NodeID
	// Namespace receives the nodes. Default: the namespace of NodeID.
	Namespace *NodeNameSpace
	// Name is the BrowseName. Default: "AlarmMetrics".
	Name string
	// Parent has the object as a component. Default: the Server object.
	Parent *ua.NodeID
	// Group restricts the metrics to the alarms of an alarm group
	// ([Server.AddAlarmGroup]). Default: all alarms of the server.
	Group *ua.NodeID
	// RateMinutes is the period of the alarm rates in minutes (the Rate
	// Property). Default: 1.
	RateMinutes uint16
}

// AlarmMetricsValues are the values of an AlarmMetrics object.
type AlarmMetricsValues struct {
	AlarmCount          uint32
	StartTime           time.Time
	MaximumActiveState  time.Duration
	MaximumUnAck        time.Duration
	MaximumReAlarmCount uint32
	// The rates are alarms per RateMinutes.
	CurrentAlarmRate, MaximumAlarmRate, AverageAlarmRate float64
}

// AlarmMetrics is an AlarmMetricsType object.
type AlarmMetrics struct {
	srv    *Server
	id     *ua.NodeID
	ns     *NodeNameSpace
	parent *Node
	group  *AlarmGroup
	period time.Duration
	rate   uint16
	nodes  []*ua.NodeID
	vars   []*ua.NodeID

	mu         sync.Mutex
	v          AlarmMetricsValues
	recent     []time.Time // activations within the last period, oldest first
	maxRateCnt int
}

// metricsState are the AlarmMetrics of a server. mu is taken with a
// condition lock held, and takes the group and metrics locks after it.
type metricsState struct {
	mu   sync.RWMutex
	byID map[string]*AlarmMetrics
	list []*AlarmMetrics
}

// of returns the metrics that count the alarm c.
func (ms *metricsState) of(c *Condition) []*AlarmMetrics {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	var out []*AlarmMetrics
	for _, m := range ms.list {
		if m.group == nil || m.group.hasMember(c) {
			out = append(out, m)
		}
	}
	return out
}

// AddAlarmMetrics creates an AlarmMetricsType object.
func (s *Server) AddAlarmMetrics(cfg AlarmMetricsConfig) (*AlarmMetrics, error) {
	ns := cfg.Namespace
	if ns == nil && cfg.NodeID != nil && cfg.NodeID.Namespace() != 0 {
		if x, err := s.Namespace(int(cfg.NodeID.Namespace())); err == nil {
			ns, _ = x.(*NodeNameSpace)
		}
	}
	if ns == nil {
		return nil, errors.New("server: AddAlarmMetrics: Namespace is required")
	}
	name := cfg.Name
	if name == "" {
		name = "AlarmMetrics"
	}
	rate := cfg.RateMinutes
	if rate == 0 {
		rate = 1
	}
	var group *AlarmGroup
	if cfg.Group != nil {
		g, ok := s.AlarmGroup(cfg.Group)
		if !ok {
			return nil, fmt.Errorf("server: AddAlarmMetrics: %v is not an alarm group", cfg.Group)
		}
		group = g
	}
	parentID := cfg.Parent
	if parentID == nil {
		parentID = ua.NewNumericNodeID(0, id.Server)
	}
	parent := s.Node(parentID)
	if parent == nil {
		return nil, fmt.Errorf("server: AddAlarmMetrics: parent %v not found", parentID)
	}
	if parentID.Namespace() == 0 {
		parent = s.ownNode(parentID.IntID())
	}
	mid := cfg.NodeID
	if mid == nil {
		mid = ua.NewNumericNodeID(ns.ID(), ns.GetNextNodeID())
	}
	if s.Node(mid) != nil {
		return nil, fmt.Errorf("server: AddAlarmMetrics: node %v exists", mid)
	}
	m := &AlarmMetrics{srv: s, id: mid, ns: ns, parent: parent, group: group,
		period: time.Duration(rate) * time.Minute, rate: rate}
	m.v.StartTime = s.now()

	s.alarms.metrics.mu.Lock()
	if _, dup := s.alarms.metrics.byID[mid.String()]; dup {
		s.alarms.metrics.mu.Unlock()
		return nil, fmt.Errorf("server: AddAlarmMetrics: %v exists", mid)
	}
	s.alarms.metrics.byID[mid.String()] = m
	s.alarms.metrics.list = append(s.alarms.metrics.list, m)
	s.alarms.metrics.mu.Unlock()

	m.build(name)
	reset := ua.NewNumericNodeID(0, id.AlarmMetricsTypeReset)
	if root := s.Node(mid); root != nil {
		s.addMethodRef(root, id.AlarmMetricsTypeReset)
	}
	s.RegisterMethod(mid, reset, m.resetMethod)
	return m, nil
}

// AlarmMetrics returns the AlarmMetrics object with the given NodeId.
func (s *Server) AlarmMetrics(metricsID *ua.NodeID) (*AlarmMetrics, bool) {
	if metricsID == nil {
		return nil, false
	}
	s.alarms.metrics.mu.RLock()
	defer s.alarms.metrics.mu.RUnlock()
	m, ok := s.alarms.metrics.byID[metricsID.String()]
	return m, ok
}

// RemoveAlarmMetrics deletes an AlarmMetrics object.
func (s *Server) RemoveAlarmMetrics(metricsID *ua.NodeID) error {
	m, ok := s.AlarmMetrics(metricsID)
	if !ok {
		return fmt.Errorf("server: alarm metrics %v not found", metricsID)
	}
	s.alarms.metrics.mu.Lock()
	delete(s.alarms.metrics.byID, metricsID.String())
	if i := slices.Index(s.alarms.metrics.list, m); i >= 0 {
		s.alarms.metrics.list = slices.Delete(s.alarms.metrics.list, i, i+1)
	}
	s.alarms.metrics.mu.Unlock()
	s.unregisterMethod(m.id, ua.NewNumericNodeID(0, id.AlarmMetricsTypeReset))
	m.parent.RemoveRef(ua.NewExpandedNodeID(m.id, "", 0), ua.NewNumericNodeID(0, id.HasComponent), true)
	for _, n := range slices.Backward(m.nodes) {
		_ = m.ns.DeleteNode(n)
	}
	return nil
}

// NodeID returns the NodeId of the object.
func (m *AlarmMetrics) NodeID() *ua.NodeID { return m.id }

// Values returns the current values.
func (m *AlarmMetrics) Values() AlarmMetricsValues {
	now := m.srv.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked(now)
	v := m.v
	v.CurrentAlarmRate = float64(len(m.recent))
	v.MaximumAlarmRate = float64(m.maxRateCnt)
	periods := float64(now.Sub(v.StartTime)) / float64(m.period)
	if periods < 1 {
		periods = 1
	}
	v.AverageAlarmRate = float64(v.AlarmCount) / periods
	return v
}

// Reset sets the counters to zero and StartTime to now.
func (m *AlarmMetrics) Reset() {
	now := m.srv.now()
	m.mu.Lock()
	m.v = AlarmMetricsValues{StartTime: now}
	m.recent, m.maxRateCnt = nil, 0
	m.mu.Unlock()
	m.notify()
}

// resetMethod implements the Reset method. With auditing on it reports an
// AuditUpdateMethodEventType event through the Server object.
func (m *AlarmMetrics) resetMethod(ctx context.Context, _, methodID *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	sc := ua.StatusOK
	if len(args) != 0 {
		sc = ua.StatusBadTooManyArguments
	} else {
		m.Reset()
	}
	if m.srv.auditing.Load() {
		name := ""
		if n := m.srv.Node(m.id); n != nil {
			name = n.BrowseName().Name
		}
		ev := m.srv.methodAuditEvent(ctx, id.AuditUpdateMethodEventType, methodID, m.id, name, args, nil, sc)
		m.srv.emitEvent(ua.NewNumericNodeID(0, id.Server), ev, true)
	}
	return nil, sc
}

func (m *AlarmMetrics) pruneLocked(now time.Time) {
	i := 0
	for i < len(m.recent) && now.Sub(m.recent[i]) >= m.period {
		i++
	}
	m.recent = m.recent[i:]
}

func (m *AlarmMetrics) activated(now time.Time) {
	m.mu.Lock()
	m.v.AlarmCount++
	m.pruneLocked(now)
	m.recent = append(m.recent, now)
	m.maxRateCnt = max(m.maxRateCnt, len(m.recent))
	m.mu.Unlock()
}

func (m *AlarmMetrics) deactivated(active time.Duration) {
	m.mu.Lock()
	m.v.MaximumActiveState = max(m.v.MaximumActiveState, active)
	m.mu.Unlock()
}

func (m *AlarmMetrics) acknowledged(unacked time.Duration) {
	m.mu.Lock()
	m.v.MaximumUnAck = max(m.v.MaximumUnAck, unacked)
	m.mu.Unlock()
}

func (m *AlarmMetrics) reAlarmed(count int16) {
	m.mu.Lock()
	m.v.MaximumReAlarmCount = max(m.v.MaximumReAlarmCount, uint32(max(count, 0)))
	m.mu.Unlock()
}

// notify notifies the monitored items of the variables. The counters
// change with a condition lock held; the condition notifies them after it
// releases it (Condition.notifyChanges).
func (m *AlarmMetrics) notify() {
	for _, v := range m.vars {
		m.srv.ChangeNotification(v)
	}
}

// build creates the nodes of the object.
func (m *AlarmMetrics) build(name string) {
	s := m.srv
	root := NewNode(m.id, Attributes{
		ua.AttributeIDNodeClass:     DataValueFromValue(uint32(ua.NodeClassObject)),
		ua.AttributeIDBrowseName:    DataValueFromValue(&ua.QualifiedName{NamespaceIndex: m.ns.ID(), Name: name}),
		ua.AttributeIDDisplayName:   DataValueFromValue(attrs.DisplayName(name, "")),
		ua.AttributeIDDescription:   DataValueFromValue(&ua.LocalizedText{}),
		ua.AttributeIDEventNotifier: DataValueFromValue(byte(0)),
	}, nil, nil)
	m.ns.AddNode(root)
	if tn := s.Node(ua.NewNumericNodeID(0, id.AlarmMetricsType)); tn != nil {
		root.AddRef(tn, RefType(id.HasTypeDefinition), true)
	}
	linkChild(m.parent, root, id.HasComponent)
	m.nodes = append(m.nodes, m.id)

	add := func(parent *Node, name string, ref, typeDef, dataType uint32, get func(v AlarmMetricsValues) any) *Node {
		nid := ua.NewNumericNodeID(m.ns.ID(), m.ns.GetNextNodeID())
		n := NewNode(nid, Attributes{
			ua.AttributeIDNodeClass:       DataValueFromValue(uint32(ua.NodeClassVariable)),
			ua.AttributeIDBrowseName:      DataValueFromValue(&ua.QualifiedName{Name: name}),
			ua.AttributeIDDisplayName:     DataValueFromValue(attrs.DisplayName(name, "")),
			ua.AttributeIDDescription:     DataValueFromValue(&ua.LocalizedText{}),
			ua.AttributeIDDataType:        DataValueFromValue(ua.NewNumericExpandedNodeID(0, dataType)),
			ua.AttributeIDValueRank:       DataValueFromValue(int32(-1)),
			ua.AttributeIDAccessLevel:     DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead)),
			ua.AttributeIDUserAccessLevel: DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead)),
		}, nil, func() *ua.DataValue { return DataValueFromValue(get(m.Values())) })
		m.ns.AddNode(n)
		if tn := s.Node(ua.NewNumericNodeID(0, typeDef)); tn != nil {
			n.AddRef(tn, RefType(id.HasTypeDefinition), true)
		}
		linkChild(parent, n, ref)
		m.nodes = append(m.nodes, nid)
		m.vars = append(m.vars, nid)
		return n
	}
	ms := func(d time.Duration) any { return float64(d) / float64(time.Millisecond) }
	add(root, "AlarmCount", id.HasComponent, id.BaseDataVariableType, id.UInt32, func(v AlarmMetricsValues) any { return v.AlarmCount })
	add(root, "StartTime", id.HasComponent, id.BaseDataVariableType, id.UtcTime, func(v AlarmMetricsValues) any { return v.StartTime })
	add(root, "MaximumActiveState", id.HasComponent, id.BaseDataVariableType, id.Duration, func(v AlarmMetricsValues) any { return ms(v.MaximumActiveState) })
	add(root, "MaximumUnAck", id.HasComponent, id.BaseDataVariableType, id.Duration, func(v AlarmMetricsValues) any { return ms(v.MaximumUnAck) })
	for _, r := range []struct {
		name string
		get  func(v AlarmMetricsValues) any
	}{
		{"CurrentAlarmRate", func(v AlarmMetricsValues) any { return v.CurrentAlarmRate }},
		{"MaximumAlarmRate", func(v AlarmMetricsValues) any { return v.MaximumAlarmRate }},
		{"AverageAlarmRate", func(v AlarmMetricsValues) any { return v.AverageAlarmRate }},
	} {
		n := add(root, r.name, id.HasComponent, id.AlarmRateVariableType, id.Double, r.get)
		rate := m.rate
		add(n, "Rate", id.HasProperty, id.PropertyType, id.UInt16, func(AlarmMetricsValues) any { return rate })
	}
	add(root, "MaximumReAlarmCount", id.HasComponent, id.BaseDataVariableType, id.UInt32, func(v AlarmMetricsValues) any { return v.MaximumReAlarmCount })
}
