// SPDX-License-Identifier: MIT

package server

import (
	"strings"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
)

// condField is one component of a condition instance: an object or a
// variable at a BrowsePath below the condition. The same table builds the
// nodes of the instance and the fields of its events, so that a Read of a
// variable and the event field of the same path always agree.
type condField struct {
	path      string // BrowseNames joined with "/", e.g. "AckedState/Id"
	refType   uint32 // reference from the parent
	object    bool   // an Object (ShelvingState, LimitState), else a Variable
	typeDef   uint32
	dataType  uint32
	valueRank int32
	// value returns the value of a variable; Condition.mu is held.
	value func(c *Condition) any
	// always marks the fields that stay valid while the condition is
	// disabled (Part 9 §5.5.2); the others read Bad_ConditionDisabled.
	always bool
}

func nullNodeID(n *ua.NodeID) *ua.NodeID {
	if n == nil {
		return ua.NewTwoByteNodeID(0)
	}
	return n
}

func stateText(on bool, t, f string) *ua.LocalizedText {
	if on {
		return ua.NewLocalizedTextWithLocale(t, "en")
	}
	return ua.NewLocalizedTextWithLocale(f, "en")
}

// twoState adds a TwoStateVariable with its Id and TransitionTime
// (Part 9 §5.2).
func twoState(fs []condField, name, t, f string, get func(c *Condition) (bool, time.Time), always bool) []condField {
	return append(fs,
		condField{path: name, refType: id.HasComponent, typeDef: id.TwoStateVariableType, dataType: id.LocalizedText, valueRank: -1, always: always,
			value: func(c *Condition) any { on, _ := get(c); return stateText(on, t, f) }},
		condField{path: name + "/Id", refType: id.HasProperty, typeDef: id.PropertyType, dataType: id.Boolean, valueRank: -1, always: always,
			value: func(c *Condition) any { on, _ := get(c); return on }},
		condField{path: name + "/TransitionTime", refType: id.HasProperty, typeDef: id.PropertyType, dataType: id.UtcTime, valueRank: -1, always: always,
			value: func(c *Condition) any { _, at := get(c); return at }},
	)
}

func prop(path string, dataType uint32, always bool, v func(c *Condition) any) condField {
	return condField{path: path, refType: id.HasProperty, typeDef: id.PropertyType, dataType: dataType, valueRank: -1, value: v, always: always}
}

// conditionVariable adds a ConditionVariable with its SourceTimestamp
// (Part 9 §5.3).
func conditionVariable(fs []condField, name string, dataType uint32, v func(c *Condition) any, at func(c *Condition) time.Time) []condField {
	return append(fs,
		condField{path: name, refType: id.HasComponent, typeDef: id.ConditionVariableType, dataType: dataType, valueRank: -1, value: v},
		prop(name+"/SourceTimestamp", id.UtcTime, false, func(c *Condition) any { return at(c) }))
}

// fields returns the components of the condition for its type and options.
func (c *Condition) fields() []condField {
	fs := []condField{
		// BaseEventType (Part 5 §6.4.2)
		prop("EventId", id.ByteString, true, func(c *Condition) any { return c.st.eventID }),
		prop("EventType", id.NodeID, true, func(c *Condition) any { return c.typeID }),
		prop("SourceNode", id.NodeID, true, func(c *Condition) any { return c.cfg.Source }),
		prop("SourceName", id.String, true, func(c *Condition) any { return c.sourceName }),
		prop("Time", id.UtcTime, true, func(c *Condition) any { return c.st.time }),
		prop("ReceiveTime", id.UtcTime, true, func(c *Condition) any { return c.st.receiveTime }),
		prop("Message", id.LocalizedText, true, func(c *Condition) any { return c.st.message }),
		prop("Severity", id.UInt16, true, func(c *Condition) any { return c.st.severity }),
		// ConditionType (Part 9 §5.5.2)
		prop("ConditionClassId", id.NodeID, true, func(c *Condition) any { return c.classID }),
		prop("ConditionClassName", id.LocalizedText, true, func(c *Condition) any { return c.className }),
		prop("ConditionName", id.String, true, func(c *Condition) any { return c.cfg.Name }),
		prop("BranchId", id.NodeID, true, func(*Condition) any { return nullNodeID(nil) }),
		prop("Retain", id.Boolean, true, func(c *Condition) any { return c.retainLocked() }),
	}
	fs = twoState(fs, "EnabledState", "Enabled", "Disabled", func(c *Condition) (bool, time.Time) { return c.st.enabled, c.st.enabledTime }, true)
	fs = conditionVariable(fs, "Quality", id.StatusCode, func(c *Condition) any { return c.st.quality }, func(c *Condition) time.Time { return c.st.qualityTime })
	fs = conditionVariable(fs, "LastSeverity", id.UInt16, func(c *Condition) any { return c.st.lastSeverity }, func(c *Condition) time.Time { return c.st.lastSeverityTime })
	fs = conditionVariable(fs, "Comment", id.LocalizedText, func(c *Condition) any { return c.st.comment }, func(c *Condition) time.Time { return c.st.commentTime })
	fs = append(fs, prop("ClientUserId", id.String, false, func(c *Condition) any { return c.st.clientUserID }))

	if c.isAck {
		// AcknowledgeableConditionType (Part 9 §5.7.2)
		fs = twoState(fs, "AckedState", "Acknowledged", "Unacknowledged", func(c *Condition) (bool, time.Time) { return c.st.acked, c.st.ackedTime }, false)
		if c.cfg.Confirmable {
			fs = twoState(fs, "ConfirmedState", "Confirmed", "Unconfirmed", func(c *Condition) (bool, time.Time) { return c.st.confirmed, c.st.confirmedTime }, false)
		}
	}
	if !c.isAlarm {
		return fs
	}
	// AlarmConditionType (Part 9 §5.8.2)
	fs = twoState(fs, "ActiveState", "Active", "Inactive", func(c *Condition) (bool, time.Time) { return c.st.active, c.st.activeTime }, false)
	fs = append(fs,
		prop("InputNode", id.NodeID, false, func(c *Condition) any { return nullNodeID(c.cfg.InputNode) }),
		prop("SuppressedOrShelved", id.Boolean, false, func(c *Condition) any { return c.st.suppressed || c.st.shelving != Unshelved }))
	if c.cfg.Suppressible {
		fs = twoState(fs, "SuppressedState", "Suppressed", "Unsuppressed", func(c *Condition) (bool, time.Time) { return c.st.suppressed, c.st.suppressedTime }, false)
	}
	if c.cfg.Shelving {
		// ShelvedStateMachineType (Part 9 §5.8.10)
		fs = append(fs,
			condField{path: "ShelvingState", refType: id.HasComponent, object: true, typeDef: id.ShelvedStateMachineType},
			condField{path: "ShelvingState/CurrentState", refType: id.HasComponent, typeDef: id.FiniteStateVariableType, dataType: id.LocalizedText, valueRank: -1,
				value: func(c *Condition) any { return ua.NewLocalizedTextWithLocale(c.st.shelving.String(), "en") }},
			prop("ShelvingState/CurrentState/Id", id.NodeID, false, func(c *Condition) any { return ua.NewNumericNodeID(0, c.st.shelving.stateID()) }),
			condField{path: "ShelvingState/LastTransition", refType: id.HasComponent, typeDef: id.FiniteTransitionVariableType, dataType: id.LocalizedText, valueRank: -1,
				value: func(c *Condition) any {
					if shelvingTransitionID(c.st.shelvingFrom, c.st.shelving) == 0 {
						return &ua.LocalizedText{}
					}
					return ua.NewLocalizedTextWithLocale(c.st.shelvingFrom.String()+"To"+c.st.shelving.String(), "en")
				}},
			prop("ShelvingState/LastTransition/Id", id.NodeID, false, func(c *Condition) any {
				return nullNodeID(transitionNodeID(shelvingTransitionID(c.st.shelvingFrom, c.st.shelving)))
			}),
			prop("ShelvingState/LastTransition/TransitionTime", id.UtcTime, false, func(c *Condition) any { return c.st.shelvingTime }),
			prop("ShelvingState/UnshelveTime", id.Duration, false, func(c *Condition) any {
				if c.st.unshelveAt.IsZero() {
					return float64(0)
				}
				return float64(max(time.Until(c.st.unshelveAt), 0)) / float64(time.Millisecond)
			}),
		)
		if c.cfg.MaxTimeShelved > 0 {
			fs = append(fs, prop("MaxTimeShelved", id.Duration, true, func(c *Condition) any {
				return float64(c.cfg.MaxTimeShelved) / float64(time.Millisecond)
			}))
		}
	}
	if c.isOffNormal {
		// OffNormalAlarmType (Part 9 §5.8.23)
		fs = append(fs, prop("NormalState", id.NodeID, true, func(c *Condition) any { return nullNodeID(c.cfg.NormalState) }))
	}
	if c.isLimit {
		// LimitAlarmType (Part 9 §5.8.11)
		for _, l := range []struct {
			name string
			v    *float64
		}{{"HighHighLimit", c.cfg.Limits.HighHigh}, {"HighLimit", c.cfg.Limits.High}, {"LowLimit", c.cfg.Limits.Low}, {"LowLowLimit", c.cfg.Limits.LowLow}} {
			if l.v != nil {
				v := *l.v
				fs = append(fs, prop(l.name, id.Double, true, func(*Condition) any { return v }))
			}
		}
	}
	if c.isExclusive {
		// ExclusiveLimitStateMachineType (Part 9 §5.8.12)
		fs = append(fs,
			condField{path: "LimitState", refType: id.HasComponent, object: true, typeDef: id.ExclusiveLimitStateMachineType},
			condField{path: "LimitState/CurrentState", refType: id.HasComponent, typeDef: id.FiniteStateVariableType, dataType: id.LocalizedText, valueRank: -1,
				value: func(c *Condition) any { return ua.NewLocalizedTextWithLocale(c.st.limit.String(), "en") }},
			prop("LimitState/CurrentState/Id", id.NodeID, false, func(c *Condition) any { return nullNodeID(transitionNodeID(c.st.limit.stateID())) }),
			condField{path: "LimitState/LastTransition", refType: id.HasComponent, typeDef: id.FiniteTransitionVariableType, dataType: id.LocalizedText, valueRank: -1,
				value: func(c *Condition) any {
					if exclusiveLimitTransitionID(c.st.limitFrom, c.st.limit) == 0 {
						return &ua.LocalizedText{}
					}
					return ua.NewLocalizedTextWithLocale(c.st.limitFrom.String()+"To"+c.st.limit.String(), "en")
				}},
			prop("LimitState/LastTransition/Id", id.NodeID, false, func(c *Condition) any {
				return nullNodeID(transitionNodeID(exclusiveLimitTransitionID(c.st.limitFrom, c.st.limit)))
			}),
			prop("LimitState/LastTransition/TransitionTime", id.UtcTime, false, func(c *Condition) any { return c.st.limitTime }),
		)
	}
	if c.isNonExclusive {
		// NonExclusiveLimitAlarmType (Part 9 §5.8.13)
		l := c.cfg.Limits
		for i, s := range []struct {
			name, t, f string
			on         *float64
			get        func(NonExclusiveLimits) bool
		}{
			{"HighHighState", "HighHigh active", "HighHigh inactive", l.HighHigh, func(n NonExclusiveLimits) bool { return n.HighHigh }},
			{"HighState", "High active", "High inactive", l.High, func(n NonExclusiveLimits) bool { return n.High }},
			{"LowState", "Low active", "Low inactive", l.Low, func(n NonExclusiveLimits) bool { return n.Low }},
			{"LowLowState", "LowLow active", "LowLow inactive", l.LowLow, func(n NonExclusiveLimits) bool { return n.LowLow }},
		} {
			if s.on == nil {
				continue
			}
			fs = twoState(fs, s.name, s.t, s.f, func(c *Condition) (bool, time.Time) { return s.get(c.st.nonExclusive), c.st.nonExclTimes[i] }, false)
		}
	}
	return fs
}

func transitionNodeID(n uint32) *ua.NodeID {
	if n == 0 {
		return nil
	}
	return ua.NewNumericNodeID(0, n)
}

// fieldValueLocked is the value of a field as a Variant: the value, or
// Bad_ConditionDisabled for a field that is not valid while disabled.
func (c *Condition) fieldValueLocked(f *condField) *ua.Variant {
	if !c.st.enabled && !f.always {
		return ua.MustVariant(ua.StatusBadConditionDisabled)
	}
	v, err := ua.NewVariant(f.value(c))
	if err != nil {
		return ua.MustVariant(nil)
	}
	return v
}

// eventLocked returns the event of the current state of the condition.
// mu must be held.
func (c *Condition) eventLocked() *BaseEvent {
	st := &c.st
	ev := &BaseEvent{
		EventID:     st.eventID,
		EventType:   c.typeID,
		SourceNode:  c.cfg.Source,
		SourceName:  c.sourceName,
		Time:        st.time,
		Message:     st.message,
		Severity:    st.severity,
		Fields:      map[string]*ua.Variant{},
		conditionID: c.id,
	}
	for i := range c.table {
		f := &c.table[i]
		if f.object {
			continue
		}
		ev.Fields[f.path] = c.fieldValueLocked(f)
	}
	return ev
}

// build creates the nodes of the condition and attaches it to its source.
func (c *Condition) build(src *Node) {
	s := c.srv
	c.table = c.fields()
	root := NewNode(c.id, Attributes{
		ua.AttributeIDNodeClass:     DataValueFromValue(uint32(ua.NodeClassObject)),
		ua.AttributeIDBrowseName:    DataValueFromValue(&ua.QualifiedName{NamespaceIndex: c.ns.ID(), Name: c.cfg.Name}),
		ua.AttributeIDDisplayName:   DataValueFromValue(attrs.DisplayName(c.cfg.Name, "")),
		ua.AttributeIDDescription:   DataValueFromValue(&ua.LocalizedText{}),
		ua.AttributeIDEventNotifier: DataValueFromValue(byte(0)),
	}, nil, nil)
	c.ns.AddNode(root)
	if tn := s.Node(c.typeID); tn != nil {
		root.AddRef(tn, RefType(id.HasTypeDefinition), true)
	}
	c.nodes = append(c.nodes, c.id)
	byPath := map[string]*Node{"": root}
	for i := range c.table {
		f := &c.table[i]
		parentPath, name := "", f.path
		if k := strings.LastIndex(f.path, "/"); k >= 0 {
			parentPath, name = f.path[:k], f.path[k+1:]
		}
		parent := byPath[parentPath]
		nid := ua.NewNumericNodeID(c.ns.ID(), c.ns.GetNextNodeID())
		a := Attributes{
			ua.AttributeIDBrowseName:  DataValueFromValue(&ua.QualifiedName{Name: name}),
			ua.AttributeIDDisplayName: DataValueFromValue(attrs.DisplayName(name, "")),
			ua.AttributeIDDescription: DataValueFromValue(&ua.LocalizedText{}),
		}
		var val ValueFunc
		if f.object {
			a[ua.AttributeIDNodeClass] = DataValueFromValue(uint32(ua.NodeClassObject))
			a[ua.AttributeIDEventNotifier] = DataValueFromValue(byte(0))
		} else {
			a[ua.AttributeIDNodeClass] = DataValueFromValue(uint32(ua.NodeClassVariable))
			a[ua.AttributeIDDataType] = DataValueFromValue(ua.NewNumericExpandedNodeID(0, f.dataType))
			a[ua.AttributeIDValueRank] = DataValueFromValue(f.valueRank)
			a[ua.AttributeIDAccessLevel] = DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead))
			a[ua.AttributeIDUserAccessLevel] = DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead))
			val = c.valueFunc(f)
			c.vars = append(c.vars, nid)
		}
		n := NewNode(nid, a, nil, val)
		c.ns.AddNode(n)
		if tn := s.Node(ua.NewNumericNodeID(0, f.typeDef)); tn != nil {
			n.AddRef(tn, RefType(id.HasTypeDefinition), true)
		}
		linkChild(parent, n, f.refType)
		byPath[f.path] = n
		c.nodes = append(c.nodes, nid)
		if f.path == "ShelvingState" {
			c.shelvingID = nid
		}
	}

	// The source: HasCondition (Part 9 §7.2) and HasComponent to the
	// condition; it becomes an event notifier the Server object reports.
	if src.ID().Namespace() == 0 {
		if own := s.ownNode(src.ID().IntID()); own != nil {
			src = own
		}
	}
	src.AddRef(root, RefType(id.HasCondition), true)
	root.AddRef(src, RefType(id.HasCondition), false)
	linkChild(src, root, id.HasComponent)
	srvID := ua.NewNumericNodeID(0, id.Server)
	var srvNode *Node
	if !src.ID().Equal(srvID) {
		_ = src.SetAttribute(ua.AttributeIDEventNotifier, DataValueFromValue(byte(ua.EventNotifierTypeSubscribeToEvents)))
		if !hasForwardRef(srvNode0(s), src.ID(), id.HasNotifier) && !hasInverseNotifier(src) {
			srvNode = s.ownNode(id.Server)
			if srvNode != nil {
				linkChild(srvNode, src, id.HasNotifier)
			}
		}
	}
	srcNode := src
	c.sourceRefs = func() {
		target := ua.NewExpandedNodeID(c.id, "", 0)
		srcNode.RemoveRef(target, ua.NewNumericNodeID(0, id.HasCondition), true)
		srcNode.RemoveRef(target, ua.NewNumericNodeID(0, id.HasComponent), true)
	}
}

func srvNode0(s *Server) *Node {
	n := s.Node(ua.NewNumericNodeID(0, id.Server))
	if n == nil {
		return &Node{}
	}
	return n
}

// hasInverseNotifier reports whether a notifier already reports the events
// of n (an inverse HasNotifier or HasEventSource reference).
func hasInverseNotifier(n *Node) bool {
	for _, r := range n.refsSnapshot() {
		if r != nil && !r.IsForward && r.ReferenceTypeID != nil {
			if t := r.ReferenceTypeID.IntID(); t == id.HasNotifier || t == id.HasEventSource {
				return true
			}
		}
	}
	return false
}

// valueFunc is the value of the variable of a field.
func (c *Condition) valueFunc(f *condField) ValueFunc {
	return func() *ua.DataValue {
		c.mu.RLock()
		defer c.mu.RUnlock()
		if !c.st.enabled && !f.always {
			return badValue(ua.StatusBadConditionDisabled)
		}
		return DataValueFromValue(c.fieldValueLocked(f))
	}
}
