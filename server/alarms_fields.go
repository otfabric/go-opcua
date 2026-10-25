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
	// value returns the value of a variable for the state st (the
	// condition's own or one of its branches); Condition.mu is held.
	value func(c *Condition, st *conditionState) any
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
func twoState(fs []condField, name, t, f string, get func(st *conditionState) (bool, time.Time), always bool) []condField {
	return append(fs,
		condField{path: name, refType: id.HasComponent, typeDef: id.TwoStateVariableType, dataType: id.LocalizedText, valueRank: -1, always: always,
			value: func(_ *Condition, st *conditionState) any { on, _ := get(st); return stateText(on, t, f) }},
		condField{path: name + "/Id", refType: id.HasProperty, typeDef: id.PropertyType, dataType: id.Boolean, valueRank: -1, always: always,
			value: func(_ *Condition, st *conditionState) any { on, _ := get(st); return on }},
		condField{path: name + "/TransitionTime", refType: id.HasProperty, typeDef: id.PropertyType, dataType: id.UtcTime, valueRank: -1, always: always,
			value: func(_ *Condition, st *conditionState) any { _, at := get(st); return at }},
	)
}

func prop(path string, dataType uint32, always bool, v func(c *Condition, st *conditionState) any) condField {
	return condField{path: path, refType: id.HasProperty, typeDef: id.PropertyType, dataType: dataType, valueRank: -1, value: v, always: always}
}

// conditionVariable adds a ConditionVariable with its SourceTimestamp
// (Part 9 §5.3).
func conditionVariable(fs []condField, name string, dataType uint32, v func(c *Condition, st *conditionState) any, at func(st *conditionState) time.Time) []condField {
	return append(fs,
		condField{path: name, refType: id.HasComponent, typeDef: id.ConditionVariableType, dataType: dataType, valueRank: -1,
			value: v},
		prop(name+"/SourceTimestamp", id.UtcTime, false, func(_ *Condition, st *conditionState) any { return at(st) }))
}

// fields returns the components of the condition for its type and options.
func (c *Condition) fields() []condField {
	fs := []condField{
		// BaseEventType (Part 5 §6.4.2)
		prop("EventId", id.ByteString, true, func(_ *Condition, st *conditionState) any { return st.eventID }),
		prop("EventType", id.NodeID, true, func(c *Condition, st *conditionState) any { return c.typeID }),
		prop("SourceNode", id.NodeID, true, func(c *Condition, st *conditionState) any { return c.cfg.Source }),
		prop("SourceName", id.String, true, func(c *Condition, st *conditionState) any { return c.sourceName }),
		prop("Time", id.UtcTime, true, func(_ *Condition, st *conditionState) any { return st.time }),
		prop("ReceiveTime", id.UtcTime, true, func(_ *Condition, st *conditionState) any { return st.receiveTime }),
		prop("Message", id.LocalizedText, true, func(_ *Condition, st *conditionState) any { return st.message }),
		prop("Severity", id.UInt16, true, func(_ *Condition, st *conditionState) any { return st.severity }),
		// ConditionType (Part 9 §5.5.2)
		prop("ConditionClassId", id.NodeID, true, func(c *Condition, st *conditionState) any { return c.classID }),
		prop("ConditionClassName", id.LocalizedText, true, func(c *Condition, st *conditionState) any { return c.className }),
		prop("ConditionName", id.String, true, func(c *Condition, st *conditionState) any { return c.cfg.Name }),
		prop("BranchId", id.NodeID, true, func(_ *Condition, st *conditionState) any { return nullNodeID(st.branchID) }),
		prop("Retain", id.Boolean, true, func(c *Condition, st *conditionState) any { return c.retainOfLocked(st) }),
	}
	fs = twoState(fs, "EnabledState", "Enabled", "Disabled", func(st *conditionState) (bool, time.Time) { return st.enabled, st.enabledTime }, true)
	fs = conditionVariable(fs, "Quality", id.StatusCode, func(_ *Condition, st *conditionState) any { return st.quality }, func(st *conditionState) time.Time { return st.qualityTime })
	fs = conditionVariable(fs, "LastSeverity", id.UInt16, func(_ *Condition, st *conditionState) any { return st.lastSeverity }, func(st *conditionState) time.Time { return st.lastSeverityTime })
	fs = conditionVariable(fs, "Comment", id.LocalizedText, func(_ *Condition, st *conditionState) any { return st.comment }, func(st *conditionState) time.Time { return st.commentTime })
	fs = append(fs, prop("ClientUserId", id.String, false, func(_ *Condition, st *conditionState) any { return st.clientUserID }))

	if c.isDialog {
		// DialogConditionType (Part 9 §5.6.2)
		d := c.dialog
		fs = twoState(fs, "DialogState", "Active", "Inactive", func(st *conditionState) (bool, time.Time) { return st.dialogActive, st.dialogTime }, false)
		fs = append(fs,
			prop("Prompt", id.LocalizedText, false, func(_ *Condition, st *conditionState) any { return st.prompt }),
			condField{path: "ResponseOptionSet", refType: id.HasProperty, typeDef: id.PropertyType, dataType: id.LocalizedText, valueRank: 1,
				value: func(*Condition, *conditionState) any { return d.options }},
			prop("DefaultResponse", id.Int32, false, func(*Condition, *conditionState) any { return d.defaultResponse }),
			prop("OkResponse", id.Int32, false, func(*Condition, *conditionState) any { return d.okResponse }),
			prop("CancelResponse", id.Int32, false, func(*Condition, *conditionState) any { return d.cancelResponse }),
			prop("LastResponse", id.Int32, false, func(_ *Condition, st *conditionState) any { return st.lastResponse }),
		)
	}

	if c.isAck {
		// AcknowledgeableConditionType (Part 9 §5.7.2)
		fs = twoState(fs, "AckedState", "Acknowledged", "Unacknowledged", func(st *conditionState) (bool, time.Time) { return st.acked, st.ackedTime }, false)
		if c.cfg.Confirmable {
			fs = twoState(fs, "ConfirmedState", "Confirmed", "Unconfirmed", func(st *conditionState) (bool, time.Time) { return st.confirmed, st.confirmedTime }, false)
		}
	}
	if !c.isAlarm {
		return c.extraProperties(fs)
	}
	// AlarmConditionType (Part 9 §5.8.2)
	fs = twoState(fs, "ActiveState", "Active", "Inactive", func(st *conditionState) (bool, time.Time) { return st.active, st.activeTime }, false)
	fs = append(fs,
		prop("InputNode", id.NodeID, false, func(c *Condition, st *conditionState) any { return nullNodeID(c.cfg.InputNode) }),
		prop("SuppressedOrShelved", id.Boolean, false, func(_ *Condition, st *conditionState) any { return st.suppressedOrShelved() }))
	if c.cfg.Suppressible {
		fs = twoState(fs, "SuppressedState", "Suppressed", "Unsuppressed", func(st *conditionState) (bool, time.Time) { return st.suppressed, st.suppressedTime }, false)
	}
	if c.cfg.Serviceable {
		// OutOfServiceState (Part 9 §5.8.2)
		fs = twoState(fs, "OutOfServiceState", "Out of Service", "In Service", func(st *conditionState) (bool, time.Time) { return st.outOfService, st.outOfServiceTime }, false)
	}
	if c.cfg.Silenceable {
		// SilenceState (Part 9 §5.8.2)
		fs = twoState(fs, "SilenceState", "Silenced", "Not Silenced", func(st *conditionState) (bool, time.Time) { return st.silenced, st.silenceTime }, false)
	}
	if c.cfg.Latching {
		// LatchedState (Part 9 §5.8.2)
		fs = twoState(fs, "LatchedState", "Latched", "Unlatched", func(st *conditionState) (bool, time.Time) { return st.latched, st.latchedTime }, false)
	}
	if c.cfg.Shelving {
		// ShelvedStateMachineType (Part 9 §5.8.10)
		fs = append(fs,
			condField{path: "ShelvingState", refType: id.HasComponent, object: true, typeDef: id.ShelvedStateMachineType},
			condField{path: "ShelvingState/CurrentState", refType: id.HasComponent, typeDef: id.FiniteStateVariableType, dataType: id.LocalizedText, valueRank: -1,
				value: func(c *Condition, st *conditionState) any {
					return ua.NewLocalizedTextWithLocale(st.shelving.String(), "en")
				}},
			prop("ShelvingState/CurrentState/Id", id.NodeID, false, func(c *Condition, st *conditionState) any { return ua.NewNumericNodeID(0, st.shelving.stateID()) }),
			condField{path: "ShelvingState/LastTransition", refType: id.HasComponent, typeDef: id.FiniteTransitionVariableType, dataType: id.LocalizedText, valueRank: -1,
				value: func(c *Condition, st *conditionState) any {
					if shelvingTransitionID(st.shelvingFrom, st.shelving) == 0 {
						return &ua.LocalizedText{}
					}
					return ua.NewLocalizedTextWithLocale(st.shelvingFrom.String()+"To"+st.shelving.String(), "en")
				}},
			prop("ShelvingState/LastTransition/Id", id.NodeID, false, func(c *Condition, st *conditionState) any {
				return nullNodeID(transitionNodeID(shelvingTransitionID(st.shelvingFrom, st.shelving)))
			}),
			prop("ShelvingState/LastTransition/TransitionTime", id.UtcTime, false, func(_ *Condition, st *conditionState) any { return st.shelvingTime }),
			prop("ShelvingState/UnshelveTime", id.Duration, false, func(c *Condition, st *conditionState) any {
				if st.unshelveAt.IsZero() {
					return float64(0)
				}
				return float64(max(st.unshelveAt.Sub(c.srv.now()), 0)) / float64(time.Millisecond)
			}),
		)
		if c.cfg.MaxTimeShelved > 0 {
			fs = append(fs, prop("MaxTimeShelved", id.Duration, true, func(c *Condition, st *conditionState) any {
				return float64(c.cfg.MaxTimeShelved) / float64(time.Millisecond)
			}))
		}
	}
	fs = c.fields105(fs)
	if c.isOffNormal {
		// OffNormalAlarmType (Part 9 §5.8.23)
		fs = append(fs, prop("NormalState", id.NodeID, true, func(c *Condition, st *conditionState) any { return nullNodeID(c.cfg.NormalState) }))
	}
	if c.isLimit {
		// LimitAlarmType (Part 9 §5.8.11)
		for _, l := range []struct {
			name string
			v    *float64
		}{{"HighHighLimit", c.cfg.Limits.HighHigh}, {"HighLimit", c.cfg.Limits.High}, {"LowLimit", c.cfg.Limits.Low}, {"LowLowLimit", c.cfg.Limits.LowLow}} {
			if l.v != nil {
				v := *l.v
				fs = append(fs, prop(l.name, id.Double, true, func(*Condition, *conditionState) any { return v }))
			}
		}
	}
	if c.isExclusive {
		// ExclusiveLimitStateMachineType (Part 9 §5.8.12)
		fs = append(fs,
			condField{path: "LimitState", refType: id.HasComponent, object: true, typeDef: id.ExclusiveLimitStateMachineType},
			condField{path: "LimitState/CurrentState", refType: id.HasComponent, typeDef: id.FiniteStateVariableType, dataType: id.LocalizedText, valueRank: -1,
				value: func(c *Condition, st *conditionState) any {
					return ua.NewLocalizedTextWithLocale(st.limit.String(), "en")
				}},
			prop("LimitState/CurrentState/Id", id.NodeID, false, func(c *Condition, st *conditionState) any { return nullNodeID(transitionNodeID(st.limit.stateID())) }),
			condField{path: "LimitState/LastTransition", refType: id.HasComponent, typeDef: id.FiniteTransitionVariableType, dataType: id.LocalizedText, valueRank: -1,
				value: func(c *Condition, st *conditionState) any {
					if exclusiveLimitTransitionID(st.limitFrom, st.limit) == 0 {
						return &ua.LocalizedText{}
					}
					return ua.NewLocalizedTextWithLocale(st.limitFrom.String()+"To"+st.limit.String(), "en")
				}},
			prop("LimitState/LastTransition/Id", id.NodeID, false, func(c *Condition, st *conditionState) any {
				return nullNodeID(transitionNodeID(exclusiveLimitTransitionID(st.limitFrom, st.limit)))
			}),
			prop("LimitState/LastTransition/TransitionTime", id.UtcTime, false, func(_ *Condition, st *conditionState) any { return st.limitTime }),
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
			fs = twoState(fs, s.name, s.t, s.f, func(st *conditionState) (bool, time.Time) { return s.get(st.nonExclusive), st.nonExclTimes[i] }, false)
		}
	}
	return c.extraProperties(fs)
}

// extraProperties adds the Properties of ConditionConfig.
func (c *Condition) extraProperties(fs []condField) []condField {
	for _, p := range c.cfg.Properties {
		if p.Name != "" && p.Value != nil {
			fs = append(fs, prop(p.Name, p.DataType, true, func(*Condition, *conditionState) any { return p.Value() }))
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
func (c *Condition) fieldValueLocked(st *conditionState, f *condField) *ua.Variant {
	if !st.enabled && !f.always {
		return ua.MustVariant(ua.StatusBadConditionDisabled)
	}
	v, err := ua.NewVariant(f.value(c, st))
	if err != nil {
		return ua.MustVariant(nil)
	}
	return v
}

// eventLocked returns the event of the current state of the condition.
// mu must be held.
func (c *Condition) eventLocked() *BaseEvent { return c.eventOfLocked(&c.st) }

// eventOfLocked returns the event of st, the state of the condition or of
// one of its branches. mu must be held.
func (c *Condition) eventOfLocked(st *conditionState) *BaseEvent {
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
		ev.Fields[f.path] = c.fieldValueLocked(st, f)
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
		switch f.path {
		case "ShelvingState":
			c.shelvingID = nid
		case "FirstInGroup":
			c.firstInGroupID = nid
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
		// Keep the history bits of a HistoricalEventNode (Part 11 §5.4.4).
		_ = src.SetAttribute(ua.AttributeIDEventNotifier, DataValueFromValue(eventNotifierOf(src)|byte(ua.EventNotifierTypeSubscribeToEvents)))
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
		return DataValueFromValue(c.fieldValueLocked(&c.st, f))
	}
}
