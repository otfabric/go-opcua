// SPDX-License-Identifier: MIT

package server

import (
	"sync"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// EventMonitoredItem extends MonitoredItem with event-specific state:
// the validated SelectClauses, the OfType filter (if any), and the full
// WhereClause stored for runtime evaluation during emission.
type EventMonitoredItem struct {
	SelectClauses []*ua.SimpleAttributeOperand
	OfTypeNodeID  *ua.NodeID        // nil means accept all event types
	WhereClause   *ua.ContentFilter // nil means no additional filtering
}

// eventItemRegistry tracks event-monitored-items and their filters.
type eventItemRegistry struct {
	mu    sync.Mutex
	items map[uint32]*EventMonitoredItem // keyed by MonitoredItem.ID
}

func newEventItemRegistry() *eventItemRegistry {
	return &eventItemRegistry{items: make(map[uint32]*EventMonitoredItem)}
}

func (r *eventItemRegistry) register(itemID uint32, emi *EventMonitoredItem) {
	r.mu.Lock()
	r.items[itemID] = emi
	r.mu.Unlock()
}

func (r *eventItemRegistry) unregister(itemID uint32) {
	r.mu.Lock()
	delete(r.items, itemID)
	r.mu.Unlock()
}

func (r *eventItemRegistry) get(itemID uint32) *EventMonitoredItem {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.items[itemID]
}

// validateEventFilter validates an EventFilter for CreateMonitoredItems.
// Returns (EventMonitoredItem, EventFilterResult, StatusCode).
// If StatusCode is not OK, the filter is rejected.
//
// Supported WhereClause operators: OfType, Equals, GreaterThan, LessThan,
// GreaterThanOrEqual, LessThanOrEqual, And, Or, Not. Unsupported operators are
// accepted with BadFilterOperatorUnsupported in the element result and are
// treated as pass-through (TRUE) at runtime so existing clients are not broken.
func (s *Server) validateEventFilter(ef *ua.EventFilter) (*EventMonitoredItem, *ua.EventFilterResult, ua.StatusCode) {
	emi := &EventMonitoredItem{}

	if ef == nil {
		return nil, nil, ua.StatusBadEventFilterInvalid
	}

	// Validate SelectClauses — at minimum one clause required.
	if len(ef.SelectClauses) == 0 {
		return nil, nil, ua.StatusBadEventFilterInvalid
	}
	emi.SelectClauses = ef.SelectClauses

	selectResults := make([]ua.StatusCode, len(ef.SelectClauses))
	for i := range ef.SelectClauses {
		selectResults[i] = ua.StatusOK
	}

	// Validate WhereClause.
	var whereResult *ua.ContentFilterResult
	if ef.WhereClause != nil && len(ef.WhereClause.Elements) > 0 {
		elemResults := make([]*ua.ContentFilterElementResult, len(ef.WhereClause.Elements))
		for i, elem := range ef.WhereClause.Elements {
			elemResults[i] = &ua.ContentFilterElementResult{
				StatusCode:         ua.StatusOK,
				OperandStatusCodes: make([]ua.StatusCode, len(elem.FilterOperands)),
			}
			for j := range elemResults[i].OperandStatusCodes {
				elemResults[i].OperandStatusCodes[j] = ua.StatusOK
			}
			switch elem.FilterOperator {
			case ua.FilterOperatorOfType:
				if len(elem.FilterOperands) != 1 {
					elemResults[i].StatusCode = ua.StatusBadFilterOperandCountMismatch
					continue
				}
				typeNodeID := extractNodeIDFromOperand(elem.FilterOperands[0])
				if typeNodeID == nil {
					elemResults[i].StatusCode = ua.StatusBadFilterOperandInvalid
					elemResults[i].OperandStatusCodes[0] = ua.StatusBadFilterOperandInvalid
					continue
				}
				if s != nil && !s.isKnownEventType(typeNodeID) {
					elemResults[i].StatusCode = ua.StatusBadFilterOperandInvalid
					elemResults[i].OperandStatusCodes[0] = ua.StatusBadFilterOperandInvalid
					continue
				}
				emi.OfTypeNodeID = typeNodeID

			case ua.FilterOperatorEquals,
				ua.FilterOperatorGreaterThan,
				ua.FilterOperatorLessThan,
				ua.FilterOperatorGreaterThanOrEqual,
				ua.FilterOperatorLessThanOrEqual:
				if len(elem.FilterOperands) != 2 {
					elemResults[i].StatusCode = ua.StatusBadFilterOperandCountMismatch
					continue
				}
				for j, op := range elem.FilterOperands {
					if op == nil || op.Value == nil {
						elemResults[i].OperandStatusCodes[j] = ua.StatusBadFilterOperandInvalid
						elemResults[i].StatusCode = ua.StatusBadFilterOperandInvalid
					}
				}

			case ua.FilterOperatorAnd, ua.FilterOperatorOr:
				if len(elem.FilterOperands) != 2 {
					elemResults[i].StatusCode = ua.StatusBadFilterOperandCountMismatch
				}

			case ua.FilterOperatorNot:
				if len(elem.FilterOperands) != 1 {
					elemResults[i].StatusCode = ua.StatusBadFilterOperandCountMismatch
				}

			default:
				// Unsupported operators are noted but do not fail filter creation —
				// they are treated as pass-through (TRUE) at emission time.
				elemResults[i].StatusCode = ua.StatusBadFilterOperatorUnsupported
			}
		}
		whereResult = &ua.ContentFilterResult{ElementResults: elemResults}
		// Store the full WhereClause for runtime evaluation.
		emi.WhereClause = ef.WhereClause
	} else {
		whereResult = &ua.ContentFilterResult{}
	}

	filterResult := &ua.EventFilterResult{
		SelectClauseResults:         selectResults,
		SelectClauseDiagnosticInfos: []*ua.DiagnosticInfo{},
		WhereClauseResult:           whereResult,
	}

	return emi, filterResult, ua.StatusOK
}

// extractNodeIDFromOperand extracts a NodeID from a LiteralOperand extension object.
func extractNodeIDFromOperand(eo *ua.ExtensionObject) *ua.NodeID {
	if eo == nil || eo.Value == nil {
		return nil
	}
	switch v := eo.Value.(type) {
	case ua.LiteralOperand:
		if v.Value == nil {
			return nil
		}
		nid, ok := v.Value.Value().(*ua.NodeID)
		if !ok {
			return nil
		}
		return nid
	case *ua.LiteralOperand:
		if v == nil || v.Value == nil {
			return nil
		}
		nid, ok := v.Value.Value().(*ua.NodeID)
		if !ok {
			return nil
		}
		return nid
	}
	return nil
}

// isKnownEventType checks if the NodeID is a recognized event type.
// For namespace 0, it checks the set of well-known OPC UA event types.
// For user namespaces (ns > 0), it accepts any ObjectType node that is
// present in the server address space, enabling custom event subtypes.
func (s *Server) isKnownEventType(nodeID *ua.NodeID) bool {
	if nodeID == nil {
		return false
	}
	if nodeID.Namespace() == 0 {
		intID := nodeID.IntID()
		switch intID {
		case id.BaseEventType,
			id.AuditEventType,
			id.AuditSecurityEventType,
			id.AuditChannelEventType,
			id.AuditSessionEventType,
			id.SystemEventType,
			id.BaseModelChangeEventType,
			id.SemanticChangeEventType,
			id.ConditionType,
			id.TransitionEventType,
			id.ProgressEventType:
			return true
		}
		return false
	}
	// For user-defined namespaces, accept any ObjectType node present in the
	// address space. This allows custom event subtypes registered via AddNode.
	if s == nil {
		return false
	}
	ns, err := s.Namespace(int(nodeID.Namespace()))
	if err != nil {
		return false
	}
	if ns.Node(nodeID) == nil {
		return false
	}
	dv := ns.Attribute(nodeID, ua.AttributeIDNodeClass)
	if dv == nil || dv.Value == nil {
		return false
	}
	nc, ok := dv.Value.Value().(uint32)
	return ok && ua.NodeClass(nc) == ua.NodeClassObjectType
}

// BaseEvent contains fields for a BaseEventType event.
// Set Fields to include user-defined properties that clients can select
// via custom BrowsePath names in their EventFilter SelectClauses.
type BaseEvent struct {
	EventID    []byte
	EventType  *ua.NodeID
	SourceNode *ua.NodeID
	SourceName string
	Time       interface{} // time.Time
	Message    *ua.LocalizedText
	Severity   uint16
	// Fields holds additional user-defined event properties. Keys match the
	// BrowsePath name in the client's SelectClause (e.g. "AlarmLevel").
	Fields map[string]*ua.Variant
}

// selectEventFields applies SelectClauses to a BaseEvent, returning the event
// field values in order. Unknown fields resolve to null.
func selectEventFields(event *BaseEvent, clauses []*ua.SimpleAttributeOperand) []*ua.Variant {
	fields := make([]*ua.Variant, len(clauses))
	for i, clause := range clauses {
		name := ""
		if len(clause.BrowsePath) > 0 {
			name = clause.BrowsePath[0].Name
		}
		fields[i] = resolveBaseEventField(event, name)
	}
	return fields
}

func resolveBaseEventField(event *BaseEvent, name string) *ua.Variant {
	switch name {
	case "EventId":
		return ua.MustVariant(event.EventID)
	case "EventType":
		return ua.MustVariant(event.EventType)
	case "SourceNode":
		return ua.MustVariant(event.SourceNode)
	case "SourceName":
		return ua.MustVariant(event.SourceName)
	case "Time":
		return ua.MustVariant(event.Time)
	case "Message":
		return ua.MustVariant(event.Message)
	case "Severity":
		return ua.MustVariant(event.Severity)
	default:
		if event.Fields != nil {
			if v, ok := event.Fields[name]; ok {
				return v
			}
		}
		return ua.MustVariant(nil)
	}
}

// evalEventFilter evaluates the WhereClause of an EventFilter against a BaseEvent.
// Returns true when the event passes the filter (should be delivered).
// A NULL result (undefined / unsupported operator) is treated as pass-through
// so that clients using operators not yet modelled here still receive events.
func (s *Server) evalEventFilter(event *BaseEvent, clause *ua.ContentFilter) bool {
	if clause == nil || len(clause.Elements) == 0 {
		return true
	}
	visiting := make([]bool, len(clause.Elements))
	result := s.evalEventElement(event, clause.Elements, 0, visiting)
	return result != tvlFalse
}

func (s *Server) evalEventElement(event *BaseEvent, elements []*ua.ContentFilterElement, idx int, visiting []bool) tvl {
	if idx < 0 || idx >= len(elements) {
		return tvlNull
	}
	if visiting[idx] {
		return tvlNull
	}
	visiting[idx] = true
	defer func() { visiting[idx] = false }()

	el := elements[idx]

	switch el.FilterOperator {
	case ua.FilterOperatorOfType:
		if len(el.FilterOperands) != 1 {
			return tvlNull
		}
		typeNodeID := extractNodeIDFromOperand(el.FilterOperands[0])
		if typeNodeID == nil || event.EventType == nil {
			return tvlNull
		}
		return boolTVL(s.eventTypeMatches(event.EventType, typeNodeID))

	case ua.FilterOperatorEquals:
		a := s.resolveEventOperand(event, elements, el, 0, visiting)
		b := s.resolveEventOperand(event, elements, el, 1, visiting)
		eq, ok := variantEquals(a, b)
		if !ok {
			return tvlNull
		}
		return boolTVL(eq)

	case ua.FilterOperatorGreaterThan:
		a := s.resolveEventOperand(event, elements, el, 0, visiting)
		b := s.resolveEventOperand(event, elements, el, 1, visiting)
		c, ok := variantOrder(a, b)
		if !ok {
			return tvlNull
		}
		return boolTVL(c > 0)

	case ua.FilterOperatorLessThan:
		a := s.resolveEventOperand(event, elements, el, 0, visiting)
		b := s.resolveEventOperand(event, elements, el, 1, visiting)
		c, ok := variantOrder(a, b)
		if !ok {
			return tvlNull
		}
		return boolTVL(c < 0)

	case ua.FilterOperatorGreaterThanOrEqual:
		a := s.resolveEventOperand(event, elements, el, 0, visiting)
		b := s.resolveEventOperand(event, elements, el, 1, visiting)
		c, ok := variantOrder(a, b)
		if !ok {
			return tvlNull
		}
		return boolTVL(c >= 0)

	case ua.FilterOperatorLessThanOrEqual:
		a := s.resolveEventOperand(event, elements, el, 0, visiting)
		b := s.resolveEventOperand(event, elements, el, 1, visiting)
		c, ok := variantOrder(a, b)
		if !ok {
			return tvlNull
		}
		return boolTVL(c <= 0)

	case ua.FilterOperatorAnd:
		a := variantTVL(s.resolveEventOperand(event, elements, el, 0, visiting))
		b := variantTVL(s.resolveEventOperand(event, elements, el, 1, visiting))
		return andTVL(a, b)

	case ua.FilterOperatorOr:
		a := variantTVL(s.resolveEventOperand(event, elements, el, 0, visiting))
		b := variantTVL(s.resolveEventOperand(event, elements, el, 1, visiting))
		return orTVL(a, b)

	case ua.FilterOperatorNot:
		a := variantTVL(s.resolveEventOperand(event, elements, el, 0, visiting))
		return notTVL(a)

	default:
		// Unsupported operators pass through so existing clients are not broken.
		return tvlTrue
	}
}

// resolveEventOperand resolves operand j of a filter element to a *ua.Variant.
// SimpleAttributeOperand BrowsePath names are resolved against the BaseEvent fields.
func (s *Server) resolveEventOperand(event *BaseEvent, elements []*ua.ContentFilterElement, el *ua.ContentFilterElement, j int, visiting []bool) *ua.Variant {
	if j >= len(el.FilterOperands) {
		return nil
	}
	op := el.FilterOperands[j]
	if op == nil {
		return nil
	}
	switch v := operandConcrete(op).(type) {
	case *ua.LiteralOperand:
		return v.Value
	case *ua.SimpleAttributeOperand:
		name := ""
		if len(v.BrowsePath) > 0 {
			name = v.BrowsePath[0].Name
		}
		return resolveBaseEventField(event, name)
	case *ua.ElementOperand:
		vv := s.evalEventElement(event, elements, int(v.Index), visiting)
		return tvlVariant(vv)
	default:
		return nil
	}
}

// eventTypeMatches reports whether actual is the same as or a subtype of expected.
// When expected is BaseEventType (ns=0, i=2041) it matches everything.
// Otherwise it uses the type hierarchy to walk the HasSubtype chain.
func (s *Server) eventTypeMatches(actual, expected *ua.NodeID) bool {
	if expected == nil {
		return false
	}
	if expected.IntID() == id.BaseEventType && expected.Namespace() == 0 {
		return true
	}
	if actual == nil {
		return false
	}
	if actual.String() == expected.String() {
		return true
	}
	if s == nil {
		return false
	}
	return s.isSubtypeOf(actual, expected)
}

// EmitBaseEvent emits a BaseEventType event to all event-monitored items watching nodeID.
// It applies each item's OfType check and full WhereClause before selecting fields.
func (s *Server) EmitBaseEvent(nodeID *ua.NodeID, event *BaseEvent) error {
	if s.MonitoredItemService == nil || s.eventItems == nil {
		return nil
	}

	s.MonitoredItemService.Mu.Lock()
	items, ok := s.MonitoredItemService.Nodes[nodeID.String()]
	if !ok {
		s.MonitoredItemService.Mu.Unlock()
		return nil
	}
	targets := make([]*MonitoredItem, len(items))
	copy(targets, items)
	s.MonitoredItemService.Mu.Unlock()

	for _, item := range targets {
		if item == nil || item.Sub == nil {
			continue
		}
		if item.Mode == ua.MonitoringModeDisabled {
			continue
		}

		emi := s.eventItems.get(item.ID)
		if emi == nil {
			continue
		}

		// Apply OfType filter (fast path from the validated OfTypeNodeID shortcut).
		if emi.OfTypeNodeID != nil && event.EventType != nil {
			if !s.eventTypeMatches(event.EventType, emi.OfTypeNodeID) {
				continue
			}
		}

		// Evaluate the full WhereClause if present (covers comparison operators).
		if emi.WhereClause != nil && len(emi.WhereClause.Elements) > 0 {
			if !s.evalEventFilter(event, emi.WhereClause) {
				continue
			}
		}

		fields := selectEventFields(event, emi.SelectClauses)
		ef := &ua.EventFieldList{
			ClientHandle: item.Req.RequestedParameters.ClientHandle,
			EventFields:  fields,
		}

		if item.Mode == ua.MonitoringModeReporting {
			select {
			case item.Sub.EventNotifyChannel <- ef:
			default:
				s.cfg.logger.Warn("event channel full, dropping event for monitored item", "id", item.ID)
			}
		}
	}

	return nil
}
