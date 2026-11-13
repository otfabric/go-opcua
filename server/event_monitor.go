// SPDX-License-Identifier: MIT

package server

import (
	"strings"
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

	// Validate WhereClause. Part 4 §7.7.1: a filter the server cannot
	// process is rejected.
	if ef.WhereClause != nil && len(ef.WhereClause.Elements) > maxFilterElements {
		return nil, nil, ua.StatusBadEventFilterInvalid
	}
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
		// Every other event type of namespace 0 (the condition and alarm
		// types of Part 9, the refresh events, ...).
		return s != nil && s.isSubtypeOf(nodeID, ua.NewNumericNodeID(0, id.BaseEventType))
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
	// The NodeClass attribute is exposed as Int32 (Part 3 §5.2.1) although
	// nodes store it as uint32, so accept both representations. Checking for
	// uint32 only made every user-defined event type look unknown.
	switch nc := dv.Value.Value().(type) {
	case int32:
		return ua.NodeClass(nc) == ua.NodeClassObjectType
	case uint32:
		return ua.NodeClass(nc) == ua.NodeClassObjectType
	}
	return false
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
	// BrowsePath of the client's SelectClause, its names joined with "/"
	// (e.g. "AlarmLevel", "AckedState/Id").
	Fields map[string]*ua.Variant

	// conditionID is the ConditionId of a condition event.
	conditionID *ua.NodeID
	// audit marks an audit event: only the sessions an
	// EventAccessController allows receive it.
	audit bool
}

// selectEventFields applies SelectClauses to a BaseEvent, returning the event
// field values in order. Unknown fields resolve to null.
func selectEventFields(event *BaseEvent, clauses []*ua.SimpleAttributeOperand) []*ua.Variant {
	fields := make([]*ua.Variant, len(clauses))
	for i, clause := range clauses {
		fields[i] = resolveEventClause(event, clause)
	}
	return fields
}

// resolveEventClause resolves a SimpleAttributeOperand against an event. The
// BrowsePath names are joined with "/" ("AckedState/Id"); an empty
// BrowsePath with AttributeId NodeId selects the ConditionId of a condition
// event (Part 9 §5.5.2).
func resolveEventClause(event *BaseEvent, clause *ua.SimpleAttributeOperand) *ua.Variant {
	if clause == nil {
		return ua.MustVariant(nil)
	}
	if len(clause.BrowsePath) == 0 && clause.AttributeID == ua.AttributeIDNodeID {
		if event.conditionID != nil {
			return ua.MustVariant(event.conditionID)
		}
		return ua.MustVariant(nil)
	}
	return resolveBaseEventField(event, eventFieldPath(clause.BrowsePath))
}

// eventFieldPath joins the names of a BrowsePath with "/".
func eventFieldPath(path []*ua.QualifiedName) string {
	names := make([]string, len(path))
	for i, q := range path {
		if q != nil {
			names[i] = q.Name
		}
	}
	return strings.Join(names, "/")
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

// eventView is what the WhereClause evaluator reads of an event: a live
// *BaseEvent or a *HistoricalEvent of the event history.
type eventView interface {
	// eventField resolves a SimpleAttributeOperand against the event.
	eventField(clause *ua.SimpleAttributeOperand) *ua.Variant
	// eventTypeID is the EventType of the event (nil if unknown).
	eventTypeID() *ua.NodeID
}

func (event *BaseEvent) eventField(clause *ua.SimpleAttributeOperand) *ua.Variant {
	return resolveEventClause(event, clause)
}

func (event *BaseEvent) eventTypeID() *ua.NodeID { return event.EventType }

// evalEventFilter evaluates the WhereClause of an EventFilter against an event.
// Returns true when the event passes the filter (should be delivered).
// A NULL result (undefined / unsupported operator) is treated as pass-through
// so that clients using operators not yet modelled here still receive events.
func (s *Server) evalEventFilter(event eventView, clause *ua.ContentFilter) bool {
	if clause == nil || len(clause.Elements) == 0 {
		return true
	}
	n := len(clause.Elements)
	st := &eventEvalState{visiting: make([]bool, n), done: make([]bool, n), memo: make([]tvl, n)}
	result := s.evalEventElement(event, clause.Elements, 0, st)
	return result != tvlFalse
}

// eventEvalState is the state of one WhereClause evaluation: the cycle
// guard and the result of each element evaluated so far, so that an element
// referenced by several operands is evaluated once.
type eventEvalState struct {
	visiting []bool
	done     []bool
	memo     []tvl
}

func (s *Server) evalEventElement(event eventView, elements []*ua.ContentFilterElement, idx int, st *eventEvalState) tvl {
	if idx < 0 || idx >= len(elements) {
		return tvlNull
	}
	if st.done[idx] {
		return st.memo[idx]
	}
	if st.visiting[idx] {
		return tvlNull
	}
	st.visiting[idx] = true
	r := s.evalEventElementOnce(event, elements, idx, st)
	st.visiting[idx] = false
	st.done[idx], st.memo[idx] = true, r
	return r
}

// evalEventElementOnce evaluates element idx; evalEventElement memoises its
// result.
func (s *Server) evalEventElementOnce(event eventView, elements []*ua.ContentFilterElement, idx int, st *eventEvalState) tvl {
	el := elements[idx]

	switch el.FilterOperator {
	case ua.FilterOperatorOfType:
		if len(el.FilterOperands) != 1 {
			return tvlNull
		}
		typeNodeID := extractNodeIDFromOperand(el.FilterOperands[0])
		eventType := event.eventTypeID()
		if typeNodeID == nil || eventType == nil {
			return tvlNull
		}
		return boolTVL(s.eventTypeMatches(eventType, typeNodeID))

	case ua.FilterOperatorEquals:
		a := s.resolveEventOperand(event, elements, el, 0, st)
		b := s.resolveEventOperand(event, elements, el, 1, st)
		eq, ok := variantEquals(a, b)
		if !ok {
			return tvlNull
		}
		return boolTVL(eq)

	case ua.FilterOperatorGreaterThan:
		a := s.resolveEventOperand(event, elements, el, 0, st)
		b := s.resolveEventOperand(event, elements, el, 1, st)
		c, ok := variantOrder(a, b)
		if !ok {
			return tvlNull
		}
		return boolTVL(c > 0)

	case ua.FilterOperatorLessThan:
		a := s.resolveEventOperand(event, elements, el, 0, st)
		b := s.resolveEventOperand(event, elements, el, 1, st)
		c, ok := variantOrder(a, b)
		if !ok {
			return tvlNull
		}
		return boolTVL(c < 0)

	case ua.FilterOperatorGreaterThanOrEqual:
		a := s.resolveEventOperand(event, elements, el, 0, st)
		b := s.resolveEventOperand(event, elements, el, 1, st)
		c, ok := variantOrder(a, b)
		if !ok {
			return tvlNull
		}
		return boolTVL(c >= 0)

	case ua.FilterOperatorLessThanOrEqual:
		a := s.resolveEventOperand(event, elements, el, 0, st)
		b := s.resolveEventOperand(event, elements, el, 1, st)
		c, ok := variantOrder(a, b)
		if !ok {
			return tvlNull
		}
		return boolTVL(c <= 0)

	case ua.FilterOperatorAnd:
		a := variantTVL(s.resolveEventOperand(event, elements, el, 0, st))
		b := variantTVL(s.resolveEventOperand(event, elements, el, 1, st))
		return andTVL(a, b)

	case ua.FilterOperatorOr:
		a := variantTVL(s.resolveEventOperand(event, elements, el, 0, st))
		b := variantTVL(s.resolveEventOperand(event, elements, el, 1, st))
		return orTVL(a, b)

	case ua.FilterOperatorNot:
		a := variantTVL(s.resolveEventOperand(event, elements, el, 0, st))
		return notTVL(a)

	default:
		// Unsupported operators pass through so existing clients are not broken.
		return tvlTrue
	}
}

// resolveEventOperand resolves operand j of a filter element to a *ua.Variant.
// SimpleAttributeOperand BrowsePath names are resolved against the event fields.
func (s *Server) resolveEventOperand(event eventView, elements []*ua.ContentFilterElement, el *ua.ContentFilterElement, j int, st *eventEvalState) *ua.Variant {
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
		return event.eventField(v)
	case *ua.ElementOperand:
		vv := s.evalEventElement(event, elements, int(v.Index), st)
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
	s.emitEvent(nodeID, event, false)
	return nil
}

// emitEvent delivers event to the event items watching nodeID. wait has no
// effect any more: the event queues of the items never block (see
// deliverToItem).
func (s *Server) emitEvent(nodeID *ua.NodeID, event *BaseEvent, wait bool) {
	_ = wait
	// PublishedEvents of the PubSub runtime see the event too.
	s.forwardPubSubEvent(nodeID, event)
	// So does the event history of a HistoricalEventNode (Part 11 §5.4).
	s.recordEventHistory(nodeID, event)

	if s.MonitoredItemService == nil || s.eventItems == nil {
		return
	}

	s.MonitoredItemService.Mu.Lock()
	items := s.MonitoredItemService.Nodes[nodeID.String()]
	targets := make([]*MonitoredItem, 0, len(items))
	for _, item := range items {
		// Only items in Reporting mode deliver events.
		if item != nil && item.Sub != nil && item.Mode == ua.MonitoringModeReporting {
			targets = append(targets, item)
		}
	}
	s.MonitoredItemService.Mu.Unlock()

	for _, item := range targets {
		s.deliverToItem(item, event, false, false)
	}
}

// deliverToItem applies the filter of an event item to event and queues the
// selected fields in the event queue of the item. bypassWhere skips the
// OfType and WhereClause checks (RefreshStart/RefreshEnd events, Part 9
// §5.5.7). The queue is bounded by the QueueSize of the item (Part 4
// §5.12.1.5), so queueing never blocks. refresh marks the events of a
// ConditionRefresh: the client asked for all of them at once, so they may
// exceed QueueSize up to maxEventQueueSize.
func (s *Server) deliverToItem(item *MonitoredItem, event *BaseEvent, bypassWhere, refresh bool) {
	emi := s.eventItems.get(item.ID)
	if emi == nil || item.Sub == nil || !s.mayReceive(item, event) {
		return
	}
	if !bypassWhere {
		// Apply OfType filter (fast path from the validated OfTypeNodeID shortcut).
		if emi.OfTypeNodeID != nil && event.EventType != nil {
			if !s.eventTypeMatches(event.EventType, emi.OfTypeNodeID) {
				return
			}
		}
		// Evaluate the full WhereClause if present (covers comparison operators).
		if emi.WhereClause != nil && len(emi.WhereClause.Elements) > 0 {
			if !s.evalEventFilter(event, emi.WhereClause) {
				return
			}
		}
	}

	item.Sub.queueEvent(item, &ua.EventFieldList{
		ClientHandle: item.Req.RequestedParameters.ClientHandle,
		EventFields:  selectEventFields(event, emi.SelectClauses),
	}, refresh)
}
