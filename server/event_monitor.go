// SPDX-License-Identifier: MIT

package server

import (
	"sync"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// EventMonitoredItem extends MonitoredItem with event-specific state:
// the validated SelectClauses and the OfType filter (if any).
type EventMonitoredItem struct {
	SelectClauses []*ua.SimpleAttributeOperand
	OfTypeNodeID  *ua.NodeID // nil means accept all event types
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
func validateEventFilter(ef *ua.EventFilter) (*EventMonitoredItem, *ua.EventFilterResult, ua.StatusCode) {
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

	// Validate WhereClause — only OfType on BaseEventType hierarchy is supported.
	var whereResult *ua.ContentFilterResult
	if ef.WhereClause != nil && len(ef.WhereClause.Elements) > 0 {
		elemResults := make([]*ua.ContentFilterElementResult, len(ef.WhereClause.Elements))
		for i, elem := range ef.WhereClause.Elements {
			elemResults[i] = &ua.ContentFilterElementResult{
				StatusCode:         ua.StatusOK,
				OperandStatusCodes: make([]ua.StatusCode, len(elem.FilterOperands)),
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
				if !isKnownEventType(typeNodeID) {
					elemResults[i].StatusCode = ua.StatusBadFilterOperandInvalid
					elemResults[i].OperandStatusCodes[0] = ua.StatusBadFilterOperandInvalid
					continue
				}
				emi.OfTypeNodeID = typeNodeID
				elemResults[i].OperandStatusCodes[0] = ua.StatusOK
			default:
				elemResults[i].StatusCode = ua.StatusBadFilterOperatorUnsupported
			}
		}
		whereResult = &ua.ContentFilterResult{ElementResults: elemResults}
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
// We accept BaseEventType and its immediate well-known subtypes.
func isKnownEventType(nodeID *ua.NodeID) bool {
	if nodeID == nil {
		return false
	}
	if nodeID.Namespace() != 0 {
		return false
	}
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

// BaseEvent contains fields for a BaseEventType event.
type BaseEvent struct {
	EventID    []byte
	EventType  *ua.NodeID
	SourceNode *ua.NodeID
	SourceName string
	Time       interface{} // time.Time
	Message    *ua.LocalizedText
	Severity   uint16
}

// selectEventFields applies SelectClauses to a BaseEvent, returning the event
// field values in order.
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
		return ua.MustVariant(nil)
	}
}

// EmitBaseEvent emits a BaseEventType event to all event-monitored items watching nodeID.
// It applies each item's SelectClauses to produce the EventFieldList.
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

		// Check OfType filter.
		if emi.OfTypeNodeID != nil && event.EventType != nil {
			if !eventTypeMatches(event.EventType, emi.OfTypeNodeID) {
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

// eventTypeMatches checks if actual is the same as or a subtype of expected.
// For simplicity, BaseEventType matches everything.
func eventTypeMatches(actual, expected *ua.NodeID) bool {
	if expected.IntID() == id.BaseEventType && expected.Namespace() == 0 {
		return true
	}
	return actual.String() == expected.String()
}
