// SPDX-License-Identifier: MIT

package server

import (
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

func TestValidateEventFilter_Valid(t *testing.T) {
	filter := ua.NewEventFilter().
		Select("EventId", "SourceName", "Severity").
		Where(ua.OfType(ua.NewNumericNodeID(0, id.BaseEventType))).
		Build()

	var s *Server
	emi, result, sc := s.validateEventFilter(filter)
	if sc != ua.StatusOK {
		t.Fatalf("validateEventFilter status=%v", sc)
	}
	if emi == nil {
		t.Fatal("nil EventMonitoredItem")
	}
	if len(emi.SelectClauses) != 3 {
		t.Fatalf("SelectClauses=%d, want 3", len(emi.SelectClauses))
	}
	if emi.OfTypeNodeID == nil {
		t.Fatal("OfTypeNodeID should be set")
	}
	if emi.OfTypeNodeID.IntID() != id.BaseEventType {
		t.Errorf("OfTypeNodeID=%v, want BaseEventType", emi.OfTypeNodeID)
	}
	if result == nil {
		t.Fatal("nil EventFilterResult")
	}
	for i, sc := range result.SelectClauseResults {
		if sc != ua.StatusOK {
			t.Errorf("SelectClauseResults[%d]=%v", i, sc)
		}
	}
}

func TestValidateEventFilter_NilFilter(t *testing.T) {
	var s *Server
	_, _, sc := s.validateEventFilter(nil)
	if sc != ua.StatusBadEventFilterInvalid {
		t.Fatalf("status=%v, want BadEventFilterInvalid", sc)
	}
}

func TestValidateEventFilter_EmptySelect(t *testing.T) {
	var s *Server
	filter := &ua.EventFilter{
		SelectClauses: []*ua.SimpleAttributeOperand{},
		WhereClause:   &ua.ContentFilter{},
	}
	_, _, sc := s.validateEventFilter(filter)
	if sc != ua.StatusBadEventFilterInvalid {
		t.Fatalf("status=%v, want BadEventFilterInvalid", sc)
	}
}

func TestValidateEventFilter_NoWhere(t *testing.T) {
	var s *Server
	filter := ua.NewEventFilter().
		Select("EventId", "Severity").
		Build()

	emi, _, sc := s.validateEventFilter(filter)
	if sc != ua.StatusOK {
		t.Fatalf("status=%v", sc)
	}
	if emi.OfTypeNodeID != nil {
		t.Errorf("OfTypeNodeID should be nil when no WhereClause")
	}
}

func TestValidateEventFilter_UnsupportedOperator(t *testing.T) {
	var s *Server
	// Like (6) is not yet implemented — should be accepted at creation with
	// BadFilterOperatorUnsupported on the element, not fail the whole filter.
	filter := &ua.EventFilter{
		SelectClauses: []*ua.SimpleAttributeOperand{
			{BrowsePath: []*ua.QualifiedName{{Name: "Severity"}}},
		},
		WhereClause: &ua.ContentFilter{
			Elements: []*ua.ContentFilterElement{
				{
					FilterOperator: ua.FilterOperatorLike,
					FilterOperands: []*ua.ExtensionObject{
						ua.NewExtensionObject(&ua.LiteralOperand{Value: ua.MustVariant("*")}),
						ua.NewExtensionObject(&ua.LiteralOperand{Value: ua.MustVariant("foo*")}),
					},
				},
			},
		},
	}

	_, result, sc := s.validateEventFilter(filter)
	if sc != ua.StatusOK {
		t.Fatalf("status=%v (should succeed with unsupported where on individual elements)", sc)
	}
	if result == nil || result.WhereClauseResult == nil {
		t.Fatal("nil WhereClauseResult")
	}
	if len(result.WhereClauseResult.ElementResults) == 0 {
		t.Fatal("no element results")
	}
	if result.WhereClauseResult.ElementResults[0].StatusCode != ua.StatusBadFilterOperatorUnsupported {
		t.Errorf("element status=%v, want BadFilterOperatorUnsupported",
			result.WhereClauseResult.ElementResults[0].StatusCode)
	}
}

func TestValidateEventFilter_UnknownEventType(t *testing.T) {
	// A real server is needed so isKnownEventType can reject the unknown ns=0 ID.
	s := newTestServer()
	filter := ua.NewEventFilter().
		Select("Severity").
		Where(ua.OfType(ua.NewNumericNodeID(0, 99999))).
		Build()

	_, result, sc := s.validateEventFilter(filter)
	if sc != ua.StatusOK {
		t.Fatalf("status=%v", sc)
	}
	if result.WhereClauseResult.ElementResults[0].StatusCode != ua.StatusBadFilterOperandInvalid {
		t.Errorf("element status=%v, want BadFilterOperandInvalid",
			result.WhereClauseResult.ElementResults[0].StatusCode)
	}
}

func TestSelectEventFields(t *testing.T) {
	event := &BaseEvent{
		EventID:    []byte("test-001"),
		EventType:  ua.NewNumericNodeID(0, id.BaseEventType),
		SourceNode: ua.NewStringNodeID(2, "MySource"),
		SourceName: "TestSource",
		Time:       time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC),
		Message:    ua.NewLocalizedText("Hello"),
		Severity:   750,
	}

	clauses := []*ua.SimpleAttributeOperand{
		{BrowsePath: []*ua.QualifiedName{{Name: "SourceName"}}},
		{BrowsePath: []*ua.QualifiedName{{Name: "Severity"}}},
		{BrowsePath: []*ua.QualifiedName{{Name: "Message"}}},
		{BrowsePath: []*ua.QualifiedName{{Name: "UnknownField"}}},
	}

	fields := selectEventFields(event, clauses)
	if len(fields) != 4 {
		t.Fatalf("fields=%d, want 4", len(fields))
	}

	if v, ok := fields[0].Value().(string); !ok || v != "TestSource" {
		t.Errorf("SourceName=%v", fields[0].Value())
	}
	if v, ok := fields[1].Value().(uint16); !ok || v != 750 {
		t.Errorf("Severity=%v", fields[1].Value())
	}
	// Unknown field should be nil variant.
	if fields[3].Value() != nil {
		t.Errorf("unknown field=%v, want nil", fields[3].Value())
	}
}

func TestEventTypeMatches(t *testing.T) {
	var s *Server
	base := ua.NewNumericNodeID(0, id.BaseEventType)
	audit := ua.NewNumericNodeID(0, id.AuditEventType)
	system := ua.NewNumericNodeID(0, id.SystemEventType)

	// BaseEventType matches everything.
	if !s.eventTypeMatches(audit, base) {
		t.Error("audit should match BaseEventType filter")
	}
	if !s.eventTypeMatches(system, base) {
		t.Error("system should match BaseEventType filter")
	}
	// Exact match.
	if !s.eventTypeMatches(audit, audit) {
		t.Error("audit should match audit")
	}
	// Non-base filter only matches same type (nil server → no hierarchy walk).
	if s.eventTypeMatches(system, audit) {
		t.Error("system should not match audit filter")
	}
}

func TestEventItemRegistry(t *testing.T) {
	r := newEventItemRegistry()

	emi := &EventMonitoredItem{
		SelectClauses: []*ua.SimpleAttributeOperand{
			{BrowsePath: []*ua.QualifiedName{{Name: "Severity"}}},
		},
		OfTypeNodeID: ua.NewNumericNodeID(0, id.BaseEventType),
	}

	r.register(1, emi)
	got := r.get(1)
	if got == nil {
		t.Fatal("expected registered item")
	}
	if got.OfTypeNodeID.IntID() != id.BaseEventType {
		t.Error("wrong OfTypeNodeID")
	}

	r.unregister(1)
	if r.get(1) != nil {
		t.Error("expected nil after unregister")
	}
}

func sampleBaseEvent(severity uint16) *BaseEvent {
	return &BaseEvent{
		EventID:    []byte("evt-1"),
		EventType:  ua.NewNumericNodeID(0, id.BaseEventType),
		SourceNode: ua.NewStringNodeID(2, "src"),
		SourceName: "Source",
		Time:       time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC),
		Message:    ua.NewLocalizedText("msg"),
		Severity:   severity,
		Fields:     map[string]*ua.Variant{"AlarmLevel": ua.MustVariant(int32(3))},
	}
}

func TestEvalEventFilter_NilAndEmpty(t *testing.T) {
	srv := newTestServer()
	ev := sampleBaseEvent(100)
	if !srv.evalEventFilter(ev, nil) {
		t.Fatal("nil clause should pass")
	}
	if !srv.evalEventFilter(ev, &ua.ContentFilter{}) {
		t.Fatal("empty clause should pass")
	}
}

func TestEvalEventFilter_Operators(t *testing.T) {
	srv := newTestServer()
	ev := sampleBaseEvent(500)

	severity := saoOp(ua.AttributeIDValue, &ua.QualifiedName{Name: "Severity"})
	cases := []struct {
		name     string
		clause   *ua.ContentFilter
		wantPass bool
	}{
		{
			name: "OfType BaseEventType",
			clause: &ua.ContentFilter{Elements: []*ua.ContentFilterElement{
				ua.OfType(ua.NewNumericNodeID(0, id.BaseEventType)),
			}},
			wantPass: true,
		},
		{
			name: "Equals Severity",
			clause: &ua.ContentFilter{Elements: []*ua.ContentFilterElement{
				cfe(ua.FilterOperatorEquals, severity, lit(ua.MustVariant(uint16(500)))),
			}},
			wantPass: true,
		},
		{
			name: "GreaterThan",
			clause: &ua.ContentFilter{Elements: []*ua.ContentFilterElement{
				cfe(ua.FilterOperatorGreaterThan, severity, lit(ua.MustVariant(uint16(100)))),
			}},
			wantPass: true,
		},
		{
			name: "LessThan fail",
			clause: &ua.ContentFilter{Elements: []*ua.ContentFilterElement{
				cfe(ua.FilterOperatorLessThan, severity, lit(ua.MustVariant(uint16(100)))),
			}},
			wantPass: false,
		},
		{
			name: "GreaterThanOrEqual",
			clause: &ua.ContentFilter{Elements: []*ua.ContentFilterElement{
				cfe(ua.FilterOperatorGreaterThanOrEqual, severity, lit(ua.MustVariant(uint16(500)))),
			}},
			wantPass: true,
		},
		{
			name: "LessThanOrEqual",
			clause: &ua.ContentFilter{Elements: []*ua.ContentFilterElement{
				cfe(ua.FilterOperatorLessThanOrEqual, severity, lit(ua.MustVariant(uint16(500)))),
			}},
			wantPass: true,
		},
		{
			name: "And",
			clause: &ua.ContentFilter{Elements: []*ua.ContentFilterElement{
				cfe(ua.FilterOperatorAnd, elemOp(1), elemOp(2)),
				cfe(ua.FilterOperatorGreaterThan, severity, lit(ua.MustVariant(uint16(100)))),
				cfe(ua.FilterOperatorLessThan, severity, lit(ua.MustVariant(uint16(900)))),
			}},
			wantPass: true,
		},
		{
			name: "Or",
			clause: &ua.ContentFilter{Elements: []*ua.ContentFilterElement{
				cfe(ua.FilterOperatorOr, elemOp(1), elemOp(2)),
				cfe(ua.FilterOperatorEquals, severity, lit(ua.MustVariant(uint16(1)))),
				cfe(ua.FilterOperatorEquals, severity, lit(ua.MustVariant(uint16(500)))),
			}},
			wantPass: true,
		},
		{
			name: "Not",
			clause: &ua.ContentFilter{Elements: []*ua.ContentFilterElement{
				cfe(ua.FilterOperatorNot, elemOp(1)),
				cfe(ua.FilterOperatorEquals, severity, lit(ua.MustVariant(uint16(1)))),
			}},
			wantPass: true,
		},
		{
			name: "unsupported operator passthrough",
			clause: &ua.ContentFilter{Elements: []*ua.ContentFilterElement{
				cfe(ua.FilterOperatorLike, lit(ua.MustVariant("a")), lit(ua.MustVariant("a*"))),
			}},
			wantPass: true,
		},
		{
			name: "custom field Equals",
			clause: &ua.ContentFilter{Elements: []*ua.ContentFilterElement{
				cfe(ua.FilterOperatorEquals,
					saoOp(ua.AttributeIDValue, &ua.QualifiedName{Name: "AlarmLevel"}),
					lit(ua.MustVariant(int32(3)))),
			}},
			wantPass: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := srv.evalEventFilter(ev, tc.clause); got != tc.wantPass {
				t.Fatalf("pass=%v, want %v", got, tc.wantPass)
			}
		})
	}
}

func TestEvalEventFilter_CycleAndBadIndex(t *testing.T) {
	srv := newTestServer()
	ev := sampleBaseEvent(10)
	// ElementOperand pointing at self → NULL → treated as pass-through (!= false).
	clause := &ua.ContentFilter{Elements: []*ua.ContentFilterElement{
		cfe(ua.FilterOperatorEquals, elemOp(0), lit(ua.MustVariant(int32(1)))),
	}}
	if !srv.evalEventFilter(ev, clause) {
		t.Fatal("cyclic filter should not reject (NULL ≠ false)")
	}
	// Out-of-range element index → NULL → pass.
	clause = &ua.ContentFilter{Elements: []*ua.ContentFilterElement{
		cfe(ua.FilterOperatorNot, elemOp(99)),
	}}
	if !srv.evalEventFilter(ev, clause) {
		t.Fatal("bad index should not reject")
	}
}

func TestEmitBaseEvent_FiltersAndDelivery(t *testing.T) {
	srv := newTestServer()
	ns, _ := addTestNamespace(srv)
	nodeID := ua.NewStringNodeID(ns.ID(), "rw_int32")

	sub := NewSubscription()
	sub.srv = srv.SubscriptionService
	sub.ID = 1

	item := &MonitoredItem{
		ID:   1,
		Sub:  sub,
		Mode: ua.MonitoringModeReporting,
		Req: &ua.MonitoredItemCreateRequest{
			ItemToMonitor:       &ua.ReadValueID{NodeID: nodeID},
			RequestedParameters: &ua.MonitoringParameters{ClientHandle: 42},
		},
	}
	srv.MonitoredItemService.Mu.Lock()
	srv.MonitoredItemService.Nodes[nodeID.String()] = []*MonitoredItem{item}
	srv.MonitoredItemService.Mu.Unlock()

	severity := saoOp(ua.AttributeIDValue, &ua.QualifiedName{Name: "Severity"})
	emi := &EventMonitoredItem{
		SelectClauses: []*ua.SimpleAttributeOperand{
			{BrowsePath: []*ua.QualifiedName{{Name: "Severity"}}},
			{BrowsePath: []*ua.QualifiedName{{Name: "SourceName"}}},
		},
		OfTypeNodeID: ua.NewNumericNodeID(0, id.BaseEventType),
		WhereClause: &ua.ContentFilter{Elements: []*ua.ContentFilterElement{
			cfe(ua.FilterOperatorGreaterThan, severity, lit(ua.MustVariant(uint16(100)))),
		}},
	}
	srv.eventItems.register(item.ID, emi)

	// Below threshold → filtered out.
	if err := srv.EmitBaseEvent(nodeID, sampleBaseEvent(50)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sub.EventNotifyChannel:
		t.Fatal("low-severity event should be filtered")
	default:
	}

	// Above threshold → delivered with selected fields.
	if err := srv.EmitBaseEvent(nodeID, sampleBaseEvent(200)); err != nil {
		t.Fatal(err)
	}
	select {
	case evt := <-sub.EventNotifyChannel:
		if evt.ClientHandle != 42 {
			t.Fatalf("ClientHandle=%d", evt.ClientHandle)
		}
		if len(evt.EventFields) != 2 {
			t.Fatalf("fields=%d", len(evt.EventFields))
		}
		if v, _ := evt.EventFields[0].Value().(uint16); v != 200 {
			t.Fatalf("Severity=%v", evt.EventFields[0].Value())
		}
	default:
		t.Fatal("expected delivered event")
	}

	// Disabled monitoring mode skips delivery.
	item.Mode = ua.MonitoringModeDisabled
	if err := srv.EmitBaseEvent(nodeID, sampleBaseEvent(200)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sub.EventNotifyChannel:
		t.Fatal("disabled item should not receive events")
	default:
	}

	// No monitored items / nil service are no-ops.
	if err := srv.EmitBaseEvent(ua.NewStringNodeID(ns.ID(), "missing"), sampleBaseEvent(200)); err != nil {
		t.Fatal(err)
	}
	srv.MonitoredItemService = nil
	if err := srv.EmitBaseEvent(nodeID, sampleBaseEvent(200)); err != nil {
		t.Fatal(err)
	}
}
