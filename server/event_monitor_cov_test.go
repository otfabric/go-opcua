// SPDX-License-Identifier: MIT

package server

import (
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestEventMonitorCov_ExtractNodeIDFromOperand(t *testing.T) {
	want := ua.NewNumericNodeID(0, id.BaseEventType)
	var nilLit *ua.LiteralOperand
	for name, tc := range map[string]struct {
		eo   *ua.ExtensionObject
		want *ua.NodeID
	}{
		"nil object":             {nil, nil},
		"nil value":              {&ua.ExtensionObject{}, nil},
		"value literal":          {&ua.ExtensionObject{Value: ua.LiteralOperand{Value: ua.MustVariant(want)}}, want},
		"value literal no val":   {&ua.ExtensionObject{Value: ua.LiteralOperand{}}, nil},
		"value literal string":   {&ua.ExtensionObject{Value: ua.LiteralOperand{Value: ua.MustVariant("x")}}, nil},
		"pointer literal":        {lit(ua.MustVariant(want)), want},
		"nil pointer literal":    {&ua.ExtensionObject{Value: nilLit}, nil},
		"pointer literal no val": {&ua.ExtensionObject{Value: &ua.LiteralOperand{}}, nil},
		"pointer literal int":    {lit(ua.MustVariant(int32(3))), nil},
		"not a literal":          {elemOp(0), nil},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.want, extractNodeIDFromOperand(tc.eo))
		})
	}
}

func TestEventMonitorCov_ValidateWhereOperandCounts(t *testing.T) {
	s := newTestServer()
	sel := []*ua.SimpleAttributeOperand{{BrowsePath: []*ua.QualifiedName{{Name: "Severity"}}}}
	sev := saoOp(ua.AttributeIDValue, &ua.QualifiedName{Name: "Severity"})
	base := lit(ua.MustVariant(ua.NewNumericNodeID(0, id.BaseEventType)))
	elems := []*ua.ContentFilterElement{
		cfe(ua.FilterOperatorOfType, base, base),                       // 0: two operands
		cfe(ua.FilterOperatorOfType, lit(ua.MustVariant("BaseEvent"))), // 1: not a NodeID
		cfe(ua.FilterOperatorGreaterThan, sev),                         // 2: one operand
		cfe(ua.FilterOperatorEquals, sev, nil),                         // 3: nil operand
		cfe(ua.FilterOperatorLessThan, &ua.ExtensionObject{}, sev),     // 4: operand without value
		cfe(ua.FilterOperatorAnd, elemOp(0)),                           // 5
		cfe(ua.FilterOperatorOr, elemOp(0), elemOp(1), elemOp(2)),      // 6
		cfe(ua.FilterOperatorNot),                                      // 7
		cfe(ua.FilterOperatorOfType, base),                             // 8: valid
	}
	emi, res, sc := s.validateEventFilter(&ua.EventFilter{SelectClauses: sel, WhereClause: &ua.ContentFilter{Elements: elems}})
	require.Equal(t, ua.StatusOK, sc, "element errors do not reject the filter")
	got := make([]ua.StatusCode, len(res.WhereClauseResult.ElementResults))
	for i, r := range res.WhereClauseResult.ElementResults {
		got[i] = r.StatusCode
	}
	require.Equal(t, []ua.StatusCode{
		ua.StatusBadFilterOperandCountMismatch,
		ua.StatusBadFilterOperandInvalid,
		ua.StatusBadFilterOperandCountMismatch,
		ua.StatusBadFilterOperandInvalid,
		ua.StatusBadFilterOperandInvalid,
		ua.StatusBadFilterOperandCountMismatch,
		ua.StatusBadFilterOperandCountMismatch,
		ua.StatusBadFilterOperandCountMismatch,
		ua.StatusOK,
	}, got)
	require.Equal(t, []ua.StatusCode{ua.StatusBadFilterOperandInvalid}, res.WhereClauseResult.ElementResults[1].OperandStatusCodes)
	require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusBadFilterOperandInvalid}, res.WhereClauseResult.ElementResults[3].OperandStatusCodes)
	require.Equal(t, []ua.StatusCode{ua.StatusBadFilterOperandInvalid, ua.StatusOK}, res.WhereClauseResult.ElementResults[4].OperandStatusCodes)
	require.True(t, emi.OfTypeNodeID.Equal(ua.NewNumericNodeID(0, id.BaseEventType)))
}

func TestEventMonitorCov_IsKnownEventType(t *testing.T) {
	s := newTestServer()
	ns := installHookNS(s, func(n *ua.NodeID, a ua.AttributeID) (*ua.DataValue, bool) {
		if a != ua.AttributeIDNodeClass {
			return nil, false
		}
		switch n.StringID() {
		case "RawClass": // NodeClass as stored (uint32), not converted to Int32
			return DataValueFromValue(uint32(ua.NodeClassObjectType)), true
		case "NoClass":
			return nil, true
		case "StringClass":
			return DataValueFromValue("ObjectType"), true
		}
		return nil, false
	})
	addType := func(name string, class ua.NodeClass) *ua.NodeID {
		n := NewNode(ua.NewStringNodeID(ns.ID(), name), map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:  DataValueFromValue(uint32(class)),
			ua.AttributeIDBrowseName: DataValueFromValue(attrs.BrowseName(name)),
		}, nil, nil)
		ns.AddNode(n)
		return n.ID()
	}
	custom := addType("CustomEvent", ua.NodeClassObjectType)
	variable := addType("Var", ua.NodeClassVariable)
	raw := addType("RawClass", ua.NodeClassVariable)
	noClass := addType("NoClass", ua.NodeClassObjectType)
	strClass := addType("StringClass", ua.NodeClassObjectType)

	require.False(t, s.isKnownEventType(nil))
	require.True(t, s.isKnownEventType(ua.NewNumericNodeID(0, id.AuditSessionEventType)))
	require.False(t, s.isKnownEventType(ua.NewNumericNodeID(0, id.Server)))
	require.True(t, s.isKnownEventType(custom))
	require.False(t, s.isKnownEventType(variable))
	require.True(t, s.isKnownEventType(raw))
	require.False(t, s.isKnownEventType(noClass))
	require.False(t, s.isKnownEventType(strClass))
	require.False(t, s.isKnownEventType(ua.NewStringNodeID(ns.ID(), "Missing")))
	require.False(t, s.isKnownEventType(ua.NewStringNodeID(99, "OtherNS")))
	var nilSrv *Server
	require.False(t, nilSrv.isKnownEventType(custom))
	require.True(t, nilSrv.isKnownEventType(ua.NewNumericNodeID(0, id.SystemEventType)))
}

func TestEventMonitorCov_ResolveFields(t *testing.T) {
	ev := sampleBaseEvent(7)
	clauses := []*ua.SimpleAttributeOperand{
		{BrowsePath: []*ua.QualifiedName{{Name: "EventId"}}},
		{BrowsePath: []*ua.QualifiedName{{Name: "EventType"}}},
		{BrowsePath: []*ua.QualifiedName{{Name: "SourceNode"}}},
		{BrowsePath: []*ua.QualifiedName{{Name: "Time"}}},
		{BrowsePath: []*ua.QualifiedName{{Name: "AlarmLevel"}}},
		{BrowsePath: []*ua.QualifiedName{{Name: "Nope"}}},
		{}, // no browse path
	}
	f := selectEventFields(ev, clauses)
	require.Equal(t, []byte("evt-1"), f[0].Value())
	require.True(t, ev.EventType.Equal(f[1].Value().(*ua.NodeID)))
	require.True(t, ev.SourceNode.Equal(f[2].Value().(*ua.NodeID)))
	require.Equal(t, time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC), f[3].Value())
	require.Equal(t, int32(3), f[4].Value())
	require.Nil(t, f[5].Value())
	require.Nil(t, f[6].Value())

	ev.Fields = nil
	require.Nil(t, resolveBaseEventField(ev, "AlarmLevel").Value())
}

func TestEventMonitorCov_EvalNullResults(t *testing.T) {
	s := newTestServer()
	ev := sampleBaseEvent(10)
	sev := saoOp(ua.AttributeIDValue, &ua.QualifiedName{Name: "Severity"})
	str := lit(ua.MustVariant("ten"))
	eval := func(ev *BaseEvent, elems ...*ua.ContentFilterElement) tvl {
		return s.evalEventElement(ev, elems, 0, make([]bool, len(elems)))
	}

	// OfType that cannot be decided.
	require.Equal(t, tvlNull, eval(ev, cfe(ua.FilterOperatorOfType)))
	require.Equal(t, tvlNull, eval(ev, cfe(ua.FilterOperatorOfType, str)))
	noType := sampleBaseEvent(10)
	noType.EventType = nil
	require.Equal(t, tvlNull, eval(noType, ua.OfType(ua.NewNumericNodeID(0, id.SystemEventType))))
	require.Equal(t, tvlFalse, eval(ev, ua.OfType(ua.NewNumericNodeID(0, id.SystemEventType))))

	// Values of different types are not equal, but cannot be ordered: an
	// ordering comparison of them is NULL, not false.
	require.Equal(t, tvlFalse, eval(ev, cfe(ua.FilterOperatorEquals, sev, str)))
	for _, op := range []ua.FilterOperator{
		ua.FilterOperatorGreaterThan, ua.FilterOperatorLessThan,
		ua.FilterOperatorGreaterThanOrEqual, ua.FilterOperatorLessThanOrEqual,
	} {
		require.Equal(t, tvlNull, eval(ev, cfe(op, sev, str)), "operator %v", op)
	}
	// Missing operands (too few, nil) and unsupported operand types.
	require.Equal(t, tvlNull, eval(ev, cfe(ua.FilterOperatorEquals, sev)))
	require.Equal(t, tvlNull, eval(ev, cfe(ua.FilterOperatorEquals, nil, sev)))
	attrOp := ua.NewExtensionObject(&ua.AttributeOperand{NodeID: ua.NewNumericNodeID(0, id.Server), AttributeID: ua.AttributeIDValue})
	require.Equal(t, tvlNull, eval(ev, cfe(ua.FilterOperatorEquals, attrOp, sev)))

	// A NULL condition keeps the event: the filter does not reject on it.
	require.True(t, s.evalEventFilter(ev, &ua.ContentFilter{Elements: []*ua.ContentFilterElement{
		cfe(ua.FilterOperatorNot, elemOp(1)), cfe(ua.FilterOperatorGreaterThan, sev, str),
	}}))
}

func TestEventMonitorCov_EventTypeMatches(t *testing.T) {
	s := newTestServer()
	ns := NewNodeNameSpace(s, "urn:cov:evtypes")
	mk := func(name string) *Node {
		n := NewNode(ua.NewStringNodeID(ns.ID(), name), map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:  DataValueFromValue(uint32(ua.NodeClassObjectType)),
			ua.AttributeIDBrowseName: DataValueFromValue(attrs.BrowseName(name)),
		}, nil, nil)
		ns.AddNode(n)
		return n
	}
	parent, child, other := mk("Parent"), mk("Child"), mk("Other")
	parent.AddRef(child, id.HasSubtype, true)

	require.False(t, s.eventTypeMatches(child.ID(), nil))
	require.True(t, s.eventTypeMatches(nil, ua.NewNumericNodeID(0, id.BaseEventType)))
	require.False(t, s.eventTypeMatches(nil, parent.ID()))
	require.True(t, s.eventTypeMatches(parent.ID(), parent.ID()))
	require.True(t, s.eventTypeMatches(child.ID(), parent.ID()))
	require.False(t, s.eventTypeMatches(parent.ID(), child.ID()))
	require.False(t, s.eventTypeMatches(other.ID(), parent.ID()))
	var nilSrv *Server
	require.False(t, nilSrv.eventTypeMatches(child.ID(), parent.ID()))
}

func TestEventMonitorCov_EmitSkipsAndDrops(t *testing.T) {
	srv := newTestServer()
	ns, _ := addTestNamespace(srv)
	nodeID := ua.NewStringNodeID(ns.ID(), "rw_int32")

	sub := NewSubscription()
	sub.srv = srv.SubscriptionService
	sub.ID = 1
	mkItem := func(itemID uint32, s *Subscription) *MonitoredItem {
		return &MonitoredItem{
			ID: itemID, Sub: s, Mode: ua.MonitoringModeReporting,
			Req: &ua.MonitoredItemCreateRequest{
				ItemToMonitor:       &ua.ReadValueID{NodeID: nodeID},
				RequestedParameters: &ua.MonitoringParameters{ClientHandle: itemID},
			},
		}
	}
	unregistered := mkItem(2, sub) // no event filter registered
	noSub := mkItem(3, nil)
	sampling := mkItem(4, sub) // Sampling: matched, but not reported
	sampling.Mode = ua.MonitoringModeSampling
	typed := mkItem(5, sub)
	plain := mkItem(6, sub)
	srv.MonitoredItemService.Mu.Lock()
	srv.MonitoredItemService.Nodes[nodeID.String()] = []*MonitoredItem{nil, noSub, unregistered, sampling, typed, plain}
	srv.MonitoredItemService.Mu.Unlock()
	sel := []*ua.SimpleAttributeOperand{{BrowsePath: []*ua.QualifiedName{{Name: "Severity"}}}}
	srv.eventItems.register(noSub.ID, &EventMonitoredItem{SelectClauses: sel})
	srv.eventItems.register(sampling.ID, &EventMonitoredItem{SelectClauses: sel})
	srv.eventItems.register(typed.ID, &EventMonitoredItem{SelectClauses: sel, OfTypeNodeID: ua.NewNumericNodeID(0, id.SystemEventType)})
	srv.eventItems.register(plain.ID, &EventMonitoredItem{SelectClauses: sel})

	// A BaseEventType event: only the item without OfType gets it.
	require.NoError(t, srv.EmitBaseEvent(nodeID, sampleBaseEvent(1)))
	require.Len(t, sub.EventNotifyChannel, 1)
	evt := <-sub.EventNotifyChannel
	require.Equal(t, uint32(6), evt.ClientHandle)

	// A full queue drops the event instead of blocking the emitter.
	for len(sub.EventNotifyChannel) < cap(sub.EventNotifyChannel) {
		sub.EventNotifyChannel <- &ua.EventFieldList{ClientHandle: 99}
	}
	require.NoError(t, srv.EmitBaseEvent(nodeID, sampleBaseEvent(2)))
	require.Len(t, sub.EventNotifyChannel, cap(sub.EventNotifyChannel))
	for len(sub.EventNotifyChannel) > 0 {
		require.Equal(t, uint32(99), (<-sub.EventNotifyChannel).ClientHandle)
	}

	// The event registry no longer knows an unregistered item.
	srv.eventItems.unregister(plain.ID)
	require.NoError(t, srv.EmitBaseEvent(nodeID, sampleBaseEvent(3)))
	require.Empty(t, sub.EventNotifyChannel)
}
