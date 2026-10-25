// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// eventHistoryServer returns a test server with a historian whose notifier
// Pump is a writable HistoricalEventNode storing whole events.
func eventHistoryServer(t *testing.T) (*Server, *AttributeService, *Historian, *Node) {
	t.Helper()
	s, _, src := alarmTestServer(t)
	h := NewHistorian()
	h.EnableEvents(src.ID(), 0)
	s.SetHistorian(h)
	require.NoError(t, s.EnableEventHistory(src.ID(), EventHistoryOptions{Writable: true}))
	return s, &AttributeService{srv: s}, h, src
}

// emitAt reports a BaseEvent named name at evAt(i) on notifier.
func emitAt(s *Server, notifier *ua.NodeID, name string, i int, extra map[string]*ua.Variant) {
	_ = s.EmitBaseEvent(notifier, &BaseEvent{
		EventID:    []byte(name),
		EventType:  ua.NewNumericNodeID(0, id.BaseEventType),
		SourceNode: notifier,
		SourceName: "Pump",
		Time:       evAt(i),
		Message:    ua.NewLocalizedText(name),
		Severity:   uint16(100 * (i + 1)),
		Fields:     extra,
	})
}

func historyReadEvents(t *testing.T, svc *AttributeService, d *ua.ReadEventDetails, release bool, nodes ...*ua.HistoryReadValueID) *ua.HistoryReadResponse {
	t.Helper()
	resp, err := svc.HistoryRead(context.Background(), nil, &ua.HistoryReadRequest{
		RequestHeader:             reqHeader(),
		HistoryReadDetails:        ua.NewExtensionObject(d),
		TimestampsToReturn:        ua.TimestampsToReturnBoth,
		ReleaseContinuationPoints: release,
		NodesToRead:               nodes,
	}, 1)
	require.NoError(t, err)
	return resp.(*ua.HistoryReadResponse)
}

// eventFields returns the fields of the events of a result.
func eventFields(t *testing.T, r *ua.HistoryReadResult) [][]any {
	t.Helper()
	require.NotNil(t, r.HistoryData)
	he, ok := r.HistoryData.Value.(*ua.HistoryEvent)
	require.True(t, ok, "got %T", r.HistoryData.Value)
	out := make([][]any, len(he.Events))
	for i, e := range he.Events {
		for _, f := range e.EventFields {
			out[i] = append(out[i], f.Value())
		}
	}
	return out
}

func idsOf(t *testing.T, r *ua.HistoryReadResult) []string {
	t.Helper()
	var out []string
	for _, f := range eventFields(t, r) {
		out = append(out, string(f[0].([]byte)))
	}
	return out
}

func historyUpdate(t *testing.T, svc *AttributeService, details ...any) []*ua.HistoryUpdateResult {
	t.Helper()
	eos := make([]*ua.ExtensionObject, len(details))
	for i, d := range details {
		eos[i] = ua.NewExtensionObject(d)
	}
	resp, err := svc.HistoryUpdate(context.Background(), nil, &ua.HistoryUpdateRequest{RequestHeader: reqHeader(), HistoryUpdateDetails: eos}, 1)
	require.NoError(t, err)
	hr := resp.(*ua.HistoryUpdateResponse)
	require.Equal(t, ua.StatusOK, hr.ResponseHeader.ServiceResult)
	return hr.Results
}

func TestEnableEventHistory(t *testing.T) {
	s, ns, src := alarmTestServer(t)
	require.ErrorIs(t, s.EnableEventHistory(nil, EventHistoryOptions{}), ua.StatusBadNodeIDInvalid)
	require.ErrorIs(t, s.EnableEventHistory(ua.NewStringNodeID(ns.ID(), "nope"), EventHistoryOptions{}), ua.StatusBadNodeIDUnknown)
	v := ns.AddNewVariableStringNode("Var", int32(1))
	require.ErrorIs(t, s.EnableEventHistory(v.ID(), EventHistoryOptions{}), ua.StatusBadNodeClassInvalid)

	require.NoError(t, s.EnableEventHistory(src.ID(), EventHistoryOptions{Writable: true}))
	require.Equal(t, byte(ua.EventNotifierTypeSubscribeToEvents|ua.EventNotifierTypeHistoryRead|ua.EventNotifierTypeHistoryWrite), eventNotifierOf(src))
	p := s.historicalEventFilterNode(src)
	require.NotNil(t, p, "HistoricalEventFilter Property (Part 11 §5.4.2)")
	require.Equal(t, historicalEventFilterName, p.BrowseName().Name)
	require.Nil(t, s.storageFilter(src.ID(), src), "no filter: whole events")
	guide := p.Value().Value.Value().(*ua.ExtensionObject).Value.(*ua.EventFilter)
	require.Len(t, guide.SelectClauses, len(baseEventFields)+1)

	// Again, read-only, with a filter: the Property is replaced, not added.
	f := ua.NewEventFilter().Select("Severity").Build()
	require.NoError(t, s.EnableEventHistory(src.ID(), EventHistoryOptions{Filter: f}))
	require.Equal(t, byte(ua.EventNotifierTypeSubscribeToEvents|ua.EventNotifierTypeHistoryRead), eventNotifierOf(src))
	require.Same(t, p, s.historicalEventFilterNode(src))
	require.Same(t, f, s.storageFilter(src.ID(), src))
	props := 0
	for _, r := range src.refsSnapshot() {
		if r.IsForward && r.ReferenceTypeID.IntID() == id.HasProperty {
			props++
		}
	}
	require.Equal(t, 1, props)

	// The Server object (namespace 0) can be a HistoricalEventNode too.
	srvID := ua.NewNumericNodeID(0, id.Server)
	require.NoError(t, s.EnableEventHistory(srvID, EventHistoryOptions{}))
	require.NotZero(t, eventNotifierOf(s.Node(srvID))&byte(ua.EventNotifierTypeHistoryRead))
}

func TestEventNotifierOf(t *testing.T) {
	n := NewFolderNode(ua.NewStringNodeID(1, "N"), "N")
	for _, v := range []any{byte(5), int32(5), uint32(5)} {
		_ = n.SetAttribute(ua.AttributeIDEventNotifier, DataValueFromValue(v))
		require.Equal(t, byte(5), eventNotifierOf(n))
	}
	_ = n.SetAttribute(ua.AttributeIDEventNotifier, DataValueFromValue("x"))
	require.Zero(t, eventNotifierOf(n))
	require.Zero(t, eventNotifierOf(NewNode(ua.NewStringNodeID(1, "M"), Attributes{}, nil, nil)))
}

func TestStorageFilterValues(t *testing.T) {
	s, _, src := alarmTestServer(t)
	require.Nil(t, s.storageFilter(src.ID(), src), "no Property")
	f := ua.NewEventFilter().Select("Severity").Build()
	require.NoError(t, s.setHistoricalEventFilter(src, f))
	p := s.historicalEventFilterNode(src)
	for _, val := range []any{
		ua.NewExtensionObject(f), &ua.ExtensionObject{Value: *f},
	} {
		p.val = func() *ua.DataValue { return DataValueFromValue(val) }
		require.Equal(t, f.SelectClauses, s.storageFilter(src.ID(), src).SelectClauses)
	}
	for _, val := range []any{int32(1), &ua.ExtensionObject{Value: int32(1)}} {
		p.val = func() *ua.DataValue { return DataValueFromValue(val) }
		require.Nil(t, s.storageFilter(src.ID(), src))
	}
	p.val = func() *ua.DataValue { return nil }
	require.Nil(t, s.storageFilter(src.ID(), src))
}

func TestRecordEventHistory(t *testing.T) {
	s, _, h, src := eventHistoryServer(t)
	emitAt(s, src.ID(), "a", 1, map[string]*ua.Variant{"Custom": ua.MustVariant(int32(7))})

	// No EventId and no Time: the history gives them.
	_ = s.EmitBaseEvent(src.ID(), &BaseEvent{EventType: ua.NewNumericNodeID(0, id.BaseEventType)})
	events, _, st := h.ReadEvents(src.ID(), evAt(0), time.Time{}, 10, nil, nil)
	require.Equal(t, ua.StatusOK, st)
	require.Len(t, events, 2)
	require.Equal(t, "a", string(events[0].EventID()))
	require.Equal(t, int32(7), events[0].field("Custom"))
	require.IsType(t, time.Time{}, events[0].field("ReceiveTime"))
	require.Len(t, events[1].EventID(), 16)
	require.False(t, events[1].Time().IsZero())

	// Not stored: a notifier without the HistoryRead bit, an unknown node,
	// a server without an event history provider.
	other := NewFolderNode(ua.NewStringNodeID(src.ID().Namespace(), "Other"), "Other")
	s.Namespaces()[src.ID().Namespace()].AddNode(other)
	h.EnableEvents(other.ID(), 0)
	emitAt(s, other.ID(), "b", 1, nil)
	_, _, st = h.ReadEvents(other.ID(), evAt(0), time.Time{}, 10, nil, nil)
	require.Equal(t, ua.StatusGoodNoData, st)
	s.recordEventHistory(ua.NewStringNodeID(9, "nope"), &BaseEvent{})
	s.recordEventHistory(nil, &BaseEvent{})
	s.recordEventHistory(src.ID(), nil)
	s.SetHistorian(dataOnlyProvider{})
	emitAt(s, src.ID(), "c", 3, nil)
	s.SetHistorian(h)
	_, _, st = h.ReadEvents(src.ID(), evAt(3), evAt(3), 0, nil, nil)
	require.Equal(t, ua.StatusGoodNoData, st)
}

func TestRecordEventHistoryFilter(t *testing.T) {
	s, _, h, src := eventHistoryServer(t)
	// Store the events of Severity >= 300 with their Message.
	f := ua.NewEventFilter().Select("Message").
		Where(&ua.ContentFilterElement{
			FilterOperator: ua.FilterOperatorGreaterThanOrEqual,
			FilterOperands: []*ua.ExtensionObject{
				ua.NewExtensionObject(&ua.SimpleAttributeOperand{TypeDefinitionID: ua.NewNumericNodeID(0, id.BaseEventType),
					BrowsePath: []*ua.QualifiedName{{Name: "Severity"}}, AttributeID: ua.AttributeIDValue}),
				ua.NewExtensionObject(&ua.LiteralOperand{Value: ua.MustVariant(uint16(300))}),
			},
		}).Build()
	require.NoError(t, s.EnableEventHistory(src.ID(), EventHistoryOptions{Filter: f, Writable: true}))
	for i := range 4 {
		emitAt(s, src.ID(), fmt.Sprintf("e%d", i), i, map[string]*ua.Variant{"Custom": ua.MustVariant(int32(i))})
	}
	events, _, _ := h.ReadEvents(src.ID(), evAt(0), evAt(100), 0, nil, nil)
	require.Equal(t, []string{"e2", "e3"}, evNames(events))
	require.Nil(t, events[0].Fields["Custom"], "not selected: not stored")
	require.Nil(t, events[0].Fields["Severity"])
	require.NotNil(t, events[0].Fields["Message"])
	require.NotNil(t, events[0].Fields["EventType"], "always stored")

	// Reading a field the history does not store gives Bad_NoData (Part 11
	// §6.5.2.2), a stored field the event lacks null (§5.4.1).
	svc := &AttributeService{srv: s}
	resp := historyReadEvents(t, svc, &ua.ReadEventDetails{StartTime: evAt(0), EndTime: evAt(100),
		Filter: ua.NewEventFilter().Select("EventId", "Custom", "Message", "ReceiveTime").SelectConditionID().Build()},
		false, &ua.HistoryReadValueID{NodeID: src.ID()})
	fields := eventFields(t, resp.Results[0])
	require.Len(t, fields, 2)
	require.Equal(t, ua.StatusBadNoData, fields[0][1])
	require.Equal(t, "e2", fields[0][2].(*ua.LocalizedText).Text)
	require.IsType(t, time.Time{}, fields[0][3])
	require.Equal(t, ua.StatusBadNoData, fields[0][4], "the ConditionId is not stored either")
}

// The events of a condition reach the history of its source and of the
// Server object, as the event items of those notifiers receive them; a
// condition keeps the history bits of its source.
func TestRecordConditionEventHistory(t *testing.T) {
	s, _, h, src := eventHistoryServer(t)
	srvID := ua.NewNumericNodeID(0, id.Server)
	h.EnableEvents(srvID, 0)
	require.NoError(t, s.EnableEventHistory(srvID, EventHistoryOptions{}))
	c, err := s.AddCondition(ConditionConfig{Name: "A", Source: src.ID(), NodeID: ua.NewStringNodeID(src.ID().Namespace(), "A")})
	require.NoError(t, err)
	defer s.alarms.close()
	require.NotZero(t, eventNotifierOf(src)&byte(ua.EventNotifierTypeHistoryRead), "AddCondition keeps the history bits")
	require.NoError(t, c.SetActive(true))

	for _, n := range []*ua.NodeID{src.ID(), srvID} {
		// Only EndTime (and NumValuesPerNode): newest first.
		events, _, st := h.ReadEvents(n, time.Time{}, time.Now().Add(time.Hour), 1, nil, nil)
		require.Equal(t, ua.StatusOK, st, n.String())
		require.Len(t, events, 1)
		last := events[0]
		require.NotNil(t, last.Fields[historicalConditionIDKey], "condition event in the history of %s", n)
		require.True(t, c.NodeID().Equal(last.Fields[historicalConditionIDKey].Value().(*ua.NodeID)))
		require.Equal(t, true, last.field("ActiveState/Id"))
	}
}

func TestHistoryReadEvents(t *testing.T) {
	s, svc, _, src := eventHistoryServer(t)
	for i := range 6 {
		emitAt(s, src.ID(), fmt.Sprintf("e%d", i), i, nil)
	}
	node := &ua.HistoryReadValueID{NodeID: src.ID()}
	sel := ua.NewEventFilter().Select("EventId", "Severity").Build()

	t.Run("range and fields", func(t *testing.T) {
		resp := historyReadEvents(t, svc, &ua.ReadEventDetails{StartTime: evAt(1), EndTime: evAt(4), Filter: sel}, false, node)
		require.Equal(t, ua.StatusOK, resp.Results[0].StatusCode)
		require.Equal(t, [][]any{{[]byte("e1"), uint16(200)}, {[]byte("e2"), uint16(300)}, {[]byte("e3"), uint16(400)}}, eventFields(t, resp.Results[0]))
	})

	t.Run("reverse", func(t *testing.T) {
		resp := historyReadEvents(t, svc, &ua.ReadEventDetails{StartTime: evAt(4), EndTime: evAt(1), Filter: sel}, false, node)
		require.Equal(t, names(4, 2), idsOf(t, resp.Results[0]))
	})

	t.Run("where clause", func(t *testing.T) {
		f := ua.NewEventFilter().Select("EventId").Where(&ua.ContentFilterElement{
			FilterOperator: ua.FilterOperatorLessThan,
			FilterOperands: []*ua.ExtensionObject{
				ua.NewExtensionObject(&ua.SimpleAttributeOperand{BrowsePath: []*ua.QualifiedName{{Name: "Severity"}}, AttributeID: ua.AttributeIDValue}),
				ua.NewExtensionObject(&ua.LiteralOperand{Value: ua.MustVariant(uint16(300))}),
			},
		}).Build()
		resp := historyReadEvents(t, svc, &ua.ReadEventDetails{StartTime: evAt(0), EndTime: evAt(100), Filter: f}, false, node)
		require.Equal(t, names(0, 1), idsOf(t, resp.Results[0]))

		of := ua.NewEventFilter().Select("EventId").Where(&ua.ContentFilterElement{
			FilterOperator: ua.FilterOperatorOfType,
			FilterOperands: []*ua.ExtensionObject{ua.NewExtensionObject(&ua.LiteralOperand{Value: ua.MustVariant(ua.NewNumericNodeID(0, id.SystemEventType))})},
		}).Build()
		resp = historyReadEvents(t, svc, &ua.ReadEventDetails{StartTime: evAt(0), EndTime: evAt(100), Filter: of}, false, node)
		require.Equal(t, ua.StatusGoodNoData, resp.Results[0].StatusCode)
		require.Empty(t, eventFields(t, resp.Results[0]))
	})

	t.Run("paging with session-bound continuation points", func(t *testing.T) {
		d := &ua.ReadEventDetails{StartTime: evAt(0), EndTime: evAt(100), NumValuesPerNode: 4, Filter: sel}
		resp := historyReadEvents(t, svc, d, false, node)
		r := resp.Results[0]
		require.Equal(t, names(0, 3), idsOf(t, r))
		require.NotEmpty(t, r.ContinuationPoint)
		resp = historyReadEvents(t, svc, d, false, &ua.HistoryReadValueID{NodeID: src.ID(), ContinuationPoint: r.ContinuationPoint})
		require.Equal(t, names(4, 5), idsOf(t, resp.Results[0]))
		require.Empty(t, resp.Results[0].ContinuationPoint)
		// One-shot.
		resp = historyReadEvents(t, svc, d, false, &ua.HistoryReadValueID{NodeID: src.ID(), ContinuationPoint: r.ContinuationPoint})
		require.Equal(t, ua.StatusBadContinuationPointInvalid, resp.Results[0].StatusCode)

		// Released.
		resp = historyReadEvents(t, svc, d, false, node)
		cp := resp.Results[0].ContinuationPoint
		resp = historyReadEvents(t, svc, d, true, &ua.HistoryReadValueID{NodeID: src.ID(), ContinuationPoint: cp})
		require.Equal(t, ua.StatusOK, resp.Results[0].StatusCode)
		require.Nil(t, resp.Results[0].HistoryData, "a release returns no data")
		resp = historyReadEvents(t, svc, d, false, &ua.HistoryReadValueID{NodeID: src.ID(), ContinuationPoint: cp})
		require.Equal(t, ua.StatusBadContinuationPointInvalid, resp.Results[0].StatusCode)
	})

	t.Run("ReadEventDetails2", func(t *testing.T) {
		resp, err := svc.HistoryRead(context.Background(), nil, &ua.HistoryReadRequest{
			RequestHeader:      reqHeader(),
			HistoryReadDetails: ua.NewExtensionObject(&ua.ReadEventDetails2{StartTime: evAt(0), EndTime: evAt(2), Filter: sel}),
			NodesToRead:        []*ua.HistoryReadValueID{node},
		}, 1)
		require.NoError(t, err)
		require.Equal(t, names(0, 1), idsOf(t, resp.(*ua.HistoryReadResponse).Results[0]))
	})

	t.Run("unsupported event details", func(t *testing.T) {
		for _, d := range []any{
			&ua.ReadEventDetails2{StartTime: evAt(0), EndTime: evAt(2), Filter: sel, ReadModified: true},
			&ua.ReadEventDetailsSorted{StartTime: evAt(0), EndTime: evAt(2), Filter: sel},
		} {
			resp, err := svc.HistoryRead(context.Background(), nil, &ua.HistoryReadRequest{
				RequestHeader: reqHeader(), HistoryReadDetails: ua.NewExtensionObject(d), NodesToRead: []*ua.HistoryReadValueID{node},
			}, 1)
			require.NoError(t, err)
			require.Equal(t, ua.StatusBadHistoryOperationUnsupported, resp.(*ua.HistoryReadResponse).Results[0].StatusCode, "%T", d)
		}
	})

	t.Run("per node results", func(t *testing.T) {
		plain := NewFolderNode(ua.NewStringNodeID(src.ID().Namespace(), "Plain"), "Plain")
		s.Namespaces()[src.ID().Namespace()].AddNode(plain)
		resp := historyReadEvents(t, svc, &ua.ReadEventDetails{StartTime: evAt(0), EndTime: evAt(1), Filter: sel}, false,
			&ua.HistoryReadValueID{NodeID: ua.NewStringNodeID(src.ID().Namespace(), "nope")},
			&ua.HistoryReadValueID{NodeID: plain.ID()},
			&ua.HistoryReadValueID{},
			node,
		)
		require.Equal(t, ua.StatusBadNodeIDUnknown, resp.Results[0].StatusCode)
		require.Equal(t, ua.StatusBadHistoryOperationUnsupported, resp.Results[1].StatusCode, "no HistoryRead bit")
		require.Equal(t, ua.StatusBadNodeIDInvalid, resp.Results[2].StatusCode)
		require.Equal(t, ua.StatusOK, resp.Results[3].StatusCode)
	})

	t.Run("service results", func(t *testing.T) {
		for name, tc := range map[string]struct {
			d     *ua.ReadEventDetails
			nodes []*ua.HistoryReadValueID
			want  ua.StatusCode
		}{
			"only start":        {&ua.ReadEventDetails{StartTime: evAt(0), Filter: sel}, []*ua.HistoryReadValueID{node}, ua.StatusBadHistoryOperationInvalid},
			"only num":          {&ua.ReadEventDetails{NumValuesPerNode: 3, Filter: sel}, []*ua.HistoryReadValueID{node}, ua.StatusBadHistoryOperationInvalid},
			"nothing":           {&ua.ReadEventDetails{Filter: sel}, []*ua.HistoryReadValueID{node}, ua.StatusBadHistoryOperationInvalid},
			"no filter":         {&ua.ReadEventDetails{StartTime: evAt(0), EndTime: evAt(1)}, []*ua.HistoryReadValueID{node}, ua.StatusBadEventFilterInvalid},
			"no select clauses": {&ua.ReadEventDetails{StartTime: evAt(0), EndTime: evAt(1), Filter: &ua.EventFilter{}}, []*ua.HistoryReadValueID{node}, ua.StatusBadEventFilterInvalid},
			"no nodes":          {&ua.ReadEventDetails{StartTime: evAt(0), EndTime: evAt(1), Filter: sel}, nil, ua.StatusBadNothingToDo},
		} {
			resp := historyReadEvents(t, svc, tc.d, false, tc.nodes...)
			require.Equal(t, tc.want, resp.ResponseHeader.ServiceResult, name)
			require.Empty(t, resp.Results, name)
		}
		s.cfg.cap.OperationalLimits.MaxNodesPerHistoryReadEvents = 1
		defer func() { s.cfg.cap.OperationalLimits.MaxNodesPerHistoryReadEvents = 32 }()
		resp := historyReadEvents(t, svc, &ua.ReadEventDetails{StartTime: evAt(0), EndTime: evAt(1), Filter: sel}, false, node, node)
		require.Equal(t, ua.StatusBadTooManyOperations, resp.ResponseHeader.ServiceResult)
	})

	t.Run("TimestampsToReturn is ignored", func(t *testing.T) {
		resp, err := svc.HistoryRead(context.Background(), nil, &ua.HistoryReadRequest{
			RequestHeader:      reqHeader(),
			HistoryReadDetails: ua.NewExtensionObject(&ua.ReadEventDetails{StartTime: evAt(0), EndTime: evAt(1), Filter: sel}),
			TimestampsToReturn: ua.TimestampsToReturnNeither,
			NodesToRead:        []*ua.HistoryReadValueID{node},
		}, 1)
		require.NoError(t, err)
		require.Equal(t, names(0, 0), idsOf(t, resp.(*ua.HistoryReadResponse).Results[0]))
	})
}

// dataOnlyProvider is a history provider without event history.
type dataOnlyProvider struct{}

func (dataOnlyProvider) ReadRaw(*ua.NodeID, time.Time, time.Time, uint32, bool, []byte) (*ua.HistoryReadResult, error) {
	return &ua.HistoryReadResult{StatusCode: ua.StatusOK}, nil
}
func (dataOnlyProvider) ReleaseContinuation([]byte) {}

// badEventProvider answers every event operation with an error.
type badEventProvider struct{ dataOnlyProvider }

func (badEventProvider) RecordEvent(*ua.NodeID, *HistoricalEvent) {}
func (badEventProvider) ReadEvents(*ua.NodeID, time.Time, time.Time, uint32, func(*HistoricalEvent) bool, []byte) ([]*HistoricalEvent, []byte, ua.StatusCode) {
	return nil, nil, ua.StatusBadDataUnavailable
}
func (badEventProvider) UpdateEvents(*ua.NodeID, ua.PerformUpdateType, []*HistoricalEvent) *ua.HistoryUpdateResult {
	return nil
}
func (badEventProvider) DeleteEvents(*ua.NodeID, [][]byte) *ua.HistoryUpdateResult { return nil }

// shortEventProvider answers updates without OperationResults or with a
// bad StatusCode.
type shortEventProvider struct {
	badEventProvider
	status ua.StatusCode
}

func (p shortEventProvider) UpdateEvents(*ua.NodeID, ua.PerformUpdateType, []*HistoricalEvent) *ua.HistoryUpdateResult {
	return &ua.HistoryUpdateResult{StatusCode: p.status}
}

func TestHistoryEventsProviders(t *testing.T) {
	s, svc, h, src := eventHistoryServer(t)
	sel := ua.NewEventFilter().Select("EventId", "EventType", "Time").Build()
	read := &ua.ReadEventDetails{StartTime: evAt(0), EndTime: evAt(1), Filter: sel}
	ins := &ua.UpdateEventDetails{NodeID: src.ID(), PerformInsertReplace: ua.PerformUpdateTypeInsert, Filter: sel,
		EventData: []*ua.HistoryEventFieldList{{EventFields: []*ua.Variant{ua.MustVariant([]byte("x")), ua.MustVariant(ua.NewNumericNodeID(0, id.BaseEventType)), ua.MustVariant(evAt(0))}}}}
	del := &ua.DeleteEventDetails{NodeID: src.ID(), EventIDs: [][]byte{[]byte("x")}}

	s.SetHistorian(dataOnlyProvider{})
	resp := historyReadEvents(t, svc, read, false, &ua.HistoryReadValueID{NodeID: src.ID()})
	require.Equal(t, ua.StatusBadHistoryOperationUnsupported, resp.Results[0].StatusCode)
	for _, r := range historyUpdate(t, svc, ins, del) {
		require.Equal(t, ua.StatusBadHistoryOperationUnsupported, r.StatusCode)
	}

	s.SetHistorian(badEventProvider{})
	resp = historyReadEvents(t, svc, read, false, &ua.HistoryReadValueID{NodeID: src.ID()})
	require.Equal(t, ua.StatusBadDataUnavailable, resp.Results[0].StatusCode)
	for _, r := range historyUpdate(t, svc, ins, del) {
		require.Equal(t, ua.StatusBadInternalError, r.StatusCode)
	}

	s.SetHistorian(shortEventProvider{})
	require.Equal(t, []ua.StatusCode{ua.StatusBadInternalError}, historyUpdate(t, svc, ins)[0].OperationResults)
	s.SetHistorian(shortEventProvider{status: ua.StatusBadOutOfMemory})
	require.Equal(t, ua.StatusBadOutOfMemory, historyUpdate(t, svc, ins)[0].StatusCode)

	s.SetHistorian(nil)
	resp = historyReadEvents(t, svc, read, false, &ua.HistoryReadValueID{NodeID: src.ID()})
	require.Equal(t, ua.StatusBadHistoryOperationUnsupported, resp.Results[0].StatusCode)
	s.SetHistorian(h)
}

func TestHistoryUpdateEvents(t *testing.T) {
	s, svc, h, src := eventHistoryServer(t)
	for i := range 3 {
		emitAt(s, src.ID(), fmt.Sprintf("e%d", i), i, nil)
	}
	base := ua.NewNumericNodeID(0, id.BaseEventType)
	sel := ua.NewEventFilter().Select("EventId", "EventType", "Time", "Severity").Build()
	row := func(eventID any, typ any, tm any, sev any) *ua.HistoryEventFieldList {
		return &ua.HistoryEventFieldList{EventFields: []*ua.Variant{ua.MustVariant(eventID), ua.MustVariant(typ), ua.MustVariant(tm), ua.MustVariant(sev)}}
	}
	upd := func(perform ua.PerformUpdateType, f *ua.EventFilter, rows ...*ua.HistoryEventFieldList) *ua.UpdateEventDetails {
		return &ua.UpdateEventDetails{NodeID: src.ID(), PerformInsertReplace: perform, Filter: f, EventData: rows}
	}

	t.Run("insert", func(t *testing.T) {
		r := historyUpdate(t, svc, upd(ua.PerformUpdateTypeInsert, sel,
			row([]byte("i1"), base, evAt(10), uint16(5)),
			row([]byte("e0"), base, evAt(11), uint16(5)),
			row(nil, nil, nil, nil),
			row([]byte("bad"), ua.NewNumericNodeID(0, id.Server), evAt(12), uint16(5)),
			row([]byte("bad"), "not a node", evAt(12), uint16(5)),
			row([]byte("bad"), base, "not a time", uint16(5)),
			row([]byte("bad"), base, evAt(12), "not a severity"),
			row([]byte{}, base, evAt(12), uint16(5)),
			&ua.HistoryEventFieldList{EventFields: []*ua.Variant{ua.MustVariant(int32(1))}},
			nil,
		))[0]
		require.Equal(t, ua.StatusOK, r.StatusCode)
		require.Equal(t, []ua.StatusCode{
			ua.StatusGoodEntryInserted, ua.StatusBadEntryExists, ua.StatusGoodEntryInserted,
			ua.StatusBadTypeDefinitionInvalid, ua.StatusBadInvalidArgument, ua.StatusBadInvalidArgument,
			ua.StatusBadInvalidArgument, ua.StatusBadInvalidArgument, ua.StatusBadInvalidArgument, ua.StatusBadInvalidArgument,
		}, r.OperationResults)
		events, _, _ := h.ReadEvents(src.ID(), evAt(10), evAt(10), 0, nil, nil)
		require.Equal(t, []string{"i1"}, evNames(events))
		// The null row got an EventId, BaseEventType and the current time.
		events, _, _ = h.ReadEvents(src.ID(), time.Time{}, time.Now().Add(time.Hour), 1, nil, nil)
		require.Len(t, events[0].EventID(), 16)
		require.True(t, events[0].EventType().Equal(base))
	})

	t.Run("source node", func(t *testing.T) {
		f := ua.NewEventFilter().Select("EventType", "Time", "SourceNode").Build()
		r := historyUpdate(t, svc, upd(ua.PerformUpdateTypeInsert, f,
			&ua.HistoryEventFieldList{EventFields: []*ua.Variant{ua.MustVariant(base), ua.MustVariant(evAt(20)), ua.MustVariant(src.ID())}},
			&ua.HistoryEventFieldList{EventFields: []*ua.Variant{ua.MustVariant(base), ua.MustVariant(evAt(20)), ua.MustVariant(ua.NewStringNodeID(9, "nope"))}},
			&ua.HistoryEventFieldList{EventFields: []*ua.Variant{ua.MustVariant(base), ua.MustVariant(evAt(20)), ua.MustVariant("x")}},
		))[0]
		require.Equal(t, []ua.StatusCode{ua.StatusGoodEntryInserted, ua.StatusBadSourceNodeIDInvalid, ua.StatusBadInvalidArgument}, r.OperationResults)
	})

	t.Run("replace", func(t *testing.T) {
		f := ua.NewEventFilter().Select("EventId", "Severity").Build()
		r := historyUpdate(t, svc, upd(ua.PerformUpdateTypeReplace, f,
			&ua.HistoryEventFieldList{EventFields: []*ua.Variant{ua.MustVariant([]byte("e1")), ua.MustVariant(uint16(777))}},
			&ua.HistoryEventFieldList{EventFields: []*ua.Variant{ua.MustVariant([]byte("none")), ua.MustVariant(uint16(1))}},
			&ua.HistoryEventFieldList{EventFields: []*ua.Variant{ua.MustVariant(nil), ua.MustVariant(uint16(1))}},
		))[0]
		require.Equal(t, []ua.StatusCode{ua.StatusGoodEntryReplaced, ua.StatusBadNoEntryExists, ua.StatusBadNoEntryExists}, r.OperationResults)
		events, _, _ := h.ReadEvents(src.ID(), evAt(1), evAt(1), 0, nil, nil)
		require.Equal(t, uint16(777), events[0].field("Severity"))
		require.Nil(t, events[0].field("Message"), "the replacement has the fields given")
	})

	t.Run("update", func(t *testing.T) {
		r := historyUpdate(t, svc, upd(ua.PerformUpdateTypeUpdate, sel,
			row([]byte("e2"), base, evAt(2), uint16(9)),
			row([]byte("u1"), base, evAt(30), uint16(9)),
		))[0]
		require.Equal(t, []ua.StatusCode{ua.StatusGoodEntryReplaced, ua.StatusGoodEntryInserted}, r.OperationResults)
	})

	t.Run("details errors", func(t *testing.T) {
		where := ua.NewEventFilter().Select("EventId", "EventType", "Time").Where(&ua.ContentFilterElement{FilterOperator: ua.FilterOperatorIsNull,
			FilterOperands: []*ua.ExtensionObject{ua.NewExtensionObject(&ua.LiteralOperand{Value: ua.MustVariant(int32(1))})}}).Build()
		ranged := ua.NewEventFilter().Select("EventId", "EventType", "Time").Build()
		ranged.SelectClauses[2].IndexRange = "1"
		for name, tc := range map[string]struct {
			d    *ua.UpdateEventDetails
			want ua.StatusCode
		}{
			"remove":            {upd(ua.PerformUpdateTypeRemove, sel), ua.StatusBadInvalidArgument},
			"no filter":         {upd(ua.PerformUpdateTypeInsert, nil), ua.StatusBadEventFilterInvalid},
			"where clause":      {upd(ua.PerformUpdateTypeInsert, where), ua.StatusBadEventFilterInvalid},
			"nil select clause": {upd(ua.PerformUpdateTypeInsert, &ua.EventFilter{SelectClauses: []*ua.SimpleAttributeOperand{nil}}), ua.StatusBadEventFilterInvalid},
			"index range":       {upd(ua.PerformUpdateTypeInsert, ranged), ua.StatusBadIndexRangeInvalid},
			"insert no Time":    {upd(ua.PerformUpdateTypeInsert, ua.NewEventFilter().Select("EventType").Build()), ua.StatusBadArgumentsMissing},
			"update no type":    {upd(ua.PerformUpdateTypeUpdate, ua.NewEventFilter().Select("Time").Build()), ua.StatusBadArgumentsMissing},
			"replace no id":     {upd(ua.PerformUpdateTypeReplace, ua.NewEventFilter().Select("Time").Build()), ua.StatusBadArgumentsMissing},
			"unknown node":      {&ua.UpdateEventDetails{NodeID: ua.NewStringNodeID(9, "x"), PerformInsertReplace: ua.PerformUpdateTypeInsert, Filter: sel}, ua.StatusBadNodeIDUnknown},
		} {
			require.Equal(t, tc.want, historyUpdate(t, svc, tc.d)[0].StatusCode, name)
		}
		r := historyUpdate(t, svc, upd(ua.PerformUpdateTypeInsert, sel))[0]
		require.Equal(t, ua.StatusOK, r.StatusCode, "no events")
		require.Empty(t, r.OperationResults)
	})

	t.Run("delete", func(t *testing.T) {
		r := historyUpdate(t, svc, &ua.DeleteEventDetails{NodeID: src.ID(), EventIDs: [][]byte{[]byte("e0"), []byte("e0")}})[0]
		require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusBadNoData}, r.OperationResults)
		r = historyUpdate(t, svc, ua.DeleteEventDetails{NodeID: ua.NewStringNodeID(9, "x")})[0]
		require.Equal(t, ua.StatusBadNodeIDUnknown, r.StatusCode)
	})

	t.Run("value details", func(t *testing.T) {
		r := historyUpdate(t, svc, *upd(ua.PerformUpdateTypeUpdate, sel, row([]byte("v1"), base, evAt(40), uint16(1))))[0]
		require.Equal(t, []ua.StatusCode{ua.StatusGoodEntryInserted}, r.OperationResults)
	})

	t.Run("read-only history", func(t *testing.T) {
		require.NoError(t, s.EnableEventHistory(src.ID(), EventHistoryOptions{}))
		defer func() { require.NoError(t, s.EnableEventHistory(src.ID(), EventHistoryOptions{Writable: true})) }()
		r := historyUpdate(t, svc, upd(ua.PerformUpdateTypeInsert, sel, row([]byte("ro"), base, evAt(1), uint16(1))),
			&ua.DeleteEventDetails{NodeID: src.ID(), EventIDs: [][]byte{[]byte("e1")}})
		require.Equal(t, ua.StatusBadNotWritable, r[0].StatusCode)
		require.Equal(t, ua.StatusBadNotWritable, r[1].StatusCode)
		plain := NewFolderNode(ua.NewStringNodeID(src.ID().Namespace(), "Plain2"), "Plain2")
		s.Namespaces()[src.ID().Namespace()].AddNode(plain)
		r = historyUpdate(t, svc, &ua.DeleteEventDetails{NodeID: plain.ID()})
		require.Equal(t, ua.StatusBadHistoryOperationUnsupported, r[0].StatusCode)
	})

	t.Run("fields the history does not store", func(t *testing.T) {
		require.NoError(t, s.EnableEventHistory(src.ID(), EventHistoryOptions{Writable: true, Filter: ua.NewEventFilter().Select("Message").Build()}))
		defer func() { require.NoError(t, s.EnableEventHistory(src.ID(), EventHistoryOptions{Writable: true})) }()
		r := historyUpdate(t, svc, upd(ua.PerformUpdateTypeInsert, sel, row([]byte("ign"), base, evAt(50), uint16(1))))[0]
		require.Equal(t, []ua.StatusCode{ua.StatusGoodDataIgnored}, r.OperationResults)
		events, _, _ := h.ReadEvents(src.ID(), evAt(50), evAt(50), 0, nil, nil)
		require.Nil(t, events[0].Fields["Severity"])
	})

	t.Run("too many operations", func(t *testing.T) {
		s.cfg.cap.OperationalLimits.MaxNodesPerHistoryUpdateEvents = 1
		defer func() { s.cfg.cap.OperationalLimits.MaxNodesPerHistoryUpdateEvents = 32 }()
		resp, err := svc.HistoryUpdate(context.Background(), nil, &ua.HistoryUpdateRequest{RequestHeader: reqHeader(), HistoryUpdateDetails: []*ua.ExtensionObject{
			ua.NewExtensionObject(&ua.DeleteEventDetails{NodeID: src.ID()}), ua.NewExtensionObject(&ua.DeleteEventDetails{NodeID: src.ID()}), nil,
		}}, 1)
		require.NoError(t, err)
		require.Equal(t, ua.StatusBadTooManyOperations, resp.(*ua.HistoryUpdateResponse).ResponseHeader.ServiceResult)
	})
}

// eventDenier is an EventAccessController that grants no event types.
type eventDenier struct {
	DefaultAccessController
	allow bool
}

func (d eventDenier) CheckReceiveEvents(context.Context, *Session, *ua.NodeID) ua.StatusCode {
	if d.allow {
		return ua.StatusOK
	}
	return ua.StatusBadUserAccessDenied
}

// Audit events in the history go to the sessions an EventAccessController
// allows, as their live events do.
func TestHistoryReadAuditEvents(t *testing.T) {
	s, svc, _, src := eventHistoryServer(t)
	s.SetAuditing(true)
	require.True(t, s.ReportAuditEvent(context.Background(), &BaseEvent{EventID: []byte("audit"), EventType: ua.NewNumericNodeID(0, id.AuditEventType), Time: evAt(1)}, src.ID()))
	emitAt(s, src.ID(), "plain", 2, nil)
	d := &ua.ReadEventDetails{StartTime: evAt(0), EndTime: evAt(100), Filter: ua.NewEventFilter().Select("EventId").Build()}
	node := &ua.HistoryReadValueID{NodeID: src.ID()}

	require.Equal(t, []string{"audit", "plain"}, idsOf(t, historyReadEvents(t, svc, d, false, node).Results[0]))
	s.cfg.accessController = eventDenier{}
	require.Equal(t, []string{"plain"}, idsOf(t, historyReadEvents(t, svc, d, false, node).Results[0]))

	audit := ua.NewNumericNodeID(0, id.AuditEventType)
	require.False(t, s.mayReadEvent(context.Background(), &session{}, audit))
	s.cfg.accessController = eventDenier{allow: true}
	require.True(t, s.mayReadEvent(context.Background(), &session{}, audit))
	require.False(t, s.mayReadEvent(context.Background(), nil, audit))
	require.True(t, s.mayReadEvent(context.Background(), nil, ua.NewNumericNodeID(0, id.BaseEventType)))
}

func TestHistoryServerCapabilities(t *testing.T) {
	s, err := New()
	require.NoError(t, err)
	value := func(nid uint32) any {
		dv := s.Node(ua.NewNumericNodeID(0, nid)).Value()
		require.NotNil(t, dv)
		return dv.Value.Value()
	}
	all := []uint32{}
	for _, c := range historyCapabilities {
		all = append(all, c.nodeID)
		require.Equal(t, false, value(c.nodeID), id.Name(c.nodeID))
	}
	s.SetHistorian(NewHistorian())
	for _, n := range all {
		require.Equal(t, true, value(n), id.Name(n))
	}
	s.SetHistorian(dataOnlyProvider{})
	require.Equal(t, true, value(id.HistoryServerCapabilitiesAccessHistoryDataCapability))
	require.Equal(t, false, value(id.HistoryServerCapabilitiesAccessHistoryEventsCapability))
	require.Equal(t, false, value(id.HistoryServerCapabilitiesInsertEventCapability))
}

func TestHistoricalEventAccessors(t *testing.T) {
	var nilEvent *HistoricalEvent
	require.Nil(t, nilEvent.field("EventId"))
	e := &HistoricalEvent{}
	require.Nil(t, e.EventID())
	require.True(t, e.Time().IsZero())
	require.Nil(t, e.EventType())
	require.Nil(t, e.eventField(nil).Value())
	require.Nil(t, e.eventField(&ua.SimpleAttributeOperand{BrowsePath: []*ua.QualifiedName{{Name: "X"}}}).Value())

	ev := NewHistoricalEvent(&BaseEvent{EventID: []byte("x"), Fields: map[string]*ua.Variant{"A": ua.MustVariant(int32(1)), "B": nil}, conditionID: ua.NewStringNodeID(1, "C")})
	require.Contains(t, ev.Fields, "A")
	require.NotContains(t, ev.Fields, "B")
	require.Equal(t, ua.NewStringNodeID(1, "C"), ev.eventField(&ua.SimpleAttributeOperand{AttributeID: ua.AttributeIDNodeID}).Value())
}

func TestEventReadDetails(t *testing.T) {
	f := ua.NewEventFilter().Select("EventId").Build()
	d, supported, ok := eventReadDetails(ua.ReadEventDetails{NumValuesPerNode: 1, Filter: f})
	require.True(t, ok && supported)
	require.Equal(t, uint32(1), d.NumValuesPerNode)
	d, supported, ok = eventReadDetails(ua.ReadEventDetails2{NumValuesPerNode: 2, Filter: f})
	require.True(t, ok && supported)
	require.Equal(t, uint32(2), d.NumValuesPerNode)
	_, supported, ok = eventReadDetails(ua.ReadEventDetailsSorted{})
	require.True(t, ok)
	require.False(t, supported)
	_, supported, ok = eventReadDetails((*ua.ReadEventDetails)(nil))
	require.True(t, ok)
	require.False(t, supported)
	_, _, ok = eventReadDetails(&ua.ReadRawModifiedDetails{})
	require.False(t, ok)
}

// noReads refuses every read and write.
type noReads struct{ DefaultAccessController }

func (noReads) CheckRead(context.Context, *Session, *ua.NodeID) ua.StatusCode {
	return ua.StatusBadUserAccessDenied
}

func (noReads) CheckWrite(context.Context, *Session, *ua.NodeID) ua.StatusCode {
	return ua.StatusBadUserAccessDenied
}

func TestHistoryEventsAccessDenied(t *testing.T) {
	s, svc, _, src := eventHistoryServer(t)
	s.cfg.accessController = noReads{}
	resp := historyReadEvents(t, svc, &ua.ReadEventDetails{StartTime: evAt(0), EndTime: evAt(1), Filter: ua.NewEventFilter().Select("EventId").Build()},
		false, &ua.HistoryReadValueID{NodeID: src.ID()})
	require.Equal(t, ua.StatusBadUserAccessDenied, resp.Results[0].StatusCode)
	r := historyUpdate(t, svc, &ua.DeleteEventDetails{NodeID: src.ID()})
	require.Equal(t, ua.StatusBadUserAccessDenied, r[0].StatusCode)
}
