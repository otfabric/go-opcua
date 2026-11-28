// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// auditTestServer returns a test server with auditing on whose Server
// object keeps its events in the event history of h, and a function that
// returns the audit events of type typ reported since the last call.
func auditTestServer(t *testing.T, opts ...Option) (*Server, *Historian, func(typ uint32) []*HistoricalEvent) {
	t.Helper()
	s := newTestServer()
	for _, o := range opts {
		require.NoError(t, o(s.cfg))
	}
	s.SetAuditing(true)
	h := NewHistorian()
	serverObj := ua.NewNumericNodeID(0, id.Server)
	h.EnableEvents(serverObj, 1000)
	s.SetHistorian(h)
	require.NoError(t, s.EnableEventHistory(serverObj, EventHistoryOptions{}))
	seen := map[string]bool{}
	return s, h, func(typ uint32) []*HistoricalEvent {
		t.Helper()
		evs, _, st := h.ReadEvents(serverObj, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), 0,
			func(*HistoricalEvent) bool { return true }, nil)
		require.False(t, isBad(st), st.Error())
		var out []*HistoricalEvent
		for _, ev := range evs {
			k := string(ev.EventID())
			if et := ev.EventType(); !seen[k] && et != nil && et.IntID() == typ {
				seen[k] = true
				out = append(out, ev)
			}
		}
		return out
	}
}

func fieldOf(ev *HistoricalEvent, name string) any {
	return ev.field(name)
}

// TestAuditWrite: an AuditWriteUpdateEventType per WriteValue, failed ones
// too (Part 4 §6.5.8, Part 5 §6.4.25), with the value before and after;
// with an IndexRange both are limited to it.
func TestAuditWrite(t *testing.T) {
	s, _, audits := auditTestServer(t)
	ns, _ := addTestNamespace(s)
	arr := ns.AddNewVariableStringNode("arr", []int32{1, 2, 3})
	svc := &AttributeService{srv: s}
	rw := ua.NewStringNodeID(ns.ID(), "rw_int32")
	req := &ua.WriteRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 1, AuditEntryID: "entry-1"},
		NodesToWrite: []*ua.WriteValue{
			{NodeID: rw, AttributeID: ua.AttributeIDValue, Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int32(7))}},
			{NodeID: arr.ID(), AttributeID: ua.AttributeIDValue, IndexRange: "1", Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant([]int32{9})}},
			{NodeID: ua.NewStringNodeID(ns.ID(), "nosuch"), AttributeID: ua.AttributeIDValue, Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int32(1))}},
			{NodeID: ua.NewStringNodeID(99, "nons"), AttributeID: ua.AttributeIDValue},
		},
	}
	resp, err := svc.Write(context.Background(), nil, req, 1)
	require.NoError(t, err)
	results := resp.(*ua.WriteResponse).Results
	require.Equal(t, ua.StatusOK, results[0])
	require.Equal(t, ua.StatusOK, results[1])

	evs := audits(id.AuditWriteUpdateEventType)
	require.Len(t, evs, 4)
	e := evs[0]
	require.Equal(t, true, fieldOf(e, "Status"))
	require.Equal(t, "Attribute/Write", fieldOf(e, "SourceName"))
	require.Equal(t, rw.String(), fieldOf(e, "SourceNode").(*ua.NodeID).String())
	require.Equal(t, uint32(ua.AttributeIDValue), fieldOf(e, "AttributeId"))
	require.Equal(t, "", fieldOf(e, "IndexRange"))
	require.Equal(t, int32(42), fieldOf(e, "OldValue"))
	require.Equal(t, int32(7), fieldOf(e, "NewValue"))
	require.Equal(t, "entry-1", fieldOf(e, "ClientAuditEntryId"))
	require.Equal(t, "", fieldOf(e, "ClientUserId"))

	e = evs[1]
	require.Equal(t, "1", fieldOf(e, "IndexRange"))
	require.Equal(t, []int32{2}, fieldOf(e, "OldValue"))
	require.Equal(t, []int32{9}, fieldOf(e, "NewValue"))

	require.Equal(t, false, fieldOf(evs[2], "Status"))
	require.Nil(t, fieldOf(evs[2], "OldValue"))
	require.Contains(t, fieldOf(evs[2], "Message").(*ua.LocalizedText).Text, "Write of Value of ns=")
	require.Equal(t, false, fieldOf(evs[3], "Status"))
	require.Nil(t, fieldOf(evs[3], "NewValue"))
}

// TestAuditWriteValueWriter: the status a ValueWriter returns is the one
// audited.
func TestAuditWriteValueWriter(t *testing.T) {
	s, _, audits := auditTestServer(t)
	ns, _ := addTestNamespace(s)
	n := ns.AddNewVariableStringNode("w", int32(1))
	n.SetValueWriter(func(_ context.Context, w *ValueWrite) ua.StatusCode { return ua.StatusBadOutOfRange })
	sess := &session{identityToken: &ua.UserNameIdentityToken{UserName: "olivia"}}
	req := &ua.WriteRequest{RequestHeader: reqHeader(), NodesToWrite: []*ua.WriteValue{
		{NodeID: n.ID(), AttributeID: ua.AttributeIDValue, Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int32(5))}},
	}}
	old := []*ua.Variant{ua.MustVariant(int32(1))}
	s.auditWrite(sess, req, old, []ua.StatusCode{ua.StatusBadOutOfRange})
	evs := audits(id.AuditWriteUpdateEventType)
	require.Len(t, evs, 1)
	require.Equal(t, false, fieldOf(evs[0], "Status"))
	require.Equal(t, "olivia", fieldOf(evs[0], "ClientUserId"))
	require.Equal(t, int32(1), fieldOf(evs[0], "OldValue"))
	// Not audited: nothing.
	s.auditWrite(sess, req, nil, []ua.StatusCode{ua.StatusOK})
	require.Empty(t, audits(id.AuditWriteUpdateEventType))
}

// TestAuditWriteOldValue: the value a WriteValue replaces.
func TestAuditWriteOldValue(t *testing.T) {
	s := newTestServer()
	ns, _ := addTestNamespace(s)
	arr := ns.AddNewVariableStringNode("arr", []int32{1, 2, 3})
	require.Equal(t, []int32{3}, writeOldValue(ns, &ua.WriteValue{NodeID: arr.ID(), AttributeID: ua.AttributeIDValue, IndexRange: "2"}).Value())
	require.Nil(t, writeOldValue(ns, &ua.WriteValue{NodeID: arr.ID(), AttributeID: ua.AttributeIDValue, IndexRange: "7"}))
	require.Nil(t, writeOldValue(ns, &ua.WriteValue{NodeID: ua.NewStringNodeID(ns.ID(), "nosuch"), AttributeID: ua.AttributeIDValue}))
}

// TestAuditOff: without auditing, and with WithChangeAuditing(false), the
// services report nothing.
func TestAuditOff(t *testing.T) {
	for name, off := range map[string]func(*Server){
		"auditing off":     func(s *Server) { s.SetAuditing(false) },
		"change audit off": func(s *Server) { require.NoError(t, WithChangeAuditing(false)(s.cfg)) },
	} {
		s, _, audits := auditTestServer(t)
		off(s)
		ns, _ := addTestNamespace(s)
		svc := &AttributeService{srv: s}
		_, err := svc.Write(context.Background(), nil, &ua.WriteRequest{RequestHeader: reqHeader(), NodesToWrite: []*ua.WriteValue{
			{NodeID: ua.NewStringNodeID(ns.ID(), "rw_int32"), AttributeID: ua.AttributeIDValue, Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int32(7))}},
		}}, 1)
		require.NoError(t, err)
		_, err = svc.HistoryUpdate(context.Background(), nil, &ua.HistoryUpdateRequest{RequestHeader: reqHeader(),
			HistoryUpdateDetails: []*ua.ExtensionObject{ua.NewExtensionObject(&ua.DeleteAtTimeDetails{NodeID: ua.NewStringNodeID(ns.ID(), "rw_int32")})}}, 2)
		require.NoError(t, err)
		s.changeServiceDone(nil, &ua.AddNodesRequest{RequestHeader: reqHeader()}, nil, ua.StatusBadServiceUnsupported)
		for _, typ := range []uint32{id.AuditWriteUpdateEventType, id.AuditHistoryAtTimeDeleteEventType, id.AuditAddNodesEventType} {
			require.Empty(t, audits(typ), name)
		}
	}
}

// TestAuditServiceFault: a request refused as a whole is one audit event.
func TestAuditServiceFault(t *testing.T) {
	s, _, audits := auditTestServer(t)
	sess := &session{identityToken: &ua.AnonymousIdentityToken{}}
	s.changeServiceDone(sess, &ua.WriteRequest{RequestHeader: reqHeader()}, nil, ua.StatusBadTooManyOperations)
	evs := audits(id.AuditWriteUpdateEventType)
	require.Len(t, evs, 1)
	require.Equal(t, false, fieldOf(evs[0], "Status"))
	require.Equal(t, "Anonymous", fieldOf(evs[0], "ClientUserId"))
	require.Equal(t, uint32(0), fieldOf(evs[0], "AttributeId"))
	require.Equal(t, uint32(id.Server), fieldOf(evs[0], "SourceNode").(*ua.NodeID).IntID())

	s.changeServiceDone(nil, &ua.HistoryUpdateRequest{RequestHeader: reqHeader()}, nil, ua.StatusBadSessionNotActivated)
	evs = audits(id.AuditHistoryUpdateEventType)
	require.Len(t, evs, 1)
	require.Nil(t, fieldOf(evs[0], "ParameterDataTypeId"))

	// A handled request is audited by the handler.
	s.changeServiceDone(nil, &ua.WriteRequest{RequestHeader: reqHeader()}, &ua.WriteResponse{}, nil)
	s.changeServiceDone(nil, &ua.HistoryUpdateRequest{RequestHeader: reqHeader()}, &ua.HistoryUpdateResponse{}, nil)
	s.changeServiceDone(nil, &ua.ReadRequest{RequestHeader: reqHeader()}, nil, ua.StatusBadTooManyOperations)
	require.Empty(t, audits(id.AuditWriteUpdateEventType))
	require.Empty(t, audits(id.AuditHistoryUpdateEventType))
}

// TestAuditNodeManagement: one event per call with the items of the
// request (Part 4 §6.5.7, Part 5 §6.4.19 to §6.4.23).
func TestAuditNodeManagement(t *testing.T) {
	s, _, audits := auditTestServer(t)
	ok := ua.StatusOK
	item := &ua.AddNodesItem{BrowseName: &ua.QualifiedName{Name: "x"}}
	s.changeServiceDone(nil, &ua.AddNodesRequest{RequestHeader: reqHeader(), NodesToAdd: []*ua.AddNodesItem{item, nil}},
		&ua.AddNodesResponse{Results: []*ua.AddNodesResult{{StatusCode: ok}, nil}}, nil)
	evs := audits(id.AuditAddNodesEventType)
	require.Len(t, evs, 1)
	require.Equal(t, "NodeManagement/AddNodes", fieldOf(evs[0], "SourceName"))
	require.Equal(t, false, fieldOf(evs[0], "Status"))
	require.Contains(t, fieldOf(evs[0], "Message").(*ua.LocalizedText).Text, "1 of 2 failed")
	nodes := fieldOf(evs[0], "NodesToAdd").([]*ua.ExtensionObject)
	require.Len(t, nodes, 2)
	require.Equal(t, item, nodes[0].Value)
	require.Nil(t, nodes[1].Value)

	s.changeServiceDone(nil, &ua.DeleteNodesRequest{RequestHeader: reqHeader(), NodesToDelete: []*ua.DeleteNodesItem{{}}},
		&ua.DeleteNodesResponse{Results: []ua.StatusCode{ok}}, nil)
	evs = audits(id.AuditDeleteNodesEventType)
	require.Len(t, evs, 1)
	require.Equal(t, true, fieldOf(evs[0], "Status"))
	require.Equal(t, "NodeManagement/DeleteNodes", fieldOf(evs[0], "SourceName"))
	require.Len(t, fieldOf(evs[0], "NodesToDelete"), 1)

	s.changeServiceDone(nil, &ua.AddReferencesRequest{RequestHeader: reqHeader(), ReferencesToAdd: []*ua.AddReferencesItem{{}}},
		&ua.AddReferencesResponse{Results: []ua.StatusCode{ua.StatusBadNodeIDUnknown}}, nil)
	evs = audits(id.AuditAddReferencesEventType)
	require.Len(t, evs, 1)
	require.Equal(t, false, fieldOf(evs[0], "Status"))
	require.Len(t, fieldOf(evs[0], "ReferencesToAdd"), 1)

	// Refused as a whole: the items, Status false, no response.
	s.changeServiceDone(nil, &ua.DeleteReferencesRequest{RequestHeader: reqHeader(), ReferencesToDelete: []*ua.DeleteReferencesItem{{}}},
		nil, ua.StatusBadServiceUnsupported)
	evs = audits(id.AuditDeleteReferencesEventType)
	require.Len(t, evs, 1)
	require.Equal(t, false, fieldOf(evs[0], "Status"))
	require.Contains(t, fieldOf(evs[0], "Message").(*ua.LocalizedText).Text, "DeleteReferences: ")
	require.Len(t, fieldOf(evs[0], "ReferencesToDelete"), 1)
	// A response with fewer results than items.
	s.changeServiceDone(nil, &ua.DeleteReferencesRequest{RequestHeader: reqHeader(), ReferencesToDelete: []*ua.DeleteReferencesItem{{}}},
		&ua.DeleteReferencesResponse{}, nil)
	evs = audits(id.AuditDeleteReferencesEventType)
	require.Len(t, evs, 1)
	require.Equal(t, false, fieldOf(evs[0], "Status"))
}

func auditHistoryUpdateCall(t *testing.T, svc *AttributeService, details ...any) []*ua.HistoryUpdateResult {
	t.Helper()
	eos := make([]*ua.ExtensionObject, len(details))
	for i, d := range details {
		if d != nil {
			eos[i] = ua.NewExtensionObject(d)
		}
	}
	resp, err := svc.HistoryUpdate(context.Background(), nil, &ua.HistoryUpdateRequest{RequestHeader: reqHeader(), HistoryUpdateDetails: eos}, 1)
	require.NoError(t, err)
	return resp.(*ua.HistoryUpdateResponse).Results
}

func sample(ts time.Time, v float64) *ua.DataValue {
	return &ua.DataValue{EncodingMask: ua.DataValueValue | ua.DataValueSourceTimestamp, Value: ua.MustVariant(v), SourceTimestamp: ts}
}

// TestAuditHistoryUpdate: the AuditHistoryUpdateEventType subtype of each
// HistoryUpdateDetails (Part 11 §5.8), with the values before the update.
func TestAuditHistoryUpdate(t *testing.T) {
	s, h, audits := auditTestServer(t)
	svc := &AttributeService{srv: s}
	node := ua.NewStringNodeID(2, "Hist.Audit")
	h.EnableNode(node, 100)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range 5 {
		h.RecordValue(node, sample(base.Add(time.Duration(i)*time.Second), float64(i)))
	}

	// UpdateData Replace: the value replaced is the OldValue.
	res := auditHistoryUpdateCall(t, svc, &ua.UpdateDataDetails{NodeID: node, PerformInsertReplace: ua.PerformUpdateTypeReplace,
		UpdateValues: []*ua.DataValue{sample(base.Add(time.Second), 10)}})
	require.Equal(t, ua.StatusOK, res[0].StatusCode)
	evs := audits(id.AuditHistoryValueUpdateEventType)
	require.Len(t, evs, 1)
	e := evs[0]
	require.Equal(t, "Attribute/HistoryUpdate", fieldOf(e, "SourceName"))
	require.Equal(t, true, fieldOf(e, "Status"))
	require.Equal(t, node.String(), fieldOf(e, "UpdatedNode").(*ua.NodeID).String())
	require.Equal(t, node.String(), fieldOf(e, "SourceNode").(*ua.NodeID).String())
	require.Equal(t, uint32(id.UpdateDataDetails), fieldOf(e, "ParameterDataTypeId").(*ua.NodeID).IntID())
	require.Equal(t, int32(ua.PerformUpdateTypeReplace), fieldOf(e, "PerformInsertReplace"))
	old := fieldOf(e, "OldValues").([]*ua.DataValue)
	require.Len(t, old, 1)
	require.Equal(t, 1.0, old[0].Value.Value())
	require.Equal(t, 10.0, fieldOf(e, "NewValues").([]*ua.DataValue)[0].Value.Value())

	// Insert of an existing value: failed, no OldValues.
	auditHistoryUpdateCall(t, svc, &ua.UpdateDataDetails{NodeID: node, PerformInsertReplace: ua.PerformUpdateTypeInsert,
		UpdateValues: []*ua.DataValue{sample(base, 10)}})
	e = audits(id.AuditHistoryValueUpdateEventType)[0]
	require.Equal(t, false, fieldOf(e, "Status"))
	require.Empty(t, fieldOf(e, "OldValues"))
	require.Contains(t, fieldOf(e, "Message").(*ua.LocalizedText).Text, "UpdateData Insert of "+node.String()+": ")

	// DeleteAtTime and DeleteRawModified: the values deleted.
	auditHistoryUpdateCall(t, svc, &ua.DeleteAtTimeDetails{NodeID: node, ReqTimes: []time.Time{base.Add(2 * time.Second), base.Add(time.Hour)}})
	e = audits(id.AuditHistoryAtTimeDeleteEventType)[0]
	require.Equal(t, false, fieldOf(e, "Status"))
	require.Len(t, fieldOf(e, "OldValues"), 1)
	require.Len(t, fieldOf(e, "ReqTimes"), 2)
	auditHistoryUpdateCall(t, svc, &ua.DeleteAtTimeDetails{NodeID: node})
	e = audits(id.AuditHistoryAtTimeDeleteEventType)[0]
	require.Empty(t, fieldOf(e, "ReqTimes"))
	require.Empty(t, fieldOf(e, "OldValues"))

	auditHistoryUpdateCall(t, svc, &ua.DeleteRawModifiedDetails{NodeID: node, StartTime: base.Add(3 * time.Second), EndTime: base.Add(3 * time.Second)})
	e = audits(id.AuditHistoryRawModifyDeleteEventType)[0]
	require.Equal(t, true, fieldOf(e, "Status"))
	require.Equal(t, 3.0, fieldOf(e, "OldValues").([]*ua.DataValue)[0].Value.Value())
	require.Equal(t, false, fieldOf(e, "IsDeleteModified"))
	auditHistoryUpdateCall(t, svc, &ua.DeleteRawModifiedDetails{NodeID: node, IsDeleteModified: true, StartTime: base, EndTime: base.Add(time.Hour)})
	e = audits(id.AuditHistoryRawModifyDeleteEventType)[0]
	require.Equal(t, false, fieldOf(e, "Status"))
	require.Empty(t, fieldOf(e, "OldValues"))
	// A range the server refuses: audited as failed.
	auditHistoryUpdateCall(t, svc, &ua.DeleteRawModifiedDetails{NodeID: node, StartTime: base.Add(time.Hour), EndTime: base})
	require.Len(t, audits(id.AuditHistoryRawModifyDeleteEventType), 1)

	// Unknown and missing details: AuditHistoryUpdateEventType.
	auditHistoryUpdateCall(t, svc, &ua.ReadRawModifiedDetails{}, nil)
	evs = audits(id.AuditHistoryUpdateEventType)
	require.Len(t, evs, 2)
	require.Equal(t, false, fieldOf(evs[0], "Status"))
	require.Nil(t, fieldOf(evs[0], "ParameterDataTypeId"))
	require.Equal(t, uint32(id.Server), fieldOf(evs[1], "SourceNode").(*ua.NodeID).IntID())

	// Value forms of the details.
	auditHistoryUpdateCall(t, svc, ua.UpdateDataDetails{NodeID: node, PerformInsertReplace: ua.PerformUpdateTypeUpdate,
		UpdateValues: []*ua.DataValue{sample(base.Add(time.Second), 11)}}, ua.DeleteAtTimeDetails{NodeID: node},
		ua.DeleteRawModifiedDetails{NodeID: node, StartTime: base, EndTime: base})
	require.Len(t, audits(id.AuditHistoryValueUpdateEventType), 1)
	require.Len(t, audits(id.AuditHistoryAtTimeDeleteEventType), 1)
	require.Len(t, audits(id.AuditHistoryRawModifyDeleteEventType), 1)
}

// TestAuditHistoryEvents: AuditHistoryEventUpdateEventType names the
// EventIds of the inserted events (Part 11 §5.8.1);
// AuditHistoryEventDeleteEventType has the EventIds deleted.
func TestAuditHistoryEvents(t *testing.T) {
	s, _, audits := auditTestServer(t)
	svc := &AttributeService{srv: s}
	// The history of the Server object, which keeps the audit events too.
	obj := s.Node(ua.NewNumericNodeID(0, id.Server))
	require.NoError(t, s.EnableEventHistory(obj.ID(), EventHistoryOptions{Writable: true}))
	filter := ua.NewEventFilter().Select("EventId", "EventType", "Time", "Message").Build()
	eventID := []byte{1, 2, 3}
	res := auditHistoryUpdateCall(t, svc, &ua.UpdateEventDetails{NodeID: obj.ID(), PerformInsertReplace: ua.PerformUpdateTypeInsert, Filter: filter,
		EventData: []*ua.HistoryEventFieldList{{EventFields: []*ua.Variant{
			ua.MustVariant(eventID), ua.MustVariant(ua.NewNumericNodeID(0, id.BaseEventType)), ua.MustVariant(time.Now()),
			ua.MustVariant(ua.NewLocalizedText("inserted")),
		}}}})
	require.Equal(t, ua.StatusGoodEntryInserted, res[0].OperationResults[0])
	e := audits(id.AuditHistoryEventUpdateEventType)[0]
	require.Equal(t, true, fieldOf(e, "Status"))
	require.Contains(t, fieldOf(e, "Message").(*ua.LocalizedText).Text, "inserted EventIds 010203")
	require.Equal(t, filter, fieldOf(e, "Filter").(*ua.ExtensionObject).Value)
	require.Len(t, fieldOf(e, "NewValues"), 1)
	require.Empty(t, fieldOf(e, "OldValues"))

	// Without a filter: refused, an empty Filter.
	auditHistoryUpdateCall(t, svc, ua.UpdateEventDetails{NodeID: obj.ID(), PerformInsertReplace: ua.PerformUpdateTypeInsert})
	e = audits(id.AuditHistoryEventUpdateEventType)[0]
	require.Equal(t, false, fieldOf(e, "Status"))
	require.Nil(t, fieldOf(e, "Filter").(*ua.ExtensionObject).Value)

	auditHistoryUpdateCall(t, svc, &ua.DeleteEventDetails{NodeID: obj.ID(), EventIDs: [][]byte{eventID}}, ua.DeleteEventDetails{NodeID: obj.ID()})
	evs := audits(id.AuditHistoryEventDeleteEventType)
	require.Len(t, evs, 2)
	require.Equal(t, true, fieldOf(evs[0], "Status"))
	require.Equal(t, [][]byte{eventID}, fieldOf(evs[0], "EventIds"))
	require.Empty(t, fieldOf(evs[1], "EventIds"))
}

func TestHistoryResultOK(t *testing.T) {
	ok, st := historyResultOK(nil)
	require.False(t, ok)
	require.Equal(t, ua.StatusBadInternalError, st)
	ok, _ = historyResultOK(&ua.HistoryUpdateResult{OperationResults: []ua.StatusCode{ua.StatusGoodEntryInserted}})
	require.True(t, ok)
	require.Equal(t, "Remove", performName(ua.PerformUpdateTypeRemove))
	require.Equal(t, "PerformUpdateType 9", performName(9))
	require.Equal(t, "null", nodeName(nil))
	require.Nil(t, oldRawValues(nil, nil, nil))
	require.Empty(t, valueTimes([]*ua.DataValue{nil, {}}))
	require.Equal(t, uint32(0), historyDetailsType(nil))
	require.Nil(t, historyDetails(nil))
}

// failingProvider is a raw history whose reads fail.
type failingProvider struct{}

func (failingProvider) ReleaseContinuation([]byte) {}

func (failingProvider) ReadRaw(*ua.NodeID, time.Time, time.Time, uint32, bool, []byte) (*ua.HistoryReadResult, error) {
	return &ua.HistoryReadResult{StatusCode: ua.StatusBadInternalError}, nil
}

func TestAuditOldValuesUnavailable(t *testing.T) {
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	require.Nil(t, oldRawValues(failingProvider{}, ua.NewStringNodeID(1, "x"), []time.Time{ts}))
	require.Nil(t, oldRawRange(failingProvider{}, ua.NewStringNodeID(1, "x"), ts, ts.Add(time.Second)))
	require.Equal(t, ts, minTime(ts.Add(time.Second), ts))
	require.Equal(t, ts.Add(time.Second), maxTime(ts, ts.Add(time.Second)))
}
