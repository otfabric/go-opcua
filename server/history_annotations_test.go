// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server/aggregate"
	"github.com/otfabric/go-opcua/ua"
)

var annBase = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func annAt(s int) time.Time { return annBase.Add(time.Duration(s) * time.Second) }

func annValue(s int, msg string) *ua.DataValue {
	return annotationValue(&ua.Annotation{Message: msg, UserName: "op", AnnotationTime: annAt(1000)}, annAt(s))
}

// annotationServer returns a test server with a Historian, a historized
// Variable with the Annotations Property and four samples.
func annotationServer(t *testing.T) (*Server, *AttributeService, *Historian, *Node) {
	t.Helper()
	s := newTestServer()
	ns, _ := addTestNamespace(s)
	v := ns.AddNewVariableStringNode("annotated", 0.0)
	h := NewHistorian()
	h.EnableNode(v.ID(), 10)
	for i := range 4 {
		h.RecordValue(v.ID(), sample(annAt(i), float64(i)))
	}
	s.SetHistorian(h)
	require.NoError(t, s.EnableAnnotations(v.ID()))
	return s, &AttributeService{srv: s}, h, v
}

func annotationProp(t *testing.T, s *Server, n *Node) *Node {
	t.Helper()
	p := s.annotationsProperty(n)
	require.NotNil(t, p)
	return p
}

func updateAnn(t *testing.T, svc *AttributeService, node *ua.NodeID, perform ua.PerformUpdateType, values ...*ua.DataValue) *ua.HistoryUpdateResult {
	t.Helper()
	resp, err := svc.HistoryUpdate(context.Background(), nil, &ua.HistoryUpdateRequest{RequestHeader: reqHeader(),
		HistoryUpdateDetails: []*ua.ExtensionObject{ua.NewExtensionObject(&ua.UpdateStructureDataDetails{NodeID: node, PerformInsertReplace: perform, UpdateValues: values})}}, 1)
	require.NoError(t, err)
	return resp.(*ua.HistoryUpdateResponse).Results[0]
}

func historyRead(t *testing.T, svc *AttributeService, details any, nodes ...*ua.HistoryReadValueID) []*ua.HistoryReadResult {
	t.Helper()
	resp, err := svc.HistoryRead(context.Background(), nil, &ua.HistoryReadRequest{RequestHeader: reqHeader(),
		HistoryReadDetails: ua.NewExtensionObject(details), TimestampsToReturn: ua.TimestampsToReturnSource, NodesToRead: nodes}, 1)
	require.NoError(t, err)
	return resp.(*ua.HistoryReadResponse).Results
}

func annotationMessages(t *testing.T, res *ua.HistoryReadResult) []string {
	t.Helper()
	require.Equal(t, ua.StatusOK, res.StatusCode)
	var out []string
	for _, dv := range historyDataValues(res) {
		if a := annotationOf(dv); a != nil {
			out = append(out, a.Message)
		} else {
			out = append(out, dv.Status.Error())
		}
	}
	return out
}

// TestEnableAnnotations: the Annotations Property (Part 11 §5.1.2, Table
// 2) on Variables and Objects only, once.
func TestEnableAnnotations(t *testing.T) {
	s, _, _, v := annotationServer(t)
	p := annotationProp(t, s, v)
	require.Equal(t, &ua.QualifiedName{Name: "Annotations"}, p.BrowseName())
	dt, err := p.Attribute(ua.AttributeIDDataType)
	require.NoError(t, err)
	require.Equal(t, uint32(id.Annotation), dt.Value.Value.Value().(*ua.ExpandedNodeID).NodeID.IntID())
	require.Nil(t, p.Value().Value.Value())
	require.True(t, isProperty(p))
	require.Equal(t, v.ID(), s.annotationsOwner(p).ID())
	require.Equal(t, v.ID(), s.annotationsPropertyOwner(p.ID()))

	// Again: the same Property.
	require.NoError(t, s.EnableAnnotations(v.ID()))
	require.Equal(t, p.ID(), annotationProp(t, s, v).ID())

	require.ErrorIs(t, s.EnableAnnotations(nil), ua.StatusBadNodeIDInvalid)
	require.ErrorIs(t, s.EnableAnnotations(ua.NewStringNodeID(99, "x")), ua.StatusBadNodeIDUnknown)
	require.ErrorIs(t, s.EnableAnnotations(ua.NewStringNodeID(v.ID().Namespace(), "nosuch")), ua.StatusBadNodeIDUnknown)
	require.ErrorIs(t, s.EnableAnnotations(ua.NewNumericNodeID(0, id.HasComponent)), ua.StatusBadNodeClassInvalid)
	require.ErrorIs(t, s.EnableAnnotations(p.ID()), ua.StatusBadNodeClassInvalid)
	// A node of namespace 0.
	require.NoError(t, s.EnableAnnotations(ua.NewNumericNodeID(0, id.ServerServerStatus)))
	require.NotNil(t, s.annotationsProperty(s.Node(ua.NewNumericNodeID(0, id.ServerServerStatus))))

	require.Nil(t, s.annotationsPropertyOwner(nil))
	require.Nil(t, s.annotationsPropertyOwner(ua.NewStringNodeID(v.ID().Namespace(), "nosuch")))
	require.Nil(t, s.annotationsPropertyOwner(v.ID()))

	// A node named Annotations whose owner is gone.
	ns, _ := s.Namespace(int(v.ID().Namespace()))
	orphan := NewNode(ua.NewStringNodeID(v.ID().Namespace(), "orphan"), Attributes{
		ua.AttributeIDNodeClass:  DataValueFromValue(uint32(ua.NodeClassVariable)),
		ua.AttributeIDBrowseName: DataValueFromValue(&ua.QualifiedName{Name: "Annotations"}),
	}, nil, nil)
	orphan = ns.AddNode(orphan)
	orphan.AddRef(NewNode(ua.NewStringNodeID(v.ID().Namespace(), "gone"), nil, nil, nil), RefType(id.HasProperty), false)
	require.Nil(t, s.annotationsOwner(orphan))
}

// TestAnnotationsUpdate: UpdateStructureDataDetails (Part 11 §6.9.3) on
// the node and on its Annotations Property, read back with
// ReadAnnotationDataDetails (§6.5.6) and with a raw read of the Property
// (§5.1.2).
func TestAnnotationsUpdate(t *testing.T) {
	s, svc, _, v := annotationServer(t)
	p := annotationProp(t, s, v)

	res := updateAnn(t, svc, v.ID(), ua.PerformUpdateTypeInsert, annValue(1, "one"), annValue(2, "two"), nil,
		&ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(1.0), SourceTimestamp: annAt(3)},
		&ua.DataValue{SourceTimestamp: annAt(3)})
	require.Equal(t, []ua.StatusCode{ua.StatusGoodEntryInserted, ua.StatusGoodEntryInserted, ua.StatusBadInvalidArgument,
		ua.StatusBadTypeMismatch, ua.StatusBadTypeMismatch}, res.OperationResults)
	res = updateAnn(t, svc, p.ID(), ua.PerformUpdateTypeInsert, annValue(1, "again"))
	require.Equal(t, []ua.StatusCode{ua.StatusBadEntryExists}, res.OperationResults)
	res = updateAnn(t, svc, p.ID(), ua.PerformUpdateTypeReplace, annValue(1, "uno"), annValue(5, "five"))
	require.Equal(t, []ua.StatusCode{ua.StatusGoodEntryReplaced, ua.StatusBadNoEntryExists}, res.OperationResults)
	res = updateAnn(t, svc, v.ID(), ua.PerformUpdateTypeUpdate, annValue(2, "dos"), annValue(3, "tres"))
	require.Equal(t, []ua.StatusCode{ua.StatusGoodEntryReplaced, ua.StatusGoodEntryInserted}, res.OperationResults)

	read := historyRead(t, svc, &ua.ReadAnnotationDataDetails{ReqTimes: []time.Time{annAt(3), annAt(0), annAt(1)}},
		&ua.HistoryReadValueID{NodeID: v.ID()}, &ua.HistoryReadValueID{NodeID: p.ID()})
	require.Equal(t, []string{"tres", ua.StatusBadNoData.Error(), "uno"}, annotationMessages(t, read[0]))
	require.Equal(t, []string{"tres", ua.StatusBadNoData.Error(), "uno"}, annotationMessages(t, read[1]))

	// The Annotation keeps what the client gave; an empty userName and
	// annotationTime are filled.
	got := annotationOf(historyDataValues(read[0])[0])
	require.Equal(t, "op", got.UserName)
	require.Equal(t, annAt(1000), got.AnnotationTime)
	res = updateAnn(t, svc, v.ID(), ua.PerformUpdateTypeInsert, annotationValue(&ua.Annotation{Message: "blank"}, annAt(7)))
	require.Equal(t, ua.StatusGoodEntryInserted, res.OperationResults[0])
	got = annotationOf(historyDataValues(historyRead(t, svc, &ua.ReadAnnotationDataDetails{ReqTimes: []time.Time{annAt(7)}}, &ua.HistoryReadValueID{NodeID: v.ID()})[0])[0])
	require.Equal(t, "", got.UserName)
	require.False(t, got.AnnotationTime.IsZero())

	// The raw read of the Property: the Annotations in time order, in
	// pages; a modified read is not supported.
	raw := historyRead(t, svc, &ua.ReadRawModifiedDetails{StartTime: annAt(0), EndTime: annAt(10), NumValuesPerNode: 2}, &ua.HistoryReadValueID{NodeID: p.ID()})
	require.Equal(t, []string{"uno", "dos"}, annotationMessages(t, raw[0]))
	require.NotEmpty(t, raw[0].ContinuationPoint)
	raw = historyRead(t, svc, &ua.ReadRawModifiedDetails{StartTime: annAt(0), EndTime: annAt(10), NumValuesPerNode: 2},
		&ua.HistoryReadValueID{NodeID: p.ID(), ContinuationPoint: raw[0].ContinuationPoint})
	require.Equal(t, []string{"tres", "blank"}, annotationMessages(t, raw[0]))
	mod := historyRead(t, svc, ua.ReadRawModifiedDetails{IsReadModified: true, StartTime: annAt(0), EndTime: annAt(10)}, &ua.HistoryReadValueID{NodeID: p.ID()})
	require.Equal(t, ua.StatusBadHistoryOperationUnsupported, mod[0].StatusCode)

	// A raw read of the node: the samples with an Annotation have the Extra
	// Data bit (Part 4 §7.38.1).
	raw = historyRead(t, svc, &ua.ReadRawModifiedDetails{StartTime: annAt(0), EndTime: annAt(10)}, &ua.HistoryReadValueID{NodeID: v.ID()})
	samples := historyDataValues(raw[0])
	require.Len(t, samples, 4)
	require.Zero(t, samples[0].Status&ua.StatusCodeHistorianExtraData)
	for _, dv := range samples[1:] {
		require.Equal(t, ua.StatusCodeHistorianExtraData|ua.StatusCodeInfoTypeDataValue, dv.Status, dv.SourceTimestamp)
	}

	// Remove.
	res = updateAnn(t, svc, v.ID(), ua.PerformUpdateTypeRemove, &ua.DataValue{SourceTimestamp: annAt(1)}, &ua.DataValue{SourceTimestamp: annAt(9)})
	require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusBadNoEntryExists}, res.OperationResults)

	// The details as a value, an invalid PerformUpdateType, nothing valid.
	resp, err := svc.HistoryUpdate(context.Background(), nil, &ua.HistoryUpdateRequest{RequestHeader: reqHeader(),
		HistoryUpdateDetails: []*ua.ExtensionObject{ua.NewExtensionObject(ua.UpdateStructureDataDetails{NodeID: v.ID(), PerformInsertReplace: ua.PerformUpdateTypeRemove,
			UpdateValues: []*ua.DataValue{{SourceTimestamp: annAt(2)}}})}}, 1)
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, resp.(*ua.HistoryUpdateResponse).Results[0].OperationResults)
	require.Equal(t, ua.StatusBadInvalidArgument, updateAnn(t, svc, v.ID(), 9, annValue(1, "x")).StatusCode)
	res = updateAnn(t, svc, v.ID(), ua.PerformUpdateTypeInsert, nil)
	require.Equal(t, ua.StatusOK, res.StatusCode)
	require.Equal(t, []ua.StatusCode{ua.StatusBadInvalidArgument}, res.OperationResults)
}

// TestAnnotationsUnsupported: a node without the Annotations Property, a
// provider without Annotations, access.
func TestAnnotationsUnsupported(t *testing.T) {
	s, svc, h, v := annotationServer(t)
	ns, _ := s.Namespace(int(v.ID().Namespace()))
	plain := ns.(*NodeNameSpace).AddNewVariableStringNode("plain", 1.0)
	h.EnableNode(plain.ID(), 10)
	require.Equal(t, ua.StatusBadHistoryOperationUnsupported, updateAnn(t, svc, plain.ID(), ua.PerformUpdateTypeInsert, annValue(1, "x")).StatusCode)
	read := historyRead(t, svc, &ua.ReadAnnotationDataDetails{ReqTimes: []time.Time{annAt(1)}}, &ua.HistoryReadValueID{NodeID: plain.ID()})
	require.Equal(t, ua.StatusBadHistoryOperationUnsupported, read[0].StatusCode)

	// A node the address space does not hold is the provider's: not
	// enabled in the Historian.
	other := ua.NewStringNodeID(5, "provider-only")
	require.Equal(t, ua.StatusBadHistoryOperationUnsupported, updateAnn(t, svc, other, ua.PerformUpdateTypeInsert, annValue(1, "x")).StatusCode)

	// The HistoryWrite bit of the node, of the Property's owner.
	p := annotationProp(t, s, v)
	readOnly := byte(ua.AccessLevelTypeCurrentRead | ua.AccessLevelTypeHistoryRead)
	require.NoError(t, v.SetAttribute(ua.AttributeIDAccessLevel, DataValueFromValue(readOnly)))
	require.Equal(t, ua.StatusBadNotWritable, updateAnn(t, svc, v.ID(), ua.PerformUpdateTypeInsert, annValue(1, "x")).StatusCode)
	require.Equal(t, ua.StatusBadNotWritable, updateAnn(t, svc, p.ID(), ua.PerformUpdateTypeInsert, annValue(1, "x")).StatusCode)
	require.NoError(t, v.SetAttribute(ua.AttributeIDAccessLevel, DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead))))
	raw := historyRead(t, svc, &ua.ReadRawModifiedDetails{StartTime: annAt(0), EndTime: annAt(10)}, &ua.HistoryReadValueID{NodeID: p.ID()})
	require.Equal(t, ua.StatusBadNotReadable, raw[0].StatusCode)
	read = historyRead(t, svc, &ua.ReadAnnotationDataDetails{ReqTimes: []time.Time{annAt(1)}}, &ua.HistoryReadValueID{NodeID: v.ID()})
	require.Equal(t, ua.StatusBadNotReadable, read[0].StatusCode)

	// A provider without Annotations.
	s.SetHistorian(&rawProvider{})
	require.Equal(t, ua.StatusBadHistoryOperationUnsupported, updateAnn(t, svc, v.ID(), ua.PerformUpdateTypeInsert, annValue(1, "x")).StatusCode)
	read = historyRead(t, svc, ua.ReadAnnotationDataDetails{ReqTimes: []time.Time{annAt(1)}}, &ua.HistoryReadValueID{NodeID: p.ID()})
	require.Equal(t, ua.StatusBadHistoryOperationUnsupported, read[0].StatusCode)
}

// annotationOnly is a provider with raw reads and Annotations, no
// processed reads, whose calls can fail.
type annotationOnly struct {
	h       *Historian
	update  *ua.HistoryUpdateResult
	nilRes  bool
	readErr error
	rawErr  error
}

func (p *annotationOnly) ReadRaw(n *ua.NodeID, a, b time.Time, nv uint32, bounds bool, cp []byte) (*ua.HistoryReadResult, error) {
	return p.h.ReadRaw(n, a, b, nv, bounds, cp)
}
func (p *annotationOnly) ReleaseContinuation(cp []byte)                 { p.h.ReleaseContinuation(cp) }
func (p *annotationOnly) RecordEvent(n *ua.NodeID, ev *HistoricalEvent) { p.h.RecordEvent(n, ev) }
func (p *annotationOnly) ReadEvents(n *ua.NodeID, a, b time.Time, nv uint32, match func(*HistoricalEvent) bool, cp []byte) ([]*HistoricalEvent, []byte, ua.StatusCode) {
	return p.h.ReadEvents(n, a, b, nv, match, cp)
}
func (p *annotationOnly) UpdateAnnotations(n *ua.NodeID, perform ua.PerformUpdateType, values []*ua.DataValue) *ua.HistoryUpdateResult {
	if p.nilRes {
		return nil
	}
	if p.update != nil {
		return p.update
	}
	return p.h.UpdateAnnotations(n, perform, values)
}
func (p *annotationOnly) ReadAnnotations(n *ua.NodeID, times []time.Time) (*ua.HistoryReadResult, error) {
	if p.readErr != nil {
		return nil, p.readErr
	}
	return p.h.ReadAnnotations(n, times)
}
func (p *annotationOnly) ReadRawAnnotations(n *ua.NodeID, a, b time.Time, nv uint32, cp []byte) (*ua.HistoryReadResult, error) {
	if p.rawErr != nil {
		return nil, p.rawErr
	}
	return p.h.ReadRawAnnotations(n, a, b, nv, cp)
}

// TestAnnotationsProvider: the results of a provider the server merges,
// and the audit of what an update replaced.
func TestAnnotationsProvider(t *testing.T) {
	s, svc, h, v := annotationServer(t)
	p := &annotationOnly{h: h}
	s.SetHistorian(p)
	require.Equal(t, ua.StatusGoodEntryInserted, updateAnn(t, svc, v.ID(), ua.PerformUpdateTypeInsert, annValue(1, "one")).OperationResults[0])

	p.nilRes = true
	require.Equal(t, ua.StatusBadInternalError, updateAnn(t, svc, v.ID(), ua.PerformUpdateTypeInsert, annValue(2, "x")).StatusCode)
	p.nilRes, p.update = false, &ua.HistoryUpdateResult{StatusCode: ua.StatusBadOutOfMemory}
	require.Equal(t, ua.StatusBadOutOfMemory, updateAnn(t, svc, v.ID(), ua.PerformUpdateTypeInsert, annValue(2, "x")).StatusCode)
	p.update = &ua.HistoryUpdateResult{StatusCode: ua.StatusOK}
	res := updateAnn(t, svc, v.ID(), ua.PerformUpdateTypeInsert, nil, annValue(2, "x"))
	require.Equal(t, []ua.StatusCode{ua.StatusBadInvalidArgument, ua.StatusBadInternalError}, res.OperationResults)
	p.update = nil

	// Audited: the Annotation replaced is the OldValue, the one written
	// the NewValue.
	s.SetAuditing(true)
	serverObj := ua.NewNumericNodeID(0, id.Server)
	h.EnableEvents(serverObj, 100)
	require.NoError(t, s.EnableEventHistory(serverObj, EventHistoryOptions{}))
	require.Equal(t, ua.StatusGoodEntryReplaced, updateAnn(t, svc, v.ID(), ua.PerformUpdateTypeReplace, annValue(1, "uno")).OperationResults[0])
	require.Equal(t, ua.StatusOK, updateAnn(t, svc, v.ID(), ua.PerformUpdateTypeRemove, &ua.DataValue{SourceTimestamp: annAt(1)}).OperationResults[0])
	p.readErr = errors.New("down")
	require.Equal(t, ua.StatusBadNoEntryExists, updateAnn(t, svc, v.ID(), ua.PerformUpdateTypeRemove, &ua.DataValue{SourceTimestamp: annAt(1)}).OperationResults[0])
	evs, _, _ := h.ReadEvents(serverObj, annBase.Add(-time.Hour*24*365), time.Now().Add(time.Hour), 0, func(e *HistoricalEvent) bool {
		return e.EventType().IntID() == id.AuditHistoryAnnotationUpdateEventType
	}, nil)
	require.Len(t, evs, 3)
	e := evs[0]
	require.Equal(t, true, e.field("Status"))
	require.Equal(t, int32(ua.PerformUpdateTypeReplace), e.field("PerformInsertReplace"))
	require.Equal(t, uint32(id.UpdateStructureDataDetails), e.field("ParameterDataTypeId").(*ua.NodeID).IntID())
	require.Equal(t, "one", e.field("OldValues").([]*ua.ExtensionObject)[0].Value.(*ua.Annotation).Message)
	require.Equal(t, "uno", e.field("NewValues").([]*ua.ExtensionObject)[0].Value.(*ua.Annotation).Message)
	require.Equal(t, v.ID().String(), e.field("SourceNode").(*ua.NodeID).String())
	e = evs[1]
	require.Empty(t, e.field("NewValues"))
	require.Equal(t, "uno", e.field("OldValues").([]*ua.ExtensionObject)[0].Value.(*ua.Annotation).Message)
	e = evs[2]
	require.Equal(t, false, e.field("Status"))
	require.Empty(t, e.field("OldValues"))

	// Reads that fail.
	read := historyRead(t, svc, &ua.ReadAnnotationDataDetails{ReqTimes: []time.Time{annAt(1)}}, &ua.HistoryReadValueID{NodeID: v.ID()})
	require.Equal(t, ua.StatusBadInternalError, read[0].StatusCode)
}

// TestHistorianAnnotations: the Historian's store (Part 11 §6.9.3).
func TestHistorianAnnotations(t *testing.T) {
	h := NewHistorian()
	n := ua.NewStringNodeID(1, "ann")
	require.Equal(t, ua.StatusBadHistoryOperationUnsupported, h.UpdateAnnotations(n, ua.PerformUpdateTypeInsert, nil).StatusCode)
	res, err := h.ReadAnnotations(n, nil)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadHistoryOperationUnsupported, res.StatusCode)
	require.Equal(t, ua.StatusBadInvalidArgument, h.UpdateAnnotations(n, 0, nil).StatusCode)

	h.EnableNode(n, 2)
	// Reads of a node without Annotations.
	res, err = h.ReadRawAnnotations(n, annAt(0), annAt(10), 0, nil)
	require.NoError(t, err)
	require.Empty(t, historyDataValues(res))
	require.Nil(t, h.annotationsOfLocked(n.String()))

	ops := h.UpdateAnnotations(n, ua.PerformUpdateTypeInsert, []*ua.DataValue{annValue(5, "a"), annValue(6, "b"), annValue(1, "old"), annValue(7, "c"), {SourceTimestamp: annAt(8)}}).OperationResults
	require.Equal(t, []ua.StatusCode{ua.StatusGoodEntryInserted, ua.StatusGoodEntryInserted, ua.StatusBadOutOfRange, ua.StatusGoodEntryInserted, ua.StatusBadInvalidArgument}, ops)
	require.Len(t, h.annotationsOfLocked(n.String()), 2)
	// Update inserts too.
	ops = h.UpdateAnnotations(n, ua.PerformUpdateTypeUpdate, []*ua.DataValue{annValue(9, "d")}).OperationResults
	require.Equal(t, []ua.StatusCode{ua.StatusGoodEntryInserted}, ops)

	// A continuation point of an Annotation read is not one of a sample
	// read, nor the other way round.
	res, err = h.ReadRawAnnotations(n, annAt(0), annAt(10), 1, nil)
	require.NoError(t, err)
	require.NotEmpty(t, res.ContinuationPoint)
	res, err = h.ReadRaw(n, annAt(0), annAt(10), 1, false, res.ContinuationPoint)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadContinuationPointInvalid, res.StatusCode)

	// EnableNode starts a new history, without Annotations.
	h.EnableNode(n, 2)
	require.Nil(t, h.annotationsOfLocked(n.String()))
}

// TestAnnotationCount: the AnnotationCount Aggregate (Part 13 §5.4.3.20)
// of the Historian and of a provider without processed reads.
func TestAnnotationCountProcessed(t *testing.T) {
	s, svc, h, v := annotationServer(t)
	updateAnn(t, svc, v.ID(), ua.PerformUpdateTypeInsert, annValue(0, "a"), annValue(1, "b"), annValue(3, "c"))
	details := &ua.ReadProcessedDetails{StartTime: annAt(0), EndTime: annAt(4), ProcessingInterval: 2000,
		AggregateType: []*ua.NodeID{ua.NewNumericNodeID(0, id.AggregateFunctionAnnotationCount)}}
	counts := func() []any {
		res := historyRead(t, svc, details, &ua.HistoryReadValueID{NodeID: v.ID()})
		require.Equal(t, ua.StatusOK, res[0].StatusCode)
		var out []any
		for _, dv := range historyDataValues(res[0]) {
			out = append(out, dv.Value.Value())
		}
		return out
	}
	require.Equal(t, []any{int32(2), int32(1)}, counts())

	p := &annotationOnly{h: h}
	s.SetHistorian(p)
	require.Equal(t, []any{int32(2), int32(1)}, counts())
	p.rawErr = errors.New("down")
	res := historyRead(t, svc, details, &ua.HistoryReadValueID{NodeID: v.ID()})
	require.Equal(t, ua.StatusBadInternalError, res[0].StatusCode)

	// AnnotationCount is historical only: a MonitoredItem cannot use it.
	require.True(t, aggregate.HistoricalOnly(details.AggregateType[0]))
	// The AggregateFunctions folders list it.
	folder := s.Node(ua.NewNumericNodeID(0, id.HistoryServerCapabilitiesAggregateFunctions))
	found := false
	for _, r := range folder.refsSnapshot() {
		if r.NodeID != nil && r.NodeID.NodeID.IntID() == id.AggregateFunctionAnnotationCount {
			found = true
		}
	}
	require.True(t, found)
}

func TestAnnotationHelpers(t *testing.T) {
	require.Nil(t, annotationOf(nil))
	require.Nil(t, annotationOf(&ua.DataValue{}))
	require.Nil(t, annotationOf(&ua.DataValue{Value: ua.MustVariant(1.0)}))
	require.Nil(t, annotationOf(&ua.DataValue{Value: ua.MustVariant(ua.NewExtensionObject(&ua.Range{}))}))
	require.Equal(t, "v", annotationOf(&ua.DataValue{Value: ua.MustVariant(&ua.ExtensionObject{Value: ua.Annotation{Message: "v"}})}).Message)
	require.Equal(t, "", annotationUser(nil))
	require.Equal(t, "", annotationUser(&session{identityToken: &ua.AnonymousIdentityToken{}}))
	require.Equal(t, "olivia", annotationUser(&session{identityToken: &ua.UserNameIdentityToken{UserName: "olivia"}}))
	require.Nil(t, annotationReadDetails(&ua.ReadRawModifiedDetails{}))
	require.Nil(t, rawModifiedDetails(&ua.ReadAtTimeDetails{}))
	require.Nil(t, historyDataValues(&ua.HistoryReadResult{HistoryData: ua.NewExtensionObject(&ua.HistoryModifiedData{})}))
	require.Nil(t, historyDataValues(nil))
	require.False(t, isAnnotationCount(nil))
}
