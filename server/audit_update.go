// SPDX-License-Identifier: MIT

package server

import (
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// Audit events of the services that change the address space or the
// history: Write and HistoryUpdate (Part 4 §6.5.8) and the NodeManagement
// Service Set (Part 4 §6.5.7). Both clauses: Servers "shall generate audit
// Events for both successful and failed Service invocations".
//
// With auditing on ([WithAuditing]) and [WithChangeAuditing] left on, the
// server reports to its Server object:
//
//   - an AuditWriteUpdateEventType (Part 5 §6.4.25) for each WriteValue of
//     a Write, "one per changed value" as Part 5 §6.4.24 has a Service call
//     generate one Event per changed value. SourceNode is the node,
//     SourceName "Attribute/Write"; AttributeId, IndexRange, NewValue (the
//     value written) and OldValue (the value before, limited to the
//     IndexRange; null when there was none);
//   - for each HistoryUpdateDetails of a HistoryUpdate the
//     AuditHistoryUpdateEventType subtype of its operation (Part 11 §5.8):
//     AuditHistoryValueUpdateEventType for UpdateDataDetails,
//     AuditHistoryAnnotationUpdateEventType for UpdateStructureDataDetails,
//     AuditHistoryEventUpdateEventType for UpdateEventDetails,
//     AuditHistoryRawModifyDeleteEventType, AuditHistoryAtTimeDeleteEventType
//     and AuditHistoryEventDeleteEventType for the deletes, and
//     AuditHistoryUpdateEventType itself for details the server does not
//     know. SourceNode is the node, SourceName "Attribute/HistoryUpdate",
//     ParameterDataTypeId the DataType of the details (Part 5 §6.4.26);
//   - an AuditAddNodesEventType, AuditDeleteNodesEventType,
//     AuditAddReferencesEventType or AuditDeleteReferencesEventType (Part 5
//     §6.4.20 to §6.4.23) for each call of AddNodes, DeleteNodes,
//     AddReferences or DeleteReferences, with the items of the request.
//     SourceNode is the Server object, SourceName "NodeManagement/" and the
//     Service (Part 5 §6.4.19).
//
// Status (Part 5 §6.4.3) is true when the operation, or every operation of
// a NodeManagement call, succeeded; the Message says why one failed. A
// Write, HistoryUpdate or NodeManagement request the server refuses as a
// whole (no activated session, too many operations) is reported with one
// event of its type, SourceNode the Server object.
//
// OldValues: the values a HistoryUpdate replaces or deletes are read from
// the provider before the update (ReadRaw of their times, ReadAnnotations);
// Part 11 §5.8 accepts null where they are not available, and they are
// null for an insert, for a modified delete and for events (the
// OldValues of AuditHistoryEventUpdateEventType and
// AuditHistoryEventDeleteEventType: the HistoryEventFieldList needs a
// filter the delete does not have). "When HistoryUpdate inserts historical
// events, the event must contain the EventId of the inserted event" (Part
// 11 §5.8.1): the Message of AuditHistoryEventUpdateEventType lists the
// EventIds of the inserted events.

// WithChangeAuditing sets whether a server with auditing on
// ([WithAuditing]) reports the audit events of Write, HistoryUpdate,
// AddNodes, DeleteNodes, AddReferences and DeleteReferences (Part 4 §6.5.7,
// §6.5.8). It is on by default; WithChangeAuditing(false) restores the
// behaviour of v1.42, which reported the audit events of the SecureChannel,
// Session and Method services only. A server without auditing reports none
// either way.
func WithChangeAuditing(enabled bool) Option {
	return func(c *serverConfig) error {
		c.changeAuditOff = !enabled
		return nil
	}
}

// auditsChanges reports whether the server reports the audit events of the
// services that change the address space or the history.
func (s *Server) auditsChanges() bool {
	return s.auditing.Load() && !s.cfg.changeAuditOff
}

// Source names of the audit events (Part 5 §6.4.19, §6.4.24).
const (
	auditSourceWrite         = "Attribute/Write"
	auditSourceHistoryUpdate = "Attribute/HistoryUpdate"
	auditSourceNodeMgmt      = "NodeManagement/"
)

// changeAuditEvent builds an AuditEventType event (Part 5 §6.4.3) of type
// typ of a session's request.
func (s *Server) changeAuditEvent(typ uint32, source string, sourceNode *ua.NodeID, msg string, ok bool, sess *session, hdr *ua.RequestHeader) *BaseEvent {
	now := s.now()
	user := ""
	if sess != nil {
		user = auditUserID(sess.identityToken)
	}
	if sourceNode == nil {
		sourceNode = ua.NewNumericNodeID(0, id.Server)
	}
	return &BaseEvent{
		EventID:    newEventID(),
		EventType:  ua.NewNumericNodeID(0, typ),
		SourceNode: sourceNode,
		SourceName: source,
		Time:       now,
		Message:    ua.NewLocalizedTextWithLocale(msg, "en"),
		Severity:   100,
		Fields: map[string]*ua.Variant{
			"ActionTimeStamp":    ua.MustVariant(now),
			"Status":             ua.MustVariant(ok),
			"ServerId":           ua.MustVariant(s.cfg.applicationURI),
			"ClientAuditEntryId": ua.MustVariant(auditEntryOf(hdr)),
			"ClientUserId":       ua.MustVariant(user),
		},
		audit: true,
	}
}

// failure is the Message suffix of an operation that failed with st.
func failure(st ua.StatusCode) string {
	if isBad(st) {
		return ": " + st.Error()
	}
	return ""
}

// variantOrNull returns v, a null Variant for nil.
func variantOrNull(v *ua.Variant) *ua.Variant {
	if v == nil {
		return ua.MustVariant(nil)
	}
	return v
}

// writeOldValue returns the value a WriteValue replaces: the Attribute
// before the write, limited to its IndexRange; nil when there is none.
func writeOldValue(ns NameSpace, n *ua.WriteValue) *ua.Variant {
	dv := ns.Attribute(n.NodeID, n.AttributeID)
	if dv == nil || dv.Value == nil || isBad(dv.Status) {
		return nil
	}
	if n.IndexRange == "" {
		return dv.Value
	}
	v, st := ua.SliceVariantRead(dv.Value, n.IndexRange)
	if st != ua.StatusOK {
		return nil
	}
	return v
}

// auditWrite reports the AuditWriteUpdateEventType of each WriteValue of a
// Write that the server answered with status (Part 5 §6.4.25); old holds
// the values before the write, by index, and is nil when the Write is not
// audited (auditing was off when it started).
func (s *Server) auditWrite(sess *session, req *ua.WriteRequest, old []*ua.Variant, status []ua.StatusCode) {
	if old == nil {
		return
	}
	for i, n := range req.NodesToWrite {
		st, oldValue := status[i], old[i]
		var newValue *ua.Variant
		if n.Value != nil {
			newValue = n.Value.Value
		}
		ev := s.changeAuditEvent(id.AuditWriteUpdateEventType, auditSourceWrite, n.NodeID,
			"Write of "+strings.TrimPrefix(n.AttributeID.String(), "AttributeID")+" of "+nodeName(n.NodeID)+failure(st), !isBad(st), sess, req.RequestHeader)
		f := ev.Fields
		f["AttributeId"] = ua.MustVariant(uint32(n.AttributeID))
		f["IndexRange"] = ua.MustVariant(n.IndexRange)
		f["NewValue"] = variantOrNull(newValue)
		f["OldValue"] = variantOrNull(oldValue)
		s.emitAudit(ev)
	}
}

// nodeName is a NodeId in a Message.
func nodeName(n *ua.NodeID) string {
	if n == nil {
		return "null"
	}
	return n.String()
}

// historyUpdateAudit is what a HistoryUpdateDetails changed, for its audit
// event: the values it replaced or deleted and, of UpdateStructureData,
// the Annotations as given to the provider; of UpdateEvent the EventIds of
// the inserted events.
type historyUpdateAudit struct {
	newValues, oldValues []*ua.DataValue
	inserted             [][]byte
}

// historyDetailsTypes are the DataTypes of the HistoryUpdateDetails, the
// ParameterDataTypeId of their audit events (Part 5 §6.4.26).
func historyDetailsType(v any) uint32 {
	switch v.(type) {
	case *ua.UpdateDataDetails, ua.UpdateDataDetails:
		return id.UpdateDataDetails
	case *ua.UpdateStructureDataDetails, ua.UpdateStructureDataDetails:
		return id.UpdateStructureDataDetails
	case *ua.UpdateEventDetails, ua.UpdateEventDetails:
		return id.UpdateEventDetails
	case *ua.DeleteRawModifiedDetails, ua.DeleteRawModifiedDetails:
		return id.DeleteRawModifiedDetails
	case *ua.DeleteAtTimeDetails, ua.DeleteAtTimeDetails:
		return id.DeleteAtTimeDetails
	case *ua.DeleteEventDetails, ua.DeleteEventDetails:
		return id.DeleteEventDetails
	}
	return 0
}

// historyResultOK reports whether a HistoryUpdateResult has no Bad status,
// and returns its first Bad status.
func historyResultOK(res *ua.HistoryUpdateResult) (bool, ua.StatusCode) {
	if res == nil {
		return false, ua.StatusBadInternalError
	}
	if isBad(res.StatusCode) {
		return false, res.StatusCode
	}
	for _, op := range res.OperationResults {
		if isBad(op) {
			return false, op
		}
	}
	return true, ua.StatusOK
}

func performName(p ua.PerformUpdateType) string {
	switch p {
	case ua.PerformUpdateTypeInsert:
		return "Insert"
	case ua.PerformUpdateTypeReplace:
		return "Replace"
	case ua.PerformUpdateTypeUpdate:
		return "Update"
	case ua.PerformUpdateTypeRemove:
		return "Remove"
	}
	return "PerformUpdateType " + strconv.Itoa(int(p))
}

// extensionObjects wraps structures in ExtensionObjects; a nil one is an
// empty ExtensionObject.
func extensionObjects[T comparable](items []T) []*ua.ExtensionObject {
	out := make([]*ua.ExtensionObject, 0, len(items))
	for _, it := range items {
		out = append(out, extensionObject(it))
	}
	return out
}

// extensionObject wraps a structure in an ExtensionObject; a nil one is an
// empty ExtensionObject.
func extensionObject[T comparable](v T) *ua.ExtensionObject {
	var zero T
	if v == zero {
		return ua.NewExtensionObject(nil)
	}
	return ua.NewExtensionObject(v)
}

// annotationsOf returns the Annotations of DataValues as ExtensionObjects,
// the Annotation[] of AuditHistoryAnnotationUpdateEventType.
func annotationsOf(values []*ua.DataValue) []*ua.ExtensionObject {
	var out []*ua.ExtensionObject
	for _, v := range values {
		if a := annotationOf(v); a != nil {
			out = append(out, ua.NewExtensionObject(a))
		}
	}
	return out
}

func dataValues(v []*ua.DataValue) []*ua.DataValue {
	if v == nil {
		return []*ua.DataValue{}
	}
	return v
}

// auditHistoryUpdate reports the audit event of one HistoryUpdateDetails
// (Part 11 §5.8) the server answered with res.
func (s *Server) auditHistoryUpdate(sess *session, hdr *ua.RequestHeader, details any, res *ua.HistoryUpdateResult, a historyUpdateAudit) {
	ok, bad := historyResultOK(res)
	typ := uint32(id.AuditHistoryUpdateEventType)
	var node *ua.NodeID
	var what string
	fields := map[string]*ua.Variant{}
	switch d := details.(type) {
	case *ua.UpdateDataDetails:
		typ, node, what = id.AuditHistoryValueUpdateEventType, d.NodeID, "UpdateData "+performName(d.PerformInsertReplace)
		fields["UpdatedNode"] = ua.MustVariant(d.NodeID)
		fields["PerformInsertReplace"] = ua.MustVariant(int32(d.PerformInsertReplace))
		fields["NewValues"] = ua.MustVariant(dataValues(d.UpdateValues))
		fields["OldValues"] = ua.MustVariant(dataValues(a.oldValues))
	case *ua.UpdateStructureDataDetails:
		typ, node, what = id.AuditHistoryAnnotationUpdateEventType, d.NodeID, "UpdateStructureData "+performName(d.PerformInsertReplace)
		fields["PerformInsertReplace"] = ua.MustVariant(int32(d.PerformInsertReplace))
		newValues := annotationsOf(a.newValues)
		if d.PerformInsertReplace == ua.PerformUpdateTypeRemove || newValues == nil {
			// "Null for a remove" (Part 11 §5.8.4).
			newValues = []*ua.ExtensionObject{}
		}
		old := annotationsOf(a.oldValues)
		if old == nil {
			old = []*ua.ExtensionObject{}
		}
		fields["NewValues"] = ua.MustVariant(newValues)
		fields["OldValues"] = ua.MustVariant(old)
	case *ua.UpdateEventDetails:
		typ, node, what = id.AuditHistoryEventUpdateEventType, d.NodeID, "UpdateEvent "+performName(d.PerformInsertReplace)
		fields["UpdatedNode"] = ua.MustVariant(d.NodeID)
		fields["PerformInsertReplace"] = ua.MustVariant(int32(d.PerformInsertReplace))
		fields["Filter"] = ua.MustVariant(extensionObject(d.Filter))
		fields["NewValues"] = ua.MustVariant(extensionObjects(d.EventData))
		fields["OldValues"] = ua.MustVariant([]*ua.ExtensionObject{})
		if len(a.inserted) > 0 {
			ids := make([]string, len(a.inserted))
			for i, b := range a.inserted {
				ids[i] = hex.EncodeToString(b)
			}
			what += ", inserted EventIds " + strings.Join(ids, ", ")
		}
	case *ua.DeleteRawModifiedDetails:
		typ, node, what = id.AuditHistoryRawModifyDeleteEventType, d.NodeID, "DeleteRawModified"
		fields["UpdatedNode"] = ua.MustVariant(d.NodeID)
		fields["IsDeleteModified"] = ua.MustVariant(d.IsDeleteModified)
		fields["StartTime"] = ua.MustVariant(d.StartTime)
		fields["EndTime"] = ua.MustVariant(d.EndTime)
		fields["OldValues"] = ua.MustVariant(dataValues(a.oldValues))
	case *ua.DeleteAtTimeDetails:
		typ, node, what = id.AuditHistoryAtTimeDeleteEventType, d.NodeID, "DeleteAtTime"
		fields["UpdatedNode"] = ua.MustVariant(d.NodeID)
		reqTimes := d.ReqTimes
		if reqTimes == nil {
			reqTimes = []time.Time{}
		}
		fields["ReqTimes"] = ua.MustVariant(reqTimes)
		fields["OldValues"] = ua.MustVariant(dataValues(a.oldValues))
	case *ua.DeleteEventDetails:
		typ, node, what = id.AuditHistoryEventDeleteEventType, d.NodeID, "DeleteEvent"
		fields["UpdatedNode"] = ua.MustVariant(d.NodeID)
		eventIDs := d.EventIDs
		if eventIDs == nil {
			eventIDs = [][]byte{}
		}
		fields["EventIds"] = ua.MustVariant(eventIDs)
		fields["OldValues"] = ua.MustVariant((*ua.ExtensionObject)(nil))
	default:
		what = "HistoryUpdate"
	}
	msg := what
	if node != nil {
		msg += " of " + node.String()
	}
	ev := s.changeAuditEvent(typ, auditSourceHistoryUpdate, node, msg+failure(bad), ok, sess, hdr)
	var param *ua.NodeID
	if t := historyDetailsType(details); t != 0 {
		param = ua.NewNumericNodeID(0, t)
	}
	ev.Fields["ParameterDataTypeId"] = ua.MustVariant(param)
	for k, v := range fields {
		ev.Fields[k] = v
	}
	s.emitAudit(ev)
}

// historyDetails returns the HistoryUpdateDetails of an ExtensionObject as
// a pointer, the value itself for unknown details.
func historyDetails(eo *ua.ExtensionObject) any {
	if eo == nil {
		return nil
	}
	switch v := eo.Value.(type) {
	case ua.UpdateDataDetails:
		return &v
	case ua.UpdateStructureDataDetails:
		return &v
	case ua.UpdateEventDetails:
		return &v
	case ua.DeleteRawModifiedDetails:
		return &v
	case ua.DeleteAtTimeDetails:
		return &v
	case ua.DeleteEventDetails:
		return &v
	}
	return eo.Value
}

// oldRawValues returns the raw values of nodeID at the times given, read
// from h before they change, for the OldValues of an audit event.
func oldRawValues(h HistoryProvider, nodeID *ua.NodeID, times []time.Time) []*ua.DataValue {
	if len(times) == 0 {
		return nil
	}
	from, to := times[0], times[0]
	want := make(map[int64]bool, len(times))
	for _, t := range times {
		from, to = minTime(from, t), maxTime(to, t)
		want[t.UnixNano()] = true
	}
	raw, st, err := readRawRange(h, nodeID, from, to.Add(time.Nanosecond))
	if err != nil || isBad(st) {
		return nil
	}
	var out []*ua.DataValue
	for _, dv := range raw {
		if dv != nil && want[dv.SourceTimestamp.UnixNano()] {
			out = append(out, dv)
		}
	}
	return out
}

// oldRawRange returns the raw values a raw delete from start to end removes
// (inRawDeleteRange), read from h before the delete.
func oldRawRange(h HistoryProvider, nodeID *ua.NodeID, start, end time.Time) []*ua.DataValue {
	to := end
	if start.Equal(end) {
		to = end.Add(time.Nanosecond)
	}
	raw, st, err := readRawRange(h, nodeID, start, to)
	if err != nil || isBad(st) {
		return nil
	}
	var out []*ua.DataValue
	for _, dv := range raw {
		if dv != nil && inRawDeleteRange(start, end, dv.SourceTimestamp) {
			out = append(out, dv)
		}
	}
	return out
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// valueTimes returns the SourceTimestamps of values.
func valueTimes(values []*ua.DataValue) []time.Time {
	out := make([]time.Time, 0, len(values))
	for _, v := range values {
		if v != nil && !v.SourceTimestamp.IsZero() {
			out = append(out, v.SourceTimestamp)
		}
	}
	return out
}

// changeServiceDone audits a Write, HistoryUpdate or NodeManagement request
// after its handler (serve). Write and HistoryUpdate audit their
// operations in the handler; here only a request refused as a whole. A
// NodeManagement call is audited here, with the results of its response.
func (s *Server) changeServiceDone(sess *session, req ua.Request, resp ua.Response, err error) {
	if !s.auditsChanges() {
		return
	}
	st := statusOfResult(resp, err)
	switch r := req.(type) {
	case *ua.WriteRequest:
		if err != nil {
			s.emitAudit(s.serviceFaultAudit(id.AuditWriteUpdateEventType, auditSourceWrite, "Write", st, sess, r.RequestHeader))
		}
	case *ua.HistoryUpdateRequest:
		if err != nil {
			ev := s.serviceFaultAudit(id.AuditHistoryUpdateEventType, auditSourceHistoryUpdate, "HistoryUpdate", st, sess, r.RequestHeader)
			ev.Fields["ParameterDataTypeId"] = ua.MustVariant((*ua.NodeID)(nil))
			s.emitAudit(ev)
		}
	case *ua.AddNodesRequest:
		var results []ua.StatusCode
		if rs, ok := resp.(*ua.AddNodesResponse); ok {
			for _, x := range rs.Results {
				results = append(results, addNodesStatus(x))
			}
		}
		ev := s.nodeManagementAudit(id.AuditAddNodesEventType, "AddNodes", len(r.NodesToAdd), results, st, sess, r.RequestHeader)
		ev.Fields["NodesToAdd"] = ua.MustVariant(extensionObjects(r.NodesToAdd))
		s.emitAudit(ev)
	case *ua.DeleteNodesRequest:
		var results []ua.StatusCode
		if rs, ok := resp.(*ua.DeleteNodesResponse); ok {
			results = rs.Results
		}
		ev := s.nodeManagementAudit(id.AuditDeleteNodesEventType, "DeleteNodes", len(r.NodesToDelete), results, st, sess, r.RequestHeader)
		ev.Fields["NodesToDelete"] = ua.MustVariant(extensionObjects(r.NodesToDelete))
		s.emitAudit(ev)
	case *ua.AddReferencesRequest:
		var results []ua.StatusCode
		if rs, ok := resp.(*ua.AddReferencesResponse); ok {
			results = rs.Results
		}
		ev := s.nodeManagementAudit(id.AuditAddReferencesEventType, "AddReferences", len(r.ReferencesToAdd), results, st, sess, r.RequestHeader)
		ev.Fields["ReferencesToAdd"] = ua.MustVariant(extensionObjects(r.ReferencesToAdd))
		s.emitAudit(ev)
	case *ua.DeleteReferencesRequest:
		var results []ua.StatusCode
		if rs, ok := resp.(*ua.DeleteReferencesResponse); ok {
			results = rs.Results
		}
		ev := s.nodeManagementAudit(id.AuditDeleteReferencesEventType, "DeleteReferences", len(r.ReferencesToDelete), results, st, sess, r.RequestHeader)
		ev.Fields["ReferencesToDelete"] = ua.MustVariant(extensionObjects(r.ReferencesToDelete))
		s.emitAudit(ev)
	}
}

func addNodesStatus(r *ua.AddNodesResult) ua.StatusCode {
	if r == nil {
		return ua.StatusBadInternalError
	}
	return r.StatusCode
}

// serviceFaultAudit is the audit event of a Write or HistoryUpdate request
// the server refused as a whole with st.
func (s *Server) serviceFaultAudit(typ uint32, source, service string, st ua.StatusCode, sess *session, hdr *ua.RequestHeader) *BaseEvent {
	ev := s.changeAuditEvent(typ, source, nil, service+failure(st), false, sess, hdr)
	if typ == id.AuditWriteUpdateEventType {
		ev.Fields["AttributeId"] = ua.MustVariant(uint32(0))
		ev.Fields["IndexRange"] = ua.MustVariant("")
		ev.Fields["NewValue"] = ua.MustVariant(nil)
		ev.Fields["OldValue"] = ua.MustVariant(nil)
	}
	return ev
}

// nodeManagementAudit is the AuditNodeManagementEventType subtype (Part 5
// §6.4.19) of a call of service with n items answered with st and, item
// by item, results.
func (s *Server) nodeManagementAudit(typ uint32, service string, n int, results []ua.StatusCode, st ua.StatusCode, sess *session, hdr *ua.RequestHeader) *BaseEvent {
	msg := service
	ok := !isBad(st)
	if !ok {
		msg += failure(st)
	} else {
		failed, first := 0, ua.StatusOK
		for i := range n {
			r := ua.StatusBadInternalError
			if i < len(results) {
				r = results[i]
			}
			if isBad(r) {
				if failed == 0 {
					first = r
				}
				failed++
			}
		}
		if failed > 0 {
			ok = false
			msg += ": " + strconv.Itoa(failed) + " of " + strconv.Itoa(n) + " failed, the first with " + first.Error()
		}
	}
	return s.changeAuditEvent(typ, auditSourceNodeMgmt+service, nil, msg, ok, sess, hdr)
}
