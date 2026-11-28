// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"fmt"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

// AttributeService implements the Attribute Service Set.
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.10
type AttributeService struct {
	srv *Server
}

// unsupportedWriteMask bits that this server does not accept on Write.
const unsupportedWriteMask = ua.DataValueStatusCode |
	ua.DataValueSourceTimestamp |
	ua.DataValueServerTimestamp |
	ua.DataValueSourcePicoseconds |
	ua.DataValueServerPicoseconds

// Read implements the OPC UA Read service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.10.2
func (s *AttributeService) Read(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.srv.cfg.logger.Debug("handling request", "type", fmt.Sprintf("%T", r))

	req, err := safeReq[*ua.ReadRequest](r)
	if err != nil {
		return nil, err
	}

	if sc := ua.ApplyTimestampsToReturn(&ua.DataValue{}, req.TimestampsToReturn); sc != ua.StatusOK {
		// Invalid TimestampsToReturn is a service-level parameter error.
		return &ua.ReadResponse{
			ResponseHeader: responseHeader(req.RequestHeader.RequestHandle, sc),
			Results:        []*ua.DataValue{},
		}, nil
	}

	sess := s.srv.sb.Session(req.RequestHeader.AuthenticationToken)

	results := make([]*ua.DataValue, len(req.NodesToRead))
	for i, n := range req.NodesToRead {
		s.srv.cfg.logger.Debug("read", "node_id", n.NodeID, "attribute", n.AttributeID)

		if sc := s.srv.checkRead(ctx, sess, n.NodeID); sc != ua.StatusOK {
			// Error DataValues must not receive fabricated timestamps.
			results[i] = &ua.DataValue{
				EncodingMask: ua.DataValueStatusCode,
				Status:       sc,
			}
			continue
		}

		ns, err := s.srv.Namespace(int(n.NodeID.Namespace()))
		if err != nil {
			results[i] = &ua.DataValue{
				EncodingMask: ua.DataValueStatusCode,
				Status:       ua.StatusBad,
			}
			continue
		}

		if node := ns.Node(n.NodeID); node != nil {
			if st := checkAccessRestrictions(sc, node); st != ua.StatusOK {
				results[i] = &ua.DataValue{
					EncodingMask: ua.DataValueStatusCode,
					Status:       st,
				}
				continue
			}
		}

		dv := ns.Attribute(n.NodeID, n.AttributeID)
		if s.srv.readsSessionRoles(n.NodeID, n.AttributeID) {
			dv = forSessionRoles(dv, sess)
		}

		if n.IndexRange != "" {
			if n.AttributeID != ua.AttributeIDValue || dv == nil || dv.Status != ua.StatusOK || dv.Value == nil {
				results[i] = &ua.DataValue{
					EncodingMask: ua.DataValueStatusCode,
					Status:       ua.StatusBadIndexRangeInvalid,
				}
				continue
			}
			sliced, st := ua.SliceVariantRead(dv.Value, n.IndexRange)
			if st != ua.StatusOK {
				results[i] = &ua.DataValue{
					EncodingMask: ua.DataValueStatusCode,
					Status:       st,
				}
				continue
			}
			dv = &ua.DataValue{
				EncodingMask:      dv.EncodingMask | ua.DataValueValue,
				Value:             sliced,
				Status:            dv.Status,
				SourceTimestamp:   dv.SourceTimestamp,
				SourcePicoseconds: dv.SourcePicoseconds,
				ServerTimestamp:   dv.ServerTimestamp,
				ServerPicoseconds: dv.ServerPicoseconds,
			}
		}

		// ns.Attribute may return the DataValue stored in the node. Work on a
		// copy so that the timestamp filtering of this request neither races
		// with other readers nor alters what the node holds.
		if dv != nil {
			cp := *dv
			dv = &cp
		}
		_ = ua.ApplyTimestampsToReturn(dv, req.TimestampsToReturn)
		results[i] = dv
	}

	response := &ua.ReadResponse{
		ResponseHeader: responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
		Results:        results,
	}

	return response, nil
}

// HistoryRead implements the OPC UA HistoryRead service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.10.3
func (s *AttributeService) HistoryRead(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.srv.cfg.logger.Debug("handling request", "type", fmt.Sprintf("%T", r))

	req, err := safeReq[*ua.HistoryReadRequest](r)
	if err != nil {
		return nil, err
	}

	sess := s.srv.sb.Session(req.RequestHeader.AuthenticationToken)
	sessionAuth := ""
	if sess != nil && sess.AuthTokenID != nil {
		sessionAuth = sess.AuthTokenID.String()
	}
	historian, cps := s.srv.history()

	// If ReleaseContinuationPoints is set, just release them.
	if req.ReleaseContinuationPoints && historian != nil {
		results := make([]*ua.HistoryReadResult, len(req.NodesToRead))
		for i, n := range req.NodesToRead {
			st := ua.StatusOK
			if len(n.ContinuationPoint) > 0 {
				if cps != nil {
					st = cps.release(sessionAuth, n.ContinuationPoint)
				} else {
					historian.ReleaseContinuation(n.ContinuationPoint)
				}
			}
			results[i] = &ua.HistoryReadResult{StatusCode: st}
		}
		return &ua.HistoryReadResponse{
			ResponseHeader:  responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
			Results:         results,
			DiagnosticInfos: []*ua.DiagnosticInfo{},
		}, nil
	}

	if historian == nil {
		return unsupportedHistoryRead(req), nil
	}

	details := any(nil)
	if req.HistoryReadDetails != nil {
		details = req.HistoryReadDetails.Value
	}

	// The parameters of ReadEventDetails hold for every node: they are
	// checked once, and their errors are service results.
	eventDetails, eventSupported, isEvent := eventReadDetails(details)
	_, eventHistory := historian.(EventHistoryProvider)
	if isEvent && eventSupported && eventHistory {
		if st := s.checkHistoryReadEvents(req, eventDetails); st != ua.StatusOK {
			return &ua.HistoryReadResponse{
				ResponseHeader:  responseHeader(req.RequestHeader.RequestHandle, st),
				Results:         []*ua.HistoryReadResult{},
				DiagnosticInfos: []*ua.DiagnosticInfo{},
			}, nil
		}
	}

	// "If the array of Aggregates does not match the array of NodesToRead
	// then the Server shall return a StatusCode of
	// Bad_AggregateListMismatch" (Part 11 §6.5.4.2): one aggregateType per
	// node to read.
	if d := processedDetails(details); d != nil && len(d.AggregateType) != len(req.NodesToRead) {
		return &ua.HistoryReadResponse{
			ResponseHeader:  responseHeader(req.RequestHeader.RequestHandle, ua.StatusBadAggregateListMismatch),
			Results:         []*ua.HistoryReadResult{},
			DiagnosticInfos: []*ua.DiagnosticInfo{},
		}, nil
	}

	results := make([]*ua.HistoryReadResult, len(req.NodesToRead))
	for i, n := range req.NodesToRead {
		providerCP := n.ContinuationPoint
		if len(providerCP) > 0 && cps != nil {
			var st ua.StatusCode
			providerCP, st = cps.resolve(sessionAuth, providerCP)
			if st != ua.StatusOK {
				results[i] = &ua.HistoryReadResult{StatusCode: st}
				continue
			}
		}

		var result *ua.HistoryReadResult
		if isEvent {
			result = &ua.HistoryReadResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}
			if p, ok := historian.(EventHistoryProvider); ok && eventSupported {
				result = s.readEventHistory(ctx, sc, sess, p, eventDetails, n.NodeID, providerCP)
			}
		} else if st := s.srv.checkDataHistory(ctx, sc, sess, n.NodeID, false); st != ua.StatusOK {
			result = &ua.HistoryReadResult{StatusCode: st}
		} else {
			result, err = s.historyReadData(ctx, sc, sess, historian, req, i, details, n.NodeID, providerCP)
			if err != nil {
				results[i] = &ua.HistoryReadResult{StatusCode: ua.StatusBadInternalError}
				continue
			}
		}
		if result == nil {
			results[i] = &ua.HistoryReadResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}
			continue
		}
		if len(result.ContinuationPoint) > 0 && cps != nil {
			result.ContinuationPoint = cps.bind(sessionAuth, result.ContinuationPoint)
		}
		results[i] = result
	}

	return &ua.HistoryReadResponse{
		ResponseHeader:  responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
		Results:         results,
		DiagnosticInfos: []*ua.DiagnosticInfo{},
	}, nil
}

// checkHistoryReadEvents checks a HistoryRead of events as a whole: the
// number of nodes (Bad_NothingToDo, Bad_TooManyOperations against
// MaxNodesPerHistoryReadEvents) and the ReadEventDetails.
func (s *AttributeService) checkHistoryReadEvents(req *ua.HistoryReadRequest, d *ua.ReadEventDetails) ua.StatusCode {
	if len(req.NodesToRead) == 0 {
		return ua.StatusBadNothingToDo
	}
	if limit := s.srv.cfg.cap.OperationalLimits.MaxNodesPerHistoryReadEvents; limit > 0 && uint32(len(req.NodesToRead)) > limit {
		return ua.StatusBadTooManyOperations
	}
	return checkReadEventDetails(d)
}

func unsupportedHistoryRead(req *ua.HistoryReadRequest) *ua.HistoryReadResponse {
	results := make([]*ua.HistoryReadResult, len(req.NodesToRead))
	for i := range req.NodesToRead {
		results[i] = &ua.HistoryReadResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}
	}
	return &ua.HistoryReadResponse{
		ResponseHeader:  responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
		Results:         results,
		DiagnosticInfos: []*ua.DiagnosticInfo{},
	}
}

// historyReadData reads the data history of operation i of req, nodeID:
// the Annotations of the node for ReadAnnotationDataDetails and for the
// ReadRawModifiedDetails of its Annotations Property (Part 11 §5.1.2,
// §6.5.6), when the provider keeps them; the values of the node otherwise
// (dispatchHistoryRead).
func (s *AttributeService) historyReadData(ctx context.Context, sc *uasc.SecureChannel, sess *session, h HistoryProvider, req *ua.HistoryReadRequest, i int, details any, nodeID *ua.NodeID, continuationPoint []byte) (*ua.HistoryReadResult, error) {
	if d := annotationReadDetails(details); d != nil {
		return s.readAnnotations(ctx, sc, sess, h, d, nodeID)
	}
	if p, ok := h.(AnnotationHistoryProvider); ok {
		if d := rawModifiedDetails(details); d != nil {
			if owner := s.srv.annotationsPropertyOwner(nodeID); owner != nil {
				if st := s.srv.checkDataHistory(ctx, sc, sess, owner, false); st != ua.StatusOK {
					return &ua.HistoryReadResult{StatusCode: st}, nil
				}
				if d.IsReadModified {
					return &ua.HistoryReadResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}, nil
				}
				return p.ReadRawAnnotations(owner, d.StartTime, d.EndTime, d.NumValuesPerNode, continuationPoint)
			}
		}
	}
	return s.dispatchHistoryRead(h, req, i, details, nodeID, continuationPoint)
}

// rawModifiedDetails returns the ReadRawModifiedDetails of a HistoryRead,
// nil for other details.
func rawModifiedDetails(details any) *ua.ReadRawModifiedDetails {
	switch v := details.(type) {
	case *ua.ReadRawModifiedDetails:
		return v
	case ua.ReadRawModifiedDetails:
		return &v
	}
	return nil
}

// dispatchHistoryRead reads the history of operation i of req, nodeID.
func (s *AttributeService) dispatchHistoryRead(h HistoryProvider, req *ua.HistoryReadRequest, i int, details any, nodeID *ua.NodeID, continuationPoint []byte) (*ua.HistoryReadResult, error) {
	switch v := details.(type) {
	case *ua.ReadRawModifiedDetails:
		return readRawModified(h, v, nodeID, continuationPoint)
	case ua.ReadRawModifiedDetails:
		return readRawModified(h, &v, nodeID, continuationPoint)
	case *ua.ReadAtTimeDetails:
		reader, ok := h.(AtTimeHistoryReader)
		if !ok {
			return &ua.HistoryReadResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}, nil
		}
		return reader.ReadAtTime(nodeID, v.ReqTimes, v.UseSimpleBounds)
	case ua.ReadAtTimeDetails:
		reader, ok := h.(AtTimeHistoryReader)
		if !ok {
			return &ua.HistoryReadResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}, nil
		}
		return reader.ReadAtTime(nodeID, v.ReqTimes, v.UseSimpleBounds)
	case *ua.ReadProcessedDetails, ua.ReadProcessedDetails:
		d := processedDetails(v)
		if d == nil {
			return &ua.HistoryReadResult{StatusCode: ua.StatusBadHistoryOperationInvalid}, nil
		}
		// HistoryRead checked that there is an aggregateType per node.
		return readProcessed(h, d, nodeID, d.AggregateType[i], req.TimestampsToReturn)
	default:
		return &ua.HistoryReadResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}, nil
	}
}

// processedDetails returns the ReadProcessedDetails of a HistoryRead, nil
// for other details.
func processedDetails(details any) *ua.ReadProcessedDetails {
	switch v := details.(type) {
	case *ua.ReadProcessedDetails:
		return v
	case ua.ReadProcessedDetails:
		return &v
	}
	return nil
}

func readRawModified(h HistoryProvider, details *ua.ReadRawModifiedDetails, nodeID *ua.NodeID, continuationPoint []byte) (*ua.HistoryReadResult, error) {
	if details.IsReadModified {
		reader, ok := h.(ModifiedHistoryReader)
		if !ok {
			return &ua.HistoryReadResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}, nil
		}
		return reader.ReadModified(nodeID, details.StartTime, details.EndTime, details.NumValuesPerNode, continuationPoint)
	}
	return h.ReadRaw(
		nodeID,
		details.StartTime,
		details.EndTime,
		details.NumValuesPerNode,
		details.ReturnBounds,
		continuationPoint,
	)
}

// Write implements the OPC UA Write service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.10.4
func (s *AttributeService) Write(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {

	req, err := safeReq[*ua.WriteRequest](r)
	if err != nil {
		return nil, err
	}

	sess := s.srv.sb.Session(req.RequestHeader.AuthenticationToken)

	status := make([]ua.StatusCode, len(req.NodesToWrite))
	// old holds the values the writes replace, for their audit events.
	audit := s.srv.auditsChanges()
	var old []*ua.Variant
	if audit {
		old = make([]*ua.Variant, len(req.NodesToWrite))
	}
	var jobs []valueWriteJob
	// The OperationGuards learn that the writes are over when the request
	// is: the writes of ValueWriters run after the loop, off the dispatcher
	// when the request is answered later.
	var dones []func()
	finish := func() {
		for _, done := range dones {
			done()
		}
	}
	answeredLater := false
	defer func() {
		if !answeredLater {
			finish()
		}
	}()

	for i := range req.NodesToWrite {
		n := req.NodesToWrite[i]
		s.srv.cfg.logger.Debug("write", "node_id", n.NodeID, "attribute", n.AttributeID)

		st, done := s.srv.checkWrite(ctx, sess, n.NodeID)
		dones = append(dones, done)
		if st != ua.StatusOK {
			status[i] = st
			continue
		}
		if isEnabledFlag(n) {
			status[i] = s.srv.diag.writeEnabledFlag(n)
			continue
		}

		ns, err := s.srv.Namespace(int(n.NodeID.Namespace()))
		if err != nil {
			status[i] = ua.StatusBadNodeNotInView
			continue
		}
		remember := func() {
			if audit {
				old[i] = writeOldValue(ns, n)
			}
		}

		// Whether the Value may be written at all comes before what the
		// DataValue carries: a Variable whose AccessLevel has no CurrentWrite
		// is Bad_NotWritable, and one whose UserAccessLevel has none is
		// Bad_UserAccessDenied (Part 3 §5.6.2, Part 4 §5.10.4), whatever
		// StatusCode or timestamps the client sent with the value. A Value a
		// ValueWriter takes is checked the same way.
		node := ns.Node(n.NodeID)
		if node != nil {
			if st := checkAccessRestrictions(sc, node); st != ua.StatusOK {
				status[i] = st
				continue
			}
			if n.AttributeID == ua.AttributeIDValue {
				if st := node.AccessStatus(ua.AccessLevelTypeCurrentWrite); st != ua.StatusOK {
					status[i] = st
					continue
				}
			}
		}
		// A Value a ValueWriter takes is written by the writer after the loop.
		var writer ValueWriter
		if node != nil && n.AttributeID == ua.AttributeIDValue && sess != nil {
			writer = node.ValueWriter()
		}
		deferWrite := func(dv *ua.DataValue) {
			jobs = append(jobs, valueWriteJob{index: i, writer: writer, write: &ValueWrite{Session: sess.handle(), NodeID: n.NodeID, Value: dv}})
		}
		// The server stores no StatusCode or timestamps a client writes
		// (Part 4 §5.10.4: Bad_WriteNotSupported); a writer gets them and
		// decides.
		if writer == nil && n.Value != nil && n.Value.EncodingMask&unsupportedWriteMask != 0 {
			status[i] = ua.StatusBadWriteNotSupported
			continue
		}

		if n.IndexRange != "" {
			if n.AttributeID != ua.AttributeIDValue || n.Value == nil || n.Value.Value == nil {
				status[i] = ua.StatusBadIndexRangeInvalid
				continue
			}
			// WriteFullArrayOnly (Part 3 §8.58): "A Server shall return a
			// Bad_WriteNotSupported error if an indexRange is provided and
			// writing of indexRange is not possible for the Node" (Part 4
			// §5.11.4.2).
			if node != nil && node.writeFullArrayOnly() {
				status[i] = ua.StatusBadWriteNotSupported
				continue
			}
			cur := ns.Attribute(n.NodeID, ua.AttributeIDValue)
			// The range is merged into the current value, so there has to be
			// one. A value of Uncertain quality is a value: only a Bad status
			// means there is nothing to merge into.
			if cur == nil || cur.Value == nil || cur.Status&0x80000000 != 0 {
				status[i] = ua.StatusBadIndexRangeInvalid
				continue
			}
			merged, st := ua.MergeVariantWrite(cur.Value, n.IndexRange, n.Value.Value)
			if st != ua.StatusOK {
				status[i] = st
				continue
			}
			remember()
			if writer != nil {
				deferWrite(&ua.DataValue{EncodingMask: ua.DataValueValue, Value: merged})
				continue
			}
			dv := stampWritten(&ua.DataValue{
				EncodingMask: ua.DataValueValue,
				Value:        merged,
			}, time.Now())
			status[i] = ns.SetAttribute(n.NodeID, n.AttributeID, dv)
			continue
		}

		if n.AttributeID != ua.AttributeIDValue {
			if st := checkAttributeWrite(ns, n.NodeID, n.AttributeID, n.Value); st != ua.StatusOK {
				status[i] = st
				continue
			}
		}

		remember()
		if writer != nil {
			if n.Value == nil {
				status[i] = ua.StatusBadTypeMismatch
				continue
			}
			deferWrite(n.Value)
			continue
		}
		val := n.Value
		if n.AttributeID == ua.AttributeIDValue && val != nil {
			val = stampWritten(val, time.Now())
		}
		status[i] = ns.SetAttribute(n.NodeID, n.AttributeID, val)

	}
	if len(jobs) > 0 {
		if reply := answerLater(ctx); reply != nil {
			answeredLater = true
			s.srv.runValueWriters(ctx, sess, req.RequestHeader, jobs, status, func(results []ua.StatusCode) {
				finish()
				s.srv.auditWrite(sess, req, old, results)
				reply(req, writeResponse(req, results))
			})
			return nil, nil
		}
		// Called outside the dispatcher: the writers run now.
		for _, j := range jobs {
			status[j.index] = s.srv.callValueWriter(ctx, j)
		}
	}
	s.srv.auditWrite(sess, req, old, status)
	return writeResponse(req, status), nil
}

// writeResponse is the response to a Write request with its results.
func writeResponse(req *ua.WriteRequest, status []ua.StatusCode) *ua.WriteResponse {
	return &ua.WriteResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		Results:         status,
		DiagnosticInfos: []*ua.DiagnosticInfo{},
	}
}

// attributeWriteBits is the AttributeWriteMask bit (Part 3 §8.60) that makes
// each non-Value Attribute writable. Value is governed by AccessLevel and
// UserAccessLevel (Part 3 §5.6.2) and is not in the table. UserRolePermissions
// has no bit: it is derived per Session (Part 3 §5.2.10) and never written.
var attributeWriteBits = map[ua.AttributeID]ua.AttributeWriteMask{
	ua.AttributeIDNodeID:                  ua.AttributeWriteMaskNodeID,
	ua.AttributeIDNodeClass:               ua.AttributeWriteMaskNodeClass,
	ua.AttributeIDBrowseName:              ua.AttributeWriteMaskBrowseName,
	ua.AttributeIDDisplayName:             ua.AttributeWriteMaskDisplayName,
	ua.AttributeIDDescription:             ua.AttributeWriteMaskDescription,
	ua.AttributeIDWriteMask:               ua.AttributeWriteMaskWriteMask,
	ua.AttributeIDUserWriteMask:           ua.AttributeWriteMaskUserWriteMask,
	ua.AttributeIDIsAbstract:              ua.AttributeWriteMaskIsAbstract,
	ua.AttributeIDSymmetric:               ua.AttributeWriteMaskSymmetric,
	ua.AttributeIDInverseName:             ua.AttributeWriteMaskInverseName,
	ua.AttributeIDContainsNoLoops:         ua.AttributeWriteMaskContainsNoLoops,
	ua.AttributeIDEventNotifier:           ua.AttributeWriteMaskEventNotifier,
	ua.AttributeIDDataType:                ua.AttributeWriteMaskDataType,
	ua.AttributeIDValueRank:               ua.AttributeWriteMaskValueRank,
	ua.AttributeIDArrayDimensions:         ua.AttributeWriteMaskArrayDimensions,
	ua.AttributeIDAccessLevel:             ua.AttributeWriteMaskAccessLevel,
	ua.AttributeIDUserAccessLevel:         ua.AttributeWriteMaskUserAccessLevel,
	ua.AttributeIDMinimumSamplingInterval: ua.AttributeWriteMaskMinimumSamplingInterval,
	ua.AttributeIDHistorizing:             ua.AttributeWriteMaskHistorizing,
	ua.AttributeIDExecutable:              ua.AttributeWriteMaskExecutable,
	ua.AttributeIDUserExecutable:          ua.AttributeWriteMaskUserExecutable,
	ua.AttributeIDDataTypeDefinition:      ua.AttributeWriteMaskDataTypeDefinition,
	ua.AttributeIDRolePermissions:         ua.AttributeWriteMaskRolePermissions,
	ua.AttributeIDAccessRestrictions:      ua.AttributeWriteMaskAccessRestrictions,
	ua.AttributeIDAccessLevelEx:           ua.AttributeWriteMaskAccessLevelEx,
}

// checkAttributeWrite decides a Write of a non-Value Attribute (Part 4
// §5.10.4) before the namespace stores it:
//
//   - NodeId and NodeClass: Bad_NotWritable whatever the WriteMask says. Part 3
//     §8.60 has bits for them, but this server keys its address space by
//     NodeId and derives references and Read results from the NodeClass, so
//     it cannot honour them (open62541 refuses both as well).
//   - UserRolePermissions and unknown Attribute ids: Bad_NotWritable and
//     Bad_AttributeIdInvalid.
//   - The bit of the Attribute must be set in the WriteMask of the Node
//     (Part 3 §5.2.7), else Bad_NotWritable. A Node without a WriteMask
//     Attribute, which includes every Node built with the Go API unless it
//     sets one, has nothing writable.
//   - If the Node carries a UserWriteMask Attribute (Part 3 §5.2.8) the bit
//     must be set there too, else Bad_UserAccessDenied, as UserAccessLevel is
//     for the Value (Node.accessStatus). Per-user decisions beyond that stay
//     with the AccessController, which is asked first.
//   - The value must be a scalar or array of the DataType Part 3 defines for
//     the Attribute (Part 3 §5.2 to §5.8, summarised in §5.9), else
//     Bad_TypeMismatch (Part 4 §5.10.4).
//
// Server-internal code that sets attributes through Node.SetAttribute or
// NameSpace.SetAttribute is not subject to these checks.
func checkAttributeWrite(ns NameSpace, id *ua.NodeID, attr ua.AttributeID, dv *ua.DataValue) ua.StatusCode {
	if attr == ua.AttributeIDNodeID || attr == ua.AttributeIDNodeClass || attr == ua.AttributeIDUserRolePermissions {
		return ua.StatusBadNotWritable
	}
	bit, ok := attributeWriteBits[attr]
	if !ok {
		return ua.StatusBadAttributeIDInvalid
	}
	mask, st := writeMaskOf(ns, id, ua.AttributeIDWriteMask)
	if st == ua.StatusBadNodeIDUnknown {
		return st
	}
	if mask&uint32(bit) == 0 {
		return ua.StatusBadNotWritable
	}
	if user, st := writeMaskOf(ns, id, ua.AttributeIDUserWriteMask); st == ua.StatusOK && user&uint32(bit) == 0 {
		return ua.StatusBadUserAccessDenied
	}
	if !attributeValueTypeOK(attr, dv) {
		return ua.StatusBadTypeMismatch
	}
	return ua.StatusOK
}

// writeMaskOf reads the WriteMask or UserWriteMask of a Node: from the Node
// itself when the namespace holds Nodes (so that the AccessLevel check of
// NodeNameSpace.Attribute, which is about the Value, does not hide it), from
// the namespace otherwise. A missing Attribute or one that is not a UInt32
// is reported as Bad_AttributeIdInvalid with a zero mask.
func writeMaskOf(ns NameSpace, id *ua.NodeID, attr ua.AttributeID) (uint32, ua.StatusCode) {
	var dv *ua.DataValue
	if n := ns.Node(id); n != nil {
		a, err := n.Attribute(attr)
		if err != nil || a == nil {
			return 0, ua.StatusBadAttributeIDInvalid
		}
		dv = a.Value
	} else {
		dv = ns.Attribute(id, attr)
		if dv != nil && dv.Status == ua.StatusBadNodeIDUnknown {
			return 0, ua.StatusBadNodeIDUnknown
		}
	}
	if dv == nil || dv.Value == nil || dv.Status != ua.StatusOK {
		return 0, ua.StatusBadAttributeIDInvalid
	}
	m, ok := dv.Value.Value().(uint32)
	if !ok {
		return 0, ua.StatusBadAttributeIDInvalid
	}
	return m, ua.StatusOK
}

// attributeValueTypeOK reports whether dv holds a value of the DataType of a
// non-Value Attribute (Part 3 §5.2 to §5.8, summarised in §5.9). A missing
// value is a mismatch: these Attributes have no null value to write.
func attributeValueTypeOK(attr ua.AttributeID, dv *ua.DataValue) bool {
	if dv == nil || dv.Value == nil {
		return false
	}
	switch v := dv.Value.Value().(type) {
	case *ua.QualifiedName:
		return v != nil && attr == ua.AttributeIDBrowseName
	case *ua.LocalizedText:
		return v != nil && (attr == ua.AttributeIDDisplayName || attr == ua.AttributeIDDescription ||
			attr == ua.AttributeIDInverseName)
	case uint32:
		// WriteMask and UserWriteMask are AttributeWriteMask, AccessLevelEx
		// is AccessLevelExType: OptionSets of UInt32 (Part 3 §8.60, §8.58).
		return attr == ua.AttributeIDWriteMask || attr == ua.AttributeIDUserWriteMask ||
			attr == ua.AttributeIDAccessLevelEx
	case bool:
		return attr == ua.AttributeIDIsAbstract || attr == ua.AttributeIDSymmetric ||
			attr == ua.AttributeIDContainsNoLoops || attr == ua.AttributeIDHistorizing ||
			attr == ua.AttributeIDExecutable || attr == ua.AttributeIDUserExecutable
	case byte:
		// EventNotifier is EventNotifierType, AccessLevel and UserAccessLevel
		// are AccessLevelType: OptionSets of Byte (Part 3 §8.59, §8.57).
		return attr == ua.AttributeIDEventNotifier || attr == ua.AttributeIDAccessLevel ||
			attr == ua.AttributeIDUserAccessLevel
	case uint16:
		// AccessRestrictionType is an OptionSet of UInt16 (Part 3 §8.56).
		return attr == ua.AttributeIDAccessRestrictions
	case *ua.NodeID:
		return v != nil && attr == ua.AttributeIDDataType
	case int32:
		return attr == ua.AttributeIDValueRank
	case []uint32:
		return attr == ua.AttributeIDArrayDimensions
	case float64:
		// Duration is a subtype of Double (Part 3 §8.13).
		return attr == ua.AttributeIDMinimumSamplingInterval
	case *ua.ExtensionObject:
		if v == nil || attr != ua.AttributeIDDataTypeDefinition {
			return false
		}
		switch v.Value.(type) {
		case *ua.StructureDefinition, *ua.EnumDefinition:
			return true
		}
		return false
	case []*ua.ExtensionObject:
		if attr != ua.AttributeIDRolePermissions {
			return false
		}
		for _, eo := range v {
			if eo == nil {
				return false
			}
			if _, ok := eo.Value.(*ua.RolePermissionType); !ok {
				return false
			}
		}
		return true
	}
	return false
}

// stampWritten returns a copy of a DataValue a client wrote to a Value
// Attribute with the time the server received it as its SourceTimestamp.
// The SourceTimestamp "should indicate the time of the last change of the
// value" (Part 4 §7.11.3): the write is that change, and the server applies
// the timestamp because the client cannot (Write answers
// Bad_WriteNotSupported for timestamps, §5.11.4.2). UA-.NETStandard
// (BaseVariableState) also stamps the SourceTimestamp of a write with the
// time of the write. The ServerTimestamp, the time the server "knew it to be
// accurate" (§7.11.4), is left to the Read, the sampling of a monitored item
// and the PubSub publisher, which stamp the time they take the value.
func stampWritten(dv *ua.DataValue, now time.Time) *ua.DataValue {
	cp := *dv
	cp.SourceTimestamp = now.UTC()
	cp.SourcePicoseconds = 0
	cp.EncodingMask = cp.EncodingMask&^ua.DataValueSourcePicoseconds | ua.DataValueSourceTimestamp
	return &cp
}

// HistoryUpdate implements the OPC UA HistoryUpdate service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.10.5
func (s *AttributeService) HistoryUpdate(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.srv.cfg.logger.Debug("handling request", "type", fmt.Sprintf("%T", r))

	req, err := safeReq[*ua.HistoryUpdateRequest](r)
	if err != nil {
		return nil, err
	}

	// MaxNodesPerHistoryUpdateEvents bounds the event details of a request.
	if limit := s.srv.cfg.cap.OperationalLimits.MaxNodesPerHistoryUpdateEvents; limit > 0 {
		var events uint32
		for _, d := range req.HistoryUpdateDetails {
			if d != nil && isEventUpdateDetails(d.Value) {
				events++
			}
		}
		if events > limit {
			return &ua.HistoryUpdateResponse{
				ResponseHeader:  responseHeader(req.RequestHeader.RequestHandle, ua.StatusBadTooManyOperations),
				Results:         []*ua.HistoryUpdateResult{},
				DiagnosticInfos: []*ua.DiagnosticInfo{},
			}, nil
		}
	}

	sess := s.srv.sb.Session(req.RequestHeader.AuthenticationToken)
	historian, _ := s.srv.history()
	results := make([]*ua.HistoryUpdateResult, len(req.HistoryUpdateDetails))
	for i, detailEO := range req.HistoryUpdateDetails {
		var a historyUpdateAudit
		results[i] = s.dispatchHistoryUpdate(ctx, sc, sess, historian, detailEO, &a)
		if s.srv.auditsChanges() {
			s.srv.auditHistoryUpdate(sess, req.RequestHeader, historyDetails(detailEO), results[i], a)
		}
	}

	return &ua.HistoryUpdateResponse{
		ResponseHeader:  responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
		Results:         results,
		DiagnosticInfos: []*ua.DiagnosticInfo{},
	}, nil
}

// isEventUpdateDetails reports whether HistoryUpdate details change event
// history.
func isEventUpdateDetails(v any) bool {
	switch v.(type) {
	case *ua.UpdateEventDetails, ua.UpdateEventDetails, *ua.DeleteEventDetails, ua.DeleteEventDetails:
		return true
	}
	return false
}

// dispatchHistoryUpdate serves one HistoryUpdateDetails. When the server
// audits it, a holds what the audit event needs that the result does not
// tell: the values the update replaces or deletes, read before it.
func (s *AttributeService) dispatchHistoryUpdate(ctx context.Context, sc *uasc.SecureChannel, sess *session, h HistoryProvider, detailEO *ua.ExtensionObject, a *historyUpdateAudit) *ua.HistoryUpdateResult {
	unsupported := &ua.HistoryUpdateResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}
	if detailEO == nil || detailEO.Value == nil || h == nil {
		return unsupported
	}
	if nodeID, ok := historyUpdateNodeID(detailEO.Value); ok {
		if st := s.srv.checkDataHistory(ctx, sc, sess, nodeID, true); st != ua.StatusOK {
			return &ua.HistoryUpdateResult{StatusCode: st}
		}
	}
	audit := s.srv.auditsChanges()
	switch v := historyDetails(detailEO).(type) {
	case *ua.UpdateDataDetails:
		updater, ok := h.(HistoryDataUpdater)
		if !ok {
			return unsupported
		}
		if audit && v.PerformInsertReplace != ua.PerformUpdateTypeInsert {
			a.oldValues = oldRawValues(h, v.NodeID, valueTimes(v.UpdateValues))
		}
		return updater.UpdateData(v.NodeID, v.PerformInsertReplace, v.UpdateValues)
	case *ua.UpdateStructureDataDetails:
		var res *ua.HistoryUpdateResult
		res, a.newValues, a.oldValues = s.updateAnnotations(ctx, sc, sess, h, v)
		return res
	case *ua.DeleteRawModifiedDetails:
		deleter, ok := h.(RawHistoryDeleter)
		if !ok {
			return unsupported
		}
		if st := checkDeleteRawRange(v.StartTime, v.EndTime); st != ua.StatusOK {
			return &ua.HistoryUpdateResult{StatusCode: st}
		}
		if audit && !v.IsDeleteModified {
			a.oldValues = oldRawRange(h, v.NodeID, v.StartTime, v.EndTime)
		}
		return deleter.DeleteRawModified(v.NodeID, v.IsDeleteModified, v.StartTime, v.EndTime)
	case *ua.DeleteAtTimeDetails:
		deleter, ok := h.(AtTimeHistoryDeleter)
		if !ok {
			return unsupported
		}
		if audit {
			a.oldValues = oldRawValues(h, v.NodeID, v.ReqTimes)
		}
		return deleter.DeleteAtTime(v.NodeID, v.ReqTimes)
	case *ua.UpdateEventDetails:
		var res *ua.HistoryUpdateResult
		res, a.inserted = s.updateEventHistory(ctx, sc, sess, h, v)
		return res
	case *ua.DeleteEventDetails:
		return s.deleteEventHistory(ctx, sc, sess, h, v)
	default:
		return unsupported
	}
}
