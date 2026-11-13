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
			result, err = s.dispatchHistoryRead(historian, details, n.NodeID, providerCP)
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

func (s *AttributeService) dispatchHistoryRead(h HistoryProvider, details any, nodeID *ua.NodeID, continuationPoint []byte) (*ua.HistoryReadResult, error) {
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
	case *ua.ReadProcessedDetails:
		return readProcessed(h, v, nodeID)
	case ua.ReadProcessedDetails:
		return readProcessed(h, &v, nodeID)
	default:
		return &ua.HistoryReadResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}, nil
	}
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

func readProcessed(h HistoryProvider, details *ua.ReadProcessedDetails, nodeID *ua.NodeID) (*ua.HistoryReadResult, error) {
	reader, ok := h.(ProcessedHistoryReader)
	if !ok {
		return &ua.HistoryReadResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}, nil
	}
	var agg *ua.NodeID
	if len(details.AggregateType) > 0 {
		agg = details.AggregateType[0]
	}
	return reader.ReadProcessed(nodeID, details.StartTime, details.EndTime, details.ProcessingInterval, agg, details.AggregateConfiguration)
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

	for i := range req.NodesToWrite {
		n := req.NodesToWrite[i]
		s.srv.cfg.logger.Debug("write", "node_id", n.NodeID, "attribute", n.AttributeID)

		if sc := s.srv.checkWrite(ctx, sess, n.NodeID); sc != ua.StatusOK {
			status[i] = sc
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

		if n.Value != nil && n.Value.EncodingMask&unsupportedWriteMask != 0 {
			status[i] = ua.StatusBadWriteNotSupported
			continue
		}

		if node := ns.Node(n.NodeID); node != nil {
			if st := checkAccessRestrictions(sc, node); st != ua.StatusOK {
				status[i] = st
				continue
			}
		}

		if n.IndexRange != "" {
			if n.AttributeID != ua.AttributeIDValue || n.Value == nil || n.Value.Value == nil {
				status[i] = ua.StatusBadIndexRangeInvalid
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
			status[i] = ns.SetAttribute(n.NodeID, n.AttributeID, stampWritten(&ua.DataValue{
				EncodingMask: ua.DataValueValue,
				Value:        merged,
			}, time.Now()))
			continue
		}

		if n.AttributeID != ua.AttributeIDValue {
			if st := checkAttributeWrite(ns, n.NodeID, n.AttributeID, n.Value); st != ua.StatusOK {
				status[i] = st
				continue
			}
		}

		val := n.Value
		if n.AttributeID == ua.AttributeIDValue && val != nil {
			val = stampWritten(val, time.Now())
		}
		status[i] = ns.SetAttribute(n.NodeID, n.AttributeID, val)

	}
	response := &ua.WriteResponse{
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

	return response, nil

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
		results[i] = s.dispatchHistoryUpdate(ctx, sc, sess, historian, detailEO)
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

func (s *AttributeService) dispatchHistoryUpdate(ctx context.Context, sc *uasc.SecureChannel, sess *session, h HistoryProvider, detailEO *ua.ExtensionObject) *ua.HistoryUpdateResult {
	unsupported := &ua.HistoryUpdateResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}
	if detailEO == nil || detailEO.Value == nil || h == nil {
		return unsupported
	}
	if nodeID, ok := historyUpdateNodeID(detailEO.Value); ok {
		if st := s.srv.checkDataHistory(ctx, sc, sess, nodeID, true); st != ua.StatusOK {
			return &ua.HistoryUpdateResult{StatusCode: st}
		}
	}
	switch v := detailEO.Value.(type) {
	case *ua.UpdateDataDetails:
		updater, ok := h.(HistoryDataUpdater)
		if !ok {
			return unsupported
		}
		return updater.UpdateData(v.NodeID, v.PerformInsertReplace, v.UpdateValues)
	case ua.UpdateDataDetails:
		updater, ok := h.(HistoryDataUpdater)
		if !ok {
			return unsupported
		}
		return updater.UpdateData(v.NodeID, v.PerformInsertReplace, v.UpdateValues)
	case *ua.DeleteRawModifiedDetails:
		deleter, ok := h.(RawHistoryDeleter)
		if !ok {
			return unsupported
		}
		return deleter.DeleteRawModified(v.NodeID, v.IsDeleteModified, v.StartTime, v.EndTime)
	case ua.DeleteRawModifiedDetails:
		deleter, ok := h.(RawHistoryDeleter)
		if !ok {
			return unsupported
		}
		return deleter.DeleteRawModified(v.NodeID, v.IsDeleteModified, v.StartTime, v.EndTime)
	case *ua.DeleteAtTimeDetails:
		deleter, ok := h.(AtTimeHistoryDeleter)
		if !ok {
			return unsupported
		}
		return deleter.DeleteAtTime(v.NodeID, v.ReqTimes)
	case ua.DeleteAtTimeDetails:
		deleter, ok := h.(AtTimeHistoryDeleter)
		if !ok {
			return unsupported
		}
		return deleter.DeleteAtTime(v.NodeID, v.ReqTimes)
	case *ua.UpdateEventDetails:
		return s.updateEventHistory(ctx, sc, sess, h, v)
	case ua.UpdateEventDetails:
		return s.updateEventHistory(ctx, sc, sess, h, &v)
	case *ua.DeleteEventDetails:
		return s.deleteEventHistory(ctx, sc, sess, h, v)
	case ua.DeleteEventDetails:
		return s.deleteEventHistory(ctx, sc, sess, h, &v)
	default:
		return unsupported
	}
}
