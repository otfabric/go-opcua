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
			status[i] = ns.SetAttribute(n.NodeID, n.AttributeID, &ua.DataValue{
				EncodingMask: ua.DataValueValue,
				Value:        merged,
			})
			continue
		}

		status[i] = ns.SetAttribute(n.NodeID, n.AttributeID, n.Value)

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
