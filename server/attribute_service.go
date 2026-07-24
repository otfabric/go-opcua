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
	ac := s.srv.cfg.accessController

	results := make([]*ua.DataValue, len(req.NodesToRead))
	for i, n := range req.NodesToRead {
		s.srv.cfg.logger.Debug("read", "node_id", n.NodeID, "attribute", n.AttributeID)

		if sc := ac.CheckRead(ctx, sess, n.NodeID); sc != ua.StatusOK {
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

	// If ReleaseContinuationPoints is set, just release them.
	if req.ReleaseContinuationPoints && s.srv.historian != nil {
		results := make([]*ua.HistoryReadResult, len(req.NodesToRead))
		for i, n := range req.NodesToRead {
			if len(n.ContinuationPoint) > 0 {
				if s.srv.historyCPs != nil {
					s.srv.historyCPs.release(n.ContinuationPoint)
				} else {
					s.srv.historian.ReleaseContinuation(n.ContinuationPoint)
				}
			}
			results[i] = &ua.HistoryReadResult{StatusCode: ua.StatusOK}
		}
		return &ua.HistoryReadResponse{
			ResponseHeader:  responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
			Results:         results,
			DiagnosticInfos: []*ua.DiagnosticInfo{},
		}, nil
	}

	if s.srv.historian == nil {
		return unsupportedHistoryRead(req), nil
	}

	details := any(nil)
	if req.HistoryReadDetails != nil {
		details = req.HistoryReadDetails.Value
	}

	results := make([]*ua.HistoryReadResult, len(req.NodesToRead))
	for i, n := range req.NodesToRead {
		providerCP := n.ContinuationPoint
		if len(providerCP) > 0 && s.srv.historyCPs != nil {
			var st ua.StatusCode
			providerCP, st = s.srv.historyCPs.resolve(sessionAuth, providerCP)
			if st != ua.StatusOK {
				results[i] = &ua.HistoryReadResult{StatusCode: st}
				continue
			}
		}

		result, err := s.dispatchHistoryRead(details, n.NodeID, providerCP)
		if err != nil {
			results[i] = &ua.HistoryReadResult{StatusCode: ua.StatusBadInternalError}
			continue
		}
		if result == nil {
			results[i] = &ua.HistoryReadResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}
			continue
		}
		if len(result.ContinuationPoint) > 0 && s.srv.historyCPs != nil {
			result.ContinuationPoint = s.srv.historyCPs.bind(sessionAuth, result.ContinuationPoint)
		}
		results[i] = result
	}

	return &ua.HistoryReadResponse{
		ResponseHeader:  responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
		Results:         results,
		DiagnosticInfos: []*ua.DiagnosticInfo{},
	}, nil
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

func (s *AttributeService) dispatchHistoryRead(details any, nodeID *ua.NodeID, continuationPoint []byte) (*ua.HistoryReadResult, error) {
	switch v := details.(type) {
	case *ua.ReadRawModifiedDetails:
		return s.readRawModified(v, nodeID, continuationPoint)
	case ua.ReadRawModifiedDetails:
		return s.readRawModified(&v, nodeID, continuationPoint)
	case *ua.ReadAtTimeDetails:
		reader, ok := s.srv.historian.(AtTimeHistoryReader)
		if !ok {
			return &ua.HistoryReadResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}, nil
		}
		return reader.ReadAtTime(nodeID, v.ReqTimes, v.UseSimpleBounds)
	case ua.ReadAtTimeDetails:
		reader, ok := s.srv.historian.(AtTimeHistoryReader)
		if !ok {
			return &ua.HistoryReadResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}, nil
		}
		return reader.ReadAtTime(nodeID, v.ReqTimes, v.UseSimpleBounds)
	case *ua.ReadProcessedDetails:
		return s.readProcessed(v, nodeID)
	case ua.ReadProcessedDetails:
		return s.readProcessed(&v, nodeID)
	default:
		return &ua.HistoryReadResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}, nil
	}
}

func (s *AttributeService) readRawModified(details *ua.ReadRawModifiedDetails, nodeID *ua.NodeID, continuationPoint []byte) (*ua.HistoryReadResult, error) {
	if details.IsReadModified {
		reader, ok := s.srv.historian.(ModifiedHistoryReader)
		if !ok {
			return &ua.HistoryReadResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}, nil
		}
		return reader.ReadModified(nodeID, details.StartTime, details.EndTime, details.NumValuesPerNode, continuationPoint)
	}
	return s.srv.historian.ReadRaw(
		nodeID,
		details.StartTime,
		details.EndTime,
		details.NumValuesPerNode,
		details.ReturnBounds,
		continuationPoint,
	)
}

func (s *AttributeService) readProcessed(details *ua.ReadProcessedDetails, nodeID *ua.NodeID) (*ua.HistoryReadResult, error) {
	reader, ok := s.srv.historian.(ProcessedHistoryReader)
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
	ac := s.srv.cfg.accessController

	status := make([]ua.StatusCode, len(req.NodesToWrite))

	for i := range req.NodesToWrite {
		n := req.NodesToWrite[i]
		s.srv.cfg.logger.Debug("write", "node_id", n.NodeID, "attribute", n.AttributeID)

		if sc := ac.CheckWrite(ctx, sess, n.NodeID); sc != ua.StatusOK {
			status[i] = sc
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
			if cur == nil || cur.Status != ua.StatusOK || cur.Value == nil {
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

	results := make([]*ua.HistoryUpdateResult, len(req.HistoryUpdateDetails))
	for i, detailEO := range req.HistoryUpdateDetails {
		results[i] = s.dispatchHistoryUpdate(detailEO)
	}

	return &ua.HistoryUpdateResponse{
		ResponseHeader:  responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
		Results:         results,
		DiagnosticInfos: []*ua.DiagnosticInfo{},
	}, nil
}

func (s *AttributeService) dispatchHistoryUpdate(detailEO *ua.ExtensionObject) *ua.HistoryUpdateResult {
	unsupported := &ua.HistoryUpdateResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}
	if detailEO == nil || detailEO.Value == nil || s.srv.historian == nil {
		return unsupported
	}
	switch v := detailEO.Value.(type) {
	case *ua.UpdateDataDetails:
		updater, ok := s.srv.historian.(HistoryDataUpdater)
		if !ok {
			return unsupported
		}
		return updater.UpdateData(v.NodeID, v.PerformInsertReplace, v.UpdateValues)
	case ua.UpdateDataDetails:
		updater, ok := s.srv.historian.(HistoryDataUpdater)
		if !ok {
			return unsupported
		}
		return updater.UpdateData(v.NodeID, v.PerformInsertReplace, v.UpdateValues)
	case *ua.DeleteRawModifiedDetails:
		deleter, ok := s.srv.historian.(RawHistoryDeleter)
		if !ok {
			return unsupported
		}
		return deleter.DeleteRawModified(v.NodeID, v.IsDeleteModified, v.StartTime, v.EndTime)
	case ua.DeleteRawModifiedDetails:
		deleter, ok := s.srv.historian.(RawHistoryDeleter)
		if !ok {
			return unsupported
		}
		return deleter.DeleteRawModified(v.NodeID, v.IsDeleteModified, v.StartTime, v.EndTime)
	case *ua.DeleteAtTimeDetails:
		deleter, ok := s.srv.historian.(AtTimeHistoryDeleter)
		if !ok {
			return unsupported
		}
		return deleter.DeleteAtTime(v.NodeID, v.ReqTimes)
	case ua.DeleteAtTimeDetails:
		deleter, ok := s.srv.historian.(AtTimeHistoryDeleter)
		if !ok {
			return unsupported
		}
		return deleter.DeleteAtTime(v.NodeID, v.ReqTimes)
	default:
		return unsupported
	}
}
