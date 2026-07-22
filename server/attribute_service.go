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

	// If ReleaseContinuationPoints is set, just release them.
	if req.ReleaseContinuationPoints && s.srv.historian != nil {
		results := make([]*ua.HistoryReadResult, len(req.NodesToRead))
		for i, n := range req.NodesToRead {
			if len(n.ContinuationPoint) > 0 {
				s.srv.historian.ReleaseContinuation(n.ContinuationPoint)
			}
			results[i] = &ua.HistoryReadResult{StatusCode: ua.StatusOK}
		}
		return &ua.HistoryReadResponse{
			ResponseHeader:  responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
			Results:         results,
			DiagnosticInfos: []*ua.DiagnosticInfo{},
		}, nil
	}

	// Extract ReadRawModifiedDetails from the HistoryReadDetails extension object.
	var rawDetails *ua.ReadRawModifiedDetails
	if req.HistoryReadDetails != nil && req.HistoryReadDetails.Value != nil {
		switch v := req.HistoryReadDetails.Value.(type) {
		case *ua.ReadRawModifiedDetails:
			rawDetails = v
		case ua.ReadRawModifiedDetails:
			rawDetails = &v
		}
	}

	// Reject modified history (IsReadModified=true).
	if rawDetails != nil && rawDetails.IsReadModified {
		results := make([]*ua.HistoryReadResult, len(req.NodesToRead))
		for i := range req.NodesToRead {
			results[i] = &ua.HistoryReadResult{
				StatusCode: ua.StatusBadHistoryOperationInvalid,
			}
		}
		return &ua.HistoryReadResponse{
			ResponseHeader:  responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
			Results:         results,
			DiagnosticInfos: []*ua.DiagnosticInfo{},
		}, nil
	}

	// If no historian is configured, return unsupported.
	if s.srv.historian == nil || rawDetails == nil {
		results := make([]*ua.HistoryReadResult, len(req.NodesToRead))
		for i := range req.NodesToRead {
			results[i] = &ua.HistoryReadResult{
				StatusCode: ua.StatusBadHistoryOperationUnsupported,
			}
		}
		return &ua.HistoryReadResponse{
			ResponseHeader:  responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
			Results:         results,
			DiagnosticInfos: []*ua.DiagnosticInfo{},
		}, nil
	}

	results := make([]*ua.HistoryReadResult, len(req.NodesToRead))
	for i, n := range req.NodesToRead {
		result, err := s.srv.historian.ReadRaw(
			n.NodeID,
			rawDetails.StartTime,
			rawDetails.EndTime,
			rawDetails.NumValuesPerNode,
			rawDetails.ReturnBounds,
			n.ContinuationPoint,
		)
		if err != nil {
			results[i] = &ua.HistoryReadResult{
				StatusCode: ua.StatusBadInternalError,
			}
			continue
		}
		results[i] = result
	}

	return &ua.HistoryReadResponse{
		ResponseHeader:  responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
		Results:         results,
		DiagnosticInfos: []*ua.DiagnosticInfo{},
	}, nil
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

	// This server does not maintain a historical data store.
	// Return BadHistoryOperationUnsupported for each update detail.
	results := make([]*ua.HistoryUpdateResult, len(req.HistoryUpdateDetails))
	for i := range req.HistoryUpdateDetails {
		results[i] = &ua.HistoryUpdateResult{
			StatusCode: ua.StatusBadHistoryOperationUnsupported,
		}
	}

	return &ua.HistoryUpdateResponse{
		ResponseHeader:  responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
		Results:         results,
		DiagnosticInfos: []*ua.DiagnosticInfo{},
	}, nil
}
