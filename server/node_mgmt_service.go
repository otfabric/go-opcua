package server

import (
	"context"
	"fmt"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

// NodeManagementService implements the Node Management Service Set.
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.7
type NodeManagementService struct {
	srv *Server
}

// AddNodes implements the OPC UA AddNodes service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.7.2
func (s *NodeManagementService) AddNodes(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.srv.cfg.logger.Debug("handling request", "type", fmt.Sprintf("%T", r))

	req, err := safeReq[*ua.AddNodesRequest](r)
	if err != nil {
		return nil, err
	}

	results := make([]*ua.AddNodesResult, len(req.NodesToAdd))
	for i, item := range req.NodesToAdd {
		results[i] = s.addNode(item)
	}

	return &ua.AddNodesResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		Results:         results,
		DiagnosticInfos: []*ua.DiagnosticInfo{},
	}, nil
}

func (s *NodeManagementService) addNode(item *ua.AddNodesItem) *ua.AddNodesResult {
	if item.RequestedNewNodeID == nil || item.RequestedNewNodeID.NodeID == nil {
		return &ua.AddNodesResult{StatusCode: ua.StatusBadNodeIDInvalid}
	}
	nid := item.RequestedNewNodeID.NodeID
	ns, err := s.srv.Namespace(int(nid.Namespace()))
	if err != nil {
		return &ua.AddNodesResult{StatusCode: ua.StatusBadNodeIDUnknown}
	}

	// Check if node already exists.
	if ns.Node(nid) != nil {
		return &ua.AddNodesResult{StatusCode: ua.StatusBadNodeIDExists}
	}

	name := ""
	if item.BrowseName != nil {
		name = item.BrowseName.Name
	}

	var n *Node
	switch item.NodeClass {
	case ua.NodeClassVariable:
		n = NewVariableNode(nid, name, nil)
	default:
		n = NewFolderNode(nid, name)
		n.SetNodeClass(item.NodeClass)
	}
	ns.AddNode(n)

	// Add reference from parent if specified.
	if item.ParentNodeID != nil && item.ParentNodeID.NodeID != nil && item.ReferenceTypeID != nil {
		parent := s.srv.Node(item.ParentNodeID.NodeID)
		if parent != nil {
			parent.AddRef(n, RefType(item.ReferenceTypeID.IntID()), true)
		}
	}

	return &ua.AddNodesResult{
		StatusCode:  ua.StatusGood,
		AddedNodeID: nid,
	}
}

// AddReferences implements the OPC UA AddReferences service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.7.3
func (s *NodeManagementService) AddReferences(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.srv.cfg.logger.Debug("handling request", "type", fmt.Sprintf("%T", r))

	req, err := safeReq[*ua.AddReferencesRequest](r)
	if err != nil {
		return nil, err
	}

	results := make([]ua.StatusCode, len(req.ReferencesToAdd))
	for i, item := range req.ReferencesToAdd {
		if item.SourceNodeID == nil {
			results[i] = ua.StatusBadSourceNodeIDInvalid
			continue
		}
		if item.ReferenceTypeID == nil {
			results[i] = ua.StatusBadReferenceTypeIDInvalid
			continue
		}
		if item.TargetNodeID == nil || item.TargetNodeID.NodeID == nil {
			results[i] = ua.StatusBadTargetNodeIDInvalid
			continue
		}

		sourceNode := s.srv.Node(item.SourceNodeID)
		if sourceNode == nil {
			results[i] = ua.StatusBadSourceNodeIDInvalid
			continue
		}

		targetNode := s.srv.Node(item.TargetNodeID.NodeID)
		if targetNode == nil {
			results[i] = ua.StatusBadTargetNodeIDInvalid
			continue
		}

		sourceNode.AddRef(targetNode, RefType(item.ReferenceTypeID.IntID()), item.IsForward)
		results[i] = ua.StatusOK
	}

	return &ua.AddReferencesResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		Results:         results,
		DiagnosticInfos: []*ua.DiagnosticInfo{},
	}, nil
}

// DeleteNodes implements the OPC UA DeleteNodes service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.7.4
func (s *NodeManagementService) DeleteNodes(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.srv.cfg.logger.Debug("handling request", "type", fmt.Sprintf("%T", r))

	req, err := safeReq[*ua.DeleteNodesRequest](r)
	if err != nil {
		return nil, err
	}

	results := make([]ua.StatusCode, len(req.NodesToDelete))
	for i, item := range req.NodesToDelete {
		if item.NodeID == nil {
			results[i] = ua.StatusBadNodeIDInvalid
			continue
		}
		ns, err := s.srv.Namespace(int(item.NodeID.Namespace()))
		if err != nil {
			results[i] = ua.StatusBadNodeIDUnknown
			continue
		}
		results[i] = ns.DeleteNode(item.NodeID)
	}

	return &ua.DeleteNodesResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		Results:         results,
		DiagnosticInfos: []*ua.DiagnosticInfo{},
	}, nil
}

// DeleteReferences implements the OPC UA DeleteReferences service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.7.5
func (s *NodeManagementService) DeleteReferences(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.srv.cfg.logger.Debug("handling request", "type", fmt.Sprintf("%T", r))

	req, err := safeReq[*ua.DeleteReferencesRequest](r)
	if err != nil {
		return nil, err
	}

	results := make([]ua.StatusCode, len(req.ReferencesToDelete))
	for i, item := range req.ReferencesToDelete {
		if item.SourceNodeID == nil {
			results[i] = ua.StatusBadSourceNodeIDInvalid
			continue
		}
		if item.ReferenceTypeID == nil {
			results[i] = ua.StatusBadReferenceTypeIDInvalid
			continue
		}
		if item.TargetNodeID == nil || item.TargetNodeID.NodeID == nil {
			results[i] = ua.StatusBadTargetNodeIDInvalid
			continue
		}

		sourceNode := s.srv.Node(item.SourceNodeID)
		if sourceNode == nil {
			results[i] = ua.StatusBadSourceNodeIDInvalid
			continue
		}

		removed := sourceNode.RemoveRef(item.TargetNodeID, item.ReferenceTypeID, item.IsForward)
		if !removed {
			results[i] = ua.StatusBadNotFound
			continue
		}

		// If DeleteBidirectional, also remove the inverse ref from the target.
		if item.DeleteBidirectional {
			targetNode := s.srv.Node(item.TargetNodeID.NodeID)
			if targetNode != nil {
				inverseTarget := ua.NewExpandedNodeID(item.SourceNodeID, "", 0)
				targetNode.RemoveRef(inverseTarget, item.ReferenceTypeID, !item.IsForward)
			}
		}

		results[i] = ua.StatusOK
	}

	return &ua.DeleteReferencesResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		Results:         results,
		DiagnosticInfos: []*ua.DiagnosticInfo{},
	}, nil
}
