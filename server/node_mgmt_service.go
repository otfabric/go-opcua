// SPDX-License-Identifier: MIT

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
		va := variableAttributes(item)
		var initial any
		if va != nil && variableAttributeSpecified(va, ua.NodeAttributesMaskValue) && va.Value != nil {
			initial = va.Value.Value()
		}
		n = NewVariableNode(nid, name, initial)
		applyVariableAttributes(n, va)
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

// variableAttributes returns the VariableAttributes carried by an AddNodesItem,
// or nil when the client supplied none (or attributes of another node class).
func variableAttributes(item *ua.AddNodesItem) *ua.VariableAttributes {
	if item.NodeAttributes == nil {
		return nil
	}
	va, _ := item.NodeAttributes.Value.(*ua.VariableAttributes)
	return va
}

// variableAttributeSpecified reports whether the client supplied attribute m.
// A SpecifiedAttributes mask of zero is read as "everything in the structure
// is meant": open62541's client API leaves the mask unset while filling in the
// attributes, and a NodeAttributes object that specifies nothing is otherwise
// meaningless.
func variableAttributeSpecified(va *ua.VariableAttributes, m ua.NodeAttributesMask) bool {
	return va.SpecifiedAttributes == 0 || va.SpecifiedAttributes&uint32(m) != 0
}

// applyVariableAttributes copies the attributes the client marked as specified
// onto a freshly created Variable node (Part 4 §5.7.2, Part 3 §5.6.2). The
// initial Value is handled by the caller. Unspecified attributes keep the
// server defaults.
func applyVariableAttributes(n *Node, va *ua.VariableAttributes) {
	if va == nil {
		return
	}
	specified := func(m ua.NodeAttributesMask) bool { return variableAttributeSpecified(va, m) }

	if specified(ua.NodeAttributesMaskDisplayName) && va.DisplayName != nil {
		n.SetDisplayName(va.DisplayName.Text, va.DisplayName.Locale)
	}
	if specified(ua.NodeAttributesMaskDescription) && va.Description != nil {
		n.SetDescription(va.Description.Text, va.Description.Locale)
	}
	if specified(ua.NodeAttributesMaskDataType) && va.DataType != nil {
		n.attr[ua.AttributeIDDataType] = DataValueFromValue(ua.NewExpandedNodeID(va.DataType, "", 0))
	}
	if specified(ua.NodeAttributesMaskValueRank) {
		n.attr[ua.AttributeIDValueRank] = DataValueFromValue(va.ValueRank)
	}
	if specified(ua.NodeAttributesMaskAccessLevel) {
		n.attr[ua.AttributeIDAccessLevel] = DataValueFromValue(va.AccessLevel)
	}
	if specified(ua.NodeAttributesMaskUserAccessLevel) {
		n.attr[ua.AttributeIDUserAccessLevel] = DataValueFromValue(va.UserAccessLevel)
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
