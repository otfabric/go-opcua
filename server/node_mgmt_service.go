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
// The service set is optional (Part 4 §5.7; the Node Management facets of
// Part 7) and off unless the server is created with [EnableNodeManagement]:
// without it AddNodes, AddReferences, DeleteNodes and DeleteReferences
// answer Bad_ServiceUnsupported. With it, each operation is authorized; see
// [NodeManagementAccessController].
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.7
type NodeManagementService struct {
	srv *Server
}

// EnableNodeManagement lets clients change the address space with the
// AddNodes, AddReferences, DeleteNodes and DeleteReferences services. Each
// operation is authorized:
//
//   - An [AccessController] that implements [NodeManagementAccessController]
//     decides every operation ([RBACAccessController] does, from the
//     AddNode, DeleteNode, AddReference and RemoveReference permissions).
//   - Any other AccessController, the [DefaultAccessController] included, is
//     asked CheckWrite for the node the operation changes: the parent of
//     AddNodes, the node of DeleteNodes and the source node of
//     AddReferences and DeleteReferences. Nodes of namespace 0 cannot be
//     added or deleted and their references cannot be changed.
//
// The diagnostics nodes of other sessions are never changed. A refused
// operation answers Bad_UserAccessDenied (Part 4 §5.7.2 to §5.7.5).
func EnableNodeManagement() Option {
	return func(s *serverConfig) error {
		s.nodeManagement = true
		return nil
	}
}

// NodeManagementAccessController is an [AccessController] that also decides
// the operations of the Node Management services, which the server asks it
// once [EnableNodeManagement] is set. Return [ua.StatusOK] to allow the
// operation, or a Bad status (e.g. [ua.StatusBadUserAccessDenied]) as its
// result.
type NodeManagementAccessController interface {
	CheckAddNodes(ctx context.Context, session *Session, item *ua.AddNodesItem) ua.StatusCode
	CheckDeleteNodes(ctx context.Context, session *Session, item *ua.DeleteNodesItem) ua.StatusCode
	CheckAddReferences(ctx context.Context, session *Session, item *ua.AddReferencesItem) ua.StatusCode
	CheckDeleteReferences(ctx context.Context, session *Session, item *ua.DeleteReferencesItem) ua.StatusCode
}

// nodeManagementOp is one operation of the Node Management services.
type nodeManagementOp struct {
	// node is the node the operation changes: the parent of AddNodes, the
	// node of DeleteNodes, the source node of Add/DeleteReferences.
	node *ua.NodeID
	// created is the node AddNodes creates or DeleteNodes deletes, nil for
	// the reference services.
	created *ua.NodeID
	// controller asks a NodeManagementAccessController.
	controller func(NodeManagementAccessController, *Session) ua.StatusCode
}

// checkNodeManagement authorizes one node management operation.
func (s *NodeManagementService) checkNodeManagement(ctx context.Context, sess *session, op nodeManagementOp) ua.StatusCode {
	for _, nid := range []*ua.NodeID{op.node, op.created} {
		if nid != nil {
			if st := s.srv.diag.checkWrite(sess, nid); st != ua.StatusOK {
				return st
			}
		}
	}
	if nmac, ok := s.srv.cfg.accessController.(NodeManagementAccessController); ok {
		return op.controller(nmac, sess.handle())
	}
	// Namespace 0 is the standard address space: its nodes are not added
	// or deleted, and their references are not changed, unless a
	// NodeManagementAccessController allows it. AddNodes below a node of
	// namespace 0 (the Objects folder) is allowed.
	if op.created != nil && op.created.Namespace() == 0 {
		return ua.StatusBadUserAccessDenied
	}
	if op.created == nil && op.node != nil && op.node.Namespace() == 0 {
		return ua.StatusBadUserAccessDenied
	}
	target := op.node
	if target == nil {
		target = op.created
	}
	if target == nil {
		return ua.StatusOK // an invalid item, refused by the service
	}
	return s.srv.cfg.accessController.CheckWrite(ctx, sess.handle(), target)
}

// enabled returns Bad_ServiceUnsupported unless node management is on.
func (s *NodeManagementService) enabled() error {
	if !s.srv.cfg.nodeManagement {
		return ua.StatusBadServiceUnsupported
	}
	return nil
}

// expandedLocal returns the local NodeId of an ExpandedNodeId, nil if none.
func expandedLocal(e *ua.ExpandedNodeID) *ua.NodeID {
	if e == nil {
		return nil
	}
	return e.NodeID
}

// AddNodes implements the OPC UA AddNodes service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.7.2
func (s *NodeManagementService) AddNodes(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.srv.cfg.logger.Debug("handling request", "type", fmt.Sprintf("%T", r))

	req, err := safeReq[*ua.AddNodesRequest](r)
	if err != nil {
		return nil, err
	}
	if err := s.enabled(); err != nil {
		return nil, err
	}
	sess := s.srv.sb.Session(req.RequestHeader.AuthenticationToken)

	results := make([]*ua.AddNodesResult, len(req.NodesToAdd))
	for i, item := range req.NodesToAdd {
		if item == nil {
			results[i] = &ua.AddNodesResult{StatusCode: ua.StatusBadNodeIDInvalid}
			continue
		}
		st := s.checkNodeManagement(ctx, sess, nodeManagementOp{
			node:    expandedLocal(item.ParentNodeID),
			created: expandedLocal(item.RequestedNewNodeID),
			controller: func(c NodeManagementAccessController, h *Session) ua.StatusCode {
				return c.CheckAddNodes(ctx, h, item)
			},
		})
		if st != ua.StatusOK {
			results[i] = &ua.AddNodesResult{StatusCode: st}
			continue
		}
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
	if item.BrowseName != nil {
		// The BrowseName the client asked for, in its namespace.
		n.attr[ua.AttributeIDBrowseName] = DataValueFromValue(&ua.QualifiedName{NamespaceIndex: item.BrowseName.NamespaceIndex, Name: item.BrowseName.Name})
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
	// The Write service lets clients write the other attributes only where
	// the WriteMask allows it (Part 3 §5.2.7, §5.2.8).
	if specified(ua.NodeAttributesMaskWriteMask) {
		n.attr[ua.AttributeIDWriteMask] = DataValueFromValue(va.WriteMask)
	}
	if specified(ua.NodeAttributesMaskUserWriteMask) {
		n.attr[ua.AttributeIDUserWriteMask] = DataValueFromValue(va.UserWriteMask)
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
	if err := s.enabled(); err != nil {
		return nil, err
	}
	sess := s.srv.sb.Session(req.RequestHeader.AuthenticationToken)

	results := make([]ua.StatusCode, len(req.ReferencesToAdd))
	for i, item := range req.ReferencesToAdd {
		if item == nil || item.SourceNodeID == nil {
			results[i] = ua.StatusBadSourceNodeIDInvalid
			continue
		}
		if st := s.checkNodeManagement(ctx, sess, nodeManagementOp{
			node: item.SourceNodeID,
			controller: func(c NodeManagementAccessController, h *Session) ua.StatusCode {
				return c.CheckAddReferences(ctx, h, item)
			},
		}); st != ua.StatusOK {
			results[i] = st
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

		// A ReferenceType of any namespace, which must exist as a
		// ReferenceType node (Part 4 §5.7.3).
		if rt := s.srv.Node(item.ReferenceTypeID); rt == nil || rt.NodeClass() != ua.NodeClassReferenceType {
			results[i] = ua.StatusBadReferenceTypeIDInvalid
			continue
		}
		if !sourceNode.addRef(targetNode, item.ReferenceTypeID, item.IsForward) {
			results[i] = ua.StatusBadDuplicateReferenceNotAllowed
			continue
		}
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
	if err := s.enabled(); err != nil {
		return nil, err
	}
	sess := s.srv.sb.Session(req.RequestHeader.AuthenticationToken)

	results := make([]ua.StatusCode, len(req.NodesToDelete))
	for i, item := range req.NodesToDelete {
		if item == nil || item.NodeID == nil {
			results[i] = ua.StatusBadNodeIDInvalid
			continue
		}
		if st := s.checkNodeManagement(ctx, sess, nodeManagementOp{
			node:    item.NodeID,
			created: item.NodeID,
			controller: func(c NodeManagementAccessController, h *Session) ua.StatusCode {
				return c.CheckDeleteNodes(ctx, h, item)
			},
		}); st != ua.StatusOK {
			results[i] = st
			continue
		}
		ns, err := s.srv.Namespace(int(item.NodeID.Namespace()))
		if err != nil {
			results[i] = ua.StatusBadNodeIDUnknown
			continue
		}
		// deleteTargetReferences: the references of which the node is the
		// target go from their source nodes too (Part 4 §5.7.4). Those of
		// which it is the source always go, with DeleteNode.
		var sources []*ua.ReferenceDescription
		if n := s.srv.Node(item.NodeID); n != nil && item.DeleteTargetReferences {
			sources = n.refsSnapshot()
		}
		results[i] = ns.DeleteNode(item.NodeID)
		if results[i] == ua.StatusGood {
			self := ua.NewExpandedNodeID(item.NodeID, "", 0)
			for _, r := range sources {
				if r == nil || r.IsForward || r.NodeID == nil || r.NodeID.NodeID == nil {
					continue
				}
				if src := s.srv.Node(r.NodeID.NodeID); src != nil {
					src.removeRefEnd(self, r.ReferenceTypeID, true)
				}
			}
		}
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
	if err := s.enabled(); err != nil {
		return nil, err
	}
	sess := s.srv.sb.Session(req.RequestHeader.AuthenticationToken)

	results := make([]ua.StatusCode, len(req.ReferencesToDelete))
	for i, item := range req.ReferencesToDelete {
		if item == nil || item.SourceNodeID == nil {
			results[i] = ua.StatusBadSourceNodeIDInvalid
			continue
		}
		if st := s.checkNodeManagement(ctx, sess, nodeManagementOp{
			node: item.SourceNodeID,
			controller: func(c NodeManagementAccessController, h *Session) ua.StatusCode {
				return c.CheckDeleteReferences(ctx, h, item)
			},
		}); st != ua.StatusOK {
			results[i] = st
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

		// The source end only, unless deleteBidirectional (Part 4 §5.7.5).
		removed := sourceNode.removeRefEnd(item.TargetNodeID, item.ReferenceTypeID, item.IsForward)
		if !removed {
			results[i] = ua.StatusBadNotFound
			continue
		}
		if item.DeleteBidirectional {
			if targetNode := s.srv.Node(item.TargetNodeID.NodeID); targetNode != nil {
				inverseTarget := ua.NewExpandedNodeID(item.SourceNodeID, "", 0)
				targetNode.removeRefEnd(inverseTarget, item.ReferenceTypeID, !item.IsForward)
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
