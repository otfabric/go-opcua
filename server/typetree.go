// SPDX-License-Identifier: MIT

package server

import (
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// nodeEnumerator is an optional interface implemented by namespaces that can
// enumerate their nodes. The Query service uses it to scan candidate nodes;
// namespaces that do not implement it are skipped.
type nodeEnumerator interface {
	// Nodes returns a snapshot of the nodes managed by the namespace.
	Nodes() []*Node
}

// Nodes returns a snapshot of the nodes in the namespace.
func (as *NodeNameSpace) Nodes() []*Node {
	as.mu.RLock()
	defer as.mu.RUnlock()
	out := make([]*Node, len(as.nodes))
	copy(out, as.nodes)
	return out
}

// Nodes synthesizes variable nodes for every key in the map namespace so the
// Query service can enumerate and type-match them. Each node is typed as a
// BaseDataVariableType via a HasTypeDefinition reference.
func (ns *MapNamespace) Nodes() []*Node {
	ns.Mu.RLock()
	keys := make([]string, 0, len(ns.Data))
	for k := range ns.Data {
		keys = append(keys, k)
	}
	ns.Mu.RUnlock()

	typedef := ua.NewNumericExpandedNodeID(0, id.BaseDataVariableType)
	out := make([]*Node, 0, len(keys))
	for _, k := range keys {
		nid := ua.NewStringNodeID(ns.ID(), k)
		n := NewNode(
			nid,
			map[ua.AttributeID]*ua.DataValue{
				ua.AttributeIDNodeClass: DataValueFromValue(uint32(ua.NodeClassVariable)),
			},
			[]*ua.ReferenceDescription{{
				ReferenceTypeID: ua.NewNumericNodeID(0, id.HasTypeDefinition),
				IsForward:       true,
				NodeID:          typedef,
			}},
			nil,
		)
		out = append(out, n)
	}
	return out
}

// nodeTypeDefinition returns the TypeDefinition NodeID of a node, i.e. the
// target of its forward HasTypeDefinition reference, or nil if it has none.
func nodeTypeDefinition(n *Node) *ua.NodeID {
	if n == nil {
		return nil
	}
	n.mu.RLock()
	defer n.mu.RUnlock()
	for _, r := range n.refs {
		if r == nil || r.NodeID == nil || r.ReferenceTypeID == nil {
			continue
		}
		if r.IsForward && r.ReferenceTypeID.IntID() == id.HasTypeDefinition {
			return r.NodeID.NodeID
		}
	}
	return nil
}

// isSubtypeOf reports whether sub is super or a (transitive) subtype of super,
// following forward HasSubtype references from super down the type tree.
func (s *Server) isSubtypeOf(sub, super *ua.NodeID) bool {
	if sub == nil || super == nil {
		return false
	}
	if sub.Equal(super) {
		return true
	}
	for _, t := range getSubRefs(s, super) {
		if t.Equal(sub) {
			return true
		}
	}
	return false
}

// resolveRelativePath walks a RelativePath from the start node and returns the
// NodeID of the final target. It mirrors the matching logic used by
// TranslateBrowsePathsToNodeIDs so View and Query share resolution semantics.
func (s *Server) resolveRelativePath(start *ua.NodeID, rp *ua.RelativePath) (*ua.NodeID, ua.StatusCode) {
	if start == nil || rp == nil || len(rp.Elements) == 0 {
		return nil, ua.StatusBadBrowseNameInvalid
	}

	current := s.Node(start)
	if current == nil {
		return nil, ua.StatusBadNodeIDUnknown
	}

	for _, elem := range rp.Elements {
		if elem.TargetName == nil {
			return nil, ua.StatusBadBrowseNameInvalid
		}

		next := s.followPathElement(current, elem)
		if next == nil {
			return nil, ua.StatusBadNoMatch
		}
		current = next
	}

	return current.ID(), ua.StatusGood
}

// followPathElement returns the node reached by following one RelativePath
// element from current, or nil if no reference matches.
func (s *Server) followPathElement(current *Node, elem *ua.RelativePathElement) *Node {
	current.mu.RLock()
	refs := make([]*ua.ReferenceDescription, len(current.refs))
	copy(refs, current.refs)
	current.mu.RUnlock()

	for _, ref := range refs {
		if ref.NodeID == nil || ref.BrowseName == nil {
			continue
		}
		if elem.IsInverse && ref.IsForward {
			continue
		}
		if !elem.IsInverse && !ref.IsForward {
			continue
		}
		if elem.ReferenceTypeID != nil && !elem.ReferenceTypeID.Equal(ua.NewNumericNodeID(0, 0)) {
			if !elem.ReferenceTypeID.Equal(ref.ReferenceTypeID) {
				if !elem.IncludeSubtypes {
					continue
				}
				if !suitableRefType(s, elem.ReferenceTypeID, ref.ReferenceTypeID, true) {
					continue
				}
			}
		}
		if ref.BrowseName.Name != elem.TargetName.Name {
			continue
		}
		if elem.TargetName.NamespaceIndex != 0 && ref.BrowseName.NamespaceIndex != elem.TargetName.NamespaceIndex {
			continue
		}
		if next := s.Node(ref.NodeID.NodeID); next != nil {
			return next
		}
	}
	return nil
}
