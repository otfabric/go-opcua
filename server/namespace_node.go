// SPDX-License-Identifier: MIT

package server

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
)

// NodeNameSpace is the base "node-centric" namespace.
type NodeNameSpace struct {
	srv            *Server
	name           string
	mu             sync.RWMutex
	nodes          []*Node
	m              map[string]*Node
	id             uint16
	nodeidSequence uint32

	ExternalNotification chan *ua.NodeID
}

func (as *NodeNameSpace) GetNextNodeID() uint32 {
	if as.nodeidSequence < 100 {
		as.nodeidSequence = 100
	}
	return atomic.AddUint32(&(as.nodeidSequence), 1)
}

func NewNodeNameSpace(srv *Server, name string) *NodeNameSpace {
	ns := &NodeNameSpace{
		srv:                  srv,
		name:                 name,
		nodes:                make([]*Node, 0),
		m:                    make(map[string]*Node),
		ExternalNotification: make(chan *ua.NodeID),
	}
	srv.AddNamespace(ns)

	//objectsNode := NewFolderNode(ua.NewNumericNodeID(ns.id, id.ObjectsFolder), ns.name)
	oid := ua.NewNumericNodeID(ns.ID(), id.ObjectsFolder)
	//eoid := ua.NewNumericExpandedNodeID(ns.ID(), id.ObjectsFolder)
	typedef := ua.NewNumericExpandedNodeID(0, id.ObjectsFolder)
	//reftype := ua.NewTwoByteNodeID(uint8(id.HasComponent)) // folder
	objectsNode := NewNode(
		oid,
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:     DataValueFromValue(uint32(ua.NodeClassObject)),
			ua.AttributeIDBrowseName:    DataValueFromValue(attrs.BrowseName(ns.name)),
			ua.AttributeIDDisplayName:   DataValueFromValue(attrs.DisplayName(ns.name, ns.name)),
			ua.AttributeIDDescription:   DataValueFromValue(&ua.LocalizedText{}),
			ua.AttributeIDDataType:      DataValueFromValue(typedef),
			ua.AttributeIDEventNotifier: DataValueFromValue(byte(0)),
		},
		[]*ua.ReferenceDescription{},
		nil,
	)

	ns.AddNode(objectsNode)

	return ns

}

// ChangeNotification notifies OPC UA subscribers if a node was changed
// without using the SetAttribute method.
func (as *NodeNameSpace) ChangeNotification(nodeid *ua.NodeID) {
	as.srv.ChangeNotification(nodeid)
}

func (as *NodeNameSpace) Name() string {
	return as.name
}

// NewNameSpace creates a bare NodeNameSpace with no server back-reference.
// It is intended only for the ns:0 bootstrap path inside New(); the server
// patches srv immediately afterwards. For user-defined namespaces always use
// NewNodeNameSpace(srv, name), which sets srv correctly from the start.
func NewNameSpace(name string) *NodeNameSpace {
	return &NodeNameSpace{name: name, m: map[string]*Node{}}
}

func (as *NodeNameSpace) AddNode(n *Node) *Node {
	as.mu.Lock()
	defer as.mu.Unlock()

	k := n.ID().String()

	// If a node with the same ID already exists, replace it in the slice.
	if old, exists := as.m[k]; exists {
		for i, node := range as.nodes {
			if node == old {
				as.nodes[i] = n
				break
			}
		}
	} else {
		as.nodes = append(as.nodes, n)
	}

	as.m[k] = n
	n.ns = as
	return n
}

// DeleteNode removes the node nid and the references it is the source of,
// also from the targets that hold their inverse direction (Part 4 §5.7.4:
// deleting a Node deletes its References; AddRef records both ends). The
// references of which it is the target stay with their source nodes.
func (as *NodeNameSpace) DeleteNode(nid *ua.NodeID) ua.StatusCode {
	as.mu.Lock()
	k := nid.String()
	n, ok := as.m[k]
	if !ok {
		as.mu.Unlock()
		return ua.StatusBadNodeIDUnknown
	}
	delete(as.m, k)

	// Remove from slice.
	for i, node := range as.nodes {
		if node == n {
			as.nodes = append(as.nodes[:i], as.nodes[i+1:]...)
			break
		}
	}
	as.mu.Unlock()

	// Without as.mu: the targets may be nodes of this namespace.
	as.unlinkTargets(n)
	return ua.StatusGood
}

// unlinkTargets removes the inverse direction of the forward references of
// the deleted node n from their targets.
func (as *NodeNameSpace) unlinkTargets(n *Node) {
	if as.srv == nil {
		return
	}
	self := ua.NewExpandedNodeID(n.ID(), "", 0)
	for _, r := range n.refsSnapshot() {
		if r == nil || !r.IsForward || r.NodeID == nil || r.NodeID.NodeID == nil || r.ReferenceTypeID == nil {
			continue
		}
		if t := as.srv.Node(r.NodeID.NodeID); t != nil && t != n {
			t.RemoveRef(self, r.ReferenceTypeID, false)
		}
	}
}

func (as *NodeNameSpace) AddNewVariableNode(name string, value any) *Node {
	n := NewVariableNode(ua.NewNumericNodeID(as.id, as.GetNextNodeID()), name, value)
	as.AddNode(n)
	return n
}
func (as *NodeNameSpace) AddNewVariableStringNode(name string, value any) *Node {
	n := NewVariableNode(ua.NewStringNodeID(as.id, name), name, value)
	as.AddNode(n)
	return n
}

func (as *NodeNameSpace) Attribute(id *ua.NodeID, attr ua.AttributeID) *ua.DataValue {
	n := as.Node(id)
	if n == nil {
		return &ua.DataValue{
			EncodingMask:    ua.DataValueServerTimestamp | ua.DataValueStatusCode,
			ServerTimestamp: time.Now(),
			Status:          ua.StatusBadNodeIDUnknown,
		}
	}

	if !n.Access(ua.AccessLevelTypeCurrentRead) {
		return &ua.DataValue{
			EncodingMask:    ua.DataValueServerTimestamp | ua.DataValueStatusCode,
			ServerTimestamp: time.Now(),
			Status:          ua.StatusBadUserAccessDenied,
		}
	}

	var err error
	var a *AttrValue

	switch attr {
	case ua.AttributeIDNodeID:
		a = &AttrValue{Value: DataValueFromValue(id)}
	case ua.AttributeIDEventNotifier:
		a, err = n.Attribute(attr)
		if err != nil {
			// Default to EventNotifier=0 (no events) if not set.
			a = &AttrValue{Value: DataValueFromValue(byte(0))}
			err = nil
		}
	case ua.AttributeIDNodeClass:
		a, err = n.Attribute(attr)
		if err != nil {
			return &ua.DataValue{
				EncodingMask:    ua.DataValueServerTimestamp | ua.DataValueStatusCode,
				ServerTimestamp: time.Now(),
				Status:          ua.StatusBadAttributeIDInvalid,
			}
		}
		// NodeClass attribute is spec'd as Int32 (Part 3 §5.2.1) but stored as uint32
		// due to the ua.NodeClass type. Convert at read time until the root type is fixed.
		x, ok := a.Value.Value.Value().(uint32)
		if ok {
			a.Value.Value = ua.MustVariant(int32(x))
		}
	case ua.AttributeIDDataType:
		a, err = n.Attribute(attr)
		if err == nil {
			if dt := variableDataType(n, a.Value); dt != nil {
				a = &AttrValue{Value: DataValueFromValue(dt)}
			}
		}
	default:
		a, err = n.Attribute(attr)
	}

	if err != nil {
		return &ua.DataValue{
			EncodingMask:    ua.DataValueServerTimestamp | ua.DataValueStatusCode,
			ServerTimestamp: time.Now(),
			Status:          ua.StatusBadAttributeIDInvalid,
		}
	}
	return a.Value
}

// variableDataType returns the NodeId to report for the DataType attribute of
// a Variable node, or nil to report the stored attribute unchanged.
//
// The DataType attribute is a NodeId (Part 3 §5.6.2). Nodes built with
// NewVariableNode for a value function store an ExpandedNodeId placeholder
// (i=267, which is not a data type): their data type is derived from the
// current value, the same way MapNamespace does. Other stored
// ExpandedNodeIds are reported as the plain NodeId they wrap.
func variableDataType(n *Node, stored *ua.DataValue) *ua.NodeID {
	if n.NodeClass() != ua.NodeClassVariable || stored == nil || stored.Value == nil {
		return nil
	}
	en, ok := stored.Value.Value().(*ua.ExpandedNodeID)
	if !ok || en == nil || en.NodeID == nil {
		return nil
	}
	if en.NodeID.Namespace() != 0 || en.NodeID.IntID() != id.VariableNode {
		return en.NodeID
	}
	if dv := n.Value(); dv != nil {
		return variantDataType(dv.Value)
	}
	return ua.NewNumericNodeID(0, id.BaseDataType)
}

func (as *NodeNameSpace) Node(id *ua.NodeID) *Node {
	as.mu.RLock()
	defer as.mu.RUnlock()
	if id == nil {
		return nil
	}
	k := id.String()

	n := as.m[k]
	if n == nil {
		return nil
	}
	return n
}

func (as *NodeNameSpace) Objects() *Node {
	of := ua.NewNumericNodeID(as.id, id.ObjectsFolder)
	return as.Node(of)
}

func (as *NodeNameSpace) Root() *Node {
	return as.Node(RootFolder)
}

func (as *NodeNameSpace) Browse(bd *ua.BrowseDescription) *ua.BrowseResult {
	// as.mu must not be held here: as.Node (and Server.Node for the type
	// definitions below) take the read lock themselves, and a recursive
	// RLock deadlocks as soon as a writer (AddNode/DeleteNode) is waiting.
	as.srv.cfg.logger.Debug("browse request", "node_id", bd.NodeID, "result_mask", bd.ResultMask)

	n := as.Node(bd.NodeID)
	if n == nil {
		return &ua.BrowseResult{StatusCode: ua.StatusBadNodeIDUnknown}
	}

	nodeRefs := n.refsSnapshot()
	refs := make([]*ua.ReferenceDescription, 0, len(nodeRefs))

	for _, r := range nodeRefs {
		// we can't have nils in these or the encoder will fail.
		if r.NodeID == nil || r.BrowseName == nil || r.DisplayName == nil || r.TypeDefinition == nil {
			continue
		}

		// see if this is a ref the client was interested in.
		if !suitableRef(as.srv, bd, r) {
			continue
		}

		td := as.srv.Node(r.NodeID.NodeID)

		// The target may be gone (deleted concurrently, or a dangling
		// reference left behind by DeleteNode). A nil ExpandedNodeID cannot
		// be encoded and would make the whole Browse response unsendable, so
		// report the null NodeId instead.
		typeDefinition := browseTypeDefinition(td)

		isTypeDef := r.ReferenceTypeID != nil && r.ReferenceTypeID.IntID() == id.HasTypeDefinition && r.IsForward
		rf := applyBrowseResultMask(&ua.ReferenceDescription{
			ReferenceTypeID: r.ReferenceTypeID,
			IsForward:       r.IsForward,
			NodeID:          r.NodeID,
			BrowseName:      r.BrowseName,
			DisplayName:     r.DisplayName,
			NodeClass:       r.NodeClass,
			TypeDefinition:  typeDefinition,
		}, bd.ResultMask)

		if isTypeDef {
			// this one has to be first!
			refs = append([]*ua.ReferenceDescription{rf}, refs...)
		} else {
			refs = append(refs, rf)
		}
	}

	return &ua.BrowseResult{
		StatusCode: ua.StatusGood,
		References: refs,
	}

}

func (as *NodeNameSpace) ID() uint16 {
	return as.id
}

func (as *NodeNameSpace) SetID(id uint16) {
	as.id = id
}
func (as *NodeNameSpace) SetAttribute(id *ua.NodeID, attr ua.AttributeID, val *ua.DataValue) ua.StatusCode {
	n := as.Node(id)
	if n == nil {
		return ua.StatusBadNodeIDUnknown
	}

	if !n.Access(ua.AccessLevelTypeCurrentWrite) {
		return ua.StatusBadUserAccessDenied
	}

	err := n.SetAttribute(attr, val)
	if err != nil {
		// Propagate StatusCode errors (e.g. BadTypeMismatch) so clients see
		// the Part 4 status rather than a collapsed BadAttributeIDInvalid.
		if sc, ok := err.(ua.StatusCode); ok {
			return sc
		}
		return ua.StatusBadAttributeIDInvalid
	}
	as.srv.ChangeNotification(id)
	select {
	case as.ExternalNotification <- id:
	default:
	}

	return ua.StatusOK
}

// browseTypeDefinition is the TypeDefinition of a ReferenceDescription to n:
// the target of its HasTypeDefinition reference if n is an Object or a
// Variable, the null NodeId otherwise (Part 4 §7.30).
func browseTypeDefinition(n *Node) *ua.ExpandedNodeID {
	if n == nil {
		return ua.NewTwoByteExpandedNodeID(0)
	}
	switch n.NodeClass() {
	case ua.NodeClassObject, ua.NodeClassVariable:
		if td := n.typeDefinition(); td != nil {
			return td
		}
	default:
	}
	return ua.NewTwoByteExpandedNodeID(0)
}
