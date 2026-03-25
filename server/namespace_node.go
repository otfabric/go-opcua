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
			ua.AttributeIDDescription:   DataValueFromValue(uint32(ua.NodeClassObject)),
			ua.AttributeIDDataType:      DataValueFromValue(typedef),
			ua.AttributeIDEventNotifier: DataValueFromValue(int16(0)),
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
	return n
}

func (as *NodeNameSpace) DeleteNode(nid *ua.NodeID) ua.StatusCode {
	as.mu.Lock()
	defer as.mu.Unlock()

	k := nid.String()
	if _, ok := as.m[k]; !ok {
		return ua.StatusBadNodeIDUnknown
	}
	delete(as.m, k)

	// Remove from slice.
	for i, n := range as.nodes {
		if n.ID().String() == k {
			as.nodes = append(as.nodes[:i], as.nodes[i+1:]...)
			break
		}
	}
	return ua.StatusGood
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
	as.mu.RLock()
	defer as.mu.RUnlock()

	as.srv.cfg.logger.Debug("browse request", "node_id", bd.NodeID, "result_mask", bd.ResultMask)

	n := as.Node(bd.NodeID)
	if n == nil {
		return &ua.BrowseResult{StatusCode: ua.StatusBadNodeIDUnknown}
	}

	refs := make([]*ua.ReferenceDescription, 0, len(n.refs))

	for i := range n.refs {
		r := n.refs[i]
		// we can't have nils in these or the encoder will fail.
		if r.NodeID == nil || r.BrowseName == nil || r.DisplayName == nil || r.TypeDefinition == nil {
			continue
		}

		// see if this is a ref the client was interested in.
		if !suitableRef(as.srv, bd, r) {
			continue
		}

		td := as.srv.Node(r.NodeID.NodeID)

		rf := &ua.ReferenceDescription{
			ReferenceTypeID: r.ReferenceTypeID,
			IsForward:       r.IsForward,
			NodeID:          r.NodeID,
			BrowseName:      r.BrowseName,
			DisplayName:     r.DisplayName,
			NodeClass:       r.NodeClass,
			TypeDefinition:  td.DataType(),
		}

		if rf.ReferenceTypeID.IntID() == id.HasTypeDefinition && rf.IsForward {
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
		return ua.StatusBadAttributeIDInvalid
	}
	as.srv.ChangeNotification(id)
	select {
	case as.ExternalNotification <- id:
	default:
	}

	return ua.StatusOK
}
