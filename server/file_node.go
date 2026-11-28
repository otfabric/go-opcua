// SPDX-License-Identifier: MIT

package server

import (
	"fmt"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uamethod"
)

// AddFile adds a FileType Object (OPC 10000-20 §4.2.1) with the NodeId
// nodeID and the BrowseName name to the address space, a component of
// parent (HasComponent), and serves it: the Properties Size, Writable,
// UserWritable, OpenCount and MaxByteStringLength, MimeType when
// FileConfig.MimeType is set, LastModifiedTime when the backend is a
// FileModTimer, and the Methods Open, Close, Read, Write, GetPosition and
// SetPosition with the InputArguments and OutputArguments of their
// declarations. The children have string NodeIds in the namespace of
// nodeID: "<id>.<BrowseName>" (see [Node.SetMethodArguments]).
//
// The namespace of nodeID must be one of the server's and nodeID must not
// exist; parent must exist.
func (s *Server) AddFile(parent, nodeID *ua.NodeID, name *ua.QualifiedName, cfg FileConfig) (*FileObject, error) {
	p, ns, err := s.newChildObject("AddFile", parent, nodeID, name)
	if err != nil {
		return nil, err
	}
	f, err := s.NewFile(cfg)
	if err != nil {
		return nil, err
	}
	s.addFileNodes(f, ns, p, nodeID, name, id.HasComponent)
	return f, nil
}

// newChildObject checks the arguments of AddFile and AddFileDirectory.
func (s *Server) newChildObject(op string, parent, nodeID *ua.NodeID, name *ua.QualifiedName) (*Node, NameSpace, error) {
	if parent == nil || nodeID == nil || name == nil || name.Name == "" {
		return nil, nil, fmt.Errorf("server: %s: parent, NodeId and BrowseName are required: %w", op, ua.StatusBadInvalidArgument)
	}
	p := s.Node(parent)
	if p == nil {
		return nil, nil, fmt.Errorf("server: %s: parent %v: %w", op, parent, ua.StatusBadParentNodeIDInvalid)
	}
	ns, err := s.Namespace(int(nodeID.Namespace()))
	if err != nil {
		return nil, nil, fmt.Errorf("server: %s: %w: %w", op, err, ua.StatusBadNodeIDInvalid)
	}
	if s.Node(nodeID) != nil {
		return nil, nil, fmt.Errorf("server: %s: %v: %w", op, nodeID, ua.StatusBadNodeIDExists)
	}
	return p, ns, nil
}

// addObjectNode adds an Object of a type of namespace 0, referenced by
// parent with refType.
func (s *Server) addObjectNode(ns NameSpace, parent *Node, nodeID *ua.NodeID, name *ua.QualifiedName, typeDef, refType uint32) *Node {
	n := NewNode(nodeID, Attributes{
		ua.AttributeIDNodeClass:     DataValueFromValue(uint32(ua.NodeClassObject)),
		ua.AttributeIDBrowseName:    DataValueFromValue(name),
		ua.AttributeIDDisplayName:   DataValueFromValue(attrs.DisplayName(name.Name, "")),
		ua.AttributeIDDescription:   DataValueFromValue(&ua.LocalizedText{}),
		ua.AttributeIDEventNotifier: DataValueFromValue(byte(0)),
	}, nil, nil)
	n = ns.AddNode(n)
	if t := s.Node(ua.NewNumericNodeID(0, typeDef)); t != nil {
		n.AddRef(t, RefType(id.HasTypeDefinition), true)
	}
	linkChild(parent, n, refType)
	return n
}

// addFileNodes adds the FileType Object of f and its children. It returns
// the NodeIds it added, the Object first.
func (s *Server) addFileNodes(f *FileObject, ns NameSpace, parent *Node, nodeID *ua.NodeID, name *ua.QualifiedName, refType uint32) []*ua.NodeID {
	obj := s.addObjectNode(ns, parent, nodeID, name, id.FileType, refType)
	added := []*ua.NodeID{obj.ID()}
	var dynamic []*ua.NodeID
	for _, p := range fileProperties {
		v := f.Property(p.name)
		if v == nil {
			continue
		}
		n := NewNode(childPropertyID(nodeID, p.name), Attributes{
			ua.AttributeIDNodeClass:       DataValueFromValue(uint32(ua.NodeClassVariable)),
			ua.AttributeIDBrowseName:      DataValueFromValue(&ua.QualifiedName{Name: p.name}),
			ua.AttributeIDDisplayName:     DataValueFromValue(attrs.DisplayName(p.name, "")),
			ua.AttributeIDDescription:     DataValueFromValue(&ua.LocalizedText{}),
			ua.AttributeIDDataType:        DataValueFromValue(ua.NewNumericExpandedNodeID(0, p.dataType)),
			ua.AttributeIDValueRank:       DataValueFromValue(int32(-1)),
			ua.AttributeIDAccessLevel:     DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead)),
			ua.AttributeIDUserAccessLevel: DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead)),
		}, nil, v)
		n = ns.AddNode(n)
		if t := s.Node(ua.NewNumericNodeID(0, id.PropertyType)); t != nil {
			n.AddRef(t, RefType(id.HasTypeDefinition), true)
		}
		linkChild(obj, n, id.HasProperty)
		added = append(added, n.ID())
		switch p.name {
		case "Size", "OpenCount", "LastModifiedTime":
			dynamic = append(dynamic, n.ID())
		}
	}
	for _, m := range fileMethods {
		added = append(added, s.addMethodNode(ns, obj, m, f.Method(m.Name))...)
	}
	f.mu.Lock()
	f.nodes = append(f.nodes, dynamic...)
	f.mu.Unlock()
	return added
}

// addMethodNode adds the Method m to obj with the InputArguments and
// OutputArguments of its declaration, and registers h for it. It returns
// the NodeIds it added, the Method first.
func (s *Server) addMethodNode(ns NameSpace, obj *Node, m *uamethod.Method, h MethodHandler) []*ua.NodeID {
	mn := NewNode(childPropertyID(obj.ID(), m.Name), Attributes{
		ua.AttributeIDNodeClass:      DataValueFromValue(uint32(ua.NodeClassMethod)),
		ua.AttributeIDBrowseName:     DataValueFromValue(&ua.QualifiedName{Name: m.Name}),
		ua.AttributeIDDisplayName:    DataValueFromValue(attrs.DisplayName(m.Name, "")),
		ua.AttributeIDDescription:    DataValueFromValue(&ua.LocalizedText{}),
		ua.AttributeIDExecutable:     DataValueFromValue(true),
		ua.AttributeIDUserExecutable: DataValueFromValue(true),
	}, nil, nil)
	mn = ns.AddNode(mn)
	linkChild(obj, mn, id.HasComponent)
	in, out := m.InputArguments(), m.OutputArguments()
	_ = mn.SetMethodArguments(in, out) // a Method node of a namespace
	s.RegisterMethod(obj.ID(), mn.ID(), h)
	added := []*ua.NodeID{mn.ID()}
	if len(in) > 0 {
		added = append(added, childPropertyID(mn.ID(), "InputArguments"))
	}
	if len(out) > 0 {
		added = append(added, childPropertyID(mn.ID(), "OutputArguments"))
	}
	return added
}

// ServeFile serves the FileType Object obj of the address space, for
// example one of an imported NodeSet: the Methods and Properties of
// FileType (OPC 10000-20 §4.2.1) among its HasComponent and HasProperty
// children are found by their BrowseName in namespace 0; a Property the
// FileObject has no value for (MimeType without FileConfig.MimeType) is
// left as it is. It returns an error if obj or one of the Mandatory Methods
// is missing.
func (s *Server) ServeFile(obj *ua.NodeID, cfg FileConfig) (*FileObject, error) {
	n := s.Node(obj)
	if n == nil {
		return nil, fmt.Errorf("server: ServeFile: node %v: %w", obj, ua.StatusBadNodeIDUnknown)
	}
	f, err := s.NewFile(cfg)
	if err != nil {
		return nil, err
	}
	found := map[string]bool{}
	for _, c := range s.fileChildren(n) {
		switch c.refType {
		case id.HasComponent:
			if h := f.Method(c.name); h != nil {
				found[c.name] = true
				s.RegisterMethod(obj, c.node.ID(), h)
			}
		case id.HasProperty:
			if v := f.Property(c.name); v != nil {
				c.node.mu.Lock()
				c.node.val = v
				c.node.mu.Unlock()
				switch c.name {
				case "Size", "OpenCount", "LastModifiedTime":
					f.nodes = append(f.nodes, c.node.ID())
				}
			}
		}
	}
	for _, m := range fileMethods {
		if !found[m.Name] {
			s.files.remove(f)
			return nil, fmt.Errorf("server: ServeFile: %v has no Method %s: %w", obj, m.Name, ua.StatusBadNodeIDUnknown)
		}
	}
	return f, nil
}

// fileChild is a child of an Object with a BrowseName of namespace 0.
type fileChild struct {
	name    string
	refType uint32
	node    *Node
}

// fileChildren returns the HasComponent and HasProperty children of n with
// a BrowseName of namespace 0. The references of an imported NodeSet carry
// no BrowseName: it is that of the target node.
func (s *Server) fileChildren(n *Node) []fileChild {
	var out []fileChild
	for _, ref := range n.refsSnapshot() {
		if ref == nil || !ref.IsForward || ref.NodeID == nil || ref.ReferenceTypeID == nil {
			continue
		}
		rt := ref.ReferenceTypeID.IntID()
		if ref.ReferenceTypeID.Namespace() != 0 || rt != id.HasComponent && rt != id.HasProperty {
			continue
		}
		tn := s.Node(ref.NodeID.NodeID)
		if tn == nil {
			continue
		}
		if bn := tn.BrowseName(); bn != nil && bn.NamespaceIndex == 0 {
			out = append(out, fileChild{name: bn.Name, refType: rt, node: tn})
		}
	}
	return out
}

// Changed tells the FileObject that the content of its backend changed
// outside the Methods: the Size and LastModifiedTime Properties are
// notified.
func (f *FileObject) Changed() { f.notify() }
