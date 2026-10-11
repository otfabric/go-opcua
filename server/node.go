// SPDX-License-Identifier: MIT

package server

import (
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/server/refs"
	"github.com/otfabric/go-opcua/ua"
)

type Attributes map[ua.AttributeID]*ua.DataValue

type References []*ua.ReferenceDescription

type ValueFunc func() *ua.DataValue

type AttrValue struct {
	Value           *ua.DataValue
	SourceTimestamp time.Time
}

func NewAttrValue(v *ua.DataValue) *AttrValue {
	return &AttrValue{Value: v}

}

func DataValueFromValue(val any) *ua.DataValue {
	// if we already have a data value, just return it.
	switch v := val.(type) {
	case *ua.DataValue:
		return v
	case ua.DataValue:
		return &v
	case ua.Variant:
		return &ua.DataValue{
			EncodingMask:    ua.DataValueValue,
			Value:           &v,
			SourceTimestamp: time.Now(),
		}
	case *ua.Variant:
		return &ua.DataValue{
			EncodingMask:    ua.DataValueValue,
			Value:           v,
			SourceTimestamp: time.Now(),
		}
	case int:
		return &ua.DataValue{
			EncodingMask:    ua.DataValueValue,
			Value:           ua.MustVariant(int32(v)),
			SourceTimestamp: time.Now(),
		}

	}

	v := ua.MustVariant(val)
	return &ua.DataValue{
		EncodingMask:    ua.DataValueValue,
		Value:           v,
		SourceTimestamp: time.Now(),
	}
}

type Node struct {
	mu   sync.RWMutex
	id   *ua.NodeID
	attr Attributes
	refs References
	val  ValueFunc

	// typeDef caches the target of the first forward HasTypeDefinition
	// reference (nil when there is none); valid only while typeDefKnown is
	// set. Appends to refs call noteRefAppended, every other change calls
	// invalidateTypeDef. Guarded by mu.
	typeDef      *ua.ExpandedNodeID
	typeDefKnown bool

	rolePermissions []*ua.RolePermissionType

	ns NameSpace
}

func NewNode(id *ua.NodeID, attr Attributes, refs References, val ValueFunc) *Node {
	n := &Node{id: id, attr: attr, refs: refs, val: val}
	n.sanitize()
	return n
}

func NewFolderNode(nodeID *ua.NodeID, name string) *Node {
	// A new folder starts without references; the caller links it into the
	// address space with AddRef. It used to be created with a forward
	// HasComponent reference to the namespace's Objects folder (labelled with
	// the folder's own name). Every folder below Objects therefore pointed
	// back up at Objects, turning the hierarchy into a cycle that sent
	// recursive browses (e.g. the client's Node.Walk) into an endless loop.
	n := NewNode(
		nodeID,
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:     DataValueFromValue(uint32(ua.NodeClassObject)),
			ua.AttributeIDBrowseName:    DataValueFromValue(attrs.BrowseName(name)),
			ua.AttributeIDDisplayName:   DataValueFromValue(attrs.DisplayName(name, name)),
			ua.AttributeIDDescription:   DataValueFromValue(&ua.LocalizedText{}),
			ua.AttributeIDEventNotifier: DataValueFromValue(byte(0)), // EventNotifier is a Byte (Part 3 §5.5.1)
		},
		[]*ua.ReferenceDescription{},
		nil,
	)
	return n
}

func NewVariableNode(nodeID *ua.NodeID, name string, value any) *Node {
	//eoid := ua.NewNumericExpandedNodeID(nodeID.Namespace(), nodeID.IntID())
	vf, ok := value.(func() *ua.DataValue)
	if !ok {
		typedef := ua.NewNumericExpandedNodeID(0, id.VariableNode)
		n := NewNode(
			nodeID,
			map[ua.AttributeID]*ua.DataValue{
				ua.AttributeIDNodeClass:     DataValueFromValue(uint32(ua.NodeClassVariable)),
				ua.AttributeIDBrowseName:    DataValueFromValue(attrs.BrowseName(name)),
				ua.AttributeIDDisplayName:   DataValueFromValue(attrs.DisplayName(name, name)),
				ua.AttributeIDDescription:   DataValueFromValue(&ua.LocalizedText{}),
				ua.AttributeIDDataType:      DataValueFromValue(typedef),
				ua.AttributeIDEventNotifier: DataValueFromValue(byte(0)), // EventNotifier is a Byte (Part 3 §5.5.1)
			},
			[]*ua.ReferenceDescription{},
			func() *ua.DataValue {
				return DataValueFromValue(value)
			},
		)
		dvFunc, ok := value.(ValueFunc)
		if ok {
			n.val = dvFunc
		}
		return n
	}
	typedef := ua.NewNumericExpandedNodeID(0, id.VariableNode)
	n := NewNode(
		nodeID,
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:     DataValueFromValue(uint32(ua.NodeClassVariable)),
			ua.AttributeIDBrowseName:    DataValueFromValue(attrs.BrowseName(name)),
			ua.AttributeIDDisplayName:   DataValueFromValue(attrs.DisplayName(name, name)),
			ua.AttributeIDDescription:   DataValueFromValue(&ua.LocalizedText{}),
			ua.AttributeIDDataType:      DataValueFromValue(typedef),
			ua.AttributeIDEventNotifier: DataValueFromValue(byte(0)), // EventNotifier is a Byte (Part 3 §5.5.1)
		},
		[]*ua.ReferenceDescription{},
		vf,
	)
	return n
}

func (n *Node) sanitize() {
	if n.attr == nil {
		n.attr = Attributes{}
	}
	if n.attr[ua.AttributeIDBrowseName] == nil {
		n.SetBrowseName("")
	}
	if n.attr[ua.AttributeIDDisplayName] == nil {
		n.SetDisplayName("", "")
	}
	if n.DisplayName().Text == "" {
		n.SetDisplayName(n.BrowseName().Name, "")
	}
	if n.attr[ua.AttributeIDDescription] == nil {
		n.SetDescription("", "")
	}
	//if n.attr[ua.AttributeIDDataType] == nil {
	//n.attr[ua.AttributeIDDataType] = ua.MustVariant(ua.NewTwoByteExpandedNodeID(0))
	//}
}

func (n *Node) ID() *ua.NodeID {
	return n.id
}

func (n *Node) Value() *ua.DataValue {
	// SetAttribute replaces the value function while requests read the
	// value (and, through it, the data type) of the node.
	n.mu.RLock()
	val := n.val
	n.mu.RUnlock()
	if val == nil {
		return nil
	}
	return val()
}

func (n *Node) attribute(id ua.AttributeID) (*AttrValue, error) {
	switch {
	case id == ua.AttributeIDValue:
		if n.val != nil {
			val := n.val()
			if val == nil {
				return nil, ua.StatusBadAttributeIDInvalid
			}
			return NewAttrValue(val), nil
		}
		return nil, ua.StatusBadAttributeIDInvalid
	case id == ua.AttributeIDRolePermissions || id == ua.AttributeIDUserRolePermissions:
		if len(n.rolePermissions) > 0 {
			extObjs := make([]*ua.ExtensionObject, len(n.rolePermissions))
			for i, rp := range n.rolePermissions {
				// NewExtensionObject fills in the TypeID and encoding mask;
				// without them the attribute cannot be encoded and the
				// whole Read response fails with BadEncodingError.
				extObjs[i] = ua.NewExtensionObject(rp)
			}
			v := ua.MustVariant(extObjs)
			return NewAttrValue(&ua.DataValue{
				EncodingMask: ua.DataValueValue,
				Value:        v,
			}), nil
		}
		return nil, ua.StatusBadAttributeIDInvalid
	case n.attr == nil:
		return nil, ua.StatusBadAttributeIDInvalid
	default:
		if v := n.attr[id]; v != nil {
			return NewAttrValue(v), nil
		}
		return nil, ua.StatusBadAttributeIDInvalid
	}
}

func (n *Node) Attribute(id ua.AttributeID) (*AttrValue, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.attribute(id)
}
func (n *Node) SetAttribute(id ua.AttributeID, val *ua.DataValue) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	switch id {
	case ua.AttributeIDValue:
		if !n.access(ua.AccessLevelTypeCurrentWrite) {
			return ua.StatusBadUserAccessDenied
		}

		// Validate the data type if the node has a DataType attribute and
		// both old and new values carry a typed variant.
		if val != nil && val.Value != nil {
			var cur *ua.DataValue
			if n.val != nil {
				cur = n.val()
			}
			if cur != nil && cur.Value != nil {
				oldVal := cur.Value.Value()
				newVal := val.Value.Value()
				if oldVal != nil && newVal != nil {
					if fmt.Sprintf("%T", oldVal) != fmt.Sprintf("%T", newVal) {
						return ua.StatusBadTypeMismatch
					}
				}
			}
		}

		n.val = func() *ua.DataValue {
			return val
		}

		return nil
	default:
		n.attr[id] = val
		return nil
	}
}

func (n *Node) BrowseName() *ua.QualifiedName {
	v := n.attr[ua.AttributeIDBrowseName]
	if v == nil || v.Value.Value() == nil {
		return &ua.QualifiedName{}
	}
	return v.Value.Value().(*ua.QualifiedName)
}

func (n *Node) SetBrowseName(s string) {
	n.attr[ua.AttributeIDBrowseName] = DataValueFromValue(&ua.QualifiedName{Name: s})
}

func (n *Node) DisplayName() *ua.LocalizedText {
	v := n.attr[ua.AttributeIDDisplayName]
	if v == nil || v.Value.Value() == nil {
		return &ua.LocalizedText{}
	}
	val := v.Value.Value().(*ua.LocalizedText)
	val.UpdateMask()
	return val
}

func (n *Node) SetDisplayName(text, locale string) {
	lt := &ua.LocalizedText{Text: text, Locale: locale}
	lt.UpdateMask()
	n.attr[ua.AttributeIDDisplayName] = DataValueFromValue(lt)
}

func (n *Node) Description() *ua.LocalizedText {
	v := n.attr[ua.AttributeIDDescription]
	if v == nil || v.Value.Value() == nil {
		return &ua.LocalizedText{}
	}
	return v.Value.Value().(*ua.LocalizedText)
}

func (n *Node) SetDescription(text, locale string) {
	lt := &ua.LocalizedText{Text: text, Locale: locale}
	// Without the encoding mask the text is not put on the wire and clients
	// read an empty description.
	lt.UpdateMask()
	n.attr[ua.AttributeIDDescription] = DataValueFromValue(lt)
}

func (n *Node) DataType() *ua.ExpandedNodeID {
	if n == nil {
		slog.Default().Warn("node is nil")
		return ua.NewTwoByteExpandedNodeID(0)
	}
	v := n.attr[ua.AttributeIDDataType]
	if v == nil || v.Value.Value() == nil {
		// if we have a type definition, return that?
		if td := n.typeDefinition(); td != nil {
			return td
		}
		return ua.NewTwoByteExpandedNodeID(0)
	}
	return v.Value.Value().(*ua.ExpandedNodeID)
}

// typeDefinition returns the target of the node's first forward
// HasTypeDefinition reference, or nil. AddRef asks this of its target for
// every reference it adds, so the answer is cached: scanning (or copying) the
// reference list each time made building the address space quadratic.
func (n *Node) typeDefinition() *ua.ExpandedNodeID {
	n.mu.RLock()
	if n.typeDefKnown {
		td := n.typeDef
		n.mu.RUnlock()
		return td
	}
	n.mu.RUnlock()

	n.mu.Lock()
	defer n.mu.Unlock()
	if n.typeDefKnown {
		return n.typeDef
	}
	n.typeDef = nil
	for _, r := range n.refs {
		if r.ReferenceTypeID == nil {
			slog.Default().Warn("reference type ID is nil")
			continue
		}
		if r.ReferenceTypeID.IntID() == id.HasTypeDefinition && r.IsForward {
			n.typeDef = r.NodeID
			break
		}
	}
	n.typeDefKnown = true
	return n.typeDef
}

// invalidateTypeDef drops the cached type definition. mu must be held.
func (n *Node) invalidateTypeDef() { n.typeDefKnown = false }

// noteRefAppended keeps the cached type definition current after ref was
// appended to refs: an append can only supply the first type definition, never
// change an existing one. mu must be held.
func (n *Node) noteRefAppended(ref *ua.ReferenceDescription) {
	if !n.typeDefKnown || n.typeDef != nil {
		return
	}
	if ref.ReferenceTypeID != nil && ref.ReferenceTypeID.IntID() == id.HasTypeDefinition && ref.IsForward {
		n.typeDef = ref.NodeID
	}
}

func (n *Node) SetNodeClass(nc ua.NodeClass) {
	n.attr[ua.AttributeIDNodeClass] = DataValueFromValue(uint32(nc))
}

func (n *Node) NodeClass() ua.NodeClass {
	v := n.attr[ua.AttributeIDNodeClass]
	if v == nil || v.Value.Value() == nil {
		return ua.NodeClassObject
	}
	vi32, ok := v.Value.Value().(int32)
	if !ok {
		vui32, ok := v.Value.Value().(uint32)
		if !ok {
			return ua.NodeClassObject
		}
		return ua.NodeClass(int32(vui32))
	}
	return ua.NodeClass(vi32)

}

func (n *Node) AddObject(o *Node) *Node {
	nn := &Node{
		id:   o.id,
		attr: maps.Clone(o.attr),
		refs: o.refsSnapshot(),
	}
	if n.attr == nil {
		n.attr = Attributes{}
	}
	nn.SetNodeClass(ua.NodeClassObject)
	ref := refs.Organizes(nn.id, nn.BrowseName().Name, nn.DisplayName().Text, nn.DataType())
	n.mu.Lock()
	n.refs = append(n.refs, ref)
	n.noteRefAppended(ref)
	n.mu.Unlock()
	return n.ns.AddNode(nn)
}

func (n *Node) AddVariable(o *Node) *Node {
	nn := &Node{
		id:   o.id,
		attr: maps.Clone(o.attr),
		refs: o.refsSnapshot(),
		val:  o.val,
	}
	if n.attr == nil {
		n.attr = Attributes{}
	}
	nn.SetNodeClass(ua.NodeClassVariable)
	ref := refs.Organizes(nn.id, nn.BrowseName().Name, nn.DisplayName().Text, nn.DataType())
	n.mu.Lock()
	n.refs = append(n.refs, ref)
	n.noteRefAppended(ref)
	n.mu.Unlock()
	return n.ns.AddNode(nn)
}

type RefType int

const (
	RefTypeIDHasComponent = id.HasComponent
	RefTypeIDOrganizes    = id.Organizes
)

func (n *Node) AddRef(o *Node, rt RefType, forward bool) {
	//eoid := ua.NewNumericExpandedNodeID(o.ns.ID(), o.)
	eoid := ua.NewExpandedNodeID(o.ID(), "", 0)

	ref := ua.ReferenceDescription{
		ReferenceTypeID: ua.NewNumericNodeID(0, uint32(rt)), //o.refs[0].ReferenceTypeID,
		IsForward:       forward,
		NodeID:          eoid,
		BrowseName:      o.BrowseName(),
		DisplayName:     o.DisplayName(),
		NodeClass:       o.NodeClass(),
		TypeDefinition:  o.DataType(),
	}
	// The reference is built before taking the lock: o may be n itself.
	n.mu.Lock()
	n.refs = append(n.refs, &ref)
	n.noteRefAppended(&ref)
	n.mu.Unlock()
}

// refsSnapshot returns a copy of the node's references. The address space
// may be mutated (AddRef/RemoveRef, AddNodes/DeleteNodes) while services
// such as Browse iterate over the references, so readers work on a snapshot.
func (n *Node) refsSnapshot() References {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return slices.Clone(n.refs)
}

// RemoveRef removes a reference from the node matching the given target, reference type, and direction.
// Returns true if a matching reference was found and removed.
func (n *Node) RemoveRef(targetID *ua.ExpandedNodeID, refTypeID *ua.NodeID, forward bool) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	for i, ref := range n.refs {
		if ref.IsForward != forward {
			continue
		}
		if ref.ReferenceTypeID.IntID() != refTypeID.IntID() {
			continue
		}
		if ref.NodeID == nil || targetID == nil {
			continue
		}
		if ref.NodeID.NodeID.String() != targetID.NodeID.String() {
			continue
		}
		// Remove by swapping with last element.
		n.refs[i] = n.refs[len(n.refs)-1]
		n.refs = n.refs[:len(n.refs)-1]
		n.invalidateTypeDef()
		return true
	}
	return false
}

// Access returns true if the node has the access level requested.
// It checks both the UserAccessLevel and AccessLevel attributes.
// If neither are present, it assumes global access and returns true.
//
// I'm not sure what the best way to implement "user" specific access levels
// is presently.  Will need functioning user authentication first, and then a way to
// pass it into the nodes user access attribute so it can be checked properly.
func (n *Node) access(flag ua.AccessLevelType) bool {

	access, err := n.attribute(ua.AttributeIDUserAccessLevel)
	if err == nil { // if we have a user access level, we need to check it.
		val0 := access.Value.Value.Value()
		val, ok := val0.(uint8)
		if !ok {
			return false
		}
		if val&uint8(flag) == 0 {
			return false
		}
	}
	access, err = n.attribute(ua.AttributeIDAccessLevel)
	if err == nil { // if we have an access level, we need to check it.
		val0 := access.Value.Value.Value()
		val, ok := val0.(uint8)
		if !ok {
			return false
		}

		if val&uint8(flag) == 0 {
			return false
		}
	}
	return true

}

// Access returns true if the node has the access level requested.
func (n *Node) Access(flag ua.AccessLevelType) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.access(flag)
}
