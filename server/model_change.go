// SPDX-License-Identifier: MIT

package server

import (
	"reflect"
	"strconv"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
)

// ModelChangeEvents and SemanticChangeEvents (Part 3 §9.32, §9.33).
//
// "There is a correlation between ModelChangeEvents and the NodeVersion
// Property of Nodes": the NodeVersion of a Node changes with each
// ModelChangeEvent issued for it, and "only those Nodes of the AddressSpace
// having a NodeVersion shall trigger a ModelChangeEvent" (Part 3 §9.32.2).
// The server keeps that rule: a node that has a NodeVersion Property (from a
// NodeSet, from [NodeNameSpace.AddNodeVersion], or from AddNodes with
// [WithNodeVersionOnAddNodes]) gets a new NodeVersion and is reported in a
// GeneralModelChangeEvent when a reference of it is added or deleted, when it
// is added or deleted, and when the DataType of a Variable or VariableType
// changes (Part 3 §5.5.1, §5.6.2, §9.32.1; Part 5 §12.16). Other nodes are
// not reported.
//
// Our choices, where the specification leaves one:
//
//   - One service request is one update: AddNodes, DeleteNodes,
//     AddReferences and DeleteReferences report all of their changes in one
//     GeneralModelChangeEvent, each node once with the verbs ORed (the
//     compression of Part 3 §9.32.4 and "exactly one ModelChangeEvent for an
//     update or series of updates", §9.32.7). A call of the Go API (AddRef,
//     RemoveRef, AddNode, DeleteNode, SetAttribute) is one update.
//   - A node that is added or deleted keeps the NodeVersion it has: the
//     NodeVersion of a new node is the version after the change, and a
//     deleted node has none to change.
//   - A NodeVersion is a decimal counter: "0" for a NodeVersion the server
//     creates, one more for each change; a value that is not a number becomes
//     "1".
//   - A change of the ValueRank or ArrayDimensions of a Variable changes its
//     NodeVersion (Part 3 §5.6.2), and every NodeVersion change needs a
//     ModelChangeEvent (§9.32.2), but Part 5 §12.16 has no verb for it: the
//     server reports it with a BaseModelChangeEvent, which "does not contain
//     information about the changes" (Part 5 §6.4.31).
//   - The events go to the Server Object, the notifier of the default View
//     (Part 3 §9.32.3); the server has no other View. SourceNode is the
//     Server Object and SourceName "Server" (Part 5 §6.4.31); Severity is 1.
//   - ImportNodeSetXML reports nothing: the import is not a change of nodes
//     that existed, and the nodes it brings carry the NodeVersion of the
//     NodeSet.
//
// A Property whose AccessLevel has the SemanticChange bit "is used for
// Properties that may change" and define the semantic of the parent Node;
// "Servers that support Event Subscriptions shall generate a
// SemanticChangeEvent whenever a Property with SemanticChange flag set
// changes", and the data change Notification of a MonitoredItem of the
// Variable carries the SemanticsChanged bit (Part 3 §5.6.2, §9.33; Part 4
// §7.38.1). The server does that when the Value of such a Property is set
// with SetAttribute, by the server or by a client's Write, to a value other
// than the one it had; NodeVersion does not change (Part 3 §9.33.2). The
// program or the NodeSet sets the bit: the server does not set it on
// EngineeringUnits, EURange or any other Property.

// addressSpaceConfig holds the options of model change and namespace
// defaults. The zero value is the default.
type addressSpaceConfig struct {
	// modelChangeOff: WithModelChangeEvents(false).
	modelChangeOff bool
	// nodeVersionOnAdd: WithNodeVersionOnAddNodes(true).
	nodeVersionOnAdd bool
	// modelDefaultsOff: WithModelDefaultPermissions(false).
	modelDefaultsOff bool
}

// WithModelChangeEvents sets whether the server maintains the NodeVersion
// Property of the nodes that have one and reports their changes in
// GeneralModelChangeEvents, and whether it reports SemanticChangeEvents and
// the SemanticsChanged bit of data change Notifications (Part 3 §9.32,
// §9.33, §5.6.2). It is on by default. WithModelChangeEvents(false)
// restores the behaviour of v1.42 and earlier: no NodeVersion changes, no
// GeneralModelChangeEvent, no SemanticChangeEvent and no SemanticsChanged
// bit. A server whose address space has no NodeVersion Property and no
// Property with the SemanticChange bit behaves the same either way.
func WithModelChangeEvents(enabled bool) Option {
	return func(s *serverConfig) error {
		s.addrSpace.modelChangeOff = !enabled
		return nil
	}
}

// WithNodeVersionOnAddNodes sets whether every node the AddNodes service
// adds gets a NodeVersion Property, so that the changes of the nodes that
// clients add are reported in GeneralModelChangeEvents (see
// [WithModelChangeEvents]); DeleteNodes deletes the Property with its node.
// It is off by default: AddNodes adds the node the client asked for and no
// other.
func WithNodeVersionOnAddNodes(enabled bool) Option {
	return func(s *serverConfig) error {
		s.addrSpace.nodeVersionOnAdd = enabled
		return nil
	}
}

const (
	// nodeVersionName is the BrowseName of the NodeVersion Property, in
	// namespace 0 (Part 3 §5.5.1 Table 11, §5.6.2 Table 13).
	nodeVersionName = "NodeVersion"
	// statusSemanticsChanged is the SemanticsChanged bit of a StatusCode
	// (Part 4 §7.38.1, bit 14).
	statusSemanticsChanged ua.StatusCode = 1 << 14
)

// isNodeVersionRef reports whether ref is the HasProperty reference of a
// node to its NodeVersion Property.
func isNodeVersionRef(ref *ua.ReferenceDescription) bool {
	return ref != nil && ref.IsForward &&
		ref.ReferenceTypeID != nil && ref.ReferenceTypeID.Namespace() == 0 && ref.ReferenceTypeID.IntID() == id.HasProperty &&
		ref.BrowseName != nil && ref.BrowseName.NamespaceIndex == 0 && ref.BrowseName.Name == nodeVersionName &&
		ref.NodeID != nil && ref.NodeID.NodeID != nil && ref.NodeID.ServerIndex == 0
}

// nodeVersionID returns the NodeId of the NodeVersion Property of n, nil if
// it has none. The answer is cached, as the type definition is.
func (n *Node) nodeVersionID() *ua.NodeID {
	n.mu.RLock()
	if n.nodeVersionKnown {
		v := n.nodeVersion
		n.mu.RUnlock()
		return v
	}
	n.mu.RUnlock()

	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.nodeVersionKnown {
		n.nodeVersion = nil
		for _, r := range n.refs {
			if isNodeVersionRef(r) {
				n.nodeVersion = r.NodeID.NodeID
				break
			}
		}
		n.nodeVersionKnown = true
	}
	return n.nodeVersion
}

// server returns the server of the namespace of n, nil if n is in no
// namespace of a server.
func (n *Node) server() *Server {
	ns, ok := n.nodeNamespace()
	if !ok {
		return nil
	}
	return ns.srv
}

// nodeNamespace returns the NodeNameSpace of n; false if n is nil or in
// no NodeNameSpace.
func (n *Node) nodeNamespace() (*NodeNameSpace, bool) {
	if n == nil {
		return nil, false
	}
	ns, ok := n.ns.(*NodeNameSpace)
	return ns, ok && ns != nil
}

// reportModelChange reports a change verb of the nodes as one update of the
// Go API.
func (n *Node) reportModelChange(verb ua.ModelChangeStructureVerbMask, nodes ...*Node) {
	mc := n.server().modelChanges()
	if mc == nil {
		return
	}
	for _, o := range nodes {
		mc.note(o, verb)
	}
	mc.flush()
}

// modelChanges collects the changes of one update. A nil *modelChanges
// (model change events are off, or there is no server) ignores them.
type modelChanges struct {
	s     *Server
	nodes []*Node
	verbs map[*Node]ua.ModelChangeStructureVerbMask
	// base marks a change that is reported in a BaseModelChangeEvent.
	base bool
}

// modelChanges returns a new collector, nil when model change events are
// off.
func (s *Server) modelChanges() *modelChanges {
	if s == nil || s.cfg == nil || s.cfg.addrSpace.modelChangeOff {
		return nil
	}
	return &modelChanges{s: s}
}

// note records verb for n.
func (mc *modelChanges) note(n *Node, verb ua.ModelChangeStructureVerbMask) {
	if mc == nil || n == nil {
		return
	}
	if mc.verbs == nil {
		mc.verbs = make(map[*Node]ua.ModelChangeStructureVerbMask)
	}
	if _, ok := mc.verbs[n]; !ok {
		mc.nodes = append(mc.nodes, n)
	}
	mc.verbs[n] |= verb
}

// noteAdded records that n was added.
func (mc *modelChanges) noteAdded(n *Node) {
	mc.note(n, ua.ModelChangeStructureVerbMaskNodeAdded)
}

// noteStructure records a change of n that no verb describes (ValueRank,
// ArrayDimensions): the update is reported in a BaseModelChangeEvent.
func (mc *modelChanges) noteStructure(n *Node) {
	if mc == nil {
		return
	}
	mc.note(n, 0)
	mc.base = true
}

// flush changes the NodeVersion of the nodes recorded that have one and
// reports them in one ModelChangeEvent.
func (mc *modelChanges) flush() {
	if mc == nil || len(mc.nodes) == 0 {
		return
	}
	var changes []*ua.ExtensionObject
	for _, n := range mc.nodes {
		vid := n.nodeVersionID()
		if vid == nil {
			continue
		}
		verb := mc.verbs[n]
		if verb&(ua.ModelChangeStructureVerbMaskNodeAdded|ua.ModelChangeStructureVerbMaskNodeDeleted) == 0 {
			mc.s.bumpNodeVersion(vid)
		}
		changes = append(changes, ua.NewExtensionObject(&ua.ModelChangeStructureDataType{
			Affected:     n.ID(),
			AffectedType: affectedType(n),
			Verb:         uint8(verb),
		}))
	}
	mc.nodes, mc.verbs = nil, nil
	if len(changes) == 0 {
		return
	}
	ev := changeEvent(id.GeneralModelChangeEventType, "The address space changed")
	if mc.base {
		ev = changeEvent(id.BaseModelChangeEventType, "The address space changed")
	} else {
		ev.Fields = map[string]*ua.Variant{"Changes": ua.MustVariant(changes)}
	}
	mc.s.emitEvent(ua.NewNumericNodeID(0, id.Server), ev, false)
}

// changeEvent returns a ModelChangeEvent or SemanticChangeEvent of the type
// eventType in the context of the whole address space (Part 5 §6.4.31).
func changeEvent(eventType uint32, msg string) *BaseEvent {
	return &BaseEvent{
		EventID:    newEventID(),
		EventType:  ua.NewNumericNodeID(0, eventType),
		SourceNode: ua.NewNumericNodeID(0, id.Server),
		SourceName: "Server",
		Time:       time.Now(),
		Message:    ua.NewLocalizedText(msg),
		Severity:   1,
	}
}

// affectedType is the AffectedType of a change of n: "If the affected Node
// was an Object or Variable, affectedType contains the NodeId of the
// TypeDefinitionNode of the affected Node. Otherwise it is set to null"
// (Part 5 §12.16, §12.17).
func affectedType(n *Node) *ua.NodeID {
	if nc := n.NodeClass(); nc != ua.NodeClassObject && nc != ua.NodeClassVariable {
		return nil
	}
	if td := n.typeDefinition(); td != nil && td.NodeID != nil {
		return td.NodeID
	}
	return nil
}

// bumpNodeVersion gives the NodeVersion Property vid its next value and
// notifies its monitored items.
func (s *Server) bumpNodeVersion(vid *ua.NodeID) {
	p := s.Node(vid)
	if p == nil {
		return
	}
	// Two updates of one node must not both read the same version.
	s.nsMeta.versionMu.Lock()
	next := "1"
	if dv := p.Value(); dv != nil && dv.Value != nil {
		if cur, ok := dv.Value.Value().(string); ok {
			if v, err := strconv.ParseUint(cur, 10, 64); err == nil && v < 1<<63 {
				next = strconv.FormatUint(v+1, 10)
			}
		}
	}
	_, _ = p.setAttribute(ua.AttributeIDValue, &ua.DataValue{
		EncodingMask:    ua.DataValueValue | ua.DataValueSourceTimestamp,
		Value:           ua.MustVariant(next),
		SourceTimestamp: time.Now(),
	})
	s.nsMeta.versionMu.Unlock()
	s.ChangeNotification(vid)
}

// AddNodeVersion gives n a NodeVersion Property in the namespace as, if it
// has none, and returns the Property. From then on the server changes the
// NodeVersion and reports a GeneralModelChangeEvent each time a reference
// of n is added or deleted, n is deleted or, for a Variable, its DataType
// changes (Part 3 §9.32.2; see [WithModelChangeEvents]). The NodeVersion is
// a String, "0" at first; its creation is not reported. Call it once n is
// in the address space or before: n need not be in as.
func (as *NodeNameSpace) AddNodeVersion(n *Node) *Node {
	if vid := n.nodeVersionID(); vid != nil {
		if p := as.srv.Node(vid); p != nil {
			return p
		}
	}
	var nid *ua.NodeID
	for {
		nid = ua.NewNumericNodeID(as.ID(), as.GetNextNodeID())
		if as.Node(nid) == nil {
			break
		}
	}
	p := NewNode(nid, Attributes{
		ua.AttributeIDNodeClass:       DataValueFromValue(uint32(ua.NodeClassVariable)),
		ua.AttributeIDBrowseName:      DataValueFromValue(&ua.QualifiedName{Name: nodeVersionName}),
		ua.AttributeIDDisplayName:     DataValueFromValue(attrs.DisplayName(nodeVersionName, nodeVersionName)),
		ua.AttributeIDDataType:        DataValueFromValue(ua.NewNumericExpandedNodeID(0, id.String)),
		ua.AttributeIDValueRank:       DataValueFromValue(int32(-1)),
		ua.AttributeIDAccessLevel:     DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead)),
		ua.AttributeIDUserAccessLevel: DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead)),
	}, nil, nil)
	_ = p.SetAttribute(ua.AttributeIDValue, DataValueFromValue("0"))
	as.addNode(p)
	if pt := as.srv.Node(ua.NewNumericNodeID(0, id.PropertyType)); pt != nil {
		p.addRef(pt, ua.NewNumericNodeID(0, id.HasTypeDefinition), true)
	}
	n.addRef(p, ua.NewNumericNodeID(0, id.HasProperty), true)
	return p
}

// attributeChange is a change of an attribute that is reported once the
// node is unlocked.
type attributeChange struct {
	n *Node
	// semantic: the Value of a Property with the SemanticChange bit
	// changed; owner is the node of the Property.
	semantic bool
	// dataType: the DataType changed (GeneralModelChangeEvent);
	// structure: the ValueRank or ArrayDimensions changed.
	dataType, structure bool
}

// attributeChange returns the change that setting id to val makes, nil if
// none is reported. mu must be held.
func (n *Node) attributeChange(id ua.AttributeID, val *ua.DataValue) *attributeChange {
	switch id {
	case ua.AttributeIDValue:
		if !hasAccessBit(n.attr[ua.AttributeIDAccessLevel], ua.AccessLevelTypeSemanticChange) {
			return nil
		}
		var cur *ua.DataValue
		if n.val != nil {
			cur = n.val()
		}
		if sameValue(cur, val) {
			return nil
		}
		return &attributeChange{n: n, semantic: true}
	case ua.AttributeIDDataType, ua.AttributeIDValueRank, ua.AttributeIDArrayDimensions:
		switch n.NodeClass() {
		case ua.NodeClassVariable, ua.NodeClassVariableType:
		default:
			return nil
		}
		if sameValue(n.attr[id], val) {
			return nil
		}
		if id == ua.AttributeIDDataType {
			return &attributeChange{n: n, dataType: true}
		}
		return &attributeChange{n: n, structure: true}
	default:
		return nil
	}
}

// report reports the change.
func (c *attributeChange) report() {
	s := c.n.server()
	if c.semantic {
		s.semanticChange(c.n)
		return
	}
	mc := s.modelChanges()
	if c.dataType {
		mc.note(c.n, ua.ModelChangeStructureVerbMaskDataTypeChanged)
	} else {
		mc.noteStructure(c.n)
	}
	mc.flush()
}

// hasAccessBit reports whether the AccessLevel dv has the bit bit.
func hasAccessBit(dv *ua.DataValue, bit ua.AccessLevelType) bool {
	if dv == nil || dv.Value == nil {
		return false
	}
	switch v := dv.Value.Value().(type) {
	case uint8:
		return ua.AccessLevelType(v)&bit != 0
	case uint32:
		return ua.AccessLevelType(v)&bit != 0
	}
	return false
}

// sameValue reports whether a and b hold the same value.
func sameValue(a, b *ua.DataValue) bool {
	var va, vb any
	if a != nil && a.Value != nil {
		va = a.Value.Value()
	}
	if b != nil && b.Value != nil {
		vb = b.Value.Value()
	}
	return reflect.DeepEqual(va, vb)
}

// propertyOwner returns the node whose Property n is (the source of its
// inverse HasProperty reference), nil if there is none.
func (n *Node) propertyOwner() *Node {
	for _, r := range n.refsSnapshot() {
		if r == nil || r.IsForward || r.ReferenceTypeID == nil || r.ReferenceTypeID.Namespace() != 0 ||
			r.ReferenceTypeID.IntID() != id.HasProperty || r.NodeID == nil || r.NodeID.ServerIndex != 0 {
			continue
		}
		return n.lookup(r.NodeID.NodeID)
	}
	return nil
}

// semanticChange reports that the Value of the Property p, which has the
// SemanticChange bit, changed: a SemanticChangeEvent for the node of the
// Property (Part 5 §6.4.33, §12.17) and the SemanticsChanged bit on the
// next data change Notification of each MonitoredItem of its Value.
func (s *Server) semanticChange(p *Node) {
	if s == nil || s.cfg.addrSpace.modelChangeOff {
		return
	}
	owner := p.propertyOwner()
	if owner == nil {
		return
	}
	ev := changeEvent(id.SemanticChangeEventType, "The semantics of a node changed")
	ev.Fields = map[string]*ua.Variant{"Changes": ua.MustVariant([]*ua.ExtensionObject{
		ua.NewExtensionObject(&ua.SemanticChangeStructureDataType{Affected: owner.ID(), AffectedType: affectedType(owner)}),
	})}
	if s.MonitoredItemService != nil {
		s.MonitoredItemService.semanticsChanged(owner.ID())
	}
	s.emitEvent(ua.NewNumericNodeID(0, id.Server), ev, false)
}

// semanticsChanged marks the data items of the Value of the node nid: the
// next data change Notification of each carries the SemanticsChanged bit
// (Part 4 §7.38.1).
func (s *MonitoredItemService) semanticsChanged(nid *ua.NodeID) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	for _, item := range s.Nodes[nid.String()] {
		if item != nil && !item.isEvent && item.Req != nil && item.Req.ItemToMonitor != nil &&
			item.Req.ItemToMonitor.AttributeID == ua.AttributeIDValue {
			item.semanticsPending = true
		}
	}
}

// markSemantics sets the SemanticsChanged bit on n when the item has one
// pending. Caller must hold s.Mu.
func (item *MonitoredItem) markSemantics(n *ua.MonitoredItemNotification) {
	if !item.semanticsPending || n == nil || n.Value == nil {
		return
	}
	n.Value.Status |= statusSemanticsChanged
	n.Value.EncodingMask |= ua.DataValueStatusCode
	item.semanticsPending = false
}

// dropSemantics is called for the notification d the queue discards in
// favour of next: the SemanticsChanged bit of d moves to next ("If that
// notification is dropped by a queue overflow, the bit moves to the next
// data change notification in the queue", Part 4 §7.38.1).
func dropSemantics(d, next *ua.MonitoredItemNotification) {
	if d == nil || d.Value == nil || d.Value.Status&statusSemanticsChanged == 0 || next == nil || next.Value == nil {
		return
	}
	next.Value.Status |= statusSemanticsChanged
	next.Value.EncodingMask |= ua.DataValueStatusCode
}
