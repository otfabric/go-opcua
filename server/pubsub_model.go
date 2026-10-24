// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/pubsub/transport/eth"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
)

// PubSubNamespaceURI is the namespace of the nodes of the PubSub components
// (connections, groups, writers, readers, published data sets).
const PubSubNamespaceURI = "urn:otfabric:go-opcua:pubsub"

// pubsubModel is the PublishSubscribe information model of a server.
type pubsubModel struct {
	s      *Server
	rt     *pubsub.PubSub
	ns     *NodeNameSpace
	root   *Node // PublishSubscribe (i=14443)
	pdsDir *Node // PublishSubscribe.PublishedDataSets (i=17371)
	comps  map[pubsub.ComponentID]*psComp
	byNode map[string]pubsub.ComponentID
}

// psComp is the representation of one component.
type psComp struct {
	id      pubsub.ComponentID
	kind    pubsub.ComponentKind
	obj     *Node
	parent  *Node
	refType uint32
	nodes   []*ua.NodeID
	methods [][2]*ua.NodeID
	pds     *psComp // the published data set of a writer
	sds     *Node   // SubscribedDataSet of a reader
	mirror  *Node
	mvars   map[string]*Node
}

// ownNode replaces a namespace 0 node by a copy of it that this server may
// change, so that changes do not reach nodes shared with other servers.
func (s *Server) ownNode(nid uint32) *Node {
	n := s.Node(ua.NewNumericNodeID(0, nid))
	if n == nil {
		return nil
	}
	n.mu.RLock()
	cp := &Node{
		id:              n.id,
		attr:            maps.Clone(n.attr),
		refs:            slices.Clone(n.refs),
		val:             n.val,
		rolePermissions: n.rolePermissions,
	}
	n.mu.RUnlock()
	return s.namespaces[0].AddNode(cp)
}

func hasForwardRef(n *Node, target *ua.NodeID, refType uint32) bool {
	for _, r := range n.refsSnapshot() {
		if r != nil && r.IsForward && r.NodeID != nil && r.ReferenceTypeID != nil && r.ReferenceTypeID.IntID() == refType && r.NodeID.NodeID.Equal(target) {
			return true
		}
	}
	return false
}

// addMethodRef references a namespace 0 method node from an object, as
// open62541 does for the methods of PubSub instances.
func (s *Server) addMethodRef(obj *Node, method uint32) {
	mn := s.Node(ua.NewNumericNodeID(0, method))
	if mn == nil || hasForwardRef(obj, mn.ID(), id.HasComponent) {
		return
	}
	obj.AddRef(mn, RefTypeIDHasComponent, true)
}

func (s *Server) unregisterMethod(objectID, methodID *ua.NodeID) {
	s.mu.Lock()
	delete(s.methods, methodKey(objectID, methodID))
	s.mu.Unlock()
}

// buildPubSubModel publishes the runtime in the address space.
func (s *Server) buildPubSubModel() error {
	s.ps.mu.Lock()
	defer s.ps.mu.Unlock()
	if s.ps.model != nil {
		return nil
	}
	rt := s.ps.rt
	root := s.ownNode(id.PublishSubscribe)
	pdsDir := s.ownNode(id.PublishSubscribePublishedDataSets)
	status := s.ownNode(id.PublishSubscribeStatus)
	state := s.ownNode(id.PublishSubscribeStatusState)
	if root == nil || pdsDir == nil || status == nil || state == nil {
		return errors.New("server: pubsub: the PublishSubscribe object is missing from namespace 0")
	}
	var ns *NodeNameSpace
	for _, x := range s.Namespaces() {
		if nns, ok := x.(*NodeNameSpace); ok && x.Name() == PubSubNamespaceURI {
			ns = nns
		}
	}
	if ns == nil {
		ns = NewNodeNameSpace(s, PubSubNamespaceURI)
	}
	m := &pubsubModel{s: s, rt: rt, ns: ns, root: root, pdsDir: pdsDir,
		comps: map[pubsub.ComponentID]*psComp{}, byNode: map[string]pubsub.ComponentID{}}

	state.mu.Lock()
	state.val = m.stateValue(pubsub.Root)
	state.mu.Unlock()
	s.addMethodRef(status, id.PubSubStatusTypeEnable)
	s.addMethodRef(status, id.PubSubStatusTypeDisable)
	s.RegisterMethod(status.ID(), ua.NewNumericNodeID(0, id.PubSubStatusTypeEnable), m.enableMethod(pubsub.Root, true))
	s.RegisterMethod(status.ID(), ua.NewNumericNodeID(0, id.PubSubStatusTypeDisable), m.enableMethod(pubsub.Root, false))

	s.RegisterMethod(root.ID(), ua.NewNumericNodeID(0, id.PublishSubscribeAddConnection), m.method("AddConnection", m.addConnection))
	s.RegisterMethod(root.ID(), ua.NewNumericNodeID(0, id.PublishSubscribeRemoveConnection), m.method("RemoveConnection", m.removeConnection))
	for _, mid := range []uint32{id.DataSetFolderTypeAddPublishedDataItems, id.DataSetFolderTypeAddPublishedDataItemsTemplate, id.DataSetFolderTypeRemovePublishedDataSet} {
		s.addMethodRef(pdsDir, mid)
	}
	s.RegisterMethod(pdsDir.ID(), ua.NewNumericNodeID(0, id.DataSetFolderTypeAddPublishedDataItems), m.method("AddPublishedDataItems", m.addPublishedDataItems))
	s.RegisterMethod(pdsDir.ID(), ua.NewNumericNodeID(0, id.DataSetFolderTypeAddPublishedDataItemsTemplate), m.method("AddPublishedDataItemsTemplate", m.addPublishedDataItemsTemplate))
	s.RegisterMethod(pdsDir.ID(), ua.NewNumericNodeID(0, id.DataSetFolderTypeRemovePublishedDataSet), m.method("RemovePublishedDataSet", m.removePublishedDataSet))

	if n := s.ownNode(id.PublishSubscribeSupportedTransportProfiles); n != nil {
		dv := DataValueFromValue(supportedTransportProfiles())
		n.mu.Lock()
		n.val = func() *ua.DataValue { return dv }
		n.mu.Unlock()
	}
	m.setCapabilities()
	m.bindRootDiagnostics()

	// Published data sets first: writers reference them.
	comps := rt.Components()
	for _, c := range comps {
		if c.Kind == pubsub.KindPublishedDataSet {
			m.add(c)
		}
	}
	for _, c := range comps {
		m.add(c)
	}
	s.ps.model = m
	return nil
}

// setCapabilities fills the PubSubCapablities properties. Zero means no
// limit.
func (m *pubsubModel) setCapabilities() {
	caps := m.s.Node(ua.NewNumericNodeID(0, id.PublishSubscribePubSubCapablities))
	if caps == nil {
		return
	}
	values := map[string]any{
		"MaxNetworkMessageSizeDatagram": uint32(65507),
		"MaxNetworkMessageSizeBroker":   uint32(1 << 20),
		"SupportSecurityKeyPull":        true,
		"SupportSecurityKeyPush":        true,
		"SupportSecurityKeyServer":      true,
	}
	for _, r := range caps.refsSnapshot() {
		if r == nil || !r.IsForward || r.ReferenceTypeID == nil || r.ReferenceTypeID.IntID() != id.HasProperty || r.NodeID == nil || r.NodeID.NodeID.Namespace() != 0 {
			continue
		}
		n := m.s.ownNode(r.NodeID.NodeID.IntID())
		if n == nil {
			continue
		}
		v, ok := values[r.BrowseName.Name]
		if !ok {
			v = uint32(0)
		}
		dv := DataValueFromValue(v)
		n.mu.Lock()
		n.val = func() *ua.DataValue { return dv }
		n.mu.Unlock()
	}
}

// onPubSubEvent keeps the information model in line with the runtime.
func (s *Server) onPubSubEvent(ev pubsub.Event) {
	s.ps.mu.Lock()
	defer s.ps.mu.Unlock()
	m := s.ps.model
	if m == nil {
		return
	}
	switch ev.Type {
	case pubsub.EventAdded:
		m.add(ev.Component)
	case pubsub.EventRemoved:
		m.remove(ev.Component.ID)
	case pubsub.EventStateChanged:
		if n := m.comps[ev.Component.ID]; n != nil && n.obj != nil {
			s.ChangeNotification(n.obj.ID())
		}
	}
}

// PubSubNodeID returns the NodeId of the object of a PubSub component in the
// information model.
func (s *Server) PubSubNodeID(c pubsub.ComponentID) (*ua.NodeID, bool) {
	s.ps.mu.Lock()
	defer s.ps.mu.Unlock()
	m := s.ps.model
	if m == nil {
		return nil, false
	}
	if c == pubsub.Root {
		return m.root.ID(), true
	}
	if n := m.comps[c]; n != nil {
		return n.obj.ID(), true
	}
	return nil, false
}

// PubSubComponentID returns the PubSub component of an object of the
// information model.
func (s *Server) PubSubComponentID(nodeID *ua.NodeID) (pubsub.ComponentID, bool) {
	s.ps.mu.Lock()
	defer s.ps.mu.Unlock()
	if s.ps.model == nil || nodeID == nil {
		return 0, false
	}
	c, ok := s.ps.model.byNode[nodeID.String()]
	return c, ok
}

func (m *pubsubModel) stateValue(c pubsub.ComponentID) ValueFunc {
	return func() *ua.DataValue {
		st, err := m.rt.State(c)
		if err != nil {
			return badValue(ua.StatusBadNodeIDUnknown)
		}
		return DataValueFromValue(int32(st))
	}
}

func (m *pubsubModel) nextID() *ua.NodeID {
	return ua.NewNumericNodeID(m.ns.ID(), m.ns.GetNextNodeID())
}

func (m *pubsubModel) typeDef(n *Node, t uint32) {
	if tn := m.s.Node(ua.NewNumericNodeID(0, t)); tn != nil {
		n.AddRef(tn, RefType(id.HasTypeDefinition), true)
	}
}

// object creates an object node below parent.
func (m *pubsubModel) object(c *psComp, parent *Node, refType uint32, name string, nsIndex uint16, typeDef uint32) *Node {
	n := NewNode(m.nextID(), Attributes{
		ua.AttributeIDNodeClass:     DataValueFromValue(uint32(ua.NodeClassObject)),
		ua.AttributeIDBrowseName:    DataValueFromValue(&ua.QualifiedName{NamespaceIndex: nsIndex, Name: name}),
		ua.AttributeIDDisplayName:   DataValueFromValue(attrs.DisplayName(name, "")),
		ua.AttributeIDDescription:   DataValueFromValue(&ua.LocalizedText{}),
		ua.AttributeIDEventNotifier: DataValueFromValue(byte(0)),
	}, nil, nil)
	m.ns.AddNode(n)
	m.typeDef(n, typeDef)
	linkChild(parent, n, refType)
	c.nodes = append(c.nodes, n.ID())
	return n
}

// variable creates a variable (a property with HasProperty) below parent.
func (m *pubsubModel) variable(c *psComp, parent *Node, refType uint32, name string, dataType uint32, valueRank int32, val ValueFunc) *Node {
	return m.variableNS(c, parent, refType, 0, name, dataType, valueRank, val)
}

// variableNS creates a variable whose BrowseName is in namespace nsIndex.
func (m *pubsubModel) variableNS(c *psComp, parent *Node, refType uint32, nsIndex uint16, name string, dataType uint32, valueRank int32, val ValueFunc) *Node {
	typeDef := uint32(id.BaseDataVariableType)
	if refType == id.HasProperty {
		typeDef = id.PropertyType
	}
	return m.variableT(c, parent, refType, nsIndex, name, dataType, valueRank, typeDef, val)
}

// variableT creates a variable of the given VariableType.
func (m *pubsubModel) variableT(c *psComp, parent *Node, refType uint32, nsIndex uint16, name string, dataType uint32, valueRank int32, typeDef uint32, val ValueFunc) *Node {
	n := NewNode(m.nextID(), Attributes{
		ua.AttributeIDNodeClass:       DataValueFromValue(uint32(ua.NodeClassVariable)),
		ua.AttributeIDBrowseName:      DataValueFromValue(&ua.QualifiedName{NamespaceIndex: nsIndex, Name: name}),
		ua.AttributeIDDisplayName:     DataValueFromValue(attrs.DisplayName(name, "")),
		ua.AttributeIDDescription:     DataValueFromValue(&ua.LocalizedText{}),
		ua.AttributeIDDataType:        DataValueFromValue(ua.NewNumericExpandedNodeID(0, dataType)),
		ua.AttributeIDValueRank:       DataValueFromValue(valueRank),
		ua.AttributeIDAccessLevel:     DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead)),
		ua.AttributeIDUserAccessLevel: DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead)),
	}, nil, val)
	m.ns.AddNode(n)
	m.typeDef(n, typeDef)
	linkChild(parent, n, refType)
	c.nodes = append(c.nodes, n.ID())
	return n
}

func static(v any) ValueFunc {
	dv := DataValueFromValue(v)
	return func() *ua.DataValue { return dv }
}

func eos[T any](xs []*T) []*ua.ExtensionObject {
	out := make([]*ua.ExtensionObject, 0, len(xs))
	for _, x := range xs {
		if x != nil {
			out = append(out, ua.NewExtensionObject(x))
		}
	}
	return out
}

func eo(v any) *ua.ExtensionObject {
	if v == nil {
		return ua.NewExtensionObject(nil)
	}
	return ua.NewExtensionObject(v)
}

func publisherIDValue(v *ua.Variant) ValueFunc {
	if v == nil {
		v = ua.MustVariant(nil)
	}
	return static(v)
}

func (m *pubsubModel) prop(c *psComp, parent *Node, name string, dataType uint32, valueRank int32, v any) {
	m.variable(c, parent, id.HasProperty, name, dataType, valueRank, static(v))
}

// status creates the Status object with its State and the Enable and
// Disable methods.
func (m *pubsubModel) status(c *psComp) {
	st := m.object(c, c.obj, id.HasComponent, "Status", 0, id.PubSubStatusType)
	m.variable(c, st, id.HasComponent, "State", id.PubSubState, -1, m.stateValue(c.id))
	m.s.addMethodRef(st, id.PubSubStatusTypeEnable)
	m.s.addMethodRef(st, id.PubSubStatusTypeDisable)
	m.register(c, st.ID(), id.PubSubStatusTypeEnable, m.enableMethod(c.id, true))
	m.register(c, st.ID(), id.PubSubStatusTypeDisable, m.enableMethod(c.id, false))
}

func (m *pubsubModel) register(c *psComp, obj *ua.NodeID, method uint32, h MethodHandler) {
	mid := ua.NewNumericNodeID(0, method)
	m.s.RegisterMethod(obj, mid, h)
	c.methods = append(c.methods, [2]*ua.NodeID{obj, mid})
}

// add creates the representation of a component.
func (m *pubsubModel) add(info pubsub.ComponentInfo) {
	if _, ok := m.comps[info.ID]; ok {
		return
	}
	c := &psComp{id: info.ID, kind: info.Kind}
	var err error
	switch info.Kind {
	case pubsub.KindConnection:
		err = m.addConnectionNodes(c, info)
	case pubsub.KindWriterGroup:
		err = m.addWriterGroupNodes(c, info)
	case pubsub.KindReaderGroup:
		err = m.addReaderGroupNodes(c, info)
	case pubsub.KindDataSetWriter:
		err = m.addWriterNodes(c, info)
	case pubsub.KindDataSetReader:
		err = m.addReaderNodes(c, info)
	case pubsub.KindPublishedDataSet:
		err = m.addPDSNodes(c, info)
	case pubsub.KindPubSub:
		return
	}
	if err != nil {
		m.s.cfg.logger.Debug("pubsub: no node for component", "id", info.ID, "error", err)
		m.drop(c)
		return
	}
	m.comps[c.id] = c
	m.byNode[c.obj.ID().String()] = c.id
	if c.kind == pubsub.KindPublishedDataSet {
		m.linkWriters(c, info.Name)
	}
}

// linkWriters adds the DataSetToWriter references from a published data set
// to the writers of it that were represented before it (see parentOf).
func (m *pubsubModel) linkWriters(pds *psComp, name string) {
	for _, w := range m.comps {
		if w.kind != pubsub.KindDataSetWriter || w.pds != nil {
			continue
		}
		if cfg, err := m.rt.DataSetWriterConfig(w.id); err == nil && cfg.DataSetName == name {
			linkChild(pds.obj, w.obj, id.DataSetToWriter)
			w.pds = pds
		}
	}
}

// parentOf returns the representation of the parent of a component,
// creating it first if needed. The runtime runs its event callbacks after it
// released its lock, so with concurrent changes the event that adds a child
// can be handled before the one that adds its parent.
func (m *pubsubModel) parentOf(info pubsub.ComponentInfo) (*psComp, error) {
	return m.ensure(info.Parent)
}

// ensure returns the representation of component cid, creating it from the
// runtime if its EventAdded has not been handled yet. It fails if the
// component no longer exists.
func (m *pubsubModel) ensure(cid pubsub.ComponentID) (*psComp, error) {
	if p := m.comps[cid]; p != nil {
		return p, nil
	}
	info, err := m.rt.Component(cid)
	if err != nil {
		return nil, fmt.Errorf("component %d: %w", cid, err)
	}
	m.add(info)
	if p := m.comps[cid]; p != nil {
		return p, nil
	}
	return nil, fmt.Errorf("component %d has no node", cid)
}

func (m *pubsubModel) addConnectionNodes(c *psComp, info pubsub.ComponentInfo) error {
	cfg, err := m.rt.ConnectionConfig(info.ID)
	if err != nil {
		return err
	}
	c.parent, c.refType = m.root, id.HasPubSubConnection
	c.obj = m.object(c, m.root, id.HasPubSubConnection, info.Name, m.ns.ID(), id.PubSubConnectionType)
	m.variable(c, c.obj, id.HasProperty, "PublisherId", id.BaseDataType, -1, publisherIDValue(cfg.PublisherID))
	m.variable(c, c.obj, id.HasComponent, "TransportProfileUri", id.String, -1, static(cfg.TransportProfileURI))
	m.prop(c, c.obj, "ConnectionProperties", id.KeyValuePair, 1, eos(cfg.ConnectionProperties))
	addr := m.object(c, c.obj, id.HasComponent, "Address", 0, id.NetworkAddressURLType)
	var url, iface string
	if a, ok := cfg.Address.Value.(*ua.NetworkAddressURLDataType); ok {
		url, iface = a.URL, a.NetworkInterface
	}
	m.variable(c, addr, id.HasComponent, "NetworkInterface", id.String, -1, static(iface))
	m.variable(c, addr, id.HasComponent, "Url", id.String, -1, static(url))
	m.status(c)
	m.diagnostics(c)
	for _, mid := range []uint32{id.PubSubConnectionTypeAddWriterGroup, id.PubSubConnectionTypeAddReaderGroup, id.PubSubConnectionTypeRemoveGroup} {
		m.s.addMethodRef(c.obj, mid)
	}
	cid := info.ID
	m.register(c, c.obj.ID(), id.PubSubConnectionTypeAddWriterGroup, m.method("AddWriterGroup", m.addGroup(cid, true)))
	m.register(c, c.obj.ID(), id.PubSubConnectionTypeAddReaderGroup, m.method("AddReaderGroup", m.addGroup(cid, false)))
	m.register(c, c.obj.ID(), id.PubSubConnectionTypeRemoveGroup, m.method("RemoveGroup", m.removeChild(cid, pubsub.KindWriterGroup, pubsub.KindReaderGroup)))
	return nil
}

func (m *pubsubModel) groupProps(c *psComp, mode ua.MessageSecurityMode, groupID string, sks []*ua.EndpointDescription, maxSize uint32, props []*ua.KeyValuePair) {
	m.prop(c, c.obj, "SecurityMode", id.MessageSecurityMode, -1, int32(mode))
	m.prop(c, c.obj, "SecurityGroupId", id.String, -1, groupID)
	m.prop(c, c.obj, "SecurityKeyServices", id.EndpointDescription, 1, eos(sks))
	m.prop(c, c.obj, "MaxNetworkMessageSize", id.UInt32, -1, maxSize)
	m.prop(c, c.obj, "GroupProperties", id.KeyValuePair, 1, eos(props))
}

func (m *pubsubModel) addWriterGroupNodes(c *psComp, info pubsub.ComponentInfo) error {
	p, err := m.parentOf(info)
	if err != nil {
		return err
	}
	cfg, err := m.rt.WriterGroupConfig(info.ID)
	if err != nil {
		return err
	}
	c.parent, c.refType = p.obj, id.HasWriterGroup
	c.obj = m.object(c, p.obj, id.HasWriterGroup, info.Name, m.ns.ID(), id.WriterGroupType)
	m.groupProps(c, cfg.SecurityMode, cfg.SecurityGroupID, cfg.SecurityKeyServices, cfg.MaxNetworkMessageSize, cfg.GroupProperties)
	m.prop(c, c.obj, "WriterGroupId", id.UInt16, -1, cfg.WriterGroupID)
	m.prop(c, c.obj, "PublishingInterval", id.Duration, -1, cfg.PublishingInterval)
	m.prop(c, c.obj, "KeepAliveTime", id.Duration, -1, cfg.KeepAliveTime)
	m.prop(c, c.obj, "Priority", id.Byte, -1, cfg.Priority)
	m.prop(c, c.obj, "LocaleIds", id.LocaleID, 1, append([]string{}, cfg.LocaleIDs...))
	m.prop(c, c.obj, "HeaderLayoutUri", id.String, -1, cfg.HeaderLayoutURI)
	switch ms := cfg.MessageSettings.Value.(type) {
	case *ua.UADPWriterGroupMessageDataType:
		o := m.object(c, c.obj, id.HasComponent, "MessageSettings", 0, id.UADPWriterGroupMessageType)
		m.prop(c, o, "GroupVersion", id.VersionTime, -1, ms.GroupVersion)
		m.prop(c, o, "DataSetOrdering", id.DataSetOrderingType, -1, int32(ms.DataSetOrdering))
		m.prop(c, o, "NetworkMessageContentMask", id.UADPNetworkMessageContentMask, -1, uint32(ms.NetworkMessageContentMask))
		m.prop(c, o, "SamplingOffset", id.Duration, -1, ms.SamplingOffset)
		m.prop(c, o, "PublishingOffset", id.Duration, 1, append([]float64{}, ms.PublishingOffset...))
	case *ua.JSONWriterGroupMessageDataType:
		o := m.object(c, c.obj, id.HasComponent, "MessageSettings", 0, id.JSONWriterGroupMessageType)
		m.prop(c, o, "NetworkMessageContentMask", id.JSONNetworkMessageContentMask, -1, uint32(ms.NetworkMessageContentMask))
	}
	m.status(c)
	m.diagnostics(c)
	m.s.addMethodRef(c.obj, id.WriterGroupTypeAddDataSetWriter)
	m.s.addMethodRef(c.obj, id.WriterGroupTypeRemoveDataSetWriter)
	gid := info.ID
	m.register(c, c.obj.ID(), id.WriterGroupTypeAddDataSetWriter, m.method("AddDataSetWriter", m.addWriter(gid)))
	m.register(c, c.obj.ID(), id.WriterGroupTypeRemoveDataSetWriter, m.method("RemoveDataSetWriter", m.removeChild(gid, pubsub.KindDataSetWriter)))
	return nil
}

func (m *pubsubModel) addReaderGroupNodes(c *psComp, info pubsub.ComponentInfo) error {
	p, err := m.parentOf(info)
	if err != nil {
		return err
	}
	cfg, err := m.rt.ReaderGroupConfig(info.ID)
	if err != nil {
		return err
	}
	c.parent, c.refType = p.obj, id.HasReaderGroup
	c.obj = m.object(c, p.obj, id.HasReaderGroup, info.Name, m.ns.ID(), id.ReaderGroupType)
	m.groupProps(c, cfg.SecurityMode, cfg.SecurityGroupID, cfg.SecurityKeyServices, cfg.MaxNetworkMessageSize, cfg.GroupProperties)
	m.status(c)
	m.diagnostics(c)
	m.s.addMethodRef(c.obj, id.ReaderGroupTypeAddDataSetReader)
	m.s.addMethodRef(c.obj, id.ReaderGroupTypeRemoveDataSetReader)
	gid := info.ID
	m.register(c, c.obj.ID(), id.ReaderGroupTypeAddDataSetReader, m.method("AddDataSetReader", m.addReader(gid)))
	m.register(c, c.obj.ID(), id.ReaderGroupTypeRemoveDataSetReader, m.method("RemoveDataSetReader", m.removeChild(gid, pubsub.KindDataSetReader)))
	return nil
}

func (m *pubsubModel) addWriterNodes(c *psComp, info pubsub.ComponentInfo) error {
	p, err := m.parentOf(info)
	if err != nil {
		return err
	}
	cfg, err := m.rt.DataSetWriterConfig(info.ID)
	if err != nil {
		return err
	}
	c.parent, c.refType = p.obj, id.HasDataSetWriter
	c.obj = m.object(c, p.obj, id.HasDataSetWriter, info.Name, m.ns.ID(), id.DataSetWriterType)
	m.prop(c, c.obj, "DataSetWriterId", id.UInt16, -1, cfg.DataSetWriterID)
	m.prop(c, c.obj, "DataSetFieldContentMask", id.DataSetFieldContentMask, -1, uint32(cfg.DataSetFieldContentMask))
	m.prop(c, c.obj, "KeyFrameCount", id.UInt32, -1, cfg.KeyFrameCount)
	m.prop(c, c.obj, "DataSetWriterProperties", id.KeyValuePair, 1, eos(cfg.DataSetWriterProperties))
	m.status(c)
	m.diagnostics(c)
	if cfg.DataSetName != "" {
		if pid, ok := m.rt.Lookup(pubsub.KindPublishedDataSet, pubsub.Root, cfg.DataSetName); ok {
			if pds, err := m.ensure(pid); err == nil {
				linkChild(pds.obj, c.obj, id.DataSetToWriter)
				c.pds = pds
			}
		}
	}
	return nil
}

func (m *pubsubModel) addReaderNodes(c *psComp, info pubsub.ComponentInfo) error {
	p, err := m.parentOf(info)
	if err != nil {
		return err
	}
	cfg, err := m.rt.DataSetReaderConfig(info.ID)
	if err != nil {
		return err
	}
	rid := info.ID
	c.parent, c.refType = p.obj, id.HasDataSetReader
	c.obj = m.object(c, p.obj, id.HasDataSetReader, info.Name, m.ns.ID(), id.DataSetReaderType)
	m.variable(c, c.obj, id.HasProperty, "PublisherId", id.BaseDataType, -1, publisherIDValue(cfg.PublisherID))
	m.prop(c, c.obj, "WriterGroupId", id.UInt16, -1, cfg.WriterGroupID)
	m.prop(c, c.obj, "DataSetWriterId", id.UInt16, -1, cfg.DataSetWriterID)
	m.variable(c, c.obj, id.HasProperty, "DataSetMetaData", id.DataSetMetaDataType, -1, func() *ua.DataValue {
		cfg, err := m.rt.DataSetReaderConfig(rid)
		if err != nil {
			return badValue(ua.StatusBadNodeIDUnknown)
		}
		return DataValueFromValue(eo(cfg.DataSetMetaData))
	})
	m.prop(c, c.obj, "DataSetFieldContentMask", id.DataSetFieldContentMask, -1, uint32(cfg.DataSetFieldContentMask))
	m.prop(c, c.obj, "MessageReceiveTimeout", id.Duration, -1, cfg.MessageReceiveTimeout)
	m.prop(c, c.obj, "KeyFrameCount", id.UInt32, -1, cfg.KeyFrameCount)
	m.prop(c, c.obj, "HeaderLayoutUri", id.String, -1, cfg.HeaderLayoutURI)
	m.prop(c, c.obj, "SecurityMode", id.MessageSecurityMode, -1, int32(cfg.SecurityMode))
	m.prop(c, c.obj, "SecurityGroupId", id.String, -1, cfg.SecurityGroupID)
	m.prop(c, c.obj, "SecurityKeyServices", id.EndpointDescription, 1, eos(cfg.SecurityKeyServices))
	m.prop(c, c.obj, "DataSetReaderProperties", id.KeyValuePair, 1, eos(cfg.DataSetReaderProperties))
	m.status(c)
	m.diagnostics(c)
	switch sds := cfg.SubscribedDataSet.Value.(type) {
	case *ua.TargetVariablesDataType:
		c.sds = m.object(c, c.obj, id.HasComponent, "SubscribedDataSet", 0, id.TargetVariablesType)
		m.prop(c, c.sds, "TargetVariables", id.FieldTargetDataType, 1, eos(sds.TargetVariables))
	case *ua.SubscribedDataSetMirrorDataType:
		c.sds = m.object(c, c.obj, id.HasComponent, "SubscribedDataSet", 0, id.SubscribedDataSetMirrorType)
	default:
		c.sds = m.object(c, c.obj, id.HasComponent, "SubscribedDataSet", 0, id.SubscribedDataSetType)
	}
	return nil
}

func (m *pubsubModel) addPDSNodes(c *psComp, info pubsub.ComponentInfo) error {
	cfg, err := m.rt.PublishedDataSetConfig(info.ID)
	if err != nil {
		return err
	}
	c.parent, c.refType = m.pdsDir, id.HasComponent
	md := cfg.DataSetMetaData
	switch src := cfg.DataSetSource.Value.(type) {
	case *ua.PublishedEventsDataType:
		c.obj = m.object(c, m.pdsDir, id.HasComponent, info.Name, m.ns.ID(), id.PublishedEventsType)
		m.prop(c, c.obj, "EventNotifier", id.NodeID, -1, src.EventNotifier)
		m.prop(c, c.obj, "SelectedFields", id.SimpleAttributeOperand, 1, eos(src.SelectedFields))
		if src.Filter != nil {
			m.prop(c, c.obj, "Filter", id.ContentFilter, -1, eo(src.Filter))
		}
	case *ua.PublishedActionDataType, *ua.PublishedActionMethodDataType:
		// The nodeset has no PublishedActionType (Part 14 v1.05):
		// a PublishedAction shows as a PublishedDataSet.
		c.obj = m.object(c, m.pdsDir, id.HasComponent, info.Name, m.ns.ID(), id.PublishedDataSetType)
	default:
		c.obj = m.object(c, m.pdsDir, id.HasComponent, info.Name, m.ns.ID(), id.PublishedDataItemsType)
		var items []*ua.PublishedVariableDataType
		if di, ok := src.(*ua.PublishedDataItemsDataType); ok {
			items = di.PublishedData
		}
		m.prop(c, c.obj, "PublishedData", id.PublishedVariableDataType, 1, eos(items))
	}
	m.prop(c, c.obj, "ConfigurationVersion", id.ConfigurationVersionDataType, -1, eo(md.ConfigurationVersion))
	m.prop(c, c.obj, "DataSetMetaData", id.DataSetMetaDataType, -1, eo(md))
	return nil
}

// remove deletes the representation of a component.
func (m *pubsubModel) remove(cid pubsub.ComponentID) {
	c := m.comps[cid]
	if c == nil {
		return
	}
	delete(m.comps, cid)
	delete(m.byNode, c.obj.ID().String())
	if c.parent != nil {
		c.parent.RemoveRef(ua.NewExpandedNodeID(c.obj.ID(), "", 0), ua.NewNumericNodeID(0, c.refType), true)
	}
	if c.pds != nil {
		c.pds.obj.RemoveRef(ua.NewExpandedNodeID(c.obj.ID(), "", 0), ua.NewNumericNodeID(0, id.DataSetToWriter), true)
	}
	m.drop(c)
	m.s.ChangeNotification(c.obj.ID())
}

// drop deletes the nodes of a component and its method registrations.
func (m *pubsubModel) drop(c *psComp) {
	for _, mm := range c.methods {
		m.s.unregisterMethod(mm[0], mm[1])
	}
	for _, n := range c.nodes {
		_ = m.ns.DeleteNode(n)
	}
	if c.parent != nil && c.obj != nil {
		c.parent.RemoveRef(ua.NewExpandedNodeID(c.obj.ID(), "", 0), ua.NewNumericNodeID(0, c.refType), true)
	}
}

// writeMirror mirrors a received DataSet below the SubscribedDataSet object
// of its reader.
func (s *Server) writeMirror(mw *pubsub.MirrorWrite) error {
	s.ps.mu.Lock()
	m := s.ps.model
	if m == nil {
		s.ps.mu.Unlock()
		return errors.New("server: pubsub: no information model")
	}
	c := m.comps[mw.Reader]
	if c == nil || c.sds == nil {
		s.ps.mu.Unlock()
		return fmt.Errorf("server: pubsub: reader %d has no SubscribedDataSet node", mw.Reader)
	}
	if c.mirror == nil {
		c.mirror = m.object(c, c.sds, id.HasComponent, mw.Mirror.ParentNodeName, m.ns.ID(), id.BaseObjectType)
		c.mvars = map[string]*Node{}
	}
	type write struct {
		n  *Node
		dv *ua.DataValue
	}
	var writes []write
	for _, i := range mw.Changed {
		if i < 0 || i >= len(mw.Fields) || mw.Fields[i].Value == nil {
			continue
		}
		f := mw.Fields[i]
		name := f.Name
		if name == "" {
			name = fmt.Sprintf("Field%d", i)
		}
		n := c.mvars[name]
		if n == nil {
			dt, vr := uint32(id.BaseDataType), int32(-1)
			if mw.MetaData != nil && i < len(mw.MetaData.Fields) && mw.MetaData.Fields[i].DataType != nil {
				dt, vr = mw.MetaData.Fields[i].DataType.IntID(), mw.MetaData.Fields[i].ValueRank
			}
			n = m.variableNS(c, c.mirror, id.HasComponent, m.ns.ID(), name, dt, vr, nil)
			c.mvars[name] = n
		}
		writes = append(writes, write{n, f.Value})
	}
	s.ps.mu.Unlock()
	for _, w := range writes {
		dv := *w.dv
		w.n.mu.Lock()
		w.n.val = func() *ua.DataValue { return &dv }
		w.n.mu.Unlock()
		s.ChangeNotification(w.n.ID())
	}
	return nil
}

// method wraps a configuration method: authorisation, then the call.
func (m *pubsubModel) method(name string, f func(ctx context.Context, obj *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode)) MethodHandler {
	return func(ctx context.Context, obj, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		if a := m.s.cfg.pubsubAuth; a != nil {
			caller, _ := MethodCallerFromContext(ctx)
			if sc := a(ctx, caller, name); sc != ua.StatusOK {
				return nil, sc
			}
		}
		return f(ctx, obj, args)
	}
}

func (m *pubsubModel) enableMethod(cid pubsub.ComponentID, on bool) MethodHandler {
	name := "Disable"
	if on {
		name = "Enable"
	}
	return m.method(name, func(context.Context, *ua.NodeID, []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		var err error
		if on {
			err = m.rt.Enable(cid)
		} else {
			err = m.rt.Disable(cid)
		}
		return nil, statusOf(err)
	})
}

// statusOf maps a runtime error to the status of a method call.
func statusOf(err error) ua.StatusCode {
	sc := pubsub.StatusCodeOf(err)
	if sc == ua.StatusBadNotFound {
		return ua.StatusBadNodeIDUnknown
	}
	return sc
}

func argValue[T any](args []*ua.Variant, i int) (T, bool) {
	var zero T
	if i >= len(args) || args[i] == nil {
		return zero, false
	}
	v, ok := args[i].Value().(T)
	return v, ok
}

// argStruct returns the decoded structure of an ExtensionObject argument.
func argStruct[T any](args []*ua.Variant, i int) (*T, bool) {
	e, ok := argValue[*ua.ExtensionObject](args, i)
	if !ok || e == nil {
		return nil, false
	}
	v, ok := e.Value.(*T)
	return v, ok && v != nil
}

// argStructs returns the decoded structures of an array of ExtensionObjects
// (an empty or null array gives none).
func argStructs[T any](args []*ua.Variant, i int) ([]*T, bool) {
	if i >= len(args) || args[i] == nil {
		return nil, false
	}
	if args[i].Value() == nil {
		return nil, true
	}
	es, ok := args[i].Value().([]*ua.ExtensionObject)
	if !ok {
		return nil, false
	}
	out := make([]*T, len(es))
	for j, e := range es {
		if e == nil {
			return nil, false
		}
		v, ok := e.Value.(*T)
		if !ok || v == nil {
			return nil, false
		}
		out[j] = v
	}
	return out, true
}

func (m *pubsubModel) nodeOf(cid pubsub.ComponentID) []*ua.Variant {
	m.s.ps.mu.Lock()
	defer m.s.ps.mu.Unlock()
	if c := m.comps[cid]; c != nil {
		return []*ua.Variant{ua.MustVariant(c.obj.ID())}
	}
	return []*ua.Variant{ua.MustVariant(ua.NewTwoByteNodeID(0))}
}

func (m *pubsubModel) componentOf(n *ua.NodeID) (pubsub.ComponentInfo, bool) {
	m.s.ps.mu.Lock()
	cid, ok := m.byNode[n.String()]
	m.s.ps.mu.Unlock()
	if !ok {
		return pubsub.ComponentInfo{}, false
	}
	info, err := m.rt.Component(cid)
	return info, err == nil
}

func (m *pubsubModel) addConnection(_ context.Context, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	cfg, ok := argStruct[ua.PubSubConnectionDataType](args, 0)
	if !ok {
		return nil, ua.StatusBadTypeMismatch
	}
	cid, err := m.rt.AddConnection(cfg)
	if err != nil {
		return nil, statusOf(err)
	}
	return m.nodeOf(cid), ua.StatusOK
}

func (m *pubsubModel) removeConnection(_ context.Context, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	n, ok := argValue[*ua.NodeID](args, 0)
	if !ok {
		return nil, ua.StatusBadTypeMismatch
	}
	info, ok := m.componentOf(n)
	if !ok || info.Kind != pubsub.KindConnection {
		return nil, ua.StatusBadNodeIDUnknown
	}
	return nil, statusOf(m.rt.RemoveConnection(info.ID))
}

func (m *pubsubModel) addGroup(conn pubsub.ComponentID, writer bool) func(context.Context, *ua.NodeID, []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	return func(_ context.Context, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		var cid pubsub.ComponentID
		var err error
		if writer {
			cfg, ok := argStruct[ua.WriterGroupDataType](args, 0)
			if !ok {
				return nil, ua.StatusBadTypeMismatch
			}
			cid, err = m.rt.AddWriterGroup(conn, cfg)
		} else {
			cfg, ok := argStruct[ua.ReaderGroupDataType](args, 0)
			if !ok {
				return nil, ua.StatusBadTypeMismatch
			}
			cid, err = m.rt.AddReaderGroup(conn, cfg)
		}
		if err != nil {
			return nil, statusOf(err)
		}
		return m.nodeOf(cid), ua.StatusOK
	}
}

func (m *pubsubModel) addWriter(group pubsub.ComponentID) func(context.Context, *ua.NodeID, []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	return func(_ context.Context, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		cfg, ok := argStruct[ua.DataSetWriterDataType](args, 0)
		if !ok {
			return nil, ua.StatusBadTypeMismatch
		}
		cid, err := m.rt.AddDataSetWriter(group, cfg)
		if err != nil {
			return nil, statusOf(err)
		}
		return m.nodeOf(cid), ua.StatusOK
	}
}

func (m *pubsubModel) addReader(group pubsub.ComponentID) func(context.Context, *ua.NodeID, []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	return func(_ context.Context, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		cfg, ok := argStruct[ua.DataSetReaderDataType](args, 0)
		if !ok {
			return nil, ua.StatusBadTypeMismatch
		}
		cid, err := m.rt.AddDataSetReader(group, cfg)
		if err != nil {
			return nil, statusOf(err)
		}
		return m.nodeOf(cid), ua.StatusOK
	}
}

// removeChild removes a child of the given kinds of the component the
// method was called on (RemoveGroup, RemoveDataSetWriter,
// RemoveDataSetReader).
func (m *pubsubModel) removeChild(parent pubsub.ComponentID, kinds ...pubsub.ComponentKind) func(context.Context, *ua.NodeID, []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	return func(_ context.Context, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		n, ok := argValue[*ua.NodeID](args, 0)
		if !ok {
			return nil, ua.StatusBadTypeMismatch
		}
		info, ok := m.componentOf(n)
		if !ok || info.Parent != parent || !slices.Contains(kinds, info.Kind) {
			return nil, ua.StatusBadNodeIDUnknown
		}
		var err error
		switch info.Kind {
		case pubsub.KindDataSetWriter:
			err = m.rt.RemoveDataSetWriter(info.ID)
		case pubsub.KindDataSetReader:
			err = m.rt.RemoveDataSetReader(info.ID)
		default:
			err = m.rt.RemoveGroup(info.ID)
		}
		return nil, statusOf(err)
	}
}

// publishedVariables checks the variables to publish: those that exist get
// Good, the others Bad_NodeIdUnknown.
func (m *pubsubModel) publishedVariables(vars []*ua.PublishedVariableDataType) []ua.StatusCode {
	results := make([]ua.StatusCode, len(vars))
	for i, v := range vars {
		if v.AttributeID == 0 {
			v.AttributeID = ua.AttributeIDValue
		}
		if v.PublishedVariable == nil || m.s.Node(v.PublishedVariable) == nil {
			results[i] = ua.StatusBadNodeIDUnknown
		}
	}
	return results
}

func (m *pubsubModel) addPublishedDataItems(_ context.Context, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	name, ok := argValue[string](args, 0)
	if !ok {
		return nil, ua.StatusBadTypeMismatch
	}
	var aliases []string
	if len(args) > 1 && args[1] != nil && args[1].Value() != nil {
		if aliases, ok = argValue[[]string](args, 1); !ok {
			return nil, ua.StatusBadTypeMismatch
		}
	}
	var flags []uint16
	if len(args) > 2 && args[2] != nil && args[2].Value() != nil {
		if flags, ok = argValue[[]uint16](args, 2); !ok {
			return nil, ua.StatusBadTypeMismatch
		}
	}
	vars, ok := argStructs[ua.PublishedVariableDataType](args, 3)
	if !ok {
		return nil, ua.StatusBadTypeMismatch
	}
	if len(aliases) != len(vars) || (len(flags) != 0 && len(flags) != len(vars)) {
		return nil, ua.StatusBadInvalidArgument
	}
	results := m.publishedVariables(vars)
	ds := serverDataSource{m.s}
	md := &ua.DataSetMetaDataType{Name: name, Description: &ua.LocalizedText{}}
	items := &ua.PublishedDataItemsDataType{}
	for i, v := range vars {
		if results[i] != ua.StatusOK {
			continue
		}
		f := ds.FieldMetaData(v)
		if f == nil {
			f = &ua.FieldMetaData{BuiltInType: uint8(ua.TypeIDVariant), DataType: ua.NewNumericNodeID(0, id.BaseDataType), ValueRank: -1}
		}
		if aliases[i] != "" {
			f.Name = aliases[i]
		}
		if len(flags) > 0 {
			f.FieldFlags = ua.DataSetFieldFlags(flags[i])
		}
		md.Fields = append(md.Fields, f)
		items.PublishedData = append(items.PublishedData, v)
	}
	cid, err := m.rt.AddPublishedDataSet(&ua.PublishedDataSetDataType{Name: name, DataSetMetaData: md, DataSetSource: ua.NewExtensionObject(items)})
	if err != nil {
		return nil, statusOf(err)
	}
	cfg, err := m.rt.PublishedDataSetConfig(cid)
	if err != nil {
		return nil, statusOf(err)
	}
	return append(m.nodeOf(cid), ua.MustVariant(eo(cfg.DataSetMetaData.ConfigurationVersion)), ua.MustVariant(results)), ua.StatusOK
}

func (m *pubsubModel) addPublishedDataItemsTemplate(_ context.Context, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	name, ok := argValue[string](args, 0)
	if !ok {
		return nil, ua.StatusBadTypeMismatch
	}
	md, ok := argStruct[ua.DataSetMetaDataType](args, 1)
	if !ok {
		return nil, ua.StatusBadTypeMismatch
	}
	vars, ok := argStructs[ua.PublishedVariableDataType](args, 2)
	if !ok {
		return nil, ua.StatusBadTypeMismatch
	}
	if len(md.Fields) != len(vars) {
		return nil, ua.StatusBadInvalidArgument
	}
	results := m.publishedVariables(vars)
	cid, err := m.rt.AddPublishedDataSet(&ua.PublishedDataSetDataType{
		Name: name, DataSetMetaData: md,
		DataSetSource: ua.NewExtensionObject(&ua.PublishedDataItemsDataType{PublishedData: vars}),
	})
	if err != nil {
		return nil, statusOf(err)
	}
	return append(m.nodeOf(cid), ua.MustVariant(results)), ua.StatusOK
}

func (m *pubsubModel) removePublishedDataSet(_ context.Context, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	n, ok := argValue[*ua.NodeID](args, 0)
	if !ok {
		return nil, ua.StatusBadTypeMismatch
	}
	info, ok := m.componentOf(n)
	if !ok || info.Kind != pubsub.KindPublishedDataSet {
		return nil, ua.StatusBadNodeIDUnknown
	}
	return nil, statusOf(m.rt.RemovePublishedDataSet(info.ID))
}

// supportedTransportProfiles lists the transport profiles of the
// PublishSubscribe object: Ethernet only on an OS where the transport works.
func supportedTransportProfiles() []string {
	profiles := []string{transport.ProfileUDPUADP, transport.ProfileMQTTUADP, transport.ProfileMQTTJSON,
		transport.ProfileAMQPUADP, transport.ProfileAMQPJSON}
	if eth.Supported {
		profiles = append(profiles, transport.ProfileEthUADP)
	}
	return profiles
}
