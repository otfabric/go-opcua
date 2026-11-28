// SPDX-License-Identifier: MIT

package server

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/nodeset"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
)

// NamespaceMetadata Objects and the default permissions of a namespace
// (Part 3 §4.9.3, §5.2.9 to §5.2.11; Part 5 §6.3.13, §6.3.14).
//
// The Namespaces Object of the Server Object holds a NamespaceMetadata
// Object for each namespace of the server: the one a NodeSet brings, or one
// the server creates in the namespace (a NodeNameSpace) at Start, and for a
// namespace added later when it is added. The NodeSet models supply what
// their Model element gives (Version, PublicationDate, ModelVersion,
// RolePermissions, AccessRestrictions; Part 6 §F.2). A namespace that is not
// a NodeNameSpace (MapNamespace) has none: "Clients should not assume that
// all namespaces provided by a Server are present in this list" (Part 5
// §6.3.14).
//
// "If not specified, the value of DefaultRolePermissions Property from the
// NamespaceMetadata Object associated with the Node shall be used instead"
// (Part 3 §5.2.9, and §4.9.3 for the evaluation): the RBACAccessController
// checks a node without RolePermissions against the DefaultRolePermissions
// of its namespace, and every service checks a node without
// AccessRestrictions against the DefaultAccessRestrictions (§5.2.11). The
// defaults come from SetNamespaceDefaults or from the Model of an imported
// NodeSet: "The list of default RolePermissions for all Nodes in the model"
// and "The default AccessRestrictions that apply to all Nodes in the model"
// (Part 6 §F.2 Table F.1), unless a node has HasNoPermissions (§F.3).
//
// Our choices, where the specification leaves one:
//
//   - A namespace without defaults keeps the behaviour of earlier versions:
//     a node without RolePermissions is allowed, one without
//     AccessRestrictions is not restricted. Part 3 §5.2.9 says only that the
//     server "should not publish any information about how it manages
//     Permissions" then.
//   - A node imported with HasNoPermissions is not checked against the
//     DefaultRolePermissions: the model's defaults do not apply to it
//     (Part 6 §F.3), and it is allowed as a node without RolePermissions was.
//   - The defaults set with SetNamespaceDefaults take the place of those of
//     a Model, whenever the NodeSet is imported.
//   - Reading the RolePermissions, UserRolePermissions or AccessRestrictions
//     Attribute of a node without its own still answers as before; the
//     defaults are read from the NamespaceMetadata Object.
//   - "The DefaultRolePermissions Property and RolePermissions Attribute
//     shall only be readable by administrators" (Part 3 §5.2.9): the server
//     gives the DefaultRolePermissions Property it fills RolePermissions that
//     let ConfigureAdmin and SecurityAdmin read it and the other well-known
//     roles browse it. Under the DefaultAccessController every session reads
//     it, as it reads every node.
//   - DefaultUserRolePermissions holds the DefaultRolePermissions; Read and
//     the monitored items reduce it to the roles of the session, as they do
//     for UserRolePermissions (Part 3 §5.2.9, §5.2.10).
//   - The nodes of a NamespaceMetadata Object the server creates, and the
//     Properties it adds to one, are not subject to the defaults of their
//     namespace: they have AccessRestrictions 0, and the
//     DefaultRolePermissions do not apply to them, so that a session learns
//     what protects the namespace.
//   - A NamespaceMetadata Object the server creates has the NodeId
//     s=NamespaceMetadata in its namespace and its Properties
//     s=NamespaceMetadata.<BrowseName> (numeric NodeIds in the namespace of
//     the session diagnostics, whose string NodeIds name sessions); IsNamespaceSubset is FALSE for a
//     namespace of the program and TRUE for one an import added without its
//     own NamespaceMetadata ("If the completeness is unknown, this Property
//     shall be set to TRUE", Part 5 §6.3.13); StaticNodeIdTypes and
//     StaticNumericNodeIdRange are empty and StaticStringNodeIdPattern null:
//     the server promises no static node. NamespaceFile and
//     ConfigurationVersion are not provided.

// NamespaceDefaults are the default permissions of the nodes of a namespace
// that have none of their own: the DefaultRolePermissions,
// DefaultUserRolePermissions and DefaultAccessRestrictions of its
// NamespaceMetadata Object (Part 3 §5.2.9 to §5.2.11, Part 5 §6.3.13).
type NamespaceDefaults struct {
	// RolePermissions are the DefaultRolePermissions. nil means the
	// namespace has none, and the RBACAccessController allows a node
	// without RolePermissions; a non-nil empty slice grants no role any
	// permission.
	RolePermissions []*ua.RolePermissionType
	// AccessRestrictions are the DefaultAccessRestrictions when
	// HasAccessRestrictions is set.
	AccessRestrictions    ua.AccessRestrictionType
	HasAccessRestrictions bool
}

// empty reports whether d has no default.
func (d NamespaceDefaults) empty() bool {
	return d.RolePermissions == nil && !d.HasAccessRestrictions
}

// clone returns a copy of d that shares nothing with it.
func (d NamespaceDefaults) clone() NamespaceDefaults {
	c := d
	if d.RolePermissions != nil {
		c.RolePermissions = make([]*ua.RolePermissionType, 0, len(d.RolePermissions))
		for _, rp := range d.RolePermissions {
			if rp == nil {
				continue
			}
			cp := *rp
			c.RolePermissions = append(c.RolePermissions, &cp)
		}
	}
	return c
}

// nsDefaults are the defaults of one namespace.
type nsDefaults struct {
	NamespaceDefaults
	// fromModel: from the Model of a NodeSet, which SetNamespaceDefaults
	// replaces and a later import may replace too.
	fromModel bool
}

// namespaceMeta is the state of the NamespaceMetadata Objects and of the
// namespace defaults of a server.
type namespaceMeta struct {
	// mu serializes the changes of the defaults and the building of the
	// NamespaceMetadata Objects.
	mu sync.Mutex
	// defaults are the defaults by namespace index: a map that is
	// replaced, never changed, so that access checks read it without a
	// lock.
	defaults atomic.Pointer[map[uint16]*nsDefaults]
	// imported marks the namespaces an import added. Guarded by mu.
	imported map[uint16]bool
	// started is set by Start: namespaces added from then on get their
	// NamespaceMetadata Object when they are added.
	started atomic.Bool
	// versionMu serializes the NodeVersion increments (model_change.go).
	versionMu sync.Mutex
}

// WithModelDefaultPermissions sets whether the RolePermissions and the
// AccessRestrictions of the Model of an imported NodeSet become the
// DefaultRolePermissions and DefaultAccessRestrictions of its namespace
// (Part 6 §F.2, §F.3), which apply to its nodes without their own. It is on
// by default. WithModelDefaultPermissions(false) restores the behaviour of
// v1.42 and earlier, which ignored them; the defaults set with
// [Server.SetNamespaceDefaults] apply either way.
func WithModelDefaultPermissions(enabled bool) Option {
	return func(s *serverConfig) error {
		s.addrSpace.modelDefaultsOff = !enabled
		return nil
	}
}

// SetNamespaceDefaults sets the default permissions of the namespace with
// the URI namespaceURI: the DefaultRolePermissions,
// DefaultUserRolePermissions and DefaultAccessRestrictions Properties of its
// NamespaceMetadata Object, which apply to the nodes of the namespace that
// have no RolePermissions or AccessRestrictions of their own (Part 3
// §4.9.3, §5.2.9, §5.2.11). The RolePermissions take effect under the
// [RBACAccessController]; the AccessRestrictions under every
// AccessController. A zero NamespaceDefaults removes the defaults. It
// replaces the defaults of an imported NodeSet Model. It returns an error
// when the server has no such namespace.
func (s *Server) SetNamespaceDefaults(namespaceURI string, d NamespaceDefaults) error {
	idx, ok := s.namespaceLookup(namespaceURI)
	if !ok {
		return fmt.Errorf("server: no namespace %q", namespaceURI)
	}
	s.nsMeta.mu.Lock()
	defer s.nsMeta.mu.Unlock()
	s.storeDefaults(idx, d.clone(), false)
	s.publishNamespaceMetadata(idx, nil)
	return nil
}

// NamespaceDefaults returns the default permissions of the namespace with
// the URI namespaceURI, false when it has none.
func (s *Server) NamespaceDefaults(namespaceURI string) (NamespaceDefaults, bool) {
	idx, ok := s.namespaceLookup(namespaceURI)
	if !ok {
		return NamespaceDefaults{}, false
	}
	d := s.namespaceDefaults(idx)
	if d == nil {
		return NamespaceDefaults{}, false
	}
	return d.clone(), true
}

// storeDefaults sets the defaults of the namespace idx. nsMeta.mu must be
// held.
func (s *Server) storeDefaults(idx uint16, d NamespaceDefaults, fromModel bool) {
	m := map[uint16]*nsDefaults{}
	if cur := s.nsMeta.defaults.Load(); cur != nil {
		for k, v := range *cur {
			m[k] = v
		}
	}
	if fromModel {
		if cur := m[idx]; cur != nil && !cur.fromModel {
			return // SetNamespaceDefaults decided
		}
	}
	if d.empty() {
		delete(m, idx)
	} else {
		m[idx] = &nsDefaults{NamespaceDefaults: d, fromModel: fromModel}
	}
	s.nsMeta.defaults.Store(&m)
}

// namespaceDefaults returns the defaults of the namespace idx, nil if it has
// none.
func (s *Server) namespaceDefaults(idx uint16) *nsDefaults {
	if s == nil {
		return nil
	}
	m := s.nsMeta.defaults.Load()
	if m == nil {
		return nil
	}
	return (*m)[idx]
}

// effectiveRolePermissions returns the RolePermissions that decide the
// access to n: its own or, when it has none, the DefaultRolePermissions of
// its namespace (Part 3 §4.9.3). ok is false when there are neither.
func (s *Server) effectiveRolePermissions(n *Node) (perms []*ua.RolePermissionType, ok bool) {
	n.mu.RLock()
	perms, exempt := n.rolePermissions, n.noDefaultPermissions
	n.mu.RUnlock()
	if len(perms) > 0 {
		return perms, true
	}
	if exempt {
		return nil, false
	}
	d := s.namespaceDefaults(n.ID().Namespace())
	if d == nil || d.RolePermissions == nil {
		return nil, false
	}
	return d.RolePermissions, true
}

// effectiveAccessRestrictions returns the AccessRestrictions of n: its own
// or, when it has none, the DefaultAccessRestrictions of its namespace
// (Part 3 §5.2.11).
func effectiveAccessRestrictions(n *Node) ua.AccessRestrictionType {
	n.mu.RLock()
	av, err := n.attribute(ua.AttributeIDAccessRestrictions)
	inherit := n.inheritRestrictions
	n.mu.RUnlock()
	own := err == nil && av != nil && av.Value != nil && av.Value.Value != nil
	if own && !inherit {
		r, _ := av.Value.Value.Value().(uint16)
		return ua.AccessRestrictionType(r)
	}
	if d := n.server().namespaceDefaults(n.ID().Namespace()); d != nil && d.HasAccessRestrictions {
		return d.AccessRestrictions
	}
	if own {
		r, _ := av.Value.Value.Value().(uint16)
		return ua.AccessRestrictionType(r)
	}
	return ua.AccessRestrictionTypeNone
}

// importPermissionFlags records on n, a node of a NodeSet, whether the
// defaults of its namespace apply to it (Part 6 §F.3).
func importPermissionFlags(n *Node, x *nodeset.Node) {
	n.noDefaultPermissions = x.HasNoPermissions
	n.inheritRestrictions = !x.HasAccessRestrictions
}

// importRoles converts the RolePermissions of a NodeSet. The role is a
// NodeId ("i=15704", "ns=1;i=1661"), as a NodeSet writes it, or the name of
// a well-known role; others are left out.
func importRoles(rp []nodeset.RolePermission) []*ua.RolePermissionType {
	var perms []*ua.RolePermissionType
	for _, p := range rp {
		var roleID *ua.NodeID
		if role, ok := ua.RoleByName[p.Role]; ok {
			roleID = role.NodeID()
		} else if v := strings.TrimSpace(p.Role); strings.Contains(v, "=") {
			n, err := ua.ParseNodeID(v)
			if err != nil {
				continue
			}
			roleID = n
		} else {
			continue
		}
		perms = append(perms, &ua.RolePermissionType{
			RoleID:      roleID,
			Permissions: ua.PermissionType(p.Permissions),
		})
	}
	return perms
}

// importModels takes the defaults of the Models of an imported NodeSet and
// fills the NamespaceMetadata Objects of their namespaces.
func (s *Server) importModels(models []nodeset.Model) {
	s.nsMeta.mu.Lock()
	defer s.nsMeta.mu.Unlock()
	for i := range models {
		m := &models[i]
		idx, ok := s.namespaceLookup(m.ModelURI)
		if !ok {
			continue
		}
		if !s.cfg.addrSpace.modelDefaultsOff && (len(m.RolePermissions) > 0 || m.HasAccessRestrictions) {
			d := NamespaceDefaults{AccessRestrictions: ua.AccessRestrictionType(m.AccessRestrictions), HasAccessRestrictions: m.HasAccessRestrictions}
			if len(m.RolePermissions) > 0 {
				d.RolePermissions = importRoles(m.RolePermissions)
				if d.RolePermissions == nil {
					d.RolePermissions = []*ua.RolePermissionType{}
				}
			}
			s.storeDefaults(idx, d, true)
		}
		s.publishNamespaceMetadata(idx, m)
	}
	if s.nsMeta.started.Load() {
		s.publishAllNamespaceMetadata()
	}
}

// markImported records that an import added the namespace idx.
func (s *Server) markImported(idx uint16) {
	s.nsMeta.mu.Lock()
	defer s.nsMeta.mu.Unlock()
	if s.nsMeta.imported == nil {
		s.nsMeta.imported = map[uint16]bool{}
	}
	s.nsMeta.imported[idx] = true
}

// startNamespaceMetadata gives every namespace its NamespaceMetadata
// Object; from then on a namespace gets one when it is added. Start calls
// it.
func (s *Server) startNamespaceMetadata() {
	s.nsMeta.mu.Lock()
	defer s.nsMeta.mu.Unlock()
	s.nsMeta.started.Store(true)
	s.publishAllNamespaceMetadata()
}

// namespaceAdded gives the namespace idx, which the program added, its
// NamespaceMetadata Object once the server has started.
func (s *Server) namespaceAdded(idx uint16) {
	if s == nil || !s.nsMeta.started.Load() {
		return
	}
	s.nsMeta.mu.Lock()
	defer s.nsMeta.mu.Unlock()
	s.publishNamespaceMetadata(idx, nil)
}

// publishAllNamespaceMetadata publishes the NamespaceMetadata Object of
// every namespace. nsMeta.mu must be held.
func (s *Server) publishAllNamespaceMetadata() {
	for i := range s.Namespaces() {
		s.publishNamespaceMetadata(uint16(i), nil) // a server has at most maxNamespaces
	}
}

// metadataProperty describes a Property of NamespaceMetadataType (Part 5
// §6.3.13 Table 22).
type metadataProperty struct {
	name      string
	dataType  uint32
	valueRank int32
}

var (
	propNamespaceURI         = metadataProperty{"NamespaceUri", id.String, -1}
	propNamespaceVersion     = metadataProperty{"NamespaceVersion", id.String, -1}
	propPublicationDate      = metadataProperty{"NamespacePublicationDate", id.DateTime, -1}
	propIsNamespaceSubset    = metadataProperty{"IsNamespaceSubset", id.Boolean, -1}
	propStaticNodeIDTypes    = metadataProperty{"StaticNodeIdTypes", id.IDType, 1}
	propStaticNumericRange   = metadataProperty{"StaticNumericNodeIdRange", id.NumericRange, 1}
	propStaticStringPattern  = metadataProperty{"StaticStringNodeIdPattern", id.String, -1}
	propDefaultRolePerms     = metadataProperty{"DefaultRolePermissions", id.RolePermissionType, 1}
	propDefaultUserRolePerms = metadataProperty{"DefaultUserRolePermissions", id.RolePermissionType, 1}
	propDefaultRestrictions  = metadataProperty{"DefaultAccessRestrictions", id.AccessRestrictionType, -1}
	propModelVersion         = metadataProperty{"ModelVersion", id.SemanticVersionString, -1}
)

// publishNamespaceMetadata finds or creates the NamespaceMetadata Object of
// the namespace idx and fills it: the mandatory Properties it lacks, the
// values of the Model m (nil for none) it lacks, and the defaults of the
// namespace. nsMeta.mu must be held.
func (s *Server) publishNamespaceMetadata(idx uint16, m *nodeset.Model) {
	ns, err := s.Namespace(int(idx))
	if err != nil {
		return
	}
	uri := ns.Name()
	obj := s.namespaceMetadataNode(uri)
	if obj == nil {
		obj = s.createNamespaceMetadata(ns)
		if obj == nil {
			return
		}
	}
	var version, modelVersion string
	var published time.Time
	if m != nil {
		version, modelVersion = m.Version, m.ModelVersion
		if t, err := time.Parse(time.RFC3339, m.PublicationDate); err == nil {
			published = t
		}
	}
	s.fillMetadata(obj, propNamespaceURI, uri)
	s.fillMetadata(obj, propNamespaceVersion, version)
	s.fillMetadata(obj, propPublicationDate, published)
	s.fillMetadata(obj, propIsNamespaceSubset, idx != 0 && s.nsMeta.imported[idx])
	s.fillMetadata(obj, propStaticNodeIDTypes, []int32{})
	s.fillMetadata(obj, propStaticNumericRange, []string{})
	s.fillMetadata(obj, propStaticStringPattern, "")
	if modelVersion != "" {
		s.fillMetadata(obj, propModelVersion, modelVersion)
	}
	s.publishDefaults(obj, s.namespaceDefaults(idx))
}

// namespaceMetadataNode returns the NamespaceMetadata Object of the
// namespace uri among the components of the Namespaces Object: the one
// whose NamespaceUri is uri or, without that Property, whose BrowseName is.
func (s *Server) namespaceMetadataNode(uri string) *Node {
	nsObj := s.Node(ua.NewNumericNodeID(0, id.ServerNamespaces))
	if nsObj == nil {
		return nil
	}
	var byName *Node
	for _, r := range nsObj.refsSnapshot() {
		if r == nil || !r.IsForward || r.ReferenceTypeID == nil || r.ReferenceTypeID.Namespace() != 0 ||
			r.ReferenceTypeID.IntID() != id.HasComponent || r.NodeID == nil || r.NodeID.ServerIndex != 0 {
			continue
		}
		t := s.Node(r.NodeID.NodeID)
		if t == nil {
			continue
		}
		if p := t.property(propNamespaceURI.name); p != nil {
			if dv := p.Value(); dv != nil && dv.Value != nil {
				if v, _ := dv.Value.Value().(string); v == uri {
					return t
				}
				continue
			}
		}
		if byName == nil && t.BrowseName().Name == uri {
			byName = t
		}
	}
	return byName
}

// property returns the Property of n with the BrowseName 0:name, nil if
// there is none.
func (n *Node) property(name string) *Node {
	for _, r := range n.refsSnapshot() {
		if r == nil || !r.IsForward || r.ReferenceTypeID == nil || r.ReferenceTypeID.Namespace() != 0 ||
			r.ReferenceTypeID.IntID() != id.HasProperty || r.BrowseName == nil || r.BrowseName.Name != name ||
			r.BrowseName.NamespaceIndex != 0 || r.NodeID == nil || r.NodeID.ServerIndex != 0 {
			continue
		}
		return n.lookup(r.NodeID.NodeID)
	}
	return nil
}

// createNamespaceMetadata creates the NamespaceMetadata Object of the
// namespace ns in ns, nil if ns is not a NodeNameSpace or the NodeId is
// taken.
func (s *Server) createNamespaceMetadata(ns NameSpace) *Node {
	nns, ok := ns.(*NodeNameSpace)
	nsObj := s.Node(ua.NewNumericNodeID(0, id.ServerNamespaces))
	typ := s.Node(ua.NewNumericNodeID(0, id.NamespaceMetadataType))
	if !ok || nns.ID() == 0 || nsObj == nil || typ == nil {
		return nil
	}
	nid := ua.NewStringNodeID(nns.ID(), "NamespaceMetadata")
	if nns.Name() == DiagnosticsNamespaceURI {
		// A string NodeId of the diagnostics namespace names a node of a
		// session (diagnosticsOwner), which only that session and the
		// administrators may use: the Object and its Properties get
		// numeric NodeIds there.
		nid = ua.NewNumericNodeID(nns.ID(), nns.GetNextNodeID())
	}
	if nns.Node(nid) != nil {
		s.cfg.logger.Warn("server: the NodeId of the NamespaceMetadata Object is taken", "node_id", nid)
		return nil
	}
	obj := NewNode(nid, Attributes{
		ua.AttributeIDNodeClass:          DataValueFromValue(uint32(ua.NodeClassObject)),
		ua.AttributeIDBrowseName:         DataValueFromValue(&ua.QualifiedName{NamespaceIndex: nns.ID(), Name: nns.Name()}),
		ua.AttributeIDDisplayName:        DataValueFromValue(attrs.DisplayName(nns.Name(), nns.Name())),
		ua.AttributeIDEventNotifier:      DataValueFromValue(byte(0)),
		ua.AttributeIDAccessRestrictions: DataValueFromValue(uint16(0)),
	}, nil, nil)
	obj.noDefaultPermissions = true
	nns.addNode(obj)
	obj.addRef(typ, ua.NewNumericNodeID(0, id.HasTypeDefinition), true)
	nsObj.addRef(obj, ua.NewNumericNodeID(0, id.HasComponent), true)
	return obj
}

// fillMetadata gives the Property p of obj the value v unless it has a
// value, creating the Property when obj has none.
func (s *Server) fillMetadata(obj *Node, p metadataProperty, v any) {
	prop := obj.property(p.name)
	if prop == nil {
		prop = s.addMetadataProperty(obj, p)
		if prop == nil {
			return
		}
	} else if hasValue(prop) {
		return
	}
	setPropertyValue(prop, v)
}

// hasValue reports whether the Value of prop is not null.
func hasValue(prop *Node) bool {
	dv := prop.Value()
	return dv != nil && dv.Value != nil && dv.Value.Value() != nil
}

// setPropertyValue sets the Value of prop, whatever the type of its value.
func setPropertyValue(prop *Node, v any) {
	dv := &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)}
	prop.SetValueFunc(func() *ua.DataValue { return dv })
}

// addMetadataProperty adds the Property p to obj, in the namespace of obj,
// with the NodeId s=<the string NodeId of obj>.<name> or, for an obj with
// another NodeId, a numeric one. It returns nil if obj is not in a
// NodeNameSpace.
func (s *Server) addMetadataProperty(obj *Node, p metadataProperty) *Node {
	nns, ok := obj.ns.(*NodeNameSpace)
	if !ok {
		return nil
	}
	var nid *ua.NodeID
	if obj.ID().Type() == ua.NodeIDTypeString {
		nid = ua.NewStringNodeID(nns.ID(), obj.ID().StringID()+"."+p.name)
	}
	for nid == nil || nns.Node(nid) != nil {
		nid = ua.NewNumericNodeID(nns.ID(), nns.GetNextNodeID())
	}
	a := Attributes{
		ua.AttributeIDNodeClass:       DataValueFromValue(uint32(ua.NodeClassVariable)),
		ua.AttributeIDBrowseName:      DataValueFromValue(&ua.QualifiedName{Name: p.name}),
		ua.AttributeIDDisplayName:     DataValueFromValue(attrs.DisplayName(p.name, p.name)),
		ua.AttributeIDDataType:        DataValueFromValue(ua.NewNumericExpandedNodeID(0, p.dataType)),
		ua.AttributeIDValueRank:       DataValueFromValue(p.valueRank),
		ua.AttributeIDAccessLevel:     DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead)),
		ua.AttributeIDUserAccessLevel: DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead)),
		// The NamespaceMetadata tells how the namespace is protected; the
		// defaults of the namespace do not protect it.
		ua.AttributeIDAccessRestrictions: DataValueFromValue(uint16(0)),
	}
	if p.valueRank == 1 {
		a[ua.AttributeIDArrayDimensions] = DataValueFromValue([]uint32{0})
	}
	prop := NewNode(nid, a, nil, nil)
	prop.noDefaultPermissions = true
	nns.addNode(prop)
	if pt := s.Node(ua.NewNumericNodeID(0, id.PropertyType)); pt != nil {
		prop.addRef(pt, ua.NewNumericNodeID(0, id.HasTypeDefinition), true)
	}
	obj.addRef(prop, ua.NewNumericNodeID(0, id.HasProperty), true)
	return prop
}

// adminReadPermissions are the RolePermissions of a DefaultRolePermissions
// Property the server fills: "shall only be readable by administrators"
// (Part 3 §5.2.9). ConfigureAdmin and SecurityAdmin read it; the other
// well-known roles browse it.
func adminReadPermissions() []*ua.RolePermissionType {
	admin := ua.PermissionTypeBrowse | ua.PermissionTypeReadRolePermissions | ua.PermissionTypeRead
	perms := []*ua.RolePermissionType{
		{RoleID: ua.RoleConfigureAdmin.NodeID(), Permissions: admin},
		{RoleID: ua.RoleSecurityAdmin.NodeID(), Permissions: admin},
	}
	for _, r := range []ua.WellKnownRole{ua.RoleAnonymous, ua.RoleAuthenticatedUser, ua.RoleObserver, ua.RoleOperator, ua.RoleEngineer, ua.RoleSupervisor} {
		perms = append(perms, &ua.RolePermissionType{RoleID: r.NodeID(), Permissions: ua.PermissionTypeBrowse})
	}
	return perms
}

// publishDefaults sets the DefaultRolePermissions,
// DefaultUserRolePermissions and DefaultAccessRestrictions of obj from d:
// Properties for the defaults the namespace has, without a value for those
// it has not.
func (s *Server) publishDefaults(obj *Node, d *nsDefaults) {
	var rp []*ua.RolePermissionType
	hasRP, hasAR := false, false
	var ar ua.AccessRestrictionType
	if d != nil {
		rp, hasRP = d.RolePermissions, d.RolePermissions != nil
		ar, hasAR = d.AccessRestrictions, d.HasAccessRestrictions
	}
	eos := make([]*ua.ExtensionObject, 0, len(rp))
	for _, p := range rp {
		eos = append(eos, ua.NewExtensionObject(p))
	}
	s.setDefault(obj, propDefaultRolePerms, hasRP, eos, func(p *Node) {
		p.mu.Lock()
		p.rolePermissions = adminReadPermissions()
		p.mu.Unlock()
	})
	s.setDefault(obj, propDefaultUserRolePerms, hasRP, slices.Clone(eos), func(p *Node) {
		p.mu.Lock()
		p.sessionRoles = true
		p.mu.Unlock()
	})
	s.setDefault(obj, propDefaultRestrictions, hasAR, uint16(ar), nil)
}

// setDefault sets the Property p of obj to v when has is set, creating it
// if needed and calling prepare on it; without has it removes the value of
// an existing Property.
func (s *Server) setDefault(obj *Node, p metadataProperty, has bool, v any, prepare func(*Node)) {
	prop := obj.property(p.name)
	if !has {
		if prop != nil && hasValue(prop) {
			prop.SetValueFunc(nil)
			s.ChangeNotification(prop.ID())
		}
		return
	}
	if prop == nil {
		if prop = s.addMetadataProperty(obj, p); prop == nil {
			return
		}
	}
	if prepare != nil {
		prepare(prop)
	}
	setPropertyValue(prop, v)
	s.ChangeNotification(prop.ID())
}
