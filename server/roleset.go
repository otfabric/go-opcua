// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"slices"
	"strconv"
	"sync"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
)

// The managed RoleSet of OPC 10000-18 (Role-Based Security, v1.05.06).
//
// With [WithRoleManagement] the server keeps the configuration of its roles
// in memory and serves it through the RoleSet Object of namespace 0
// (Server.ServerCapabilities.RoleSet, §4.3): the Properties Identities,
// Applications, ApplicationsExclude, Endpoints, EndpointsExclude and
// CustomConfiguration of each role (§4.4.1), the Methods AddRole and
// RemoveRole of the RoleSet (§4.2.2, §4.2.3) and AddIdentity,
// RemoveIdentity, AddApplication, RemoveApplication, AddEndpoint and
// RemoveEndpoint of the roles (§4.4.5 to §4.4.10). The application reaches
// the same configuration with [Server.RoleSet].
//
// At ActivateSession a session gets the roles of the RoleMapper
// ([WithRoleMapper], [DefaultRoleMapper] without one) and then every role of
// the RoleSet whose Identities, Applications and Endpoints it complies with
// (§4.4.1): the union, the roles of the RoleMapper first, each role once.
// When the configuration of a role changes, the roles of the active
// sessions are evaluated again (§4.4.1: "the Role assignment to active
// Session shall be re-evaluated and applied"); the roles of the RoleMapper
// are those of the last activation, as the RoleMapper is not called again.
//
// Without WithRoleManagement nothing of this applies: the roles come from
// the RoleMapper alone, the Methods are not served (Bad_MethodInvalid) and
// the Properties have the values of the NodeSet, as in v1.42 and earlier.
//
// The library's choices, where the specification leaves one:
//
//   - The roles of namespace 0 cannot be removed (Bad_RequestNotAllowed):
//     §4.3 forbids it for Anonymous, AuthenticatedUser and
//     TrustedApplication, and §4.2.3 lets a server keep the roles it needs;
//     AddRole of a well-known role therefore always finds it
//     (Bad_AlreadyExists). The three roles of §4.3 cannot be changed
//     either; their Identities are the defaults of §4.3. Their Objects in
//     the NodeSet of namespace 0 have no Methods (a Call is
//     Bad_MethodInvalid) and no Exclude Properties; the [RoleSet] methods
//     refuse a change of them with Bad_RequestNotAllowed.
//   - AddRole puts the role Objects in the namespace [RolesNamespaceURI],
//     which the server adds at the first AddRole, with the String NodeId
//     "<namespace index of the BrowseName>:<RoleName>". An empty
//     NamespaceUri qualifies the BrowseName with that namespace; any other
//     NamespaceUri has to be in the NamespaceArray (Bad_InvalidArgument).
//     An application that registered RolesNamespaceURI itself with a
//     NameSpace other than a NodeNameSpace gets Bad_NotSupported.
//   - The defaults of §4.3 apply as written: the Identities of Anonymous
//     are Anonymous and AuthenticatedUser, so every session has the role
//     Anonymous, an authenticated one AuthenticatedUser as well.
//   - RemoveRole deletes the RolePermissions of the role from every node
//     and from the DefaultRolePermissions of every namespace (§4.2.3).
//   - An Anonymous rule is refused (Bad_RequestNotAllowed) for SecurityAdmin,
//     ConfigureAdmin and SecurityKeyServerAdmin, the roles with
//     administrator rights (§4.4.1).
//   - A Client Certificate is trusted when the server validates client
//     certificates ([WithClientCertificateTrustList],
//     [WithClientCertificateValidator] or [WithPushManagement]) and the
//     session uses a signed channel; without a validator the server accepts
//     every certificate, so none is trusted. The Applications and the
//     Application rules use the ApplicationUri of the certificate (its URI
//     subjectAltName, Part 6 §6.2.2).
//   - The Endpoint of a session is the configured EndpointDescription with
//     the endpointUrl of CreateSession (compared as GetEndpoints compares
//     it) and the SecurityPolicy and SecurityMode of the channel. A session
//     whose endpointUrl names no configured Endpoint has none: a role with
//     Endpoints is not granted to it, in include or exclude mode.
//   - A Thumbprint is the SHA-1 of the DER encoded user certificate (Part 6
//     §3.1.1: SHA1 "in contexts where no SecurityPolicy applies").
//   - The Role and GroupId rules apply to issued tokens of a server whose
//     IssuedToken policy is [IssuedTokenTypeJWT] (WithIssuedTokenPolicy);
//     the server reads the roles, groups and iss claims of the JWT the
//     IssuedTokenValidator accepted (Part 6 §6.5.2.3). Without JWTs they are
//     refused with Bad_NotSupported.
//   - With auditing on, a change of a role reports a
//     RoleMappingRuleChangedAuditEventType event (§4.5), and AddRole,
//     RemoveRole and refused calls an AuditUpdateMethodEventType event.
//   - The configuration lives in memory: it starts from the defaults of
//     §4.3 with each New and is lost when the process ends.

// RolesNamespaceURI is the namespace of the role Objects that AddRole adds.
// The server adds it to the NamespaceArray at the first AddRole of a role
// outside namespace 0.
const RolesNamespaceURI = "urn:otfabric:go-opcua:roles"

const (
	// DefaultMaxRoles is the number of roles AddRole may add when
	// RoleManagement.MaxRoles is zero.
	DefaultMaxRoles = 64
	// DefaultMaxRoleEntries is the number of Identities, Applications and
	// Endpoints, each, of a role when RoleManagement.MaxEntries is zero.
	DefaultMaxRoleEntries = 256
	// maxRoleText is the longest RoleName, criteria, ApplicationUri and
	// EndpointUrl taken, in bytes.
	maxRoleText = 4096
)

// RoleManagement configures the managed RoleSet ([WithRoleManagement]).
type RoleManagement struct {
	// MaxRoles is the most roles AddRole adds besides those of namespace 0;
	// past it AddRole returns Bad_NotSupported, "the Server does not allow
	// more Roles to be added" (OPC 10000-18 §4.2.2). Zero is
	// DefaultMaxRoles.
	MaxRoles int
	// MaxEntries is the most Identities, Applications and Endpoints, each,
	// of one role; past it the Add Methods return Bad_ResourceUnavailable.
	// Zero is DefaultMaxRoleEntries.
	MaxEntries int
	// Authorizer, when set, decides who may change the roles in place of
	// the SecurityAdmin role (OPC 10000-18 §4.2.2: "user credentials with
	// administrator rights like SecurityAdmin Role"). It gets the caller
	// and the BrowseName of the Method, or "ApplicationsExclude" or
	// "EndpointsExclude" for a Write of those Properties, and returns
	// StatusOK to allow it. The encrypted channel is checked before it.
	Authorizer func(ctx context.Context, caller *MethodCaller, method string) ua.StatusCode
}

// WithRoleManagement serves the RoleSet of OPC 10000-18 and grants the
// sessions the roles whose rules they comply with, in addition to the roles
// of the RoleMapper (see [RoleSet]). Without it the roles come from the
// RoleMapper alone and the RoleSet Methods are not served, as in v1.42 and
// earlier.
func WithRoleManagement(cfg RoleManagement) Option {
	return func(s *serverConfig) error {
		c := cfg
		s.roleMgmt = &c
		return nil
	}
}

// Role is the configuration of a role of the RoleSet (OPC 10000-18 §4.4.1).
type Role struct {
	// NodeID is the NodeId of the role Object, BrowseName its BrowseName.
	NodeID     *ua.NodeID
	BrowseName *ua.QualifiedName
	// Identities are the rules that map a UserIdentityToken to the role.
	Identities []*ua.IdentityMappingRuleType
	// Applications are ApplicationUris; ApplicationsExclude makes them an
	// exclude list.
	Applications        []string
	ApplicationsExclude bool
	// Endpoints are Endpoints; EndpointsExclude makes them an exclude list.
	Endpoints        []*ua.EndpointType
	EndpointsExclude bool
	// Fixed reports a role whose configuration cannot be changed
	// (Anonymous, AuthenticatedUser and TrustedApplication, §4.3).
	Fixed bool
	// Removable reports a role RemoveRole may remove: one AddRole added.
	Removable bool
}

// RoleSet is the managed RoleSet of a server ([WithRoleManagement]): the
// application's access to the configuration the RoleSet Methods change.
// Its methods return a ua.StatusCode as error, the result the Method would
// have: Bad_NodeIdUnknown for a role that does not exist,
// Bad_InvalidArgument, Bad_AlreadyExists, Bad_NotFound,
// Bad_RequestNotAllowed, Bad_NotSupported or Bad_ResourceUnavailable.
// They need no session and no SecurityAdmin role: the application is the
// server.
type RoleSet struct {
	s          *Server
	maxRoles   int
	maxEntries int
	authorizer func(ctx context.Context, caller *MethodCaller, method string) ua.StatusCode

	// opMu serializes the changes, which add and delete nodes; mu guards
	// roles, which the Properties read. opMu is taken before mu, and
	// before the rolesMu of a session no lock of the RoleSet is held.
	opMu  sync.Mutex
	mu    sync.RWMutex
	roles []*managedRole
	// ns is the namespace of the roles AddRole adds, nil before the first.
	ns *NodeNameSpace
}

// managedRole is a role of the RoleSet. The slices are replaced, never
// changed in place, so a reader may keep them.
type managedRole struct {
	id         *ua.NodeID
	browseName *ua.QualifiedName
	fixed      bool
	removable  bool
	// admin marks a role with administrator rights: no Anonymous rule.
	admin bool

	identities   []*ua.IdentityMappingRuleType
	applications []string
	appsExclude  bool
	endpoints    []*ua.EndpointType
	epExclude    bool

	// props are the Properties whose values the role serves, for
	// ChangeNotification; nodes are all the nodes AddRole added.
	props []*ua.NodeID
	nodes []*ua.NodeID
}

func (r *managedRole) snapshot() Role {
	return Role{
		NodeID:              r.id,
		BrowseName:          r.browseName,
		Identities:          cloneRules(r.identities),
		Applications:        slices.Clone(r.applications),
		ApplicationsExclude: r.appsExclude,
		Endpoints:           cloneEndpoints(r.endpoints),
		EndpointsExclude:    r.epExclude,
		Fixed:               r.fixed,
		Removable:           r.removable,
	}
}

func cloneRules(xs []*ua.IdentityMappingRuleType) []*ua.IdentityMappingRuleType {
	out := make([]*ua.IdentityMappingRuleType, len(xs))
	for i, x := range xs {
		c := *x
		out[i] = &c
	}
	return out
}

func cloneEndpoints(xs []*ua.EndpointType) []*ua.EndpointType {
	out := make([]*ua.EndpointType, len(xs))
	for i, x := range xs {
		c := *x
		out[i] = &c
	}
	return out
}

// RoleSet returns the managed RoleSet, nil without [WithRoleManagement].
func (s *Server) RoleSet() *RoleSet { return s.roleSet }

// Roles returns the roles of the RoleSet, in the order of the RoleSet.
func (rs *RoleSet) Roles() []Role {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	out := make([]Role, len(rs.roles))
	for i, r := range rs.roles {
		out[i] = r.snapshot()
	}
	return out
}

// Role returns the role with the NodeId id; false if there is none.
func (rs *RoleSet) Role(id *ua.NodeID) (Role, bool) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	if r := rs.findLocked(id); r != nil {
		return r.snapshot(), true
	}
	return Role{}, false
}

func (rs *RoleSet) findLocked(id *ua.NodeID) *managedRole {
	if id == nil {
		return nil
	}
	for _, r := range rs.roles {
		if r.id.Equal(id) {
			return r
		}
	}
	return nil
}

// The NodeIds of namespace 0 the RoleSet uses.
var (
	roleSetNodeID       = ua.NewNumericNodeID(0, id.ServerServerCapabilitiesRoleSet)
	roleSetAddRoleID    = ua.NewNumericNodeID(0, id.ServerServerCapabilitiesRoleSetAddRole)
	roleSetRemoveRoleID = ua.NewNumericNodeID(0, id.ServerServerCapabilitiesRoleSetRemoveRole)
)

// The BrowseNames of the Properties and Methods of RoleType (§4.4.1).
const (
	propIdentities          = "Identities"
	propApplications        = "Applications"
	propApplicationsExclude = "ApplicationsExclude"
	propEndpoints           = "Endpoints"
	propEndpointsExclude    = "EndpointsExclude"
	propCustomConfiguration = "CustomConfiguration"
)

// bindRoleSet builds the managed RoleSet from the role Objects of the
// RoleSet of namespace 0 (WithRoleManagement).
func (s *Server) bindRoleSet() {
	cfg := s.cfg.roleMgmt
	if cfg == nil || s.Node(roleSetNodeID) == nil {
		return
	}
	rs := &RoleSet{s: s, maxRoles: cfg.MaxRoles, maxEntries: cfg.MaxEntries, authorizer: cfg.Authorizer}
	if rs.maxRoles <= 0 {
		rs.maxRoles = DefaultMaxRoles
	}
	if rs.maxEntries <= 0 {
		rs.maxEntries = DefaultMaxRoleEntries
	}
	set := s.ownNode(id.ServerServerCapabilitiesRoleSet)
	for _, ref := range set.refsSnapshot() {
		if !isForwardRef(ref, id.HasComponent) {
			continue
		}
		n := s.Node(ref.NodeID.NodeID)
		if n == nil || n.NodeClass() != ua.NodeClassObject || !s.isRoleObject(n) {
			continue
		}
		r := newWellKnownRole(n)
		rs.roles = append(rs.roles, r)
		rs.bindRole(r, n)
	}
	s.RegisterMethod(roleSetNodeID, roleSetAddRoleID, rs.handler("AddRole", rs.callAddRole))
	s.RegisterMethod(roleSetNodeID, roleSetRemoveRoleID, rs.handler("RemoveRole", rs.callRemoveRole))
	s.roleSet = rs
}

// isRoleObject reports whether n is an Object of RoleType or a subtype.
func (s *Server) isRoleObject(n *Node) bool {
	seen := map[string]bool{}
	for t := nodeTypeDefinition(n); t != nil && !seen[t.String()]; t = s.superType(t) {
		if t.Namespace() == 0 && t.IntID() == id.RoleType {
			return true
		}
		seen[t.String()] = true
	}
	return false
}

func isForwardRef(ref *ua.ReferenceDescription, refType uint32) bool {
	return ref != nil && ref.IsForward && ref.ReferenceTypeID != nil && ref.ReferenceTypeID.Namespace() == 0 &&
		ref.ReferenceTypeID.IntID() == refType && ref.NodeID != nil && ref.NodeID.NodeID != nil && ref.NodeID.ServerIndex == 0
}

// newWellKnownRole is the managed role of a role Object of namespace 0 with
// the defaults of §4.3: the Identities of Anonymous, AuthenticatedUser and
// TrustedApplication, which cannot be changed, and no Identities for the
// others. ApplicationsExclude and EndpointsExclude are TRUE, "the default
// value ... if the Applications Property has an empty array" (§4.4.1).
func newWellKnownRole(n *Node) *managedRole {
	r := &managedRole{id: n.ID(), browseName: n.BrowseName(), appsExclude: true, epExclude: true}
	if r.id.Namespace() != 0 {
		return r
	}
	rule := func(t ua.IdentityCriteriaType) *ua.IdentityMappingRuleType {
		return &ua.IdentityMappingRuleType{CriteriaType: t}
	}
	switch r.id.IntID() {
	case id.WellKnownRoleAnonymous:
		r.fixed = true
		r.identities = []*ua.IdentityMappingRuleType{rule(ua.IdentityCriteriaTypeAnonymous), rule(ua.IdentityCriteriaTypeAuthenticatedUser)}
	case id.WellKnownRoleAuthenticatedUser:
		r.fixed = true
		r.identities = []*ua.IdentityMappingRuleType{rule(ua.IdentityCriteriaTypeAuthenticatedUser)}
	case id.WellKnownRoleTrustedApplication:
		r.fixed = true
		r.identities = []*ua.IdentityMappingRuleType{rule(ua.IdentityCriteriaTypeTrustedApplication)}
	case id.WellKnownRoleSecurityAdmin, id.WellKnownRoleConfigureAdmin, id.WellKnownRoleSecurityKeyServerAdmin:
		r.admin = true
	}
	return r
}

// bindRole serves the Properties of the role Object n from r and registers
// the handlers of its Methods.
func (rs *RoleSet) bindRole(r *managedRole, n *Node) {
	s := rs.s
	for _, ref := range n.refsSnapshot() {
		if !isForwardRef(ref, id.HasProperty) && !isForwardRef(ref, id.HasComponent) {
			continue
		}
		child := ref.NodeID.NodeID
		name := s.childName(child)
		switch {
		case isForwardRef(ref, id.HasProperty):
			v := rs.propertyValue(r, name)
			if v == nil {
				continue
			}
			p := s.Node(child)
			if child.Namespace() == 0 {
				p = s.ownNode(child.IntID())
			}
			p.SetValueFunc(v)
			if w := rs.propertyWriter(r, name); w != nil {
				p.SetValueWriter(w)
				// The NodeSet has no UserAccessLevel for these Properties,
				// which makes it CurrentRead. The writer checks the user
				// (§4.4.1), so UserAccessLevel is the AccessLevel.
				p.mu.Lock()
				p.attr[ua.AttributeIDUserAccessLevel] = DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead | ua.AccessLevelTypeCurrentWrite))
				p.mu.Unlock()
			}
			r.props = append(r.props, child)
		default:
			if h := rs.roleMethod(r, name); h != nil {
				s.RegisterMethod(r.id, child, h)
			}
		}
	}
}

// childName returns the BrowseName of the node nid when it is a name of
// namespace 0, "" otherwise.
func (s *Server) childName(nid *ua.NodeID) string {
	if n := s.Node(nid); n != nil {
		if bn := n.BrowseName(); bn != nil && bn.NamespaceIndex == 0 {
			return bn.Name
		}
	}
	return ""
}

// propertyValue returns the ValueFunc of the Property name of r, nil for a
// Property the RoleSet does not serve.
func (rs *RoleSet) propertyValue(r *managedRole, name string) ValueFunc {
	read := func(f func() any) ValueFunc {
		return func() *ua.DataValue {
			rs.mu.RLock()
			v := f()
			rs.mu.RUnlock()
			return DataValueFromValue(v)
		}
	}
	switch name {
	case propIdentities:
		return read(func() any { return eos(r.identities) })
	case propApplications:
		return read(func() any { return orEmpty(r.applications) })
	case propApplicationsExclude:
		return read(func() any { return r.appsExclude })
	case propEndpoints:
		return read(func() any { return eos(r.endpoints) })
	case propEndpointsExclude:
		return read(func() any { return r.epExclude })
	case propCustomConfiguration:
		// The standard configuration of §4.4.1, not a vendor specific one.
		return static(false)
	}
	return nil
}

func orEmpty(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}

// propertyWriter returns the ValueWriter of ApplicationsExclude and
// EndpointsExclude, "configured with the Write Service" (§4.4.1); nil for
// the other Properties, which the Methods configure.
func (rs *RoleSet) propertyWriter(r *managedRole, name string) ValueWriter {
	var set func(*ua.NodeID, bool) error
	switch name {
	case propApplicationsExclude:
		set = rs.SetApplicationsExclude
	case propEndpointsExclude:
		set = rs.SetEndpointsExclude
	default:
		return nil
	}
	return func(ctx context.Context, w *ValueWrite) ua.StatusCode {
		var sess *session
		if w.Session != nil {
			sess = w.Session.s
		}
		if st := rs.authorizeSession(ctx, sess, name); st != ua.StatusOK {
			return st
		}
		if w.Value == nil || w.Value.Value == nil {
			return ua.StatusBadTypeMismatch
		}
		b, ok := w.Value.Value.Value().(bool)
		if !ok {
			return ua.StatusBadTypeMismatch
		}
		return roleStatus(set(r.id, b))
	}
}

// roleStatus returns the StatusCode of an error of the RoleSet, StatusOK
// for nil.
func roleStatus(err error) ua.StatusCode {
	if sc, ok := err.(ua.StatusCode); ok || err == nil {
		return sc
	}
	return ua.StatusBadInternalError
}

// changed reports the change of the roles: the Properties of the roles
// changed report a data change and the active sessions get their roles
// again.
func (rs *RoleSet) changed(props []*ua.NodeID) {
	for _, p := range props {
		rs.s.ChangeNotification(p)
	}
	rs.reevaluate()
}

// mutable returns the role id that the rules of may change: a role that
// exists (Bad_NodeIdUnknown) and is not fixed (Bad_RequestNotAllowed,
// §4.3). rs.mu must be held.
func (rs *RoleSet) mutableLocked(id *ua.NodeID) (*managedRole, error) {
	r := rs.findLocked(id)
	if r == nil {
		return nil, ua.StatusBadNodeIDUnknown
	}
	if r.fixed {
		return nil, ua.StatusBadRequestNotAllowed
	}
	return r, nil
}

// update changes the role id with f under the locks of the RoleSet and
// reports the change.
func (rs *RoleSet) update(id *ua.NodeID, f func(r *managedRole) error) error {
	rs.opMu.Lock()
	rs.mu.Lock()
	r, err := rs.mutableLocked(id)
	if err == nil {
		err = f(r)
	}
	var props []*ua.NodeID
	if r != nil {
		props = slices.Clone(r.props)
	}
	rs.mu.Unlock()
	rs.opMu.Unlock()
	if err != nil {
		return err
	}
	rs.changed(props)
	return nil
}

// AddIdentity adds the identity mapping rule to the role (OPC 10000-18
// §4.4.5).
func (rs *RoleSet) AddIdentity(role *ua.NodeID, rule *ua.IdentityMappingRuleType) error {
	if err := rs.checkRule(rule); err != nil {
		return err
	}
	c := *rule
	return rs.update(role, func(r *managedRole) error {
		if r.admin && c.CriteriaType == ua.IdentityCriteriaTypeAnonymous {
			return ua.StatusBadRequestNotAllowed
		}
		if slices.ContainsFunc(r.identities, func(x *ua.IdentityMappingRuleType) bool { return sameRule(x, &c) }) {
			return ua.StatusBadAlreadyExists
		}
		if len(r.identities) >= rs.maxEntries {
			return ua.StatusBadResourceUnavailable
		}
		r.identities = append(slices.Clip(r.identities), &c)
		return nil
	})
}

// RemoveIdentity removes the identity mapping rule from the role (OPC
// 10000-18 §4.4.6).
func (rs *RoleSet) RemoveIdentity(role *ua.NodeID, rule *ua.IdentityMappingRuleType) error {
	return rs.update(role, func(r *managedRole) error {
		i := slices.IndexFunc(r.identities, func(x *ua.IdentityMappingRuleType) bool { return sameRule(x, rule) })
		if i < 0 {
			return ua.StatusBadNotFound
		}
		r.identities = slices.Delete(slices.Clone(r.identities), i, i+1)
		return nil
	})
}

// AddApplication adds the ApplicationUri to the Applications of the role
// (OPC 10000-18 §4.4.7).
func (rs *RoleSet) AddApplication(role *ua.NodeID, applicationURI string) error {
	if !validURI(applicationURI) {
		return ua.StatusBadInvalidArgument
	}
	return rs.update(role, func(r *managedRole) error {
		if slices.Contains(r.applications, applicationURI) {
			return ua.StatusBadAlreadyExists
		}
		if len(r.applications) >= rs.maxEntries {
			return ua.StatusBadResourceUnavailable
		}
		r.applications = append(slices.Clip(r.applications), applicationURI)
		return nil
	})
}

// RemoveApplication removes the ApplicationUri from the Applications of the
// role (OPC 10000-18 §4.4.8).
func (rs *RoleSet) RemoveApplication(role *ua.NodeID, applicationURI string) error {
	return rs.update(role, func(r *managedRole) error {
		i := slices.Index(r.applications, applicationURI)
		if i < 0 {
			return ua.StatusBadNotFound
		}
		r.applications = slices.Delete(slices.Clone(r.applications), i, i+1)
		return nil
	})
}

// AddEndpoint adds the Endpoint to the Endpoints of the role (OPC 10000-18
// §4.4.9).
func (rs *RoleSet) AddEndpoint(role *ua.NodeID, ep *ua.EndpointType) error {
	if !validEndpoint(ep) {
		return ua.StatusBadInvalidArgument
	}
	c := *ep
	return rs.update(role, func(r *managedRole) error {
		if slices.ContainsFunc(r.endpoints, func(x *ua.EndpointType) bool { return sameEndpoint(x, &c) }) {
			return ua.StatusBadAlreadyExists
		}
		if len(r.endpoints) >= rs.maxEntries {
			return ua.StatusBadResourceUnavailable
		}
		r.endpoints = append(slices.Clip(r.endpoints), &c)
		return nil
	})
}

// RemoveEndpoint removes the Endpoint from the Endpoints of the role (OPC
// 10000-18 §4.4.10).
func (rs *RoleSet) RemoveEndpoint(role *ua.NodeID, ep *ua.EndpointType) error {
	return rs.update(role, func(r *managedRole) error {
		i := slices.IndexFunc(r.endpoints, func(x *ua.EndpointType) bool { return sameEndpoint(x, ep) })
		if i < 0 {
			return ua.StatusBadNotFound
		}
		r.endpoints = slices.Delete(slices.Clone(r.endpoints), i, i+1)
		return nil
	})
}

// SetApplicationsExclude sets ApplicationsExclude of the role: whether the
// Applications are an exclude list (OPC 10000-18 §4.4.1).
func (rs *RoleSet) SetApplicationsExclude(role *ua.NodeID, exclude bool) error {
	return rs.update(role, func(r *managedRole) error {
		r.appsExclude = exclude
		return nil
	})
}

// SetEndpointsExclude sets EndpointsExclude of the role: whether the
// Endpoints are an exclude list (OPC 10000-18 §4.4.1).
func (rs *RoleSet) SetEndpointsExclude(role *ua.NodeID, exclude bool) error {
	return rs.update(role, func(r *managedRole) error {
		r.epExclude = exclude
		return nil
	})
}

// AddRole adds the role name, qualified by namespaceURI, to the RoleSet and
// returns the NodeId of its Object (OPC 10000-18 §4.2.2). An empty
// namespaceURI is [RolesNamespaceURI].
func (rs *RoleSet) AddRole(name, namespaceURI string) (*ua.NodeID, error) {
	if name == "" || len(name) > maxRoleText || !printable(name) {
		return nil, ua.StatusBadInvalidArgument
	}
	s := rs.s
	rs.opMu.Lock()
	defer rs.opMu.Unlock()

	if namespaceURI == uaNamespaceURI {
		// "the name of the Role from OPC 10000-3 shall be used together
		// with the OPC UA namespace URI": the well-known roles, which the
		// RoleSet has.
		if _, ok := ua.RoleByName[name]; ok {
			return nil, ua.StatusBadAlreadyExists
		}
		return nil, ua.StatusBadInvalidArgument
	}
	ns, err := rs.namespace()
	if err != nil {
		return nil, err
	}
	nsIdx := ns.ID()
	if namespaceURI != "" && namespaceURI != RolesNamespaceURI {
		idx, ok := s.namespaceLookup(namespaceURI)
		if !ok {
			return nil, ua.StatusBadInvalidArgument
		}
		nsIdx = idx
	}
	bn := &ua.QualifiedName{NamespaceIndex: nsIdx, Name: name}

	rs.mu.RLock()
	exists, added := false, 0
	for _, r := range rs.roles {
		if r.browseName != nil && r.browseName.NamespaceIndex == bn.NamespaceIndex && r.browseName.Name == bn.Name {
			exists = true
		}
		if r.removable {
			added++
		}
	}
	rs.mu.RUnlock()
	if exists {
		return nil, ua.StatusBadAlreadyExists
	}
	if added >= rs.maxRoles {
		return nil, ua.StatusBadNotSupported
	}

	r := &managedRole{
		id:          ua.NewStringNodeID(ns.ID(), strconv.Itoa(int(nsIdx))+":"+name),
		browseName:  bn,
		removable:   true,
		appsExclude: true, // "the initial values ... shall be TRUE" (§4.2.2)
		epExclude:   true,
	}
	rs.addRoleNodes(r)
	rs.mu.Lock()
	rs.roles = append(rs.roles, r)
	rs.mu.Unlock()
	return r.id, nil
}

// namespace returns the namespace of the roles AddRole adds, adding it;
// Bad_NotSupported when the application registered RolesNamespaceURI with a
// NameSpace that is no NodeNameSpace, to which AddRole cannot add nodes.
// rs.opMu must be held.
func (rs *RoleSet) namespace() (*NodeNameSpace, error) {
	if rs.ns != nil {
		return rs.ns, nil
	}
	if idx, ok := rs.s.namespaceLookup(RolesNamespaceURI); ok {
		nns, ok := rs.s.namespaceAt(idx).(*NodeNameSpace)
		if !ok {
			return nil, ua.StatusBadNotSupported
		}
		rs.ns = nns
		return nns, nil
	}
	rs.ns = NewNodeNameSpace(rs.s, RolesNamespaceURI)
	return rs.ns, nil
}

// namespaceAt returns the namespace idx, nil if there is none.
func (s *Server) namespaceAt(idx uint16) NameSpace {
	ns, err := s.Namespace(int(idx))
	if err != nil {
		return nil
	}
	return ns
}

// roleTemplate returns the node of a role of namespace 0 with the Methods
// of RoleType whose RolePermissions and AccessRestrictions the nodes of an
// added role take: Observer, as the standard NodeSet has it.
func (s *Server) roleTemplate() *Node {
	return s.Node(ua.NewNumericNodeID(0, id.WellKnownRoleObserver))
}

// childNamed returns the child of n with the BrowseName name of namespace 0
// by a forward reference of refType.
func (s *Server) childNamed(n *Node, refType uint32, name string) *Node {
	if n == nil {
		return nil
	}
	for _, ref := range n.refsSnapshot() {
		if isForwardRef(ref, refType) && s.childName(ref.NodeID.NodeID) == name {
			return s.Node(ref.NodeID.NodeID)
		}
	}
	return nil
}

// copyAccess gives n the RolePermissions and AccessRestrictions of the node
// of the template.
func copyAccess(n, template *Node) {
	if template == nil {
		return
	}
	template.mu.RLock()
	perms := slices.Clone(template.rolePermissions)
	ar := template.attr[ua.AttributeIDAccessRestrictions]
	template.mu.RUnlock()
	n.rolePermissions = perms
	if ar != nil {
		n.attr[ua.AttributeIDAccessRestrictions] = ar
	}
}

// roleProperties are the Properties of an added role: those of RoleType
// (§4.4.1) with their DataType and ValueRank.
var roleProperties = []struct {
	name     string
	dataType uint32
	array    bool
	writable bool
}{
	{propIdentities, id.IdentityMappingRuleType, true, false},
	{propApplications, id.String, true, false},
	{propApplicationsExclude, id.Boolean, false, true},
	{propEndpoints, id.EndpointType, true, false},
	{propEndpointsExclude, id.Boolean, false, true},
	{propCustomConfiguration, id.Boolean, false, false},
}

// roleMethods are the Methods of RoleType with their declaration.
var roleMethods = []struct {
	name string
	decl uint32
}{
	{"AddIdentity", id.RoleTypeAddIdentity},
	{"RemoveIdentity", id.RoleTypeRemoveIdentity},
	{"AddApplication", id.RoleTypeAddApplication},
	{"RemoveApplication", id.RoleTypeRemoveApplication},
	{"AddEndpoint", id.RoleTypeAddEndpoint},
	{"RemoveEndpoint", id.RoleTypeRemoveEndpoint},
}

// addRoleNodes adds the Object of the role r with its Properties and
// Methods (RoleType, §4.4.1) below the RoleSet. rs.opMu must be held.
func (rs *RoleSet) addRoleNodes(r *managedRole) {
	s := rs.s
	ns := rs.ns
	tmpl := s.roleTemplate()
	name := r.browseName.Name
	child := func(suffix string) *ua.NodeID { return ua.NewStringNodeID(ns.ID(), r.id.StringID()+"/"+suffix) }

	obj := NewNode(r.id, Attributes{
		ua.AttributeIDNodeClass:     DataValueFromValue(uint32(ua.NodeClassObject)),
		ua.AttributeIDBrowseName:    DataValueFromValue(r.browseName),
		ua.AttributeIDDisplayName:   DataValueFromValue(attrs.DisplayName(name, "")),
		ua.AttributeIDDescription:   DataValueFromValue(&ua.LocalizedText{}),
		ua.AttributeIDEventNotifier: DataValueFromValue(byte(0)),
	}, nil, nil)
	copyAccess(obj, tmpl)
	var nodes []*ua.NodeID
	add := func(n *Node) *Node {
		ns.AddNode(n)
		nodes = append(nodes, n.ID())
		return n
	}
	add(obj)
	if t := s.Node(ua.NewNumericNodeID(0, id.RoleType)); t != nil {
		obj.AddRef(t, RefType(id.HasTypeDefinition), true)
	}
	propType := s.Node(ua.NewNumericNodeID(0, id.PropertyType))

	for _, p := range roleProperties {
		al := byte(ua.AccessLevelTypeCurrentRead)
		if p.writable {
			al |= byte(ua.AccessLevelTypeCurrentWrite)
		}
		a := Attributes{
			ua.AttributeIDNodeClass:       DataValueFromValue(uint32(ua.NodeClassVariable)),
			ua.AttributeIDBrowseName:      DataValueFromValue(&ua.QualifiedName{Name: p.name}),
			ua.AttributeIDDisplayName:     DataValueFromValue(attrs.DisplayName(p.name, "")),
			ua.AttributeIDDescription:     DataValueFromValue(&ua.LocalizedText{}),
			ua.AttributeIDDataType:        DataValueFromValue(ua.NewNumericExpandedNodeID(0, p.dataType)),
			ua.AttributeIDValueRank:       DataValueFromValue(int32(-1)),
			ua.AttributeIDAccessLevel:     DataValueFromValue(al),
			ua.AttributeIDUserAccessLevel: DataValueFromValue(al),
		}
		if p.array {
			a[ua.AttributeIDValueRank] = DataValueFromValue(int32(1))
			a[ua.AttributeIDArrayDimensions] = DataValueFromValue([]uint32{0})
		}
		pn := NewNode(child(p.name), a, nil, rs.propertyValue(r, p.name))
		copyAccess(pn, s.childNamed(tmpl, id.HasProperty, p.name))
		if w := rs.propertyWriter(r, p.name); w != nil {
			pn.writer = w
		}
		add(pn)
		if propType != nil {
			pn.AddRef(propType, RefType(id.HasTypeDefinition), true)
		}
		linkChild(obj, pn, id.HasProperty)
		r.props = append(r.props, pn.ID())
	}

	for _, m := range roleMethods {
		mid := child(m.name)
		mn := NewNode(mid, Attributes{
			ua.AttributeIDNodeClass:      DataValueFromValue(uint32(ua.NodeClassMethod)),
			ua.AttributeIDBrowseName:     DataValueFromValue(&ua.QualifiedName{Name: m.name}),
			ua.AttributeIDDisplayName:    DataValueFromValue(attrs.DisplayName(m.name, "")),
			ua.AttributeIDDescription:    DataValueFromValue(&ua.LocalizedText{}),
			ua.AttributeIDExecutable:     DataValueFromValue(true),
			ua.AttributeIDUserExecutable: DataValueFromValue(true),
		}, nil, nil)
		copyAccess(mn, s.childNamed(tmpl, id.HasComponent, m.name))
		add(mn)
		linkChild(obj, mn, id.HasComponent)
		if in := s.childNamed(s.Node(ua.NewNumericNodeID(0, m.decl)), id.HasProperty, "InputArguments"); in != nil {
			if dv := in.Value(); dv != nil && dv.Value != nil {
				v := dv.Value
				an := NewNode(ua.NewStringNodeID(ns.ID(), mid.StringID()+"/InputArguments"), Attributes{
					ua.AttributeIDNodeClass:       DataValueFromValue(uint32(ua.NodeClassVariable)),
					ua.AttributeIDBrowseName:      DataValueFromValue(&ua.QualifiedName{Name: "InputArguments"}),
					ua.AttributeIDDisplayName:     DataValueFromValue(attrs.DisplayName("InputArguments", "")),
					ua.AttributeIDDescription:     DataValueFromValue(&ua.LocalizedText{}),
					ua.AttributeIDDataType:        DataValueFromValue(ua.NewNumericExpandedNodeID(0, id.Argument)),
					ua.AttributeIDValueRank:       DataValueFromValue(int32(1)),
					ua.AttributeIDArrayDimensions: DataValueFromValue([]uint32{0}),
					ua.AttributeIDAccessLevel:     DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead)),
					ua.AttributeIDUserAccessLevel: DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead)),
				}, nil, func() *ua.DataValue { return &ua.DataValue{EncodingMask: ua.DataValueValue, Value: v} })
				add(an)
				if propType != nil {
					an.AddRef(propType, RefType(id.HasTypeDefinition), true)
				}
				linkChild(mn, an, id.HasProperty)
			}
		}
		s.RegisterMethod(r.id, mid, rs.roleMethod(r, m.name))
	}
	r.nodes = nodes
	if set := s.Node(roleSetNodeID); set != nil {
		linkChild(set, obj, id.HasComponent)
	}
}

// RemoveRole removes the role from the RoleSet (OPC 10000-18 §4.2.3) with
// its nodes and its RolePermissions.
func (rs *RoleSet) RemoveRole(role *ua.NodeID) error {
	s := rs.s
	rs.opMu.Lock()
	rs.mu.Lock()
	r := rs.findLocked(role)
	switch {
	case r == nil:
		rs.mu.Unlock()
		rs.opMu.Unlock()
		return ua.StatusBadNodeIDUnknown
	case !r.removable:
		rs.mu.Unlock()
		rs.opMu.Unlock()
		return ua.StatusBadRequestNotAllowed
	}
	rs.roles = slices.DeleteFunc(slices.Clone(rs.roles), func(x *managedRole) bool { return x == r })
	rs.mu.Unlock()

	s.mu.Lock()
	for _, n := range r.nodes {
		delete(s.methods, methodKey(r.id, n))
	}
	s.mu.Unlock()
	if set := s.Node(roleSetNodeID); set != nil {
		set.RemoveRef(ua.NewExpandedNodeID(r.id, "", 0), ua.NewNumericNodeID(0, id.HasComponent), true)
	}
	// The children first: the Object is the target of their inverse
	// references, which DeleteNode does not remove from it.
	for i := len(r.nodes) - 1; i >= 0; i-- {
		// Bad_NodeIdUnknown for a node a client deleted with DeleteNodes
		// already: it is gone, as it should be.
		_ = rs.ns.DeleteNode(r.nodes[i])
	}
	s.deleteRolePermissions(r.id)
	rs.opMu.Unlock()
	rs.reevaluate()
	return nil
}

// deleteRolePermissions deletes the RolePermissions of the role from every
// node and from the DefaultRolePermissions of every namespace: "If a Role
// is removed all Permissions associated with the Role shall be deleted"
// (OPC 10000-18 §4.2.3).
func (s *Server) deleteRolePermissions(role *ua.NodeID) {
	other := func(rp *ua.RolePermissionType) bool { return rp == nil || !rp.RoleID.Equal(role) }
	for _, ns := range s.Namespaces() {
		nns, ok := ns.(*NodeNameSpace)
		if !ok {
			continue
		}
		nns.mu.RLock()
		nodes := slices.Clone(nns.nodes)
		nns.mu.RUnlock()
		for _, n := range nodes {
			n.mu.Lock()
			if !slices.ContainsFunc(n.rolePermissions, func(rp *ua.RolePermissionType) bool { return !other(rp) }) {
				n.mu.Unlock()
				continue
			}
			var kept []*ua.RolePermissionType
			for _, rp := range n.rolePermissions {
				if other(rp) {
					kept = append(kept, rp)
				}
			}
			n.rolePermissions = kept
			n.mu.Unlock()
		}
	}
	s.nsMeta.mu.Lock()
	defer s.nsMeta.mu.Unlock()
	m := s.nsMeta.defaults.Load()
	if m == nil {
		return
	}
	for idx, d := range *m {
		if !slices.ContainsFunc(d.RolePermissions, func(rp *ua.RolePermissionType) bool { return !other(rp) }) {
			continue
		}
		c := d.clone()
		c.RolePermissions = slices.DeleteFunc(c.RolePermissions, func(rp *ua.RolePermissionType) bool { return !other(rp) })
		s.storeDefaults(idx, c, d.fromModel)
		s.publishNamespaceMetadata(idx, nil)
	}
}
