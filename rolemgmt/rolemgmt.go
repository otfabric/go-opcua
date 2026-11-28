// SPDX-License-Identifier: MIT

// Package rolemgmt is the client of the role management of OPC 10000-18
// (Role-Based Security): the RoleSet Object of a server (§4.3) with its
// Methods AddRole and RemoveRole (§4.2.2, §4.2.3), and the role Objects
// (RoleType, §4.4.1) with their Properties Identities, Applications,
// ApplicationsExclude, Endpoints, EndpointsExclude and CustomConfiguration
// and their Methods AddIdentity, RemoveIdentity, AddApplication,
// RemoveApplication, AddEndpoint and RemoveEndpoint (§4.4.5 to §4.4.10).
//
// The Methods are called with the contracts of package uamethod: the
// arguments are packed and the results checked against the declarations
// of namespace 0. A Method of the Object is found by its BrowseName below
// the Object; an Object without it is called with the declaration of the
// type, which Part 4 §5.12.2.2 (1.05.06) allows. A Bad result is a
// *uamethod.CallError, so errors.Is(err, ua.StatusBadUserAccessDenied)
// holds.
//
// The server requires an encrypted channel and administrator rights such as
// the SecurityAdmin role for all of it, reading the Properties included
// (§4.4.1): connect with MessageSecurityModeSignAndEncrypt and a user the
// server grants SecurityAdmin.
package rolemgmt

import (
	"context"
	"fmt"
	"sync"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uamethod"
)

// RoleSet is the RoleSet Object of a server (OPC 10000-18 §4.3).
type RoleSet struct {
	c   *opcua.Client
	id  *ua.NodeID
	res *resolver
}

// New returns the RoleSet of the server of c, the Object
// Server.ServerCapabilities.RoleSet of namespace 0.
func New(c *opcua.Client) *RoleSet {
	return NewRoleSet(c, ua.NewNumericNodeID(0, id.ServerServerCapabilitiesRoleSet))
}

// NewRoleSet returns the RoleSetType Object obj of the server of c.
func NewRoleSet(c *opcua.Client, obj *ua.NodeID) *RoleSet {
	return &RoleSet{c: c, id: obj, res: newResolver(c, obj)}
}

// NodeID returns the NodeId of the RoleSet.
func (s *RoleSet) NodeID() *ua.NodeID { return s.id }

// Roles returns the roles of the RoleSet: the Objects it has as
// components whose TypeDefinition is RoleType (§4.2.1). A role of a
// subtype of RoleType is recognized by the TypeDefinition of the type only,
// which this method does not follow.
func (s *RoleSet) Roles(ctx context.Context) ([]*Role, error) {
	refs, err := s.c.Node(s.id).References(ctx, id.HasComponent, ua.BrowseDirectionForward, ua.NodeClassObject, true)
	if err != nil {
		return nil, fmt.Errorf("rolemgmt: browsing %v: %w", s.id, err)
	}
	var out []*Role
	for _, r := range refs {
		if !isRole(r) {
			continue
		}
		role := s.Role(r.NodeID.NodeID)
		role.BrowseName = r.BrowseName
		out = append(out, role)
	}
	return out, nil
}

// isRole reports a reference to an Object whose TypeDefinition is RoleType.
func isRole(r *ua.ReferenceDescription) bool {
	if r == nil || r.NodeID == nil || r.NodeID.NodeID == nil || r.TypeDefinition == nil || r.TypeDefinition.NodeID == nil {
		return false
	}
	td := r.TypeDefinition.NodeID
	return td.Namespace() == 0 && td.IntID() == id.RoleType
}

// Role returns the role Object nodeID of the server.
func (s *RoleSet) Role(nodeID *ua.NodeID) *Role {
	return &Role{c: s.c, NodeID: nodeID, res: newResolver(s.c, nodeID)}
}

// AddRole adds the role name to the RoleSet (§4.2.2) and returns it. The
// name is qualified by namespaceURI; an empty one is the namespace the
// server chooses. A well-known role of OPC 10000-3 has the OPC UA
// namespace URI "http://opcfoundation.org/UA/".
func (s *RoleSet) AddRole(ctx context.Context, name, namespaceURI string) (*Role, error) {
	out, err := uamethod.CallRoleSetTypeAddRole(ctx, s.c, s.id, s.res.method(ctx, uamethod.RoleSetTypeAddRole.Name),
		&uamethod.RoleSetTypeAddRoleInput{RoleName: name, NamespaceURI: namespaceURI})
	if err != nil {
		return nil, err
	}
	return s.Role(out.RoleNodeID), nil
}

// RemoveRole removes the role from the RoleSet (§4.2.3).
func (s *RoleSet) RemoveRole(ctx context.Context, role *ua.NodeID) error {
	return uamethod.CallRoleSetTypeRemoveRole(ctx, s.c, s.id, s.res.method(ctx, uamethod.RoleSetTypeRemoveRole.Name),
		&uamethod.RoleSetTypeRemoveRoleInput{RoleNodeID: role})
}

// Role is a role Object of a server (RoleType, OPC 10000-18 §4.4.1).
type Role struct {
	// NodeID is the NodeId of the role Object. BrowseName is set for the
	// roles of RoleSet.Roles.
	NodeID     *ua.NodeID
	BrowseName *ua.QualifiedName

	c   *opcua.Client
	res *resolver
}

// Config is the configuration of a role: the values of its Properties
// (§4.4.1). An optional Property the role does not have is zero.
type Config struct {
	Identities          []*ua.IdentityMappingRuleType
	Applications        []string
	ApplicationsExclude bool
	Endpoints           []*ua.EndpointType
	EndpointsExclude    bool
	CustomConfiguration bool
}

// Config reads the Properties of the role.
func (r *Role) Config(ctx context.Context) (*Config, error) {
	props, err := r.res.properties(ctx)
	if err != nil {
		return nil, err
	}
	var names []string
	var nodes []*ua.NodeID
	for _, name := range roleProperties {
		if nid := props[name]; nid != nil {
			names = append(names, name)
			nodes = append(nodes, nid)
		}
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("rolemgmt: %v has no Properties of RoleType: %w", r.NodeID, ua.StatusBadNotFound)
	}
	res, err := r.c.ReadValues(ctx, nodes...)
	if err != nil {
		return nil, fmt.Errorf("rolemgmt: reading the Properties of %v: %w", r.NodeID, err)
	}
	return configOf(names, res)
}

// configOf returns the Config of the values read for the Properties names,
// one result for each. A Bad value is an error: the server refuses the
// Properties to all but administrators on an encrypted channel. A value of
// another type leaves its field zero.
func configOf(names []string, results []*ua.DataValue) (*Config, error) {
	cfg := &Config{}
	for i, dv := range results {
		if dv == nil {
			continue
		}
		if dv.Status&0x80000000 != 0 { // Severity Bad (Part 4 §7.38.1)
			return nil, fmt.Errorf("rolemgmt: reading %s: %w", names[i], dv.Status)
		}
		if dv.Value == nil {
			continue
		}
		switch v := dv.Value.Value(); names[i] {
		case propIdentities:
			cfg.Identities = structures[ua.IdentityMappingRuleType](v)
		case propApplications:
			cfg.Applications, _ = v.([]string)
		case propApplicationsExclude:
			cfg.ApplicationsExclude, _ = v.(bool)
		case propEndpoints:
			cfg.Endpoints = structures[ua.EndpointType](v)
		case propEndpointsExclude:
			cfg.EndpointsExclude, _ = v.(bool)
		case propCustomConfiguration:
			cfg.CustomConfiguration, _ = v.(bool)
		}
	}
	return cfg, nil
}

// structures returns the structures T of an array of ExtensionObjects.
func structures[T any](v any) []*T {
	eos, _ := v.([]*ua.ExtensionObject)
	var out []*T
	for _, eo := range eos {
		if eo == nil {
			continue
		}
		if x, ok := eo.Value.(*T); ok {
			out = append(out, x)
		}
	}
	return out
}

// AddIdentity adds the identity mapping rule to the role (§4.4.5).
func (r *Role) AddIdentity(ctx context.Context, rule *ua.IdentityMappingRuleType) error {
	return uamethod.CallRoleTypeAddIdentity(ctx, r.c, r.NodeID, r.res.method(ctx, uamethod.RoleTypeAddIdentity.Name),
		&uamethod.RoleTypeAddIdentityInput{Rule: rule})
}

// RemoveIdentity removes the identity mapping rule from the role (§4.4.6).
func (r *Role) RemoveIdentity(ctx context.Context, rule *ua.IdentityMappingRuleType) error {
	return uamethod.CallRoleTypeRemoveIdentity(ctx, r.c, r.NodeID, r.res.method(ctx, uamethod.RoleTypeRemoveIdentity.Name),
		&uamethod.RoleTypeRemoveIdentityInput{Rule: rule})
}

// AddApplication adds the ApplicationUri to the Applications of the role
// (§4.4.7).
func (r *Role) AddApplication(ctx context.Context, applicationURI string) error {
	return uamethod.CallRoleTypeAddApplication(ctx, r.c, r.NodeID, r.res.method(ctx, uamethod.RoleTypeAddApplication.Name),
		&uamethod.RoleTypeAddApplicationInput{ApplicationURI: applicationURI})
}

// RemoveApplication removes the ApplicationUri from the Applications of
// the role (§4.4.8).
func (r *Role) RemoveApplication(ctx context.Context, applicationURI string) error {
	return uamethod.CallRoleTypeRemoveApplication(ctx, r.c, r.NodeID, r.res.method(ctx, uamethod.RoleTypeRemoveApplication.Name),
		&uamethod.RoleTypeRemoveApplicationInput{ApplicationURI: applicationURI})
}

// AddEndpoint adds the Endpoint to the Endpoints of the role (§4.4.9).
func (r *Role) AddEndpoint(ctx context.Context, ep *ua.EndpointType) error {
	return uamethod.CallRoleTypeAddEndpoint(ctx, r.c, r.NodeID, r.res.method(ctx, uamethod.RoleTypeAddEndpoint.Name),
		&uamethod.RoleTypeAddEndpointInput{Endpoint: ep})
}

// RemoveEndpoint removes the Endpoint from the Endpoints of the role
// (§4.4.10).
func (r *Role) RemoveEndpoint(ctx context.Context, ep *ua.EndpointType) error {
	return uamethod.CallRoleTypeRemoveEndpoint(ctx, r.c, r.NodeID, r.res.method(ctx, uamethod.RoleTypeRemoveEndpoint.Name),
		&uamethod.RoleTypeRemoveEndpointInput{Endpoint: ep})
}

// SetApplicationsExclude writes ApplicationsExclude: whether the
// Applications are an exclude list. It and EndpointsExclude "are
// configured with the Write Service" (§4.4.1).
func (r *Role) SetApplicationsExclude(ctx context.Context, exclude bool) error {
	return r.write(ctx, propApplicationsExclude, exclude)
}

// SetEndpointsExclude writes EndpointsExclude: whether the Endpoints are an
// exclude list (§4.4.1).
func (r *Role) SetEndpointsExclude(ctx context.Context, exclude bool) error {
	return r.write(ctx, propEndpointsExclude, exclude)
}

func (r *Role) write(ctx context.Context, name string, v bool) error {
	props, err := r.res.properties(ctx)
	if err != nil {
		return err
	}
	nid := props[name]
	if nid == nil {
		return fmt.Errorf("rolemgmt: %v has no Property %s: %w", r.NodeID, name, ua.StatusBadNotFound)
	}
	sc, err := r.c.WriteValue(ctx, nid, &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)})
	if err == nil && sc != ua.StatusOK {
		err = sc
	}
	if err != nil {
		return fmt.Errorf("rolemgmt: writing %s of %v: %w", name, r.NodeID, err)
	}
	return nil
}

// The BrowseNames of the Properties of RoleType (§4.4.1).
const (
	propIdentities          = "Identities"
	propApplications        = "Applications"
	propApplicationsExclude = "ApplicationsExclude"
	propEndpoints           = "Endpoints"
	propEndpointsExclude    = "EndpointsExclude"
	propCustomConfiguration = "CustomConfiguration"
)

var roleProperties = []string{propIdentities, propApplications, propApplicationsExclude, propEndpoints, propEndpointsExclude, propCustomConfiguration}

// resolver finds the Methods and Properties of an Object by their
// BrowseNames, once.
type resolver struct {
	c   *opcua.Client
	obj *ua.NodeID

	mu      sync.Mutex
	methods map[string]*ua.NodeID // nil until browsed
	props   map[string]*ua.NodeID // nil until browsed
}

func newResolver(c *opcua.Client, obj *ua.NodeID) *resolver { return &resolver{c: c, obj: obj} }

// method returns the NodeId of the Method name of the Object, nil for the
// declaration of the type when the Object has none of that name or cannot
// be browsed (the Call service then reports the status).
func (r *resolver) method(ctx context.Context, name string) *ua.NodeID {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.methods == nil {
		m, err := r.browse(ctx, id.HasComponent, ua.NodeClassMethod)
		if err != nil {
			return nil // not cached: the next call browses again
		}
		r.methods = m
	}
	return r.methods[name]
}

// properties returns the NodeIds of the Properties of the Object by their
// BrowseNames.
func (r *resolver) properties(ctx context.Context) (map[string]*ua.NodeID, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.props == nil {
		p, err := r.browse(ctx, id.HasProperty, ua.NodeClassVariable)
		if err != nil {
			return nil, fmt.Errorf("rolemgmt: browsing %v: %w", r.obj, err)
		}
		r.props = p
	}
	return r.props, nil
}

func (r *resolver) browse(ctx context.Context, refType uint32, class ua.NodeClass) (map[string]*ua.NodeID, error) {
	refs, err := r.c.Node(r.obj).References(ctx, refType, ua.BrowseDirectionForward, class, true)
	if err != nil {
		return nil, err
	}
	out := map[string]*ua.NodeID{}
	for _, ref := range refs {
		if ref.BrowseName != nil && ref.BrowseName.NamespaceIndex == 0 && ref.NodeID != nil {
			if _, dup := out[ref.BrowseName.Name]; !dup {
				out[ref.BrowseName.Name] = ref.NodeID.NodeID
			}
		}
	}
	return out, nil
}
