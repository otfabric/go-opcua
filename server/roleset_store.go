// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/otfabric/go-opcua/ua"
)

// RoleSetStore persists the managed RoleSet of a server
// ([WithRoleManagement], OPC 10000-18): the roles AddRole added (§4.2.2)
// and the Identities, Applications, ApplicationsExclude, Endpoints and
// EndpointsExclude of every role whose configuration can change (§4.4.1),
// the well-known roles of namespace 0 included. Package server/rolestore
// implements it on a directory.
//
// The server calls StoreRoleSet after each change that succeeded, whatever
// makes it (the Methods of §4.2.2, §4.2.3 and §4.4.5 to §4.4.10, a Write
// of ApplicationsExclude or EndpointsExclude, or the [RoleSet] methods),
// and LoadRoleSet once, before the first session can be activated
// ([WithRoleSetStore]).
type RoleSetStore interface {
	// LoadRoleSet returns the stored roles with their NodeIds and
	// BrowseNames in the namespaces of namespaces, the NamespaceArray of the
	// server, or nil when the store holds no roles. An error, a namespace
	// the server does not have included, fails the restore: the server does
	// not start with a RoleSet other than the latest one.
	LoadRoleSet(ctx context.Context, namespaces []string) ([]Role, error)
	// StoreRoleSet makes roles, whose NodeIds and BrowseNames are in the
	// namespaces of namespaces, the stored roles, all or nothing, in their
	// order. It returns nil when roles are durable. On an error the server
	// does not apply the change and fails it with Bad_InternalError. After
	// an error the store must hold the roles it held before, or refuse later
	// writes until it does, so that a restarted server never starts with a
	// change it did not apply. roles are those of the RoleSet that are not
	// Fixed; the store does not keep them.
	StoreRoleSet(ctx context.Context, roles []Role, namespaces []string) error
}

// WithRoleSetStore persists the managed RoleSet of [WithRoleManagement] in
// st. Once st holds roles they are the configuration of the RoleSet: the
// server restores them once, at Start before it accepts a connection, or at
// the first change made through [Server.RoleSet] before Start, whichever
// comes first; the changes an application makes at each start are made on
// the restored roles. A store that cannot be loaded, or roles that are not
// valid, fail the restore: Start returns the error and the server does not
// start (fail closed). Register the namespaces the BrowseNames of the
// added roles use before Start.
//
// Every change of the RoleSet is written in one call of st after it
// succeeded in memory and before the Method, Write or function that made it
// returns; a write that fails leaves the RoleSet as it was and fails the
// change with Bad_InternalError (a library interpretation: OPC 10000-18
// gives no result code for it).
//
// It needs WithRoleManagement.
func WithRoleSetStore(st RoleSetStore) Option {
	return func(c *serverConfig) error {
		if st == nil {
			return errors.New("server: WithRoleSetStore: nil store")
		}
		c.roleSetStore = st
		return nil
	}
}

// restore is restoreLocked under opMu, with the change it reports.
func (rs *RoleSet) restore() error {
	rs.opMu.Lock()
	props, err := rs.restoreLocked()
	rs.opMu.Unlock()
	if err == nil && props != nil {
		rs.changed(props)
	}
	return err
}

// restoredRole is a role of the store as the RoleSet takes it: the role it
// changes (nil for a role AddRole added) and its configuration.
type restoredRole struct {
	into *managedRole
	r    *managedRole
}

// restoreLocked brings the RoleSet to the roles of the store once
// (WithRoleSetStore) and returns the Properties of the roles it changed,
// not nil when it restored, for the caller to report with changed once it
// released opMu. It fails, and is tried again by the next call, when the
// store cannot be loaded or its roles cannot be restored; the RoleSet then
// keeps the roles it had. rs.opMu must be held.
func (rs *RoleSet) restoreLocked() ([]*ua.NodeID, error) {
	st := rs.s.cfg.roleSetStore
	if st == nil || rs.restored {
		return nil, nil
	}
	s := rs.s
	// The roles AddRole added are in RolesNamespaceURI, which the server
	// adds at the first of them: the store maps them to the index it will
	// have.
	namespaces := s.namespaceURIs()
	if !slices.Contains(namespaces, RolesNamespaceURI) {
		namespaces = append(namespaces, RolesNamespaceURI)
	}
	stored, err := st.LoadRoleSet(context.Background(), namespaces)
	if err != nil {
		return nil, fmt.Errorf("server: roleset: load the store: %w", err)
	}
	plan, err := rs.planRestore(stored, namespaces)
	if err != nil {
		return nil, fmt.Errorf("server: roleset: the stored roles: %w", err)
	}
	var added []*managedRole
	for _, p := range plan {
		if p.into == nil {
			added = append(added, p.r)
		}
	}
	if len(added) > 0 {
		ns, err := rs.namespace()
		if err != nil {
			return nil, fmt.Errorf("server: roleset: the namespace of the stored roles: %w", err)
		}
		for _, r := range added {
			r.id = ua.NewStringNodeID(ns.ID(), r.id.StringID())
			if uri := namespaces[r.browseName.NamespaceIndex]; uri == RolesNamespaceURI {
				r.browseName.NamespaceIndex = ns.ID()
			}
		}
	}
	props := []*ua.NodeID{}
	rs.mu.Lock()
	for _, p := range plan {
		if p.into != nil {
			p.into.setConfig(p.r)
			props = append(props, p.into.props...)
		}
	}
	rs.mu.Unlock()
	for _, r := range added {
		rs.addRoleNodes(r)
		rs.mu.Lock()
		rs.roles = append(rs.roles, r)
		rs.mu.Unlock()
	}
	rs.restored = true
	return props, nil
}

// planRestore checks the stored roles against the RoleSet: a role that is
// not an added one has to be a role of the RoleSet whose configuration can
// change; an added one a String NodeId in RolesNamespaceURI and a
// BrowseName no other role has. The rules are those the Methods take.
func (rs *RoleSet) planRestore(stored []Role, namespaces []string) ([]restoredRole, error) {
	plan := make([]restoredRole, 0, len(stored))
	seen := map[string]bool{}
	names := map[ua.QualifiedName]bool{}
	for _, r := range rs.roles {
		if r.browseName != nil {
			names[*r.browseName] = true
		}
	}
	for _, x := range stored {
		if x.NodeID == nil || x.BrowseName == nil {
			return nil, errors.New("a role without NodeId or BrowseName")
		}
		key := x.NodeID.String()
		if seen[key] {
			return nil, fmt.Errorf("the role %v twice", x.NodeID)
		}
		seen[key] = true
		r := &managedRole{
			id: x.NodeID, browseName: &ua.QualifiedName{NamespaceIndex: x.BrowseName.NamespaceIndex, Name: x.BrowseName.Name},
			identities: cloneRules(x.Identities), applications: slices.Clone(x.Applications), appsExclude: x.ApplicationsExclude,
			endpoints: cloneEndpoints(x.Endpoints), epExclude: x.EndpointsExclude,
		}
		var into *managedRole
		if x.Removable {
			if int(x.NodeID.Namespace()) >= len(namespaces) || namespaces[x.NodeID.Namespace()] != RolesNamespaceURI ||
				x.NodeID.Type() != ua.NodeIDTypeString || int(x.BrowseName.NamespaceIndex) >= len(namespaces) ||
				x.BrowseName.Name == "" || names[*x.BrowseName] {
				return nil, fmt.Errorf("the added role %v (%v) cannot be restored", x.NodeID, x.BrowseName)
			}
			names[*x.BrowseName] = true
			r.removable = true
		} else {
			into = rs.findLocked(x.NodeID)
			if into == nil || into.fixed {
				return nil, fmt.Errorf("the role %v is not a role of the RoleSet whose configuration can change", x.NodeID)
			}
			r.admin = into.admin
		}
		if err := rs.checkConfig(r); err != nil {
			return nil, fmt.Errorf("the role %v: %w", x.NodeID, err)
		}
		plan = append(plan, restoredRole{into: into, r: r})
	}
	return plan, nil
}

// checkConfig checks the configuration of a stored role as the Methods
// check what they add (§4.4.5, §4.4.7, §4.4.9).
func (rs *RoleSet) checkConfig(r *managedRole) error {
	for _, x := range r.identities {
		if err := rs.checkRule(x); err != nil {
			return fmt.Errorf("the identity mapping rule %v: %w", x, err)
		}
		if r.admin && x.CriteriaType == ua.IdentityCriteriaTypeAnonymous {
			return errors.New("an Anonymous rule of a role with administrator rights")
		}
	}
	for _, a := range r.applications {
		if !validURI(a) {
			return fmt.Errorf("the ApplicationUri %q: %w", a, ua.StatusBadInvalidArgument)
		}
	}
	for _, ep := range r.endpoints {
		if !validEndpoint(ep) {
			return fmt.Errorf("the Endpoint %q: %w", ep.EndpointURL, ua.StatusBadInvalidArgument)
		}
	}
	return nil
}

// setConfig sets the configuration of r to that of c. rs.mu must be held.
func (r *managedRole) setConfig(c *managedRole) {
	r.identities, r.applications, r.appsExclude = c.identities, c.applications, c.appsExclude
	r.endpoints, r.epExclude = c.endpoints, c.epExclude
}

// persistLocked writes roles, the RoleSet with a change, to the store of
// WithRoleSetStore: the roles that are not fixed, in their order. The error
// wraps Bad_InternalError. rs.opMu must be held.
func (rs *RoleSet) persistLocked(roles []*managedRole) error {
	st := rs.s.cfg.roleSetStore
	if st == nil {
		return nil
	}
	out := make([]Role, 0, len(roles))
	for _, r := range roles {
		if !r.fixed {
			out = append(out, r.snapshot())
		}
	}
	if err := st.StoreRoleSet(context.Background(), out, rs.s.namespaceURIs()); err != nil {
		rs.s.cfg.logger.Warn("roleset: storing the roles failed", "error", err)
		return fmt.Errorf("%w: server: roleset: store the roles: %w", ua.StatusBadInternalError, err)
	}
	return nil
}
