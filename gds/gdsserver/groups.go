// SPDX-License-Identifier: MIT

package gdsserver

import (
	"slices"

	"github.com/otfabric/go-opcua/gds/gdsid"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// makeGroups sets up the certificate groups of the Directory after load:
//
//   - the DefaultApplicationGroup issues the application certificate types
//     of Config.CertificateTypes; its trust list holds every CA of the GDS,
//   - the DefaultHttpsGroup issues HttpsCertificateType certificates (TLS,
//     RSA or ECDSA on P-256 or P-384) when the GDS has a CA for such keys
//     (RSA, NistP256, NistP384); its trust list holds those CAs,
//   - the DefaultUserTokenGroup issues no certificates; its trust list holds
//     what a CertificateAuthorityAdmin adds (the issuers of the user
//     certificates the servers accept).
func (g *GDS) makeGroups() {
	app := &group{key: GroupApplication, node: gdsid.DirectoryCertificateGroupsDefaultApplicationGroup,
		trustNode: gdsid.DirectoryCertificateGroupsDefaultApplicationGroupTrustList,
		typesNode: gdsid.DirectoryCertificateGroupsDefaultApplicationGroupCertificateTypes,
		types:     g.types, issuers: g.caNamesLocked()}
	https := &group{key: GroupHTTPS, node: gdsid.DirectoryCertificateGroupsDefaultHTTPSGroup,
		trustNode: gdsid.DirectoryCertificateGroupsDefaultHTTPSGroupTrustList,
		typesNode: gdsid.DirectoryCertificateGroupsDefaultHTTPSGroupCertificateTypes}
	for _, name := range httpsIssuers {
		if g.cas[name] != nil {
			https.issuers = append(https.issuers, name)
		}
	}
	if len(https.issuers) > 0 {
		https.types = []uint32{id.HTTPSCertificateType}
	}
	user := &group{key: GroupUserToken, node: gdsid.DirectoryCertificateGroupsDefaultUserTokenGroup,
		trustNode: gdsid.DirectoryCertificateGroupsDefaultUserTokenGroupTrustList,
		typesNode: gdsid.DirectoryCertificateGroupsDefaultUserTokenGroupCertificateTypes}
	g.groups = []*group{app, https, user}
}

// groupOf returns the group a CertificateGroupId names, nil for none; a
// null NodeId is the DefaultApplicationGroup.
func (g *GDS) groupOf(n *ua.NodeID) *group {
	if isNull(n) {
		return g.groups[0]
	}
	for _, gr := range g.groups {
		if n.Equal(g.node(gr.node)) {
			return gr
		}
	}
	return nil
}

// groupByKey returns the group of a store key.
func (g *GDS) groupByKey(key string) *group {
	for _, gr := range g.groups {
		if gr.key == key {
			return gr
		}
	}
	return g.groups[0]
}

// groupsOf returns the groups of an application (GetCertificateGroups):
// the DefaultApplicationGroup, and for a server the DefaultHttpsGroup (if
// it issues certificates) and the DefaultUserTokenGroup.
func (g *GDS) groupsOf(app *Application) []*group {
	out := []*group{g.groups[0]}
	if app.Record.ApplicationType == ua.ApplicationTypeClient {
		return out
	}
	if len(g.groups[1].types) > 0 {
		out = append(out, g.groups[1])
	}
	return append(out, g.groups[2])
}

// extraTrustLocked returns the trust list additions of a group.
func (g *GDS) extraTrustLocked(gr *group) *ua.TrustListDataType {
	if gr.key == GroupApplication {
		return g.meta.TrustList
	}
	return g.meta.GroupTrustLists[gr.key]
}

// trustChanged tells the clients of every TrustList object that the trust
// lists changed (a CRL was renewed or re-signed).
func (g *GDS) trustChanged() {
	for _, gr := range g.groups {
		if gr.trust != nil {
			gr.trust.Changed()
		}
	}
}

// selfMethods are the methods an application may call for itself without
// a role, by the ApplicationSelfAdmin privilege of Part 12 §6.2: their
// handlers check that the caller is the application.
var selfMethods = map[uint32]bool{
	gdsid.DirectoryUpdateApplication:      true,
	gdsid.DirectoryUnregisterApplication:  true,
	gdsid.DirectoryStartSigningRequest:    true,
	gdsid.DirectoryStartNewKeyPairRequest: true,
	gdsid.DirectoryFinishRequest:          true,
	gdsid.DirectoryGetCertificateGroups:   true,
	gdsid.DirectoryGetCertificates:        true,
	gdsid.DirectoryGetTrustList:           true,
	gdsid.DirectoryGetCertificateStatus:   true,
}

// rolePermissions returns the RolePermissions of a node of the server (of
// the GDS NodeSet).
func (g *GDS) rolePermissions(n *ua.NodeID) []*ua.RolePermissionType {
	node := g.srv.Node(n)
	if node == nil {
		return nil
	}
	av, err := node.Attribute(ua.AttributeIDRolePermissions)
	if err != nil || av == nil || av.Value == nil || av.Value.Value == nil {
		return nil
	}
	eos, _ := av.Value.Value.Value().([]*ua.ExtensionObject)
	var out []*ua.RolePermissionType
	for _, eo := range eos {
		if rp, ok := eo.Value.(*ua.RolePermissionType); ok {
			out = append(out, rp)
		}
	}
	return out
}

// permits reports whether RolePermissions let the caller call a method: it
// has none, or one of the roles of the session has the Call permission. A
// session without roles has the Anonymous role, as for the
// RBACAccessController.
func (c *caller) permits(perms []*ua.RolePermissionType) bool {
	if len(perms) == 0 {
		return true
	}
	roles := c.mc.Roles
	if len(roles) == 0 {
		roles = []*ua.NodeID{ua.RoleAnonymous.NodeID()}
	}
	for _, rp := range perms {
		if rp.Permissions&ua.PermissionTypeCall == 0 {
			continue
		}
		if slices.ContainsFunc(roles, func(r *ua.NodeID) bool { return r.Equal(rp.RoleID) }) {
			return true
		}
	}
	return false
}
