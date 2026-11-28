// SPDX-License-Identifier: MIT

package server

import (
	"slices"

	"github.com/otfabric/go-opcua/ua"
)

// sessionRoles returns the roles granted to sess. A request without a
// session, or a session that was granted no role, has the Anonymous role:
// the RBACAccessController checks the RolePermissions of a node against the
// same set.
func sessionRoles(sess *session) []*ua.NodeID {
	var roles []*ua.NodeID
	if sess != nil {
		roles = sess.roles
	}
	if len(roles) == 0 {
		roles = []*ua.NodeID{ua.RoleAnonymous.NodeID()}
	}
	return roles
}

// readsSessionRoles reports whether Read reduces the attribute attr of the
// node nid to the roles of the session: UserRolePermissions, and the Value
// of a DefaultUserRolePermissions Property (namespace_metadata.go).
func (s *Server) readsSessionRoles(nid *ua.NodeID, attr ua.AttributeID) bool {
	if attr == ua.AttributeIDUserRolePermissions {
		return true
	}
	if attr != ua.AttributeIDValue || nid == nil {
		return false
	}
	n := s.Node(nid)
	if n == nil {
		return false
	}
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.sessionRoles
}

// forSessionRoles reduces dv, the value of a UserRolePermissions Attribute
// as a namespace returns it (the RolePermissions of the node), to the
// entries for the roles granted to sess: the Attribute "specifies the
// Permissions that apply to a Node for all Roles granted to current
// Session" (Part 3 §5.2.10). A role that the session does not have is not
// listed. A DataValue without an array of RolePermissionType is returned as
// it is. dv is not modified; the result is a copy when it differs.
func forSessionRoles(dv *ua.DataValue, sess *session) *ua.DataValue {
	if dv == nil || dv.Value == nil {
		return dv
	}
	eos, ok := dv.Value.Value().([]*ua.ExtensionObject)
	if !ok {
		return dv
	}
	roles := sessionRoles(sess)
	kept := make([]*ua.ExtensionObject, 0, len(eos))
	for _, eo := range eos {
		if eo == nil {
			continue
		}
		rp, ok := eo.Value.(*ua.RolePermissionType)
		if !ok || rp == nil || rp.RoleID == nil {
			continue
		}
		if slices.ContainsFunc(roles, rp.RoleID.Equal) {
			kept = append(kept, eo)
		}
	}
	cp := *dv
	cp.Value = ua.MustVariant(kept)
	return &cp
}
