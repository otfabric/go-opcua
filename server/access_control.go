package server

import (
	"context"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

// AccessController defines the interface for controlling access to server operations.
//
// Each method is called before the corresponding service executes. Return
// [ua.StatusOK] to allow the operation, or an appropriate status code
// (e.g., [ua.StatusBadUserAccessDenied]) to deny it.
//
// The session parameter provides the authenticated session context, which
// can be used to implement role-based or user-based access control.
//
// Provide a custom implementation via [WithAccessController]. The default
// is [DefaultAccessController] which allows all operations.
type AccessController interface {
	CheckRead(ctx context.Context, session *session, nodeID *ua.NodeID) ua.StatusCode
	CheckWrite(ctx context.Context, session *session, nodeID *ua.NodeID) ua.StatusCode
	CheckBrowse(ctx context.Context, session *session, nodeID *ua.NodeID) ua.StatusCode
	CheckCall(ctx context.Context, session *session, methodID *ua.NodeID) ua.StatusCode
}

// DefaultAccessController is a permissive access controller that allows all
// operations. It is used when no custom [AccessController] is configured.
type DefaultAccessController struct{}

func (DefaultAccessController) CheckRead(_ context.Context, _ *session, _ *ua.NodeID) ua.StatusCode {
	return ua.StatusOK
}

func (DefaultAccessController) CheckWrite(_ context.Context, _ *session, _ *ua.NodeID) ua.StatusCode {
	return ua.StatusOK
}

func (DefaultAccessController) CheckBrowse(_ context.Context, _ *session, _ *ua.NodeID) ua.StatusCode {
	return ua.StatusOK
}

func (DefaultAccessController) CheckCall(_ context.Context, _ *session, _ *ua.NodeID) ua.StatusCode {
	return ua.StatusOK
}

// WithAccessController sets a custom access controller on the server.
func WithAccessController(ac AccessController) Option {
	return func(s *serverConfig) {
		s.accessController = ac
	}
}

// checkAccessRestrictions verifies that the secure channel meets the
// AccessRestrictions defined on the given node. It returns ua.StatusOK if the
// restrictions are satisfied, or an appropriate Bad status code otherwise.
//
// The OPC UA spec (Part 3 §5.2.11) defines AccessRestrictions as a bitmask:
//   - SigningRequired (1): the channel must use at least MessageSecurityModeSign.
//   - EncryptionRequired (2): the channel must use MessageSecurityModeSignAndEncrypt.
//   - SessionRequired (4): a session must be active (currently always true for us).
func checkAccessRestrictions(sc *uasc.SecureChannel, n *Node) ua.StatusCode {
	av, err := n.Attribute(ua.AttributeIDAccessRestrictions)
	if err != nil || av == nil || av.Value == nil || av.Value.Value == nil {
		return ua.StatusOK
	}
	restrictions, ok := av.Value.Value.Value().(uint16)
	if !ok {
		return ua.StatusOK
	}
	ar := ua.AccessRestrictionType(restrictions)
	if ar == ua.AccessRestrictionTypeNone {
		return ua.StatusOK
	}
	mode := ua.MessageSecurityModeNone
	if sc != nil {
		mode = sc.SecurityMode()
	}
	if ar&ua.AccessRestrictionTypeEncryptionRequired != 0 && mode != ua.MessageSecurityModeSignAndEncrypt {
		return ua.StatusBadSecurityModeInsufficient
	}
	if ar&ua.AccessRestrictionTypeSigningRequired != 0 && mode < ua.MessageSecurityModeSign {
		return ua.StatusBadSecurityModeInsufficient
	}
	return ua.StatusOK
}

// checkAccessRestrictionsForBrowse is like checkAccessRestrictions but only
// enforces restrictions when the ApplyRestrictionsToBrowse bit (8) is set.
// Per OPC UA Part 3 §5.2.11, access restrictions do not apply to Browse
// operations unless this bit is present.
func checkAccessRestrictionsForBrowse(sc *uasc.SecureChannel, n *Node) ua.StatusCode {
	av, err := n.Attribute(ua.AttributeIDAccessRestrictions)
	if err != nil || av == nil || av.Value == nil || av.Value.Value == nil {
		return ua.StatusOK
	}
	restrictions, ok := av.Value.Value.Value().(uint16)
	if !ok {
		return ua.StatusOK
	}
	if ua.AccessRestrictionType(restrictions)&ua.AccessRestrictionTypeApplyRestrictionsToBrowse == 0 {
		return ua.StatusOK
	}
	return checkAccessRestrictions(sc, n)
}

// RoleMapper resolves the set of well-known role NodeIDs for a given identity
// token. Implementations should return the appropriate roles based on the
// token type and credentials (e.g. AnonymousIdentityToken → [Anonymous],
// UserNameIdentityToken → [AuthenticatedUser, ...]).
type RoleMapper func(token ua.IdentityToken) []*ua.NodeID

// DefaultRoleMapper maps anonymous tokens to the Anonymous role and all other
// token types to AuthenticatedUser.
func DefaultRoleMapper(token ua.IdentityToken) []*ua.NodeID {
	switch token.(type) {
	case *ua.AnonymousIdentityToken, nil:
		return []*ua.NodeID{ua.RoleAnonymous.NodeID()}
	default:
		return []*ua.NodeID{ua.RoleAuthenticatedUser.NodeID()}
	}
}

// WithRoleMapper configures a custom role mapper for session identity → role resolution.
func WithRoleMapper(rm RoleMapper) Option {
	return func(s *serverConfig) {
		s.roleMapper = rm
	}
}

// RBACAccessController enforces OPC UA role-based access control by checking the
// node's RolePermissions against the session's assigned roles.
//
// For each operation, it looks up the target node, retrieves its rolePermissions,
// and verifies that at least one of the session's roles has the required permission.
// If the node has no rolePermissions defined, the operation is allowed.
type RBACAccessController struct {
	srv *Server
}

// NewRBACAccessController creates an RBAC access controller bound to the given server.
func NewRBACAccessController(srv *Server) *RBACAccessController {
	return &RBACAccessController{srv: srv}
}

func (ac *RBACAccessController) CheckRead(ctx context.Context, sess *session, nodeID *ua.NodeID) ua.StatusCode {
	return ac.checkPermission(sess, nodeID, ua.PermissionTypeRead)
}

func (ac *RBACAccessController) CheckWrite(ctx context.Context, sess *session, nodeID *ua.NodeID) ua.StatusCode {
	return ac.checkPermission(sess, nodeID, ua.PermissionTypeWrite)
}

func (ac *RBACAccessController) CheckBrowse(ctx context.Context, sess *session, nodeID *ua.NodeID) ua.StatusCode {
	return ac.checkPermission(sess, nodeID, ua.PermissionTypeBrowse)
}

func (ac *RBACAccessController) CheckCall(ctx context.Context, sess *session, nodeID *ua.NodeID) ua.StatusCode {
	return ac.checkPermission(sess, nodeID, ua.PermissionTypeCall)
}

func (ac *RBACAccessController) checkPermission(sess *session, nodeID *ua.NodeID, required ua.PermissionType) ua.StatusCode {
	if nodeID == nil {
		return ua.StatusOK
	}
	n := ac.srv.Node(nodeID)
	if n == nil {
		return ua.StatusOK
	}
	if len(n.rolePermissions) == 0 {
		return ua.StatusOK
	}
	var roles []*ua.NodeID
	if sess != nil {
		roles = sess.roles
	}
	if len(roles) == 0 {
		roles = []*ua.NodeID{ua.RoleAnonymous.NodeID()}
	}
	for _, rp := range n.rolePermissions {
		for _, role := range roles {
			if rp.RoleID != nil && rp.RoleID.String() == role.String() {
				if rp.Permissions&required != 0 {
					return ua.StatusOK
				}
			}
		}
	}
	return ua.StatusBadUserAccessDenied
}
