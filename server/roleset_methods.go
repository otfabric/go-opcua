// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"slices"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uamethod"
)

// The RoleSet Methods (OPC 10000-18 §4.2.2, §4.2.3, §4.4.5 to §4.4.10).
//
// "The Client shall use an encrypted channel and shall provide user
// credentials with administrator rights like SecurityAdmin Role when
// invoking this Method": a call without a session, or without the
// SecurityAdmin role (or what RoleManagement.Authorizer allows), is refused
// with Bad_UserAccessDenied, one on a channel that is not SignAndEncrypt
// with Bad_SecurityModeInsufficient. The Methods of namespace 0 also have
// the AccessRestrictions SigningRequired and EncryptionRequired, which the
// Call service checks first.

// authorizeSession checks a session that changes the roles through method:
// a session on a SignAndEncrypt channel with the SecurityAdmin role, or
// what the Authorizer allows.
func (rs *RoleSet) authorizeSession(ctx context.Context, sess *session, method string) ua.StatusCode {
	if sess == nil {
		return ua.StatusBadUserAccessDenied
	}
	c, _ := MethodCallerFromContext(withMethodCaller(ctx, sess, sess.channel.Load()))
	return rs.authorize(ctx, c, method)
}

// authorize checks the caller of a RoleSet Method.
func (rs *RoleSet) authorize(ctx context.Context, c *MethodCaller, method string) ua.StatusCode {
	if c == nil || c.SessionID == nil {
		return ua.StatusBadUserAccessDenied
	}
	if c.SecurityMode != ua.MessageSecurityModeSignAndEncrypt {
		return ua.StatusBadSecurityModeInsufficient
	}
	if a := rs.authorizer; a != nil {
		return a(ctx, c, method)
	}
	admin := ua.RoleSecurityAdmin.NodeID()
	if !slices.ContainsFunc(c.Roles, func(r *ua.NodeID) bool { return r.Equal(admin) }) {
		return ua.StatusBadUserAccessDenied
	}
	return ua.StatusOK
}

// roleCall is the implementation of a RoleSet Method: the output arguments
// and the result.
type roleCall func(ctx context.Context, object *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode)

// handler wraps a RoleSet Method with authorize and the audit event of the
// call.
func (rs *RoleSet) handler(name string, f roleCall) MethodHandler {
	return func(ctx context.Context, object, method *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		c, _ := MethodCallerFromContext(ctx)
		out, sc := []*ua.Variant(nil), rs.authorize(ctx, c, name)
		if sc == ua.StatusOK {
			out, sc = f(ctx, object, args)
		}
		rs.audit(ctx, name, object, method, args, out, sc)
		return out, sc
	}
}

// audit reports the audit event of a call with auditing on: a change of a
// role by one of its Methods a RoleMappingRuleChangedAuditEventType event,
// "raised when the AddIdentity, RemoveIdentity, AddApplication,
// RemoveApplication, AddEndpoint or RemoveEndpoint Method causes an update
// to a Role" (OPC 10000-18 §4.5); AddRole, RemoveRole and the calls that
// change nothing an AuditUpdateMethodEventType event (Part 5 §6.4.27).
func (rs *RoleSet) audit(ctx context.Context, name string, object, method *ua.NodeID, args, out []*ua.Variant, sc ua.StatusCode) {
	s := rs.s
	if !s.auditing.Load() {
		return
	}
	auditType := uint32(id.AuditUpdateMethodEventType)
	if sc == ua.StatusOK && name != "AddRole" && name != "RemoveRole" {
		auditType = id.RoleMappingRuleChangedAuditEventType
	}
	subject := object.String()
	if n := s.Node(object); n != nil && n.BrowseName() != nil {
		subject = n.BrowseName().Name
	}
	ev := s.methodAuditEvent(ctx, auditType, method, object, subject, args, out, sc)
	// The Methods of an added role have String NodeIds, whose names
	// methodAuditEvent cannot look up.
	msg := name + " of " + subject
	if isBad(sc) {
		msg += ": " + sc.Error()
	}
	ev.SourceName = "Method/" + name
	ev.Message = ua.NewLocalizedTextWithLocale(msg, "en")
	s.emitAudit(ev)
}

// roleMethod returns the handler of the Method name of the role r, nil for
// a name that is no Method of RoleType.
func (rs *RoleSet) roleMethod(r *managedRole, name string) MethodHandler {
	role := r.id
	var f roleCall
	switch name {
	case "AddIdentity":
		f = func(_ context.Context, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			var in uamethod.RoleTypeAddIdentityInput
			if err := in.Unpack(args); err != nil {
				return nil, uamethod.StatusOf(err)
			}
			return nil, roleStatus(rs.AddIdentity(role, in.Rule))
		}
	case "RemoveIdentity":
		f = func(_ context.Context, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			var in uamethod.RoleTypeRemoveIdentityInput
			if err := in.Unpack(args); err != nil {
				return nil, uamethod.StatusOf(err)
			}
			return nil, roleStatus(rs.RemoveIdentity(role, in.Rule))
		}
	case "AddApplication":
		f = func(_ context.Context, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			var in uamethod.RoleTypeAddApplicationInput
			if err := in.Unpack(args); err != nil {
				return nil, uamethod.StatusOf(err)
			}
			return nil, roleStatus(rs.AddApplication(role, in.ApplicationURI))
		}
	case "RemoveApplication":
		f = func(_ context.Context, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			var in uamethod.RoleTypeRemoveApplicationInput
			if err := in.Unpack(args); err != nil {
				return nil, uamethod.StatusOf(err)
			}
			return nil, roleStatus(rs.RemoveApplication(role, in.ApplicationURI))
		}
	case "AddEndpoint":
		f = func(_ context.Context, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			var in uamethod.RoleTypeAddEndpointInput
			if err := in.Unpack(args); err != nil {
				return nil, uamethod.StatusOf(err)
			}
			return nil, roleStatus(rs.AddEndpoint(role, in.Endpoint))
		}
	case "RemoveEndpoint":
		f = func(_ context.Context, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			var in uamethod.RoleTypeRemoveEndpointInput
			if err := in.Unpack(args); err != nil {
				return nil, uamethod.StatusOf(err)
			}
			return nil, roleStatus(rs.RemoveEndpoint(role, in.Endpoint))
		}
	default:
		return nil
	}
	return rs.handler(name, f)
}

// callAddRole implements AddRole (OPC 10000-18 §4.2.2).
func (rs *RoleSet) callAddRole(_ context.Context, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	var in uamethod.RoleSetTypeAddRoleInput
	if err := in.Unpack(args); err != nil {
		return nil, uamethod.StatusOf(err)
	}
	nid, err := rs.AddRole(in.RoleName, in.NamespaceURI)
	if err != nil {
		return nil, roleStatus(err)
	}
	return (&uamethod.RoleSetTypeAddRoleOutput{RoleNodeID: nid}).Pack(), ua.StatusOK
}

// callRemoveRole implements RemoveRole (OPC 10000-18 §4.2.3).
func (rs *RoleSet) callRemoveRole(_ context.Context, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	var in uamethod.RoleSetTypeRemoveRoleInput
	if err := in.Unpack(args); err != nil {
		return nil, uamethod.StatusOf(err)
	}
	return nil, roleStatus(rs.RemoveRole(in.RoleNodeID))
}
