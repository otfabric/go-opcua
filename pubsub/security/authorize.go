// SPDX-License-Identifier: MIT

package security

import (
	"context"
	"slices"

	"github.com/otfabric/go-opcua/ua"
)

// Operation is a Security Key Service operation subject to authorization.
type Operation int

// Operations of the Security Key Service (Part 14 §8.3, §8.4).
const (
	// OpGetSecurityKeys reads the keys of a SecurityGroup.
	OpGetSecurityKeys Operation = iota + 1
	// OpSetSecurityKeys pushes keys to a Publisher or Subscriber.
	OpSetSecurityKeys
	// OpAddSecurityGroup creates a SecurityGroup.
	OpAddSecurityGroup
	// OpRemoveSecurityGroup deletes a SecurityGroup.
	OpRemoveSecurityGroup
	// OpGetSecurityGroup looks up the node of a SecurityGroup.
	OpGetSecurityGroup
)

func (o Operation) String() string {
	switch o {
	case OpGetSecurityKeys:
		return "GetSecurityKeys"
	case OpSetSecurityKeys:
		return "SetSecurityKeys"
	case OpAddSecurityGroup:
		return "AddSecurityGroup"
	case OpRemoveSecurityGroup:
		return "RemoveSecurityGroup"
	case OpGetSecurityGroup:
		return "GetSecurityGroup"
	}
	return "Operation(?)"
}

// Caller describes the session that calls a Security Key Service method.
type Caller struct {
	// SessionID is the NodeId of the session.
	SessionID *ua.NodeID
	// SecurityPolicyURI and SecurityMode are those of the secure channel.
	SecurityPolicyURI string
	SecurityMode      ua.MessageSecurityMode
	// Identity is the user identity token of the session: nil or
	// *ua.AnonymousIdentityToken for an anonymous user,
	// *ua.UserNameIdentityToken, *ua.X509IdentityToken, ...
	Identity ua.IdentityToken
	// Roles are the role NodeIds granted to the session.
	Roles []*ua.NodeID
}

// Anonymous reports whether the caller has no user identity.
func (c *Caller) Anonymous() bool {
	if c == nil || c.Identity == nil {
		return true
	}
	_, anon := c.Identity.(*ua.AnonymousIdentityToken)
	return anon
}

// UserName is the user name of a UserNameIdentityToken, "" otherwise.
func (c *Caller) UserName() string {
	if c == nil {
		return ""
	}
	if t, ok := c.Identity.(*ua.UserNameIdentityToken); ok {
		return t.UserName
	}
	return ""
}

// HasRole reports whether the caller was granted a role.
func (c *Caller) HasRole(role *ua.NodeID) bool {
	if c == nil || role == nil {
		return false
	}
	return slices.ContainsFunc(c.Roles, func(r *ua.NodeID) bool { return r != nil && r.Equal(role) })
}

// Authorizer decides whether a caller may perform an operation on a
// SecurityGroup (securityGroupID is "" for operations without one). It
// returns nil to allow it, else an error, typically
// ua.StatusBadUserAccessDenied. It is consulted after the secure channel
// was found to be encrypted.
type Authorizer func(ctx context.Context, c *Caller, op Operation, securityGroupID string) error

// DefaultAuthorizer allows every operation to a caller with a user identity
// and denies anonymous callers, like the central SKS example of open62541
// (examples/pubsub/sks/server_pubsub_central_sks.c).
func DefaultAuthorizer(_ context.Context, c *Caller, _ Operation, _ string) error {
	if c.Anonymous() {
		return ua.StatusBadUserAccessDenied
	}
	return nil
}

// AllowAll is an Authorizer that allows every operation, including to
// anonymous callers (the default access control of open62541). The secure
// channel must still be encrypted.
func AllowAll(context.Context, *Caller, Operation, string) error { return nil }

// RequireRoles returns an Authorizer that allows an operation when the
// caller has at least one of the given roles.
func RequireRoles(roles ...*ua.NodeID) Authorizer {
	return func(_ context.Context, c *Caller, _ Operation, _ string) error {
		for _, r := range roles {
			if c.HasRole(r) {
				return nil
			}
		}
		return ua.StatusBadUserAccessDenied
	}
}

// Authorize checks a call to a Security Key Service method: the secure
// channel must use SignAndEncrypt (Part 14 §8.3.2, §8.4: the keys must only
// travel encrypted; Bad_SecurityModeInsufficient otherwise), then the
// Authorizer (DefaultAuthorizer if nil) decides (Bad_UserAccessDenied).
func Authorize(ctx context.Context, a Authorizer, c *Caller, op Operation, securityGroupID string) error {
	if c == nil || c.SecurityMode != ua.MessageSecurityModeSignAndEncrypt {
		return ua.StatusBadSecurityModeInsufficient
	}
	if a == nil {
		a = DefaultAuthorizer
	}
	return a(ctx, c, op, securityGroupID)
}
