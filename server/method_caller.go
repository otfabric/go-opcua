// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"slices"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

// MethodCaller describes the session and the secure channel a method call
// came in on. A MethodHandler gets it with [MethodCallerFromContext], for
// example to authorize the call.
type MethodCaller struct {
	// SessionID is the NodeId of the session; nil without a session.
	SessionID *ua.NodeID
	// SecurityPolicyURI and SecurityMode are those of the secure channel.
	SecurityPolicyURI string
	SecurityMode      ua.MessageSecurityMode
	// Identity is the user identity token of the session.
	Identity ua.IdentityToken
	// Roles are the role NodeIds granted to the session.
	Roles []*ua.NodeID
	// AuditEntryID is the AuditEntryId of the request header (Part 4
	// §7.33), which audit events report as ClientAuditEntryId.
	AuditEntryID string
	// ClientCertificate is the application instance certificate (DER, the
	// leaf first if the client sent a chain) the client opened the secure
	// channel with; nil on a channel without security. The channel
	// handshake proved that the client holds its key.
	ClientCertificate []byte
}

type methodCallerKey struct{}

// MethodCallerFromContext returns the caller of the method call whose
// handler got ctx.
func MethodCallerFromContext(ctx context.Context) (*MethodCaller, bool) {
	c, ok := ctx.Value(methodCallerKey{}).(*MethodCaller)
	return c, ok
}

// withMethodCaller returns ctx carrying the MethodCaller of a call made by
// sess over sc.
func withMethodCaller(ctx context.Context, sess *session, sc *uasc.SecureChannel) context.Context {
	c := &MethodCaller{SecurityMode: ua.MessageSecurityModeNone}
	if sc != nil {
		c.SecurityMode = sc.SecurityMode()
		c.SecurityPolicyURI = sc.SecurityPolicyURI()
		c.ClientCertificate = sc.RemoteCertificate()
	}
	if sess != nil {
		c.SessionID = sess.ID
		c.Identity = sess.identityToken
		c.Roles = slices.Clone(sess.roles)
	}
	return context.WithValue(ctx, methodCallerKey{}, c)
}
