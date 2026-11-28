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
	// Identity is the user identity token of the session, without the
	// password of a UserNameIdentityToken.
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
	// ClientApplicationURI is the ApplicationUri of the ApplicationDescription
	// the client sent with CreateSession (Part 4 §5.6.2); "" without a
	// session.
	ClientApplicationURI string
	// SpanContext is the SpanContextDataType the client passed in the
	// AdditionalHeader of the request header (OPC 10000-26 §5.6.4, OPC
	// 10000-4 §7.32): the trace the LogRecords of the call belong to. Nil
	// when the request has none, or one with SpanId 0 (an invalid SpanId,
	// OPC 10000-26 §5.6.2).
	SpanContext *ua.SpanContextDataType
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
		c.Roles = slices.Clone(sess.currentRoles())
		sess.diag.mu.Lock()
		if d := sess.diag.client; d != nil {
			c.ClientApplicationURI = d.ApplicationURI
		}
		sess.diag.mu.Unlock()
	}
	return context.WithValue(ctx, methodCallerKey{}, c)
}

// spanContextName is the name of the AdditionalHeader parameter that
// carries a SpanContextDataType (OPC 10000-26 §5.6.4), in namespace 0.
const spanContextName = "SpanContext"

// spanContextOf returns the SpanContext the AdditionalHeader of hdr
// carries (OPC 10000-26 §5.6.4), nil when it has none or one that is not a
// SpanContextDataType with a SpanId.
func spanContextOf(hdr *ua.RequestHeader) *ua.SpanContextDataType {
	if hdr == nil || hdr.AdditionalHeader == nil {
		return nil
	}
	ap, ok := hdr.AdditionalHeader.Value.(*ua.AdditionalParametersType)
	if !ok || ap == nil {
		return nil
	}
	for _, p := range ap.Parameters {
		if p == nil || p.Key == nil || p.Key.NamespaceIndex != 0 || p.Key.Name != spanContextName || p.Value == nil {
			continue
		}
		eo, _ := p.Value.Value().(*ua.ExtensionObject)
		if eo == nil {
			return nil
		}
		sc, _ := eo.Value.(*ua.SpanContextDataType)
		if sc == nil || sc.SpanID == 0 {
			return nil
		}
		cp := *sc
		return &cp
	}
	return nil
}
