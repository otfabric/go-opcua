// SPDX-License-Identifier: MIT

package gdsserver

import (
	"context"
	"slices"

	"github.com/otfabric/go-opcua/gds/gdsid"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// auditMethod describes the audit event of a method of the Directory.
type auditMethod struct {
	name      string
	eventType uint32 // in the GDS namespace
	// secretIn and secretOut are the indexes of the arguments the event
	// leaves out (a password, a private key); -1 for none.
	secretIn, secretOut int
}

// auditMethods are the methods of the Directory that report audit events
// (Part 12 §6.6.x, §7.9.x): the changes of the directory, certificate
// requests, issued certificates and revocations.
var auditMethods = map[uint32]auditMethod{
	gdsid.DirectoryRegisterApplication:    {"RegisterApplication", gdsid.ApplicationRegistrationChangedAuditEventType, -1, -1},
	gdsid.DirectoryUpdateApplication:      {"UpdateApplication", gdsid.ApplicationRegistrationChangedAuditEventType, -1, -1},
	gdsid.DirectoryUnregisterApplication:  {"UnregisterApplication", gdsid.ApplicationRegistrationChangedAuditEventType, -1, -1},
	gdsid.DirectoryStartSigningRequest:    {"StartSigningRequest", gdsid.CertificateRequestedAuditEventType, -1, -1},
	gdsid.DirectoryStartNewKeyPairRequest: {"StartNewKeyPairRequest", gdsid.CertificateRequestedAuditEventType, 6, -1},
	gdsid.DirectoryFinishRequest:          {"FinishRequest", gdsid.CertificateDeliveredAuditEventType, -1, 1},
	gdsid.DirectoryRevokeCertificate:      {"RevokeCertificate", gdsid.CertificateRevokedAuditEventType, -1, -1},
}

// redact returns vs with the value at index i replaced by null. An
// ExtensionObject package ua could not decode (an ApplicationRecord) keeps
// its body.
func redact(vs []*ua.Variant, i int) []*ua.Variant {
	out := slices.Clone(vs)
	if out == nil {
		out = []*ua.Variant{}
	}
	for j, v := range out {
		if eo, ok := v.Value().(*ua.ExtensionObject); ok && eo != nil && eo.Value == nil && eo.RawBody != nil {
			out[j] = ua.MustVariant(&ua.ExtensionObject{TypeID: eo.TypeID, EncodingMask: ua.ExtensionObjectBinary, Value: slices.Clone(eo.RawBody)})
		}
	}
	if i >= 0 && i < len(out) {
		out[i] = ua.MustVariant(nil)
	}
	return out
}

// audit reports the audit event of a call of a method of the Directory
// when the server audits (server.WithAuditing): to the Server object and
// the Directory. FinishRequest reports an event only when it completes the
// request or fails for another reason than a request that waits for
// approval (Bad_NothingToDo), which a client polls for. The audit events of
// Part 12 carry the arguments, without the password of
// StartNewKeyPairRequest and the private key FinishRequest returns.
func (g *GDS) audit(ctx context.Context, c *caller, mid uint32, args, out []*ua.Variant, sc ua.StatusCode) {
	m, ok := auditMethods[mid]
	if !ok || !g.srv.Auditing() || (mid == gdsid.DirectoryFinishRequest && sc == ua.StatusBadNothingToDo) {
		return
	}
	good := sc.Uint32()&0xC0000000 == 0
	msg := m.name
	if !good {
		msg += ": " + sc.Error()
	}
	f := map[string]*ua.Variant{
		"Status":          ua.MustVariant(good),
		"MethodId":        ua.MustVariant(g.node(mid)),
		"StatusCodeId":    ua.MustVariant(sc),
		"InputArguments":  ua.MustVariant(redact(args, m.secretIn)),
		"OutputArguments": ua.MustVariant(redact(out, m.secretOut)),
	}
	if m.eventType == gdsid.CertificateRequestedAuditEventType || m.eventType == gdsid.CertificateDeliveredAuditEventType {
		f["CertificateGroup"] = ua.MustVariant(nodeOrNull(c.auditGroup))
		f["CertificateType"] = ua.MustVariant(nodeOrNull(c.auditType))
	}
	dir := g.node(gdsid.Directory)
	g.srv.ReportAuditEvent(ctx, &server.BaseEvent{
		EventType:  g.node(m.eventType),
		SourceNode: dir,
		SourceName: "Method/" + m.name,
		Message:    ua.NewLocalizedTextWithLocale(msg, "en"),
		Fields:     f,
	}, dir)
}

// nodeOrNull returns n, or the null NodeId for nil.
func nodeOrNull(n *ua.NodeID) *ua.NodeID {
	if n == nil {
		return ua.NewTwoByteNodeID(0)
	}
	return n
}
