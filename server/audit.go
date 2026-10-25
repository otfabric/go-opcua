// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"strings"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// Audit events (Part 5 §6.4.3, Part 9 §5.10).
//
// With auditing on ([WithAuditing], [Server.SetAuditing]) every call of a
// condition method reports an audit event of the AuditConditionEventType
// subtype of the method (AuditConditionEnableEventType,
// AuditConditionCommentEventType, AuditConditionAcknowledgeEventType,
// AuditConditionConfirmEventType, AuditConditionShelvingEventType,
// AuditConditionSuppressionEventType, AuditConditionOutOfServiceEventType,
// AuditConditionSilenceEventType, AuditConditionResetEventType,
// AuditConditionRespondEventType), refused calls too (Status false). The
// SourceNode of the event is the ConditionId; it is reported to the
// notifiers of the condition, as its events are. The Server object's
// Auditing Property tells whether auditing is on.
//
// Audit events carry the user and the arguments of the call: an
// AccessController that implements [EventAccessController] (the
// RBACAccessController does, with the ReceiveEvents permission of the event
// type, which namespace 0 grants to SecurityAdmin only) decides which
// sessions receive them.

// WithAuditing turns the audit events on or off (default off).
func WithAuditing(enabled bool) Option {
	return func(c *serverConfig) error {
		c.auditing = enabled
		return nil
	}
}

// SetAuditing turns the audit events on or off.
func (s *Server) SetAuditing(enabled bool) {
	s.auditing.Store(enabled)
	s.ChangeNotification(ua.NewNumericNodeID(0, id.ServerAuditing))
}

// Auditing reports whether the server reports audit events.
func (s *Server) Auditing() bool { return s.auditing.Load() }

// bindAuditing makes the Server object's Auditing Property report the
// auditing setting.
func (s *Server) bindAuditing() {
	s.auditing.Store(s.cfg.auditing)
	if n := s.ownNode(id.ServerAuditing); n != nil {
		n.mu.Lock()
		n.val = func() *ua.DataValue { return DataValueFromValue(s.auditing.Load()) }
		n.mu.Unlock()
	}
}

// EventAccessController is an [AccessController] that also decides which
// sessions receive the events of a type. The server asks it for audit
// events; without it every session that monitors the notifier receives
// them.
type EventAccessController interface {
	CheckReceiveEvents(ctx context.Context, session *session, eventType *ua.NodeID) ua.StatusCode
}

// CheckReceiveEvents grants the events of eventType to the sessions with the
// ReceiveEvents permission of the event type node.
func (ac *RBACAccessController) CheckReceiveEvents(_ context.Context, sess *session, eventType *ua.NodeID) ua.StatusCode {
	return ac.checkPermission(sess, eventType, ua.PermissionTypeReceiveEvents)
}

// mayReceive reports whether the session of an event item may receive an
// audit event.
func (s *Server) mayReceive(item *MonitoredItem, event *BaseEvent) bool {
	if !event.audit {
		return true
	}
	eac, ok := s.cfg.accessController.(EventAccessController)
	if !ok {
		return true
	}
	sess, _ := item.Sub.sessionChannel()
	if sess == nil {
		return false
	}
	return eac.CheckReceiveEvents(context.Background(), sess, event.EventType) == ua.StatusOK
}

// audited wraps the handler of a condition method so that the call reports
// an audit event of type auditType.
func (c *Condition) audited(auditType uint32, h MethodHandler) MethodHandler {
	return func(ctx context.Context, objectID, methodID *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		out, sc := h(ctx, objectID, methodID, args)
		if c.srv.auditing.Load() {
			c.deliverAudit(c.auditEvent(ctx, auditType, methodID, args, out, sc))
		}
		return out, sc
	}
}

// deliverAudit reports an audit event to the notifiers of the condition.
func (c *Condition) deliverAudit(ev *BaseEvent) {
	for _, t := range c.targets {
		c.srv.emitEvent(t, ev, true)
	}
}

// auditEvent builds the audit event of a call of a condition method.
func (c *Condition) auditEvent(ctx context.Context, auditType uint32, methodID *ua.NodeID, args, out []*ua.Variant, sc ua.StatusCode) *BaseEvent {
	now := time.Now()
	// The BrowseName of the method: the generated names carry the type
	// ("AcknowledgeableConditionType_Acknowledge").
	name := id.MethodName(methodID.IntID())
	if i := strings.LastIndexByte(name, '_'); i >= 0 {
		name = name[i+1:]
	}
	auditEntry := ""
	if caller, ok := MethodCallerFromContext(ctx); ok && caller != nil {
		auditEntry = caller.AuditEntryID
	}
	if args == nil {
		args = []*ua.Variant{}
	}
	if out == nil {
		out = []*ua.Variant{}
	}
	ok := sc.Uint32()&0xC0000000 == 0
	msg := name + " of " + c.cfg.Name
	if !ok {
		msg += ": " + sc.Error()
	}
	f := map[string]*ua.Variant{
		// AuditEventType (Part 5 §6.4.3)
		"ActionTimeStamp":    ua.MustVariant(now),
		"Status":             ua.MustVariant(ok),
		"ServerId":           ua.MustVariant(c.srv.cfg.applicationURI),
		"ClientAuditEntryId": ua.MustVariant(auditEntry),
		"ClientUserId":       ua.MustVariant(clientUserID(ctx)),
		// AuditUpdateMethodEventType (Part 5 §6.4.27)
		"MethodId":        ua.MustVariant(methodID),
		"StatusCodeId":    ua.MustVariant(sc),
		"InputArguments":  ua.MustVariant(args),
		"OutputArguments": ua.MustVariant(out),
	}
	arg := func(i int) *ua.Variant {
		if i < len(args) && args[i] != nil {
			return args[i]
		}
		return ua.MustVariant(nil)
	}
	// The fields of the subtypes (Part 9 §5.10).
	switch auditType {
	case id.AuditConditionCommentEventType, id.AuditConditionAcknowledgeEventType, id.AuditConditionConfirmEventType:
		f["ConditionEventId"] = arg(0)
		f["Comment"] = arg(1)
	case id.AuditConditionRespondEventType:
		f["SelectedResponse"] = arg(0)
	case id.AuditConditionShelvingEventType:
		if methodID.IntID() == id.ShelvedStateMachineTypeTimedShelve || methodID.IntID() == id.ShelvedStateMachineTypeTimedShelve2 ||
			methodID.IntID() == id.AlarmConditionTypeShelvingStateTimedShelve || methodID.IntID() == id.AlarmConditionTypeShelvingStateTimedShelve2 {
			f["ShelvingTime"] = arg(0)
		}
	}
	return &BaseEvent{
		EventID:    newEventID(),
		EventType:  ua.NewNumericNodeID(0, auditType),
		SourceNode: c.id,
		SourceName: "Method/" + name,
		Time:       now,
		Message:    ua.NewLocalizedTextWithLocale(msg, "en"),
		Severity:   100,
		Fields:     f,
		audit:      true,
	}
}
