// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// ReportAuditEvent reports an audit event (Part 5 §6.4.3) of an application
// method, for example one of the AuditUpdateMethodEventType subtypes a
// companion specification defines, when auditing is on ([WithAuditing]); it
// returns whether the event was reported.
//
// The event goes to the event items of the Server object and of the
// notifiers given. Like the audit events of the server itself, only the
// sessions an [EventAccessController] allows receive it. ReportAuditEvent
// sets what ev leaves unset: the EventId, the Time, the Severity (100) and
// the AuditEventType fields ActionTimeStamp, ServerId, ClientAuditEntryId
// and ClientUserId, the last two from the [MethodCaller] of ctx. ev.Fields
// should carry Status and the fields of the event type. A subscription
// whose event queue is full is waited for a while (as for the events of
// conditions), so do not call it with a lock held that other calls need.
func (s *Server) ReportAuditEvent(ctx context.Context, ev *BaseEvent, notifiers ...*ua.NodeID) bool {
	if ev == nil || !s.auditing.Load() {
		return false
	}
	now := time.Now()
	e := *ev
	e.audit = true
	if e.EventID == nil {
		e.EventID = newEventID()
	}
	if e.Time == nil {
		e.Time = now
	}
	if e.Severity == 0 {
		e.Severity = 100
	}
	f := make(map[string]*ua.Variant, len(ev.Fields)+5)
	for k, v := range ev.Fields {
		f[k] = v
	}
	auditEntry := ""
	if caller, ok := MethodCallerFromContext(ctx); ok && caller != nil {
		auditEntry = caller.AuditEntryID
	}
	def := map[string]*ua.Variant{
		"ActionTimeStamp":    ua.MustVariant(now),
		"ServerId":           ua.MustVariant(s.cfg.applicationURI),
		"ClientAuditEntryId": ua.MustVariant(auditEntry),
		"ClientUserId":       ua.MustVariant(clientUserID(ctx)),
	}
	for k, v := range def {
		if f[k] == nil {
			f[k] = v
		}
	}
	e.Fields = f

	serverObj := ua.NewNumericNodeID(0, id.Server)
	s.emitEvent(serverObj, &e, true)
	for i, n := range notifiers {
		if n == nil || n.Equal(serverObj) {
			continue
		}
		dup := false
		for _, m := range notifiers[:i] {
			if m != nil && m.Equal(n) {
				dup = true
			}
		}
		if !dup {
			s.emitEvent(n, &e, true)
		}
	}
	return true
}
