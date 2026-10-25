// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"math"
	"slices"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// conditionAction is a method that refers to an event of the condition.
type conditionAction int

const (
	actionAcknowledge conditionAction = iota
	actionConfirm
	actionAddComment
)

// registerMethods references the methods of the condition's type from the
// instance (as for the PubSub objects, the instances share the method nodes
// of namespace 0) and registers their handlers.
func (c *Condition) registerMethods() {
	s := c.srv
	// reg registers the handler of a method, which reports an audit event
	// of type audit (none when 0).
	reg := func(obj *ua.NodeID, method uint32, h MethodHandler, ref bool, audit uint32) {
		if ref {
			if on := s.Node(obj); on != nil {
				s.addMethodRef(on, method)
			}
		}
		mid := ua.NewNumericNodeID(0, method)
		if audit != 0 {
			h = c.audited(audit, h)
		}
		s.RegisterMethod(obj, mid, h)
		c.methods = append(c.methods, [2]*ua.NodeID{obj, mid})
	}
	// ConditionType (Part 9 §5.5.4 - §5.5.6)
	reg(c.id, id.ConditionTypeEnable, c.enableMethod(true), true, id.AuditConditionEnableEventType)
	reg(c.id, id.ConditionTypeDisable, c.enableMethod(false), true, id.AuditConditionEnableEventType)
	reg(c.id, id.ConditionTypeAddComment, c.actionMethod(actionAddComment), true, id.AuditConditionCommentEventType)
	if c.isAck {
		// AcknowledgeableConditionType (Part 9 §5.7.3, §5.7.4)
		reg(c.id, id.AcknowledgeableConditionTypeAcknowledge, c.actionMethod(actionAcknowledge), true, id.AuditConditionAcknowledgeEventType)
		if c.cfg.Confirmable {
			reg(c.id, id.AcknowledgeableConditionTypeConfirm, c.actionMethod(actionConfirm), true, id.AuditConditionConfirmEventType)
		}
	}
	if c.isDialog {
		// DialogConditionType (Part 9 §5.6.3, §5.6.4)
		reg(c.id, id.DialogConditionTypeRespond, c.respondMethod(false), true, id.AuditConditionRespondEventType)
		reg(c.id, id.DialogConditionTypeRespond2, c.respondMethod(true), true, id.AuditConditionRespondEventType)
	}
	if c.isAlarm {
		// AlarmConditionType (Part 9 1.05 §5.8.4 - §5.8.9)
		for _, m := range []struct {
			method uint32
			op     alarmOp
			on     bool
			audit  uint32
			comm   bool
		}{
			{id.AlarmConditionTypeSuppress, opSuppress, c.cfg.Suppressible, id.AuditConditionSuppressionEventType, false},
			{id.AlarmConditionTypeSuppress2, opSuppress, c.cfg.Suppressible, id.AuditConditionSuppressionEventType, true},
			{id.AlarmConditionTypeUnsuppress, opUnsuppress, c.cfg.Suppressible, id.AuditConditionSuppressionEventType, false},
			{id.AlarmConditionTypeUnsuppress2, opUnsuppress, c.cfg.Suppressible, id.AuditConditionSuppressionEventType, true},
			{id.AlarmConditionTypeRemoveFromService, opRemoveFromService, c.cfg.Serviceable, id.AuditConditionOutOfServiceEventType, false},
			{id.AlarmConditionTypeRemoveFromService2, opRemoveFromService, c.cfg.Serviceable, id.AuditConditionOutOfServiceEventType, true},
			{id.AlarmConditionTypePlaceInService, opPlaceInService, c.cfg.Serviceable, id.AuditConditionOutOfServiceEventType, false},
			{id.AlarmConditionTypePlaceInService2, opPlaceInService, c.cfg.Serviceable, id.AuditConditionOutOfServiceEventType, true},
			{id.AlarmConditionTypeSilence, opSilence, c.cfg.Silenceable, id.AuditConditionSilenceEventType, false},
			{id.AlarmConditionTypeReset, opReset, c.cfg.Latching, id.AuditConditionResetEventType, false},
			{id.AlarmConditionTypeReset2, opReset, c.cfg.Latching, id.AuditConditionResetEventType, true},
		} {
			if m.on {
				reg(c.id, m.method, c.alarmMethod(m.op, m.comm), true, m.audit)
			}
		}
		reg(c.id, id.AlarmConditionTypeGetGroupMemberships, c.groupMembershipsMethod, true, 0)
	}
	if c.shelvingID != nil {
		// ShelvedStateMachineType (Part 9 §5.8.10.2 - §5.8.10.7); the
		// methods of the AlarmConditionType's ShelvingState are accepted
		// too.
		for _, m := range []struct {
			typ, inst uint32
			state     ShelvingState
			comment   bool
		}{
			{id.ShelvedStateMachineTypeUnshelve, id.AlarmConditionTypeShelvingStateUnshelve, Unshelved, false},
			{id.ShelvedStateMachineTypeOneShotShelve, id.AlarmConditionTypeShelvingStateOneShotShelve, OneShotShelved, false},
			{id.ShelvedStateMachineTypeTimedShelve, id.AlarmConditionTypeShelvingStateTimedShelve, TimedShelved, false},
			{id.ShelvedStateMachineTypeUnshelve2, id.AlarmConditionTypeShelvingStateUnshelve2, Unshelved, true},
			{id.ShelvedStateMachineTypeOneShotShelve2, id.AlarmConditionTypeShelvingStateOneShotShelve2, OneShotShelved, true},
			{id.ShelvedStateMachineTypeTimedShelve2, id.AlarmConditionTypeShelvingStateTimedShelve2, TimedShelved, true},
		} {
			h := c.shelveMethod(m.state, m.comment)
			reg(c.shelvingID, m.typ, h, true, id.AuditConditionShelvingEventType)
			reg(c.shelvingID, m.inst, h, false, id.AuditConditionShelvingEventType)
		}
	}
}

// eventArgs decodes the EventId and Comment arguments of Acknowledge,
// Confirm and AddComment.
func eventArgs(args []*ua.Variant) ([]byte, *ua.LocalizedText, ua.StatusCode) {
	if len(args) != 2 || args[0] == nil || args[1] == nil {
		return nil, nil, ua.StatusBadArgumentsMissing
	}
	eventID, ok := args[0].Value().([]byte)
	if !ok {
		return nil, nil, ua.StatusBadTypeMismatch
	}
	var comment *ua.LocalizedText
	switch v := args[1].Value().(type) {
	case *ua.LocalizedText:
		comment = v
	case nil:
	default:
		return nil, nil, ua.StatusBadTypeMismatch
	}
	if comment == nil {
		comment = &ua.LocalizedText{}
	}
	return eventID, comment, ua.StatusOK
}

// checkActionLocked checks a method that refers to an event of the
// condition or of one of its branches against the state of that one, which
// it returns. mu must be held.
func (c *Condition) checkActionLocked(a conditionAction, eventID []byte) (*conditionState, ua.StatusCode) {
	switch {
	case c.st.removed:
		return nil, ua.StatusBadNodeIDUnknown
	case !c.st.enabled:
		return nil, ua.StatusBadConditionDisabled
	}
	st := c.stateOfEventLocked(eventID)
	switch {
	case st == nil:
		return nil, ua.StatusBadEventIDUnknown
	case a == actionAcknowledge && st.acked:
		return nil, ua.StatusBadConditionBranchAlreadyAcked
	case a == actionConfirm && st.confirmed:
		return nil, ua.StatusBadConditionBranchAlreadyConfirmed
	}
	return st, ua.StatusOK
}

// actionMethod implements Acknowledge, Confirm and AddComment. The EventId
// must be one of the recent events of the condition (Bad_EventIdUnknown); a
// null Comment leaves the Comment unchanged, except for AddComment (Part 9
// §5.5.6, §5.7.3, §5.7.4).
func (c *Condition) actionMethod(a conditionAction) MethodHandler {
	return func(ctx context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		eventID, comment, sc := eventArgs(args)
		if sc != ua.StatusOK {
			return nil, sc
		}
		c.mu.RLock()
		st, sc := c.checkActionLocked(a, eventID)
		var branch *ua.NodeID
		if st != nil {
			branch = st.branchID
		}
		c.mu.RUnlock()
		if sc != ua.StatusOK {
			return nil, sc
		}
		hook := c.cfg.OnAddComment
		switch a {
		case actionAcknowledge:
			hook = c.cfg.OnAcknowledge
		case actionConfirm:
			hook = c.cfg.OnConfirm
		case actionAddComment:
		}
		if hook != nil {
			if branch != nil {
				ctx = context.WithValue(ctx, branchCtxKey{}, branch)
			}
			if sc := hook(ctx, c, comment); sc != ua.StatusOK {
				return nil, sc
			}
		}
		user := clientUserID(ctx)

		c.emitMu.Lock()
		defer c.emitMu.Unlock()
		c.mu.Lock()
		// The state may have changed while the hook ran.
		st, sc = c.checkActionLocked(a, eventID)
		if sc != ua.StatusOK {
			c.mu.Unlock()
			return nil, sc
		}
		now := time.Now()
		if a == actionAddComment || comment.Text != "" || comment.Locale != "" {
			st.comment, st.commentTime = comment, now
		}
		st.clientUserID = user
		switch a {
		case actionAcknowledge:
			st.acked, st.ackedTime = true, now
		case actionConfirm:
			st.confirmed, st.confirmedTime = true, now
		case actionAddComment:
		}
		var ev *BaseEvent
		if st.branchID != nil && !c.retainOfLocked(st) {
			// A branch that needs nothing more ends (Part 9 §5.5.2).
			ev = c.endBranchLocked(st)
		} else {
			ev = c.newEventOfLocked(st)
		}
		c.mu.Unlock()
		c.deliver(ev)
		c.notifyChanges()
		return nil, ua.StatusOK
	}
}

// enableMethod implements Enable and Disable (Part 9 §5.5.4, §5.5.5).
func (c *Condition) enableMethod(enable bool) MethodHandler {
	return func(ctx context.Context, _, _ *ua.NodeID, _ []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		c.mu.RLock()
		sc := c.enableCheckLocked(enable)
		c.mu.RUnlock()
		if sc != ua.StatusOK {
			return nil, sc
		}
		if c.cfg.OnEnable != nil {
			if sc := c.cfg.OnEnable(ctx, c, enable); sc != ua.StatusOK {
				return nil, sc
			}
		}
		return nil, c.setEnabled(enable)
	}
}

// checkShelveLocked checks a transition of the ShelvedStateMachine
// (Part 9 §5.8.10.1). mu must be held.
func (c *Condition) checkShelveLocked(to ShelvingState, d time.Duration) ua.StatusCode {
	st := &c.st
	switch {
	case st.removed:
		return ua.StatusBadNodeIDUnknown
	case !st.enabled:
		return ua.StatusBadConditionDisabled
	case to == Unshelved && st.shelving == Unshelved:
		return ua.StatusBadConditionNotShelved
	case to != Unshelved && st.shelving == to:
		return ua.StatusBadConditionAlreadyShelved
	case to == TimedShelved && (d <= 0 || (c.cfg.MaxTimeShelved > 0 && d > c.cfg.MaxTimeShelved)):
		return ua.StatusBadShelvingTimeOutOfRange
	}
	return ua.StatusOK
}

// shelveMethod implements Unshelve, OneShotShelve and TimedShelve
// (Part 9 §5.8.10.2 - §5.8.10.4).
func (c *Condition) shelveMethod(to ShelvingState, withComment bool) MethodHandler {
	return func(ctx context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		var d time.Duration
		var comment *ua.LocalizedText
		if withComment {
			// The Comment is the last argument of the *2 variants.
			if len(args) == 0 {
				return nil, ua.StatusBadArgumentsMissing
			}
			var sc ua.StatusCode
			if comment, sc = commentArg(args[len(args)-1]); sc != ua.StatusOK {
				return nil, sc
			}
			args = args[:len(args)-1]
		}
		if to == TimedShelved {
			if len(args) != 1 || args[0] == nil {
				return nil, ua.StatusBadArgumentsMissing
			}
			ms, ok := args[0].Value().(float64)
			if !ok {
				return nil, ua.StatusBadTypeMismatch
			}
			if math.IsNaN(ms) || ms <= 0 || ms > float64(math.MaxInt64/int64(time.Millisecond)) {
				return nil, ua.StatusBadShelvingTimeOutOfRange
			}
			d = time.Duration(ms * float64(time.Millisecond))
		}
		c.mu.RLock()
		sc := c.checkShelveLocked(to, d)
		c.mu.RUnlock()
		if sc != ua.StatusOK {
			return nil, sc
		}
		if c.cfg.OnShelve != nil {
			if sc := c.cfg.OnShelve(ctx, c, to, d); sc != ua.StatusOK {
				return nil, sc
			}
		}
		c.emitMu.Lock()
		defer c.emitMu.Unlock()
		c.mu.Lock()
		if sc := c.checkShelveLocked(to, d); sc != ua.StatusOK {
			c.mu.Unlock()
			return nil, sc
		}
		now := time.Now()
		c.st.clientUserID = clientUserID(ctx)
		c.applyCommentLocked(comment, now)
		c.setShelvingLocked(to, d, now)
		ev := c.newEventLocked()
		c.mu.Unlock()
		c.deliver(ev)
		c.notifyChanges()
		return nil, ua.StatusOK
	}
}

// --- ConditionRefresh ---------------------------------------------------------

func (s *Server) conditionRefreshMethod(ctx context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	if len(args) != 1 {
		return nil, ua.StatusBadArgumentsMissing
	}
	subID, ok := args[0].Value().(uint32)
	if !ok {
		return nil, ua.StatusBadTypeMismatch
	}
	return nil, s.conditionRefresh(ctx, subID, 0, false)
}

func (s *Server) conditionRefresh2Method(ctx context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	if len(args) != 2 {
		return nil, ua.StatusBadArgumentsMissing
	}
	subID, ok1 := args[0].Value().(uint32)
	itemID, ok2 := args[1].Value().(uint32)
	if !ok1 || !ok2 {
		return nil, ua.StatusBadTypeMismatch
	}
	return nil, s.conditionRefresh(ctx, subID, itemID, true)
}

// refreshTarget is an event item a ConditionRefresh reports to.
type refreshTarget struct {
	item *MonitoredItem
	node *ua.NodeID
}

// conditionRefresh implements ConditionRefresh (Part 9 §5.5.7) and, with
// one, ConditionRefresh2 (§5.5.8) for the event item itemID: every event
// item of the subscription (in Reporting mode) gets a RefreshStartEvent, the
// current event of every retained condition its notifier reports, and a
// RefreshEndEvent. The refresh events pass the WhereClause unfiltered; the
// condition events are filtered as usual. The events keep the EventId of the
// condition's latest event, so a client can acknowledge with it.
func (s *Server) conditionRefresh(ctx context.Context, subID, itemID uint32, one bool) ua.StatusCode {
	caller, _ := MethodCallerFromContext(ctx)
	if s.SubscriptionService == nil || s.MonitoredItemService == nil || caller == nil || caller.SessionID == nil {
		return ua.StatusBadSubscriptionIDInvalid
	}
	s.SubscriptionService.Mu.Lock()
	sub := s.SubscriptionService.Subs[subID]
	s.SubscriptionService.Mu.Unlock()
	if sub == nil {
		return ua.StatusBadSubscriptionIDInvalid
	}
	if sess, _ := sub.sessionChannel(); sess == nil || !sess.ID.Equal(caller.SessionID) {
		return ua.StatusBadSubscriptionIDInvalid
	}

	var targets []refreshTarget
	found := false
	s.MonitoredItemService.Mu.Lock()
	for _, it := range s.MonitoredItemService.Subs[subID] {
		if it == nil || !it.isEvent {
			continue
		}
		if one {
			if it.ID != itemID {
				continue
			}
			found = true
		}
		if it.Mode != ua.MonitoringModeReporting || it.Req == nil || it.Req.ItemToMonitor == nil {
			continue
		}
		targets = append(targets, refreshTarget{item: it, node: it.Req.ItemToMonitor.NodeID})
	}
	s.MonitoredItemService.Mu.Unlock()
	if one && !found {
		return ua.StatusBadMonitoredItemIDInvalid
	}

	s.alarms.mu.Lock()
	if s.alarms.refreshing[subID] {
		s.alarms.mu.Unlock()
		return ua.StatusBadRefreshInProgress
	}
	s.alarms.refreshing[subID] = true
	s.alarms.mu.Unlock()
	defer func() {
		s.alarms.mu.Lock()
		delete(s.alarms.refreshing, subID)
		s.alarms.mu.Unlock()
	}()

	conds := s.alarms.list()
	for _, t := range targets {
		s.deliverToItem(t.item, refreshEvent(id.RefreshStartEventType, "ConditionRefresh start"), true, true)
		for _, c := range conds {
			if !slices.ContainsFunc(c.targets, t.node.Equal) {
				continue
			}
			// The condition and then its retained branches (Part 9
			// §5.5.7).
			c.emitMu.Lock()
			c.mu.RLock()
			var evs []*BaseEvent
			if !c.st.removed {
				if c.retainLocked() {
					evs = append(evs, c.eventLocked())
				}
				for _, b := range c.branches {
					if c.retainOfLocked(b) {
						evs = append(evs, c.eventOfLocked(b))
					}
				}
			}
			c.mu.RUnlock()
			for _, ev := range evs {
				s.deliverToItem(t.item, ev, false, true)
			}
			c.emitMu.Unlock()
		}
		s.deliverToItem(t.item, refreshEvent(id.RefreshEndEventType, "ConditionRefresh end"), true, true)
	}
	return ua.StatusOK
}

// refreshEvent is a RefreshStartEvent or RefreshEndEvent (Part 9 §5.11.2,
// §5.11.3) of the Server object.
func refreshEvent(typ uint32, msg string) *BaseEvent {
	return &BaseEvent{
		EventID:    newEventID(),
		EventType:  ua.NewNumericNodeID(0, typ),
		SourceNode: ua.NewNumericNodeID(0, id.Server),
		SourceName: "Server",
		Time:       time.Now(),
		Message:    ua.NewLocalizedTextWithLocale(msg, "en"),
		Severity:   100,
	}
}
