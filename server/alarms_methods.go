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
	reg := func(obj *ua.NodeID, method uint32, h MethodHandler, ref bool) {
		if ref {
			if on := s.Node(obj); on != nil {
				s.addMethodRef(on, method)
			}
		}
		mid := ua.NewNumericNodeID(0, method)
		s.RegisterMethod(obj, mid, h)
		c.methods = append(c.methods, [2]*ua.NodeID{obj, mid})
	}
	// ConditionType (Part 9 §5.5.4 - §5.5.6)
	reg(c.id, id.ConditionTypeEnable, c.enableMethod(true), true)
	reg(c.id, id.ConditionTypeDisable, c.enableMethod(false), true)
	reg(c.id, id.ConditionTypeAddComment, c.actionMethod(actionAddComment), true)
	if c.isAck {
		// AcknowledgeableConditionType (Part 9 §5.7.3, §5.7.4)
		reg(c.id, id.AcknowledgeableConditionTypeAcknowledge, c.actionMethod(actionAcknowledge), true)
		if c.cfg.Confirmable {
			reg(c.id, id.AcknowledgeableConditionTypeConfirm, c.actionMethod(actionConfirm), true)
		}
	}
	if c.shelvingID != nil {
		// ShelvedStateMachineType (Part 9 §5.8.10.2 - §5.8.10.4); the
		// methods of the AlarmConditionType's ShelvingState are accepted
		// too.
		for _, m := range []struct {
			typ, inst uint32
			state     ShelvingState
		}{
			{id.ShelvedStateMachineTypeUnshelve, id.AlarmConditionTypeShelvingStateUnshelve, Unshelved},
			{id.ShelvedStateMachineTypeOneShotShelve, id.AlarmConditionTypeShelvingStateOneShotShelve, OneShotShelved},
			{id.ShelvedStateMachineTypeTimedShelve, id.AlarmConditionTypeShelvingStateTimedShelve, TimedShelved},
		} {
			h := c.shelveMethod(m.state)
			reg(c.shelvingID, m.typ, h, true)
			reg(c.shelvingID, m.inst, h, false)
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
// condition against its state. mu must be held.
func (c *Condition) checkActionLocked(a conditionAction, eventID []byte) ua.StatusCode {
	st := &c.st
	switch {
	case st.removed:
		return ua.StatusBadNodeIDUnknown
	case !st.enabled:
		return ua.StatusBadConditionDisabled
	case !c.knownEventIDLocked(eventID):
		return ua.StatusBadEventIDUnknown
	case a == actionAcknowledge && st.acked:
		return ua.StatusBadConditionBranchAlreadyAcked
	case a == actionConfirm && st.confirmed:
		return ua.StatusBadConditionBranchAlreadyConfirmed
	}
	return ua.StatusOK
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
		sc = c.checkActionLocked(a, eventID)
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
			if sc := hook(ctx, c, comment); sc != ua.StatusOK {
				return nil, sc
			}
		}
		user := clientUserID(ctx)

		c.emitMu.Lock()
		defer c.emitMu.Unlock()
		c.mu.Lock()
		// The state may have changed while the hook ran.
		if sc := c.checkActionLocked(a, eventID); sc != ua.StatusOK {
			c.mu.Unlock()
			return nil, sc
		}
		now := time.Now()
		st := &c.st
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
		ev := c.newEventLocked()
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
func (c *Condition) shelveMethod(to ShelvingState) MethodHandler {
	return func(ctx context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		var d time.Duration
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
		c.st.clientUserID = clientUserID(ctx)
		c.setShelvingLocked(to, d, time.Now())
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
			c.emitMu.Lock()
			c.mu.RLock()
			var ev *BaseEvent
			if !c.st.removed && c.retainLocked() {
				ev = c.eventLocked()
			}
			c.mu.RUnlock()
			if ev != nil {
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
