// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"time"

	"github.com/otfabric/go-opcua/ua"
)

// The methods of Part 9 1.05: Suppress, Unsuppress, RemoveFromService,
// PlaceInService, Silence and Reset of AlarmConditionType with their *2
// variants that take a Comment (Part 9 §5.8, AlarmConditionType), Respond and Respond2 of
// DialogConditionType (§5.6.3, §5.6.4) and GetGroupMemberships (§5.8).

// alarmOp is a method that changes an optional state of an alarm.
type alarmOp int

const (
	opSuppress alarmOp = iota
	opUnsuppress
	opRemoveFromService
	opPlaceInService
	opSilence
	opReset
)

// commentArg decodes a Comment argument; null is an empty comment.
func commentArg(v *ua.Variant) (*ua.LocalizedText, ua.StatusCode) {
	if v == nil {
		return &ua.LocalizedText{}, ua.StatusOK
	}
	switch x := v.Value().(type) {
	case *ua.LocalizedText:
		if x == nil {
			return &ua.LocalizedText{}, ua.StatusOK
		}
		return x, ua.StatusOK
	case nil:
		return &ua.LocalizedText{}, ua.StatusOK
	}
	return nil, ua.StatusBadTypeMismatch
}

// applyCommentLocked sets the Comment of the condition to a non-empty
// comment of a method (Part 9: an empty Comment leaves it unchanged). mu
// must be held.
func (c *Condition) applyCommentLocked(comment *ua.LocalizedText, now time.Time) {
	if comment != nil && (comment.Text != "" || comment.Locale != "") {
		c.st.comment, c.st.commentTime = comment, now
	}
}

// checkAlarmOpLocked checks a method of an optional alarm state against the
// state; it returns false for a call that changes nothing (the alarm is
// already in the requested state: the call is accepted and ignored). mu must
// be held.
func (c *Condition) checkAlarmOpLocked(op alarmOp) (bool, ua.StatusCode) {
	st := &c.st
	switch {
	case st.removed:
		return false, ua.StatusBadNodeIDUnknown
	case !st.enabled:
		return false, ua.StatusBadConditionDisabled
	}
	switch op {
	case opSuppress:
		return !st.suppressed, ua.StatusOK
	case opUnsuppress:
		return st.suppressed, ua.StatusOK
	case opRemoveFromService:
		return !st.outOfService, ua.StatusOK
	case opPlaceInService:
		return st.outOfService, ua.StatusOK
	case opSilence:
		return !st.silenced, ua.StatusOK
	case opReset:
		// Only an inactive alarm can be reset (Part 9 §5.8, Reset).
		if st.active {
			return false, ua.StatusBadInvalidState
		}
		return st.latched, ua.StatusOK
	}
	return false, ua.StatusBadMethodInvalid
}

// alarmHook calls the hook of the application for op.
func (c *Condition) alarmHook(ctx context.Context, op alarmOp, comment *ua.LocalizedText) ua.StatusCode {
	cfg := &c.cfg
	switch op {
	case opSuppress, opUnsuppress:
		if cfg.OnSuppress != nil {
			return cfg.OnSuppress(ctx, c, op == opSuppress, comment)
		}
	case opRemoveFromService, opPlaceInService:
		if cfg.OnService != nil {
			return cfg.OnService(ctx, c, op == opPlaceInService, comment)
		}
	case opSilence:
		if cfg.OnSilence != nil {
			return cfg.OnSilence(ctx, c)
		}
	case opReset:
		if cfg.OnReset != nil {
			return cfg.OnReset(ctx, c, comment)
		}
	}
	return ua.StatusOK
}

// alarmMethod implements Suppress, Unsuppress, RemoveFromService,
// PlaceInService, Silence and Reset, and with withComment their *2
// variants. A call for the state the alarm is in is accepted and changes
// nothing (Part 9: "the command is ignored"); Reset of an active alarm is
// Bad_InvalidState.
func (c *Condition) alarmMethod(op alarmOp, withComment bool) MethodHandler {
	return func(ctx context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		var comment *ua.LocalizedText
		if withComment {
			if len(args) != 1 {
				return nil, ua.StatusBadArgumentsMissing
			}
			var sc ua.StatusCode
			if comment, sc = commentArg(args[0]); sc != ua.StatusOK {
				return nil, sc
			}
		}
		c.mu.RLock()
		change, sc := c.checkAlarmOpLocked(op)
		c.mu.RUnlock()
		if sc != ua.StatusOK || !change {
			return nil, sc
		}
		if sc := c.alarmHook(ctx, op, comment); sc != ua.StatusOK {
			return nil, sc
		}
		user := clientUserID(ctx)

		c.emitMu.Lock()
		defer c.emitMu.Unlock()
		c.mu.Lock()
		change, sc = c.checkAlarmOpLocked(op)
		if sc != ua.StatusOK || !change {
			c.mu.Unlock()
			return nil, sc
		}
		now := c.srv.now()
		st := &c.st
		switch op {
		case opSuppress, opUnsuppress:
			st.suppressed, st.suppressedTime = op == opSuppress, now
		case opRemoveFromService, opPlaceInService:
			st.outOfService, st.outOfServiceTime = op == opRemoveFromService, now
		case opSilence:
			st.silenced, st.silenceTime = true, now
		case opReset:
			st.latched, st.latchedTime = false, now
		}
		st.clientUserID = user
		c.applyCommentLocked(comment, now)
		ev := c.newEventLocked()
		c.mu.Unlock()
		c.deliver(ev)
		c.notifyChanges()
		return nil, ua.StatusOK
	}
}

// checkRespondLocked checks a Respond call. mu must be held.
func (c *Condition) checkRespondLocked(selected int32) ua.StatusCode {
	st := &c.st
	switch {
	case st.removed:
		return ua.StatusBadNodeIDUnknown
	case !st.enabled:
		return ua.StatusBadConditionDisabled
	case !st.dialogActive:
		return ua.StatusBadDialogNotActive
	case selected < 0 || int(selected) >= len(c.dialog.options):
		return ua.StatusBadDialogResponseInvalid
	}
	return ua.StatusOK
}

// respondMethod implements Respond and, withComment, Respond2 (Part 9
// §5.6.3, §5.6.4): the response sets LastResponse and ends the dialog.
func (c *Condition) respondMethod(withComment bool) MethodHandler {
	return func(ctx context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		want := 1
		if withComment {
			want = 2
		}
		if len(args) != want || args[0] == nil {
			return nil, ua.StatusBadArgumentsMissing
		}
		selected, ok := args[0].Value().(int32)
		if !ok {
			return nil, ua.StatusBadTypeMismatch
		}
		var comment *ua.LocalizedText
		if withComment {
			var sc ua.StatusCode
			if comment, sc = commentArg(args[1]); sc != ua.StatusOK {
				return nil, sc
			}
		}
		c.mu.RLock()
		sc := c.checkRespondLocked(selected)
		c.mu.RUnlock()
		if sc != ua.StatusOK {
			return nil, sc
		}
		if c.cfg.OnRespond != nil {
			if sc := c.cfg.OnRespond(ctx, c, selected, comment); sc != ua.StatusOK {
				return nil, sc
			}
		}
		user := clientUserID(ctx)

		c.emitMu.Lock()
		defer c.emitMu.Unlock()
		c.mu.Lock()
		if sc := c.checkRespondLocked(selected); sc != ua.StatusOK {
			c.mu.Unlock()
			return nil, sc
		}
		now := c.srv.now()
		st := &c.st
		st.lastResponse = selected
		st.dialogActive, st.dialogTime = false, now
		st.clientUserID = user
		c.applyCommentLocked(comment, now)
		ev := c.newEventLocked()
		c.mu.Unlock()
		c.deliver(ev)
		c.notifyChanges()
		return nil, ua.StatusOK
	}
}

// groupMembershipsMethod implements GetGroupMemberships (Part 9 §5.8):
// the AlarmGroups the alarm is a member of.
func (c *Condition) groupMembershipsMethod(context.Context, *ua.NodeID, *ua.NodeID, []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	c.mu.RLock()
	removed := c.st.removed
	c.mu.RUnlock()
	if removed {
		return nil, ua.StatusBadNodeIDUnknown
	}
	groups := c.srv.groupsOf(c)
	if groups == nil {
		groups = []*ua.NodeID{}
	}
	return []*ua.Variant{ua.MustVariant(groups)}, ua.StatusOK
}

// ShowDialog activates a dialog with the given prompt (Part 9 §5.6): the
// dialog is retained until a client responds or [Condition.CloseDialog]
// withdraws it.
func (c *Condition) ShowDialog(prompt string) error {
	active := true
	return c.Update(ConditionUpdate{DialogActive: &active, Prompt: &prompt})
}

// CloseDialog withdraws an active dialog without a response.
func (c *Condition) CloseDialog() error {
	active := false
	return c.Update(ConditionUpdate{DialogActive: &active})
}
