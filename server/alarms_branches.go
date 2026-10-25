// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"

	"github.com/otfabric/go-opcua/ua"
)

// Condition branches (Part 9 §4.4, §5.5.2).
//
// A branch is an earlier state of a condition that still needs an
// acknowledgement or a confirmation while the condition itself has moved on.
// It has its own BranchId and EventIds and is reported with the ConditionId
// of its condition; it has no nodes in the address space. Acknowledge,
// Confirm and AddComment act on the branch whose EventId they get, and
// ConditionRefresh reports the retained branches after their condition. A
// branch ends when it is acknowledged (and confirmed, if the condition is
// confirmable), when it is deleted with [Condition.DeleteBranch], or when the
// condition is disabled: it then reports a last event with Retain false.

// checkConfig checks the options of the configuration against the type of
// the condition.
func (c *Condition) checkConfig() error {
	cfg := &c.cfg
	switch {
	case (cfg.Serviceable || cfg.Silenceable || cfg.Latching) && !c.isAlarm:
		return errors.New("server: AddCondition: Serviceable, Silenceable and Latching need an alarm type")
	case cfg.Branching && !c.isAck:
		return errors.New("server: AddCondition: Branching needs an acknowledgeable type")
	case len(cfg.SuppressionGroups) > 0 && (!cfg.Suppressible || !c.isAlarm):
		return errors.New("server: AddCondition: SuppressionGroups need a Suppressible alarm")
	case c.isDialog && cfg.Dialog == nil:
		return errors.New("server: AddCondition: a DialogConditionType needs Dialog")
	case !c.isDialog && cfg.Dialog != nil:
		return errors.New("server: AddCondition: Dialog needs a DialogConditionType")
	}
	if c.isDialog {
		d := cfg.Dialog
		if len(d.ResponseOptions) == 0 {
			return errors.New("server: AddCondition: a dialog needs ResponseOptions")
		}
		c.dialog = &dialogInfo{defaultResponse: -1, okResponse: -1, cancelResponse: -1}
		for _, o := range d.ResponseOptions {
			c.dialog.options = append(c.dialog.options, ua.NewLocalizedText(o))
		}
		for _, r := range []struct {
			in  *int32
			out *int32
		}{{d.DefaultResponse, &c.dialog.defaultResponse}, {d.OkResponse, &c.dialog.okResponse}, {d.CancelResponse, &c.dialog.cancelResponse}} {
			if r.in == nil {
				continue
			}
			if *r.in < 0 || int(*r.in) >= len(d.ResponseOptions) {
				return fmt.Errorf("server: AddCondition: dialog response %d is not an index of ResponseOptions", *r.in)
			}
			*r.out = *r.in
		}
	}
	if err := c.checkConfig105(); err != nil {
		return err
	}
	for _, g := range cfg.SuppressionGroups {
		if ag, ok := c.srv.AlarmGroup(g); !ok || !ag.suppression {
			return fmt.Errorf("server: AddCondition: %v is not an AlarmSuppressionGroup", g)
		}
	}
	return nil
}

// newBranchID returns a new BranchId: a GUID NodeId in the namespace of the
// condition.
func (c *Condition) newBranchID() *ua.NodeID {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	g := fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
	return ua.NewGUIDNodeID(c.ns.ID(), g)
}

// newBranchLocked adds a branch with the state from (a copy) and returns
// it; the caller reports it with newEventOfLocked. mu must be held.
func (c *Condition) newBranchLocked(from *conditionState) *conditionState {
	b := *from
	b.branchID = c.newBranchID()
	b.recentIDs = nil
	b.shelveTimer = nil
	b.deleted = false
	c.branches = append(c.branches, &b)
	return &b
}

// CreateBranch creates a branch of an acknowledgeable condition with the
// current state of the condition and reports it in an event, and returns its
// BranchId. The application then changes the condition itself, e.g. to
// require a new acknowledgement; the branch keeps the earlier state until it
// is acknowledged (and confirmed) or deleted.
func (c *Condition) CreateBranch() (*ua.NodeID, error) {
	c.emitMu.Lock()
	defer c.emitMu.Unlock()
	c.mu.Lock()
	switch {
	case c.st.removed:
		c.mu.Unlock()
		return nil, ErrConditionRemoved
	case !c.isAck:
		c.mu.Unlock()
		return nil, ErrConditionUnsupport
	case len(c.branches) >= maxConditionBranches:
		c.mu.Unlock()
		return nil, ErrTooManyBranches
	}
	b := c.newBranchLocked(&c.st)
	bid := b.branchID
	ev := c.newEventOfLocked(b)
	enabled := c.st.enabled
	c.mu.Unlock()
	if enabled {
		c.deliver(ev)
	}
	return bid, nil
}

// Branches returns snapshots of the branches of the condition, oldest
// first.
func (c *Condition) Branches() []ConditionState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]ConditionState, len(c.branches))
	for i, b := range c.branches {
		out[i] = c.snapshotLocked(b)
	}
	return out
}

// Branch returns a snapshot of the branch with the given BranchId.
func (c *Condition) Branch(branchID *ua.NodeID) (ConditionState, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if b := c.branchLocked(branchID); b != nil {
		return c.snapshotLocked(b), true
	}
	return ConditionState{}, false
}

func (c *Condition) branchLocked(branchID *ua.NodeID) *conditionState {
	if branchID == nil {
		return nil
	}
	for _, b := range c.branches {
		if b.branchID.Equal(branchID) {
			return b
		}
	}
	return nil
}

// DeleteBranch deletes a branch; it reports a last event with Retain false.
func (c *Condition) DeleteBranch(branchID *ua.NodeID) error {
	c.emitMu.Lock()
	defer c.emitMu.Unlock()
	c.mu.Lock()
	b := c.branchLocked(branchID)
	if b == nil {
		c.mu.Unlock()
		return ErrBranchUnknown
	}
	ev := c.endBranchLocked(b)
	enabled := c.st.enabled
	c.mu.Unlock()
	if enabled {
		c.deliver(ev)
	}
	return nil
}

// endBranchLocked removes a branch and returns its last event (Retain
// false). mu must be held.
func (c *Condition) endBranchLocked(b *conditionState) *BaseEvent {
	b.deleted = true
	ev := c.newEventOfLocked(b)
	c.branches = slices.DeleteFunc(c.branches, func(x *conditionState) bool { return x == b })
	return ev
}

// branchCtxKey carries the BranchId of a method call to the hooks.
type branchCtxKey struct{}

// BranchIDFromContext returns the BranchId of the branch an Acknowledge,
// Confirm or AddComment call refers to, in the hooks OnAcknowledge,
// OnConfirm and OnAddComment; nil when the call refers to the condition
// itself.
func BranchIDFromContext(ctx context.Context) *ua.NodeID {
	b, _ := ctx.Value(branchCtxKey{}).(*ua.NodeID)
	return b
}
