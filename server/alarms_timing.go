// SPDX-License-Identifier: MIT

package server

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// The optional AlarmConditionType components of Part 9 1.05 §5.8.2:
// AudibleEnabled / AudibleSound, OnDelay / OffDelay, ReAlarmTime /
// ReAlarmRepeatCount and FirstInGroupFlag / FirstInGroup. The timers run on
// the server's alarm clock ([WithAlarmClock]).

// checkConfig105 checks these options.
func (c *Condition) checkConfig105() error {
	cfg := &c.cfg
	if (cfg.AudibleSound != nil || cfg.OnDelay != 0 || cfg.OffDelay != 0 || cfg.ReAlarmTime != 0 || cfg.FirstInGroup != nil) && !c.isAlarm {
		return errors.New("server: AddCondition: AudibleSound, OnDelay, OffDelay, ReAlarmTime and FirstInGroup need an alarm type")
	}
	if cfg.OnDelay < 0 || cfg.OffDelay < 0 || cfg.ReAlarmTime < 0 {
		return errors.New("server: AddCondition: OnDelay, OffDelay and ReAlarmTime must not be negative")
	}
	if cfg.FirstInGroup != nil {
		g, ok := c.srv.AlarmGroup(cfg.FirstInGroup)
		if !ok {
			return fmt.Errorf("server: AddCondition: FirstInGroup %v is not an alarm group", cfg.FirstInGroup)
		}
		if g.suppression && !cfg.Suppressible {
			return fmt.Errorf("server: AddCondition: FirstInGroup %v is an AlarmSuppressionGroup: the alarm must be Suppressible", cfg.FirstInGroup)
		}
		c.firstGroup = g
	}
	return nil
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

// fields105 adds the components of the options to the fields of an alarm.
func (c *Condition) fields105(fs []condField) []condField {
	cfg := &c.cfg
	if a := cfg.AudibleSound; a != nil {
		sound := slices.Clone(a.Sound)
		fs = append(fs,
			prop("AudibleEnabled", id.Boolean, false, func(_ *Condition, st *conditionState) any { return st.audibleEnabled }),
			condField{path: "AudibleSound", refType: id.HasComponent, typeDef: id.AudioVariableType, dataType: id.AudioDataType, valueRank: -1, always: true,
				value: func(*Condition, *conditionState) any { return sound }})
		for _, p := range []struct{ name, v string }{{"ListId", a.ListID}, {"AgencyId", a.AgencyID}, {"VersionId", a.VersionID}} {
			if p.v != "" {
				v := p.v
				fs = append(fs, prop("AudibleSound/"+p.name, id.String, true, func(*Condition, *conditionState) any { return v }))
			}
		}
	}
	if cfg.OnDelay > 0 {
		fs = append(fs, prop("OnDelay", id.Duration, true, func(c *Condition, _ *conditionState) any { return ms(c.cfg.OnDelay) }))
	}
	if cfg.OffDelay > 0 {
		fs = append(fs, prop("OffDelay", id.Duration, true, func(c *Condition, _ *conditionState) any { return ms(c.cfg.OffDelay) }))
	}
	if c.firstGroup != nil {
		fs = append(fs,
			condField{path: "FirstInGroupFlag", refType: id.HasComponent, typeDef: id.BaseDataVariableType, dataType: id.Boolean, valueRank: -1,
				value: func(c *Condition, st *conditionState) any { return c.firstInGroupOfLocked(st) }},
			condField{path: "FirstInGroup", refType: id.HasComponent, object: true, typeDef: id.AlarmGroupType})
	}
	if cfg.ReAlarmTime > 0 {
		fs = append(fs,
			prop("ReAlarmTime", id.Duration, true, func(c *Condition, _ *conditionState) any { return ms(c.cfg.ReAlarmTime) }),
			condField{path: "ReAlarmRepeatCount", refType: id.HasComponent, typeDef: id.BaseDataVariableType, dataType: id.Int16, valueRank: -1,
				value: func(_ *Condition, st *conditionState) any { return st.reAlarmCount }})
	}
	return fs
}

// stopTimersLocked stops the timers of the condition (removal, Close).
func (c *Condition) stopTimersLocked() {
	c.stopShelveTimerLocked()
	c.stopDelayLocked()
	c.stopReAlarmLocked()
}

// --- OnDelay / OffDelay -------------------------------------------------------

// activationOf returns the ActiveState that u sets (nil: u leaves it) and
// the part of u that sets it.
func activationOf(u ConditionUpdate) (*bool, ConditionUpdate) {
	active := u.Active
	if u.Limit != nil {
		a := *u.Limit != LimitNone
		active = &a
	}
	if u.NonExclusiveLimits != nil {
		a := u.NonExclusiveLimits.any()
		active = &a
	}
	return active, ConditionUpdate{Active: u.Active, Limit: u.Limit, NonExclusiveLimits: u.NonExclusiveLimits}
}

// isEmpty reports whether u changes nothing.
func (u ConditionUpdate) isEmpty() bool {
	return u == ConditionUpdate{}
}

// delayLocked applies OnDelay and OffDelay to u: an activation of an
// inactive alarm (OnDelay) or a return to normal of an active one
// (OffDelay) waits for its delay and is taken out of u; a change back
// cancels the waiting one. It returns the part of u to apply now and
// whether u was nothing but a waiting (or cancelled) activation change,
// which reports no event. mu must be held.
func (c *Condition) delayLocked(u ConditionUpdate) (ConditionUpdate, bool) {
	cfg := &c.cfg
	if !c.isAlarm || (cfg.OnDelay <= 0 && cfg.OffDelay <= 0) {
		return u, false
	}
	target, act := activationOf(u)
	if target == nil {
		return u, false
	}
	st := &c.st
	rest := u
	rest.Active, rest.Limit, rest.NonExclusiveLimits = nil, nil, nil
	switch {
	case *target && !st.active && cfg.OnDelay > 0:
		// A newer activation change replaces the waiting one; the delay
		// counts from the first.
		if st.delayed == nil || !st.delayOn {
			c.startDelayLocked(true, cfg.OnDelay)
		}
		st.delayed = &act
		return rest, rest.isEmpty()
	case !*target && st.active && cfg.OffDelay > 0:
		if st.delayed == nil || st.delayOn {
			c.startDelayLocked(false, cfg.OffDelay)
		}
		st.delayed = &act
		return rest, rest.isEmpty()
	}
	cancelledOn := st.delayed != nil && st.delayOn
	c.stopDelayLocked()
	if cancelledOn && !*target {
		// The alarm returned to normal within OnDelay: the activation is
		// never reported, and an inactive alarm has no limit to reset.
		return rest, rest.isEmpty()
	}
	return u, false
}

func (c *Condition) startDelayLocked(on bool, d time.Duration) {
	c.stopDelayLocked()
	st := &c.st
	st.delayOn = on
	gen := st.delayGen
	st.delayTimer = c.srv.alarmClock().AfterFunc(d, func() { c.delayExpired(gen) })
}

// stopDelayLocked cancels the waiting activation change.
func (c *Condition) stopDelayLocked() {
	st := &c.st
	if st.delayTimer != nil {
		st.delayTimer()
		st.delayTimer = nil
	}
	st.delayed = nil
	st.delayGen++
}

// delayExpired applies the activation change that waited for its delay.
func (c *Condition) delayExpired(gen uint64) {
	c.emitMu.Lock()
	defer c.emitMu.Unlock()
	c.mu.Lock()
	st := &c.st
	if st.removed || gen != st.delayGen || st.delayed == nil {
		c.mu.Unlock()
		return
	}
	u := *st.delayed
	st.delayed, st.delayTimer = nil, nil
	st.delayGen++
	c.commitLocked(u, c.srv.now())
}

// --- ReAlarmTime ------------------------------------------------------------

// startReAlarmLocked starts the re-alarm timer of an active alarm.
func (c *Condition) startReAlarmLocked() {
	if c.cfg.ReAlarmTime <= 0 {
		return
	}
	c.stopReAlarmLocked()
	st := &c.st
	gen := st.reAlarmGen
	st.reAlarmTimer = c.srv.alarmClock().AfterFunc(c.cfg.ReAlarmTime, func() { c.reAlarm(gen) })
}

func (c *Condition) stopReAlarmLocked() {
	st := &c.st
	if st.reAlarmTimer != nil {
		st.reAlarmTimer()
		st.reAlarmTimer = nil
	}
	st.reAlarmGen++
}

// reAlarm reports an alarm that is still active ReAlarmTime after its
// activation or last re-alarm as a new occurrence and counts it in
// ReAlarmRepeatCount. A disabled alarm does not re-alarm; its timer
// continues.
func (c *Condition) reAlarm(gen uint64) {
	c.emitMu.Lock()
	defer c.emitMu.Unlock()
	c.mu.Lock()
	st := &c.st
	if st.removed || gen != st.reAlarmGen || !st.active {
		c.mu.Unlock()
		return
	}
	st.reAlarmTimer = nil
	c.startReAlarmLocked()
	if !st.enabled {
		c.mu.Unlock()
		return
	}
	now := c.srv.now()
	if st.reAlarmCount < math.MaxInt16 {
		st.reAlarmCount++
	}
	count := st.reAlarmCount
	evs := c.annunciateLocked(nil, now)
	c.metricsLocked(func(m *AlarmMetrics) { m.reAlarmed(count) })
	evs = append(evs, c.newEventLocked())
	c.mu.Unlock()
	for _, ev := range evs {
		c.deliver(ev)
	}
	c.notifyChanges()
}

// --- FirstInGroup -----------------------------------------------------------

// firstInGroupOfLocked is the FirstInGroupFlag of st: a branch keeps the
// flag of its occurrence. mu must be held.
func (c *Condition) firstInGroupOfLocked(st *conditionState) bool {
	if c.firstGroup == nil {
		return false
	}
	if st.branchID != nil {
		return st.firstInGroup
	}
	return c.firstGroup.isFirst(c)
}

// joinFirstInGroup makes a new alarm a member of its FirstInGroup group and
// links its FirstInGroup object with those of the other alarms of the group
// (AlarmGroupMember references to each of them).
func (c *Condition) joinFirstInGroup() {
	g := c.firstGroup
	if g == nil {
		return
	}
	_ = g.AddMember(c)
	g.fmu.Lock()
	peers := append(slices.Clone(g.firstOut), c)
	g.firstOut = append(g.firstOut, c)
	g.fmu.Unlock()
	s := c.srv
	own := s.Node(c.firstInGroupID)
	for _, p := range peers {
		pn, pf := s.Node(p.id), s.Node(p.firstInGroupID)
		if own != nil && pn != nil {
			linkChild(own, pn, id.AlarmGroupMember)
		}
		if p != c && pf != nil {
			if cn := s.Node(c.id); cn != nil {
				linkChild(pf, cn, id.AlarmGroupMember)
			}
		}
	}
}

// leaveFirstInGroup removes a removed alarm from the first-out tracking of
// its group and from the FirstInGroup objects of the other alarms.
func (c *Condition) leaveFirstInGroup() {
	g := c.firstGroup
	if g == nil {
		return
	}
	g.fmu.Lock()
	if i := slices.Index(g.firstOut, c); i >= 0 {
		g.firstOut = slices.Delete(g.firstOut, i, i+1)
	}
	delete(g.activeOut, c)
	if g.first == c {
		g.first = nil
	}
	peers := slices.Clone(g.firstOut)
	g.fmu.Unlock()
	s := c.srv
	ct := ua.NewExpandedNodeID(c.id, "", 0)
	ref := ua.NewNumericNodeID(0, id.AlarmGroupMember)
	for _, p := range peers {
		if pf := s.Node(p.firstInGroupID); pf != nil {
			pf.RemoveRef(ct, ref, true)
		}
		if pn := s.Node(p.id); pn != nil {
			pn.RemoveRef(ua.NewExpandedNodeID(c.firstInGroupID, "", 0), ref, false)
		}
	}
}

// noteActive records an activation change of an alarm of the group's
// first-out tracking and returns the other alarms whose FirstInGroupFlag
// changed.
func (g *AlarmGroup) noteActive(c *Condition, active bool) []*Condition {
	g.fmu.Lock()
	defer g.fmu.Unlock()
	if g.activeOut == nil {
		g.activeOut = map[*Condition]bool{}
	}
	var changed []*Condition
	if active {
		if len(g.activeOut) == 0 {
			if g.first != nil && g.first != c {
				changed = append(changed, g.first)
			}
			g.first = c
		}
		g.activeOut[c] = true
		return changed
	}
	delete(g.activeOut, c)
	if len(g.activeOut) == 0 && g.first != nil {
		if g.first != c {
			changed = append(changed, g.first)
		}
		g.first = nil
	}
	return changed
}

// isFirst reports whether c is the first-out alarm of the group.
func (g *AlarmGroup) isFirst(c *Condition) bool {
	g.fmu.Lock()
	defer g.fmu.Unlock()
	return g.first == c
}

// --- metrics ----------------------------------------------------------------

// metricsLocked calls f for every AlarmMetrics that counts the alarm. mu
// of the condition must be held; the metrics locks are taken after it.
func (c *Condition) metricsLocked(f func(m *AlarmMetrics)) {
	if !c.isAlarm {
		return
	}
	for _, m := range c.srv.alarms.metrics.of(c) {
		f(m)
		if !slices.Contains(c.metricsTouched, m) {
			c.metricsTouched = append(c.metricsTouched, m)
		}
	}
}
