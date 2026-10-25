// SPDX-License-Identifier: MIT

package conformance

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/fakeclock"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// Part 9 1.05: AudibleSound, OnDelay / OffDelay, ReAlarmTime, FirstInGroup
// and AlarmMetrics. The timers run on a manual clock: the test advances it
// and the server applies the timer before Advance returns.

func newClockedAlarmEnv(t *testing.T) (*alarmEnv, *fakeclock.Clock) {
	t.Helper()
	clk := fakeclock.New(time.Date(2026, 4, 1, 6, 0, 0, 0, time.UTC))
	return newAlarmEnv(t, server.WithAlarmClock(clk)), clk
}

// marker reports the current state of cond with a new Message: the events
// that precede it in the stream were all reported before it.
func marker(t *testing.T, s *condStream, cond *server.Condition, msg string) *opcua.ConditionEvent {
	t.Helper()
	require.NoError(t, cond.SetMessage(msg))
	return s.next(t, msg, of(cond, func(ev *opcua.ConditionEvent) bool { return ev.Message == msg }))
}

// An activation shorter than OnDelay is never reported; a longer one is
// reported when OnDelay ends. A return to normal waits for OffDelay.
func TestAlarms_OnOffDelay(t *testing.T) {
	e, clk := newClockedAlarmEnv(t)
	cond := e.alarm(t, server.ConditionConfig{OnDelay: 2 * time.Second, OffDelay: 3 * time.Second})
	s := e.watch(t, e.c, nil)
	marker(t, s, cond, "start")

	require.NoError(t, cond.SetActive(true))
	clk.Advance(time.Second)
	require.NoError(t, cond.SetActive(false))
	clk.Advance(time.Minute)
	require.NoError(t, cond.SetMessage("after excursion"))
	ev := s.next(t, "next event", of(cond))
	require.Equal(t, "after excursion", ev.Message, "the excursion is not reported")
	require.True(t, is(ev.Active, false))

	require.NoError(t, cond.SetActive(true))
	clk.Advance(2 * time.Second)
	ev = s.next(t, "delayed activation", of(cond))
	require.True(t, is(ev.Active, true))
	require.True(t, is(ev.Acked, false))

	require.NoError(t, cond.SetActive(false))
	ev = marker(t, s, cond, "waiting off")
	require.True(t, is(ev.Active, true), "still active during OffDelay")
	clk.Advance(3 * time.Second)
	ev = s.next(t, "delayed return to normal", of(cond))
	require.True(t, is(ev.Active, false))

	// The Properties.
	for path, want := range map[string]float64{"OnDelay": 2000, "OffDelay": 3000} {
		require.Equal(t, want, readPath(t, e, cond.NodeID(), path))
	}
}

// readPath reads the value of the component at a BrowsePath below node.
func readPath(t *testing.T, e *alarmEnv, node *ua.NodeID, path ...string) any {
	t.Helper()
	ctx := context.Background()
	names := make([]*ua.QualifiedName, len(path))
	for i, p := range path {
		names[i] = &ua.QualifiedName{Name: p}
	}
	nid, err := e.c.Node(node).TranslateBrowsePathsToNodeIDs(ctx, names)
	require.NoError(t, err, "%v", path)
	v, err := e.c.Node(nid).Value(ctx)
	require.NoError(t, err)
	return v.Value()
}

// An alarm that stays active re-alarms after ReAlarmTime: a new occurrence
// that needs a new acknowledgement, counted in ReAlarmRepeatCount.
func TestAlarms_ReAlarm(t *testing.T) {
	e, clk := newClockedAlarmEnv(t)
	ctx := context.Background()
	cond := e.alarm(t, server.ConditionConfig{ReAlarmTime: 10 * time.Minute, Silenceable: true})
	s := e.watch(t, e.c, nil)
	require.NoError(t, cond.SetActive(true))
	act := s.next(t, "activation", of(cond, func(ev *opcua.ConditionEvent) bool { return is(ev.Active, true) }))
	require.Equal(t, int16(0), *act.ReAlarmRepeatCount)
	require.NoError(t, e.c.Acknowledge(ctx, cond.NodeID(), act.EventID, "seen"))
	require.NoError(t, e.c.Silence(ctx, cond.NodeID()))
	s.next(t, "silenced", of(cond, func(ev *opcua.ConditionEvent) bool { return is(ev.Silenced, true) }))

	clk.Advance(10 * time.Minute)
	re := s.next(t, "re-alarm", of(cond, func(ev *opcua.ConditionEvent) bool {
		return ev.ReAlarmRepeatCount != nil && *ev.ReAlarmRepeatCount == 1
	}))
	require.True(t, is(re.Acked, false))
	require.True(t, is(re.Silenced, false))
	require.Equal(t, 600000.0, readPath(t, e, cond.NodeID(), "ReAlarmTime"))
	require.Equal(t, int16(1), readPath(t, e, cond.NodeID(), "ReAlarmRepeatCount"))
	clk.Advance(10 * time.Minute)
	s.next(t, "second re-alarm", of(cond, func(ev *opcua.ConditionEvent) bool {
		return ev.ReAlarmRepeatCount != nil && *ev.ReAlarmRepeatCount == 2
	}))
}

// FirstInGroupFlag marks the first alarm of the group; FirstInGroup lists
// the alarms of the group.
func TestAlarms_FirstInGroup(t *testing.T) {
	e, _ := newClockedAlarmEnv(t)
	ctx := context.Background()
	g, err := e.srv.AddAlarmGroup(server.AlarmGroupConfig{Name: "Trip", Namespace: e.ns})
	require.NoError(t, err)
	a := e.alarm(t, server.ConditionConfig{Name: "Pressure", FirstInGroup: g.NodeID()})
	b := e.alarm(t, server.ConditionConfig{Name: "Flame", FirstInGroup: g.NodeID()})
	s := e.watch(t, e.c, nil)

	require.NoError(t, b.SetActive(true))
	ev := s.next(t, "first", of(b, func(ev *opcua.ConditionEvent) bool { return is(ev.Active, true) }))
	require.True(t, is(ev.FirstInGroup, true))
	require.NoError(t, a.SetActive(true))
	ev = s.next(t, "second", of(a, func(ev *opcua.ConditionEvent) bool { return is(ev.Active, true) }))
	require.True(t, is(ev.FirstInGroup, false))
	require.Equal(t, true, readPath(t, e, b.NodeID(), "FirstInGroupFlag"))

	// The FirstInGroup object is an AlarmGroupType with both alarms.
	fig, err := e.c.Node(a.NodeID()).TranslateBrowsePathsToNodeIDs(ctx, []*ua.QualifiedName{{Name: "FirstInGroup"}})
	require.NoError(t, err)
	refs, err := e.c.Node(fig).References(ctx, id.AlarmGroupMember, ua.BrowseDirectionForward, ua.NodeClassAll, true)
	require.NoError(t, err)
	require.Len(t, refs, 2)
	td, err := e.c.Node(fig).References(ctx, id.HasTypeDefinition, ua.BrowseDirectionForward, ua.NodeClassAll, true)
	require.NoError(t, err)
	require.Equal(t, uint32(id.AlarmGroupType), td[0].NodeID.NodeID.IntID())
	groups, err := e.c.GetGroupMemberships(ctx, a.NodeID())
	require.NoError(t, err)
	require.Len(t, groups, 1)
}

// AudibleEnabled and AudibleSound (AudioVariableType).
func TestAlarms_AudibleSound(t *testing.T) {
	e, _ := newClockedAlarmEnv(t)
	cond := e.alarm(t, server.ConditionConfig{AudibleSound: &server.AudibleSound{Sound: []byte{1, 2, 3}, ListID: "horns"}})
	s := e.watch(t, e.c, nil)
	require.NoError(t, cond.SetActive(true))
	ev := s.next(t, "activation", of(cond, func(ev *opcua.ConditionEvent) bool { return is(ev.Active, true) }))
	require.True(t, is(ev.AudibleEnabled, true))
	require.Equal(t, []byte{1, 2, 3}, readPath(t, e, cond.NodeID(), "AudibleSound"))
	require.Equal(t, "horns", readPath(t, e, cond.NodeID(), "AudibleSound", "ListId"))
	off := false
	require.NoError(t, cond.Update(server.ConditionUpdate{AudibleEnabled: &off}))
	s.next(t, "muted", of(cond, func(ev *opcua.ConditionEvent) bool { return is(ev.AudibleEnabled, false) }))
}

// AlarmMetrics count the alarms; Reset starts anew.
func TestAlarms_Metrics(t *testing.T) {
	e, clk := newClockedAlarmEnv(t)
	ctx := context.Background()
	m, err := e.srv.AddAlarmMetrics(server.AlarmMetricsConfig{Namespace: e.ns})
	require.NoError(t, err)
	cond := e.alarm(t, server.ConditionConfig{})
	for range 3 {
		require.NoError(t, cond.SetActive(true))
		clk.Advance(20 * time.Second)
		require.NoError(t, cond.SetActive(false))
	}
	got, err := e.c.ReadAlarmMetrics(ctx, m.NodeID())
	require.NoError(t, err)
	require.Equal(t, uint32(3), got.AlarmCount)
	require.Equal(t, 20*time.Second, got.MaximumActiveState)
	require.Equal(t, 3.0, got.MaximumAlarmRate)
	require.Equal(t, uint16(1), got.RateMinutes)

	// The object is a component of the Server object.
	refs, err := e.c.Node(ua.NewNumericNodeID(0, id.Server)).References(ctx, id.HasComponent, ua.BrowseDirectionForward, ua.NodeClassObject, true)
	require.NoError(t, err)
	found := false
	for _, r := range refs {
		found = found || r.NodeID.NodeID.Equal(m.NodeID())
	}
	require.True(t, found)

	require.NoError(t, e.c.ResetAlarmMetrics(ctx, m.NodeID()))
	got, err = e.c.ReadAlarmMetrics(ctx, m.NodeID())
	require.NoError(t, err)
	require.Zero(t, got.AlarmCount)
	require.True(t, got.StartTime.Equal(clk.Now()))
}
