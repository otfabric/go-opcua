// SPDX-License-Identifier: MIT

package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/fakeclock"
	"github.com/otfabric/go-opcua/ua"
)

var clockStart = time.Date(2026, 3, 1, 8, 0, 0, 0, time.UTC)

// clockedAlarmServer is alarmTestServer with a manual alarm clock.
func clockedAlarmServer(t *testing.T) (*Server, *NodeNameSpace, *Node, *fakeclock.Clock) {
	t.Helper()
	s, ns, src := alarmTestServer(t)
	clk := fakeclock.New(clockStart)
	s.cfg.alarmClock = clk
	return s, ns, src, clk
}

// field returns the value of a field of the condition's state.
func field(t *testing.T, c *Condition, path string) any {
	t.Helper()
	c.mu.RLock()
	defer c.mu.RUnlock()
	for i := range c.table {
		if c.table[i].path == path {
			return c.fieldValueLocked(&c.st, &c.table[i]).Value()
		}
	}
	t.Fatalf("no field %s", path)
	return nil
}

func hasField(c *Condition, path string) bool {
	for i := range c.table {
		if c.table[i].path == path {
			return true
		}
	}
	return false
}

func TestWithAlarmClock(t *testing.T) {
	cfg := &serverConfig{}
	require.Error(t, WithAlarmClock(nil)(cfg))
	clk := fakeclock.New(clockStart)
	require.NoError(t, WithAlarmClock(clk)(cfg))
	s := &Server{cfg: cfg}
	require.Equal(t, clockStart, s.now())
	s.cfg.alarmClock = nil
	require.WithinDuration(t, time.Now(), s.now(), time.Minute)
	stop := s.alarmClock().AfterFunc(time.Hour, func() {})
	require.True(t, stop())
}

func TestAlarm105OptionChecks(t *testing.T) {
	s, ns, src, _ := clockedAlarmServer(t)
	sg, err := s.AddAlarmGroup(AlarmGroupConfig{Name: "S", Namespace: ns, Suppression: true})
	require.NoError(t, err)
	ack := ua.NewNumericNodeID(0, id.AcknowledgeableConditionType)
	for name, cfg := range map[string]ConditionConfig{
		"audible non-alarm":        {Type: ack, AudibleSound: &AudibleSound{}},
		"on delay non-alarm":       {Type: ack, OnDelay: time.Second},
		"off delay non-alarm":      {Type: ack, OffDelay: time.Second},
		"realarm non-alarm":        {Type: ack, ReAlarmTime: time.Second},
		"first in group non-alarm": {Type: ack, FirstInGroup: sg.NodeID()},
		"negative delay":           {OnDelay: -time.Second},
		"unknown group":            {FirstInGroup: ua.NewStringNodeID(ns.ID(), "nope")},
		"suppression group":        {FirstInGroup: sg.NodeID()},
	} {
		cfg.Name, cfg.Source = "X", src.ID()
		_, err := s.AddCondition(cfg)
		require.Error(t, err, name)
	}
	plain, err := s.AddCondition(ConditionConfig{Name: "Plain", Source: src.ID()})
	require.NoError(t, err)
	tr := true
	require.ErrorIs(t, plain.Update(ConditionUpdate{AudibleEnabled: &tr}), ErrConditionUnsupport)
	for _, p := range []string{"AudibleEnabled", "AudibleSound", "OnDelay", "OffDelay", "ReAlarmTime", "ReAlarmRepeatCount", "FirstInGroupFlag", "FirstInGroup"} {
		require.False(t, hasField(plain, p), p)
	}
	// A suppression group is a FirstInGroup of a Suppressible alarm.
	_, err = s.AddCondition(ConditionConfig{Name: "S1", Source: src.ID(), Suppressible: true, FirstInGroup: sg.NodeID()})
	require.NoError(t, err)
}

func TestAudibleSound(t *testing.T) {
	s, _, src, _ := clockedAlarmServer(t)
	c, err := s.AddCondition(ConditionConfig{Name: "Horn", Source: src.ID(),
		AudibleSound: &AudibleSound{Sound: []byte("RIFF"), ListID: "l", AgencyID: "a", VersionID: "1"}})
	require.NoError(t, err)
	require.True(t, c.State().AudibleEnabled)
	require.Equal(t, true, field(t, c, "AudibleEnabled"))
	require.Equal(t, []byte("RIFF"), field(t, c, "AudibleSound"))
	require.Equal(t, "l", field(t, c, "AudibleSound/ListId"))
	require.Equal(t, "a", field(t, c, "AudibleSound/AgencyId"))
	require.Equal(t, "1", field(t, c, "AudibleSound/VersionId"))
	off := false
	require.NoError(t, c.Update(ConditionUpdate{AudibleEnabled: &off}))
	require.False(t, c.State().AudibleEnabled)

	c2, err := s.AddCondition(ConditionConfig{Name: "Quiet", Source: src.ID(), AudibleSound: &AudibleSound{}})
	require.NoError(t, err)
	require.False(t, hasField(c2, "AudibleSound/ListId"))
	// The sound node has the AudioVariableType and the AudioDataType.
	n := s.Node(c2.nodeOf(t, "AudibleSound"))
	require.NotNil(t, n)
	require.Equal(t, uint32(id.AudioDataType), n.DataType().NodeID.IntID())
}

// nodeOf returns the NodeId of the component at path.
func (c *Condition) nodeOf(t *testing.T, path string) *ua.NodeID {
	t.Helper()
	k := 0
	for i := range c.table {
		k++
		if c.table[i].path == path {
			return c.nodes[k]
		}
	}
	t.Fatalf("no node %s", path)
	return nil
}

func TestOnDelay(t *testing.T) {
	s, _, src, clk := clockedAlarmServer(t)
	c, err := s.AddCondition(ConditionConfig{Name: "Level", Source: src.ID(), Type: ua.NewNumericNodeID(0, id.ExclusiveLevelAlarmType),
		OnDelay: 5 * time.Second, Limits: AlarmLimits{High: ptr(80.0), HighHigh: ptr(95.0)}})
	require.NoError(t, err)
	require.Equal(t, 5000.0, field(t, c, "OnDelay"))
	ev0 := c.State().EventID

	// An excursion shorter than OnDelay is never reported.
	require.NoError(t, c.EvaluateLimits(85))
	st := c.State()
	require.False(t, st.Active)
	require.True(t, st.PendingActive)
	require.Equal(t, ev0, st.EventID, "no event while the activation waits")
	clk.Advance(4 * time.Second)
	require.NoError(t, c.EvaluateLimits(50))
	st = c.State()
	require.False(t, st.Active)
	require.False(t, st.PendingActive)
	require.Equal(t, ev0, st.EventID)
	clk.Advance(time.Minute)
	require.False(t, c.State().Active)
	require.Zero(t, clk.Pending())

	// A longer one is reported after OnDelay with its latest limit; the
	// delay counts from the first activation.
	require.NoError(t, c.EvaluateLimits(85))
	clk.Advance(3 * time.Second)
	require.NoError(t, c.EvaluateLimits(97))
	clk.Advance(2*time.Second - time.Millisecond)
	require.False(t, c.State().Active)
	clk.Advance(time.Millisecond)
	st = c.State()
	require.True(t, st.Active)
	require.Equal(t, LimitHighHigh, st.Limit)
	require.False(t, st.Acked)
	require.NotEqual(t, ev0, st.EventID)
	require.Equal(t, clockStart.Add(time.Minute+9*time.Second), st.Time)

	// Other changes of an update are not delayed.
	require.NoError(t, c.SetActive(false))
	sev := uint16(900)
	on := true
	require.NoError(t, c.Update(ConditionUpdate{Active: &on, Severity: &sev}))
	st = c.State()
	require.Equal(t, uint16(900), st.Severity)
	require.False(t, st.Active)
	require.True(t, st.PendingActive)

	// Removing the condition stops the timer.
	require.NoError(t, s.RemoveCondition(c.NodeID()))
	clk.Advance(time.Minute)
	require.False(t, c.State().Active)
	require.ErrorIs(t, c.SetActive(true), ErrConditionRemoved)
}

func ptr[T any](v T) *T { return &v }

func TestOffDelay(t *testing.T) {
	s, _, src, clk := clockedAlarmServer(t)
	c, err := s.AddCondition(ConditionConfig{Name: "Flow", Source: src.ID(), OffDelay: 10 * time.Second, Confirmable: true})
	require.NoError(t, err)
	require.Equal(t, 10000.0, field(t, c, "OffDelay"))
	require.NoError(t, c.SetActive(true), "no OnDelay: at once")
	require.True(t, c.State().Active)
	evID := c.State().EventID
	require.NoError(t, c.Update(ConditionUpdate{Acked: ptr(true)}))

	// A return to normal waits for OffDelay; an activation within it
	// continues the alarm: no new occurrence, still acknowledged.
	require.NoError(t, c.SetActive(false))
	st := c.State()
	require.True(t, st.Active)
	require.True(t, st.PendingInactive)
	clk.Advance(9 * time.Second)
	require.NoError(t, c.SetActive(true))
	st = c.State()
	require.True(t, st.Active)
	require.True(t, st.Acked)
	require.False(t, st.PendingInactive)
	require.NotEqual(t, evID, st.EventID)

	require.NoError(t, c.SetActive(false))
	clk.Advance(10 * time.Second)
	st = c.State()
	require.False(t, st.Active)
	require.False(t, st.PendingInactive)
	require.Zero(t, clk.Pending())

	// A repeated return to normal keeps the running delay.
	require.NoError(t, c.SetActive(true))
	require.NoError(t, c.SetActive(false))
	clk.Advance(5 * time.Second)
	require.NoError(t, c.SetActive(false))
	clk.Advance(5 * time.Second)
	require.False(t, c.State().Active)
}

func TestOnAndOffDelay(t *testing.T) {
	s, _, src, clk := clockedAlarmServer(t)
	c, err := s.AddCondition(ConditionConfig{Name: "Both", Source: src.ID(), Type: ua.NewNumericNodeID(0, id.NonExclusiveLevelAlarmType),
		OnDelay: time.Second, OffDelay: time.Second, Limits: AlarmLimits{High: ptr(10.0), Low: ptr(0.0)}})
	require.NoError(t, err)
	require.NoError(t, c.EvaluateLimits(20))
	require.False(t, c.State().Active)
	// A repeated activation while it waits replaces the change.
	require.NoError(t, c.EvaluateLimits(30))
	clk.Advance(time.Second)
	st := c.State()
	require.True(t, st.Active)
	require.True(t, st.NonExclusiveLimits.High)
	require.NoError(t, c.EvaluateLimits(5))
	require.True(t, c.State().Active)
	require.True(t, c.State().PendingInactive)
	clk.Advance(time.Second)
	require.False(t, c.State().Active)
	require.False(t, c.State().NonExclusiveLimits.High)
	// A change that sets nothing else reports nothing while it waits.
	ev := c.State().EventID
	require.NoError(t, c.SetActive(true))
	require.Equal(t, ev, c.State().EventID)
	// The delay does not apply when the change keeps the state.
	require.NoError(t, c.SetActive(false))
	require.Equal(t, ev, c.State().EventID)
	require.NoError(t, c.Report())
	require.NotEqual(t, ev, c.State().EventID)
}

func TestReAlarm(t *testing.T) {
	s, _, src, clk := clockedAlarmServer(t)
	c, err := s.AddCondition(ConditionConfig{Name: "Re", Source: src.ID(), ReAlarmTime: time.Minute,
		Confirmable: true, Silenceable: true, Branching: true})
	require.NoError(t, err)
	require.Equal(t, 60000.0, field(t, c, "ReAlarmTime"))
	require.Equal(t, int16(0), field(t, c, "ReAlarmRepeatCount"))
	clk.Advance(time.Hour)
	require.Zero(t, clk.Pending(), "an inactive alarm does not re-alarm")

	require.NoError(t, c.SetActive(true))
	require.NoError(t, c.Update(ConditionUpdate{Acked: ptr(true), Confirmed: ptr(true), Silenced: ptr(true)}))
	ev := c.State().EventID
	clk.Advance(time.Minute)
	st := c.State()
	require.Equal(t, int16(1), st.ReAlarmRepeatCount)
	require.False(t, st.Acked)
	require.False(t, st.Confirmed)
	require.False(t, st.Silenced)
	require.NotEqual(t, ev, st.EventID)
	require.Empty(t, c.Branches(), "the previous occurrence was acknowledged and confirmed")

	// Not acknowledged: the previous occurrence becomes a branch.
	clk.Advance(time.Minute)
	require.Equal(t, int16(2), c.State().ReAlarmRepeatCount)
	require.Len(t, c.Branches(), 1)

	// A disabled alarm does not re-alarm, its timer continues.
	require.NoError(t, c.Disable())
	clk.Advance(time.Minute)
	require.Equal(t, int16(2), c.State().ReAlarmRepeatCount)
	require.NoError(t, c.Enable())
	clk.Advance(time.Minute)
	require.Equal(t, int16(3), c.State().ReAlarmRepeatCount)

	// Returning to normal stops it; a new activation counts anew.
	require.NoError(t, c.SetActive(false))
	require.Zero(t, clk.Pending())
	require.Equal(t, int16(3), c.State().ReAlarmRepeatCount)
	require.NoError(t, c.SetActive(true))
	require.Equal(t, int16(0), c.State().ReAlarmRepeatCount)
	c.reAlarm(0) // a stale timer does nothing
	require.Equal(t, int16(0), c.State().ReAlarmRepeatCount)
	c.mu.Lock()
	c.st.reAlarmCount = 32767
	c.mu.Unlock()
	clk.Advance(time.Minute)
	require.Equal(t, int16(32767), c.State().ReAlarmRepeatCount, "the count saturates")
	s.alarms.close()
	require.Zero(t, clk.Pending())
}

func TestFirstInGroup(t *testing.T) {
	s, ns, src, _ := clockedAlarmServer(t)
	g, err := s.AddAlarmGroup(AlarmGroupConfig{Name: "Boiler", Namespace: ns})
	require.NoError(t, err)
	add := func(name string) *Condition {
		c, err := s.AddCondition(ConditionConfig{Name: name, Source: src.ID(), FirstInGroup: g.NodeID()})
		require.NoError(t, err)
		return c
	}
	a, b, d := add("A"), add("B"), add("C")
	require.Len(t, g.Members(), 3)
	for _, c := range []*Condition{a, b, d} {
		require.Equal(t, false, field(t, c, "FirstInGroupFlag"))
		// The FirstInGroup object lists the alarms of the group.
		fig := s.Node(c.firstInGroupID)
		require.NotNil(t, fig)
		n := 0
		for _, r := range fig.refsSnapshot() {
			if r.IsForward && r.ReferenceTypeID.IntID() == id.AlarmGroupMember {
				n++
			}
		}
		require.Equal(t, 3, n, c.Name())
	}

	require.NoError(t, b.SetActive(true))
	require.NoError(t, a.SetActive(true))
	require.True(t, b.State().FirstInGroup)
	require.False(t, a.State().FirstInGroup)
	// The first-out alarm keeps the flag until all are inactive.
	require.NoError(t, b.SetActive(false))
	require.True(t, b.State().FirstInGroup)
	require.NoError(t, a.SetActive(false))
	require.False(t, b.State().FirstInGroup)
	require.NoError(t, d.SetActive(true))
	require.True(t, d.State().FirstInGroup)

	// A removed alarm leaves the group and the other FirstInGroup objects.
	require.NoError(t, s.RemoveCondition(d.NodeID()))
	require.False(t, g.isFirst(d))
	require.Len(t, g.Members(), 2)
	for _, r := range s.Node(a.firstInGroupID).refsSnapshot() {
		if r.IsForward && r.ReferenceTypeID.IntID() == id.AlarmGroupMember {
			require.False(t, r.NodeID.NodeID.Equal(d.NodeID()))
		}
	}
	require.NoError(t, a.SetActive(true))
	require.True(t, a.State().FirstInGroup)
}

func TestFirstInGroupBranch(t *testing.T) {
	s, ns, src, _ := clockedAlarmServer(t)
	g, err := s.AddAlarmGroup(AlarmGroupConfig{Name: "G", Namespace: ns})
	require.NoError(t, err)
	c, err := s.AddCondition(ConditionConfig{Name: "A", Source: src.ID(), FirstInGroup: g.NodeID(), Branching: true})
	require.NoError(t, err)
	require.NoError(t, c.SetActive(true))
	require.NoError(t, c.SetActive(false))
	require.NoError(t, c.SetActive(true))
	br := c.Branches()
	require.Len(t, br, 1)
	require.True(t, br[0].FirstInGroup, "the branch keeps the flag of its occurrence")
}

func TestAlarmMetrics(t *testing.T) {
	s, ns, src, clk := clockedAlarmServer(t)
	_, err := s.AddAlarmMetrics(AlarmMetricsConfig{})
	require.Error(t, err, "no namespace")
	_, err = s.AddAlarmMetrics(AlarmMetricsConfig{Namespace: ns, Group: ua.NewStringNodeID(ns.ID(), "nope")})
	require.Error(t, err)
	_, err = s.AddAlarmMetrics(AlarmMetricsConfig{Namespace: ns, Parent: ua.NewStringNodeID(ns.ID(), "nope")})
	require.Error(t, err)

	m, err := s.AddAlarmMetrics(AlarmMetricsConfig{NodeID: ua.NewStringNodeID(ns.ID(), "Metrics")})
	require.NoError(t, err)
	_, err = s.AddAlarmMetrics(AlarmMetricsConfig{NodeID: m.NodeID()})
	require.Error(t, err, "duplicate")
	got, ok := s.AlarmMetrics(m.NodeID())
	require.True(t, ok)
	require.Same(t, m, got)
	_, ok = s.AlarmMetrics(nil)
	require.False(t, ok)
	require.Equal(t, clockStart, m.Values().StartTime)

	c, err := s.AddCondition(ConditionConfig{Name: "A", Source: src.ID(), ReAlarmTime: time.Minute})
	require.NoError(t, err)
	info, err := s.AddCondition(ConditionConfig{Name: "Info", Source: src.ID(), Type: ua.NewNumericNodeID(0, id.AcknowledgeableConditionType)})
	require.NoError(t, err)
	require.NoError(t, info.Update(ConditionUpdate{Acked: ptr(false)}))
	require.NoError(t, info.Update(ConditionUpdate{Acked: ptr(true)}), "not an alarm: not counted")

	require.NoError(t, c.SetActive(true))
	clk.Advance(30 * time.Second)
	require.NoError(t, c.Update(ConditionUpdate{Acked: ptr(true)}))
	clk.Advance(150 * time.Second) // re-alarms at 1, 2 and 3 minutes
	require.NoError(t, c.SetActive(false))
	require.NoError(t, c.SetActive(true))
	v := m.Values()
	require.Equal(t, uint32(2), v.AlarmCount)
	require.Equal(t, 30*time.Second, v.MaximumUnAck)
	require.Equal(t, 180*time.Second, v.MaximumActiveState)
	require.Equal(t, uint32(3), v.MaximumReAlarmCount)
	require.Equal(t, 1.0, v.CurrentAlarmRate, "one activation in the last minute")
	require.Equal(t, 1.0, v.MaximumAlarmRate)
	require.InDelta(t, 2.0/3.0, v.AverageAlarmRate, 1e-9, "2 alarms in 3 minutes")
	clk.Advance(time.Minute)
	v = m.Values()
	require.Zero(t, v.CurrentAlarmRate)

	// The nodes read the values.
	root := s.Node(m.NodeID())
	require.NotNil(t, root)
	require.Equal(t, uint32(id.AlarmMetricsType), root.typeDefinition().NodeID.IntID())
	require.Len(t, m.vars, 11)
	dv := s.Node(m.vars[0]).Value()
	require.Equal(t, uint32(2), dv.Value.Value())

	// Reset: the method (audited) and the API.
	s.SetAuditing(true)
	_, sc := m.resetMethod(callerCtx(nil), m.NodeID(), ua.NewNumericNodeID(0, id.AlarmMetricsTypeReset), []*ua.Variant{ua.MustVariant(int32(1))})
	require.Equal(t, ua.StatusBadTooManyArguments, sc)
	require.Equal(t, uint32(2), m.Values().AlarmCount)
	_, sc = m.resetMethod(callerCtx(nil), m.NodeID(), ua.NewNumericNodeID(0, id.AlarmMetricsTypeReset), nil)
	require.Equal(t, ua.StatusOK, sc)
	v = m.Values()
	require.Zero(t, v.AlarmCount)
	require.Equal(t, clk.Now(), v.StartTime)

	require.NoError(t, s.RemoveAlarmMetrics(m.NodeID()))
	require.Nil(t, s.Node(m.NodeID()))
	require.Error(t, s.RemoveAlarmMetrics(m.NodeID()))
	require.NoError(t, c.SetActive(false))
}

func TestAlarmMetricsOfGroup(t *testing.T) {
	s, ns, src, _ := clockedAlarmServer(t)
	g, err := s.AddAlarmGroup(AlarmGroupConfig{Name: "G", Namespace: ns})
	require.NoError(t, err)
	m, err := s.AddAlarmMetrics(AlarmMetricsConfig{Namespace: ns, Group: g.NodeID(), Parent: g.NodeID(), RateMinutes: 60})
	require.NoError(t, err)
	in, err := s.AddCondition(ConditionConfig{Name: "In", Source: src.ID()})
	require.NoError(t, err)
	out, err := s.AddCondition(ConditionConfig{Name: "Out", Source: src.ID()})
	require.NoError(t, err)
	require.NoError(t, g.AddMember(in))
	require.NoError(t, in.SetActive(true))
	require.NoError(t, out.SetActive(true))
	require.Equal(t, uint32(1), m.Values().AlarmCount)
	require.NoError(t, g.RemoveMember(in))
	require.NoError(t, in.SetActive(false))
	require.NoError(t, in.SetActive(true))
	require.Equal(t, uint32(1), m.Values().AlarmCount)
	// The Rate Property is the period in minutes.
	rate := s.Node(m.vars[5]) // CurrentAlarmRate/Rate
	require.Equal(t, "Rate", rate.BrowseName().Name)
	require.Equal(t, uint16(60), rate.Value().Value.Value())
	m.Reset()
	require.Zero(t, m.Values().AlarmCount)
}

// A re-alarm of an alarm that is still unacknowledged keeps its unacknowledged
// time: MaximumUnAck counts from the first annunciation, unless the
// occurrence moved to a branch.
func TestAlarmMetricsUnAckAcrossReAlarm(t *testing.T) {
	for _, branching := range []bool{false, true} {
		s, ns, src, clk := clockedAlarmServer(t)
		m, err := s.AddAlarmMetrics(AlarmMetricsConfig{Namespace: ns})
		require.NoError(t, err)
		c, err := s.AddCondition(ConditionConfig{Name: "A", Source: src.ID(), ReAlarmTime: time.Minute, Branching: branching})
		require.NoError(t, err)
		require.NoError(t, c.SetActive(true))
		clk.Advance(90 * time.Second) // one re-alarm while unacknowledged
		require.NoError(t, c.Update(ConditionUpdate{Acked: ptr(true)}))
		want := 90 * time.Second
		if branching {
			want = 30 * time.Second
			require.Len(t, c.Branches(), 1)
		}
		require.Equal(t, want, m.Values().MaximumUnAck, "branching %v", branching)
	}
}
