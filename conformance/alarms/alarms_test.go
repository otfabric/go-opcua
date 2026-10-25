// SPDX-License-Identifier: MIT

package alarms

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// Part 9 §5.7.3 / §5.7.4: Acknowledge and Confirm of an active alarm, the
// event of each transition, Retain, and the refusals of a repeated or
// unknown EventId.
func TestAlarms_AcknowledgeConfirm(t *testing.T) {
	e := newAlarmEnv(t)
	ctx := context.Background()
	cond := e.alarm(t, server.ConditionConfig{Confirmable: true, Message: "too hot", Severity: 700})
	s := e.watch(t, e.c, nil)

	require.NoError(t, cond.SetActive(true))
	act := s.next(t, "activation", of(cond, func(ev *opcua.ConditionEvent) bool { return is(ev.Active, true) }))
	require.True(t, act.Retain)
	require.True(t, is(act.Acked, false))
	require.True(t, is(act.Confirmed, false))
	require.True(t, act.Enabled)
	require.Equal(t, uint16(700), act.Severity)
	require.Equal(t, "too hot", act.Message)
	require.Equal(t, "HighTemperature", act.ConditionName)
	require.Equal(t, "Boiler", act.SourceName)
	require.True(t, e.source.Equal(act.SourceNode))
	require.True(t, ua.NewNumericNodeID(0, id.AlarmConditionType).Equal(act.EventType))
	require.Equal(t, cond.State().EventID, act.EventID)

	require.ErrorIs(t, e.c.Acknowledge(ctx, cond.NodeID(), []byte("nope"), ""), ua.StatusBadEventIDUnknown)
	require.ErrorIs(t, e.c.Confirm(ctx, cond.NodeID(), []byte("nope"), ""), ua.StatusBadEventIDUnknown)

	require.NoError(t, e.c.Acknowledge(ctx, cond.NodeID(), act.EventID, "on it"))
	ack := s.next(t, "acknowledged", of(cond, func(ev *opcua.ConditionEvent) bool { return is(ev.Acked, true) }))
	require.NotEqual(t, act.EventID, ack.EventID, "every state change has a new EventId")
	require.Equal(t, "on it", ack.Comment.Text)
	require.Equal(t, "Anonymous", ack.ClientUserID)
	require.True(t, ack.Retain, "active alarms are retained")
	require.False(t, ack.Time.Before(act.Time))

	// The old EventId is still known, the state is acknowledged.
	require.ErrorIs(t, e.c.Acknowledge(ctx, cond.NodeID(), act.EventID, ""), ua.StatusBadConditionBranchAlreadyAcked)

	require.NoError(t, e.c.Confirm(ctx, cond.NodeID(), ack.EventID, ""))
	conf := s.next(t, "confirmed", of(cond, func(ev *opcua.ConditionEvent) bool { return is(ev.Confirmed, true) }))
	require.Equal(t, "on it", conf.Comment.Text, "a null comment keeps the Comment")
	require.ErrorIs(t, e.c.Confirm(ctx, cond.NodeID(), conf.EventID, ""), ua.StatusBadConditionBranchAlreadyConfirmed)

	require.NoError(t, cond.SetActive(false))
	off := s.next(t, "inactive", of(cond, func(ev *opcua.ConditionEvent) bool { return is(ev.Active, false) }))
	require.False(t, off.Retain, "inactive, acknowledged and confirmed: not retained")

	// A new activation needs a new acknowledgement.
	require.NoError(t, cond.SetActive(true))
	again := s.next(t, "re-activation", of(cond, func(ev *opcua.ConditionEvent) bool { return is(ev.Active, true) }))
	require.True(t, is(again.Acked, false))
	require.True(t, is(again.Confirmed, false))
	require.True(t, again.Retain)

	st := cond.State()
	require.False(t, st.Acked)
	require.Equal(t, again.EventID, st.EventID)
}

// Part 9 §5.5.6: AddComment sets the Comment and ClientUserId.
func TestAlarms_AddComment(t *testing.T) {
	e := newAlarmEnv(t)
	cond := e.alarm(t, server.ConditionConfig{})
	s := e.watch(t, e.c, nil)
	require.NoError(t, cond.SetActive(true))
	ev := s.next(t, "activation", of(cond))
	require.NoError(t, e.c.AddComment(context.Background(), cond.NodeID(), ev.EventID, "checked"))
	got := s.next(t, "comment", of(cond, func(ev *opcua.ConditionEvent) bool { return ev.Comment != nil && ev.Comment.Text == "checked" }))
	require.True(t, is(got.Acked, false), "a comment does not acknowledge")
	require.Equal(t, "Anonymous", got.ClientUserID)
	require.ErrorIs(t, e.c.AddComment(context.Background(), cond.NodeID(), []byte{1}, "x"), ua.StatusBadEventIDUnknown)
}

// Part 9 §5.5.4 / §5.5.5: Disable reports Retain false and the state as
// Bad_ConditionDisabled; a disabled condition refuses the methods, is not
// refreshed and reports no events; Enable reports the current state.
func TestAlarms_EnableDisable(t *testing.T) {
	e := newAlarmEnv(t)
	ctx := context.Background()
	cond := e.alarm(t, server.ConditionConfig{})
	s := e.watch(t, e.c, nil)
	require.NoError(t, cond.SetActive(true))
	act := s.next(t, "activation", of(cond))

	require.NoError(t, e.c.DisableCondition(ctx, cond.NodeID()))
	dis := s.next(t, "disabled", of(cond, func(ev *opcua.ConditionEvent) bool { return !ev.Enabled }))
	require.False(t, dis.Retain)
	require.Nil(t, dis.Acked, "state fields are Bad_ConditionDisabled")
	require.Nil(t, dis.Active)
	require.Nil(t, dis.Quality)
	require.Equal(t, "HighTemperature", dis.ConditionName)
	require.ErrorIs(t, e.c.DisableCondition(ctx, cond.NodeID()), ua.StatusBadConditionAlreadyDisabled)
	require.ErrorIs(t, e.c.Acknowledge(ctx, cond.NodeID(), dis.EventID, ""), ua.StatusBadConditionDisabled)
	require.ErrorIs(t, e.c.AddComment(ctx, cond.NodeID(), dis.EventID, ""), ua.StatusBadConditionDisabled)

	// A Read of a state variable reports Bad_ConditionDisabled.
	acked, err := e.c.Node(cond.NodeID()).TranslateBrowsePathsToNodeIDs(ctx, []*ua.QualifiedName{{Name: "AckedState"}, {Name: "Id"}})
	require.NoError(t, err)
	dv, err := e.c.ReadValue(ctx, acked)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadConditionDisabled, dv.Status)

	// No event while disabled; refresh skips the condition.
	require.NoError(t, cond.SetSeverity(900))
	require.Empty(t, s.refresh(t))

	require.NoError(t, e.c.EnableCondition(ctx, cond.NodeID()))
	en := s.next(t, "enabled", of(cond, func(ev *opcua.ConditionEvent) bool { return ev.Enabled }))
	require.True(t, en.Retain)
	require.Equal(t, uint16(900), en.Severity, "the change made while disabled is reported")
	require.True(t, is(en.Acked, false))
	require.NotEqual(t, act.EventID, en.EventID)
	require.ErrorIs(t, e.c.EnableCondition(ctx, cond.NodeID()), ua.StatusBadConditionAlreadyEnabled)
	dv, err = e.c.ReadValue(ctx, acked)
	require.NoError(t, err)
	require.Equal(t, false, dv.Value.Value())
}

// Part 9 §5.5.7: ConditionRefresh brackets the retained conditions of the
// notifier between RefreshStart and RefreshEnd with the EventId of their
// latest event, which a client can acknowledge.
func TestAlarms_ConditionRefresh(t *testing.T) {
	e := newAlarmEnv(t)
	ctx := context.Background()
	hot := e.alarm(t, server.ConditionConfig{Name: "Hot"})
	cold := e.alarm(t, server.ConditionConfig{Name: "Cold"})
	plain := e.alarm(t, server.ConditionConfig{Name: "Note", Type: ua.NewNumericNodeID(0, id.ConditionType), Retain: true})
	require.NoError(t, hot.SetActive(true))

	s := e.watch(t, e.c, nil)
	require.NoError(t, s.sub.ConditionRefresh(ctx))
	got := s.collectRefresh(t)
	names := map[string]*opcua.ConditionEvent{}
	for _, ev := range got {
		names[ev.ConditionName] = ev
	}
	require.Len(t, got, 2, "Hot (active) and Note (Retain), not the inactive Cold")
	require.Contains(t, names, "Hot")
	require.Contains(t, names, "Note")
	require.NotContains(t, names, cold.Name())
	require.Equal(t, hot.State().EventID, names["Hot"].EventID)
	require.True(t, ua.NewNumericNodeID(0, id.ConditionType).Equal(names["Note"].EventType))
	require.Nil(t, names["Note"].Acked, "a ConditionType has no AckedState")

	require.NoError(t, e.c.Acknowledge(ctx, hot.NodeID(), names["Hot"].EventID, ""))
	s.next(t, "acknowledged", of(hot, func(ev *opcua.ConditionEvent) bool { return is(ev.Acked, true) }))

	// An item on the source gets the source's conditions; the Server
	// object's item too.
	src := e.watch(t, e.c, e.source)
	require.Len(t, src.refresh(t), 2)
	require.NoError(t, plain.SetRetain(false))
	src.next(t, "Note not retained", of(plain, func(ev *opcua.ConditionEvent) bool { return !ev.Retain }))
	require.Len(t, src.refresh(t), 1)
}

// Part 9 §5.5.8: ConditionRefresh2 and the refusals of both methods.
func TestAlarms_ConditionRefreshErrors(t *testing.T) {
	e := newAlarmEnv(t)
	ctx := context.Background()
	cond := e.alarm(t, server.ConditionConfig{})
	require.NoError(t, cond.SetActive(true))

	sub, ch, err := e.c.NewSubscription().Interval(fastInterval).Start(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(ctx) })
	res, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, &ua.MonitoredItemCreateRequest{
		ItemToMonitor:  &ua.ReadValueID{NodeID: ua.NewNumericNodeID(0, id.Server), AttributeID: ua.AttributeIDEventNotifier},
		MonitoringMode: ua.MonitoringModeReporting,
		RequestedParameters: &ua.MonitoringParameters{ClientHandle: 7, QueueSize: 100, DiscardOldest: true,
			Filter: ua.NewExtensionObject(opcua.NewConditionEventFilter())},
	})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, res.Results[0].StatusCode)
	s := &condStream{sub: sub, ch: ch}

	require.NoError(t, sub.ConditionRefresh2(ctx, res.Results[0].MonitoredItemID))
	got := s.collectRefresh(t)
	require.Len(t, got, 1)
	require.True(t, cond.NodeID().Equal(got[0].ConditionID))

	require.ErrorIs(t, sub.ConditionRefresh2(ctx, 4242), ua.StatusBadMonitoredItemIDInvalid)
	require.ErrorIs(t, e.c.ConditionRefresh(ctx, 4242), ua.StatusBadSubscriptionIDInvalid)
	// The subscription of another session is not the caller's.
	other := newClient(t, e.url)
	require.ErrorIs(t, other.ConditionRefresh(ctx, sub.SubscriptionID), ua.StatusBadSubscriptionIDInvalid)
	// ConditionRefresh on the Server object is accepted too.
	r, err := e.c.Call(ctx, &ua.CallMethodRequest{ObjectID: ua.NewNumericNodeID(0, id.Server),
		MethodID: ua.NewNumericNodeID(0, id.ConditionTypeConditionRefresh), InputArguments: []*ua.Variant{ua.MustVariant(sub.SubscriptionID)}})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, r.StatusCode)
	require.Len(t, s.collectRefresh(t), 1)
	// A wrong argument type is refused by the Call service.
	r, err = e.c.Call(ctx, &ua.CallMethodRequest{ObjectID: ua.NewNumericNodeID(0, id.ConditionType),
		MethodID: ua.NewNumericNodeID(0, id.ConditionTypeConditionRefresh), InputArguments: []*ua.Variant{ua.MustVariant("x")}})
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadTypeMismatch, r.StatusCode)
}

// Part 9 §5.8.10: the ShelvedStateMachine of an alarm.
func TestAlarms_Shelving(t *testing.T) {
	e := newAlarmEnv(t)
	ctx := context.Background()
	cond := e.alarm(t, server.ConditionConfig{Shelving: true, MaxTimeShelved: time.Hour})
	s := e.watch(t, e.c, nil)
	require.NoError(t, cond.SetActive(true))
	s.next(t, "activation", of(cond))
	shelved := func(state uint32) func(*opcua.ConditionEvent) bool {
		return func(ev *opcua.ConditionEvent) bool {
			return ev.ShelvingState != nil && ev.ShelvingState.Equal(ua.NewNumericNodeID(0, state))
		}
	}

	require.ErrorIs(t, e.c.Unshelve(ctx, cond.NodeID()), ua.StatusBadConditionNotShelved)
	require.NoError(t, e.c.OneShotShelve(ctx, cond.NodeID()))
	ev := s.next(t, "OneShotShelved", of(cond, shelved(id.ShelvedStateMachineTypeOneShotShelved)))
	require.True(t, is(ev.SuppressedOrShelved, true))
	require.ErrorIs(t, e.c.OneShotShelve(ctx, cond.NodeID()), ua.StatusBadConditionAlreadyShelved)

	// A OneShotShelved alarm unshelves when it becomes inactive.
	require.NoError(t, cond.SetActive(false))
	s.next(t, "unshelved on inactive", of(cond, shelved(id.ShelvedStateMachineTypeUnshelved)))

	require.ErrorIs(t, e.c.TimedShelve(ctx, cond.NodeID(), 2*time.Hour), ua.StatusBadShelvingTimeOutOfRange)
	require.ErrorIs(t, e.c.TimedShelve(ctx, cond.NodeID(), 0), ua.StatusBadShelvingTimeOutOfRange)
	require.NoError(t, e.c.TimedShelve(ctx, cond.NodeID(), time.Minute))
	s.next(t, "TimedShelved", of(cond, shelved(id.ShelvedStateMachineTypeTimedShelved)))
	require.ErrorIs(t, e.c.TimedShelve(ctx, cond.NodeID(), time.Minute), ua.StatusBadConditionAlreadyShelved)
	st := cond.State()
	require.Equal(t, server.TimedShelved, st.Shelving)
	require.False(t, st.UnshelveAt.IsZero())

	// UnshelveTime counts down from the shelving time.
	ss, err := e.c.Node(cond.NodeID()).TranslateBrowsePathsToNodeIDs(ctx, []*ua.QualifiedName{{Name: "ShelvingState"}, {Name: "UnshelveTime"}})
	require.NoError(t, err)
	dv, err := e.c.ReadValue(ctx, ss)
	require.NoError(t, err)
	left := dv.Value.Value().(float64)
	require.Greater(t, left, 0.0)
	require.LessOrEqual(t, left, float64(time.Minute/time.Millisecond))

	require.NoError(t, e.c.Unshelve(ctx, cond.NodeID()))
	s.next(t, "unshelved", of(cond, shelved(id.ShelvedStateMachineTypeUnshelved)))

	// The shelving time expires.
	require.NoError(t, e.c.TimedShelve(ctx, cond.NodeID(), 30*time.Millisecond))
	s.next(t, "TimedShelved", of(cond, shelved(id.ShelvedStateMachineTypeTimedShelved)))
	s.next(t, "unshelved by the timer", of(cond, shelved(id.ShelvedStateMachineTypeUnshelved)))
}

// Part 9 §5.8.12 / §5.8.13: limit alarms follow the input value.
func TestAlarms_LimitAlarms(t *testing.T) {
	e := newAlarmEnv(t)
	ctx := context.Background()
	limits := server.AlarmLimits{HighHigh: ptr(100.0), High: ptr(80.0), Low: ptr(10.0), LowLow: ptr(0.0)}
	excl := e.alarm(t, server.ConditionConfig{Name: "Level", Type: ua.NewNumericNodeID(0, id.ExclusiveLevelAlarmType), Limits: limits})
	nonExcl := e.alarm(t, server.ConditionConfig{Name: "Level2", Type: ua.NewNumericNodeID(0, id.NonExclusiveLevelAlarmType), Limits: limits})

	f := ua.NewEventFilter().SelectConditionID().
		TypeDefinition(ua.NewNumericNodeID(0, id.ExclusiveLimitAlarmType)).SelectPaths("LimitState/CurrentState/Id", "ActiveState/Id").
		TypeDefinition(ua.NewNumericNodeID(0, id.NonExclusiveLimitAlarmType)).SelectPaths("HighState/Id", "HighHighState/Id").
		Build()
	sub, ch, err := e.c.NewSubscription().Interval(fastInterval).MonitorEvents(f, ua.NewNumericNodeID(0, id.Server)).Start(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	require.NoError(t, excl.EvaluateLimits(90))
	require.NoError(t, nonExcl.EvaluateLimits(120))
	var gotExcl, gotNon bool
	for !gotExcl || !gotNon {
		for _, ev := range nextEvents(t, ch) {
			cid := ev.EventFields[0].Value().(*ua.NodeID)
			switch {
			case cid.Equal(excl.NodeID()):
				require.Equal(t, ua.NewNumericNodeID(0, id.ExclusiveLimitStateMachineTypeHigh), ev.EventFields[1].Value())
				require.Equal(t, true, ev.EventFields[2].Value())
				require.Nil(t, ev.EventFields[3].Value(), "not a field of an exclusive alarm")
				gotExcl = true
			case cid.Equal(nonExcl.NodeID()):
				require.Equal(t, true, ev.EventFields[3].Value())
				require.Equal(t, true, ev.EventFields[4].Value())
				gotNon = true
			}
		}
	}
	require.Equal(t, server.LimitHigh, excl.State().Limit)
	require.Equal(t, server.NonExclusiveLimits{HighHigh: true, High: true}, nonExcl.State().NonExclusiveLimits)
	require.NoError(t, excl.EvaluateLimits(50))
	require.False(t, excl.State().Active)
	require.ErrorIs(t, excl.SetNonExclusiveLimits(server.NonExclusiveLimits{}), server.ErrConditionUnsupport)

	// The limits are Properties of the instance.
	hl, err := e.c.Node(excl.NodeID()).TranslateBrowsePathsToNodeIDs(ctx, []*ua.QualifiedName{{Name: "HighLimit"}})
	require.NoError(t, err)
	dv, err := e.c.ReadValue(ctx, hl)
	require.NoError(t, err)
	require.Equal(t, 80.0, dv.Value.Value())
}

// Part 4 §7.7.3: a WhereClause on a condition field (a two-segment path).
func TestAlarms_WhereClause(t *testing.T) {
	e := newAlarmEnv(t)
	ctx := context.Background()
	cond := e.alarm(t, server.ConditionConfig{})
	f := ua.NewEventFilter().SelectConditionID().SelectPaths("ActiveState/Id").
		Where(ua.FieldPath("ActiveState/Id").Equals(true)).Build()
	sub, ch, err := e.c.NewSubscription().Interval(fastInterval).MonitorEvents(f, ua.NewNumericNodeID(0, id.Server)).Start(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	require.NoError(t, cond.SetSeverity(300)) // inactive: filtered
	require.NoError(t, cond.SetActive(true))
	evs := nextEvents(t, ch)
	require.Len(t, evs, 1)
	require.Equal(t, true, evs[0].EventFields[1].Value())
}

// Part 9 §5.5.2, §7.2: the instance in the address space.
func TestAlarms_AddressSpace(t *testing.T) {
	e := newAlarmEnv(t)
	ctx := context.Background()
	cond := e.alarm(t, server.ConditionConfig{Confirmable: true, Suppressible: true, Shelving: true,
		Type: ua.NewNumericNodeID(0, id.OffNormalAlarmType), NormalState: ua.NewStringNodeID(e.ns.ID(), "Normal")})

	conds, err := e.c.Node(e.source).ReferencedNodes(ctx, id.HasCondition, ua.BrowseDirectionForward, ua.NodeClassAll, false)
	require.NoError(t, err)
	require.Len(t, conds, 1, "source --HasCondition--> condition")
	require.True(t, conds[0].ID.Equal(cond.NodeID()))

	// The source is an event notifier of the Server object.
	notifier, err := e.c.Node(e.source).Attribute(ctx, ua.AttributeIDEventNotifier)
	require.NoError(t, err)
	require.Equal(t, byte(ua.EventNotifierTypeSubscribeToEvents), notifier.Value())
	srvRefs, err := e.c.BrowseAll(ctx, ua.NewNumericNodeID(0, id.Server))
	require.NoError(t, err)
	var hasNotifier bool
	for _, r := range srvRefs {
		if r.ReferenceTypeID.IntID() == id.HasNotifier && r.NodeID.NodeID.Equal(e.source) {
			hasNotifier = true
		}
	}
	require.True(t, hasNotifier)

	read := func(path ...string) *ua.DataValue {
		t.Helper()
		qn := make([]*ua.QualifiedName, len(path))
		for i, p := range path {
			qn[i] = &ua.QualifiedName{Name: p}
		}
		n, err := e.c.Node(cond.NodeID()).TranslateBrowsePathsToNodeIDs(ctx, qn)
		require.NoError(t, err, "%v", path)
		dv, err := e.c.ReadValue(ctx, n)
		require.NoError(t, err)
		return dv
	}
	require.Equal(t, "HighTemperature", read("ConditionName").Value.Value())
	require.Equal(t, true, read("Retain").Value.Value() == false)
	require.Equal(t, false, read("ActiveState", "Id").Value.Value())
	require.Equal(t, true, read("AckedState", "Id").Value.Value())
	require.Equal(t, "Acknowledged", read("AckedState").Value.Value().(*ua.LocalizedText).Text)
	require.Equal(t, false, read("SuppressedState", "Id").Value.Value())
	require.Equal(t, ua.NewNumericNodeID(0, id.ShelvedStateMachineTypeUnshelved), read("ShelvingState", "CurrentState", "Id").Value.Value())
	require.Equal(t, ua.NewStringNodeID(e.ns.ID(), "Normal"), read("NormalState").Value.Value())
	require.Equal(t, ua.NewNumericNodeID(0, id.BaseConditionClassType), read("ConditionClassId").Value.Value())
	require.Equal(t, ua.StatusOK, read("Quality").Value.Value())

	// A data change item on a condition variable follows the state.
	activeID, err := e.c.Node(cond.NodeID()).TranslateBrowsePathsToNodeIDs(ctx, []*ua.QualifiedName{{Name: "ActiveState"}, {Name: "Id"}})
	require.NoError(t, err)
	sub, ch, err := e.c.NewSubscription().Interval(fastInterval).Monitor(activeID).Start(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(ctx) })
	awaitValue(t, ch, 0, false)
	require.NoError(t, cond.SetActive(true))
	awaitValue(t, ch, 0, true)

	// Suppression.
	require.NoError(t, cond.SetSuppressed(true))
	require.Equal(t, true, read("SuppressedOrShelved").Value.Value())

	// The type definition of the instance.
	td, err := e.c.Node(cond.NodeID()).ReferencedNodes(ctx, id.HasTypeDefinition, ua.BrowseDirectionForward, ua.NodeClassAll, false)
	require.NoError(t, err)
	require.Len(t, td, 1)
	require.Equal(t, uint32(id.OffNormalAlarmType), td[0].ID.IntID())

	// Removing the condition removes its nodes and references.
	require.NoError(t, e.srv.RemoveCondition(cond.NodeID()))
	_, ok := e.srv.Condition(cond.NodeID())
	require.False(t, ok)
	_, err = e.c.ReadValue(ctx, activeID)
	require.NoError(t, err)
	r, err := e.c.Call(ctx, &ua.CallMethodRequest{ObjectID: cond.NodeID(), MethodID: ua.NewNumericNodeID(0, id.ConditionTypeDisable)})
	require.NoError(t, err)
	require.NotEqual(t, ua.StatusOK, r.StatusCode)
}

// The application hooks may refuse a method.
func TestAlarms_Hooks(t *testing.T) {
	e := newAlarmEnv(t)
	ctx := context.Background()
	var acked, enabled, shelved atomic.Int32
	cond := e.alarm(t, server.ConditionConfig{Shelving: true,
		OnAcknowledge: func(_ context.Context, c *server.Condition, comment *ua.LocalizedText) ua.StatusCode {
			acked.Add(1)
			if comment.Text == "deny" {
				return ua.StatusBadUserAccessDenied
			}
			return ua.StatusOK
		},
		OnEnable: func(context.Context, *server.Condition, bool) ua.StatusCode {
			enabled.Add(1)
			return ua.StatusBadUserAccessDenied
		},
		OnShelve: func(_ context.Context, c *server.Condition, st server.ShelvingState, _ time.Duration) ua.StatusCode {
			shelved.Add(1)
			return ua.StatusBadUserAccessDenied
		},
	})
	require.NoError(t, cond.SetActive(true))
	evID := cond.State().EventID
	require.ErrorIs(t, e.c.Acknowledge(ctx, cond.NodeID(), evID, "deny"), ua.StatusBadUserAccessDenied)
	require.False(t, cond.State().Acked)
	require.ErrorIs(t, e.c.DisableCondition(ctx, cond.NodeID()), ua.StatusBadUserAccessDenied)
	require.ErrorIs(t, e.c.OneShotShelve(ctx, cond.NodeID()), ua.StatusBadUserAccessDenied)
	require.NoError(t, e.c.Acknowledge(ctx, cond.NodeID(), evID, "ok"))
	require.True(t, cond.State().Acked)
	require.Equal(t, int32(2), acked.Load())
	require.Equal(t, int32(1), enabled.Load())
	require.Equal(t, int32(1), shelved.Load())
}
