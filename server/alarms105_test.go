// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

func TestAddConditionConfigChecks(t *testing.T) {
	s, ns, src := alarmTestServer(t)
	g, err := s.AddAlarmGroup(AlarmGroupConfig{Name: "G", Namespace: ns})
	require.NoError(t, err)
	dialog := ua.NewNumericNodeID(0, id.DialogConditionType)
	ack := ua.NewNumericNodeID(0, id.AcknowledgeableConditionType)
	cond := ua.NewNumericNodeID(0, id.ConditionType)
	bad := int32(5)
	for name, cfg := range map[string]ConditionConfig{
		"serviceable non-alarm":   {Type: ack, Serviceable: true},
		"silenceable non-alarm":   {Type: ack, Silenceable: true},
		"latching non-alarm":      {Type: ack, Latching: true},
		"branching non-ack":       {Type: cond, Branching: true},
		"groups without suppress": {SuppressionGroups: []*ua.NodeID{g.NodeID()}},
		"group not suppression":   {Suppressible: true, SuppressionGroups: []*ua.NodeID{g.NodeID()}},
		"unknown group":           {Suppressible: true, SuppressionGroups: []*ua.NodeID{ua.NewStringNodeID(ns.ID(), "nope")}},
		"dialog without config":   {Type: dialog},
		"config without dialog":   {Dialog: &DialogConfig{ResponseOptions: []string{"Ok"}}},
		"dialog without options":  {Type: dialog, Dialog: &DialogConfig{}},
		"dialog bad response":     {Type: dialog, Dialog: &DialogConfig{ResponseOptions: []string{"Ok"}, OkResponse: &bad}},
	} {
		cfg.Name, cfg.Source = "X", src.ID()
		_, err := s.AddCondition(cfg)
		require.Error(t, err, name)
	}
	require.Empty(t, s.Conditions())

	c, err := s.AddCondition(ConditionConfig{Name: "Plain", Source: src.ID(), Type: cond})
	require.NoError(t, err)
	tr, p := true, "p"
	for name, u := range map[string]ConditionUpdate{
		"out of service": {OutOfService: &tr},
		"silenced":       {Silenced: &tr},
		"latched":        {Latched: &tr},
		"dialog":         {DialogActive: &tr},
		"prompt":         {Prompt: &p},
	} {
		require.ErrorIs(t, c.Update(u), ErrConditionUnsupport, name)
	}
	_, err = c.CreateBranch()
	require.ErrorIs(t, err, ErrConditionUnsupport)
	require.ErrorIs(t, c.ShowDialog("x"), ErrConditionUnsupport)
}

func TestConditionStatesUpdate(t *testing.T) {
	s, _, src := alarmTestServer(t)
	c, err := s.AddCondition(ConditionConfig{Name: "A", Source: src.ID(), Serviceable: true, Silenceable: true, Latching: true})
	require.NoError(t, err)
	tr, f := true, false
	require.NoError(t, c.Update(ConditionUpdate{OutOfService: &tr, Silenced: &tr, Latched: &tr}))
	st := c.State()
	require.True(t, st.OutOfService)
	require.True(t, st.Silenced)
	require.True(t, st.Latched)
	require.True(t, st.Retain, "latched")
	require.NoError(t, c.Update(ConditionUpdate{OutOfService: &f, Silenced: &f, Latched: &f}))
	st = c.State()
	require.False(t, st.OutOfService || st.Silenced || st.Latched || st.Retain)
}

func TestAlarmMethodsDirect(t *testing.T) {
	s, _, src := alarmTestServer(t)
	var hooks []string
	c, err := s.AddCondition(ConditionConfig{Name: "A", Source: src.ID(), Suppressible: true, Serviceable: true, Silenceable: true, Latching: true,
		OnSuppress: func(_ context.Context, _ *Condition, on bool, _ *ua.LocalizedText) ua.StatusCode {
			hooks = append(hooks, "suppress")
			if !on {
				return ua.StatusBadUserAccessDenied
			}
			return ua.StatusOK
		},
		OnService: func(context.Context, *Condition, bool, *ua.LocalizedText) ua.StatusCode {
			hooks = append(hooks, "service")
			return ua.StatusOK
		},
		OnSilence: func(context.Context, *Condition) ua.StatusCode { hooks = append(hooks, "silence"); return ua.StatusOK },
		OnReset: func(context.Context, *Condition, *ua.LocalizedText) ua.StatusCode {
			hooks = append(hooks, "reset")
			return ua.StatusOK
		},
	})
	require.NoError(t, err)
	ctx := callerCtx(nil)
	call := func(op alarmOp, args ...*ua.Variant) ua.StatusCode {
		_, sc := c.alarmMethod(op, len(args) > 0)(ctx, nil, nil, args)
		return sc
	}
	require.Equal(t, ua.StatusOK, call(opSuppress))
	require.Equal(t, ua.StatusBadUserAccessDenied, call(opUnsuppress), "the hook refuses")
	require.True(t, c.State().Suppressed)
	require.Equal(t, ua.StatusOK, call(opRemoveFromService, ua.MustVariant(nil)))
	require.Equal(t, ua.StatusOK, call(opPlaceInService, ua.MustVariant(ua.NewLocalizedText("x"))))
	require.Equal(t, "x", c.State().Comment.Text)
	require.Equal(t, ua.StatusBadTypeMismatch, call(opPlaceInService, ua.MustVariant(int32(1))))
	_, sc := c.alarmMethod(opSuppress, true)(ctx, nil, nil, nil)
	require.Equal(t, ua.StatusBadArgumentsMissing, sc)
	require.Equal(t, ua.StatusOK, call(opSilence))
	require.NoError(t, c.SetActive(true))
	require.Equal(t, ua.StatusBadInvalidState, call(opReset))
	require.NoError(t, c.SetActive(false))
	require.Equal(t, ua.StatusOK, call(opReset))
	require.Equal(t, []string{"suppress", "suppress", "service", "service", "silence", "reset"}, hooks)
	require.Equal(t, ua.StatusBadMethodInvalid, func() ua.StatusCode { _, sc := c.checkAlarmOpLocked(alarmOp(99)); return sc }())

	require.NoError(t, c.Disable())
	require.Equal(t, ua.StatusBadConditionDisabled, call(opSilence))
	require.NoError(t, s.RemoveCondition(c.NodeID()))
	require.Equal(t, ua.StatusBadNodeIDUnknown, call(opSilence))
	_, sc = c.groupMembershipsMethod(ctx, nil, nil, nil)
	require.Equal(t, ua.StatusBadNodeIDUnknown, sc)
}

func TestRespondDirect(t *testing.T) {
	s, _, src := alarmTestServer(t)
	refuse := true
	c, err := s.AddCondition(ConditionConfig{Name: "D", Source: src.ID(), Type: ua.NewNumericNodeID(0, id.DialogConditionType),
		Dialog: &DialogConfig{Prompt: "?", ResponseOptions: []string{"Yes", "No"}, Active: true},
		OnRespond: func(context.Context, *Condition, int32, *ua.LocalizedText) ua.StatusCode {
			if refuse {
				return ua.StatusBadUserAccessDenied
			}
			return ua.StatusOK
		}})
	require.NoError(t, err)
	require.True(t, c.State().Retain)
	ctx := callerCtx(nil)
	respond, respond2 := c.respondMethod(false), c.respondMethod(true)
	for name, args := range map[string][]*ua.Variant{
		"none":     nil,
		"nil":      {nil},
		"type":     {ua.MustVariant("x")},
		"two args": {ua.MustVariant(int32(0)), ua.MustVariant(nil)},
	} {
		_, sc := respond(ctx, nil, nil, args)
		require.NotEqual(t, ua.StatusOK, sc, name)
	}
	_, sc := respond2(ctx, nil, nil, []*ua.Variant{ua.MustVariant(int32(0)), ua.MustVariant(int32(0))})
	require.Equal(t, ua.StatusBadTypeMismatch, sc)
	_, sc = respond(ctx, nil, nil, []*ua.Variant{ua.MustVariant(int32(0))})
	require.Equal(t, ua.StatusBadUserAccessDenied, sc)
	refuse = false
	_, sc = respond2(ctx, nil, nil, []*ua.Variant{ua.MustVariant(int32(1)), ua.MustVariant(ua.NewLocalizedText("no"))})
	require.Equal(t, ua.StatusOK, sc)
	st := c.State()
	require.Equal(t, int32(1), st.LastResponse)
	require.False(t, st.DialogActive)
	require.Equal(t, "no", st.Comment.Text)
	require.NoError(t, c.Disable())
	_, sc = respond(ctx, nil, nil, []*ua.Variant{ua.MustVariant(int32(0))})
	require.Equal(t, ua.StatusBadConditionDisabled, sc)
	require.NoError(t, s.RemoveCondition(c.NodeID()))
	_, sc = respond(ctx, nil, nil, []*ua.Variant{ua.MustVariant(int32(0))})
	require.Equal(t, ua.StatusBadNodeIDUnknown, sc)
}

func TestConditionBranchesDirect(t *testing.T) {
	s, _, src := alarmTestServer(t)
	var hookBranch *ua.NodeID
	c, err := s.AddCondition(ConditionConfig{Name: "A", Source: src.ID(),
		OnAcknowledge: func(ctx context.Context, _ *Condition, _ *ua.LocalizedText) ua.StatusCode {
			hookBranch = BranchIDFromContext(ctx)
			return ua.StatusOK
		}})
	require.NoError(t, err)
	require.NoError(t, c.SetActive(true))
	bid, err := c.CreateBranch()
	require.NoError(t, err)
	require.Equal(t, uint16(c.ns.ID()), bid.Namespace())
	b, ok := c.Branch(bid)
	require.True(t, ok)
	require.True(t, b.Retain)
	require.True(t, b.BranchID.Equal(bid))
	_, ok = c.Branch(nil)
	require.False(t, ok)

	// Acknowledge the branch: it ends (not confirmable).
	_, sc := c.actionMethod(actionAcknowledge)(callerCtx(nil), nil, nil, []*ua.Variant{ua.MustVariant(b.EventID), ua.MustVariant(nil)})
	require.Equal(t, ua.StatusOK, sc)
	require.True(t, hookBranch.Equal(bid))
	require.Empty(t, c.Branches())
	require.False(t, c.State().Acked, "the condition itself is not acknowledged")

	// The bound of the branches.
	for range maxConditionBranches {
		_, err := c.CreateBranch()
		require.NoError(t, err)
	}
	_, err = c.CreateBranch()
	require.ErrorIs(t, err, ErrTooManyBranches)
	require.NoError(t, s.RemoveCondition(c.NodeID()))
	_, err = c.CreateBranch()
	require.ErrorIs(t, err, ErrConditionRemoved)
	require.ErrorIs(t, c.DeleteBranch(bid), ErrBranchUnknown)
	require.Nil(t, BranchIDFromContext(context.Background()))
}

func TestAlarmGroupsDirect(t *testing.T) {
	s, ns, src := alarmTestServer(t)
	_, err := s.AddAlarmGroup(AlarmGroupConfig{})
	require.Error(t, err, "no name")
	_, err = s.AddAlarmGroup(AlarmGroupConfig{Name: "G"})
	require.Error(t, err, "no namespace")
	_, err = s.AddAlarmGroup(AlarmGroupConfig{Name: "G", Namespace: ns, DigitalVariables: []*ua.NodeID{src.ID()}})
	require.Error(t, err, "digital variables of a plain group")
	_, err = s.AddAlarmGroup(AlarmGroupConfig{Name: "G", Namespace: ns, Suppression: true, DigitalVariables: []*ua.NodeID{src.ID()}})
	require.Error(t, err, "not a variable")
	_, err = s.AddAlarmGroup(AlarmGroupConfig{Name: "G", Namespace: ns, Parent: ua.NewStringNodeID(ns.ID(), "nope")})
	require.Error(t, err, "unknown parent")
	g, err := s.AddAlarmGroup(AlarmGroupConfig{Name: "G", NodeID: ua.NewStringNodeID(ns.ID(), "G"), Parent: src.ID()})
	require.NoError(t, err)
	require.Equal(t, "G", g.Name())
	require.False(t, g.IsSuppressionGroup())
	_, err = s.AddAlarmGroup(AlarmGroupConfig{Name: "G", NodeID: g.NodeID()})
	require.Error(t, err, "exists")
	require.ErrorIs(t, g.SetSuppressing(true), ErrConditionUnsupport)
	require.False(t, g.Suppressing())
	_, ok := s.AlarmGroup(nil)
	require.False(t, ok)
	require.Error(t, s.RemoveAlarmGroup(ua.NewStringNodeID(ns.ID(), "nope")))

	plain, err := s.AddCondition(ConditionConfig{Name: "P", Source: src.ID(), Type: ua.NewNumericNodeID(0, id.AcknowledgeableConditionType)})
	require.NoError(t, err)
	require.ErrorIs(t, g.AddMember(plain), ErrConditionNotAlarm)
	require.Error(t, g.AddMember(nil))
	a, err := s.AddCondition(ConditionConfig{Name: "A", Source: src.ID()})
	require.NoError(t, err)
	require.NoError(t, g.AddMember(a))
	require.NoError(t, g.AddMember(a), "twice is once")
	require.Len(t, g.Members(), 1)
	require.Error(t, g.RemoveMember(plain))

	sg, err := s.AddAlarmGroup(AlarmGroupConfig{Name: "S", Namespace: ns, Suppression: true})
	require.NoError(t, err)
	require.ErrorIs(t, sg.AddMember(a), ErrConditionUnsupport, "not suppressible")
	b, err := s.AddCondition(ConditionConfig{Name: "B", Source: src.ID(), Suppressible: true})
	require.NoError(t, err)
	require.NoError(t, sg.SetSuppressing(true))
	require.NoError(t, sg.AddMember(b))
	require.True(t, b.State().Suppressed, "joins a suppressing group")
	require.NoError(t, sg.RemoveMember(b))
	require.False(t, b.State().Suppressed)
	require.NoError(t, sg.AddMember(b))
	require.NoError(t, sg.Evaluate(), "no variables: stops suppressing")
	require.False(t, b.State().Suppressed)
	require.NoError(t, sg.SetSuppressing(true))
	require.NoError(t, s.RemoveAlarmGroup(sg.NodeID()))
	require.False(t, b.State().Suppressed, "a removed group stops suppressing")
	require.Error(t, sg.SetSuppressing(true), "removed")
	require.Error(t, sg.AddMember(b), "removed")

	// A removed condition leaves its groups and cannot join.
	require.NoError(t, s.RemoveCondition(a.NodeID()))
	require.Empty(t, g.Members())
	require.ErrorIs(t, g.AddMember(a), ErrConditionRemoved)
	require.NoError(t, s.RemoveAlarmGroup(g.NodeID()))
}

func TestAuditEventsDirect(t *testing.T) {
	s, _, src := alarmTestServer(t)
	require.False(t, s.Auditing())
	s.SetAuditing(true)
	require.True(t, s.Auditing())
	c, err := s.AddCondition(ConditionConfig{Name: "A", Source: src.ID(), Shelving: true})
	require.NoError(t, err)
	ev := c.auditEvent(callerCtx(nil), id.AuditConditionShelvingEventType, ua.NewNumericNodeID(0, id.ShelvedStateMachineTypeTimedShelve2),
		[]*ua.Variant{ua.MustVariant(1000.0), ua.MustVariant(nil)}, nil, ua.StatusBadConditionDisabled)
	require.True(t, ev.audit)
	require.Equal(t, false, ev.Fields["Status"].Value())
	require.Equal(t, 1000.0, ev.Fields["ShelvingTime"].Value())
	require.Equal(t, "Method/TimedShelve2", ev.SourceName)
	ev = c.auditEvent(context.Background(), id.AuditConditionRespondEventType, ua.NewNumericNodeID(0, id.DialogConditionTypeRespond), nil, nil, ua.StatusOK)
	require.Nil(t, ev.Fields["SelectedResponse"].Value())
	require.Equal(t, "", ev.Fields["ClientAuditEntryId"].Value())

	// mayReceive: the RBACAccessController decides by ReceiveEvents.
	sub := &Subscription{}
	item := &MonitoredItem{Sub: sub}
	require.True(t, s.mayReceive(item, &BaseEvent{}), "not an audit event")
	require.True(t, s.mayReceive(item, ev), "no EventAccessController")
	s.cfg.accessController = NewRBACAccessController(s)
	require.False(t, s.mayReceive(item, ev), "no session")
}
