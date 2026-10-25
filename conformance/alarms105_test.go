// SPDX-License-Identifier: MIT

package conformance

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

// Part 9 1.05: the optional states of AlarmConditionType and their methods.

// Suppress / Unsuppress (and the *2 variants with a Comment), with
// SuppressedOrShelved following.
func TestAlarms_SuppressMethods(t *testing.T) {
	e := newAlarmEnv(t)
	ctx := context.Background()
	cond := e.alarm(t, server.ConditionConfig{Suppressible: true})
	s := e.watch(t, e.c, nil)
	require.NoError(t, cond.SetActive(true))
	s.next(t, "activation", of(cond))

	require.NoError(t, e.c.Suppress(ctx, cond.NodeID()))
	ev := s.next(t, "suppressed", of(cond, func(ev *opcua.ConditionEvent) bool { return is(ev.Suppressed, true) }))
	require.True(t, is(ev.SuppressedOrShelved, true))
	require.Equal(t, "Anonymous", ev.ClientUserID)
	require.NoError(t, e.c.Suppress(ctx, cond.NodeID()), "a suppressed alarm stays suppressed")

	require.NoError(t, e.c.Unsuppress2(ctx, cond.NodeID(), "back"))
	ev = s.next(t, "unsuppressed", of(cond, func(ev *opcua.ConditionEvent) bool { return is(ev.Suppressed, false) }))
	require.True(t, is(ev.SuppressedOrShelved, false))
	require.Equal(t, "back", ev.Comment.Text)

	require.NoError(t, e.c.Suppress2(ctx, cond.NodeID(), "maintenance"))
	ev = s.next(t, "suppressed2", of(cond, func(ev *opcua.ConditionEvent) bool { return is(ev.Suppressed, true) }))
	require.Equal(t, "maintenance", ev.Comment.Text)
	require.NoError(t, e.c.Unsuppress(ctx, cond.NodeID()))
	s.next(t, "unsuppressed", of(cond, func(ev *opcua.ConditionEvent) bool { return is(ev.Suppressed, false) }))
	require.False(t, cond.State().Suppressed)

	// A disabled alarm refuses the methods.
	require.NoError(t, cond.Disable())
	require.ErrorIs(t, e.c.Suppress(ctx, cond.NodeID()), ua.StatusBadConditionDisabled)
}

// RemoveFromService / PlaceInService (OutOfServiceState).
func TestAlarms_ServiceMethods(t *testing.T) {
	e := newAlarmEnv(t)
	ctx := context.Background()
	cond := e.alarm(t, server.ConditionConfig{Serviceable: true})
	s := e.watch(t, e.c, nil)

	require.NoError(t, e.c.RemoveFromService(ctx, cond.NodeID()))
	ev := s.next(t, "out of service", of(cond, func(ev *opcua.ConditionEvent) bool { return is(ev.OutOfService, true) }))
	require.True(t, is(ev.SuppressedOrShelved, true), "out of service counts as suppressed or shelved")
	require.Nil(t, ev.Suppressed, "no SuppressedState")
	require.NoError(t, e.c.PlaceInService2(ctx, cond.NodeID(), "repaired"))
	ev = s.next(t, "in service", of(cond, func(ev *opcua.ConditionEvent) bool { return is(ev.OutOfService, false) }))
	require.Equal(t, "repaired", ev.Comment.Text)
	require.NoError(t, e.c.RemoveFromService2(ctx, cond.NodeID(), "broken"))
	s.next(t, "out of service 2", of(cond, func(ev *opcua.ConditionEvent) bool { return is(ev.OutOfService, true) }))
	require.NoError(t, e.c.PlaceInService(ctx, cond.NodeID()))
	s.next(t, "in service 2", of(cond, func(ev *opcua.ConditionEvent) bool { return is(ev.OutOfService, false) }))

	// An alarm without the state does not have the methods.
	plain := e.alarm(t, server.ConditionConfig{Name: "Plain"})
	for _, call := range []func(context.Context, *ua.NodeID) error{e.c.RemoveFromService, e.c.Suppress, e.c.Silence, e.c.Reset} {
		require.ErrorIs(t, call(ctx, plain.NodeID()), ua.StatusBadMethodInvalid)
	}
}

// Silence ends with a new activation; Reset clears a latched alarm that is
// inactive, and the latched alarm is retained until then.
func TestAlarms_SilenceLatchReset(t *testing.T) {
	e := newAlarmEnv(t)
	ctx := context.Background()
	cond := e.alarm(t, server.ConditionConfig{Silenceable: true, Latching: true})
	s := e.watch(t, e.c, nil)

	require.NoError(t, cond.SetActive(true))
	act := s.next(t, "activation", of(cond, func(ev *opcua.ConditionEvent) bool { return is(ev.Active, true) }))
	require.True(t, is(act.Latched, true))
	require.True(t, is(act.Silenced, false))

	require.NoError(t, e.c.Silence(ctx, cond.NodeID()))
	s.next(t, "silenced", of(cond, func(ev *opcua.ConditionEvent) bool { return is(ev.Silenced, true) }))
	require.NoError(t, e.c.Silence(ctx, cond.NodeID()), "silencing a silent alarm is ignored")

	require.ErrorIs(t, e.c.Reset(ctx, cond.NodeID()), ua.StatusBadInvalidState, "an active alarm cannot be reset")
	require.NoError(t, e.c.Acknowledge(ctx, cond.NodeID(), cond.State().EventID, ""))
	require.NoError(t, cond.SetActive(false))
	off := s.next(t, "inactive", of(cond, func(ev *opcua.ConditionEvent) bool { return is(ev.Active, false) }))
	require.True(t, off.Retain, "a latched alarm is retained")
	require.True(t, is(off.Latched, true))
	require.Len(t, s.refresh(t), 1)

	require.NoError(t, e.c.Reset2(ctx, cond.NodeID(), "cleared"))
	rst := s.next(t, "reset", of(cond, func(ev *opcua.ConditionEvent) bool { return is(ev.Latched, false) }))
	require.False(t, rst.Retain)
	require.Equal(t, "cleared", rst.Comment.Text)
	require.NoError(t, e.c.Reset(ctx, cond.NodeID()), "resetting an unlatched alarm is ignored")

	// A new activation latches again and ends the silence.
	require.NoError(t, cond.SetActive(true))
	again := s.next(t, "re-activation", of(cond, func(ev *opcua.ConditionEvent) bool { return is(ev.Active, true) }))
	require.True(t, is(again.Latched, true))
	require.True(t, is(again.Silenced, false))
	require.NoError(t, cond.SetActive(false))
	require.NoError(t, e.c.Reset(ctx, cond.NodeID()))
	require.False(t, cond.State().Latched)
}

// TimedShelve2, OneShotShelve2 and Unshelve2 take a Comment.
func TestAlarms_Shelving2(t *testing.T) {
	e := newAlarmEnv(t)
	ctx := context.Background()
	cond := e.alarm(t, server.ConditionConfig{Shelving: true})
	s := e.watch(t, e.c, nil)
	require.NoError(t, cond.SetActive(true))
	s.next(t, "activation", of(cond))

	require.NoError(t, e.c.TimedShelve2(ctx, cond.NodeID(), time.Hour, "an hour"))
	ev := s.next(t, "timed", of(cond, func(ev *opcua.ConditionEvent) bool {
		return ev.ShelvingState != nil && ev.ShelvingState.IntID() == id.ShelvedStateMachineTypeTimedShelved
	}))
	require.Equal(t, "an hour", ev.Comment.Text)
	require.NoError(t, e.c.OneShotShelve2(ctx, cond.NodeID(), "once"))
	ev = s.next(t, "one shot", of(cond, func(ev *opcua.ConditionEvent) bool {
		return ev.ShelvingState != nil && ev.ShelvingState.IntID() == id.ShelvedStateMachineTypeOneShotShelved
	}))
	require.Equal(t, "once", ev.Comment.Text)
	require.NoError(t, e.c.Unshelve2(ctx, cond.NodeID(), "done"))
	ev = s.next(t, "unshelved", of(cond, func(ev *opcua.ConditionEvent) bool {
		return ev.ShelvingState != nil && ev.ShelvingState.IntID() == id.ShelvedStateMachineTypeUnshelved
	}))
	require.Equal(t, "done", ev.Comment.Text)
	require.ErrorIs(t, e.c.Unshelve2(ctx, cond.NodeID(), ""), ua.StatusBadConditionNotShelved)
	require.ErrorIs(t, e.c.TimedShelve2(ctx, cond.NodeID(), 0, ""), ua.StatusBadShelvingTimeOutOfRange)
}

// DialogConditionType: Respond and Respond2.
func TestAlarms_Dialog(t *testing.T) {
	e := newAlarmEnv(t)
	ctx := context.Background()
	ok, cancel := int32(0), int32(1)
	var responded atomic.Int32
	dlg := e.alarm(t, server.ConditionConfig{Name: "Confirm", Type: ua.NewNumericNodeID(0, id.DialogConditionType),
		Dialog: &server.DialogConfig{Prompt: "Start?", ResponseOptions: []string{"Ok", "Cancel"}, OkResponse: &ok, CancelResponse: &cancel, DefaultResponse: &cancel},
		OnRespond: func(_ context.Context, _ *server.Condition, sel int32, _ *ua.LocalizedText) ua.StatusCode {
			responded.Add(1)
			return ua.StatusOK
		}})
	s := e.watch(t, e.c, nil)

	require.ErrorIs(t, e.c.Respond(ctx, dlg.NodeID(), 0), ua.StatusBadDialogNotActive)
	require.NoError(t, dlg.ShowDialog("Start the pump?"))
	ev := s.next(t, "dialog", of(dlg, func(ev *opcua.ConditionEvent) bool { return is(ev.DialogActive, true) }))
	require.True(t, ev.Retain, "an active dialog is retained")
	require.Equal(t, "Start the pump?", ev.Prompt.Text)
	require.Equal(t, int32(-1), *ev.LastResponse)
	require.True(t, ua.NewNumericNodeID(0, id.DialogConditionType).Equal(ev.EventType))

	// The Properties of the dialog.
	opts, err := e.c.Node(dlg.NodeID()).TranslateBrowsePathsToNodeIDs(ctx, []*ua.QualifiedName{{Name: "ResponseOptionSet"}})
	require.NoError(t, err)
	dv, err := e.c.ReadValue(ctx, opts)
	require.NoError(t, err)
	require.Len(t, dv.Value.Value(), 2)
	okID, err := e.c.Node(dlg.NodeID()).TranslateBrowsePathsToNodeIDs(ctx, []*ua.QualifiedName{{Name: "OkResponse"}})
	require.NoError(t, err)
	dv, err = e.c.ReadValue(ctx, okID)
	require.NoError(t, err)
	require.Equal(t, int32(0), dv.Value.Value())

	require.ErrorIs(t, e.c.Respond(ctx, dlg.NodeID(), 2), ua.StatusBadDialogResponseInvalid)
	require.ErrorIs(t, e.c.Respond(ctx, dlg.NodeID(), -1), ua.StatusBadDialogResponseInvalid)
	require.NoError(t, e.c.Respond2(ctx, dlg.NodeID(), 1, "not now"))
	ev = s.next(t, "responded", of(dlg, func(ev *opcua.ConditionEvent) bool { return is(ev.DialogActive, false) }))
	require.False(t, ev.Retain)
	require.Equal(t, int32(1), *ev.LastResponse)
	require.Equal(t, "not now", ev.Comment.Text)
	require.ErrorIs(t, e.c.Respond(ctx, dlg.NodeID(), 0), ua.StatusBadDialogNotActive)

	require.NoError(t, dlg.ShowDialog("Again?"))
	require.NoError(t, e.c.Respond(ctx, dlg.NodeID(), 0))
	require.Equal(t, int32(0), dlg.State().LastResponse)
	require.Equal(t, int32(2), responded.Load())
	require.NoError(t, dlg.ShowDialog("Withdrawn"))
	require.NoError(t, dlg.CloseDialog())
	require.False(t, dlg.State().DialogActive)
}

// Branches (Part 9 §5.5.2): with Branching, an unacknowledged occurrence
// moves to a branch when the alarm becomes active again; the branch is
// refreshed, acknowledged by its EventId and ends with Retain false.
func TestAlarms_Branches(t *testing.T) {
	e := newAlarmEnv(t)
	ctx := context.Background()
	cond := e.alarm(t, server.ConditionConfig{Branching: true, Confirmable: true})
	s := e.watch(t, e.c, nil)

	require.NoError(t, cond.SetActive(true))
	first := s.next(t, "first", of(cond, func(ev *opcua.ConditionEvent) bool { return is(ev.Active, true) }))
	require.False(t, first.IsBranch())
	require.NoError(t, cond.SetActive(false))
	require.NoError(t, cond.SetActive(true))
	br := s.next(t, "branch", of(cond, (*opcua.ConditionEvent).IsBranch))
	require.True(t, br.Retain)
	require.True(t, is(br.Acked, false))
	require.True(t, is(br.Active, false), "the branch keeps the earlier, inactive state")
	require.Len(t, cond.Branches(), 1)
	require.True(t, cond.Branches()[0].BranchID.Equal(br.BranchID))
	trunk := s.next(t, "trunk", of(cond, func(ev *opcua.ConditionEvent) bool { return !ev.IsBranch() && is(ev.Active, true) }))

	// ConditionRefresh reports the condition and its branch.
	ref := s.refresh(t)
	require.Len(t, ref, 2)
	require.False(t, ref[0].IsBranch())
	require.True(t, ref[1].IsBranch())
	require.Equal(t, br.EventID, ref[1].EventID)

	// Acknowledge and confirm the branch by its EventId; the trunk is not
	// touched.
	require.NoError(t, e.c.Acknowledge(ctx, cond.NodeID(), br.EventID, "old one"))
	acked := s.next(t, "branch acked", of(cond, func(ev *opcua.ConditionEvent) bool { return ev.IsBranch() && is(ev.Acked, true) }))
	require.True(t, acked.Retain, "still unconfirmed")
	require.False(t, cond.State().Acked)
	require.ErrorIs(t, e.c.Acknowledge(ctx, cond.NodeID(), br.EventID, ""), ua.StatusBadConditionBranchAlreadyAcked)
	require.NoError(t, e.c.Confirm(ctx, cond.NodeID(), acked.EventID, ""))
	end := s.next(t, "branch end", of(cond, func(ev *opcua.ConditionEvent) bool { return ev.IsBranch() && is(ev.Confirmed, true) }))
	require.False(t, end.Retain)
	require.Empty(t, cond.Branches())
	require.ErrorIs(t, e.c.Acknowledge(ctx, cond.NodeID(), end.EventID, ""), ua.StatusBadEventIDUnknown)
	require.NoError(t, e.c.Acknowledge(ctx, cond.NodeID(), trunk.EventID, ""))

	// CreateBranch / DeleteBranch, and Disable ends the branches.
	b1, err := cond.CreateBranch()
	require.NoError(t, err)
	s.next(t, "created", of(cond, func(ev *opcua.ConditionEvent) bool { return ev.IsBranch() && ev.BranchID.Equal(b1) }))
	require.NoError(t, cond.DeleteBranch(b1))
	del := s.next(t, "deleted", of(cond, func(ev *opcua.ConditionEvent) bool { return ev.IsBranch() && ev.BranchID.Equal(b1) }))
	require.False(t, del.Retain)
	require.ErrorIs(t, cond.DeleteBranch(b1), server.ErrBranchUnknown)
	b2, err := cond.CreateBranch()
	require.NoError(t, err)
	_, ok := cond.Branch(b2)
	require.True(t, ok)
	require.NoError(t, cond.Disable())
	gone := s.next(t, "disabled branch", of(cond, func(ev *opcua.ConditionEvent) bool { return ev.IsBranch() && ev.BranchID.Equal(b2) && !ev.Retain }))
	require.False(t, gone.Enabled)
	require.Empty(t, cond.Branches())
}

// auditStream receives the audit events of the condition methods.
type auditStream struct {
	ch  chan *opcua.PublishNotificationData
	buf []*opcua.AuditConditionEvent
}

func watchAudit(t *testing.T, c *opcua.Client) *auditStream {
	t.Helper()
	sub, ch, err := c.NewSubscription().Interval(fastInterval).
		MonitorEvents(opcua.NewAuditConditionEventFilter(), ua.NewNumericNodeID(0, id.Server)).Start(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(context.Background()) })
	return &auditStream{ch: ch}
}

func (a *auditStream) next(t *testing.T, typ uint32) *opcua.AuditConditionEvent {
	t.Helper()
	deadline := time.After(waitTimeout)
	for {
		for len(a.buf) > 0 {
			ev := a.buf[0]
			a.buf = a.buf[1:]
			if ev.EventType != nil && ev.EventType.IntID() == typ {
				return ev
			}
		}
		select {
		case msg := <-a.ch:
			require.NoError(t, msg.Error)
			if enl, ok := msg.Value.(*ua.EventNotificationList); ok {
				for _, f := range enl.Events {
					ev, err := opcua.ParseAuditConditionEvent(f)
					require.NoError(t, err)
					a.buf = append(a.buf, ev)
				}
			}
		case <-deadline:
			t.Fatalf("timed out waiting for audit event %d", typ)
			return nil
		}
	}
}

// Audit events (Part 9 §5.10) of the condition methods, with the
// AuditEventType fields and the ClientAuditEntryId of the request.
func TestAlarms_AuditEvents(t *testing.T) {
	e := newAlarmEnv(t, server.WithAuditing(true), server.ApplicationURI("urn:conformance:audit"))
	ctx := context.Background()
	require.True(t, e.srv.Auditing())
	dv, err := e.c.ReadValue(ctx, ua.NewNumericNodeID(0, id.ServerAuditing))
	require.NoError(t, err)
	require.Equal(t, true, dv.Value.Value())

	ok := int32(0)
	cond := e.alarm(t, server.ConditionConfig{Confirmable: true, Suppressible: true, Serviceable: true, Silenceable: true, Latching: true, Shelving: true})
	dlg := e.alarm(t, server.ConditionConfig{Name: "Dialog", Type: ua.NewNumericNodeID(0, id.DialogConditionType),
		Dialog: &server.DialogConfig{ResponseOptions: []string{"Ok"}, OkResponse: &ok, Active: true}})
	a := watchAudit(t, e.c)
	require.NoError(t, cond.SetActive(true))
	evID := cond.State().EventID

	actx := opcua.WithAuditEntryID(ctx, "ticket-42")
	require.NoError(t, e.c.Acknowledge(actx, cond.NodeID(), evID, "seen"))
	ack := a.next(t, id.AuditConditionAcknowledgeEventType)
	require.True(t, ack.Status)
	require.Equal(t, "ticket-42", ack.ClientAuditEntryID)
	require.Equal(t, "Anonymous", ack.ClientUserID)
	require.True(t, cond.NodeID().Equal(ack.SourceNode))
	require.Equal(t, "Method/Acknowledge", ack.SourceName)
	require.Equal(t, evID, ack.ConditionEventID)
	require.Equal(t, "seen", ack.Comment.Text)
	require.Equal(t, uint32(id.AcknowledgeableConditionTypeAcknowledge), ack.MethodID.IntID())
	require.Len(t, ack.InputArguments, 2)
	require.Equal(t, "urn:conformance:audit", ack.ServerID)
	require.False(t, ack.ActionTimeStamp.IsZero())

	// A refused call is audited with Status false.
	require.Error(t, e.c.Acknowledge(ctx, cond.NodeID(), evID, ""))
	bad := a.next(t, id.AuditConditionAcknowledgeEventType)
	require.False(t, bad.Status)
	require.Empty(t, bad.ClientAuditEntryID)

	for _, tc := range []struct {
		call func() error
		typ  uint32
	}{
		{func() error { return e.c.Confirm(ctx, cond.NodeID(), cond.State().EventID, "") }, id.AuditConditionConfirmEventType},
		{func() error { return e.c.AddComment(ctx, cond.NodeID(), cond.State().EventID, "c") }, id.AuditConditionCommentEventType},
		{func() error { return e.c.Suppress2(ctx, cond.NodeID(), "s") }, id.AuditConditionSuppressionEventType},
		{func() error { return e.c.RemoveFromService(ctx, cond.NodeID()) }, id.AuditConditionOutOfServiceEventType},
		{func() error { return e.c.Silence(ctx, cond.NodeID()) }, id.AuditConditionSilenceEventType},
		{func() error { return e.c.Reset(ctx, cond.NodeID()) }, id.AuditConditionResetEventType},
		{func() error { return e.c.DisableCondition(ctx, dlg.NodeID()) }, id.AuditConditionEnableEventType},
		{func() error { return e.c.EnableCondition(ctx, dlg.NodeID()) }, id.AuditConditionEnableEventType},
	} {
		_ = tc.call()
		a.next(t, tc.typ)
	}
	require.NoError(t, e.c.TimedShelve(ctx, cond.NodeID(), time.Minute))
	sh := a.next(t, id.AuditConditionShelvingEventType)
	require.NotNil(t, sh.ShelvingTime)
	require.Equal(t, time.Minute, *sh.ShelvingTime)
	require.NoError(t, e.c.Respond(ctx, dlg.NodeID(), 0))
	rsp := a.next(t, id.AuditConditionRespondEventType)
	require.Equal(t, int32(0), *rsp.SelectedResponse)

	// Auditing off: no more audit events, and the Property says so.
	e.srv.SetAuditing(false)
	dv, err = e.c.ReadValue(ctx, ua.NewNumericNodeID(0, id.ServerAuditing))
	require.NoError(t, err)
	require.Equal(t, false, dv.Value.Value())
}

// With the RBACAccessController only sessions with the ReceiveEvents
// permission of the audit event types (SecurityAdmin) receive audit events.
func TestAlarms_AuditEventsRBAC(t *testing.T) {
	roleFor := map[string]ua.WellKnownRole{"sam": ua.RoleSecurityAdmin, "olivia": ua.RoleOperator}
	e := newAlarmEnv(t, server.WithAuditing(true),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.AllowUsernameOnNone(),
		server.WithUsernameValidator(func(user, pass string) error {
			if _, ok := roleFor[user]; ok && pass == user+"-pw" {
				return nil
			}
			return ua.StatusBadUserAccessDenied
		}),
		server.WithRoleMapper(func(tok ua.IdentityToken) []*ua.NodeID {
			if u, ok := tok.(*ua.UserNameIdentityToken); ok {
				return []*ua.NodeID{roleFor[u.UserName].NodeID()}
			}
			return server.DefaultRoleMapper(tok)
		}),
		server.WithAccessController(server.NewRBACAccessController(nil)))
	ep := endpointFor(t, e.url, ua.SecurityPolicyURINone, ua.MessageSecurityModeNone)
	login := func(user string) *opcua.Client {
		return newClient(t, e.url, opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeUserName), opcua.AuthUsername(user, user+"-pw"))
	}
	admin, operator := login("sam"), login("olivia")
	cond := e.alarm(t, server.ConditionConfig{Suppressible: true})
	adminAudit := watchAudit(t, admin)
	// The operator monitors audit and condition events in one
	// subscription, whose notifications keep the order of the events.
	srvID := ua.NewNumericNodeID(0, id.Server)
	sub, ch, err := operator.NewSubscription().Interval(fastInterval).
		MonitorEvents(opcua.NewAuditConditionEventFilter(), srvID).
		MonitorEvents(opcua.NewConditionEventFilter(), srvID).Start(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(context.Background()) })

	require.NoError(t, operator.Suppress(context.Background(), cond.NodeID()))
	got := adminAudit.next(t, id.AuditConditionSuppressionEventType)
	require.Equal(t, "olivia", got.ClientUserID)
	// The audit event was emitted before the Call returned; the event of
	// this change comes after it.
	require.NoError(t, cond.SetSuppressed(false))
	deadline := time.After(waitTimeout)
	for done := false; !done; {
		select {
		case msg := <-ch:
			require.NoError(t, msg.Error)
			enl, ok := msg.Value.(*ua.EventNotificationList)
			if !ok {
				continue
			}
			for _, f := range enl.Events {
				ev, err := opcua.ParseConditionEvent(f)
				require.NoError(t, err, "the operator receives no audit events")
				if of(cond, func(ev *opcua.ConditionEvent) bool { return is(ev.Suppressed, false) })(ev) {
					done = true
				}
			}
		case <-deadline:
			t.Fatal("timed out waiting for the unsuppressed event")
		}
	}
}

// Alarm groups (Part 9 §5.8.18): GetGroupMemberships and suppression
// groups.
func TestAlarms_Groups(t *testing.T) {
	e := newAlarmEnv(t)
	ctx := context.Background()
	area, err := e.srv.AddAlarmGroup(server.AlarmGroupConfig{Name: "Area1", Namespace: e.ns})
	require.NoError(t, err)
	dig := server.NewVariableNode(ua.NewStringNodeID(e.ns.ID(), "Maintenance"), "Maintenance", false)
	e.ns.AddNode(dig)
	sup, err := e.srv.AddAlarmGroup(server.AlarmGroupConfig{Name: "Maintenance", Namespace: e.ns, Suppression: true,
		DigitalVariables: []*ua.NodeID{dig.ID()}})
	require.NoError(t, err)
	cond := e.alarm(t, server.ConditionConfig{Suppressible: true, SuppressionGroups: []*ua.NodeID{sup.NodeID()}})
	require.NoError(t, area.AddMember(cond))
	s := e.watch(t, e.c, nil)

	groups, err := e.c.GetGroupMemberships(ctx, cond.NodeID())
	require.NoError(t, err)
	require.Len(t, groups, 2)

	// The group references: AlarmGroupMember, AlarmSuppressionGroupMember
	// and HasAlarmSuppressionGroup.
	refs, err := e.c.Node(cond.NodeID()).ReferencedNodes(ctx, id.HasAlarmSuppressionGroup, ua.BrowseDirectionForward, ua.NodeClassAll, false)
	require.NoError(t, err)
	require.Len(t, refs, 1)
	require.True(t, sup.NodeID().Equal(refs[0].ID))
	refs, err = e.c.Node(area.NodeID()).ReferencedNodes(ctx, id.AlarmGroupMember, ua.BrowseDirectionForward, ua.NodeClassAll, false)
	require.NoError(t, err)
	require.Len(t, refs, 1)

	// The digital variable drives the suppression group.
	require.NoError(t, dig.SetAttribute(ua.AttributeIDValue, server.DataValueFromValue(true)))
	require.NoError(t, sup.Evaluate())
	require.True(t, sup.Suppressing())
	s.next(t, "suppressed by group", of(cond, func(ev *opcua.ConditionEvent) bool { return is(ev.Suppressed, true) }))
	require.NoError(t, dig.SetAttribute(ua.AttributeIDValue, server.DataValueFromValue(false)))
	require.NoError(t, sup.Evaluate())
	s.next(t, "unsuppressed by group", of(cond, func(ev *opcua.ConditionEvent) bool { return is(ev.Suppressed, false) }))

	require.NoError(t, area.RemoveMember(cond))
	groups, err = e.c.GetGroupMemberships(ctx, cond.NodeID())
	require.NoError(t, err)
	require.Len(t, groups, 1)
	require.NoError(t, e.srv.RemoveAlarmGroup(sup.NodeID()))
	groups, err = e.c.GetGroupMemberships(ctx, cond.NodeID())
	require.NoError(t, err)
	require.Empty(t, groups)
	require.Nil(t, e.srv.Node(sup.NodeID()))
}
