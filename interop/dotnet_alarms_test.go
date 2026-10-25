//go:build interop

// SPDX-License-Identifier: MIT

// Alarms & Conditions (Part 9) against UA-.NETStandard, both directions
// (shared assertions: alarms_peer_test.go).
// COVERAGE: testdata/ledger-dotnet.json alarms.condition-refresh,
// alarms.acknowledgeable, alarms.alarm-state-methods, alarms.dialog,
// alarms.branches, alarms.alarm-groups, alarms.audible-sound,
// alarms.audit-events

package interop

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

func TestDotnetServer_Alarms(t *testing.T) {
	requireServerFeature(t, dotnetEnv, defaultDotnetImage, "alarms")
	s := newPeerAlarmSession(t, startDotnetServer(t).endpoint)
	t.Run("coverage/alarms.condition-refresh/go-client-to-dotnet-server", s.assertRefresh)
	t.Run("coverage/alarms.acknowledgeable/go-client-to-dotnet-server", s.assertActions)
}

func TestGoServer_DotnetClient_Alarms(t *testing.T) {
	requireAdapterOp(t, dotnetEnv, defaultDotnetImage, "alarms")
	r := runPeerAlarms(t, runDotnetClientResult)
	t.Run("coverage/alarms.condition-refresh/dotnet-client-to-go-server", r.assertRefresh)
	t.Run("coverage/alarms.acknowledgeable/dotnet-client-to-go-server", r.assertActions)
}

func TestGoServer_DotnetClient_Alarms105(t *testing.T) {
	requireAdapterOp(t, dotnetEnv, defaultDotnetImage, "call")
	requireAdapterOp(t, dotnetEnv, defaultDotnetImage, "event-subscribe")
	p := startAlarms105(t, runDotnetClientResult)
	t.Run("coverage/alarms.alarm-state-methods/dotnet-client-to-go-server", p.assertStateMethods)
	t.Run("coverage/alarms.dialog/dotnet-client-to-go-server", p.assertDialog)
	t.Run("coverage/alarms.branches/dotnet-client-to-go-server", p.assertBranches)
	t.Run("coverage/alarms.alarm-groups/dotnet-client-to-go-server", p.assertGroups)
	t.Run("coverage/alarms.audit-events/dotnet-client-to-go-server", p.assertAudit)
}

func TestGoServer_DotnetClient_Alarms105Timing(t *testing.T) {
	requireAdapterOp(t, dotnetEnv, defaultDotnetImage, "read")
	requireAdapterOp(t, dotnetEnv, defaultDotnetImage, "call")
	p := startAlarmTiming(t, runDotnetClientResult)
	t.Run("coverage/alarms.alarm-timing/dotnet-client-to-go-server", p.assertTiming)
	t.Run("coverage/alarms.audible-sound/dotnet-client-to-go-server", p.assertAudible)
	t.Run("coverage/alarms.first-in-group/dotnet-client-to-go-server", p.assertFirstInGroup)
	t.Run("coverage/alarms.alarm-metrics/dotnet-client-to-go-server", p.assertMetrics)
}

// TestDotnetServer_Alarms105: the go-opcua client against the Part 9 1.05
// alarm fixture of the UA-.NETStandard server (opcua-interop
// fixtures/baseline "Alarms (1.05)", serverFeatures "alarms-105", adapter
// 0.15.0): s=Alarms.ExtAlarm with the optional states and methods,
// s=Alarms.Dialog, s=Alarms.Group and the fixture methods ResetExt,
// Deactivate and Branch. Every condition method is the stack's own handler.
// Where UA-.NETStandard 2.0.1 has no handler (TimedShelve2, Respond2) the
// fixture has no such method and the test records the refusal.
func TestDotnetServer_Alarms105(t *testing.T) {
	requireServerFeature(t, dotnetEnv, defaultDotnetImage, "alarms-105")
	p := newDotnetAlarm105(t, startDotnetServer(t).endpoint)
	t.Run("coverage/alarms.alarm-state-methods/"+dirGoClientToDotnetServer, p.assertStateMethods)
	t.Run("coverage/alarms.dialog/"+dirGoClientToDotnetServer, p.assertDialog)
	t.Run("coverage/alarms.branches/"+dirGoClientToDotnetServer, p.assertBranches)
	t.Run("coverage/alarms.alarm-groups/"+dirGoClientToDotnetServer, p.assertGroups)
	t.Run("coverage/alarms.audible-sound/"+dirGoClientToDotnetServer, p.assertAudible)
}

// TestDotnetServer_AlarmAudit: the condition audit events of the
// UA-.NETStandard server started with --auditing (serverFeatures "auditing",
// adapter 0.15.0); the stack delivers audit events to SignAndEncrypt sessions
// only. Its events carry the condition's own method as MethodId, and the
// Acknowledge / Confirm events leave ConditionEventId and Comment out (2.0.1
// sets them with SetChildValue on children its audit event states do not
// create): the EventId and the Comment are in InputArguments only.
func TestDotnetServer_AlarmAudit(t *testing.T) {
	requireServerFeature(t, dotnetEnv, defaultDotnetImage, "alarms")
	requireServerFeature(t, dotnetEnv, defaultDotnetImage, "auditing")
	s := newPeerAuditAlarmSession(t, dotnetEnv, defaultDotnetImage, "dotnet-server", "--auditing")
	t.Run("coverage/alarms.audit-events/"+dirGoClientToDotnetServer, func(t *testing.T) {
		s.assertAudit(t, auditPeer{instanceMethodID: true, ackArgsOnly: true})
	})
}

type dotnetAlarm105 struct {
	c                *opcua.Client
	ctx              context.Context
	ns               uint16
	source, ext, dlg *ua.NodeID
}

func newDotnetAlarm105(t *testing.T, endpoint string) *dotnetAlarm105 {
	t.Helper()
	c := dialClient(t, endpoint)
	ctx, ns := findNS(t, c)
	p := &dotnetAlarm105{c: c, ctx: ctx, ns: ns,
		source: ua.NewStringNodeID(ns, "Alarms.Source"),
		ext:    ua.NewStringNodeID(ns, "Alarms.ExtAlarm"),
		dlg:    ua.NewStringNodeID(ns, "Alarms.Dialog"),
	}
	t.Cleanup(func() { p.fixture(t, "Alarms.ResetExt") })
	return p
}

// fixture calls a fixture method of Alarms.Source and returns its outputs.
func (p *dotnetAlarm105) fixture(t *testing.T, method string) []*ua.Variant {
	t.Helper()
	res, err := p.c.Call(p.ctx, &ua.CallMethodRequest{ObjectID: p.source, MethodID: ua.NewStringNodeID(p.ns, method)})
	if err != nil {
		t.Fatalf("Call %s: %v", method, err)
	}
	if res.StatusCode != ua.StatusOK {
		t.Fatalf("%s: %v", method, res.StatusCode)
	}
	return res.OutputArguments
}

// value reads the variable at the browse path below node (Part 9 names in
// namespace 0).
func (p *dotnetAlarm105) value(t *testing.T, node *ua.NodeID, names ...string) any {
	t.Helper()
	qn := make([]*ua.QualifiedName, len(names))
	for i, n := range names {
		qn[i] = &ua.QualifiedName{Name: n}
	}
	nid, err := p.c.Node(node).TranslateBrowsePathsToNodeIDs(p.ctx, qn)
	if err != nil {
		t.Fatalf("TranslateBrowsePaths %v %v: %v", node, names, err)
	}
	dv, err := p.c.ReadValue(p.ctx, nid)
	if err != nil {
		t.Fatalf("Read %v: %v", names, err)
	}
	if dv.Status != ua.StatusOK || dv.Value == nil {
		t.Fatalf("Read %v: %v", names, dv.Status)
	}
	return dv.Value.Value()
}

func (p *dotnetAlarm105) state(t *testing.T, node *ua.NodeID, names ...string) bool {
	t.Helper()
	v, ok := p.value(t, node, append(names, "Id")...).(bool)
	if !ok {
		t.Fatalf("%v/Id is not a Boolean", names)
	}
	return v
}

func (p *dotnetAlarm105) comment(t *testing.T, node *ua.NodeID) string {
	t.Helper()
	lt, _ := p.value(t, node, "Comment").(*ua.LocalizedText)
	if lt == nil {
		return ""
	}
	return lt.Text
}

func wantStatus(t *testing.T, what string, err error, want ua.StatusCode) {
	t.Helper()
	if want == ua.StatusOK {
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		return
	}
	if !errors.Is(err, want) {
		t.Fatalf("%s = %v, want %v", what, err, want)
	}
}

func (p *dotnetAlarm105) assertStateMethods(t *testing.T) {
	p.fixture(t, "Alarms.ResetExt")
	ctx, ext := p.ctx, p.ext
	wantStatus(t, "Suppress2", p.c.Suppress2(ctx, ext, "maintenance"), ua.StatusOK)
	if !p.state(t, ext, "SuppressedState") || p.comment(t, ext) != "maintenance" {
		t.Fatalf("after Suppress2: suppressed=%v comment=%q", p.state(t, ext, "SuppressedState"), p.comment(t, ext))
	}
	// UA-.NETStandard answers a transition to the current state with
	// Bad_NothingToDo.
	wantStatus(t, "repeated Suppress", p.c.Suppress(ctx, ext), ua.StatusBadNothingToDo)
	wantStatus(t, "Unsuppress", p.c.Unsuppress(ctx, ext), ua.StatusOK)
	if p.state(t, ext, "SuppressedState") {
		t.Fatal("Unsuppress: still suppressed")
	}
	wantStatus(t, "Silence", p.c.Silence(ctx, ext), ua.StatusOK)
	if !p.state(t, ext, "SilenceState") {
		t.Fatal("Silence: not silenced")
	}
	wantStatus(t, "RemoveFromService2", p.c.RemoveFromService2(ctx, ext, "out"), ua.StatusOK)
	if !p.state(t, ext, "OutOfServiceState") || p.comment(t, ext) != "out" {
		t.Fatal("RemoveFromService2: in service")
	}
	wantStatus(t, "PlaceInService", p.c.PlaceInService(ctx, ext), ua.StatusOK)
	if p.state(t, ext, "OutOfServiceState") {
		t.Fatal("PlaceInService: out of service")
	}
	// Reset of a latched alarm (Part 9 §5.8): refused while it is active
	// and while it is unacknowledged.
	wantStatus(t, "Reset2 of the active alarm", p.c.Reset2(ctx, ext, "early"), ua.StatusBadInvalidState)
	p.fixture(t, "Alarms.Deactivate")
	if p.state(t, ext, "ActiveState") || !p.state(t, ext, "LatchedState") {
		t.Fatal("Deactivate: the alarm is active or not latched")
	}
	wantStatus(t, "Reset of the unacknowledged alarm", p.c.Reset(ctx, ext), ua.StatusBadInvalidState)
	eventID, _ := p.value(t, ext, "EventId").([]byte)
	wantStatus(t, "Acknowledge", p.c.Acknowledge(ctx, ext, eventID, "ack"), ua.StatusOK)
	wantStatus(t, "Reset2", p.c.Reset2(ctx, ext, "reset"), ua.StatusOK)
	if p.state(t, ext, "LatchedState") || p.comment(t, ext) != "reset" {
		t.Fatalf("Reset2: latched=%v comment=%q", p.state(t, ext, "LatchedState"), p.comment(t, ext))
	}
	// TimedShelve2 has no handler in UA-.NETStandard 2.0.1: the fixture's
	// ShelvingState has TimedShelve, OneShotShelve and Unshelve only.
	err := p.c.TimedShelve2(ctx, ext, time.Hour, "shelved")
	if !refusal(err) {
		t.Fatalf("TimedShelve2 = %v, want the refusal of a method the server does not have", err)
	}
	t.Logf("TimedShelve2 (not served by UA-.NETStandard 2.0.1): %v", err)
	wantStatus(t, "TimedShelve", p.c.TimedShelve(ctx, ext, time.Hour), ua.StatusOK)
	cur, _ := p.value(t, ext, "ShelvingState", "CurrentState", "Id").(*ua.NodeID)
	if cur == nil || cur.IntID() != id.ShelvedStateMachineTypeTimedShelved {
		t.Fatalf("TimedShelve: CurrentState/Id = %v, want TimedShelved", cur)
	}
	wantStatus(t, "Unshelve", p.c.Unshelve(ctx, ext), ua.StatusOK)
	cur, _ = p.value(t, ext, "ShelvingState", "CurrentState", "Id").(*ua.NodeID)
	if cur == nil || cur.IntID() != id.ShelvedStateMachineTypeUnshelved {
		t.Fatalf("Unshelve: CurrentState/Id = %v, want Unshelved", cur)
	}
}

func (p *dotnetAlarm105) assertDialog(t *testing.T) {
	p.fixture(t, "Alarms.ResetExt")
	ctx, dlg := p.ctx, p.dlg
	if !p.state(t, dlg, "DialogState") {
		t.Fatal("the dialog is not active after ResetExt")
	}
	// Respond2 has no handler in UA-.NETStandard 2.0.1: the fixture
	// dialog has Respond only.
	err := p.c.Respond2(ctx, dlg, 1, "no")
	if !refusal(err) {
		t.Fatalf("Respond2 = %v, want the refusal of a method the server does not have", err)
	}
	t.Logf("Respond2 (not served by UA-.NETStandard 2.0.1): %v", err)
	// Option 2 does not exist (ResponseOptionSet [Yes, No]).
	wantStatus(t, "Respond 2", p.c.Respond(ctx, dlg, 2), ua.StatusBadDialogResponseInvalid)
	wantStatus(t, "Respond 1", p.c.Respond(ctx, dlg, 1), ua.StatusOK)
	if p.state(t, dlg, "DialogState") {
		t.Fatal("Respond: the dialog is still active")
	}
	if last, _ := p.value(t, dlg, "LastResponse").(int32); last != 1 {
		t.Fatalf("LastResponse = %d, want 1", last)
	}
	wantStatus(t, "Respond to the inactive dialog", p.c.Respond(ctx, dlg, 0), ua.StatusBadDialogNotActive)
}

func (p *dotnetAlarm105) assertBranches(t *testing.T) {
	p.fixture(t, "Alarms.ResetExt")
	trunk, _ := p.value(t, p.ext, "EventId").([]byte)
	out := p.fixture(t, "Alarms.Branch")
	if len(out) != 1 {
		t.Fatalf("Alarms.Branch: %d outputs, want 1", len(out))
	}
	branch, _ := out[0].Value().([]byte)
	if len(branch) == 0 || bytes.Equal(branch, trunk) {
		t.Fatalf("branch EventId %x (trunk %x)", branch, trunk)
	}
	// Acknowledge of the branch by its EventId (Part 9 §5.5.2, §5.7.3):
	// the condition has no ConfirmedState, so the branch needs no more
	// action and ends; the trunk is untouched.
	wantStatus(t, "Acknowledge of the branch", p.c.Acknowledge(p.ctx, p.ext, branch, "branch"), ua.StatusOK)
	if p.state(t, p.ext, "AckedState") {
		t.Fatal("the trunk was acknowledged")
	}
	if now, _ := p.value(t, p.ext, "EventId").([]byte); !bytes.Equal(now, trunk) {
		t.Fatalf("the trunk EventId changed: %x, was %x", now, trunk)
	}
	// The ended branch's EventId: UA-.NETStandard remembers it was
	// acknowledged.
	err := p.c.Acknowledge(p.ctx, p.ext, branch, "again")
	if !errors.Is(err, ua.StatusBadConditionBranchAlreadyAcked) && !errors.Is(err, ua.StatusBadEventIDUnknown) {
		t.Fatalf("second Acknowledge of the branch = %v, want Bad_ConditionBranchAlreadyAcked or Bad_EventIdUnknown", err)
	}
	t.Logf("second Acknowledge of the ended branch: %v", err)
}

func (p *dotnetAlarm105) assertGroups(t *testing.T) {
	p.fixture(t, "Alarms.ResetExt")
	groups, err := p.c.GetGroupMemberships(p.ctx, p.ext)
	if err != nil {
		t.Fatalf("GetGroupMemberships: %v", err)
	}
	if len(groups) != 1 || !groups[0].Equal(ua.NewStringNodeID(p.ns, "Alarms.Group")) {
		t.Fatalf("GetGroupMemberships = %v, want [s=Alarms.Group]", groups)
	}
	// The dialog is no alarm: it has no such method.
	_, err = p.c.GetGroupMemberships(p.ctx, p.dlg)
	if !refusal(err) {
		t.Fatalf("GetGroupMemberships of the dialog = %v, want a refusal", err)
	}
}

func (p *dotnetAlarm105) assertAudible(t *testing.T) {
	p.fixture(t, "Alarms.ResetExt")
	if on, _ := p.value(t, p.ext, "AudibleEnabled").(bool); !on {
		t.Fatal("AudibleEnabled is not true")
	}
	if sound, _ := p.value(t, p.ext, "AudibleSound").([]byte); string(sound) != "interop-horn" {
		t.Fatalf("AudibleSound = %q, want interop-horn", sound)
	}
	if list, _ := p.value(t, p.ext, "AudibleSound", "ListId").(string); list != "interop-sounds" {
		t.Fatalf("AudibleSound/ListId = %q, want interop-sounds", list)
	}
}
