//go:build interop

// SPDX-License-Identifier: MIT

// Part 9 v1.05 Alarms & Conditions peer tests: every adapter's generic
// `client call` and `client event-subscribe` operations (CLIENT_CONTRACT §1
// "call flags", "event-subscribe flags") against the go-opcua server:
//
//   - alarms.alarm-state-methods: Suppress2, Silence, RemoveFromService2,
//     PlaceInService, Reset2 / Reset (§5.8.2) and TimedShelve2 on the
//     ShelvingState (§5.8.10);
//   - alarms.dialog: Respond2 / Respond of a DialogConditionType (§5.6);
//   - alarms.branches: Acknowledge of a condition branch by its EventId
//     (§5.5.2, §5.7.3), which ends the branch;
//   - alarms.alarm-groups: GetGroupMemberships (§5.8.2);
//   - alarms.audit-events: an AuditConditionEventType subtype (§5.10)
//     selected with an OfType filter.
//
// No peer server fixture has these features, so the go-opcua client side
// has ledger rows only (see coverage.json and the ledger-*.json files). The
// UA-.NETStandard, node-opcua and async-opcua tests are in
// dotnet_alarms_test.go, nodeopcua_alarms_test.go and
// asyncopcua_alarms_test.go.
//
// COVERAGE.md: alarms-conditions / alarms.alarm-state-methods, alarms.dialog,
// alarms.branches, alarms.alarm-groups, alarms.audit-events

package interop

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

func TestGoServer_Open62541Client_Alarms105(t *testing.T) {
	requireAdapterOp(t, "OPEN62541_IMAGE", defaultOpen62541Image, "call")
	requireAdapterOp(t, "OPEN62541_IMAGE", defaultOpen62541Image, "event-subscribe")
	p := startAlarms105(t, runOpen62541ClientResult)
	t.Run("coverage/alarms.alarm-state-methods/open62541-client-to-go-server", p.assertStateMethods)
	t.Run("coverage/alarms.dialog/open62541-client-to-go-server", p.assertDialog)
	t.Run("coverage/alarms.branches/open62541-client-to-go-server", p.assertBranches)
	t.Run("coverage/alarms.alarm-groups/open62541-client-to-go-server", p.assertGroups)
	t.Run("coverage/alarms.audit-events/open62541-client-to-go-server", p.assertAudit)
}

func TestGoServer_MiloClient_Alarms105(t *testing.T) {
	requireAdapterOp(t, "MILO_IMAGE", defaultMiloImage, "call")
	requireAdapterOp(t, "MILO_IMAGE", defaultMiloImage, "event-subscribe")
	p := startAlarms105(t, runMiloClientResult)
	t.Run("coverage/alarms.alarm-state-methods/milo-client-to-go-server", p.assertStateMethods)
	t.Run("coverage/alarms.dialog/milo-client-to-go-server", p.assertDialog)
	t.Run("coverage/alarms.branches/milo-client-to-go-server", p.assertBranches)
	t.Run("coverage/alarms.alarm-groups/milo-client-to-go-server", p.assertGroups)
	t.Run("coverage/alarms.audit-events/milo-client-to-go-server", p.assertAudit)
}

func TestGoServer_AsyncuaClient_Alarms105(t *testing.T) {
	requireAdapterOp(t, asyncuaEnv, defaultAsyncuaImage, "call")
	requireAdapterOp(t, asyncuaEnv, defaultAsyncuaImage, "event-subscribe")
	p := startAlarms105(t, runAsyncuaClientResult)
	t.Run("coverage/alarms.alarm-state-methods/asyncua-client-to-go-server", p.assertStateMethods)
	t.Run("coverage/alarms.dialog/asyncua-client-to-go-server", p.assertDialog)
	t.Run("coverage/alarms.branches/asyncua-client-to-go-server", p.assertBranches)
	t.Run("coverage/alarms.alarm-groups/asyncua-client-to-go-server", p.assertGroups)
	t.Run("coverage/alarms.audit-events/asyncua-client-to-go-server", p.assertAudit)
}

// alarms105Peer is the go-opcua server fixture of the v1.05 alarm tests and
// the adapter client that drives it.
type alarms105Peer struct {
	run      func(t *testing.T, endpoint, subcmd string, args ...string) adapterResult
	endpoint string
	alarm    *server.Condition // every v1.05 alarm option, active
	dialog   *server.Condition // an active dialog with the options Ok / Cancel
	branched *server.Condition // a branching alarm without Confirm
	group    *server.AlarmGroup
	shelving *ua.NodeID // the ShelvingState object of alarm
	client   *opcua.Client
}

// startAlarms105 starts a go-opcua server with auditing on and the alarms of
// the v1.05 tests on s=Alarms105.Source, a notifier of the Server object.
func startAlarms105(t *testing.T, run func(t *testing.T, endpoint, subcmd string, args ...string) adapterResult) *alarms105Peer {
	t.Helper()
	endpoint, srv := startGoServerWithOptions(t, server.WithAuditing(true))
	_, nsIdx := findNSFromServer(t, srv)
	ns, err := srv.Namespace(int(nsIdx))
	if err != nil {
		t.Fatalf("Namespace: %v", err)
	}
	nns, ok := ns.(*server.NodeNameSpace)
	if !ok {
		t.Fatalf("namespace %d is a %T", nsIdx, ns)
	}
	src := server.NewFolderNode(ua.NewStringNodeID(nsIdx, "Alarms105.Source"), "Alarms105.Source")
	nns.AddNode(src)
	nns.Objects().AddRef(src, server.RefTypeIDOrganizes, true)

	add := func(cfg server.ConditionConfig) *server.Condition {
		t.Helper()
		cfg.NodeID = ua.NewStringNodeID(nsIdx, "Alarms105."+cfg.Name)
		cfg.Source = src.ID()
		cfg.SourceName = "Alarms105.Source"
		c, err := srv.AddCondition(cfg)
		if err != nil {
			t.Fatalf("AddCondition %s: %v", cfg.Name, err)
		}
		return c
	}
	p := &alarms105Peer{run: run, endpoint: endpoint}
	p.alarm = add(server.ConditionConfig{Name: "Alarm", Severity: 500, Confirmable: true,
		Suppressible: true, Serviceable: true, Silenceable: true, Latching: true, Shelving: true})
	ok0, cancel1 := int32(0), int32(1)
	p.dialog = add(server.ConditionConfig{Name: "Dialog", Type: ua.NewNumericNodeID(0, id.DialogConditionType),
		Dialog: &server.DialogConfig{Prompt: "Proceed?", ResponseOptions: []string{"Ok", "Cancel"},
			OkResponse: &ok0, CancelResponse: &cancel1, DefaultResponse: &cancel1, Active: true}})
	p.branched = add(server.ConditionConfig{Name: "Branched", Severity: 300, Branching: true})
	p.group, err = srv.AddAlarmGroup(server.AlarmGroupConfig{NodeID: ua.NewStringNodeID(nsIdx, "Alarms105.Group"),
		Namespace: nns, Name: "Alarms105.Group"})
	if err != nil {
		t.Fatalf("AddAlarmGroup: %v", err)
	}
	if err := p.group.AddMember(p.alarm); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	for _, c := range []*server.Condition{p.alarm, p.branched} {
		if err := c.SetActive(true); err != nil {
			t.Fatalf("SetActive: %v", err)
		}
	}

	// The ShelvingState object has a numeric NodeId: look it up with the
	// go-opcua client, which also pulses the audited calls.
	p.client = dialClient(t, endpoint)
	ctx := context.Background()
	res, err := p.client.Node(p.alarm.NodeID()).TranslateBrowsePathsToNodeIDs(ctx, []*ua.QualifiedName{{Name: "ShelvingState"}})
	if err != nil {
		t.Fatalf("ShelvingState: %v", err)
	}
	p.shelving = res
	return p
}

type alarms105CallResult struct {
	StatusCode      statusCodeObj   `json:"statusCode"`
	OutputArguments json.RawMessage `json:"outputArguments"`
}

// call calls method on object with the adapter client and returns the
// result of the method.
func (p *alarms105Peer) call(t *testing.T, object *ua.NodeID, method uint32, inputs ...string) alarms105CallResult {
	t.Helper()
	args := []string{"--object", object.String(), "--method", ua.NewNumericNodeID(0, method).String()}
	for _, in := range inputs {
		args = append(args, "--input", in)
	}
	result := p.run(t, p.endpoint, "call", args...)
	var items []alarms105CallResult
	if err := json.Unmarshal(result.Results, &items); err != nil || len(items) == 0 {
		t.Fatalf("call %d: parse results: %v; result: %+v raw: %s", method, err, result, result.Results)
	}
	return items[0]
}

// mustCall is call that expects want.
func (p *alarms105Peer) mustCall(t *testing.T, want ua.StatusCode, object *ua.NodeID, method uint32, inputs ...string) alarms105CallResult {
	t.Helper()
	r := p.call(t, object, method, inputs...)
	if r.StatusCode.Code != uint32(want) {
		t.Fatalf("call %d on %s: status %s (0x%08x), want %s", method, object, r.StatusCode.Name, r.StatusCode.Code, want)
	}
	return r
}

func (p *alarms105Peer) assertStateMethods(t *testing.T) {
	cid := p.alarm.NodeID()
	p.mustCall(t, ua.StatusOK, cid, id.AlarmConditionTypeSuppress2, "LocalizedText:en:maintenance")
	if st := p.alarm.State(); !st.Suppressed || st.Comment == nil || st.Comment.Text != "maintenance" {
		t.Fatalf("after Suppress2: suppressed=%v comment=%v", st.Suppressed, st.Comment)
	}
	p.mustCall(t, ua.StatusOK, cid, id.AlarmConditionTypeSilence)
	if !p.alarm.State().Silenced {
		t.Fatal("Silence: not silenced")
	}
	p.mustCall(t, ua.StatusOK, cid, id.AlarmConditionTypeRemoveFromService2, "LocalizedText:en:out")
	if !p.alarm.State().OutOfService {
		t.Fatal("RemoveFromService2: in service")
	}
	p.mustCall(t, ua.StatusOK, cid, id.AlarmConditionTypePlaceInService)
	if p.alarm.State().OutOfService {
		t.Fatal("PlaceInService: out of service")
	}
	// An active alarm stays latched (Part 9 §5.8.2 Reset).
	p.mustCall(t, ua.StatusBadInvalidState, cid, id.AlarmConditionTypeReset2, "LocalizedText:en:early")
	if err := p.alarm.SetActive(false); err != nil {
		t.Fatalf("SetActive: %v", err)
	}
	if !p.alarm.State().Latched {
		t.Fatal("the inactive alarm is not latched")
	}
	p.mustCall(t, ua.StatusOK, cid, id.AlarmConditionTypeReset)
	if p.alarm.State().Latched {
		t.Fatal("Reset: still latched")
	}
	p.mustCall(t, ua.StatusOK, p.shelving, id.ShelvedStateMachineTypeTimedShelve2, "Double:3600000", "LocalizedText:en:shelved")
	if st := p.alarm.State(); st.Shelving != server.TimedShelved || st.Comment == nil || st.Comment.Text != "shelved" {
		t.Fatalf("TimedShelve2: shelving=%v comment=%v", st.Shelving, st.Comment)
	}
}

func (p *alarms105Peer) assertDialog(t *testing.T) {
	cid := p.dialog.NodeID()
	// Option 2 does not exist.
	p.mustCall(t, ua.StatusBadDialogResponseInvalid, cid, id.DialogConditionTypeRespond2, "Int32:2", "LocalizedText:en:x")
	p.mustCall(t, ua.StatusOK, cid, id.DialogConditionTypeRespond2, "Int32:1", "LocalizedText:en:no")
	st := p.dialog.State()
	if st.DialogActive || st.LastResponse != 1 || st.Comment == nil || st.Comment.Text != "no" {
		t.Fatalf("Respond2: active=%v lastResponse=%d comment=%v", st.DialogActive, st.LastResponse, st.Comment)
	}
	p.mustCall(t, ua.StatusBadDialogNotActive, cid, id.DialogConditionTypeRespond, "Int32:0")
}

func (p *alarms105Peer) assertBranches(t *testing.T) {
	bid, err := p.branched.CreateBranch()
	if err != nil {
		t.Fatalf("CreateBranch: %v", err)
	}
	b, ok := p.branched.Branch(bid)
	if !ok {
		t.Fatal("no branch")
	}
	trunk := p.branched.State().EventID
	p.mustCall(t, ua.StatusOK, p.branched.NodeID(), id.AcknowledgeableConditionTypeAcknowledge,
		"ByteString:"+base64.StdEncoding.EncodeToString(b.EventID), "LocalizedText:en:branch")
	// The acknowledged branch needs no more action: it is gone; the
	// condition itself is untouched.
	if _, ok := p.branched.Branch(bid); ok {
		t.Fatal("the acknowledged branch still exists")
	}
	st := p.branched.State()
	if st.Acked || string(st.EventID) != string(trunk) {
		t.Fatalf("the trunk changed: acked=%v", st.Acked)
	}
	// Its EventId is no longer one of the condition's.
	r := p.call(t, p.branched.NodeID(), id.AcknowledgeableConditionTypeAcknowledge,
		"ByteString:"+base64.StdEncoding.EncodeToString(b.EventID), "LocalizedText:en:again")
	if r.StatusCode.Code != uint32(ua.StatusBadEventIDUnknown) {
		t.Fatalf("second Acknowledge: %s, want BadEventIdUnknown", r.StatusCode.Name)
	}
}

func (p *alarms105Peer) assertGroups(t *testing.T) {
	r := p.mustCall(t, ua.StatusOK, p.alarm.NodeID(), id.AlarmConditionTypeGetGroupMemberships)
	var out []json.RawMessage
	if err := json.Unmarshal(r.OutputArguments, &out); err != nil || len(out) != 1 {
		t.Fatalf("GetGroupMemberships outputs: %v %s", err, r.OutputArguments)
	}
	var groups []json.RawMessage
	if err := json.Unmarshal(out[0], &groups); err != nil || len(groups) != 1 {
		t.Fatalf("GetGroupMemberships Groups: %v %s", err, out[0])
	}
	// The canonical string of §6; the Milo adapter prints a NodeId of an
	// array as the Java object (namespaceIndex, identifier).
	var s string
	var obj struct {
		Identifier any `json:"identifier"`
	}
	switch {
	case json.Unmarshal(groups[0], &s) == nil && strings.HasSuffix(s, "s=Alarms105.Group"):
	case json.Unmarshal(groups[0], &obj) == nil && obj.Identifier == "Alarms105.Group":
	default:
		t.Fatalf("GetGroupMemberships Groups = %s, want the s=Alarms105.Group", out[0])
	}
	// The dialog is no alarm: it has no such method.
	p.mustCall(t, ua.StatusBadMethodInvalid, p.dialog.NodeID(), id.AlarmConditionTypeGetGroupMemberships)
}

// assertAudit subscribes to AuditConditionEventType events of the Server
// object with the adapter client while the go-opcua client calls Silence
// (audited even when the alarm is silenced already) until the adapter
// returns.
func (p *alarms105Peer) assertAudit(t *testing.T) {
	done, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				_ = p.client.Silence(ctx, p.alarm.NodeID())
				cancel()
			}
		}
	}()
	result := p.run(t, p.endpoint, "event-subscribe",
		"--node", "i=2253",
		"--of-type", "i=2790",
		"--events", "1",
		"--timeout-ms", "15000",
	)
	close(done)
	<-stopped
	if !result.Success {
		t.Fatalf("event-subscribe failed: %+v", result)
	}
	item := parseEventSubscribeItem(t, result)
	if len(item.Events) == 0 {
		t.Fatalf("no audit event: %+v", item)
	}
	fields := map[string]string{}
	for _, f := range item.Events[0].Fields {
		var s *string
		if json.Unmarshal(f.Value, &s) == nil && s != nil {
			fields[f.Name] = *s
		}
	}
	// The condition events of the same notifier have the SourceName
	// Alarms105.Source: Method/Silence is the audit event the OfType filter
	// selected. The open62541 adapter prints only numbers and strings of an
	// event (NodeId fields are null), so EventType is checked when present.
	if got := fields["SourceName"]; got != "Method/Silence" {
		t.Fatalf("SourceName = %q, want Method/Silence; fields %v", got, item.Events[0].Fields)
	}
	if got, ok := fields["EventType"]; ok && !strings.HasSuffix(got, "i=17242") {
		t.Fatalf("EventType = %q, want i=17242 (AuditConditionSilenceEventType)", got)
	}
}
