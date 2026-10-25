//go:build interop

// SPDX-License-Identifier: MIT

// Alarms & Conditions (OPC UA Part 9) peer tests, both directions:
//
//   - the go-opcua client against the alarm fixture of the peer servers that
//     declare serverFeatures "alarms" (UA-.NETStandard, node-opcua,
//     open62541; opcua-interop fixtures/baseline/README.md "Alarms"):
//     ConditionRefresh (Part 9 §5.5.7), Acknowledge / Confirm (§5.7.3,
//     §5.7.4), AddComment (§5.5.6), Disable / Enable (§5.5.4, §5.5.5);
//   - every adapter's `client alarms` operation against a condition of the
//     go-opcua server (CLIENT_CONTRACT §1 "alarms flags", §4 "alarms").
//
// The UA-.NETStandard, node-opcua and async-opcua tests are in
// dotnet_alarms_test.go, nodeopcua_alarms_test.go and asyncopcua_alarms_test.go
// (their ledgers look up the cases in those files).
//
// COVERAGE.md: alarms-conditions / alarms.condition-refresh,
// alarms.acknowledgeable

package interop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// interopAlarmName is the ConditionName of the alarm fixture, on both sides.
const interopAlarmName = "InteropAlarm"

// ---------------------------------------------------------------------------
// go-opcua client → peer alarm servers
// ---------------------------------------------------------------------------

func TestOpen62541Server_Alarms(t *testing.T) {
	requireServerFeature(t, "OPEN62541_IMAGE", defaultOpen62541Image, "alarms")
	s := newPeerAlarmSession(t, startOpen62541Server(t).endpoint)
	t.Run("coverage/alarms.condition-refresh/go-client-to-open62541-server", s.assertRefresh)
	t.Run("coverage/alarms.acknowledgeable/go-client-to-open62541-server", s.assertActions)
}

// peerAlarmSession is a go-opcua client with one event monitored item on the
// Server object (the alarm fixture's source is one of its notifiers) and the
// condition events it received.
type peerAlarmSession struct {
	c      *opcua.Client
	ctx    context.Context
	sub    *opcua.Subscription
	ch     <-chan *opcua.PublishNotificationData
	buf    []*opcua.ConditionEvent
	source *ua.NodeID
	reset  *ua.NodeID
	// cond is the refreshed InteropAlarm (assertRefresh).
	cond *opcua.ConditionEvent
}

func newPeerAlarmSession(t *testing.T, endpoint string) *peerAlarmSession {
	t.Helper()
	return newPeerAlarmSessionOn(t, dialClient(t, endpoint))
}

// newPeerAlarmSessionOn is newPeerAlarmSession on a connected client.
func newPeerAlarmSessionOn(t *testing.T, c *opcua.Client) *peerAlarmSession {
	t.Helper()
	ctx, nsIdx := findNS(t, c)
	s := &peerAlarmSession{
		c:      c,
		ctx:    ctx,
		source: ua.NewStringNodeID(nsIdx, "Alarms.Source"),
		reset:  ua.NewStringNodeID(nsIdx, "Alarms.Reset"),
	}
	// The server container may be shared: re-arm the alarm first, and
	// again at the end (re-enables a condition a failed run left disabled).
	s.callReset(t)
	t.Cleanup(func() { s.callReset(t) })
	sub, ch, err := c.NewSubscription().Interval(100 * time.Millisecond).Start(ctx)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Cancel(context.Background()) })
	res, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, &ua.MonitoredItemCreateRequest{
		ItemToMonitor:  &ua.ReadValueID{NodeID: ua.NewNumericNodeID(0, id.Server), AttributeID: ua.AttributeIDEventNotifier},
		MonitoringMode: ua.MonitoringModeReporting,
		RequestedParameters: &ua.MonitoringParameters{
			ClientHandle: 1,
			Filter:       ua.NewExtensionObject(opcua.NewConditionEventFilter()),
			QueueSize:    1000,
		},
	})
	if err != nil {
		t.Fatalf("CreateMonitoredItems: %v", err)
	}
	if len(res.Results) != 1 || res.Results[0].StatusCode != ua.StatusOK {
		t.Fatalf("event monitored item: %+v", res.Results)
	}
	if fr, ok := res.Results[0].FilterResult.Value.(*ua.EventFilterResult); ok {
		for i, sc := range fr.SelectClauseResults {
			if sc != ua.StatusOK {
				t.Logf("select clause %d: %v", i, sc)
			}
		}
	}
	s.sub, s.ch = sub, ch
	return s
}

func (s *peerAlarmSession) callReset(t *testing.T) {
	t.Helper()
	res, err := s.c.Call(s.ctx, &ua.CallMethodRequest{ObjectID: s.source, MethodID: s.reset})
	if err != nil {
		t.Fatalf("Call Alarms.Reset: %v", err)
	}
	if res.StatusCode != ua.StatusOK {
		t.Fatalf("Alarms.Reset: %v", res.StatusCode)
	}
}

// next waits for the next condition event that satisfies pred (the
// asserted event, not a count of events within a time window).
func (s *peerAlarmSession) next(t *testing.T, what string, pred func(*opcua.ConditionEvent) bool) *opcua.ConditionEvent {
	t.Helper()
	deadline := time.After(20 * time.Second)
	for {
		for len(s.buf) > 0 {
			ev := s.buf[0]
			s.buf = s.buf[1:]
			if pred(ev) {
				return ev
			}
		}
		select {
		case msg := <-s.ch:
			if msg.Error != nil {
				t.Fatalf("notification error: %v", msg.Error)
			}
			enl, ok := msg.Value.(*ua.EventNotificationList)
			if !ok {
				continue
			}
			for _, f := range enl.Events {
				ev, err := opcua.ParseConditionEvent(f)
				if err != nil {
					t.Fatalf("ParseConditionEvent: %v", err)
				}
				s.buf = append(s.buf, ev)
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %s", what)
			return nil
		}
	}
}

func (s *peerAlarmSession) isAlarm(ev *opcua.ConditionEvent) bool {
	return ev.ConditionName == interopAlarmName && ev.SourceNode != nil && ev.SourceNode.Equal(s.source)
}

// refresh calls ConditionRefresh and returns the InteropAlarm event between
// the RefreshStartEvent and the RefreshEndEvent (Part 9 §5.5.7, §4.5).
func (s *peerAlarmSession) refresh(t *testing.T) *opcua.ConditionEvent {
	t.Helper()
	if err := s.sub.ConditionRefresh(s.ctx); err != nil {
		t.Fatalf("ConditionRefresh: %v", err)
	}
	s.next(t, "RefreshStartEvent", (*opcua.ConditionEvent).IsRefreshStart)
	var cond *opcua.ConditionEvent
	s.next(t, "RefreshEndEvent", func(ev *opcua.ConditionEvent) bool {
		if s.isAlarm(ev) {
			cond = ev
		}
		return ev.IsRefreshEnd()
	})
	return cond
}

func (s *peerAlarmSession) assertRefresh(t *testing.T) {
	cond := s.refresh(t)
	if cond == nil {
		t.Fatalf("ConditionRefresh did not report %s", interopAlarmName)
	}
	if cond.ConditionID == nil || cond.ConditionID.IntID() == 0 && cond.ConditionID.StringID() == "" {
		t.Errorf("ConditionId = %v", cond.ConditionID)
	}
	if len(cond.EventID) == 0 {
		t.Error("refreshed condition event without EventId")
	}
	if cond.EventType == nil || cond.EventType.Namespace() != 0 || cond.EventType.IntID() != id.AlarmConditionType {
		t.Errorf("EventType = %v, want AlarmConditionType", cond.EventType)
	}
	if !cond.Retain || !cond.Enabled || cond.Severity != 500 {
		t.Errorf("retain=%v enabled=%v severity=%d, want true/true/500", cond.Retain, cond.Enabled, cond.Severity)
	}
	if cond.Active == nil || !*cond.Active || cond.Acked == nil || *cond.Acked {
		t.Errorf("active=%v acked=%v, want an active unacknowledged alarm after Reset", cond.Active, cond.Acked)
	}
	s.cond = cond
}

func (s *peerAlarmSession) assertActions(t *testing.T) {
	if s.cond == nil {
		t.Skip("no refreshed condition (the condition-refresh case failed)")
	}
	condID, eventID := s.cond.ConditionID, s.cond.EventID
	isCond := func(ev *opcua.ConditionEvent) bool { return ev.ConditionID != nil && ev.ConditionID.Equal(condID) }

	if err := s.c.Acknowledge(s.ctx, condID, eventID, "go-ack"); err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}
	acked := s.next(t, "the acknowledged event", func(ev *opcua.ConditionEvent) bool {
		return isCond(ev) && ev.Acked != nil && *ev.Acked
	})
	if acked.Comment == nil || acked.Comment.Text != "go-ack" {
		t.Errorf("Comment after Acknowledge = %v, want go-ack", acked.Comment)
	}
	// A repeated Acknowledge with the now stale EventId (Part 9 §5.7.3):
	// UA-.NETStandard answers Bad_ConditionBranchAlreadyAcked, node-opcua and
	// open62541 Bad_EventIdUnknown.
	err := s.c.Acknowledge(s.ctx, condID, eventID, "go-ack")
	if !errors.Is(err, ua.StatusBadConditionBranchAlreadyAcked) && !errors.Is(err, ua.StatusBadEventIDUnknown) {
		t.Errorf("repeated Acknowledge = %v, want Bad_ConditionBranchAlreadyAcked or Bad_EventIdUnknown", err)
	}

	if err := s.c.Confirm(s.ctx, condID, acked.EventID, "go-confirm"); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	confirmed := s.next(t, "the confirmed event", func(ev *opcua.ConditionEvent) bool {
		return isCond(ev) && ev.Confirmed != nil && *ev.Confirmed
	})

	if err := s.c.AddComment(s.ctx, condID, confirmed.EventID, "go-comment"); err != nil {
		t.Fatalf("AddComment: %v", err)
	}
	s.next(t, "the comment event", func(ev *opcua.ConditionEvent) bool {
		return isCond(ev) && ev.Comment != nil && ev.Comment.Text == "go-comment"
	})

	// Disable / Enable (Part 9 §5.5.4, §5.5.5), each repeated.
	if err := s.c.DisableCondition(s.ctx, condID); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if err := s.c.DisableCondition(s.ctx, condID); !errors.Is(err, ua.StatusBadConditionAlreadyDisabled) {
		t.Errorf("repeated Disable = %v, want Bad_ConditionAlreadyDisabled", err)
	}
	if err := s.c.EnableCondition(s.ctx, condID); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if err := s.c.EnableCondition(s.ctx, condID); !errors.Is(err, ua.StatusBadConditionAlreadyEnabled) {
		t.Errorf("repeated Enable = %v, want Bad_ConditionAlreadyEnabled", err)
	}
}

// auditMethod is a condition method of assertAudit and the audit event type
// the server raises for it (Part 9 §5.10).
type auditMethod struct {
	name      string
	method    uint32
	eventType uint32
	comment   string
	// source is the expected SourceNode (the ConditionId per Part 9
	// §5.10.2; nil skips the check), sourceName the expected SourceName
	// ("" skips it).
	source     *ua.NodeID
	sourceName string
	// statusBool: Status is a Boolean (Part 5 §6.4.3), checked to be true.
	statusBool bool
}

// auditPeer is what a peer server fills in its condition audit events where
// it departs from Part 9 §5.10, as observed.
type auditPeer struct {
	// noMethodID: MethodId (AuditUpdateMethodEventType) is null, not the
	// called method.
	noMethodID bool
	// ackEventIDAfter: the ConditionEventId of the Acknowledge audit event
	// is the EventId of the condition after the call (the acknowledged
	// event), not the EventId the client acknowledged.
	ackEventIDAfter bool
	// commentOnServer: the AuditConditionCommentEventType of AddComment is
	// raised on the Server object with SourceName "Method/AddComment", not
	// on the condition.
	commentOnServer bool
	// ackStatusCode: the Status of the Acknowledge and Confirm audit events
	// is a StatusCode, not the Boolean of AuditEventType.
	ackStatusCode bool
	// instanceMethodID: MethodId is the method of the condition instance
	// (its Acknowledge, Confirm, AddComment component), not the method of
	// the type the client called.
	instanceMethodID bool
	// ackArgsOnly: the Acknowledge and Confirm audit events have no
	// ConditionEventId and Comment; the EventId and the Comment are only in
	// InputArguments.
	ackArgsOnly bool
}

// newPeerAuditAlarmSession starts the peer server (with serverArgs) with the
// baseline fixture plus a SecurityAdmin user (pushFixtureDir) and opens the alarm session as
// that user over Basic256Sha256 SignAndEncrypt: the peers deliver Audit
// Events only to sessions holding ReceiveEvents on the audit event types,
// which Opc.Ua.NodeSet2.xml grants to SecurityAdmin alone (Part 2 §4.14,
// Part 3 §5.2.10).
func newPeerAuditAlarmSession(t *testing.T, env, image, pki string, serverArgs ...string) *peerAlarmSession {
	t.Helper()
	h := startSecureAdapterServerIn(t, env, image, pki, pushFixtureDir(t), serverArgs...)
	return newPeerAlarmSessionOn(t, pushClient(t, h.endpoint, true))
}

// assertAudit monitors the audit events of condition methods on the Server
// object (opcua.NewAuditConditionEventFilter, OfType AuditConditionEventType)
// with a second subscription, acknowledges, confirms and comments the
// refreshed InteropAlarm and asserts the AuditConditionAcknowledgeEventType,
// AuditConditionConfirmEventType and AuditConditionCommentEventType event of
// each call: its ConditionEventId, Comment, SourceNode, SourceName and, as
// the peer fills them (p), MethodId and Status.
func (s *peerAlarmSession) assertAudit(t *testing.T, p auditPeer) {
	sub, ch, err := s.c.NewSubscription().Interval(100 * time.Millisecond).Start(s.ctx)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Cancel(context.Background()) })
	res, err := sub.Monitor(s.ctx, ua.TimestampsToReturnBoth, &ua.MonitoredItemCreateRequest{
		ItemToMonitor:  &ua.ReadValueID{NodeID: ua.NewNumericNodeID(0, id.Server), AttributeID: ua.AttributeIDEventNotifier},
		MonitoringMode: ua.MonitoringModeReporting,
		RequestedParameters: &ua.MonitoringParameters{
			ClientHandle: 2,
			Filter:       ua.NewExtensionObject(opcua.NewAuditConditionEventFilter()),
			QueueSize:    1000,
		},
	})
	if err != nil {
		t.Fatalf("CreateMonitoredItems: %v", err)
	}
	if len(res.Results) != 1 || res.Results[0].StatusCode != ua.StatusOK {
		t.Fatalf("audit event monitored item: %+v", res.Results)
	}

	cond := s.refresh(t)
	if cond == nil {
		t.Fatalf("ConditionRefresh did not report %s", interopAlarmName)
	}
	condID, eventID := cond.ConditionID, cond.EventID
	isCond := func(ev *opcua.ConditionEvent) bool { return ev.ConditionID != nil && ev.ConditionID.Equal(condID) }

	var pending []*opcua.AuditConditionEvent
	nextAudit := func(m auditMethod) *opcua.AuditConditionEvent {
		t.Helper()
		deadline := time.After(20 * time.Second)
		for {
			for len(pending) > 0 {
				ev := pending[0]
				pending = pending[1:]
				// node-opcua raises an AuditConditionCommentEventType for
				// Confirm too (SourceName Method/Confirm): sourceName tells
				// them apart.
				if ev.EventType != nil && ev.EventType.Namespace() == 0 && ev.EventType.IntID() == m.eventType &&
					(m.sourceName == "" || ev.SourceName == m.sourceName) {
					return ev
				}
				t.Logf("audit event %v skipped: %+v", ev.EventType, ev)
			}
			select {
			case msg := <-ch:
				if msg.Error != nil {
					t.Fatalf("notification error: %v", msg.Error)
				}
				enl, ok := msg.Value.(*ua.EventNotificationList)
				if !ok {
					continue
				}
				for _, f := range enl.Events {
					ev, err := opcua.ParseAuditConditionEvent(f)
					if err != nil {
						t.Fatalf("ParseAuditConditionEvent: %v", err)
					}
					pending = append(pending, ev)
				}
			case <-deadline:
				t.Fatalf("timed out waiting for the %s audit event (i=%d)", m.name, m.eventType)
				return nil
			}
		}
	}
	check := func(m auditMethod, condEventID []byte) {
		t.Helper()
		ev := nextAudit(m)
		t.Logf("%s audit event: %+v", m.name, ev)
		switch {
		case p.noMethodID:
		case p.instanceMethodID:
			want, err := s.c.Node(condID).TranslateBrowsePathsToNodeIDs(s.ctx, []*ua.QualifiedName{{Name: m.name}})
			if err != nil {
				t.Fatalf("%s of the condition: %v", m.name, err)
			}
			if ev.MethodID == nil || !ev.MethodID.Equal(want) {
				t.Errorf("%s: MethodId = %v, want the condition's %v", m.name, ev.MethodID, want)
			}
		case ev.MethodID == nil || ev.MethodID.Namespace() != 0 || ev.MethodID.IntID() != m.method:
			t.Errorf("%s: MethodId = %v, want i=%d", m.name, ev.MethodID, m.method)
		}
		if m.source != nil && (ev.SourceNode == nil || !ev.SourceNode.Equal(m.source)) {
			t.Errorf("%s: SourceNode = %v, want %v", m.name, ev.SourceNode, m.source)
		}
		if m.sourceName != "" && ev.SourceName != m.sourceName {
			t.Errorf("%s: SourceName = %q, want %q", m.name, ev.SourceName, m.sourceName)
		}
		if p.ackArgsOnly && m.method != id.ConditionTypeAddComment {
			// Only the InputArguments (EventId, Comment) of the call.
			if len(ev.ConditionEventID) != 0 || ev.Comment != nil && ev.Comment.Text != "" {
				t.Errorf("%s: ConditionEventId %x Comment %v, want none", m.name, ev.ConditionEventID, ev.Comment)
			}
			var gotID []byte
			var gotComment *ua.LocalizedText
			if len(ev.InputArguments) == 2 {
				gotID, _ = ev.InputArguments[0].Value().([]byte)
				gotComment, _ = ev.InputArguments[1].Value().(*ua.LocalizedText)
			}
			if !bytes.Equal(gotID, condEventID) || gotComment == nil || gotComment.Text != m.comment {
				t.Errorf("%s: InputArguments %v, want [%x %s]", m.name, ev.InputArguments, condEventID, m.comment)
			}
		} else {
			if !bytes.Equal(ev.ConditionEventID, condEventID) {
				t.Errorf("%s: ConditionEventId = %x, want %x", m.name, ev.ConditionEventID, condEventID)
			}
			if ev.Comment == nil || ev.Comment.Text != m.comment {
				t.Errorf("%s: Comment = %v, want %s", m.name, ev.Comment, m.comment)
			}
		}
		if m.statusBool && !ev.Status {
			t.Errorf("%s: Status = false, want true", m.name)
		}
		if len(ev.EventID) == 0 || ev.Time.IsZero() {
			t.Errorf("%s: EventId %x Time %v", m.name, ev.EventID, ev.Time)
		}
	}

	if err := s.c.Acknowledge(s.ctx, condID, eventID, "go-audit-ack"); err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}
	acked := s.next(t, "the acknowledged event", func(ev *opcua.ConditionEvent) bool {
		return isCond(ev) && ev.Acked != nil && *ev.Acked
	})
	ackEventID := eventID
	if p.ackEventIDAfter {
		ackEventID = acked.EventID
	}
	check(auditMethod{name: "Acknowledge", method: id.AcknowledgeableConditionTypeAcknowledge,
		eventType: id.AuditConditionAcknowledgeEventType, comment: "go-audit-ack",
		source: condID, statusBool: !p.ackStatusCode}, ackEventID)

	if err := s.c.Confirm(s.ctx, condID, acked.EventID, "go-audit-confirm"); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	confirmed := s.next(t, "the confirmed event", func(ev *opcua.ConditionEvent) bool {
		return isCond(ev) && ev.Confirmed != nil && *ev.Confirmed
	})
	check(auditMethod{name: "Confirm", method: id.AcknowledgeableConditionTypeConfirm,
		eventType: id.AuditConditionConfirmEventType, comment: "go-audit-confirm",
		source: condID, statusBool: !p.ackStatusCode}, acked.EventID)

	if err := s.c.AddComment(s.ctx, condID, confirmed.EventID, "go-audit-comment"); err != nil {
		t.Fatalf("AddComment: %v", err)
	}
	comment := auditMethod{name: "AddComment", method: id.ConditionTypeAddComment,
		eventType: id.AuditConditionCommentEventType, comment: "go-audit-comment",
		source: condID, statusBool: true}
	if p.commentOnServer {
		comment.source, comment.sourceName = ua.NewNumericNodeID(0, id.Server), "Method/AddComment"
	}
	check(comment, confirmed.EventID)
}

// ---------------------------------------------------------------------------
// peer clients (`client alarms`) → go-opcua server
// ---------------------------------------------------------------------------

func TestGoServer_Open62541Client_Alarms(t *testing.T) {
	requireAdapterOp(t, "OPEN62541_IMAGE", defaultOpen62541Image, "alarms")
	r := runPeerAlarms(t, runOpen62541ClientResult)
	t.Run("coverage/alarms.condition-refresh/open62541-client-to-go-server", r.assertRefresh)
	t.Run("coverage/alarms.acknowledgeable/open62541-client-to-go-server", r.assertActions)
}

func TestGoServer_MiloClient_Alarms(t *testing.T) {
	requireAdapterOp(t, "MILO_IMAGE", defaultMiloImage, "alarms")
	r := runPeerAlarms(t, runMiloClientResult)
	t.Run("coverage/alarms.condition-refresh/milo-client-to-go-server", r.assertRefresh)
	t.Run("coverage/alarms.acknowledgeable/milo-client-to-go-server", r.assertActions)
}

func TestGoServer_AsyncuaClient_Alarms(t *testing.T) {
	requireAdapterOp(t, asyncuaEnv, defaultAsyncuaImage, "alarms")
	r := runPeerAlarms(t, runAsyncuaClientResult)
	t.Run("coverage/alarms.condition-refresh/asyncua-client-to-go-server", r.assertRefresh)
	t.Run("coverage/alarms.acknowledgeable/asyncua-client-to-go-server", r.assertActions)
}

// alarmsConditionEntry is a ConditionEntry of the `alarms` result
// (CLIENT_CONTRACT §4). Nullable fields are pointers.
type alarmsConditionEntry struct {
	ConditionID   string  `json:"conditionId"`
	EventID       *string `json:"eventId"`
	EventType     *string `json:"eventType"`
	SourceNode    *string `json:"sourceNode"`
	SourceName    *string `json:"sourceName"`
	ConditionName *string `json:"conditionName"`
	Time          *string `json:"time"`
	Message       *string `json:"message"`
	Severity      *int    `json:"severity"`
	Retain        *bool   `json:"retain"`
	Enabled       *bool   `json:"enabled"`
	Acked         *bool   `json:"acked"`
	Confirmed     *bool   `json:"confirmed"`
	Active        *bool   `json:"active"`
	Comment       *string `json:"comment"`
}

type alarmsAction struct {
	StatusCode       statusCodeObj         `json:"statusCode"`
	Event            *alarmsConditionEntry `json:"event"`
	RepeatStatusCode *statusCodeObj        `json:"repeatStatusCode"`
}

type alarmsResultItem struct {
	NodeID        string        `json:"nodeId"`
	MonitoredItem statusCodeObj `json:"monitoredItemStatusCode"`
	Refresh       struct {
		StatusCode statusCodeObj `json:"statusCode"`
		StartSeen  bool          `json:"startSeen"`
		EndSeen    bool          `json:"endSeen"`
	} `json:"refresh"`
	Conditions  []alarmsConditionEntry `json:"conditions"`
	Target      *alarmsConditionEntry  `json:"target"`
	Acknowledge *alarmsAction          `json:"acknowledge"`
	Confirm     *alarmsAction          `json:"confirm"`
	AddComment  *alarmsAction          `json:"addComment"`
}

// peerAlarmsRun is one `client alarms` run against a go-opcua server
// condition, with the server-side condition for the state assertions.
type peerAlarmsRun struct {
	result adapterResult
	item   alarmsResultItem
	cond   *server.Condition
}

// startGoServerWithAlarm starts the baseline go-opcua server with the alarm
// fixture of opcua-interop (fixtures/baseline/README.md "Alarms"): an active,
// unacknowledged, confirmable AlarmConditionType InteropAlarm on
// s=Alarms.Source, a notifier of the Server object.
func startGoServerWithAlarm(t *testing.T) (string, *server.Condition) {
	t.Helper()
	endpoint, srv := startGoServerWithOptions(t)
	_, nsIdx := findNSFromServer(t, srv)
	ns, err := srv.Namespace(int(nsIdx))
	if err != nil {
		t.Fatalf("Namespace: %v", err)
	}
	nns, ok := ns.(*server.NodeNameSpace)
	if !ok {
		t.Fatalf("namespace %d is a %T", nsIdx, ns)
	}
	src := server.NewFolderNode(ua.NewStringNodeID(nsIdx, "Alarms.Source"), "Alarms.Source")
	nns.AddNode(src)
	nns.Objects().AddRef(src, server.RefTypeIDOrganizes, true)
	cond, err := srv.AddCondition(server.ConditionConfig{
		NodeID:      ua.NewStringNodeID(nsIdx, "Alarms.InteropAlarm"),
		Name:        interopAlarmName,
		Source:      src.ID(),
		SourceName:  "Alarms.Source",
		Severity:    500,
		Message:     "interop-alarm",
		Confirmable: true,
	})
	if err != nil {
		t.Fatalf("AddCondition: %v", err)
	}
	if err := cond.SetActive(true); err != nil {
		t.Fatalf("SetActive: %v", err)
	}
	return endpoint, cond
}

func runPeerAlarms(t *testing.T, run func(t *testing.T, endpoint, subcmd string, args ...string) adapterResult) *peerAlarmsRun {
	t.Helper()
	endpoint, cond := startGoServerWithAlarm(t)
	result := run(t, endpoint, "alarms",
		"--node", "i=2253",
		"--condition-name", interopAlarmName,
		"--acknowledge", "--confirm", "--add-comment",
		"--timeout-ms", "20000",
	)
	r := &peerAlarmsRun{result: result, cond: cond}
	var items []alarmsResultItem
	if err := json.Unmarshal(result.Results, &items); err != nil || len(items) == 0 {
		t.Fatalf("parse alarms results: %v; result: %+v raw: %s", err, result, result.Results)
	}
	r.item = items[0]
	return r
}

func (r *peerAlarmsRun) isAlarm(e *alarmsConditionEntry) bool {
	return e != nil && strings.HasSuffix(e.ConditionID, "s=Alarms.InteropAlarm")
}

func (r *peerAlarmsRun) assertRefresh(t *testing.T) {
	it := r.item
	if it.MonitoredItem.Code != 0 {
		t.Fatalf("event monitored item: %+v", it.MonitoredItem)
	}
	if it.Refresh.StatusCode.Code != 0 || !it.Refresh.StartSeen || !it.Refresh.EndSeen {
		t.Fatalf("ConditionRefresh: %+v", it.Refresh)
	}
	var found *alarmsConditionEntry
	for i := range it.Conditions {
		if r.isAlarm(&it.Conditions[i]) {
			found = &it.Conditions[i]
		}
	}
	if found == nil {
		t.Fatalf("refreshed conditions %+v lack s=Alarms.InteropAlarm", it.Conditions)
	}
	if found.ConditionName == nil || *found.ConditionName != interopAlarmName {
		t.Errorf("conditionName = %v", found.ConditionName)
	}
	if found.EventType == nil || *found.EventType != "i=2915" {
		t.Errorf("eventType = %v, want i=2915", found.EventType)
	}
	if found.SourceName == nil || *found.SourceName != "Alarms.Source" {
		t.Errorf("sourceName = %v", found.SourceName)
	}
	if found.Message == nil || *found.Message != "interop-alarm" {
		t.Errorf("message = %v", found.Message)
	}
	if found.Severity == nil || *found.Severity != 500 {
		t.Errorf("severity = %v", found.Severity)
	}
	for name, v := range map[string]*bool{"retain": found.Retain, "enabled": found.Enabled, "active": found.Active} {
		if v == nil || !*v {
			t.Errorf("%s = %v, want true", name, v)
		}
	}
	if found.Acked == nil || *found.Acked || found.Confirmed == nil || *found.Confirmed {
		t.Errorf("acked=%v confirmed=%v, want false/false", found.Acked, found.Confirmed)
	}
	if !r.isAlarm(it.Target) {
		t.Errorf("target = %+v", it.Target)
	}
}

func (r *peerAlarmsRun) assertActions(t *testing.T) {
	it := r.item
	if !r.result.Success {
		t.Errorf("alarms: success=false: %+v %s", r.result.ServiceResult, r.result.Error)
	}
	check := func(name string, a *alarmsAction, ok func(*alarmsConditionEntry) bool) {
		t.Helper()
		switch {
		case a == nil:
			t.Errorf("%s: not run", name)
		case a.StatusCode.Code != 0:
			t.Errorf("%s: %+v", name, a.StatusCode)
		case a.Event == nil || !ok(a.Event):
			t.Errorf("%s: event %+v", name, a.Event)
		}
	}
	isTrue := func(b *bool) bool { return b != nil && *b }
	check("acknowledge", it.Acknowledge, func(e *alarmsConditionEntry) bool { return isTrue(e.Acked) })
	check("confirm", it.Confirm, func(e *alarmsConditionEntry) bool { return isTrue(e.Confirmed) })
	check("addComment", it.AddComment, func(e *alarmsConditionEntry) bool {
		return e.Comment != nil && *e.Comment == "interop-comment"
	})
	// The go-opcua server still knows the recent EventIds of the condition,
	// so it refuses the repeated Acknowledge for the state (Part 9 §5.7.3).
	if a := it.Acknowledge; a != nil {
		if a.RepeatStatusCode == nil || a.RepeatStatusCode.Code != uint32(ua.StatusBadConditionBranchAlreadyAcked) {
			t.Errorf("repeated Acknowledge = %+v, want Bad_ConditionBranchAlreadyAcked", a.RepeatStatusCode)
		}
	}
	st := r.cond.State()
	if !st.Acked || !st.Confirmed || !st.Active || !st.Retain {
		t.Errorf("server state acked=%v confirmed=%v active=%v retain=%v, want all true", st.Acked, st.Confirmed, st.Active, st.Retain)
	}
	if st.Comment == nil || st.Comment.Text != "interop-comment" {
		t.Errorf("server Comment = %v, want interop-comment", st.Comment)
	}
	if st.ClientUserID == "" {
		t.Error("server ClientUserId is empty")
	}
}
