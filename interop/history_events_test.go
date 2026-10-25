//go:build interop

// SPDX-License-Identifier: MIT

// The historical events fixture of opcua-interop (CLIENT_CONTRACT §17) on
// the go-opcua server, the assertions the peer clients run against it and
// the ones the go-opcua client runs against the peer servers.
// COVERAGE.md: history / history.read.events, history.read.events.continuation,
// history.read.events.filter, history.update.events, history.delete.events

package interop

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// histEventsBase is the Time of the first seeded event (§17.1); event n is
// at histEventsBase + 5 s × n.
var histEventsBase = time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)

const (
	histEventsName      = "History.Events"
	histEventsResetName = "History.ResetEvents"
	histEventsSeedCount = 5
	// histEventsNode is the fixture notifier as the adapter clients take it.
	histEventsNode = "nsu=" + interopNamespaceURI + ";s=" + histEventsName
)

// histEventID is the EventId of seeded event n: the ASCII bytes hist-evt-n.
func histEventID(n int) []byte { return []byte("hist-evt-" + strconv.Itoa(n)) }

// histEventType is the EventType of seeded event n: SystemEventType for
// hist-evt-3, BaseEventType for the others.
func histEventType(n int) *ua.NodeID {
	if n == 3 {
		return ua.NewNumericNodeID(0, id.SystemEventType)
	}
	return ua.NewNumericNodeID(0, id.BaseEventType)
}

// goEventHistory is a go-opcua server with the fixture s=History.Events: a
// writable HistoricalEventNode of the built-in Historian with the five seed
// events, and the method s=History.ResetEvents that restores the seed.
type goEventHistory struct {
	endpoint string
	srv      *server.Server
	hist     *server.Historian
	notifier *ua.NodeID
}

// reset restores the seed: EnableEvents starts an empty history of the
// notifier, then the five events are recorded.
func (g *goEventHistory) reset() {
	g.hist.EnableEvents(g.notifier, 1000)
	for n := range histEventsSeedCount {
		at := histEventsBase.Add(time.Duration(n) * 5 * time.Second)
		g.hist.RecordEvent(g.notifier, &server.HistoricalEvent{Fields: map[string]*ua.Variant{
			"EventId":     ua.MustVariant(histEventID(n)),
			"EventType":   ua.MustVariant(histEventType(n)),
			"SourceNode":  ua.MustVariant(g.notifier),
			"SourceName":  ua.MustVariant(histEventsName),
			"Time":        ua.MustVariant(at),
			"ReceiveTime": ua.MustVariant(at),
			"Message":     ua.MustVariant(ua.NewLocalizedTextWithLocale("history-event-"+strconv.Itoa(n), "en")),
			"Severity":    ua.MustVariant(uint16(100 * (n + 1))),
		}})
	}
}

// startGoServerWithEventHistory starts a go-opcua server (None, anonymous)
// with the fixture s=History.Events (§17.1) below the folder s=History.
func startGoServerWithEventHistory(t *testing.T) *goEventHistory {
	t.Helper()
	s, err := server.New(
		server.ListenOn("0.0.0.0:0"),
		server.EndPoint("host.docker.internal", 0),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
	)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ns := server.NewNodeNameSpace(s, interopNamespaceURI)
	s.AddNamespace(ns)
	nsIdx := ns.ID()

	folder := server.NewFolderNode(ua.NewStringNodeID(nsIdx, "History"), "History")
	ns.AddNode(folder)
	ns.Objects().AddRef(folder, id.Organizes, true)

	g := &goEventHistory{srv: s, hist: server.NewHistorian(), notifier: ua.NewStringNodeID(nsIdx, histEventsName)}
	obj := server.NewFolderNode(g.notifier, histEventsName)
	ns.AddNode(obj)
	folder.AddRef(obj, id.Organizes, true)
	if tn := s.Node(ua.NewNumericNodeID(0, id.BaseObjectType)); tn != nil {
		obj.AddRef(tn, id.HasTypeDefinition, true)
	}

	resetID := ua.NewStringNodeID(nsIdx, histEventsResetName)
	reset := server.NewFolderNode(resetID, histEventsResetName)
	reset.SetNodeClass(ua.NodeClassMethod)
	ns.AddNode(reset)
	obj.AddRef(reset, id.HasComponent, true)
	s.RegisterMethod(g.notifier, resetID, func(context.Context, *ua.NodeID, *ua.NodeID, []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		g.reset()
		return nil, ua.StatusOK
	})

	s.SetHistorian(g.hist)
	if err := s.EnableEventHistory(g.notifier, server.EventHistoryOptions{Writable: true}); err != nil {
		t.Fatalf("EnableEventHistory: %v", err)
	}
	g.reset()

	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("server.Start: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if s.Port() == 0 {
		t.Fatal("server.Start: bound port is 0")
	}
	g.endpoint = fmt.Sprintf("opc.tcp://localhost:%d", s.Port())
	return g
}

// ---------------------------------------------------------------------------
// Adapter client results (CLIENT_CONTRACT §4 history-read-events,
// history-update-events)
// ---------------------------------------------------------------------------

type histEventField struct {
	Name        string          `json:"name"`
	DataType    string          `json:"dataType"`
	BuiltInType int             `json:"builtInType"`
	Value       json.RawMessage `json:"value"`
}

type histEvent struct {
	Fields []histEventField `json:"fields"`
}

type histEventsPage struct {
	StatusCode        statusCodeObj `json:"statusCode"`
	ContinuationPoint *string       `json:"continuationPoint"`
	Events            []histEvent   `json:"events"`
}

type histEventsResult struct {
	NodeID            string           `json:"nodeId"`
	StatusCode        statusCodeObj    `json:"statusCode"`
	ContinuationPoint *string          `json:"continuationPoint"`
	SelectClauses     []string         `json:"selectClauses"`
	Events            []histEvent      `json:"events"`
	Scenario          string           `json:"scenario"`
	Pages             []histEventsPage `json:"pages"`
	ReleaseStatusCode *statusCodeObj   `json:"releaseStatusCode"`
	ReuseStatusCode   *statusCodeObj   `json:"reuseAfterReleaseStatusCode"`
}

type histUpdateResult struct {
	NodeID            string          `json:"nodeId"`
	PerformUpdateType string          `json:"performUpdateType"`
	StatusCode        statusCodeObj   `json:"statusCode"`
	OperationResults  []statusCodeObj `json:"operationResults"`
}

// field returns the field of ev named name.
func (ev histEvent) field(name string) (histEventField, bool) {
	for _, f := range ev.Fields {
		if f.Name == name {
			return f, true
		}
	}
	return histEventField{}, false
}

// histEventIDs returns the EventIds of the events as strings (hist-evt-n).
func histEventIDs(t *testing.T, events []histEvent) []string {
	t.Helper()
	out := []string{}
	for i, ev := range events {
		f, ok := ev.field("EventId")
		if !ok {
			t.Fatalf("event %d has no EventId field: %+v", i, ev)
		}
		var s string
		if err := json.Unmarshal(f.Value, &s); err != nil {
			t.Fatalf("event %d: EventId %s: %v", i, f.Value, err)
		}
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("event %d: EventId %q is no Base64: %v", i, s, err)
		}
		out = append(out, string(b))
	}
	return out
}

// histIDs returns hist-evt-n for each n.
func histIDs(n ...int) []string {
	out := []string{}
	for _, i := range n {
		out = append(out, string(histEventID(i)))
	}
	return out
}

// peerEventClient is an adapter client of the event history tests.
type peerEventClient struct {
	name, env, image string
	run              func(t *testing.T, endpoint, subcmd string, args ...string) adapterResult
}

var (
	open62541EventClient  = peerEventClient{"open62541", "OPEN62541_IMAGE", defaultOpen62541Image, runOpen62541ClientResult}
	miloEventClient       = peerEventClient{"milo", "MILO_IMAGE", defaultMiloImage, runMiloClientResult}
	dotnetEventClient     = peerEventClient{"dotnet", dotnetEnv, defaultDotnetImage, runDotnetClientResult}
	nodeOpcuaEventClient  = peerEventClient{"node-opcua", nodeOpcuaEnv, defaultNodeOpcuaImage, runNodeOpcuaClientResult}
	asyncuaEventClient    = peerEventClient{"asyncua", asyncuaEnv, defaultAsyncuaImage, runAsyncuaClientResult}
	asyncOpcuaEventClient = peerEventClient{"async-opcua", asyncOpcuaEnv, defaultAsyncOpcuaImage, runAsyncOpcuaClientResult}
)

// readEvents runs client history-read-events against the fixture of g and
// returns its single result; the run must succeed.
func (p peerEventClient) readEvents(t *testing.T, g *goEventHistory, args ...string) histEventsResult {
	t.Helper()
	args = append([]string{"--node", histEventsNode}, args...)
	r := p.run(t, g.endpoint, "history-read-events", args...)
	if !r.Success {
		t.Fatalf("%s history-read-events %v: serviceResult %s, error %s, results %s", p.name, args, r.ServiceResult, r.Error, r.Results)
	}
	var items []histEventsResult
	if err := json.Unmarshal(r.Results, &items); err != nil || len(items) != 1 {
		t.Fatalf("%s history-read-events: parse results: %v; raw %s", p.name, err, r.Results)
	}
	return items[0]
}

// updateEvents runs client history-update-events against the fixture of g
// and returns its single result.
func (p peerEventClient) updateEvents(t *testing.T, g *goEventHistory, args ...string) histUpdateResult {
	t.Helper()
	args = append([]string{"--node", histEventsNode}, args...)
	r := p.run(t, g.endpoint, "history-update-events", args...)
	var items []histUpdateResult
	if err := json.Unmarshal(r.Results, &items); err != nil || len(items) != 1 {
		t.Fatalf("%s history-update-events %v: parse results: %v; serviceResult %s, error %s, raw %s",
			p.name, args, err, r.ServiceResult, r.Error, r.Results)
	}
	return items[0]
}

// requireEventIDs fails unless the events are the seeded events want, in order.
func requireEventIDs(t *testing.T, what string, events []histEvent, want []string) {
	t.Helper()
	if got := histEventIDs(t, events); !slices.Equal(got, want) {
		t.Fatalf("%s: events %v, want %v", what, got, want)
	}
}

// requireStatus fails unless the status has the code want (the numeric code:
// Milo spells the names with an underscore).
func requireStatus(t *testing.T, what string, got statusCodeObj, want ua.StatusCode) {
	t.Helper()
	if !statusCodeIs(got, want) {
		t.Fatalf("%s: status %s, want %s (0x%08X)", what, got, want, uint32(want))
	}
}

// requireOperationResults fails unless the operation results have the codes want.
func requireOperationResults(t *testing.T, what string, r histUpdateResult, want ...ua.StatusCode) {
	t.Helper()
	ok := len(r.OperationResults) == len(want)
	for i := 0; ok && i < len(want); i++ {
		ok = statusCodeIs(r.OperationResults[i], want[i])
	}
	if !ok {
		t.Fatalf("%s: operationResults %v (node status %s), want %v", what, r.OperationResults, r.StatusCode, want)
	}
}

// ---------------------------------------------------------------------------
// Peer client → go-opcua server
// ---------------------------------------------------------------------------

// assertPeerReadsGoEvents: forward and reverse reads of the seed, and an
// empty range (Good_NoData).
func assertPeerReadsGoEvents(t *testing.T, p peerEventClient) {
	t.Helper()
	requireAdapterOp(t, p.env, p.image, "history-read-events")
	g := startGoServerWithEventHistory(t)

	fwd := p.readEvents(t, g, "--start", "2026-07-24T10:00:00Z", "--end", "2026-07-24T10:01:00Z")
	requireStatus(t, "forward read", fwd.StatusCode, ua.StatusOK)
	requireEventIDs(t, "forward read", fwd.Events, histIDs(0, 1, 2, 3, 4))
	for i, ev := range fwd.Events {
		sev, ok := ev.field("Severity")
		if !ok || string(sev.Value) != strconv.Itoa(100*(i+1)) {
			t.Errorf("event %d: Severity %+v, want %d", i, sev, 100*(i+1))
		}
		et, ok := ev.field("EventType")
		if want := strconv.Quote(histEventType(i).String()); !ok || string(et.Value) != want {
			t.Errorf("event %d: EventType %+v, want %s", i, et, want)
		}
	}

	// go-opcua excludes EndTime in both directions (Part 11 §6.5.2.2): the
	// reverse range ends before the first event.
	rev := p.readEvents(t, g, "--start", "2026-07-24T10:01:00Z", "--end", "2026-07-24T09:59:00Z")
	requireStatus(t, "reverse read", rev.StatusCode, ua.StatusOK)
	requireEventIDs(t, "reverse read", rev.Events, histIDs(4, 3, 2, 1, 0))

	empty := p.readEvents(t, g, "--start", "2027-01-01T00:00:00Z", "--end", "2027-01-02T00:00:00Z")
	requireStatus(t, "empty range", empty.StatusCode, ua.StatusGoodNoData)
	requireEventIDs(t, "empty range", empty.Events, histIDs())
}

// assertPeerContinuesGoEvents: --scenario continue pages 2, 2, 1 on one
// session; the last continuation point was consumed by the third request,
// so releasing and reusing it are Bad_ContinuationPointInvalid
// (Part 4 §5.10.3).
func assertPeerContinuesGoEvents(t *testing.T, p peerEventClient) {
	t.Helper()
	requireAdapterOp(t, p.env, p.image, "history-read-events")
	g := startGoServerWithEventHistory(t)

	r := p.readEvents(t, g, "--start", "2026-07-24T10:00:00Z", "--end", "2026-07-24T10:01:00Z",
		"--num-values", "2", "--scenario", "continue")
	if r.Scenario != "continue" {
		t.Fatalf("scenario %q, want continue", r.Scenario)
	}
	var sizes []int
	for i, pg := range r.Pages {
		sizes = append(sizes, len(pg.Events))
		last := i == len(r.Pages)-1
		if hasCP := pg.ContinuationPoint != nil && *pg.ContinuationPoint != ""; hasCP == last {
			t.Errorf("page %d of %d: continuationPoint %v", i+1, len(r.Pages), pg.ContinuationPoint)
		}
	}
	if !slices.Equal(sizes, []int{2, 2, 1}) {
		t.Fatalf("page sizes %v, want [2 2 1]", sizes)
	}
	requireEventIDs(t, "continued read", r.Events, histIDs(0, 1, 2, 3, 4))
	if r.ReleaseStatusCode == nil || r.ReuseStatusCode == nil {
		t.Fatalf("release %v / reuse %v status missing", r.ReleaseStatusCode, r.ReuseStatusCode)
	}
	requireStatus(t, "release of the consumed continuation point", *r.ReleaseStatusCode, ua.StatusBadContinuationPointInvalid)
	requireStatus(t, "reuse after release", *r.ReuseStatusCode, ua.StatusBadContinuationPointInvalid)
}

// assertPeerFiltersGoEvents: the WhereClause with OfType (subtypes match),
// a minimum Severity, and both.
func assertPeerFiltersGoEvents(t *testing.T, p peerEventClient) {
	t.Helper()
	requireAdapterOp(t, p.env, p.image, "history-read-events")
	g := startGoServerWithEventHistory(t)
	rng := []string{"--start", "2026-07-24T10:00:00Z", "--end", "2026-07-24T10:01:00Z"}

	r := p.readEvents(t, g, append(rng, "--of-type", "i=2130")...)
	requireEventIDs(t, "OfType SystemEventType", r.Events, histIDs(3))
	r = p.readEvents(t, g, append(rng, "--min-severity", "300")...)
	requireEventIDs(t, "Severity >= 300", r.Events, histIDs(2, 3, 4))
	r = p.readEvents(t, g, append(rng, "--of-type", "i=2041", "--min-severity", "300")...)
	requireEventIDs(t, "OfType BaseEventType and Severity >= 300", r.Events, histIDs(2, 3, 4))
}

// histUpdateSelect are the SelectClauses of the update tests (§17.1).
var histUpdateSelect = []string{"--select", "EventId", "--select", "EventType", "--select", "Time",
	"--select", "Severity", "--select", "Message"}

// histEventJSON is an --event of the update tests.
func histEventJSON(eventID string, at time.Time, severity int, text string) string {
	b, _ := json.Marshal(map[string]any{
		"EventId":   map[string]any{"type": "ByteString", "value": base64.StdEncoding.EncodeToString([]byte(eventID))},
		"EventType": map[string]any{"type": "NodeId", "value": "i=2041"},
		"Time":      map[string]any{"type": "DateTime", "value": at.UTC().Format(time.RFC3339)},
		"Severity":  map[string]any{"type": "UInt16", "value": severity},
		"Message":   map[string]any{"type": "LocalizedText", "value": map[string]string{"locale": "en", "text": text}},
	})
	return string(b)
}

// eventIDs reads the history of g in process (oldest first).
func (g *goEventHistory) eventIDs(t *testing.T) []string {
	t.Helper()
	var out []string
	match := func(*server.HistoricalEvent) bool { return true }
	evs, _, st := g.hist.ReadEvents(g.notifier, histEventsBase.Add(-time.Hour), histEventsBase.Add(time.Hour), 0, match, nil)
	if st.Uint32()&0x80000000 != 0 {
		t.Fatalf("in-process read: %s", st)
	}
	for _, e := range evs {
		out = append(out, string(e.EventID()))
	}
	return out
}

// assertPeerUpdatesGoEvents: insert, replace and update (Part 11 §6.9.4),
// the seed restored before each.
func assertPeerUpdatesGoEvents(t *testing.T, p peerEventClient) {
	t.Helper()
	requireAdapterOp(t, p.env, p.image, "history-update-events")
	g := startGoServerWithEventHistory(t)
	newAt := histEventsBase.Add(25 * time.Second)

	r := p.updateEvents(t, g, append(slices.Clone(histUpdateSelect), "--perform", "insert",
		"--event", histEventJSON("hist-evt-5", newAt, 600, "inserted"),
		"--event", histEventJSON("hist-evt-0", histEventsBase, 600, "inserted again"))...)
	requireStatus(t, "insert: node status", r.StatusCode, ua.StatusOK)
	requireOperationResults(t, "insert", r, ua.StatusGoodEntryInserted, ua.StatusBadEntryExists)
	if got, want := g.eventIDs(t), histIDs(0, 1, 2, 3, 4, 5); !slices.Equal(got, want) {
		t.Fatalf("after insert: history %v, want %v", got, want)
	}

	g.reset()
	r = p.updateEvents(t, g, append(slices.Clone(histUpdateSelect), "--perform", "replace",
		"--event", histEventJSON("hist-evt-0", histEventsBase, 150, "replaced"),
		"--event", histEventJSON("hist-evt-unknown", newAt, 150, "replaced"))...)
	requireStatus(t, "replace: node status", r.StatusCode, ua.StatusOK)
	requireOperationResults(t, "replace", r, ua.StatusGoodEntryReplaced, ua.StatusBadNoEntryExists)

	g.reset()
	r = p.updateEvents(t, g, append(slices.Clone(histUpdateSelect), "--perform", "update",
		"--event", histEventJSON("hist-evt-unknown", newAt, 650, "upserted"),
		"--event", histEventJSON("hist-evt-0", histEventsBase, 650, "upserted"))...)
	requireStatus(t, "update: node status", r.StatusCode, ua.StatusOK)
	requireOperationResults(t, "update", r, ua.StatusGoodEntryInserted, ua.StatusGoodEntryReplaced)
	if got, want := g.eventIDs(t), append(histIDs(0, 1, 2, 3, 4), "hist-evt-unknown"); !slices.Equal(got, want) {
		t.Fatalf("after update: history %v, want %v", got, want)
	}
}

// assertPeerDeletesGoEvents: DeleteEventDetails (Part 11 §6.9.7) of a stored
// and an unknown EventId; go-opcua answers Bad_NoData for the unknown one
// (§6.9.7.2).
func assertPeerDeletesGoEvents(t *testing.T, p peerEventClient) {
	t.Helper()
	requireAdapterOp(t, p.env, p.image, "history-update-events")
	g := startGoServerWithEventHistory(t)

	r := p.updateEvents(t, g, "--perform", "delete",
		"--event-id", base64.StdEncoding.EncodeToString(histEventID(1)),
		"--event-id", base64.StdEncoding.EncodeToString([]byte("hist-evt-unknown")))
	requireStatus(t, "delete: node status", r.StatusCode, ua.StatusOK)
	requireOperationResults(t, "delete", r, ua.StatusOK, ua.StatusBadNoData)
	if got, want := g.eventIDs(t), histIDs(0, 2, 3, 4); !slices.Equal(got, want) {
		t.Fatalf("after delete: history %v, want %v", got, want)
	}
	// The peer reads what it deleted.
	read := p.readEvents(t, g, "--start", "2026-07-24T10:00:00Z", "--end", "2026-07-24T10:01:00Z")
	requireEventIDs(t, "read after delete", read.Events, histIDs(0, 2, 3, 4))
}

// ---------------------------------------------------------------------------
// go-opcua client → peer server
// ---------------------------------------------------------------------------

// peerEventServer is the fixture s=History.Events of a peer server, seen by
// the go-opcua client.
type peerEventServer struct {
	c        *opcua.Client
	notifier *ua.NodeID
	reset    *ua.NodeID
}

func dialPeerEventServer(t *testing.T, endpoint string) *peerEventServer {
	t.Helper()
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	return &peerEventServer{
		c:        c,
		notifier: ua.NewStringNodeID(nsIdx, histEventsName),
		reset:    ua.NewStringNodeID(nsIdx, histEventsResetName),
	}
}

// histReadFilter selects the EventId and Severity; where is the WhereClause.
func histReadFilter(where ...*ua.ContentFilterElement) *ua.EventFilter {
	f := ua.NewEventFilter().Select("EventId", "Severity").Build()
	f.WhereClause = &ua.ContentFilter{Elements: where}
	return f
}

// eventFieldIDs returns the EventIds (the first field) of the events.
func eventFieldIDs(t *testing.T, evs []*ua.HistoryEventFieldList) []string {
	t.Helper()
	out := []string{}
	for i, e := range evs {
		if e == nil || len(e.EventFields) == 0 {
			t.Fatalf("event %d has no fields", i)
		}
		b, ok := e.EventFields[0].Value().([]byte)
		if !ok {
			t.Fatalf("event %d: EventId %v", i, e.EventFields[0].Value())
		}
		out = append(out, string(b))
	}
	return out
}

func (p *peerEventServer) read(t *testing.T, ctx context.Context, start, end time.Time, filter *ua.EventFilter, maxEvents uint32) []string {
	t.Helper()
	if filter == nil {
		filter = histReadFilter()
	}
	evs, err := p.c.ReadEventHistory(ctx, p.notifier, start, end, filter, maxEvents)
	if err != nil {
		t.Fatalf("ReadEventHistory %v..%v: %v", start, end, err)
	}
	return eventFieldIDs(t, evs)
}

func requireIDs(t *testing.T, what string, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("%s: events %v, want %v", what, got, want)
	}
}

// assertGoReadsPeerEvents: forward, reverse and an empty range. The
// reverse range ends at 09:59:00, so that it holds the first event whether
// the server includes EndTime or not; emptyStatus is the node status of the
// empty range (Good_NoData; Good on asyncua 2.1.0, §17.4).
func assertGoReadsPeerEvents(t *testing.T, endpoint string, emptyStatus ua.StatusCode) {
	t.Helper()
	p := dialPeerEventServer(t, endpoint)
	ctx := shortTestCtx(t)
	end := histEventsBase.Add(time.Minute)

	requireIDs(t, "forward read", p.read(t, ctx, histEventsBase, end, nil, 0), histIDs(0, 1, 2, 3, 4))
	requireIDs(t, "reverse read", p.read(t, ctx, end, histEventsBase.Add(-time.Minute), nil, 0), histIDs(4, 3, 2, 1, 0))

	evs, err := p.c.ReadEventHistory(ctx, p.notifier, histEventsBase.AddDate(1, 0, 0), histEventsBase.AddDate(1, 0, 1), histReadFilter(), 0)
	if err != nil || len(evs) != 0 {
		t.Fatalf("empty range: %d events, err %v", len(evs), err)
	}
	resp, err := p.c.HistoryReadEvent(ctx, []*ua.HistoryReadValueID{{NodeID: p.notifier}}, &ua.ReadEventDetails{
		StartTime: histEventsBase.AddDate(1, 0, 0), EndTime: histEventsBase.AddDate(1, 0, 1), Filter: histReadFilter(),
	})
	if err != nil || len(resp.Results) != 1 {
		t.Fatalf("empty range HistoryRead: %v", err)
	}
	if got := resp.Results[0].StatusCode; got != emptyStatus {
		t.Fatalf("empty range: node status %s, want %s", got, emptyStatus)
	}
}

// assertGoContinuesPeerEvents: ReadEventHistoryAll pages of 2; a
// continuation point released with HistoryReleaseContinuationPoints, then
// reused. statefulCPs: the server forgets a released point (Part 4
// §5.10.3); asyncua 2.1.0's points are stateless (§17.4), release and reuse
// are Good.
func assertGoContinuesPeerEvents(t *testing.T, endpoint string, statefulCPs bool) {
	t.Helper()
	p := dialPeerEventServer(t, endpoint)
	ctx := shortTestCtx(t)
	end := histEventsBase.Add(time.Minute)

	var all []*ua.HistoryEventFieldList
	for ev, err := range p.c.ReadEventHistoryAll(ctx, p.notifier, histEventsBase, end, histReadFilter(), 2) {
		if err != nil {
			t.Fatalf("ReadEventHistoryAll: %v", err)
		}
		all = append(all, ev)
	}
	requireIDs(t, "paged read", eventFieldIDs(t, all), histIDs(0, 1, 2, 3, 4))
	// Limited to 3 events: two pages, the point of the second released.
	limited, err := p.c.ReadEventHistory(ctx, p.notifier, histEventsBase, end, histReadFilter(), 3)
	if err != nil {
		t.Fatalf("ReadEventHistory max 3: %v", err)
	}
	requireIDs(t, "limited read", eventFieldIDs(t, limited), histIDs(0, 1, 2))

	details := &ua.ReadEventDetails{StartTime: histEventsBase, EndTime: end, NumValuesPerNode: 2, Filter: histReadFilter()}
	resp, err := p.c.HistoryReadEvent(ctx, []*ua.HistoryReadValueID{{NodeID: p.notifier}}, details)
	if err != nil || len(resp.Results) != 1 {
		t.Fatalf("first page: %v", err)
	}
	cp := resp.Results[0].ContinuationPoint
	if len(cp) == 0 {
		t.Fatalf("first page: no continuation point (status %s)", resp.Results[0].StatusCode)
	}
	sts, err := p.c.HistoryReleaseContinuationPoints(ctx, details, &ua.HistoryReadValueID{NodeID: p.notifier, ContinuationPoint: cp})
	if err != nil || len(sts) != 1 || sts[0] != ua.StatusOK {
		t.Fatalf("release: %v, %v", sts, err)
	}
	resp, err = p.c.HistoryReadEvent(ctx, []*ua.HistoryReadValueID{{NodeID: p.notifier, ContinuationPoint: cp}}, details)
	if err != nil || len(resp.Results) != 1 {
		t.Fatalf("reuse after release: %v", err)
	}
	want := ua.StatusBadContinuationPointInvalid
	if !statefulCPs {
		want = ua.StatusOK
	}
	if got := resp.Results[0].StatusCode; got != want {
		t.Fatalf("reuse after release: node status %s, want %s", got, want)
	}
}

// assertGoFiltersPeerEvents: OfType SystemEventType, Severity >= 300 and
// [And(1, 2), OfType BaseEventType, Severity >= 300] (an And before its
// operands, CLIENT_CONTRACT §1).
func assertGoFiltersPeerEvents(t *testing.T, endpoint string, subtypes bool) {
	t.Helper()
	p := dialPeerEventServer(t, endpoint)
	ctx := shortTestCtx(t)
	end := histEventsBase.Add(time.Minute)
	minSev := ua.Field("Severity").GreaterThanOrEqual(uint16(300))

	requireIDs(t, "OfType SystemEventType",
		p.read(t, ctx, histEventsBase, end, histReadFilter(ua.OfType(ua.NewNumericNodeID(0, id.SystemEventType))), 0), histIDs(3))
	requireIDs(t, "Severity >= 300", p.read(t, ctx, histEventsBase, end, histReadFilter(minSev), 0), histIDs(2, 3, 4))
	and := &ua.ContentFilterElement{
		FilterOperator: ua.FilterOperatorAnd,
		FilterOperands: []*ua.ExtensionObject{
			ua.NewExtensionObject(&ua.ElementOperand{Index: 1}),
			ua.NewExtensionObject(&ua.ElementOperand{Index: 2}),
		},
	}
	want := histIDs(2, 3, 4)
	if !subtypes {
		want = histIDs(2, 4)
	}
	requireIDs(t, "OfType BaseEventType and Severity >= 300",
		p.read(t, ctx, histEventsBase, end, histReadFilter(and, ua.OfType(ua.NewNumericNodeID(0, id.BaseEventType)), minSev), 0), want)
}

// resetEvents calls s=History.ResetEvents.
func (p *peerEventServer) resetEvents(t *testing.T, ctx context.Context) {
	t.Helper()
	res, err := p.c.Call(ctx, &ua.CallMethodRequest{ObjectID: p.notifier, MethodID: p.reset})
	if err != nil || res.StatusCode != ua.StatusOK {
		t.Fatalf("call %s: %v, %v", histEventsResetName, res, err)
	}
}

// histUpdateFilter selects the fields of the update tests (§17.1).
func histUpdateFilter() *ua.EventFilter {
	f := ua.NewEventFilter().Select("EventId", "EventType", "Time", "Severity", "Message").Build()
	f.WhereClause = nil
	return f
}

func histUpdateFields(eventID string, at time.Time, severity uint16, text string) *ua.HistoryEventFieldList {
	return &ua.HistoryEventFieldList{EventFields: []*ua.Variant{
		ua.MustVariant([]byte(eventID)),
		ua.MustVariant(ua.NewNumericNodeID(0, id.BaseEventType)),
		ua.MustVariant(at),
		ua.MustVariant(severity),
		ua.MustVariant(ua.NewLocalizedTextWithLocale(text, "en")),
	}}
}

// historyUpdateResult returns the single result of a HistoryUpdate.
func historyUpdateResult(t *testing.T, what string, resp *ua.HistoryUpdateResponse, err error) *ua.HistoryUpdateResult {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	if len(resp.Results) != 1 || resp.Results[0] == nil {
		t.Fatalf("%s: %d results", what, len(resp.Results))
	}
	return resp.Results[0]
}

func requireOps(t *testing.T, what string, r *ua.HistoryUpdateResult, want ...ua.StatusCode) {
	t.Helper()
	if !slices.Equal(r.OperationResults, want) {
		t.Fatalf("%s: operation results %v (node status %s), want %v", what, r.OperationResults, r.StatusCode, want)
	}
}

// assertGoUpdatesPeerEvents: insert, replace and update with
// HistoryUpdateEvents, s=History.ResetEvents before each and after.
func assertGoUpdatesPeerEvents(t *testing.T, endpoint string) {
	t.Helper()
	p := dialPeerEventServer(t, endpoint)
	ctx := shortTestCtx(t)
	end := histEventsBase.Add(time.Minute)
	newAt := histEventsBase.Add(25 * time.Second)
	update := func(perform ua.PerformUpdateType, events ...*ua.HistoryEventFieldList) *ua.HistoryUpdateResult {
		t.Helper()
		resp, err := p.c.HistoryUpdateEvents(ctx, &ua.UpdateEventDetails{
			NodeID: p.notifier, PerformInsertReplace: perform, Filter: histUpdateFilter(), EventData: events,
		})
		return historyUpdateResult(t, fmt.Sprintf("HistoryUpdate %v", perform), resp, err)
	}
	t.Cleanup(func() { p.resetEvents(t, context.Background()) })

	p.resetEvents(t, ctx)
	r := update(ua.PerformUpdateTypeInsert,
		histUpdateFields("hist-evt-5", newAt, 600, "inserted"),
		histUpdateFields("hist-evt-0", histEventsBase, 600, "inserted again"))
	requireOps(t, "insert", r, ua.StatusGoodEntryInserted, ua.StatusBadEntryExists)
	requireIDs(t, "after insert", p.read(t, ctx, histEventsBase, end, nil, 0), histIDs(0, 1, 2, 3, 4, 5))

	p.resetEvents(t, ctx)
	r = update(ua.PerformUpdateTypeReplace,
		histUpdateFields("hist-evt-0", histEventsBase, 150, "replaced"),
		histUpdateFields("hist-evt-unknown", newAt, 150, "replaced"))
	requireOps(t, "replace", r, ua.StatusGoodEntryReplaced, ua.StatusBadNoEntryExists)

	p.resetEvents(t, ctx)
	r = update(ua.PerformUpdateTypeUpdate,
		histUpdateFields("hist-evt-unknown", newAt, 650, "upserted"),
		histUpdateFields("hist-evt-0", histEventsBase, 650, "upserted"))
	requireOps(t, "update", r, ua.StatusGoodEntryInserted, ua.StatusGoodEntryReplaced)
	requireIDs(t, "after update", p.read(t, ctx, histEventsBase, end, nil, 0), append(histIDs(0, 1, 2, 3, 4), "hist-evt-unknown"))
}

// assertGoDeletesPeerEvents: HistoryDeleteEvents of a stored and an unknown
// EventId; unknownStatus is the result of the unknown one.
func assertGoDeletesPeerEvents(t *testing.T, endpoint string, unknownStatus ua.StatusCode) {
	t.Helper()
	p := dialPeerEventServer(t, endpoint)
	ctx := shortTestCtx(t)
	t.Cleanup(func() { p.resetEvents(t, context.Background()) })

	p.resetEvents(t, ctx)
	resp, err := p.c.HistoryDeleteEvents(ctx, &ua.DeleteEventDetails{
		NodeID: p.notifier, EventIDs: [][]byte{histEventID(1), []byte("hist-evt-unknown")},
	})
	r := historyUpdateResult(t, "HistoryUpdate delete", resp, err)
	requireOps(t, "delete", r, ua.StatusOK, unknownStatus)
	requireIDs(t, "after delete", p.read(t, ctx, histEventsBase, histEventsBase.Add(time.Minute), nil, 0), histIDs(0, 2, 3, 4))
}

// TestGoServer_GoClient_HistoryEventsFixture checks the go-opcua fixture
// with the go-opcua client (the reference results of §17.1), without Docker.
func TestGoServer_GoClient_HistoryEventsFixture(t *testing.T) {
	g := startGoServerWithEventHistory(t)
	assertGoReadsPeerEvents(t, g.endpoint, ua.StatusGoodNoData)
	assertGoContinuesPeerEvents(t, g.endpoint, true)
	assertGoFiltersPeerEvents(t, g.endpoint, true)
	assertGoUpdatesPeerEvents(t, g.endpoint)
	assertGoDeletesPeerEvents(t, g.endpoint, ua.StatusBadNoData)
}

// assertGoHistoryUpdateRefused: a HistoryUpdate (UpdateEventDetails insert,
// or DeleteEventDetails with del) of the fixture is refused with want, as a
// service result or as the node status.
func assertGoHistoryUpdateRefused(t *testing.T, endpoint string, del bool, want ua.StatusCode) {
	t.Helper()
	p := dialPeerEventServer(t, endpoint)
	ctx := shortTestCtx(t)
	var resp *ua.HistoryUpdateResponse
	var err error
	if del {
		resp, err = p.c.HistoryDeleteEvents(ctx, &ua.DeleteEventDetails{NodeID: p.notifier, EventIDs: [][]byte{histEventID(1)}})
	} else {
		resp, err = p.c.HistoryUpdateEvents(ctx, &ua.UpdateEventDetails{
			NodeID: p.notifier, PerformInsertReplace: ua.PerformUpdateTypeInsert, Filter: histUpdateFilter(),
			EventData: []*ua.HistoryEventFieldList{histUpdateFields("hist-evt-5", histEventsBase.Add(25*time.Second), 600, "inserted")},
		})
	}
	switch {
	case err != nil:
		if !errors.Is(err, want) {
			t.Fatalf("HistoryUpdate: %v, want %s", err, want)
		}
	case len(resp.Results) != 1 || resp.Results[0] == nil || resp.Results[0].StatusCode != want:
		t.Fatalf("HistoryUpdate: results %+v, want the node status %s", resp.Results, want)
	}
	// The history is unchanged.
	requireIDs(t, "after the refused update", p.read(t, ctx, histEventsBase, histEventsBase.Add(time.Minute), nil, 0), histIDs(0, 1, 2, 3, 4))
}
