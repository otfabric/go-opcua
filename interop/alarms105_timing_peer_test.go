//go:build interop

// SPDX-License-Identifier: MIT

// Part 9 v1.05 alarm timing, sound, first-in-group and metrics peer tests:
// every adapter's generic `client read` and `client call` operations
// (CLIENT_CONTRACT §1) against the go-opcua server, whose alarm timers run
// on a manual clock the test advances:
//
//   - alarms.alarm-timing: OnDelay / OffDelay / ReAlarmTime Properties, an
//     activation that waits for OnDelay, and ReAlarmRepeatCount (§5.8.2);
//   - alarms.audible-sound: AudibleEnabled and AudibleSound with its
//     AudioVariableType ListId (§5.8.2, §8.3);
//   - alarms.first-in-group: FirstInGroupFlag of the first and the second
//     alarm of a group (§5.8.2);
//   - alarms.alarm-metrics: the AlarmCount of an AlarmMetricsType object and
//     its Reset method (§8.5).
//
// No peer server fixture has these features, so the go-opcua client side
// has ledger rows only (see coverage.json and the ledger-*.json files). The
// UA-.NETStandard, node-opcua and async-opcua tests are in
// dotnet_alarms_test.go, nodeopcua_alarms_test.go and
// asyncopcua_alarms_test.go.
//
// COVERAGE.md: alarms-conditions / alarms.alarm-timing, alarms.audible-sound,
// alarms.first-in-group, alarms.alarm-metrics

package interop

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/fakeclock"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

func TestGoServer_Open62541Client_Alarms105Timing(t *testing.T) {
	requireAdapterOp(t, "OPEN62541_IMAGE", defaultOpen62541Image, "read")
	requireAdapterOp(t, "OPEN62541_IMAGE", defaultOpen62541Image, "call")
	p := startAlarmTiming(t, runOpen62541ClientResult)
	t.Run("coverage/alarms.alarm-timing/open62541-client-to-go-server", p.assertTiming)
	t.Run("coverage/alarms.audible-sound/open62541-client-to-go-server", p.assertAudible)
	t.Run("coverage/alarms.first-in-group/open62541-client-to-go-server", p.assertFirstInGroup)
	t.Run("coverage/alarms.alarm-metrics/open62541-client-to-go-server", p.assertMetrics)
}

func TestGoServer_MiloClient_Alarms105Timing(t *testing.T) {
	requireAdapterOp(t, "MILO_IMAGE", defaultMiloImage, "read")
	requireAdapterOp(t, "MILO_IMAGE", defaultMiloImage, "call")
	p := startAlarmTiming(t, runMiloClientResult)
	t.Run("coverage/alarms.alarm-timing/milo-client-to-go-server", p.assertTiming)
	t.Run("coverage/alarms.audible-sound/milo-client-to-go-server", p.assertAudible)
	t.Run("coverage/alarms.first-in-group/milo-client-to-go-server", p.assertFirstInGroup)
	t.Run("coverage/alarms.alarm-metrics/milo-client-to-go-server", p.assertMetrics)
}

func TestGoServer_AsyncuaClient_Alarms105Timing(t *testing.T) {
	requireAdapterOp(t, asyncuaEnv, defaultAsyncuaImage, "read")
	requireAdapterOp(t, asyncuaEnv, defaultAsyncuaImage, "call")
	p := startAlarmTiming(t, runAsyncuaClientResult)
	t.Run("coverage/alarms.alarm-timing/asyncua-client-to-go-server", p.assertTiming)
	t.Run("coverage/alarms.audible-sound/asyncua-client-to-go-server", p.assertAudible)
	t.Run("coverage/alarms.first-in-group/asyncua-client-to-go-server", p.assertFirstInGroup)
	t.Run("coverage/alarms.alarm-metrics/asyncua-client-to-go-server", p.assertMetrics)
}

// alarmTimingPeer is the go-opcua server fixture of the timing tests and the
// adapter client that reads it.
type alarmTimingPeer struct {
	run      func(t *testing.T, endpoint, subcmd string, args ...string) adapterResult
	endpoint string
	clock    *fakeclock.Clock
	client   *opcua.Client
	delayed  *server.Condition // OnDelay 2 s, OffDelay 3 s, ReAlarmTime 1 min
	audible  *server.Condition
	first    *server.Condition // the first and the second alarm of group
	second   *server.Condition
	counted  *server.Condition // the alarm of the metrics' group
	metrics  *server.AlarmMetrics
}

// startAlarmTiming starts a go-opcua server with a manual alarm clock and
// the alarms of the timing tests on s=Alarms105T.Source.
func startAlarmTiming(t *testing.T, run func(t *testing.T, endpoint, subcmd string, args ...string) adapterResult) *alarmTimingPeer {
	t.Helper()
	clk := fakeclock.New(time.Date(2026, 6, 1, 8, 0, 0, 0, time.UTC))
	endpoint, srv := startGoServerWithOptions(t, server.WithAuditing(true), server.WithAlarmClock(clk))
	_, nsIdx := findNSFromServer(t, srv)
	ns, err := srv.Namespace(int(nsIdx))
	if err != nil {
		t.Fatalf("Namespace: %v", err)
	}
	nns, ok := ns.(*server.NodeNameSpace)
	if !ok {
		t.Fatalf("namespace %d is a %T", nsIdx, ns)
	}
	src := server.NewFolderNode(ua.NewStringNodeID(nsIdx, "Alarms105T.Source"), "Alarms105T.Source")
	nns.AddNode(src)
	nns.Objects().AddRef(src, server.RefTypeIDOrganizes, true)
	group := func(name string) *server.AlarmGroup {
		t.Helper()
		g, err := srv.AddAlarmGroup(server.AlarmGroupConfig{NodeID: ua.NewStringNodeID(nsIdx, "Alarms105T."+name), Namespace: nns, Name: name})
		if err != nil {
			t.Fatalf("AddAlarmGroup: %v", err)
		}
		return g
	}
	add := func(cfg server.ConditionConfig) *server.Condition {
		t.Helper()
		cfg.NodeID = ua.NewStringNodeID(nsIdx, "Alarms105T."+cfg.Name)
		cfg.Source = src.ID()
		c, err := srv.AddCondition(cfg)
		if err != nil {
			t.Fatalf("AddCondition %s: %v", cfg.Name, err)
		}
		return c
	}
	trip, counting := group("Trip"), group("Counting")
	p := &alarmTimingPeer{run: run, endpoint: endpoint, clock: clk}
	p.delayed = add(server.ConditionConfig{Name: "Delayed", OnDelay: 2 * time.Second, OffDelay: 3 * time.Second, ReAlarmTime: time.Minute})
	p.audible = add(server.ConditionConfig{Name: "Audible", AudibleSound: &server.AudibleSound{Sound: []byte("RIFF"), ListID: "horns"}})
	p.first = add(server.ConditionConfig{Name: "First", FirstInGroup: trip.NodeID()})
	p.second = add(server.ConditionConfig{Name: "Second", FirstInGroup: trip.NodeID()})
	p.counted = add(server.ConditionConfig{Name: "Counted"})
	if err := counting.AddMember(p.counted); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	p.metrics, err = srv.AddAlarmMetrics(server.AlarmMetricsConfig{NodeID: ua.NewStringNodeID(nsIdx, "Alarms105T.Metrics"),
		Namespace: nns, Group: counting.NodeID()})
	if err != nil {
		t.Fatalf("AddAlarmMetrics: %v", err)
	}
	p.client = dialClient(t, endpoint)
	return p
}

// path resolves a BrowsePath below node with the go-opcua client; the
// components of a condition have numeric NodeIds.
func (p *alarmTimingPeer) path(t *testing.T, node *ua.NodeID, names ...string) string {
	t.Helper()
	qn := make([]*ua.QualifiedName, len(names))
	for i, n := range names {
		qn[i] = &ua.QualifiedName{Name: n}
	}
	nid, err := p.client.Node(node).TranslateBrowsePathsToNodeIDs(context.Background(), qn)
	if err != nil {
		t.Fatalf("%v/%v: %v", node, names, err)
	}
	return nid.String()
}

// read reads the values of nodes with the adapter client; every read must
// be Good.
func (p *alarmTimingPeer) read(t *testing.T, nodes ...string) []diagnosticsReadResult {
	t.Helper()
	args := []string{}
	for _, n := range nodes {
		args = append(args, "--node", n)
	}
	result := p.run(t, p.endpoint, "read", args...)
	if !result.Success {
		t.Fatalf("read %v: serviceResult=%s error=%s", nodes, result.ServiceResult, result.Error)
	}
	var items []diagnosticsReadResult
	if err := json.Unmarshal(result.Results, &items); err != nil || len(items) != len(nodes) {
		t.Fatalf("read %v: %d results (%v): %s", nodes, len(items), err, result.Results)
	}
	for i, it := range items {
		if !statusCodeIs(it.StatusCode, ua.StatusOK) {
			t.Fatalf("read %s: %s", nodes[i], it.StatusCode)
		}
	}
	return items
}

// num parses a number of the adapter output, which some adapters quote.
func num(t *testing.T, raw json.RawMessage) float64 {
	t.Helper()
	f, err := strconv.ParseFloat(strings.Trim(strings.TrimSpace(string(raw)), `"`), 64)
	if err != nil {
		t.Fatalf("not a number: %s", raw)
	}
	return f
}

// boolean parses a Boolean of the adapter output.
func boolean(t *testing.T, raw json.RawMessage) bool {
	t.Helper()
	b, err := strconv.ParseBool(strings.Trim(strings.TrimSpace(string(raw)), `"`))
	if err != nil {
		t.Fatalf("not a Boolean: %s", raw)
	}
	return b
}

func (p *alarmTimingPeer) assertTiming(t *testing.T) {
	cid := p.delayed.NodeID()
	active := p.path(t, cid, "ActiveState", "Id")
	props := p.read(t, p.path(t, cid, "OnDelay"), p.path(t, cid, "OffDelay"), p.path(t, cid, "ReAlarmTime"))
	for i, want := range []float64{2000, 3000, 60000} {
		if got := num(t, props[i].Value); got != want {
			t.Fatalf("property %d = %v ms, want %v", i, got, want)
		}
	}
	if err := p.delayed.SetActive(true); err != nil {
		t.Fatalf("SetActive: %v", err)
	}
	if boolean(t, p.read(t, active)[0].Value) {
		t.Fatal("active before OnDelay ended")
	}
	p.clock.Advance(2 * time.Second)
	if !boolean(t, p.read(t, active)[0].Value) {
		t.Fatal("inactive after OnDelay")
	}
	p.clock.Advance(time.Minute)
	if got := num(t, p.read(t, p.path(t, cid, "ReAlarmRepeatCount"))[0].Value); got != 1 {
		t.Fatalf("ReAlarmRepeatCount = %v, want 1", got)
	}
}

func (p *alarmTimingPeer) assertAudible(t *testing.T) {
	cid := p.audible.NodeID()
	// The AudibleSound value is a ByteString, which not every adapter
	// prints; its read must be Good. ListId is a String.
	items := p.read(t, p.path(t, cid, "AudibleEnabled"), p.path(t, cid, "AudibleSound"), p.path(t, cid, "AudibleSound", "ListId"))
	if !boolean(t, items[0].Value) {
		t.Fatalf("AudibleEnabled = %s, want true", items[0].Value)
	}
	var list string
	if err := json.Unmarshal(items[2].Value, &list); err != nil || list != "horns" {
		t.Fatalf("AudibleSound/ListId = %s, want horns", items[2].Value)
	}
	off := false
	if err := p.audible.Update(server.ConditionUpdate{AudibleEnabled: &off}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if boolean(t, p.read(t, p.path(t, cid, "AudibleEnabled"))[0].Value) {
		t.Fatal("AudibleEnabled still true")
	}
}

func (p *alarmTimingPeer) assertFirstInGroup(t *testing.T) {
	for _, c := range []*server.Condition{p.first, p.second} {
		if err := c.SetActive(true); err != nil {
			t.Fatalf("SetActive: %v", err)
		}
	}
	items := p.read(t, p.path(t, p.first.NodeID(), "FirstInGroupFlag"), p.path(t, p.second.NodeID(), "FirstInGroupFlag"))
	if !boolean(t, items[0].Value) || boolean(t, items[1].Value) {
		t.Fatalf("FirstInGroupFlag = %s, %s, want true, false", items[0].Value, items[1].Value)
	}
}

func (p *alarmTimingPeer) assertMetrics(t *testing.T) {
	for range 2 {
		for _, on := range []bool{true, false} {
			if err := p.counted.SetActive(on); err != nil {
				t.Fatalf("SetActive: %v", err)
			}
		}
	}
	mid := p.metrics.NodeID()
	if got := num(t, p.read(t, p.path(t, mid, "AlarmCount"))[0].Value); got != 2 {
		t.Fatalf("AlarmCount = %v, want 2", got)
	}
	args := []string{"--object", mid.String(), "--method", ua.NewNumericNodeID(0, id.AlarmMetricsTypeReset).String()}
	result := p.run(t, p.endpoint, "call", args...)
	var items []alarms105CallResult
	if err := json.Unmarshal(result.Results, &items); err != nil || len(items) == 0 {
		t.Fatalf("Reset: parse results: %v; result: %+v", err, result)
	}
	if !statusCodeIs(items[0].StatusCode, ua.StatusOK) {
		t.Fatalf("Reset: %s", items[0].StatusCode.Name)
	}
	if v := p.metrics.Values(); v.AlarmCount != 0 || !v.StartTime.Equal(p.clock.Now()) {
		t.Fatalf("after Reset: %+v", v)
	}
}
