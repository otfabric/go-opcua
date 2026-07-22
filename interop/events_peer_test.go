//go:build interop

// SPDX-License-Identifier: MIT

// Peer event subscription tests (O→S / M→S).
// COVERAGE.md: events / event.subscription, event.emission.base,
// event.filter.select-clauses

package interop

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

func emitPeerEvent(t *testing.T, srv *server.Server, source *ua.NodeID) {
	t.Helper()
	evt := &server.BaseEvent{
		EventID:    []byte("peer-event"),
		EventType:  ua.NewNumericNodeID(0, id.BaseEventType),
		SourceNode: source,
		SourceName: "Events.Source",
		Time:       time.Now().UTC(),
		Message:    ua.NewLocalizedText("peer-event"),
		Severity:   500,
	}
	if err := srv.EmitBaseEvent(source, evt); err != nil {
		t.Logf("EmitBaseEvent: %v", err)
	}
}

type eventField struct {
	Name  string          `json:"name"`
	Value json.RawMessage `json:"value"`
}

type eventEntry struct {
	SequenceNumber uint32       `json:"sequenceNumber"`
	Fields         []eventField `json:"fields"`
}

type eventSubscribeItem struct {
	NodeID        string        `json:"nodeId"`
	SelectClauses []string      `json:"selectClauses"`
	Events        []eventEntry  `json:"events"`
	MonitoredItem statusCodeObj `json:"monitoredItemStatusCode"`
}

var baseEventSelectClauses = []string{
	"EventId", "EventType", "SourceName", "Message", "Severity", "Time",
}

// pulsePeerEvents emits BaseEvents on a short interval so slow adapter clients
// (notably Milo JVM cold-start on CI) still observe at least one notification
// after CreateMonitoredItems completes.
func pulsePeerEvents(t *testing.T, srv *server.Server, source *ua.NodeID, forDur time.Duration) {
	t.Helper()
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		deadline := time.After(forDur)
		// First emit after a short delay so the client can subscribe.
		time.Sleep(500 * time.Millisecond)
		emitPeerEvent(t, srv, source)
		for {
			select {
			case <-done:
				return
			case <-deadline:
				return
			case <-ticker.C:
				emitPeerEvent(t, srv, source)
			}
		}
	}()
}

func runPeerEventSubscribe(t *testing.T, endpoint string, srv *server.Server, run func(t *testing.T, endpoint, subcmd string, args ...string) adapterResult) adapterResult {
	t.Helper()
	_, nsIdx := findNSFromServer(t, srv)
	source := ua.NewStringNodeID(nsIdx, "Events.Source")
	node := "nsu=" + interopNamespaceURI + ";s=Events.Source"
	pulsePeerEvents(t, srv, source, 14*time.Second)
	result := run(t, endpoint, "event-subscribe",
		"--node", node,
		"--events", "1",
		"--timeout-ms", "15000",
	)
	if !result.Success {
		t.Fatalf("event-subscribe failed: %+v", result)
	}
	return result
}

func parseEventSubscribeItem(t *testing.T, result adapterResult) eventSubscribeItem {
	t.Helper()
	var items []eventSubscribeItem
	if err := json.Unmarshal(result.Results, &items); err != nil || len(items) == 0 {
		t.Fatalf("parse event-subscribe results: %v; raw: %s", err, result.Results)
	}
	return items[0]
}

func assertSelectClauses(t *testing.T, got []string) {
	t.Helper()
	want := map[string]bool{}
	for _, w := range baseEventSelectClauses {
		want[w] = false
	}
	for _, g := range got {
		if _, ok := want[g]; ok {
			want[g] = true
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("selectClauses missing %q; got %v", name, got)
		}
	}
	// Ledger evidence for BaseEvent filter fields (subset always required).
	for _, req := range []string{"EventId", "EventType", "Severity", "Message"} {
		found := false
		for _, g := range got {
			if g == req {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("selectClauses must include %q; got %v", req, got)
		}
	}
}

func assertPeerEventPayload(t *testing.T, item eventSubscribeItem) {
	t.Helper()
	if len(item.Events) < 1 {
		t.Fatalf("events length=%d, want >=1; selectClauses=%v", len(item.Events), item.SelectClauses)
	}
	assertSelectClauses(t, item.SelectClauses)

	ev := item.Events[0]
	fieldByName := map[string]json.RawMessage{}
	for _, f := range ev.Fields {
		fieldByName[f.Name] = f.Value
	}
	matched := false
	if raw, ok := fieldByName["Severity"]; ok {
		var sev float64
		if err := json.Unmarshal(raw, &sev); err == nil && int(sev) == 500 {
			matched = true
		}
		// Some adapters encode integers as strings.
		var sevStr string
		if err := json.Unmarshal(raw, &sevStr); err == nil && (sevStr == "500" || sevStr == "500.0") {
			matched = true
		}
	}
	if raw, ok := fieldByName["Message"]; ok {
		// LocalizedText object or plain string.
		var lt struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(raw, &lt); err == nil && lt.Text == "peer-event" {
			matched = true
		}
		var s string
		if err := json.Unmarshal(raw, &s); err == nil && s == "peer-event" {
			matched = true
		}
	}
	if !matched {
		t.Errorf("event payload did not match severity=500 or message=peer-event; fields=%+v", ev.Fields)
	}
}

func TestGoServer_Open62541Client_EventSubscribe(t *testing.T) {
	t.Run("coverage/event.subscription/open62541-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, "OPEN62541_IMAGE", defaultOpen62541Image, "event-subscribe")
		endpoint, srv := startGoServerWithEvents(t)
		result := runPeerEventSubscribe(t, endpoint, srv, runOpen62541ClientResult)
		assertPeerEventPayload(t, parseEventSubscribeItem(t, result))
	})
}

func TestGoServer_MiloClient_EventSubscribe(t *testing.T) {
	t.Run("coverage/event.subscription/milo-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, "MILO_IMAGE", defaultMiloImage, "event-subscribe")
		endpoint, srv := startGoServerWithEvents(t)
		result := runPeerEventSubscribe(t, endpoint, srv, runMiloClientResult)
		assertPeerEventPayload(t, parseEventSubscribeItem(t, result))
	})
}

// TestGoServer_Open62541Client_EventEmissionBase proves BaseEvent emission from
// the Go server is visible to the open62541 adapter client.
func TestGoServer_Open62541Client_EventEmissionBase(t *testing.T) {
	t.Run("coverage/event.emission.base/open62541-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, "OPEN62541_IMAGE", defaultOpen62541Image, "event-subscribe")
		endpoint, srv := startGoServerWithEvents(t)
		result := runPeerEventSubscribe(t, endpoint, srv, runOpen62541ClientResult)
		item := parseEventSubscribeItem(t, result)
		if len(item.Events) < 1 {
			t.Fatal("EventEmissionBase: no events received")
		}
		assertPeerEventPayload(t, item)
	})
}

// TestGoServer_MiloClient_EventEmissionBase proves BaseEvent emission from the
// Go server is visible to the Milo adapter client.
func TestGoServer_MiloClient_EventEmissionBase(t *testing.T) {
	t.Run("coverage/event.emission.base/milo-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, "MILO_IMAGE", defaultMiloImage, "event-subscribe")
		endpoint, srv := startGoServerWithEvents(t)
		result := runPeerEventSubscribe(t, endpoint, srv, runMiloClientResult)
		item := parseEventSubscribeItem(t, result)
		if len(item.Events) < 1 {
			t.Fatal("EventEmissionBase: no events received")
		}
		assertPeerEventPayload(t, item)
	})
}

// TestGoServer_Open62541Client_EventFilterSelectClauses asserts the adapter
// reports BaseEvent selectClauses per CLIENT_CONTRACT.
func TestGoServer_Open62541Client_EventFilterSelectClauses(t *testing.T) {
	t.Run("coverage/event.filter.select-clauses/open62541-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, "OPEN62541_IMAGE", defaultOpen62541Image, "event-subscribe")
		endpoint, srv := startGoServerWithEvents(t)
		result := runPeerEventSubscribe(t, endpoint, srv, runOpen62541ClientResult)
		item := parseEventSubscribeItem(t, result)
		assertSelectClauses(t, item.SelectClauses)
		for _, want := range baseEventSelectClauses {
			found := false
			for _, g := range item.SelectClauses {
				if g == want {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("selectClauses missing contract field %q; got %v", want, item.SelectClauses)
			}
		}
	})
}

// TestGoServer_MiloClient_EventFilterSelectClauses asserts the Milo adapter
// reports BaseEvent selectClauses per CLIENT_CONTRACT.
func TestGoServer_MiloClient_EventFilterSelectClauses(t *testing.T) {
	t.Run("coverage/event.filter.select-clauses/milo-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, "MILO_IMAGE", defaultMiloImage, "event-subscribe")
		endpoint, srv := startGoServerWithEvents(t)
		result := runPeerEventSubscribe(t, endpoint, srv, runMiloClientResult)
		item := parseEventSubscribeItem(t, result)
		assertSelectClauses(t, item.SelectClauses)
		for _, want := range baseEventSelectClauses {
			found := false
			for _, g := range item.SelectClauses {
				if g == want {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("selectClauses missing contract field %q; got %v", want, item.SelectClauses)
			}
		}
	})
}

func runPeerEventSubscribeFiltered(t *testing.T, endpoint string, srv *server.Server,
	run func(t *testing.T, endpoint, subcmd string, args ...string) adapterResult,
	extra ...string) adapterResult {
	t.Helper()
	_, nsIdx := findNSFromServer(t, srv)
	source := ua.NewStringNodeID(nsIdx, "Events.Source")
	node := "nsu=" + interopNamespaceURI + ";s=Events.Source"
	pulsePeerEvents(t, srv, source, 14*time.Second)
	args := []string{"--node", node, "--events", "1", "--timeout-ms", "15000"}
	args = append(args, extra...)
	result := run(t, endpoint, "event-subscribe", args...)
	if !result.Success {
		t.Fatalf("event-subscribe failed: %+v", result)
	}
	return result
}

func TestGoServer_Open62541Client_EventFilterOfType(t *testing.T) {
	t.Run("coverage/event.filter.of-type/open62541-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, "OPEN62541_IMAGE", defaultOpen62541Image, "event-subscribe")
		endpoint, srv := startGoServerWithEvents(t)
		result := runPeerEventSubscribeFiltered(t, endpoint, srv, runOpen62541ClientResult,
			"--of-type", "i=2041")
		assertPeerEventPayload(t, parseEventSubscribeItem(t, result))
	})
}

func TestGoServer_MiloClient_EventFilterOfType(t *testing.T) {
	t.Run("coverage/event.filter.of-type/milo-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, "MILO_IMAGE", defaultMiloImage, "event-subscribe")
		endpoint, srv := startGoServerWithEvents(t)
		result := runPeerEventSubscribeFiltered(t, endpoint, srv, runMiloClientResult,
			"--of-type", "i=2041")
		assertPeerEventPayload(t, parseEventSubscribeItem(t, result))
	})
}

func TestGoServer_Open62541Client_EventFilterSeverityThreshold(t *testing.T) {
	t.Run("coverage/event.filter.severity-threshold/open62541-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, "OPEN62541_IMAGE", defaultOpen62541Image, "event-subscribe")
		endpoint, srv := startGoServerWithEvents(t)
		result := runPeerEventSubscribeFiltered(t, endpoint, srv, runOpen62541ClientResult,
			"--min-severity", "100")
		assertPeerEventPayload(t, parseEventSubscribeItem(t, result))
	})
}

func TestGoServer_MiloClient_EventFilterSeverityThreshold(t *testing.T) {
	t.Run("coverage/event.filter.severity-threshold/milo-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, "MILO_IMAGE", defaultMiloImage, "event-subscribe")
		endpoint, srv := startGoServerWithEvents(t)
		result := runPeerEventSubscribeFiltered(t, endpoint, srv, runMiloClientResult,
			"--min-severity", "100")
		assertPeerEventPayload(t, parseEventSubscribeItem(t, result))
	})
}
