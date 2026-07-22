//go:build interop

// SPDX-License-Identifier: MIT

// Peer event subscription tests (C→O / C→M) against reference-server BaseEvent emission.
// COVERAGE.md: events / event.subscription, event.notification.decode,
// event.filter.select-clauses, event.filter.of-type, event.filter.severity-threshold

package interop

import (
	"context"
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

func subscribePeerBaseEvent(t *testing.T, endpoint string, withOfType, withMinSeverity bool) *ua.EventFieldList {
	t.Helper()
	c := dialClient(t, endpoint)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	_, nsIdx := findNS(t, c)
	source := ua.NewStringNodeID(nsIdx, "Events.Source")

	notifyCh := make(chan *opcua.PublishNotificationData, 32)
	sub, _, err := c.NewSubscription().
		Interval(200 * time.Millisecond).
		NotifyChannel(notifyCh).
		Start(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	builder := ua.NewEventFilter().
		Select("EventId", "EventType", "SourceName", "Message", "Severity", "Time")
	if withOfType {
		builder = builder.Where(ua.OfType(ua.NewNumericNodeID(0, id.BaseEventType)))
	}
	if withMinSeverity {
		builder = builder.Where(ua.Field("Severity").GreaterThanOrEqual(uint16(100)))
	}
	filterEO := ua.NewExtensionObject(builder.Build())

	monReq := &ua.MonitoredItemCreateRequest{
		ItemToMonitor: &ua.ReadValueID{
			NodeID:      source,
			AttributeID: ua.AttributeIDEventNotifier,
		},
		MonitoringMode: ua.MonitoringModeReporting,
		RequestedParameters: &ua.MonitoringParameters{
			ClientHandle:     42,
			SamplingInterval: 0,
			Filter:           filterEO,
			QueueSize:        10,
			DiscardOldest:    true,
		},
	}
	monResp, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, monReq)
	if err != nil {
		t.Fatalf("Monitor: %v", err)
	}
	if len(monResp.Results) == 0 || monResp.Results[0].StatusCode != ua.StatusOK {
		t.Fatalf("monitor status=%v", monResp.Results)
	}

	deadline := time.After(20 * time.Second)
	for {
		select {
		case msg, ok := <-notifyCh:
			if !ok {
				t.Fatal("notify channel closed")
			}
			if msg.Error != nil {
				t.Fatalf("notification error: %v", msg.Error)
			}
			if enl, ok := msg.Value.(*ua.EventNotificationList); ok && enl != nil && len(enl.Events) > 0 {
				return enl.Events[0]
			}
		case <-deadline:
			t.Fatal("timeout waiting for peer BaseEvent")
		}
	}
}

func assertPeerBaseEventFields(t *testing.T, ef *ua.EventFieldList) {
	t.Helper()
	if ef == nil || len(ef.EventFields) < 6 {
		t.Fatalf("expected >=6 event fields, got %#v", ef)
	}
	matched := false
	if sev, ok := ef.EventFields[4].Value().(uint16); ok && sev == 500 {
		matched = true
	}
	if msg, ok := ef.EventFields[3].Value().(*ua.LocalizedText); ok && msg != nil && msg.Text == "peer-event" {
		matched = true
	}
	if msg, ok := ef.EventFields[3].Value().(string); ok && msg == "peer-event" {
		matched = true
	}
	if !matched {
		t.Errorf("event fields did not match severity=500 or message=peer-event: %#v", ef.EventFields)
	}
}

func TestMiloServer_EventSubscription(t *testing.T) {
	t.Run("coverage/event.subscription/go-client-to-milo-server", func(t *testing.T) {
		h := startMiloServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		ef := subscribePeerBaseEvent(t, h.endpoint, false, false)
		assertPeerBaseEventFields(t, ef)
	})
}

func TestMiloServer_EventNotificationDecode(t *testing.T) {
	t.Run("coverage/event.notification.decode/go-client-to-milo-server", func(t *testing.T) {
		h := startMiloServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		ef := subscribePeerBaseEvent(t, h.endpoint, false, false)
		assertPeerBaseEventFields(t, ef)
	})
}

func TestMiloServer_EventFilterSelectClauses(t *testing.T) {
	t.Run("coverage/event.filter.select-clauses/go-client-to-milo-server", func(t *testing.T) {
		h := startMiloServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		ef := subscribePeerBaseEvent(t, h.endpoint, false, false)
		if len(ef.EventFields) < 6 {
			t.Fatalf("selectClauses fields=%d, want >=6", len(ef.EventFields))
		}
	})
}

func TestMiloServer_EventFilterOfType(t *testing.T) {
	t.Run("coverage/event.filter.of-type/go-client-to-milo-server", func(t *testing.T) {
		h := startMiloServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		ef := subscribePeerBaseEvent(t, h.endpoint, true, false)
		assertPeerBaseEventFields(t, ef)
	})
}

func TestMiloServer_EventFilterSeverityThreshold(t *testing.T) {
	t.Run("coverage/event.filter.severity-threshold/go-client-to-milo-server", func(t *testing.T) {
		h := startMiloServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		ef := subscribePeerBaseEvent(t, h.endpoint, false, true)
		assertPeerBaseEventFields(t, ef)
	})
}

func TestOpen62541Server_EventSubscription(t *testing.T) {
	t.Run("coverage/event.subscription/go-client-to-open62541-server", func(t *testing.T) {
		h := startOpen62541Server(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		ef := subscribePeerBaseEvent(t, h.endpoint, false, false)
		assertPeerBaseEventFields(t, ef)
	})
}

func TestOpen62541Server_EventNotificationDecode(t *testing.T) {
	t.Run("coverage/event.notification.decode/go-client-to-open62541-server", func(t *testing.T) {
		h := startOpen62541Server(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		ef := subscribePeerBaseEvent(t, h.endpoint, false, false)
		assertPeerBaseEventFields(t, ef)
	})
}

func TestOpen62541Server_EventFilterSelectClauses(t *testing.T) {
	t.Run("coverage/event.filter.select-clauses/go-client-to-open62541-server", func(t *testing.T) {
		h := startOpen62541Server(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		ef := subscribePeerBaseEvent(t, h.endpoint, false, false)
		if len(ef.EventFields) < 6 {
			t.Fatalf("selectClauses fields=%d, want >=6", len(ef.EventFields))
		}
	})
}

func TestOpen62541Server_EventFilterOfType(t *testing.T) {
	t.Run("coverage/event.filter.of-type/go-client-to-open62541-server", func(t *testing.T) {
		h := startOpen62541Server(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		ef := subscribePeerBaseEvent(t, h.endpoint, true, false)
		assertPeerBaseEventFields(t, ef)
	})
}

func TestOpen62541Server_EventFilterSeverityThreshold(t *testing.T) {
	t.Run("coverage/event.filter.severity-threshold/go-client-to-open62541-server", func(t *testing.T) {
		h := startOpen62541Server(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		ef := subscribePeerBaseEvent(t, h.endpoint, false, true)
		assertPeerBaseEventFields(t, ef)
	})
}
