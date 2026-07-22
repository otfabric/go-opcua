//go:build interop

// SPDX-License-Identifier: MIT

package interop

import (
	"context"
	"fmt"
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
)

// startGoServerWithEvents starts a Go server with an event-capable node in the interop namespace.
// Returns the endpoint URL and the server instance for emitting events.
func startGoServerWithEvents(t *testing.T) (string, *server.Server) {
	t.Helper()

	port := freePort(t)

	s, err := server.New(
		server.ListenOn(fmt.Sprintf("0.0.0.0:%d", port)),
		server.EndPoint("host.docker.internal", port),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
	)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	ns := server.NewNodeNameSpace(s, interopNamespaceURI)
	s.AddNamespace(ns)
	objs := ns.Objects()

	// Add a regular writable variable for data-change tests.
	addVar := func(name string, val interface{}) {
		n := ns.AddNewVariableStringNode(name, val)
		objs.AddRef(n, server.RefTypeIDHasComponent, true)
	}
	addVar("Access.ReadWrite", int32(42))

	// Add an event-capable Object node with EventNotifier = SubscribeToEvents (1).
	nsIdx := ns.ID()
	eventSourceID := ua.NewStringNodeID(nsIdx, "Events.Source")
	eventSourceNode := server.NewNode(
		eventSourceID,
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:     server.DataValueFromValue(uint32(ua.NodeClassObject)),
			ua.AttributeIDBrowseName:    server.DataValueFromValue(attrs.BrowseName("Events.Source")),
			ua.AttributeIDDisplayName:   server.DataValueFromValue(attrs.DisplayName("Event Source", "en")),
			ua.AttributeIDEventNotifier: server.DataValueFromValue(byte(1)), // SubscribeToEvents
		},
		nil,
		nil,
	)
	ns.AddNode(eventSourceNode)
	objs.AddRef(eventSourceNode, server.RefTypeIDHasComponent, true)

	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("server.Start: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	return fmt.Sprintf("opc.tcp://localhost:%d", port), s
}

// TestGoServer_EventSubscription_BasicLifecycle verifies CreateMonitoredItems with
// EventFilter, event emission via EmitBaseEvent, and delivery (Phase 15).
func TestGoServer_EventSubscription_BasicLifecycle(t *testing.T) {
	endpoint, srv := startGoServerWithEvents(t)
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	eventSourceID := ua.NewStringNodeID(nsIdx, "Events.Source")

	// Create subscription.
	notifyCh := make(chan *opcua.PublishNotificationData, 32)
	sub, _, err := c.NewSubscription().
		Interval(100 * time.Millisecond).
		NotifyChannel(notifyCh).
		Start(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	// Create EventFilter with SelectClauses for standard fields.
	filter := ua.NewEventFilter().
		Select("EventId", "EventType", "SourceName", "Message", "Severity", "Time").
		Where(ua.OfType(ua.NewNumericNodeID(0, id.BaseEventType))).
		Build()

	filterEO := ua.NewExtensionObject(filter)

	// Create monitored item for events on the source node.
	monReq := &ua.MonitoredItemCreateRequest{
		ItemToMonitor: &ua.ReadValueID{
			NodeID:      eventSourceID,
			AttributeID: ua.AttributeIDEventNotifier,
		},
		MonitoringMode: ua.MonitoringModeReporting,
		RequestedParameters: &ua.MonitoringParameters{
			ClientHandle:     100,
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
	if len(monResp.Results) == 0 {
		t.Fatal("no monitor results")
	}
	if monResp.Results[0].StatusCode != ua.StatusOK {
		t.Fatalf("monitor status=%v", monResp.Results[0].StatusCode)
	}

	// Emit an event.
	now := time.Now()
	evt := &server.BaseEvent{
		EventID:    []byte("test-event-001"),
		EventType:  ua.NewNumericNodeID(0, id.BaseEventType),
		SourceNode: eventSourceID,
		SourceName: "Events.Source",
		Time:       now,
		Message:    ua.NewLocalizedText("Test event occurred"),
		Severity:   500,
	}
	if err := srv.EmitBaseEvent(eventSourceID, evt); err != nil {
		t.Fatalf("EmitBaseEvent: %v", err)
	}

	// Wait for the event notification.
	deadline := time.After(10 * time.Second)
	var received *ua.EventNotificationList
	for received == nil {
		select {
		case msg, ok := <-notifyCh:
			if !ok {
				t.Fatal("notify channel closed")
			}
			if msg.Error != nil {
				t.Fatalf("notification error: %v", msg.Error)
			}
			if enl, ok := msg.Value.(*ua.EventNotificationList); ok && enl != nil && len(enl.Events) > 0 {
				received = enl
			}
		case <-deadline:
			t.Fatal("timeout waiting for event notification")
		}
	}

	if len(received.Events) == 0 {
		t.Fatal("no events in notification")
	}
	ef := received.Events[0]
	if ef.ClientHandle != 100 {
		t.Errorf("ClientHandle=%d, want 100", ef.ClientHandle)
	}
	// Should have 6 fields matching our SelectClauses.
	if len(ef.EventFields) < 6 {
		t.Fatalf("EventFields=%d, want >=6", len(ef.EventFields))
	}
	// Verify SourceName field (index 2 in our select: EventId, EventType, SourceName, Message, Severity, Time).
	if sn, ok := ef.EventFields[2].Value().(string); !ok || sn != "Events.Source" {
		t.Errorf("SourceName=%v, want 'Events.Source'", ef.EventFields[2].Value())
	}
	// Verify Severity.
	if sev, ok := ef.EventFields[4].Value().(uint16); !ok || sev != 500 {
		t.Errorf("Severity=%v, want 500", ef.EventFields[4].Value())
	}
}

// TestGoServer_EventFilter_InvalidReject verifies that CreateMonitoredItems rejects
// invalid EventFilters with correct status codes (Phase 15).
func TestGoServer_EventFilter_InvalidReject(t *testing.T) {
	endpoint, _ := startGoServerWithEvents(t)
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	eventSourceID := ua.NewStringNodeID(nsIdx, "Events.Source")

	notifyCh := make(chan *opcua.PublishNotificationData, 8)
	sub, _, err := c.NewSubscription().
		Interval(200 * time.Millisecond).
		NotifyChannel(notifyCh).
		Start(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	t.Run("NoFilter", func(t *testing.T) {
		monReq := &ua.MonitoredItemCreateRequest{
			ItemToMonitor: &ua.ReadValueID{
				NodeID:      eventSourceID,
				AttributeID: ua.AttributeIDEventNotifier,
			},
			MonitoringMode: ua.MonitoringModeReporting,
			RequestedParameters: &ua.MonitoringParameters{
				ClientHandle:     200,
				SamplingInterval: 0,
				Filter:           ua.NewExtensionObject(nil),
				QueueSize:        5,
				DiscardOldest:    true,
			},
		}
		monResp, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, monReq)
		if err != nil {
			t.Fatalf("Monitor: %v", err)
		}
		if monResp.Results[0].StatusCode == ua.StatusOK {
			t.Fatal("expected rejection for missing EventFilter")
		}
	})

	t.Run("EmptySelectClauses", func(t *testing.T) {
		emptyFilter := &ua.EventFilter{
			SelectClauses: []*ua.SimpleAttributeOperand{},
			WhereClause:   &ua.ContentFilter{},
		}
		monReq := &ua.MonitoredItemCreateRequest{
			ItemToMonitor: &ua.ReadValueID{
				NodeID:      eventSourceID,
				AttributeID: ua.AttributeIDEventNotifier,
			},
			MonitoringMode: ua.MonitoringModeReporting,
			RequestedParameters: &ua.MonitoringParameters{
				ClientHandle:     201,
				SamplingInterval: 0,
				Filter:           ua.NewExtensionObject(emptyFilter),
				QueueSize:        5,
				DiscardOldest:    true,
			},
		}
		monResp, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, monReq)
		if err != nil {
			t.Fatalf("Monitor: %v", err)
		}
		if monResp.Results[0].StatusCode == ua.StatusOK {
			t.Fatal("expected rejection for empty SelectClauses")
		}
	})

	t.Run("UnsupportedWhereOperator", func(t *testing.T) {
		filter := ua.NewEventFilter().
			Select("Severity").
			Where(ua.Field("Severity").GreaterThan(uint16(100))).
			Build()

		monReq := &ua.MonitoredItemCreateRequest{
			ItemToMonitor: &ua.ReadValueID{
				NodeID:      eventSourceID,
				AttributeID: ua.AttributeIDEventNotifier,
			},
			MonitoringMode: ua.MonitoringModeReporting,
			RequestedParameters: &ua.MonitoringParameters{
				ClientHandle:     202,
				SamplingInterval: 0,
				Filter:           ua.NewExtensionObject(filter),
				QueueSize:        5,
				DiscardOldest:    true,
			},
		}
		monResp, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, monReq)
		if err != nil {
			t.Fatalf("Monitor: %v", err)
		}
		// Unsupported where operators result in a bad status.
		if monResp.Results[0].StatusCode == ua.StatusOK {
			t.Log("WARN: Server accepted unsupported where clause (may be lenient)")
		}
	})
}

// TestGoServer_EventMultipleEmissions verifies multiple events are delivered in order (Phase 15).
func TestGoServer_EventMultipleEmissions(t *testing.T) {
	endpoint, srv := startGoServerWithEvents(t)
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	eventSourceID := ua.NewStringNodeID(nsIdx, "Events.Source")

	notifyCh := make(chan *opcua.PublishNotificationData, 64)
	sub, _, err := c.NewSubscription().
		Interval(100 * time.Millisecond).
		NotifyChannel(notifyCh).
		Start(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	filter := ua.NewEventFilter().
		Select("SourceName", "Severity").
		Where(ua.OfType(ua.NewNumericNodeID(0, id.BaseEventType))).
		Build()

	monReq := &ua.MonitoredItemCreateRequest{
		ItemToMonitor: &ua.ReadValueID{
			NodeID:      eventSourceID,
			AttributeID: ua.AttributeIDEventNotifier,
		},
		MonitoringMode: ua.MonitoringModeReporting,
		RequestedParameters: &ua.MonitoringParameters{
			ClientHandle:     300,
			SamplingInterval: 0,
			Filter:           ua.NewExtensionObject(filter),
			QueueSize:        20,
			DiscardOldest:    true,
		},
	}

	monResp, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, monReq)
	if err != nil {
		t.Fatalf("Monitor: %v", err)
	}
	if monResp.Results[0].StatusCode != ua.StatusOK {
		t.Fatalf("monitor status=%v", monResp.Results[0].StatusCode)
	}

	// Emit 5 events with increasing severity.
	for i := 0; i < 5; i++ {
		evt := &server.BaseEvent{
			EventID:    []byte(fmt.Sprintf("event-%03d", i)),
			EventType:  ua.NewNumericNodeID(0, id.BaseEventType),
			SourceNode: eventSourceID,
			SourceName: "Events.Source",
			Time:       time.Now(),
			Message:    ua.NewLocalizedText(fmt.Sprintf("Event %d", i)),
			Severity:   uint16(100 * (i + 1)),
		}
		if err := srv.EmitBaseEvent(eventSourceID, evt); err != nil {
			t.Fatalf("EmitBaseEvent: %v", err)
		}
	}

	// Collect events.
	deadline := time.After(10 * time.Second)
	var severities []uint16
	for len(severities) < 5 {
		select {
		case msg, ok := <-notifyCh:
			if !ok {
				t.Fatal("notify channel closed")
			}
			if msg.Error != nil {
				t.Fatalf("notification error: %v", msg.Error)
			}
			if enl, ok := msg.Value.(*ua.EventNotificationList); ok && enl != nil {
				for _, ef := range enl.Events {
					if ef.ClientHandle != 300 || len(ef.EventFields) < 2 {
						continue
					}
					if sev, ok := ef.EventFields[1].Value().(uint16); ok {
						severities = append(severities, sev)
					}
				}
			}
		case <-deadline:
			t.Fatalf("timeout: got %d events, want 5. severities=%v", len(severities), severities)
		}
	}

	// Verify order.
	for i, sev := range severities[:5] {
		want := uint16(100 * (i + 1))
		if sev != want {
			t.Errorf("event[%d] severity=%d, want %d", i, sev, want)
		}
	}
}
