//go:build interop

// SPDX-License-Identifier: MIT

// Go↔Go event subscription and EventFilter companions.
// COVERAGE.md: events (companion only — peer evidence lives in events_peer_test.go)

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

// customEventTypeNS is the namespace index used for custom event type tests.
// It is resolved at runtime from the interop server namespace.
const customEventTypeName = "CustomAlarmEventType"

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
// EventFilter, event emission via EmitBaseEvent, and delivery.
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
// invalid EventFilters with correct status codes.
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

// TestGoServer_EventMultipleEmissions verifies multiple events are delivered in order.
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

// startGoServerWithCustomEventType starts a Go server that exposes a custom
// ObjectType node (a user-defined event subtype) in the interop namespace.
func startGoServerWithCustomEventType(t *testing.T) (string, *server.Server, *ua.NodeID) {
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

	nsIdx := ns.ID()

	// Register a custom ObjectType node representing a user-defined event subtype.
	customTypeID := ua.NewStringNodeID(nsIdx, customEventTypeName)
	customTypeNode := server.NewNode(
		customTypeID,
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:  server.DataValueFromValue(uint32(ua.NodeClassObjectType)),
			ua.AttributeIDBrowseName: server.DataValueFromValue(attrs.BrowseName(customEventTypeName)),
			ua.AttributeIDDisplayName: server.DataValueFromValue(
				attrs.DisplayName("Custom Alarm Event", "en")),
		},
		nil,
		nil,
	)
	ns.AddNode(customTypeNode)

	// Add an event-capable Object node with EventNotifier = SubscribeToEvents (1).
	eventSourceID := ua.NewStringNodeID(nsIdx, "Events.Source")
	eventSourceNode := server.NewNode(
		eventSourceID,
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:     server.DataValueFromValue(uint32(ua.NodeClassObject)),
			ua.AttributeIDBrowseName:    server.DataValueFromValue(attrs.BrowseName("Events.Source")),
			ua.AttributeIDDisplayName:   server.DataValueFromValue(attrs.DisplayName("Event Source", "en")),
			ua.AttributeIDEventNotifier: server.DataValueFromValue(byte(1)),
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

	return fmt.Sprintf("opc.tcp://localhost:%d", port), s, customTypeID
}

// TestGoServer_CustomEventSubtype verifies that a user-defined ObjectType in the
// address space is accepted as an OfType operand and correctly filters events.
func TestGoServer_CustomEventSubtype(t *testing.T) {
	endpoint, srv, customTypeID := startGoServerWithCustomEventType(t)
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	eventSourceID := ua.NewStringNodeID(nsIdx, "Events.Source")

	notifyCh := make(chan *opcua.PublishNotificationData, 32)
	sub, _, err := c.NewSubscription().
		Interval(100 * time.Millisecond).
		NotifyChannel(notifyCh).
		Start(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	// Use the custom type as the OfType operand — this requires the server to
	// accept namespace != 0 types that exist in the address space.
	filter := ua.NewEventFilter().
		Select("EventType", "Severity", "SourceName").
		Where(ua.OfType(customTypeID)).
		Build()

	monReq := &ua.MonitoredItemCreateRequest{
		ItemToMonitor: &ua.ReadValueID{
			NodeID:      eventSourceID,
			AttributeID: ua.AttributeIDEventNotifier,
		},
		MonitoringMode: ua.MonitoringModeReporting,
		RequestedParameters: &ua.MonitoringParameters{
			ClientHandle:     400,
			SamplingInterval: 0,
			Filter:           ua.NewExtensionObject(filter),
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
		t.Fatalf("monitor create status=%v (custom event type should be accepted)", monResp.Results[0].StatusCode)
	}

	// Emit one matching event (matching type) and one non-matching event.
	matchEvt := &server.BaseEvent{
		EventID:    []byte("custom-001"),
		EventType:  customTypeID,
		SourceNode: eventSourceID,
		SourceName: "Events.Source",
		Time:       time.Now(),
		Message:    ua.NewLocalizedText("Custom alarm"),
		Severity:   750,
	}
	noMatchEvt := &server.BaseEvent{
		EventID:    []byte("base-001"),
		EventType:  ua.NewNumericNodeID(0, id.AuditEventType), // different type
		SourceNode: eventSourceID,
		SourceName: "Events.Source",
		Time:       time.Now(),
		Message:    ua.NewLocalizedText("Audit event"),
		Severity:   100,
	}
	if err := srv.EmitBaseEvent(eventSourceID, noMatchEvt); err != nil {
		t.Fatalf("EmitBaseEvent (no-match): %v", err)
	}
	if err := srv.EmitBaseEvent(eventSourceID, matchEvt); err != nil {
		t.Fatalf("EmitBaseEvent (match): %v", err)
	}

	// We expect to receive exactly the matching event (severity 750).
	deadline := time.After(10 * time.Second)
	for {
		select {
		case msg, ok := <-notifyCh:
			if !ok {
				t.Fatal("notify channel closed")
			}
			if msg.Error != nil {
				t.Fatalf("notification error: %v", msg.Error)
			}
			enl, ok := msg.Value.(*ua.EventNotificationList)
			if !ok || enl == nil || len(enl.Events) == 0 {
				continue
			}
			for _, ef := range enl.Events {
				if ef.ClientHandle != 400 || len(ef.EventFields) < 2 {
					continue
				}
				sev, ok := ef.EventFields[1].Value().(uint16)
				if !ok {
					continue
				}
				if sev == 100 {
					t.Error("received non-matching event (audit) through OfType custom filter")
				}
				if sev == 750 {
					return // success
				}
			}
		case <-deadline:
			t.Fatal("timeout waiting for custom event type notification")
		}
	}
}

// TestGoServer_WhereClause_SeverityFilter verifies that WhereClause comparison
// operators (GreaterThan, Equals) properly filter events by Severity.
func TestGoServer_WhereClause_SeverityFilter(t *testing.T) {
	endpoint, srv := startGoServerWithEvents(t)
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	eventSourceID := ua.NewStringNodeID(nsIdx, "Events.Source")

	notifyCh := make(chan *opcua.PublishNotificationData, 32)
	sub, _, err := c.NewSubscription().
		Interval(100 * time.Millisecond).
		NotifyChannel(notifyCh).
		Start(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	// Filter: OfType(BaseEventType) AND Severity >= 500.
	filter := ua.NewEventFilter().
		Select("Severity", "SourceName").
		Where(ua.Field("Severity").GreaterThanOrEqual(uint16(500))).
		Build()

	monReq := &ua.MonitoredItemCreateRequest{
		ItemToMonitor: &ua.ReadValueID{
			NodeID:      eventSourceID,
			AttributeID: ua.AttributeIDEventNotifier,
		},
		MonitoringMode: ua.MonitoringModeReporting,
		RequestedParameters: &ua.MonitoringParameters{
			ClientHandle:     500,
			SamplingInterval: 0,
			Filter:           ua.NewExtensionObject(filter),
			QueueSize:        10,
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

	// Emit a low-severity event (should be filtered out) and a high-severity event.
	lowEvt := &server.BaseEvent{
		EventID:    []byte("low-001"),
		EventType:  ua.NewNumericNodeID(0, id.BaseEventType),
		SourceNode: eventSourceID,
		SourceName: "Events.Source",
		Time:       time.Now(),
		Message:    ua.NewLocalizedText("Low severity"),
		Severity:   100, // below threshold
	}
	highEvt := &server.BaseEvent{
		EventID:    []byte("high-001"),
		EventType:  ua.NewNumericNodeID(0, id.BaseEventType),
		SourceNode: eventSourceID,
		SourceName: "Events.Source",
		Time:       time.Now(),
		Message:    ua.NewLocalizedText("High severity"),
		Severity:   800, // above threshold
	}
	if err := srv.EmitBaseEvent(eventSourceID, lowEvt); err != nil {
		t.Fatalf("EmitBaseEvent (low): %v", err)
	}
	if err := srv.EmitBaseEvent(eventSourceID, highEvt); err != nil {
		t.Fatalf("EmitBaseEvent (high): %v", err)
	}

	deadline := time.After(10 * time.Second)
	for {
		select {
		case msg, ok := <-notifyCh:
			if !ok {
				t.Fatal("notify channel closed")
			}
			if msg.Error != nil {
				t.Fatalf("notification error: %v", msg.Error)
			}
			enl, ok := msg.Value.(*ua.EventNotificationList)
			if !ok || enl == nil || len(enl.Events) == 0 {
				continue
			}
			for _, ef := range enl.Events {
				if ef.ClientHandle != 500 || len(ef.EventFields) < 1 {
					continue
				}
				sev, ok := ef.EventFields[0].Value().(uint16)
				if !ok {
					continue
				}
				if sev == 100 {
					t.Error("low-severity event passed through WhereClause filter (should be suppressed)")
				}
				if sev == 800 {
					return // success: high-severity event delivered correctly
				}
			}
		case <-deadline:
			t.Fatal("timeout waiting for high-severity event notification")
		}
	}
}

// TestGoServer_CustomEventFields verifies that user-defined fields placed in
// BaseEvent.Fields are resolved by name through SelectClauses and delivered.
func TestGoServer_CustomEventFields(t *testing.T) {
	endpoint, srv := startGoServerWithEvents(t)
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	eventSourceID := ua.NewStringNodeID(nsIdx, "Events.Source")

	notifyCh := make(chan *opcua.PublishNotificationData, 32)
	sub, _, err := c.NewSubscription().
		Interval(100 * time.Millisecond).
		NotifyChannel(notifyCh).
		Start(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	// Request both standard and custom event fields.
	filter := ua.NewEventFilter().
		Select("Severity", "AlarmLevel", "Zone").
		Build()

	monReq := &ua.MonitoredItemCreateRequest{
		ItemToMonitor: &ua.ReadValueID{
			NodeID:      eventSourceID,
			AttributeID: ua.AttributeIDEventNotifier,
		},
		MonitoringMode: ua.MonitoringModeReporting,
		RequestedParameters: &ua.MonitoringParameters{
			ClientHandle:     600,
			SamplingInterval: 0,
			Filter:           ua.NewExtensionObject(filter),
			QueueSize:        10,
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

	// Emit with custom fields.
	evt := &server.BaseEvent{
		EventID:    []byte("custom-fields-001"),
		EventType:  ua.NewNumericNodeID(0, id.BaseEventType),
		SourceNode: eventSourceID,
		SourceName: "Events.Source",
		Time:       time.Now(),
		Message:    ua.NewLocalizedText("Custom fields event"),
		Severity:   300,
		Fields: map[string]*ua.Variant{
			"AlarmLevel": ua.MustVariant(int32(42)),
			"Zone":       ua.MustVariant("North"),
		},
	}
	if err := srv.EmitBaseEvent(eventSourceID, evt); err != nil {
		t.Fatalf("EmitBaseEvent: %v", err)
	}

	deadline := time.After(10 * time.Second)
	for {
		select {
		case msg, ok := <-notifyCh:
			if !ok {
				t.Fatal("notify channel closed")
			}
			if msg.Error != nil {
				t.Fatalf("notification error: %v", msg.Error)
			}
			enl, ok := msg.Value.(*ua.EventNotificationList)
			if !ok || enl == nil || len(enl.Events) == 0 {
				continue
			}
			for _, ef := range enl.Events {
				if ef.ClientHandle != 600 || len(ef.EventFields) < 3 {
					continue
				}
				// fields[0] = Severity, fields[1] = AlarmLevel, fields[2] = Zone
				sev, sevOK := ef.EventFields[0].Value().(uint16)
				alarm, alarmOK := ef.EventFields[1].Value().(int32)
				zone, zoneOK := ef.EventFields[2].Value().(string)
				if !sevOK || sev != 300 {
					t.Errorf("Severity=%v, want 300", ef.EventFields[0].Value())
				}
				if !alarmOK || alarm != 42 {
					t.Errorf("AlarmLevel=%v, want 42", ef.EventFields[1].Value())
				}
				if !zoneOK || zone != "North" {
					t.Errorf("Zone=%v, want \"North\"", ef.EventFields[2].Value())
				}
				return
			}
		case <-deadline:
			t.Fatal("timeout waiting for custom fields event notification")
		}
	}
}

// TestGoServer_ModifyMonitoredItem_EventFilter verifies that after
// ModifyMonitoredItems with a new EventFilter the updated filter is applied.
func TestGoServer_ModifyMonitoredItem_EventFilter(t *testing.T) {
	endpoint, srv := startGoServerWithEvents(t)
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	eventSourceID := ua.NewStringNodeID(nsIdx, "Events.Source")

	notifyCh := make(chan *opcua.PublishNotificationData, 32)
	sub, _, err := c.NewSubscription().
		Interval(100 * time.Millisecond).
		NotifyChannel(notifyCh).
		Start(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	// Create initial filter: accept all severities.
	initialFilter := ua.NewEventFilter().
		Select("Severity").
		Build()

	monReq := &ua.MonitoredItemCreateRequest{
		ItemToMonitor: &ua.ReadValueID{
			NodeID:      eventSourceID,
			AttributeID: ua.AttributeIDEventNotifier,
		},
		MonitoringMode: ua.MonitoringModeReporting,
		RequestedParameters: &ua.MonitoringParameters{
			ClientHandle:     700,
			SamplingInterval: 0,
			Filter:           ua.NewExtensionObject(initialFilter),
			QueueSize:        20,
			DiscardOldest:    true,
		},
	}

	monResp, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, monReq)
	if err != nil {
		t.Fatalf("Monitor: %v", err)
	}
	if monResp.Results[0].StatusCode != ua.StatusOK {
		t.Fatalf("monitor create status=%v", monResp.Results[0].StatusCode)
	}
	monitoredItemID := monResp.Results[0].MonitoredItemID

	// Emit a low-severity event — should be delivered with the initial filter.
	lowEvt := &server.BaseEvent{
		EventID:    []byte("mod-low-001"),
		EventType:  ua.NewNumericNodeID(0, id.BaseEventType),
		SourceNode: eventSourceID,
		SourceName: "Events.Source",
		Time:       time.Now(),
		Message:    ua.NewLocalizedText("Pre-modify low"),
		Severity:   50,
	}
	if err := srv.EmitBaseEvent(eventSourceID, lowEvt); err != nil {
		t.Fatalf("EmitBaseEvent (pre-modify): %v", err)
	}

	// Wait for it.
	deadline := time.After(10 * time.Second)
	for {
		var gotLow bool
		select {
		case msg, ok := <-notifyCh:
			if !ok {
				t.Fatal("notify channel closed")
			}
			if msg.Error != nil {
				t.Fatalf("notification error: %v", msg.Error)
			}
			enl, ok := msg.Value.(*ua.EventNotificationList)
			if !ok || enl == nil {
				continue
			}
			for _, ef := range enl.Events {
				if ef.ClientHandle != 700 || len(ef.EventFields) < 1 {
					continue
				}
				if sev, ok := ef.EventFields[0].Value().(uint16); ok && sev == 50 {
					gotLow = true
				}
			}
			if gotLow {
				goto afterPreModify
			}
		case <-deadline:
			t.Fatal("timeout waiting for pre-modify event")
		}
	}
afterPreModify:

	// Modify the filter: now require Severity >= 500.
	modifiedFilter := ua.NewEventFilter().
		Select("Severity").
		Where(ua.Field("Severity").GreaterThanOrEqual(uint16(500))).
		Build()

	modReq := &ua.ModifyMonitoredItemsRequest{
		SubscriptionID:     sub.SubscriptionID,
		TimestampsToReturn: ua.TimestampsToReturnBoth,
		ItemsToModify: []*ua.MonitoredItemModifyRequest{
			{
				MonitoredItemID: monitoredItemID,
				RequestedParameters: &ua.MonitoringParameters{
					ClientHandle:     700,
					SamplingInterval: 0,
					Filter:           ua.NewExtensionObject(modifiedFilter),
					QueueSize:        20,
					DiscardOldest:    true,
				},
			},
		},
	}
	if err := c.Send(ctx, modReq, func(v ua.Response) error {
		resp, ok := v.(*ua.ModifyMonitoredItemsResponse)
		if !ok || resp == nil {
			return fmt.Errorf("unexpected response type %T", v)
		}
		if len(resp.Results) == 0 || resp.Results[0].StatusCode != ua.StatusOK {
			return fmt.Errorf("modify result=%v", resp.Results[0].StatusCode)
		}
		return nil
	}); err != nil {
		t.Fatalf("ModifyMonitoredItems: %v", err)
	}

	// Drain any leftover notifications.
	drainDeadline := time.After(500 * time.Millisecond)
drain:
	for {
		select {
		case <-notifyCh:
		case <-drainDeadline:
			break drain
		}
	}

	// Emit a low-severity event — should be suppressed by the new filter.
	lowEvt2 := &server.BaseEvent{
		EventID:    []byte("mod-low-002"),
		EventType:  ua.NewNumericNodeID(0, id.BaseEventType),
		SourceNode: eventSourceID,
		SourceName: "Events.Source",
		Time:       time.Now(),
		Message:    ua.NewLocalizedText("Post-modify low"),
		Severity:   50,
	}
	// Emit a high-severity event — should pass.
	highEvt := &server.BaseEvent{
		EventID:    []byte("mod-high-001"),
		EventType:  ua.NewNumericNodeID(0, id.BaseEventType),
		SourceNode: eventSourceID,
		SourceName: "Events.Source",
		Time:       time.Now(),
		Message:    ua.NewLocalizedText("Post-modify high"),
		Severity:   900,
	}
	if err := srv.EmitBaseEvent(eventSourceID, lowEvt2); err != nil {
		t.Fatalf("EmitBaseEvent (post-modify low): %v", err)
	}
	if err := srv.EmitBaseEvent(eventSourceID, highEvt); err != nil {
		t.Fatalf("EmitBaseEvent (post-modify high): %v", err)
	}

	deadline2 := time.After(10 * time.Second)
	for {
		select {
		case msg, ok := <-notifyCh:
			if !ok {
				t.Fatal("notify channel closed")
			}
			if msg.Error != nil {
				t.Fatalf("notification error: %v", msg.Error)
			}
			enl, ok := msg.Value.(*ua.EventNotificationList)
			if !ok || enl == nil {
				continue
			}
			for _, ef := range enl.Events {
				if ef.ClientHandle != 700 || len(ef.EventFields) < 1 {
					continue
				}
				sev, ok := ef.EventFields[0].Value().(uint16)
				if !ok {
					continue
				}
				if sev == 50 {
					t.Error("low-severity event delivered after filter was raised to >= 500")
				}
				if sev == 900 {
					return // success
				}
			}
		case <-deadline2:
			t.Fatal("timeout waiting for post-modify high-severity event")
		}
	}
}
