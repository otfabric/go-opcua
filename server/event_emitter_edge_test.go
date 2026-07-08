// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEventEmitter_NilMonitoredItemService(t *testing.T) {
	srv := newTestServer()
	srv.MonitoredItemService = nil

	err := srv.EmitEvent(ua.NewStringNodeID(1, "x"), &ua.EventFieldList{
		EventFields: []*ua.Variant{ua.MustVariant("hello")},
	})
	assert.NoError(t, err, "EmitEvent should silently return when MonitoredItemService is nil")
}

func TestEventEmitter_NilItemInList(t *testing.T) {
	srv := newTestServer()
	ns, _ := addTestNamespace(srv)

	nodeID := ua.NewStringNodeID(ns.ID(), "rw_int32")

	sub := NewSubscription()
	sub.srv = srv.SubscriptionService
	sub.ID = 1

	item := &MonitoredItem{
		ID:  1,
		Sub: sub,
		Req: &ua.MonitoredItemCreateRequest{
			ItemToMonitor:       &ua.ReadValueID{NodeID: nodeID},
			RequestedParameters: &ua.MonitoringParameters{ClientHandle: 10},
		},
	}

	// Insert a nil entry alongside a valid entry.
	srv.MonitoredItemService.Mu.Lock()
	srv.MonitoredItemService.Nodes[nodeID.String()] = []*MonitoredItem{nil, item}
	srv.MonitoredItemService.Mu.Unlock()

	err := srv.EmitEvent(nodeID, &ua.EventFieldList{
		EventFields: []*ua.Variant{ua.MustVariant("event1")},
	})
	require.NoError(t, err)

	select {
	case evt := <-sub.EventNotifyChannel:
		assert.Equal(t, uint32(10), evt.ClientHandle)
	default:
		t.Fatal("expected event even when nil items are present in the list")
	}
}

func TestEventEmitter_NilSubInItem(t *testing.T) {
	srv := newTestServer()
	ns, _ := addTestNamespace(srv)

	nodeID := ua.NewStringNodeID(ns.ID(), "rw_int32")

	// Item with nil Sub — should be skipped without panic.
	item := &MonitoredItem{
		ID:  1,
		Sub: nil,
		Req: &ua.MonitoredItemCreateRequest{
			ItemToMonitor:       &ua.ReadValueID{NodeID: nodeID},
			RequestedParameters: &ua.MonitoringParameters{ClientHandle: 5},
		},
	}

	srv.MonitoredItemService.Mu.Lock()
	srv.MonitoredItemService.Nodes[nodeID.String()] = []*MonitoredItem{item}
	srv.MonitoredItemService.Mu.Unlock()

	err := srv.EmitEvent(nodeID, &ua.EventFieldList{
		EventFields: []*ua.Variant{ua.MustVariant("skip_me")},
	})
	assert.NoError(t, err, "EmitEvent should skip items with nil Sub without error")
}

func TestEventEmitter_MultipleSubscribers(t *testing.T) {
	srv := newTestServer()
	ns, _ := addTestNamespace(srv)

	nodeID := ua.NewStringNodeID(ns.ID(), "rw_int32")

	sub1 := NewSubscription()
	sub1.srv = srv.SubscriptionService
	sub1.ID = 1

	sub2 := NewSubscription()
	sub2.srv = srv.SubscriptionService
	sub2.ID = 2

	item1 := &MonitoredItem{
		ID:  1,
		Sub: sub1,
		Req: &ua.MonitoredItemCreateRequest{
			ItemToMonitor:       &ua.ReadValueID{NodeID: nodeID},
			RequestedParameters: &ua.MonitoringParameters{ClientHandle: 100},
		},
	}
	item2 := &MonitoredItem{
		ID:  2,
		Sub: sub2,
		Req: &ua.MonitoredItemCreateRequest{
			ItemToMonitor:       &ua.ReadValueID{NodeID: nodeID},
			RequestedParameters: &ua.MonitoringParameters{ClientHandle: 200},
		},
	}

	srv.MonitoredItemService.Mu.Lock()
	srv.MonitoredItemService.Nodes[nodeID.String()] = []*MonitoredItem{item1, item2}
	srv.MonitoredItemService.Mu.Unlock()

	err := srv.EmitEvent(nodeID, &ua.EventFieldList{
		EventFields: []*ua.Variant{ua.MustVariant("multi_event")},
	})
	require.NoError(t, err)

	// Both subscribers should receive the event.
	select {
	case evt := <-sub1.EventNotifyChannel:
		assert.Equal(t, uint32(100), evt.ClientHandle)
		require.Len(t, evt.EventFields, 1)
		assert.Equal(t, "multi_event", evt.EventFields[0].Value())
	default:
		t.Fatal("subscriber 1 did not receive event")
	}

	select {
	case evt := <-sub2.EventNotifyChannel:
		assert.Equal(t, uint32(200), evt.ClientHandle)
		require.Len(t, evt.EventFields, 1)
		assert.Equal(t, "multi_event", evt.EventFields[0].Value())
	default:
		t.Fatal("subscriber 2 did not receive event")
	}
}

func TestEventEmitter_FullChannelDropsEvent(t *testing.T) {
	srv := newTestServer()
	ns, _ := addTestNamespace(srv)

	nodeID := ua.NewStringNodeID(ns.ID(), "rw_int32")

	sub := NewSubscription()
	sub.srv = srv.SubscriptionService
	sub.ID = 1

	item := &MonitoredItem{
		ID:  1,
		Sub: sub,
		Req: &ua.MonitoredItemCreateRequest{
			ItemToMonitor:       &ua.ReadValueID{NodeID: nodeID},
			RequestedParameters: &ua.MonitoringParameters{ClientHandle: 77},
		},
	}

	srv.MonitoredItemService.Mu.Lock()
	srv.MonitoredItemService.Nodes[nodeID.String()] = []*MonitoredItem{item}
	srv.MonitoredItemService.Mu.Unlock()

	// Fill the event channel (buffer is 100).
	for i := 0; i < 100; i++ {
		sub.EventNotifyChannel <- &ua.EventFieldList{
			ClientHandle: uint32(i),
			EventFields:  []*ua.Variant{ua.MustVariant(int32(i))},
		}
	}

	// This should not block and should not error — the event is dropped.
	err := srv.EmitEvent(nodeID, &ua.EventFieldList{
		EventFields: []*ua.Variant{ua.MustVariant("dropped")},
	})
	assert.NoError(t, err, "EmitEvent should not error when channel is full")

	// Channel should still contain the original 100 events.
	assert.Equal(t, 100, len(sub.EventNotifyChannel))
}

func TestEventEmitter_MultipleEventFields(t *testing.T) {
	srv := newTestServer()
	ns, _ := addTestNamespace(srv)

	sub := NewSubscription()
	sub.srv = srv.SubscriptionService
	sub.ID = 1

	nodeID := ua.NewStringNodeID(ns.ID(), "rw_int32")
	item := &MonitoredItem{
		ID:  1,
		Sub: sub,
		Req: &ua.MonitoredItemCreateRequest{
			ItemToMonitor:       &ua.ReadValueID{NodeID: nodeID},
			RequestedParameters: &ua.MonitoringParameters{ClientHandle: 33},
		},
	}
	srv.MonitoredItemService.Mu.Lock()
	srv.MonitoredItemService.Nodes[nodeID.String()] = []*MonitoredItem{item}
	srv.MonitoredItemService.Mu.Unlock()

	// Emit event with multiple fields.
	fields := &ua.EventFieldList{
		EventFields: []*ua.Variant{
			ua.MustVariant("EventType"),
			ua.MustVariant(int32(42)),
			ua.MustVariant(float64(3.14)),
		},
	}

	err := srv.EmitEvent(nodeID, fields)
	require.NoError(t, err)

	select {
	case evt := <-sub.EventNotifyChannel:
		assert.Equal(t, uint32(33), evt.ClientHandle)
		require.Len(t, evt.EventFields, 3)
		assert.Equal(t, "EventType", evt.EventFields[0].Value())
		assert.Equal(t, int32(42), evt.EventFields[1].Value())
		assert.Equal(t, float64(3.14), evt.EventFields[2].Value())
	default:
		t.Fatal("expected event with multiple fields")
	}
}
