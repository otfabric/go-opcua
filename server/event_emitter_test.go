package server

import (
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEventEmitter_EmitEvent(t *testing.T) {
	srv := newTestServer()
	ns, _ := addTestNamespace(srv)

	// Create subscription and monitored item manually.
	sub := NewSubscription()
	sub.srv = srv.SubscriptionService
	sub.ID = 1

	nodeID := ua.NewStringNodeID(ns.ID(), "rw_int32")
	item := &MonitoredItem{
		ID:  1,
		Sub: sub,
		Req: &ua.MonitoredItemCreateRequest{
			ItemToMonitor: &ua.ReadValueID{
				NodeID: nodeID,
			},
			RequestedParameters: &ua.MonitoringParameters{
				ClientHandle: 42,
			},
		},
	}
	srv.MonitoredItemService.Mu.Lock()
	srv.MonitoredItemService.Items[item.ID] = item
	srv.MonitoredItemService.Nodes[nodeID.String()] = []*MonitoredItem{item}
	srv.MonitoredItemService.Mu.Unlock()

	fields := &ua.EventFieldList{
		ClientHandle: 0,
		EventFields:  []*ua.Variant{ua.MustVariant("test_event")},
	}

	err := srv.EmitEvent(nodeID, fields)
	require.NoError(t, err)

	// Read the event from the subscription's event channel.
	select {
	case evt := <-sub.EventNotifyChannel:
		assert.Equal(t, uint32(42), evt.ClientHandle)
		require.Len(t, evt.EventFields, 1)
		assert.Equal(t, "test_event", evt.EventFields[0].Value())
	default:
		t.Fatal("expected event notification on EventNotifyChannel")
	}
}

func TestEventEmitter_NoMonitoredItems(t *testing.T) {
	srv := newTestServer()
	ns, _ := addTestNamespace(srv)

	nodeID := ua.NewStringNodeID(ns.ID(), "rw_int32")
	// No monitored items set up - should not error.
	err := srv.EmitEvent(nodeID, &ua.EventFieldList{EventFields: []*ua.Variant{ua.MustVariant(int32(1))}})
	assert.NoError(t, err)
}
