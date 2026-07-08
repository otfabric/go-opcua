// SPDX-License-Identifier: MIT

package server

import (
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestChangeNotification_SingleItem verifies that writing a value triggers
// a data change notification on the subscription's notify channel.
func TestChangeNotification_SingleItem(t *testing.T) {
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
			ItemToMonitor: &ua.ReadValueID{
				NodeID:      nodeID,
				AttributeID: ua.AttributeIDValue,
			},
			RequestedParameters: &ua.MonitoringParameters{ClientHandle: 1},
		},
	}

	srv.MonitoredItemService.Mu.Lock()
	srv.MonitoredItemService.Items[item.ID] = item
	srv.MonitoredItemService.Nodes[nodeID.String()] = []*MonitoredItem{item}
	srv.MonitoredItemService.Mu.Unlock()

	srv.MonitoredItemService.ChangeNotification(nodeID)

	select {
	case notif := <-sub.NotifyChannel:
		assert.Equal(t, uint32(1), notif.ClientHandle)
		require.NotNil(t, notif.Value)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for change notification")
	}
}

// TestChangeNotification_UnmonitoredNode verifies that ChangeNotification
// is a no-op for nodes with no monitored items.
func TestChangeNotification_UnmonitoredNode(t *testing.T) {
	srv := newTestServer()
	ns, _ := addTestNamespace(srv)

	nodeID := ua.NewStringNodeID(ns.ID(), "rw_int32")

	// No monitored items — should not panic or block.
	srv.MonitoredItemService.ChangeNotification(nodeID)
}

// TestChangeNotification_MultipleItems verifies notifications fan out
// to multiple monitored items on the same node.
func TestChangeNotification_MultipleItems(t *testing.T) {
	srv := newTestServer()
	ns, _ := addTestNamespace(srv)

	sub1 := NewSubscription()
	sub1.srv = srv.SubscriptionService
	sub1.ID = 1

	sub2 := NewSubscription()
	sub2.srv = srv.SubscriptionService
	sub2.ID = 2

	nodeID := ua.NewStringNodeID(ns.ID(), "rw_int32")
	item1 := &MonitoredItem{
		ID:  1,
		Sub: sub1,
		Req: &ua.MonitoredItemCreateRequest{
			ItemToMonitor: &ua.ReadValueID{
				NodeID:      nodeID,
				AttributeID: ua.AttributeIDValue,
			},
			RequestedParameters: &ua.MonitoringParameters{ClientHandle: 10},
		},
	}
	item2 := &MonitoredItem{
		ID:  2,
		Sub: sub2,
		Req: &ua.MonitoredItemCreateRequest{
			ItemToMonitor: &ua.ReadValueID{
				NodeID:      nodeID,
				AttributeID: ua.AttributeIDValue,
			},
			RequestedParameters: &ua.MonitoringParameters{ClientHandle: 20},
		},
	}

	srv.MonitoredItemService.Mu.Lock()
	srv.MonitoredItemService.Items[item1.ID] = item1
	srv.MonitoredItemService.Items[item2.ID] = item2
	srv.MonitoredItemService.Nodes[nodeID.String()] = []*MonitoredItem{item1, item2}
	srv.MonitoredItemService.Mu.Unlock()

	srv.MonitoredItemService.ChangeNotification(nodeID)

	select {
	case notif := <-sub1.NotifyChannel:
		assert.Equal(t, uint32(10), notif.ClientHandle)
	case <-time.After(time.Second):
		t.Fatal("sub1 did not receive notification")
	}

	select {
	case notif := <-sub2.NotifyChannel:
		assert.Equal(t, uint32(20), notif.ClientHandle)
	case <-time.After(time.Second):
		t.Fatal("sub2 did not receive notification")
	}
}

// TestChangeNotification_HighThroughput sends many rapid change notifications
// and verifies that all are received correctly.
func TestChangeNotification_HighThroughput(t *testing.T) {
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
			ItemToMonitor: &ua.ReadValueID{
				NodeID:      nodeID,
				AttributeID: ua.AttributeIDValue,
			},
			RequestedParameters: &ua.MonitoringParameters{ClientHandle: 7},
		},
	}

	srv.MonitoredItemService.Mu.Lock()
	srv.MonitoredItemService.Items[item.ID] = item
	srv.MonitoredItemService.Nodes[nodeID.String()] = []*MonitoredItem{item}
	srv.MonitoredItemService.Mu.Unlock()

	const count = 50

	// Drain notifications in a goroutine.
	received := make(chan *ua.MonitoredItemNotification, count)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < count; i++ {
			select {
			case n := <-sub.NotifyChannel:
				received <- n
			case <-time.After(5 * time.Second):
				return
			}
		}
	}()

	// Send notifications rapidly.
	for i := 0; i < count; i++ {
		srv.MonitoredItemService.ChangeNotification(nodeID)
	}

	wg.Wait()
	close(received)

	got := 0
	for range received {
		got++
	}
	assert.Equal(t, count, got, "should receive all %d notifications", count)
}

// TestSubscription_RetransmissionQueueOverflow verifies that the retransmission
// queue handles rapid sequence number overflow correctly.
func TestSubscription_RetransmissionQueueOverflow(t *testing.T) {
	sub := NewSubscription()

	// Store messages beyond the limit.
	for i := uint32(1); i <= uint32(maxRetransmissionQueueSize*3); i++ {
		sub.storeSentMessage(&ua.NotificationMessage{SequenceNumber: i})
	}

	// Only the most recent maxRetransmissionQueueSize should remain.
	nums := sub.availableSequenceNumbers()
	assert.Len(t, nums, maxRetransmissionQueueSize)

	// The oldest should have been evicted.
	for i := uint32(1); i <= uint32(maxRetransmissionQueueSize*2); i++ {
		assert.Nil(t, sub.getSentMessage(i), "message %d should have been evicted", i)
	}

	// The newest should still be available.
	newest := uint32(maxRetransmissionQueueSize * 3)
	assert.NotNil(t, sub.getSentMessage(newest))
}

// TestSubscription_ModifyChannel verifies that the modify channel
// accepts a ModifySubscriptionRequest.
func TestSubscription_ModifyChannel(t *testing.T) {
	sub := NewSubscription()

	req := &ua.ModifySubscriptionRequest{
		RequestedPublishingInterval: 500,
		RequestedLifetimeCount:      20,
		RequestedMaxKeepAliveCount:  5,
	}

	// Should not block (buffer is 2).
	sub.ModifyChannel <- req

	select {
	case got := <-sub.ModifyChannel:
		assert.Equal(t, float64(500), got.RequestedPublishingInterval)
		assert.Equal(t, uint32(20), got.RequestedLifetimeCount)
		assert.Equal(t, uint32(5), got.RequestedMaxKeepAliveCount)
	default:
		t.Fatal("modify channel should contain the request")
	}
}

// TestSubscription_Update verifies the Update method applies the request parameters.
func TestSubscription_Update(t *testing.T) {
	sub := NewSubscription()
	sub.RevisedPublishingInterval = 100
	sub.RevisedLifetimeCount = 10
	sub.RevisedMaxKeepAliveCount = 3

	sub.Update(&ua.ModifySubscriptionRequest{
		RequestedPublishingInterval: 500,
		RequestedLifetimeCount:      50,
		RequestedMaxKeepAliveCount:  10,
	})

	assert.Equal(t, float64(500), sub.RevisedPublishingInterval)
	assert.Equal(t, uint32(50), sub.RevisedLifetimeCount)
	assert.Equal(t, uint32(10), sub.RevisedMaxKeepAliveCount)
}

// TestMonitoredItemService_NextID verifies that NextID generates
// unique monotonically increasing IDs.
func TestMonitoredItemService_NextID(t *testing.T) {
	srv := newTestServer()
	svc := srv.MonitoredItemService

	ids := make(map[uint32]bool)
	for i := 0; i < 100; i++ {
		id := svc.NextID()
		assert.False(t, ids[id], "duplicate ID generated: %d", id)
		ids[id] = true
	}
}

// TestMonitoredItemService_DeleteSub removes all items for a subscription.
func TestMonitoredItemService_DeleteSub(t *testing.T) {
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
			ItemToMonitor: &ua.ReadValueID{
				NodeID:      nodeID,
				AttributeID: ua.AttributeIDValue,
			},
			RequestedParameters: &ua.MonitoringParameters{ClientHandle: 1},
		},
	}

	srv.MonitoredItemService.Mu.Lock()
	srv.MonitoredItemService.Items[item.ID] = item
	srv.MonitoredItemService.Nodes[nodeID.String()] = []*MonitoredItem{item}
	srv.MonitoredItemService.Subs[sub.ID] = []*MonitoredItem{item}
	srv.MonitoredItemService.Mu.Unlock()

	srv.MonitoredItemService.DeleteSub(sub.ID)

	srv.MonitoredItemService.Mu.Lock()
	_, exists := srv.MonitoredItemService.Items[item.ID]
	srv.MonitoredItemService.Mu.Unlock()

	assert.False(t, exists, "item should be deleted after DeleteSub")
}
