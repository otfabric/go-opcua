// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// newItemTestSub registers a subscription owned by a new session.
func newItemTestSub(t *testing.T, srv *Server, subID uint32) (*Subscription, *ua.RequestHeader) {
	t.Helper()
	sess, hdr := activatedSession(t, srv)
	sub := NewSubscription()
	sub.srv = srv.SubscriptionService
	sub.Session = sess
	sub.ID = subID
	sub.RevisedPublishingInterval = 100
	srv.SubscriptionService.Mu.Lock()
	srv.SubscriptionService.Subs[subID] = sub
	srv.SubscriptionService.Mu.Unlock()
	return sub, hdr
}

func createItems(t *testing.T, srv *Server, hdr *ua.RequestHeader, subID uint32, node *ua.NodeID, n int) []ua.StatusCode {
	t.Helper()
	reqs := make([]*ua.MonitoredItemCreateRequest, n)
	for i := range reqs {
		reqs[i] = &ua.MonitoredItemCreateRequest{
			ItemToMonitor:       &ua.ReadValueID{NodeID: node, AttributeID: ua.AttributeIDValue},
			MonitoringMode:      ua.MonitoringModeDisabled,
			RequestedParameters: &ua.MonitoringParameters{ClientHandle: uint32(i), QueueSize: 1},
		}
	}
	resp, err := srv.MonitoredItemService.CreateMonitoredItems(context.Background(), nil, &ua.CreateMonitoredItemsRequest{
		RequestHeader:      hdr,
		SubscriptionID:     subID,
		TimestampsToReturn: ua.TimestampsToReturnBoth,
		ItemsToCreate:      reqs,
	}, 1)
	require.NoError(t, err)
	out := make([]ua.StatusCode, n)
	for i, r := range resp.(*ua.CreateMonitoredItemsResponse).Results {
		out[i] = r.StatusCode
	}
	return out
}

func TestMonitoredItemLimits(t *testing.T) {
	node := ua.NewNumericNodeID(0, id.ServerServerStatusCurrentTime)

	t.Run("per subscription", func(t *testing.T) {
		srv := newTestServer()
		srv.cfg.maxMonitoredItemsPerSubscription = 3
		_, hdr := newItemTestSub(t, srv, 1)
		st := createItems(t, srv, hdr, 1, node, 4)
		require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusOK, ua.StatusOK, ua.StatusBadTooManyMonitoredItems}, st)
		st = createItems(t, srv, hdr, 1, node, 1)
		require.Equal(t, []ua.StatusCode{ua.StatusBadTooManyMonitoredItems}, st)
	})

	t.Run("per session", func(t *testing.T) {
		srv := newTestServer()
		srv.cfg.maxMonitoredItemsPerSession = 3
		sub1, hdr := newItemTestSub(t, srv, 1)
		sub2 := NewSubscription()
		sub2.srv = srv.SubscriptionService
		sub2.Session = sub1.Session
		sub2.ID = 2
		srv.SubscriptionService.Subs[2] = sub2
		require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusOK}, createItems(t, srv, hdr, 1, node, 2))
		require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusBadTooManyMonitoredItems}, createItems(t, srv, hdr, 2, node, 2))
		// Another session is not affected.
		_, hdr3 := newItemTestSub(t, srv, 3)
		require.Equal(t, []ua.StatusCode{ua.StatusOK}, createItems(t, srv, hdr3, 3, node, 1))
	})

	t.Run("server", func(t *testing.T) {
		srv := newTestServer()
		srv.cfg.maxMonitoredItems = 2
		_, hdr1 := newItemTestSub(t, srv, 1)
		_, hdr2 := newItemTestSub(t, srv, 2)
		require.Equal(t, []ua.StatusCode{ua.StatusOK}, createItems(t, srv, hdr1, 1, node, 1))
		require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusBadTooManyMonitoredItems}, createItems(t, srv, hdr2, 2, node, 2))
	})

	t.Run("advertised", func(t *testing.T) {
		srv, err := New(WithMaxMonitoredItems(7), WithMaxMonitoredItemsPerSubscription(5),
			WithMaxMonitoredItemsPerSession(6))
		require.NoError(t, err)
		val := func(n uint32) uint32 {
			return srv.Node(ua.NewNumericNodeID(0, n)).Value().Value.Value().(uint32)
		}
		require.Equal(t, uint32(7), val(id.ServerServerCapabilitiesMaxMonitoredItems))
		require.Equal(t, uint32(5), val(id.ServerServerCapabilitiesMaxMonitoredItemsPerSubscription))
		require.Equal(t, 6, srv.cfg.monitoredItemsPerSessionLimit())
	})
}

func TestDeleteManyMonitoredItemsKeepsIndexes(t *testing.T) {
	srv := newTestServer()
	srv.cfg.maxMonitoredItemsPerSubscription = 100_000
	node := ua.NewNumericNodeID(0, id.ServerServerStatusCurrentTime)
	_, hdr := newItemTestSub(t, srv, 1)
	_, hdr2 := newItemTestSub(t, srv, 2)
	const n = 5000
	for i := 0; i < n/32; i++ {
		createItems(t, srv, hdr, 1, node, 32)
	}
	createItems(t, srv, hdr2, 2, node, 3)
	mis := srv.MonitoredItemService
	require.Len(t, mis.Nodes[node.String()], n/32*32+3)

	// Delete a few items of subscription 1 by id: order is kept.
	ids := []uint32{mis.Subs[1][0].ID, mis.Subs[1][5].ID}
	keep := mis.Subs[1][1].ID
	resp, err := mis.DeleteMonitoredItems(context.Background(), nil, &ua.DeleteMonitoredItemsRequest{
		RequestHeader: hdr, SubscriptionID: 1, MonitoredItemIDs: ids}, 1)
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusOK}, resp.(*ua.DeleteMonitoredItemsResponse).Results)
	require.Equal(t, keep, mis.Subs[1][0].ID)

	start := time.Now()
	mis.DeleteSub(1)
	t.Logf("deleted %d items in %v", n, time.Since(start))
	require.NotContains(t, mis.Subs, uint32(1))
	require.Len(t, mis.Nodes[node.String()], 3)
	require.Len(t, mis.Items, 3)
	for _, it := range mis.Nodes[node.String()] {
		require.Equal(t, uint32(2), it.Sub.ID)
	}
	mis.DeleteSub(2)
	require.Empty(t, mis.Nodes)
	require.Empty(t, mis.Items)
}

func TestEventItemUnregisteredOnDelete(t *testing.T) {
	srv := newTestServer()
	_, hdr := newItemTestSub(t, srv, 1)
	resp, err := srv.MonitoredItemService.CreateMonitoredItems(context.Background(), nil, &ua.CreateMonitoredItemsRequest{
		RequestHeader: hdr, SubscriptionID: 1, TimestampsToReturn: ua.TimestampsToReturnBoth,
		ItemsToCreate: []*ua.MonitoredItemCreateRequest{eventItemRequest(0, true)},
	}, 1)
	require.NoError(t, err)
	r := resp.(*ua.CreateMonitoredItemsResponse).Results[0]
	require.Equal(t, ua.StatusOK, r.StatusCode)
	require.Equal(t, defaultEventQueueSize, r.RevisedQueueSize)
	require.NotNil(t, srv.eventItems.get(r.MonitoredItemID))
	srv.MonitoredItemService.DeleteSub(1)
	require.Nil(t, srv.eventItems.get(r.MonitoredItemID))
}

func eventItemRequest(queueSize uint32, discardOldest bool) *ua.MonitoredItemCreateRequest {
	return &ua.MonitoredItemCreateRequest{
		ItemToMonitor:  &ua.ReadValueID{NodeID: ua.NewNumericNodeID(0, id.Server), AttributeID: ua.AttributeIDEventNotifier},
		MonitoringMode: ua.MonitoringModeReporting,
		RequestedParameters: &ua.MonitoringParameters{
			ClientHandle:  42,
			QueueSize:     queueSize,
			DiscardOldest: discardOldest,
			Filter: ua.NewExtensionObject(&ua.EventFilter{SelectClauses: []*ua.SimpleAttributeOperand{
				{TypeDefinitionID: ua.NewNumericNodeID(0, id.BaseEventType), BrowsePath: []*ua.QualifiedName{{Name: "EventType"}}, AttributeID: ua.AttributeIDValue},
				{TypeDefinitionID: ua.NewNumericNodeID(0, id.BaseEventType), BrowsePath: []*ua.QualifiedName{{Name: "Message"}}, AttributeID: ua.AttributeIDValue},
			}}),
		},
	}
}

// newEventItem creates an event item on the Server object for sub.
func newEventItem(t *testing.T, srv *Server, hdr *ua.RequestHeader, subID, queueSize uint32, discardOldest bool) *MonitoredItem {
	t.Helper()
	resp, err := srv.MonitoredItemService.CreateMonitoredItems(context.Background(), nil, &ua.CreateMonitoredItemsRequest{
		RequestHeader: hdr, SubscriptionID: subID, TimestampsToReturn: ua.TimestampsToReturnBoth,
		ItemsToCreate: []*ua.MonitoredItemCreateRequest{eventItemRequest(queueSize, discardOldest)},
	}, 1)
	require.NoError(t, err)
	r := resp.(*ua.CreateMonitoredItemsResponse).Results[0]
	require.Equal(t, ua.StatusOK, r.StatusCode)
	require.Equal(t, queueSize, r.RevisedQueueSize)
	return srv.MonitoredItemService.Items[r.MonitoredItemID]
}

func emitN(srv *Server, n int, from int) {
	for i := 0; i < n; i++ {
		srv.emitEvent(ua.NewNumericNodeID(0, id.Server), &BaseEvent{
			EventID:   []byte{byte(from + i)},
			EventType: ua.NewNumericNodeID(0, id.BaseEventType),
			Message:   ua.NewLocalizedText(string(rune('a' + from + i))),
		}, false)
	}
}

func eventType(ef *ua.EventFieldList) uint32 {
	return ef.EventFields[0].Value().(*ua.NodeID).IntID()
}

func eventMsg(ef *ua.EventFieldList) string {
	return ef.EventFields[1].Value().(*ua.LocalizedText).Text
}

// nextQueuedEvent takes the oldest queued event of sub.
func nextQueuedEvent(sub *Subscription) (*ua.EventFieldList, bool) {
	evs, _ := sub.takeEvents(1, false)
	if len(evs) == 0 {
		return nil, false
	}
	return evs[0], true
}

func TestEventQueueBoundedDiscardOldest(t *testing.T) {
	srv := newTestServer()
	sub, hdr := newItemTestSub(t, srv, 1)
	item := newEventItem(t, srv, hdr, 1, 3, true)

	emitN(srv, 10, 0)
	sub.evMu.Lock()
	require.Len(t, item.events, 4, "QueueSize events and one overflow event")
	sub.evMu.Unlock()

	evs, more := sub.takeEvents(0, true)
	require.False(t, more)
	require.Len(t, evs, 4)
	require.Equal(t, uint32(id.EventQueueOverflowEventType), eventType(evs[0]))
	require.Equal(t, uint32(42), evs[0].ClientHandle)
	require.Equal(t, []string{"h", "i", "j"}, []string{eventMsg(evs[1]), eventMsg(evs[2]), eventMsg(evs[3])})
	require.False(t, sub.pendingEvents())
}

func TestEventQueueBoundedKeepOldest(t *testing.T) {
	srv := newTestServer()
	sub, hdr := newItemTestSub(t, srv, 1)
	newEventItem(t, srv, hdr, 1, 2, false)

	emitN(srv, 5, 0)
	evs, _ := sub.takeEvents(0, true)
	require.Len(t, evs, 3)
	require.Equal(t, []string{"a", "b"}, []string{eventMsg(evs[0]), eventMsg(evs[1])})
	require.Equal(t, uint32(id.EventQueueOverflowEventType), eventType(evs[2]))
}

func TestEventQueueTakeHonoursLimitAndOrder(t *testing.T) {
	srv := newTestServer()
	sub, hdr := newItemTestSub(t, srv, 1)
	newEventItem(t, srv, hdr, 1, 100, true)
	newEventItem(t, srv, hdr, 1, 100, true)
	sub.EventNotifyChannel <- &ua.EventFieldList{ClientHandle: 9}
	sub.drainEvents()
	emitN(srv, 3, 0)

	evs, more := sub.takeEvents(4, false)
	require.True(t, more)
	require.Len(t, evs, 4)
	require.Equal(t, uint32(9), evs[0].ClientHandle, "events keep the order they were queued in")
	require.Equal(t, "a", eventMsg(evs[1]))
	require.Equal(t, "a", eventMsg(evs[2]))
	require.Equal(t, "b", eventMsg(evs[3]))
	require.True(t, sub.pendingEvents())
	evs, more = sub.takeEvents(10, false)
	require.False(t, more)
	require.Len(t, evs, 3)

	// Shrinking the queue keeps the newest events.
	item := srv.MonitoredItemService.Subs[1][0]
	emitN(srv, 5, 0)
	item.setEventQueue(2, true)
	sub.evMu.Lock()
	require.Len(t, item.events, 2)
	sub.evMu.Unlock()
}

func TestConditionRefreshEventsExceedQueueSize(t *testing.T) {
	srv := newTestServer()
	sub, hdr := newItemTestSub(t, srv, 1)
	item := newEventItem(t, srv, hdr, 1, 2, true)
	for i := 0; i < 5; i++ {
		srv.deliverToItem(item, &BaseEvent{EventType: ua.NewNumericNodeID(0, id.BaseEventType), Message: ua.NewLocalizedText(string(rune('a' + i)))}, true, true)
	}
	evs, _ := sub.takeEvents(0, true)
	require.Len(t, evs, 5, "the events of a ConditionRefresh are all kept")
	require.Equal(t, "a", eventMsg(evs[0]))
}
