// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func notif(v int32) *ua.MonitoredItemNotification {
	return &ua.MonitoredItemNotification{
		ClientHandle: 1,
		Value: &ua.DataValue{
			EncodingMask: ua.DataValueValue,
			Value:        ua.MustVariant(v),
		},
	}
}

func valuesOf(q []*ua.MonitoredItemNotification) []int32 {
	out := make([]int32, len(q))
	for i, n := range q {
		out[i] = n.Value.Value.Value().(int32)
	}
	return out
}

func TestMonitoredItemEnqueue_DiscardOldest(t *testing.T) {
	item := &MonitoredItem{queueSize: 3, discardOldest: true}
	for _, v := range []int32{1, 2, 3, 4, 5} {
		item.enqueue(notif(v))
	}
	require.Equal(t, []int32{3, 4, 5}, valuesOf(item.queue))
	require.True(t, item.queue[0].Value.Status.HasOverflow())
}

func TestMonitoredItemEnqueue_KeepOldest(t *testing.T) {
	item := &MonitoredItem{queueSize: 3, discardOldest: false}
	for _, v := range []int32{1, 2, 3, 4, 5} {
		item.enqueue(notif(v))
	}
	require.Equal(t, []int32{1, 2, 5}, valuesOf(item.queue))
	require.True(t, item.queue[2].Value.Status.HasOverflow())
}

func TestMonitoredItemEnqueue_QueueSizeOne(t *testing.T) {
	item := &MonitoredItem{queueSize: 1, discardOldest: true}
	for _, v := range []int32{1, 2, 3, 4, 5} {
		item.enqueue(notif(v))
	}
	require.Equal(t, []int32{5}, valuesOf(item.queue))
	require.False(t, item.queue[0].Value.Status.HasOverflow())
}

func TestReviseQueueSize(t *testing.T) {
	require.Equal(t, uint32(1), reviseQueueSize(0))
	require.Equal(t, uint32(3), reviseQueueSize(3))
	require.Equal(t, uint32(maxMonitoredItemQueueSize), reviseQueueSize(1000))
}

func TestReviseSubscriptionParams(t *testing.T) {
	pi, life, ka := reviseSubscriptionParams(100, 10000, 3000)
	require.Equal(t, 100.0, pi)
	require.Equal(t, uint32(10000), life)
	require.Equal(t, uint32(3000), ka)

	pi, life, ka = reviseSubscriptionParams(1, 10, 10)
	require.Equal(t, minPublishingIntervalMS, pi)
	require.Equal(t, uint32(10), ka)
	require.GreaterOrEqual(t, life, ka*3)

	pi, life, ka = reviseSubscriptionParams(50, 5, 5)
	require.Equal(t, 50.0, pi)
	require.Equal(t, uint32(15), life) // 3 × keepalive
	require.Equal(t, uint32(5), ka)
}

func TestDrainQueuedNotifications_MaxAndMode(t *testing.T) {
	svc := &MonitoredItemService{Subs: map[uint32][]*MonitoredItem{}}
	reporting := &MonitoredItem{
		Mode:      ua.MonitoringModeReporting,
		queueSize: 10,
		queue:     []*ua.MonitoredItemNotification{notif(1), notif(2), notif(3)},
	}
	sampling := &MonitoredItem{
		Mode:      ua.MonitoringModeSampling,
		queueSize: 10,
		queue:     []*ua.MonitoredItemNotification{notif(99)},
	}
	svc.Subs[1] = []*MonitoredItem{reporting, sampling}

	out, more := svc.DrainQueuedNotifications(1, 2)
	require.Equal(t, []int32{1, 2}, valuesOf(out))
	require.True(t, more)
	require.Len(t, reporting.queue, 1)
	require.Len(t, sampling.queue, 1) // Sampling not drained

	out, more = svc.DrainQueuedNotifications(1, 0)
	require.Equal(t, []int32{3}, valuesOf(out))
	require.False(t, more)
	require.True(t, svc.PendingQueuedNotifications(1))
	require.False(t, svc.PendingReportableNotifications(1))
}

// The Sampling-mode items a reporting item triggers are drained with it, in
// the order of their ids, and the limit applies to them too: a linked item
// cut off by it leaves more to report.
func TestDrainQueuedNotifications_TriggeredItems(t *testing.T) {
	sub := &Subscription{ID: 1}
	trigger := &MonitoredItem{ID: 1, Sub: sub, Mode: ua.MonitoringModeReporting, queueSize: 10,
		queue: []*ua.MonitoredItemNotification{notif(1)}, triggers: map[uint32]struct{}{3: {}, 2: {}, 4: {}, 9: {}}}
	linked := &MonitoredItem{ID: 2, Sub: sub, Mode: ua.MonitoringModeSampling, queueSize: 10,
		queue: []*ua.MonitoredItemNotification{notif(20), notif(21)}}
	reporting := &MonitoredItem{ID: 3, Sub: sub, Mode: ua.MonitoringModeReporting, queueSize: 10}
	other := &MonitoredItem{ID: 4, Sub: &Subscription{ID: 2}, Mode: ua.MonitoringModeSampling, queueSize: 10,
		queue: []*ua.MonitoredItemNotification{notif(40)}}
	svc := &MonitoredItemService{
		Subs:  map[uint32][]*MonitoredItem{1: {trigger, linked, reporting}},
		Items: map[uint32]*MonitoredItem{1: trigger, 2: linked, 3: reporting, 4: other},
	}

	out, more := svc.DrainQueuedNotifications(1, 2)
	require.Equal(t, []int32{1, 20}, valuesOf(out))
	require.True(t, more, "the linked item still holds a sample")
	require.Len(t, linked.queue, 1)
	require.Len(t, other.queue, 1, "an item of another subscription is not drained")
}
