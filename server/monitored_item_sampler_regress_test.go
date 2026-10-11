// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// Regression tests for defects found by the chaos suite in chaos/datachange.

// TestSampler_LateTimerDoesNotSampleTwice covers the race between a change
// and the sampler timer at the end of a sampling interval. The timer callback
// runs on its own goroutine, so a change can be handled after the interval
// ended but before the callback got the lock. That change is sampled right
// away - and used to leave the postponed sample pending with a due time in
// the past, so that the next change, although inside the new interval, was
// sampled as soon as the callback ran: two samples within one interval.
func TestSampler_LateTimerDoesNotSampleTwice(t *testing.T) {
	f := newSamplerFixture(t)
	node := f.node("rw_int32")
	item := f.add(1, node, func(mi *MonitoredItem) { mi.samplingInterval = time.Hour })

	f.set(node, int32(1))
	f.set(node, int32(2)) // postponed
	require.Equal(t, []any{int32(1)}, f.queued(item))

	// The interval ends; the timer has fired but its callback is still
	// waiting for the lock.
	f.svc.Mu.Lock()
	require.Len(t, f.svc.due, 1)
	item.lastSampled = time.Now().Add(-2 * time.Hour)
	item.sampleDue = time.Now().Add(-time.Millisecond)
	f.svc.Mu.Unlock()

	// A change gets in first and is sampled: it is the sample that was
	// postponed.
	f.set(node, int32(3))
	require.Equal(t, []any{int32(1), int32(3)}, f.queued(item))
	f.svc.Mu.Lock()
	require.Empty(t, f.svc.due, "the postponed sample was taken")
	require.True(t, item.sampleDue.IsZero())
	require.True(t, f.svc.samplerAt.IsZero(), "nothing is due, so no timer is armed")
	f.svc.Mu.Unlock()

	// The next change is inside the new interval and has to wait for its end.
	f.set(node, int32(4))
	f.svc.Mu.Lock()
	require.Equal(t, item.lastSampled.Add(time.Hour), item.sampleDue)
	f.svc.Mu.Unlock()

	// The late callback must not take it.
	f.svc.runSampler()
	require.Equal(t, []any{int32(1), int32(3)}, f.queued(item), "at most one sample per sampling interval")
	f.svc.Mu.Lock()
	require.Len(t, f.svc.due, 1)
	f.svc.Mu.Unlock()
}

// TestSampler_TimerStopsWithLastPostponedSample verifies that the sampler
// timer does not outlive the postponed samples it was armed for: it used to
// stay armed (for up to the sampling interval, which can be an hour) after
// the item was deleted or disabled, and so also after the server was closed.
func TestSampler_TimerStopsWithLastPostponedSample(t *testing.T) {
	armed := func(f *samplerFixture) (timer bool, due int) {
		f.svc.Mu.Lock()
		defer f.svc.Mu.Unlock()
		return !f.svc.samplerAt.IsZero(), len(f.svc.due)
	}
	postpone := func(f *samplerFixture, ids ...uint32) []*MonitoredItem {
		node := f.node("rw_int32")
		items := make([]*MonitoredItem, len(ids))
		for i, id := range ids {
			items[i] = f.add(id, node, func(mi *MonitoredItem) { mi.samplingInterval = time.Hour })
		}
		f.set(node, int32(1))
		f.set(node, int32(2))
		timer, due := armed(f)
		require.True(t, timer)
		require.Equal(t, len(ids), due)
		return items
	}
	requireIdle := func(f *samplerFixture) {
		t.Helper()
		timer, due := armed(f)
		require.False(t, timer, "sampler timer still armed")
		require.Zero(t, due)
		f.svc.Mu.Lock()
		defer f.svc.Mu.Unlock()
		require.False(t, f.svc.sampler.Stop(), "the timer itself must have been stopped")
	}

	t.Run("delete", func(t *testing.T) {
		f := newSamplerFixture(t)
		items := postpone(f, 1, 2)
		f.svc.DeleteMonitoredItem(items[0].ID)
		timer, due := armed(f)
		require.True(t, timer, "the other item is still due")
		require.Equal(t, 1, due)
		f.svc.DeleteMonitoredItem(items[1].ID)
		requireIdle(f)
	})

	t.Run("delete subscription", func(t *testing.T) {
		f := newSamplerFixture(t)
		postpone(f, 1, 2)
		f.svc.DeleteSub(f.sub.ID)
		requireIdle(f)
	})

	t.Run("disable", func(t *testing.T) {
		mis, _, hdr, itemID := setupMonitoredItemTest(t)
		mis.Mu.Lock()
		item := mis.Items[itemID]
		item.samplingInterval = time.Hour
		mis.deferSample(item, time.Now().Add(time.Hour))
		require.False(t, mis.samplerAt.IsZero())
		mis.Mu.Unlock()

		_, err := mis.SetMonitoringMode(context.Background(), nil, &ua.SetMonitoringModeRequest{
			RequestHeader: hdr, MonitoringMode: ua.MonitoringModeDisabled, MonitoredItemIDs: []uint32{itemID},
		}, 1)
		require.NoError(t, err)
		mis.Mu.Lock()
		defer mis.Mu.Unlock()
		require.True(t, mis.samplerAt.IsZero(), "sampler timer still armed for a disabled item")
		require.Empty(t, mis.due)
		require.True(t, item.sampleDue.IsZero())
		require.False(t, mis.sampler.Stop())
	})
}

// TestDeleteMonitoredItems_IsSynchronous verifies that an item is gone when
// DeleteMonitoredItems answers. The delete used to run in a goroutine after
// the response, so that a second delete of the same id (or a modify) could
// still succeed and the item could still be sampled.
func TestDeleteMonitoredItems_IsSynchronous(t *testing.T) {
	mis, _, hdr, itemID := setupMonitoredItemTest(t)
	// Index the hand-made item by node, as CreateMonitoredItems does.
	mis.Mu.Lock()
	item := mis.Items[itemID]
	node := item.Req.ItemToMonitor.NodeID.String()
	mis.Nodes[node] = append(mis.Nodes[node], item)
	mis.Mu.Unlock()
	del := func() ua.StatusCode {
		resp, err := mis.DeleteMonitoredItems(context.Background(), nil, &ua.DeleteMonitoredItemsRequest{
			RequestHeader: hdr, MonitoredItemIDs: []uint32{itemID},
		}, 1)
		require.NoError(t, err)
		return resp.(*ua.DeleteMonitoredItemsResponse).Results[0]
	}
	require.Equal(t, ua.StatusOK, del())
	mis.Mu.Lock()
	_, exists := mis.Items[itemID]
	mis.Mu.Unlock()
	require.False(t, exists, "item still registered after DeleteMonitoredItems returned")
	require.Equal(t, ua.StatusBadMonitoredItemIDInvalid, del())
}
