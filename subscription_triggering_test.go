// SPDX-License-Identifier: MIT

package opcua

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// TestRememberTriggering follows the results of SetTriggering responses:
// removals first, then additions (Part 4 §5.13.5.2), only for items the
// subscription has, and links of deleted items go with them (§5.13.6.1).
func TestRememberTriggering(t *testing.T) {
	t.Parallel()
	sub, _ := newNotifyTestSub(1)
	for _, id := range []uint32{1, 2, 3, 4} {
		sub.items[id] = &monitoredItem{serverID: id + 10}
	}
	ok, bad := ua.StatusOK, ua.StatusBadMonitoredItemIDInvalid
	links := func(trigger uint32) []uint32 {
		sub.itemsMu.Lock()
		defer sub.itemsMu.Unlock()
		var out []uint32
		for id := range sub.triggers[trigger] {
			out = append(out, id)
		}
		return out
	}

	// An unknown triggering item records nothing.
	sub.rememberTriggering(99, []uint32{2}, nil, &ua.SetTriggeringResponse{AddResults: []ua.StatusCode{ok}})
	require.Empty(t, sub.triggers)

	// Refused links, unknown items and missing results are not recorded.
	sub.rememberTriggering(1, []uint32{2, 3, 98, 4}, nil, &ua.SetTriggeringResponse{AddResults: []ua.StatusCode{ok, bad, ok}})
	require.Equal(t, []uint32{2}, links(1))

	// Removals are processed before additions; a removal the server reports
	// as a link that does not exist is forgotten too, one with no result
	// is kept.
	sub.rememberTriggering(1, []uint32{3}, []uint32{2, 3}, &ua.SetTriggeringResponse{
		AddResults: []ua.StatusCode{ok}, RemoveResults: []ua.StatusCode{ok, bad},
	})
	require.Equal(t, []uint32{3}, links(1))
	sub.rememberTriggering(1, nil, []uint32{3}, &ua.SetTriggeringResponse{})
	require.Equal(t, []uint32{3}, links(1))

	// The last link removed drops the triggering item.
	sub.rememberTriggering(1, nil, []uint32{3}, &ua.SetTriggeringResponse{RemoveResults: []ua.StatusCode{ok}})
	require.NotContains(t, sub.triggers, uint32(1))
}

// TestRestoreTriggering_SendFails: a SetTriggering request that cannot be
// sent is reported, and the links stay recorded for the next recreation.
// Triggering items and items to report the subscription no longer has are
// skipped.
func TestRestoreTriggering_SendFails(t *testing.T) {
	t.Parallel()
	c := newNotifyTestClient(t) // not connected: every request fails
	sub, _ := newNotifyTestSub(1)
	sub.c = c
	sub.items[1] = &monitoredItem{serverID: 11}
	sub.items[2] = &monitoredItem{serverID: 12}
	sub.items[5] = &monitoredItem{serverID: 15}
	sub.triggers = map[uint32]map[uint32]struct{}{
		1: {2: {}, 3: {}},
		4: {2: {}}, // gone triggering item
		5: {6: {}}, // only gone items to report
	}
	err := sub.restoreTriggering(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "triggering item 1")
	require.NotContains(t, err.Error(), "triggering item 4")
	require.NotContains(t, err.Error(), "triggering item 5")
	require.Len(t, sub.triggers, 3, "the links are kept")

	sub.triggers = nil
	require.NoError(t, sub.restoreTriggering(context.Background()))
}

// TestRecreatedEvent: a recreation that did not restore every triggering
// link is a partial recovery and says which links are missing.
func TestRecreatedEvent(t *testing.T) {
	t.Parallel()
	ev := recreatedEvent(3, "recreated", nil)
	require.Equal(t, SubscriptionRecoveryEvent{SubscriptionID: 3, Outcome: SubscriptionRecoveryRecreated, Detail: "recreated"}, ev)

	ev = recreatedEvent(3, "recreated", ua.StatusBadMonitoredItemIDInvalid)
	require.Equal(t, SubscriptionRecoveryPartial, ev.Outcome)
	require.Contains(t, ev.Detail, "recreated; triggering links not restored: ")
	require.Contains(t, ev.Detail, ua.StatusBadMonitoredItemIDInvalid.Error())
}

// TestSetPublishingMode_NotConnected: a request that fails changes nothing
// the recreation would use.
func TestSetPublishingMode_NotConnected(t *testing.T) {
	t.Parallel()
	c := newNotifyTestClient(t)
	sub, _ := newNotifyTestSub(1)
	sub.c = c
	_, err := sub.SetPublishingMode(context.Background(), false)
	require.Error(t, err)
	_, err = c.SetPublishingMode(context.Background(), false, 1)
	require.Error(t, err)
	require.False(t, sub.publishingDisabled)

	_, err = sub.SetTriggering(context.Background(), 1, []uint32{2}, nil)
	require.Error(t, err)
	require.Empty(t, sub.triggers)
}
