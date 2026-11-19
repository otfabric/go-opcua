// SPDX-License-Identifier: MIT

package subscription

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
)

// TestMonitoredItem_Triggering verifies the triggering links of Part 4
// §5.12.1.6: an item in Sampling mode that another item triggers is reported
// when, and only when, its triggering item reports; a Reporting item reports by
// itself; deleting the triggering item or the link ends it.
func TestMonitoredItem_Triggering(t *testing.T) {
	c, f, _ := rawSetup(t)
	sub := newRawSub(t, c, rawSubParams{keepAlive: 1})

	onlyKeepAlives := func(msg string) {
		t.Helper()
		for i := 0; i < 3; i++ {
			p := publish(t, c)
			require.True(t, isKeepAlive(p), "%s: got %v", msg, values(dataOf(t, p)))
		}
	}

	ids := sub.mustCreateItems(ua.TimestampsToReturnNeither,
		itemSpec{node: f.Int32, handle: 1, queue: 5, discard: true},
		itemSpec{node: f.Double, handle: 2, queue: 5, discard: true, modeSet: true, mode: ua.MonitoringModeSampling},
	)
	trig, linked := ids[0], ids[1]
	require.Equal(t, []uint32{1}, handles(sub.nextData()), "the initial value of the Reporting item only")

	res := mustSendRaw[ua.SetTriggeringResponse](t, c, &ua.SetTriggeringRequest{
		SubscriptionID: sub.id, TriggeringItemID: trig, LinksToAdd: []uint32{linked},
	})
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, res.AddResults)

	// The sampled item changes: queued, not reported on its own.
	writeDouble(t, c, f.Double, 1.5)
	writeDouble(t, c, f.Double, 2.5)
	onlyKeepAlives("a triggered item in Sampling mode")

	// The triggering item reports: the triggered item's queue goes with it,
	// its initial value and both changes.
	writeInt32(t, c, f.Int32, 7)
	got := sub.nextData()
	require.Equal(t, []uint32{1, 2, 2, 2}, handles(got))
	v := values(got)
	require.Equal(t, int32(7), v[0])
	require.Equal(t, []any{1.5, 2.5}, v[2:], "the changes after the fixture's initial value")

	// Nothing queued: the next trigger reports itself alone.
	writeInt32(t, c, f.Int32, 8)
	require.Equal(t, []uint32{1}, handles(sub.nextData()))

	// The link removed: the sampled item stays silent when the trigger reports.
	res = mustSendRaw[ua.SetTriggeringResponse](t, c, &ua.SetTriggeringRequest{
		SubscriptionID: sub.id, TriggeringItemID: trig, LinksToRemove: []uint32{linked},
	})
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, res.RemoveResults)
	writeDouble(t, c, f.Double, 3.5)
	writeInt32(t, c, f.Int32, 9)
	require.Equal(t, []uint32{1}, handles(sub.nextData()))

	// Nothing to add or remove, and a trigger of another subscription.
	_, err := sendRaw[ua.SetTriggeringResponse](t, c, &ua.SetTriggeringRequest{SubscriptionID: sub.id, TriggeringItemID: trig})
	require.ErrorIs(t, err, ua.StatusBadNothingToDo)
	_, err = sendRaw[ua.SetTriggeringResponse](t, c, &ua.SetTriggeringRequest{
		SubscriptionID: sub.id + 1000, TriggeringItemID: trig, LinksToAdd: []uint32{linked},
	})
	require.ErrorIs(t, err, ua.StatusBadMonitoredItemIDInvalid)

	// Linked again, then the triggering item deleted: its links go with it.
	mustSendRaw[ua.SetTriggeringResponse](t, c, &ua.SetTriggeringRequest{
		SubscriptionID: sub.id, TriggeringItemID: trig, LinksToAdd: []uint32{linked},
	})
	mustSendRaw[ua.DeleteMonitoredItemsResponse](t, c, &ua.DeleteMonitoredItemsRequest{SubscriptionID: sub.id, MonitoredItemIDs: []uint32{trig}})
	writeDouble(t, c, f.Double, 4.5)
	onlyKeepAlives("a triggered item whose trigger is gone")
}
