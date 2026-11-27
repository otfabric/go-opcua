// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"maps"
	"slices"
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// TestSetTriggering_RemoveBeforeAdd: "The list of linksToRemove is
// processed before the linksToAdd" (Part 4 §5.13.5.2, Table 72), and each
// list of results has the size and order of its own list in the request.
//
// Regression: the additions were processed first, so a link named in both
// lists was gone afterwards.
func TestSetTriggering_RemoveBeforeAdd(t *testing.T) {
	ok, bad := ua.StatusOK, ua.StatusBadMonitoredItemIDInvalid
	for _, c := range []struct {
		name                 string
		initial, remove, add []uint32
		removeRes, addRes    []ua.StatusCode
		final                []uint32
	}{
		{"remove and add the same link", []uint32{42}, []uint32{42}, []uint32{42}, []ua.StatusCode{ok}, []ua.StatusCode{ok}, []uint32{42}},
		{"remove a missing link and add it", nil, []uint32{42}, []uint32{42}, []ua.StatusCode{bad}, []ua.StatusCode{ok}, []uint32{42}},
		{"replace a link", []uint32{42}, []uint32{42}, []uint32{43}, []ua.StatusCode{ok}, []ua.StatusCode{ok}, []uint32{43}},
		{"replace one of two links", []uint32{42, 43}, []uint32{42}, []uint32{44}, []ua.StatusCode{ok}, []ua.StatusCode{ok}, []uint32{43, 44}},
		{"add only", []uint32{42}, nil, []uint32{43}, []ua.StatusCode{}, []ua.StatusCode{ok}, []uint32{42, 43}},
		{"remove only", []uint32{42}, []uint32{42}, nil, []ua.StatusCode{ok}, []ua.StatusCode{}, nil},
		{"results in request order", []uint32{43}, []uint32{99, 43, 42}, []uint32{44, 99, 42}, []ua.StatusCode{bad, ok, bad}, []ua.StatusCode{ok, bad, ok}, []uint32{42, 44}},
	} {
		t.Run(c.name, func(t *testing.T) {
			svc, sub, hdr, itemID := setupMonitoredItemTest(t)
			svc.Mu.Lock()
			for _, id := range []uint32{42, 43, 44} {
				require.NotEqual(t, itemID, id)
				svc.Items[id] = &MonitoredItem{ID: id, Sub: sub, Mode: ua.MonitoringModeSampling}
			}
			trigger := svc.Items[itemID]
			trigger.triggers = nil
			for _, id := range c.initial {
				if trigger.triggers == nil {
					trigger.triggers = map[uint32]struct{}{}
				}
				trigger.triggers[id] = struct{}{}
			}
			svc.Mu.Unlock()

			resp, err := svc.SetTriggering(context.Background(), nil, &ua.SetTriggeringRequest{
				RequestHeader: hdr, SubscriptionID: sub.ID, TriggeringItemID: itemID,
				LinksToAdd: c.add, LinksToRemove: c.remove,
			}, 1)
			require.NoError(t, err)
			res := resp.(*ua.SetTriggeringResponse)
			require.Equal(t, ua.StatusOK, res.ResponseHeader.ServiceResult)
			require.Equal(t, c.removeRes, res.RemoveResults)
			require.Equal(t, c.addRes, res.AddResults)

			svc.Mu.Lock()
			final := slices.Sorted(maps.Keys(trigger.triggers))
			svc.Mu.Unlock()
			require.Equal(t, c.final, final)
		})
	}
}
