// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupMonitoredItemTest creates a server with a subscription and a monitored item for testing.
func setupMonitoredItemTest(t *testing.T) (*MonitoredItemService, *Subscription, *ua.RequestHeader, uint32) {
	t.Helper()
	srv := newTestServer()
	ns, _ := addTestNamespace(srv)

	sess := srv.sb.NewSession()
	sub := NewSubscription()
	sub.srv = srv.SubscriptionService
	sub.Session = sess
	sub.ID = 1
	sub.running = true
	sub.RevisedPublishingInterval = 100

	srv.SubscriptionService.Mu.Lock()
	srv.SubscriptionService.Subs[sub.ID] = sub
	srv.SubscriptionService.Mu.Unlock()

	hdr := &ua.RequestHeader{
		RequestHandle:       1,
		AuthenticationToken: sess.AuthTokenID,
	}

	svc := srv.MonitoredItemService

	// Create a monitored item.
	itemID := svc.NextID()
	mi := &MonitoredItem{
		ID:  itemID,
		Sub: sub,
		Req: &ua.MonitoredItemCreateRequest{
			ItemToMonitor: &ua.ReadValueID{
				NodeID:      ua.NewStringNodeID(ns.ID(), "rw_int32"),
				AttributeID: ua.AttributeIDValue,
			},
			MonitoringMode: ua.MonitoringModeReporting,
			RequestedParameters: &ua.MonitoringParameters{
				ClientHandle:     1,
				SamplingInterval: 100,
				QueueSize:        1,
			},
		},
		Mode: ua.MonitoringModeReporting,
	}

	svc.Mu.Lock()
	svc.Items[itemID] = mi
	svc.Mu.Unlock()

	return svc, sub, hdr, itemID
}

func TestMonitoredItemService_ModifyMonitoredItems(t *testing.T) {
	svc, sub, hdr, itemID := setupMonitoredItemTest(t)

	t.Run("modify existing item", func(t *testing.T) {
		req := &ua.ModifyMonitoredItemsRequest{
			RequestHeader:  hdr,
			SubscriptionID: sub.ID,
			ItemsToModify: []*ua.MonitoredItemModifyRequest{
				{
					MonitoredItemID: itemID,
					RequestedParameters: &ua.MonitoringParameters{
						ClientHandle:     1,
						SamplingInterval: 500,
						QueueSize:        10,
					},
				},
			},
		}
		resp, err := svc.ModifyMonitoredItems(context.Background(), nil, req, 1)
		require.NoError(t, err)

		modResp := resp.(*ua.ModifyMonitoredItemsResponse)
		assert.Equal(t, ua.StatusOK, modResp.ResponseHeader.ServiceResult)
		require.Len(t, modResp.Results, 1)
		assert.Equal(t, ua.StatusOK, modResp.Results[0].StatusCode)
		assert.Equal(t, float64(500), modResp.Results[0].RevisedSamplingInterval)
		assert.Equal(t, uint32(10), modResp.Results[0].RevisedQueueSize)
	})

	t.Run("modify nonexistent item", func(t *testing.T) {
		req := &ua.ModifyMonitoredItemsRequest{
			RequestHeader:  hdr,
			SubscriptionID: sub.ID,
			ItemsToModify: []*ua.MonitoredItemModifyRequest{
				{
					MonitoredItemID: 99999,
					RequestedParameters: &ua.MonitoringParameters{
						SamplingInterval: 200,
					},
				},
			},
		}
		resp, err := svc.ModifyMonitoredItems(context.Background(), nil, req, 2)
		require.NoError(t, err)

		modResp := resp.(*ua.ModifyMonitoredItemsResponse)
		require.Len(t, modResp.Results, 1)
		assert.Equal(t, ua.StatusBadMonitoredItemIDInvalid, modResp.Results[0].StatusCode)
	})

	t.Run("wrong request type", func(t *testing.T) {
		_, err := svc.ModifyMonitoredItems(context.Background(), nil, &ua.ReadRequest{RequestHeader: reqHeader()}, 1)
		assert.Error(t, err)
	})
}

func TestMonitoredItemService_SetTriggering(t *testing.T) {
	svc, sub, hdr, itemID := setupMonitoredItemTest(t)

	// Create a second monitored item to use as a link target.
	linkedID := svc.NextID()
	svc.Mu.Lock()
	svc.Items[linkedID] = &MonitoredItem{
		ID:  linkedID,
		Sub: sub,
		Req: &ua.MonitoredItemCreateRequest{
			ItemToMonitor: &ua.ReadValueID{
				NodeID:      ua.NewStringNodeID(2, "rw_float64"),
				AttributeID: ua.AttributeIDValue,
			},
			RequestedParameters: &ua.MonitoringParameters{ClientHandle: 2},
		},
		Mode: ua.MonitoringModeSampling,
	}
	svc.Mu.Unlock()

	t.Run("set triggering with valid items", func(t *testing.T) {
		req := &ua.SetTriggeringRequest{
			RequestHeader:    hdr,
			SubscriptionID:   sub.ID,
			TriggeringItemID: itemID,
			LinksToAdd:       []uint32{linkedID},
			LinksToRemove:    []uint32{},
		}
		resp, err := svc.SetTriggering(context.Background(), nil, req, 1)
		require.NoError(t, err)

		trigResp := resp.(*ua.SetTriggeringResponse)
		assert.Equal(t, ua.StatusOK, trigResp.ResponseHeader.ServiceResult)
		require.Len(t, trigResp.AddResults, 1)
		assert.Equal(t, ua.StatusOK, trigResp.AddResults[0])
	})

	t.Run("set triggering with invalid trigger item", func(t *testing.T) {
		req := &ua.SetTriggeringRequest{
			RequestHeader:    hdr,
			SubscriptionID:   sub.ID,
			TriggeringItemID: 99999,
			LinksToAdd:       []uint32{linkedID},
		}
		resp, err := svc.SetTriggering(context.Background(), nil, req, 2)
		require.NoError(t, err)

		trigResp := resp.(*ua.SetTriggeringResponse)
		assert.Equal(t, ua.StatusBadMonitoredItemIDInvalid, trigResp.ResponseHeader.ServiceResult)
	})

	t.Run("set triggering with invalid linked item", func(t *testing.T) {
		req := &ua.SetTriggeringRequest{
			RequestHeader:    hdr,
			SubscriptionID:   sub.ID,
			TriggeringItemID: itemID,
			LinksToAdd:       []uint32{99999},
			LinksToRemove:    []uint32{},
		}
		resp, err := svc.SetTriggering(context.Background(), nil, req, 3)
		require.NoError(t, err)

		trigResp := resp.(*ua.SetTriggeringResponse)
		assert.Equal(t, ua.StatusOK, trigResp.ResponseHeader.ServiceResult)
		require.Len(t, trigResp.AddResults, 1)
		assert.Equal(t, ua.StatusBadMonitoredItemIDInvalid, trigResp.AddResults[0])
	})

	t.Run("wrong request type", func(t *testing.T) {
		_, err := svc.SetTriggering(context.Background(), nil, &ua.ReadRequest{RequestHeader: reqHeader()}, 1)
		assert.Error(t, err)
	})
}

// TestSetMonitoringMode_NilSession verifies that SetMonitoringMode does not
// panic when the request has no valid session (srv.Session returns nil).
func TestSetMonitoringMode_NilSession(t *testing.T) {
	mis, _, _, itemID := setupMonitoredItemTest(t)

	badHdr := &ua.RequestHeader{
		RequestHandle:       99,
		AuthenticationToken: ua.NewByteStringNodeID(0, []byte("bad-session")),
	}
	req := &ua.SetMonitoringModeRequest{
		RequestHeader:    badHdr,
		MonitoringMode:   ua.MonitoringModeDisabled,
		MonitoredItemIDs: []uint32{itemID},
	}
	require.NotPanics(t, func() {
		resp, err := mis.SetMonitoringMode(context.Background(), nil, req, 1)
		require.NoError(t, err)
		r := resp.(*ua.SetMonitoringModeResponse)
		require.Equal(t, ua.StatusBadSessionIDInvalid, r.Results[0])
	})
}

// TestSetMonitoringMode_UnknownItemID verifies that SetMonitoringMode returns
// BadMonitoredItemIDInvalid (not panic) when the item ID is unknown.
func TestSetMonitoringMode_UnknownItemID(t *testing.T) {
	mis, _, hdr, _ := setupMonitoredItemTest(t)

	req := &ua.SetMonitoringModeRequest{
		RequestHeader:    hdr,
		MonitoringMode:   ua.MonitoringModeDisabled,
		MonitoredItemIDs: []uint32{99999},
	}
	require.NotPanics(t, func() {
		resp, err := mis.SetMonitoringMode(context.Background(), nil, req, 1)
		require.NoError(t, err)
		r := resp.(*ua.SetMonitoringModeResponse)
		require.Equal(t, ua.StatusBadMonitoredItemIDInvalid, r.Results[0])
	})
}

// TestDeleteMonitoredItems_NilSession verifies that DeleteMonitoredItems does
// not panic when Session() returns nil for the request.
func TestDeleteMonitoredItems_NilSession(t *testing.T) {
	mis, _, _, itemID := setupMonitoredItemTest(t)

	badHdr := &ua.RequestHeader{
		RequestHandle:       99,
		AuthenticationToken: ua.NewByteStringNodeID(0, []byte("bad-session")),
	}
	req := &ua.DeleteMonitoredItemsRequest{
		RequestHeader:    badHdr,
		MonitoredItemIDs: []uint32{itemID},
	}
	require.NotPanics(t, func() {
		resp, err := mis.DeleteMonitoredItems(context.Background(), nil, req, 1)
		require.NoError(t, err)
		r := resp.(*ua.DeleteMonitoredItemsResponse)
		require.Equal(t, ua.StatusBadSessionIDInvalid, r.Results[0])
	})
}

// TestDeleteMonitoredItems_UnknownItemID verifies that DeleteMonitoredItems
// returns BadMonitoredItemIDInvalid (not panic) for an unknown item ID.
func TestDeleteMonitoredItems_UnknownItemID(t *testing.T) {
	mis, _, hdr, _ := setupMonitoredItemTest(t)

	req := &ua.DeleteMonitoredItemsRequest{
		RequestHeader:    hdr,
		MonitoredItemIDs: []uint32{99999},
	}
	require.NotPanics(t, func() {
		resp, err := mis.DeleteMonitoredItems(context.Background(), nil, req, 1)
		require.NoError(t, err)
		r := resp.(*ua.DeleteMonitoredItemsResponse)
		require.Equal(t, ua.StatusBadMonitoredItemIDInvalid, r.Results[0])
	})
}
