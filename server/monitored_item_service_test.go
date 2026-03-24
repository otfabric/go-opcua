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
