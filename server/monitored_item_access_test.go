// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func createItems(t *testing.T, svc *MonitoredItemService, hdr *ua.RequestHeader, subID uint32, items ...*ua.ReadValueID) []*ua.MonitoredItemCreateResult {
	t.Helper()
	reqs := make([]*ua.MonitoredItemCreateRequest, len(items))
	for i, rv := range items {
		reqs[i] = &ua.MonitoredItemCreateRequest{
			ItemToMonitor:       rv,
			MonitoringMode:      ua.MonitoringModeReporting,
			RequestedParameters: &ua.MonitoringParameters{ClientHandle: uint32(i), SamplingInterval: 100, QueueSize: 1},
		}
	}
	resp, err := svc.CreateMonitoredItems(context.Background(), nil, &ua.CreateMonitoredItemsRequest{
		RequestHeader:      hdr,
		SubscriptionID:     subID,
		TimestampsToReturn: ua.TimestampsToReturnBoth,
		ItemsToCreate:      reqs,
	}, 1)
	require.NoError(t, err)
	return resp.(*ua.CreateMonitoredItemsResponse).Results
}

func TestCreateMonitoredItems_DeniedByAccessController(t *testing.T) {
	svc, sub, hdr, itemID := setupMonitoredItemTest(t)
	srv := svc.SubService.srv
	secret := svc.Items[itemID].Req.ItemToMonitor.NodeID
	srv.cfg.accessController = historyDenier{node: secret}

	res := createItems(t, svc, hdr, sub.ID,
		&ua.ReadValueID{NodeID: secret, AttributeID: ua.AttributeIDValue},
		&ua.ReadValueID{NodeID: ua.NewStringNodeID(secret.Namespace(), "ro_bool"), AttributeID: ua.AttributeIDValue},
		// Event items are not reads of the node: the controller is not asked.
		&ua.ReadValueID{NodeID: ua.NewNumericNodeID(0, id.Server), AttributeID: ua.AttributeIDEventNotifier},
	)
	require.Equal(t, ua.StatusBadUserAccessDenied, res[0].StatusCode)
	require.Equal(t, ua.StatusOK, res[1].StatusCode)
	// Bad_EventFilterInvalid (no filter given): past the access checks.
	require.Equal(t, ua.StatusBadEventFilterInvalid, res[2].StatusCode)
}

func TestCreateMonitoredItems_AccessRestrictions(t *testing.T) {
	svc, sub, hdr, itemID := setupMonitoredItemTest(t)
	srv := svc.SubService.srv
	nid := svc.Items[itemID].Req.ItemToMonitor.NodeID
	n := srv.Node(nid)
	require.NotNil(t, n)
	n.mu.Lock()
	n.attr[ua.AttributeIDAccessRestrictions] = DataValueFromValue(uint16(ua.AccessRestrictionTypeSigningRequired))
	n.mu.Unlock()
	res := createItems(t, svc, hdr, sub.ID, &ua.ReadValueID{NodeID: nid, AttributeID: ua.AttributeIDValue})
	require.Equal(t, ua.StatusBadSecurityModeInsufficient, res[0].StatusCode)
}
