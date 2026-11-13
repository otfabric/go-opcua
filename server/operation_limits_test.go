// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func readIDs(n int) []*ua.ReadValueID {
	out := make([]*ua.ReadValueID, n)
	for i := range out {
		out[i] = &ua.ReadValueID{NodeID: ua.NewNumericNodeID(0, id.ServerServerStatusCurrentTime), AttributeID: ua.AttributeIDValue}
	}
	return out
}

func TestOperationLimitsEnforced(t *testing.T) {
	srv := newTestServer()
	l := srv.cfg.cap.OperationalLimits
	require.Equal(t, uint32(32), l.MaxNodesPerRead, "default limit")

	ext := func(v any) *ua.ExtensionObject { return ua.NewExtensionObject(v) }
	for _, tc := range []struct {
		name string
		req  func(n int) ua.Request
	}{
		{"Read", func(n int) ua.Request { return &ua.ReadRequest{NodesToRead: make([]*ua.ReadValueID, n)} }},
		{"Write", func(n int) ua.Request { return &ua.WriteRequest{NodesToWrite: make([]*ua.WriteValue, n)} }},
		{"Call", func(n int) ua.Request { return &ua.CallRequest{MethodsToCall: make([]*ua.CallMethodRequest, n)} }},
		{"Browse", func(n int) ua.Request { return &ua.BrowseRequest{NodesToBrowse: make([]*ua.BrowseDescription, n)} }},
		{"BrowseNext", func(n int) ua.Request { return &ua.BrowseNextRequest{ContinuationPoints: make([][]byte, n)} }},
		{"RegisterNodes", func(n int) ua.Request { return &ua.RegisterNodesRequest{NodesToRegister: make([]*ua.NodeID, n)} }},
		{"UnregisterNodes", func(n int) ua.Request { return &ua.UnregisterNodesRequest{NodesToUnregister: make([]*ua.NodeID, n)} }},
		{"TranslateBrowsePaths", func(n int) ua.Request {
			return &ua.TranslateBrowsePathsToNodeIDsRequest{BrowsePaths: make([]*ua.BrowsePath, n)}
		}},
		{"AddNodes", func(n int) ua.Request { return &ua.AddNodesRequest{NodesToAdd: make([]*ua.AddNodesItem, n)} }},
		{"AddReferences", func(n int) ua.Request {
			return &ua.AddReferencesRequest{ReferencesToAdd: make([]*ua.AddReferencesItem, n)}
		}},
		{"DeleteNodes", func(n int) ua.Request { return &ua.DeleteNodesRequest{NodesToDelete: make([]*ua.DeleteNodesItem, n)} }},
		{"DeleteReferences", func(n int) ua.Request {
			return &ua.DeleteReferencesRequest{ReferencesToDelete: make([]*ua.DeleteReferencesItem, n)}
		}},
		{"CreateMonitoredItems", func(n int) ua.Request {
			return &ua.CreateMonitoredItemsRequest{ItemsToCreate: make([]*ua.MonitoredItemCreateRequest, n)}
		}},
		{"ModifyMonitoredItems", func(n int) ua.Request {
			return &ua.ModifyMonitoredItemsRequest{ItemsToModify: make([]*ua.MonitoredItemModifyRequest, n)}
		}},
		{"SetMonitoringMode", func(n int) ua.Request { return &ua.SetMonitoringModeRequest{MonitoredItemIDs: make([]uint32, n)} }},
		{"DeleteMonitoredItems", func(n int) ua.Request {
			return &ua.DeleteMonitoredItemsRequest{MonitoredItemIDs: make([]uint32, n)}
		}},
		{"SetTriggeringAdd", func(n int) ua.Request { return &ua.SetTriggeringRequest{LinksToAdd: make([]uint32, n)} }},
		{"SetTriggeringRemove", func(n int) ua.Request { return &ua.SetTriggeringRequest{LinksToRemove: make([]uint32, n)} }},
		{"HistoryReadData", func(n int) ua.Request {
			return &ua.HistoryReadRequest{HistoryReadDetails: ext(&ua.ReadRawModifiedDetails{}), NodesToRead: make([]*ua.HistoryReadValueID, n)}
		}},
		{"HistoryUpdateData", func(n int) ua.Request {
			d := make([]*ua.ExtensionObject, n)
			for i := range d {
				d[i] = ext(&ua.UpdateDataDetails{})
			}
			return &ua.HistoryUpdateRequest{HistoryUpdateDetails: d}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, ua.StatusOK, srv.checkOperationLimits(tc.req(32)))
			require.Equal(t, ua.StatusBadTooManyOperations, srv.checkOperationLimits(tc.req(33)))
		})
	}

	// Event reads and event updates are left to their handlers.
	require.Equal(t, ua.StatusOK, srv.checkOperationLimits(&ua.HistoryReadRequest{
		HistoryReadDetails: ext(&ua.ReadEventDetails{}), NodesToRead: make([]*ua.HistoryReadValueID, 33)}))
	ev := make([]*ua.ExtensionObject, 33)
	for i := range ev {
		ev[i] = ext(&ua.UpdateEventDetails{})
	}
	require.Equal(t, ua.StatusOK, srv.checkOperationLimits(&ua.HistoryUpdateRequest{HistoryUpdateDetails: ev}))
	require.Equal(t, ua.StatusOK, srv.checkOperationLimits(&ua.GetEndpointsRequest{}))
}

func TestOperationLimitsServeRejectsWholeRequest(t *testing.T) {
	srv := newTestServer()
	srv.initHandlers()
	_, hdr := activatedSession(t, srv)

	resp := srv.serve(context.Background(), nil, 1, &ua.ReadRequest{RequestHeader: hdr, NodesToRead: readIDs(33)})
	fault, ok := resp.(*ua.ServiceFault)
	require.True(t, ok, "got %T", resp)
	require.Equal(t, ua.StatusBadTooManyOperations, fault.ResponseHeader.ServiceResult)

	resp = srv.serve(context.Background(), nil, 2, &ua.ReadRequest{RequestHeader: hdr, NodesToRead: readIDs(32)})
	rr, ok := resp.(*ua.ReadResponse)
	require.True(t, ok, "got %T", resp)
	require.Len(t, rr.Results, 32)
}

func TestWithOperationLimitsConfigurableAndAdvertised(t *testing.T) {
	srv, err := newServerNoNS(WithOperationLimits(OperationalLimits{MaxNodesPerRead: 100, MaxNodesPerWrite: 0}))
	require.NoError(t, err)

	require.Equal(t, ua.StatusOK, srv.checkOperationLimits(&ua.ReadRequest{NodesToRead: make([]*ua.ReadValueID, 100)}))
	require.Equal(t, ua.StatusBadTooManyOperations, srv.checkOperationLimits(&ua.ReadRequest{NodesToRead: make([]*ua.ReadValueID, 101)}))
	// Zero is no limit.
	require.Equal(t, ua.StatusOK, srv.checkOperationLimits(&ua.WriteRequest{NodesToWrite: make([]*ua.WriteValue, 10_000)}))

	adv := map[uint32]uint32{}
	for _, n := range ServerCapabilitiesNodes(srv) {
		dv := n.Value()
		adv[n.ID().IntID()] = dv.Value.Value().(uint32)
	}
	require.Equal(t, uint32(100), adv[id.ServerServerCapabilitiesOperationLimitsMaxNodesPerRead])
	require.Equal(t, uint32(0), adv[id.ServerServerCapabilitiesOperationLimitsMaxNodesPerWrite])
}
