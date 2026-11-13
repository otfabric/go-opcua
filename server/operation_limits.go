// SPDX-License-Identifier: MIT

package server

import (
	"github.com/otfabric/go-opcua/ua"
)

// WithOperationLimits sets the OperationLimits of the server: how many
// operations one call of a service may carry (Part 5 §6.3.11
// OperationLimitsType). A request with more operations than its limit fails
// as a whole with Bad_TooManyOperations (Part 4 §7.38). The limits are
// published in Server.ServerCapabilities.OperationLimits, so the advertised
// values are always the enforced ones.
//
// A field of zero means no limit, which is also how the spec reads a zero in
// OperationLimits. Without this option every limit is 32.
//
// The limits apply as follows:
//
//   - MaxNodesPerRead: Read
//   - MaxNodesPerWrite: Write
//   - MaxNodesPerMethodCall: Call
//   - MaxNodesPerBrowse: Browse, BrowseNext
//   - MaxNodesPerRegisterNodes: RegisterNodes, UnregisterNodes
//   - MaxNodesPerTranslateBrowsePathsToNodeIDs: TranslateBrowsePathsToNodeIds
//   - MaxNodesPerNodeManagement: AddNodes, AddReferences, DeleteNodes,
//     DeleteReferences
//   - MaxMonitoredItemsPerCall: CreateMonitoredItems, ModifyMonitoredItems,
//     SetMonitoringMode, DeleteMonitoredItems, SetTriggering (each of its
//     link lists)
//   - MaxNodesPerHistoryReadData / MaxNodesPerHistoryReadEvents: HistoryRead
//     of data / of events
//   - MaxNodesPerHistoryUpdateData / MaxNodesPerHistoryUpdateEvents: the data
//     / event details of HistoryUpdate
func WithOperationLimits(l OperationalLimits) Option {
	return func(s *serverConfig) error {
		s.cap.OperationalLimits = l
		return nil
	}
}

// exceeds reports whether n operations exceed limit; zero is no limit.
func exceeds(n int, limit uint32) bool {
	return limit > 0 && uint64(n) > uint64(limit)
}

// checkOperationLimits checks the number of operations of a request against
// the OperationLimits of the server (Part 5 §6.3.11). It returns
// Bad_TooManyOperations when a limit is exceeded (Part 4 §7.38: the service
// fails as a whole), StatusOK otherwise.
func (s *Server) checkOperationLimits(req ua.Request) ua.StatusCode {
	l := &s.cfg.cap.OperationalLimits
	over := false
	switch r := req.(type) {
	case *ua.ReadRequest:
		over = exceeds(len(r.NodesToRead), l.MaxNodesPerRead)
	case *ua.WriteRequest:
		over = exceeds(len(r.NodesToWrite), l.MaxNodesPerWrite)
	case *ua.CallRequest:
		over = exceeds(len(r.MethodsToCall), l.MaxNodesPerMethodCall)
	case *ua.BrowseRequest:
		over = exceeds(len(r.NodesToBrowse), l.MaxNodesPerBrowse)
	case *ua.BrowseNextRequest:
		over = exceeds(len(r.ContinuationPoints), l.MaxNodesPerBrowse)
	case *ua.RegisterNodesRequest:
		over = exceeds(len(r.NodesToRegister), l.MaxNodesPerRegisterNodes)
	case *ua.UnregisterNodesRequest:
		over = exceeds(len(r.NodesToUnregister), l.MaxNodesPerRegisterNodes)
	case *ua.TranslateBrowsePathsToNodeIDsRequest:
		over = exceeds(len(r.BrowsePaths), l.MaxNodesPerTranslateBrowsePathsToNodeIDs)
	case *ua.AddNodesRequest:
		over = exceeds(len(r.NodesToAdd), l.MaxNodesPerNodeManagement)
	case *ua.AddReferencesRequest:
		over = exceeds(len(r.ReferencesToAdd), l.MaxNodesPerNodeManagement)
	case *ua.DeleteNodesRequest:
		over = exceeds(len(r.NodesToDelete), l.MaxNodesPerNodeManagement)
	case *ua.DeleteReferencesRequest:
		over = exceeds(len(r.ReferencesToDelete), l.MaxNodesPerNodeManagement)
	case *ua.CreateMonitoredItemsRequest:
		over = exceeds(len(r.ItemsToCreate), l.MaxMonitoredItemsPerCall)
	case *ua.ModifyMonitoredItemsRequest:
		over = exceeds(len(r.ItemsToModify), l.MaxMonitoredItemsPerCall)
	case *ua.SetMonitoringModeRequest:
		over = exceeds(len(r.MonitoredItemIDs), l.MaxMonitoredItemsPerCall)
	case *ua.DeleteMonitoredItemsRequest:
		over = exceeds(len(r.MonitoredItemIDs), l.MaxMonitoredItemsPerCall)
	case *ua.SetTriggeringRequest:
		over = exceeds(len(r.LinksToAdd), l.MaxMonitoredItemsPerCall) ||
			exceeds(len(r.LinksToRemove), l.MaxMonitoredItemsPerCall)
	case *ua.HistoryReadRequest:
		// The event limit is checked by the HistoryRead handler together
		// with the ReadEventDetails.
		if !isEventReadDetails(r.HistoryReadDetails) {
			over = exceeds(len(r.NodesToRead), l.MaxNodesPerHistoryReadData)
		}
	case *ua.HistoryUpdateRequest:
		// The event details are counted by the HistoryUpdate handler.
		data := 0
		for _, d := range r.HistoryUpdateDetails {
			if d == nil || !isEventUpdateDetails(d.Value) {
				data++
			}
		}
		over = exceeds(data, l.MaxNodesPerHistoryUpdateData)
	}
	if over {
		return ua.StatusBadTooManyOperations
	}
	return ua.StatusOK
}

// isEventReadDetails reports whether the HistoryReadDetails of a HistoryRead
// read events.
func isEventReadDetails(eo *ua.ExtensionObject) bool {
	if eo == nil {
		return false
	}
	switch eo.Value.(type) {
	case *ua.ReadEventDetails, ua.ReadEventDetails,
		*ua.ReadEventDetails2, ua.ReadEventDetails2,
		*ua.ReadEventDetailsSorted, ua.ReadEventDetailsSorted:
		return true
	}
	return false
}
