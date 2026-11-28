// SPDX-License-Identifier: MIT

package server

import (
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// The Mandatory Properties of the Server Object the ConformanceUnit Base
// Info Core Structure 2 of OPC 10000-7 exposes and the built-in node set
// declares without a value: ServerArray and ServiceLevel of ServerType
// (OPC 10000-5 §6.3.1) and RedundancySupport of its ServerRedundancy
// Object (OPC 10000-5 §6.3.7).

// The ServiceLevel sub-ranges of OPC 10000-4 §6.6.2.4.2, Table 105.
const (
	// serviceLevelMaintenance: "new Clients shall not connect and
	// currently connected Clients shall disconnect".
	serviceLevelMaintenance byte = 0
	// serviceLevelNoData: "The Failed Server is not operational ... The
	// Server most likely has no data other than ServiceLevel, ServerStatus
	// and diagnostic information available".
	serviceLevelNoData byte = 1
	// serviceLevelDegraded is the top of the Degraded sub-range 2-199:
	// "The Server is partially operational".
	serviceLevelDegraded byte = 199
	// serviceLevelHealthy is the top of the Healthy sub-range 200-255:
	// "The Server is fully operational".
	serviceLevelHealthy byte = 255
)

// serviceLevel returns the ServiceLevel for a ServerState. The algorithm
// within each sub-range is server specific, but every server "shall adhere
// to the sub-ranges" (OPC 10000-4 §6.6.2.4.2). The server knows nothing of
// the data sources of the application, so it derives the level from the
// State of its ServerStatus (OPC 10000-5 §12.6, Table 234):
//
//   - RUNNING_0, "The Server is running normally", is Healthy (255);
//   - TEST_5, where "The outputs are disconnected from the real hardware,
//     but the Server will otherwise behave normally", is Degraded (199);
//   - SHUTDOWN_4, "an indication to Clients connected to the Server to
//     orderly disconnect", is Maintenance (0), with EstimatedReturnTime
//     telling when to come back;
//   - FAILED_1, NO_CONFIGURATION_2 ("does not transfer data"),
//     SUSPENDED_3 ("not receiving or sending data"), COMMUNICATION_FAULT_6
//     (Part 4: "If the underlying system has failed, typically the
//     ServerStatus would indicate COMMUNICATION_FAULT") and UNKNOWN_7 are
//     NoData (1).
func serviceLevel(state ua.ServerState) byte {
	switch state {
	case ua.ServerStateRunning:
		return serviceLevelHealthy
	case ua.ServerStateTest:
		return serviceLevelDegraded
	case ua.ServerStateShutdown:
		return serviceLevelMaintenance
	default:
		return serviceLevelNoData
	}
}

// bindServerObject serves the Properties of the Server Object without a
// value in the node set:
//
//   - ServerArray, the server table: "Index 0 is reserved for the URI of
//     the local Server", and "The ApplicationUri of an OPC UA Server shall
//     be identical to the URI set in index 0 of the ServerArray" (OPC
//     10000-5 §6.3.1). The server knows no remote servers: the array is its
//     ApplicationUri alone;
//   - ServiceLevel, from the ServerState (serviceLevel);
//   - ServerRedundancy.RedundancySupport: a server that does not support
//     redundancy "provides an Object of type ServerRedundancyType with the
//     Property RedundancySupport set to none" (OPC 10000-5 §6.3.1, §6.3.7).
func (s *Server) bindServerObject() {
	for _, c := range []struct {
		nodeID uint32
		value  func() any
	}{
		{id.ServerServerArray, func() any { return []string{s.cfg.applicationURI} }},
		{id.ServerServiceLevel, func() any { return serviceLevel(s.Status().State) }},
		{id.ServerServerRedundancyRedundancySupport, func() any { return int32(ua.RedundancySupportNone) }},
	} {
		n := s.ownNode(c.nodeID)
		if n == nil {
			continue
		}
		value := c.value
		n.mu.Lock()
		n.val = func() *ua.DataValue { return DataValueFromValue(value()) }
		n.mu.Unlock()
	}
}
