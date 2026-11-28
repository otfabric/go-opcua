// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// TestServerObjectProperties: ServerArray, ServiceLevel and
// ServerRedundancy.RedundancySupport have values (Part 5 §6.3.1, §6.3.7):
// the ApplicationUri at index 0, the ServiceLevel of the ServerState and
// RedundancySupport None.
func TestServerObjectProperties(t *testing.T) {
	srv, err := New(ApplicationURI("urn:go-opcua:test"))
	require.NoError(t, err)
	require.Equal(t, []string{"urn:go-opcua:test"}, capabilityOf(t, srv, id.ServerServerArray))
	require.Equal(t, int32(ua.RedundancySupportNone), capabilityOf(t, srv, id.ServerServerRedundancyRedundancySupport))

	for _, tc := range []struct {
		state ua.ServerState
		level byte
	}{
		{ua.ServerStateRunning, 255},
		{ua.ServerStateTest, 199},
		{ua.ServerStateShutdown, 0},
		{ua.ServerStateFailed, 1},
		{ua.ServerStateNoConfiguration, 1},
		{ua.ServerStateSuspended, 1},
		{ua.ServerStateCommunicationFault, 1},
		{ua.ServerStateUnknown, 1},
	} {
		srv.SetServerState(ServerStateChange{State: tc.state})
		require.Equal(t, tc.level, capabilityOf(t, srv, id.ServerServiceLevel), "%v", tc.state)
	}
}

// TestServerServiceLevelSubRanges: every ServerState has a ServiceLevel in
// the sub-range of OPC 10000-4 §6.6.2.4.2 Table 105 that fits it.
func TestServerServiceLevelSubRanges(t *testing.T) {
	require.GreaterOrEqual(t, serviceLevel(ua.ServerStateRunning), byte(200), "Healthy")
	require.Equal(t, byte(0), serviceLevel(ua.ServerStateShutdown), "Maintenance")
	level := serviceLevel(ua.ServerStateTest)
	require.True(t, level >= 2 && level <= 199, "Degraded: %d", level)
	require.Equal(t, byte(1), serviceLevel(ua.ServerStateFailed), "NoData")
}

// TestBindServerObjectWithoutNode: a server without one of the Properties
// binds the others.
func TestBindServerObjectWithoutNode(t *testing.T) {
	s := newTestServer()
	require.Equal(t, ua.StatusGood, s.ns0().DeleteNode(ua.NewNumericNodeID(0, id.ServerServerArray)))
	s.bindServerObject()
	require.Nil(t, s.Node(ua.NewNumericNodeID(0, id.ServerServerArray)))
	require.Equal(t, int32(ua.RedundancySupportNone), capabilityOf(t, s, id.ServerServerRedundancyRedundancySupport))
}

// TestBindModellingRulesWithoutNodes: without the Folder nothing is bound,
// and a ModellingRule that is not there is left out.
func TestBindModellingRulesWithoutNodes(t *testing.T) {
	s := newTestServer()
	require.Equal(t, ua.StatusGood, s.ns0().DeleteNode(ua.NewNumericNodeID(0, id.ModellingRuleExposesItsArray)))
	s.ns0().AddNode(NewFolderNode(ua.NewNumericNodeID(0, id.ServerServerCapabilitiesModellingRules), "ModellingRules"))
	s.bindModellingRules()
	var organized []uint32
	for _, r := range s.Node(ua.NewNumericNodeID(0, id.ServerServerCapabilitiesModellingRules)).refsSnapshot() {
		if r.IsForward && r.ReferenceTypeID.IntID() == id.Organizes {
			organized = append(organized, r.NodeID.NodeID.IntID())
		}
	}
	require.ElementsMatch(t, []uint32{id.ModellingRuleMandatory, id.ModellingRuleOptional,
		id.ModellingRuleOptionalPlaceholder, id.ModellingRuleMandatoryPlaceholder}, organized)

	require.Equal(t, ua.StatusGood, s.ns0().DeleteNode(ua.NewNumericNodeID(0, id.ServerServerCapabilitiesModellingRules)))
	s.bindModellingRules()
	require.Nil(t, s.Node(ua.NewNumericNodeID(0, id.ServerServerCapabilitiesModellingRules)))
}
