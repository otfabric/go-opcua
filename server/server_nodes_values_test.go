// SPDX-License-Identifier: MIT

package server

import (
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func nodeByID(t *testing.T, nodes []*Node, nid uint32) *Node {
	t.Helper()
	for _, n := range nodes {
		if n.ID().IntID() == nid && n.ID().Namespace() == 0 {
			return n
		}
	}
	require.Failf(t, "node not found", "i=%d", nid)
	return nil
}

func TestServerCapabilitiesNodes_ReportConfiguredLimits(t *testing.T) {
	srv := newTestServer()
	caps := srv.cfg.cap
	caps.OperationalLimits = OperationalLimits{
		MaxNodesPerRead:                          101,
		MaxNodesPerWrite:                         102,
		MaxNodesPerBrowse:                        103,
		MaxNodesPerMethodCall:                    104,
		MaxNodesPerRegisterNodes:                 105,
		MaxNodesPerTranslateBrowsePathsToNodeIDs: 106,
		MaxNodesPerNodeManagement:                107,
		MaxMonitoredItemsPerCall:                 108,
		MaxNodesPerHistoryReadData:               109,
		MaxNodesPerHistoryReadEvents:             110,
		MaxNodesPerHistoryUpdateData:             111,
		MaxNodesPerHistoryUpdateEvents:           112,
	}
	srv.cfg.cap = caps

	want := map[uint32]uint32{
		id.ServerServerCapabilitiesOperationLimitsMaxNodesPerRead:                          101,
		id.ServerServerCapabilitiesOperationLimitsMaxNodesPerWrite:                         102,
		id.ServerServerCapabilitiesOperationLimitsMaxNodesPerBrowse:                        103,
		id.ServerServerCapabilitiesOperationLimitsMaxNodesPerMethodCall:                    104,
		id.ServerServerCapabilitiesOperationLimitsMaxNodesPerRegisterNodes:                 105,
		id.ServerServerCapabilitiesOperationLimitsMaxNodesPerTranslateBrowsePathsToNodeIDs: 106,
		id.ServerServerCapabilitiesOperationLimitsMaxNodesPerNodeManagement:                107,
		id.ServerServerCapabilitiesOperationLimitsMaxMonitoredItemsPerCall:                 108,
		id.ServerServerCapabilitiesOperationLimitsMaxNodesPerHistoryReadData:               109,
		id.ServerServerCapabilitiesOperationLimitsMaxNodesPerHistoryReadEvents:             110,
		id.ServerServerCapabilitiesOperationLimitsMaxNodesPerHistoryUpdateData:             111,
		id.ServerServerCapabilitiesOperationLimitsMaxNodesPerHistoryUpdateEvents:           112,
	}

	nodes := ServerCapabilitiesNodes(srv)
	require.Len(t, nodes, len(want))
	for nid, limit := range want {
		n := nodeByID(t, nodes, nid)
		dv := n.Value()
		require.NotNil(t, dv)
		assert.Equal(t, limit, dv.Value.Value(), "limit node i=%d (%s)", nid, n.BrowseName().Name)
		assert.Equal(t, ua.NodeClassVariable, n.NodeClass())
	}
}

func TestServerStatusNodes_Values(t *testing.T) {
	srv := newTestServer()
	srv.cfg.softwareVersion = "9.8.7"
	srv.cfg.manufacturerName = "ACME"
	srv.cfg.productName = "Widget"

	// A private Server object that does not yet reference ServerStatus.
	serverNode := NewNode(ua.NewNumericNodeID(0, id.Server), nil, nil, nil)
	other := NewNode(ua.NewNumericNodeID(0, id.ServerServerCapabilities), nil, nil, nil)
	serverNode.AddRef(other, id.HasComponent, true)

	before := time.Now()
	nodes := ServerStatusNodes(srv, serverNode)
	after := time.Now()

	str := func(nid uint32) string {
		v, ok := nodeByID(t, nodes, nid).Value().Value.Value().(string)
		require.True(t, ok, "i=%d is not a string", nid)
		return v
	}
	assert.Equal(t, "ACME", str(id.ServerServerStatusBuildInfoManufacturerName))
	assert.Equal(t, "Widget", str(id.ServerServerStatusBuildInfoProductName))
	assert.Equal(t, "9.8.7", str(id.ServerServerStatusBuildInfoSoftwareVersion))

	tm := func(nid uint32) time.Time {
		v, ok := nodeByID(t, nodes, nid).Value().Value.Value().(time.Time)
		require.True(t, ok, "i=%d is not a time", nid)
		return v
	}
	start := tm(id.ServerServerStatusStartTime)
	assert.False(t, start.Before(before.Truncate(time.Microsecond)))
	assert.False(t, start.After(after))
	assert.Equal(t, start, tm(id.ServerServerStatusStartTime), "the start time is fixed")
	assert.False(t, tm(id.ServerServerStatusCurrentTime).Before(start), "the current time advances from the start time")

	// The status object is linked below Server exactly once, even when the
	// nodes are built a second time.
	statusID := ua.NewNumericNodeID(0, id.ServerServerStatus)
	require.True(t, hasReference(serverNode, statusID, id.HasComponent, true))
	require.False(t, hasReference(serverNode, statusID, id.HasComponent, false))
	require.False(t, hasReference(serverNode, statusID, id.Organizes, true))
	ServerStatusNodes(srv, serverNode)
	count := 0
	for _, r := range serverNode.refsSnapshot() {
		if r.NodeID.NodeID.Equal(statusID) {
			count++
		}
	}
	require.Equal(t, 1, count)

	// Every status component hangs below the status object.
	status := nodeByID(t, nodes, id.ServerServerStatus)
	for _, n := range nodes {
		if n == status {
			continue
		}
		assert.True(t, hasReference(status, n.ID(), id.HasComponent, true), "missing component %s", n.ID())
	}
}

func TestCurrentTimeNode_TracksTheClock(t *testing.T) {
	n := CurrentTimeNode()
	require.Equal(t, uint32(id.ServerServerStatusCurrentTime), n.ID().IntID())

	before := time.Now().Truncate(time.Microsecond)
	got, ok := n.Value().Value.Value().(time.Time)
	require.True(t, ok)
	require.False(t, got.Before(before))
	require.False(t, got.After(time.Now()))
}

func TestHasReference_IgnoresMalformedEntries(t *testing.T) {
	target := ua.NewNumericNodeID(0, 1234)
	n := NewNode(ua.NewNumericNodeID(0, 1), nil, References{
		nil,
		{IsForward: true, NodeID: ua.NewExpandedNodeID(target, "", 0)},                                            // no reference type
		{IsForward: true, ReferenceTypeID: ua.NewNumericNodeID(0, id.HasComponent)},                               // no target
		{IsForward: true, ReferenceTypeID: ua.NewNumericNodeID(0, id.HasComponent), NodeID: &ua.ExpandedNodeID{}}, // empty target
	}, nil)
	require.False(t, hasReference(n, target, id.HasComponent, true))

	n.AddRef(NewNode(target, nil, nil, nil), id.HasComponent, true)
	require.True(t, hasReference(n, target, id.HasComponent, true))
}
