// SPDX-License-Identifier: MIT

package server

import (
	"math"
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server/aggregate"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/stretchr/testify/require"
)

// TestServerCapabilitiesEnforcedLimits: the Optional Properties of
// ServerCapabilitiesType (Part 5 §6.3.2) the ConformanceUnits Base Info
// Server Capabilities 2 and Base Info Server Capabilities
// MaxMonitoredItemsQueueSize expose carry the limits the server enforces.
func TestServerCapabilitiesEnforcedLimits(t *testing.T) {
	srv, err := New()
	require.NoError(t, err)
	require.Equal(t, uint32(ua.MaxVariantArrayLength), capabilityOf(t, srv, id.ServerServerCapabilitiesMaxArrayLength))
	require.Equal(t, uacp.DefaultServerACK.MaxMessageSize, capabilityOf(t, srv, id.ServerServerCapabilitiesMaxStringLength))
	require.Equal(t, uacp.DefaultServerACK.MaxMessageSize, capabilityOf(t, srv, id.ServerServerCapabilitiesMaxByteStringLength))
	require.Equal(t, defaultDurableQueueSize, capabilityOf(t, srv, id.ServerServerCapabilitiesMaxMonitoredItemsQueueSize), "a durable subscription has the largest queues")

	for _, tc := range []struct {
		name string
		d    DurableSubscriptions
		want uint32
	}{
		{"durable disabled", DurableSubscriptions{Disabled: true}, maxMonitoredItemQueueSize},
		{"durable smaller", DurableSubscriptions{MaxQueueSize: 10}, maxMonitoredItemQueueSize},
		{"durable larger", DurableSubscriptions{MaxQueueSize: 500}, 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := New(WithDurableSubscriptions(tc.d))
			require.NoError(t, err)
			require.Equal(t, tc.want, capabilityOf(t, s, id.ServerServerCapabilitiesMaxMonitoredItemsQueueSize))
		})
	}

	// No QueueSize granted is larger than the Property.
	plain := &serverConfig{durable: DurableSubscriptions{Disabled: true}}
	require.Equal(t, plain.maxDataQueueSize(), reviseQueueSize(math.MaxUint32))
	durable := &serverConfig{}
	require.Equal(t, durable.maxDataQueueSize(), durable.durable.reviseDurableQueueSize(math.MaxUint32, false))

	// The values follow the limits they report.
	defer func(n int) { ua.MaxVariantArrayLength = n }(ua.MaxVariantArrayLength)
	ua.MaxVariantArrayLength = 42
	require.Equal(t, uint32(42), capabilityOf(t, srv, id.ServerServerCapabilitiesMaxArrayLength))
	defer func(n uint32) { uacp.DefaultServerACK.MaxMessageSize = n }(uacp.DefaultServerACK.MaxMessageSize)
	uacp.DefaultServerACK.MaxMessageSize = 4096
	require.Equal(t, uint32(4096), capabilityOf(t, srv, id.ServerServerCapabilitiesMaxStringLength))
}

// TestServerCapabilitiesFolders: the ModellingRules and AggregateFunctions
// Folders of the ServerCapabilities "browse to all ModellingRules" and "to
// all AggregateFunctions supported by the Server" (Part 5 §6.3.2).
func TestServerCapabilitiesFolders(t *testing.T) {
	srv, err := New()
	require.NoError(t, err)
	organized := func(folder uint32) []uint32 {
		var out []uint32
		for _, r := range srv.Node(ua.NewNumericNodeID(0, folder)).refsSnapshot() {
			if r.IsForward && r.ReferenceTypeID.IntID() == id.Organizes {
				out = append(out, r.NodeID.NodeID.IntID())
			}
		}
		return out
	}
	require.ElementsMatch(t, []uint32{id.ModellingRuleMandatory, id.ModellingRuleOptional, id.ModellingRuleExposesItsArray,
		id.ModellingRuleOptionalPlaceholder, id.ModellingRuleMandatoryPlaceholder}, organized(id.ServerServerCapabilitiesModellingRules))
	var aggregates []uint32
	for _, n := range aggregate.Functions() {
		aggregates = append(aggregates, n.IntID())
	}
	require.ElementsMatch(t, aggregates, organized(id.ServerServerCapabilitiesAggregateFunctions))
}
