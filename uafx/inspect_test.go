// SPDX-License-Identifier: MIT

package uafx_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxcmid"
	"github.com/otfabric/go-opcua/uafx/fxdataid"
)

func TestInspect(t *testing.T) {
	_, c, ns := uafx.FXTestServer(t, false)
	ctx := context.Background()
	r, err := uafx.Inspect(ctx, c, uafx.Limits{})
	require.NoError(t, err)

	assert.True(t, r.IsFXServer())
	require.Len(t, r.Namespaces, 4)
	for _, n := range r.Namespaces[1:] {
		assert.True(t, n.Present, n.URI)
		assert.Equal(t, "1.00.04", n.Version, n.URI)
		assert.Equal(t, 2026, n.PublicationDate.Year(), n.URI)
	}
	data, ok := r.Namespace(fxdataid.NamespaceURI)
	require.True(t, ok)
	assert.Equal(t, ns.Data, data.Index)
	assert.NotEqual(t, uint16(1), ns.DI, "the test needs indexes that differ from the NodeSet documents")
	assert.True(t, ua.NewNumericNodeID(ns.Data, fxdataid.FxRoot).Equal(r.FxRoot))
	assert.False(t, r.Truncated)

	require.Len(t, r.AutomationComponents, 2)
	ac := r.AutomationComponents[0]
	if ac.BrowseName.Name != "Controller" {
		ac = r.AutomationComponents[1]
	}
	assert.Equal(t, "Controller", ac.BrowseName.Name)
	assert.True(t, ua.NewNumericNodeID(ns.AC, fxacid.AutomationComponentType).Equal(ac.TypeDefinition))
	assert.Equal(t, "https://opcfoundation.org/products/view/example", ac.ConformanceName)
	require.NotNil(t, ac.AggregatedHealth)
	assert.Equal(t, uafx.DeviceMaintenanceRequired, ac.AggregatedHealth.AggregatedDeviceHealth)
	assert.Equal(t, uafx.OperationalWarning, ac.AggregatedHealth.AggregatedOperationalHealth)
	require.Len(t, ac.Descriptors, 1)
	assert.Equal(t, "Profile", ac.Descriptors[0].BrowseName.Name)

	require.Len(t, ac.Assets, 1)
	a := ac.Assets[0]
	assert.Equal(t, uafx.Asset{
		Node: a.Node, Manufacturer: "Example Automation", ManufacturerURI: "urn:example:automation",
		Model: "Drive 100", ProductCode: "D-100", HardwareRevision: "1.0", SoftwareRevision: "2.3.1",
		DeviceRevision: "7", SerialNumber: "SN-0042", ProductInstanceURI: "urn:example:automation:SN-0042",
		AssetID: "Drive-A", ComponentName: "Feed drive", DeviceClass: "Drive",
	}, a)

	require.Len(t, ac.FunctionalEntities, 1)
	fe := ac.FunctionalEntities[0]
	assert.Equal(t, "Motion", fe.BrowseName.Name)
	assert.Equal(t, "urn:example:automation", fe.AuthorURI)
	assert.Equal(t, "Motion-1", fe.AuthorAssignedIdentifier)
	require.NotNil(t, fe.AuthorAssignedVersion)
	assert.Equal(t, "1.2.3.4", fe.AuthorAssignedVersion.String())
	require.NotNil(t, fe.OperationalHealth)
	assert.Equal(t, uafx.OperationalWarning, *fe.OperationalHealth)
	require.Len(t, fe.SubFunctionalEntities, 1)
	assert.Equal(t, "Axis", fe.SubFunctionalEntities[0].BrowseName.Name)

	require.Len(t, fe.ConnectionEndpoints, 2)
	ep := fe.ConnectionEndpoints[0]
	if ep.BrowseName.Name != "ToLine" {
		ep = fe.ConnectionEndpoints[1]
	}
	assert.True(t, ua.NewNumericNodeID(ns.AC, fxacid.PubSubConnectionEndpointType).Equal(ep.TypeDefinition))
	require.NotNil(t, ep.Status)
	assert.Equal(t, uafx.ConnectionEndpointOperational, *ep.Status)
	assert.True(t, ep.IsPersistent)
	assert.Equal(t, 1500*time.Millisecond, ep.CleanupTimeout)
	assert.Equal(t, "urn:example:cm", ep.ConnectionManagerApplicationURI)

	require.Len(t, r.ConnectionManagers, 1)
	cm := r.ConnectionManagers[0]
	assert.True(t, ua.NewNumericNodeID(ns.CM, fxcmid.FxRootConnectionManager).Equal(cm.NodeID))
	assert.True(t, ua.NewNumericNodeID(ns.CM, fxcmid.ConnectionManagerType).Equal(cm.TypeDefinition))
	require.Len(t, cm.ConnectionConfigurationSets, 1)
	assert.Equal(t, "Line1", cm.ConnectionConfigurationSets[0].BrowseName.Name)

	var findings []string
	for _, f := range r.Findings {
		findings = append(findings, f.String())
	}
	assert.ElementsMatch(t, []string{
		"Broken: AutomationComponent has no mandatory AggregatedHealth (Part 81 §6.2.2)",
		"Broken: AutomationComponent has no mandatory CloseConnections (Part 81 §6.2.2)",
		"Broken: AutomationComponent has no mandatory ComponentCapabilities (Part 81 §6.2.2)",
		"Broken: AutomationComponent has no mandatory Descriptors (Part 81 §6.2.2)",
		"Broken: AutomationComponent has no mandatory EstablishConnections (Part 81 §6.2.2)",
		"Broken: AutomationComponent has no mandatory FunctionalEntities (Part 81 §6.2.2)",
		"Controller/FunctionalEntities/Motion/ConnectionEndpoints/Bare: ConnectionEndpoint has no mandatory CleanupTimeout (Part 81 §6.6.2)",
		"Controller/FunctionalEntities/Motion/ConnectionEndpoints/Bare: ConnectionEndpoint has no mandatory IsPersistent (Part 81 §6.6.2)",
		"Controller/FunctionalEntities/Motion/ConnectionEndpoints/Bare: ConnectionEndpoint has no mandatory RelatedEndpoint (Part 81 §6.6.2)",
		"Controller/FunctionalEntities/Motion/ConnectionEndpoints/Bare: ConnectionEndpoint has no mandatory Status (Part 81 §6.6.2)",
		"Controller/FunctionalEntities/Motion/ConnectionEndpoints/Bare: PubSubConnectionEndpoint has no mandatory Mode (Part 81 §6.6.3)",
	}, findings)
}
