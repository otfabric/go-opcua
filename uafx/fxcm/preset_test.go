// SPDX-License-Identifier: MIT

package fxcm_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/testutil/fxtest"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxcm"
	"github.com/otfabric/go-opcua/uafx/fxserver"
)

// presetConf is e2eConf with one Connection from Motion of a to the
// preconfigured endpoint Preset of b, which subscribes to Setpoint.
func presetConf(t *testing.T, a, b *ac) *uafx.ConnectionConfigurationSetConf {
	t.Helper()
	conf := e2eConf(t, "Preset", a, b)
	links := func(writer, reader bool) *ua.ExtensionObject {
		l := &uafx.PubSubCommunicationLinkConfiguration{}
		if writer {
			l.DataSetWriterRef = &ua.PubSubConfigurationRefDataType{ConfigurationMask: ua.PubSubConfigurationRefMaskReferenceWriter}
		}
		if reader {
			l.DataSetReaderRef = &ua.PubSubConfigurationRefDataType{ConfigurationMask: ua.PubSubConfigurationRefMaskReferenceReader, ConnectionIndex: 1}
		}
		eo, err := uafx.EncodeStructure(l, uafx.NamespaceIndexes{Data: e2eData, AC: e2eAC})
		require.NoError(t, err)
		return eo
	}
	c := conf.Connections[0]
	c.BrowseName = "Pre"
	c.Endpoint1.Name, c.Endpoint1.InputVariableIDs, c.Endpoint1.InboundFlowIndex = "ToPreset", nil, nil
	c.Endpoint1.CommunicationLinks = links(true, false)
	c.Endpoint2.Name, c.Endpoint2.IsPreconfigured, c.Endpoint2.CleanupTimeout = "Preset", true, 5000
	c.Endpoint2.OutputVariableIDs, c.Endpoint2.OutboundFlowIndex, c.Endpoint2.InboundFlowIndex = nil, nil, []int32{0, 0}
	c.Endpoint2.ConfigurationData = nil
	c.Endpoint2.CommunicationLinks = links(false, true)
	conf.CommunicationFlows = conf.CommunicationFlows[:1]
	// a only publishes: a reader no endpoint links to would stay after a
	// close (§6.2.5.2) and collide with the next establish.
	model := conf.AutomationComponentConfigurations[0].CommunicationModelConfig.(*uafx.PubSubCommunicationModelConfiguration)
	model.ConfigurationReferences = model.ConfigurationReferences[:6]
	return conf
}

// TestPreconfigured: a preconfigured endpoint is taken, not created
// (Table 79, §6.2.4.3.5), and stays after a remove (§6.2.5.2); a take
// whose response is lost is proven by its RelatedEndpoint (design §5.4)
// and rolled back.
func TestPreconfigured(t *testing.T) {
	t.Parallel()
	a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
	conf := presetConf(t, a, b)
	m := newManager(t, fxcm.Options{})
	cfg, err := m.Add(conf)
	require.NoError(t, err)
	k := cfg.Key()
	res := process(t, m, uafx.ActionEstablishConnectionsEnabled, k)
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	require.Len(t, res.Created, 2)
	classes := map[string]fxcm.Ownership{}
	for _, r := range res.Created {
		classes[r.Name] = r.Class
	}
	assert.Equal(t, fxcm.TakenPreconfigured, classes["Preset"])
	assert.Equal(t, fxcm.KnownOwned, classes["ToPreset"])
	require.Eventually(t, func() bool { return b.value(t, fxtest.ConnSetpoint) == 42.5 }, 10*time.Second, 10*time.Millisecond)
	assert.Equal(t, 5000.0, b.value(t, fxtest.ConnPreset+3))

	// Establishing again closes the take first and takes it again.
	res = process(t, m, uafx.ActionEstablishConnectionsDisabled, k)
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	res = process(t, m, uafx.ActionRemoveConnections, k)
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	assert.NotNil(t, b.srv.Node(b.id(fxtest.ConnPreset)), "a preconfigured endpoint stays")
	assert.Empty(t, a.endpoints())
	require.NoError(t, m.Close())

	// The response of the take is lost.
	d := newHookDialer()
	var lost atomic.Bool
	d.hook = func(addr fxcm.ServerAddress, req *ua.CallMethodRequest) (bool, error) {
		if addr.Address == b.url && commandMask(req)&uafx.CreateConnectionEndpointCmd != 0 && lost.CompareAndSwap(false, true) {
			return true, ua.StatusBadCommunicationError
		}
		return false, nil
	}
	m = newManager(t, fxcm.Options{Dialer: d})
	cfg, err = m.Add(conf)
	require.NoError(t, err)
	res = process(t, m, uafx.ActionEstablishConnectionsEnabled, cfg.Key())
	require.Equal(t, fxcm.StateError, res.State)
	assert.Empty(t, res.Unresolved)
	assert.True(t, res.RolledBack)
	assert.True(t, res.RollbackComplete, "%+v", res.Failures)
	assert.Empty(t, a.endpoints())
	res = process(t, m, uafx.ActionEstablishConnectionsEnabled, cfg.Key())
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	res = process(t, m, uafx.ActionRemoveConnections, cfg.Key())
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
}

// TestReconcileUnresolved: Reconcile checks Unresolved endpoints again: one
// that is still there stays Unresolved, one that went is forgotten.
func TestReconcileUnresolved(t *testing.T) {
	t.Parallel()
	a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
	conf := e2eConf(t, "Recheck", a, b)
	m1 := newManager(t, fxcm.Options{})
	cfg, err := m1.Add(conf)
	require.NoError(t, err)
	res := process(t, m1, uafx.ActionEstablishConnectionsDisabled, cfg.Key())
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)

	m2 := newManager(t, fxcm.Options{})
	_, err = m2.Add(conf)
	require.NoError(t, err)
	res = process(t, m2, uafx.ActionEstablishConnectionsDisabled, cfg.Key())
	require.Equal(t, fxcm.StateError, res.State)
	require.Len(t, res.Unresolved, 2)
	reconcile := func() *fxcm.RunResult {
		st := m2.Reconcile(cfg.Key())
		require.NoError(t, st.Err)
		r, err := st.Run.Wait(context.Background())
		require.NoError(t, err)
		return r
	}
	r := reconcile()
	assert.Len(t, r.Unresolved, 2)
	assert.Equal(t, fxcm.StateReady, r.State, "%+v", r.Failures)

	// The first Manager removes its Connection: the second forgets them.
	res = process(t, m1, uafx.ActionRemoveConnections, cfg.Key())
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	r = reconcile()
	assert.Empty(t, r.Unresolved)
	st, _ := m2.Status(cfg.Key())
	assert.Empty(t, st.Endpoints)
	res = process(t, m2, uafx.ActionEstablishConnectionsDisabled, cfg.Key())
	assert.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
}

// TestEndpointGone: an endpoint the AC removed by itself (a restart, a
// cleanup) is forgotten when the next run finds its Name free.
func TestEndpointGone(t *testing.T) {
	t.Parallel()
	a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
	m := newManager(t, fxcm.Options{})
	cfg, err := m.Add(e2eConf(t, "Gone", a, b))
	require.NoError(t, err)
	res := process(t, m, uafx.ActionEstablishConnectionsDisabled, cfg.Key())
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	cleanAC(t, a)
	res = process(t, m, uafx.ActionEstablishConnectionsDisabled, cfg.Key())
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	assert.Len(t, res.Closed, 1, "only the endpoint of b was closed first")
	assert.Equal(t, []string{"ToB"}, a.endpoints())

	// Enable and Disable of an endpoint that went: Bad_NodeIdUnknown.
	cleanAC(t, a)
	res = process(t, m, uafx.ActionEnableConnections, cfg.Key())
	assert.Equal(t, fxcm.StateError, res.State)
	res = process(t, m, uafx.ActionDisableConnections, cfg.Key())
	assert.Equal(t, fxcm.StateReady, res.State, "a close of an endpoint that is gone succeeds: %+v", res.Failures)
	st, _ := m.Status(cfg.Key())
	assert.Len(t, st.Endpoints, 1)
}
