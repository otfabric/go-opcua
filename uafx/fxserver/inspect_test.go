// SPDX-License-Identifier: MIT

package fxserver_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxserver"
	"github.com/otfabric/go-opcua/uafx/fxstore"
)

// inspectAC returns the AutomationComponent n of the report of
// uafx.Inspect against f, and the report.
func (f *fx) inspectAC(t *testing.T, n *ua.NodeID) (uafx.AutomationComponent, *uafx.Report) {
	t.Helper()
	r, err := uafx.Inspect(context.Background(), f.c, uafx.Limits{})
	require.NoError(t, err)
	for _, ac := range r.AutomationComponents {
		if ac.NodeID.Equal(n) {
			return ac, r
		}
	}
	require.Failf(t, "no AutomationComponent", "%v is not in the report", n)
	return uafx.AutomationComponent{}, nil
}

// endpointOf returns the ConnectionEndpoint n of ac, nil if ac has none.
func endpointOf(ac uafx.AutomationComponent, n *ua.NodeID) *uafx.ConnectionEndpoint {
	var walk func([]uafx.FunctionalEntity) *uafx.ConnectionEndpoint
	walk = func(fes []uafx.FunctionalEntity) *uafx.ConnectionEndpoint {
		for _, fe := range fes {
			for i := range fe.ConnectionEndpoints {
				if fe.ConnectionEndpoints[i].NodeID.Equal(n) {
					return &fe.ConnectionEndpoints[i]
				}
			}
			if ep := walk(fe.SubFunctionalEntities); ep != nil {
				return ep
			}
		}
		return nil
	}
	return walk(ac.FunctionalEntities)
}

// persistenceFindings are the Findings of r about persistence (Part 81
// §6.2.6 and the CleanupTimeout of §6.6.2). The test fixture has other
// findings (it has no Descriptors).
func persistenceFindings(r *uafx.Report) []string {
	var out []string
	for _, f := range r.Findings {
		if f.Clause == "6.2.6" || strings.HasPrefix(f.Text, "persistent ConnectionEndpoint") {
			out = append(out, f.String())
		}
	}
	return out
}

// TestInspectPersistence: Inspect reports what a persistent
// AutomationComponent announces: SupportsPersistence TRUE in its
// ComponentCapabilities (Part 81 §6.2.6 Table 26), the negative
// CleanupTimeout of a persistent endpoint (§6.6.2) and its CreationTime
// and ModificationTime (Table 74), the same after a restart, and no
// persistence finding. Without a store SupportsPersistence is absent.
func TestInspectPersistence(t *testing.T) {
	t.Parallel()
	opts := fxserver.ConnectionOptions{Store: &fxstore.MemoryStore{}}
	f := newFX(t, opts)
	ac, _ := f.inspectAC(t, f.id(ctlID))
	require.NotNil(t, ac.Capabilities)
	require.True(t, ac.Capabilities.Persistence())

	p := f.persistent(t, "P")
	ac, r := f.inspectAC(t, f.id(ctlID))
	require.Empty(t, persistenceFindings(r))
	ep := endpointOf(ac, p)
	require.NotNil(t, ep)
	require.True(t, ep.IsPersistent)
	require.NotNil(t, ep.CleanupTimeoutMs)
	require.Negative(t, *ep.CleanupTimeoutMs)
	require.Zero(t, ep.CleanupTimeout, "a negative CleanupTimeout is 0 in CleanupTimeout")
	require.False(t, ep.CreationTime.IsZero())
	require.False(t, ep.ModificationTime.Before(ep.CreationTime))
	created := ep.CreationTime

	f = f.restart(t, opts)
	f.waitStatus(t, p, uafx.ConnectionEndpointOperational)
	ac, r = f.inspectAC(t, f.id(ctlID))
	require.Empty(t, persistenceFindings(r))
	require.True(t, ac.Capabilities.Persistence())
	ep = endpointOf(ac, p)
	require.NotNil(t, ep)
	require.True(t, created.Equal(ep.CreationTime), "CreationTime %v, after the restart %v", created, ep.CreationTime)

	// Without a store: no SupportsPersistence, and a non-persistent
	// endpoint with its positive CleanupTimeout and its Diagnostics.
	f = newFX(t, fxserver.ConnectionOptions{})
	n := f.operational(t, "N", 2500)
	ac, r = f.inspectAC(t, f.id(ctlID))
	require.Empty(t, persistenceFindings(r))
	require.False(t, ac.Capabilities.Persistence())
	if ac.Capabilities != nil {
		require.Nil(t, ac.Capabilities.SupportsPersistence)
	}
	np := endpointOf(ac, n)
	require.NotNil(t, np)
	require.False(t, np.IsPersistent)
	require.NotNil(t, np.CleanupTimeoutMs)
	require.InDelta(t, 2500.0, *np.CleanupTimeoutMs, 0)
	require.False(t, np.CreationTime.IsZero())
}
