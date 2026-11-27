// SPDX-License-Identifier: MIT

package uafx_test

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/di/diid"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxcmid"
	"github.com/otfabric/go-opcua/uafx/fxdataid"
	"github.com/otfabric/go-opcua/uafx/fxserver"
	"github.com/otfabric/go-opcua/uafx/internal/model"
)

func TestInspectNoFX(t *testing.T) {
	_, url := testutil.NewTestServer(t)
	c := testutil.NewTestClient(t, url)
	r, err := uafx.Inspect(context.Background(), c, uafx.Limits{})
	require.NoError(t, err)
	assert.False(t, r.IsFXServer())
	assert.Nil(t, r.FxRoot)
	assert.Empty(t, r.Findings)
	for _, n := range r.Namespaces {
		assert.False(t, n.Present, n.URI)
		assert.Zero(t, n.Index)
	}
	_, ok := r.Namespace(fxdataid.NamespaceURI)
	assert.False(t, ok)
	_, ok = r.Namespace("urn:none")
	assert.False(t, ok)
}

func TestInspectACOnly(t *testing.T) {
	_, c, ns := FXTestServer(t, true, fxserver.ModelAC)
	assert.Zero(t, ns.CM)
	r, err := uafx.Inspect(context.Background(), c, uafx.Limits{})
	require.NoError(t, err)
	assert.True(t, r.IsFXServer())
	assert.Empty(t, r.ConnectionManagers)
	assert.Empty(t, r.AutomationComponents)
	assert.Empty(t, r.Findings)
}

func TestInspectCMOnly(t *testing.T) {
	_, c, ns := FXTestServer(t, true, fxserver.ModelCM)
	assert.Zero(t, ns.AC)
	r, err := uafx.Inspect(context.Background(), c, uafx.Limits{})
	require.NoError(t, err)
	assert.True(t, r.IsFXServer())
	require.Len(t, r.ConnectionManagers, 1)
	assert.True(t, ua.NewNumericNodeID(ns.CM, fxcmid.FxRootConnectionManager).Equal(r.ConnectionManagers[0].NodeID))
	assert.Empty(t, r.Findings)
}

func TestInspectDataOnly(t *testing.T) {
	srv := NewTestServer(t)
	require.NoError(t, fxserver.ImportNodeSet(srv, model.Data))
	c := StartTestServer(t, srv)
	r, err := uafx.Inspect(context.Background(), c, uafx.Limits{})
	require.NoError(t, err)
	assert.False(t, r.IsFXServer())
	assert.False(t, r.HasFXNamespaces())
	require.Len(t, r.Findings, 2)
	assert.Equal(t, "the server has the UAFX Data namespace but neither the AC nor the CM namespace (Part 81 §14.2)", r.Findings[0].String())
	assert.Equal(t, "the server has the UAFX Data namespace but not the mandatory DI namespace (Part 81 §14.2)", r.Findings[1].String())
}

func TestInspectNoData(t *testing.T) {
	srv := NewTestServer(t)
	server.NewNodeNameSpace(srv, fxacid.NamespaceURI)
	c := StartTestServer(t, srv)
	r, err := uafx.Inspect(context.Background(), c, uafx.Limits{})
	require.NoError(t, err)
	assert.False(t, r.IsFXServer())
	require.Len(t, r.Findings, 1)
	assert.Equal(t, "14.2", r.Findings[0].Clause)
}

// TestInspectNoFxRoot checks a server with the namespaces of a UAFX server
// but no model in them: it has the namespaces, but not the structure.
func TestInspectNoFxRoot(t *testing.T) {
	srv := NewTestServer(t)
	server.NewNodeNameSpace(srv, diid.NamespaceURI)
	server.NewNodeNameSpace(srv, fxdataid.NamespaceURI)
	server.NewNodeNameSpace(srv, fxacid.NamespaceURI)
	c := StartTestServer(t, srv)
	r, err := uafx.Inspect(context.Background(), c, uafx.Limits{})
	require.NoError(t, err)
	assert.True(t, r.HasFXNamespaces())
	assert.False(t, r.IsFXServer(), "no FxRoot (Part 81 §12.2)")
	assert.Nil(t, r.FxRoot)
	require.Len(t, r.Findings, 1)
	assert.Equal(t, "12.2", r.Findings[0].Clause)
}

// TestInspectNoDI checks a server with the UAFX model but without the
// mandatory DI namespace (Part 81 §14.2).
func TestInspectNoDI(t *testing.T) {
	srv := NewTestServer(t)
	require.NoError(t, fxserver.ImportNodeSet(srv, model.Data))
	server.NewNodeNameSpace(srv, fxacid.NamespaceURI)
	c := StartTestServer(t, srv)
	r, err := uafx.Inspect(context.Background(), c, uafx.Limits{})
	require.NoError(t, err)
	assert.False(t, r.HasFXNamespaces())
	assert.False(t, r.IsFXServer())
	assert.NotNil(t, r.FxRoot)
	require.Len(t, r.Findings, 1)
	assert.Equal(t, "the server has the UAFX Data namespace but not the mandatory DI namespace (Part 81 §14.2)", r.Findings[0].String())
}

func TestInspectLimits(t *testing.T) {
	_, c, _ := FXTestServer(t, false)
	ctx := context.Background()

	r, err := uafx.Inspect(ctx, c, uafx.Limits{MaxComponents: 1})
	require.NoError(t, err)
	assert.True(t, r.Truncated)
	assert.Equal(t, 1, len(r.AutomationComponents)+len(r.ConnectionManagers))

	r, err = uafx.Inspect(ctx, c, uafx.Limits{MaxChildren: 1})
	require.NoError(t, err)
	assert.True(t, r.Truncated)

	r, err = uafx.Inspect(ctx, c, uafx.Limits{MaxDepth: 1})
	require.NoError(t, err)
	assert.True(t, r.Truncated)
	for _, ac := range r.AutomationComponents {
		for _, fe := range ac.FunctionalEntities {
			assert.Empty(t, fe.SubFunctionalEntities)
		}
	}
}

// TestInspectBadStructures checks that a structure value of the wrong
// encoding becomes a Finding, not a value.
func TestInspectBadStructures(t *testing.T) {
	srv := NewTestServer(t)
	ns, err := fxserver.AddModel(srv)
	require.NoError(t, err)
	doc := ReadFixture(t)
	require.NoError(t, fxserver.ImportNodeSet(srv, doc))
	test := NSIndex(t, srv, TestNS)
	// AggregatedHealth with the encoding of FxVersion, FxVersion too short.
	SetValue(t, srv, ua.NewNumericNodeID(test, 1004), &ua.ExtensionObject{
		TypeID:       ua.NewNumericExpandedNodeID(ns.AC, fxacid.FxVersionEncodingDefaultBinary),
		EncodingMask: ua.ExtensionObjectBinary,
		Value:        []byte{1, 0, 2, 0, 3, 0, 4, 0},
	})
	SetValue(t, srv, ua.NewNumericNodeID(test, 1203), &ua.ExtensionObject{
		TypeID:       ua.NewNumericExpandedNodeID(ns.AC, fxacid.FxVersionEncodingDefaultBinary),
		EncodingMask: ua.ExtensionObjectBinary,
		Value:        []byte{1, 0},
	})
	c := StartTestServer(t, srv)
	r, err := uafx.Inspect(context.Background(), c, uafx.Limits{})
	require.NoError(t, err)
	clauses := map[string]bool{}
	for _, f := range r.Findings {
		clauses[f.Clause] = true
	}
	assert.True(t, clauses["10.1"], "AggregatedHealth finding")
	assert.True(t, clauses["10.28"], "FxVersion finding")
	for _, ac := range r.AutomationComponents {
		assert.Nil(t, ac.AggregatedHealth)
		for _, fe := range ac.FunctionalEntities {
			assert.Nil(t, fe.AuthorAssignedVersion)
		}
	}
}

func TestInspectClosedClient(t *testing.T) {
	_, c, _ := FXTestServer(t, true)
	require.NoError(t, c.Close(context.Background()))
	_, err := uafx.Inspect(context.Background(), c, uafx.Limits{})
	require.ErrorIs(t, err, uafx.ErrInspect)
}

// capsServer returns a server with the fixture whose Controller has the
// ComponentCapabilities members of Part 81 §6.2.6 Table 26 and whose
// persistent endpoint ToLine has the CleanupTimeout cleanup.
func capsServer(t *testing.T, cleanup float64, supportsPersistence bool) *uafx.Report {
	t.Helper()
	r, err := uafx.Inspect(context.Background(), capsClient(t, cleanup, supportsPersistence), uafx.Limits{})
	require.NoError(t, err)
	return r
}

// The CreationTime and ModificationTime capsClient gives ToLine.
var (
	toLineCreated  = time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC)
	toLineModified = time.Date(2026, 11, 27, 9, 30, 0, 0, time.UTC)
)

// capsClient is capsServer with a client of the server, whose endpoint
// ToLine has Diagnostics (Part 81 §6.6.2 Table 74).
func capsClient(t *testing.T, cleanup float64, supportsPersistence bool) *opcua.Client {
	t.Helper()
	srv := NewTestServer(t)
	ns, err := fxserver.AddModel(srv)
	require.NoError(t, err)
	require.NoError(t, fxserver.ImportNodeSet(srv, ReadFixture(t)))
	test := NSIndex(t, srv, TestNS)
	space, err := srv.Namespace(int(test))
	require.NoError(t, err)
	caps := srv.Node(ua.NewNumericNodeID(test, 1003))
	require.NotNil(t, caps)
	for i, m := range []struct {
		name  string
		value any
	}{
		{"SupportsPersistence", supportsPersistence},
		{"MaxConnections", uint32(8)},
		{"MaxConnectionsPerCall", uint32(2)},
		{"MaxFunctionalEntities", uint32(4)},
		{"MinConnections", uint32(1)},
		{"CommandBundleRequired", true},
	} {
		v := server.NewVariableNode(ua.NewNumericNodeID(test, uint32(90000+i)), m.name, m.value)
		require.NoError(t, v.SetAttribute(ua.AttributeIDBrowseName, server.DataValueFromValue(&ua.QualifiedName{NamespaceIndex: ns.AC, Name: m.name})))
		space.AddNode(v)
		caps.AddRef(v, server.RefTypeIDHasComponent, true)
	}
	SetValue(t, srv, ua.NewNumericNodeID(test, 1303), cleanup)
	// The Diagnostics has the BrowseName of DI, its members those of AC.
	ep := srv.Node(ua.NewNumericNodeID(test, 1300))
	require.NotNil(t, ep)
	diag := server.NewFolderNode(ua.NewNumericNodeID(test, 90100), "Diagnostics")
	require.NoError(t, diag.SetAttribute(ua.AttributeIDBrowseName, server.DataValueFromValue(&ua.QualifiedName{NamespaceIndex: ns.DI, Name: "Diagnostics"})))
	space.AddNode(diag)
	ep.AddRef(diag, server.RefTypeIDHasComponent, true)
	for i, m := range []struct {
		name  string
		value time.Time
	}{{"CreationTime", toLineCreated}, {"ModificationTime", toLineModified}} {
		v := server.NewVariableNode(ua.NewNumericNodeID(test, uint32(90101+i)), m.name, m.value)
		require.NoError(t, v.SetAttribute(ua.AttributeIDBrowseName, server.DataValueFromValue(&ua.QualifiedName{NamespaceIndex: ns.AC, Name: m.name})))
		space.AddNode(v)
		diag.AddRef(v, server.RefTypeIDHasComponent, true)
	}
	return StartTestServer(t, srv)
}

// persistenceFindings are the Findings of r about persistence.
func persistenceFindings(r *uafx.Report) []string {
	var out []string
	for _, f := range r.Findings {
		if f.Clause == "6.2.6" || strings.HasPrefix(f.Text, "persistent ConnectionEndpoint") {
			out = append(out, f.String())
		}
	}
	return out
}

// TestInspectCapabilities: the ComponentCapabilities members are reported
// (Part 81 §6.2.6 Table 26); a persistent endpoint whose CleanupTimeout is
// not negative is a finding (§6.6.2), NaN and 0 included, and one on a
// component without SupportsPersistence TRUE is a finding (§6.2.6).
func TestInspectCapabilities(t *testing.T) {
	r := capsServer(t, -1, true)
	var ac *uafx.AutomationComponent
	for i := range r.AutomationComponents {
		if r.AutomationComponents[i].BrowseName.Name == "Controller" {
			ac = &r.AutomationComponents[i]
		}
	}
	require.NotNil(t, ac)
	require.NotNil(t, ac.Capabilities)
	u := func(v uint32) *uint32 { return &v }
	b := func(v bool) *bool { return &v }
	assert.Equal(t, uafx.ComponentCapabilities{
		SupportsPersistence: b(true), MaxConnections: u(8), MaxConnectionsPerCall: u(2),
		MaxFunctionalEntities: u(4), MinConnections: u(1), CommandBundleRequired: b(true),
	}, *ac.Capabilities)
	assert.True(t, ac.Capabilities.Persistence())
	assert.Empty(t, persistenceFindings(r))
	ep := ac.FunctionalEntities[0].ConnectionEndpoints
	for _, e := range ep {
		if e.BrowseName.Name == "ToLine" {
			require.NotNil(t, e.CleanupTimeoutMs)
			assert.Equal(t, -1.0, *e.CleanupTimeoutMs)
			assert.Zero(t, e.CleanupTimeout)
			assert.True(t, toLineCreated.Equal(e.CreationTime), "%v", e.CreationTime)
			assert.True(t, toLineModified.Equal(e.ModificationTime), "%v", e.ModificationTime)
		}
	}

	const path = "Controller/FunctionalEntities/Motion/ConnectionEndpoints/ToLine: "
	for _, c := range []struct {
		cleanup float64
		text    string
	}{
		{0, "0 ms"},
		{math.NaN(), "NaN ms"},
	} {
		assert.Equal(t, []string{
			path + "persistent ConnectionEndpoint has CleanupTimeout " + c.text + "; it shall be negative (Part 81 §6.6.2)",
		}, persistenceFindings(capsServer(t, c.cleanup, true)))
	}
	assert.Equal(t, []string{
		path + "ConnectionEndpoint has IsPersistent TRUE, but its AutomationComponent does not announce SupportsPersistence TRUE (Part 81 §6.2.6)",
	}, persistenceFindings(capsServer(t, -1, false)))
	var nilCaps *uafx.ComponentCapabilities
	assert.False(t, nilCaps.Persistence())
}
