// SPDX-License-Identifier: MIT

package uafx_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
