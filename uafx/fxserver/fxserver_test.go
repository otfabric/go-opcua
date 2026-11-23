// SPDX-License-Identifier: MIT

package fxserver_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/di/diid"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxcmid"
	"github.com/otfabric/go-opcua/uafx/fxdataid"
	"github.com/otfabric/go-opcua/uafx/fxserver"
)

func newServer(t *testing.T) *server.Server {
	t.Helper()
	srv, err := server.New(
		server.EndPoint("localhost", 0),
		server.InsecureNoSecurity(),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
	)
	require.NoError(t, err)
	return srv
}

func index(srv *server.Server, uri string) int {
	for i, ns := range srv.Namespaces() {
		if ns.Name() == uri {
			return i
		}
	}
	return -1
}

func TestAddModel(t *testing.T) {
	srv := newServer(t)
	server.NewNodeNameSpace(srv, "urn:app")
	ns, err := fxserver.AddModel(srv)
	require.NoError(t, err)
	assert.Equal(t, fxserver.Namespaces{DI: 2, Data: 3, AC: 4, CM: 5}, ns)
	for uri, idx := range map[string]uint16{diid.NamespaceURI: ns.DI, fxdataid.NamespaceURI: ns.Data, fxacid.NamespaceURI: ns.AC, fxcmid.NamespaceURI: ns.CM} {
		assert.Equal(t, int(idx), index(srv, uri), uri)
	}

	root := srv.Node(ua.NewNumericNodeID(ns.Data, fxdataid.FxRoot))
	require.NotNil(t, root)
	assert.Equal(t, &ua.QualifiedName{NamespaceIndex: ns.Data, Name: "FxRoot"}, root.BrowseName())

	for _, nid := range []*ua.NodeID{
		ua.NewNumericNodeID(ns.AC, fxacid.AutomationComponentType),
		ua.NewNumericNodeID(ns.AC, fxacid.AutomationComponentTypeEstablishConnections),
		ua.NewNumericNodeID(ns.CM, fxcmid.FxRootConnectionManager),
		ua.NewNumericNodeID(ns.DI, diid.DeviceSet),
	} {
		assert.NotNil(t, srv.Node(nid), "%v", nid)
	}
	// A BrowseName of namespace 0 in the NodeSet stays in namespace 0.
	ia := srv.Node(ua.NewNumericNodeID(ns.CM, fxcmid.ConnectionManagerTypeEditConnectionConfigurationSetsInputArguments))
	require.NotNil(t, ia)
	assert.Equal(t, &ua.QualifiedName{NamespaceIndex: 0, Name: "InputArguments"}, ia.BrowseName())

	_, err = fxserver.AddModel(srv)
	assert.ErrorIs(t, err, fxserver.ErrModel, "a second time")

	// FxRoot is organized by the Objects folder (Part 81 §12.2).
	found := false
	for _, ref := range objectsRefs(t, srv) {
		if ref.NodeID.NodeID.Equal(root.ID()) {
			found = true
		}
	}
	assert.True(t, found, "Objects organizes FxRoot")
}

func objectsRefs(t *testing.T, srv *server.Server) []*ua.ReferenceDescription {
	t.Helper()
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })
	c := testutil.NewTestClient(t, fmt.Sprintf("opc.tcp://localhost:%d", srv.Port()))
	refs, err := c.Node(ua.NewNumericNodeID(0, id.ObjectsFolder)).References(context.Background(), id.Organizes, ua.BrowseDirectionForward, ua.NodeClassObject, false)
	require.NoError(t, err)
	return refs
}

func TestAddModelParts(t *testing.T) {
	srv := newServer(t)
	ns, err := fxserver.AddModel(srv, fxserver.ModelAC)
	require.NoError(t, err)
	assert.NotZero(t, ns.AC)
	assert.Zero(t, ns.CM)
	assert.Equal(t, -1, index(srv, fxcmid.NamespaceURI))

	srv = newServer(t)
	ns, err = fxserver.AddModel(srv, fxserver.ModelCM)
	require.NoError(t, err)
	assert.Zero(t, ns.AC)
	assert.NotZero(t, ns.CM)

	_, err = fxserver.AddModel(newServer(t), fxserver.Model(8))
	assert.ErrorIs(t, err, fxserver.ErrModel)
}

// TestAddModelDI checks that a DI namespace the server has already is
// used, not imported a second time.
func TestAddModelDI(t *testing.T) {
	srv := newServer(t)
	di := server.NewNodeNameSpace(srv, diid.NamespaceURI)
	ns, err := fxserver.AddModel(srv, fxserver.ModelAC)
	require.NoError(t, err)
	assert.Equal(t, di.ID(), ns.DI)
	n := 0
	for _, s := range srv.Namespaces() {
		if s.Name() == diid.NamespaceURI {
			n++
		}
	}
	assert.Equal(t, 1, n)
}

func TestImportNodeSetErrors(t *testing.T) {
	srv := newServer(t)
	err := fxserver.ImportNodeSet(srv, []byte(`<UANodeSet><NamespaceUris><Uri>urn:a</Uri></NamespaceUris><UAObject NodeId="ns=2;i=1" BrowseName="1:X"/></UANodeSet>`))
	assert.Error(t, err, "index outside the table of the document")

	err = fxserver.ImportNodeSet(srv, []byte(`<UANodeSet><`))
	assert.Error(t, err)
}
