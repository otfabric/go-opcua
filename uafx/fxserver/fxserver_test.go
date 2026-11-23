// SPDX-License-Identifier: MIT

package fxserver_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/di/diid"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxcmid"
	"github.com/otfabric/go-opcua/uafx/fxdataid"
	"github.com/otfabric/go-opcua/uafx/fxserver"
	"github.com/otfabric/go-opcua/uafx/internal/model"
)

// appURI is the ApplicationUri of the servers of the tests.
const appURI = "urn:go-opcua:fxserver:test"

func newServer(t *testing.T, opts ...server.Option) *server.Server {
	t.Helper()
	srv, err := server.New(append([]server.Option{
		server.EndPoint("localhost", 0),
		server.InsecureNoSecurity(),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.ApplicationURI(appURI),
	}, opts...)...)
	require.NoError(t, err)
	return srv
}

// start starts srv and returns a client connected to it.
func start(t *testing.T, srv *server.Server) *opcua.Client {
	t.Helper()
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })
	return testutil.NewTestClient(t, fmt.Sprintf("opc.tcp://localhost:%d", srv.Port()))
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
	c := start(t, srv)
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

// TestAddModelLocalNamespace checks that namespace 1 of the server, as a
// client reads the NamespaceArray, is the namespace of the local server
// (Part 81 §14.2), named by the ApplicationUri when AddModel adds it.
func TestAddModelLocalNamespace(t *testing.T) {
	srv := newServer(t)
	ns, err := fxserver.AddModel(srv)
	require.NoError(t, err)
	assert.Equal(t, fxserver.Namespaces{DI: 2, Data: 3, AC: 4, CM: 5}, ns)
	arr, err := start(t, srv).NamespaceArray(context.Background())
	require.NoError(t, err)
	require.Greater(t, len(arr), 5)
	assert.Equal(t, []string{"http://opcfoundation.org/UA/", appURI, diid.NamespaceURI, fxdataid.NamespaceURI, fxacid.NamespaceURI, fxcmid.NamespaceURI}, arr[:6])

	// No ApplicationUri to name it: an error, and nothing imported.
	srv, err = server.New(server.EndPoint("localhost", 0), server.InsecureNoSecurity())
	require.NoError(t, err)
	_, err = fxserver.AddModel(srv)
	assert.ErrorIs(t, err, fxserver.ErrModel)
	assert.Len(t, srv.Namespaces(), 1)

	// DI imported first takes index 1, which belongs to the local server.
	srv = newServer(t)
	require.NoError(t, fxserver.ImportNodeSet(srv, model.DI))
	_, err = fxserver.AddModel(srv)
	assert.ErrorIs(t, err, fxserver.ErrModel)
	assert.ErrorContains(t, err, "namespace 1")
	assert.Equal(t, -1, index(srv, fxdataid.NamespaceURI))
}

// TestAddModelDI checks that a complete DI namespace the server has
// already is used, not imported a second time, with the UAFX types
// deriving from its types, and that an incomplete one is refused.
func TestAddModelDI(t *testing.T) {
	srv := newServer(t)
	server.NewNodeNameSpace(srv, appURI)
	require.NoError(t, fxserver.ImportNodeSet(srv, model.DI))
	di := uint16(index(srv, diid.NamespaceURI))
	ns, err := fxserver.AddModel(srv, fxserver.ModelAC)
	require.NoError(t, err)
	assert.Equal(t, di, ns.DI)
	n := 0
	for _, s := range srv.Namespaces() {
		if s.Name() == diid.NamespaceURI {
			n++
		}
	}
	assert.Equal(t, 1, n)

	// The type hierarchy reaches into DI: ConfigurationDataFolderType is a
	// FunctionalGroupType, FxAssetType has the DI nameplate interfaces.
	c := start(t, srv)
	ctx := context.Background()
	super, err := c.Node(ua.NewNumericNodeID(ns.AC, fxacid.ConfigurationDataFolderType)).References(ctx, id.HasSubtype, ua.BrowseDirectionInverse, ua.NodeClassObjectType, false)
	require.NoError(t, err)
	require.Len(t, super, 1)
	assert.Equal(t, ua.NewNumericNodeID(di, diid.FunctionalGroupType).String(), super[0].NodeID.NodeID.String())
	ifaces, err := c.Node(ua.NewNumericNodeID(ns.AC, fxacid.FxAssetType)).References(ctx, id.HasInterface, ua.BrowseDirectionForward, ua.NodeClassObjectType, false)
	require.NoError(t, err)
	var got []string
	for _, r := range ifaces {
		got = append(got, r.NodeID.NodeID.String())
	}
	assert.Subset(t, got, []string{
		ua.NewNumericNodeID(di, diid.IDeviceHealthType).String(),
		ua.NewNumericNodeID(di, diid.ITagNameplateType).String(),
		ua.NewNumericNodeID(di, diid.IVendorNameplateType).String(),
	})

	// An empty DI namespace lacks the nodes the model refers to.
	srv = newServer(t)
	server.NewNodeNameSpace(srv, appURI)
	server.NewNodeNameSpace(srv, diid.NamespaceURI)
	_, err = fxserver.AddModel(srv, fxserver.ModelAC)
	assert.ErrorIs(t, err, fxserver.ErrModel)
	assert.ErrorContains(t, err, fmt.Sprintf("i=%d", diid.FunctionalGroupType))
	assert.Equal(t, -1, index(srv, fxdataid.NamespaceURI), "nothing imported")

	// A DI node of the wrong NodeClass.
	srv = newServer(t)
	server.NewNodeNameSpace(srv, appURI)
	dins := server.NewNodeNameSpace(srv, diid.NamespaceURI)
	dins.AddNode(server.NewVariableNode(ua.NewNumericNodeID(dins.ID(), diid.FunctionalGroupType), "FunctionalGroupType", int32(0)))
	_, err = fxserver.AddModel(srv, fxserver.ModelAC)
	assert.ErrorIs(t, err, fxserver.ErrModel)
	assert.ErrorContains(t, err, fmt.Sprintf("i=%d (a ", diid.FunctionalGroupType))
}

func TestImportNodeSetErrors(t *testing.T) {
	srv := newServer(t)
	err := fxserver.ImportNodeSet(srv, []byte(`<UANodeSet><NamespaceUris><Uri>urn:a</Uri></NamespaceUris><UAObject NodeId="ns=2;i=1" BrowseName="1:X"/></UANodeSet>`))
	assert.Error(t, err, "index outside the table of the document")

	err = fxserver.ImportNodeSet(srv, []byte(`<UANodeSet><`))
	assert.Error(t, err)
}
