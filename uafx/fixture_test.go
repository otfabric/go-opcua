// SPDX-License-Identifier: MIT

package uafx

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxserver"
)

// The helpers of this file are exported to the tests of package uafx_test.

// TestNS is the namespace of testdata/automation_component.xml.
const TestNS = "urn:go-opcua:uafx:test"

// NewTestServer returns a server, not started, with a None endpoint and an
// application namespace, so that the UAFX namespaces added after it have
// indexes that differ from those of the NodeSet documents.
func NewTestServer(t *testing.T) *server.Server {
	t.Helper()
	srv, err := server.New(
		server.EndPoint("localhost", 0),
		server.InsecureNoSecurity(),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
	)
	require.NoError(t, err)
	server.NewNodeNameSpace(srv, "urn:go-opcua:uafx:application")
	return srv
}

// StartTestServer starts srv and returns a client connected to it.
func StartTestServer(t *testing.T, srv *server.Server) *opcua.Client {
	t.Helper()
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })
	return testutil.NewTestClient(t, fmt.Sprintf("opc.tcp://localhost:%d", srv.Port()))
}

// FXTestServer starts a server with the UAFX model of models and, unless
// bare, the test AutomationComponents with their structure values.
func FXTestServer(t *testing.T, bare bool, models ...fxserver.Model) (*server.Server, *opcua.Client, fxserver.Namespaces) {
	t.Helper()
	srv := NewTestServer(t)
	ns, err := fxserver.AddModel(srv, models...)
	require.NoError(t, err)
	if !bare {
		require.NoError(t, fxserver.ImportNodeSet(srv, ReadFixture(t)))
		test := NSIndex(t, srv, TestNS)
		SetValue(t, srv, ua.NewNumericNodeID(test, 1004), &ua.ExtensionObject{
			TypeID:       ua.NewNumericExpandedNodeID(ns.AC, fxacid.AggregatedHealthDataTypeEncodingDefaultBinary),
			EncodingMask: ua.ExtensionObjectBinary,
			Value:        []byte{0x04, 0x00, 0x00, 0x00, 0x01, 0x00}, // DeviceMaintenanceRequired, OperationalWarning
		})
		SetValue(t, srv, ua.NewNumericNodeID(test, 1203), &ua.ExtensionObject{
			TypeID:       ua.NewNumericExpandedNodeID(ns.AC, fxacid.FxVersionEncodingDefaultBinary),
			EncodingMask: ua.ExtensionObjectBinary,
			Value:        []byte{1, 0, 2, 0, 3, 0, 4, 0},
		})
	}
	return srv, StartTestServer(t, srv), ns
}

// ReadFixture returns testdata/automation_component.xml.
func ReadFixture(t *testing.T) []byte {
	t.Helper()
	doc, err := os.ReadFile("testdata/automation_component.xml")
	require.NoError(t, err)
	return doc
}

// NSIndex returns the index of the namespace uri on srv.
func NSIndex(t *testing.T, srv *server.Server, uri string) uint16 {
	t.Helper()
	var idx uint16
	for _, ns := range srv.Namespaces() {
		if ns.Name() == uri {
			return idx
		}
		idx++
	}
	t.Fatalf("no namespace %s", uri)
	return 0
}

// SetValue sets the Value of the node nid of srv to v.
func SetValue(t *testing.T, srv *server.Server, nid *ua.NodeID, v any) {
	t.Helper()
	n := srv.Node(nid)
	require.NotNil(t, n, "node %v", nid)
	require.NoError(t, n.SetAttribute(ua.AttributeIDValue, &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)}))
}
