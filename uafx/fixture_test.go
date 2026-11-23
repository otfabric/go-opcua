// SPDX-License-Identifier: MIT

package uafx

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/fxtest"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxserver"
)

// The helpers of this file are exported to the tests of package uafx_test.

// TestNS is the namespace of the test NodeSet (internal/testutil/fxtest).
const TestNS = fxtest.NS

// NewTestServer returns a server, not started, with a None endpoint and the
// ApplicationUri of fxtest, which AddModel makes namespace 1, so that the
// UAFX namespaces added after it have indexes that differ from those of the
// NodeSet documents.
func NewTestServer(t *testing.T) *server.Server {
	t.Helper()
	srv, err := server.New(
		server.EndPoint("localhost", 0),
		server.InsecureNoSecurity(),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.ApplicationURI(fxtest.AppNS),
	)
	require.NoError(t, err)
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
	ns, err := fxtest.Prepare(srv, bare, models...)
	require.NoError(t, err)
	return srv, StartTestServer(t, srv), ns
}

// ReadFixture returns the test NodeSet.
func ReadFixture(t *testing.T) []byte {
	t.Helper()
	return fxtest.NodeSet()
}

// NSIndex returns the index of the namespace uri on srv.
func NSIndex(t *testing.T, srv *server.Server, uri string) uint16 {
	t.Helper()
	idx, ok := fxtest.Index(srv, uri)
	if !ok {
		t.Fatalf("no namespace %s", uri)
	}
	return idx
}

// SetValue sets the Value of the node nid of srv to v.
func SetValue(t *testing.T, srv *server.Server, nid *ua.NodeID, v any) {
	t.Helper()
	require.NoError(t, fxtest.SetValue(srv, nid, v))
}
