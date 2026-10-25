// SPDX-License-Identifier: MIT

package opcua_test

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/stretchr/testify/require"
)

// A client that re-fetches the endpoints of its server (it does so when the
// server certificate was replaced) must do it the way it connects: over a
// reverse connection, since it cannot reach the server otherwise.
func TestReverseConnectRefetchEndpoints(t *testing.T) {
	t.Parallel()
	const appURI = "urn:otfabric:test:reverse"
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	l, err := uacp.ListenReverse(ctx, "127.0.0.1:0", nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })

	srv, _ := testutil.NewTestServer(t,
		server.ApplicationURI(appURI),
		server.WithReverseConnect("opc.tcp://"+l.Addr().String(),
			server.ReverseConnectRetryInterval(20*time.Millisecond, 200*time.Millisecond)),
	)

	// The client knows no address of the server at all.
	c, err := opcua.NewClient("",
		opcua.ReverseConnectListener(l, opcua.ReverseServerURI(appURI)),
		opcua.SecurityMode(ua.MessageSecurityModeNone),
		opcua.DialTimeout(30*time.Second),
		opcua.AutoReconnect(false),
	)
	require.NoError(t, err)
	require.NoError(t, c.Connect(ctx))
	t.Cleanup(func() { _ = c.Close(context.Background()) })

	require.NoError(t, c.TestingRefetchEndpoints(ctx))

	// Both the session and the discovery ran over connections the server
	// opened.
	rc := srv.ReverseConnects()[0]
	require.Equal(t, server.ReverseConnectConnected, rc.State())
	require.NoError(t, rc.Err())
}
