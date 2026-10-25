// SPDX-License-Identifier: MIT

package server_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// TestEndPoint_IPv6Loopback serves on the IPv6 loopback address given as
// EndPoint("::1", 0) and connects a client to the endpoint URL it advertises.
func TestEndPoint_IPv6Loopback(t *testing.T) {
	t.Parallel()
	l, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	_ = l.Close()

	srv, err := server.New(
		server.EndPoint("::1", 0),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
	)
	require.NoError(t, err)
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })

	want := fmt.Sprintf("opc.tcp://[::1]:%d", srv.Port())
	require.Equal(t, []string{want}, srv.URLs())
	eps := srv.Endpoints()
	require.NotEmpty(t, eps)
	require.Equal(t, want, eps[0].EndpointURL)

	c := testutil.NewTestClient(t, eps[0].EndpointURL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dv, err := c.ReadValue(ctx, ua.NewNumericNodeID(0, id.ServerServerStatusState))
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, dv.Status)
}
