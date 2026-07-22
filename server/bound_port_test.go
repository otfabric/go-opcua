// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"fmt"
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestRewriteOPCURLPort(t *testing.T) {
	require.Equal(t, "opc.tcp://host.docker.internal:4840", rewriteOPCURLPort("opc.tcp://host.docker.internal:0", 4840))
	require.Equal(t, "opc.tcp://0.0.0.0:5555", rewriteOPCURLPort("opc.tcp://0.0.0.0:0", 5555))
	require.Equal(t, "opc.tcp://localhost:4840/path", rewriteOPCURLPort("opc.tcp://localhost:0/path", 4840))
	require.Equal(t, "opc.tcp://localhost:4840", rewriteOPCURLPort("opc.tcp://localhost:4840", 9999))
	require.Equal(t, "opc.tcp://localhost:1234", rewriteOPCURLPort("opc.tcp://localhost", 1234))
}

func TestServer_ListenPortZero_AssignsConcretePort(t *testing.T) {
	s, err := New(
		ListenOn("127.0.0.1:0"),
		EndPoint("127.0.0.1", 0),
		EnableSecurity("None", ua.MessageSecurityModeNone),
		EnableAuthMode(ua.UserTokenTypeAnonymous),
	)
	require.NoError(t, err)
	require.NoError(t, s.Start(context.Background()))
	t.Cleanup(func() { _ = s.Close() })

	port := s.Port()
	require.NotZero(t, port)
	require.Equal(t, []string{fmt.Sprintf("opc.tcp://127.0.0.1:%d", port)}, s.URLs())
}
