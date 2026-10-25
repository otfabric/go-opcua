// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEndpointURL(t *testing.T) {
	cases := []struct {
		scheme, host string
		port         int
		want         string
	}{
		{"opc.tcp", "localhost", 4840, "opc.tcp://localhost:4840"},
		{"opc.tcp", "127.0.0.1", 0, "opc.tcp://127.0.0.1:0"},
		{"opc.tcp", "::1", 4840, "opc.tcp://[::1]:4840"},
		{"opc.tcp", "[::1]", 4840, "opc.tcp://[::1]:4840"},
		{"opc.tcp", "::", 0, "opc.tcp://[::]:0"},
		{"opc.tcp", "fe80::1%eth0", 4840, "opc.tcp://[fe80::1%25eth0]:4840"},
		{"opc.tcp", "[fe80::1%25eth0]", 4840, "opc.tcp://[fe80::1%25eth0]:4840"},
		{"opc.wss", "::1", 443, "opc.wss://[::1]:443"},
		{"opc.https", "fe80::1%en0", 4843, "opc.https://[fe80::1%25en0]:4843"},
	}
	for _, c := range cases {
		require.Equal(t, c.want, endpointURL(c.scheme, c.host, c.port), c.host)
	}
}

func TestEndPoint_IPv6Options(t *testing.T) {
	cfg := &serverConfig{}
	require.NoError(t, EndPoint("::1", 4840)(cfg))
	require.NoError(t, EndPoint("fe80::1%eth0", 4841)(cfg))
	require.NoError(t, WebSocketEndPoint("::1", 4843)(cfg))
	require.NoError(t, HTTPSEndPoint("[::1]", 4844)(cfg))
	require.Equal(t, []string{"opc.tcp://[::1]:4840", "opc.tcp://[fe80::1%25eth0]:4841"}, cfg.endpoints)
	require.Equal(t, []string{"opc.wss://[::1]:4843"}, cfg.wss.endpoints)
	require.Equal(t, []string{"opc.https://[::1]:4844"}, cfg.https.endpoints)

	// The bind address of a zoned endpoint keeps the zone.
	tc := transportConfig{endpoints: []string{"opc.wss://[fe80::1%25eth0]:4843"}}
	addr, err := tc.bindAddr()
	require.NoError(t, err)
	require.Equal(t, "[fe80::1%eth0]:4843", addr)
	require.Equal(t, "opc.tcp://[::1]:5555", rewriteOPCURLPort("opc.tcp://[::1]:0", 5555))
	require.Equal(t, "opc.tcp://[fe80::1%25eth0]:5555", rewriteOPCURLPort("opc.tcp://[fe80::1%25eth0]:0", 5555))
}
