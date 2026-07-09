// SPDX-License-Identifier: MIT

package uacp

import (
	"context"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseEndpoint(t *testing.T) {
	cases := []struct {
		input   string
		network string
		u       *url.URL
		errStr  string
	}{
		{ // Valid, full EndpointURL with IP
			"opc.tcp://10.0.0.1:4840/foo/bar",
			"tcp",
			&url.URL{
				Scheme: "opc.tcp",
				Host:   "10.0.0.1:4840",
				Path:   "/foo/bar",
			},
			"",
		},
		{ // Valid, port number omitted
			"opc.tcp://10.0.0.1/foo/bar",
			"tcp",
			&url.URL{
				Scheme: "opc.tcp",
				Host:   "10.0.0.1:4840",
				Path:   "/foo/bar",
			},
			"",
		},
		{ // Valid, hostname preserved (no DNS lookup)
			"opc.tcp://www.example.com:4840/foo/bar",
			"tcp",
			&url.URL{
				Scheme: "opc.tcp",
				Host:   "www.example.com:4840",
				Path:   "/foo/bar",
			},
			"",
		},
		{ // Valid, IPv6 literal
			"opc.tcp://[::1]:4840/foo/bar",
			"tcp",
			&url.URL{
				Scheme: "opc.tcp",
				Host:   "[::1]:4840",
				Path:   "/foo/bar",
			},
			"",
		},
		{ // Invalid, missing host
			"opc.tcp://:4840/foo/bar",
			"",
			nil,
			"opcua: invalid endpoint: missing host",
		},
		{ // Invalid, zero port
			"opc.tcp://host:0/path",
			"",
			nil,
			`opcua: invalid endpoint: invalid port "0"`,
		},
		{ // Invalid, port out of range
			"opc.tcp://host:70000/path",
			"",
			nil,
			`opcua: invalid endpoint: invalid port "70000"`,
		},
		{ // Invalid, schema is not "opc.tcp"
			"tcp://10.0.0.1:4840/foo/bar",
			"",
			nil,
			`opcua: invalid endpoint: unsupported scheme "tcp"`,
		},
	}

	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			network, u, err := ParseEndpoint(c.input)
			if c.errStr != "" {
				require.EqualError(t, err, c.errStr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, c.network, network)
			require.Equal(t, c.u, u)
		})
	}
}

func TestEndpointMatch(t *testing.T) {
	cases := []struct {
		client string
		server string
		match  bool
	}{
		// Normal case: identical hostnames.
		{
			client: "opc.tcp://localhost:4840/opcua-interop",
			server: "opc.tcp://localhost:4840/opcua-interop",
			match:  true,
		},
		// Wildcard IPv4: 0.0.0.0 accepts any client hostname.
		{
			client: "opc.tcp://localhost:4840/opcua-interop",
			server: "opc.tcp://0.0.0.0:4840/opcua-interop",
			match:  true,
		},
		// Wildcard IPv6 compressed form: [::] accepts any client hostname.
		{
			client: "opc.tcp://127.0.0.1:4840/opcua-interop",
			server: "opc.tcp://[::]:4840/opcua-interop",
			match:  true,
		},
		// Wildcard IPv6 full form: 0:0:0:0:0:0:0:0 also accepted.
		{
			client: "opc.tcp://host.docker.internal:4840/opcua-interop",
			server: "opc.tcp://[0:0:0:0:0:0:0:0]:4840/opcua-interop",
			match:  true,
		},
		// Path mismatch with wildcard host is still rejected.
		{
			client: "opc.tcp://localhost:4840/wrong",
			server: "opc.tcp://0.0.0.0:4840/opcua-interop",
			match:  false,
		},
		// Port mismatch with wildcard host is rejected.
		{
			client: "opc.tcp://localhost:4841/opcua-interop",
			server: "opc.tcp://0.0.0.0:4840/opcua-interop",
			match:  false,
		},
		// Non-wildcard hostname: different hosts are rejected.
		{
			client: "opc.tcp://other-host:4840/opcua-interop",
			server: "opc.tcp://expected-host:4840/opcua-interop",
			match:  false,
		},
		// Scheme mismatch.
		{
			client: "opc.tcp://localhost:4840/path",
			server: "opc.https://localhost:4840/path",
			match:  false,
		},
	}

	for _, c := range cases {
		t.Run(c.client+"_vs_"+c.server, func(t *testing.T) {
			got := endpointMatch(c.client, c.server)
			require.Equal(t, c.match, got)
		})
	}
}

func TestDialTCP(t *testing.T) {
	t.Run("invalid endpoint returns error", func(t *testing.T) {
		conn, err := DialTCP(context.Background(), "tcp://127.0.0.1:4840")
		require.Error(t, err)
		require.Nil(t, conn)
	})
	t.Run("valid format dial attempts connection", func(t *testing.T) {
		// Port likely closed; either connection refused or (rarely) something listening
		conn, err := DialTCP(context.Background(), "opc.tcp://127.0.0.1:59999")
		if err != nil {
			require.Nil(t, conn)
			return
		}
		_ = conn.Close()
	})
}
