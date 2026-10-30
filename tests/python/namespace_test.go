//go:build integration

// SPDX-License-Identifier: MIT

package uatest

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua"
	"github.com/stretchr/testify/require"
)

func TestNamespace(t *testing.T) {
	ctx := context.Background()

	srv := NewPythonServer("rw_server.py")
	defer func() { _ = srv.Close() }()

	c, err := opcua.NewClient(srv.Endpoint, append([]opcua.Option{opcua.InsecureNoSecurity()}, srv.Opts...)...)
	require.NoError(t, err, "NewClient failed")

	err = c.Connect(ctx)
	require.NoError(t, err, "Connect failed")
	defer func() { _ = c.Close(ctx) }()

	t.Run("NamespaceArray", func(t *testing.T) {
		got, err := c.NamespaceArray(ctx)
		require.NoError(t, err, "NamespaceArray failed")

		want := []string{
			"http://opcfoundation.org/UA/",
			"urn:freeopcua:python:server",
			"http://otfabric.com/",
		}
		require.Equal(t, want, got)
	})
	t.Run("FindNamespace", func(t *testing.T) {
		ns, err := c.FindNamespace(ctx, "http://otfabric.com/")
		require.NoError(t, err, "FindNamespace failed")
		require.Equal(t, uint16(2), ns, "namespace id not equal")
	})
	t.Run("UpdateNamespaces", func(t *testing.T) {
		err := c.UpdateNamespaces(ctx)
		require.NoError(t, err, "UpdateNamespaces failed")
	})
}
