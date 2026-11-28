// SPDX-License-Identifier: MIT

package fxserver_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil/fxtest"
	"github.com/otfabric/go-opcua/pubsub/sks"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxserver"
)

// TestConnectionsSecurityKeys: SecurityKeys needs a Dial; with one the
// Connections pull the keys of their secured groups until Close (the pull
// itself: uafx/fxcm TestSKSE2E).
func TestConnectionsSecurityKeys(t *testing.T) {
	t.Parallel()
	srv := newServer(t, server.WithPubSub(nil))
	ns, _, err := fxtest.PrepareConnections(srv)
	require.NoError(t, err)
	opts := fxserver.ConnectionOptions{Logger: slog.New(slog.DiscardHandler), SecurityKeys: &sks.PullerOptions{}}
	_, err = fxserver.EnableConnections(srv, ns, opts)
	require.ErrorIs(t, err, fxserver.ErrConnections)
	assert.ErrorContains(t, err, "SecurityKeys without a Dial")
	opts.SecurityKeys.Dial = func(context.Context, *ua.EndpointDescription) (*opcua.Client, error) {
		return nil, errors.New("no SKS")
	}
	c, err := fxserver.EnableConnections(srv, ns, opts)
	require.NoError(t, err)
	require.NoError(t, c.Close())
}
