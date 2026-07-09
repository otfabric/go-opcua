// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestDefaultAccessController_AllowsAll(t *testing.T) {
	ac := DefaultAccessController{}
	nid := ua.NewNumericNodeID(0, 85)
	ctx := context.Background()

	require.Equal(t, ua.StatusOK, ac.CheckRead(ctx, nil, nid))
	require.Equal(t, ua.StatusOK, ac.CheckWrite(ctx, nil, nid))
	require.Equal(t, ua.StatusOK, ac.CheckBrowse(ctx, nil, nid))
	require.Equal(t, ua.StatusOK, ac.CheckCall(ctx, nil, nid))
}

func TestWithAccessController(t *testing.T) {
	deny := DefaultAccessController{}
	srv, err := New(WithAccessController(deny))
	require.NoError(t, err)
	require.NotNil(t, srv)
}
