// SPDX-License-Identifier: MIT

package opcua_test

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestPackageFindServers(t *testing.T) {
	_, url := testutil.NewTestServer(t)
	servers, err := opcua.FindServers(context.Background(), url)
	require.NoError(t, err)
	require.NotEmpty(t, servers)
}

func TestPackageGetEndpoints(t *testing.T) {
	_, url := testutil.NewTestServer(t)
	eps, err := opcua.GetEndpoints(context.Background(), url)
	require.NoError(t, err)
	require.NotEmpty(t, eps)
}

func TestPackageFindServersOnNetwork(t *testing.T) {
	_, url := testutil.NewTestServer(t)
	_, err := opcua.FindServersOnNetwork(context.Background(), url)
	require.Error(t, err)
	require.ErrorIs(t, err, ua.StatusBadServiceUnsupported)
}
