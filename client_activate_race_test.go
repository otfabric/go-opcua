// SPDX-License-Identifier: MIT

package opcua_test

import (
	"context"
	"sync"
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// TestActivateSessionConcurrent activates the session of the client from
// several goroutines at once, as the reconnect logic and an application can:
// the activations of one session take turns (each one uses the nonce the
// previous one brought).
func TestActivateSessionConcurrent(t *testing.T) {
	t.Parallel()
	_, url := testutil.NewTestServer(t)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()
	s := c.Session()
	require.NotNil(t, s)

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() { errs <- c.ActivateSession(ctx, s) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.Same(t, s, c.Session())
	dv, err := c.ReadValue(ctx, ua.NewNumericNodeID(0, id.ServerServerStatusState))
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, dv.Status, "the session still serves requests")
}
