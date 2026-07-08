// SPDX-License-Identifier: MIT

package conformance

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// TestConcurrency_ManyClients drives one server with many concurrent clients,
// each performing a mix of reads, writes, browses and method calls. Run under
// the race detector (go test -race) to surface data races in the client/server
// stacks.
func TestConcurrency_ManyClients(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	f := testutil.AddFixture(t, srv)

	const (
		clients    = 8
		iterations = 25
	)

	// Create all clients up front on the main goroutine.
	cs := make([]*opcua.Client, clients)
	for i := range cs {
		cs[i] = testutil.NewTestClient(t, url)
	}

	ctx := context.Background()
	var wg sync.WaitGroup
	errCh := make(chan error, clients)

	for i := range cs {
		wg.Add(1)
		go func(c *opcua.Client) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				if _, err := c.ReadValue(ctx, f.Int32); err != nil {
					errCh <- err
					return
				}
				if _, err := c.WriteValue(ctx, f.Writable, &ua.DataValue{
					EncodingMask: ua.DataValueValue,
					Value:        ua.MustVariant(int32(j)),
				}); err != nil {
					errCh <- err
					return
				}
				if _, err := c.BrowseAll(ctx, f.MethodObject); err != nil {
					errCh <- err
					return
				}
				if _, err := c.CallMethod(ctx, f.MethodObject, f.SquareMethod, int32(j)); err != nil {
					errCh <- err
					return
				}
			}
		}(cs[i])
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}
}

// TestConcurrency_Subscriptions creates and tears down subscriptions from many
// clients concurrently.
func TestConcurrency_Subscriptions(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	f := testutil.AddFixture(t, srv)

	const clients = 6
	cs := make([]*opcua.Client, clients)
	for i := range cs {
		cs[i] = testutil.NewTestClient(t, url)
	}

	ctx := context.Background()
	var wg sync.WaitGroup
	errCh := make(chan error, clients)

	for i := range cs {
		wg.Add(1)
		go func(c *opcua.Client) {
			defer wg.Done()
			sub, _, err := c.NewSubscription().
				Interval(50 * time.Millisecond).
				Monitor(f.Int32).
				Start(ctx)
			if err != nil {
				errCh <- err
				return
			}
			time.Sleep(100 * time.Millisecond)
			if err := sub.Cancel(ctx); err != nil {
				errCh <- err
				return
			}
		}(cs[i])
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}
}
