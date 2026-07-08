// SPDX-License-Identifier: MIT

package opcua_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/stretchr/testify/require"
)

// TestConcurrentReads starts a server with test nodes and reads them
// from multiple goroutines concurrently. Run with -race to detect
// data races.
func TestConcurrentReads(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	ns := testutil.AddTestNodes(t, srv)

	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	nsID := ns.ID()
	nodeNames := []string{"IntVar", "FloatVar", "StringVar"}

	const goroutines = 10
	const iterations = 20

	var wg sync.WaitGroup
	wg.Add(goroutines)
	errs := make(chan error, goroutines*iterations)

	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				name := nodeNames[i%len(nodeNames)]
				nodeID := ua.NewStringNodeID(nsID, name)
				resp, err := c.Read(ctx, &ua.ReadRequest{
					NodesToRead: []*ua.ReadValueID{
						{NodeID: nodeID, AttributeID: ua.AttributeIDValue},
					},
					TimestampsToReturn: ua.TimestampsToReturnBoth,
				})
				if err != nil {
					errs <- err
					return
				}
				if resp.Results[0].Status != ua.StatusOK {
					errs <- resp.Results[0].Status
					return
				}
			}
		}()
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent read error: %v", err)
	}
}

// TestConcurrentSubscriptions creates and cancels subscriptions from
// multiple goroutines. Run with -race to detect data races.
func TestConcurrentSubscriptions(t *testing.T) {
	_, url := testutil.NewTestServer(t)

	const goroutines = 5

	var wg sync.WaitGroup
	wg.Add(goroutines)
	errs := make(chan error, goroutines)

	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			ctx := context.Background()

			c, err := opcua.NewClient(url,
				opcua.SecurityMode(ua.MessageSecurityModeNone),
				opcua.Dialer(&uacp.Dialer{
					Dialer: &net.Dialer{},
					ClientACK: &uacp.Acknowledge{
						ReceiveBufSize: uacp.DefaultReceiveBufSize,
						SendBufSize:    uacp.DefaultSendBufSize,
					},
				}),
			)
			if err != nil {
				errs <- err
				return
			}
			if err := c.Connect(ctx); err != nil {
				errs <- err
				return
			}
			defer func() { _ = c.Close(ctx) }()

			notifyCh := make(chan *opcua.PublishNotificationData, 16)
			sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{
				Interval: 100 * time.Millisecond,
			}, notifyCh)
			if err != nil {
				errs <- err
				return
			}

			// Keep the subscription alive briefly then cancel.
			time.Sleep(200 * time.Millisecond)
			if err := sub.Cancel(ctx); err != nil {
				errs <- err
				return
			}
		}()
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent subscription error: %v", err)
	}
}

// TestReconnectDuringOperation closes the server while reads are in-flight
// and checks that the client reports an error rather than hanging or panicking.
func TestReconnectDuringOperation(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	ns := testutil.AddTestNodes(t, srv)
	nsID := ns.ID()

	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	// Verify the connection works first.
	resp, err := c.Read(ctx, &ua.ReadRequest{
		NodesToRead: []*ua.ReadValueID{
			{NodeID: ua.NewStringNodeID(nsID, "IntVar"), AttributeID: ua.AttributeIDValue},
		},
		TimestampsToReturn: ua.TimestampsToReturnBoth,
	})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, resp.Results[0].Status)

	// Close the server while the client is still connected.
	_ = srv.Close()

	// Give the server a moment to fully shut down.
	time.Sleep(500 * time.Millisecond)

	// Reads after server closure should return an error, not hang.
	readCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err = c.Read(readCtx, &ua.ReadRequest{
		NodesToRead: []*ua.ReadValueID{
			{NodeID: ua.NewStringNodeID(nsID, "IntVar"), AttributeID: ua.AttributeIDValue},
		},
		TimestampsToReturn: ua.TimestampsToReturnBoth,
	})
	// We expect an error (connection closed, timeout, etc.).
	require.Error(t, err, "expected error reading from closed server")
}
