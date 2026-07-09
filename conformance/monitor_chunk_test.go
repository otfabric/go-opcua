// SPDX-License-Identifier: MIT

package conformance

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/monitor"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/stretchr/testify/require"
)

func TestSubscription_MonitorPartialBatch(t *testing.T) {
	c, f, ctx := setup(t)

	sub, _, err := c.NewSubscription().Interval(100 * time.Millisecond).Start(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	resp, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth,
		opcua.NewMonitoredItemCreateRequestWithDefaults(f.Int32, ua.AttributeIDValue, 1),
		opcua.NewMonitoredItemCreateRequestWithDefaults(
			ua.NewStringNodeID(f.NSIndex, "ghost-monitor"), ua.AttributeIDValue, 2),
		opcua.NewMonitoredItemCreateRequestWithDefaults(f.Double, ua.AttributeIDValue, 3),
	)
	require.NoError(t, err)
	require.Len(t, resp.Results, 3)
	require.Equal(t, ua.StatusOK, resp.Results[0].StatusCode)
	require.Equal(t, ua.StatusBadNodeIDUnknown, resp.Results[1].StatusCode)
	require.Equal(t, ua.StatusOK, resp.Results[2].StatusCode)
}

func TestMonitor_ItemErrorPartialBatch(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	f := testutil.AddFixture(t, srv)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	m, err := monitor.NewNodeMonitor(c)
	require.NoError(t, err)

	sub, err := m.ChanSubscribe(ctx, &opcua.SubscriptionParameters{
		Interval: 100 * time.Millisecond,
	}, make(chan *monitor.DataChangeMessage, 8))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Unsubscribe(ctx) })

	items, err := sub.AddMonitorItems(ctx,
		monitor.Request{NodeID: f.Int32},
		monitor.Request{NodeID: ua.NewStringNodeID(f.NSIndex, "ghost-monitor")},
		monitor.Request{NodeID: f.Double},
	)
	require.Len(t, items, 2, "valid nodes should still be monitored")
	require.Error(t, err)

	var itemErr *monitor.ItemError
	require.True(t, errors.As(err, &itemErr))
	require.Equal(t, ua.StatusBadNodeIDUnknown, itemErr.StatusCode)
	require.Equal(t, ua.NewStringNodeID(f.NSIndex, "ghost-monitor").String(), itemErr.NodeID.String())
}

func TestView_BrowseLargeResponseMultiChunk(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	f := testutil.AddFixture(t, srv)

	// A small receive buffer forces the server to negotiate a smaller send buffer
	// and split large Browse responses across multiple chunks.
	c := testutil.NewTestClientWithACK(t, url, &uacp.Acknowledge{
		ReceiveBufSize: 2048,
		SendBufSize:    uacp.DefaultSendBufSize,
		MaxChunkCount:  0,
		MaxMessageSize: 0,
	})
	ctx := context.Background()

	// The fixture object folder has many children; browsing it exercises the
	// server's multi-chunk response path.
	root := c.Node(f.MethodObject)
	refs, err := root.References(ctx, 0, ua.BrowseDirectionForward, ua.NodeClassAll, true)
	require.NoError(t, err)
	require.NotEmpty(t, refs, "large browse response should succeed over multi-chunk transport")
}
