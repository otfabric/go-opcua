// SPDX-License-Identifier: MIT

package opcua_test

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// TestTransports runs the same session over opc.tcp, opc.wss and opc.https:
// read, write, browse and a subscription whose data changes arrive.
func TestTransports(t *testing.T) {
	t.Parallel()
	srv, urls := testutil.NewTransportTestServer(t)
	f := testutil.AddFixture(t, srv)

	for i, url := range []string{urls.TCP, urls.WSS, urls.HTTPS} {
		t.Run(url, func(t *testing.T) {
			ctx := context.Background()
			c := testutil.NewTransportTestClient(t, url)

			want := int32(100 + i)
			res, err := c.Write(ctx, &ua.WriteRequest{NodesToWrite: []*ua.WriteValue{{
				NodeID: f.Int32, AttributeID: ua.AttributeIDValue,
				Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(want)},
			}}})
			require.NoError(t, err)
			require.Equal(t, ua.StatusOK, res.Results[0])
			got, err := c.Node(f.Int32).Value(ctx)
			require.NoError(t, err)
			require.Equal(t, want, got.Value())

			v, err := c.Node(ua.NewNumericNodeID(0, id.ServerServerStatusState)).Value(ctx)
			require.NoError(t, err)
			require.Equal(t, int32(ua.ServerStateRunning), v.Value())

			refs, err := c.Node(ua.NewNumericNodeID(0, id.ObjectsFolder)).ReferencedNodes(ctx, id.HierarchicalReferences, ua.BrowseDirectionForward, ua.NodeClassAll, true)
			require.NoError(t, err)
			require.NotEmpty(t, refs)

			eps, err := c.GetEndpoints(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, eps.Endpoints)

			notifs := make(chan *opcua.PublishNotificationData, 16)
			sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 20 * time.Millisecond}, notifs)
			require.NoError(t, err)
			defer func() { _ = sub.Cancel(ctx) }()
			_, err = sub.Monitor(ctx, ua.TimestampsToReturnBoth, opcua.NewMonitoredItemCreateRequestWithDefaults(ua.NewNumericNodeID(0, id.ServerServerStatusCurrentTime), ua.AttributeIDValue, 1))
			require.NoError(t, err)
			select {
			case n := <-notifs:
				require.NoError(t, n.Error)
			case <-time.After(20 * time.Second):
				t.Fatal("no notification")
			}
		})
	}
}
