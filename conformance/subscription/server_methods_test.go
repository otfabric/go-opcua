// SPDX-License-Identifier: MIT

package subscription

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/cleanup"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uamethod"
)

// TestServerMethods_GetMonitoredItems: the serverHandles and clientHandles
// of every MonitoredItem of the subscription (OPC 10000-5 §9.1), for the
// session that owns it only.
func TestServerMethods_GetMonitoredItems(t *testing.T) {
	c, f, url := rawSetup(t)
	ctx := context.Background()
	sub := newRawSub(t, c, rawSubParams{})

	empty, err := c.GetMonitoredItems(ctx, sub.id)
	require.NoError(t, err)
	require.Empty(t, empty.ServerHandles)
	require.Empty(t, empty.ClientHandles)

	ids := sub.mustCreateItems(ua.TimestampsToReturnNeither,
		itemSpec{node: f.Int32, handle: 11},
		itemSpec{node: f.Double, handle: 12, modeSet: true, mode: ua.MonitoringModeSampling},
		itemSpec{node: f.EventObject, attr: ua.AttributeIDEventNotifier, handle: 13, queue: 5, filter: eventFilter([]string{"Message"})},
	)
	got, err := c.GetMonitoredItems(ctx, sub.id)
	require.NoError(t, err)
	require.Equal(t, ids, got.ServerHandles)
	require.Equal(t, []uint32{11, 12, 13}, got.ClientHandles)

	// The declaration of ServerType called on the Server Object.
	got, err = uamethod.CallServerTypeGetMonitoredItems(ctx, c, ua.NewNumericNodeID(0, id.Server), nil,
		&uamethod.ServerTypeGetMonitoredItemsInput{SubscriptionID: sub.id})
	require.NoError(t, err)
	require.Equal(t, ids, got.ServerHandles)

	_, err = c.GetMonitoredItems(ctx, sub.id+1000)
	require.ErrorIs(t, err, ua.StatusBadSubscriptionIDInvalid)
	_, err = newClient(t, url).GetMonitoredItems(ctx, sub.id)
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied, "another session")
}

// TestServerMethods_ResendData: after ResendData the next Publish response
// carries the last value sent of every data item in Reporting mode, or its
// queued value, and nothing for the items in Sampling mode and the event
// items (OPC 10000-4 §6.7).
func TestServerMethods_ResendData(t *testing.T) {
	c, f, url := rawSetup(t)
	ctx := context.Background()
	sub := newRawSub(t, c, rawSubParams{keepAlive: 1})
	sub.mustCreateItems(ua.TimestampsToReturnNeither,
		itemSpec{node: f.Int32, handle: 1, queue: 5, discard: true},
		itemSpec{node: f.Double, handle: 2, queue: 5, discard: true},
		itemSpec{node: f.String, handle: 3, modeSet: true, mode: ua.MonitoringModeSampling},
		itemSpec{node: f.EventObject, attr: ua.AttributeIDEventNotifier, handle: 4, queue: 5, filter: eventFilter([]string{"Message"})},
	)
	require.ElementsMatch(t, []uint32{1, 2}, handles(dataOf(t, publish(t, c))), "the initial values")
	require.True(t, isKeepAlive(publish(t, c)))

	require.NoError(t, c.ResendData(ctx, sub.id))
	p := publish(t, c)
	got := dataOf(t, p)
	require.ElementsMatch(t, []uint32{1, 2}, handles(got), "the last values sent, again")
	require.Equal(t, int32(42), got[indexOf(got, 1)].DV.Value.Value())
	require.True(t, isKeepAlive(publish(t, c)), "once")

	// A queued value is sent instead of the last one.
	writeInt32(t, c, f.Int32, 7)
	require.NoError(t, c.ResendData(ctx, sub.id))
	got = dataOf(t, publish(t, c))
	require.Equal(t, []any{int32(7)}, values(got[indexOf(got, 1):indexOf(got, 1)+1]))
	require.ElementsMatch(t, []uint32{1, 2}, handles(got))

	require.ErrorIs(t, c.ResendData(ctx, sub.id+1000), ua.StatusBadSubscriptionIDInvalid)
	require.ErrorIs(t, newClient(t, url).ResendData(ctx, sub.id), ua.StatusBadUserAccessDenied)
}

func indexOf(samples []dataChange, handle uint32) int {
	for i, s := range samples {
		if s.Handle == handle {
			return i
		}
	}
	return -1
}

// TestServerMethods_SetSubscriptionDurable: a durable subscription
// (OPC 10000-5 §9.3, OPC 10000-4 §6.8) has the LifetimeCount of its
// revisedLifetimeInHours, items with queues beyond those of other
// subscriptions and a ModifySubscription with a longer lifetime, and keeps
// its queue for the session that takes it over.
func TestServerMethods_SetSubscriptionDurable(t *testing.T) {
	c, f, url := rawSetup(t)
	ctx := context.Background()
	sub := newRawSub(t, c, rawSubParams{})

	hours, err := c.SetSubscriptionDurable(ctx, sub.id, 1)
	require.NoError(t, err)
	require.Equal(t, uint32(1), hours)
	hours, err = c.SetSubscriptionDurable(ctx, sub.id, 0)
	require.NoError(t, err)
	require.Equal(t, uint32(24), hours, "the highest lifetime of the server")

	res := sub.createItems(ua.TimestampsToReturnNeither, itemSpec{node: f.Int32, handle: 1, queue: 500, discard: true})
	require.Equal(t, ua.StatusOK, res[0].StatusCode)
	require.Equal(t, uint32(500), res[0].RevisedQueueSize, "a normal subscription has at most 100")
	_, err = c.SetSubscriptionDurable(ctx, sub.id, 1)
	require.ErrorIs(t, err, ua.StatusBadInvalidState, "after the first MonitoredItem")

	mod := mustSendRaw[ua.ModifySubscriptionResponse](t, c, &ua.ModifySubscriptionRequest{
		SubscriptionID: sub.id, RequestedPublishingInterval: sub.interval,
		RequestedLifetimeCount: 500_000, RequestedMaxKeepAliveCount: sub.keepAlive,
	})
	require.Equal(t, uint32(500_000), mod.RevisedLifetimeCount, "a normal subscription has at most 100000")

	// A normal subscription for comparison.
	normal := newRawSub(t, c, rawSubParams{})
	res = normal.createItems(ua.TimestampsToReturnNeither, itemSpec{node: f.Int32, handle: 2, queue: 500})
	require.Equal(t, uint32(100), res[0].RevisedQueueSize)
	mustSendRaw[ua.DeleteSubscriptionsResponse](t, c, &ua.DeleteSubscriptionsRequest{SubscriptionIDs: []uint32{normal.id}})

	sub.primeItem(int32(42))
	const n = 150
	for i := range n {
		writeInt32(t, c, f.Int32, int32(1000+i))
	}
	// Another session takes the subscription over with its queue.
	c2 := newClient(t, url)
	tr, err := c2.TransferSubscriptions(ctx, []uint32{sub.id}, false)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, tr.Results[0].StatusCode)
	var got []any
	for len(got) < n {
		p := publish(t, c2)
		require.Equal(t, sub.id, p.SubscriptionID)
		got = append(got, values(dataOf(t, p))...)
	}
	require.Len(t, got, n)
	require.Equal(t, int32(1000), got[0])
	require.Equal(t, int32(1000+n-1), got[n-1])

	_, err = c2.SetSubscriptionDurable(ctx, sub.id+1000, 1)
	require.ErrorIs(t, err, ua.StatusBadSubscriptionIDInvalid)
	_, err = c.SetSubscriptionDurable(ctx, sub.id, 1)
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied, "the session it left")
}

// TestServerMethods_DurableLimits: the limits of WithDurableSubscriptions,
// and a server without durable subscriptions.
func TestServerMethods_DurableLimits(t *testing.T) {
	srv, url := newServer(t, server.WithDurableSubscriptions(server.DurableSubscriptions{MaxLifetimeInHours: 2, MaxQueueSize: 200}))
	f := testutil.AddFixture(t, srv)
	c := newClient(t, url)
	ctx := context.Background()
	sub := newRawSub(t, c, rawSubParams{})
	hours, err := c.SetSubscriptionDurable(ctx, sub.id, 1000)
	require.NoError(t, err)
	require.Equal(t, uint32(2), hours)
	res := sub.createItems(ua.TimestampsToReturnNeither, itemSpec{node: f.Int32, handle: 1, queue: 500})
	require.Equal(t, uint32(200), res[0].RevisedQueueSize)

	_, url = newServer(t, server.WithDurableSubscriptions(server.DurableSubscriptions{Disabled: true}))
	c = newClient(t, url)
	sub = newRawSub(t, c, rawSubParams{})
	_, err = c.SetSubscriptionDurable(ctx, sub.id, 1)
	require.ErrorIs(t, err, ua.StatusBadMethodInvalid)
}

// TestServerMethods_Subscription: the calls of *opcua.Subscription, whose
// GetMonitoredItems gives the ids Monitor returned.
func TestServerMethods_Subscription(t *testing.T) {
	c, f, _ := rawSetup(t)
	ctx := context.Background()
	ch := make(chan *opcua.PublishNotificationData, 16)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: fastInterval}, ch)
	require.NoError(t, err)
	cleanup.Register(t, func() { _ = sub.Cancel(ctx) })

	hours, err := sub.SetDurable(ctx, 3)
	require.NoError(t, err)
	require.Equal(t, uint32(3), hours)
	res, err := sub.Monitor(ctx, ua.TimestampsToReturnNeither, opcua.NewMonitoredItemCreateRequestWithDefaults(f.Int32, ua.AttributeIDValue, 77))
	require.NoError(t, err)
	got, err := sub.GetMonitoredItems(ctx)
	require.NoError(t, err)
	require.Equal(t, []uint32{res.Results[0].MonitoredItemID}, got.ServerHandles)
	require.Equal(t, []uint32{77}, got.ClientHandles)

	awaitValue(t, ch, 77, int32(42))
	require.NoError(t, sub.ResendData(ctx))
	awaitValue(t, ch, 77, int32(42))
}
