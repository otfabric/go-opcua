// SPDX-License-Identifier: MIT

package conformance

import (
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestSubscription_DataChangeNotification(t *testing.T) {
	c, f, ctx := setup(t)

	sub, notifyCh, err := c.NewSubscription().
		Interval(50 * time.Millisecond).
		Monitor(f.Int32).
		Start(ctx)
	require.NoError(t, err)
	require.NotZero(t, sub.SubscriptionID)
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	// Change the value to trigger a data-change notification.
	status, err := c.WriteValue(ctx, f.Int32, &ua.DataValue{
		EncodingMask: ua.DataValueValue,
		Value:        ua.MustVariant(int32(12345)),
	})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, status)

	deadline := time.After(8 * time.Second)
	for {
		select {
		case msg := <-notifyCh:
			require.NoError(t, msg.Error)
			if dcn, ok := msg.Value.(*ua.DataChangeNotification); ok {
				for _, item := range dcn.MonitoredItems {
					if item.Value.Value.Value() == int32(12345) {
						return // got the expected data change
					}
				}
			}
		case <-deadline:
			t.Fatal("did not receive expected data change notification")
		}
	}
}

func TestSubscription_LowLevelSubscribe(t *testing.T) {
	c, _, ctx := setup(t)

	notifyCh := make(chan *opcua.PublishNotificationData, 16)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{
		Interval: 100 * time.Millisecond,
	}, notifyCh)
	require.NoError(t, err)
	require.NotZero(t, sub.SubscriptionID)
	require.Contains(t, c.SubscriptionIDs(), sub.SubscriptionID)
	require.NoError(t, sub.Cancel(ctx))
}

func TestSubscription_Lifecycle(t *testing.T) {
	c, f, ctx := setup(t)

	sub, _, err := c.NewSubscription().Interval(100 * time.Millisecond).Start(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	// Create two monitored items and capture their server IDs.
	monResp, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth,
		opcua.NewMonitoredItemCreateRequestWithDefaults(f.Int32, ua.AttributeIDValue, 1),
		opcua.NewMonitoredItemCreateRequestWithDefaults(f.Double, ua.AttributeIDValue, 2),
	)
	require.NoError(t, err)
	require.Len(t, monResp.Results, 2)
	require.Equal(t, ua.StatusOK, monResp.Results[0].StatusCode)
	require.Equal(t, ua.StatusOK, monResp.Results[1].StatusCode)
	item1 := monResp.Results[0].MonitoredItemID
	item2 := monResp.Results[1].MonitoredItemID

	t.Run("ModifySubscription", func(t *testing.T) {
		resp, err := sub.ModifySubscription(ctx, opcua.SubscriptionParameters{
			Interval:          200 * time.Millisecond,
			MaxKeepAliveCount: 5,
			LifetimeCount:     100,
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
	})

	t.Run("SetPublishingMode", func(t *testing.T) {
		resp, err := sub.SetPublishingMode(ctx, false)
		require.NoError(t, err)
		require.Len(t, resp.Results, 1)
		require.Equal(t, ua.StatusOK, resp.Results[0])
		_, err = sub.SetPublishingMode(ctx, true)
		require.NoError(t, err)
	})

	t.Run("ClientSetPublishingMode", func(t *testing.T) {
		resp, err := c.SetPublishingMode(ctx, true, sub.SubscriptionID)
		require.NoError(t, err)
		require.Len(t, resp.Results, 1)
		require.Equal(t, ua.StatusOK, resp.Results[0])
	})

	t.Run("ModifyMonitoredItems", func(t *testing.T) {
		resp, err := sub.ModifyMonitoredItems(ctx, ua.TimestampsToReturnBoth,
			&ua.MonitoredItemModifyRequest{
				MonitoredItemID: item1,
				RequestedParameters: &ua.MonitoringParameters{
					ClientHandle:     1,
					SamplingInterval: 250,
					QueueSize:        5,
					DiscardOldest:    true,
				},
			},
		)
		require.NoError(t, err)
		require.Len(t, resp.Results, 1)
		require.Equal(t, ua.StatusOK, resp.Results[0].StatusCode)
	})

	t.Run("SetMonitoringMode", func(t *testing.T) {
		resp, err := sub.SetMonitoringMode(ctx, ua.MonitoringModeReporting, item1, item2)
		require.NoError(t, err)
		require.Len(t, resp.Results, 2)
		require.Equal(t, ua.StatusOK, resp.Results[0])
		require.Equal(t, ua.StatusOK, resp.Results[1])
	})

	t.Run("SetTriggering", func(t *testing.T) {
		resp, err := sub.SetTriggering(ctx, item1, []uint32{item2}, nil)
		require.NoError(t, err)
		require.Len(t, resp.AddResults, 1)
		require.Equal(t, ua.StatusOK, resp.AddResults[0])
	})

	t.Run("Unmonitor", func(t *testing.T) {
		resp, err := sub.Unmonitor(ctx, item1, item2)
		require.NoError(t, err)
		require.Len(t, resp.Results, 2)
		require.Equal(t, ua.StatusOK, resp.Results[0])
		require.Equal(t, ua.StatusOK, resp.Results[1])
	})
}
