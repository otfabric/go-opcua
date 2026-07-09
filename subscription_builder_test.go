// SPDX-License-Identifier: MIT

package opcua

import (
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestSubscriptionBuilder_Chaining(t *testing.T) {
	c, err := NewClient("opc.tcp://example.com:4840")
	require.NoError(t, err)

	nid := ua.NewNumericNodeID(0, 42)
	custom := NewMonitoredItemCreateRequestWithDefaults(nid, ua.AttributeIDValue, 99)

	b := c.NewSubscription().
		Interval(time.Second).
		LifetimeCount(10).
		MaxKeepAliveCount(20).
		MaxNotificationsPerPublish(5).
		Priority(1).
		Timestamps(ua.TimestampsToReturnServer).
		SamplingInterval(50 * time.Millisecond).
		Monitor(nid).
		MonitorItems(custom)

	require.Equal(t, time.Second, b.params.Interval)
	require.Equal(t, uint32(10), b.params.LifetimeCount)
	require.Equal(t, ua.TimestampsToReturnServer, b.ts)
	require.Len(t, b.monitorReq, 2)
	require.Equal(t, float64(50), b.monitorReq[0].RequestedParameters.SamplingInterval)
}

func TestSubscriptionBuilder_MonitorEventsBuildsRequests(t *testing.T) {
	c, err := NewClient("opc.tcp://example.com:4840")
	require.NoError(t, err)

	filter := ua.NewEventFilter().Select("Message").Build()
	nid := ua.NewNumericNodeID(0, 100)

	b := c.NewSubscription().
		SamplingInterval(25*time.Millisecond).
		MonitorEvents(filter, nid)

	require.Len(t, b.monitorReq, 1)
	require.Equal(t, ua.AttributeIDEventNotifier, b.monitorReq[0].ItemToMonitor.AttributeID)
	require.Equal(t, float64(25), b.monitorReq[0].RequestedParameters.SamplingInterval)
}

func TestSubscriptionBuilder_NotifyChannel(t *testing.T) {
	c, err := NewClient("opc.tcp://example.com:4840")
	require.NoError(t, err)

	ch := make(chan *PublishNotificationData, 1)
	b := c.NewSubscription().NotifyChannel(ch)
	require.Equal(t, ch, b.notifyCh)
}
