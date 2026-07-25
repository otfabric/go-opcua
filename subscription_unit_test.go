// SPDX-License-Identifier: MIT

package opcua

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubscriptionParameters_setDefaults(t *testing.T) {
	var p SubscriptionParameters
	p.setDefaults()
	assert.Equal(t, uint32(DefaultSubscriptionMaxNotificationsPerPublish), p.MaxNotificationsPerPublish)
	assert.Equal(t, uint32(DefaultSubscriptionLifetimeCount), p.LifetimeCount)
	assert.Equal(t, uint32(DefaultSubscriptionMaxKeepAliveCount), p.MaxKeepAliveCount)
	assert.Equal(t, DefaultSubscriptionInterval, p.Interval)
	assert.Equal(t, uint8(DefaultSubscriptionPriority), p.Priority)

	p = SubscriptionParameters{
		MaxNotificationsPerPublish: 7,
		LifetimeCount:              3,
		MaxKeepAliveCount:          4,
		Interval:                   250 * time.Millisecond,
		Priority:                   9,
	}
	p.setDefaults()
	assert.Equal(t, uint32(7), p.MaxNotificationsPerPublish)
	assert.Equal(t, uint32(3), p.LifetimeCount)
	assert.Equal(t, uint32(4), p.MaxKeepAliveCount)
	assert.Equal(t, 250*time.Millisecond, p.Interval)
	assert.Equal(t, uint8(9), p.Priority)
}

func TestNewMonitoredItemCreateRequestWithDefaults(t *testing.T) {
	nid := ua.NewNumericNodeID(0, 2258)
	req := NewMonitoredItemCreateRequestWithDefaults(nid, 0, 42)
	require.NotNil(t, req)
	assert.Equal(t, ua.AttributeIDValue, req.ItemToMonitor.AttributeID)
	assert.Equal(t, ua.MonitoringModeReporting, req.MonitoringMode)
	assert.True(t, req.RequestedParameters.DiscardOldest)
	assert.Equal(t, uint32(10), req.RequestedParameters.QueueSize)
	assert.Equal(t, uint32(42), req.RequestedParameters.ClientHandle)

	req = NewMonitoredItemCreateRequestWithDefaults(nid, ua.AttributeIDBrowseName, 1)
	assert.Equal(t, ua.AttributeIDBrowseName, req.ItemToMonitor.AttributeID)
}

func TestModifyMonitoredItems_UnknownItemID(t *testing.T) {
	c, err := NewClient("opc.tcp://example.com:4840")
	require.NoError(t, err)
	sub := &Subscription{
		SubscriptionID: 1,
		c:              c,
		items: map[uint32]*monitoredItem{
			1: {},
		},
	}
	_, err = sub.ModifyMonitoredItems(context.Background(), ua.TimestampsToReturnBoth,
		&ua.MonitoredItemModifyRequest{MonitoredItemID: 99})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown monitored item")
}

func TestSetMonitoringMode_UnknownItemID(t *testing.T) {
	c, err := NewClient("opc.tcp://example.com:4840")
	require.NoError(t, err)
	sub := &Subscription{
		SubscriptionID: 1,
		c:              c,
		items:          map[uint32]*monitoredItem{1: {}},
	}
	_, err = sub.SetMonitoringMode(context.Background(), ua.MonitoringModeReporting, 99)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown monitored item")
}

func TestSubscription_notify(t *testing.T) {
	// Unbuffered: with a cancelled ctx, only <-ctx.Done is ready (send would block),
	// so notify must return without hanging. A buffered channel would race both cases.
	ch := make(chan *PublishNotificationData)
	sub := &Subscription{Notifs: ch}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sub.notify(ctx, &PublishNotificationData{Error: assert.AnError})

	ch = make(chan *PublishNotificationData, 1)
	sub.Notifs = ch
	want := &PublishNotificationData{SubscriptionID: 7}
	sub.notify(context.Background(), want)
	got := <-ch
	assert.Equal(t, want, got)
}

func TestSubscription_publishTimeout(t *testing.T) {
	c, err := NewClient("opc.tcp://example.com:4840")
	require.NoError(t, err)
	c.cfg.sechan = &uasc.Config{RequestTimeout: 25 * time.Millisecond}

	sub := &Subscription{
		c:                         c,
		RevisedPublishingInterval: uasc.MaxTimeout,
		RevisedMaxKeepAliveCount:  2, // exceeds MaxTimeout
	}
	assert.Equal(t, uasc.MaxTimeout, sub.publishTimeout())

	sub.RevisedPublishingInterval = time.Millisecond
	sub.RevisedMaxKeepAliveCount = 1
	assert.Equal(t, 25*time.Millisecond, sub.publishTimeout())

	sub.RevisedPublishingInterval = 200 * time.Millisecond
	sub.RevisedMaxKeepAliveCount = 2 // 400ms
	assert.Equal(t, 400*time.Millisecond, sub.publishTimeout())
}
