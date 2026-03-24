package opcua

import (
	"context"
	"time"

	"github.com/otfabric/go-opcua/ua"
)

// SubscriptionBuilder provides a fluent API for constructing and starting
// subscriptions with monitored items.
//
// Create a builder with [Client.NewSubscription] and chain configuration
// methods. Call [SubscriptionBuilder.Start] to create the subscription on
// the server:
//
//	sub, ch, err := c.NewSubscription().
//	    Interval(100 * time.Millisecond).
//	    Monitor(nodeID1, nodeID2).
//	    Start(ctx)
//
// If no notification channel is set via [SubscriptionBuilder.NotifyChannel],
// Start creates a buffered channel with capacity 256.
type SubscriptionBuilder struct {
	c                *Client
	params           SubscriptionParameters
	notifyCh         chan *PublishNotificationData
	monitorReq       []*ua.MonitoredItemCreateRequest
	ts               ua.TimestampsToReturn
	samplingInterval time.Duration // if > 0, applied to Monitor/MonitorEvents items (server-side sampling rate in ms)
}

// NewSubscription returns a SubscriptionBuilder for configuring a new subscription.
// Call Start to create the subscription on the server.
func (c *Client) NewSubscription() *SubscriptionBuilder {
	return &SubscriptionBuilder{
		c:  c,
		ts: ua.TimestampsToReturnBoth,
	}
}

// Interval sets the requested publishing interval.
func (b *SubscriptionBuilder) Interval(d time.Duration) *SubscriptionBuilder {
	b.params.Interval = d
	return b
}

// LifetimeCount sets the requested lifetime count.
func (b *SubscriptionBuilder) LifetimeCount(n uint32) *SubscriptionBuilder {
	b.params.LifetimeCount = n
	return b
}

// MaxKeepAliveCount sets the requested maximum keep-alive count.
func (b *SubscriptionBuilder) MaxKeepAliveCount(n uint32) *SubscriptionBuilder {
	b.params.MaxKeepAliveCount = n
	return b
}

// MaxNotificationsPerPublish sets the maximum notifications per publish response.
func (b *SubscriptionBuilder) MaxNotificationsPerPublish(n uint32) *SubscriptionBuilder {
	b.params.MaxNotificationsPerPublish = n
	return b
}

// Priority sets the subscription priority.
func (b *SubscriptionBuilder) Priority(p uint8) *SubscriptionBuilder {
	b.params.Priority = p
	return b
}

// Timestamps sets the timestamps to return for monitored items.
func (b *SubscriptionBuilder) Timestamps(ts ua.TimestampsToReturn) *SubscriptionBuilder {
	b.ts = ts
	return b
}

// SamplingInterval sets the requested sampling interval for monitored items added by
// Monitor or MonitorEvents. The server samples at this rate (in milliseconds); the
// subscription's publishing interval controls how often notifications are sent to the client.
// If not set or zero, the server uses the fastest practical rate (0.0 in OPC UA).
// Call this before Monitor or MonitorEvents to apply to those items.
func (b *SubscriptionBuilder) SamplingInterval(d time.Duration) *SubscriptionBuilder {
	b.samplingInterval = d
	return b
}

// NotifyChannel sets the channel for receiving notifications.
// If not set, Start creates a buffered channel with capacity 256.
func (b *SubscriptionBuilder) NotifyChannel(ch chan *PublishNotificationData) *SubscriptionBuilder {
	b.notifyCh = ch
	return b
}

// Monitor adds node IDs to be monitored for data changes.
func (b *SubscriptionBuilder) Monitor(nodeIDs ...*ua.NodeID) *SubscriptionBuilder {
	for _, nid := range nodeIDs {
		req := NewMonitoredItemCreateRequestWithDefaults(
			nid, ua.AttributeIDValue, uint32(len(b.monitorReq)),
		)
		if b.samplingInterval > 0 {
			req.RequestedParameters.SamplingInterval = float64(b.samplingInterval.Milliseconds())
		}
		b.monitorReq = append(b.monitorReq, req)
	}
	return b
}

// MonitorItems adds custom monitored item create requests.
func (b *SubscriptionBuilder) MonitorItems(items ...*ua.MonitoredItemCreateRequest) *SubscriptionBuilder {
	b.monitorReq = append(b.monitorReq, items...)
	return b
}

// MonitorEvents adds event-monitoring items for the given node IDs using the
// provided EventFilter. Each node is monitored on AttributeIDEventNotifier.
func (b *SubscriptionBuilder) MonitorEvents(filter *ua.EventFilter, nodeIDs ...*ua.NodeID) *SubscriptionBuilder {
	filterEO := ua.NewExtensionObject(filter)
	samplingMs := 0.0
	if b.samplingInterval > 0 {
		samplingMs = float64(b.samplingInterval.Milliseconds())
	}
	for _, nid := range nodeIDs {
		b.monitorReq = append(b.monitorReq, &ua.MonitoredItemCreateRequest{
			ItemToMonitor: &ua.ReadValueID{
				NodeID:       nid,
				AttributeID:  ua.AttributeIDEventNotifier,
				DataEncoding: &ua.QualifiedName{},
			},
			MonitoringMode: ua.MonitoringModeReporting,
			RequestedParameters: &ua.MonitoringParameters{
				ClientHandle:     uint32(len(b.monitorReq)),
				DiscardOldest:    true,
				Filter:           filterEO,
				QueueSize:        10,
				SamplingInterval: samplingMs,
			},
		})
	}
	return b
}

// Start creates the subscription and monitored items on the server.
// It returns the subscription and the notification channel.
// If the server closes the connection during creation, the error may wrap io.EOF
// with a message suggesting the server may not support subscriptions or event/alarm monitoring.
func (b *SubscriptionBuilder) Start(ctx context.Context) (*Subscription, chan *PublishNotificationData, error) {
	if b.notifyCh == nil {
		b.notifyCh = make(chan *PublishNotificationData, 256)
	}

	sub, err := b.c.Subscribe(ctx, &b.params, b.notifyCh)
	if err != nil {
		return nil, nil, err
	}

	if len(b.monitorReq) > 0 {
		if _, err := sub.Monitor(ctx, b.ts, b.monitorReq...); err != nil {
			_ = sub.Cancel(ctx)
			return nil, nil, err
		}
	}

	return sub, b.notifyCh, nil
}
