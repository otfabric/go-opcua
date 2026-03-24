package opcua

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/stats"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

const (
	DefaultSubscriptionMaxNotificationsPerPublish = 10000
	DefaultSubscriptionLifetimeCount              = 10000
	DefaultSubscriptionMaxKeepAliveCount          = 3000
	DefaultSubscriptionInterval                   = 100 * time.Millisecond
	DefaultSubscriptionPriority                   = 0
)

// Subscription represents an active OPC-UA subscription on the server.
//
// A subscription receives periodic notifications about data changes and events
// from monitored items. Notifications are delivered to the Notifs channel.
//
// Create a subscription with [Client.Subscribe] or [SubscriptionBuilder.Start].
// Add monitored items with [Subscription.Monitor]. Call [Subscription.Cancel]
// when done to clean up resources on both client and server.
//
// The RevisedPublishingInterval, RevisedLifetimeCount, and
// RevisedMaxKeepAliveCount fields contain the values negotiated with the
// server, which may differ from the requested values.
type Subscription struct {
	SubscriptionID            uint32
	RevisedPublishingInterval time.Duration
	RevisedLifetimeCount      uint32
	RevisedMaxKeepAliveCount  uint32
	Notifs                    chan<- *PublishNotificationData
	params                    *SubscriptionParameters
	paramsMu                  sync.Mutex
	items                     map[uint32]*monitoredItem
	itemsMu                   sync.Mutex
	lastSeq                   uint32
	nextSeq                   uint32
	c                         *Client
}

// SubscriptionParameters configures a subscription's behavior.
//
// Fields that are left at their zero value will use the defaults:
//   - Interval: 100ms
//   - LifetimeCount: 10000
//   - MaxKeepAliveCount: 3000
//   - MaxNotificationsPerPublish: 10000
//   - Priority: 0
type SubscriptionParameters struct {
	Interval                   time.Duration
	LifetimeCount              uint32
	MaxKeepAliveCount          uint32
	MaxNotificationsPerPublish uint32
	Priority                   uint8
}

type monitoredItem struct {
	req *ua.MonitoredItemCreateRequest
	res *ua.MonitoredItemCreateResult
	ts  ua.TimestampsToReturn
}

// NewMonitoredItemCreateRequestWithDefaults creates a MonitoredItemCreateRequest
// with sensible defaults: reporting mode, queue size of 10, discard oldest,
// and no filter. If attributeID is 0, it defaults to AttributeIDValue.
func NewMonitoredItemCreateRequestWithDefaults(nodeID *ua.NodeID, attributeID ua.AttributeID, clientHandle uint32) *ua.MonitoredItemCreateRequest {
	if attributeID == 0 {
		attributeID = ua.AttributeIDValue
	}
	return &ua.MonitoredItemCreateRequest{
		ItemToMonitor: &ua.ReadValueID{
			NodeID:       nodeID,
			AttributeID:  attributeID,
			DataEncoding: &ua.QualifiedName{},
		},
		MonitoringMode: ua.MonitoringModeReporting,
		RequestedParameters: &ua.MonitoringParameters{
			ClientHandle:     clientHandle,
			DiscardOldest:    true,
			Filter:           nil,
			QueueSize:        10,
			SamplingInterval: 0.0,
		},
	}
}

// PublishNotificationData contains a notification received from a subscription.
//
// Check Error first — if non-nil, Value will be nil. When Error is nil,
// Value contains the notification which can be a [*ua.DataChangeNotification],
// [*ua.EventNotificationList], or [*ua.StatusChangeNotification].
type PublishNotificationData struct {
	SubscriptionID uint32
	Error          error
	Value          ua.Notification
}

// Cancel stops the subscription and removes it
// from the client and the server.
func (s *Subscription) Cancel(ctx context.Context) error {
	stats.Subscription().Add("Cancel", 1)
	s.c.forgetSubscription(ctx, s.SubscriptionID)
	return s.delete(ctx)
}

// delete removes the subscription from the server.
func (s *Subscription) delete(ctx context.Context) error {
	req := &ua.DeleteSubscriptionsRequest{
		SubscriptionIDs: []uint32{s.SubscriptionID},
	}

	res, err := send[ua.DeleteSubscriptionsResponse](ctx, s.c, req)

	switch {
	case err != nil:
		return err
	case res.Results[0] == ua.StatusOK:
		s.itemsMu.Lock()
		s.items = make(map[uint32]*monitoredItem)
		s.itemsMu.Unlock()
		return nil
	default:
		return res.Results[0]
	}
}

func (s *Subscription) ModifySubscription(ctx context.Context, params SubscriptionParameters) (*ua.ModifySubscriptionResponse, error) {
	stats.Subscription().Add("ModifySubscription", 1)

	params.setDefaults()
	req := &ua.ModifySubscriptionRequest{
		SubscriptionID:              s.SubscriptionID,
		RequestedPublishingInterval: float64(params.Interval.Milliseconds()),
		RequestedLifetimeCount:      params.LifetimeCount,
		RequestedMaxKeepAliveCount:  params.MaxKeepAliveCount,
		MaxNotificationsPerPublish:  params.MaxNotificationsPerPublish,
		Priority:                    params.Priority,
	}

	res, err := send[ua.ModifySubscriptionResponse](ctx, s.c, req)

	if err != nil {
		return nil, err
	}

	// update subscription parameters
	s.paramsMu.Lock()
	s.params = &params
	s.paramsMu.Unlock()
	// update revised subscription parameters
	s.RevisedPublishingInterval = time.Duration(res.RevisedPublishingInterval) * time.Millisecond
	s.RevisedLifetimeCount = res.RevisedLifetimeCount
	s.RevisedMaxKeepAliveCount = res.RevisedMaxKeepAliveCount

	return res, nil
}

// Monitor creates monitored items on the server for data change or event notifications.
// If the server closes the connection (e.g. because it does not support event or alarm
// subscriptions), the returned error wraps io.EOF with a message suggesting that the
// server may not support event or alarm subscriptions; callers can use errors.Is(err, io.EOF).
func (s *Subscription) Monitor(ctx context.Context, ts ua.TimestampsToReturn, items ...*ua.MonitoredItemCreateRequest) (*ua.CreateMonitoredItemsResponse, error) {
	stats.Subscription().Add("Monitor", 1)
	stats.Subscription().Add("MonitoredItems", int64(len(items)))

	// Part 4, 5.12.2.2 CreateMonitoredItems Service Parameters
	req := &ua.CreateMonitoredItemsRequest{
		SubscriptionID:     s.SubscriptionID,
		TimestampsToReturn: ts,
		ItemsToCreate:      items,
	}

	res, err := send[ua.CreateMonitoredItemsResponse](ctx, s.c, req)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("connection closed while creating monitored items (server may not support event or alarm subscriptions): %w", err)
		}
		return nil, err
	}

	// store monitored items
	s.itemsMu.Lock()
	for i, item := range items {
		result := res.Results[i]
		s.items[result.MonitoredItemID] = &monitoredItem{
			req: item,
			res: result,
			ts:  ts,
		}
	}
	s.itemsMu.Unlock()

	return res, err
}

func (s *Subscription) Unmonitor(ctx context.Context, monitoredItemIDs ...uint32) (*ua.DeleteMonitoredItemsResponse, error) {
	stats.Subscription().Add("Unmonitor", 1)
	stats.Subscription().Add("UnmonitoredItems", int64(len(monitoredItemIDs)))

	req := &ua.DeleteMonitoredItemsRequest{
		MonitoredItemIDs: monitoredItemIDs,
		SubscriptionID:   s.SubscriptionID,
	}

	res, err := send[ua.DeleteMonitoredItemsResponse](ctx, s.c, req)
	if err != nil {
		return nil, err
	}

	// remove monitored items
	s.itemsMu.Lock()
	for _, id := range monitoredItemIDs {
		delete(s.items, id)
	}
	s.itemsMu.Unlock()

	return res, nil
}

func (s *Subscription) ModifyMonitoredItems(ctx context.Context, ts ua.TimestampsToReturn, items ...*ua.MonitoredItemModifyRequest) (*ua.ModifyMonitoredItemsResponse, error) {
	stats.Subscription().Add("ModifyMonitoredItems", 1)
	stats.Subscription().Add("ModifiedMonitoredItems", int64(len(items)))

	var err error
	s.itemsMu.Lock()
	for _, item := range items {
		id := item.MonitoredItemID
		if _, exists := s.items[id]; !exists {
			err = fmt.Errorf("opcua: sub %d: cannot modify unknown monitored item id: %d", s.SubscriptionID, id)
			break
		}
	}
	s.itemsMu.Unlock()

	if err != nil {
		return nil, err
	}

	req := &ua.ModifyMonitoredItemsRequest{
		SubscriptionID:     s.SubscriptionID,
		TimestampsToReturn: ts,
		ItemsToModify:      items,
	}
	var res *ua.ModifyMonitoredItemsResponse

	res, err = send[ua.ModifyMonitoredItemsResponse](ctx, s.c, req)
	if err != nil {
		return nil, err
	}

	// update monitored items
	s.itemsMu.Lock()
	for i, res := range res.Results {
		if res.StatusCode != ua.StatusOK {
			continue
		}

		id := req.ItemsToModify[i].MonitoredItemID
		item := s.items[id]
		item.ts = req.TimestampsToReturn
		item.req.RequestedParameters = req.ItemsToModify[i].RequestedParameters
		item.res.StatusCode = res.StatusCode
		item.res.RevisedSamplingInterval = res.RevisedSamplingInterval
		item.res.RevisedQueueSize = res.RevisedQueueSize
		item.res.FilterResult = res.FilterResult
	}
	s.itemsMu.Unlock()

	return res, nil
}

func (s *Subscription) SetMonitoringMode(ctx context.Context, monitoringMode ua.MonitoringMode, monitoredItemIDs ...uint32) (*ua.SetMonitoringModeResponse, error) {
	stats.Subscription().Add("SetMonitoringMode", 1)
	stats.Subscription().Add("SetMonitoringModeMonitoredItems", int64(len(monitoredItemIDs)))

	var err error
	s.itemsMu.Lock()
	for _, id := range monitoredItemIDs {
		if _, exists := s.items[id]; !exists {
			err = fmt.Errorf("opcua: sub %d: cannot set monitoring mode for unknown monitored item id: %d", s.SubscriptionID, id)
			break
		}
	}
	s.itemsMu.Unlock()

	if err != nil {
		return nil, err
	}

	req := &ua.SetMonitoringModeRequest{
		SubscriptionID:   s.SubscriptionID,
		MonitoringMode:   monitoringMode,
		MonitoredItemIDs: monitoredItemIDs,
	}
	var res *ua.SetMonitoringModeResponse
	res, err = send[ua.SetMonitoringModeResponse](ctx, s.c, req)
	if err != nil {
		return nil, err
	}

	return res, nil
}

// SetTriggering sends a request to the server to add and/or remove triggering links from a triggering item.
// To add links from a triggering item to an item to report provide the server assigned ID(s) in the `add` argument.
// To remove links from a triggering item to an item to report provide the server assigned ID(s) in the `remove` argument.
func (s *Subscription) SetTriggering(ctx context.Context, triggeringItemID uint32, add, remove []uint32) (*ua.SetTriggeringResponse, error) {
	stats.Subscription().Add("SetTriggering", 1)

	// Part 4, 5.12.5.2 SetTriggering Service Parameters
	req := &ua.SetTriggeringRequest{
		SubscriptionID:   s.SubscriptionID,
		TriggeringItemID: triggeringItemID,
		LinksToAdd:       add,
		LinksToRemove:    remove,
	}

	return send[ua.SetTriggeringResponse](ctx, s.c, req)
}

// SetPublishingMode enables or disables publishing of notification messages for this subscription.
//
// Part 4, Section 5.13.4.
func (s *Subscription) SetPublishingMode(ctx context.Context, publishingEnabled bool) (*ua.SetPublishingModeResponse, error) {
	stats.Subscription().Add("SetPublishingMode", 1)

	req := &ua.SetPublishingModeRequest{
		PublishingEnabled: publishingEnabled,
		SubscriptionIDs:   []uint32{s.SubscriptionID},
	}

	return send[ua.SetPublishingModeResponse](ctx, s.c, req)
}

func (s *Subscription) publishTimeout() time.Duration {
	timeout := time.Duration(s.RevisedMaxKeepAliveCount) * s.RevisedPublishingInterval // expected keepalive interval
	if timeout > uasc.MaxTimeout {
		return uasc.MaxTimeout
	}
	if timeout < s.c.cfg.sechan.RequestTimeout {
		return s.c.cfg.sechan.RequestTimeout
	}
	return timeout
}

func (s *Subscription) notify(ctx context.Context, data *PublishNotificationData) {
	select {
	case <-ctx.Done():
		return
	case s.Notifs <- data:
	}
}

// Stats returns a diagnostic struct with metadata about the current subscription.
//
// This reads the full SubscriptionDiagnosticsArray from the server and filters
// by SubscriptionID. A future optimisation could browse for the specific
// diagnostics node (e.g. i=2290/<subscription-guid>) and cache its NodeID,
// but the current approach works with all servers regardless of how they
// structure the diagnostics address space.
func (s *Subscription) Stats(ctx context.Context) (*ua.SubscriptionDiagnosticsDataType, error) {
	node := s.c.Node(ua.NewNumericNodeID(0, id.ServerServerDiagnosticsSubscriptionDiagnosticsArray))
	v, err := node.Value(ctx)
	if err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: sub=%d", errors.ErrEmptyResponse, s.SubscriptionID)
	}

	eos, ok := v.Value().([]*ua.ExtensionObject)
	if !ok {
		return nil, fmt.Errorf("%w: sub=%d nodeID=%s got=%T", errors.ErrInvalidResponseType, s.SubscriptionID, node.String(), v.Value())
	}

	for _, eo := range eos {
		stat, ok := eo.Value.(*ua.SubscriptionDiagnosticsDataType)
		if !ok {
			continue
		}

		if stat.SubscriptionID == s.SubscriptionID {
			return stat, nil
		}
	}

	return nil, fmt.Errorf("%w: sub=%d", errors.ErrSubscriptionNotFound, s.SubscriptionID)
}

func (p *SubscriptionParameters) setDefaults() {
	if p.MaxNotificationsPerPublish == 0 {
		p.MaxNotificationsPerPublish = DefaultSubscriptionMaxNotificationsPerPublish
	}
	if p.LifetimeCount == 0 {
		p.LifetimeCount = DefaultSubscriptionLifetimeCount
	}
	if p.MaxKeepAliveCount == 0 {
		p.MaxKeepAliveCount = DefaultSubscriptionMaxKeepAliveCount
	}
	if p.Interval == 0 {
		p.Interval = DefaultSubscriptionInterval
	}
	if p.Priority == 0 {
		// DefaultSubscriptionPriority is 0 at the time of writing, so this redundant assignment is
		// made only to allow for a one-liner change of default priority should a need arise
		// and to explicitly expose the default priority as a constant
		p.Priority = DefaultSubscriptionPriority
	}
}

// recreateDelete is called by the client when it is trying to
// recreate an existing subscription. This function deletes the
// existing subscription from the server.
func (s *Subscription) recreateDelete(ctx context.Context) error { //nolint:unparam
	req := &ua.DeleteSubscriptionsRequest{
		SubscriptionIDs: []uint32{s.SubscriptionID},
	}
	if _, err := send[ua.DeleteSubscriptionsResponse](ctx, s.c, req); err != nil {
		s.c.cfg.logger.Debugf("recreateDelete: delete failed (continuing anyway) sub_id=%v error=%v", s.SubscriptionID, err)
	}
	s.c.cfg.logger.Debugf("recreateDelete: subscription deleted sub_id=%v", s.SubscriptionID)
	return nil
}

// recreateCreate is called by the client when it is trying to
// recreate an existing subscription. This function creates a
// new subscription with the same parameters as the previous one.
func (s *Subscription) recreateCreate(ctx context.Context) error {
	s.paramsMu.Lock()
	params := s.params
	s.paramsMu.Unlock()

	req := &ua.CreateSubscriptionRequest{
		RequestedPublishingInterval: float64(params.Interval / time.Millisecond),
		RequestedLifetimeCount:      params.LifetimeCount,
		RequestedMaxKeepAliveCount:  params.MaxKeepAliveCount,
		PublishingEnabled:           true,
		MaxNotificationsPerPublish:  params.MaxNotificationsPerPublish,
		Priority:                    params.Priority,
	}
	res, err := send[ua.CreateSubscriptionResponse](ctx, s.c, req)
	if err != nil {
		s.c.cfg.logger.Debugf("recreateCreate: failed to recreate subscription sub_id=%v", s.SubscriptionID)
		return err
	}
	// Redundant: send[T]() already checks ServiceResult via SecureChannel.Receive().
	// Kept as defense-in-depth.
	if status := res.ResponseHeader.ServiceResult; status != ua.StatusOK {
		return status
	}
	s.c.cfg.logger.Debugf("recreateCreate: recreated subscription sub_id=%v new_sub_id=%v", s.SubscriptionID, res.SubscriptionID)

	s.SubscriptionID = res.SubscriptionID
	s.RevisedPublishingInterval = time.Duration(res.RevisedPublishingInterval) * time.Millisecond
	s.RevisedLifetimeCount = res.RevisedLifetimeCount
	s.RevisedMaxKeepAliveCount = res.RevisedMaxKeepAliveCount
	s.lastSeq = 0
	s.nextSeq = 1

	if err := s.c.registerSubscriptionNeedsSubMuxLock(s); err != nil {
		return err
	}
	s.c.cfg.logger.Debugf("recreateCreate: subscription registered sub_id=%v", s.SubscriptionID)

	// Sort by timestamp to return
	itemsByTimestamps := make(map[ua.TimestampsToReturn][]*ua.MonitoredItemCreateRequest)
	s.itemsMu.Lock()
	for _, mi := range s.items {
		itemsByTimestamps[mi.ts] = append(itemsByTimestamps[mi.ts], mi.req)
	}
	s.items = make(map[uint32]*monitoredItem, len(s.items))
	s.itemsMu.Unlock()

	for ts, items := range itemsByTimestamps {
		req := &ua.CreateMonitoredItemsRequest{
			SubscriptionID:     s.SubscriptionID,
			TimestampsToReturn: ts,
			ItemsToCreate:      items,
		}

		res, err := send[ua.CreateMonitoredItemsResponse](ctx, s.c, req)
		if err != nil {
			s.c.cfg.logger.Debugf("recreateCreate: failed to create monitored items sub_id=%v error=%v", s.SubscriptionID, err)
			return err
		}

		for _, result := range res.Results {
			if status := result.StatusCode; status != ua.StatusOK {
				return status
			}
		}

		s.itemsMu.Lock()
		for i, item := range items {
			s.items[res.Results[i].MonitoredItemID] = &monitoredItem{
				req: item,
				res: res.Results[i],
				ts:  ts,
			}
		}
		s.itemsMu.Unlock()
	}
	s.c.cfg.logger.Debugf("recreateCreate: subscription successfully recreated sub_id=%v", s.SubscriptionID)

	return nil
}
