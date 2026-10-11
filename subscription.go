// SPDX-License-Identifier: MIT

package opcua

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
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
	nextItemID                uint32 // see stableItemIDNeedsLock; guarded by itemsMu
	itemsMu                   sync.Mutex
	lastSeq                   uint32
	nextSeq                   uint32
	c                         *Client

	// idMu guards SubscriptionID, which changes when the subscription is
	// recreated after a reconnect while other goroutines use it. Code in
	// this package reads it through id().
	idMu sync.RWMutex

	// needsRecreate is set when recreating the subscription after a
	// reconnect failed. The next recovery then recreates it instead of
	// trying to transfer and republish it. Guarded by Client.subMux.
	needsRecreate bool

	// lastActivity is when the server last sent a message for the
	// subscription (unix nanoseconds), or when the client last had reason
	// to start counting anew. See Client.markSilentSubscriptions.
	lastActivity atomic.Int64

	// cancelled is closed by Cancel. It releases a notification that is
	// being handed to Notifs: the consumer of a cancelled subscription
	// usually stops reading, and the client's single publish loop must not
	// block on it forever.
	cancelled  chan struct{}
	cancelOnce sync.Once
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

	// serverID is the id the server currently knows the item by. The key of
	// Subscription.items is the id the caller was given by Monitor; the two
	// are the same until the subscription is recreated after a reconnect,
	// when the server assigns new ids. See [Subscription.Monitor].
	serverID uint32
}

// stableItemIDNeedsLock returns the id under which a new monitored item is
// handed to the caller: the server's id, unless that id already denotes
// another item of this subscription (possible once a recreation has given the
// existing items new server ids), in which case an unused one is chosen.
// itemsMu must be held.
func (s *Subscription) stableItemIDNeedsLock(serverID uint32) uint32 {
	if _, taken := s.items[serverID]; !taken {
		return serverID
	}
	for {
		s.nextItemID++
		if s.nextItemID == 0 {
			continue
		}
		id := s.nextItemID | 1<<31 // away from the small ids servers hand out
		if _, taken := s.items[id]; !taken {
			return id
		}
	}
}

// serverItemIDNeedsLock translates an id held by the caller into the id the
// server knows the item by. An id that denotes no item is passed through, so
// the server reports it as invalid. itemsMu must be held.
func (s *Subscription) serverItemIDNeedsLock(id uint32) uint32 {
	if item, ok := s.items[id]; ok {
		return item.serverID
	}
	return id
}

func (s *Subscription) serverItemIDs(ids []uint32) []uint32 {
	if ids == nil {
		return nil
	}
	out := make([]uint32, len(ids))
	s.itemsMu.Lock()
	for i, id := range ids {
		out[i] = s.serverItemIDNeedsLock(id)
	}
	s.itemsMu.Unlock()
	return out
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

// NewDataChangeFilter returns a DataChangeFilter (Part 4 §7.22.2) wrapped for
// use as [ua.MonitoringParameters].Filter of a monitored item on the Value
// attribute:
//
//	req := opcua.NewMonitoredItemCreateRequestWithDefaults(nodeID, ua.AttributeIDValue, 1)
//	req.RequestedParameters.Filter = opcua.NewDataChangeFilter(
//	    ua.DataChangeTriggerStatusValue, ua.DeadbandTypeAbsolute, 0.5)
//
// trigger selects what counts as a change (status only, status or value, or
// status, value or source timestamp). deadbandType and deadbandValue suppress
// value changes that stay within the deadband of the last reported value:
// [ua.DeadbandTypeAbsolute] takes the absolute change, [ua.DeadbandTypePercent]
// a percentage (0–100) of the node's EURange, and [ua.DeadbandTypeNone]
// ignores deadbandValue. A deadband needs a numeric variable; the server
// answers the item with a Bad status when it cannot apply the filter.
func NewDataChangeFilter(trigger ua.DataChangeTrigger, deadbandType ua.DeadbandType, deadbandValue float64) *ua.ExtensionObject {
	return ua.NewExtensionObject(&ua.DataChangeFilter{
		Trigger:       trigger,
		DeadbandType:  uint32(deadbandType),
		DeadbandValue: deadbandValue,
	})
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

// id returns the current subscription id.
func (s *Subscription) id() uint32 {
	s.idMu.RLock()
	defer s.idMu.RUnlock()
	return s.SubscriptionID
}

// setID sets the subscription id after the server assigned a new one.
func (s *Subscription) setID(id uint32) {
	s.idMu.Lock()
	s.SubscriptionID = id
	s.idMu.Unlock()
}

// Cancel stops the subscription and removes it
// from the client and the server.
func (s *Subscription) Cancel(ctx context.Context) error {
	stats.Subscription().Add("Cancel", 1)
	if s.cancelled != nil {
		s.cancelOnce.Do(func() { close(s.cancelled) })
	}
	// The subscription is looked up by identity, and its id is read under
	// the client's subscription lock: a reconnect may be recreating it right
	// now, which gives it a new id. Cancelling "the old id" would leave the
	// recreated subscription registered and alive on the server.
	id := s.c.forgetSubscriptionOf(ctx, s)
	return s.delete(ctx, id)
}

// delete removes the subscription with the given id from the server.
func (s *Subscription) delete(ctx context.Context, id uint32) error {
	req := &ua.DeleteSubscriptionsRequest{
		SubscriptionIDs: []uint32{id},
	}

	res, err := send[ua.DeleteSubscriptionsResponse](ctx, s.c, req)

	switch {
	case err != nil:
		return err
	case len(res.Results) != 1:
		// The number of results is the server's to get right; a response
		// with another number must not take the application down.
		return ua.StatusBadUnknownResponse
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
		SubscriptionID:              s.id(),
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

	// update subscription parameters and revised subscription parameters.
	// The revised values are read by the publish loop (publishTimeout) and
	// may be modified by several goroutines, so they share paramsMu.
	s.paramsMu.Lock()
	s.params = &params
	s.RevisedPublishingInterval = time.Duration(res.RevisedPublishingInterval) * time.Millisecond
	s.RevisedLifetimeCount = res.RevisedLifetimeCount
	s.RevisedMaxKeepAliveCount = res.RevisedMaxKeepAliveCount
	s.paramsMu.Unlock()

	return res, nil
}

// Monitor creates monitored items on the server for data change or event notifications.
// If the server closes the connection (e.g. because it does not support event or alarm
// subscriptions), the returned error wraps io.EOF with a message suggesting that the
// server may not support event or alarm subscriptions; callers can use errors.Is(err, io.EOF).
//
// The MonitoredItemID of each result stays valid for the life of the
// subscription: [Subscription.Unmonitor], [Subscription.ModifyMonitoredItems],
// [Subscription.SetMonitoringMode] and [Subscription.SetTriggering] accept it
// even after the subscription was recreated on the server following a
// reconnect, when the server knows the item by a new id. For that reason the
// id can differ from the one on the wire.
func (s *Subscription) Monitor(ctx context.Context, ts ua.TimestampsToReturn, items ...*ua.MonitoredItemCreateRequest) (*ua.CreateMonitoredItemsResponse, error) {
	stats.Subscription().Add("Monitor", 1)
	stats.Subscription().Add("MonitoredItems", int64(len(items)))

	// Part 4, 5.12.2.2 CreateMonitoredItems Service Parameters
	req := &ua.CreateMonitoredItemsRequest{
		SubscriptionID:     s.id(),
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

	// One result per item: anything else is not an answer to this request.
	// (Indexing the results of a short response panicked, with the lock on
	// the items held.)
	if len(res.Results) != len(items) {
		return nil, fmt.Errorf("opcua: %d results for %d monitored items: %w", len(res.Results), len(items), ua.StatusBadUnknownResponse)
	}

	// store monitored items
	s.itemsMu.Lock()
	for i, item := range items {
		result := res.Results[i]
		// An item the server rejected does not exist. Remembering it would
		// make every later recreation of the subscription (after a reconnect)
		// replay the failing request and abort, taking the items that did
		// succeed down with it.
		if result == nil || result.StatusCode != ua.StatusOK {
			continue
		}
		serverID := result.MonitoredItemID
		id := s.stableItemIDNeedsLock(serverID)
		result.MonitoredItemID = id
		s.items[id] = &monitoredItem{
			req:      item,
			res:      result,
			ts:       ts,
			serverID: serverID,
		}
	}
	s.itemsMu.Unlock()

	// The subscription was recreated (after a reconnect, or because the
	// server had dropped it) while the request was on its way: the items
	// were created in the subscription that no longer exists, and the
	// recreation may have run before they were stored above. Have it done
	// again with them, or they would never report.
	if s.id() != req.SubscriptionID {
		s.c.recreateSubscriptionLater(s)
	}

	return res, err
}

func (s *Subscription) Unmonitor(ctx context.Context, monitoredItemIDs ...uint32) (*ua.DeleteMonitoredItemsResponse, error) {
	stats.Subscription().Add("Unmonitor", 1)
	stats.Subscription().Add("UnmonitoredItems", int64(len(monitoredItemIDs)))

	req := &ua.DeleteMonitoredItemsRequest{
		MonitoredItemIDs: s.serverItemIDs(monitoredItemIDs),
		SubscriptionID:   s.id(),
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
			err = fmt.Errorf("opcua: sub %d: cannot modify unknown monitored item id: %d", s.id(), id)
			break
		}
	}
	s.itemsMu.Unlock()

	if err != nil {
		return nil, err
	}

	// The request goes out with the ids the server knows; the caller's
	// requests are not changed.
	onWire := make([]*ua.MonitoredItemModifyRequest, len(items))
	s.itemsMu.Lock()
	for i, item := range items {
		cp := *item
		cp.MonitoredItemID = s.serverItemIDNeedsLock(item.MonitoredItemID)
		onWire[i] = &cp
	}
	s.itemsMu.Unlock()

	req := &ua.ModifyMonitoredItemsRequest{
		SubscriptionID:     s.id(),
		TimestampsToReturn: ts,
		ItemsToModify:      onWire,
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

		if i >= len(items) {
			break
		}
		id := items[i].MonitoredItemID
		item := s.items[id]
		if item == nil {
			// Unmonitor removed the item while the request was in flight.
			continue
		}
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
			err = fmt.Errorf("opcua: sub %d: cannot set monitoring mode for unknown monitored item id: %d", s.id(), id)
			break
		}
	}
	s.itemsMu.Unlock()

	if err != nil {
		return nil, err
	}

	req := &ua.SetMonitoringModeRequest{
		SubscriptionID:   s.id(),
		MonitoringMode:   monitoringMode,
		MonitoredItemIDs: s.serverItemIDs(monitoredItemIDs),
	}
	var res *ua.SetMonitoringModeResponse
	res, err = send[ua.SetMonitoringModeResponse](ctx, s.c, req)
	if err != nil {
		return nil, err
	}

	// Remember the mode: it is part of what the subscription monitors, so an
	// item that was disabled (or set to sampling) must come back that way
	// when the subscription is recreated after a reconnect, not in the mode
	// it was created with. The stored request is copied because it belongs
	// to the caller of Monitor.
	s.itemsMu.Lock()
	for i, id := range monitoredItemIDs {
		if i >= len(res.Results) || res.Results[i] != ua.StatusOK {
			continue
		}
		if item, ok := s.items[id]; ok && item.req != nil && item.req.MonitoringMode != monitoringMode {
			cp := *item.req
			cp.MonitoringMode = monitoringMode
			item.req = &cp
		}
	}
	s.itemsMu.Unlock()

	return res, nil
}

// SetTriggering sends a request to the server to add and/or remove triggering links from a triggering item.
// To add links from a triggering item to an item to report provide the ID(s) returned by Monitor in the `add` argument.
// To remove links from a triggering item to an item to report provide the ID(s) returned by Monitor in the `remove` argument.
func (s *Subscription) SetTriggering(ctx context.Context, triggeringItemID uint32, add, remove []uint32) (*ua.SetTriggeringResponse, error) {
	stats.Subscription().Add("SetTriggering", 1)

	// Part 4, 5.12.5.2 SetTriggering Service Parameters
	req := &ua.SetTriggeringRequest{
		SubscriptionID:   s.id(),
		TriggeringItemID: s.serverItemIDs([]uint32{triggeringItemID})[0],
		LinksToAdd:       s.serverItemIDs(add),
		LinksToRemove:    s.serverItemIDs(remove),
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
		SubscriptionIDs:   []uint32{s.id()},
	}

	return send[ua.SetPublishingModeResponse](ctx, s.c, req)
}

func (s *Subscription) publishTimeout() time.Duration {
	s.paramsMu.Lock()
	timeout := time.Duration(s.RevisedMaxKeepAliveCount) * s.RevisedPublishingInterval // expected keepalive interval
	s.paramsMu.Unlock()
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
	case <-s.cancelled:
		// nobody is expected to read Notifs any more
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
		return nil, fmt.Errorf("%w: sub=%d", errors.ErrEmptyResponse, s.id())
	}

	eos, ok := v.Value().([]*ua.ExtensionObject)
	if !ok {
		return nil, fmt.Errorf("%w: sub=%d nodeID=%s got=%T", errors.ErrInvalidResponseType, s.id(), node.String(), v.Value())
	}

	for _, eo := range eos {
		stat, ok := eo.Value.(*ua.SubscriptionDiagnosticsDataType)
		if !ok {
			continue
		}

		if stat.SubscriptionID == s.id() {
			return stat, nil
		}
	}

	return nil, fmt.Errorf("%w: sub=%d", errors.ErrSubscriptionNotFound, s.id())
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
		SubscriptionIDs: []uint32{s.id()},
	}
	if _, err := send[ua.DeleteSubscriptionsResponse](ctx, s.c, req); err != nil {
		s.c.cfg.logger.Debug("recreateDelete: delete failed (continuing anyway)", "sub_id", s.id(), "error", err)
	}
	s.c.cfg.logger.Debug("recreateDelete: subscription deleted", "sub_id", s.id())
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
	res, err := s.c.createSubscription(ctx, req)
	if err != nil {
		s.c.cfg.logger.Debug("recreateCreate: failed to recreate subscription", "sub_id", s.id())
		return err
	}
	// Redundant: send[T]() already checks ServiceResult via SecureChannel.Receive().
	// Kept as defense-in-depth.
	if status := res.ResponseHeader.ServiceResult; status != ua.StatusOK {
		return status
	}
	s.c.cfg.logger.Debug("recreateCreate: recreated subscription", "sub_id", s.id(), "new_sub_id", res.SubscriptionID)

	s.setID(res.SubscriptionID)
	s.paramsMu.Lock()
	s.RevisedPublishingInterval = time.Duration(res.RevisedPublishingInterval) * time.Millisecond
	s.RevisedLifetimeCount = res.RevisedLifetimeCount
	s.RevisedMaxKeepAliveCount = res.RevisedMaxKeepAliveCount
	s.paramsMu.Unlock()
	s.lastSeq = 0
	s.nextSeq = 1

	if err := s.c.registerSubscriptionNeedsSubMuxLock(s); err != nil {
		return err
	}
	s.c.cfg.logger.Debug("recreateCreate: subscription registered", "sub_id", s.id())

	// Sort by timestamp to return
	itemsByTimestamps := make(map[ua.TimestampsToReturn][]*ua.MonitoredItemCreateRequest)
	// idsByTimestamps holds, in the same order, the ids the caller knows the
	// items by. They are kept: only the server's ids change.
	idsByTimestamps := make(map[ua.TimestampsToReturn][]uint32)
	s.itemsMu.Lock()
	previous := s.items
	for id, mi := range s.items {
		itemsByTimestamps[mi.ts] = append(itemsByTimestamps[mi.ts], mi.req)
		idsByTimestamps[mi.ts] = append(idsByTimestamps[mi.ts], id)
	}
	s.items = make(map[uint32]*monitoredItem, len(s.items))
	s.itemsMu.Unlock()

	// If the monitored items cannot all be created, keep the complete list
	// of what the subscription is supposed to monitor: the next recovery
	// recreates the subscription from it. Dropping the list here would turn
	// one failed attempt into a subscription that never delivers again.
	restored := false
	defer func() {
		if !restored {
			s.itemsMu.Lock()
			s.items = previous
			s.itemsMu.Unlock()
		}
	}()

	for ts, items := range itemsByTimestamps {
		req := &ua.CreateMonitoredItemsRequest{
			SubscriptionID:     s.id(),
			TimestampsToReturn: ts,
			ItemsToCreate:      items,
		}

		res, err := send[ua.CreateMonitoredItemsResponse](ctx, s.c, req)
		if err != nil {
			s.c.cfg.logger.Debug("recreateCreate: failed to create monitored items", "sub_id", s.id(), "error", err)
			return err
		}

		if len(res.Results) != len(items) {
			return fmt.Errorf("opcua: %d results for %d monitored items: %w", len(res.Results), len(items), ua.StatusBadUnknownResponse)
		}
		for _, result := range res.Results {
			if result == nil {
				return ua.StatusBadUnknownResponse
			}
			if status := result.StatusCode; status != ua.StatusOK {
				return status
			}
		}

		ids := idsByTimestamps[ts]
		s.itemsMu.Lock()
		for i, item := range items {
			result := res.Results[i]
			serverID := result.MonitoredItemID
			result.MonitoredItemID = ids[i]
			s.items[ids[i]] = &monitoredItem{
				req:      item,
				res:      result,
				ts:       ts,
				serverID: serverID,
			}
		}
		s.itemsMu.Unlock()
	}
	s.c.cfg.logger.Debug("recreateCreate: subscription successfully recreated", "sub_id", s.id())

	restored = true
	return nil
}
