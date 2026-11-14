// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

// MonitoredItemService implements the MonitoredItem Service Set.
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.12
type MonitoredItemService struct {
	SubService *SubscriptionService
	Mu         sync.Mutex

	// items tracked by ID
	Items map[uint32]*MonitoredItem
	// items tracked by node
	Nodes map[string][]*MonitoredItem
	// items tracked by subscription
	Subs map[uint32][]*MonitoredItem

	id uint32

	// due holds the items whose next sample was postponed to the end of
	// their sampling interval, and sampler is the one timer that serves
	// them; see monitored_item_filter.go. Guarded by Mu.
	due       map[uint32]*MonitoredItem
	sampler   *time.Timer
	samplerAt time.Time
	// samplerRuns is the number of sampler callbacks in flight (for tests).
	samplerRuns atomic.Int32
}

// DeleteMonitoredItem removes all references to a specific monitored item by ID.
func (s *MonitoredItemService) DeleteMonitoredItem(id uint32) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	s.deleteMonitoredItemNeedsLock(id)
}

// deleteMonitoredItemNeedsLock is DeleteMonitoredItem for callers that hold
// s.Mu.
func (s *MonitoredItemService) deleteMonitoredItemNeedsLock(id uint32) {
	if item, ok := s.Items[id]; ok {
		s.removeItemsNeedsLock([]*MonitoredItem{item})
	}
}

// removeItemsNeedsLock removes items from all indexes. Every node and
// subscription list the items are on is compacted once, so removing n items
// costs O(n) plus the length of the lists they were on, not O(n²).
// Caller must hold s.Mu.
func (s *MonitoredItemService) removeItemsNeedsLock(items []*MonitoredItem) {
	if len(items) == 0 {
		return
	}
	gone := make(map[*MonitoredItem]struct{}, len(items))
	nodes := make(map[string]struct{})
	subs := make(map[uint32]struct{})
	for _, item := range items {
		if item == nil || s.Items[item.ID] != item {
			continue
		}
		delete(s.Items, item.ID)
		gone[item] = struct{}{}
		s.diagnostics().untrackItem(item)
		// A postponed sample dies with the item, and the sampler timer with
		// the last postponed sample.
		s.cancelDeferredSample(item)
		if item.isEvent && s.SubService != nil && s.SubService.srv != nil && s.SubService.srv.eventItems != nil {
			s.SubService.srv.eventItems.unregister(item.ID)
		}
		if item.Sub != nil {
			// The events of the item are discarded with it.
			item.Sub.dropEventQueue(item)
		}
		if item.Req != nil && item.Req.ItemToMonitor != nil && item.Req.ItemToMonitor.NodeID != nil {
			nodes[item.Req.ItemToMonitor.NodeID.String()] = struct{}{}
		}
		if item.Sub != nil {
			subs[item.Sub.ID] = struct{}{}
		}
	}
	if len(gone) == 0 {
		return
	}
	isGone := func(m *MonitoredItem) bool {
		_, ok := gone[m]
		return m == nil || ok
	}
	for k := range nodes {
		if l := slices.DeleteFunc(s.Nodes[k], isGone); len(l) > 0 {
			s.Nodes[k] = l
		} else {
			delete(s.Nodes, k)
		}
	}
	for k := range subs {
		if l, ok := s.Subs[k]; ok {
			if l = slices.DeleteFunc(l, isGone); len(l) > 0 {
				s.Subs[k] = l
			} else {
				delete(s.Subs, k)
			}
		}
	}
}

// DeleteSub deletes all monitored items associated with a specific subscription ID.
func (s *MonitoredItemService) DeleteSub(id uint32) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	items, ok := s.Subs[id]
	delete(s.Subs, id)
	if !ok {
		return
	}
	s.removeItemsNeedsLock(items)
}

const maxMonitoredItemQueueSize = 100

func reviseQueueSize(requested uint32) uint32 {
	if requested == 0 {
		return 1
	}
	if requested > maxMonitoredItemQueueSize {
		return maxMonitoredItemQueueSize
	}
	return requested
}

// enqueue applies Part 4 MonitoringParameters queue semantics.
// Caller must hold s.Mu.
func (item *MonitoredItem) enqueue(n *ua.MonitoredItemNotification) {
	if item.queueSize <= 1 {
		item.queue = item.queue[:0]
		item.queue = append(item.queue, n)
		return
	}
	if len(item.queue) < int(item.queueSize) {
		item.queue = append(item.queue, n)
		return
	}
	// Queue full — apply discard policy and set Overflow InfoBit.
	if item.discardOldest {
		item.queue = append(item.queue[1:], n)
		if item.queue[0].Value != nil {
			item.queue[0].Value.Status = item.queue[0].Value.Status.WithOverflow()
			item.queue[0].Value.EncodingMask |= ua.DataValueStatusCode
		}
	} else {
		item.queue[len(item.queue)-1] = n
		if n.Value != nil {
			n.Value.Status = n.Value.Status.WithOverflow()
			n.Value.EncodingMask |= ua.DataValueStatusCode
		}
	}
}

// DrainQueuedNotifications removes and returns queued notifications for
// Reporting-mode items of the subscription, in monitored-item registration
// order. Same ClientHandle may appear multiple times when QueueSize > 1.
//
// max limits how many notifications are returned in this Publish (0 = unlimited).
// more is true when Reporting queues still hold samples after this drain.
func (s *MonitoredItemService) DrainQueuedNotifications(subID uint32, max uint32) (out []*ua.MonitoredItemNotification, more bool) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	items := s.Subs[subID]
	limit := intOfUint32(max)
	unlimited := max == 0
	for _, item := range items {
		if item == nil || item.Mode != ua.MonitoringModeReporting || len(item.queue) == 0 {
			continue
		}
		for len(item.queue) > 0 {
			if !unlimited && len(out) >= limit {
				more = true
				return out, more
			}
			out = append(out, item.queue[0])
			item.queue = item.queue[1:]
		}
	}
	return out, false
}

// PendingQueuedNotifications reports whether any monitored item for subID
// currently has queued notifications (any MonitoringMode).
func (s *MonitoredItemService) PendingQueuedNotifications(subID uint32) bool {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	for _, item := range s.Subs[subID] {
		if item != nil && len(item.queue) > 0 {
			return true
		}
	}
	return false
}

// PendingReportableNotifications reports whether any Reporting-mode item for
// subID currently has queued notifications ready for Publish.
func (s *MonitoredItemService) PendingReportableNotifications(subID uint32) bool {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	for _, item := range s.Subs[subID] {
		if item != nil && item.Mode == ua.MonitoringModeReporting && len(item.queue) > 0 {
			return true
		}
	}
	return false
}

// ChangeNotification tells the service that the node changed. Every enabled
// data item on the node is sampled, subject to its sampling interval, and the
// sample is queued when the item's DataChangeFilter lets it through; see
// monitored_item_filter.go.
func (s *MonitoredItemService) ChangeNotification(n *ua.NodeID) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	items, ok := s.Nodes[n.String()]
	if !ok {
		// this node isn't monitored - don't have to do anything.
		return
	}

	now := time.Now()
	for i := range items {
		item := items[i]
		// Event items are fed by EmitEvent, not by data changes.
		if item == nil || item.isEvent {
			continue
		}
		// Disabled: do not sample or enqueue (Part 4 §5.12.1.3).
		if item.Mode == ua.MonitoringModeDisabled {
			continue
		}
		if item.samplingInterval > 0 {
			// At most one sample per sampling interval: a change inside the
			// current interval is picked up when the interval ends.
			if due := item.lastSampled.Add(item.samplingInterval); now.Before(due) {
				s.deferSample(item, due)
				continue
			}
		}
		s.sampleItem(item, now, false)
	}
}

// sampleInitial queues the first value of a newly created item. Only that
// item is sampled: its siblings on the same node have nothing new to report.
// Caller must hold s.Mu.
func (s *MonitoredItemService) sampleInitial(item *MonitoredItem) {
	defer func() {
		if r := recover(); r != nil {
			logPanic(s.SubService.srv.cfg.logger, "sampling the initial value of a monitored item", r)
		}
	}()
	s.sampleItem(item, time.Now(), true)
}

// nodeExists reports whether the given node id resolves to a node in a
// registered namespace.
func (s *MonitoredItemService) nodeExists(nodeid *ua.NodeID) bool {
	if nodeid == nil {
		return false
	}
	ns, err := s.SubService.srv.Namespace(int(nodeid.Namespace()))
	if err != nil {
		return false
	}
	if ns.Node(nodeid) != nil {
		return true
	}
	// Not every namespace is backed by Node objects: MapNamespace serves its
	// keys through Attribute only and has no Node for them. Such a variable
	// exists if its Value can be read; otherwise none of its keys could ever
	// be monitored.
	if dv := ns.Attribute(nodeid, ua.AttributeIDValue); dv != nil && dv.Status == ua.StatusOK {
		return true
	}
	return false
}

func (s *MonitoredItemService) NextID() uint32 {
	i := atomic.AddUint32(&s.id, 1)
	if i == 0 {
		i = atomic.AddUint32(&s.id, 1)
	}
	return i
}

type MonitoredItem struct {
	ID  uint32
	Sub *Subscription
	Req *ua.MonitoredItemCreateRequest

	// Mode controls sampling and Publish delivery (Part 4 §5.12.1.3):
	// Disabled = no enqueue; Sampling = enqueue only; Reporting = enqueue + Publish.
	Mode ua.MonitoringMode

	queueSize          uint32
	discardOldest      bool
	timestampsToReturn ua.TimestampsToReturn
	queue              []*ua.MonitoredItemNotification

	// isEvent marks an item on the EventNotifier attribute.
	isEvent bool
	// The event queue of an event item, its revised QueueSize and its
	// DiscardOldest, guarded by Sub.evMu (event_queue.go).
	events          []queuedEvent
	evQueueSize     uint32
	evDiscardOldest bool
	// Data-change sampling state, see monitored_item_filter.go.
	filter           dataChangeFilter
	indexRange       string
	samplingInterval time.Duration // 0 = exception based
	lastSampled      time.Time
	sampleDue        time.Time // non-zero while a postponed sample is pending
	last             sampleState
	hasLast          bool
}

// CreateMonitoredItems implements the OPC UA CreateMonitoredItems service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.12.2
func (s *MonitoredItemService) CreateMonitoredItems(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.SubService.srv.cfg.logger.Debug("handling request", "type", fmt.Sprintf("%T", r))

	req, err := safeReq[*ua.CreateMonitoredItemsRequest](r)
	if err != nil {
		return nil, err
	}
	s.Mu.Lock()
	defer s.Mu.Unlock()

	count := len(req.ItemsToCreate)

	res := make([]*ua.MonitoredItemCreateResult, count)

	subID := req.SubscriptionID
	s.SubService.srv.cfg.logger.Debug("creating monitored items", "sub_id", subID)
	s.SubService.Mu.Lock()
	sub, ok := s.SubService.Subs[subID]
	s.SubService.Mu.Unlock()
	if !ok {
		// Part 4 §5.12.2.3: an unknown subscription is a service-level
		// BadSubscriptionIdInvalid, not an internal error.
		return nil, ua.StatusBadSubscriptionIDInvalid
	}
	// Session and timing may be changed concurrently by TransferSubscriptions
	// and ModifySubscription.
	subSess, _ := sub.sessionChannel()
	pubInterval, _, _ := sub.timing()

	sess := s.SubService.srv.session(req.RequestHeader)
	if sess == nil || subSess == nil || subSess.AuthTokenID == nil ||
		sess.AuthTokenID == nil || !subSess.AuthTokenID.Equal(sess.AuthTokenID) {
		// Wrong/missing session must not become BadUnexpectedError via a plain error.
		return &ua.CreateMonitoredItemsResponse{
			ResponseHeader: &ua.ResponseHeader{
				Timestamp:          time.Now(),
				RequestHandle:      req.RequestHeader.RequestHandle,
				ServiceResult:      ua.StatusBadSubscriptionIDInvalid,
				ServiceDiagnostics: &ua.DiagnosticInfo{},
				StringTable:        []string{},
				AdditionalHeader:   ua.NewExtensionObject(nil),
			},
			Results:         res,
			DiagnosticInfos: []*ua.DiagnosticInfo{},
		}, nil
	}

	ts := req.TimestampsToReturn
	if sc := ua.ApplyTimestampsToReturn(&ua.DataValue{}, ts); sc != ua.StatusOK {
		return &ua.CreateMonitoredItemsResponse{
			ResponseHeader: &ua.ResponseHeader{
				Timestamp:          time.Now(),
				RequestHandle:      req.RequestHeader.RequestHandle,
				ServiceResult:      sc,
				ServiceDiagnostics: &ua.DiagnosticInfo{},
				StringTable:        []string{},
				AdditionalHeader:   ua.NewExtensionObject(nil),
			},
			Results:         res,
			DiagnosticInfos: []*ua.DiagnosticInfo{},
		}, nil
	}

	counts := s.itemCountsLocked(sess, subID)
	for i := range req.ItemsToCreate {
		itemreq := req.ItemsToCreate[i]
		if counts.full(s.SubService.srv.cfg) {
			// Part 4 §5.12.2: Bad_TooManyMonitoredItems.
			res[i] = &ua.MonitoredItemCreateResult{
				StatusCode:   ua.StatusBadTooManyMonitoredItems,
				FilterResult: ua.NewExtensionObject(nil),
			}
			continue
		}
		if itemreq == nil || itemreq.ItemToMonitor == nil {
			res[i] = &ua.MonitoredItemCreateResult{
				StatusCode:   ua.StatusBadNodeIDInvalid,
				FilterResult: ua.NewExtensionObject(nil),
			}
			continue
		}
		nodeid := itemreq.ItemToMonitor.NodeID

		// Validate the node exists. Reject unknown nodes individually so a
		// single bad node id does not fail the whole batch (Part 4 §5.12.2).
		if !s.nodeExists(nodeid) {
			s.SubService.srv.cfg.logger.Debug("rejecting monitored item for unknown node", "node_id", nodeid, "sub_id", subID)
			res[i] = &ua.MonitoredItemCreateResult{
				StatusCode:   ua.StatusBadNodeIDUnknown,
				FilterResult: ua.NewExtensionObject(nil),
			}
			continue
		}
		// The diagnostics of other sessions cannot be monitored either; a data
		// item needs what Read needs.
		if st := s.SubService.srv.checkMonitorRead(ctx, sc, sess, itemreq.ItemToMonitor); st != ua.StatusOK {
			res[i] = &ua.MonitoredItemCreateResult{StatusCode: st, FilterResult: ua.NewExtensionObject(nil)}
			continue
		}

		if itemreq.RequestedParameters == nil {
			itemreq.RequestedParameters = &ua.MonitoringParameters{DiscardOldest: true}
		}
		discardOldest := itemreq.RequestedParameters.DiscardOldest
		isEventItem := itemreq.ItemToMonitor.AttributeID == ua.AttributeIDEventNotifier
		qsize := reviseQueueSize(itemreq.RequestedParameters.QueueSize)
		if isEventItem {
			qsize = reviseEventQueueSize(itemreq.RequestedParameters.QueueSize)
		}

		// Data items: validate the IndexRange and the DataChangeFilter and
		// revise the sampling interval before anything is registered.
		// Events are not sampled (Part 4 §5.13.1.2), their interval is 0.
		filter := defaultDataChangeFilter()
		samplingMS := 0.0
		if !isEventItem {
			if r := itemreq.ItemToMonitor.IndexRange; r != "" {
				if _, err := ua.ParseNumericRanges(r); err != nil {
					res[i] = &ua.MonitoredItemCreateResult{
						StatusCode:   ua.StatusBadIndexRangeInvalid,
						FilterResult: ua.NewExtensionObject(nil),
					}
					continue
				}
			}
			var st ua.StatusCode
			if filter, st = s.parseDataChangeFilter(itemreq.ItemToMonitor, itemreq.RequestedParameters.Filter); st != ua.StatusOK {
				res[i] = &ua.MonitoredItemCreateResult{
					StatusCode:   st,
					FilterResult: ua.NewExtensionObject(nil),
				}
				continue
			}
			samplingMS = reviseSamplingInterval(itemreq.RequestedParameters.SamplingInterval,
				float64(pubInterval)/float64(time.Millisecond))
		}

		item := MonitoredItem{
			ID:                 s.NextID(),
			Sub:                sub,
			Req:                itemreq,
			Mode:               itemreq.MonitoringMode,
			queueSize:          qsize,
			discardOldest:      discardOldest,
			timestampsToReturn: ts,
			queue:              make([]*ua.MonitoredItemNotification, 0, min(qsize, maxMonitoredItemQueueSize)),
			isEvent:            isEventItem,
			evQueueSize:        qsize,
			evDiscardOldest:    discardOldest,
			filter:             filter,
			indexRange:         itemreq.ItemToMonitor.IndexRange,
			samplingInterval:   time.Duration(samplingMS * float64(time.Millisecond)),
		}

		// Check for event monitoring (AttributeIDEventNotifier with EventFilter).
		var filterResult *ua.ExtensionObject
		if isEventItem {
			var ef *ua.EventFilter
			if itemreq.RequestedParameters != nil && itemreq.RequestedParameters.Filter != nil {
				if filter, ok := itemreq.RequestedParameters.Filter.Value.(*ua.EventFilter); ok {
					ef = filter
				} else if filter, ok := itemreq.RequestedParameters.Filter.Value.(ua.EventFilter); ok {
					ef = &filter
				}
			}
			if ef == nil {
				res[i] = &ua.MonitoredItemCreateResult{
					StatusCode:   ua.StatusBadEventFilterInvalid,
					FilterResult: ua.NewExtensionObject(nil),
				}
				continue
			}
			emi, efr, sc := s.SubService.srv.validateEventFilter(ef)
			if sc != ua.StatusOK {
				res[i] = &ua.MonitoredItemCreateResult{
					StatusCode:   sc,
					FilterResult: ua.NewExtensionObject(nil),
				}
				continue
			}
			s.SubService.srv.eventItems.register(item.ID, emi)
			filterResult = ua.NewExtensionObject(efr)
		} else {
			filterResult = ua.NewExtensionObject(nil)
		}

		// book keeping of the new item
		s.Items[item.ID] = &item
		s.diagnostics().trackItem(&item)
		list, ok := s.Nodes[item.Req.ItemToMonitor.NodeID.String()]
		if !ok {
			list = make([]*MonitoredItem, 0, 1)
		}
		s.Nodes[item.Req.ItemToMonitor.NodeID.String()] = append(list, &item)

		list, ok = s.Subs[item.Sub.ID]
		if !ok {
			list = make([]*MonitoredItem, 0, 1)
		}
		s.Subs[item.Sub.ID] = append(list, &item)
		counts.total++
		counts.session++
		counts.subscription++

		s.SubService.srv.cfg.logger.Debug("adding monitored item", "node_id", nodeid.String(), "sub_id", subID, "item_id", item.ID, "client_handle", itemreq.RequestedParameters.ClientHandle, "queue_size", qsize)
		res[i] = &ua.MonitoredItemCreateResult{
			StatusCode:              ua.StatusOK,
			MonitoredItemID:         item.ID,
			RevisedSamplingInterval: samplingMS,
			RevisedQueueSize:        qsize,
			FilterResult:            filterResult,
		}
		// A data item reports its current value first (Part 4 §5.13.1.1).
		if !isEventItem && item.Mode != ua.MonitoringModeDisabled {
			s.sampleInitial(&item)
		}

	}

	resp := &ua.CreateMonitoredItemsResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		Results:         res,                    //                  []StatusCode
		DiagnosticInfos: []*ua.DiagnosticInfo{}, //          []*DiagnosticInfo
	}

	return resp, nil

}

// ModifyMonitoredItems implements the OPC UA ModifyMonitoredItems service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.12.3
func (s *MonitoredItemService) ModifyMonitoredItems(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.SubService.srv.cfg.logger.Debug("handling request", "type", fmt.Sprintf("%T", r))

	req, err := safeReq[*ua.ModifyMonitoredItemsRequest](r)
	if err != nil {
		return nil, err
	}

	s.Mu.Lock()
	defer s.Mu.Unlock()

	sess := s.SubService.srv.session(req.RequestHeader)

	results := make([]*ua.MonitoredItemModifyResult, len(req.ItemsToModify))
	for i, item := range req.ItemsToModify {
		mi, ok := s.Items[item.MonitoredItemID]
		if !ok {
			results[i] = &ua.MonitoredItemModifyResult{
				StatusCode: ua.StatusBadMonitoredItemIDInvalid,
			}
			continue
		}

		if !mi.Sub.ownedBy(sess) {
			results[i] = &ua.MonitoredItemModifyResult{
				StatusCode: ua.StatusBadSessionIDInvalid,
			}
			continue
		}

		// A data item gets its new filter validated first: an item whose
		// filter is rejected keeps all its current parameters.
		revisedSampling := float64(mi.samplingInterval) / float64(time.Millisecond)
		if item.RequestedParameters != nil && !mi.isEvent {
			filter, st := s.parseDataChangeFilter(mi.Req.ItemToMonitor, item.RequestedParameters.Filter)
			if st != ua.StatusOK {
				results[i] = &ua.MonitoredItemModifyResult{
					StatusCode:   st,
					FilterResult: ua.NewExtensionObject(nil),
				}
				continue
			}
			// The new filter and sampling interval apply to the samples
			// taken from now on; the last queued value stays the reference.
			mi.filter = filter
			pubInterval, _, _ := mi.Sub.timing()
			revisedSampling = reviseSamplingInterval(item.RequestedParameters.SamplingInterval,
				float64(pubInterval)/float64(time.Millisecond))
			mi.samplingInterval = time.Duration(revisedSampling * float64(time.Millisecond))
			s.diagnostics().trackItem(mi)
			// A sample that was postponed under the old interval becomes
			// due under the new one.
			if !mi.sampleDue.IsZero() {
				mi.sampleDue = mi.lastSampled.Add(mi.samplingInterval)
				s.armSampler(mi.sampleDue)
			}
		}

		// Update the monitored item's parameters.
		if item.RequestedParameters != nil {
			mi.Req.RequestedParameters = item.RequestedParameters
			mi.discardOldest = item.RequestedParameters.DiscardOldest
			if mi.isEvent {
				mi.queueSize = reviseEventQueueSize(item.RequestedParameters.QueueSize)
				mi.setEventQueue(mi.queueSize, mi.discardOldest)
			} else {
				mi.queueSize = reviseQueueSize(item.RequestedParameters.QueueSize)
			}
			if len(mi.queue) > int(mi.queueSize) {
				// Keep the newest samples when shrinking the queue.
				mi.queue = mi.queue[len(mi.queue)-int(mi.queueSize):]
			}
			// Re-validate and update event filter when the item monitors events.
			if mi.isEvent && item.RequestedParameters.Filter != nil {
				var ef *ua.EventFilter
				switch fv := item.RequestedParameters.Filter.Value.(type) {
				case *ua.EventFilter:
					ef = fv
				case ua.EventFilter:
					ef = &fv
				}
				if ef != nil {
					srv := s.SubService.srv
					if emi, _, sc := srv.validateEventFilter(ef); sc == ua.StatusOK && emi != nil {
						srv.eventItems.register(mi.ID, emi)
					}
				}
			}
		}
		if req.TimestampsToReturn != ua.TimestampsToReturnInvalid {
			if sc := ua.ApplyTimestampsToReturn(&ua.DataValue{}, req.TimestampsToReturn); sc == ua.StatusOK {
				mi.timestampsToReturn = req.TimestampsToReturn
			}
		}

		results[i] = &ua.MonitoredItemModifyResult{
			StatusCode:              ua.StatusOK,
			RevisedSamplingInterval: revisedSampling,
			RevisedQueueSize:        mi.queueSize,
			FilterResult:            ua.NewExtensionObject(nil),
		}
	}

	return &ua.ModifyMonitoredItemsResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		Results:         results,
		DiagnosticInfos: []*ua.DiagnosticInfo{},
	}, nil
}

// SetMonitoringMode implements the OPC UA SetMonitoringMode service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.12.4
func (s *MonitoredItemService) SetMonitoringMode(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.SubService.srv.cfg.logger.Debug("handling request", "type", fmt.Sprintf("%T", r))

	req, err := safeReq[*ua.SetMonitoringModeRequest](r)
	if err != nil {
		return nil, err
	}
	s.Mu.Lock()
	defer s.Mu.Unlock()

	results := make([]ua.StatusCode, len(req.MonitoredItemIDs))

	sess := s.SubService.srv.session(req.RequestHeader)

	for i := range req.MonitoredItemIDs {
		id := req.MonitoredItemIDs[i]
		item, ok := s.Items[id]
		if !ok {
			results[i] = ua.StatusBadMonitoredItemIDInvalid
			continue
		}

		if !item.Sub.ownedBy(sess) {
			results[i] = ua.StatusBadSessionIDInvalid
			continue
		}

		prev := item.Mode
		item.Mode = req.MonitoringMode
		s.diagnostics().trackItem(item)
		if req.MonitoringMode == ua.MonitoringModeDisabled {
			item.queue = item.queue[:0]
			// Nothing is cached while disabled: the first change after the
			// item is enabled again is reported whatever the filter.
			item.hasLast = false
			// A disabled item is not sampled, so nothing stays postponed.
			s.cancelDeferredSample(item)
		} else if prev != ua.MonitoringModeReporting && req.MonitoringMode == ua.MonitoringModeReporting {
			// Wake Publish so already-queued Sampling samples can be delivered.
			if len(item.queue) > 0 && item.Sub != nil {
				select {
				case item.Sub.NotifyChannel <- &ua.MonitoredItemNotification{}:
				default:
				}
			}
		}
		results[i] = ua.StatusOK
	}

	return &ua.SetMonitoringModeResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		Results:         results,
		DiagnosticInfos: []*ua.DiagnosticInfo{},
	}, nil

}

// SetTriggering implements the OPC UA SetTriggering service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.12.5
func (s *MonitoredItemService) SetTriggering(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.SubService.srv.cfg.logger.Debug("handling request", "type", fmt.Sprintf("%T", r))

	req, err := safeReq[*ua.SetTriggeringRequest](r)
	if err != nil {
		return nil, err
	}

	s.Mu.Lock()
	defer s.Mu.Unlock()

	// Validate the triggering item exists.
	triggerItem, ok := s.Items[req.TriggeringItemID]
	if !ok {
		return &ua.SetTriggeringResponse{
			ResponseHeader: responseHeader(req.RequestHeader.RequestHandle, ua.StatusBadMonitoredItemIDInvalid),
		}, nil
	}

	sess := s.SubService.srv.session(req.RequestHeader)
	if !triggerItem.Sub.ownedBy(sess) {
		return &ua.SetTriggeringResponse{
			ResponseHeader: responseHeader(req.RequestHeader.RequestHandle, ua.StatusBadSessionIDInvalid),
		}, nil
	}

	// Process links to add — validate each linked item exists.
	addResults := make([]ua.StatusCode, len(req.LinksToAdd))
	for i, linkID := range req.LinksToAdd {
		if _, exists := s.Items[linkID]; !exists {
			addResults[i] = ua.StatusBadMonitoredItemIDInvalid
		} else {
			addResults[i] = ua.StatusOK
		}
	}

	// Process links to remove — validate each linked item exists.
	removeResults := make([]ua.StatusCode, len(req.LinksToRemove))
	for i, linkID := range req.LinksToRemove {
		if _, exists := s.Items[linkID]; !exists {
			removeResults[i] = ua.StatusBadMonitoredItemIDInvalid
		} else {
			removeResults[i] = ua.StatusOK
		}
	}

	return &ua.SetTriggeringResponse{
		ResponseHeader:        responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
		AddResults:            addResults,
		AddDiagnosticInfos:    []*ua.DiagnosticInfo{},
		RemoveResults:         removeResults,
		RemoveDiagnosticInfos: []*ua.DiagnosticInfo{},
	}, nil
}

// DeleteMonitoredItems implements the OPC UA DeleteMonitoredItems service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.12.6
func (s *MonitoredItemService) DeleteMonitoredItems(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.SubService.srv.cfg.logger.Debug("handling request", "type", fmt.Sprintf("%T", r))

	req, err := safeReq[*ua.DeleteMonitoredItemsRequest](r)
	if err != nil {
		return nil, err
	}

	s.Mu.Lock()
	defer s.Mu.Unlock()

	sess := s.SubService.srv.session(req.RequestHeader)

	results := make([]ua.StatusCode, len(req.MonitoredItemIDs))
	for i := range req.MonitoredItemIDs {
		id := req.MonitoredItemIDs[i]
		item, ok := s.Items[id]
		if !ok {
			results[i] = ua.StatusBadMonitoredItemIDInvalid
			continue
		}

		if !item.Sub.ownedBy(sess) {
			results[i] = ua.StatusBadSessionIDInvalid
			continue
		}

		// The item is gone when the response is sent: a second delete of the
		// same id answers BadMonitoredItemIdInvalid, and nothing is sampled
		// for it any more.
		s.deleteMonitoredItemNeedsLock(id)
		results[i] = ua.StatusOK
	}

	response := &ua.DeleteMonitoredItemsResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		Results:         results,
		DiagnosticInfos: []*ua.DiagnosticInfo{},
	}
	return response, nil

}
