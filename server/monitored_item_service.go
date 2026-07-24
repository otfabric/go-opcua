// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
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
}

// DeleteMonitoredItem removes all references to a specific monitored item by ID.
func (s *MonitoredItemService) DeleteMonitoredItem(id uint32) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	item, ok := s.Items[id]
	if !ok {
		// id does not exist.
		return
	}

	if item == nil || item.Req == nil || item.Req.ItemToMonitor == nil || item.Req.ItemToMonitor.NodeID == nil {
		return
	}
	nodeid := item.Req.ItemToMonitor.NodeID.String()

	if s == nil || s.Nodes == nil || s.Nodes[nodeid] == nil {
		return
	}

	// delete the monitored item from all nodes
	// was using slices.DeleteFunc but that is from a newer go version so we'll do it manually with /exp/slices
	// we've got to go backwards because we're deleting from the slice as we go.
	// I'm guessing this loop is less efficient than slices.DeleteFunc but it's what we've got.
	delete(s.Items, id)
	for i := len(s.Nodes[nodeid]) - 1; i >= 0; i-- {
		n := s.Nodes[nodeid][i]
		if n == nil {
			continue
		}
		if n.ID == id {
			s.Nodes[nodeid] = slices.Delete(s.Nodes[nodeid], i, i+1)
		}
	}
	//slices.DeleteFunc(s.Nodes[nodeid], func(i *MonitoredItem) bool { return i.ID == item.ID })
	if len(s.Nodes[nodeid]) == 0 {
		delete(s.Nodes, nodeid)
	}

	for i := len(s.Subs[item.Sub.ID]) - 1; i >= 0; i-- {
		n := s.Subs[item.Sub.ID][i]
		if n == nil {
			continue
		}
		if n.ID == id {
			s.Subs[item.Sub.ID] = slices.Delete(s.Subs[item.Sub.ID], i, i+1)
		}
	}
	//slices.DeleteFunc(s.Subs[item.Sub.ID], func(i *MonitoredItem) bool { return i.ID == item.ID })
	if len(s.Subs[item.Sub.ID]) == 0 {
		delete(s.Subs, item.Sub.ID)
	}
}

// DeleteSub deletes all monitored items associated with a specific subscription ID.
func (s *MonitoredItemService) DeleteSub(id uint32) {
	s.Mu.Lock()
	items, ok := s.Subs[id]
	delete(s.Subs, id)
	s.Mu.Unlock()
	if !ok {
		return
	}
	for i := range items {
		if items[i] != nil {
			s.DeleteMonitoredItem(items[i].ID)
		}
	}
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
	limit := int(max)
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

func (s *MonitoredItemService) ChangeNotification(n *ua.NodeID) {

	s.Mu.Lock()
	defer s.Mu.Unlock()
	items, ok := s.Nodes[n.String()]

	if !ok {
		// this node isn't monitored - don't have to do anything.
		return
	}

	ns, err := s.SubService.srv.Namespace(int(n.Namespace()))

	for i := range items {
		item := items[i]
		if item == nil {
			continue
		}
		// Disabled: do not sample or enqueue (Part 4 §5.12.1.3).
		if item.Mode == ua.MonitoringModeDisabled {
			continue
		}
		val := new(ua.MonitoredItemNotification)
		val.ClientHandle = item.Req.RequestedParameters.ClientHandle
		if err != nil {
			s.SubService.srv.cfg.logger.Warn("error getting namespace", "namespace", n.Namespace(), "error", err)
			val.Value = &ua.DataValue{}
			val.Value.Status = ua.StatusBad
			val.Value.EncodingMask |= ua.DataValueStatusCode
			item.enqueue(val)
			if item.Mode == ua.MonitoringModeReporting {
				select {
				case item.Sub.NotifyChannel <- val:
				default:
				}
			}
			continue
		}
		dv := ns.Attribute(n, item.Req.ItemToMonitor.AttributeID)
		if dv != nil {
			// Copy so timestamp filtering / overflow bits do not mutate the node store.
			cp := *dv
			dv = &cp
			_ = ua.ApplyTimestampsToReturn(dv, item.timestampsToReturn)
		}
		val.Value = dv
		item.enqueue(val)
		// Sampling queues without waking Publish; Reporting wakes the publish loop.
		if item.Mode == ua.MonitoringModeReporting {
			select {
			case item.Sub.NotifyChannel <- val:
			default:
			}
		}
	}

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
	return ns.Node(nodeid) != nil
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
		return nil, errors.New("sub doesn't exist")
	}

	sess := s.SubService.srv.Session(req.RequestHeader)
	if sess == nil || sub.Session == nil || sub.Session.AuthTokenID == nil ||
		sess.AuthTokenID == nil || !sub.Session.AuthTokenID.Equal(sess.AuthTokenID) {
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

	for i := range req.ItemsToCreate {
		itemreq := req.ItemsToCreate[i]
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

		qsize := uint32(1)
		discardOldest := true
		if itemreq.RequestedParameters != nil {
			qsize = reviseQueueSize(itemreq.RequestedParameters.QueueSize)
			discardOldest = itemreq.RequestedParameters.DiscardOldest
		}

		item := MonitoredItem{
			ID:                 s.NextID(),
			Sub:                sub,
			Req:                itemreq,
			Mode:               itemreq.MonitoringMode,
			queueSize:          qsize,
			discardOldest:      discardOldest,
			timestampsToReturn: ts,
			queue:              make([]*ua.MonitoredItemNotification, 0, qsize),
		}

		// Check for event monitoring (AttributeIDEventNotifier with EventFilter).
		isEventItem := itemreq.ItemToMonitor.AttributeID == ua.AttributeIDEventNotifier
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

		s.SubService.srv.cfg.logger.Debug("adding monitored item", "node_id", nodeid.String(), "sub_id", subID, "item_id", item.ID, "client_handle", itemreq.RequestedParameters.ClientHandle, "queue_size", qsize)
		res[i] = &ua.MonitoredItemCreateResult{
			StatusCode:              ua.StatusOK,
			MonitoredItemID:         item.ID,
			RevisedSamplingInterval: sub.RevisedPublishingInterval,
			RevisedQueueSize:        qsize,
			FilterResult:            filterResult,
		}
		// For data items, do an initial update for the nodeids in the background.
		if !isEventItem {
			go s.ChangeNotification(nodeid)
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

	sess := s.SubService.srv.Session(req.RequestHeader)

	results := make([]*ua.MonitoredItemModifyResult, len(req.ItemsToModify))
	for i, item := range req.ItemsToModify {
		mi, ok := s.Items[item.MonitoredItemID]
		if !ok {
			results[i] = &ua.MonitoredItemModifyResult{
				StatusCode: ua.StatusBadMonitoredItemIDInvalid,
			}
			continue
		}

		if sess == nil || mi.Sub.Session.AuthTokenID.String() != sess.AuthTokenID.String() {
			results[i] = &ua.MonitoredItemModifyResult{
				StatusCode: ua.StatusBadSessionIDInvalid,
			}
			continue
		}

		// Update the monitored item's parameters.
		if item.RequestedParameters != nil {
			mi.Req.RequestedParameters = item.RequestedParameters
			mi.queueSize = reviseQueueSize(item.RequestedParameters.QueueSize)
			mi.discardOldest = item.RequestedParameters.DiscardOldest
			if len(mi.queue) > int(mi.queueSize) {
				// Keep the newest samples when shrinking the queue.
				mi.queue = mi.queue[len(mi.queue)-int(mi.queueSize):]
			}
			// Re-validate and update event filter when the item monitors events.
			if mi.Req.ItemToMonitor != nil &&
				mi.Req.ItemToMonitor.AttributeID == ua.AttributeIDEventNotifier &&
				item.RequestedParameters.Filter != nil {
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

		revisedSampling := float64(0)
		revisedQueue := mi.queueSize
		if item.RequestedParameters != nil {
			revisedSampling = item.RequestedParameters.SamplingInterval
		}

		results[i] = &ua.MonitoredItemModifyResult{
			StatusCode:              ua.StatusOK,
			RevisedSamplingInterval: revisedSampling,
			RevisedQueueSize:        revisedQueue,
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

	sess := s.SubService.srv.Session(req.RequestHeader)

	for i := range req.MonitoredItemIDs {
		id := req.MonitoredItemIDs[i]
		item, ok := s.Items[id]
		if !ok {
			results[i] = ua.StatusBadMonitoredItemIDInvalid
			continue
		}

		if sess == nil || item.Sub.Session.AuthTokenID.String() != sess.AuthTokenID.String() {
			results[i] = ua.StatusBadSessionIDInvalid
			continue
		}

		prev := item.Mode
		item.Mode = req.MonitoringMode
		if req.MonitoringMode == ua.MonitoringModeDisabled {
			item.queue = item.queue[:0]
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

	sess := s.SubService.srv.Session(req.RequestHeader)
	if sess == nil || triggerItem.Sub.Session.AuthTokenID.String() != sess.AuthTokenID.String() {
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

	sess := s.SubService.srv.Session(req.RequestHeader)

	results := make([]ua.StatusCode, len(req.MonitoredItemIDs))
	for i := range req.MonitoredItemIDs {
		id := req.MonitoredItemIDs[i]
		item, ok := s.Items[id]
		if !ok {
			results[i] = ua.StatusBadMonitoredItemIDInvalid
			continue
		}

		if sess == nil || item.Sub.Session.AuthTokenID.String() != sess.AuthTokenID.String() {
			results[i] = ua.StatusBadSessionIDInvalid
			continue
		}

		// this function gets the lock so we need to do it in the background so it can happen after our lock is released.
		go s.DeleteMonitoredItem(id)
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
