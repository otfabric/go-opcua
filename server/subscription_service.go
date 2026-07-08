// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

// SubscriptionService implements the Subscription Service Set.
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.13
type SubscriptionService struct {
	srv *Server
	// pub sub stuff
	Mu   sync.Mutex
	Subs map[uint32]*Subscription
}

// DeleteSubscription removes all references to a subscription and all monitored items pointed at it.
func (s *SubscriptionService) DeleteSubscription(id uint32) {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	sub, ok := s.Subs[id]
	if ok {
		sub.Mu.Lock()
		if sub.running {
			sub.running = false
			close(sub.shutdown)
		}
		sub.Mu.Unlock()
	}

	delete(s.Subs, id)

	// ask the monitored item service to purge out any items that use this subscription
	s.srv.MonitoredItemService.DeleteSub(id)

}

// CreateSubscription implements the OPC UA CreateSubscription service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.13.2
func (s *SubscriptionService) CreateSubscription(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.srv.cfg.logger.Debug("handling request", "type", fmt.Sprintf("%T", r))

	req, err := safeReq[*ua.CreateSubscriptionRequest](r)
	if err != nil {
		return nil, err
	}

	s.Mu.Lock()
	defer s.Mu.Unlock()

	newsubid := uint32(len(s.Subs)) + 1

	s.srv.cfg.logger.Info("new subscription", "sub_id", newsubid, "remote_addr", sc.RemoteAddr())

	sub := NewSubscription()
	sub.srv = s
	sub.Session = s.srv.Session(r.Header())
	sub.Channel = sc
	sub.ID = newsubid
	sub.RevisedPublishingInterval = req.RequestedPublishingInterval
	sub.RevisedLifetimeCount = req.RequestedLifetimeCount
	sub.RevisedMaxKeepAliveCount = req.RequestedMaxKeepAliveCount
	sub.publishingEnabled = req.PublishingEnabled

	s.Subs[newsubid] = sub
	sub.running = true
	sub.Start()

	resp := &ua.CreateSubscriptionResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		SubscriptionID:            uint32(newsubid),
		RevisedPublishingInterval: req.RequestedPublishingInterval,
		RevisedLifetimeCount:      req.RequestedLifetimeCount,
		RevisedMaxKeepAliveCount:  req.RequestedMaxKeepAliveCount,
	}
	return resp, nil
}

// ModifySubscription implements the OPC UA ModifySubscription service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.13.3
func (s *SubscriptionService) ModifySubscription(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.srv.cfg.logger.Debug("handling request", "type", fmt.Sprintf("%T", r))

	req, err := safeReq[*ua.ModifySubscriptionRequest](r)
	if err != nil {
		return nil, err
	}

	session := s.srv.Session(req.Header())

	s.Mu.Lock()
	defer s.Mu.Unlock()

	sub, ok := s.Subs[req.SubscriptionID]
	if !ok {
		return &ua.ModifySubscriptionResponse{
			ResponseHeader: &ua.ResponseHeader{
				Timestamp:          time.Now(),
				RequestHandle:      req.RequestHeader.RequestHandle,
				ServiceResult:      ua.StatusBadSubscriptionIDInvalid,
				ServiceDiagnostics: &ua.DiagnosticInfo{},
				StringTable:        []string{},
				AdditionalHeader:   ua.NewExtensionObject(nil),
			},
		}, nil
	}

	if session == nil || session.AuthTokenID.String() != sub.Session.AuthTokenID.String() {
		return &ua.ModifySubscriptionResponse{
			ResponseHeader: &ua.ResponseHeader{
				Timestamp:          time.Now(),
				RequestHandle:      req.RequestHeader.RequestHandle,
				ServiceResult:      ua.StatusBadSessionIDInvalid,
				ServiceDiagnostics: &ua.DiagnosticInfo{},
				StringTable:        []string{},
				AdditionalHeader:   ua.NewExtensionObject(nil),
			},
		}, nil
	}

	// Send the modify request to the subscription's background goroutine.
	select {
	case sub.ModifyChannel <- req:
	default:
	}

	return &ua.ModifySubscriptionResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		RevisedPublishingInterval: req.RequestedPublishingInterval,
		RevisedLifetimeCount:      req.RequestedLifetimeCount,
		RevisedMaxKeepAliveCount:  req.RequestedMaxKeepAliveCount,
	}, nil
}

// SetPublishingMode implements the OPC UA SetPublishingMode service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.13.4
func (s *SubscriptionService) SetPublishingMode(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.srv.cfg.logger.Debug("handling request", "type", fmt.Sprintf("%T", r))

	req, err := safeReq[*ua.SetPublishingModeRequest](r)
	if err != nil {
		return nil, err
	}

	session := s.srv.Session(req.Header())

	s.Mu.Lock()
	defer s.Mu.Unlock()

	results := make([]ua.StatusCode, len(req.SubscriptionIDs))
	for i, subID := range req.SubscriptionIDs {
		sub, ok := s.Subs[subID]
		if !ok {
			results[i] = ua.StatusBadSubscriptionIDInvalid
			continue
		}
		if session == nil || session.AuthTokenID.String() != sub.Session.AuthTokenID.String() {
			results[i] = ua.StatusBadSessionIDInvalid
			continue
		}
		sub.Mu.Lock()
		sub.publishingEnabled = req.PublishingEnabled
		sub.Mu.Unlock()
		results[i] = ua.StatusOK
	}

	return &ua.SetPublishingModeResponse{
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

// Publish implements the OPC UA Publish service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.13.5
func (s *SubscriptionService) Publish(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.srv.cfg.logger.Debug("raw publish request")

	req, err := safeReq[*ua.PublishRequest](r)
	if err != nil {
		s.srv.cfg.logger.Error("bad PublishRequest struct")
		return nil, err
	}

	session := s.srv.Session(req.RequestHeader)

	if session == nil {
		response := &ua.PublishResponse{
			ResponseHeader: &ua.ResponseHeader{
				Timestamp:          time.Now(),
				RequestHandle:      req.RequestHeader.RequestHandle,
				ServiceResult:      ua.StatusBadSessionIDInvalid,
				ServiceDiagnostics: &ua.DiagnosticInfo{},
				StringTable:        []string{},
				AdditionalHeader:   ua.NewExtensionObject(nil),
			},
			SubscriptionID:           0,
			MoreNotifications:        false,
			NotificationMessage:      &ua.NotificationMessage{NotificationData: []*ua.ExtensionObject{}},
			AvailableSequenceNumbers: []uint32{}, // an empty array indicates that we don't support retransmission of messages
			Results:                  []ua.StatusCode{},
			DiagnosticInfos:          []*ua.DiagnosticInfo{},
		}

		return response, nil
	}

	select {
	case session.PublishRequests <- PubReq{Req: req, ID: reqID}:
	default:
		s.srv.cfg.logger.Warn("too many publish requests")
	}

	// per opcua spec, we don't respond now.  When data is available on the subscription,
	// the Subscription will respond in the background.
	return nil, nil
}

// Republish implements the OPC UA Republish service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.13.6
func (s *SubscriptionService) Republish(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.srv.cfg.logger.Debug("handling request", "type", fmt.Sprintf("%T", r))

	req, err := safeReq[*ua.RepublishRequest](r)
	if err != nil {
		return nil, err
	}

	s.Mu.Lock()
	sub, ok := s.Subs[req.SubscriptionID]
	s.Mu.Unlock()

	if !ok {
		return &ua.RepublishResponse{
			ResponseHeader: responseHeader(req.RequestHeader.RequestHandle, ua.StatusBadSubscriptionIDInvalid),
		}, nil
	}

	msg := sub.getSentMessage(req.RetransmitSequenceNumber)
	if msg == nil {
		return &ua.RepublishResponse{
			ResponseHeader: responseHeader(req.RequestHeader.RequestHandle, ua.StatusBadMessageNotAvailable),
		}, nil
	}

	return &ua.RepublishResponse{
		ResponseHeader:      responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
		NotificationMessage: msg,
	}, nil
}

// TransferSubscriptions implements the OPC UA TransferSubscriptions service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.13.7
func (s *SubscriptionService) TransferSubscriptions(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.srv.cfg.logger.Debug("handling request", "type", fmt.Sprintf("%T", r))

	req, err := safeReq[*ua.TransferSubscriptionsRequest](r)
	if err != nil {
		return nil, err
	}

	session := s.srv.Session(req.Header())

	s.Mu.Lock()
	defer s.Mu.Unlock()

	results := make([]*ua.TransferResult, len(req.SubscriptionIDs))
	for i, subID := range req.SubscriptionIDs {
		sub, ok := s.Subs[subID]
		if !ok {
			results[i] = &ua.TransferResult{
				StatusCode: ua.StatusBadSubscriptionIDInvalid,
			}
			continue
		}

		// Reassign the subscription to the requesting session and channel.
		sub.Mu.Lock()
		sub.Session = session
		sub.Channel = sc
		sub.Mu.Unlock()

		results[i] = &ua.TransferResult{
			StatusCode:               ua.StatusOK,
			AvailableSequenceNumbers: sub.availableSequenceNumbers(),
		}
	}

	return &ua.TransferSubscriptionsResponse{
		ResponseHeader:  responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
		Results:         results,
		DiagnosticInfos: []*ua.DiagnosticInfo{},
	}, nil
}

// DeleteSubscriptions implements the OPC UA DeleteSubscriptions service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.13.8
func (s *SubscriptionService) DeleteSubscriptions(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.srv.cfg.logger.Debug("handling request", "type", fmt.Sprintf("%T", r))

	req, err := safeReq[*ua.DeleteSubscriptionsRequest](r)
	if err != nil {
		return nil, err
	}
	session := s.srv.Session(req.Header())

	s.Mu.Lock()
	defer s.Mu.Unlock()

	results := make([]ua.StatusCode, len(req.SubscriptionIDs))
	for i := range req.SubscriptionIDs {

		subid := req.SubscriptionIDs[i]
		s.srv.cfg.logger.Info("subscription deleted by client", "sub_id", subid)
		sub, ok := s.Subs[subid]
		if !ok {
			results[i] = ua.StatusBadSubscriptionIDInvalid
			continue
		}
		if session.AuthTokenID.String() != sub.Session.AuthTokenID.String() {
			results[i] = ua.StatusBadSessionIDInvalid
			continue
		}
		// delete subscription gets the lock so we set them up to run in the background
		// once this function releases its lock
		go s.DeleteSubscription(subid)
		results[i] = ua.StatusOK
	}
	return &ua.DeleteSubscriptionsResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		Results:         results,                //                  []StatusCode
		DiagnosticInfos: []*ua.DiagnosticInfo{}, //          []*DiagnosticInfo
	}, nil
}

type PubReq struct {
	// The data of the publish request
	Req *ua.PublishRequest

	// The request ID (from the header) of the publish request.  This has to be used when replying.
	ID uint32
}

// Subscription is the type that with its run function works in the background fulfilling subscription
// publishes.
//
// MonitoredItems will send updates on the NotifyChannel to let the background task know that
// an event has occurred that needs to be published.
type Subscription struct {
	srv                       *SubscriptionService
	Session                   *session
	ID                        uint32
	RevisedPublishingInterval float64
	RevisedLifetimeCount      uint32
	RevisedMaxKeepAliveCount  uint32
	Channel                   *uasc.SecureChannel
	SequenceID                uint32
	//SeqNums                   map[uint32]struct{}
	T *time.Ticker

	NotifyChannel      chan *ua.MonitoredItemNotification
	EventNotifyChannel chan *ua.EventFieldList
	ModifyChannel      chan *ua.ModifySubscriptionRequest

	// sentMessages stores the last N notification messages for retransmission via Republish.
	sentMessages map[uint32]*ua.NotificationMessage

	// the running flag and shutdown channel are used to signal the background task that it should stop.
	// multiple places can kill the subscription so make sure you check the running flag using the mutex
	// before closing the shutdown channel.
	Mu                sync.Mutex
	running           bool
	publishingEnabled bool
	shutdown          chan struct{}
}

func NewSubscription() *Subscription {
	return &Subscription{
		//SeqNums:       map[uint32]struct{}{},
		NotifyChannel:      make(chan *ua.MonitoredItemNotification, 100),
		EventNotifyChannel: make(chan *ua.EventFieldList, 100),
		ModifyChannel:      make(chan *ua.ModifySubscriptionRequest, 2),
		sentMessages:       make(map[uint32]*ua.NotificationMessage),
		shutdown:           make(chan struct{}),
	}
}

func (s *Subscription) Update(req *ua.ModifySubscriptionRequest) {
	s.RevisedPublishingInterval = req.RequestedPublishingInterval
	s.RevisedLifetimeCount = req.RequestedLifetimeCount
	s.RevisedMaxKeepAliveCount = req.RequestedMaxKeepAliveCount
}

// maxRetransmissionQueueSize is the maximum number of notification messages kept for Republish.
const maxRetransmissionQueueSize = 10

// storeSentMessage saves a notification message for potential retransmission.
// It caps the queue at maxRetransmissionQueueSize by evicting the oldest entry.
func (s *Subscription) storeSentMessage(msg *ua.NotificationMessage) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	s.sentMessages[msg.SequenceNumber] = msg
	if len(s.sentMessages) > maxRetransmissionQueueSize {
		// evict oldest (lowest sequence number)
		var oldest uint32
		for seq := range s.sentMessages {
			if oldest == 0 || seq < oldest {
				oldest = seq
			}
		}
		delete(s.sentMessages, oldest)
	}
}

// availableSequenceNumbers returns the sequence numbers available for retransmission.
func (s *Subscription) availableSequenceNumbers() []uint32 {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	nums := make([]uint32, 0, len(s.sentMessages))
	for seq := range s.sentMessages {
		nums = append(nums, seq)
	}
	return nums
}

// getSentMessage returns a previously sent notification message by sequence number.
func (s *Subscription) getSentMessage(seqNum uint32) *ua.NotificationMessage {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	return s.sentMessages[seqNum]
}

func (s *Subscription) Start() {
	go s.run()

}

func (s *Subscription) keepalive(pubreq PubReq) error {
	eo := make([]*ua.ExtensionObject, 0)

	msg := ua.NotificationMessage{
		SequenceNumber:   s.SequenceID + 1, // not sure why but ua expert wants the next sequence number on keepalives.
		PublishTime:      time.Now(),
		NotificationData: eo,
	}

	response := &ua.PublishResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      pubreq.Req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		SubscriptionID:           s.ID,
		MoreNotifications:        false,
		NotificationMessage:      &msg,
		AvailableSequenceNumbers: []uint32{}, // an empty array indicates that we don't support retransmission of messages
		Results:                  []ua.StatusCode{},
		DiagnosticInfos:          []*ua.DiagnosticInfo{},
	}
	err := s.Channel.SendResponseWithContext(context.Background(), pubreq.ID, response)
	if err != nil {
		return err
	}
	return nil
}

// this function should be run as a go-routine and will handle sending data out
// to the client at the correct rate assuming there are publish requests queued up.
// if the function returns it deletes the subscription.
func (s *Subscription) run() {
	// if this go routine dies, we need to delete ourselves.
	defer func() {
		s.srv.srv.cfg.logger.Info("subscription shutting down", "sub_id", s.ID)
		s.srv.DeleteSubscription(s.ID)
	}()

	keepaliveCounter := 0
	lifetimeCounter := 0
	//TODO: if a sub is modified, this ticker time may need to change.
	s.T = time.NewTicker(time.Millisecond * time.Duration(s.RevisedPublishingInterval))
	defer s.T.Stop()

	// This is the master run event loop.  It has effectively 3 states that it can be in.  The first two are designated with
	// the labels L0, and L2.  Everything after the L2 loop is the third state where we send any pending notifications.
	// The states always go L0 -> L2 -> Sending -> L0.  L0 and L2 are both places where we wait so they are done as for loops with
	// breaks to go to the next state.
	// The sending state always runs to completion.
	//
	// L0 waits for our notification interval to expire.  Any notifications that come in
	// while waiting will be stored in the publishQueue.  Once the interval expires, we'll move on to L2 if we've got notifications.
	// In L2 we wait for a publish request.  If we get one, we'll publish the notifications in the publishQueue.  If we don't
	// get a publish request, we'll continue to count intervals without a publish request.
	//
	// In L0 and L2, If we get to the lifetime count without a publish request, we'll kill the subscription.
	for {
		// we don't need to do anything if we don't have at least one thing to publish so lets get that first
		publishQueue := make(map[uint32]*ua.MonitoredItemNotification)
		var eventQueue []*ua.EventFieldList

		// Collect notifications until our publication interval is ready
	L0:
		for {
			select {
			case <-s.shutdown:
				return
			case newNotification := <-s.NotifyChannel:
				publishQueue[newNotification.ClientHandle] = newNotification
			case evt := <-s.EventNotifyChannel:
				eventQueue = append(eventQueue, evt)
			case <-s.T.C:
				s.Mu.Lock()
				enabled := s.publishingEnabled
				s.Mu.Unlock()

				if (len(publishQueue) == 0 && len(eventQueue) == 0) || !enabled {
					// nothing to publish, increment the keepalive counter and send a keepalive if it
					// has been enough intervals.
					keepaliveCounter++
					if keepaliveCounter > int(s.RevisedMaxKeepAliveCount) {
						keepaliveCounter = 0
						select {
						case pubreq := <-s.Session.PublishRequests:
							err := s.keepalive(pubreq)
							if err != nil {
								s.srv.srv.cfg.logger.Warn("problem sending keepalive", "sub_id", s.ID, "error", err)
								return
							}
						default:
							lifetimeCounter++
							if lifetimeCounter > int(s.RevisedLifetimeCount) {
								s.srv.srv.cfg.logger.Warn("subscription timed out", "sub_id", s.ID)
								return
							}
						}
					}
					continue // nothing to publish this interval
				}
				// we have things to publish so we'll break out to do that.
				break L0
			case update := <-s.ModifyChannel:
				s.Update(update) // Reset the ticker to the new publishing interval.
				s.T.Reset(time.Millisecond * time.Duration(s.RevisedPublishingInterval))
			}
		}
		var pubreq PubReq

		// now we need to continue to collect notifications until we've got a publish request
	L2:
		for {
			select {
			case <-s.shutdown:
				return
			case pubreq = <-s.Session.PublishRequests:
				// once we get a publish request, we should move on to publish them back
				break L2
			case newNotification := <-s.NotifyChannel:
				publishQueue[newNotification.ClientHandle] = newNotification
			case evt := <-s.EventNotifyChannel:
				eventQueue = append(eventQueue, evt)

			case <-s.T.C:
				// we had another tick without a publish request.
				lifetimeCounter++
				if lifetimeCounter > int(s.RevisedLifetimeCount) {
					s.srv.srv.cfg.logger.Warn("subscription timed out", "sub_id", s.ID)
					return
				}
			}
		}
		lifetimeCounter = 0
		keepaliveCounter = 0

		s.SequenceID++
		if s.SequenceID == 0 {
			// per the spec, the sequence ID cannot be 0
			s.SequenceID = 1
		}
		s.srv.srv.cfg.logger.Debug("got publish request", "sub_id", s.ID, "sequence_id", s.SequenceID)
		// then get all the tags and send them back to the client

		//for x := range pubreq.Req.SubscriptionAcknowledgements {
		//a := pubreq.Req.SubscriptionAcknowledgements[x]
		//delete(s.SeqNums, a.SequenceNumber)
		//}

		finalItems := make([]*ua.MonitoredItemNotification, len(publishQueue))
		i := 0
		for k := range publishQueue {
			finalItems[i] = publishQueue[k]
			i++
		}

		eo := make([]*ua.ExtensionObject, 0, 2)
		if len(finalItems) > 0 {
			dcn := ua.DataChangeNotification{
				MonitoredItems:  finalItems,
				DiagnosticInfos: []*ua.DiagnosticInfo{},
			}
			dcnEO := ua.NewExtensionObject(&dcn)
			dcnEO.UpdateMask()
			eo = append(eo, dcnEO)
		}
		if len(eventQueue) > 0 {
			enl := ua.EventNotificationList{
				Events: eventQueue,
			}
			enlEO := ua.NewExtensionObject(&enl)
			enlEO.UpdateMask()
			eo = append(eo, enlEO)
		}

		msg := ua.NotificationMessage{
			SequenceNumber:   s.SequenceID,
			PublishTime:      time.Now(),
			NotificationData: eo,
		}
		s.storeSentMessage(&msg)

		response := &ua.PublishResponse{
			ResponseHeader: &ua.ResponseHeader{
				Timestamp:          time.Now(),
				RequestHandle:      pubreq.Req.RequestHeader.RequestHandle,
				ServiceResult:      ua.StatusOK,
				ServiceDiagnostics: &ua.DiagnosticInfo{},
				StringTable:        []string{},
				AdditionalHeader:   ua.NewExtensionObject(nil),
			},
			SubscriptionID:           s.ID,
			MoreNotifications:        false,
			NotificationMessage:      &msg,
			AvailableSequenceNumbers: s.availableSequenceNumbers(),
			Results:                  []ua.StatusCode{},
			DiagnosticInfos:          []*ua.DiagnosticInfo{},
		}
		err := s.Channel.SendResponseWithContext(context.Background(), pubreq.ID, response)
		if err != nil {
			s.srv.srv.cfg.logger.Error("problem sending channel response", "error", err)
			s.srv.srv.cfg.logger.Error("killing subscription", "sub_id", s.ID)
			return
		}
		s.srv.srv.cfg.logger.Debug("published items", "count", len(publishQueue), "sub_id", s.ID)
		// wait till we've got a publish request.
	}
}

//PublishRequest_Encoding_DefaultBinary
