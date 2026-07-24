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

	pi, lifetime, keepalive := reviseSubscriptionParams(
		req.RequestedPublishingInterval,
		req.RequestedLifetimeCount,
		req.RequestedMaxKeepAliveCount,
	)

	sub := NewSubscription()
	sub.srv = s
	sub.Session = s.srv.Session(r.Header())
	sub.Channel = sc
	sub.ID = newsubid
	sub.RevisedPublishingInterval = pi
	sub.RevisedLifetimeCount = lifetime
	sub.RevisedMaxKeepAliveCount = keepalive
	sub.MaxNotificationsPerPublish = req.MaxNotificationsPerPublish
	sub.Priority = req.Priority
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
		RevisedPublishingInterval: pi,
		RevisedLifetimeCount:      lifetime,
		RevisedMaxKeepAliveCount:  keepalive,
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

	pi, lifetime, keepalive := reviseSubscriptionParams(
		req.RequestedPublishingInterval,
		req.RequestedLifetimeCount,
		req.RequestedMaxKeepAliveCount,
	)
	// Apply revised values on the modify request so the subscription goroutine
	// stores the same numbers we return to the client.
	req.RequestedPublishingInterval = pi
	req.RequestedLifetimeCount = lifetime
	req.RequestedMaxKeepAliveCount = keepalive

	select {
	case sub.ModifyChannel <- req:
	default:
		// Apply synchronously if the modify channel is full.
		sub.Update(req)
		if sub.T != nil {
			sub.T.Reset(time.Millisecond * time.Duration(sub.RevisedPublishingInterval))
		}
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
		RevisedPublishingInterval: pi,
		RevisedLifetimeCount:      lifetime,
		RevisedMaxKeepAliveCount:  keepalive,
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
		if session == nil || session.AuthTokenID.String() != sub.Session.AuthTokenID.String() {
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
	srv                        *SubscriptionService
	Session                    *session
	ID                         uint32
	RevisedPublishingInterval  float64
	RevisedLifetimeCount       uint32
	RevisedMaxKeepAliveCount   uint32
	MaxNotificationsPerPublish uint32
	Priority                   uint8
	Channel                    *uasc.SecureChannel
	SequenceID                 uint32
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

// Subscription parameter revision policy (Part 4 §5.13.2). Peers may choose
// different numbers; this stack enforces a stable, documented clamp and the
// LifetimeCount ≥ 3 × MaxKeepAliveCount constraint.
const (
	minPublishingIntervalMS = 10.0
	maxPublishingIntervalMS = 3_600_000.0 // 1 hour
	minKeepAliveCount       = uint32(1)
	maxKeepAliveCount       = uint32(10_000)
	minLifetimeCount        = uint32(3)
	maxLifetimeCount        = uint32(100_000)
)

// reviseSubscriptionParams clamps publishing interval / keepalive / lifetime
// and enforces RevisedLifetimeCount >= 3 × RevisedMaxKeepAliveCount.
func reviseSubscriptionParams(pi float64, lifetime, keepalive uint32) (float64, uint32, uint32) {
	if pi < minPublishingIntervalMS {
		pi = minPublishingIntervalMS
	}
	if pi > maxPublishingIntervalMS {
		pi = maxPublishingIntervalMS
	}
	if keepalive < minKeepAliveCount {
		keepalive = minKeepAliveCount
	}
	if keepalive > maxKeepAliveCount {
		keepalive = maxKeepAliveCount
	}
	if lifetime < minLifetimeCount {
		lifetime = minLifetimeCount
	}
	if lifetime > maxLifetimeCount {
		lifetime = maxLifetimeCount
	}
	minLife := keepalive * 3
	if lifetime < minLife {
		lifetime = minLife
	}
	return pi, lifetime, keepalive
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
	s.MaxNotificationsPerPublish = req.MaxNotificationsPerPublish
	s.Priority = req.Priority
}

// ackPublishAcknowledgements applies Publish SubscriptionAcknowledgements for
// this session's subscriptions and returns per-ack StatusCodes.
func (s *SubscriptionService) ackPublishAcknowledgements(acks []*ua.SubscriptionAcknowledgement) []ua.StatusCode {
	if len(acks) == 0 {
		return []ua.StatusCode{}
	}
	results := make([]ua.StatusCode, len(acks))
	for i, ack := range acks {
		if ack == nil {
			results[i] = ua.StatusBadSubscriptionIDInvalid
			continue
		}
		s.Mu.Lock()
		sub, ok := s.Subs[ack.SubscriptionID]
		s.Mu.Unlock()
		if !ok || sub == nil {
			results[i] = ua.StatusBadSubscriptionIDInvalid
			continue
		}
		sub.Mu.Lock()
		if _, exists := sub.sentMessages[ack.SequenceNumber]; exists {
			delete(sub.sentMessages, ack.SequenceNumber)
			results[i] = ua.StatusOK
		} else {
			results[i] = ua.StatusBadSequenceNumberUnknown
		}
		sub.Mu.Unlock()
	}
	return results
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

// sessionChannel returns the current session and secure channel under Mu.
// TransferSubscriptions may reassign these fields concurrently with run().
func (s *Subscription) sessionChannel() (*session, *uasc.SecureChannel) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	return s.Session, s.Channel
}

func (s *Subscription) keepalive(pubreq PubReq) error {
	_, ch := s.sessionChannel()
	if ch == nil {
		return fmt.Errorf("subscription %d has no channel", s.ID)
	}
	ackResults := s.srv.ackPublishAcknowledgements(pubreq.Req.SubscriptionAcknowledgements)

	// Keepalive: empty NotificationData, next sequence number (not consumed).
	msg := ua.NotificationMessage{
		SequenceNumber:   s.SequenceID + 1,
		PublishTime:      time.Now(),
		NotificationData: []*ua.ExtensionObject{},
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
		AvailableSequenceNumbers: s.availableSequenceNumbers(),
		Results:                  ackResults,
		DiagnosticInfos:          []*ua.DiagnosticInfo{},
	}
	err := ch.SendResponseWithContext(context.Background(), pubreq.ID, response)
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

	// A subscription created with an invalid session token will have a nil
	// Session. Fail fast rather than panicking inside the select.
	// Session/Channel may be reassigned by TransferSubscriptions under Mu.
	sess, ch := s.sessionChannel()
	if sess == nil {
		s.srv.srv.cfg.logger.Warn("subscription has no session, shutting down", "sub_id", s.ID)
		return
	}
	if ch == nil {
		s.srv.srv.cfg.logger.Warn("subscription has no channel, shutting down", "sub_id", s.ID)
		return
	}

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
		// Refresh session/channel each loop so TransferSubscriptions takes effect.
		sess, ch = s.sessionChannel()
		if sess == nil || ch == nil {
			s.srv.srv.cfg.logger.Warn("subscription lost session/channel, shutting down", "sub_id", s.ID)
			return
		}

		// NotifyChannel wakes are ignored for payload; real samples live in
		// per-monitored-item queues (Part 4 QueueSize / DiscardOldest).
		var eventQueue []*ua.EventFieldList
		pendingData := false

		// Collect notifications until our publication interval is ready
	L0:
		for {
			select {
			case <-s.shutdown:
				return
			case <-s.NotifyChannel:
				pendingData = true
			case evt := <-s.EventNotifyChannel:
				eventQueue = append(eventQueue, evt)
			case <-s.T.C:
				s.Mu.Lock()
				enabled := s.publishingEnabled
				s.Mu.Unlock()

				hasQueued := pendingData || s.srv.srv.MonitoredItemService.PendingReportableNotifications(s.ID)
				if (!hasQueued && len(eventQueue) == 0) || !enabled {
					keepaliveCounter++
					if keepaliveCounter > int(s.RevisedMaxKeepAliveCount) {
						keepaliveCounter = 0
						select {
						case pubreq := <-sess.PublishRequests:
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
				break L0
			case update := <-s.ModifyChannel:
				s.Update(update)
				s.T.Reset(time.Millisecond * time.Duration(s.RevisedPublishingInterval))
			}
		}
		var pubreq PubReq

	L2:
		for {
			select {
			case <-s.shutdown:
				return
			case pubreq = <-sess.PublishRequests:
				break L2
			case <-s.NotifyChannel:
				pendingData = true
			case evt := <-s.EventNotifyChannel:
				eventQueue = append(eventQueue, evt)

			case <-s.T.C:
				lifetimeCounter++
				if lifetimeCounter > int(s.RevisedLifetimeCount) {
					s.srv.srv.cfg.logger.Warn("subscription timed out", "sub_id", s.ID)
					return
				}
			}
		}
		lifetimeCounter = 0
		keepaliveCounter = 0

		ackResults := s.srv.ackPublishAcknowledgements(pubreq.Req.SubscriptionAcknowledgements)

		s.SequenceID++
		if s.SequenceID == 0 {
			s.SequenceID = 1
		}
		s.srv.srv.cfg.logger.Debug("got publish request", "sub_id", s.ID, "sequence_id", s.SequenceID)

		s.Mu.Lock()
		maxNotif := s.MaxNotificationsPerPublish
		s.Mu.Unlock()
		finalItems, moreData := s.srv.srv.MonitoredItemService.DrainQueuedNotifications(s.ID, maxNotif)

		// Events currently drain fully in one Publish (event overflow is Phase 15).
		moreEvents := false
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
			eventQueue = nil
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
			MoreNotifications:        moreData || moreEvents,
			NotificationMessage:      &msg,
			AvailableSequenceNumbers: s.availableSequenceNumbers(),
			Results:                  ackResults,
			DiagnosticInfos:          []*ua.DiagnosticInfo{},
		}
		// Re-read channel in case TransferSubscriptions reassigned it.
		_, ch = s.sessionChannel()
		if ch == nil {
			s.srv.srv.cfg.logger.Warn("subscription has no channel after transfer, shutting down", "sub_id", s.ID)
			return
		}
		err := ch.SendResponseWithContext(context.Background(), pubreq.ID, response)
		if err != nil {
			s.srv.srv.cfg.logger.Error("problem sending channel response", "error", err)
			s.srv.srv.cfg.logger.Error("killing subscription", "sub_id", s.ID)
			return
		}
		s.srv.srv.cfg.logger.Debug("published items", "count", len(finalItems), "more", moreData, "sub_id", s.ID)

		// If MoreNotifications is set, wake the loop so the next interval can
		// publish remaining queued samples without waiting for a new write.
		if moreData || moreEvents {
			select {
			case s.NotifyChannel <- &ua.MonitoredItemNotification{}:
			default:
			}
		}
	}
}

//PublishRequest_Encoding_DefaultBinary
