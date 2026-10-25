// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"sync/atomic"
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

	// lastID is the most recently assigned subscription id. Guarded by Mu.
	lastID uint32

	// closed is set while the server is shut down: a CreateSubscription
	// request that is still being handled then must not start a
	// subscription that nothing would stop. Guarded by Mu.
	closed bool
}

// nextSubscriptionID returns an id that is not in use. Ids are handed out
// from a monotonic counter instead of being derived from the number of live
// subscriptions: after a delete, len(Subs)+1 is the id of a subscription that
// still exists, which the new one would silently replace.
// Caller must hold s.Mu.
func (s *SubscriptionService) nextSubscriptionID() uint32 {
	for {
		s.lastID++
		if s.lastID == 0 {
			continue
		}
		if _, used := s.Subs[s.lastID]; !used {
			return s.lastID
		}
	}
}

// deleteAll stops every subscription. It is called when the server shuts
// down so that no subscription goroutine outlives it.
func (s *SubscriptionService) deleteAll() {
	s.Mu.Lock()
	s.closed = true
	ids := make([]uint32, 0, len(s.Subs))
	for id := range s.Subs {
		ids = append(ids, id)
	}
	s.Mu.Unlock()
	for _, id := range ids {
		s.DeleteSubscription(id)
	}
}

// reopen lets subscriptions be created again. It is called when the server
// starts.
func (s *SubscriptionService) reopen() {
	s.Mu.Lock()
	s.closed = false
	s.Mu.Unlock()
}

// DeleteSubscription removes all references to a subscription and all monitored items pointed at it.
func (s *SubscriptionService) DeleteSubscription(id uint32) {
	s.Mu.Lock()
	sub := s.removeNeedsLock(id)
	s.Mu.Unlock()

	s.finishDelete(id, sub)
}

// removeNeedsLock takes the subscription out of the table so that no further
// request can address it. The caller must hold s.Mu and call finishDelete
// after releasing it.
func (s *SubscriptionService) removeNeedsLock(id uint32) *Subscription {
	sub := s.Subs[id]
	delete(s.Subs, id)
	return sub
}

// finishDelete stops the goroutine of a removed subscription and purges its
// monitored items.
//
// It must be called without s.Mu: the monitored item service takes its own
// lock before s.Mu (CreateMonitoredItems), so calling into it with s.Mu held
// is a lock-order inversion that deadlocks the server when a subscription is
// deleted while items are created on another one.
func (s *SubscriptionService) finishDelete(id uint32, sub *Subscription) {
	if sub != nil {
		sub.Mu.Lock()
		if sub.running {
			sub.running = false
			close(sub.shutdown)
		}
		sub.Mu.Unlock()
	}

	// ask the monitored item service to purge out any items that use this subscription.
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

	// A subscription belongs to a session (Part 4 §5.13.2). Without one there
	// is nobody to deliver notifications to.
	sess := s.srv.Session(r.Header())
	if sess == nil {
		return nil, ua.StatusBadSessionIDInvalid
	}

	s.Mu.Lock()
	defer s.Mu.Unlock()
	if s.closed {
		return nil, ua.StatusBadShutdown
	}

	newsubid := s.nextSubscriptionID()

	s.srv.cfg.logger.Info("new subscription", "sub_id", newsubid, "remote_addr", sc.RemoteAddr())

	pi, lifetime, keepalive := reviseSubscriptionParams(
		req.RequestedPublishingInterval,
		req.RequestedLifetimeCount,
		req.RequestedMaxKeepAliveCount,
	)

	sub := NewSubscription()
	sub.srv = s
	sub.Session = sess
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

	if !sub.ownedBy(session) {
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

	// Apply the new parameters before responding so that they are in effect
	// for whatever the client sends next, then wake the subscription
	// goroutine (which owns the ticker) to re-arm its publishing timer. A nil
	// message only re-arms; if the channel is full a wake-up is already
	// pending.
	sub.Update(req)
	select {
	case sub.ModifyChannel <- nil:
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
		if !sub.ownedBy(session) {
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

	// A subscription of this session ended (its lifetime expired) while no
	// Publish request was available. Tell the client now, before anything
	// else: this is how it learns that the subscription is gone.
	if change, ok := session.takeStatusChange(); ok {
		return statusChangeResponse(req, change, s.ackPublishAcknowledgements(req.SubscriptionAcknowledgements)), nil
	}

	// Part 4 §5.13.5: a Publish request for a session without subscriptions
	// is answered right away. Queuing it instead would leave the client
	// waiting for a response that no subscription will ever produce.
	if !s.sessionHasSubscriptions(session) {
		return nil, ua.StatusBadNoSubscription
	}

	select {
	case session.PublishRequests <- PubReq{Req: req, ID: reqID, Channel: sc}:
	default:
		// The per-session queue is full. Tell the client instead of silently
		// dropping the request, which it would only notice as a timeout.
		s.srv.cfg.logger.Warn("too many publish requests")
		return nil, ua.StatusBadTooManyPublishRequests
	}

	// per opcua spec, we don't respond now.  When data is available on the subscription,
	// the Subscription will respond in the background.
	return nil, nil
}

// statusChangeResponse builds the Publish response that carries a
// StatusChangeNotification (Part 4 §7.20.4).
func statusChangeResponse(req *ua.PublishRequest, change pendingStatusChange, ackResults []ua.StatusCode) *ua.PublishResponse {
	eo := ua.NewExtensionObject(&ua.StatusChangeNotification{
		Status:         change.status,
		DiagnosticInfo: &ua.DiagnosticInfo{},
	})
	eo.UpdateMask()
	return &ua.PublishResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		SubscriptionID: change.subID,
		NotificationMessage: &ua.NotificationMessage{
			SequenceNumber:   change.seq,
			PublishTime:      time.Now(),
			NotificationData: []*ua.ExtensionObject{eo},
		},
		AvailableSequenceNumbers: []uint32{},
		Results:                  ackResults,
		DiagnosticInfos:          []*ua.DiagnosticInfo{},
	}
}

// nextSequenceNumber is the sequence number of the notification message
// after last, which a keep-alive or a StatusChangeNotification carries
// without consuming it.
func nextSequenceNumber(last uint32) uint32 {
	seq := last + 1
	if seq == 0 {
		seq = 1
	}
	return seq
}

// announce sends change to the client of sess with one of its queued Publish
// requests, or keeps it on sess for the next one. ch is the channel of a
// request that does not name its own.
func (s *Subscription) announce(sess *session, ch *uasc.SecureChannel, change pendingStatusChange) {
	select {
	case pubreq := <-sess.PublishRequests:
		resp := statusChangeResponse(pubreq.Req, change, s.srv.ackPublishAcknowledgements(pubreq.Req.SubscriptionAcknowledgements))
		if err := s.srv.srv.sendPublishResponse(pubreq.replyChannel(ch), pubreq.ID, resp); err == nil {
			return
		}
	default:
	}
	sess.addStatusChange(change)
}

// announceExpiry tells the client that the subscription's lifetime has
// expired, with a StatusChangeNotification carrying BadTimeout
// (Part 4 §5.13.1.1). The lifetime expires precisely because the client sent
// no Publish request, so there is usually none to answer: the notification
// then waits on the session for the next one. Without it a client that is
// still there never learns that its subscription is gone.
func (s *Subscription) announceExpiry(sess *session) {
	if sess == nil {
		return
	}
	_, ch := s.sessionChannel()
	s.announce(sess, ch, pendingStatusChange{subID: s.ID, seq: nextSequenceNumber(s.SequenceID), status: ua.StatusBadTimeout})
}

// releasePublishRequests answers every Publish request that is queued for
// sess with a ServiceFault of the given status. A queued request is answered
// when a subscription of the session has something to send; once the session
// is closed that will never happen, and the client would wait for its own
// timeout before it publishes again.
func (s *SubscriptionService) releasePublishRequests(sess *session, status ua.StatusCode) {
	if sess == nil {
		return
	}
	for {
		select {
		case pr := <-sess.PublishRequests:
			h := faultHeader(status)
			if pr.Req != nil && pr.Req.RequestHeader != nil {
				h.RequestHandle = pr.Req.RequestHeader.RequestHandle
			}
			_ = s.srv.sendPublishResponse(pr.replyChannel(nil), pr.ID, &ua.ServiceFault{ResponseHeader: h})
		default:
			return
		}
	}
}

// sessionHasSubscriptions reports whether at least one subscription is
// currently assigned to sess.
func (s *SubscriptionService) sessionHasSubscriptions(sess *session) bool {
	s.Mu.Lock()
	subs := make([]*Subscription, 0, len(s.Subs))
	for _, sub := range s.Subs {
		subs = append(subs, sub)
	}
	s.Mu.Unlock()
	for _, sub := range subs {
		if owner, _ := sub.sessionChannel(); owner == sess {
			return true
		}
	}
	return false
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

	requester := s.srv.Session(req.Header())
	if requester == nil {
		return nil, ua.StatusBadSessionIDInvalid
	}

	// The subscriptions that leave another session, with the session and
	// channel they leave.
	type moved struct {
		sub     *Subscription
		from    *session
		channel *uasc.SecureChannel
	}
	var left []moved

	s.Mu.Lock()

	results := make([]*ua.TransferResult, len(req.SubscriptionIDs))
	for i, subID := range req.SubscriptionIDs {
		sub, ok := s.Subs[subID]
		if !ok {
			results[i] = &ua.TransferResult{
				StatusCode: ua.StatusBadSubscriptionIDInvalid,
			}
			continue
		}

		// A subscription can only be taken over by its owner: the user
		// of the session it belongs to (Part 4 §5.13.7). Subscription ids
		// are easy to guess, so without this check any client could help
		// itself to the data of another.
		owner, ownerChannel := sub.sessionChannel()
		if !sameUser(owner, requester) {
			results[i] = &ua.TransferResult{
				StatusCode: ua.StatusBadUserAccessDenied,
			}
			continue
		}
		if owner != requester {
			left = append(left, moved{sub: sub, from: owner, channel: ownerChannel})
		}

		// Reassign the subscription to the requesting session and channel.
		sub.Mu.Lock()
		sub.Session = requester
		sub.Channel = sc
		sub.Mu.Unlock()

		results[i] = &ua.TransferResult{
			StatusCode:               ua.StatusOK,
			AvailableSequenceNumbers: sub.availableSequenceNumbers(),
		}
	}
	s.Mu.Unlock()

	// The session a subscription has left learns it from a
	// StatusChangeNotification with Good_SubscriptionTransferred
	// (Part 4 §5.13.7), sent with one of its queued Publish requests or kept
	// for its next one. It carries the subscription's next sequence number
	// without consuming it, so it cannot hide a notification of the
	// subscription in its new session. Publish requests still queued in a
	// session that has no subscription left would wait for nothing: they are
	// answered with Bad_NoSubscription (Part 4 §5.13.5).
	for _, m := range left {
		m.sub.announce(m.from, m.channel, pendingStatusChange{subID: m.sub.ID, seq: nextSequenceNumber(m.sub.seq.Load()), status: ua.StatusGoodSubscriptionTransferred})
		if !s.sessionHasSubscriptions(m.from) {
			s.releasePublishRequests(m.from, ua.StatusBadNoSubscription)
		}
	}

	return &ua.TransferSubscriptionsResponse{
		ResponseHeader:  responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
		Results:         results,
		DiagnosticInfos: []*ua.DiagnosticInfo{},
	}, nil
}

// sameUser reports whether the session to is used by the user who owns the
// subscriptions of the session from, which is the condition for transferring
// them (Part 4 §5.13.7): the same user name, the same user certificate, or
// for anonymous users and issued tokens, which do not identify anybody across
// sessions, the same client application certificate. Two anonymous sessions
// without an application certificate (no security) cannot be told apart and
// count as the same.
func sameUser(from, to *session) bool {
	if from == nil || to == nil {
		return false
	}
	if from == to {
		return true
	}
	sameApplication := bytes.Equal(from.remoteCertificate, to.remoteCertificate)
	switch a := from.identityToken.(type) {
	case *ua.UserNameIdentityToken:
		b, ok := to.identityToken.(*ua.UserNameIdentityToken)
		return ok && a != nil && b != nil && a.UserName == b.UserName
	case *ua.X509IdentityToken:
		b, ok := to.identityToken.(*ua.X509IdentityToken)
		return ok && a != nil && b != nil && bytes.Equal(a.CertificateData, b.CertificateData)
	case *ua.IssuedIdentityToken:
		_, ok := to.identityToken.(*ua.IssuedIdentityToken)
		return ok && sameApplication
	default: // anonymous
		switch to.identityToken.(type) {
		case nil, *ua.AnonymousIdentityToken:
			return sameApplication
		}
		return false
	}
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

	// The subscriptions are taken out of the table under the lock, so a
	// second request for the same id is answered with
	// BadSubscriptionIdInvalid, and are torn down before the response is
	// sent, so the client can rely on them being gone. (Deleting them from a
	// background goroutine reported success twice for concurrent requests
	// and left the subscription alive for a moment after the response.)
	removed := make(map[uint32]*Subscription)

	s.Mu.Lock()
	results := make([]ua.StatusCode, len(req.SubscriptionIDs))
	for i := range req.SubscriptionIDs {

		subid := req.SubscriptionIDs[i]
		s.srv.cfg.logger.Info("subscription deleted by client", "sub_id", subid)
		sub, ok := s.Subs[subid]
		if !ok {
			results[i] = ua.StatusBadSubscriptionIDInvalid
			continue
		}
		if !sub.ownedBy(session) {
			results[i] = ua.StatusBadSessionIDInvalid
			continue
		}
		removed[subid] = s.removeNeedsLock(subid)
		results[i] = ua.StatusOK
	}
	s.Mu.Unlock()

	for subid, sub := range removed {
		s.finishDelete(subid, sub)
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

	// Channel is the secure channel the Publish request arrived on. The
	// response has to be sent on the same channel: after a client reconnect
	// the session lives on a new channel, while the channel the subscription
	// was created on is gone.
	Channel *uasc.SecureChannel
}

// replyChannel returns the secure channel on which the response to this
// request is sent: the one it arrived on, or fallback for requests that were
// queued without one.
func (p PubReq) replyChannel(fallback *uasc.SecureChannel) *uasc.SecureChannel {
	if p.Channel != nil {
		return p.Channel
	}
	return fallback
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
	// seq is SequenceID for the goroutines other than run, which alone
	// changes SequenceID (TransferSubscriptions reads it).
	seq atomic.Uint32
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
	s.Mu.Lock()
	defer s.Mu.Unlock()
	s.RevisedPublishingInterval = req.RequestedPublishingInterval
	s.RevisedLifetimeCount = req.RequestedLifetimeCount
	s.RevisedMaxKeepAliveCount = req.RequestedMaxKeepAliveCount
	s.MaxNotificationsPerPublish = req.MaxNotificationsPerPublish
	s.Priority = req.Priority
}

// ownedBy reports whether the subscription currently belongs to sess. It is
// false for a nil session and for a subscription without a session.
func (s *Subscription) ownedBy(sess *session) bool {
	own, _ := s.sessionChannel()
	if sess == nil || own == nil || sess.AuthTokenID == nil || own.AuthTokenID == nil {
		return false
	}
	return own.AuthTokenID.Equal(sess.AuthTokenID)
}

// timing returns the publishing interval and the keep-alive and lifetime
// counts under Mu; ModifySubscription may change them at any time.
func (s *Subscription) timing() (interval time.Duration, keepAlive, lifetime int) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	return time.Duration(s.RevisedPublishingInterval * float64(time.Millisecond)),
		int(s.RevisedMaxKeepAliveCount), int(s.RevisedLifetimeCount)
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

// retransmittable reports whether the message with sequence number seq is
// still in the retransmission queue.
func (s *Subscription) retransmittable(seq uint32) bool {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	_, ok := s.sentMessages[seq]
	return ok
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
		SequenceNumber:   nextSequenceNumber(s.SequenceID),
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
	err := s.srv.srv.sendPublishResponse(pubreq.replyChannel(ch), pubreq.ID, response)
	if err != nil {
		return err
	}
	s.touchSession()
	return nil
}

// touchSession restarts the timeout of the owning session after a Publish
// response was sent. A client whose only activity is waiting for Publish
// responses issues its next request only after the keep-alive interval,
// which may be longer than the session timeout; answering its Publish
// requests shows that the session is in use.
func (s *Subscription) touchSession() {
	if sess, _ := s.sessionChannel(); sess != nil {
		sess.touch()
	}
}

// this function should be run as a go-routine and will handle sending data out
// to the client at the correct rate assuming there are publish requests queued up.
// if the function returns it deletes the subscription.
func (s *Subscription) run() {
	s.seq.Store(s.SequenceID)

	// if this go routine dies, we need to delete ourselves.
	defer func() {
		// A panic here (for instance in a value function called while the
		// notifications are collected) ends this subscription only.
		if r := recover(); r != nil {
			logPanic(s.srv.srv.cfg.logger, "running a subscription", r, "sub_id", s.ID)
		}
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
	interval, _, _ := s.timing()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	s.Mu.Lock()
	s.T = ticker
	s.Mu.Unlock()

	// unsent is a notification message whose Publish response could not be
	// sent because the connection of its Publish request was gone (a request
	// may be queued just before its channel closes). It goes out with the
	// next Publish request: otherwise the client learns of it only from the
	// sequence number of a later message, which may be a keep-alive many
	// publishing intervals away.
	var unsent *ua.NotificationMessage

	// Events wait here until a notification message carries them; a resent
	// message leaves them for the next one.
	var eventQueue []*ua.EventFieldList

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
		pendingData := false
		if unsent != nil && !s.retransmittable(unsent.SequenceNumber) {
			// Acknowledged after a Republish, or evicted: the client has it
			// or can no longer get it.
			unsent = nil
		}

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
			case <-ticker.C:
				// TransferSubscriptions may have moved the subscription to
				// another session while this loop was waiting. Follow it, so
				// the Publish requests of the new session are the ones served.
				if cur, _ := s.sessionChannel(); cur != nil {
					sess = cur
				}
				s.Mu.Lock()
				enabled := s.publishingEnabled
				s.Mu.Unlock()
				_, maxKeepAlive, maxLifetime := s.timing()

				// The lifetime counter counts consecutive publishing cycles
				// without a Publish request to answer (Part 4 §5.13.1.1). It
				// has to run in every cycle, not only when a keep-alive is
				// due: otherwise an idle subscription whose client vanished
				// lives for keep-alive × lifetime cycles, i.e. practically
				// forever with common parameters.
				if len(sess.PublishRequests) == 0 {
					lifetimeCounter++
					if lifetimeCounter > maxLifetime {
						s.srv.srv.cfg.logger.Warn("subscription timed out", "sub_id", s.ID)
						s.announceExpiry(sess)
						return
					}
				} else {
					lifetimeCounter = 0
				}

				hasQueued := unsent != nil || pendingData || s.srv.srv.MonitoredItemService.PendingReportableNotifications(s.ID)
				if (!hasQueued && len(eventQueue) == 0) || !enabled {
					keepaliveCounter++
					if keepaliveCounter > maxKeepAlive {
						select {
						case pubreq := <-sess.PublishRequests:
							keepaliveCounter = 0
							lifetimeCounter = 0
							err := s.keepalive(pubreq)
							if err != nil {
								// The connection of this request is gone. That does
								// not end the subscription: the client may come
								// back and send new Publish requests until the
								// lifetime expires (Part 4 §5.13.1.1).
								s.srv.srv.cfg.logger.Warn("problem sending keepalive", "sub_id", s.ID, "error", err)
								continue
							}
						default:
							// no Publish request: the keep-alive stays due
						}
					}
					continue // nothing to publish this interval
				}
				break L0
			case update := <-s.ModifyChannel:
				if update != nil {
					s.Update(update)
				}
				interval, _, _ := s.timing()
				ticker.Reset(interval)
			}
		}
		var pubreq PubReq

	L2:
		for {
			select {
			case <-s.shutdown:
				return
			case pubreq = <-sess.PublishRequests:
				if s.srv.srv.publishAbandoned(pubreq) {
					// Its client has gone (HTTPS): a notification
					// message sent there would be lost.
					continue
				}
				break L2
			case <-s.NotifyChannel:
				pendingData = true
			case evt := <-s.EventNotifyChannel:
				eventQueue = append(eventQueue, evt)

			case <-ticker.C:
				// See L0: keep following a transferred subscription.
				if cur, _ := s.sessionChannel(); cur != nil {
					sess = cur
				}
				lifetimeCounter++
				if _, _, maxLifetime := s.timing(); lifetimeCounter > maxLifetime {
					s.srv.srv.cfg.logger.Warn("subscription timed out", "sub_id", s.ID)
					s.announceExpiry(sess)
					return
				}
			}
		}
		lifetimeCounter = 0
		keepaliveCounter = 0

		// select picks at random among ready cases: the Publish request may
		// have been taken while events emitted before it were still in the
		// channel. They belong in this notification message, in order.
		eventQueue = s.drainEvents(eventQueue)

		ackResults := s.srv.ackPublishAcknowledgements(pubreq.Req.SubscriptionAcknowledgements)

		var (
			msg                  ua.NotificationMessage
			finalItems           []*ua.MonitoredItemNotification
			moreData, moreEvents bool
		)
		if unsent != nil {
			msg, unsent = *unsent, nil
			s.srv.srv.cfg.logger.Debug("resending publish response", "sub_id", s.ID, "sequence_id", msg.SequenceNumber)
		} else {
			s.SequenceID++
			if s.SequenceID == 0 {
				s.SequenceID = 1
			}
			s.seq.Store(s.SequenceID)
			s.srv.srv.cfg.logger.Debug("got publish request", "sub_id", s.ID, "sequence_id", s.SequenceID)

			s.Mu.Lock()
			maxNotif := s.MaxNotificationsPerPublish
			s.Mu.Unlock()
			finalItems, moreData = s.srv.srv.MonitoredItemService.DrainQueuedNotifications(s.ID, maxNotif)

			// Events currently drain fully in one Publish (event overflow is Phase 15).
			moreEvents = false
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

			msg = ua.NotificationMessage{
				SequenceNumber:   s.SequenceID,
				PublishTime:      time.Now(),
				NotificationData: eo,
			}
			s.storeSentMessage(&msg)
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
		err := s.srv.srv.sendPublishResponse(pubreq.replyChannel(ch), pubreq.ID, response)
		if err != nil {
			// The connection of this Publish request is gone. The message
			// stays in the retransmission queue, so a client that reconnects
			// can fetch it with Republish; the subscription itself lives on
			// until its lifetime expires (Part 4 §5.13.1.1).
			s.srv.srv.cfg.logger.Warn("problem sending publish response", "sub_id", s.ID, "error", err)
			unsent = &msg
			continue
		}
		s.srv.srv.cfg.logger.Debug("published items", "count", len(finalItems), "more", moreData, "sub_id", s.ID)
		s.touchSession()

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

// drainEvents appends the events waiting in EventNotifyChannel to q without
// blocking.
func (s *Subscription) drainEvents(q []*ua.EventFieldList) []*ua.EventFieldList {
	for {
		select {
		case evt := <-s.EventNotifyChannel:
			q = append(q, evt)
		default:
			return q
		}
	}
}
