// SPDX-License-Identifier: MIT

package opcua

import (
	"context"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/internal/stats"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

// Subscribe creates a new OPC-UA subscription with the given parameters.
//
// The subscription receives data change and event notifications from the
// server. Notifications are delivered to notifyCh. If the channel is full,
// the notification is dropped and counted in stats.
//
// Parameters that have not been set use their defaults:
//   - Interval: 100ms
//   - LifetimeCount: 10000
//   - MaxKeepAliveCount: 3000
//   - MaxNotificationsPerPublish: 10000
//
// The caller must call [Subscription.Cancel] when done to clean up resources.
// For a fluent builder API, see [Client.NewSubscription].
//
// See OPC-UA Part 4, Section 5.13.1 for the specification.
func (c *Client) Subscribe(ctx context.Context, params *SubscriptionParameters, notifyCh chan<- *PublishNotificationData) (*Subscription, error) {
	stats.Client().Add("Subscribe", 1)

	if params == nil {
		params = &SubscriptionParameters{}
	}

	params.setDefaults()
	req := &ua.CreateSubscriptionRequest{
		RequestedPublishingInterval: float64(params.Interval / time.Millisecond),
		RequestedLifetimeCount:      params.LifetimeCount,
		RequestedMaxKeepAliveCount:  params.MaxKeepAliveCount,
		PublishingEnabled:           true,
		MaxNotificationsPerPublish:  params.MaxNotificationsPerPublish,
		Priority:                    params.Priority,
	}

	// Until the subscription is registered below, a Publish response for it
	// is a response for a subscription the client does not know yet. It must
	// not be taken for one that was left behind, see
	// orphanSubscriptionNeedsSubMuxLock.
	c.subCreating.Add(1)
	defer c.subCreating.Add(-1)

	res, err := c.createSubscription(ctx, req)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("connection closed while creating subscription (server may not support subscriptions): %w", err)
		}
		return nil, err
	}
	if res.ResponseHeader.ServiceResult != ua.StatusOK {
		return nil, res.ResponseHeader.ServiceResult
	}

	stats.Subscription().Add("Count", 1)

	sub := &Subscription{
		SubscriptionID:            res.SubscriptionID,
		RevisedPublishingInterval: time.Duration(res.RevisedPublishingInterval) * time.Millisecond,
		RevisedLifetimeCount:      res.RevisedLifetimeCount,
		RevisedMaxKeepAliveCount:  res.RevisedMaxKeepAliveCount,
		Notifs:                    notifyCh,
		items:                     make(map[uint32]*monitoredItem),
		params:                    params,
		nextSeq:                   1,
		c:                         c,
		cancelled:                 make(chan struct{}),
	}

	c.subMux.Lock()
	defer c.subMux.Unlock()

	if sub.id() == 0 || c.subs[sub.id()] != nil {
		// this should not happen and is usually indicative of a server bug
		// see: Part 4 Section 5.13.2.2, Table 88 – CreateSubscription Service Parameters
		return nil, ua.StatusBadSubscriptionIDInvalid
	}

	c.subs[sub.id()] = sub
	c.subGen++
	c.updatePublishTimeoutNeedsSubMuxLock()

	// Start the publish loop if it isn't already running. This is done while
	// holding subMux, after the subscription is registered, so that it is
	// ordered with the pause issued when the last subscription is forgotten:
	// a concurrent Cancel of another subscription either still sees it (and
	// pauses before this resume) or sees the new one (and does not pause).
	// It never blocks, see setPublishPaused.
	c.setPublishPaused(false)
	return sub, nil
}

// createSubscription sends a CreateSubscription request.
//
// A request that fails says nothing about what the server did: it may have
// created the subscription and the response got lost with the connection, or
// the caller gave up waiting for it. Such a subscription belongs to the
// session, so it lives on when the client reconnects and takes the session up
// again, kept alive by the Publish requests for the other subscriptions, and
// nobody knows its id. The failure is counted so that the subscription is
// deleted when it shows up in a Publish response, see
// orphanSubscriptionNeedsSubMuxLock.
func (c *Client) createSubscription(ctx context.Context, req *ua.CreateSubscriptionRequest) (*ua.CreateSubscriptionResponse, error) {
	res, err := send[ua.CreateSubscriptionResponse](ctx, c, req)
	if err != nil {
		c.subCreatesLost.Add(1)
	}
	return res, err
}

// orphanSubscriptionNeedsSubMuxLock reports whether a Publish response for a subscription
// the client does not know is to be answered by deleting that subscription:
// a CreateSubscription request failed without telling whether the server
// created the subscription, and no subscription is being created right now
// whose first notification could have overtaken its registration.
//
// It must be called with subMux held, which orders it with the registration
// of the subscriptions.
func (c *Client) orphanSubscriptionNeedsSubMuxLock() bool {
	return c.subCreatesLost.Load() > 0 && c.subCreating.Load() == 0
}

// deleteOrphanSubscription deletes a subscription of the session that the
// client does not know. Failing is fine: the subscription shows up again
// with its next keep-alive message.
func (c *Client) deleteOrphanSubscription(ctx context.Context, id uint32) {
	res, err := send[ua.DeleteSubscriptionsResponse](ctx, c, &ua.DeleteSubscriptionsRequest{SubscriptionIDs: []uint32{id}})
	if err != nil {
		c.cfg.logger.Debug("publish: deleting unknown subscription failed", "sub_id", id, "error", err)
		return
	}
	if len(res.Results) != 1 || res.Results[0] != ua.StatusOK {
		// Not there any more: it was a subscription the caller cancelled.
		return
	}
	c.cfg.logger.Warn("publish: deleted a subscription that a failed CreateSubscription request left behind", "sub_id", id)
	// One request left at most one subscription behind.
	for {
		n := c.subCreatesLost.Load()
		if n <= 0 || c.subCreatesLost.CompareAndSwap(n, n-1) {
			return
		}
	}
}

// SubscriptionIDs gets a list of subscriptionIDs.
func (c *Client) SubscriptionIDs() []uint32 {
	c.subMux.RLock()
	defer c.subMux.RUnlock()

	var ids []uint32
	for id := range c.subs {
		ids = append(ids, id)
	}
	return ids
}

// partitionSubscriptions splits the registered subscriptions into those that
// are expected to exist on the server and those whose last recreation failed
// and that therefore have to be recreated from scratch.
func (c *Client) partitionSubscriptions() (intact, broken []uint32) {
	c.subMux.RLock()
	defer c.subMux.RUnlock()

	for id, sub := range c.subs {
		if sub.needsRecreate {
			broken = append(broken, id)
		} else {
			intact = append(intact, id)
		}
	}
	return intact, broken
}

// recreateSubscriptions creates new subscriptions
// with the same parameters to replace the previous one.
func (c *Client) recreateSubscription(ctx context.Context, id uint32) error {
	c.subMux.Lock()
	defer c.subMux.Unlock()

	sub, ok := c.subs[id]
	if !ok {
		return ua.StatusBadSubscriptionIDInvalid
	}

	_ = sub.recreateDelete(ctx)
	// forgetSubscription pauses the publish loop when this was the last
	// subscription. Resume after a successful recreate so standalone callers
	// (outside the reconnect path) do not leave publishing permanently paused.
	c.forgetSubscriptionNeedsSubMuxLock(ctx, id)
	if err := sub.recreateCreate(ctx); err != nil {
		// Do not lose the subscription: without an entry in c.subs no later
		// recovery would ever try again and its consumer would silently
		// stop receiving data. recreateCreate registers the subscription
		// itself once the server has assigned a new id; if it failed before
		// that, put it back under the id it is known by.
		if _, ok := c.subs[sub.id()]; !ok {
			c.subs[sub.id()] = sub
			c.subGen++
			stats.Subscription().Add("Count", 1)
			c.updatePublishTimeoutNeedsSubMuxLock()
		}
		// Whatever exists on the server now is incomplete (for example a
		// subscription without its monitored items).
		sub.needsRecreate = true
		return err
	}
	sub.needsRecreate = false
	c.resumeSubscriptions(ctx)
	return nil
}

// Republish requests retransmission of a notification message for a subscription.
//
// The response is returned to the caller without mutating subscription delivery
// state or inserting into notification channels. Automatic reconnect recovery
// uses a separate internal path that may dispatch recovered notifications.
//
// Part 4, Section 5.13.6.
func (c *Client) Republish(ctx context.Context, subscriptionID, sequenceNumber uint32) (*ua.RepublishResponse, error) {
	stats.Client().Add("Republish", 1)

	req := &ua.RepublishRequest{
		SubscriptionID:           subscriptionID,
		RetransmitSequenceNumber: sequenceNumber,
	}
	return send[ua.RepublishResponse](ctx, c, req)
}

// TransferSubscriptions asks the server to transfer the given subscriptions
// to the current session. Returns the full TransferSubscriptionsResponse,
// including per-subscription TransferResults.
//
// Part 4, Section 5.13.7.
func (c *Client) TransferSubscriptions(ctx context.Context, subscriptionIDs []uint32, sendInitialValues bool) (*ua.TransferSubscriptionsResponse, error) {
	stats.Client().Add("TransferSubscriptions", 1)

	req := &ua.TransferSubscriptionsRequest{
		SubscriptionIDs:   subscriptionIDs,
		SendInitialValues: sendInitialValues,
	}
	return send[ua.TransferSubscriptionsResponse](ctx, c, req)
}

// transferSubscriptions is used by reconnect to transfer subscriptions of the
// previous session to the current one without sending initial values.
func (c *Client) transferSubscriptions(ctx context.Context, ids []uint32) (*ua.TransferSubscriptionsResponse, error) {
	return c.TransferSubscriptions(ctx, ids, false)
}

// republishSubscriptions sends republish requests for the given subscription id.
// It returns the republishResult so the caller can emit a SubscriptionRecoveryEvent.
func (c *Client) republishSubscription(ctx context.Context, id uint32, availableSeq []uint32) (republishResult, error) {
	c.subMux.RLock()
	sub := c.subs[id]
	c.subMux.RUnlock()

	if sub == nil {
		return republishResult{}, fmt.Errorf("%w: id=%d", errors.ErrInvalidSubscriptionID, id)
	}

	c.cfg.logger.Debug("republishing subscription", "sub_id", sub.id())
	rr, err := c.sendRepublishRequests(ctx, sub, availableSeq)
	if err != nil {
		switch {
		case errors.Is(err, ua.StatusBadSessionIDInvalid):
			return rr, nil
		case errors.Is(err, ua.StatusBadSubscriptionIDInvalid):
			c.cfg.logger.Debug("republish failed, subscription invalid", "sub_id", sub.id())
			return rr, fmt.Errorf("%w: subscription %d is invalid", errors.ErrInvalidSubscriptionID, sub.id())
		default:
			return rr, err
		}
	}
	return rr, nil
}

// republishResult carries the outcome of a sendRepublishRequests call so the
// caller can emit a structured SubscriptionRecoveryEvent.
type republishResult struct {
	// gapDetected is true when the client's expected next sequence number was
	// absent from the server's retransmission buffer (unrecoverable data loss).
	gapDetected bool
	// republishedCount is the number of notifications successfully recovered.
	republishedCount int
}

// sendRepublishRequests sends republish requests for the given subscription
// until it gets a BadMessageNotAvailable which implies that there are no
// more messages to restore. It returns a republishResult describing what
// happened so the caller can surface a SubscriptionRecoveryEvent.
func (c *Client) sendRepublishRequests(ctx context.Context, sub *Subscription, availableSeq []uint32) (republishResult, error) {
	var result republishResult

	// Republishing reads and advances the subscription's sequence numbers and
	// delivers to its consumer, just like the publish loop does for a live
	// PublishResponse. deliverMu keeps the two apart, see
	// deliverPublishResponse.
	c.deliverMu.Lock()
	defer c.deliverMu.Unlock()

	// If our expected next sequence number isn't in the server's retransmission queue
	// some notifications may have been lost. We log a warning and continue rather than
	// failing because data loss during reconnection is expected per Part 4 §6.5.
	if len(availableSeq) > 0 && !slices.Contains(availableSeq, sub.nextSeq) {
		c.cfg.logger.Warn("next sequence number not in retransmission buffer", "sub_id", sub.id(), "next_seq", sub.nextSeq, "available_seq", availableSeq)
		result.gapDetected = true
	}

	for {
		req := &ua.RepublishRequest{
			SubscriptionID:           sub.id(),
			RetransmitSequenceNumber: sub.nextSeq,
		}

		c.cfg.logger.Debug("republishing subscription", "sub_id", req.SubscriptionID, "seq_num", req.RetransmitSequenceNumber)

		s := c.Session()
		if s == nil {
			c.cfg.logger.Debug("republishing subscription aborted", "sub_id", req.SubscriptionID)
			return result, ua.StatusBadSessionClosed
		}

		sc := c.SecureChannel()
		if sc == nil {
			c.cfg.logger.Debug("republishing subscription aborted", "sub_id", req.SubscriptionID)
			return result, ua.StatusBadNotConnected
		}

		c.cfg.logger.Debug("republish request", "request", req)
		var res *ua.RepublishResponse
		err := sc.SendRequest(ctx, req, c.Session().resp.AuthenticationToken, func(v ua.Response) error {
			return assign(v, &res)
		})
		c.cfg.logger.Debug("republish response", "response", res, "error", err)

		switch {
		case errors.Is(err, ua.StatusBadMessageNotAvailable):
			c.cfg.logger.Debug("republishing subscription OK", "sub_id", req.SubscriptionID)
			return result, nil

		case err != nil:
			c.cfg.logger.Debug("republishing subscription failed", "sub_id", req.SubscriptionID, "error", err)
			return result, err

		default:
			status := ua.StatusBad
			if res != nil {
				status = res.ResponseHeader.ServiceResult
			}

			if status != ua.StatusOK {
				c.cfg.logger.Debug("republishing subscription failed", "sub_id", req.SubscriptionID, "status", status)
				return result, status
			}

			// Process the republished notification and advance sequence number
			if res.NotificationMessage != nil {
				c.notifySubscription(ctx, sub, res.NotificationMessage)
				sub.lastSeq = res.NotificationMessage.SequenceNumber
				sub.nextSeq = sub.lastSeq + 1
				result.republishedCount++
				c.cfg.logger.Debug("republished notification", "seq_num", res.NotificationMessage.SequenceNumber, "sub_id", sub.id())

				if len(availableSeq) > 0 && !slices.Contains(availableSeq, sub.nextSeq) {
					c.cfg.logger.Debug("republishing subscription complete", "sub_id", sub.id())
					return result, nil
				}
			}
		}

		// more notifications may be buffered: fetch the next one, unless
		// the client is shutting down
		if err := ctx.Err(); err != nil {
			return result, err
		}
	}
}

// registerSubscriptionNeedsSubMuxLock registers a subscription.
func (c *Client) registerSubscriptionNeedsSubMuxLock(sub *Subscription) error {
	if sub.id() == 0 {
		return ua.StatusBadSubscriptionIDInvalid
	}

	if _, ok := c.subs[sub.id()]; ok {
		return fmt.Errorf("%w: id=%d", errors.ErrInvalidSubscriptionID, sub.id())
	}

	c.subs[sub.id()] = sub
	c.subGen++
	sub.lastActivity.Store(time.Now().UnixNano())
	return nil
}

// silentSubscriptionFloor is the shortest time without a message after which
// a subscription counts as silent, see markSilentSubscriptions.
const silentSubscriptionFloor = 5 * time.Second

// touchSubscriptions restarts the silence clock of every subscription. It is
// called when publishing (re)starts: what a subscription did not receive
// while nothing was received at all says nothing about it.
func (c *Client) touchSubscriptions() {
	now := time.Now().UnixNano()
	c.lastPublishResponse.Store(now)
	c.subMux.RLock()
	defer c.subMux.RUnlock()
	for _, sub := range c.subs {
		sub.lastActivity.Store(now)
	}
}

// markSilentSubscriptions marks the subscriptions for recreation that the
// server has stopped serving, and returns how many it marked.
//
// A server sends a message for every subscription at least once per
// keep-alive interval (Part 4 §5.13.1.1). A subscription for which nothing
// has arrived for three such intervals (and at least
// silentSubscriptionFloor), while Publish responses for other subscriptions
// of the session did keep arriving all that time, does not exist on the
// server any more, or not in this session: it was deleted behind the
// client's back, or it stayed behind in a session the client has left. No
// error ever tells; without this check the client would report Connected
// with a subscription that never delivers again.
//
// The silence is measured against the last Publish response of any
// subscription, not against the clock: while the publish loop is paused,
// blocked by a consumer that does not read, or the connection is slow,
// nothing arrives for anybody and no subscription is singled out.
func (c *Client) markSilentSubscriptions() int {
	last := c.lastPublishResponse.Load()
	marked := 0
	c.subMux.Lock()
	defer c.subMux.Unlock()
	for _, sub := range c.subs {
		if sub.needsRecreate {
			continue
		}
		sub.paramsMu.Lock()
		limit := 3 * time.Duration(sub.RevisedMaxKeepAliveCount) * sub.RevisedPublishingInterval
		sub.paramsMu.Unlock()
		if limit < silentSubscriptionFloor {
			limit = silentSubscriptionFloor
		}
		seen := sub.lastActivity.Load()
		if seen == 0 {
			// registered without a time stamp: count from now
			sub.lastActivity.Store(time.Now().UnixNano())
			continue
		}
		if time.Duration(last-seen) > limit {
			c.cfg.logger.Warn("subscription is silent although others are served, scheduling its recreation", "sub_id", sub.id(), "silent_for", limit)
			sub.needsRecreate = true
			marked++
		}
	}
	return marked
}

// forgetSubscriptionOf removes sub from the client and returns the id it was
// registered with.
func (c *Client) forgetSubscriptionOf(ctx context.Context, sub *Subscription) uint32 {
	c.subMux.Lock()
	defer c.subMux.Unlock()

	id := sub.id()
	if c.subs[id] == sub {
		c.forgetSubscriptionNeedsSubMuxLock(ctx, id)
	}
	return id
}

func (c *Client) forgetSubscriptionNeedsSubMuxLock(ctx context.Context, id uint32) {
	delete(c.subs, id)
	c.updatePublishTimeoutNeedsSubMuxLock()
	stats.Subscription().Add("Count", -1)

	if len(c.subs) == 0 {
		// Pause the publish loop. This runs under the subscription mutex and
		// never blocks, see setPublishPaused.
		c.setPublishPaused(true)
	}
}

func (c *Client) updatePublishTimeoutNeedsSubMuxLock() {
	maxTimeout := uasc.MaxTimeout
	for _, s := range c.subs {
		if d := s.publishTimeout(); d < maxTimeout {
			maxTimeout = d
		}
	}
	c.setPublishTimeout(maxTimeout)
}

func (c *Client) notifySubscriptionOfError(ctx context.Context, subID uint32, err error) {
	c.subMux.RLock()
	s := c.subs[subID]
	c.subMux.RUnlock()

	if s == nil {
		return
	}
	go s.notify(ctx, &PublishNotificationData{Error: err})
}

func (c *Client) notifyAllSubscriptionsOfError(ctx context.Context, err error) {
	c.subMux.RLock()
	defer c.subMux.RUnlock()

	for _, s := range c.subs {
		go func(s *Subscription) {
			s.notify(ctx, &PublishNotificationData{Error: err})
		}(s)
	}
}

func (c *Client) notifySubscription(ctx context.Context, sub *Subscription, notif *ua.NotificationMessage) {
	// Note: Publish ACK results are already handled in handleAcksNeedsSubMuxLock().
	// See https://github.com/otfabric/go-opcua/issues/337 for discussion.

	if notif == nil {
		sub.notify(ctx, &PublishNotificationData{
			SubscriptionID: sub.id(),
			Error:          errors.ErrEmptyResponse,
		})
		return
	}

	// Part 4, 7.21 NotificationMessage
	for _, data := range notif.NotificationData {
		// Part 4, 7.20 NotificationData parameters
		if data == nil || data.Value == nil {
			sub.notify(ctx, &PublishNotificationData{
				SubscriptionID: sub.id(),
				Error:          errors.ErrEmptyResponse,
			})
			continue
		}

		switch v := data.Value.(type) {
		// Part 4, 7.20.2 DataChangeNotification parameter
		// Part 4, 7.20.3 EventNotificationList parameter
		// Part 4, 7.20.4 StatusChangeNotification parameter
		case ua.Notification:
			sub.notify(ctx, &PublishNotificationData{
				SubscriptionID: sub.id(),
				Value:          v,
			})

		// Error
		default:
			sub.notify(ctx, &PublishNotificationData{
				SubscriptionID: sub.id(),
				Error:          fmt.Errorf("%w: %T", errors.ErrInvalidResponseType, data.Value),
			})
		}
	}
}

// The publish loop is controlled by a piece of state, publishPaused, rather
// than by the order in which pause and resume signals arrive: the signals
// travel on two separate channels, so their relative order is lost, and a
// pause that overtakes a later resume would leave the loop paused for good
// while subscriptions exist. pausech and resumech only wake the loop up so
// that it looks at the state again.

// setPublishRecovering marks the start and the end of a connection recovery.
// While a recovery is in progress the publish loop is held regardless of
// publishPaused: the recovery republishes missed notifications, and a live
// PublishResponse delivered at the same time would break their order. A
// plain pause would not do, because Subscribe (which can succeed as soon as
// the new session is up) resumes publishing.
func (c *Client) setPublishRecovering(recovering bool) {
	c.publishMu.Lock()
	c.publishRecovering = recovering
	c.publishMu.Unlock()

	ch := c.resumech
	if recovering {
		ch = c.pausech
	}
	select {
	case ch <- struct{}{}:
	default:
	}
}

// publishRecoveryInProgress reports whether a connection recovery is in
// progress.
func (c *Client) publishRecoveryInProgress() bool {
	c.publishMu.Lock()
	defer c.publishMu.Unlock()
	return c.publishRecovering
}

// setPublishPaused sets whether the publish loop should be paused and wakes
// it up. It never blocks: if the wake-up buffer is full the loop is already
// going to re-read the state.
func (c *Client) setPublishPaused(paused bool) {
	c.publishMu.Lock()
	c.publishPaused = paused
	if !paused {
		// A new generation invalidates the pause a failing publish attempt
		// that started earlier is about to request, see pausePublishIfGen.
		c.publishGen++
	}
	c.publishMu.Unlock()

	ch := c.resumech
	if paused {
		ch = c.pausech
	}
	select {
	case ch <- struct{}{}:
	default:
	}
}

// publishState returns whether the publish loop has to hold (it is paused or
// a recovery is in progress) and the current resume generation.
func (c *Client) publishState() (paused bool, gen uint64) {
	c.publishMu.Lock()
	defer c.publishMu.Unlock()
	return c.publishPaused || c.publishRecovering, c.publishGen
}

// pausePublishIfGen pauses the publish loop after a failed publish attempt
// unless the loop was resumed since the attempt started. Such a resume means
// that whatever made the attempt fail (typically a lost connection) has
// already been repaired, and pausing now would never be undone.
func (c *Client) pausePublishIfGen(gen uint64) {
	c.publishMu.Lock()
	if c.publishGen == gen {
		c.publishPaused = true
	}
	c.publishMu.Unlock()
}

// pauseSubscriptions suspends the publish loop.
// It has no effect if the publish loop is already paused.
func (c *Client) pauseSubscriptions(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	c.setPublishPaused(true)
}

// resumeSubscriptions restarts the publish loop.
// It has no effect if the publish loop is not paused.
func (c *Client) resumeSubscriptions(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	c.setPublishPaused(false)
}

// monitorSubscriptions sends publish requests and handles publish responses
// for all active subscriptions.
func (c *Client) monitorSubscriptions(ctx context.Context) {
	defer c.cfg.logger.Debug("monitorSubscriptions: done")

	for {
		if ctx.Err() != nil {
			c.cfg.logger.Debug("monitorSubscriptions: ctx.Done()")
			return
		}

		paused, gen := c.publishState()
		if paused {
			c.cfg.logger.Debug("monitorSubscriptions: pause")
			select {
			case <-ctx.Done():
			case <-c.resumech:
			case <-c.pausech:
			}
			continue
		}

		// drop wake-ups that are already reflected in the state
		select {
		case <-c.resumech:
		default:
		}
		select {
		case <-c.pausech:
		default:
		}

		if err := c.publish(ctx); err != nil {
			c.cfg.logger.Debug("monitorSubscriptions: error", "error", err)
			c.pausePublishIfGen(gen)
		}
	}
}

// publish sends a publish request and handles the response.
func (c *Client) publish(ctx context.Context) error {
	c.subMux.RLock()
	c.cfg.logger.Debug("publish: pending acks", "pending_acks", c.pendingAcks)
	gen := c.subGen
	c.subMux.RUnlock()

	// send the next publish request
	// note that res contains data even if an error was returned
	session := c.Session()
	res, err := c.sendPublishRequest(ctx)
	stats.RecordError(err)
	switch {
	case err != nil && session != c.Session() && staleSessionError(err):
		// The request was sent in a session the client has left in the
		// meantime (the application activated another one, or the reconnect
		// logic replaced it), and the server says that this session is
		// gone. That is no news and says nothing about the session the
		// client has now: carry on publishing there. Returning the error
		// would pause the publish loop, and nothing would resume it.
		c.cfg.logger.Debug("publish: error for a session the client has left, ignoring", "error", err)
	case errors.Is(err, io.EOF):
		c.cfg.logger.Debug("publish: eof: pausing publish loop")
		return err

	case errors.Is(err, ua.StatusBadSessionNotActivated):
		c.cfg.logger.Debug("publish: session not active, pausing publish loop")
		return err

	case errors.Is(err, ua.StatusBadSessionIDInvalid):
		c.cfg.logger.Debug("publish: session not valid, pausing publish loop")
		return err

	case errors.Is(err, ua.StatusBadServerNotConnected):
		c.cfg.logger.Debug("publish: no connection, pausing publish loop")
		return err

	case errors.Is(err, ua.StatusBadSequenceNumberUnknown):
		c.cfg.logger.Debug("publish: sequence number unknown during ACK", "error", err)

	case errors.Is(err, ua.StatusBadTooManyPublishRequests):
		c.cfg.logger.Debug("publish: too many publish requests, backing off for 1s", "error", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}

	case errors.Is(err, ua.StatusBadTimeout):
		c.cfg.logger.Debug("publish: timeout, ignoring", "error", err)

	case errors.Is(err, ua.StatusBadNoSubscription):
		// The session has no subscription on the server. If the client
		// believes it has some that existed when the request was sent, they
		// ended on the server (expired or deleted): recreate them.
		c.cfg.logger.Debug("publish: no subscriptions but the publishing loop is still running", "error", err)
		if c.cfg.sechan.AutoReconnect && c.markSubscriptionsBrokenSince(gen) > 0 {
			c.requestSubscriptionRecovery()
		}
		return err

	case err != nil && res != nil:
		// Irrecoverable error — notify subscribers so they can react.
		// We don't forget the subscription here; the caller is responsible for cleanup.
		if res.SubscriptionID == 0 {
			c.notifyAllSubscriptionsOfError(ctx, err)
		} else {
			c.notifySubscriptionOfError(ctx, res.SubscriptionID, err)
		}
		c.cfg.logger.Debug("publish: publish error", "error", err)
		return err

	case err != nil:
		c.cfg.logger.Debug("publish: unexpected error, do we need to stop the publish loop?", "error", err)
		return err

	default:
		if orphan := c.deliverPublishResponse(ctx, res); orphan != 0 {
			c.deleteOrphanSubscription(ctx, orphan)
		}
	}

	return nil
}

// staleSessionError reports whether err is how a server answers a request of
// a session that was closed or is not known (any more).
func staleSessionError(err error) bool {
	return errors.Is(err, ua.StatusBadSessionClosed) ||
		errors.Is(err, ua.StatusBadSessionIDInvalid) ||
		errors.Is(err, ua.StatusBadSessionNotActivated)
}

// deliverPublishResponse processes a successful PublishResponse: it updates
// the acknowledgement and sequence number bookkeeping and hands the
// notification to its subscription.
//
// It returns the id of the subscription of the response if that is one a
// failed CreateSubscription request left behind on the server, which the
// caller is to delete, and 0 otherwise.
func (c *Client) deliverPublishResponse(ctx context.Context, res *ua.PublishResponse) (orphan uint32) {
	// For markSilentSubscriptions: a response arrived, and it was for this
	// subscription.
	now := time.Now().UnixNano()
	c.lastPublishResponse.Store(now)
	c.subMux.RLock()
	if sub, ok := c.subs[res.SubscriptionID]; ok {
		sub.lastActivity.Store(now)
	}
	c.subMux.RUnlock()

	// deliverMu orders this delivery with the republishing done by the
	// reconnect logic, which delivers to the same subscriptions.
	c.deliverMu.Lock()
	defer c.deliverMu.Unlock()

	// The response belongs to a request that was sent before a recovery
	// started. The recovery republishes everything from the subscription's
	// next expected sequence number on, including this message, so
	// delivering it here as well would duplicate it or, worse, deliver it
	// after newer ones. It has not been acknowledged, so the server keeps it.
	if c.publishRecoveryInProgress() {
		c.cfg.logger.Debug("publish: response arrived during recovery, leaving it to republish", "sub_id", res.SubscriptionID)
		return 0
	}

	c.subMux.Lock()
	// handle pending acks for all subscriptions
	c.handleAcksNeedsSubMuxLock(res.Results)

	sub, ok := c.subs[res.SubscriptionID]
	if !ok {
		isOrphan := c.orphanSubscriptionNeedsSubMuxLock()
		c.subMux.Unlock()
		// Subscription may have been deleted between PublishRequest and PublishResponse.
		// Returning is correct — the warning log is sufficient.
		c.cfg.logger.Debug("publish: unknown subscription", "sub_id", res.SubscriptionID)
		if isOrphan {
			return res.SubscriptionID
		}
		return 0
	}

	// The notification message the subscription delivered last, once more.
	// The recovery republishes from the subscription's next sequence number
	// while a Publish response with the same message, sent before the
	// recovery began, waits for deliverMu above. When the recovery is over
	// by the time it gets its turn, the check above lets it pass: without
	// this one the consumer would receive the message twice, the second
	// time after newer values. It is acknowledged again and dropped.
	if msg := res.NotificationMessage; len(msg.NotificationData) > 0 && sub.lastSeq != 0 && msg.SequenceNumber == sub.lastSeq {
		c.pendingAcks = append(c.pendingAcks, &ua.SubscriptionAcknowledgement{
			SubscriptionID: res.SubscriptionID,
			SequenceNumber: msg.SequenceNumber,
		})
		c.subMux.Unlock()
		c.cfg.logger.Debug("publish: notification message was delivered already, dropping it", "sub_id", res.SubscriptionID, "seq_num", msg.SequenceNumber)
		return 0
	}

	// handle the publish response for a specific subscription
	c.handleNotificationNeedsSubMuxLock(sub, res)

	// The server announces the end of a subscription (typically BadTimeout,
	// its lifetime expired because no Publish request reached the server in
	// time) with a StatusChangeNotification. Nothing more will ever arrive
	// for it, so have it recreated. The notification itself is still
	// delivered to the consumer below.
	ended := c.cfg.sechan.AutoReconnect && subscriptionEnded(res.NotificationMessage)
	if ended {
		sub.needsRecreate = true
	}
	c.subMux.Unlock()

	c.notifySubscription(ctx, sub, res.NotificationMessage)
	c.cfg.logger.Debug("publish: notification received", "seq_num", res.NotificationMessage.SequenceNumber)

	if ended {
		c.cfg.logger.Debug("publish: subscription ended on the server, scheduling its recreation", "sub_id", res.SubscriptionID)
		c.requestSubscriptionRecovery()
	}
	return 0
}

// subscriptionEnded reports whether a notification message carries a
// StatusChangeNotification with a bad status, which means that the server
// has closed the subscription (Part 4 §5.13.1.1 and §7.20.4). A good status
// such as GoodSubscriptionTransferred does not count: the subscription lives
// on, in another session.
func subscriptionEnded(msg *ua.NotificationMessage) bool {
	if msg == nil {
		return false
	}
	for _, data := range msg.NotificationData {
		if data == nil {
			continue
		}
		if sc, ok := data.Value.(*ua.StatusChangeNotification); ok && sc != nil && sc.Status&0x80000000 != 0 {
			return true
		}
	}
	return false
}

// requestSubscriptionRecovery asks the connection monitor to recreate the
// subscriptions marked with needsRecreate. It never blocks.
func (c *Client) requestSubscriptionRecovery() {
	select {
	case c.subRecoverCh <- struct{}{}:
	default:
	}
}

// recreateSubscriptionLater marks sub for recreation and wakes the connection
// monitor to do it. It never blocks on the network.
func (c *Client) recreateSubscriptionLater(sub *Subscription) {
	c.subMux.Lock()
	sub.needsRecreate = true
	c.subMux.Unlock()
	c.requestSubscriptionRecovery()
}

// markSubscriptionsBroken marks every registered subscription as gone on the
// server and returns how many there are.
func (c *Client) markSubscriptionsBroken() int {
	c.subMux.Lock()
	defer c.subMux.Unlock()
	return c.markSubscriptionsBrokenNeedsSubMuxLock()
}

// markSubscriptionsBrokenSince is markSubscriptionsBroken for a Publish
// request that found the session without subscriptions, sent when subGen
// was gen. A subscription registered since then (a recreation completing
// while the request was under way) is not what the server answered about:
// nothing is marked.
func (c *Client) markSubscriptionsBrokenSince(gen uint64) int {
	c.subMux.Lock()
	defer c.subMux.Unlock()
	if c.subGen != gen {
		return 0
	}
	return c.markSubscriptionsBrokenNeedsSubMuxLock()
}

func (c *Client) markSubscriptionsBrokenNeedsSubMuxLock() int {
	for _, sub := range c.subs {
		sub.needsRecreate = true
	}
	return len(c.subs)
}

// recoverBrokenSubscriptions recreates the subscriptions that ended on the
// server although the connection and the session are fine: their lifetime
// expired, or the server deleted them. It is the recreate step of the
// reconnect logic applied to just those subscriptions; the others are not
// touched and keep publishing. The connection state does not change.
//
// It runs on the connection monitor's goroutine, so it cannot overlap with a
// reconnect. A subscription that cannot be recreated stays marked and is
// tried again by the next recovery; its consumer receives the error.
func (c *Client) recoverBrokenSubscriptions(ctx context.Context) {
	_, broken := c.partitionSubscriptions()
	for _, id := range broken {
		if ctx.Err() != nil {
			return
		}
		if err := c.recreateSubscription(ctx, id); err != nil {
			c.cfg.logger.Debug("recreating ended subscription failed", "sub_id", id, "error", err)
			c.notifySubscriptionOfError(ctx, id, err)
			continue
		}
		c.notifyRecoveryFromMonitor(SubscriptionRecoveryEvent{
			SubscriptionID: id,
			Outcome:        SubscriptionRecoveryRecreated,
			Detail:         "subscription ended on the server (lifetime expired or deleted); recreated as new, previous notification history lost",
		})
	}
}

func (c *Client) handleAcksNeedsSubMuxLock(res []ua.StatusCode) {
	// we assume that the number of results in the response match
	// the number of pending acks from the previous PublishRequest.
	if len(c.pendingAcks) != len(res) {
		c.cfg.logger.Debug("publish: pending ACK count mismatch", "got", len(res), "want", len(c.pendingAcks))
		c.pendingAcks = []*ua.SubscriptionAcknowledgement{}
	}

	// find the messages which we have received but which we have not acked.
	var notAcked []*ua.SubscriptionAcknowledgement
	for i, ack := range c.pendingAcks {
		err := res[i]
		switch err {
		case ua.StatusOK:
			// message ack'ed
		case ua.StatusBadSubscriptionIDInvalid:
			// old subscription id -> skip
			c.cfg.logger.Debug("publish: subscription id invalid, skipping", "error", err)
		case ua.StatusBadSequenceNumberUnknown:
			c.cfg.logger.Debug("publish: notification not on server anymore", "sub_id", ack.SubscriptionID, "seq_num", ack.SequenceNumber, "error", err)
		default:
			// otherwise, we try to ack again
			notAcked = append(notAcked, ack)
			c.cfg.logger.Debug("publish: retrying ACK", "sub_id", ack.SubscriptionID, "seq_num", ack.SequenceNumber, "error", err)
		}
	}
	c.pendingAcks = notAcked
	c.cfg.logger.Debug("publish: not acked", "not_acked", notAcked)
}

func (c *Client) handleNotificationNeedsSubMuxLock(sub *Subscription, res *ua.PublishResponse) {
	// keep-alive message
	// Per OPC-UA Part 4 §7.21, keep-alive messages reuse the last sequence number.
	// Updating nextSeq to the server's value is correct.
	if len(res.NotificationMessage.NotificationData) == 0 {
		sub.nextSeq = res.NotificationMessage.SequenceNumber
		return
	}

	if res.NotificationMessage.SequenceNumber != sub.nextSeq {
		c.cfg.logger.Debug("publish: unexpected sequence number, data loss?", "sub_id", res.SubscriptionID, "got", res.NotificationMessage.SequenceNumber, "want", sub.nextSeq)
	}

	sub.lastSeq = res.NotificationMessage.SequenceNumber
	sub.nextSeq = sub.lastSeq + 1
	c.pendingAcks = append(c.pendingAcks, &ua.SubscriptionAcknowledgement{
		SubscriptionID: res.SubscriptionID,
		SequenceNumber: res.NotificationMessage.SequenceNumber,
	})
}

// publishRequestFn, when non-nil, replaces sendPublishRequest. Used by unit tests
// to exercise the publish() error switch without a live SecureChannel.
var publishRequestFn func(ctx context.Context, c *Client) (*ua.PublishResponse, error)

func (c *Client) sendPublishRequest(ctx context.Context) (*ua.PublishResponse, error) {
	if publishRequestFn != nil {
		return publishRequestFn(ctx, c)
	}

	c.subMux.RLock()
	req := &ua.PublishRequest{
		SubscriptionAcknowledgements: c.pendingAcks,
	}
	if req.SubscriptionAcknowledgements == nil {
		req.SubscriptionAcknowledgements = []*ua.SubscriptionAcknowledgement{}
	}
	c.subMux.RUnlock()

	c.cfg.logger.Debug("publish: publish request", "request", req)
	var res *ua.PublishResponse
	err := c.sendWithTimeout(ctx, req, c.publishTimeout(), func(v ua.Response) error {
		return assign(v, &res)
	})
	stats.RecordError(err)
	c.cfg.logger.Debug("publish: publish response", "response", res)
	return res, err
}
