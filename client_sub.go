package opcua

import (
	"context"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/stats"
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

	res, err := send[ua.CreateSubscriptionResponse](ctx, c, req)
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

	// start the publish loop if it isn't already running
	c.resumech <- struct{}{}

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
	}

	c.subMux.Lock()
	defer c.subMux.Unlock()

	if sub.SubscriptionID == 0 || c.subs[sub.SubscriptionID] != nil {
		// this should not happen and is usually indicative of a server bug
		// see: Part 4 Section 5.13.2.2, Table 88 – CreateSubscription Service Parameters
		return nil, ua.StatusBadSubscriptionIDInvalid
	}

	c.subs[sub.SubscriptionID] = sub
	c.updatePublishTimeoutNeedsSubMuxLock()
	return sub, nil
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
	c.forgetSubscriptionNeedsSubMuxLock(ctx, id)
	return sub.recreateCreate(ctx)
}

// transferSubscriptions ask the server to transfer the given subscriptions
// of the previous session to the current one.
func (c *Client) transferSubscriptions(ctx context.Context, ids []uint32) (*ua.TransferSubscriptionsResponse, error) {
	req := &ua.TransferSubscriptionsRequest{
		SubscriptionIDs:   ids,
		SendInitialValues: false,
	}

	return send[ua.TransferSubscriptionsResponse](ctx, c, req)
}

// republishSubscriptions sends republish requests for the given subscription id.
func (c *Client) republishSubscription(ctx context.Context, id uint32, availableSeq []uint32) error {
	c.subMux.RLock()
	sub := c.subs[id]
	c.subMux.RUnlock()

	if sub == nil {
		return fmt.Errorf("%w: id=%d", errors.ErrInvalidSubscriptionID, id)
	}

	c.cfg.logger.Debugf("republishing subscription sub_id=%v", sub.SubscriptionID)
	if err := c.sendRepublishRequests(ctx, sub, availableSeq); err != nil {
		switch {
		case errors.Is(err, ua.StatusBadSessionIDInvalid):
			return nil
		case errors.Is(err, ua.StatusBadSubscriptionIDInvalid):
			// The server no longer recognises this subscription (may have timed out).
			// We do not call forgetSubscription here because the publish loop will
			// detect the invalid ID and clean up on the next cycle.
			c.cfg.logger.Debugf("republish failed, subscription invalid sub_id=%v", sub.SubscriptionID)
			return fmt.Errorf("%w: subscription %d is invalid", errors.ErrInvalidSubscriptionID, sub.SubscriptionID)
		default:
			return err
		}
	}
	return nil
}

// sendRepublishRequests sends republish requests for the given subscription
// until it gets a BadMessageNotAvailable which implies that there are no
// more messages to restore.
func (c *Client) sendRepublishRequests(ctx context.Context, sub *Subscription, availableSeq []uint32) error {
	// If our expected next sequence number isn't in the server's retransmission queue
	// some notifications may have been lost. We log a warning and continue rather than
	// failing because data loss during reconnection is expected per Part 4 §6.5.
	if len(availableSeq) > 0 && !slices.Contains(availableSeq, sub.nextSeq) {
		c.cfg.logger.Warnf("next sequence number not in retransmission buffer sub_id=%v next_seq=%v available_seq=%v", sub.SubscriptionID, sub.nextSeq, availableSeq)
	}

	for {
		req := &ua.RepublishRequest{
			SubscriptionID:           sub.SubscriptionID,
			RetransmitSequenceNumber: sub.nextSeq,
		}

		c.cfg.logger.Debugf("republishing subscription sub_id=%v seq_num=%v", req.SubscriptionID, req.RetransmitSequenceNumber)

		s := c.Session()
		if s == nil {
			c.cfg.logger.Debugf("republishing subscription aborted sub_id=%v", req.SubscriptionID)
			return ua.StatusBadSessionClosed
		}

		sc := c.SecureChannel()
		if sc == nil {
			c.cfg.logger.Debugf("republishing subscription aborted sub_id=%v", req.SubscriptionID)
			return ua.StatusBadNotConnected
		}

		c.cfg.logger.Debugf("republish request request=%v", req)
		var res *ua.RepublishResponse
		err := sc.SendRequest(ctx, req, c.Session().resp.AuthenticationToken, func(v ua.Response) error {
			return assign(v, &res)
		})
		c.cfg.logger.Debugf("republish response response=%v error=%v", res, err)

		switch {
		case err == ua.StatusBadMessageNotAvailable:
			// No more message to restore
			c.cfg.logger.Debugf("republishing subscription OK sub_id=%v", req.SubscriptionID)
			return nil

		case err != nil:
			c.cfg.logger.Debugf("republishing subscription failed sub_id=%v error=%v", req.SubscriptionID, err)
			return err

		default:
			status := ua.StatusBad
			if res != nil {
				status = res.ResponseHeader.ServiceResult
			}

			if status != ua.StatusOK {
				c.cfg.logger.Debugf("republishing subscription failed sub_id=%v status=%v", req.SubscriptionID, status)
				return status
			}

			// Process the republished notification and advance sequence number
			if res.NotificationMessage != nil {
				c.notifySubscription(ctx, sub, res.NotificationMessage)
				sub.lastSeq = res.NotificationMessage.SequenceNumber
				sub.nextSeq = sub.lastSeq + 1
				c.cfg.logger.Debugf("republished notification seq_num=%v sub_id=%v", res.NotificationMessage.SequenceNumber, sub.SubscriptionID)

				if len(availableSeq) > 0 && !slices.Contains(availableSeq, sub.nextSeq) {
					c.cfg.logger.Debugf("republishing subscription complete sub_id=%v", sub.SubscriptionID)
					return nil
				}
			}
		}

		time.Sleep(time.Second)
	}
}

// registerSubscriptionNeedsSubMuxLock registers a subscription.
func (c *Client) registerSubscriptionNeedsSubMuxLock(sub *Subscription) error {
	if sub.SubscriptionID == 0 {
		return ua.StatusBadSubscriptionIDInvalid
	}

	if _, ok := c.subs[sub.SubscriptionID]; ok {
		return fmt.Errorf("%w: id=%d", errors.ErrInvalidSubscriptionID, sub.SubscriptionID)
	}

	c.subs[sub.SubscriptionID] = sub
	return nil
}

func (c *Client) forgetSubscription(ctx context.Context, id uint32) {
	c.subMux.Lock()
	c.forgetSubscriptionNeedsSubMuxLock(ctx, id)
	c.subMux.Unlock()
}

func (c *Client) forgetSubscriptionNeedsSubMuxLock(ctx context.Context, id uint32) {
	delete(c.subs, id)
	c.updatePublishTimeoutNeedsSubMuxLock()
	stats.Subscription().Add("Count", -1)

	if len(c.subs) == 0 {
		// pauseSubscriptions blocks on channel send; this is acceptable under the
		// subscription mutex since there are no remaining subs to contend.
		c.pauseSubscriptions(ctx)
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
			SubscriptionID: sub.SubscriptionID,
			Error:          errors.ErrEmptyResponse,
		})
		return
	}

	// Part 4, 7.21 NotificationMessage
	for _, data := range notif.NotificationData {
		// Part 4, 7.20 NotificationData parameters
		if data == nil || data.Value == nil {
			sub.notify(ctx, &PublishNotificationData{
				SubscriptionID: sub.SubscriptionID,
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
				SubscriptionID: sub.SubscriptionID,
				Value:          v,
			})

		// Error
		default:
			sub.notify(ctx, &PublishNotificationData{
				SubscriptionID: sub.SubscriptionID,
				Error:          fmt.Errorf("%w: %T", errors.ErrInvalidResponseType, data.Value),
			})
		}
	}
}

// pauseSubscriptions suspends the publish loop by signalling the pausech.
// It has no effect if the publish loop is already paused.
func (c *Client) pauseSubscriptions(ctx context.Context) {
	select {
	case <-ctx.Done():
	case c.pausech <- struct{}{}:
	}
}

// resumeSubscriptions restarts the publish loop by signalling the resumech.
// It has no effect if the publish loop is not paused.
func (c *Client) resumeSubscriptions(ctx context.Context) {
	select {
	case <-ctx.Done():
	case c.resumech <- struct{}{}:
	}
}

// monitorSubscriptions sends publish requests and handles publish responses
// for all active subscriptions.
func (c *Client) monitorSubscriptions(ctx context.Context) {
	defer c.cfg.logger.Debugf("monitorSubscriptions: done")

publish:
	for {
		select {
		case <-ctx.Done():
			c.cfg.logger.Debugf("monitorSubscriptions: ctx.Done()")
			return

		case <-c.resumech:
			c.cfg.logger.Debugf("monitorSubscriptions: resume")
			// ignore since not paused

		case <-c.pausech:
			c.cfg.logger.Debugf("monitorSubscriptions: pause")
			for {
				select {
				case <-ctx.Done():
					c.cfg.logger.Debugf("monitorSubscriptions: pause: ctx.Done()")
					return

				case <-c.resumech:
					c.cfg.logger.Debugf("monitorSubscriptions: pause: resume")
					continue publish

				case <-c.pausech:
					c.cfg.logger.Debugf("monitorSubscriptions: pause: pause")
					// ignore since already paused
				}
			}

		default:
			// send publish request and handle response
			//
			// publish() blocks until a PublishResponse
			// is received or the context is cancelled.
			if err := c.publish(ctx); err != nil {
				c.cfg.logger.Debugf("monitorSubscriptions: error error=%v", err)
				c.pauseSubscriptions(ctx)
			}
		}
	}
}

// publish sends a publish request and handles the response.
func (c *Client) publish(ctx context.Context) error {
	c.subMux.RLock()
	c.cfg.logger.Debugf("publish: pending acks pending_acks=%v", c.pendingAcks)
	c.subMux.RUnlock()

	// send the next publish request
	// note that res contains data even if an error was returned
	res, err := c.sendPublishRequest(ctx)
	stats.RecordError(err)
	switch {
	case err == io.EOF:
		c.cfg.logger.Debugf("publish: eof: pausing publish loop")
		return err

	case err == ua.StatusBadSessionNotActivated:
		c.cfg.logger.Debugf("publish: session not active, pausing publish loop")
		return err

	case err == ua.StatusBadSessionIDInvalid:
		c.cfg.logger.Debugf("publish: session not valid, pausing publish loop")
		return err

	case err == ua.StatusBadServerNotConnected:
		c.cfg.logger.Debugf("publish: no connection, pausing publish loop")
		return err

	case err == ua.StatusBadSequenceNumberUnknown:
		// Per Part 4 §5.13.5, this occurs when an ACK'd sequence number is
		// not in the server's retransmission queue. Logged for diagnostics.
		c.cfg.logger.Debugf("publish: sequence number unknown during ACK error=%v", err)

	case err == ua.StatusBadTooManyPublishRequests:
		// Server indicates we have too many outstanding PublishRequests.
		// Back off for one second before retrying (Part 4 §5.13.5).
		c.cfg.logger.Debugf("publish: too many publish requests, backing off for 1s error=%v", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}

	case err == ua.StatusBadTimeout:
		// ignore and continue the loop
		c.cfg.logger.Debugf("publish: timeout, ignoring error=%v", err)

	case err == ua.StatusBadNoSubscription:
		// All subscriptions have been deleted, but the publishing loop is still running
		// We should pause publishing until a subscription has been created
		c.cfg.logger.Debugf("publish: no subscriptions but the publishing loop is still running error=%v", err)
		return err

	case err != nil && res != nil:
		// Irrecoverable error — notify subscribers so they can react.
		// We don't forget the subscription here; the caller is responsible for cleanup.
		if res.SubscriptionID == 0 {
			c.notifyAllSubscriptionsOfError(ctx, err)
		} else {
			c.notifySubscriptionOfError(ctx, res.SubscriptionID, err)
		}
		c.cfg.logger.Debugf("publish: publish error error=%v", err)
		return err

	case err != nil:
		c.cfg.logger.Debugf("publish: unexpected error, do we need to stop the publish loop? error=%v", err)
		return err

	default:
		c.subMux.Lock()
		// handle pending acks for all subscriptions
		c.handleAcksNeedsSubMuxLock(res.Results)

		sub, ok := c.subs[res.SubscriptionID]
		if !ok {
			c.subMux.Unlock()
			// Subscription may have been deleted between PublishRequest and PublishResponse.
			// Returning nil is correct — the warning log is sufficient.
			c.cfg.logger.Debugf("publish: unknown subscription sub_id=%v", res.SubscriptionID)
			return nil
		}

		// handle the publish response for a specific subscription
		c.handleNotificationNeedsSubMuxLock(sub, res)
		c.subMux.Unlock()

		c.notifySubscription(ctx, sub, res.NotificationMessage)
		c.cfg.logger.Debugf("publish: notification received seq_num=%v", res.NotificationMessage.SequenceNumber)
	}

	return nil
}

func (c *Client) handleAcksNeedsSubMuxLock(res []ua.StatusCode) {
	// we assume that the number of results in the response match
	// the number of pending acks from the previous PublishRequest.
	if len(c.pendingAcks) != len(res) {
		c.cfg.logger.Debugf("publish: pending ACK count mismatch got=%v want=%v", len(res), len(c.pendingAcks))
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
			c.cfg.logger.Debugf("publish: subscription id invalid, skipping error=%v", err)
		case ua.StatusBadSequenceNumberUnknown:
			// server does not have the message in its retransmission queue anymore
			c.cfg.logger.Debugf("publish: notification not on server anymore sub_id=%v seq_num=%v error=%v", ack.SubscriptionID, ack.SequenceNumber, err)
		default:
			// otherwise, we try to ack again
			notAcked = append(notAcked, ack)
			c.cfg.logger.Debugf("publish: retrying ACK sub_id=%v seq_num=%v error=%v", ack.SubscriptionID, ack.SequenceNumber, err)
		}
	}
	c.pendingAcks = notAcked
	c.cfg.logger.Debugf("publish: not acked not_acked=%v", notAcked)
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
		c.cfg.logger.Debugf("publish: unexpected sequence number, data loss? sub_id=%v got=%v want=%v", res.SubscriptionID, res.NotificationMessage.SequenceNumber, sub.nextSeq)
	}

	sub.lastSeq = res.NotificationMessage.SequenceNumber
	sub.nextSeq = sub.lastSeq + 1
	c.pendingAcks = append(c.pendingAcks, &ua.SubscriptionAcknowledgement{
		SubscriptionID: res.SubscriptionID,
		SequenceNumber: res.NotificationMessage.SequenceNumber,
	})
}

func (c *Client) sendPublishRequest(ctx context.Context) (*ua.PublishResponse, error) {
	c.subMux.RLock()
	req := &ua.PublishRequest{
		SubscriptionAcknowledgements: c.pendingAcks,
	}
	if req.SubscriptionAcknowledgements == nil {
		req.SubscriptionAcknowledgements = []*ua.SubscriptionAcknowledgement{}
	}
	c.subMux.RUnlock()

	c.cfg.logger.Debugf("publish: publish request request=%v", req)
	var res *ua.PublishResponse
	err := c.sendWithTimeout(ctx, req, c.publishTimeout(), func(v ua.Response) error {
		return assign(v, &res)
	})
	stats.RecordError(err)
	c.cfg.logger.Debugf("publish: publish response response=%v", res)
	return res, err
}
