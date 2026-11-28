// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"slices"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uamethod"
)

// The Methods of the Server Object (OPC 10000-5 §9, ServerType §6.3.1):
// GetMonitoredItems (§9.1), ResendData (§9.2), SetSubscriptionDurable
// (§9.3) and RequestServerStateChange (§9.4). Their InputArguments and
// OutputArguments are the generated contracts of package uamethod.

// registerServerMethods registers the Methods of the Server Object. A call
// of the declaration of ServerType on the Server Object reaches them too
// (instanceMethod).
func (s *Server) registerServerMethods() {
	obj := ua.NewNumericNodeID(0, id.Server)
	m := func(nid uint32) *ua.NodeID { return ua.NewNumericNodeID(0, nid) }
	s.RegisterMethod(obj, m(id.ServerGetMonitoredItems), s.getMonitoredItemsMethod)
	s.RegisterMethod(obj, m(id.ServerResendData), s.resendDataMethod)
	if !s.cfg.durable.Disabled {
		s.RegisterMethod(obj, m(id.ServerSetSubscriptionDurable), s.setSubscriptionDurableMethod)
	}
	s.RegisterMethod(obj, m(id.ServerRequestServerStateChange), s.requestServerStateChangeMethod)
}

// ownedSubscription returns the subscription subID when the session of the
// call owns it. "The Method shall be called from the Session that owns the
// Subscription" (Part 4 §6.7, §6.8): an unknown subscription is
// Bad_SubscriptionIdInvalid, one of another session, or a call without a
// session, Bad_UserAccessDenied ("The Method was not called in the context
// of the Session that owns the Subscription", Part 5 §9.1 to §9.3). "The
// Server shall verify that the Method is called within the Session context
// of the Session that owns the Subscription" (Part 4 §6.7, §6.8).
func (s *Server) ownedSubscription(ctx context.Context, subID uint32) (*Subscription, ua.StatusCode) {
	ss := s.SubscriptionService
	if ss == nil || s.MonitoredItemService == nil {
		return nil, ua.StatusBadSubscriptionIDInvalid
	}
	ss.Mu.Lock()
	sub := ss.Subs[subID]
	ss.Mu.Unlock()
	if sub == nil {
		return nil, ua.StatusBadSubscriptionIDInvalid
	}
	caller, _ := MethodCallerFromContext(ctx)
	owner, _ := sub.sessionChannel()
	if caller == nil || caller.SessionID == nil || owner == nil || !caller.SessionID.Equal(owner.ID) {
		return nil, ua.StatusBadUserAccessDenied
	}
	return sub, ua.StatusOK
}

// getMonitoredItemsMethod implements GetMonitoredItems (Part 5 §9.1): the
// serverHandles (the MonitoredItemIds) and the clientHandles of all
// MonitoredItems of the subscription, data and event items, in the order
// they were created.
func (s *Server) getMonitoredItemsMethod(ctx context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	var in uamethod.ServerTypeGetMonitoredItemsInput
	if err := in.Unpack(args); err != nil {
		return nil, uamethod.StatusOf(err)
	}
	if _, sc := s.ownedSubscription(ctx, in.SubscriptionID); sc != ua.StatusOK {
		return nil, sc
	}
	out := uamethod.ServerTypeGetMonitoredItemsOutput{ServerHandles: []uint32{}, ClientHandles: []uint32{}}
	mis := s.MonitoredItemService
	mis.Mu.Lock()
	for _, it := range mis.Subs[in.SubscriptionID] {
		if it == nil {
			continue
		}
		var handle uint32
		if it.Req != nil && it.Req.RequestedParameters != nil {
			handle = it.Req.RequestedParameters.ClientHandle
		}
		out.ServerHandles = append(out.ServerHandles, it.ID)
		out.ClientHandles = append(out.ClientHandles, handle)
	}
	mis.Mu.Unlock()
	return out.Pack(), ua.StatusOK
}

// resendDataMethod implements ResendData (Part 5 §9.2, Part 4 §6.7): it
// "initiates resending of all data monitored items in a Subscription", the
// data items in Reporting mode. "If a value is queued for a data
// MonitoredItem, the next value in the queue is sent in the Publish
// response. If no value is queued for a data MonitoredItem, the last value
// sent is repeated in the Publish response." The values go out at the end
// of the current publishing interval, as any notification: "The data
// should be sent in the next regular PublishingInterval". Event items and
// items in Sampling or Disabled mode are left alone; an item that has sent
// nothing yet has nothing to repeat.
func (s *Server) resendDataMethod(ctx context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	var in uamethod.ServerTypeResendDataInput
	if err := in.Unpack(args); err != nil {
		return nil, uamethod.StatusOf(err)
	}
	sub, sc := s.ownedSubscription(ctx, in.SubscriptionID)
	if sc != ua.StatusOK {
		return nil, sc
	}
	if s.MonitoredItemService.resend(in.SubscriptionID) {
		select {
		case sub.NotifyChannel <- &ua.MonitoredItemNotification{}:
		default: // a wake-up is pending
		}
	}
	return nil, ua.StatusOK
}

// resend queues the last value sent of every data item of the
// subscription in Reporting mode with an empty queue, and reports whether
// a Reporting data item has something to send.
func (s *MonitoredItemService) resend(subID uint32) bool {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	pending := false
	for _, it := range s.Subs[subID] {
		if it == nil || it.isEvent || it.Mode != ua.MonitoringModeReporting {
			continue
		}
		if len(it.queue) == 0 {
			if it.lastSent == nil {
				continue
			}
			it.queue = append(it.queue, copyNotification(it.lastSent))
		}
		pending = true
	}
	return pending
}

// copyNotification returns a copy of n with a copy of its DataValue: the
// one sent may still be referenced by the retransmission queue.
func copyNotification(n *ua.MonitoredItemNotification) *ua.MonitoredItemNotification {
	cp := *n
	if n.Value != nil {
		dv := *n.Value
		cp.Value = &dv
	}
	return &cp
}

// setSubscriptionDurableMethod implements SetSubscriptionDurable (Part 5
// §9.3, Part 4 §6.8). "This Method shall be called before MonitoredItems
// are created in the durable Subscription": a subscription with
// MonitoredItems is Bad_InvalidState (Part 5 §9.3). "A value of 0 for the
// parameter lifetimeInHours requests the highest lifetime supported by the
// Server"; a longer one is revised to it too.
// "The revisedLifetimeInHours is used to set the LifetimeCount of the
// Subscription" (Part 4 §6.8): the count of publishing intervals of that
// many hours (see DurableSubscriptions).
func (s *Server) setSubscriptionDurableMethod(ctx context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	var in uamethod.ServerTypeSetSubscriptionDurableInput
	if err := in.Unpack(args); err != nil {
		return nil, uamethod.StatusOf(err)
	}
	sub, sc := s.ownedSubscription(ctx, in.SubscriptionID)
	if sc != ua.StatusOK {
		return nil, sc
	}
	d := s.cfg.durable
	// The monitored item lock is held while the subscription becomes
	// durable, so no CreateMonitoredItems can add an item in between, and
	// the item it adds next has the queue size of a durable subscription.
	mis := s.MonitoredItemService
	mis.Mu.Lock()
	defer mis.Mu.Unlock()
	if len(mis.Subs[in.SubscriptionID]) > 0 {
		return nil, ua.StatusBadInvalidState
	}
	hours := in.LifetimeInHours
	if maxHours := d.maxLifetimeInHours(); hours == 0 || hours > maxHours {
		hours = maxHours
	}
	sub.Mu.Lock()
	count := lifetimeCountFor(hours, sub.RevisedPublishingInterval, sub.RevisedMaxKeepAliveCount)
	sub.RevisedLifetimeCount = count
	revised := lifetimeInHours(count, sub.RevisedPublishingInterval)
	sub.Mu.Unlock()
	sub.durable.Store(true)
	out := uamethod.ServerTypeSetSubscriptionDurableOutput{RevisedLifetimeInHours: revised}
	return out.Pack(), ua.StatusOK
}

// requestServerStateChangeMethod implements RequestServerStateChange (Part
// 5 §9.4). "The Client shall provide credentials with administrative
// rights when invoking this Method on the Server": the session needs the
// role ConfigureAdmin or SecurityAdmin, the roles the RolePermissions of
// the Method in the NodeSet grant Call to (else Bad_UserAccessDenied). The
// application carries the change out (WithServerStateChange); without a
// handler, and for a State that is no ServerState (Part 5 §12.6), the
// server does not accept the requested state (Bad_InvalidState).
func (s *Server) requestServerStateChangeMethod(ctx context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	var in uamethod.ServerTypeRequestServerStateChangeInput
	if err := in.Unpack(args); err != nil {
		return nil, uamethod.StatusOf(err)
	}
	caller, _ := MethodCallerFromContext(ctx)
	if caller == nil || caller.SessionID == nil || !callerHasRole(caller, ua.RoleConfigureAdmin, ua.RoleSecurityAdmin) {
		return nil, ua.StatusBadUserAccessDenied
	}
	state := ua.ServerState(in.State)
	if s.cfg.stateChange == nil || state < ua.ServerStateRunning || state > ua.ServerStateUnknown {
		return nil, ua.StatusBadInvalidState
	}
	c := ServerStateChange{
		State:               state,
		EstimatedReturnTime: in.EstimatedReturnTime,
		SecondsTillShutdown: in.SecondsTillShutdown,
		Reason:              in.Reason,
		Restart:             in.Restart,
	}
	if sc := s.cfg.stateChange(ctx, c); sc != ua.StatusOK {
		return nil, sc
	}
	s.SetServerState(c)
	return nil, ua.StatusOK
}

// callerHasRole reports whether the caller was granted one of the roles.
func callerHasRole(c *MethodCaller, roles ...ua.WellKnownRole) bool {
	return slices.ContainsFunc(c.Roles, func(r *ua.NodeID) bool {
		if r == nil || r.Namespace() != 0 {
			return false
		}
		return slices.ContainsFunc(roles, func(want ua.WellKnownRole) bool { return r.IntID() == uint32(want) })
	})
}
