// SPDX-License-Identifier: MIT

package opcua

import (
	"context"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uamethod"
)

// The Methods of the Server Object (OPC 10000-5 §9), called with the
// contracts of package uamethod on the Server Object (i=2253) and its
// Methods (Server_GetMonitoredItems and the others). A Bad result is a
// *uamethod.CallError, which errors.Is matches with its StatusCode
// (ua.StatusBadSubscriptionIDInvalid, ua.StatusBadUserAccessDenied, ...).

// serverMethod returns the Object and Method NodeIds of a Method of the
// Server Object.
func serverMethod(method uint32) (obj, m *ua.NodeID) {
	return ua.NewNumericNodeID(0, id.Server), ua.NewNumericNodeID(0, method)
}

// GetMonitoredItems calls GetMonitoredItems (OPC 10000-5 §9.1): the
// serverHandles (MonitoredItemIds) and clientHandles of the MonitoredItems
// of the subscription subscriptionID, which the session of the client must
// own (else ua.StatusBadUserAccessDenied). [Subscription.GetMonitoredItems]
// calls it for a subscription of the client.
func (c *Client) GetMonitoredItems(ctx context.Context, subscriptionID uint32) (*uamethod.ServerTypeGetMonitoredItemsOutput, error) {
	obj, m := serverMethod(id.ServerGetMonitoredItems)
	return uamethod.CallServerTypeGetMonitoredItems(ctx, c, obj, m, &uamethod.ServerTypeGetMonitoredItemsInput{SubscriptionID: subscriptionID})
}

// ResendData calls ResendData (OPC 10000-5 §9.2): the next Publish
// responses of the subscription carry the current value of each of its
// data MonitoredItems in Reporting mode, "to make sure the Client has the
// latest values for all MonitoredItems" after it lost NotificationMessages
// it cannot get with Republish (OPC 10000-4 §6.7).
func (c *Client) ResendData(ctx context.Context, subscriptionID uint32) error {
	obj, m := serverMethod(id.ServerResendData)
	return uamethod.CallServerTypeResendData(ctx, c, obj, m, &uamethod.ServerTypeResendDataInput{SubscriptionID: subscriptionID})
}

// SetSubscriptionDurable calls SetSubscriptionDurable (OPC 10000-5 §9.3,
// OPC 10000-4 §6.8) and returns the revisedLifetimeInHours. It is called
// before the subscription has MonitoredItems (else
// ua.StatusBadInvalidState); lifetimeInHours 0 asks for the longest
// lifetime of the server.
func (c *Client) SetSubscriptionDurable(ctx context.Context, subscriptionID, lifetimeInHours uint32) (uint32, error) {
	obj, m := serverMethod(id.ServerSetSubscriptionDurable)
	out, err := uamethod.CallServerTypeSetSubscriptionDurable(ctx, c, obj, m, &uamethod.ServerTypeSetSubscriptionDurableInput{
		SubscriptionID: subscriptionID, LifetimeInHours: lifetimeInHours,
	})
	if err != nil {
		return 0, err
	}
	return out.RevisedLifetimeInHours, nil
}

// RequestServerStateChange calls RequestServerStateChange (OPC 10000-5
// §9.4), which needs a user with administrative rights
// (ua.StatusBadUserAccessDenied otherwise); ua.StatusBadInvalidState is a
// state the server did not accept. in.State is a ua.ServerState as an
// Int32: int32(ua.ServerStateShutdown).
func (c *Client) RequestServerStateChange(ctx context.Context, in *uamethod.ServerTypeRequestServerStateChangeInput) error {
	obj, m := serverMethod(id.ServerRequestServerStateChange)
	return uamethod.CallServerTypeRequestServerStateChange(ctx, c, obj, m, in)
}

// GetMonitoredItems calls GetMonitoredItems for the subscription. The
// ServerHandles are the ids [Subscription.Monitor] returned for the items
// the client created, which differ from the server's after a recreation of
// the subscription; an item the client does not know keeps the server's
// id.
func (s *Subscription) GetMonitoredItems(ctx context.Context) (*uamethod.ServerTypeGetMonitoredItemsOutput, error) {
	out, err := s.c.GetMonitoredItems(ctx, s.id())
	if err != nil {
		return nil, err
	}
	s.itemsMu.Lock()
	for i, h := range out.ServerHandles {
		out.ServerHandles[i] = s.callerItemIDNeedsLock(h)
	}
	s.itemsMu.Unlock()
	return out, nil
}

// callerItemIDNeedsLock translates the server's id of an item into the id
// the caller holds, the inverse of serverItemIDNeedsLock. itemsMu must be
// held.
func (s *Subscription) callerItemIDNeedsLock(serverID uint32) uint32 {
	for id, item := range s.items {
		if item.serverID == serverID {
			return id
		}
	}
	return serverID
}

// ResendData calls ResendData for the subscription.
func (s *Subscription) ResendData(ctx context.Context) error {
	return s.c.ResendData(ctx, s.id())
}

// SetDurable calls SetSubscriptionDurable for the subscription, before
// [Subscription.Monitor] creates its first item, and returns the
// revisedLifetimeInHours. The server sets the LifetimeCount from it;
// RevisedLifetimeCount keeps the value of the creation, and a later
// [Subscription.ModifySubscription] sets the LifetimeCount of its
// parameters: "If the Client would like to keep the previous life time
// setting, the Client needs to calculate the LifetimeCount" (OPC 10000-4
// §6.8). A subscription the client recreates after a reconnect, when it
// could not transfer it, is not durable.
func (s *Subscription) SetDurable(ctx context.Context, lifetimeInHours uint32) (uint32, error) {
	return s.c.SetSubscriptionDurable(ctx, s.id(), lifetimeInHours)
}
