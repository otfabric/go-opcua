// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil/cleanup"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uamethod"
)

// methodCtx is the context of a call of the session sess (nil: no
// session) with roles.
func methodCtx(sess *session, roles ...*ua.NodeID) context.Context {
	c := &MethodCaller{Roles: roles}
	if sess != nil {
		c.SessionID = sess.ID
	}
	return context.WithValue(context.Background(), methodCallerKey{}, c)
}

// addItem adds a monitored item to sub as CreateMonitoredItems would.
func addItem(srv *Server, sub *Subscription, it *MonitoredItem) *MonitoredItem {
	mis := srv.MonitoredItemService
	it.Sub = sub
	if it.ID == 0 {
		it.ID = mis.NextID()
	}
	mis.Mu.Lock()
	mis.Items[it.ID] = it
	mis.Subs[sub.ID] = append(mis.Subs[sub.ID], it)
	mis.Mu.Unlock()
	return it
}

func clientItem(handle uint32) *ua.MonitoredItemCreateRequest {
	return &ua.MonitoredItemCreateRequest{RequestedParameters: &ua.MonitoringParameters{ClientHandle: handle}}
}

// TestServerMethodsRegistered: the four Methods of the Server Object have
// handlers, SetSubscriptionDurable only with durable subscriptions.
func TestServerMethodsRegistered(t *testing.T) {
	has := func(s *Server, m uint32) bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		_, ok := s.methods[methodKey(ua.NewNumericNodeID(0, id.Server), ua.NewNumericNodeID(0, m))]
		return ok
	}
	s := newTestServer()
	for _, m := range []uint32{id.ServerGetMonitoredItems, id.ServerResendData, id.ServerSetSubscriptionDurable, id.ServerRequestServerStateChange} {
		require.True(t, has(s, m), "i=%d", m)
	}
	// The declaration of ServerType called on the Server Object is the
	// Method of the Server Object.
	r := s.instanceMethod(&ua.CallMethodRequest{ObjectID: ua.NewNumericNodeID(0, id.Server), MethodID: ua.NewNumericNodeID(0, id.ServerTypeResendData)})
	require.True(t, r.MethodID.Equal(ua.NewNumericNodeID(0, id.ServerResendData)))

	off, err := newServerNoNS(WithDurableSubscriptions(DurableSubscriptions{Disabled: true}))
	require.NoError(t, err)
	require.False(t, has(off, id.ServerSetSubscriptionDurable))
	require.True(t, has(off, id.ServerGetMonitoredItems))
}

// TestServerMethodsOwnership: the subscription Methods are refused for an
// unknown subscription, another session, no session and wrong arguments.
func TestServerMethodsOwnership(t *testing.T) {
	s := newTestServer()
	_, sub, _ := newTestSubscription(s)
	other := s.sb.NewSession()
	arg := func(xs ...any) []*ua.Variant {
		out := make([]*ua.Variant, len(xs))
		for i, x := range xs {
			out[i] = ua.MustVariant(x)
		}
		return out
	}
	for name, h := range map[string]MethodHandler{
		"GetMonitoredItems":      s.getMonitoredItemsMethod,
		"ResendData":             s.resendDataMethod,
		"SetSubscriptionDurable": s.setSubscriptionDurableMethod,
	} {
		args := arg(sub.ID)
		bad := arg(sub.ID + 1)
		if name == "SetSubscriptionDurable" {
			args, bad = arg(sub.ID, uint32(1)), arg(sub.ID+1, uint32(1))
		}
		_, sc := h(methodCtx(sub.Session), nil, nil, bad)
		require.Equal(t, ua.StatusBadSubscriptionIDInvalid, sc, name)
		_, sc = h(methodCtx(other), nil, nil, args)
		require.Equal(t, ua.StatusBadUserAccessDenied, sc, name)
		_, sc = h(methodCtx(nil), nil, nil, args)
		require.Equal(t, ua.StatusBadUserAccessDenied, sc, name)
		_, sc = h(context.Background(), nil, nil, args)
		require.Equal(t, ua.StatusBadUserAccessDenied, sc, name)
		_, sc = h(methodCtx(sub.Session), nil, nil, nil)
		require.Equal(t, ua.StatusBadArgumentsMissing, sc, name)
		_, sc = h(methodCtx(sub.Session), nil, nil, arg("x", "y")[:len(args)])
		require.Equal(t, ua.StatusBadTypeMismatch, sc, name)
	}

	// A subscription that lost its session belongs to nobody.
	sub.Mu.Lock()
	owner := sub.Session
	sub.Session = nil
	sub.Mu.Unlock()
	_, sc := s.getMonitoredItemsMethod(methodCtx(owner), nil, nil, arg(sub.ID))
	require.Equal(t, ua.StatusBadUserAccessDenied, sc)

	// A server without the subscription services.
	s.SubscriptionService = nil
	_, sc = s.resendDataMethod(methodCtx(owner), nil, nil, arg(sub.ID))
	require.Equal(t, ua.StatusBadSubscriptionIDInvalid, sc)
}

// TestGetMonitoredItemsMethod: the server and client handles of every item
// of the subscription, in the order of creation (Part 5 §9.1).
func TestGetMonitoredItemsMethod(t *testing.T) {
	s := newTestServer()
	_, sub, _ := newTestSubscription(s)
	ctx := methodCtx(sub.Session)
	in := (&uamethod.ServerTypeGetMonitoredItemsInput{SubscriptionID: sub.ID}).Pack()

	got, sc := s.getMonitoredItemsMethod(ctx, nil, nil, in)
	require.Equal(t, ua.StatusOK, sc)
	var out uamethod.ServerTypeGetMonitoredItemsOutput
	require.NoError(t, out.Unpack(got))
	require.Equal(t, []uint32{}, out.ServerHandles, "no items: empty arrays")
	require.Equal(t, []uint32{}, out.ClientHandles)

	a := addItem(s, sub, &MonitoredItem{Req: clientItem(7)})
	b := addItem(s, sub, &MonitoredItem{Req: clientItem(9), isEvent: true})
	c := addItem(s, sub, &MonitoredItem{}) // no request: handle 0
	s.MonitoredItemService.Mu.Lock()
	s.MonitoredItemService.Subs[sub.ID] = append(s.MonitoredItemService.Subs[sub.ID], nil)
	s.MonitoredItemService.Mu.Unlock()

	got, sc = s.getMonitoredItemsMethod(ctx, nil, nil, in)
	require.Equal(t, ua.StatusOK, sc)
	require.NoError(t, out.Unpack(got))
	require.Equal(t, []uint32{a.ID, b.ID, c.ID}, out.ServerHandles)
	require.Equal(t, []uint32{7, 9, 0}, out.ClientHandles)
}

// TestResendDataMethod: a Reporting data item with a queue sends its queue,
// one without repeats its last value sent; event items, items in another
// mode and items that sent nothing are left alone (Part 4 §6.7).
func TestResendDataMethod(t *testing.T) {
	s := newTestServer()
	_, sub, _ := newTestSubscription(s)
	ctx := methodCtx(sub.Session)
	in := (&uamethod.ServerTypeResendDataInput{SubscriptionID: sub.ID}).Pack()
	sent := &ua.MonitoredItemNotification{ClientHandle: 1, Value: &ua.DataValue{Value: ua.MustVariant(int32(5))}}

	// Nothing to resend: no wake-up.
	none := addItem(s, sub, &MonitoredItem{Mode: ua.MonitoringModeReporting})
	_, sc := s.resendDataMethod(ctx, nil, nil, in)
	require.Equal(t, ua.StatusOK, sc)
	require.Empty(t, sub.NotifyChannel)
	require.Empty(t, none.queue)

	repeat := addItem(s, sub, &MonitoredItem{Mode: ua.MonitoringModeReporting, lastSent: sent})
	queued := addItem(s, sub, &MonitoredItem{Mode: ua.MonitoringModeReporting, lastSent: sent,
		queue: []*ua.MonitoredItemNotification{{ClientHandle: 2}}})
	sampling := addItem(s, sub, &MonitoredItem{Mode: ua.MonitoringModeSampling, lastSent: sent})
	event := addItem(s, sub, &MonitoredItem{Mode: ua.MonitoringModeReporting, isEvent: true, lastSent: sent})
	s.MonitoredItemService.Mu.Lock()
	s.MonitoredItemService.Subs[sub.ID] = append(s.MonitoredItemService.Subs[sub.ID], nil)
	s.MonitoredItemService.Mu.Unlock()

	_, sc = s.resendDataMethod(ctx, nil, nil, in)
	require.Equal(t, ua.StatusOK, sc)
	require.Len(t, sub.NotifyChannel, 1, "the subscription is woken")
	require.Len(t, repeat.queue, 1)
	require.Equal(t, sent.Value.Value, repeat.queue[0].Value.Value)
	require.NotSame(t, sent, repeat.queue[0], "a copy")
	require.NotSame(t, sent.Value, repeat.queue[0].Value)
	require.Len(t, queued.queue, 1, "the queued value goes instead")
	require.Equal(t, uint32(2), queued.queue[0].ClientHandle)
	require.Empty(t, sampling.queue)
	require.Empty(t, event.queue)
	require.Empty(t, none.queue)

	// A wake-up already pending: the call does not block.
	for len(sub.NotifyChannel) < cap(sub.NotifyChannel) {
		sub.NotifyChannel <- &ua.MonitoredItemNotification{}
	}
	_, sc = s.resendDataMethod(ctx, nil, nil, in)
	require.Equal(t, ua.StatusOK, sc)

	// A notification without a value is copied as it is.
	require.Nil(t, copyNotification(&ua.MonitoredItemNotification{ClientHandle: 3}).Value)
}

// TestDrainRecordsLastSent: the notification a Publish response takes is
// the one ResendData repeats.
func TestDrainRecordsLastSent(t *testing.T) {
	s := newTestServer()
	_, sub, _ := newTestSubscription(s)
	n1 := &ua.MonitoredItemNotification{ClientHandle: 1}
	n2 := &ua.MonitoredItemNotification{ClientHandle: 1}
	it := addItem(s, sub, &MonitoredItem{Mode: ua.MonitoringModeReporting, queue: []*ua.MonitoredItemNotification{n1, n2}})
	out, more := s.MonitoredItemService.DrainQueuedNotifications(sub.ID, 0)
	require.Len(t, out, 2)
	require.False(t, more)
	require.Same(t, n2, it.lastSent)
}

// TestSetSubscriptionDurableMethod: the revised lifetime, the LifetimeCount
// it sets, the refusal once the subscription has items, and the queue
// sizes and ModifySubscription of a durable subscription (Part 4 §6.8).
func TestSetSubscriptionDurableMethod(t *testing.T) {
	s := newTestServer()
	_, sub, hdr := newTestSubscription(s)
	ctx := methodCtx(sub.Session)
	call := func(hours uint32) (uint32, ua.StatusCode) {
		t.Helper()
		got, sc := s.setSubscriptionDurableMethod(ctx, nil, nil, (&uamethod.ServerTypeSetSubscriptionDurableInput{SubscriptionID: sub.ID, LifetimeInHours: hours}).Pack())
		if sc != ua.StatusOK {
			return 0, sc
		}
		var out uamethod.ServerTypeSetSubscriptionDurableOutput
		require.NoError(t, out.Unpack(got))
		return out.RevisedLifetimeInHours, sc
	}
	// The publishing interval of newTestSubscription is 100 ms.
	h, sc := call(2)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, uint32(2), h)
	_, _, lifetime := sub.timing()
	require.Equal(t, 72_000, lifetime, "2 h of 100 ms intervals")
	require.True(t, sub.durable.Load())

	h, _ = call(0)
	require.Equal(t, defaultDurableLifetimeInHours, h, "0 is the highest lifetime")
	h, _ = call(1000)
	require.Equal(t, defaultDurableLifetimeInHours, h, "revised to the highest")

	// ModifySubscription keeps the durable lifetime limit.
	resp, err := s.SubscriptionService.ModifySubscription(context.Background(), nil, &ua.ModifySubscriptionRequest{
		RequestHeader: hdr, SubscriptionID: sub.ID, RequestedPublishingInterval: 1000,
		RequestedLifetimeCount: 50_000, RequestedMaxKeepAliveCount: 10,
	}, 1)
	require.NoError(t, err)
	mr := resp.(*ua.ModifySubscriptionResponse)
	require.Equal(t, uint32(50_000), mr.RevisedLifetimeCount, "above the 100000 of other subscriptions is allowed, below 24 h")
	resp, err = s.SubscriptionService.ModifySubscription(context.Background(), nil, &ua.ModifySubscriptionRequest{
		RequestHeader: hdr, SubscriptionID: sub.ID, RequestedPublishingInterval: 1000,
		RequestedLifetimeCount: math.MaxUint32, RequestedMaxKeepAliveCount: 10,
	}, 1)
	require.NoError(t, err)
	require.Equal(t, uint32(86_400), resp.(*ua.ModifySubscriptionResponse).RevisedLifetimeCount, "24 h of 1 s")
	require.True(t, sub.durable.Load(), "ModifySubscription does not change the durable mode")

	// The queues of its items.
	cfg := s.cfg
	require.Equal(t, uint32(5000), cfg.reviseItemQueueSize(sub, 5000, false))
	require.Equal(t, uint32(5000), cfg.reviseItemQueueSize(sub, 5000, true))
	require.Equal(t, defaultDurableQueueSize, cfg.reviseItemQueueSize(sub, math.MaxUint32, false))
	require.Equal(t, uint32(1), cfg.reviseItemQueueSize(sub, 0, false))
	require.Equal(t, defaultEventQueueSize, cfg.reviseItemQueueSize(sub, 0, true))
	plain := NewSubscription()
	require.Equal(t, uint32(maxMonitoredItemQueueSize), cfg.reviseItemQueueSize(plain, 5000, false))
	require.Equal(t, maxEventQueueSize, cfg.reviseItemQueueSize(plain, 50_000, true))
	require.Equal(t, uint32(maxMonitoredItemQueueSize), cfg.reviseItemQueueSize(nil, 5000, false))

	// With items it is too late.
	addItem(s, sub, &MonitoredItem{})
	_, sc = call(1)
	require.Equal(t, ua.StatusBadInvalidState, sc)
}

// TestDurableLifetimeArithmetic: the counts and hours at their bounds.
func TestDurableLifetimeArithmetic(t *testing.T) {
	require.Equal(t, uint32(36_000), lifetimeCountFor(1, 100, 10))
	require.Equal(t, uint32(30), lifetimeCountFor(1, msPerHour, 10), "three keep-alive counts at least")
	require.Equal(t, minLifetimeCount, lifetimeCountFor(0, 100, 0))
	require.Equal(t, uint32(maxDurableLifetimeCount), lifetimeCountFor(math.MaxUint32, 10, 1), "an int on every platform")
	require.Equal(t, uint32(10), lifetimeCountFor(1, msPerHour/10, 1))
	require.Equal(t, uint32(1), lifetimeInHours(36_000, 100))
	require.Equal(t, uint32(30), lifetimeInHours(30, msPerHour))
	require.Equal(t, uint32(math.MaxUint32), lifetimeInHours(math.MaxUint32, 2*msPerHour))
	// A count rounded up from exactly 24 h is 24 h.
	require.Equal(t, uint32(24), lifetimeInHours(lifetimeCountFor(24, 33.3, 1), 33.3))

	d := DurableSubscriptions{MaxLifetimeInHours: 1, MaxQueueSize: 50}
	require.Equal(t, uint32(1), d.maxLifetimeInHours())
	require.Equal(t, uint32(50), d.maxQueueSize())
	require.Equal(t, uint32(36_000), d.reviseDurableLifetime(math.MaxUint32, 100, 1))
	require.Equal(t, uint32(30), d.reviseDurableLifetime(0, 100, 10))
	require.Equal(t, uint32(50), d.reviseDurableQueueSize(51, false))

	cfg := &serverConfig{}
	require.NoError(t, WithDurableSubscriptions(d)(cfg))
	require.Equal(t, d, cfg.durable)
}

// TestRequestServerStateChangeMethod: the authorization, the handler and
// the states (Part 5 §9.4).
func TestRequestServerStateChangeMethod(t *testing.T) {
	var got []ServerStateChange
	accept := ua.StatusOK
	s, err := newServerNoNS(WithServerStateChange(func(ctx context.Context, c ServerStateChange) ua.StatusCode {
		caller, ok := MethodCallerFromContext(ctx)
		require.True(t, ok)
		require.NotNil(t, caller.SessionID)
		got = append(got, c)
		return accept
	}))
	require.NoError(t, err)
	sess := s.sb.NewSession()
	admin := methodCtx(sess, ua.RoleSecurityAdmin.NodeID())
	in := func(c uamethod.ServerTypeRequestServerStateChangeInput) []*ua.Variant { return c.Pack() }
	reason := ua.NewLocalizedText("update")

	_, sc := s.requestServerStateChangeMethod(admin, nil, nil, nil)
	require.Equal(t, ua.StatusBadArgumentsMissing, sc)
	for name, ctx := range map[string]context.Context{
		"no caller":  context.Background(),
		"no session": methodCtx(nil, ua.RoleSecurityAdmin.NodeID()),
		"no role":    methodCtx(sess, ua.RoleAuthenticatedUser.NodeID(), nil, ua.NewNumericNodeID(1, uint32(ua.RoleSecurityAdmin))),
	} {
		_, sc = s.requestServerStateChangeMethod(ctx, nil, nil, in(uamethod.ServerTypeRequestServerStateChangeInput{}))
		require.Equal(t, ua.StatusBadUserAccessDenied, sc, name)
	}
	_, sc = s.requestServerStateChangeMethod(admin, nil, nil, in(uamethod.ServerTypeRequestServerStateChangeInput{State: 8}))
	require.Equal(t, ua.StatusBadInvalidState, sc, "no ServerState")
	_, sc = s.requestServerStateChangeMethod(admin, nil, nil, in(uamethod.ServerTypeRequestServerStateChangeInput{State: -1}))
	require.Equal(t, ua.StatusBadInvalidState, sc)
	require.Empty(t, got)

	_, sc = s.requestServerStateChangeMethod(methodCtx(sess, ua.RoleConfigureAdmin.NodeID()), nil, nil, in(uamethod.ServerTypeRequestServerStateChangeInput{
		State: int32(ua.ServerStateShutdown), SecondsTillShutdown: 30, Reason: reason,
	}))
	require.Equal(t, ua.StatusOK, sc)
	require.Len(t, got, 1)
	require.Equal(t, ServerStateChange{State: ua.ServerStateShutdown, SecondsTillShutdown: 30, Reason: reason}, got[0])
	st := s.Status()
	require.Equal(t, ua.ServerStateShutdown, st.State)
	require.InDelta(t, 30, st.SecondsTillShutdown, 1)
	require.Equal(t, reason, st.ShutdownReason)

	// Refused by the application: nothing changes.
	accept = ua.StatusBadInvalidState
	_, sc = s.requestServerStateChangeMethod(admin, nil, nil, in(uamethod.ServerTypeRequestServerStateChangeInput{State: int32(ua.ServerStateRunning)}))
	require.Equal(t, ua.StatusBadInvalidState, sc)
	require.Equal(t, ua.ServerStateShutdown, s.Status().State)

	// Without a handler nothing is accepted.
	plain := newTestServer()
	_, sc = plain.requestServerStateChangeMethod(admin, nil, nil, in(uamethod.ServerTypeRequestServerStateChangeInput{}))
	require.Equal(t, ua.StatusBadInvalidState, sc)
}

// TestSetServerState: the ServerStatus and EstimatedReturnTime of each
// kind of change (Part 5 §9.4, §12.10).
func TestSetServerState(t *testing.T) {
	s := newTestServer()
	back := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	reason := ua.NewLocalizedText("x")

	s.SetServerState(ServerStateChange{State: ua.ServerStateSuspended, EstimatedReturnTime: back, SecondsTillShutdown: 9, Reason: reason})
	st := s.Status()
	require.Equal(t, ua.ServerStateSuspended, st.State)
	require.Zero(t, st.SecondsTillShutdown, "only for a shutdown")
	require.Equal(t, &ua.LocalizedText{}, st.ShutdownReason)
	require.Equal(t, back, s.EstimatedReturnTime())

	// A restart with a delay is a shutdown first.
	s.SetServerState(ServerStateChange{State: ua.ServerStateRunning, Restart: true, SecondsTillShutdown: 100, Reason: reason, EstimatedReturnTime: back})
	st = s.Status()
	require.Equal(t, ua.ServerStateShutdown, st.State)
	require.InDelta(t, 100, st.SecondsTillShutdown, 1)
	require.Equal(t, reason, st.ShutdownReason)
	require.True(t, s.EstimatedReturnTime().IsZero(), "RUNNING_0 requested: null")

	// A restart at once leaves the state as it is.
	s.SetServerState(ServerStateChange{State: ua.ServerStateTest, Restart: true, EstimatedReturnTime: back})
	st = s.Status()
	require.Equal(t, ua.ServerStateShutdown, st.State)
	require.Zero(t, st.SecondsTillShutdown)
	require.Equal(t, &ua.LocalizedText{}, st.ShutdownReason, "no reason given")
	require.Equal(t, back, s.EstimatedReturnTime())

	// The countdown ends at 0 and is bounded by a UInt32.
	s.mu.Lock()
	s.shutdownAt = time.Now().Add(-time.Second)
	s.mu.Unlock()
	require.Zero(t, s.Status().SecondsTillShutdown)
	s.mu.Lock()
	s.shutdownAt = time.Now().Add(time.Duration(math.MaxUint32+10) * time.Second)
	s.mu.Unlock()
	require.Equal(t, uint32(math.MaxUint32), s.Status().SecondsTillShutdown)

	s.SetServerState(ServerStateChange{State: ua.ServerStateRunning})
	st = s.Status()
	require.Equal(t, ua.ServerStateRunning, st.State)
	require.Zero(t, st.SecondsTillShutdown)
	require.True(t, s.EstimatedReturnTime().IsZero())
}

// TestEstimatedReturnTimeNode: the Property is the null DateTime until a
// change sets it; SecondsTillShutdown and ShutdownReason
// are of their DataTypes (Part 5 §12.10).
func TestEstimatedReturnTimeNode(t *testing.T) {
	s, err := New()
	require.NoError(t, err)
	cleanup.Register(t, func() { _ = s.Close() })
	read := func(nid uint32) *ua.Variant {
		t.Helper()
		dv := s.Node(ua.NewNumericNodeID(0, nid)).Value()
		require.NotNil(t, dv)
		return dv.Value
	}
	require.Equal(t, time.Time{}, read(id.ServerEstimatedReturnTime).Value(), "the null DateTime")
	require.Equal(t, uint32(0), read(id.ServerServerStatusSecondsTillShutdown).Value())
	require.Equal(t, &ua.LocalizedText{}, read(id.ServerServerStatusShutdownReason).Value())

	back := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	s.SetServerState(ServerStateChange{State: ua.ServerStateShutdown, EstimatedReturnTime: back, SecondsTillShutdown: 50, Reason: ua.NewLocalizedText("r")})
	require.Equal(t, back, read(id.ServerEstimatedReturnTime).Value())
	require.InDelta(t, 50, read(id.ServerServerStatusSecondsTillShutdown).Value(), 1)
	require.Equal(t, "r", read(id.ServerServerStatusShutdownReason).Value().(*ua.LocalizedText).Text)

	s.SetServerState(ServerStateChange{State: ua.ServerStateRunning})
	require.Equal(t, time.Time{}, read(id.ServerEstimatedReturnTime).Value())

	// A server without the node.
	plain := newTestServer()
	require.Equal(t, ua.StatusGood, plain.ns0().DeleteNode(ua.NewNumericNodeID(0, id.ServerEstimatedReturnTime)))
	plain.bindEstimatedReturnTime()
}
