// SPDX-License-Identifier: MIT

package opcua_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uamethod"
)

// TestClientServerMethods: the client calls of the Methods of the Server
// Object (OPC 10000-5 §9) against the server.
func TestClientServerMethods(t *testing.T) {
	t.Parallel()
	srv, url := testutil.NewTestServer(t,
		server.WithServerStateChange(func(context.Context, server.ServerStateChange) ua.StatusCode { return ua.StatusOK }))
	ns := server.NewNodeNameSpace(srv, "urn:test:server-methods")
	v := ns.AddNewVariableNode("v", int32(1))

	c := testutil.NewTestClient(t, url)
	ctx := context.Background()
	notify := make(chan *opcua.PublishNotificationData, 16)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 20 * time.Millisecond}, notify)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	hours, err := sub.SetDurable(ctx, 2)
	require.NoError(t, err)
	require.Equal(t, uint32(2), hours)

	res, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, opcua.NewMonitoredItemCreateRequestWithDefaults(v.ID(), ua.AttributeIDValue, 42))
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, res.Results[0].StatusCode)
	item := res.Results[0].MonitoredItemID

	// A durable subscription with an item cannot be made durable again.
	_, err = sub.SetDurable(ctx, 1)
	require.ErrorIs(t, err, ua.StatusBadInvalidState)

	items, err := sub.GetMonitoredItems(ctx)
	require.NoError(t, err)
	require.Equal(t, []uint32{item}, items.ServerHandles)
	require.Equal(t, []uint32{42}, items.ClientHandles)

	value := func() int32 {
		t.Helper()
		select {
		case n := <-notify:
			require.NoError(t, n.Error)
			dcn, ok := n.Value.(*ua.DataChangeNotification)
			require.True(t, ok, "%T", n.Value)
			return dcn.MonitoredItems[0].Value.Value.Value().(int32)
		case <-time.After(10 * time.Second):
			t.Fatal("no data change")
			return 0
		}
	}
	require.Equal(t, int32(1), value(), "the initial value")
	require.NoError(t, sub.ResendData(ctx))
	require.Equal(t, int32(1), value(), "the last value sent, again")

	// Another session owns the subscription: access denied.
	other := testutil.NewTestClient(t, url)
	_, err = other.GetMonitoredItems(ctx, sub.SubscriptionID)
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
	require.ErrorIs(t, other.ResendData(ctx, sub.SubscriptionID), ua.StatusBadUserAccessDenied)
	_, err = other.SetSubscriptionDurable(ctx, sub.SubscriptionID, 0)
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
	_, err = c.GetMonitoredItems(ctx, sub.SubscriptionID+1000)
	require.ErrorIs(t, err, ua.StatusBadSubscriptionIDInvalid)

	// RequestServerStateChange is restricted to signed channels by the
	// AccessRestrictions of the NodeSet (SigningRequired); the calls that
	// pass are in conformance/security.
	err = c.RequestServerStateChange(ctx, &uamethod.ServerTypeRequestServerStateChangeInput{State: int32(ua.ServerStateShutdown)})
	require.ErrorIs(t, err, ua.StatusBadSecurityModeInsufficient)
	require.Equal(t, ua.ServerStateRunning, srv.Status().State)

	// A closed client fails the calls.
	require.NoError(t, c.Close(ctx))
	_, err = c.GetMonitoredItems(ctx, 1)
	require.Error(t, err)
	_, err = sub.GetMonitoredItems(ctx)
	require.Error(t, err)
	_, err = c.SetSubscriptionDurable(ctx, 1, 1)
	require.Error(t, err)
}
