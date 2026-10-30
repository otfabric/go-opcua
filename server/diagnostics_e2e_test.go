// SPDX-License-Identifier: MIT

package server_test

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testhook"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func diagServer(t *testing.T, opts ...server.Option) (*server.Server, string) {
	t.Helper()
	srv, err := server.New(append([]server.Option{
		server.EndPoint("localhost", 0),
		server.InsecureNoSecurity(),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
	}, opts...)...)
	require.NoError(t, err)
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })
	return srv, srv.Endpoints()[0].EndpointURL
}

// TestDiagnostics_SessionObjectVariables reads every variable of the
// diagnostics object of a session: the structures and their components.
func TestDiagnostics_SessionObjectVariables(t *testing.T) {
	t.Parallel()
	srv, url := diagServer(t)
	c := testutil.NewTestClient(t, url)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sid := c.Session().SessionID()
	require.Equal(t, srv.Namespaces()[len(srv.Namespaces())-1].Name(), server.DiagnosticsNamespaceURI)
	obj := c.Node(sid)
	name, err := obj.BrowseName(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, name.Name)
	def, err := obj.TypeDefinition(ctx)
	require.NoError(t, err)
	require.Equal(t, uint32(id.SessionDiagnosticsObjectType), def.IntID())

	children, err := obj.Children(ctx, id.HasComponent, ua.NodeClassVariable)
	require.NoError(t, err)
	require.Len(t, children, 3) // SessionDiagnostics, SessionSecurityDiagnostics, SubscriptionDiagnosticsArray
	props, err := obj.Children(ctx, id.HasProperty, ua.NodeClassVariable)
	require.NoError(t, err)
	require.Len(t, props, 1) // CurrentRoleIds
	roles, err := props[0].Value(ctx)
	require.NoError(t, err)
	require.IsType(t, []*ua.NodeID{}, roles.Value())
	var leaves int
	for _, ch := range children {
		dv, err := ch.Value(ctx)
		require.NoError(t, err, ch.ID.String())
		require.NotNil(t, dv, ch.ID.String())
		comps, err := ch.Children(ctx, id.HasComponent, ua.NodeClassVariable)
		require.NoError(t, err)
		for _, comp := range comps {
			v, err := c.ReadValue(ctx, comp.ID)
			require.NoError(t, err)
			require.Equal(t, ua.StatusOK, v.Status, comp.ID.String())
			leaves++
		}
	}
	require.GreaterOrEqual(t, leaves, 43+9, "the components of SessionDiagnostics and SessionSecurityDiagnostics")

	// The summary components.
	sum, err := c.Node(ua.NewNumericNodeID(0, id.ServerServerDiagnosticsServerDiagnosticsSummary)).Children(ctx, id.HasComponent, ua.NodeClassVariable)
	require.NoError(t, err)
	require.Len(t, sum, 12)
	for _, comp := range sum {
		v, err := c.ReadValue(ctx, comp.ID)
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, v.Status, comp.ID.String())
		require.IsType(t, uint32(0), v.Value.Value())
	}

	// The diagnostics nodes are read-only, except EnabledFlag.
	st, err := c.WriteValue(ctx, ua.NewNumericNodeID(0, id.ServerServerDiagnosticsServerDiagnosticsSummaryCurrentSessionCount), &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(uint32(9))})
	require.NoError(t, err)
	require.True(t, st != ua.StatusOK)
	// EnabledFlag is for administrators only.
	require.ErrorIs(t, c.SetServerDiagnosticsEnabled(ctx, true), ua.StatusBadUserAccessDenied)
}

// TestDiagnostics_SubscriptionCounters drives the subscription services and
// checks the counters of SubscriptionDiagnosticsDataType.
func TestDiagnostics_SubscriptionCounters(t *testing.T) {
	t.Parallel()
	srv, url := diagServer(t)
	f := testutil.AddFixture(t, srv)
	c := testutil.NewTestClient(t, url)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ch := make(chan *opcua.PublishNotificationData, 64)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 20 * time.Millisecond}, ch)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(context.Background()) })
	res, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, opcua.NewMonitoredItemCreateRequestWithDefaults(f.Int32, ua.AttributeIDValue, 1))
	require.NoError(t, err)
	itemID := res.Results[0].MonitoredItemID
	select {
	case <-ch:
	case <-ctx.Done():
		t.Fatal("no notification")
	}

	_, err = sub.ModifySubscription(ctx, opcua.SubscriptionParameters{Interval: 25 * time.Millisecond})
	require.NoError(t, err)
	_, err = c.SetPublishingMode(ctx, false, sub.SubscriptionID)
	require.NoError(t, err)
	_, err = c.SetPublishingMode(ctx, true, sub.SubscriptionID)
	require.NoError(t, err)
	_, _ = c.Republish(ctx, sub.SubscriptionID, 1)
	_, err = sub.SetMonitoringMode(ctx, ua.MonitoringModeDisabled, itemID)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		subs, err := c.SubscriptionDiagnostics(ctx)
		if err != nil || len(subs) != 1 {
			return false
		}
		d := subs[0]
		return d.ModifyCount == 1 && d.EnableCount == 1 && d.DisableCount == 1 && d.RepublishRequestCount == 1 &&
			d.DisabledMonitoredItemCount == 1 && d.MonitoredItemCount == 1 && d.PublishRequestCount > 0 &&
			d.NotificationsCount > 0 && d.NextSequenceNumber > 1 && d.PublishingInterval == 25
	}, 10*time.Second, 10*time.Millisecond)

	samp, err := c.SamplingIntervalDiagnostics(ctx)
	require.NoError(t, err)
	require.Len(t, samp, 1)
	require.Equal(t, uint32(1), samp[0].DisabledMonitoredItemCount)

	// The SubscriptionDiagnosticsArray of the session object.
	sessSubs, err := c.Node(ua.NewStringNodeID(c.Session().SessionID().Namespace(), c.Session().SessionID().StringID()+".SubscriptionDiagnosticsArray")).Value(ctx)
	require.NoError(t, err)
	require.Len(t, sessSubs.Value().([]*ua.ExtensionObject), 1)

	// Deleting the item and the subscription.
	_, err = sub.Unmonitor(ctx, itemID)
	require.NoError(t, err)
	samp, err = c.SamplingIntervalDiagnostics(ctx)
	require.NoError(t, err)
	require.Empty(t, samp)
	require.NoError(t, sub.Cancel(ctx))
	subs, err := c.SubscriptionDiagnostics(ctx)
	require.NoError(t, err)
	require.Empty(t, subs)
}

// TestDiagnostics_Transfer transfers a subscription between the sessions
// of two clients and checks the transfer counters.
func TestDiagnostics_Transfer(t *testing.T) {
	t.Parallel()
	_, url := diagServer(t)
	a := testutil.NewTestClient(t, url)
	b := testutil.NewTestClient(t, url)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sub, err := a.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: time.Second}, make(chan *opcua.PublishNotificationData, 8))
	require.NoError(t, err)
	resp, err := b.TransferSubscriptions(ctx, []uint32{sub.SubscriptionID, 4242}, false)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, resp.Results[0].StatusCode)

	subs, err := b.SubscriptionDiagnostics(ctx)
	require.NoError(t, err)
	require.Len(t, subs, 1)
	require.Equal(t, uint32(1), subs[0].TransferRequestCount)
	// The test clients share their ApplicationURI.
	require.Equal(t, uint32(1), subs[0].TransferredToSameClientCount)
	require.True(t, subs[0].SessionID.Equal(b.Session().SessionID()))
	sd, err := b.SessionDiagnosticsOf(ctx, nil)
	require.NoError(t, err)
	require.Equal(t, uint32(1), sd.CurrentSubscriptionsCount)
	require.Equal(t, uint32(1), sd.TransferSubscriptionsCount.TotalCount)
}

// TestDiagnostics_SessionTimeout lets a session time out and checks
// SessionTimeoutCount and the removal of its object.
func TestDiagnostics_SessionTimeout(t *testing.T) {
	t.Parallel()
	srv, url := diagServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	short, err := opcua.NewClient(url, opcua.InsecureNoSecurity(), opcua.SessionTimeout(time.Second), opcua.AutoReconnect(false))
	require.NoError(t, err)
	require.NoError(t, short.Connect(ctx))
	t.Cleanup(func() { _ = short.Close(context.Background()) })
	sid := short.Session().SessionID()
	require.Equal(t, 1, testhook.ServerResourcesOf(srv).DiagnosticsSessionObjects)
	// Drop the connection without closing the session; the session times
	// out.
	_ = short.SecureChannel().Close()

	require.Eventually(t, func() bool {
		return srv.ServerDiagnosticsSummary().SessionTimeoutCount == 1
	}, 20*time.Second, 20*time.Millisecond)
	require.Eventually(t, func() bool { return testhook.ServerResourcesOf(srv).DiagnosticsSessionObjects == 0 }, 5*time.Second, 10*time.Millisecond)
	require.Nil(t, srv.Node(sid))
	sum := srv.ServerDiagnosticsSummary()
	require.Zero(t, sum.CurrentSessionCount)
	require.Equal(t, uint32(1), sum.CumulatedSessionCount)
}

// TestDiagnostics_ServerAPI verifies the server side API.
func TestDiagnostics_ServerAPI(t *testing.T) {
	t.Parallel()
	srv, url := diagServer(t, server.WithServerDiagnostics(false))
	require.False(t, srv.ServerDiagnosticsEnabled())
	c := testutil.NewTestClient(t, url)
	require.Zero(t, testhook.ServerResourcesOf(srv).DiagnosticsSessionObjects)
	srv.SetServerDiagnosticsEnabled(true)
	require.True(t, srv.ServerDiagnosticsEnabled())
	require.Equal(t, 1, testhook.ServerResourcesOf(srv).DiagnosticsSessionObjects)
	sum := srv.ServerDiagnosticsSummary()
	require.Equal(t, uint32(1), sum.CurrentSessionCount)
	require.Equal(t, uint32(1), sum.CumulatedSessionCount)
	// Enabling again resets, keeping the current counts.
	srv.SetServerDiagnosticsEnabled(true)
	require.Equal(t, uint32(1), srv.ServerDiagnosticsSummary().CumulatedSessionCount)
	require.NoError(t, c.Close(context.Background()))
	require.Eventually(t, func() bool { return testhook.ServerResourcesOf(srv).DiagnosticsSessionObjects == 0 }, 5*time.Second, 10*time.Millisecond)
	srv.SetServerDiagnosticsEnabled(false)
	srv.SetServerDiagnosticsEnabled(false)
	require.Equal(t, uint32(1), srv.ServerDiagnosticsSummary().CumulatedSessionCount)
}

// BenchmarkDiagnostics_Read measures a Read round trip with the server
// diagnostics on (the default) and off, and with operation diagnostics
// requested.
func BenchmarkDiagnostics_Read(b *testing.B) {
	for _, tc := range []struct {
		name string
		on   bool
		mask uint32
	}{{"enabled", true, 0}, {"disabled", false, 0}, {"returnDiagnostics", true, ua.ReturnDiagnosticsAll}} {
		b.Run(tc.name, func(b *testing.B) {
			srv, err := server.New(server.EndPoint("localhost", 0),
				server.InsecureNoSecurity(),
				server.EnableAuthMode(ua.UserTokenTypeAnonymous),
				server.WithServerDiagnostics(tc.on))
			if err != nil {
				b.Fatal(err)
			}
			if err := srv.Start(context.Background()); err != nil {
				b.Fatal(err)
			}
			defer func() { _ = srv.Close() }()
			ctx := context.Background()
			c, err := opcua.NewClient(srv.Endpoints()[0].EndpointURL, opcua.InsecureNoSecurity(), opcua.ReturnDiagnostics(tc.mask))
			if err != nil {
				b.Fatal(err)
			}
			if err := c.Connect(ctx); err != nil {
				b.Fatal(err)
			}
			defer func() { _ = c.Close(ctx) }()
			req := &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{
				{NodeID: ua.NewNumericNodeID(0, id.ServerServerStatusState), AttributeID: ua.AttributeIDValue},
				{NodeID: ua.NewNumericNodeID(0, 999999), AttributeID: ua.AttributeIDValue},
			}}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := c.Read(ctx, req); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
