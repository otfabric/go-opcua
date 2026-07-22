// SPDX-License-Identifier: MIT

package opcua_test

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/stretchr/testify/require"
)

// Stress / race-oriented lifecycle tests for subscriptions and recovery.
// Recommended local command:
//
//	go test -race -count=50 -run 'Recovery|Reconnect|Republish|Transfer|Stress_' ./...

func stressDialer() *uacp.Dialer {
	return &uacp.Dialer{
		Dialer: &net.Dialer{Timeout: 30 * time.Second},
		ClientACK: &uacp.Acknowledge{
			ReceiveBufSize: uacp.DefaultReceiveBufSize,
			SendBufSize:    uacp.DefaultSendBufSize,
		},
	}
}

// TestStress_ConcurrentCloseWithActiveSubscription closes the client while a
// subscription is still publishing. Must not hang or panic under -race.
func TestStress_ConcurrentCloseWithActiveSubscription(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	ns := testutil.AddTestNodes(t, srv)
	nsID := ns.ID()

	ctx := context.Background()
	c, err := opcua.NewClient(url,
		opcua.SecurityMode(ua.MessageSecurityModeNone),
		opcua.DialTimeout(30*time.Second),
		opcua.RequestTimeout(30*time.Second),
		opcua.Dialer(stressDialer()),
	)
	require.NoError(t, err)
	require.NoError(t, c.Connect(ctx))

	notifyCh := make(chan *opcua.PublishNotificationData, 64)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{
		Interval: 100 * time.Millisecond,
	}, notifyCh)
	require.NoError(t, err)

	_, err = sub.Monitor(ctx, ua.TimestampsToReturnBoth,
		opcua.NewMonitoredItemCreateRequestWithDefaults(
			ua.NewStringNodeID(nsID, "IntVar"), ua.AttributeIDValue, 1))
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		deadline := time.After(2 * time.Second)
		for {
			select {
			case <-deadline:
				return
			case <-notifyCh:
			}
		}
	}()
	go func() {
		defer wg.Done()
		time.Sleep(200 * time.Millisecond)
		_ = c.Close(ctx)
	}()
	wg.Wait()
	_ = sub.Cancel(context.Background())
}

// TestStress_CancelSubscriptionDuringPublish cancels a subscription while the
// notify channel is still being drained.
func TestStress_CancelSubscriptionDuringPublish(t *testing.T) {
	_, url := testutil.NewTestServer(t)
	ctx := context.Background()
	c := testutil.NewTestClient(t, url)

	notifyCh := make(chan *opcua.PublishNotificationData, 8)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{
		Interval: 50 * time.Millisecond,
	}, notifyCh)
	require.NoError(t, err)

	var cancelled atomic.Bool
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = sub.Cancel(ctx)
		cancelled.Store(true)
	}()

	deadline := time.After(2 * time.Second)
	for !cancelled.Load() {
		select {
		case <-deadline:
			t.Fatal("cancel did not complete")
		case <-notifyCh:
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// TestStress_EventAndDataChangeTogether keeps a data-change item and an event
// monitored item on one subscription. Asserts CreateMonitoredItems + a
// subsequent data-change notification without hang/panic.
func TestStress_EventAndDataChangeTogether(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	ns := testutil.AddTestNodes(t, srv)
	nsID := ns.ID()

	ctx := context.Background()
	c := testutil.NewTestClient(t, url)

	notifyCh := make(chan *opcua.PublishNotificationData, 64)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{
		Interval: 100 * time.Millisecond,
	}, notifyCh)
	require.NoError(t, err)
	defer func() { _ = sub.Cancel(ctx) }()

	dcResp, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth,
		opcua.NewMonitoredItemCreateRequestWithDefaults(
			ua.NewStringNodeID(nsID, "IntVar"), ua.AttributeIDValue, 1))
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, dcResp.Results[0].StatusCode)

	ef := ua.NewEventFilter().
		Select("EventId", "Severity", "Message").
		Where(ua.OfType(ua.NewNumericNodeID(0, id.BaseEventType))).
		Build()
	evReq := &ua.MonitoredItemCreateRequest{
		ItemToMonitor: &ua.ReadValueID{
			NodeID:      ua.NewNumericNodeID(0, id.Server),
			AttributeID: ua.AttributeIDEventNotifier,
		},
		MonitoringMode: ua.MonitoringModeReporting,
		RequestedParameters: &ua.MonitoringParameters{
			ClientHandle:     2,
			SamplingInterval: 0,
			Filter:           ua.NewExtensionObject(ef),
			QueueSize:        10,
			DiscardOldest:    true,
		},
	}
	evResp, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, evReq)
	require.NoError(t, err)
	require.NotNil(t, evResp)

	_, err = c.Write(ctx, &ua.WriteRequest{
		NodesToWrite: []*ua.WriteValue{{
			NodeID:      ua.NewStringNodeID(nsID, "IntVar"),
			AttributeID: ua.AttributeIDValue,
			Value: &ua.DataValue{
				EncodingMask: ua.DataValueValue,
				Value:        ua.MustVariant(int32(99)),
			},
		}},
	})
	require.NoError(t, err)

	deadline := time.After(3 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("timeout waiting for data-change with dual monitors")
		case msg := <-notifyCh:
			if msg == nil || msg.Error != nil {
				continue
			}
			if _, ok := msg.Value.(*ua.DataChangeNotification); ok {
				return
			}
		}
	}
}

// TestStress_CloseWhileReconnectArmed starts a client with AutoReconnect and
// closes it while a subscription is active. Ensures Close does not deadlock
// against the reconnect/publish loops under -race.
func TestStress_CloseWhileReconnectArmed(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	ns := testutil.AddTestNodes(t, srv)
	nsID := ns.ID()

	ctx := context.Background()
	c, err := opcua.NewClient(url,
		opcua.SecurityMode(ua.MessageSecurityModeNone),
		opcua.AutoReconnect(true),
		opcua.ReconnectInterval(100*time.Millisecond),
		opcua.DialTimeout(30*time.Second),
		opcua.RequestTimeout(30*time.Second),
		opcua.Dialer(stressDialer()),
	)
	require.NoError(t, err)
	require.NoError(t, c.Connect(ctx))

	notifyCh := make(chan *opcua.PublishNotificationData, 16)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{
		Interval: 100 * time.Millisecond,
	}, notifyCh)
	require.NoError(t, err)
	_, err = sub.Monitor(ctx, ua.TimestampsToReturnBoth,
		opcua.NewMonitoredItemCreateRequestWithDefaults(
			ua.NewStringNodeID(nsID, "IntVar"), ua.AttributeIDValue, 1))
	require.NoError(t, err)

	// Drop the server to provoke reconnect attempts, then Close the client.
	_ = srv.Close()
	time.Sleep(150 * time.Millisecond)

	closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = c.Close(closeCtx)
	require.NoError(t, err)
	_ = sub
}

// TestStress_ConcurrentSubscribeCancel races Subscribe/Cancel across clients.
func TestStress_ConcurrentSubscribeCancel(t *testing.T) {
	_, url := testutil.NewTestServer(t)
	const n = 8
	var wg sync.WaitGroup
	wg.Add(n)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			ctx := context.Background()
			c, err := opcua.NewClient(url,
				opcua.SecurityMode(ua.MessageSecurityModeNone),
				opcua.DialTimeout(30*time.Second),
				opcua.RequestTimeout(30*time.Second),
				opcua.Dialer(stressDialer()),
			)
			if err != nil {
				errs <- err
				return
			}
			if err := c.Connect(ctx); err != nil {
				errs <- err
				return
			}
			defer func() { _ = c.Close(ctx) }()
			ch := make(chan *opcua.PublishNotificationData, 4)
			sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{
				Interval: 100 * time.Millisecond,
			}, ch)
			if err != nil {
				errs <- err
				return
			}
			time.Sleep(50 * time.Millisecond)
			_ = sub.Cancel(ctx)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent subscribe/cancel: %v", err)
	}
}
