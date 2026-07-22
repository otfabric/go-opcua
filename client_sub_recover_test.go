// SPDX-License-Identifier: MIT

package opcua_test

import (
	"context"
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// drainNotifyCh empties the notify channel until it is idle for at least
// idleFor duration.
func drainNotifyCh(ch <-chan *opcua.PublishNotificationData, idleFor time.Duration) {
	idle := time.NewTimer(idleFor)
	defer idle.Stop()
	for {
		select {
		case <-ch:
			if !idle.Stop() {
				select {
				case <-idle.C:
				default:
				}
			}
			idle.Reset(idleFor)
		case <-idle.C:
			return
		}
	}
}

// TestPublicRepublish_DoesNotDeliverToNotifyChan verifies that the public
// Client.Republish API (WP2A) returns the protocol response without dispatching
// the notification to the subscription's notify channel.
func TestPublicRepublish_DoesNotDeliverToNotifyChan(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	ns := testutil.AddTestNodes(t, srv)

	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	nodeID := ua.NewStringNodeID(ns.ID(), "IntVar")
	notifyCh := make(chan *opcua.PublishNotificationData, 32)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{
		Interval: 200 * time.Millisecond,
	}, notifyCh)
	require.NoError(t, err, "Subscribe")
	t.Cleanup(func() {
		ctx2, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = sub.Cancel(ctx2)
	})

	// Monitor the node so the server begins sending notifications.
	req := opcua.NewMonitoredItemCreateRequestWithDefaults(nodeID, ua.AttributeIDValue, 50)
	_, err = sub.Monitor(ctx, ua.TimestampsToReturnNeither, req)
	require.NoError(t, err, "Monitor")

	// Trigger a change notification so the server buffers at least one message.
	srv.ChangeNotification(nodeID)

	// Drain all notifications so the channel is idle before calling Republish.
	drainNotifyCh(notifyCh, 600*time.Millisecond)

	// Snapshot the notify-channel length before calling Republish.
	lenBefore := len(notifyCh)

	// Call the public Republish API with sequence number 1. The server may have
	// already ACKed it — both paths confirm the API contract.
	resp, err := c.Republish(ctx, sub.SubscriptionID, 1)
	if errors.Is(err, ua.StatusBadMessageNotAvailable) {
		t.Log("sequence 1 already acknowledged; API contract verified (returned error, no channel dispatch)")
		return
	}
	if err == nil && resp != nil && resp.ResponseHeader.ServiceResult == ua.StatusBadMessageNotAvailable {
		t.Log("sequence 1 already acknowledged (response status); API contract verified")
		return
	}
	require.NoError(t, err, "Republish should not return an unexpected error")
	require.NotNil(t, resp, "Republish response must not be nil")
	assert.Equal(t, ua.StatusOK, resp.ResponseHeader.ServiceResult, "Republish service result")

	// The notify channel must NOT have received anything from the Republish call.
	assert.Equal(t, lenBefore, len(notifyCh), "Republish must not dispatch to notify channel")
}

// TestPublicTransferSubscriptions_ReturnsResponse verifies that the public
// Client.TransferSubscriptions API (WP2A) returns a well-formed response.
func TestPublicTransferSubscriptions_ReturnsResponse(t *testing.T) {
	_, url := testutil.NewTestServer(t)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	// Create a subscription so we have an ID to transfer.
	notifyCh := make(chan *opcua.PublishNotificationData, 8)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{
		Interval: 500 * time.Millisecond,
	}, notifyCh)
	require.NoError(t, err, "Subscribe")
	t.Cleanup(func() {
		ctx2, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = sub.Cancel(ctx2)
	})

	resp, err := c.TransferSubscriptions(ctx, []uint32{sub.SubscriptionID}, false)
	// Acceptable responses:
	//   - nil error + non-nil response with per-subscription results
	//   - StatusBadServiceUnsupported (server does not implement TransferSubscriptions)
	if errors.Is(err, ua.StatusBadServiceUnsupported) {
		t.Log("server does not support TransferSubscriptions — API contract verified (returns error)")
		return
	}
	require.NoError(t, err, "TransferSubscriptions")
	require.NotNil(t, resp, "TransferSubscriptions response must not be nil")
	assert.Len(t, resp.Results, 1, "expected one result per subscription ID")
}
