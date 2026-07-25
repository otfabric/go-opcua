// SPDX-License-Identifier: MIT

package opcua_test

import (
	"context"
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func waitDataChange(t *testing.T, notify <-chan *opcua.PublishNotificationData, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case msg := <-notify:
			if msg == nil || msg.Error != nil {
				continue
			}
			if _, ok := msg.Value.(*ua.DataChangeNotification); ok {
				return
			}
		case <-deadline:
			t.Fatalf("timed out waiting for data-change notification after %s", timeout)
		}
	}
}

func TestClient_recreateSubscription_Live(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	ns := testutil.AddTestNodes(t, srv)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	notify := make(chan *opcua.PublishNotificationData, 16)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{
		Interval: 100 * time.Millisecond,
	}, notify)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx2, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = sub.Cancel(ctx2)
	})

	nodeID := ua.NewStringNodeID(ns.ID(), "IntVar")
	_, err = sub.Monitor(ctx, ua.TimestampsToReturnBoth,
		opcua.NewMonitoredItemCreateRequestWithDefaults(nodeID, ua.AttributeIDValue, 1))
	require.NoError(t, err)

	// Ensure publishing is healthy before recreate (also absorbs the initial sample).
	srv.ChangeNotification(nodeID)
	waitDataChange(t, notify, 5*time.Second)

	oldID := sub.SubscriptionID
	require.NotZero(t, oldID)
	require.NoError(t, c.TestingRecreateSubscription(ctx, oldID))
	require.NotZero(t, sub.SubscriptionID)

	// Drain anything already queued, then force a post-recreate change.
	for {
		select {
		case <-notify:
		default:
			goto written
		}
	}
written:
	_, err = c.Write(ctx, &ua.WriteRequest{
		NodesToWrite: []*ua.WriteValue{{
			NodeID:      nodeID,
			AttributeID: ua.AttributeIDValue,
			Value: &ua.DataValue{
				EncodingMask: ua.DataValueValue,
				Value:        ua.MustVariant(int32(99)),
			},
		}},
	})
	require.NoError(t, err)
	srv.ChangeNotification(nodeID)
	waitDataChange(t, notify, 5*time.Second)
}

func TestClient_recreateSubscription_InvalidID(t *testing.T) {
	c, err := opcua.NewClient("opc.tcp://127.0.0.1:1")
	require.NoError(t, err)
	err = c.TestingRecreateSubscription(context.Background(), 999)
	require.ErrorIs(t, err, ua.StatusBadSubscriptionIDInvalid)
}

func TestClient_recreateSubscription_MonitoredItemFails(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	ns := testutil.AddTestNodes(t, srv)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	notify := make(chan *opcua.PublishNotificationData, 4)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{
		Interval: 200 * time.Millisecond,
	}, notify)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx2, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = sub.Cancel(ctx2)
	})

	nodeID := ua.NewStringNodeID(ns.ID(), "IntVar")
	_, err = sub.Monitor(ctx, ua.TimestampsToReturnBoth,
		opcua.NewMonitoredItemCreateRequestWithDefaults(nodeID, ua.AttributeIDValue, 1))
	require.NoError(t, err)

	// Delete the node so recreateCreate's CreateMonitoredItems path fails.
	require.Equal(t, ua.StatusOK, ns.DeleteNode(nodeID))

	err = c.TestingRecreateSubscription(ctx, sub.SubscriptionID)
	require.Error(t, err)
}
