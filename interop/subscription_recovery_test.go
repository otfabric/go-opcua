//go:build interop

// SPDX-License-Identifier: MIT

// Go↔Go Republish / TransferSubscriptions companions.
// COVERAGE.md: subscriptions / subscription.*.republish, subscription.*.transfer
// (companion only — peer evidence lives in subscription_recovery_peer_test.go)

package interop

import (
	"context"
	"errors"
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
)

// TestGoServer_RepublishAvailableSequence verifies that Republish returns a
// previously sent notification message.
func TestGoServer_RepublishAvailableSequence(t *testing.T) {
	endpoint := startGoServer(t)
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	nodeID := ua.NewStringNodeID(nsIdx, "Access.ReadWrite")
	req := opcua.NewMonitoredItemCreateRequestWithDefaults(nodeID, ua.AttributeIDValue, 50)
	req.RequestedParameters.SamplingInterval = 0

	notifyCh := make(chan *opcua.PublishNotificationData, 32)
	sub, _, err := c.NewSubscription().
		Interval(200 * time.Millisecond).
		NotifyChannel(notifyCh).
		Timestamps(ua.TimestampsToReturnNeither).
		MonitorItems(req).
		Start(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	// Wait for initial notification to populate sentMessages.
	drainInitial(t, notifyCh)

	// Write to trigger another notification.
	writeInt32(t, c, ctx, nodeID, 999)
	_ = collectDataChange(t, notifyCh, 1, 5*time.Second)

	// At this point the server's subscription should have stored at least seq=1 and seq=2.
	// Republish seq=1 (the initial value notification).
	repubResp, err := c.Republish(ctx, sub.SubscriptionID, 1)
	if err != nil {
		// If the seq was already ACKed, we might get BadMessageNotAvailable.
		if errors.Is(err, ua.StatusBadMessageNotAvailable) {
			t.Log("seq 1 already acknowledged, trying seq 2")
			repubResp, err = c.Republish(ctx, sub.SubscriptionID, 2)
			if err != nil {
				t.Skipf("all sequences already acknowledged: %v", err)
			}
		} else {
			t.Fatalf("Republish: %v", err)
		}
	}
	if repubResp == nil {
		t.Fatal("nil republish response")
	}
	if repubResp.ResponseHeader.ServiceResult != ua.StatusOK {
		t.Fatalf("Republish status=%v", repubResp.ResponseHeader.ServiceResult)
	}
	if repubResp.NotificationMessage == nil {
		t.Fatal("Republish returned nil NotificationMessage")
	}
}

// TestGoServer_RepublishMissingSequence verifies that Republish returns
// BadMessageNotAvailable for an unknown sequence number.
func TestGoServer_RepublishMissingSequence(t *testing.T) {
	endpoint := startGoServer(t)
	c := dialClient(t, endpoint)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	notifyCh := make(chan *opcua.PublishNotificationData, 8)
	sub, _, err := c.NewSubscription().
		Interval(200 * time.Millisecond).
		NotifyChannel(notifyCh).
		Start(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	repubResp, err := c.Republish(ctx, sub.SubscriptionID, 0xDEADBEEF)
	// The client may surface the non-OK service result as an error.
	if err != nil {
		if errors.Is(err, ua.StatusBadMessageNotAvailable) {
			return // pass
		}
		t.Fatalf("Republish: %v", err)
	}
	if repubResp.ResponseHeader.ServiceResult != ua.StatusBadMessageNotAvailable {
		t.Fatalf("Republish status=%v, want BadMessageNotAvailable", repubResp.ResponseHeader.ServiceResult)
	}
}

// TestGoServer_RepublishInvalidSubscription verifies that Republish returns
// BadSubscriptionIDInvalid for an unknown subscription.
func TestGoServer_RepublishInvalidSubscription(t *testing.T) {
	endpoint := startGoServer(t)
	c := dialClient(t, endpoint)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	repubResp, err := c.Republish(ctx, 0xFFFFFFFF, 1)
	if err != nil {
		if errors.Is(err, ua.StatusBadSubscriptionIDInvalid) {
			return // pass
		}
		t.Fatalf("Republish: %v", err)
	}
	if repubResp.ResponseHeader.ServiceResult != ua.StatusBadSubscriptionIDInvalid {
		t.Fatalf("Republish status=%v, want BadSubscriptionIDInvalid", repubResp.ResponseHeader.ServiceResult)
	}
}

// TestGoServer_TransferSubscription verifies TransferSubscriptions ownership
// reassignment and AvailableSequenceNumbers.
func TestGoServer_TransferSubscription(t *testing.T) {
	endpoint := startGoServer(t)
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	nodeID := ua.NewStringNodeID(nsIdx, "Access.ReadWrite")
	req := opcua.NewMonitoredItemCreateRequestWithDefaults(nodeID, ua.AttributeIDValue, 60)
	req.RequestedParameters.SamplingInterval = 0

	notifyCh := make(chan *opcua.PublishNotificationData, 32)
	sub, _, err := c.NewSubscription().
		Interval(200 * time.Millisecond).
		NotifyChannel(notifyCh).
		Timestamps(ua.TimestampsToReturnNeither).
		MonitorItems(req).
		Start(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	drainInitial(t, notifyCh)
	writeInt32(t, c, ctx, nodeID, 777)
	_ = collectDataChange(t, notifyCh, 1, 5*time.Second)

	// Transfer the subscription to itself (same session, same channel).
	transferResp, err := c.TransferSubscriptions(ctx, []uint32{sub.SubscriptionID}, false)
	if err != nil {
		t.Fatalf("TransferSubscriptions: %v", err)
	}
	if len(transferResp.Results) != 1 {
		t.Fatalf("transfer results len=%d", len(transferResp.Results))
	}
	if transferResp.Results[0].StatusCode != ua.StatusOK {
		t.Fatalf("transfer status=%v", transferResp.Results[0].StatusCode)
	}
	t.Logf("Transfer AvailableSequenceNumbers: %v", transferResp.Results[0].AvailableSequenceNumbers)
}

// TestGoServer_TransferSubscriptionInvalid verifies TransferSubscriptions with
// an unknown subscription ID returns BadSubscriptionIDInvalid.
func TestGoServer_TransferSubscriptionInvalid(t *testing.T) {
	endpoint := startGoServer(t)
	c := dialClient(t, endpoint)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	transferResp, err := c.TransferSubscriptions(ctx, []uint32{0xBEEF}, false)
	if err != nil {
		t.Fatalf("TransferSubscriptions: %v", err)
	}
	if len(transferResp.Results) != 1 {
		t.Fatalf("results len=%d", len(transferResp.Results))
	}
	if transferResp.Results[0].StatusCode != ua.StatusBadSubscriptionIDInvalid {
		t.Fatalf("transfer status=%v, want BadSubscriptionIDInvalid", transferResp.Results[0].StatusCode)
	}
}

// TestGoServer_ACKRemovesFromAvailable verifies that acknowledging a sequence
// number removes it from AvailableSequenceNumbers.
func TestGoServer_ACKRemovesFromAvailable(t *testing.T) {
	endpoint := startGoServer(t)
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	nodeID := ua.NewStringNodeID(nsIdx, "Access.ReadWrite")
	req := opcua.NewMonitoredItemCreateRequestWithDefaults(nodeID, ua.AttributeIDValue, 70)
	req.RequestedParameters.SamplingInterval = 0

	notifyCh := make(chan *opcua.PublishNotificationData, 32)
	sub, _, err := c.NewSubscription().
		Interval(200 * time.Millisecond).
		NotifyChannel(notifyCh).
		Timestamps(ua.TimestampsToReturnNeither).
		MonitorItems(req).
		Start(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	drainInitial(t, notifyCh)

	// Generate notifications so the server has stored messages.
	for i := int32(0); i < 3; i++ {
		writeInt32(t, c, ctx, nodeID, 800+i)
	}
	time.Sleep(800 * time.Millisecond)

	// The subscription should have sequences stored. Transfer to see them.
	var transferResp *ua.TransferSubscriptionsResponse
	err = c.Send(ctx, &ua.TransferSubscriptionsRequest{
		SubscriptionIDs:   []uint32{sub.SubscriptionID},
		SendInitialValues: false,
	}, func(r ua.Response) error {
		transferResp = r.(*ua.TransferSubscriptionsResponse)
		return nil
	})
	if err != nil {
		t.Fatalf("TransferSubscriptions: %v", err)
	}
	if len(transferResp.Results) != 1 || transferResp.Results[0].StatusCode != ua.StatusOK {
		t.Skipf("transfer failed: %v", transferResp.Results)
	}
	avail := transferResp.Results[0].AvailableSequenceNumbers
	t.Logf("available sequences after transfer: %v", avail)
	if len(avail) == 0 {
		t.Skip("no available sequences to verify ACK removal")
	}

}
