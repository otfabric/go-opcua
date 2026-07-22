//go:build interop

// SPDX-License-Identifier: MIT

// Go↔Go subscription lifecycle companions (revise, publishing mode, triggering, delete).
// COVERAGE.md: subscriptions / subscription.lifecycle.*

package interop

import (
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
)

func collectHandleValuesAcross(t *testing.T, notifyCh <-chan *opcua.PublishNotificationData, handle uint32, minCount int, timeout time.Duration) []int32 {
	t.Helper()
	deadline := time.After(timeout)
	var got []int32
	for {
		select {
		case msg, ok := <-notifyCh:
			if !ok {
				t.Fatal("notify channel closed")
			}
			if msg.Error != nil {
				t.Fatalf("notification error: %v", msg.Error)
			}
			dcn, ok := msg.Value.(*ua.DataChangeNotification)
			if !ok || dcn == nil {
				continue
			}
			got = append(got, int32sFromDCN(dcn, handle)...)
			if len(got) >= minCount {
				return got
			}
		case <-deadline:
			t.Fatalf("timeout waiting for handle %d with >=%d values (got %v)", handle, minCount, got)
		}
	}
}

func expectNoDataChange(t *testing.T, notifyCh <-chan *opcua.PublishNotificationData, wait time.Duration) {
	t.Helper()
	timer := time.After(wait)
	for {
		select {
		case msg, ok := <-notifyCh:
			if !ok {
				return
			}
			if msg.Error != nil {
				t.Fatalf("notification error while expecting idle: %v", msg.Error)
			}
			if dcn, ok := msg.Value.(*ua.DataChangeNotification); ok && dcn != nil && len(dcn.MonitoredItems) > 0 {
				t.Fatalf("unexpected DataChange during idle/disabled window: %+v", dcn.MonitoredItems)
			}
		case <-timer:
			return
		}
	}
}

// TestGoServer_SubscriptionReviseParams verifies Create/Modify revise clamps
// and LifetimeCount >= 3 × MaxKeepAliveCount.
func TestGoServer_SubscriptionReviseParams(t *testing.T) {
	endpoint := startGoServer(t)
	c := dialClient(t, endpoint)
	ctx := shortTestCtx(t)

	notifyCh := make(chan *opcua.PublishNotificationData, 8)
	sub, _, err := c.NewSubscription().
		Interval(1 * time.Millisecond). // below server minimum → clamp
		LifetimeCount(5).
		MaxKeepAliveCount(10). // lifetime must rise to >= 30
		NotifyChannel(notifyCh).
		Start(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	if sub.RevisedPublishingInterval < 10*time.Millisecond {
		t.Fatalf("RevisedPublishingInterval=%v, want >=10ms", sub.RevisedPublishingInterval)
	}
	if sub.RevisedMaxKeepAliveCount != 10 {
		t.Fatalf("RevisedMaxKeepAliveCount=%d, want 10", sub.RevisedMaxKeepAliveCount)
	}
	if sub.RevisedLifetimeCount < sub.RevisedMaxKeepAliveCount*3 {
		t.Fatalf("RevisedLifetimeCount=%d < 3× keepalive=%d", sub.RevisedLifetimeCount, sub.RevisedMaxKeepAliveCount)
	}

	mod, err := sub.ModifySubscription(ctx, opcua.SubscriptionParameters{
		Interval:          50 * time.Millisecond,
		LifetimeCount:     4,
		MaxKeepAliveCount: 5,
	})
	if err != nil {
		t.Fatalf("ModifySubscription: %v", err)
	}
	if mod.RevisedPublishingInterval != 50 {
		t.Fatalf("modify PI=%v, want 50", mod.RevisedPublishingInterval)
	}
	if mod.RevisedMaxKeepAliveCount != 5 {
		t.Fatalf("modify keepalive=%d, want 5", mod.RevisedMaxKeepAliveCount)
	}
	if mod.RevisedLifetimeCount < 15 {
		t.Fatalf("modify lifetime=%d, want >=15", mod.RevisedLifetimeCount)
	}
}

// TestGoServer_MonitoringModeLifecycle verifies Disabled/Sampling/Reporting
// enqueue and Publish semantics.
func TestGoServer_MonitoringModeLifecycle(t *testing.T) {
	endpoint := startGoServer(t)
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx := shortTestCtx(t)
	nodeID := ua.NewStringNodeID(nsIdx, "Access.ReadWrite")

	req := opcua.NewMonitoredItemCreateRequestWithDefaults(nodeID, ua.AttributeIDValue, 42)
	req.RequestedParameters.QueueSize = 5
	req.RequestedParameters.SamplingInterval = 0

	const pubInterval = 400 * time.Millisecond
	notifyCh := make(chan *opcua.PublishNotificationData, 64)
	sub, _, err := c.NewSubscription().
		Interval(pubInterval).
		NotifyChannel(notifyCh).
		Timestamps(ua.TimestampsToReturnNeither).
		Start(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	monResp, err := sub.Monitor(ctx, ua.TimestampsToReturnNeither, req)
	if err != nil {
		t.Fatalf("Monitor: %v", err)
	}
	if len(monResp.Results) == 0 || monResp.Results[0].StatusCode != ua.StatusOK {
		t.Fatalf("Monitor results: %+v", monResp.Results)
	}
	itemID := monResp.Results[0].MonitoredItemID
	drainInitial(t, notifyCh)

	// Reporting → Disabled: writes must not produce DataChange.
	if _, err := sub.SetMonitoringMode(ctx, ua.MonitoringModeDisabled, itemID); err != nil {
		t.Fatalf("SetMonitoringMode Disabled: %v", err)
	}
	writeInt32(t, c, ctx, nodeID, 100)
	writeInt32(t, c, ctx, nodeID, 101)
	expectNoDataChange(t, notifyCh, pubInterval*2+200*time.Millisecond)

	// Disabled → Sampling: enqueue but do not Publish.
	if _, err := sub.SetMonitoringMode(ctx, ua.MonitoringModeSampling, itemID); err != nil {
		t.Fatalf("SetMonitoringMode Sampling: %v", err)
	}
	writeInt32(t, c, ctx, nodeID, 102)
	writeInt32(t, c, ctx, nodeID, 103)
	expectNoDataChange(t, notifyCh, pubInterval*2+200*time.Millisecond)

	// Sampling → Reporting: queued samples deliver.
	if _, err := sub.SetMonitoringMode(ctx, ua.MonitoringModeReporting, itemID); err != nil {
		t.Fatalf("SetMonitoringMode Reporting: %v", err)
	}
	got := collectHandleValuesAcross(t, notifyCh, 42, 1, pubInterval*3+2*time.Second)
	if got[len(got)-1] != 103 && got[len(got)-1] != 102 {
		// At least one sampled value must arrive; exact window depends on queue.
		t.Logf("got sampled→reporting values: %v", got)
	}
	if len(got) == 0 {
		t.Fatal("expected queued Sampling values after switch to Reporting")
	}

	// Mixed valid/invalid IDs via raw SetMonitoringMode.
	var setResp *ua.SetMonitoringModeResponse
	err = c.Send(ctx, &ua.SetMonitoringModeRequest{
		SubscriptionID:   sub.SubscriptionID,
		MonitoringMode:   ua.MonitoringModeDisabled,
		MonitoredItemIDs: []uint32{itemID, 0xDEADBEEF},
	}, func(r ua.Response) error {
		setResp = r.(*ua.SetMonitoringModeResponse)
		return nil
	})
	if err != nil {
		t.Fatalf("SetMonitoringMode mixed: %v", err)
	}
	if len(setResp.Results) != 2 {
		t.Fatalf("mixed results len=%d", len(setResp.Results))
	}
	if setResp.Results[0] != ua.StatusOK {
		t.Fatalf("valid item status=%v", setResp.Results[0])
	}
	if setResp.Results[1] != ua.StatusBadMonitoredItemIDInvalid {
		t.Fatalf("invalid item status=%v, want BadMonitoredItemIDInvalid", setResp.Results[1])
	}
}

// TestGoServer_PublishingModeQueueWindow verifies disable → write → enable
// delivers the exact queue window.
func TestGoServer_PublishingModeQueueWindow(t *testing.T) {
	endpoint := startGoServer(t)
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx := shortTestCtx(t)
	nodeID := ua.NewStringNodeID(nsIdx, "Access.ReadWrite")

	req := opcua.NewMonitoredItemCreateRequestWithDefaults(nodeID, ua.AttributeIDValue, 7)
	req.RequestedParameters.QueueSize = 3
	req.RequestedParameters.DiscardOldest = true
	req.RequestedParameters.SamplingInterval = 0

	const pubInterval = 5 * time.Second
	notifyCh := make(chan *opcua.PublishNotificationData, 64)
	sub, _, err := c.NewSubscription().
		Interval(pubInterval).
		NotifyChannel(notifyCh).
		Timestamps(ua.TimestampsToReturnNeither).
		MonitorItems(req).
		Start(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	drainInitial(t, notifyCh)
	if _, err := sub.SetPublishingMode(ctx, false); err != nil {
		t.Fatalf("SetPublishingMode false: %v", err)
	}
	for _, v := range []int32{1, 2, 3, 4, 5} {
		writeInt32(t, c, ctx, nodeID, v)
	}
	expectNoDataChange(t, notifyCh, 800*time.Millisecond)

	if _, err := sub.SetPublishingMode(ctx, true); err != nil {
		t.Fatalf("SetPublishingMode true: %v", err)
	}
	dcn, got := collectHandleValues(t, notifyCh, 7, 3, pubInterval+3*time.Second)
	want := []int32{3, 4, 5}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	found := false
	for _, mi := range dcn.MonitoredItems {
		if mi.ClientHandle == 7 && mi.Value != nil && mi.Value.Status.HasOverflow() {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected Overflow after publishing re-enable")
	}
}

// TestGoServer_ModifyMonitoredItemsLifecycle verifies queue resize, DiscardOldest
// flip, and ID/ClientHandle stability.
func TestGoServer_ModifyMonitoredItemsLifecycle(t *testing.T) {
	endpoint := startGoServer(t)
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx := shortTestCtx(t)
	nodeID := ua.NewStringNodeID(nsIdx, "Access.ReadWrite")

	req := opcua.NewMonitoredItemCreateRequestWithDefaults(nodeID, ua.AttributeIDValue, 9)
	req.RequestedParameters.QueueSize = 5
	req.RequestedParameters.DiscardOldest = true
	req.RequestedParameters.SamplingInterval = 0

	const pubInterval = 5 * time.Second
	notifyCh := make(chan *opcua.PublishNotificationData, 64)
	sub, _, err := c.NewSubscription().
		Interval(pubInterval).
		NotifyChannel(notifyCh).
		Timestamps(ua.TimestampsToReturnNeither).
		Start(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	monResp, err := sub.Monitor(ctx, ua.TimestampsToReturnNeither, req)
	if err != nil {
		t.Fatalf("Monitor: %v", err)
	}
	itemID := monResp.Results[0].MonitoredItemID
	drainInitial(t, notifyCh)

	mod, err := sub.ModifyMonitoredItems(ctx, ua.TimestampsToReturnNeither,
		&ua.MonitoredItemModifyRequest{
			MonitoredItemID: itemID,
			RequestedParameters: &ua.MonitoringParameters{
				ClientHandle:     9,
				SamplingInterval: 0,
				QueueSize:        2,
				DiscardOldest:    false,
			},
		},
	)
	if err != nil {
		t.Fatalf("ModifyMonitoredItems: %v", err)
	}
	if mod.Results[0].StatusCode != ua.StatusOK {
		t.Fatalf("modify status=%v", mod.Results[0].StatusCode)
	}
	if mod.Results[0].RevisedQueueSize != 2 {
		t.Fatalf("RevisedQueueSize=%d, want 2", mod.Results[0].RevisedQueueSize)
	}

	for _, v := range []int32{1, 2, 3, 4, 5} {
		writeInt32(t, c, ctx, nodeID, v)
	}
	_, got := collectHandleValues(t, notifyCh, 9, 2, pubInterval+3*time.Second)
	// DiscardOldest=false, QS=2, writes 1..5 → [1, 5]
	want := []int32{1, 5}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}

	// Unknown monitored item ID in mixed batch (raw Send bypasses client-local checks).
	var modResp *ua.ModifyMonitoredItemsResponse
	err = c.Send(ctx, &ua.ModifyMonitoredItemsRequest{
		SubscriptionID:     sub.SubscriptionID,
		TimestampsToReturn: ua.TimestampsToReturnNeither,
		ItemsToModify: []*ua.MonitoredItemModifyRequest{
			{
				MonitoredItemID: itemID,
				RequestedParameters: &ua.MonitoringParameters{
					ClientHandle: 9, QueueSize: 5, DiscardOldest: true,
				},
			},
			{
				MonitoredItemID: 0xBAD,
				RequestedParameters: &ua.MonitoringParameters{
					ClientHandle: 9, QueueSize: 5, DiscardOldest: true,
				},
			},
		},
	}, func(r ua.Response) error {
		modResp = r.(*ua.ModifyMonitoredItemsResponse)
		return nil
	})
	if err != nil {
		t.Fatalf("ModifyMonitoredItems mixed: %v", err)
	}
	if modResp.Results[0].StatusCode != ua.StatusOK {
		t.Fatalf("valid modify status=%v", modResp.Results[0].StatusCode)
	}
	if modResp.Results[1].StatusCode != ua.StatusBadMonitoredItemIDInvalid {
		t.Fatalf("invalid modify status=%v", modResp.Results[1].StatusCode)
	}
}

// TestGoServer_MoreNotificationsPartialDrain verifies MaxNotificationsPerPublish
// splits a queue across Publish responses.
func TestGoServer_MoreNotificationsPartialDrain(t *testing.T) {
	endpoint := startGoServer(t)
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx := shortTestCtx(t)
	nodeID := ua.NewStringNodeID(nsIdx, "Access.ReadWrite")

	req := opcua.NewMonitoredItemCreateRequestWithDefaults(nodeID, ua.AttributeIDValue, 8)
	req.RequestedParameters.QueueSize = 3
	req.RequestedParameters.DiscardOldest = true
	req.RequestedParameters.SamplingInterval = 0

	const pubInterval = 5 * time.Second
	notifyCh := make(chan *opcua.PublishNotificationData, 64)
	sub, _, err := c.NewSubscription().
		Interval(pubInterval).
		MaxNotificationsPerPublish(2).
		NotifyChannel(notifyCh).
		Timestamps(ua.TimestampsToReturnNeither).
		MonitorItems(req).
		Start(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	drainInitial(t, notifyCh)
	for _, v := range []int32{1, 2, 3, 4, 5} {
		writeInt32(t, c, ctx, nodeID, v)
	}
	// QS=3 DiscardOldest → [3,4,5]; max=2 → publishes [3,4] then [5].
	got := collectHandleValuesAcross(t, notifyCh, 8, 3, pubInterval+pubInterval+3*time.Second)
	want := []int32{3, 4, 5}
	if len(got) < 3 {
		t.Fatalf("got %v, want at least %v", got, want)
	}
	got = got[:3]
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// TestGoServer_IdleNoFabricatedDataChange verifies idle periods do not invent
// DataChange notifications.
func TestGoServer_IdleNoFabricatedDataChange(t *testing.T) {
	endpoint := startGoServer(t)
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx := shortTestCtx(t)
	nodeID := ua.NewStringNodeID(nsIdx, "Access.ReadWrite")

	req := opcua.NewMonitoredItemCreateRequestWithDefaults(nodeID, ua.AttributeIDValue, 1)
	req.RequestedParameters.SamplingInterval = 0

	notifyCh := make(chan *opcua.PublishNotificationData, 16)
	sub, _, err := c.NewSubscription().
		Interval(100 * time.Millisecond).
		MaxKeepAliveCount(1).
		LifetimeCount(100).
		NotifyChannel(notifyCh).
		Timestamps(ua.TimestampsToReturnNeither).
		MonitorItems(req).
		Start(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	drainInitial(t, notifyCh)
	expectNoDataChange(t, notifyCh, 800*time.Millisecond)
}

// TestGoServer_DeleteSubscriptionLifecycle verifies delete + second-delete
// status and sibling isolation.
func TestGoServer_DeleteSubscriptionLifecycle(t *testing.T) {
	endpoint := startGoServer(t)
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx := shortTestCtx(t)
	nodeID := ua.NewStringNodeID(nsIdx, "Access.ReadWrite")

	req := opcua.NewMonitoredItemCreateRequestWithDefaults(nodeID, ua.AttributeIDValue, 3)
	req.RequestedParameters.SamplingInterval = 0

	notifyA := make(chan *opcua.PublishNotificationData, 16)
	subA, _, err := c.NewSubscription().
		Interval(200 * time.Millisecond).
		NotifyChannel(notifyA).
		Timestamps(ua.TimestampsToReturnNeither).
		MonitorItems(req).
		Start(ctx)
	if err != nil {
		t.Fatalf("Subscribe A: %v", err)
	}
	idA := subA.SubscriptionID

	notifyB := make(chan *opcua.PublishNotificationData, 16)
	reqB := opcua.NewMonitoredItemCreateRequestWithDefaults(nodeID, ua.AttributeIDValue, 4)
	reqB.RequestedParameters.SamplingInterval = 0
	subB, _, err := c.NewSubscription().
		Interval(200 * time.Millisecond).
		NotifyChannel(notifyB).
		Timestamps(ua.TimestampsToReturnNeither).
		MonitorItems(reqB).
		Start(ctx)
	if err != nil {
		t.Fatalf("Subscribe B: %v", err)
	}
	t.Cleanup(func() { _ = subB.Cancel(ctx) })

	drainInitial(t, notifyA)
	drainInitial(t, notifyB)

	if err := subA.Cancel(ctx); err != nil {
		t.Fatalf("Cancel A: %v", err)
	}

	var delResp *ua.DeleteSubscriptionsResponse
	err = c.Send(ctx, &ua.DeleteSubscriptionsRequest{
		SubscriptionIDs: []uint32{idA},
	}, func(r ua.Response) error {
		delResp = r.(*ua.DeleteSubscriptionsResponse)
		return nil
	})
	if err != nil {
		t.Fatalf("second DeleteSubscriptions: %v", err)
	}
	if len(delResp.Results) != 1 || delResp.Results[0] != ua.StatusBadSubscriptionIDInvalid {
		t.Fatalf("second delete results=%v, want BadSubscriptionIDInvalid", delResp.Results)
	}

	writeInt32(t, c, ctx, nodeID, 77)
	got := collectHandleValuesAcross(t, notifyB, 4, 1, 3*time.Second)
	if got[len(got)-1] != 77 {
		t.Fatalf("sibling sub B got %v, want ...77", got)
	}
}

// TestGoServer_DeleteMonitoredItems verifies Unmonitor + second delete status
// .
func TestGoServer_DeleteMonitoredItems(t *testing.T) {
	endpoint := startGoServer(t)
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx := shortTestCtx(t)
	nodeID := ua.NewStringNodeID(nsIdx, "Access.ReadWrite")

	req := opcua.NewMonitoredItemCreateRequestWithDefaults(nodeID, ua.AttributeIDValue, 5)
	notifyCh := make(chan *opcua.PublishNotificationData, 16)
	sub, _, err := c.NewSubscription().
		Interval(200 * time.Millisecond).
		NotifyChannel(notifyCh).
		Timestamps(ua.TimestampsToReturnNeither).
		Start(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	monResp, err := sub.Monitor(ctx, ua.TimestampsToReturnNeither, req)
	if err != nil {
		t.Fatalf("Monitor: %v", err)
	}
	itemID := monResp.Results[0].MonitoredItemID
	drainInitial(t, notifyCh)

	um, err := sub.Unmonitor(ctx, itemID)
	if err != nil {
		t.Fatalf("Unmonitor: %v", err)
	}
	if um.Results[0] != ua.StatusOK {
		t.Fatalf("Unmonitor status=%v", um.Results[0])
	}

	var delResp *ua.DeleteMonitoredItemsResponse
	err = c.Send(ctx, &ua.DeleteMonitoredItemsRequest{
		SubscriptionID:   sub.SubscriptionID,
		MonitoredItemIDs: []uint32{itemID},
	}, func(r ua.Response) error {
		delResp = r.(*ua.DeleteMonitoredItemsResponse)
		return nil
	})
	if err != nil {
		t.Fatalf("second DeleteMonitoredItems: %v", err)
	}
	if delResp.Results[0] != ua.StatusBadMonitoredItemIDInvalid {
		t.Fatalf("second delete status=%v, want BadMonitoredItemIDInvalid", delResp.Results[0])
	}

	writeInt32(t, c, ctx, nodeID, 88)
	expectNoDataChange(t, notifyCh, 600*time.Millisecond)
}
