//go:build interop

// SPDX-License-Identifier: MIT

// Go↔Go monitored-item queue window companions.
// COVERAGE.md: subscriptions / exact QueueSize / DiscardOldest

package interop

import (
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
)

// TestGoServer_QueueExactWindow verifies Part 4 monitored-item queue windows
// with explicit writes 1..5.
func TestGoServer_QueueExactWindow(t *testing.T) {
	endpoint := startGoServer(t)

	cases := []struct {
		name          string
		queueSize     uint32
		discardOldest bool
		want          []int32
		wantOverflow  bool
	}{
		{"QueueSize1", 1, true, []int32{5}, false},
		{"DiscardOldestTrue", 3, true, []int32{3, 4, 5}, true},
		{"DiscardOldestFalse", 3, false, []int32{1, 2, 5}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Fresh client per case avoids publish-request contention across
			// rapid subscribe/cancel cycles on one session.
			c := dialClient(t, endpoint)
			_, nsIdx := findNS(t, c)
			ctx := shortTestCtx(t)
			nodeID := ua.NewStringNodeID(nsIdx, "Access.ReadWrite")

			req := opcua.NewMonitoredItemCreateRequestWithDefaults(nodeID, ua.AttributeIDValue, 7)
			req.RequestedParameters.QueueSize = tc.queueSize
			req.RequestedParameters.DiscardOldest = tc.discardOldest
			req.RequestedParameters.SamplingInterval = 0

			// Long interval: after the initial publish, all writes enqueue
			// before the next Publish (Part 4 exact-window driver).
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
			defer sub.Cancel(ctx) //nolint:errcheck

			drainInitial(t, notifyCh)
			// Right after a publish, the next tick is a full interval away.
			for _, v := range []int32{1, 2, 3, 4, 5} {
				writeInt32(t, c, ctx, nodeID, v)
			}

			dcn, got := collectHandleValues(t, notifyCh, 7, len(tc.want), pubInterval+3*time.Second)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
			if tc.wantOverflow {
				found := false
				for _, mi := range dcn.MonitoredItems {
					if mi.ClientHandle == 7 && mi.Value != nil && mi.Value.Status.HasOverflow() {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected Overflow InfoBit on at least one queued value")
				}
			}
		})
	}
}

// TestGoServer_QueueItemIsolation verifies overflow on one monitored item does
// not affect another.

// TestGoServer_QueueItemIsolation verifies overflow on one monitored item does
// not affect another.
func TestGoServer_QueueItemIsolation(t *testing.T) {
	endpoint := startGoServer(t)
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ctx := shortTestCtx(t)
	nodeA := ua.NewStringNodeID(nsIdx, "Access.ReadWrite")
	nodeB := ua.NewStringNodeID(nsIdx, "Scalar.Int32")

	reqA := opcua.NewMonitoredItemCreateRequestWithDefaults(nodeA, ua.AttributeIDValue, 11)
	reqA.RequestedParameters.QueueSize = 3
	reqA.RequestedParameters.DiscardOldest = true
	reqA.RequestedParameters.SamplingInterval = 0

	reqB := opcua.NewMonitoredItemCreateRequestWithDefaults(nodeB, ua.AttributeIDValue, 22)
	reqB.RequestedParameters.QueueSize = 1
	reqB.RequestedParameters.DiscardOldest = true
	reqB.RequestedParameters.SamplingInterval = 0

	notifyCh := make(chan *opcua.PublishNotificationData, 64)
	sub, _, err := c.NewSubscription().
		Interval(2*time.Second).
		NotifyChannel(notifyCh).
		Timestamps(ua.TimestampsToReturnNeither).
		MonitorItems(reqA, reqB).
		Start(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Cancel(ctx) //nolint:errcheck

	// Drain initials (may arrive as one or two publishes).
	deadline := time.After(6 * time.Second)
drainLoop:
	for {
		select {
		case msg := <-notifyCh:
			if msg.Error != nil {
				t.Fatalf("initial: %v", msg.Error)
			}
		case <-deadline:
			break drainLoop
		case <-time.After(500 * time.Millisecond):
			break drainLoop
		}
	}

	for _, v := range []int32{1, 2, 3, 4, 5} {
		writeInt32(t, c, ctx, nodeA, v)
	}
	writeInt32(t, c, ctx, nodeB, 42)

	// Collect until we see both handles.
	var gotA, gotB []int32
	deadline = time.After(8 * time.Second)
	for len(gotA) < 3 || len(gotB) < 1 {
		select {
		case msg := <-notifyCh:
			if msg.Error != nil {
				t.Fatalf("notif: %v", msg.Error)
			}
			dcn, ok := msg.Value.(*ua.DataChangeNotification)
			if !ok {
				continue
			}
			gotA = append(gotA, int32sFromDCN(dcn, 11)...)
			gotB = append(gotB, int32sFromDCN(dcn, 22)...)
		case <-deadline:
			t.Fatalf("timeout: A=%v B=%v", gotA, gotB)
		}
	}
	if len(gotA) != 3 || gotA[0] != 3 || gotA[1] != 4 || gotA[2] != 5 {
		t.Errorf("item A window: got %v, want [3 4 5]", gotA)
	}
	if len(gotB) != 1 || gotB[0] != 42 {
		t.Errorf("item B: got %v, want [42]", gotB)
	}
}

// TestGoServer_SubscribeTimestampsToReturn verifies DataChange EncodingMask
// honors TimestampsToReturn.
