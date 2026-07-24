//go:build interop

// SPDX-License-Identifier: MIT

// Go↔Go subscription TimestampsToReturn companions.
// COVERAGE.md: subscriptions / subscription.timestamps

package interop

import (
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
)

// TestGoServer_SubscribeTimestampsToReturn verifies DataChange EncodingMask
// honors TimestampsToReturn.
func TestGoServer_SubscribeTimestampsToReturn(t *testing.T) {
	endpoint := startGoServer(t)

	cases := []struct {
		name       string
		ts         ua.TimestampsToReturn
		wantSrc    bool
		wantServer bool
		writeVal   int32
	}{
		{"Neither", ua.TimestampsToReturnNeither, false, false, 101},
		{"Source", ua.TimestampsToReturnSource, false, false, 102}, // no source stored on node → absent
		{"Server", ua.TimestampsToReturnServer, false, true, 103},
		{"Both", ua.TimestampsToReturnBoth, false, true, 104},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := dialClient(t, endpoint)
			_, nsIdx := findNS(t, c)
			ctx := shortTestCtx(t)
			nodeID := ua.NewStringNodeID(nsIdx, "Access.ReadWrite")

			req := opcua.NewMonitoredItemCreateRequestWithDefaults(nodeID, ua.AttributeIDValue, 1)
			req.RequestedParameters.QueueSize = 1
			notifyCh := make(chan *opcua.PublishNotificationData, 16)
			sub, _, err := c.NewSubscription().
				Interval(500 * time.Millisecond).
				NotifyChannel(notifyCh).
				Timestamps(tc.ts).
				MonitorItems(req).
				Start(ctx)
			if err != nil {
				t.Fatalf("Subscribe: %v", err)
			}
			defer sub.Cancel(ctx) //nolint:errcheck

			dcn := collectDataChange(t, notifyCh, 1, 5*time.Second)
			dv := dcn.MonitoredItems[0].Value
			hasSrc := dv.EncodingMask&ua.DataValueSourceTimestamp != 0
			hasSrv := dv.EncodingMask&ua.DataValueServerTimestamp != 0
			if hasSrc != tc.wantSrc {
				t.Errorf("source timestamp present=%v, want %v (mask=%#x)", hasSrc, tc.wantSrc, dv.EncodingMask)
			}
			if hasSrv != tc.wantServer {
				t.Errorf("server timestamp present=%v, want %v (mask=%#x)", hasSrv, tc.wantServer, dv.EncodingMask)
			}

			writeInt32(t, c, ctx, nodeID, tc.writeVal)
			dcn2 := collectDataChange(t, notifyCh, 1, 5*time.Second)
			dv2 := dcn2.MonitoredItems[0].Value
			hasSrv2 := dv2.EncodingMask&ua.DataValueServerTimestamp != 0
			if hasSrv2 != tc.wantServer {
				t.Errorf("subsequent server timestamp present=%v, want %v", hasSrv2, tc.wantServer)
			}
		})
	}
}

// TestGoServer_MatrixIndexRangeRead verifies multidimensional NumericRange Read
// on Array.Matrix2D.
