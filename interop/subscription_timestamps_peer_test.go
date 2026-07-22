//go:build interop

// SPDX-License-Identifier: MIT

// Peer subscription TimestampsToReturn tests (all 4 directions).
// COVERAGE.md: subscriptions / subscription.timestamps

package interop

import (
	"encoding/json"
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
)

// TestOpen62541Server_SubscribeTimestampsToReturn verifies DataChange
// EncodingMask honors TimestampsToReturn against an open62541 peer.
func TestOpen62541Server_SubscribeTimestampsToReturn(t *testing.T) {
	t.Run("coverage/subscription.timestamps/go-client-to-open62541-server", func(t *testing.T) {
		h := startOpen62541Server(t)
		assertPeerSubscribeTimestamps(t, h.endpoint)
	})
}

// TestMiloServer_SubscribeTimestampsToReturn verifies DataChange EncodingMask
// honors TimestampsToReturn against a Milo peer.
func TestMiloServer_SubscribeTimestampsToReturn(t *testing.T) {
	t.Run("coverage/subscription.timestamps/go-client-to-milo-server", func(t *testing.T) {
		h := startMiloServer(t)
		assertPeerSubscribeTimestamps(t, h.endpoint)
	})
}

func assertPeerSubscribeTimestamps(t *testing.T, endpoint string) {
	t.Helper()

	cases := []struct {
		name         string
		ts           ua.TimestampsToReturn
		forbidSrc    bool // when true, source bit must be clear
		forbidServer bool // when true, server bit must be clear
		requireSrc   bool // when true, source bit must be set
		requireSrv   bool // when true, server bit must be set
		writeVal     int32
	}{
		// Neither must omit both. Source/Both may include source if the peer stores it.
		{"Neither", ua.TimestampsToReturnNeither, true, true, false, false, 201},
		{"Source", ua.TimestampsToReturnSource, false, true, false, false, 202},
		{"Server", ua.TimestampsToReturnServer, true, false, false, true, 203},
		{"Both", ua.TimestampsToReturnBoth, false, false, false, true, 204},
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

			dcn := collectDataChange(t, notifyCh, 1, 10*time.Second)
			assertPeerDVTimestamps(t, "initial", dcn.MonitoredItems[0].Value, tc.forbidSrc, tc.forbidServer, tc.requireSrc, tc.requireSrv)

			writeInt32(t, c, ctx, nodeID, tc.writeVal)
			dcn2 := collectDataChange(t, notifyCh, 1, 10*time.Second)
			assertPeerDVTimestamps(t, "after-write", dcn2.MonitoredItems[0].Value, tc.forbidSrc, tc.forbidServer, tc.requireSrc, tc.requireSrv)
		})
	}
}

func assertPeerDVTimestamps(t *testing.T, label string, dv *ua.DataValue, forbidSrc, forbidServer, requireSrc, requireSrv bool) {
	t.Helper()
	if dv == nil {
		t.Fatalf("%s: nil DataValue", label)
	}
	hasSrc := dv.EncodingMask&ua.DataValueSourceTimestamp != 0
	hasSrv := dv.EncodingMask&ua.DataValueServerTimestamp != 0
	if forbidSrc && hasSrc {
		t.Errorf("%s: source timestamp present, want absent (mask=%#x)", label, dv.EncodingMask)
	}
	if forbidServer && hasSrv {
		t.Errorf("%s: server timestamp present, want absent (mask=%#x)", label, dv.EncodingMask)
	}
	if requireSrc && !hasSrc {
		t.Errorf("%s: source timestamp absent, want present (mask=%#x)", label, dv.EncodingMask)
	}
	if requireSrv && !hasSrv {
		t.Errorf("%s: server timestamp absent, want present (mask=%#x)", label, dv.EncodingMask)
	}
}

type subscribeNotifTimestamps struct {
	SourceTimestamp *string `json:"sourceTimestamp"`
	ServerTimestamp *string `json:"serverTimestamp"`
}

type subscribeTimestampItem struct {
	Notifications []subscribeNotifTimestamps `json:"notifications"`
}

// TestGoServer_Open62541Client_SubscribeTimestamps verifies adapter subscribe
// --timestamps Neither/Both against the Go server (CLIENT_CONTRACT omission rules).
func TestGoServer_Open62541Client_SubscribeTimestamps(t *testing.T) {
	t.Run("coverage/subscription.timestamps/open62541-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, "OPEN62541_IMAGE", defaultOpen62541Image, "subscribe")
		endpoint := startGoServer(t)
		assertAdapterSubscribeTimestamps(t, endpoint, runOpen62541ClientResult)
	})
}

// TestGoServer_MiloClient_SubscribeTimestamps verifies Milo adapter subscribe
// --timestamps Neither/Both against the Go server.
func TestGoServer_MiloClient_SubscribeTimestamps(t *testing.T) {
	t.Run("coverage/subscription.timestamps/milo-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, "MILO_IMAGE", defaultMiloImage, "subscribe")
		endpoint := startGoServer(t)
		assertAdapterSubscribeTimestamps(t, endpoint, runMiloClientResult)
	})
}

func assertAdapterSubscribeTimestamps(t *testing.T, endpoint string, run func(t *testing.T, endpoint, subcmd string, args ...string) adapterResult) {
	t.Helper()
	node := "nsu=" + interopNamespaceURI + ";s=Dynamic.Counter"

	t.Run("Neither", func(t *testing.T) {
		result := run(t, endpoint, "subscribe",
			"--node", node,
			"--notifications", "2",
			"--publishing-interval-ms", "200",
			"--timeout-ms", "15000",
			"--timestamps", "Neither",
		)
		if !result.Success {
			t.Fatalf("subscribe Neither failed: %+v", result)
		}
		notifs := parseSubscribeTimestampNotifs(t, result.Results)
		if len(notifs) == 0 {
			t.Fatal("no notifications")
		}
		for i, n := range notifs {
			if tsMeaningful(n.SourceTimestamp) {
				t.Errorf("notif[%d]: sourceTimestamp present under Neither: %q", i, *n.SourceTimestamp)
			}
			if tsMeaningful(n.ServerTimestamp) {
				t.Errorf("notif[%d]: serverTimestamp present under Neither: %q", i, *n.ServerTimestamp)
			}
		}
	})

	t.Run("Both", func(t *testing.T) {
		result := run(t, endpoint, "subscribe",
			"--node", node,
			"--notifications", "2",
			"--publishing-interval-ms", "200",
			"--timeout-ms", "15000",
			"--timestamps", "Both",
		)
		if !result.Success {
			t.Fatalf("subscribe Both failed: %+v", result)
		}
		notifs := parseSubscribeTimestampNotifs(t, result.Results)
		if len(notifs) == 0 {
			t.Fatal("no notifications")
		}
		// Go Dynamic.Counter has no stored source timestamp; serverTimestamp must be present.
		sawServer := false
		for i, n := range notifs {
			if n.SourceTimestamp != nil {
				t.Logf("notif[%d]: sourceTimestamp=%q (optional for Dynamic.Counter)", i, *n.SourceTimestamp)
			}
			if n.ServerTimestamp != nil {
				sawServer = true
			}
		}
		if !sawServer {
			t.Fatal("Both: no notification carried serverTimestamp")
		}
	})
}

func parseSubscribeTimestampNotifs(t *testing.T, raw json.RawMessage) []subscribeNotifTimestamps {
	t.Helper()
	var items []subscribeTimestampItem
	if err := json.Unmarshal(raw, &items); err != nil || len(items) == 0 {
		t.Fatalf("parse subscribe results: %v; raw: %s", err, raw)
	}
	return items[0].Notifications
}

// tsMeaningful reports whether an adapter timestamp string represents a real
// OPC UA DateTime (null/zero DateTime is commonly serialized as 1601-01-01).
func tsMeaningful(ts *string) bool {
	if ts == nil || *ts == "" {
		return false
	}
	s := *ts
	return !(len(s) >= 10 && s[:10] == "1601-01-01")
}
