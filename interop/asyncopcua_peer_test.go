//go:build interop

// SPDX-License-Identifier: MIT

// async-opcua (Rust) peer tests that reuse the parameterised assertions of the
// *_peer_test.go files (DataChangeFilter, events, history, discovery, register
// nodes, node management, subscription services, reverse connect, ...).
//
// Directions: go-client-to-async-opcua-server, async-opcua-client-to-go-server.
// The subtest names follow the coverage/<capability>/<direction> convention.

package interop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
)

const asyncOpcuaEnv = "ASYNC_OPCUA_IMAGE"

// peerDeadbandSVTDeviation lists the go-client-to-peer directions whose server
// does not apply an absolute deadband under the StatusValueTimestamp trigger
// (consulted by assertPeerDataChangeFilter).
//
// async-opcua 0.19 (ParsedDataChangeFilter::is_changed in
// async-opcua-types/src/data_change.rs) reports a sample under
// StatusValueTimestamp whenever its SourceTimestamp changed, even when the
// value stayed inside the deadband; open62541 and Milo apply the deadband.
// Part 4 §7.22.2 does not spell out how the two combine, so this is recorded
// as an interpretation difference, not asserted either way.
var peerDeadbandSVTDeviation = map[string]string{
	"go-client-to-async-opcua-server": "async-opcua 0.19 reports every SourceTimestamp change under StatusValueTimestamp, the deadband only filters StatusValue",
}

// ---------------------------------------------------------------------------
// DataChangeFilter (datachange_filter_peer_test.go)
// ---------------------------------------------------------------------------

func TestAsyncOpcuaServer_DataChangeFilter(t *testing.T) {
	requireAsyncOpcuaImage(t)
	h := startAsyncOpcuaServer(t)
	assertPeerDataChangeFilter(t, h.endpoint, "go-client-to-async-opcua-server")
	t.Run("coverage/monitoreditem.percent-deadband/go-client-to-async-opcua-server", func(t *testing.T) {
		requireServerFeature(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, "percent-deadband")
		assertAsyncOpcuaPercentDeadband(t, h.endpoint)
	})
}

// assertAsyncOpcuaPercentDeadband is assertPeerPercentDeadband with the
// exact-boundary rounding deviation of async-opcua 0.19 logged, not failed.
func assertAsyncOpcuaPercentDeadband(t *testing.T, endpoint string) {
	t.Helper()
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	level := ua.NewStringNodeID(nsIdx, "Analog.Level")
	ramp := ua.NewStringNodeID(nsIdx, "Dynamic.Ramp")

	const hRef, hTen, hFull, hNoRange = 0, 1, 2, 3
	item := func(node *ua.NodeID, handle uint32, percent float64) *ua.MonitoredItemCreateRequest {
		req := opcua.NewMonitoredItemCreateRequestWithDefaults(node, ua.AttributeIDValue, handle)
		req.RequestedParameters.QueueSize = 100
		req.RequestedParameters.SamplingInterval = 50
		if percent >= 0 {
			req.RequestedParameters.Filter = opcua.NewDataChangeFilter(ua.DataChangeTriggerStatusValue, ua.DeadbandTypePercent, percent)
		}
		return req
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	notifyCh := make(chan *opcua.PublishNotificationData, 256)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 100 * time.Millisecond}, notifyCh)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer func() { _ = sub.Cancel(ctx) }()

	res, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth,
		item(level, hRef, -1),
		item(level, hTen, 10),
		item(level, hFull, 100),
		// Dynamic.Ramp is a plain variable without EURange.
		item(ramp, hNoRange, 10),
	)
	if err != nil {
		t.Fatalf("Monitor: %v", err)
	}
	if len(res.Results) != 4 {
		t.Fatalf("Monitor: %d results for 4 items", len(res.Results))
	}
	for _, h := range []int{hRef, hTen, hFull} {
		if st := res.Results[h].StatusCode; st != ua.StatusOK {
			t.Fatalf("item %d on Analog.Level: peer rejected the monitored item: %v", h, st)
		}
	}
	// Negative: a PercentDeadband needs an EURange. Part 4 names
	// Bad_MonitoredItemFilterUnsupported; Bad_FilterNotAllowed is the status
	// open62541 uses for a node that is not an AnalogItem.
	switch st := res.Results[hNoRange].StatusCode; st {
	case ua.StatusBadMonitoredItemFilterUnsupported, ua.StatusBadFilterNotAllowed, ua.StatusBadDeadbandFilterInvalid:
		t.Logf("percent deadband on a variable without EURange: %v", st)
	default:
		t.Errorf("percent deadband on a variable without EURange: got %v, want the item rejected", st)
	}

	var samples [3][]float64
	// 60 reference samples: more than one full sweep of the ramp (51 steps).
	for len(samples[hRef]) < 60 {
		select {
		case msg := <-notifyCh:
			if msg.Error != nil {
				t.Fatalf("notification error: %v", msg.Error)
			}
			dcn, ok := msg.Value.(*ua.DataChangeNotification)
			if !ok {
				continue
			}
			for _, mi := range dcn.MonitoredItems {
				if mi.ClientHandle < 3 && mi.Value != nil && mi.Value.Value != nil {
					samples[mi.ClientHandle] = append(samples[mi.ClientHandle], mi.Value.Value.Float())
				}
			}
		case <-ctx.Done():
			t.Fatalf("timed out with %d of 60 reference samples", len(samples[hRef]))
		}
	}
	ref, ten, full := samples[hRef], samples[hTen], samples[hFull]
	t.Logf("reference: %d samples; 10 %%: %v; 100 %%: %v", len(ref), ten, full)

	// Positive: changes beyond 10 % of the range are reported.
	if len(ten) < 4 {
		t.Errorf("10 %% deadband: want the initial value and at least 3 changes, got %v", ten)
	}
	// Negative: nothing within it is. A step of exactly the deadband is
	// reported by async-opcua 0.19: it compares differences of normalised
	// values, (56-0)/100 - (46-0)/100 = 0.10000000000000009 > 0.1
	// (Deadband::is_changed, async-opcua-types/src/data_change.rs). That
	// rounding deviation is logged; any step really inside the deadband fails.
	for i := 1; i < len(ten); i++ {
		step := rampStep(ten[i-1], ten[i])
		if math.Abs(step-10) < 1e-9 {
			t.Logf("10 %% deadband: step %v -> %v equals the deadband and was reported (async-opcua rounding deviation)", ten[i-1], ten[i])
			continue
		}
		if step <= 10 {
			t.Errorf("10 %% deadband: step %v -> %v is within the deadband", ten[i-1], ten[i])
		}
	}
	if len(ten)*3 > len(ref) {
		t.Errorf("10 %% deadband: %d samples against %d unfiltered: not filtered", len(ten), len(ref))
	}
	// 100 % of the range is never exceeded by a value inside the range, the
	// reset from 100 to 0 included.
	if len(full) != 1 {
		t.Errorf("100 %% deadband: want only the initial value, got %v", full)
	}
}

func TestGoServer_AsyncOpcuaClient_SamplingInterval(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/monitoreditem.sampling-interval/async-opcua-client-to-go-server", func(t *testing.T) {
		assertPeerClientSamplingInterval(t, runAsyncOpcuaClient)
	})
}

func TestGoServer_AsyncOpcuaClient_Deadband(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/monitoreditem.deadband/async-opcua-client-to-go-server", func(t *testing.T) {
		requireAdapterClientFeature(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, "deadband")
		assertPeerClientDeadband(t, runAsyncOpcuaClient, runAsyncOpcuaClientResult)
	})
}

func TestGoServer_AsyncOpcuaClient_PercentDeadband(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/monitoreditem.percent-deadband/async-opcua-client-to-go-server", func(t *testing.T) {
		requireAdapterClientFeature(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, "deadband")
		assertPeerClientPercentDeadband(t, runAsyncOpcuaClient, runAsyncOpcuaClientResult)
	})
}

func TestGoServer_AsyncOpcuaClient_Trigger(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/monitoreditem.trigger/async-opcua-client-to-go-server", func(t *testing.T) {
		requireAdapterClientFeature(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, "deadband")
		assertPeerClientTrigger(t, runAsyncOpcuaClient, runAsyncOpcuaClientResult)
	})
}

// ---------------------------------------------------------------------------
// Discovery (discovery_peer_test.go, discovery_lds_peer_test.go)
// ---------------------------------------------------------------------------

func TestAsyncOpcuaServer_FindServers(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/discovery.find-servers/go-client-to-async-opcua-server", func(t *testing.T) {
		h := startAsyncOpcuaServer(t)
		ctx := shortTestCtx(t)
		servers, err := opcua.FindServers(ctx, h.endpoint)
		if err != nil {
			t.Fatalf("FindServers: %v", err)
		}
		assertFindServersResult(t, servers)
	})
}

func TestGoServer_AsyncOpcuaClient_FindServers(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/discovery.find-servers/async-opcua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, "find-servers")
		endpoint := startGoServer(t)
		result := runAsyncOpcuaClient(t, endpoint, "find-servers")
		assertAdapterFindServers(t, result)
	})
}

// TestAsyncOpcuaServer_DiscoveryServerUnsupported pins why the directions
// towards an async-opcua discovery server are unsupported: the async-opcua
// 0.19 server answers FindServersOnNetwork, RegisterServer2 and
// RegisterServer with BadServiceUnsupported (docs/compatibility.md: "stub").
func TestAsyncOpcuaServer_DiscoveryServerUnsupported(t *testing.T) {
	requireAsyncOpcuaImage(t)
	h := startAsyncOpcuaServer(t)

	ctx := shortTestCtx(t)
	if _, err := opcua.FindServersOnNetwork(ctx, h.endpoint); !errors.Is(err, ua.StatusBadServiceUnsupported) {
		t.Errorf("FindServersOnNetwork on the async-opcua server: %v, want BadServiceUnsupported", err)
	}

	events := make(chan server.RegistrationEvent, 16)
	srv, err := server.New(
		server.ListenOn("127.0.0.1:0"),
		server.EndPoint("localhost", 0),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.ApplicationURI("urn:otfabric:go-opcua:interop:registrant"),
		server.WithDiscoveryRegistration(h.endpoint,
			server.RegisterInsecure(),
			server.RegisterEventHandler(func(e server.RegistrationEvent) {
				select {
				case events <- e:
				default:
				}
			}),
		),
	)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("server.Start: %v", err)
	}
	defer srv.Close() //nolint:errcheck
	select {
	case e := <-events:
		if e.Service != "RegisterServer" || !errors.Is(e.Err, ua.StatusBadServiceUnsupported) {
			t.Errorf("registration with the async-opcua server: service=%s err=%v, want RegisterServer / BadServiceUnsupported", e.Service, e.Err)
		}
	case <-time.After(discoveryWait):
		t.Fatal("no registration attempt was reported")
	}
}

func TestGoLDS_AsyncOpcuaServerRegisters(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/discovery.lds-registration/async-opcua-server-to-go-lds", func(t *testing.T) {
		assertPeerServerRegistersWithGoLDS(t, asyncOpcuaEnv, defaultAsyncOpcuaImage)
	})
}

func TestGoLDS_AsyncOpcuaClient_RegisterServer(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/discovery.register-server/async-opcua-client-to-go-lds", func(t *testing.T) {
		assertClientRegistersWithGoLDS(t, asyncOpcuaEnv, defaultAsyncOpcuaImage)
	})
}

// ---------------------------------------------------------------------------
// Translate, methods, security (translate/method/security_peer_test.go)
// ---------------------------------------------------------------------------

func TestAsyncOpcuaServer_TranslateBrowsePath(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/translate.browse-path/go-client-to-async-opcua-server", func(t *testing.T) {
		h := startAsyncOpcuaServer(t)
		c := dialClient(t, h.endpoint)
		ctx := shortTestCtx(t)
		node, err := c.NodeFromPath(ctx, "Server")
		if err != nil {
			t.Fatalf("NodeFromPath(Server): %v", err)
		}
		if node == nil || node.ID == nil {
			t.Fatal("NodeFromPath(Server): nil NodeID")
		}
		t.Logf("TranslateBrowsePath Server → %s", node.ID)
	})
}

func TestGoServer_AsyncOpcuaClient_TranslateBrowsePath(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/translate.browse-path/async-opcua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, "translate")
		endpoint := startGoServer(t)
		result := runAsyncOpcuaClient(t, endpoint, "translate",
			"--starting-node", "i=85",
			"--path", "Server",
		)
		assertAdapterTranslateServer(t, result)
	})
}

func TestAsyncOpcuaServer_MethodValidation(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/method.validation/go-client-to-async-opcua-server", func(t *testing.T) {
		h := startAsyncOpcuaServer(t)
		c := dialClient(t, h.endpoint)
		ctx, nsIdx := findNS(t, c)
		assertMethodTooFewArgs(t, c, ctx, nsIdx)
	})
}

func TestAsyncOpcuaServer_TrustedCert_Accepted(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/security.cert.trusted/go-client-to-async-opcua-server", func(t *testing.T) {
		h := startAsyncOpcuaSecureServer(t)
		c := dialSecureClient(t, h.endpoint, "Basic256Sha256", "SignAndEncrypt")
		ctx, nsIdx := findNS(t, c)
		v, err := c.Node(ua.NewStringNodeID(nsIdx, "Scalar.Int32")).Value(ctx)
		if err != nil {
			t.Fatalf("Value(Scalar.Int32): %v", err)
		}
		got, ok := v.Value().(int32)
		if !ok {
			t.Fatalf("Scalar.Int32 type %T, want int32", v.Value())
		}
		const want int32 = -123456789
		if got != want {
			t.Errorf("Scalar.Int32: got %d, want %d", got, want)
		}
	})
}

func TestAsyncOpcuaServer_SecureChannelRenewal(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/security.channel.renewal/go-client-to-async-opcua-server", func(t *testing.T) {
		h := startAsyncOpcuaSecureServer(t)
		assertClientChannelRenewal(t, h.endpoint)
	})
}

func TestGoServer_AsyncOpcuaClient_SecureChannelRenewal(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/security.channel.renewal/async-opcua-client-to-go-server", func(t *testing.T) {
		assertPeerChannelRenewal(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, "async-opcua-client")
	})
}

// ---------------------------------------------------------------------------
// History (history_*_peer_test.go, extended_peer_test.go)
// ---------------------------------------------------------------------------

func TestAsyncOpcuaServer_HistoryReadRaw(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/history.read.raw/go-client-to-async-opcua-server", func(t *testing.T) {
		h := startAsyncOpcuaServer(t)
		requirePeerNode(t, h.endpoint, "History.Temperature")
		assertPeerHistoryRaw(t, h.endpoint)
	})
}

func TestAsyncOpcuaServer_HistoryReadContinuation(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/history.read.continuation/go-client-to-async-opcua-server", func(t *testing.T) {
		h := startAsyncOpcuaServer(t)
		requirePeerNode(t, h.endpoint, "History.Temperature")
		// The async-opcua server keeps history continuation points per
		// session and honours ReleaseContinuationPoints.
		assertPeerHistoryContinuation(t, h.endpoint, true)
	})
}

func TestGoServer_AsyncOpcuaClient_HistoryReadRaw(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/history.read.raw/async-opcua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, "history-read")
		endpoint, _, _ := startGoServerWithHistory(t)
		node := "nsu=" + interopNamespaceURI + ";s=History.Temperature"
		result := runAsyncOpcuaClientResult(t, endpoint, "history-read",
			"--node", node,
			"--start", "2026-07-24T10:00:00Z",
			"--end", "2026-07-24T10:00:20Z",
			"--num-values", "5",
		)
		if !result.Success {
			t.Fatalf("history-read failed: %+v", result)
		}
	})
}

func TestGoServer_AsyncOpcuaClient_HistoryReadContinuation(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/history.read.continuation/async-opcua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, "history-read")
		requireHistoryContinueScenario(t, asyncOpcuaEnv, defaultAsyncOpcuaImage)
		endpoint, _, _ := startGoServerWithHistory(t)
		assertHistoryContinuation(t, endpoint, runAsyncOpcuaClientResult)
	})
}

// ---------------------------------------------------------------------------
// Register nodes, node management (extended_peer_test.go)
// ---------------------------------------------------------------------------

func TestAsyncOpcuaServer_RegisterNodes(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/view.register-nodes/go-client-to-async-opcua-server", func(t *testing.T) {
		h := startAsyncOpcuaServer(t)
		assertClientRegisterNodes(t, h.endpoint)
	})
}

func TestGoServer_AsyncOpcuaClient_RegisterNodes(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/view.register-nodes/async-opcua-client-to-go-server", func(t *testing.T) {
		assertPeerRegisterNodes(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, runAsyncOpcuaClientResult)
	})
}

func TestAsyncOpcuaServer_AddNodes(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/nodemgmt.add-nodes/go-client-to-async-opcua-server", func(t *testing.T) {
		requireServerFeature(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, "node-management")
		h := startAsyncOpcuaServer(t)
		assertClientNodeManagement(t, h.endpoint, false)
	})
}

func TestAsyncOpcuaServer_DeleteNodes(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/nodemgmt.delete-nodes/go-client-to-async-opcua-server", func(t *testing.T) {
		requireServerFeature(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, "node-management")
		h := startAsyncOpcuaServer(t)
		assertClientNodeManagement(t, h.endpoint, true)
	})
}

func TestGoServer_AsyncOpcuaClient_AddNodes(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/nodemgmt.add-nodes/async-opcua-client-to-go-server", func(t *testing.T) {
		assertPeerAddNodes(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, runAsyncOpcuaClientResult)
	})
}

func TestGoServer_AsyncOpcuaClient_DeleteNodes(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/nodemgmt.delete-nodes/async-opcua-client-to-go-server", func(t *testing.T) {
		assertPeerDeleteNodes(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, runAsyncOpcuaClientResult)
	})
}

// ---------------------------------------------------------------------------
// Subscriptions (subscription_*_peer_test.go, extended_peer_test.go)
// ---------------------------------------------------------------------------

func TestAsyncOpcuaServer_ModifySubscription(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/subscription.modify/go-client-to-async-opcua-server", func(t *testing.T) {
		assertClientModifySubscription(t, startAsyncOpcuaServer(t).endpoint)
	})
}

func TestAsyncOpcuaServer_ModifyMonitoredItems(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/monitoreditem.modify/go-client-to-async-opcua-server", func(t *testing.T) {
		assertClientModifyMonitoredItems(t, startAsyncOpcuaServer(t).endpoint)
	})
}

func TestAsyncOpcuaServer_SetMonitoringMode(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/monitoreditem.monitoring-mode/go-client-to-async-opcua-server", func(t *testing.T) {
		assertClientSetMonitoringMode(t, startAsyncOpcuaServer(t).endpoint)
	})
}

func TestAsyncOpcuaServer_SubscribeTimestampsToReturn(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/subscription.timestamps/go-client-to-async-opcua-server", func(t *testing.T) {
		h := startAsyncOpcuaServer(t)
		assertPeerSubscribeTimestamps(t, h.endpoint)
	})
}

func TestGoServer_AsyncOpcuaClient_SubscribeTimestamps(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/subscription.timestamps/async-opcua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, "subscribe")
		endpoint := startGoServer(t)
		assertAdapterSubscribeTimestamps(t, endpoint, runAsyncOpcuaClientResult)
	})
}

func TestAsyncOpcuaServer_SubscriptionRecoveryReconnect(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/subscription.recovery.reconnect/go-client-to-async-opcua-server", func(t *testing.T) {
		h := startAsyncOpcuaServer(t)
		outcome := runReconnectRecovery(t, h.endpoint)
		t.Logf("async-opcua recovery outcome=%s", outcome)
		if outcome == "" {
			t.Fatal("empty recovery outcome")
		}
	})
}

// qualifyAsyncOpcuaSubscriptionService is qualifyMiloSubscriptionService for
// the async-opcua server: any defined StatusCode other than
// BadServiceUnsupported / BadNotImplemented proves the service path exists.
func qualifyAsyncOpcuaSubscriptionService(t *testing.T, kind string) (status string, detail string) {
	t.Helper()
	h := startAsyncOpcuaServer(t)
	c := dialClient(t, h.endpoint)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	notifyCh := make(chan *opcua.PublishNotificationData, 4)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 200 * time.Millisecond}, notifyCh)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	unsupported := func(msg string) bool {
		return strings.Contains(msg, "BadServiceUnsupported") || strings.Contains(msg, "BadNotImplemented")
	}
	switch kind {
	case "republish":
		_, err = c.Republish(ctx, sub.SubscriptionID, 1)
		if err == nil {
			return "verified", "Republish returned nil error"
		}
		if unsupported(err.Error()) {
			return "unsupported", err.Error()
		}
		return "verified", err.Error()
	case "transfer":
		resp, err := c.TransferSubscriptions(ctx, []uint32{sub.SubscriptionID}, false)
		if err != nil {
			if unsupported(err.Error()) {
				return "unsupported", err.Error()
			}
			return "verified", err.Error()
		}
		if resp == nil {
			t.Fatal("TransferSubscriptions: nil response")
		}
		sc := ua.StatusOK
		if resp.ResponseHeader != nil {
			sc = resp.ResponseHeader.ServiceResult
		}
		if len(resp.Results) > 0 {
			sc = resp.Results[0].StatusCode
		}
		if sc == ua.StatusBadServiceUnsupported || sc == ua.StatusBadNotImplemented {
			return "unsupported", sc.Error()
		}
		return "verified", sc.Error()
	default:
		t.Fatalf("unknown qualify kind %q", kind)
		return "", ""
	}
}

func TestAsyncOpcuaServer_ClientRepublish(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/subscription.client.republish/go-client-to-async-opcua-server", func(t *testing.T) {
		status, detail := qualifyAsyncOpcuaSubscriptionService(t, "republish")
		t.Logf("async-opcua Republish qualification: status=%s detail=%s", status, detail)
		if status != "verified" {
			t.Fatalf("Republish not served: %s (%s)", status, detail)
		}
	})
}

func TestAsyncOpcuaServer_ClientTransferSubscriptions(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/subscription.client.transfer/go-client-to-async-opcua-server", func(t *testing.T) {
		status, detail := qualifyAsyncOpcuaSubscriptionService(t, "transfer")
		t.Logf("async-opcua TransferSubscriptions qualification: status=%s detail=%s", status, detail)
		if status != "verified" {
			t.Fatalf("TransferSubscriptions not served: %s (%s)", status, detail)
		}
	})
}

func TestGoServer_AsyncOpcuaClient_Republish(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/subscription.server.republish/async-opcua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, "republish")
		endpoint := startGoServer(t)
		result := runAsyncOpcuaClientResult(t, endpoint, "republish",
			"--subscription-id", "1",
			"--sequence-number", "1",
		)
		if result.ServiceResult.Name == "" {
			t.Fatalf("expected serviceResult from republish: %+v", result)
		}
	})
}

func TestGoServer_AsyncOpcuaClient_TransferSubscriptions(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/subscription.server.transfer/async-opcua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, "transfer-subscriptions")
		endpoint := startGoServer(t)
		result := runAsyncOpcuaClientResult(t, endpoint, "transfer-subscriptions",
			"--subscription-id", "1",
			"--send-initial-values", "false",
		)
		if result.ServiceResult.Name == "" {
			t.Fatalf("expected serviceResult from transfer-subscriptions: %+v", result)
		}
	})
}

func TestGoServer_AsyncOpcuaClient_SubscribeRevisedFields(t *testing.T) {
	requireAsyncOpcuaImage(t)
	endpoint := startGoServer(t)
	result := runAsyncOpcuaClientResult(t, endpoint, "subscribe",
		"--node", "nsu="+interopNamespaceURI+";s=Dynamic.Counter",
		"--notifications", "1",
		"--publishing-interval-ms", "200",
		"--timeout-ms", "15000",
	)
	assertSubscribeRevisedFields(t, result)
}

func TestGoServer_AsyncOpcuaClient_SubscriptionLifecycle_Revise(t *testing.T) {
	requireAsyncOpcuaImage(t)
	endpoint := startGoServer(t)
	result := runAsyncOpcuaClientResult(t, endpoint, "subscription-lifecycle",
		"--node", "nsu="+interopNamespaceURI+";s=Access.ReadWrite",
		"--scenario", "revise",
		"--timeout-ms", "15000",
	)
	assertReviseLifecycle(t, result)
}

func TestGoServer_AsyncOpcuaClient_SubscriptionLifecycle_Delete(t *testing.T) {
	requireAsyncOpcuaImage(t)
	endpoint := startGoServer(t)
	result := runAsyncOpcuaClientResult(t, endpoint, "subscription-lifecycle",
		"--node", "nsu="+interopNamespaceURI+";s=Access.ReadWrite",
		"--scenario", "delete",
		"--timeout-ms", "15000",
	)
	if !result.Success {
		t.Fatalf("lifecycle delete failed: serviceResult=%s error=%s raw=%s",
			result.ServiceResult, result.Error, result.Results)
	}
}

func TestGoServer_AsyncOpcuaClient_SubscriptionLifecycle_PublishingMode(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/subscription.publishing-mode/async-opcua-client-to-go-server", func(t *testing.T) {
		assertPeerPublishingMode(t, runAsyncOpcuaClientResult)
	})
}

func TestGoServer_AsyncOpcuaClient_SubscriptionLifecycle_MonitoringMode(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/monitoreditem.monitoring-mode/async-opcua-client-to-go-server", func(t *testing.T) {
		assertPeerMonitoringMode(t, runAsyncOpcuaClientResult)
	})
}

// ---------------------------------------------------------------------------
// Events (events_*_test.go, extended_peer_test.go)
// ---------------------------------------------------------------------------

func TestAsyncOpcuaServer_EventSubscription(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/event.subscription/go-client-to-async-opcua-server", func(t *testing.T) {
		h := startAsyncOpcuaServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		ef := subscribePeerBaseEvent(t, h.endpoint, false, false)
		assertPeerBaseEventFields(t, ef)
	})
}

func TestAsyncOpcuaServer_EventNotificationDecode(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/event.notification.decode/go-client-to-async-opcua-server", func(t *testing.T) {
		h := startAsyncOpcuaServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		ef := subscribePeerBaseEvent(t, h.endpoint, false, false)
		assertPeerBaseEventFields(t, ef)
	})
}

func TestAsyncOpcuaServer_EventFilterSelectClauses(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/event.filter.select-clauses/go-client-to-async-opcua-server", func(t *testing.T) {
		h := startAsyncOpcuaServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		ef := subscribePeerBaseEvent(t, h.endpoint, false, false)
		if len(ef.EventFields) < 6 {
			t.Fatalf("selectClauses fields=%d, want >=6", len(ef.EventFields))
		}
	})
}

func TestAsyncOpcuaServer_EventFilterOfType(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/event.filter.of-type/go-client-to-async-opcua-server", func(t *testing.T) {
		h := startAsyncOpcuaServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		ef := subscribePeerBaseEvent(t, h.endpoint, true, false)
		assertPeerBaseEventFields(t, ef)
	})
}

func TestAsyncOpcuaServer_EventFilterSeverityThreshold(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/event.filter.severity-threshold/go-client-to-async-opcua-server", func(t *testing.T) {
		h := startAsyncOpcuaServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		ef := subscribePeerBaseEvent(t, h.endpoint, false, true)
		assertPeerBaseEventFields(t, ef)
	})
}

func TestAsyncOpcuaServer_EventFilterWhereClause(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/event.filter.where-clause/go-client-to-async-opcua-server", func(t *testing.T) {
		h := startAsyncOpcuaServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		assertPeerEventWhereClause(t, h.endpoint)
	})
}

// TestAsyncOpcuaServer_EventQueueOverflow is assertPeerEventQueueOverflow
// with one difference: async-opcua 0.19 does not generate the
// EventQueueOverflowEventType event (its MonitoredItem only sets the overflow
// bit of DataValue notifications, async-opcua-server/src/subscriptions/
// monitored_item.rs), so a batch of exactly queueSize events without an
// overflow event skips with that reason instead of failing.
func TestAsyncOpcuaServer_EventQueueOverflow(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/event.queue-overflow/go-client-to-async-opcua-server", func(t *testing.T) {
		h := startAsyncOpcuaServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		c := dialClient(t, h.endpoint)
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		_, nsIdx := findNS(t, c)

		notifyCh := make(chan *opcua.PublishNotificationData, 64)
		sub, _, err := c.NewSubscription().
			Interval(9 * time.Second).
			NotifyChannel(notifyCh).
			Start(ctx)
		if err != nil {
			t.Fatalf("Subscribe: %v", err)
		}
		t.Cleanup(func() { _ = sub.Cancel(context.Background()) })

		const queueSize = 2
		filter := ua.NewEventFilter().Select("EventType", "Severity").Build()
		resp, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, &ua.MonitoredItemCreateRequest{
			ItemToMonitor:  &ua.ReadValueID{NodeID: ua.NewStringNodeID(nsIdx, "Events.Source"), AttributeID: ua.AttributeIDEventNotifier},
			MonitoringMode: ua.MonitoringModeReporting,
			RequestedParameters: &ua.MonitoringParameters{
				ClientHandle:  1,
				Filter:        ua.NewExtensionObject(filter),
				QueueSize:     queueSize,
				DiscardOldest: true,
			},
		})
		if err != nil {
			t.Fatalf("Monitor: %v", err)
		}
		if len(resp.Results) != 1 || resp.Results[0].StatusCode != ua.StatusOK {
			t.Fatalf("monitor result: %+v", resp.Results)
		}
		if resp.Results[0].RevisedQueueSize != queueSize {
			t.Fatalf("revisedQueueSize=%d, want %d", resp.Results[0].RevisedQueueSize, queueSize)
		}
		overflowType := ua.NewNumericNodeID(0, id.EventQueueOverflowEventType)
		deadline := time.After(30 * time.Second)
		for {
			select {
			case msg := <-notifyCh:
				if msg.Error != nil {
					t.Fatalf("notification error: %v", msg.Error)
				}
				enl, ok := msg.Value.(*ua.EventNotificationList)
				if !ok || enl == nil || len(enl.Events) == 0 {
					continue
				}
				overflows := 0
				for _, ev := range enl.Events {
					if typ, ok := ev.EventFields[0].Value().(*ua.NodeID); ok && typ.String() == overflowType.String() {
						overflows++
					}
				}
				if len(enl.Events) == queueSize && overflows == 0 {
					t.Skipf("async-opcua 0.19 discards the oldest events of a full queue without an EventQueueOverflowEventType event (batch of %d): stack deviation", len(enl.Events))
				}
				if len(enl.Events) != queueSize+1 || overflows != 1 {
					t.Fatalf("batch of %d events with %d overflow events, want overflow event + %d queued", len(enl.Events), overflows, queueSize)
				}
				return
			case <-deadline:
				t.Fatal("no event batch within 30s")
			}
		}
	})
}

func TestGoServer_AsyncOpcuaClient_EventSubscribe(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/event.subscription/async-opcua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, "event-subscribe")
		endpoint, srv := startGoServerWithEvents(t)
		result := runPeerEventSubscribe(t, endpoint, srv, runAsyncOpcuaClientResult)
		assertPeerEventPayload(t, parseEventSubscribeItem(t, result))
	})
}

func TestGoServer_AsyncOpcuaClient_EventEmissionBase(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/event.emission.base/async-opcua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, "event-subscribe")
		endpoint, srv := startGoServerWithEvents(t)
		result := runPeerEventSubscribe(t, endpoint, srv, runAsyncOpcuaClientResult)
		item := parseEventSubscribeItem(t, result)
		if len(item.Events) < 1 {
			t.Fatal("EventEmissionBase: no events received")
		}
		assertPeerEventPayload(t, item)
	})
}

func TestGoServer_AsyncOpcuaClient_EventFilterSelectClauses(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/event.filter.select-clauses/async-opcua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, "event-subscribe")
		endpoint, srv := startGoServerWithEvents(t)
		result := runPeerEventSubscribe(t, endpoint, srv, runAsyncOpcuaClientResult)
		item := parseEventSubscribeItem(t, result)
		assertSelectClauses(t, item.SelectClauses)
		for _, want := range baseEventSelectClauses {
			found := false
			for _, g := range item.SelectClauses {
				if g == want {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("selectClauses missing contract field %q; got %v", want, item.SelectClauses)
			}
		}
	})
}

func TestGoServer_AsyncOpcuaClient_EventFilterOfType(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/event.filter.of-type/async-opcua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, "event-subscribe")
		endpoint, srv := startGoServerWithEvents(t)
		result := runPeerEventSubscribeFiltered(t, endpoint, srv, runAsyncOpcuaClientResult,
			"--of-type", "i=2041")
		assertPeerEventPayload(t, parseEventSubscribeItem(t, result))
	})
}

func TestGoServer_AsyncOpcuaClient_EventFilterSeverityThreshold(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/event.filter.severity-threshold/async-opcua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, "event-subscribe")
		endpoint, srv := startGoServerWithEvents(t)
		result := runPeerEventSubscribeFiltered(t, endpoint, srv, runAsyncOpcuaClientResult,
			"--min-severity", "100")
		assertPeerEventPayload(t, parseEventSubscribeItem(t, result))
	})
}

func TestGoServer_AsyncOpcuaClient_EventFilterSeverityRejects(t *testing.T) {
	requireAsyncOpcuaImage(t)
	requireAdapterOp(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, "event-subscribe")
	assertPeerEventSeverityRejects(t, runAsyncOpcuaClientResult)
}

// ---------------------------------------------------------------------------
// Reverse connect (reverse_connect_peer_test.go)
// ---------------------------------------------------------------------------

// TestAsyncOpcuaServer_ReverseConnect: the async-opcua server dials the Go
// client's reverse listener (ReverseHello), the client reads and subscribes
// over that connection.
func TestAsyncOpcuaServer_ReverseConnect(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/transport.reverse-connect/go-client-to-async-opcua-server", func(t *testing.T) {
		requireAdapterFeature(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, "serverFeatures", "reverse-connect")

		var mu sync.Mutex
		var hellos []uacp.ReverseHello
		l, err := uacp.ListenReverse(context.Background(), "0.0.0.0:0", &uacp.ReverseListenerConfig{
			Filter: func(rhe *uacp.ReverseHello) error {
				mu.Lock()
				hellos = append(hellos, *rhe)
				mu.Unlock()
				return nil
			},
		})
		if err != nil {
			t.Fatalf("ListenReverse: %v", err)
		}
		t.Cleanup(func() { _ = l.Close() })

		startAdapterReverseServer(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, l.Addr().(*net.TCPAddr).Port)

		ctx, cancel := context.WithTimeout(context.Background(), 2*reverseDialTimeout)
		defer cancel()
		c, err := opcua.NewClient("",
			opcua.SecurityModeString("None"),
			opcua.AuthAnonymous(),
			opcua.DialTimeout(reverseDialTimeout),
			opcua.AutoReconnect(false),
			opcua.ReverseConnectListener(l),
		)
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		if err := c.Connect(ctx); err != nil {
			t.Fatalf("Connect over reverse connection: %v", err)
		}
		t.Cleanup(func() {
			ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel2()
			_ = c.Close(ctx2)
		})

		mu.Lock()
		if len(hellos) == 0 {
			mu.Unlock()
			t.Fatal("no ReverseHello recorded")
		}
		rhe := hellos[len(hellos)-1]
		mu.Unlock()
		t.Logf("ReverseHello: ServerUri=%q EndpointUrl=%q", rhe.ServerURI, rhe.EndpointURL)
		eps := c.Session().ServerEndpoints()
		if len(eps) == 0 {
			t.Fatal("no server endpoints in the session")
		}
		if appURI := eps[0].Server.ApplicationURI; rhe.ServerURI != appURI {
			t.Errorf("ReverseHello ServerUri = %q, want the server's ApplicationUri %q", rhe.ServerURI, appURI)
		}

		_, nsIdx := findNS(t, c)
		dv, err := c.ReadValue(ctx, ua.NewStringNodeID(nsIdx, "Scalar.Int32"))
		if err != nil {
			t.Fatalf("Read Scalar.Int32: %v", err)
		}
		if got, ok := dv.Value.Value().(int32); !ok || got != -123456789 {
			t.Errorf("Scalar.Int32 = %v, want -123456789", dv.Value.Value())
		}
		sub, notifyCh, err := c.NewSubscription().
			Interval(200 * time.Millisecond).
			Monitor(ua.NewStringNodeID(nsIdx, "Dynamic.Counter")).
			Start(ctx)
		if err != nil {
			t.Fatalf("Subscribe Dynamic.Counter: %v", err)
		}
		last := awaitCounterAdvance(t, notifyCh, -1, 30*time.Second, "first sample")
		for i := range 3 {
			last = awaitCounterAdvance(t, notifyCh, last, 30*time.Second, fmt.Sprintf("advance %d", i+1))
		}
		_ = sub.Cancel(ctx)
	})
}

func TestGoServer_AsyncOpcuaClient_ReverseConnect_Read(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/transport.reverse-connect/async-opcua-client-to-go-server", func(t *testing.T) {
		requireAdapterFeature(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, "clientFeatures", "reverse-listen")
		endpoint, hostPort, rc, counter := reverseGoServer(t)
		result := runAdapterReverseClient(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, endpoint, hostPort, "read",
			"--node", "nsu="+interopNamespaceURI+";s=Scalar.Int32",
		)
		if !result.Success {
			t.Fatalf("read over reverse connection failed: serviceResult=%s error=%s (target: %s, %v)",
				result.ServiceResult, result.Error, rc.State(), rc.Err())
		}
		var items []struct {
			Value json.RawMessage `json:"value"`
		}
		if err := json.Unmarshal(result.Results, &items); err != nil || len(items) == 0 {
			t.Fatalf("parse read results: %v; raw: %s", err, result.Results)
		}
		if !strings.Contains(string(items[0].Value), "-123456789") {
			t.Errorf("Scalar.Int32 = %s, want -123456789", items[0].Value)
		}
		requireOnlyReverseConnections(t, counter)
	})
}

func TestGoServer_AsyncOpcuaClient_ReverseConnect_Subscribe(t *testing.T) {
	requireAsyncOpcuaImage(t)
	requireAdapterFeature(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, "clientFeatures", "reverse-listen")
	endpoint, hostPort, rc, counter := reverseGoServer(t)
	result := runAdapterReverseClient(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, endpoint, hostPort, "subscribe",
		"--node", "nsu="+interopNamespaceURI+";s=Dynamic.Counter",
		"--notifications", "3",
		"--publishing-interval-ms", "300",
		"--sampling-interval-ms", "100",
		"--timeout-ms", "30000",
	)
	if !result.Success {
		t.Fatalf("subscribe over reverse connection failed: serviceResult=%s error=%s (target: %s, %v)",
			result.ServiceResult, result.Error, rc.State(), rc.Err())
	}
	var items []struct {
		Notifications json.RawMessage `json:"notifications"`
	}
	if err := json.Unmarshal(result.Results, &items); err != nil || len(items) == 0 {
		t.Fatalf("parse subscribe results: %v; raw: %s", err, result.Results)
	}
	vals := parseNotificationValues(t, items[0].Notifications)
	if len(vals) < 3 {
		t.Errorf("expected at least 3 notifications, got %d: %v", len(vals), vals)
	}
	requireOnlyReverseConnections(t, counter)
}

// TestAsyncOpcuaServer_ReverseConnect_Secure: the async-opcua server dials
// the listening Go client, which reads the endpoints over one reverse
// connection and opens a Basic256Sha256/SignAndEncrypt channel on the next
// (async-opcua 0.19 has no ECC policies, so only the RSA case applies).
func TestAsyncOpcuaServer_ReverseConnect_Secure(t *testing.T) {
	requireAsyncOpcuaImage(t)
	requireAdapterFeature(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, "serverFeatures", "reverse-connect")
	t.Run("coverage/transport.reverse-connect.secure/go-client-to-async-opcua-server/Basic256Sha256", func(t *testing.T) {
		l, err := uacp.ListenReverse(context.Background(), "0.0.0.0:0", nil)
		if err != nil {
			t.Fatalf("ListenReverse: %v", err)
		}
		t.Cleanup(func() { _ = l.Close() })
		startAsyncOpcuaSecureReverseServer(t, l.Addr().(*net.TCPAddr).Port)

		ctx, cancel := context.WithTimeout(context.Background(), 2*reverseDialTimeout)
		defer cancel()
		base := []opcua.Option{
			opcua.DialTimeout(reverseDialTimeout),
			opcua.AutoReconnect(false),
			opcua.ReverseConnectListener(l),
		}
		eps, err := opcua.GetEndpoints(ctx, "", append([]opcua.Option{opcua.SecurityModeString("None"), opcua.AuthAnonymous()}, base...)...)
		if err != nil {
			t.Fatalf("GetEndpoints over a reverse connection: %v", err)
		}
		var ep *ua.EndpointDescription
		for _, e := range eps {
			if e.SecurityPolicyURI == ua.SecurityPolicyURIBasic256Sha256 && e.SecurityMode == ua.MessageSecurityModeSignAndEncrypt {
				ep = e
			}
		}
		if ep == nil {
			t.Fatalf("the server does not offer Basic256Sha256/SignAndEncrypt over the reverse connection (%d endpoints)", len(eps))
		}
		pki := pkiDir(t)
		c, err := opcua.NewClient("", append([]opcua.Option{
			opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous),
			opcua.CertificateFile(filepath.Join(pki, "consumer", "cert.crt")),
			opcua.PrivateKeyFile(filepath.Join(pki, "consumer", "cert.key")),
			opcua.TrustedCertificates(loadCACert(t, filepath.Join(pki, "ca", "ca.crt"))),
			opcua.AuthAnonymous(),
		}, base...)...)
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		if err := c.Connect(ctx); err != nil {
			t.Fatalf("Connect Basic256Sha256/SignAndEncrypt over a reverse connection: %v", err)
		}
		defer func() {
			ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel2()
			_ = c.Close(ctx2)
		}()
		if got := c.SecurityPolicy(); got != ua.SecurityPolicyURIBasic256Sha256 {
			t.Fatalf("connected with %s, want Basic256Sha256", got)
		}
		_, nsIdx := findNS(t, c)
		dv, err := c.ReadValue(ctx, ua.NewStringNodeID(nsIdx, "Scalar.Int32"))
		if err != nil {
			t.Fatalf("Read Scalar.Int32: %v", err)
		}
		if got, ok := dv.Value.Value().(int32); !ok || got != -123456789 {
			t.Errorf("Scalar.Int32 = %v, want -123456789", dv.Value.Value())
		}
	})
}

// TestGoServer_AsyncOpcuaClient_ReverseConnect_Secure: the Go server dials
// the listening async-opcua client, which subscribes over a
// Basic256Sha256/SignAndEncrypt channel on the connections the server opened.
func TestGoServer_AsyncOpcuaClient_ReverseConnect_Secure(t *testing.T) {
	requireAsyncOpcuaImage(t)
	requireAdapterFeature(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, "clientFeatures", "reverse-listen")
	t.Run("coverage/transport.reverse-connect.secure/async-opcua-client-to-go-server/Basic256Sha256", func(t *testing.T) {
		endpoint, hostPort, target, counter := reverseGoServer(t,
			server.Certificate(loadGoServerCert(t)),
			server.PrivateKey(loadGoServerKey(t)),
			server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		)
		pki := pkiDir(t)
		mounts := []string{
			"-v", filepath.Join(pki, "async-opcua-client", "cert.crt") + ":/certs/cert.crt:ro",
			"-v", filepath.Join(pki, "async-opcua-client", "cert.key") + ":/certs/cert.key:ro",
			"-v", filepath.Join(pki, "ca", "ca.crt") + ":/certs/ca.crt:ro",
		}
		result := runAdapterReverseClientWith(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, endpoint, hostPort, mounts, "subscribe",
			"--security-policy", "Basic256Sha256", "--security-mode", "SignAndEncrypt",
			"--certificate", "/certs/cert.crt", "--private-key", "/certs/cert.key", "--trust-list", "/certs/ca.crt",
			"--node", "nsu="+interopNamespaceURI+";s=Dynamic.Counter",
			"--notifications", "3",
			"--publishing-interval-ms", "300",
			"--sampling-interval-ms", "100",
			"--timeout-ms", "30000",
		)
		if !result.Success {
			t.Fatalf("subscribe over a secured reverse connection failed: serviceResult=%s error=%s (target: %s, %v)",
				result.ServiceResult, result.Error, target.State(), target.Err())
		}
		var items []struct {
			Notifications json.RawMessage `json:"notifications"`
		}
		if err := json.Unmarshal(result.Results, &items); err != nil || len(items) == 0 {
			t.Fatalf("parse subscribe results: %v; raw: %s", err, result.Results)
		}
		if vals := parseNotificationValues(t, items[0].Notifications); len(vals) < 3 {
			t.Errorf("expected at least 3 notifications, got %d: %v", len(vals), vals)
		}
		requireOnlyReverseConnections(t, counter)
	})
}

// ---------------------------------------------------------------------------
// PubSub: async-opcua 0.19 has no Part 14 implementation
// ---------------------------------------------------------------------------

// TestPubSub_AsyncOpcuaHasNoPubSub pins the reason the PubSub rows of the
// async-opcua directions are unsupported: the adapter declares
// pubsub.supported=false and refuses --pubsub-config and codec pubsub-*.
func TestPubSub_AsyncOpcuaHasNoPubSub(t *testing.T) {
	caps, image := imageCapabilities(t, asyncOpcuaEnv, defaultAsyncOpcuaImage)
	requirePinnedVersion(t, asyncOpcuaEnv, caps, image)
	raw, err := printCapabilities(image)
	if err != nil {
		t.Fatalf("print-capabilities: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	var doc struct {
		PubSub *struct {
			Supported bool   `json:"supported"`
			Reason    string `json:"reason"`
		} `json:"pubsub"`
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &doc); err != nil {
		t.Fatalf("print-capabilities: %v", err)
	}
	if doc.PubSub == nil {
		t.Fatal("the async-opcua adapter does not declare pubsub")
	}
	if doc.PubSub.Supported {
		t.Fatalf("the async-opcua adapter declares PubSub support: add the pubsub rows to the ledger")
	}
	t.Logf("async-opcua: %s", doc.PubSub.Reason)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "docker", "run", "--rm", image, "client", "codec", "pubsub-uadp-decode", "--document", "AQ==").Output()
	r, err := parseAdapterOutput(out)
	if err != nil {
		t.Fatalf("codec pubsub-uadp-decode: %v\nraw: %s", err, out)
	}
	if r.Success {
		t.Errorf("the async-opcua adapter ran codec pubsub-uadp-decode: %+v", r)
	}
	srvOut, err := exec.CommandContext(ctx, "docker", "run", "--rm", image, "server",
		"--fixture", "/fixtures/fixture.json", "--pubsub-config", "/dev/null").CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 2 {
		t.Errorf("server --pubsub-config: err=%v, want exit 2\n%s", err, srvOut)
	}
}

// ---------------------------------------------------------------------------
// C→P services (c2p_services_peer_test.go): chunked secure messages,
// SetTriggering, TransferSubscriptions identity rules, AddReferences /
// DeleteReferences, server diagnostics
// ---------------------------------------------------------------------------

func TestAsyncOpcuaServer_ChunkedSecureMessages(t *testing.T) {
	t.Run("coverage/transport.chunking.secure/go-client-to-async-opcua-server", func(t *testing.T) {
		assertPeerChunkedSecure(t, startAsyncOpcuaSecureServer(t).endpoint)
	})
}

func TestAsyncOpcuaServer_SetTriggering(t *testing.T) {
	t.Run("coverage/monitoreditem.set-triggering/go-client-to-async-opcua-server", func(t *testing.T) {
		requireSetTriggering(t, startAsyncOpcuaServer(t).endpoint)
	})
}

func TestAsyncOpcuaServer_TransferSubscriptionsIdentity(t *testing.T) {
	t.Run("coverage/subscription.client.transfer.anonymous/go-client-to-async-opcua-server", func(t *testing.T) {
		assertPeerTransferAnonymous(t, startAsyncOpcuaSecureServer(t).endpoint, ua.StatusOK)
	})
	t.Run("coverage/subscription.client.transfer.other-identity/go-client-to-async-opcua-server", func(t *testing.T) {
		assertPeerTransferOtherIdentity(t, startAsyncOpcuaSecureServer(t).endpoint, ua.StatusBadUserAccessDenied)
	})
}

// TestAsyncOpcuaServer_ReferencesUnsupported pins why nodemgmt.*-references
// are unsupported for async-opcua: its server implements AddNodes and
// DeleteNodes, but answers AddReferences / DeleteReferences operations with
// BadServiceUnsupported.
func TestAsyncOpcuaServer_ReferencesUnsupported(t *testing.T) {
	assertPeerReferencesRefused(t, startAsyncOpcuaServer(t).endpoint)
}

func TestAsyncOpcuaServer_Diagnostics(t *testing.T) {
	h := startAsyncOpcuaServer(t)
	t.Run("coverage/diagnostics.server-summary/go-client-to-async-opcua-server", func(t *testing.T) {
		assertPeerServerDiagnostics(t, h.endpoint)
	})
	t.Run("coverage/diagnostics.return-diagnostics/go-client-to-async-opcua-server", func(t *testing.T) {
		assertPeerReturnDiagnostics(t, h.endpoint)
	})
}

// Server diagnostics of go-opcua read by the peer client
// (assertGoServerDiagnosticsFromPeer, diagnostics_peer_test.go).
func TestGoServer_AsyncOpcuaClient_Diagnostics(t *testing.T) {
	requireAsyncOpcuaImage(t)
	t.Run("coverage/diagnostics.server-summary/async-opcua-client-to-go-server", func(t *testing.T) {
		assertGoServerDiagnosticsFromPeer(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, runAsyncOpcuaClientResult)
	})
}
