//go:build interop

// SPDX-License-Identifier: MIT

// asyncua (opcua-asyncio) peer for the capability tests that are shared by
// all peers (the *_peer_test.go helpers), both directions:
// go-client-to-asyncua-server and asyncua-client-to-go-server.
// Generated from the Asyncua peer tests, then adjusted where asyncua differs
// (see asyncuaDeviation and the opcua-interop asyncua/README.md).

package interop

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

func TestAsyncuaServer_FindServers(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/discovery.find-servers/go-client-to-asyncua-server", func(t *testing.T) {
		h := startAsyncuaServer(t)
		ctx := shortTestCtx(t)
		servers, err := opcua.FindServers(ctx, h.endpoint)
		if err != nil {
			t.Fatalf("FindServers: %v", err)
		}
		assertFindServersResult(t, servers)
	})
}

func TestGoServer_AsyncuaClient_FindServers(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/discovery.find-servers/asyncua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, asyncuaEnv, defaultAsyncuaImage, "find-servers")
		endpoint := startGoServer(t)
		result := runAsyncuaClient(t, endpoint, "find-servers")
		assertAdapterFindServers(t, result)
	})
}

func TestGoServer_AsyncuaClient_EventSubscribe(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/event.subscription/asyncua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, asyncuaEnv, defaultAsyncuaImage, "event-subscribe")
		endpoint, srv := startGoServerWithEvents(t)
		result := runPeerEventSubscribe(t, endpoint, srv, runAsyncuaClientResult)
		assertPeerEventPayload(t, parseEventSubscribeItem(t, result))
	})
}

func TestGoServer_AsyncuaClient_EventEmissionBase(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/event.emission.base/asyncua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, asyncuaEnv, defaultAsyncuaImage, "event-subscribe")
		endpoint, srv := startGoServerWithEvents(t)
		result := runPeerEventSubscribe(t, endpoint, srv, runAsyncuaClientResult)
		item := parseEventSubscribeItem(t, result)
		if len(item.Events) < 1 {
			t.Fatal("EventEmissionBase: no events received")
		}
		assertPeerEventPayload(t, item)
	})
}

func TestGoServer_AsyncuaClient_EventFilterSelectClauses(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/event.filter.select-clauses/asyncua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, asyncuaEnv, defaultAsyncuaImage, "event-subscribe")
		endpoint, srv := startGoServerWithEvents(t)
		result := runPeerEventSubscribe(t, endpoint, srv, runAsyncuaClientResult)
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

func TestGoServer_AsyncuaClient_EventFilterOfType(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/event.filter.of-type/asyncua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, asyncuaEnv, defaultAsyncuaImage, "event-subscribe")
		endpoint, srv := startGoServerWithEvents(t)
		result := runPeerEventSubscribeFiltered(t, endpoint, srv, runAsyncuaClientResult,
			"--of-type", "i=2041")
		assertPeerEventPayload(t, parseEventSubscribeItem(t, result))
	})
}

func TestGoServer_AsyncuaClient_EventFilterSeverityThreshold(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/event.filter.severity-threshold/asyncua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, asyncuaEnv, defaultAsyncuaImage, "event-subscribe")
		endpoint, srv := startGoServerWithEvents(t)
		result := runPeerEventSubscribeFiltered(t, endpoint, srv, runAsyncuaClientResult,
			"--min-severity", "100")
		assertPeerEventPayload(t, parseEventSubscribeItem(t, result))
	})
}

func TestAsyncuaServer_SecureChannelRenewal(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/security.channel.renewal/go-client-to-asyncua-server", func(t *testing.T) {
		h := startAsyncuaSecureServer(t)
		assertClientChannelRenewal(t, h.endpoint)
	})
}

func TestGoServer_AsyncuaClient_SecureChannelRenewal(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/security.channel.renewal/asyncua-client-to-go-server", func(t *testing.T) {
		assertPeerChannelRenewal(t, asyncuaEnv, defaultAsyncuaImage, asyncuaClientPKI)
	})
}

func TestAsyncuaServer_HistoryReadContinuation(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/history.read.continuation/go-client-to-asyncua-server", func(t *testing.T) {
		h := startAsyncuaServer(t)
		requirePeerNode(t, h.endpoint, "History.Temperature")
		asyncuaProbeHistoryPaging(t, h.endpoint)
		assertPeerHistoryContinuation(t, h.endpoint, false)
	})
}

func TestAsyncuaServer_RegisterNodes(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/view.register-nodes/go-client-to-asyncua-server", func(t *testing.T) {
		h := startAsyncuaServer(t)
		assertClientRegisterNodes(t, h.endpoint)
	})
}

func TestGoServer_AsyncuaClient_RegisterNodes(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/view.register-nodes/asyncua-client-to-go-server", func(t *testing.T) {
		assertPeerRegisterNodes(t, asyncuaEnv, defaultAsyncuaImage, runAsyncuaClientResult)
	})
}

func TestGoServer_AsyncuaClient_AddNodes(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/nodemgmt.add-nodes/asyncua-client-to-go-server", func(t *testing.T) {
		assertPeerAddNodes(t, asyncuaEnv, defaultAsyncuaImage, runAsyncuaClientResult)
	})
}

func TestGoServer_AsyncuaClient_DeleteNodes(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/nodemgmt.delete-nodes/asyncua-client-to-go-server", func(t *testing.T) {
		assertPeerDeleteNodes(t, asyncuaEnv, defaultAsyncuaImage, runAsyncuaClientResult)
	})
}

func TestAsyncuaServer_ModifySubscription(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/subscription.modify/go-client-to-asyncua-server", func(t *testing.T) {
		h := startAsyncuaServer(t)
		asyncuaProbeModifySubscription(t, h.endpoint)
		assertClientModifySubscription(t, h.endpoint)
	})
}

func TestAsyncuaServer_ModifyMonitoredItems(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/monitoreditem.modify/go-client-to-asyncua-server", func(t *testing.T) {
		h := startAsyncuaServer(t)
		asyncuaProbeModifyMonitoredItems(t, h.endpoint)
		assertClientModifyMonitoredItems(t, h.endpoint)
	})
}

func TestAsyncuaServer_SetMonitoringMode(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/monitoreditem.monitoring-mode/go-client-to-asyncua-server", func(t *testing.T) {
		h := startAsyncuaServer(t)
		asyncuaProbeSamplingMode(t, h.endpoint)
		assertClientSetMonitoringMode(t, h.endpoint)
	})
}

func TestAsyncuaServer_EventFilterWhereClause(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/event.filter.where-clause/go-client-to-asyncua-server", func(t *testing.T) {
		h := startAsyncuaServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		assertPeerEventWhereClause(t, h.endpoint)
	})
}

func TestGoServer_AsyncuaClient_SubscriptionLifecycle_PublishingMode(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/subscription.publishing-mode/asyncua-client-to-go-server", func(t *testing.T) {
		assertPeerPublishingMode(t, runAsyncuaClientResult)
	})
}

func TestGoServer_AsyncuaClient_SubscriptionLifecycle_MonitoringMode(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/monitoreditem.monitoring-mode/asyncua-client-to-go-server", func(t *testing.T) {
		assertPeerMonitoringMode(t, runAsyncuaClientResult)
	})
}

func TestGoServer_AsyncuaClient_EventFilterSeverityRejects(t *testing.T) {
	requireAsyncuaImage(t)
	requireAdapterOp(t, asyncuaEnv, defaultAsyncuaImage, "event-subscribe")
	assertPeerEventSeverityRejects(t, runAsyncuaClientResult)
}

func TestAsyncuaServer_EventQueueOverflow(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/event.queue-overflow/go-client-to-asyncua-server", func(t *testing.T) {
		h := startAsyncuaServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		asyncuaProbeEventQueueOverflow(t, h.endpoint)
		assertPeerEventQueueOverflow(t, h.endpoint)
	})
}

func TestGoServer_AsyncuaClient_HistoryReadContinuation(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/history.read.continuation/asyncua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, asyncuaEnv, defaultAsyncuaImage, "history-read")
		requireHistoryContinueScenario(t, asyncuaEnv, defaultAsyncuaImage)
		endpoint, _, _ := startGoServerWithHistory(t)
		assertHistoryContinuation(t, endpoint, runAsyncuaClientResult)
	})
}

func TestGoServer_AsyncuaClient_HistoryReadRaw(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/history.read.raw/asyncua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, asyncuaEnv, defaultAsyncuaImage, "history-read")
		endpoint, _, _ := startGoServerWithHistory(t)
		node := "nsu=" + interopNamespaceURI + ";s=History.Temperature"
		result := runAsyncuaClientResult(t, endpoint, "history-read",
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

func TestAsyncuaServer_MethodValidation(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/method.validation/go-client-to-asyncua-server", func(t *testing.T) {
		h := startAsyncuaServer(t)
		c := dialClient(t, h.endpoint)
		ctx, nsIdx := findNS(t, c)
		assertMethodTooFewArgs(t, c, ctx, nsIdx)
	})
}

func TestGoServer_AsyncuaClient_SubscribeRevisedFields(t *testing.T) {
	requireAsyncuaImage(t)
	endpoint := startGoServer(t)
	result := runAsyncuaClientResult(t, endpoint, "subscribe",
		"--node", "nsu="+interopNamespaceURI+";s=Dynamic.Counter",
		"--notifications", "1",
		"--publishing-interval-ms", "200",
		"--timeout-ms", "15000",
	)
	assertSubscribeRevisedFields(t, result)
}

func TestGoServer_AsyncuaClient_SubscriptionLifecycle_Revise(t *testing.T) {
	requireAsyncuaImage(t)
	endpoint := startGoServer(t)
	result := runAsyncuaClientResult(t, endpoint, "subscription-lifecycle",
		"--node", "nsu="+interopNamespaceURI+";s=Access.ReadWrite",
		"--scenario", "revise",
		"--timeout-ms", "15000",
	)
	assertReviseLifecycle(t, result)
}

func TestGoServer_AsyncuaClient_SubscriptionLifecycle_Delete(t *testing.T) {
	requireAsyncuaImage(t)
	endpoint := startGoServer(t)
	result := runAsyncuaClientResult(t, endpoint, "subscription-lifecycle",
		"--node", "nsu="+interopNamespaceURI+";s=Access.ReadWrite",
		"--scenario", "delete",
		"--timeout-ms", "15000",
	)
	if !result.Success {
		t.Fatalf("lifecycle delete failed: serviceResult=%s error=%s raw=%s",
			result.ServiceResult, result.Error, result.Results)
	}
}

func TestAsyncuaServer_SubscriptionRecoveryReconnect(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/subscription.recovery.reconnect/go-client-to-asyncua-server", func(t *testing.T) {
		h := startAsyncuaServer(t)
		outcome := runReconnectRecovery(t, h.endpoint)
		t.Logf("asyncua recovery outcome=%s", outcome)
		if outcome == "" {
			t.Fatal("empty recovery outcome")
		}
	})
}

func TestAsyncuaServer_TranslateBrowsePath(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/translate.browse-path/go-client-to-asyncua-server", func(t *testing.T) {
		h := startAsyncuaServer(t)
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

func TestGoServer_AsyncuaClient_TranslateBrowsePath(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/translate.browse-path/asyncua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, asyncuaEnv, defaultAsyncuaImage, "translate")
		endpoint := startGoServer(t)
		result := runAsyncuaClient(t, endpoint, "translate",
			"--starting-node", "i=85",
			"--path", "Server",
		)
		assertAdapterTranslateServer(t, result)
	})
}

func TestAsyncuaServer_EventSubscription(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/event.subscription/go-client-to-asyncua-server", func(t *testing.T) {
		h := startAsyncuaServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		ef := subscribePeerBaseEvent(t, h.endpoint, false, false)
		assertPeerBaseEventFields(t, ef)
	})
}

func TestAsyncuaServer_EventNotificationDecode(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/event.notification.decode/go-client-to-asyncua-server", func(t *testing.T) {
		h := startAsyncuaServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		ef := subscribePeerBaseEvent(t, h.endpoint, false, false)
		assertPeerBaseEventFields(t, ef)
	})
}

func TestAsyncuaServer_EventFilterSelectClauses(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/event.filter.select-clauses/go-client-to-asyncua-server", func(t *testing.T) {
		h := startAsyncuaServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		ef := subscribePeerBaseEvent(t, h.endpoint, false, false)
		if len(ef.EventFields) < 6 {
			t.Fatalf("selectClauses fields=%d, want >=6", len(ef.EventFields))
		}
	})
}

func TestAsyncuaServer_EventFilterOfType(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/event.filter.of-type/go-client-to-asyncua-server", func(t *testing.T) {
		h := startAsyncuaServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		ef := subscribePeerBaseEvent(t, h.endpoint, true, false)
		assertPeerBaseEventFields(t, ef)
	})
}

func TestAsyncuaServer_EventFilterSeverityThreshold(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/event.filter.severity-threshold/go-client-to-asyncua-server", func(t *testing.T) {
		h := startAsyncuaServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		ef := subscribePeerBaseEvent(t, h.endpoint, false, true)
		assertPeerBaseEventFields(t, ef)
	})
}

func TestGoServer_AsyncuaClient_Republish(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/subscription.server.republish/asyncua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, asyncuaEnv, defaultAsyncuaImage, "republish")
		endpoint := startGoServer(t)
		result := runAsyncuaClientResult(t, endpoint, "republish",
			"--subscription-id", "1",
			"--sequence-number", "1",
		)
		if result.ServiceResult.Name == "" {
			t.Fatalf("expected serviceResult from republish: %+v", result)
		}
	})
}

func TestGoServer_AsyncuaClient_TransferSubscriptions(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/subscription.server.transfer/asyncua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, asyncuaEnv, defaultAsyncuaImage, "transfer-subscriptions")
		endpoint := startGoServer(t)
		result := runAsyncuaClientResult(t, endpoint, "transfer-subscriptions",
			"--subscription-id", "1",
			"--send-initial-values", "false",
		)
		if result.ServiceResult.Name == "" {
			t.Fatalf("expected serviceResult from transfer-subscriptions: %+v", result)
		}
	})
}

func TestAsyncuaServer_TrustedCert_Accepted(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/security.cert.trusted/go-client-to-asyncua-server", func(t *testing.T) {
		h := startAsyncuaSecureServer(t)
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

func TestAsyncuaServer_HistoryReadRaw(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/history.read.raw/go-client-to-asyncua-server", func(t *testing.T) {
		h := startAsyncuaServer(t)
		requirePeerNode(t, h.endpoint, "History.Temperature")
		assertPeerHistoryRaw(t, h.endpoint)
	})
}

func TestAsyncuaServer_SubscribeTimestampsToReturn(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/subscription.timestamps/go-client-to-asyncua-server", func(t *testing.T) {
		h := startAsyncuaServer(t)
		// The same deviation as TestAsyncuaServer_TimestampsToReturn: the
		// server never reads TimestampsToReturn, for Read or monitored items.
		if mask := asyncuaReadNeitherMask(t, h.endpoint); mask != 0 {
			asyncuaDeviation(t, "the server ignores TimestampsToReturn (asyncua/server never reads it; "+
				"Read with Neither returned timestamp bits %#x): monitored items report both timestamps", mask)
		}
		assertPeerSubscribeTimestamps(t, h.endpoint)
	})
}

func TestGoServer_AsyncuaClient_SubscribeTimestamps(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/subscription.timestamps/asyncua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, asyncuaEnv, defaultAsyncuaImage, "subscribe")
		endpoint := startGoServer(t)
		assertAdapterSubscribeTimestamps(t, endpoint, runAsyncuaClientResult)
	})
}

func TestGoLDS_AsyncuaServerRegisters(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/discovery.lds-registration/asyncua-server-to-go-lds", func(t *testing.T) {
		assertPeerServerRegistersWithGoLDS(t, asyncuaEnv, defaultAsyncuaImage)
	})
}

func TestGoLDS_AsyncuaClient_RegisterServer(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/discovery.register-server/asyncua-client-to-go-lds", func(t *testing.T) {
		assertClientRegistersWithGoLDS(t, asyncuaEnv, defaultAsyncuaImage)
	})
}

// ---------------------------------------------------------------------------
// Hand-written: capabilities where asyncua needs its own gate or check
// ---------------------------------------------------------------------------

// peerDataChangeDeviation lists, per go-client-to-peer direction, the cases
// of assertPeerDataChangeFilter ("deadband", "sampling-interval") whose server
// deviates from Part 4 §7.22.2 / §5.12.1.2; that case skips with the reason,
// the others are asserted.
var peerDataChangeDeviation = map[string]map[string]string{
	dirGoClientToAsyncuaServer: {
		"deadband":          "asyncua 2.1.0 compares the absolute deadband with the previous sample (MonitoredItemService._is_deadband_exceeded), not with the last reported value, so a slow ramp is never reported",
		"sampling-interval": "asyncua 2.1.0 does not sample: it revises the SamplingInterval to the publishing interval (MonitoredItemService, RevisedSamplingInterval = RevisedPublishingInterval) and reports every write of the value",
	},
}

// TestAsyncuaServer_DataChangeFilter: the adapter does not advertise the
// "deadband" / "percent-deadband" server features. asyncua 2.1.0 compares an
// absolute deadband with the previous *sample* (MonitoredItemService.
// _is_deadband_exceeded uses old_dvalue) instead of the last reported value,
// so a slow ramp is never reported (peerDataChangeDeviation), and it accepts
// but ignores percent deadbands (also on nodes without EURange). It does not
// sample at the requested SamplingInterval either. The trigger case is
// asserted.
func TestAsyncuaServer_DataChangeFilter(t *testing.T) {
	requireAsyncuaImage(t)
	h := startAsyncuaServer(t)
	assertPeerDataChangeFilter(t, h.endpoint, dirGoClientToAsyncuaServer)
	t.Run("coverage/monitoreditem.percent-deadband/go-client-to-asyncua-server", func(t *testing.T) {
		asyncuaDeviation(t, "a percent deadband is accepted but not applied, also on a node without EURange (MonitoredItemService); the adapter does not advertise percent-deadband")
	})
}

func TestGoServer_AsyncuaClient_SamplingInterval(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/monitoreditem.sampling-interval/asyncua-client-to-go-server", func(t *testing.T) {
		assertPeerClientSamplingInterval(t, runAsyncuaClient)
	})
}

func TestGoServer_AsyncuaClient_Deadband(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/monitoreditem.deadband/asyncua-client-to-go-server", func(t *testing.T) {
		requireAdapterClientFeature(t, asyncuaEnv, defaultAsyncuaImage, "deadband")
		assertPeerClientDeadband(t, runAsyncuaClient, runAsyncuaClientResult)
	})
}

func TestGoServer_AsyncuaClient_PercentDeadband(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/monitoreditem.percent-deadband/asyncua-client-to-go-server", func(t *testing.T) {
		requireAdapterClientFeature(t, asyncuaEnv, defaultAsyncuaImage, "deadband")
		assertPeerClientPercentDeadband(t, runAsyncuaClient, runAsyncuaClientResult)
	})
}

func TestGoServer_AsyncuaClient_Trigger(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/monitoreditem.trigger/asyncua-client-to-go-server", func(t *testing.T) {
		requireAdapterClientFeature(t, asyncuaEnv, defaultAsyncuaImage, "deadband")
		assertPeerClientTrigger(t, runAsyncuaClient, runAsyncuaClientResult)
	})
}

// TestAsyncuaServer_NodeManagementUnsupported: asyncua serves AddNodes /
// DeleteNodes only to its Admin role, which also bypasses the AccessLevel
// checks on Write; the adapter gives every session the User role, so AddNodes
// is refused. Fails (asking for promotion) if that ever changes.
func TestAsyncuaServer_NodeManagementUnsupported(t *testing.T) {
	requireAsyncuaImage(t)
	h := startAsyncuaServer(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)
	parent := ua.NewStringNodeID(nsIdx, "Compatibility")
	newID := ua.NewStringNodeID(nsIdx, "Interop.GoAdded")
	add, err := c.AddNodes(ctx, addVariableRequest(nsIdx, parent, newID, 1))
	if err == nil && len(add.Results) == 1 && add.Results[0].StatusCode == ua.StatusOK {
		t.Fatal("asyncua accepted AddNodes: promote nodemgmt.add-nodes go-client-to-asyncua-server to a verified test")
	}
	if err != nil {
		if !errors.Is(err, ua.StatusBadUserAccessDenied) {
			t.Errorf("AddNodes: %v, want BadUserAccessDenied", err)
		}
		return
	}
	for _, r := range add.Results {
		if r.StatusCode != ua.StatusBadUserAccessDenied {
			t.Errorf("AddNodes item status %v, want BadUserAccessDenied", r.StatusCode)
		}
	}
}

// TestAsyncuaServer_ClientRepublish: Republish of a sequence number the
// server does not hold must fail with BadMessageNotAvailable (Part 4 §5.13.6).
func TestAsyncuaServer_ClientRepublish(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/subscription.client.republish/go-client-to-asyncua-server", func(t *testing.T) {
		h := startAsyncuaServer(t)
		c := dialClient(t, h.endpoint)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		notifyCh := make(chan *opcua.PublishNotificationData, 4)
		sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 200 * time.Millisecond}, notifyCh)
		if err != nil {
			t.Fatalf("Subscribe: %v", err)
		}
		t.Cleanup(func() { _ = sub.Cancel(ctx) })
		_, err = c.Republish(ctx, sub.SubscriptionID, 4242)
		if err == nil {
			asyncuaDeviation(t, "Republish of unknown sequence number 4242 answered Good with an empty NotificationMessage "+
				"(InternalSubscription.republish), want BadMessageNotAvailable")
		}
		if !errors.Is(err, ua.StatusBadMessageNotAvailable) {
			t.Fatalf("Republish: %v, want BadMessageNotAvailable", err)
		}
	})
}

// TestAsyncuaServer_ClientTransferSubscriptions: a second session takes over
// the first session's subscription.
func TestAsyncuaServer_ClientTransferSubscriptions(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/subscription.client.transfer/go-client-to-asyncua-server", func(t *testing.T) {
		h := startAsyncuaServer(t)
		c1 := dialClient(t, h.endpoint)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		notifyCh := make(chan *opcua.PublishNotificationData, 4)
		sub, err := c1.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 200 * time.Millisecond}, notifyCh)
		if err != nil {
			t.Fatalf("Subscribe: %v", err)
		}
		c2 := dialClient(t, h.endpoint)
		resp, err := c2.TransferSubscriptions(ctx, []uint32{sub.SubscriptionID}, false)
		if err != nil {
			t.Fatalf("TransferSubscriptions: %v", err)
		}
		if len(resp.Results) != 1 || resp.Results[0].StatusCode != ua.StatusOK {
			sc := ua.StatusBad
			if len(resp.Results) == 1 {
				sc = resp.Results[0].StatusCode
			}
			t.Fatalf("TransferSubscriptions result %v, want Good", sc)
		}
	})
}

// TestAsyncuaServer_DiscoveryServer: an asyncua server accepts RegisterServer /
// RegisterServer2 from anyone (no LDS mode needed) and lists the registered
// server in FindServers, but has no FindServersOnNetwork and keeps a server
// that unregisters (IsOnline=false) listed.
func TestAsyncuaServer_DiscoveryServer(t *testing.T) {
	requireAsyncuaImage(t)
	h := startAsyncuaServer(t)
	ctx := shortTestCtx(t)
	if _, err := opcua.FindServersOnNetwork(ctx, h.endpoint); err == nil {
		t.Error("FindServersOnNetwork on the asyncua server succeeded; asyncua has no LDS-ME")
	} else {
		t.Logf("FindServersOnNetwork: %v", err)
	}

	const uri = "urn:otfabric:go-opcua:interop:registrant"
	events := make(chan server.RegistrationEvent, 16)
	srv, err := server.New(
		server.ListenOn("127.0.0.1:0"),
		server.EndPoint("localhost", 0),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.ApplicationURI(uri),
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
	t.Run("coverage/discovery.lds-registration/go-client-to-asyncua-server", func(t *testing.T) {
		select {
		case e := <-events:
			if e.Err != nil || !e.Online {
				t.Fatalf("registration with the asyncua server: service=%s err=%v online=%v", e.Service, e.Err, e.Online)
			}
			t.Logf("registered via %s, configuration results %v", e.Service, e.ConfigurationResults)
		case <-time.After(discoveryWait):
			t.Fatal("no registration attempt was reported")
		}
		awaitDiscovery(t, "the asyncua server to list the go-opcua server", func() bool {
			for _, u := range foundServerURIs(h.endpoint) {
				if u == uri {
					return true
				}
			}
			return false
		})
		if err := srv.Close(); err != nil {
			t.Fatalf("server.Close: %v", err)
		}
		// The unregistration (IsOnline=false) withdraws the record: poll
		// until it is gone; one that stays for discoveryWait is the stack's.
		deadline := time.Now().Add(discoveryWait)
		for slices.Contains(foundServerURIs(h.endpoint), uri) {
			if time.Now().After(deadline) {
				asyncuaDeviation(t, "RegisterServer with IsOnline=false is stored like a registration "+
					"(InternalServer.register_server ignores IsOnline): the unregistered server is still in FindServers after %v", discoveryWait)
			}
			time.Sleep(250 * time.Millisecond)
		}
	})
	_ = srv.Close()
}

// ---------------------------------------------------------------------------
// Deviation probes. Each checks for one documented asyncua 2.1.0
// non-conformance and skips (asyncuaDeviation) when it is present; when the
// server behaves, the shared assertion runs and decides the test.
// ---------------------------------------------------------------------------

func asyncuaProbeHistoryPaging(t *testing.T, endpoint string) {
	t.Helper()
	c := dialClient(t, endpoint)
	ctx := shortTestCtx(t)
	_, nsIdx := findNS(t, c)
	res := historyReadPage(t, ctx, c, ua.NewStringNodeID(nsIdx, "History.Temperature"), nil, false)
	if vals := historyDoubles(t, res); res.StatusCode == ua.StatusOK && len(vals) == 2 && len(res.ContinuationPoint) == 0 {
		asyncuaDeviation(t, "HistoryRead with NumValuesPerNode=2 over 5 samples returns 2 values and no "+
			"ContinuationPoint (HistoryDict truncates); paging cannot continue")
	}
}

func asyncuaProbeModifySubscription(t *testing.T, endpoint string) {
	t.Helper()
	ctx, _, sub, _, _ := startCounterSubscription(t, endpoint)
	resp, err := sub.ModifySubscription(ctx, opcua.SubscriptionParameters{
		Interval: 1 * time.Second, LifetimeCount: 60, MaxKeepAliveCount: 5,
	})
	if err == nil && resp.RevisedPublishingInterval == 250 && resp.RevisedMaxKeepAliveCount != 5 {
		asyncuaDeviation(t, "ModifySubscription ignores the requested parameters and returns the create-time values "+
			"(revisedPublishingInterval=%v, revisedMaxKeepAliveCount=%d; SubscriptionService.modify_subscription)",
			resp.RevisedPublishingInterval, resp.RevisedMaxKeepAliveCount)
	}
}

func asyncuaProbeModifyMonitoredItems(t *testing.T, endpoint string) {
	t.Helper()
	ctx, _, sub, notifyCh, itemID := startCounterSubscription(t, endpoint)
	resp, err := sub.ModifyMonitoredItems(ctx, ua.TimestampsToReturnBoth, &ua.MonitoredItemModifyRequest{
		MonitoredItemID: itemID,
		RequestedParameters: &ua.MonitoringParameters{
			ClientHandle: 99, SamplingInterval: 500, QueueSize: 4, DiscardOldest: true,
		},
	})
	if err != nil || len(resp.Results) != 1 || resp.Results[0].StatusCode != ua.StatusOK {
		return // the shared assertion reports it
	}
	old, modified := 0, 0
	deadline := time.After(5 * time.Second)
	for old+modified < 4 {
		select {
		case msg := <-notifyCh:
			if msg == nil || msg.Error != nil {
				continue
			}
			if dcn, ok := msg.Value.(*ua.DataChangeNotification); ok && dcn != nil {
				for _, mi := range dcn.MonitoredItems {
					switch mi.ClientHandle {
					case 99:
						modified++
					case 7:
						old++
					}
				}
			}
		case <-deadline:
			return
		}
	}
	if modified == 0 && old > 0 {
		asyncuaDeviation(t, "ModifyMonitoredItems does not apply the new ClientHandle: %d notifications still carry "+
			"the old handle (MonitoredItemService._modify_monitored_item)", old)
	}
}

func asyncuaProbeSamplingMode(t *testing.T, endpoint string) {
	t.Helper()
	ctx, _, sub, notifyCh, itemID := startCounterSubscription(t, endpoint)
	resp, err := sub.SetMonitoringMode(ctx, ua.MonitoringModeSampling, itemID)
	if err != nil || len(resp.Results) != 1 || resp.Results[0] != ua.StatusOK {
		return
	}
	quietFor(notifyCh, 1500*time.Millisecond)
	if quiet, n := quietFor(notifyCh, 3*time.Second); !quiet {
		asyncuaDeviation(t, "MonitoringMode Sampling still reports: %d data changes in 3 s "+
			"(MonitoredItemService.datachange_callback only checks for Disabled)", n)
	}
}

func asyncuaProbeEventQueueOverflow(t *testing.T, endpoint string) {
	t.Helper()
	c := dialClient(t, endpoint)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	_, nsIdx := findNS(t, c)
	notifyCh := make(chan *opcua.PublishNotificationData, 64)
	sub, _, err := c.NewSubscription().Interval(9 * time.Second).NotifyChannel(notifyCh).Start(ctx)
	if err != nil {
		return
	}
	defer sub.Cancel(context.Background()) //nolint:errcheck
	filter := ua.NewEventFilter().Select("EventType", "Severity").Build()
	if _, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, &ua.MonitoredItemCreateRequest{
		ItemToMonitor:  &ua.ReadValueID{NodeID: ua.NewStringNodeID(nsIdx, "Events.Source"), AttributeID: ua.AttributeIDEventNotifier},
		MonitoringMode: ua.MonitoringModeReporting,
		RequestedParameters: &ua.MonitoringParameters{
			ClientHandle: 1, Filter: ua.NewExtensionObject(filter), QueueSize: 2, DiscardOldest: true,
		},
	}); err != nil {
		return
	}
	overflow := ua.NewNumericNodeID(0, 3035).String() // EventQueueOverflowEventType
	deadline := time.After(30 * time.Second)
	for {
		select {
		case msg := <-notifyCh:
			if msg == nil || msg.Error != nil {
				continue
			}
			enl, ok := msg.Value.(*ua.EventNotificationList)
			if !ok || enl == nil || len(enl.Events) == 0 {
				continue
			}
			for _, ev := range enl.Events {
				if len(ev.EventFields) > 0 {
					if typ, ok := ev.EventFields[0].Value().(*ua.NodeID); ok && typ.String() == overflow {
						return
					}
				}
			}
			asyncuaDeviation(t, "no EventQueueOverflowEventType event when a queue of 2 overflows "+
				"(InternalSubscription._enqueue_event drops the oldest silently); batch of %d events", len(enl.Events))
		case <-deadline:
			return
		}
	}
}

// ---------------------------------------------------------------------------
// C→P services (c2p_services_peer_test.go): chunked secure messages,
// SetTriggering, TransferSubscriptions identity rules, AddReferences /
// DeleteReferences, server diagnostics
// ---------------------------------------------------------------------------

func TestAsyncuaServer_ChunkedSecureMessages(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/transport.chunking.secure/go-client-to-asyncua-server", func(t *testing.T) {
		assertPeerChunkedSecure(t, startAsyncuaSecureServer(t).endpoint)
	})
}

func TestAsyncuaServer_SetTriggering(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/monitoreditem.set-triggering/go-client-to-asyncua-server", func(t *testing.T) {
		h := startAsyncuaServer(t)
		// The linked item sits in Sampling mode, which asyncua 2.1.0 does not
		// honour (TestAsyncuaServer_SetMonitoringMode).
		asyncuaProbeSamplingMode(t, h.endpoint)
		requireSetTriggering(t, h.endpoint)
	})
}

func TestAsyncuaServer_TransferSubscriptionsIdentity(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/subscription.client.transfer.anonymous/go-client-to-asyncua-server", func(t *testing.T) {
		assertPeerTransferAnonymous(t, startAsyncuaSecureServer(t).endpoint, ua.StatusOK)
	})
	t.Run("coverage/subscription.client.transfer.other-identity/go-client-to-asyncua-server", func(t *testing.T) {
		// assertPeerTransferOtherIdentity, with the asyncua deviation told
		// apart from any other result.
		endpoint := startAsyncuaSecureServer(t).endpoint
		switch got := transferBetween(t, dialSecureUser(t, endpoint, "test-user", "test-password"), dialSecureAnonymous(t, endpoint)); got {
		case ua.StatusBadUserAccessDenied:
		case ua.StatusOK:
			asyncuaDeviation(t, "TransferSubscriptions moves a subscription of test-user to an anonymous session (Good); "+
				"SubscriptionService.transfer_subscriptions checks no identity, Part 4 §5.14.7 requires BadUserAccessDenied")
		default:
			t.Fatalf("test-user → anonymous: %v, want BadUserAccessDenied", got)
		}
	})
}

// TestAsyncuaServer_ReferencesUnsupported pins why nodemgmt.*-references
// are unsupported for asyncua: like AddNodes / DeleteNodes
// (TestAsyncuaServer_NodeManagementUnsupported), AddReferences and
// DeleteReferences are served only to the Admin role, and the adapter gives
// every session the User role, so both are refused with BadUserAccessDenied
// and the address space is unchanged. Fails (asking for promotion) if that
// ever changes.
func TestAsyncuaServer_ReferencesUnsupported(t *testing.T) {
	requireAsyncuaImage(t)
	h := startAsyncuaServer(t)
	c := dialClient(t, h.endpoint)
	_, nsIdx := findNS(t, c)
	source, target, refType := referencesProbe(nsIdx)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	denied := func(what string, err error, results []ua.StatusCode) {
		t.Helper()
		if err != nil {
			if !errors.Is(err, ua.StatusBadUserAccessDenied) {
				t.Fatalf("%s: %v, want BadUserAccessDenied", what, err)
			}
			return
		}
		if len(results) == 1 && results[0] == ua.StatusOK {
			t.Fatalf("asyncua accepted %s: promote nodemgmt.*-references go-client-to-asyncua-server to a verified test", what)
		}
		if len(results) != 1 || results[0] != ua.StatusBadUserAccessDenied {
			t.Fatalf("%s results %v, want [BadUserAccessDenied]", what, results)
		}
	}
	add, err := c.AddReferences(ctx, addReferenceRequest(source, target, refType))
	var addResults []ua.StatusCode
	if add != nil {
		addResults = add.Results
	}
	denied("AddReferences", err, addResults)
	if browseHasTarget(t, c, source, target) {
		t.Fatal("the refused AddReferences changed the address space")
	}
	scalars := ua.NewStringNodeID(nsIdx, "Scalars")
	del, err := c.DeleteReferences(ctx, &ua.DeleteReferencesRequest{ReferencesToDelete: []*ua.DeleteReferencesItem{{
		SourceNodeID: scalars, ReferenceTypeID: refType, IsForward: true,
		TargetNodeID: ua.NewExpandedNodeID(target, "", 0), DeleteBidirectional: true,
	}}})
	var delResults []ua.StatusCode
	if del != nil {
		delResults = del.Results
	}
	denied("DeleteReferences", err, delResults)
	if !browseHasTarget(t, c, scalars, target) {
		t.Fatal("the refused DeleteReferences removed Scalars → Scalar.Int32")
	}
}

func TestAsyncuaServer_Diagnostics(t *testing.T) {
	requireAsyncuaImage(t)
	h := startAsyncuaServer(t)
	t.Run("coverage/diagnostics.server-summary/go-client-to-asyncua-server", func(t *testing.T) {
		assertPeerServerDiagnostics(t, h.endpoint)
	})
	t.Run("coverage/diagnostics.return-diagnostics/go-client-to-asyncua-server", func(t *testing.T) {
		assertPeerReturnDiagnostics(t, h.endpoint)
	})
}

// Server diagnostics of go-opcua read by the peer client
// (assertGoServerDiagnosticsFromPeer, diagnostics_peer_test.go).
func TestGoServer_AsyncuaClient_Diagnostics(t *testing.T) {
	requireAsyncuaImage(t)
	t.Run("coverage/diagnostics.server-summary/asyncua-client-to-go-server", func(t *testing.T) {
		assertGoServerDiagnosticsFromPeer(t, asyncuaEnv, defaultAsyncuaImage, runAsyncuaClientResult)
	})
}
