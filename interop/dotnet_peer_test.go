//go:build interop

// SPDX-License-Identifier: MIT

// Capability tests against the dotnet adapter (OPC Foundation UA-.NETStandard),
// both directions, on the shared peer assertions of the *_peer_test.go files.
// The subtest names carry the ledger rows (coverage/<capability>/<direction>,
// testdata/ledger-dotnet.json).

package interop

import (
	"context"
	"errors"
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// ---------------------------------------------------------------------------
// discovery
// ---------------------------------------------------------------------------

func TestDotnetServer_FindServers(t *testing.T) {
	t.Run("coverage/discovery.find-servers/go-client-to-dotnet-server", func(t *testing.T) {
		h := startDotnetServer(t)
		ctx := shortTestCtx(t)
		servers, err := opcua.FindServers(ctx, h.endpoint)
		if err != nil {
			t.Fatalf("FindServers: %v", err)
		}
		assertFindServersResult(t, servers)
	})
}

func TestGoServer_DotnetClient_FindServers(t *testing.T) {
	t.Run("coverage/discovery.find-servers/dotnet-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, dotnetEnv, defaultDotnetImage, "find-servers")
		endpoint := startGoServer(t)
		result := runDotnetClient(t, endpoint, "find-servers")
		assertAdapterFindServers(t, result)
	})
}

func TestGoLDS_DotnetServerRegisters(t *testing.T) {
	t.Run("coverage/discovery.lds-registration/dotnet-server-to-go-lds", func(t *testing.T) {
		requireDotnetImage(t)
		assertPeerServerRegistersWithGoLDS(t, dotnetEnv, defaultDotnetImage)
	})
}

func TestGoLDS_DotnetClient_RegisterServer(t *testing.T) {
	t.Run("coverage/discovery.register-server/dotnet-client-to-go-lds", func(t *testing.T) {
		requireDotnetImage(t)
		assertClientRegistersWithGoLDS(t, dotnetEnv, defaultDotnetImage)
	})
}

// TestDotnetServer_DiscoveryServerUnsupported: the dotnet adapter server is
// not a Local Discovery Server; FindServersOnNetwork and RegisterServer(2)
// must be refused with a service fault, and go-opcua must report that.
func TestDotnetServer_DiscoveryServerUnsupported(t *testing.T) {
	h := startDotnetServer(t)

	ctx := shortTestCtx(t)
	_, err := opcua.FindServersOnNetwork(ctx, h.endpoint)
	if err == nil {
		t.Fatal("FindServersOnNetwork on the dotnet server succeeded: it is not an LDS")
	}
	var sc ua.StatusCode
	if !errors.As(err, &sc) {
		t.Fatalf("FindServersOnNetwork on the dotnet server: %v, want a service fault", err)
	}
	t.Logf("FindServersOnNetwork on the dotnet server: %v", err)

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
		if e.Err == nil {
			t.Errorf("registration with the dotnet server succeeded (service=%s): it is not an LDS", e.Service)
		}
		t.Logf("registration with the dotnet server: service=%s err=%v", e.Service, e.Err)
	case <-time.After(discoveryWait):
		t.Fatal("no registration attempt was reported")
	}
}

// ---------------------------------------------------------------------------
// monitored items, subscriptions
// ---------------------------------------------------------------------------

func TestDotnetServer_DataChangeFilter(t *testing.T) {
	h := startDotnetServer(t)
	assertPeerDataChangeFilter(t, h.endpoint, dirGoClientToDotnetServer)
	t.Run("coverage/monitoreditem.percent-deadband/go-client-to-dotnet-server", func(t *testing.T) {
		requireServerFeature(t, dotnetEnv, defaultDotnetImage, "percent-deadband")
		assertPeerPercentDeadband(t, h.endpoint)
	})
}

func TestGoServer_DotnetClient_SamplingInterval(t *testing.T) {
	t.Run("coverage/monitoreditem.sampling-interval/dotnet-client-to-go-server", func(t *testing.T) {
		requireDotnetImage(t)
		assertPeerClientSamplingInterval(t, runDotnetClient)
	})
}

func TestGoServer_DotnetClient_Deadband(t *testing.T) {
	t.Run("coverage/monitoreditem.deadband/dotnet-client-to-go-server", func(t *testing.T) {
		requireAdapterClientFeature(t, dotnetEnv, defaultDotnetImage, "deadband")
		assertPeerClientDeadband(t, runDotnetClient, runDotnetClientResult)
	})
}

func TestGoServer_DotnetClient_PercentDeadband(t *testing.T) {
	t.Run("coverage/monitoreditem.percent-deadband/dotnet-client-to-go-server", func(t *testing.T) {
		requireAdapterClientFeature(t, dotnetEnv, defaultDotnetImage, "deadband")
		assertPeerClientPercentDeadband(t, runDotnetClient, runDotnetClientResult)
	})
}

func TestGoServer_DotnetClient_Trigger(t *testing.T) {
	t.Run("coverage/monitoreditem.trigger/dotnet-client-to-go-server", func(t *testing.T) {
		requireAdapterClientFeature(t, dotnetEnv, defaultDotnetImage, "deadband")
		assertPeerClientTrigger(t, runDotnetClient, runDotnetClientResult)
	})
}

func TestDotnetServer_ModifySubscription(t *testing.T) {
	t.Run("coverage/subscription.modify/go-client-to-dotnet-server", func(t *testing.T) {
		assertClientModifySubscription(t, startDotnetServer(t).endpoint)
	})
}

func TestDotnetServer_ModifyMonitoredItems(t *testing.T) {
	t.Run("coverage/monitoreditem.modify/go-client-to-dotnet-server", func(t *testing.T) {
		assertClientModifyMonitoredItems(t, startDotnetServer(t).endpoint)
	})
}

func TestDotnetServer_SetMonitoringMode(t *testing.T) {
	t.Run("coverage/monitoreditem.monitoring-mode/go-client-to-dotnet-server", func(t *testing.T) {
		assertClientSetMonitoringMode(t, startDotnetServer(t).endpoint)
	})
}

func TestGoServer_DotnetClient_SubscriptionLifecycle_PublishingMode(t *testing.T) {
	t.Run("coverage/subscription.publishing-mode/dotnet-client-to-go-server", func(t *testing.T) {
		requireDotnetImage(t)
		assertPeerPublishingMode(t, runDotnetClientResult)
	})
}

func TestGoServer_DotnetClient_SubscriptionLifecycle_MonitoringMode(t *testing.T) {
	t.Run("coverage/monitoreditem.monitoring-mode/dotnet-client-to-go-server", func(t *testing.T) {
		requireDotnetImage(t)
		assertPeerMonitoringMode(t, runDotnetClientResult)
	})
}

func TestGoServer_DotnetClient_SubscribeRevisedFields(t *testing.T) {
	t.Run("revised-fields", func(t *testing.T) {
		requireDotnetImage(t)
		endpoint := startGoServer(t)
		result := runDotnetClientResult(t, endpoint, "subscribe",
			"--node", "nsu="+interopNamespaceURI+";s=Dynamic.Counter",
			"--notifications", "1",
			"--publishing-interval-ms", "200",
			"--timeout-ms", "15000",
		)
		assertSubscribeRevisedFields(t, result)
	})
}

func TestGoServer_DotnetClient_SubscriptionLifecycle_Revise(t *testing.T) {
	t.Run("coverage/subscription.lifecycle.revise/dotnet-client-to-go-server", func(t *testing.T) {
		requireDotnetImage(t)
		endpoint := startGoServer(t)
		result := runDotnetClientResult(t, endpoint, "subscription-lifecycle",
			"--node", "nsu="+interopNamespaceURI+";s=Access.ReadWrite",
			"--scenario", "revise",
			"--timeout-ms", "15000",
		)
		assertReviseLifecycle(t, result)
	})
}

func TestGoServer_DotnetClient_SubscriptionLifecycle_Delete(t *testing.T) {
	t.Run("coverage/subscription.lifecycle.delete/dotnet-client-to-go-server", func(t *testing.T) {
		requireDotnetImage(t)
		endpoint := startGoServer(t)
		result := runDotnetClientResult(t, endpoint, "subscription-lifecycle",
			"--node", "nsu="+interopNamespaceURI+";s=Access.ReadWrite",
			"--scenario", "delete",
			"--timeout-ms", "15000",
		)
		if !result.Success {
			t.Fatalf("lifecycle delete failed: serviceResult=%s error=%s raw=%s",
				result.ServiceResult, result.Error, result.Results)
		}
	})
}

func TestDotnetServer_SubscribeTimestampsToReturn(t *testing.T) {
	t.Run("coverage/subscription.timestamps/go-client-to-dotnet-server", func(t *testing.T) {
		h := startDotnetServer(t)
		assertPeerSubscribeTimestamps(t, h.endpoint)
	})
}

func TestGoServer_DotnetClient_SubscribeTimestamps(t *testing.T) {
	t.Run("coverage/subscription.timestamps/dotnet-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, dotnetEnv, defaultDotnetImage, "subscribe")
		endpoint := startGoServer(t)
		assertAdapterSubscribeTimestamps(t, endpoint, runDotnetClientResult)
	})
}

func TestDotnetServer_SubscriptionRecoveryReconnect(t *testing.T) {
	t.Run("coverage/subscription.recovery.reconnect/go-client-to-dotnet-server", func(t *testing.T) {
		h := startDotnetServer(t)
		outcome := runReconnectRecovery(t, h.endpoint)
		t.Logf("dotnet recovery outcome=%s", outcome)
		if outcome == "" {
			t.Fatal("empty recovery outcome")
		}
	})
}

// TestDotnetServer_ClientRepublish: Republish of a sequence number the
// server never sent must be answered with BadMessageNotAvailable (Part 4
// §5.13.6), which proves the service path end to end.
func TestDotnetServer_ClientRepublish(t *testing.T) {
	t.Run("coverage/subscription.client.republish/go-client-to-dotnet-server", func(t *testing.T) {
		h := startDotnetServer(t)
		c := dialClient(t, h.endpoint)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		notifyCh := make(chan *opcua.PublishNotificationData, 4)
		sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 200 * time.Millisecond}, notifyCh)
		if err != nil {
			t.Fatalf("Subscribe: %v", err)
		}
		t.Cleanup(func() { _ = sub.Cancel(ctx) })
		_, err = c.Republish(ctx, sub.SubscriptionID, 99999)
		if !errors.Is(err, ua.StatusBadMessageNotAvailable) {
			t.Fatalf("Republish(seq 99999): %v, want BadMessageNotAvailable", err)
		}
	})
}

// TestDotnetServer_ClientTransferSubscriptions: a second go-opcua session
// takes over a subscription of the first. UA-.NETStandard transfers only
// between sessions of the same user (Part 4 §5.14.7), so both sessions log in
// as the fixture user; two anonymous sessions on a None channel carry no
// identity to compare and are refused with BadUserAccessDenied.
func TestDotnetServer_ClientTransferSubscriptions(t *testing.T) {
	transfer := func(t *testing.T, c1, c2 *opcua.Client) ua.StatusCode {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		notifyCh := make(chan *opcua.PublishNotificationData, 4)
		sub, err := c1.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 200 * time.Millisecond}, notifyCh)
		if err != nil {
			t.Fatalf("Subscribe: %v", err)
		}
		resp, err := c2.TransferSubscriptions(ctx, []uint32{sub.SubscriptionID}, false)
		if err != nil {
			t.Fatalf("TransferSubscriptions: %v", err)
		}
		if len(resp.Results) != 1 {
			t.Fatalf("TransferSubscriptions: %d results, want 1", len(resp.Results))
		}
		t.Logf("TransferSubscriptions(%d): %v, available sequence numbers %v",
			sub.SubscriptionID, resp.Results[0].StatusCode, resp.Results[0].AvailableSequenceNumbers)
		return resp.Results[0].StatusCode
	}
	dialUser := func(t *testing.T, endpoint string) *opcua.Client {
		t.Helper()
		c, err := dialUsernameClient(t, endpoint, "test-user", "test-password")
		if err != nil {
			t.Fatalf("dial as test-user: %v", err)
		}
		return c
	}

	t.Run("coverage/subscription.client.transfer/go-client-to-dotnet-server", func(t *testing.T) {
		h := startDotnetServer(t)
		if st := transfer(t, dialUser(t, h.endpoint), dialUser(t, h.endpoint)); st != ua.StatusOK {
			t.Fatalf("transfer between two sessions of test-user: %v, want Good", st)
		}
	})
	t.Run("anonymous-refused", func(t *testing.T) {
		h := startDotnetServer(t)
		if st := transfer(t, dialClient(t, h.endpoint), dialClient(t, h.endpoint)); st != ua.StatusBadUserAccessDenied {
			t.Fatalf("transfer between two anonymous sessions: %v, want BadUserAccessDenied", st)
		}
	})
}

func TestGoServer_DotnetClient_Republish(t *testing.T) {
	t.Run("coverage/subscription.server.republish/dotnet-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, dotnetEnv, defaultDotnetImage, "republish")
		endpoint := startGoServer(t)
		result := runDotnetClientResult(t, endpoint, "republish",
			"--subscription-id", "1",
			"--sequence-number", "1",
		)
		if result.ServiceResult.Name == "" {
			t.Fatalf("expected serviceResult from republish: %+v", result)
		}
		t.Logf("republish of an unknown subscription: %s", result.ServiceResult)
	})
}

func TestGoServer_DotnetClient_TransferSubscriptions(t *testing.T) {
	t.Run("coverage/subscription.server.transfer/dotnet-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, dotnetEnv, defaultDotnetImage, "transfer-subscriptions")
		endpoint := startGoServer(t)
		result := runDotnetClientResult(t, endpoint, "transfer-subscriptions",
			"--subscription-id", "1",
			"--send-initial-values", "false",
		)
		if result.ServiceResult.Name == "" {
			t.Fatalf("expected serviceResult from transfer-subscriptions: %+v", result)
		}
		t.Logf("transfer of an unknown subscription: %s %s", result.ServiceResult, result.Results)
	})
}

// ---------------------------------------------------------------------------
// events
// ---------------------------------------------------------------------------

func TestDotnetServer_EventSubscription(t *testing.T) {
	t.Run("coverage/event.subscription/go-client-to-dotnet-server", func(t *testing.T) {
		h := startDotnetServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		ef := subscribePeerBaseEvent(t, h.endpoint, false, false)
		assertPeerBaseEventFields(t, ef)
	})
}

func TestDotnetServer_EventNotificationDecode(t *testing.T) {
	t.Run("coverage/event.notification.decode/go-client-to-dotnet-server", func(t *testing.T) {
		h := startDotnetServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		ef := subscribePeerBaseEvent(t, h.endpoint, false, false)
		assertPeerBaseEventFields(t, ef)
	})
}

func TestDotnetServer_EventFilterSelectClauses(t *testing.T) {
	t.Run("coverage/event.filter.select-clauses/go-client-to-dotnet-server", func(t *testing.T) {
		h := startDotnetServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		ef := subscribePeerBaseEvent(t, h.endpoint, false, false)
		if len(ef.EventFields) < 6 {
			t.Fatalf("selectClauses fields=%d, want >=6", len(ef.EventFields))
		}
	})
}

func TestDotnetServer_EventFilterOfType(t *testing.T) {
	t.Run("coverage/event.filter.of-type/go-client-to-dotnet-server", func(t *testing.T) {
		h := startDotnetServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		ef := subscribePeerBaseEvent(t, h.endpoint, true, false)
		assertPeerBaseEventFields(t, ef)
	})
}

func TestDotnetServer_EventFilterSeverityThreshold(t *testing.T) {
	t.Run("coverage/event.filter.severity-threshold/go-client-to-dotnet-server", func(t *testing.T) {
		h := startDotnetServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		ef := subscribePeerBaseEvent(t, h.endpoint, false, true)
		assertPeerBaseEventFields(t, ef)
	})
}

func TestDotnetServer_EventFilterWhereClause(t *testing.T) {
	t.Run("coverage/event.filter.where-clause/go-client-to-dotnet-server", func(t *testing.T) {
		h := startDotnetServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		assertPeerEventWhereClause(t, h.endpoint)
	})
}

func TestDotnetServer_EventQueueOverflow(t *testing.T) {
	t.Run("coverage/event.queue-overflow/go-client-to-dotnet-server", func(t *testing.T) {
		h := startDotnetServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		assertPeerEventQueueOverflow(t, h.endpoint)
	})
}

func TestGoServer_DotnetClient_EventSubscribe(t *testing.T) {
	t.Run("coverage/event.subscription/dotnet-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, dotnetEnv, defaultDotnetImage, "event-subscribe")
		endpoint, srv := startGoServerWithEvents(t)
		result := runPeerEventSubscribe(t, endpoint, srv, runDotnetClientResult)
		assertPeerEventPayload(t, parseEventSubscribeItem(t, result))
	})
}

func TestGoServer_DotnetClient_EventEmissionBase(t *testing.T) {
	t.Run("coverage/event.emission.base/dotnet-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, dotnetEnv, defaultDotnetImage, "event-subscribe")
		endpoint, srv := startGoServerWithEvents(t)
		result := runPeerEventSubscribe(t, endpoint, srv, runDotnetClientResult)
		item := parseEventSubscribeItem(t, result)
		if len(item.Events) < 1 {
			t.Fatal("EventEmissionBase: no events received")
		}
		assertPeerEventPayload(t, item)
	})
}

func TestGoServer_DotnetClient_EventFilterSelectClauses(t *testing.T) {
	t.Run("coverage/event.filter.select-clauses/dotnet-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, dotnetEnv, defaultDotnetImage, "event-subscribe")
		endpoint, srv := startGoServerWithEvents(t)
		result := runPeerEventSubscribe(t, endpoint, srv, runDotnetClientResult)
		item := parseEventSubscribeItem(t, result)
		assertSelectClauses(t, item.SelectClauses)
	})
}

func TestGoServer_DotnetClient_EventFilterOfType(t *testing.T) {
	t.Run("coverage/event.filter.of-type/dotnet-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, dotnetEnv, defaultDotnetImage, "event-subscribe")
		endpoint, srv := startGoServerWithEvents(t)
		result := runPeerEventSubscribeFiltered(t, endpoint, srv, runDotnetClientResult,
			"--of-type", "i=2041")
		assertPeerEventPayload(t, parseEventSubscribeItem(t, result))
	})
}

func TestGoServer_DotnetClient_EventFilterSeverityThreshold(t *testing.T) {
	t.Run("coverage/event.filter.severity-threshold/dotnet-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, dotnetEnv, defaultDotnetImage, "event-subscribe")
		endpoint, srv := startGoServerWithEvents(t)
		result := runPeerEventSubscribeFiltered(t, endpoint, srv, runDotnetClientResult,
			"--min-severity", "100")
		assertPeerEventPayload(t, parseEventSubscribeItem(t, result))
	})
}

func TestGoServer_DotnetClient_EventFilterSeverityRejects(t *testing.T) {
	t.Run("severity-rejects", func(t *testing.T) {
		requireAdapterOp(t, dotnetEnv, defaultDotnetImage, "event-subscribe")
		assertPeerEventSeverityRejects(t, runDotnetClientResult)
	})
}

// ---------------------------------------------------------------------------
// history
// ---------------------------------------------------------------------------

func TestDotnetServer_HistoryReadRaw(t *testing.T) {
	t.Run("coverage/history.read.raw/go-client-to-dotnet-server", func(t *testing.T) {
		h := startDotnetServer(t)
		requirePeerNode(t, h.endpoint, "History.Temperature")
		assertPeerHistoryRaw(t, h.endpoint)
	})
}

func TestDotnetServer_HistoryReadContinuation(t *testing.T) {
	t.Run("coverage/history.read.continuation/go-client-to-dotnet-server", func(t *testing.T) {
		h := startDotnetServer(t)
		requirePeerNode(t, h.endpoint, "History.Temperature")
		// The adapter serves History.Temperature from the stack's in-memory
		// historian, whose continuation points are released by
		// ReleaseContinuationPoints.
		assertPeerHistoryContinuation(t, h.endpoint, true)
	})
}

func TestGoServer_DotnetClient_HistoryReadRaw(t *testing.T) {
	t.Run("coverage/history.read.raw/dotnet-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, dotnetEnv, defaultDotnetImage, "history-read")
		endpoint, _, _ := startGoServerWithHistory(t)
		node := "nsu=" + interopNamespaceURI + ";s=History.Temperature"
		result := runDotnetClientResult(t, endpoint, "history-read",
			"--node", node,
			"--start", "2026-07-24T10:00:00Z",
			"--end", "2026-07-24T10:00:20Z",
			"--num-values", "5",
		)
		if !result.Success {
			t.Fatalf("history-read failed: %+v", result)
		}
		items := parseHistoryReadItems(t, result.Results)
		t.Logf("history-read: %s", items[0].Values)
	})
}

func TestGoServer_DotnetClient_HistoryReadContinuation(t *testing.T) {
	t.Run("coverage/history.read.continuation/dotnet-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, dotnetEnv, defaultDotnetImage, "history-read")
		requireHistoryContinueScenario(t, dotnetEnv, defaultDotnetImage)
		endpoint, _, _ := startGoServerWithHistory(t)
		assertHistoryContinuation(t, endpoint, runDotnetClientResult)
	})
}

// ---------------------------------------------------------------------------
// view, node management, methods, security
// ---------------------------------------------------------------------------

func TestDotnetServer_TranslateBrowsePath(t *testing.T) {
	t.Run("coverage/translate.browse-path/go-client-to-dotnet-server", func(t *testing.T) {
		h := startDotnetServer(t)
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

func TestGoServer_DotnetClient_TranslateBrowsePath(t *testing.T) {
	t.Run("coverage/translate.browse-path/dotnet-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, dotnetEnv, defaultDotnetImage, "translate")
		endpoint := startGoServer(t)
		result := runDotnetClient(t, endpoint, "translate",
			"--starting-node", "i=85",
			"--path", "Server",
		)
		assertAdapterTranslateServer(t, result)
	})
}

func TestDotnetServer_RegisterNodes(t *testing.T) {
	t.Run("coverage/view.register-nodes/go-client-to-dotnet-server", func(t *testing.T) {
		h := startDotnetServer(t)
		assertClientRegisterNodes(t, h.endpoint)
	})
}

func TestGoServer_DotnetClient_RegisterNodes(t *testing.T) {
	t.Run("coverage/view.register-nodes/dotnet-client-to-go-server", func(t *testing.T) {
		requireDotnetImage(t)
		assertPeerRegisterNodes(t, dotnetEnv, defaultDotnetImage, runDotnetClientResult)
	})
}

func TestDotnetServer_AddNodes(t *testing.T) {
	t.Run("coverage/nodemgmt.add-nodes/go-client-to-dotnet-server", func(t *testing.T) {
		requireServerFeature(t, dotnetEnv, defaultDotnetImage, "node-management")
		h := startDotnetServer(t)
		assertClientNodeManagement(t, h.endpoint, false)
	})
}

func TestDotnetServer_DeleteNodes(t *testing.T) {
	t.Run("coverage/nodemgmt.delete-nodes/go-client-to-dotnet-server", func(t *testing.T) {
		requireServerFeature(t, dotnetEnv, defaultDotnetImage, "node-management")
		h := startDotnetServer(t)
		assertClientNodeManagement(t, h.endpoint, true)
	})
}

func TestGoServer_DotnetClient_AddNodes(t *testing.T) {
	t.Run("coverage/nodemgmt.add-nodes/dotnet-client-to-go-server", func(t *testing.T) {
		requireDotnetImage(t)
		assertPeerAddNodes(t, dotnetEnv, defaultDotnetImage, runDotnetClientResult)
	})
}

func TestGoServer_DotnetClient_DeleteNodes(t *testing.T) {
	t.Run("coverage/nodemgmt.delete-nodes/dotnet-client-to-go-server", func(t *testing.T) {
		requireDotnetImage(t)
		assertPeerDeleteNodes(t, dotnetEnv, defaultDotnetImage, runDotnetClientResult)
	})
}

func TestDotnetServer_MethodValidation(t *testing.T) {
	t.Run("coverage/method.validation/go-client-to-dotnet-server", func(t *testing.T) {
		h := startDotnetServer(t)
		c := dialClient(t, h.endpoint)
		ctx, nsIdx := findNS(t, c)
		assertMethodTooFewArgs(t, c, ctx, nsIdx)
	})
}

func TestDotnetServer_TrustedCert_Accepted(t *testing.T) {
	t.Run("coverage/security.cert.trusted/go-client-to-dotnet-server", func(t *testing.T) {
		h := startDotnetSecureServer(t)
		c := dialSecureClient(t, h.endpoint, "Basic256Sha256", "SignAndEncrypt")
		ctx, nsIdx := findNS(t, c)
		v, err := c.Node(ua.NewStringNodeID(nsIdx, "Scalar.Int32")).Value(ctx)
		if err != nil {
			t.Fatalf("Value(Scalar.Int32): %v", err)
		}
		if got, ok := v.Value().(int32); !ok || got != -123456789 {
			t.Errorf("Scalar.Int32: got %v (%T), want -123456789", v.Value(), v.Value())
		}
	})
}

func TestDotnetServer_SecureChannelRenewal(t *testing.T) {
	t.Run("coverage/security.channel.renewal/go-client-to-dotnet-server", func(t *testing.T) {
		h := startDotnetSecureServer(t)
		assertClientChannelRenewal(t, h.endpoint)
	})
}

func TestGoServer_DotnetClient_SecureChannelRenewal(t *testing.T) {
	t.Run("coverage/security.channel.renewal/dotnet-client-to-go-server", func(t *testing.T) {
		requireDotnetImage(t)
		assertPeerChannelRenewal(t, dotnetEnv, defaultDotnetImage, "dotnet-client")
	})
}

// ---------------------------------------------------------------------------
// JSON / XML DataEncoding
// ---------------------------------------------------------------------------

// codecDotnet: the UA-.NETStandard JsonEncoder / XmlEncoder of the adapter.
var codecDotnet = codecPeer{
	name: "dotnet", imageEnv: dotnetEnv, defaultImage: defaultDotnetImage,
	run:                 runDotnetClient,
	encodeGaps:          map[string]string{},
	decodeGaps:          map[string]string{},
	dataValueDecodeGaps: map[string]string{},
}

func TestCodec_DotnetEncodes_GoDecodes(t *testing.T) {
	requireDotnetImage(t)
	assertPeerEncodesGoDecodes(t, codecDotnet)
}

func TestCodec_GoEncodes_DotnetDecodes(t *testing.T) {
	requireDotnetImage(t)
	assertGoEncodesPeerDecodes(t, codecDotnet)
}

// codecDotnetVerbose: JsonEncoderOptions.Verbose of the UA-.NETStandard
// JsonEncoder.
var codecDotnetVerbose = func() codecPeer {
	p := codecDotnet
	p.jsonMode = "verbose"
	return p
}()

func TestCodec_DotnetEncodesVerbose_GoDecodes(t *testing.T) {
	requireDotnetImage(t)
	assertPeerEncodesGoDecodes(t, codecDotnetVerbose)
}

func TestCodec_GoEncodesVerbose_DotnetDecodes(t *testing.T) {
	requireDotnetImage(t)
	assertGoEncodesPeerDecodes(t, codecDotnetVerbose)
}

// ---------------------------------------------------------------------------
// C→P services (c2p_services_peer_test.go): chunked secure messages,
// SetTriggering, TransferSubscriptions identity rules, AddReferences /
// DeleteReferences, server diagnostics
// ---------------------------------------------------------------------------

func TestDotnetServer_ChunkedSecureMessages(t *testing.T) {
	t.Run("coverage/transport.chunking.secure/go-client-to-dotnet-server", func(t *testing.T) {
		assertPeerChunkedSecure(t, startDotnetSecureServer(t).endpoint)
	})
}

func TestDotnetServer_SetTriggering(t *testing.T) {
	t.Run("coverage/monitoreditem.set-triggering/go-client-to-dotnet-server", func(t *testing.T) {
		requireSetTriggering(t, startDotnetServer(t).endpoint)
	})
}

func TestDotnetServer_TransferSubscriptionsIdentity(t *testing.T) {
	t.Run("coverage/subscription.client.transfer.anonymous/go-client-to-dotnet-server", func(t *testing.T) {
		assertPeerTransferAnonymous(t, startDotnetSecureServer(t).endpoint, ua.StatusOK)
	})
	t.Run("coverage/subscription.client.transfer.other-identity/go-client-to-dotnet-server", func(t *testing.T) {
		assertPeerTransferOtherIdentity(t, startDotnetSecureServer(t).endpoint, ua.StatusBadUserAccessDenied)
	})
}

func TestDotnetServer_AddDeleteReferences(t *testing.T) {
	h := startDotnetServer(t)
	t.Run("coverage/nodemgmt.add-references/go-client-to-dotnet-server", func(t *testing.T) {
		assertPeerAddDeleteReferences(t, h.endpoint)
	})
	t.Run("coverage/nodemgmt.delete-references/go-client-to-dotnet-server", func(t *testing.T) {
		assertPeerAddDeleteReferences(t, h.endpoint)
	})
}

func TestDotnetServer_Diagnostics(t *testing.T) {
	h := startDotnetServer(t)
	t.Run("coverage/diagnostics.server-summary/go-client-to-dotnet-server", func(t *testing.T) {
		assertPeerServerDiagnostics(t, h.endpoint)
	})
	t.Run("coverage/diagnostics.return-diagnostics/go-client-to-dotnet-server", func(t *testing.T) {
		assertPeerReturnDiagnostics(t, h.endpoint)
	})
}
