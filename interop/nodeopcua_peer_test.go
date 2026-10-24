//go:build interop

// SPDX-License-Identifier: MIT

// node-opcua (TypeScript / Node.js) peer tests that reuse the parameterised assertions of the
// *_peer_test.go files (DataChangeFilter, events, history, discovery, register
// nodes, node management, subscription services, reverse connect, ...).
//
// Directions: go-client-to-node-opcua-server, node-opcua-client-to-go-server.
// The subtest names follow the coverage/<capability>/<direction> convention.

package interop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
)

const nodeOpcuaEnv = "NODE_OPCUA_IMAGE"

// ---------------------------------------------------------------------------
// DataChangeFilter (datachange_filter_peer_test.go)
// ---------------------------------------------------------------------------

func TestNodeOpcuaServer_DataChangeFilter(t *testing.T) {
	requireNodeOpcuaImage(t)
	h := startNodeOpcuaServer(t)
	assertPeerDataChangeFilter(t, h.endpoint, "go-client-to-node-opcua-server")
	t.Run("coverage/monitoreditem.percent-deadband/go-client-to-node-opcua-server", func(t *testing.T) {
		requireServerFeature(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "percent-deadband")
		assertPeerPercentDeadband(t, h.endpoint)
	})
}

func TestGoServer_NodeOpcuaClient_SamplingInterval(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/monitoreditem.sampling-interval/node-opcua-client-to-go-server", func(t *testing.T) {
		assertPeerClientSamplingInterval(t, runNodeOpcuaClient)
	})
}

func TestGoServer_NodeOpcuaClient_Deadband(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/monitoreditem.deadband/node-opcua-client-to-go-server", func(t *testing.T) {
		requireAdapterClientFeature(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "deadband")
		assertPeerClientDeadband(t, runNodeOpcuaClient, runNodeOpcuaClientResult)
	})
}

func TestGoServer_NodeOpcuaClient_PercentDeadband(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/monitoreditem.percent-deadband/node-opcua-client-to-go-server", func(t *testing.T) {
		requireAdapterClientFeature(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "deadband")
		assertPeerClientPercentDeadband(t, runNodeOpcuaClient, runNodeOpcuaClientResult)
	})
}

func TestGoServer_NodeOpcuaClient_Trigger(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/monitoreditem.trigger/node-opcua-client-to-go-server", func(t *testing.T) {
		requireAdapterClientFeature(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "deadband")
		assertPeerClientTrigger(t, runNodeOpcuaClient, runNodeOpcuaClientResult)
	})
}

// ---------------------------------------------------------------------------
// Discovery (discovery_peer_test.go, discovery_lds_peer_test.go)
// ---------------------------------------------------------------------------

func TestNodeOpcuaServer_FindServers(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/discovery.find-servers/go-client-to-node-opcua-server", func(t *testing.T) {
		h := startNodeOpcuaServer(t)
		ctx := shortTestCtx(t)
		servers, err := opcua.FindServers(ctx, h.endpoint)
		if err != nil {
			t.Fatalf("FindServers: %v", err)
		}
		assertFindServersResult(t, servers)
	})
}

func TestGoServer_NodeOpcuaClient_FindServers(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/discovery.find-servers/node-opcua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "find-servers")
		endpoint := startGoServer(t)
		result := runNodeOpcuaClient(t, endpoint, "find-servers")
		assertAdapterFindServers(t, result)
	})
}

// TestNodeOpcuaServer_DiscoveryServerUnsupported pins the rows towards a
// node-opcua discovery server: the adapter's OPCUAServer is no LDS (node-opcua
// ships the LDS as a separate application, not wired into the adapter: --lds
// is refused) and answers FindServersOnNetwork, RegisterServer2 and
// RegisterServer with a service fault.
func TestNodeOpcuaServer_DiscoveryServerUnsupported(t *testing.T) {
	requireNodeOpcuaImage(t)
	h := startNodeOpcuaServer(t)
	ctx := shortTestCtx(t)
	_, err := opcua.FindServersOnNetwork(ctx, h.endpoint)
	if err == nil {
		t.Fatal("FindServersOnNetwork on the node-opcua server succeeded: promote discovery.find-servers-on-network")
	}
	var sc ua.StatusCode
	if !errors.As(err, &sc) {
		t.Fatalf("FindServersOnNetwork: %v, want a StatusCode", err)
	}
	t.Logf("FindServersOnNetwork on the node-opcua server: %v", err)

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
			t.Fatalf("registration with the node-opcua server succeeded via %s", e.Service)
		}
		t.Logf("registration with the node-opcua server: service=%s err=%v", e.Service, e.Err)
	case <-time.After(discoveryWait):
		t.Fatal("no registration attempt was reported")
	}
}

// TestGoLDS_NodeOpcuaServerRegisters: node-opcua server -> go-opcua LDS.
//
// node-opcua's RegisterServerManager registers only over an LDS endpoint that
// has a server certificate (it picks the most secure endpoint and drops one
// without a certificate) — RegisterServer(2) is meant for authenticated
// channels (Part 4 §5.4.5). The shared assertPeerServerRegistersWithGoLDS
// uses a None-only LDS (LDSAllowInsecureRegistration), against which
// node-opcua never registers; this variant runs the LDS with the go-server
// certificate and Basic256Sha256/SignAndEncrypt, trusting the test CA, and the
// node-opcua server with its test-PKI identity.
func TestGoLDS_NodeOpcuaServerRegisters(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/discovery.lds-registration/node-opcua-server-to-go-lds", func(t *testing.T) {
		requireServerFeature(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "register-with")
		pki := pkiDir(t)
		identity := "node-opcua-server"

		var mu sync.Mutex
		online := map[string]bool{}
		lds, ldsURL := startGoLDS(t,
			server.Certificate(loadGoServerCert(t)),
			server.PrivateKey(loadGoServerKey(t)),
			server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
			server.WithClientCertificateTrustList(loadCACertDER(t)),
			server.WithLocalDiscoveryServer(server.LDSRegistrationCallback(func(rs *ua.RegisteredServer) {
				mu.Lock()
				online[rs.ServerURI] = rs.IsOnline
				mu.Unlock()
			})),
		)
		runtimePKI := filepath.Join(containerScratchDir(t), "pki")
		if err := copyDir(filepath.Join(pki, identity, "pki"), runtimePKI); err != nil {
			t.Fatalf("copy PKI: %v", err)
		}
		if err := shareWithContainers(runtimePKI); err != nil {
			t.Fatalf("share PKI: %v", err)
		}
		ldsFromContainer := strings.ReplaceAll(ldsURL, "localhost", "host.docker.internal")
		peer, _ := startAdapterServerWith(t, nodeOpcuaEnv, defaultNodeOpcuaImage,
			[]string{
				"-v", filepath.Join(pki, identity, "cert.crt") + ":/certs/cert.crt:ro",
				"-v", filepath.Join(pki, identity, "cert.key") + ":/certs/cert.key:ro",
				"-v", runtimePKI + ":/certs/pki",
			},
			[]string{
				"--certificate", "/certs/cert.crt", "--private-key", "/certs/cert.key", "--pki-dir", "/certs/pki",
				"--advertised-host", "localhost", "--advertised-port", "{port}",
				"--register-with", ldsFromContainer,
			})

		awaitDiscovery(t, "the node-opcua server to register with the go-opcua LDS", func() bool {
			return len(lds.RegisteredServers()) > 0
		})
		reg := lds.RegisteredServers()[0]
		t.Logf("registered: uri=%s urls=%v names=%d type=%v", reg.ServerURI, reg.DiscoveryURLs, len(reg.ServerNames), reg.ServerType)
		if reg.ServerURI != "urn:otfabric:opcua-interop:server" {
			t.Errorf("registered ServerUri = %q, want the adapter's ApplicationUri", reg.ServerURI)
		}
		if !slices.Contains(reg.DiscoveryURLs, peer.endpoint) {
			t.Errorf("registered discovery URLs %v do not contain the advertised endpoint %s", reg.DiscoveryURLs, peer.endpoint)
		}
		if len(reg.ServerNames) == 0 || reg.ServerNames[0].Text == "" || !reg.IsOnline {
			t.Errorf("registration: names=%+v online=%v", reg.ServerNames, reg.IsOnline)
		}
		// The go-opcua client finds the server through the LDS and reads.
		ctx := shortTestCtx(t)
		found, err := opcua.FindServers(ctx, ldsURL)
		if err != nil {
			t.Fatalf("FindServers on the go-opcua LDS: %v", err)
		}
		var app *ua.ApplicationDescription
		for _, a := range found {
			if a.ApplicationURI == reg.ServerURI {
				app = a
			}
		}
		if app == nil || len(app.DiscoveryURLs) == 0 {
			t.Fatalf("FindServers on the go-opcua LDS does not list %s with a discovery URL", reg.ServerURI)
		}
		url := app.DiscoveryURLs[0]
		for _, u := range app.DiscoveryURLs {
			if u == peer.endpoint {
				url = u
			}
		}
		c := dialClient(t, url)
		_, nsIdx := findNS(t, c)
		if dv, err := c.ReadValue(ctx, ua.NewStringNodeID(nsIdx, "Scalar.Int32")); err != nil || dv.Value.Int() != -123456789 {
			t.Errorf("read through the discovered URL %s: %v %v", url, dv, err)
		}
		// Stopping the server unregisters it (IsOnline=false).
		peer.stopFn()
		awaitDiscovery(t, "the node-opcua server to unregister", func() bool {
			return len(lds.RegisteredServers()) == 0
		})
		mu.Lock()
		defer mu.Unlock()
		if on, seen := online[reg.ServerURI]; !seen || on {
			t.Errorf("the last RegisterServer call for %s had IsOnline=%v, want false", reg.ServerURI, on)
		}
	})
}

func TestGoLDS_NodeOpcuaClient_RegisterServer(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/discovery.register-server/node-opcua-client-to-go-lds", func(t *testing.T) {
		assertClientRegistersWithGoLDS(t, nodeOpcuaEnv, defaultNodeOpcuaImage)
	})
}

// ---------------------------------------------------------------------------
// Translate, methods, security (translate/method/security_peer_test.go)
// ---------------------------------------------------------------------------

func TestNodeOpcuaServer_TranslateBrowsePath(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/translate.browse-path/go-client-to-node-opcua-server", func(t *testing.T) {
		h := startNodeOpcuaServer(t)
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

func TestGoServer_NodeOpcuaClient_TranslateBrowsePath(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/translate.browse-path/node-opcua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "translate")
		endpoint := startGoServer(t)
		result := runNodeOpcuaClient(t, endpoint, "translate",
			"--starting-node", "i=85",
			"--path", "Server",
		)
		assertAdapterTranslateServer(t, result)
	})
}

func TestNodeOpcuaServer_MethodValidation(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/method.validation/go-client-to-node-opcua-server", func(t *testing.T) {
		h := startNodeOpcuaServer(t)
		c := dialClient(t, h.endpoint)
		ctx, nsIdx := findNS(t, c)
		assertMethodTooFewArgs(t, c, ctx, nsIdx)
	})
}

func TestNodeOpcuaServer_TrustedCert_Accepted(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/security.cert.trusted/go-client-to-node-opcua-server", func(t *testing.T) {
		h := startNodeOpcuaSecureServer(t)
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

func TestNodeOpcuaServer_SecureChannelRenewal(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/security.channel.renewal/go-client-to-node-opcua-server", func(t *testing.T) {
		h := startNodeOpcuaSecureServer(t)
		assertClientChannelRenewal(t, h.endpoint)
	})
}

func TestGoServer_NodeOpcuaClient_SecureChannelRenewal(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/security.channel.renewal/node-opcua-client-to-go-server", func(t *testing.T) {
		assertPeerChannelRenewal(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "node-opcua-client")
	})
}

// ---------------------------------------------------------------------------
// History (history_*_peer_test.go, extended_peer_test.go)
// ---------------------------------------------------------------------------

func TestNodeOpcuaServer_HistoryReadRaw(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/history.read.raw/go-client-to-node-opcua-server", func(t *testing.T) {
		h := startNodeOpcuaServer(t)
		requirePeerNode(t, h.endpoint, "History.Temperature")
		assertPeerHistoryRaw(t, h.endpoint)
	})
}

func TestNodeOpcuaServer_HistoryReadContinuation(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/history.read.continuation/go-client-to-node-opcua-server", func(t *testing.T) {
		h := startNodeOpcuaServer(t)
		requirePeerNode(t, h.endpoint, "History.Temperature")
		// The node-opcua server keeps history continuation points per
		// session and honours ReleaseContinuationPoints.
		assertPeerHistoryContinuation(t, h.endpoint, true)
	})
}

func TestGoServer_NodeOpcuaClient_HistoryReadRaw(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/history.read.raw/node-opcua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "history-read")
		endpoint, _, _ := startGoServerWithHistory(t)
		node := "nsu=" + interopNamespaceURI + ";s=History.Temperature"
		result := runNodeOpcuaClientResult(t, endpoint, "history-read",
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

func TestGoServer_NodeOpcuaClient_HistoryReadContinuation(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/history.read.continuation/node-opcua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "history-read")
		requireHistoryContinueScenario(t, nodeOpcuaEnv, defaultNodeOpcuaImage)
		endpoint, _, _ := startGoServerWithHistory(t)
		assertHistoryContinuation(t, endpoint, runNodeOpcuaClientResult)
	})
}

// ---------------------------------------------------------------------------
// Register nodes, node management (extended_peer_test.go)
// ---------------------------------------------------------------------------

func TestNodeOpcuaServer_RegisterNodes(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/view.register-nodes/go-client-to-node-opcua-server", func(t *testing.T) {
		h := startNodeOpcuaServer(t)
		assertClientRegisterNodes(t, h.endpoint)
	})
}

func TestGoServer_NodeOpcuaClient_RegisterNodes(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/view.register-nodes/node-opcua-client-to-go-server", func(t *testing.T) {
		assertPeerRegisterNodes(t, nodeOpcuaEnv, defaultNodeOpcuaImage, runNodeOpcuaClientResult)
	})
}

func TestGoServer_NodeOpcuaClient_AddNodes(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/nodemgmt.add-nodes/node-opcua-client-to-go-server", func(t *testing.T) {
		assertPeerAddNodes(t, nodeOpcuaEnv, defaultNodeOpcuaImage, runNodeOpcuaClientResult)
	})
}

func TestGoServer_NodeOpcuaClient_DeleteNodes(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/nodemgmt.delete-nodes/node-opcua-client-to-go-server", func(t *testing.T) {
		assertPeerDeleteNodes(t, nodeOpcuaEnv, defaultNodeOpcuaImage, runNodeOpcuaClientResult)
	})
}

// ---------------------------------------------------------------------------
// Subscriptions (subscription_*_peer_test.go, extended_peer_test.go)
// ---------------------------------------------------------------------------

func TestNodeOpcuaServer_ModifySubscription(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/subscription.modify/go-client-to-node-opcua-server", func(t *testing.T) {
		assertClientModifySubscription(t, startNodeOpcuaServer(t).endpoint)
	})
}

func TestNodeOpcuaServer_ModifyMonitoredItems(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/monitoreditem.modify/go-client-to-node-opcua-server", func(t *testing.T) {
		assertClientModifyMonitoredItems(t, startNodeOpcuaServer(t).endpoint)
	})
}

func TestNodeOpcuaServer_SetMonitoringMode(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/monitoreditem.monitoring-mode/go-client-to-node-opcua-server", func(t *testing.T) {
		assertClientSetMonitoringMode(t, startNodeOpcuaServer(t).endpoint)
	})
}

func TestNodeOpcuaServer_SubscribeTimestampsToReturn(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/subscription.timestamps/go-client-to-node-opcua-server", func(t *testing.T) {
		h := startNodeOpcuaServer(t)
		assertPeerSubscribeTimestamps(t, h.endpoint)
	})
}

func TestGoServer_NodeOpcuaClient_SubscribeTimestamps(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/subscription.timestamps/node-opcua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "subscribe")
		endpoint := startGoServer(t)
		assertAdapterSubscribeTimestamps(t, endpoint, runNodeOpcuaClientResult)
	})
}

func TestNodeOpcuaServer_SubscriptionRecoveryReconnect(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/subscription.recovery.reconnect/go-client-to-node-opcua-server", func(t *testing.T) {
		h := startNodeOpcuaServer(t)
		outcome := runReconnectRecovery(t, h.endpoint)
		t.Logf("node-opcua recovery outcome=%s", outcome)
		if outcome == "" {
			t.Fatal("empty recovery outcome")
		}
	})
}

// qualifyNodeOpcuaSubscriptionService is qualifyMiloSubscriptionService for
// the node-opcua server: any defined StatusCode other than
// BadServiceUnsupported / BadNotImplemented proves the service path exists.
func qualifyNodeOpcuaSubscriptionService(t *testing.T, kind string) (status string, detail string) {
	t.Helper()
	h := startNodeOpcuaServer(t)
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

func TestNodeOpcuaServer_ClientRepublish(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/subscription.client.republish/go-client-to-node-opcua-server", func(t *testing.T) {
		status, detail := qualifyNodeOpcuaSubscriptionService(t, "republish")
		t.Logf("node-opcua Republish qualification: status=%s detail=%s", status, detail)
		if status != "verified" {
			t.Fatalf("Republish not served: %s (%s)", status, detail)
		}
	})
}

func TestNodeOpcuaServer_ClientTransferSubscriptions(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/subscription.client.transfer/go-client-to-node-opcua-server", func(t *testing.T) {
		status, detail := qualifyNodeOpcuaSubscriptionService(t, "transfer")
		t.Logf("node-opcua TransferSubscriptions qualification: status=%s detail=%s", status, detail)
		if status != "verified" {
			t.Fatalf("TransferSubscriptions not served: %s (%s)", status, detail)
		}
	})
}

func TestGoServer_NodeOpcuaClient_Republish(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/subscription.server.republish/node-opcua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "republish")
		endpoint := startGoServer(t)
		result := runNodeOpcuaClientResult(t, endpoint, "republish",
			"--subscription-id", "1",
			"--sequence-number", "1",
		)
		if result.ServiceResult.Name == "" {
			t.Fatalf("expected serviceResult from republish: %+v", result)
		}
	})
}

func TestGoServer_NodeOpcuaClient_TransferSubscriptions(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/subscription.server.transfer/node-opcua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "transfer-subscriptions")
		endpoint := startGoServer(t)
		result := runNodeOpcuaClientResult(t, endpoint, "transfer-subscriptions",
			"--subscription-id", "1",
			"--send-initial-values", "false",
		)
		if result.ServiceResult.Name == "" {
			t.Fatalf("expected serviceResult from transfer-subscriptions: %+v", result)
		}
	})
}

func TestGoServer_NodeOpcuaClient_SubscribeRevisedFields(t *testing.T) {
	requireNodeOpcuaImage(t)
	endpoint := startGoServer(t)
	result := runNodeOpcuaClientResult(t, endpoint, "subscribe",
		"--node", "nsu="+interopNamespaceURI+";s=Dynamic.Counter",
		"--notifications", "1",
		"--publishing-interval-ms", "200",
		"--timeout-ms", "15000",
	)
	assertSubscribeRevisedFields(t, result)
}

func TestGoServer_NodeOpcuaClient_SubscriptionLifecycle_Revise(t *testing.T) {
	requireNodeOpcuaImage(t)
	endpoint := startGoServer(t)
	result := runNodeOpcuaClientResult(t, endpoint, "subscription-lifecycle",
		"--node", "nsu="+interopNamespaceURI+";s=Access.ReadWrite",
		"--scenario", "revise",
		"--timeout-ms", "15000",
	)
	assertReviseLifecycle(t, result)
}

func TestGoServer_NodeOpcuaClient_SubscriptionLifecycle_Delete(t *testing.T) {
	requireNodeOpcuaImage(t)
	endpoint := startGoServer(t)
	result := runNodeOpcuaClientResult(t, endpoint, "subscription-lifecycle",
		"--node", "nsu="+interopNamespaceURI+";s=Access.ReadWrite",
		"--scenario", "delete",
		"--timeout-ms", "15000",
	)
	if !result.Success {
		t.Fatalf("lifecycle delete failed: serviceResult=%s error=%s raw=%s",
			result.ServiceResult, result.Error, result.Results)
	}
}

func TestGoServer_NodeOpcuaClient_SubscriptionLifecycle_PublishingMode(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/subscription.publishing-mode/node-opcua-client-to-go-server", func(t *testing.T) {
		assertPeerPublishingMode(t, runNodeOpcuaClientResult)
	})
}

func TestGoServer_NodeOpcuaClient_SubscriptionLifecycle_MonitoringMode(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/monitoreditem.monitoring-mode/node-opcua-client-to-go-server", func(t *testing.T) {
		assertPeerMonitoringMode(t, runNodeOpcuaClientResult)
	})
}

// ---------------------------------------------------------------------------
// Events (events_*_test.go, extended_peer_test.go)
// ---------------------------------------------------------------------------

func TestNodeOpcuaServer_EventSubscription(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/event.subscription/go-client-to-node-opcua-server", func(t *testing.T) {
		h := startNodeOpcuaServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		ef := subscribePeerBaseEvent(t, h.endpoint, false, false)
		assertPeerBaseEventFields(t, ef)
	})
}

func TestNodeOpcuaServer_EventNotificationDecode(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/event.notification.decode/go-client-to-node-opcua-server", func(t *testing.T) {
		h := startNodeOpcuaServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		ef := subscribePeerBaseEvent(t, h.endpoint, false, false)
		assertPeerBaseEventFields(t, ef)
	})
}

func TestNodeOpcuaServer_EventFilterSelectClauses(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/event.filter.select-clauses/go-client-to-node-opcua-server", func(t *testing.T) {
		h := startNodeOpcuaServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		ef := subscribePeerBaseEvent(t, h.endpoint, false, false)
		if len(ef.EventFields) < 6 {
			t.Fatalf("selectClauses fields=%d, want >=6", len(ef.EventFields))
		}
	})
}

func TestNodeOpcuaServer_EventFilterOfType(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/event.filter.of-type/go-client-to-node-opcua-server", func(t *testing.T) {
		h := startNodeOpcuaServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		ef := subscribePeerBaseEvent(t, h.endpoint, true, false)
		assertPeerBaseEventFields(t, ef)
	})
}

func TestNodeOpcuaServer_EventFilterSeverityThreshold(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/event.filter.severity-threshold/go-client-to-node-opcua-server", func(t *testing.T) {
		h := startNodeOpcuaServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		ef := subscribePeerBaseEvent(t, h.endpoint, false, true)
		assertPeerBaseEventFields(t, ef)
	})
}

func TestNodeOpcuaServer_EventFilterWhereClause(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/event.filter.where-clause/go-client-to-node-opcua-server", func(t *testing.T) {
		h := startNodeOpcuaServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		assertPeerEventWhereClause(t, h.endpoint)
	})
}

func TestNodeOpcuaServer_EventQueueOverflow(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/event.queue-overflow/go-client-to-node-opcua-server", func(t *testing.T) {
		h := startNodeOpcuaServer(t)
		requirePeerNode(t, h.endpoint, "Events.Source")
		if revised := nodeOpcuaRevisedEventQueueSize(t, h.endpoint, 2); revised != 2 {
			// node-opcua 2.187.12 (monitored_item.js _adjust_event_queue_size)
			// raises every event queue to at least 100, although its own
			// comment (and Part 4 v1.05.07 §7.21) says a size between 1 and
			// MaxUInt32 is honoured as asked. With one fixture event every
			// 2 s the queue cannot overflow within a publishing interval.
			t.Skipf("node-opcua deviation: event queueSize 2 revised to %d; the overflow cannot be provoked with the fixture's event rate", revised)
		}
		assertPeerEventQueueOverflow(t, h.endpoint)
	})
}

// nodeOpcuaRevisedEventQueueSize creates an event monitored item with the
// given queue size and returns the size the server revised it to.
func nodeOpcuaRevisedEventQueueSize(t *testing.T, endpoint string, queueSize uint32) uint32 {
	t.Helper()
	c := dialClient(t, endpoint)
	ctx, nsIdx := findNS(t, c)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: time.Second}, make(chan *opcua.PublishNotificationData, 8))
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Cancel(context.Background()) //nolint:errcheck
	filter := ua.NewEventFilter().Select("EventType", "Severity").Build()
	resp, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, &ua.MonitoredItemCreateRequest{
		ItemToMonitor:  &ua.ReadValueID{NodeID: ua.NewStringNodeID(nsIdx, "Events.Source"), AttributeID: ua.AttributeIDEventNotifier},
		MonitoringMode: ua.MonitoringModeReporting,
		RequestedParameters: &ua.MonitoringParameters{
			ClientHandle: 7, Filter: ua.NewExtensionObject(filter), QueueSize: queueSize, DiscardOldest: true,
		},
	})
	if err != nil || len(resp.Results) != 1 || resp.Results[0].StatusCode != ua.StatusOK {
		t.Fatalf("event monitor probe: %v %+v", err, resp)
	}
	return resp.Results[0].RevisedQueueSize
}

func TestGoServer_NodeOpcuaClient_EventSubscribe(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/event.subscription/node-opcua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "event-subscribe")
		endpoint, srv := startGoServerWithEvents(t)
		result := runPeerEventSubscribe(t, endpoint, srv, runNodeOpcuaClientResult)
		assertPeerEventPayload(t, parseEventSubscribeItem(t, result))
	})
}

func TestGoServer_NodeOpcuaClient_EventEmissionBase(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/event.emission.base/node-opcua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "event-subscribe")
		endpoint, srv := startGoServerWithEvents(t)
		result := runPeerEventSubscribe(t, endpoint, srv, runNodeOpcuaClientResult)
		item := parseEventSubscribeItem(t, result)
		if len(item.Events) < 1 {
			t.Fatal("EventEmissionBase: no events received")
		}
		assertPeerEventPayload(t, item)
	})
}

func TestGoServer_NodeOpcuaClient_EventFilterSelectClauses(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/event.filter.select-clauses/node-opcua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "event-subscribe")
		endpoint, srv := startGoServerWithEvents(t)
		result := runPeerEventSubscribe(t, endpoint, srv, runNodeOpcuaClientResult)
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

func TestGoServer_NodeOpcuaClient_EventFilterOfType(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/event.filter.of-type/node-opcua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "event-subscribe")
		endpoint, srv := startGoServerWithEvents(t)
		result := runPeerEventSubscribeFiltered(t, endpoint, srv, runNodeOpcuaClientResult,
			"--of-type", "i=2041")
		assertPeerEventPayload(t, parseEventSubscribeItem(t, result))
	})
}

func TestGoServer_NodeOpcuaClient_EventFilterSeverityThreshold(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/event.filter.severity-threshold/node-opcua-client-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "event-subscribe")
		endpoint, srv := startGoServerWithEvents(t)
		result := runPeerEventSubscribeFiltered(t, endpoint, srv, runNodeOpcuaClientResult,
			"--min-severity", "100")
		assertPeerEventPayload(t, parseEventSubscribeItem(t, result))
	})
}

func TestGoServer_NodeOpcuaClient_EventFilterSeverityRejects(t *testing.T) {
	requireNodeOpcuaImage(t)
	requireAdapterOp(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "event-subscribe")
	assertPeerEventSeverityRejects(t, runNodeOpcuaClientResult)
}

// ---------------------------------------------------------------------------
// Reverse connect (reverse_connect_peer_test.go)
// ---------------------------------------------------------------------------

// TestNodeOpcuaServer_ReverseConnect: the node-opcua server dials the Go
// client's reverse listener (ReverseHello), the client reads and subscribes
// over that connection.
func TestNodeOpcuaServer_ReverseConnect(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/transport.reverse-connect/go-client-to-node-opcua-server", func(t *testing.T) {
		requireAdapterFeature(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "serverFeatures", "reverse-connect")

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

		startAdapterReverseServer(t, nodeOpcuaEnv, defaultNodeOpcuaImage, l.Addr().(*net.TCPAddr).Port)

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

func TestGoServer_NodeOpcuaClient_ReverseConnect_Read(t *testing.T) {
	requireNodeOpcuaImage(t)
	t.Run("coverage/transport.reverse-connect/node-opcua-client-to-go-server", func(t *testing.T) {
		requireAdapterFeature(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "clientFeatures", "reverse-listen")
		endpoint, hostPort, rc, counter := reverseGoServer(t)
		result := runAdapterReverseClient(t, nodeOpcuaEnv, defaultNodeOpcuaImage, endpoint, hostPort, "read",
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

func TestGoServer_NodeOpcuaClient_ReverseConnect_Subscribe(t *testing.T) {
	requireNodeOpcuaImage(t)
	requireAdapterFeature(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "clientFeatures", "reverse-listen")
	endpoint, hostPort, rc, counter := reverseGoServer(t)
	result := runAdapterReverseClient(t, nodeOpcuaEnv, defaultNodeOpcuaImage, endpoint, hostPort, "subscribe",
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

// TestNodeOpcuaServer_ReverseConnect_Secure: the node-opcua server dials
// the listening Go client, which reads the endpoints over one reverse
// connection and opens a Basic256Sha256/SignAndEncrypt channel on the next
// (node-opcua 2.187 has no ECC policies, so only the RSA case applies).
func TestNodeOpcuaServer_ReverseConnect_Secure(t *testing.T) {
	requireNodeOpcuaImage(t)
	requireAdapterFeature(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "serverFeatures", "reverse-connect")
	t.Run("coverage/transport.reverse-connect.secure/go-client-to-node-opcua-server/Basic256Sha256", func(t *testing.T) {
		l, err := uacp.ListenReverse(context.Background(), "0.0.0.0:0", nil)
		if err != nil {
			t.Fatalf("ListenReverse: %v", err)
		}
		t.Cleanup(func() { _ = l.Close() })
		startNodeOpcuaSecureReverseServer(t, l.Addr().(*net.TCPAddr).Port)

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

// TestGoServer_NodeOpcuaClient_ReverseConnect_Secure: the Go server dials
// the listening node-opcua client, which subscribes over a
// Basic256Sha256/SignAndEncrypt channel on the connections the server opened.
func TestGoServer_NodeOpcuaClient_ReverseConnect_Secure(t *testing.T) {
	requireNodeOpcuaImage(t)
	requireAdapterFeature(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "clientFeatures", "reverse-listen")
	t.Run("coverage/transport.reverse-connect.secure/node-opcua-client-to-go-server/Basic256Sha256", func(t *testing.T) {
		endpoint, hostPort, target, counter := reverseGoServer(t,
			server.Certificate(loadGoServerCert(t)),
			server.PrivateKey(loadGoServerKey(t)),
			server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		)
		pki := pkiDir(t)
		mounts := []string{
			"-v", filepath.Join(pki, "node-opcua-client", "cert.crt") + ":/certs/cert.crt:ro",
			"-v", filepath.Join(pki, "node-opcua-client", "cert.key") + ":/certs/cert.key:ro",
			"-v", filepath.Join(pki, "ca", "ca.crt") + ":/certs/ca.crt:ro",
		}
		result := runAdapterReverseClientWith(t, nodeOpcuaEnv, defaultNodeOpcuaImage, endpoint, hostPort, mounts, "subscribe",
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
// PubSub: node-opcua 2.187 has no open-source Part 14 implementation
// ---------------------------------------------------------------------------

// TestPubSub_NodeOpcuaHasNoPubSub pins the reason the PubSub rows of the
// node-opcua directions are unsupported: the adapter declares
// pubsub.supported=false and refuses --pubsub-config and codec pubsub-*.
func TestPubSub_NodeOpcuaHasNoPubSub(t *testing.T) {
	caps, image := imageCapabilities(t, nodeOpcuaEnv, defaultNodeOpcuaImage)
	requirePinnedVersion(t, nodeOpcuaEnv, caps, image)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	raw, err := exec.CommandContext(ctx, "docker", "run", "--rm", image, "print-capabilities").Output()
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
		t.Fatal("the node-opcua adapter does not declare pubsub")
	}
	if doc.PubSub.Supported {
		t.Fatalf("the node-opcua adapter declares PubSub support: add the pubsub rows to the ledger")
	}
	t.Logf("node-opcua: %s", doc.PubSub.Reason)

	out, _ := exec.CommandContext(ctx, "docker", "run", "--rm", image, "client", "codec", "pubsub-uadp-decode", "--document", "AQ==").Output()
	r, err := parseAdapterOutput(out)
	if err != nil {
		t.Fatalf("codec pubsub-uadp-decode: %v\nraw: %s", err, out)
	}
	if r.Success {
		t.Errorf("the node-opcua adapter ran codec pubsub-uadp-decode: %+v", r)
	}
	srvOut, err := exec.CommandContext(ctx, "docker", "run", "--rm", image, "server",
		"--fixture", "/fixtures/fixture.json", "--pubsub-config", "/dev/null").CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 2 {
		t.Errorf("server --pubsub-config: err=%v, want exit 2\n%s", err, srvOut)
	}
}

// TestNodeOpcuaServer_EccUnsupported pins the ledger rows of the ECC
// capabilities: node-opcua 2.187.12 implements no ECC SecurityPolicy, so the
// server offers no ECC endpoint even with --ecc-dir, and the adapter client
// refuses an ECC policy with exit 2 / "input" instead of falling back.
func TestNodeOpcuaServer_EccUnsupported(t *testing.T) {
	caps := requireNodeOpcuaImage(t)
	for _, f := range append(caps.ClientFeatures, caps.ServerFeatures...) {
		if strings.HasPrefix(f, "ecc-") {
			t.Fatalf("the node-opcua adapter advertises %q: replace this test with real ECC coverage", f)
		}
	}
	h := startNodeOpcuaSecureServer(t)
	ctx := shortTestCtx(t)
	eps, err := opcua.GetEndpoints(ctx, h.endpoint)
	if err != nil {
		t.Fatalf("GetEndpoints: %v", err)
	}
	for _, ep := range eps {
		if strings.Contains(ep.SecurityPolicyURI, "ECC_") {
			t.Errorf("node-opcua offers %s", ep.SecurityPolicyURI)
		}
	}
	result := runNodeOpcuaClientResult(t, h.endpoint, "read", "--node", "i=2258",
		"--security-policy", "ECC_nistP256", "--security-mode", "SignAndEncrypt")
	if result.Success || !strings.Contains(string(result.Error), `"input"`) {
		t.Errorf("client read with ECC_nistP256: want an input error, got %+v", result)
	}
}

// TestNodeOpcuaServer_NodeManagementUnsupported pins the reason the C→N
// node-management rows are unsupported: node-opcua's OPCUAServer answers
// AddNodes / DeleteNodes with BadServiceUnsupported (opcua_server.js
// _on_AddNodes / _on_DeleteNodes).
func TestNodeOpcuaServer_NodeManagementUnsupported(t *testing.T) {
	requireNodeOpcuaImage(t)
	h := startNodeOpcuaServer(t)
	c := dialClient(t, h.endpoint)
	ctx, nsIdx := findNS(t, c)
	parent := ua.NewStringNodeID(nsIdx, "Compatibility")
	newID := ua.NewStringNodeID(nsIdx, "Interop.GoAdded")
	add, err := c.AddNodes(ctx, addVariableRequest(nsIdx, parent, newID, 1))
	if err == nil && len(add.Results) == 1 && add.Results[0].StatusCode == ua.StatusOK {
		t.Fatal("node-opcua accepted AddNodes: promote nodemgmt.add-nodes to a verified test")
	}
	if err != nil && !errors.Is(err, ua.StatusBadServiceUnsupported) {
		t.Fatalf("AddNodes: %v, want BadServiceUnsupported", err)
	}
	t.Logf("node-opcua AddNodes rejected: %v", err)
}

// TestNodeOpcuaAdapter_CodecUnsupported pins the ledger rows of the
// encoding.* capabilities: the adapter has no codec command (node-opcua has
// no Part 6 XML Variant encoding and its 1.05 JSON encoder is not wired in),
// so codec is refused per the contract. PubSub is pinned by
// TestPubSub_NodeOpcuaHasNoPubSub.
func TestNodeOpcuaAdapter_CodecUnsupported(t *testing.T) {
	caps := requireNodeOpcuaImage(t)
	image := getEnvOr(nodeOpcuaEnv, defaultNodeOpcuaImage)
	if slices.Contains(caps.ClientOperations, "codec") {
		t.Fatal("the node-opcua adapter advertises codec: replace this test with codec coverage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", image, "client", "codec", "encode",
		"--format", "json", "--type", "Int32", "--value", "1")
	cmd.Stderr = os.Stderr
	raw, err := cmd.Output()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 {
		t.Errorf("client codec: exit %v, want 2", err)
	}
	if r, perr := parseAdapterOutput(raw); perr != nil || r.Success || !strings.Contains(string(r.Error), `"input"`) {
		t.Errorf("client codec result: %v %+v", perr, r)
	}
}
