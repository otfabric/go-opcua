//go:build interop

// SPDX-License-Identifier: MIT

// Peer subscription recovery via stack-neutral TCP disruption.
// COVERAGE.md: subscriptions / subscription.recovery.reconnect

package interop

import (
	"context"
	"net"
	"net/url"
	"sync"
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
)

func backendHostPort(t *testing.T, endpoint string) (hostport, path string) {
	t.Helper()
	u, err := url.Parse(endpoint)
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "4840"
	}
	// Force IPv4 loopback for the proxy backend dial.
	if host == "localhost" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port), u.Path
}

func runReconnectRecovery(t *testing.T, peerEndpoint string) opcua.SubscriptionRecoveryOutcome {
	t.Helper()
	hostport, path := backendHostPort(t, peerEndpoint)
	proxy := startTCPDisruptor(t, hostport)
	proxyEP := proxy.EndpointURL(path)

	var (
		mu       sync.Mutex
		outcomes []opcua.SubscriptionRecoveryEvent
	)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	c, err := opcua.NewClient(proxyEP,
		opcua.SecurityMode(ua.MessageSecurityModeNone),
		opcua.AutoReconnect(true),
		opcua.ReconnectInterval(500*time.Millisecond),
		opcua.WithSubscriptionRecoveryHandler(func(ev opcua.SubscriptionRecoveryEvent) {
			mu.Lock()
			outcomes = append(outcomes, ev)
			mu.Unlock()
			t.Logf("recovery event: id=%d outcome=%s detail=%s",
				ev.SubscriptionID, ev.Outcome, ev.Detail)
		}),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })

	_, nsIdx := findNS(t, c)
	nodeID := ua.NewStringNodeID(nsIdx, "Dynamic.Counter")

	notifyCh := make(chan *opcua.PublishNotificationData, 16)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 200 * time.Millisecond}, notifyCh)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Cancel(context.Background()) })

	req := opcua.NewMonitoredItemCreateRequestWithDefaults(nodeID, ua.AttributeIDValue, 1)
	if _, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, req); err != nil {
		t.Fatalf("Monitor: %v", err)
	}
	drainInitial(t, notifyCh)

	// Ensure at least one live notification before disruption.
	_ = collectDataChange(t, notifyCh, 1, 10*time.Second)

	proxy.Disrupt()

	deadline := time.After(45 * time.Second)
	for {
		mu.Lock()
		n := len(outcomes)
		var last opcua.SubscriptionRecoveryEvent
		if n > 0 {
			last = outcomes[n-1]
		}
		mu.Unlock()
		if n > 0 {
			switch last.Outcome {
			case opcua.SubscriptionRecoveryTransferred,
				opcua.SubscriptionRecoveryRepublished,
				opcua.SubscriptionRecoveryRecreated,
				opcua.SubscriptionRecoveryPartial,
				opcua.SubscriptionRecoveryUnrecoverableGap:
				return last.Outcome
			}
		}
		select {
		case <-deadline:
			t.Fatalf("timeout waiting for SubscriptionRecoveryEvent; got %d events", n)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func TestOpen62541Server_SubscriptionRecoveryReconnect(t *testing.T) {
	t.Run("coverage/subscription.recovery.reconnect/go-client-to-open62541-server", func(t *testing.T) {
		h := startOpen62541Server(t)
		outcome := runReconnectRecovery(t, h.endpoint)
		t.Logf("open62541 recovery outcome=%s", outcome)
		if outcome == "" {
			t.Fatal("empty recovery outcome")
		}
	})
}

func TestMiloServer_SubscriptionRecoveryReconnect(t *testing.T) {
	t.Run("coverage/subscription.recovery.reconnect/go-client-to-milo-server", func(t *testing.T) {
		// Wave 4 confirmed Milo exposes Republish/Transfer service paths.
		h := startMiloServer(t)
		outcome := runReconnectRecovery(t, h.endpoint)
		t.Logf("milo recovery outcome=%s", outcome)
		if outcome == "" {
			t.Fatal("empty recovery outcome")
		}
	})
}
