// SPDX-License-Identifier: MIT

package discovery

import (
	"context"
	"fmt"
	"math/rand"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/mdns"
	"github.com/otfabric/go-opcua/internal/testhook"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// TestDiscoveryLifecycle starts and stops discovery servers, servers that
// register with them and mDNS responders in every order, including with a
// discovery server that is down and with a registration that is cut off by
// Close. Whatever the order, Close returns in time and none of the background
// goroutines of the discovery machinery (registration loops, registration
// cleanup, mDNS readers and timers, the channels to the discovery server)
// survives it.
//
// The test is serial: it checks for leaked goroutines.
func TestDiscoveryLifecycle(t *testing.T) {
	seed := chaoskit.Seed(t)
	rng := rand.New(rand.NewSource(seed))
	wd := chaoskit.NewWatchdog(t)
	// A discovery server that never answers: the proxy accepts the
	// connection and resets it.
	dead := testutil.NewChaosProxy(t, "127.0.0.1:1", seed)
	dead.SetRefuse(true)
	// The helpers above have goroutines of their own; everything started
	// from here on must be gone at the end.
	verifyLeaks := chaoskit.LeakCheck(t)

	start := func(opts ...server.Option) *server.Server {
		t.Helper()
		all := append([]server.Option{
			server.EndPoint("localhost", 0),
			server.EnableSecurity("None", ua.MessageSecurityModeNone),
			server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		}, opts...)
		srv, err := server.New(all...)
		if err != nil {
			t.Fatalf("chaos: new server: %v", err)
		}
		if err := wd.Do("Start", func() error { return srv.Start(context.Background()) }); err != nil {
			t.Fatalf("chaos: start server: %v", err)
		}
		return srv
	}
	stop := func(srv *server.Server) {
		t.Helper()
		begin := time.Now()
		_ = wd.Do("Close", srv.Close)
		if d := time.Since(begin); d > 30*time.Second {
			t.Errorf("Close took %v", d)
		}
	}

	const rounds = 12
	for round := 0; round < rounds; round++ {
		link := mdns.NewMemNetwork()
		onLink := testhook.ServerMulticastTransport(link).(server.Option)

		lds := start(
			server.ApplicationURI("urn:chaos:lds"),
			server.WithLocalDiscoveryServer(server.LDSAllowInsecureRegistration(), server.LDSRegistrationTimeout(time.Second)),
			server.WithMulticastDiscovery(server.MulticastHostname("lds")),
			onLink,
		)
		ldsURL := fmt.Sprintf("opc.tcp://localhost:%d", lds.Port())

		var ok, bad atomic.Int32
		count := func(e server.RegistrationEvent) {
			if e.Err == nil {
				ok.Add(1)
			} else {
				bad.Add(1)
			}
		}
		registrant := start(
			server.ApplicationURI(fmt.Sprintf("urn:chaos:registrant:%d", round)),
			server.ServerName("Registrant"),
			server.WithMulticastDiscovery(server.MulticastHostname("registrant"), server.MulticastCapabilities("DA")),
			onLink,
			server.WithDiscoveryRegistration(ldsURL,
				server.RegisterInsecure(),
				server.RegisterInterval(5*time.Millisecond),
				server.RegisterBackoff(time.Millisecond, 10*time.Millisecond),
				server.RegisterRequestTimeout(10*time.Second),
				server.RegisterEventHandler(count),
			),
			server.WithDiscoveryRegistration(dead.EndpointURL(),
				server.RegisterInsecure(),
				server.RegisterBackoff(time.Millisecond, 5*time.Millisecond),
				server.RegisterRequestTimeout(10*time.Second),
				server.RegisterEventHandler(count),
			),
		)

		// In some rounds everything is torn down right away, in the middle
		// of the first registration and of the mDNS announcements.
		if round%3 != 0 {
			if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool { return ok.Load() >= 3 && bad.Load() >= 3 }) {
				t.Fatalf("round %d: %d successful and %d failed registration attempts", round, ok.Load(), bad.Load())
			}
			// Three servers on the network for both: the discovery server,
			// the registrant announcing itself, and the registrant as
			// announced by the discovery server it registered with.
			if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool {
				return len(lds.ServersOnNetwork()) == 3 && len(registrant.ServersOnNetwork()) == 3
			}) {
				t.Fatalf("round %d: servers on network: lds %d, registrant %d", round,
					len(lds.ServersOnNetwork()), len(registrant.ServersOnNetwork()))
			}
			ctx, cancel := chaoskit.OpCtx()
			servers, err := opcua.FindServers(ctx, ldsURL)
			cancel()
			if err != nil || len(servers) != 2 {
				t.Fatalf("round %d: FindServers: %v, %d servers", round, err, len(servers))
			}
		}

		// Either one goes first. When the discovery server is gone, the
		// registrant's unregistration fails and must not hold up Close.
		if rng.Intn(2) == 0 {
			stop(lds)
			stop(registrant)
		} else {
			stop(registrant)
			if n := len(lds.RegisteredServers()); round%3 != 0 && n != 0 {
				t.Errorf("round %d: %d servers still registered after the registrant closed", round, n)
			}
			stop(lds)
		}
		// Closing twice is harmless.
		stop(registrant)
	}

	verifyLeaks()
}
