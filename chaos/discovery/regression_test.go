// SPDX-License-Identifier: MIT

package discovery

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// TestRegressionUnregisterAfterLostResponse pins down a registration that the
// discovery server accepted but whose response never reached the server: the
// attempt failed, and a server that was closed before its next attempt
// succeeded did not unregister, because it did not know that it was
// registered. The discovery server kept handing out the dead server until the
// registration timed out (an hour by default).
func TestRegressionUnregisterAfterLostResponse(t *testing.T) {
	t.Parallel()
	wd := chaoskit.NewWatchdog(t)
	sink := &chaoskit.ErrSink{}
	defer sink.Report(t)

	proxy := testutil.NewChaosProxy(t, "", 1)
	// The discovery server accepts the registration; its response is lost
	// with the connection.
	var accepted atomic.Int32
	lds := mustStart(t, wd, serverOpts(
		server.ApplicationURI("urn:chaos:discovery:lds"),
		server.WithLocalDiscoveryServer(
			server.LDSAllowInsecureRegistration(),
			server.LDSRegistrationCallback(func(rs *ua.RegisteredServer) {
				if rs.IsOnline && accepted.Add(1) == 1 {
					proxy.SetBlackhole(testutil.ServerToClient, true)
					proxy.DropAll()
				}
			}),
		),
	)...)
	proxy.SetBackend(fmt.Sprintf("localhost:%d", lds.Port()))

	log := &eventLog{}
	const uri = "urn:chaos:discovery:lost-response"
	srv := mustStart(t, wd, serverOpts(
		server.ApplicationURI(uri),
		server.ServerName("LostResponse"),
		server.WithDiscoveryRegistration(proxy.EndpointURL(),
			server.RegisterInsecure(),
			// The next attempt is far away: Close comes first.
			server.RegisterBackoff(time.Hour, time.Hour),
			server.RegisterRequestTimeout(10*time.Second),
			server.RegisterEventHandler(log.handle),
		),
	)...)

	// The one attempt fails although the server is registered.
	if !chaoskit.Eventually(settleLimit, func() bool { return len(log.snapshot()) == 1 }) {
		t.Fatalf("no registration attempt was reported")
	}
	if ev := log.snapshot()[0]; ev.Err == nil || !ev.Online {
		t.Fatalf("the registration whose response was lost was reported as %+v", ev)
	}
	if got := registered(sink, lds); len(got) != 1 || got[uri] == nil {
		t.Fatalf("the discovery server does not have the registration:%v", got)
	}

	// The discovery server can be reached again; Close unregisters.
	proxy.Heal()
	closeServer(sink, wd, "the registrant", srv, closeSlack)
	log.markClosed()
	if got := registered(sink, lds); len(got) != 0 {
		t.Errorf("the closed server is still registered:%v", got)
	}
	events := log.snapshot()
	if last := events[len(events)-1]; len(events) != 2 || last.Online || last.Err != nil {
		t.Errorf("want a failed registration and a successful unregistration, got %+v", events)
	}
}

// TestRegressionCloseDuringRegistration pins down a server that is closed
// while its registration request is on its way. Close gave up on the request
// and unregistered on a new channel; the discovery server, which had nothing
// to remove yet, then got the request and registered the server that was
// already closed, for as long as the registration timeout (an hour by
// default).
func TestRegressionCloseDuringRegistration(t *testing.T) {
	t.Parallel()
	wd := chaoskit.NewWatchdog(t)
	sink := &chaoskit.ErrSink{}
	defer sink.Report(t)

	lds := mustStart(t, wd, serverOpts(
		server.ApplicationURI("urn:chaos:discovery:lds"),
		server.WithLocalDiscoveryServer(server.LDSAllowInsecureRegistration()),
	)...)
	proxy := testutil.NewChaosProxy(t, fmt.Sprintf("localhost:%d", lds.Port()), 1)
	// The registration request is held up on its way to the discovery
	// server; what follows on other connections is not delayed.
	delayed := make(chan struct{})
	proxy.SetMangle(testutil.ClientToServer, onFirstRequest(func(b []byte) []byte {
		close(delayed)
		time.Sleep(500 * time.Millisecond)
		return b
	}))

	log := &eventLog{}
	srv := mustStart(t, wd, serverOpts(
		server.ApplicationURI("urn:chaos:discovery:closed-early"),
		server.ServerName("ClosedEarly"),
		server.WithDiscoveryRegistration(proxy.EndpointURL(),
			server.RegisterInsecure(),
			server.RegisterInterval(time.Hour),
			server.RegisterRequestTimeout(30*time.Second),
			server.RegisterEventHandler(log.handle),
		),
	)...)
	select {
	case <-delayed:
	case <-time.After(settleLimit):
		t.Fatalf("the registration request was not sent")
	}
	closeServer(sink, wd, "the registrant", srv, closeSlack)
	log.markClosed()

	// The request has arrived by now, if it was abandoned: nothing may be
	// registered, now or later.
	time.Sleep(700 * time.Millisecond)
	if got := registered(sink, lds); len(got) != 0 {
		t.Errorf("the closed server is registered:%v", got)
	}
	events := log.snapshot()
	if len(events) != 2 || !events[0].Online || events[0].Err != nil || events[1].Online || events[1].Err != nil {
		t.Errorf("want a registration and an unregistration, got %+v", events)
	}
}

// TestRegressionUnregistrationBoundedByRequestTimeout pins down the time
// Close spends on a discovery server that answers too slowly. The request
// timeout bounds the unregistration as a whole, but OpenSecureChannel was
// given a full request timeout of its own after the connection had already
// used most of the first: Close took almost twice as long as documented.
func TestRegressionUnregistrationBoundedByRequestTimeout(t *testing.T) {
	t.Parallel()
	wd := chaoskit.NewWatchdog(t)
	sink := &chaoskit.ErrSink{}
	defer sink.Report(t)

	const reqTimeout = 2 * time.Second
	lds := mustStart(t, wd, serverOpts(
		server.ApplicationURI("urn:chaos:discovery:lds"),
		server.WithLocalDiscoveryServer(server.LDSAllowInsecureRegistration()),
	)...)
	proxy := testutil.NewChaosProxy(t, fmt.Sprintf("localhost:%d", lds.Port()), 1)

	log := &eventLog{}
	srv := mustStart(t, wd, serverOpts(
		server.ApplicationURI("urn:chaos:discovery:slow-lds"),
		server.ServerName("SlowLDS"),
		server.WithDiscoveryRegistration(proxy.EndpointURL(),
			server.RegisterInsecure(),
			server.RegisterInterval(time.Hour),
			server.RegisterRequestTimeout(reqTimeout),
			server.RegisterEventHandler(log.handle),
		),
	)...)
	if !chaoskit.Eventually(settleLimit, func() bool { return log.registrations() == 1 }) {
		t.Fatalf("the server did not register")
	}

	// Every answer of the discovery server now takes 90% of the request
	// timeout: the Acknowledge arrives in time, the OpenSecureChannel
	// response would arrive after 180% of it.
	proxy.SetMangle(testutil.ServerToClient, func(b []byte) []byte {
		time.Sleep(reqTimeout * 9 / 10)
		return b
	})
	took := closeServer(sink, wd, "the registrant", srv, closeSlack)
	log.markClosed()
	proxy.Heal()
	proxy.DropAll()
	if limit := reqTimeout * 14 / 10; took > limit {
		t.Errorf("Close took %v with a request timeout of %v: the unregistration is not bounded by it", took, reqTimeout)
	}
	events := log.snapshot()
	if last := events[len(events)-1]; len(events) != 2 || last.Online || last.Err == nil {
		t.Errorf("want a registration and a failed unregistration, got %+v", events)
	}
}
