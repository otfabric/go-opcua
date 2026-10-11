// SPDX-License-Identifier: MIT

package discovery

import (
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// registrant is a server that registers with a discovery server.
type registrant struct {
	uri  string
	name string
	srv  *server.Server
	log  *eventLog
}

// ldsHolder is a discovery server that can be restarted: a restart loses the
// table, like a crash of a real one does.
type ldsHolder struct {
	t     *testing.T
	wd    *chaoskit.Watchdog
	sink  *chaoskit.ErrSink
	opts  []server.LDSOption
	proxy *testutil.ChaosProxy

	mu       sync.Mutex
	srv      *server.Server
	known    map[string]bool // ServerUris that may register
	restarts int
}

func (h *ldsHolder) allow(uri string) {
	h.mu.Lock()
	h.known[uri] = true
	h.mu.Unlock()
}

// accepted is the registration callback of the discovery server: whatever it
// accepts must come from a registrant of the test.
func (h *ldsHolder) accepted(rs *ua.RegisteredServer) {
	h.mu.Lock()
	known := h.known[rs.ServerURI]
	h.mu.Unlock()
	if !known {
		h.sink.Addf("the discovery server accepted a request for the unknown server %q", rs.ServerURI)
	}
}

func (h *ldsHolder) current() *server.Server {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.srv
}

// start starts a discovery server and points the proxy at it.
func (h *ldsHolder) start() {
	h.t.Helper()
	opts := append([]server.LDSOption{server.LDSRegistrationCallback(h.accepted)}, h.opts...)
	srv := mustStart(h.t, h.wd, serverOpts(
		server.ApplicationURI("urn:chaos:discovery:lds"),
		server.ServerName("LDS"),
		server.WithLocalDiscoveryServer(opts...),
	)...)
	h.mu.Lock()
	h.srv = srv
	h.mu.Unlock()
	h.proxy.SetBackend(fmt.Sprintf("localhost:%d", srv.Port()))
}

// restart closes the discovery server and starts a new, empty one on another
// port.
func (h *ldsHolder) restart() {
	h.t.Helper()
	closeServer(h.sink, h.wd, "the discovery server", h.current(), closeSlack)
	h.start()
	h.mu.Lock()
	h.restarts++
	h.mu.Unlock()
}

// TestRegistrationUnderFaults puts the fault proxy between registering
// servers and their discovery server. While the servers register and renew,
// the proxy resets, refuses, blackholes, stalls, delays, fragments, throttles,
// truncates and half-closes the connections, the discovery server is
// restarted (and loses its table), and registrants are closed and replaced in
// the middle of all that: also while the discovery server swallows what they
// send, their unregistration included.
//
// Invariants:
//
//   - Start never waits for the discovery server; Close returns within the
//     time one registration attempt and the unregistration may take
//   - the discovery server only ever accepts requests of the registrants
//   - once the faults stop, the table of the discovery server and the result
//     of FindServers are exactly the live registrants with their discovery
//     URLs: servers that closed are gone, by unregistration or by expiry
//   - the events of every registration loop are consistent (see
//     eventLog.check) and every live registrant registers again after the
//     faults
//   - no goroutine is left behind (TestMain)
func TestRegistrationUnderFaults(t *testing.T) {
	t.Parallel()
	seed := chaoskit.Seed(t)
	rng := rand.New(rand.NewSource(seed))
	dur := chaoskit.Duration(t, 2500*time.Millisecond)
	wd := chaoskit.NewWatchdog(t)
	sink := &chaoskit.ErrSink{}
	defer sink.Report(t)

	const (
		population = 6
		reqTimeout = 500 * time.Millisecond
		// An attempt that is cut short by Close and the unregistration are
		// each bounded by the request timeout.
		closeBound = 2*reqTimeout + closeSlack
	)

	proxy := testutil.NewChaosProxy(t, "", seed)
	lds := &ldsHolder{t: t, wd: wd, sink: sink, proxy: proxy, known: map[string]bool{},
		opts: []server.LDSOption{
			server.LDSAllowInsecureRegistration(),
			// Short enough for the registrations of servers that could not
			// unregister to expire within the test, long enough for a live
			// server to renew in time once the faults are over.
			server.LDSRegistrationTimeout(1500 * time.Millisecond),
		}}
	lds.start()
	regURL := proxy.EndpointURL()

	next := 0
	start := func() *registrant {
		t.Helper()
		next++
		r := &registrant{
			uri:  fmt.Sprintf("urn:chaos:discovery:registrant:%d", next),
			name: fmt.Sprintf("Registrant%d", next),
			log:  &eventLog{},
		}
		lds.allow(r.uri)
		r.srv = mustStart(t, wd, serverOpts(
			server.ApplicationURI(r.uri),
			server.ServerName(r.name),
			server.WithDiscoveryRegistration(regURL,
				server.RegisterInsecure(),
				server.RegisterInterval(40*time.Millisecond),
				server.RegisterBackoff(10*time.Millisecond, 100*time.Millisecond),
				server.RegisterRequestTimeout(reqTimeout),
				server.RegisterEventHandler(r.log.handle),
			),
		)...)
		return r
	}
	var (
		closed []*registrant
		worst  time.Duration
	)
	stop := func(r *registrant) {
		d := closeServer(sink, wd, r.name, r.srv, closeBound)
		worst = max(worst, d)
		r.log.markClosed()
		closed = append(closed, r)
	}
	truth := func(live []*registrant) table {
		want := table{}
		for _, r := range live {
			want[r.uri] = r.srv.URLs()
		}
		return want
	}
	converge := func(phase string, live []*registrant) {
		t.Helper()
		want := truth(live)
		var got table
		if !chaoskit.Eventually(settleLimit, func() bool {
			got = registered(sink, lds.current())
			return got.equal(want)
		}) {
			t.Fatalf("%s: the table of the discovery server did not converge:\n  have:%v\n  want:%v", phase, got, want)
		}
	}

	var live []*registrant
	for i := 0; i < population; i++ {
		live = append(live, start())
	}
	converge("before the faults", live)

	// --- fault phase ---------------------------------------------------------
	faults := map[string]int{}
	fault := func(name string) { faults[name]++ }
	dirOf := func() testutil.Direction { return testutil.Direction(rng.Intn(2)) }
	deadline := time.Now().Add(dur)
	for time.Now().Before(deadline) {
		switch rng.Intn(12) {
		case 0:
			fault("reset")
			proxy.DropAll()
		case 1:
			fault("refuse")
			proxy.SetRefuse(true)
			proxy.DropAll()
		case 2:
			fault("blackhole")
			proxy.SetBlackhole(dirOf(), true)
		case 3:
			fault("blackhole both")
			proxy.SetBlackhole(testutil.ClientToServer, true)
			proxy.SetBlackhole(testutil.ServerToClient, true)
		case 4:
			fault("stall")
			proxy.SetStall(dirOf(), true)
		case 5:
			fault("latency")
			proxy.SetLatency(time.Duration(rng.Intn(30))*time.Millisecond, time.Duration(1+rng.Intn(40))*time.Millisecond)
		case 6:
			fault("fragment")
			proxy.SetFragment(1 + rng.Intn(7))
		case 7:
			fault("throttle")
			proxy.SetThrottle(2000 + rng.Intn(20000))
		case 8:
			fault("truncate")
			proxy.TruncateNext(dirOf(), 1+rng.Intn(200))
		case 9:
			fault("half-close")
			proxy.HalfClose(dirOf())
		case 10:
			fault("restart of the discovery server")
			lds.restart()
		case 11:
			fault("none")
		}
		time.Sleep(time.Duration(40+rng.Intn(160)) * time.Millisecond)

		// A registrant leaves while the fault is standing: its attempt in
		// flight is cut short and its unregistration may go nowhere. Another
		// one takes its place and starts with the discovery server in
		// whatever state it is in.
		if rng.Intn(3) == 0 {
			i := rng.Intn(len(live))
			stop(live[i])
			live[i] = start()
		}
		if rng.Intn(3) != 0 {
			proxy.Heal()
		}
	}
	proxy.Heal()
	t.Logf("faults: %v; %d registrants closed during the faults, slowest Close %v", faults, len(closed), worst)

	// --- after the faults ----------------------------------------------------
	converge("after the faults", live)

	// Every live registrant keeps renewing.
	before := make([]int, len(live))
	for i, r := range live {
		before[i] = r.log.registrations()
	}
	for i, r := range live {
		if !chaoskit.Eventually(settleLimit, func() bool { return r.log.registrations() >= before[i]+2 }) {
			t.Fatalf("%s does not register any more after the faults", r.name)
		}
	}
	converge("after the faults, renewed", live)

	// What a client is told is the same.
	ctx, cancel := chaoskit.OpCtx()
	servers, err := opcua.FindServers(ctx, serverURL(lds.current()))
	cancel()
	if err != nil {
		t.Fatalf("FindServers after the faults: %v", err)
	}
	if got, want := found(sink, "urn:chaos:discovery:lds", servers), truth(live); !got.equal(want) {
		t.Errorf("FindServers after the faults:\n  have:%v\n  want:%v", got, want)
	}
	if len(servers) != len(live)+1 {
		t.Errorf("FindServers after the faults: %d servers, want the discovery server and %d registrants", len(servers), len(live))
	}

	// --- everybody leaves, at the same time ----------------------------------
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, r := range live {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := closeServer(sink, wd, r.name, r.srv, closeBound)
			r.log.markClosed()
			mu.Lock()
			worst = max(worst, d)
			mu.Unlock()
		}()
	}
	if !wd.Wait("closing the registrants", &wg) {
		return
	}
	closed = append(closed, live...)
	// The discovery server was reachable, so the registrants unregistered,
	// unless the machine was too slow for the short request timeout: what is
	// left then expires.
	lingering := len(lds.current().RegisteredServers())
	converge("after the registrants closed", nil)
	t.Logf("%d registrants closed, slowest Close %v; %d registration(s) left to expire; discovery server restarted %d times",
		len(closed), worst, lingering, lds.restarts)

	for _, r := range closed {
		r.log.check(sink, expectation{name: r.name, url: regURL,
			policy: ua.SecurityPolicyURINone, mode: ua.MessageSecurityModeNone})
	}
	closeServer(sink, wd, "the discovery server", lds.current(), closeSlack)
}

// TestCloseWhileDiscoveryServerSwallows closes a registering server at the
// moments its discovery server is of no use to it, each of them on purpose:
// the discovery server swallows the connection attempt, the RegisterServer2
// request or its response, or the unregistration, by dropping the bytes
// (blackhole) or by not reading them (stall).
//
// Invariants: Start does not wait for the discovery server; Close returns
// within the time the attempt it cuts short and the unregistration may take;
// the events are consistent; a server that is or may be registered tries to
// unregister, and a server the discovery server never heard of does not.
func TestCloseWhileDiscoveryServerSwallows(t *testing.T) {
	t.Parallel()
	wd := chaoskit.NewWatchdog(t)
	sink := &chaoskit.ErrSink{}
	defer sink.Report(t)

	const (
		reqTimeout = 500 * time.Millisecond
		closeBound = 2*reqTimeout + closeSlack
	)
	proxy := testutil.NewChaosProxy(t, "", 1)
	// onAccept is called when the discovery server has accepted a request
	// and before it answers.
	var (
		hookMu   sync.Mutex
		onAccept func(rs *ua.RegisteredServer)
	)
	setHook := func(fn func(rs *ua.RegisteredServer)) {
		hookMu.Lock()
		onAccept = fn
		hookMu.Unlock()
	}
	lds := mustStart(t, wd, serverOpts(
		server.ApplicationURI("urn:chaos:discovery:lds"),
		server.WithLocalDiscoveryServer(
			server.LDSAllowInsecureRegistration(),
			server.LDSRegistrationCallback(func(rs *ua.RegisteredServer) {
				hookMu.Lock()
				fn := onAccept
				hookMu.Unlock()
				if fn != nil {
					fn(rs)
				}
			}),
		),
	)...)
	proxy.SetBackend(fmt.Sprintf("localhost:%d", lds.Port()))

	swallow := map[string]func(d testutil.Direction){
		"blackhole": func(d testutil.Direction) { proxy.SetBlackhole(d, true) },
		"stall":     func(d testutil.Direction) { proxy.SetStall(d, true) },
	}
	n := 0
	for _, how := range []string{"blackhole", "stall"} {
		for _, when := range []string{"connect", "request", "response", "unregistration"} {
			n++
			name := fmt.Sprintf("%s/%s", how, when)
			log := &eventLog{}
			reached := make(chan struct{}, 16)

			switch when {
			case "connect":
				// Nothing the server sends arrives, from the Hello on.
				swallow[how](testutil.ClientToServer)
			case "request":
				// The channel is opened; the request goes nowhere.
				proxy.SetMangle(testutil.ClientToServer, onFirstRequest(func(b []byte) []byte {
					swallow[how](testutil.ClientToServer)
					reached <- struct{}{}
					return nil
				}))
			case "response":
				// The discovery server registers the server; its answer
				// goes nowhere.
				setHook(func(*ua.RegisteredServer) {
					swallow[how](testutil.ServerToClient)
					reached <- struct{}{}
				})
			}

			srv := mustStart(t, wd, serverOpts(
				server.ApplicationURI(fmt.Sprintf("urn:chaos:discovery:swallowed:%d", n)),
				server.ServerName(fmt.Sprintf("Swallowed%d", n)),
				server.WithDiscoveryRegistration(proxy.EndpointURL(),
					server.RegisterInsecure(),
					server.RegisterInterval(time.Hour),
					// An attempt that times out on a slow machine before
					// it gets to the point is repeated.
					server.RegisterBackoff(20*time.Millisecond, 100*time.Millisecond),
					server.RegisterRequestTimeout(reqTimeout),
					server.RegisterEventHandler(log.handle),
				),
			)...)

			// Close at the moment in question.
			switch when {
			case "connect":
				time.Sleep(20 * time.Millisecond)
			case "request", "response":
				select {
				case <-reached:
				case <-time.After(settleLimit):
					t.Fatalf("%s: the registration request was not sent", name)
				}
			case "unregistration":
				if !chaoskit.Eventually(settleLimit, func() bool { return log.registrations() == 1 }) {
					t.Fatalf("%s: the server did not register", name)
				}
				swallow[how](testutil.ClientToServer)
				swallow[how](testutil.ServerToClient)
			}
			took := closeServer(sink, wd, name, srv, closeBound)
			log.markClosed()

			events := log.snapshot()
			if when == "connect" {
				// The discovery server never heard of the server: there is
				// nothing to unregister. (A failed attempt is only reported
				// if the machine is so slow that it timed out before Close.)
				for _, e := range events {
					if !e.Online || e.Err == nil {
						sink.Addf("%s: events %+v, want no registration and no unregistration", name, events)
					}
				}
			} else if last := len(events) - 1; last < 0 || events[last].Online || events[last].Err == nil {
				// The server is, or may be, registered: it tried to
				// unregister, in vain.
				sink.Addf("%s: events %+v, want a failed unregistration at the end", name, events)
			}
			log.check(sink, expectation{name: name, url: proxy.EndpointURL(),
				policy: ua.SecurityPolicyURINone, mode: ua.MessageSecurityModeNone})
			t.Logf("%s: Close took %v, %d event(s)", name, took.Round(time.Millisecond), len(events))

			setHook(nil)
			proxy.Heal()
			proxy.DropAll()
		}
	}
	closeServer(sink, wd, "the discovery server", lds, closeSlack)
}
