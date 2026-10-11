// SPDX-License-Identifier: MIT

package chaos

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testhook"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
)

// Reverse connect under faults (Part 6 §7.1.3): the server opens the
// connections, to a client that listens for them. The chaos proxy sits on
// that path, so in its terms the "client" is the OPC UA server and the
// "backend" is the OPC UA client's listener.

const reverseAppURI = "urn:otfabric:chaos:reverse"

// reverseEnv is an env whose server reaches the clients through reverse
// connections that pass a chaos proxy of their own. The proxy of the env
// itself stays in place for clients that connect the usual way.
type reverseEnv struct {
	*env
	listener *uacp.ReverseListener
	rproxy   *testutil.ChaosProxy
}

func newReverseEnv(t *testing.T, seed int64) *reverseEnv {
	t.Helper()
	l, err := uacp.ListenReverse(context.Background(), "127.0.0.1:0", &uacp.ReverseListenerConfig{Logger: debugLogger()})
	if err != nil {
		t.Fatalf("chaos: reverse listener: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	r := &reverseEnv{listener: l}
	r.rproxy = testutil.NewChaosProxy(t, l.Addr().String(), seed)
	r.env = newEnv(t, seed,
		server.ApplicationURI(reverseAppURI),
		server.WithReverseConnect(r.rproxy.EndpointURL(),
			server.ReverseConnectRetryInterval(20*time.Millisecond, 250*time.Millisecond)),
	)
	return r
}

// reverseOption makes a client take its connection from the listener.
func (r *reverseEnv) reverseOption() opcua.Option {
	return opcua.ReverseConnectListener(r.listener, opcua.ReverseServerURI(reverseAppURI))
}

// target returns the reverse connect target of the running server.
func (r *reverseEnv) target() *server.ReverseConnect {
	srv := r.server()
	if srv == nil {
		return nil
	}
	if rcs := srv.ReverseConnects(); len(rcs) == 1 {
		return rcs[0]
	}
	return nil
}

// testhookChannels returns the number of secure channels srv holds.
func testhookChannels(srv *server.Server) int {
	return testhook.ServerResourcesOf(srv).Channels
}

// feed keeps counter 0 changing until the returned function is called.
func (e *env) feed() (stop func()) {
	var wg sync.WaitGroup
	done := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				e.bump(0)
				time.Sleep(2 * time.Millisecond)
			}
		}
	}()
	return func() { close(done); wg.Wait() }
}

// TestChaosReverseConnect drops, blackholes and refuses the reverse
// connection under a running subscription, and restarts the server. After
// every fault the client must return to Connected over a new connection the
// server opens, and the subscription must deliver again without ever going
// backwards. The usual invariants hold at the end: legal state transitions, a
// server that still serves a new client and holds nothing for the departed
// ones, and no goroutine left behind.
func TestChaosReverseConnect(t *testing.T) {
	verifyLeaks := leakCheck(t)
	r := newReverseEnv(t, seedFor(t))
	wd := newWatchdog(t)

	rec := newStateRecorder("reverse", true)
	c := r.connect(rec, r.reverseOption(),
		// short timeouts: a request or handshake swallowed by a blackhole
		// must return quickly
		opcua.RequestTimeout(2*time.Second),
		opcua.DialTimeout(2*time.Second),
		opcua.SessionTimeout(10*time.Second),
	)
	if rc := r.target(); rc == nil || rc.Connections() != 1 {
		t.Fatalf("the client is not connected over a reverse connection: %+v", rc)
	}
	// Nothing reached the server the usual way.
	if n := r.proxy.Accepted(); n != 0 {
		t.Fatalf("%d connection(s) were opened to the server", n)
	}

	stopFeed := r.feed()
	ctx, cancel := opCtx()
	defer cancel()
	st, err := openStreamWith(ctx, r.env, c, "reverse", 0, faultStreamParams(), 0)
	if err != nil {
		stopFeed()
		t.Fatal(err)
	}
	if !eventually(settleLimit, func() bool { return st.received.Load() > 3 }) {
		stopFeed()
		t.Fatal("no data before the faults")
	}

	// recovered waits for the client to reconnect and the stream to resume.
	recovered := func(fault string, reconnectsBefore int) {
		t.Helper()
		if !eventually(settleLimit, func() bool {
			return countState(rec, opcua.Reconnecting) > reconnectsBefore && c.State() == opcua.Connected
		}) {
			t.Fatalf("%s: client did not reconnect: state %v, transitions %v, target %v (%v)\n%s",
				fault, c.State(), rec.snapshot(), r.target().State(), r.target().Err(), allStacks())
		}
		marker := r.counters[0].Load()
		if !eventually(settleLimit, func() bool { return st.lastValue(0) > marker }) {
			t.Fatalf("%s: subscription did not resume: last delivered %d, node at %d; client subscriptions %v, server %+v",
				fault, st.lastValue(0), r.counters[0].Load(), c.SubscriptionIDs(), r.resources())
		}
	}

	faults := []struct {
		name  string
		apply func()
	}{
		{"drop", func() {
			// Reset the connection in use and the idle one behind it.
			r.rproxy.DropAll()
		}},
		{"blackhole", func() {
			// Both directions go silent, for the connection in use and for
			// the idle one behind it. Requests are no longer answered.
			r.rproxy.SetBlackhole(testutil.ClientToServer, true)
			r.rproxy.SetBlackhole(testutil.ServerToClient, true)
			rctx, rcancel := context.WithTimeout(context.Background(), opLimit)
			_, err := c.ReadValue(rctx, r.scratchID(0))
			rcancel()
			if err == nil {
				t.Errorf("blackhole: read succeeded over a silent connection")
			} else if !isConnectionError(err) {
				t.Errorf("blackhole: read failed with %v, want a connection-class error", err)
			}
			r.rproxy.SetBlackhole(testutil.ClientToServer, false)
			r.rproxy.SetBlackhole(testutil.ServerToClient, false)
			// Bytes were swallowed, so what is left of the byte streams is
			// cut inside a message. A real network would have lost these
			// connections too.
			r.rproxy.DropAll()
		}},
		{"client unreachable", func() {
			// The server cannot reach the client for a while: it retries
			// with back-off and reports why.
			r.rproxy.SetRefuse(true)
			r.rproxy.DropAll()
			rc := r.target()
			if !eventually(settleLimit, func() bool {
				return rc.State() == server.ReverseConnectBackoff && rc.Err() != nil
			}) {
				t.Errorf("client unreachable: target is %v (%v), want Backoff with an error", rc.State(), rc.Err())
			}
			// The client notices the reset of its connection on its own
			// goroutine and in its own time: wait for it instead of looking
			// once. (The server can be in Backoff before the client has
			// processed the reset; CI seed 1791779854273078837.) It cannot
			// be back already: nothing gets through to it.
			if !eventually(settleLimit, func() bool { return c.State() != opcua.Connected }) {
				t.Errorf("client unreachable: client still reports Connected")
			}
			r.rproxy.SetRefuse(false)
		}},
		{"server restart", func() {
			// A new server instance: it connects to the client again, with
			// no session and no subscription.
			r.stopServer()
			time.Sleep(50 * time.Millisecond)
			r.startServer()
		}},
		{"half-close", func() {
			r.rproxy.HalfClose(testutil.ServerToClient)
		}},
	}
	for round := range 2 {
		for _, f := range faults {
			name := fmt.Sprintf("round %d: %s", round, f.name)
			_ = wd.do(name, func() error {
				before := countState(rec, opcua.Reconnecting)
				t.Logf("%s %s", time.Now().Format("15:04:05.000"), name)
				f.apply()
				recovered(name, before)
				return nil
			})
		}
	}

	// The client ended up on a reverse connection again, and still nothing
	// was opened to the server.
	if rc := r.target(); !eventually(settleLimit, func() bool { return rc.Connections() == 1 }) {
		t.Errorf("target has %d connections in use after the faults, want 1 (state %v, %v)", rc.Connections(), rc.State(), rc.Err())
	}
	if n := r.proxy.Accepted(); n != 0 {
		t.Errorf("%d connection(s) were opened to the server", n)
	}

	rec.check(t, false)
	stopFeed()
	_ = wd.do("cancel stream", func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return st.sub.Cancel(ctx)
	})
	_ = wd.do("Close", func() error { closeClient(c, rec); return nil })
	st.close()
	st.report(t)
	if !eventually(settleLimit, func() bool { last, ok := rec.last(); return ok && last == opcua.Closed && c.State() == opcua.Closed }) {
		t.Errorf("client is %v after Close, reported %v", c.State(), rec.snapshot())
	}
	rec.check(t, true)

	// The server is healthy for a client that connects the usual way, and
	// for one more that waits for it.
	r.requireCleanClient()
	c2 := r.connect(nil, r.reverseOption(), opcua.AutoReconnect(false))
	ctx2, cancel2 := opCtx()
	if _, err := c2.ReadValue(ctx2, r.scratchID(0)); err != nil {
		t.Errorf("new reverse client: read: %v", err)
	}
	cancel2()
	closeClient(c2, nil)
	r.requireServerDrained(settleLimit)

	r.stopServer()
	r.proxy.Close()
	r.rproxy.Close()
	if err := r.listener.Close(); err != nil {
		t.Errorf("close listener: %v", err)
	}
	wd.close()
	verifyLeaks()
}

// TestReverseConnectShutdownLeavesNoGoroutines closes servers, targets,
// clients and listeners of reverse connections in every order and state and
// verifies each time that nothing is left running.
func TestReverseConnectShutdownLeavesNoGoroutines(t *testing.T) {
	ctx, cancel := opCtx()
	defer cancel()

	newListener := func(t *testing.T) *uacp.ReverseListener {
		t.Helper()
		l, err := uacp.ListenReverse(ctx, "127.0.0.1:0", nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close() })
		return l
	}
	newServer := func(t *testing.T, clientURL string) *server.Server {
		t.Helper()
		srv, err := server.New(
			server.EndPoint("localhost", 0),
			server.EnableSecurity("None", ua.MessageSecurityModeNone),
			server.EnableAuthMode(ua.UserTokenTypeAnonymous),
			server.ApplicationURI(reverseAppURI),
			server.WithReverseConnect(clientURL, server.ReverseConnectRetryInterval(10*time.Millisecond, 100*time.Millisecond)),
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := srv.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = srv.Close() })
		return srv
	}
	newClient := func(t *testing.T, opts ...opcua.Option) *opcua.Client {
		t.Helper()
		c, err := opcua.NewClient("", append([]opcua.Option{
			opcua.SecurityMode(ua.MessageSecurityModeNone),
			opcua.DialTimeout(30 * time.Second),
			opcua.RequestTimeout(30 * time.Second),
			opcua.ReconnectInterval(20 * time.Millisecond),
		}, opts...)...)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close(context.Background()) })
		return c
	}
	subscribe := func(t *testing.T, c *opcua.Client) {
		t.Helper()
		ch := make(chan *opcua.PublishNotificationData, 16)
		sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 20 * time.Millisecond}, ch)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth,
			opcua.NewMonitoredItemCreateRequestWithDefaults(ua.NewNumericNodeID(0, 2258), ua.AttributeIDValue, 1)); err != nil {
			t.Fatal(err)
		}
		select {
		case <-ch:
		case <-time.After(settleLimit):
			t.Fatal("no notification")
		}
	}

	t.Run("client closes first", func(t *testing.T) {
		verify := leakCheck(t)
		l := newListener(t)
		srv := newServer(t, "opc.tcp://"+l.Addr().String())
		c := newClient(t, opcua.ReverseConnectListener(l))
		if err := c.Connect(ctx); err != nil {
			t.Fatal(err)
		}
		subscribe(t, c)
		if err := c.Close(ctx); err != nil {
			t.Error(err)
		}
		if err := srv.Close(); err != nil {
			t.Error(err)
		}
		if err := l.Close(); err != nil {
			t.Error(err)
		}
		verify()
	})

	t.Run("server closes first", func(t *testing.T) {
		verify := leakCheck(t)
		l := newListener(t)
		srv := newServer(t, "opc.tcp://"+l.Addr().String())
		rec := newStateRecorder("c", true)
		c := newClient(t, opcua.ReverseConnectListener(l), opcua.WithConnStateHandler(rec.handle))
		if err := c.Connect(ctx); err != nil {
			t.Fatal(err)
		}
		subscribe(t, c)
		if err := srv.Close(); err != nil {
			t.Error(err)
		}
		// The client is back to waiting for a server that never comes.
		if !eventually(settleLimit, func() bool { return countState(rec, opcua.Reconnecting) > 0 }) {
			t.Errorf("client did not start waiting for the server again: %v", rec.snapshot())
		}
		closeClient(c, rec)
		rec.check(t, true)
		if err := l.Close(); err != nil {
			t.Error(err)
		}
		verify()
	})

	t.Run("target removed while in use", func(t *testing.T) {
		verify := leakCheck(t)
		l := newListener(t)
		srv := newServer(t, "opc.tcp://"+l.Addr().String())
		c := newClient(t, opcua.ReverseConnectListener(l), opcua.AutoReconnect(false))
		if err := c.Connect(ctx); err != nil {
			t.Fatal(err)
		}
		subscribe(t, c)
		rc := srv.ReverseConnects()[0]
		if err := rc.Close(); err != nil {
			t.Error(err)
		}
		if st := rc.State(); st != server.ReverseConnectClosed {
			t.Errorf("target state %v after Close", st)
		}
		if err := c.Close(ctx); err != nil {
			t.Error(err)
		}
		// Only the target's connections are gone: the server still runs.
		if !eventually(settleLimit, func() bool { return testhookChannels(srv) == 0 }) {
			t.Errorf("server still holds %d channel(s)", testhookChannels(srv))
		}
		if err := srv.Close(); err != nil {
			t.Error(err)
		}
		if err := l.Close(); err != nil {
			t.Error(err)
		}
		verify()
	})

	t.Run("client closed while waiting", func(t *testing.T) {
		verify := leakCheck(t)
		l := newListener(t)
		c := newClient(t, opcua.ReverseConnectListener(l), opcua.DialTimeout(0))
		errCh := make(chan error, 1)
		go func() { errCh <- c.Connect(context.Background()) }()
		// Wait until Connect is waiting at the listener, then close.
		if !eventually(settleLimit, func() bool { return c.State() == opcua.Connecting }) {
			t.Fatal("Connect did not start")
		}
		if err := c.Close(ctx); err != nil {
			t.Error(err)
		}
		select {
		case err := <-errCh:
			if err == nil {
				t.Error("Connect succeeded without a server")
			}
		case <-time.After(settleLimit):
			t.Fatalf("Connect did not return after Close\n%s", allStacks())
		}
		if err := l.Close(); err != nil {
			t.Error(err)
		}
		verify()
	})

	t.Run("own listener closed with the client", func(t *testing.T) {
		verify := leakCheck(t)
		// The port is taken by the listener of the first attempt that
		// manages to bind it.
		var c *opcua.Client
		var srv *server.Server
		ok := eventually(settleLimit, func() bool {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				return false
			}
			addr := ln.Addr().String()
			_ = ln.Close()
			c = newClient(t, opcua.ReverseConnect(addr, opcua.ReverseServerURI(reverseAppURI)), opcua.DialTimeout(5*time.Second))
			srv = newServer(t, "opc.tcp://"+addr)
			if err := c.Connect(ctx); err != nil {
				_ = c.Close(ctx)
				_ = srv.Close()
				return false
			}
			return true
		})
		if !ok {
			t.Fatal("could not connect over the client's own listener")
		}
		subscribe(t, c)
		if err := c.Close(ctx); err != nil {
			t.Error(err)
		}
		// The server keeps trying to reach the listener that is gone.
		rc := srv.ReverseConnects()[0]
		if !eventually(settleLimit, func() bool { return rc.State() == server.ReverseConnectBackoff }) {
			t.Errorf("target state %v, want Backoff", rc.State())
		}
		if err := srv.Close(); err != nil {
			t.Error(err)
		}
		verify()
	})

	t.Run("server closed while the client is unreachable", func(t *testing.T) {
		verify := leakCheck(t)
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		_ = ln.Close()
		srv := newServer(t, "opc.tcp://"+addr)
		rc := srv.ReverseConnects()[0]
		if !eventually(settleLimit, func() bool { return rc.State() == server.ReverseConnectBackoff && rc.Err() != nil }) {
			t.Errorf("target state %v (%v), want Backoff", rc.State(), rc.Err())
		}
		if err := srv.Close(); err != nil {
			t.Error(err)
		}
		verify()
	})

	t.Run("server closed with an idle connection", func(t *testing.T) {
		verify := leakCheck(t)
		l := newListener(t)
		srv := newServer(t, "opc.tcp://"+l.Addr().String())
		rc := srv.ReverseConnects()[0]
		if !eventually(settleLimit, func() bool { return rc.State() == server.ReverseConnectWaiting && l.Pending() == 1 }) {
			t.Errorf("target state %v, pending %d", rc.State(), l.Pending())
		}
		if err := srv.Close(); err != nil {
			t.Error(err)
		}
		// The listener notices that the announced connection is gone.
		if !eventually(settleLimit, func() bool { return l.Pending() == 0 }) {
			t.Errorf("listener still holds %d pending connection(s)", l.Pending())
		}
		if err := l.Close(); err != nil {
			t.Error(err)
		}
		verify()
	})
}
