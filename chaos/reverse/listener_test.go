// SPDX-License-Identifier: MIT

package reverse

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
)

// waitingClient is a client whose Connect is waiting at a listener.
type waitingClient struct {
	name string
	rec  *chaoskit.StateRecorder
	c    *opcua.Client
	err  chan error
}

// startWaiting creates a client and calls Connect in the background.
func startWaiting(t *testing.T, name, endpoint string, opts ...opcua.Option) *waitingClient {
	t.Helper()
	w := &waitingClient{name: name, rec: chaoskit.NewStateRecorder(name, false), err: make(chan error, 1)}
	c, err := opcua.NewClient(endpoint, append(opts, opcua.AutoReconnect(false), opcua.WithConnStateHandler(w.rec.Handle))...)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	w.c = c
	t.Cleanup(func() { chaoskit.CloseClient(c, nil) })
	go func() {
		ctx, cancel := chaoskit.OpCtx()
		defer cancel()
		w.err <- c.Connect(ctx)
	}()
	return w
}

// TestReverseListenerClosedWhileWaiting closes a listener that is busy in
// every way a listener can be: two servers are in the middle of announcing
// themselves (their ReverseHello message is stuck on the way), a peer sent
// half a message, a server nobody asked for has announced itself, three
// clients wait in Connect (with and without a dial timeout, for a server
// that is stuck and for one that does not exist) and a client that lost its
// connection waits to reconnect.
//
// Close must return at once, and with it every Connect, with an error that
// says that the listener is closed. The half-open connections must be
// closed. The client that reconnects keeps waiting (it never gives up on its
// own) and can be closed at once. The servers must notice, report why, and
// keep trying with back-off, not in a tight loop. Nothing may be left when
// everything is closed.
func TestReverseListenerClosedWhileWaiting(t *testing.T) {
	// The certificates are created before the goroutines are counted.
	profiles := map[string]profile{
		"stuck-a": noneProfile("urn:otfabric:chaos:reverse:stuck-a"),
		"stuck-b": aeadProfile(t, "urn:otfabric:chaos:reverse:stuck-b"),
		"unasked": noneProfile("urn:otfabric:chaos:reverse:unasked"),
		"used":    rsaProfile(t),
	}
	verifyLeaks := chaoskit.LeakCheck(t)
	wd := chaoskit.NewWatchdog(t)

	l := listen(t, nil)
	// What the servers behind this proxy send does not arrive.
	stalled := testutil.NewChaosProxy(t, l.Addr().String(), 1)
	stalled.SetStall(testutil.ClientToServer, true)
	plain := testutil.NewChaosProxy(t, l.Addr().String(), 2)

	// The servers that will be stuck fetch nothing through the listener, so
	// they can be started right away.
	stuckA := newNode(t, "stuck-a", 0, profiles["stuck-a"], 1).up(stalled.EndpointURL())
	stuckB := newNode(t, "stuck-b", 1, profiles["stuck-b"], 2).up(stalled.EndpointURL())
	unasked := newNode(t, "unasked", 2, profiles["unasked"], 3).up(plain.EndpointURL())
	used := newNode(t, "used", 3, profiles["used"], 4).up(plain.EndpointURL())
	nodes := []*node{stuckA, stuckB, unasked, used}

	logf(t, "servers started")
	// A peer that sends half a ReverseHello message.
	raw, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	if _, err := raw.Write([]byte("RHEF\x40")); err != nil {
		t.Fatal(err)
	}

	// A client with a session and a subscription whose server stops
	// connecting to it: it waits to reconnect.
	recUsed := chaoskit.NewStateRecorder("used", true)
	cUsed := used.connect(recUsed, used.reverseOption(l),
		opcua.RequestTimeout(3*time.Second), opcua.DialTimeout(30*time.Second))
	ctx, cancel := chaoskit.OpCtx()
	defer cancel()
	stopFeed := used.feed()
	st, err := openStream(ctx, used, cUsed, "used")
	if err != nil {
		stopFeed()
		t.Fatal(err)
	}
	if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool { return st.received.Load() > 0 }) {
		t.Error("no data before the listener is closed")
	}
	stopFeed()
	if err := used.target().Close(); err != nil {
		t.Error(err)
	}

	// Clients waiting in Connect: without a time limit for a server that is
	// stuck, with a dial timeout for the other one, and for a server that
	// does not exist.
	waiting := []*waitingClient{
		startWaiting(t, "waits for stuck-a", stuckA.url(),
			stuckA.clientOptions(nil, stuckA.reverseOption(l), opcua.DialTimeout(0))...),
		startWaiting(t, "waits for stuck-b", stuckB.url(),
			stuckB.clientOptions(nil, stuckB.reverseOption(l), opcua.DialTimeout(60*time.Second))...),
		startWaiting(t, "waits for nobody", "",
			opcua.SecurityMode(ua.MessageSecurityModeNone), opcua.DialTimeout(0),
			opcua.ReverseConnectListener(l, opcua.ReverseServerURI("urn:otfabric:chaos:reverse:nobody"))),
	}

	// Everything is in place.
	if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool {
		for _, w := range waiting {
			if w.c.State() != opcua.Connecting {
				return false
			}
		}
		return stalled.ActiveLinks() == 2 && l.Pending() == 1 &&
			cUsed.State() == opcua.Reconnecting && recUsed.Count(opcua.Reconnecting) > 0
	}) {
		t.Fatalf("setup: %d stuck connection(s), %d pending, client is %v (%v)",
			stalled.ActiveLinks(), l.Pending(), cUsed.State(), recUsed.Snapshot())
	}
	for _, n := range []*node{stuckA, stuckB, unasked} {
		// These servers believe that the client knows of their connection.
		if rc := n.target(); !chaoskit.Eventually(chaoskit.SettleLimit, func() bool { return rc.State() == server.ReverseConnectWaiting }) {
			t.Errorf("%s: %s, want Waiting", n.name, n.describeTarget())
		}
	}
	logf(t, "everything is waiting")
	// Let the clients get from "Connecting" to the listener.
	time.Sleep(50 * time.Millisecond)

	start := time.Now()
	if err := wd.Do("listener Close", l.Close); err != nil {
		t.Errorf("close listener: %v", err)
	}
	if d := time.Since(start); d > promptLimit {
		t.Errorf("closing the listener took %v", d)
	}
	logf(t, "listener closed in %v", time.Since(start))

	// Every Connect returns, with the reason.
	for _, w := range waiting {
		select {
		case err := <-w.err:
			if !errors.Is(err, net.ErrClosed) {
				t.Errorf("%s: Connect returned %v, want an error that wraps net.ErrClosed", w.name, err)
			}
		case <-time.After(promptLimit):
			t.Fatalf("%s: Connect did not return after the listener was closed (%v since Close)\n%s",
				w.name, time.Since(start), chaoskit.AllStacks())
		}
		if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool { return w.c.State() == opcua.Closed }) {
			t.Errorf("%s: client is %v after the failed Connect", w.name, w.c.State())
		}
		w.rec.Check(t, true)
	}
	// So does a Connect that starts now.
	late := startWaiting(t, "comes late", "",
		opcua.SecurityMode(ua.MessageSecurityModeNone), opcua.DialTimeout(0), opcua.ReverseConnectListener(l))
	select {
	case err := <-late.err:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("%s: Connect returned %v, want an error that wraps net.ErrClosed", late.name, err)
		}
	case <-time.After(promptLimit):
		t.Fatalf("%s: Connect did not return on a closed listener\n%s", late.name, chaoskit.AllStacks())
	}

	logf(t, "every Connect returned")
	// The listener dropped the connections it held.
	if got := l.Pending(); got != 0 {
		t.Errorf("closed listener holds %d pending connection(s)", got)
	}
	_ = raw.SetReadDeadline(time.Now().Add(promptLimit))
	if _, err := raw.Read(make([]byte, 1)); err == nil || errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
		t.Errorf("half-announced connection was not closed with the listener: read returned %v", err)
	}

	// The servers notice, say why, and keep trying with back-off.
	stalled.SetStall(testutil.ClientToServer, false)
	for _, n := range []*node{stuckA, stuckB, unasked} {
		rc := n.target()
		if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool {
			return rc.State() == server.ReverseConnectBackoff && rc.Err() != nil
		}) {
			t.Errorf("%s: %s, want Backoff with an error", n.name, n.describeTarget())
		}
	}
	logf(t, "the servers back off")
	// Three servers retry at most every 20ms at first and every 250ms in the
	// end, which makes 15 attempts in this window. Without back-off they
	// would make 60, and far more in a tight loop.
	const window = 400 * time.Millisecond
	attempts := func() int64 { return stalled.Accepted() + plain.Accepted() }
	before := attempts()
	time.Sleep(window)
	if got := attempts() - before; got > 30 {
		t.Errorf("the servers made %d connection attempts in %v: no back-off", got, window)
	}
	if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool { return attempts() > before }) {
		t.Errorf("the servers stopped trying to reach the client")
	}

	logf(t, "the servers keep trying")
	// The client that lost its connection is still waiting for its server.
	// It can be used (to no avail) and closed without delay.
	if got := cUsed.State(); got != opcua.Reconnecting {
		t.Errorf("reconnecting client is %v, want Reconnecting", got)
	}
	rctx, rcancel := context.WithTimeout(context.Background(), promptLimit)
	if _, err := cUsed.ReadValue(rctx, used.markerID()); err == nil || !chaoskit.IsConnectionError(err) {
		t.Errorf("read on the reconnecting client returned %v, want a connection-class error", err)
	}
	rcancel()
	recUsed.Check(t, false)
	start = time.Now()
	_ = wd.Do("Close of the reconnecting client", func() error { chaoskit.CloseClient(cUsed, recUsed); return nil })
	if d := time.Since(start); d > promptLimit {
		t.Errorf("closing the reconnecting client took %v", d)
	}
	st.close()
	st.report(t)
	if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool { return cUsed.State() == opcua.Closed }) {
		t.Errorf("client is %v after Close", cUsed.State())
	}
	recUsed.Check(t, true)

	logf(t, "reconnecting client closed")
	for _, w := range append(waiting, late) {
		chaoskit.CloseClient(w.c, nil)
	}
	for _, n := range nodes {
		n.stop()
		n.fwd.Close()
	}
	stalled.Close()
	plain.Close()
	wd.Close()
	verifyLeaks()
}

// isTimeout reports whether err is a network timeout.
func isTimeout(err error) bool {
	var nerr net.Error
	return errors.As(err, &nerr) && nerr.Timeout()
}

// TestChaosReverseListenerCloseRace closes listeners at random moments while
// servers connect to them as fast as they can and clients connect, read and
// disconnect in a loop: the listener is closed with connections being
// accepted, announced, handed over and claimed.
//
// Close must return at once every time and so must every Connect; a client
// that did connect must have reached its own server; the errors must be
// connection-class errors; and nothing may be left behind.
func TestChaosReverseListenerCloseRace(t *testing.T) {
	verifyLeaks := chaoskit.LeakCheck(t)
	seed := chaoskit.Seed(t)
	dur := chaoskit.Duration(t, defaultDuration/2)
	rng := rand.New(rand.NewSource(seed))
	wd := chaoskit.NewWatchdog(t)

	nodes := make([]*node, 3)
	for i := range nodes {
		name := fmt.Sprintf("s%d", i)
		nodes[i] = newNode(t, name, i, noneProfile("urn:otfabric:chaos:reverse:race:"+name), seed+int64(i)).up("")
		// The endpoint URL does not matter: the listeners differ per round.
		nodes[i].anyEndpoint = true
	}

	var sink chaoskit.ErrSink
	var tally chaoskit.ErrorTally
	deadline := time.Now().Add(dur)
	rounds := 0
	for ; rounds < 3 || time.Now().Before(deadline); rounds++ {
		l, err := uacp.ListenReverse(context.Background(), "127.0.0.1:0", &uacp.ReverseListenerConfig{Logger: chaoskit.Logger()})
		if err != nil {
			t.Fatal(err)
		}
		url := listenerURL(l)
		targets := make([]*server.ReverseConnect, len(nodes))
		for i, n := range nodes {
			rc, err := n.server().AddReverseConnect(url, server.ReverseConnectRetryInterval(2*time.Millisecond, 20*time.Millisecond))
			if err != nil {
				t.Fatal(err)
			}
			targets[i] = rc
		}

		var clients sync.WaitGroup
		for _, n := range nodes {
			clients.Add(1)
			go func() {
				defer clients.Done()
				for {
					c, err := opcua.NewClient("", n.clientOptions(nil, n.reverseOption(l),
						opcua.AutoReconnect(false), opcua.DialTimeout(time.Second), opcua.RequestTimeout(3*time.Second),
						opcua.SessionTimeout(2*time.Second))...)
					if err != nil {
						sink.Addf("%s: %v", n.name, err)
						return
					}
					ctx, cancel := chaoskit.OpCtx()
					err = c.Connect(ctx)
					if err == nil {
						var dv *ua.DataValue
						if dv, err = c.ReadValue(ctx, n.markerID()); err == nil && dv.Value.Value() != n.marker {
							sink.Addf("%s: WRONG SERVER: marker is %v, want %q", n.name, dv.Value.Value(), n.marker)
						}
					}
					cancel()
					tally.Add(err)
					chaoskit.CloseClient(c, nil)
					if err != nil && !chaoskit.IsConnectionError(err) {
						sink.Addf("%s: unexpected error: %v", n.name, err)
					}
					if errors.Is(err, net.ErrClosed) {
						return // the listener is closed
					}
				}
			}()
		}

		sleepRand(rng, 2*time.Millisecond, 90*time.Millisecond)
		start := time.Now()
		if err := wd.Do("listener Close", l.Close); err != nil {
			sink.Addf("close listener: %v", err)
		}
		if d := time.Since(start); d > promptLimit {
			sink.Addf("closing the listener took %v", d)
		}
		if !wd.Wait("clients of a closed listener", &clients) {
			break
		}
		if got := l.Pending(); got != 0 {
			sink.Addf("closed listener holds %d pending connection(s)", got)
		}
		for _, rc := range targets {
			_ = wd.Do("ReverseConnect.Close", rc.Close)
		}
	}
	sink.Report(t)
	t.Logf("%d round(s); connects: %s", rounds, tally.String())
	if tally.OK() == 0 {
		t.Errorf("no client ever connected")
	}

	for _, n := range nodes {
		n.requireDrained()
		n.stop()
		n.fwd.Close()
	}
	wd.Close()
	verifyLeaks()
}
