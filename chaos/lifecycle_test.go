// SPDX-License-Identifier: MIT

package chaos

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
)

// TestParallelConnectClose races Connect against Close on the same client,
// as happens when an application is shut down while it is still starting.
// Whatever the interleaving, every call returns, the client ends up Closed
// and nothing it created on the server survives.
func TestParallelConnectClose(t *testing.T) {
	t.Parallel()
	seed := seedFor(t)
	e := newEnv(t, seed)
	wd := newWatchdog(t)
	rng := rand.New(rand.NewSource(seed))

	const rounds, closers = 24, 3
	var connected, refused atomic.Int32
	for round := 0; round < rounds; round++ {
		rec := newStateRecorder(fmt.Sprintf("r%d", round), true)
		// A session whose activation is cut short by Close cannot be closed
		// by the client any more (its channel is gone). The server reclaims
		// it when its timeout expires, so keep that short.
		c, err := opcua.NewClient(e.url(), e.clientOptions(rec, opcua.SessionTimeout(2*time.Second))...)
		if err != nil {
			t.Fatal(err)
		}

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = wd.do("Connect", func() error {
				ctx, cancel := opCtx()
				defer cancel()
				if err := c.Connect(ctx); err != nil {
					refused.Add(1)
				} else {
					connected.Add(1)
				}
				return nil
			})
		}()
		for i := 0; i < closers; i++ {
			// Connect takes a few (tens of) milliseconds; spread the Close
			// calls so that they hit every phase of it and sometimes lose.
			delay := time.Duration(rng.Intn(40000)) * time.Microsecond
			wg.Add(1)
			go func() {
				defer wg.Done()
				time.Sleep(delay)
				_ = wd.do("Close", func() error { closeClient(c, rec); return nil })
			}()
		}
		if !wd.wait("Connect racing with Close", &wg) {
			return
		}

		// Whoever won, the client must be closed now.
		if !eventually(settleLimit, func() bool { return c.State() == opcua.Closed }) {
			t.Fatalf("round %d: State() is %v after Close; transitions %v", round, c.State(), rec.snapshot())
		}
		if !eventually(settleLimit, func() bool { last, ok := rec.last(); return !ok || last == opcua.Closed }) {
			t.Fatalf("round %d: last reported state is not Closed: %v", round, rec.snapshot())
		}
		if sc := c.SecureChannel(); sc != nil {
			t.Fatalf("round %d: client still holds a secure channel after Close", round)
		}
		// a closed client stays closed
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if _, err := c.ReadValue(ctx, e.scratchID(0)); err == nil {
			t.Fatalf("round %d: read succeeded on a closed client", round)
		}
		cancel()
	}
	t.Logf("Connect won %d times, lost %d times", connected.Load(), refused.Load())

	// No session, channel or connection may be left behind by a Connect that
	// was overtaken by Close.
	e.requireServerDrained(settleLimit)
	if !eventually(settleLimit, func() bool { return e.proxy.ActiveLinks() == 0 }) {
		t.Errorf("%d TCP connection(s) are still open after all clients were closed", e.proxy.ActiveLinks())
	}
}

// TestParallelCloseWithCallsInFlight closes a busy client from several
// goroutines at once. All in-flight and later calls return with an error.
func TestParallelCloseWithCallsInFlight(t *testing.T) {
	t.Parallel()
	seed := seedFor(t)
	e := newEnv(t, seed)
	s := &scenario{t: t, e: e, seed: seed, wd: newWatchdog(t), strict: true, stop: make(chan struct{})}

	for round := 0; round < 6; round++ {
		rec := newStateRecorder(fmt.Sprintf("r%d", round), true)
		c := e.connect(rec)
		ctx, cancel := opCtx()
		st, err := openStream(ctx, e, c, "s", round%2, false, 0)
		cancel()
		if err != nil {
			t.Fatal(err)
		}

		stop := make(chan struct{})
		var workers, closers sync.WaitGroup
		for w := 0; w < 4; w++ {
			workers.Add(1)
			rng := rand.New(rand.NewSource(seed + int64(round*10+w)))
			go func() {
				defer workers.Done()
				s.worker(c, rng, stop)
			}()
		}
		time.Sleep(time.Duration(20+round*15) * time.Millisecond)
		for i := 0; i < 3; i++ {
			closers.Add(1)
			go func() {
				defer closers.Done()
				_ = s.wd.do("Close", func() error { closeClient(c, rec); return nil })
			}()
		}
		s.wd.wait("concurrent Close", &closers)
		close(stop)
		s.wd.wait("workers of a closed client", &workers)
		st.close()
		st.report(t)

		if !eventually(settleLimit, func() bool { return c.State() == opcua.Closed }) {
			t.Fatalf("round %d: State() is %v after Close", round, c.State())
		}
		rec.check(t, true)
	}
	s.unexpected.report(t)
	e.requireServerDrained(settleLimit)
}

// TestServerCloseWithActiveClients shuts the server down while clients are
// in the middle of calls and publish cycles. Every call returns with a
// connection error, clients without AutoReconnect end up Closed, a client
// with AutoReconnect keeps trying until it is closed, and neither side
// leaves a goroutine behind.
func TestServerCloseWithActiveClients(t *testing.T) {
	verifyLeaks := leakCheck(t)
	seed := seedFor(t)
	e := newEnv(t, seed)
	s := &scenario{t: t, e: e, seed: seed, wd: newWatchdog(t), strict: true, stop: make(chan struct{})}

	type cl struct {
		c         *opcua.Client
		rec       *stateRecorder
		st        *stream
		reconnect bool
	}
	var clients []*cl
	var workers sync.WaitGroup
	for i := 0; i < 5; i++ {
		reconnect := i == 0
		rec := newStateRecorder(fmt.Sprintf("c%d", i), reconnect)
		c := e.connect(rec, opcua.AutoReconnect(reconnect), opcua.RequestTimeout(3*time.Second))
		ctx, cancel := opCtx()
		st, err := openStream(ctx, e, c, rec.name, i%2, false, i%numCounters)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, &cl{c, rec, st, reconnect})
		for w := 0; w < 3; w++ {
			workers.Add(1)
			rng := rand.New(rand.NewSource(seed + int64(i*10+w)))
			go func() {
				defer workers.Done()
				s.worker(c, rng, s.stop)
			}()
		}
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		for !s.stopped() {
			for i := 0; i < numCounters; i++ {
				e.bump(i)
			}
			s.sleep(2 * time.Millisecond)
		}
	}()

	time.Sleep(300 * time.Millisecond)
	_ = s.wd.do("Server.Close", func() error { e.stopServer(); return nil })

	for _, x := range clients {
		want := opcua.Closed
		if x.reconnect {
			want = opcua.Reconnecting
		}
		if !eventually(settleLimit, func() bool { return x.c.State() == want }) {
			t.Errorf("client %s: state %v after the server closed, want %v; transitions %v\n%s", x.rec.name, x.c.State(), want, x.rec.snapshot(), allStacks())
		}
	}

	close(s.stop)
	s.wd.wait("workload", &workers)
	for _, x := range clients {
		_ = s.wd.do("Close", func() error { closeClient(x.c, x.rec); return nil })
		x.st.close()
		x.st.report(t)
		if !eventually(settleLimit, func() bool { return x.c.State() == opcua.Closed }) {
			t.Errorf("client %s: State() is %v after Close", x.rec.name, x.c.State())
		}
		x.rec.check(t, true)
	}
	s.unexpected.report(t)
	t.Logf("workload: %d operations: %s", s.ops.Load(), s.tally.String())

	e.proxy.Close()
	s.wd.close()
	verifyLeaks()
}

// TestServerRestartOnSamePort stops the server in the middle of traffic and
// starts a brand-new instance on the very same port, as after a crash or an
// upgrade. Sessions, subscriptions and monitored items are gone. A client
// with AutoReconnect has to notice, build a new session, recreate its
// subscriptions and deliver again, without any value going backwards.
func TestServerRestartOnSamePort(t *testing.T) {
	verifyLeaks := leakCheck(t)
	seed := seedFor(t)
	e := newDirectEnv(t, seed)
	wd := newWatchdog(t)

	rec := newStateRecorder("c", true)
	c := e.connect(rec, opcua.RequestTimeout(3*time.Second))
	ctx, cancel := opCtx()
	defer cancel()
	st, err := openStream(ctx, e, c, "s", 0, false, 0, 1)
	if err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var bumper sync.WaitGroup
	bumper.Add(1)
	go func() {
		defer bumper.Done()
		for {
			select {
			case <-stop:
				return
			default:
				e.bump(0)
				e.bump(1)
				time.Sleep(2 * time.Millisecond)
			}
		}
	}()

	for round := 0; round < 3; round++ {
		if !eventually(settleLimit, func() bool { return st.lastValue(0) > 0 && st.lastValue(1) > 0 }) {
			t.Fatalf("round %d: no data before the restart: delivered %d/%d, nodes at %d/%d; client state %v, transitions %v, subscriptions %v, server %+v",
				round, st.lastValue(0), st.lastValue(1), e.counters[0].Load(), e.counters[1].Load(), c.State(), rec.snapshot(), c.SubscriptionIDs(), e.resources())
		}
		reconnects := countState(rec, opcua.Reconnecting)

		_ = wd.do("restart server", func() error {
			e.stopServer()
			time.Sleep(time.Duration(50*round) * time.Millisecond)
			e.startServer()
			return nil
		})

		if !eventually(settleLimit, func() bool {
			return countState(rec, opcua.Reconnecting) > reconnects && c.State() == opcua.Connected
		}) {
			t.Fatalf("round %d: client did not reconnect to the restarted server: state %v, transitions %v", round, c.State(), rec.snapshot())
		}
		m0, m1 := e.counters[0].Load(), e.counters[1].Load()
		if !eventually(settleLimit, func() bool { return st.lastValue(0) > m0 && st.lastValue(1) > m1 }) {
			t.Fatalf("round %d: subscription did not resume on the restarted server: delivered %d/%d, nodes at %d/%d; client subscriptions %v, server %+v",
				round, st.lastValue(0), st.lastValue(1), e.counters[0].Load(), e.counters[1].Load(), c.SubscriptionIDs(), e.resources())
		}
		// regular services work on the new instance
		if err := wd.do("read", func() error {
			ctx, cancel := opCtx()
			defer cancel()
			_, err := c.ReadValue(ctx, e.scratchID(0))
			return err
		}); err != nil {
			t.Fatalf("round %d: read after restart: %v", round, err)
		}
	}

	close(stop)
	wd.wait("bumper", &bumper)
	if err := st.sub.Cancel(ctx); err != nil {
		t.Errorf("cancel: %v", err)
	}
	closeClient(c, rec)
	st.close()
	st.report(t)
	rec.check(t, true)
	e.requireServerDrained(settleLimit)

	e.stopServer()
	wd.close()
	verifyLeaks()
}
