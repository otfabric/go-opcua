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
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/ua"
)

// monkeyClient is a long-lived client that must survive the whole storm.
type monkeyClient struct {
	name    string
	c       *opcua.Client
	rec     *stateRecorder
	streams []*stream
}

// scenario is one randomized chaos run: a mixed workload on several clients
// plus a monkey that injects faults.
type scenario struct {
	t    *testing.T
	e    *env
	seed int64
	wd   *watchdog

	// strict is true when the injected faults cannot alter message contents.
	// Results are then verified and only connection-class errors are legal.
	strict bool

	clients []*monkeyClient

	stop    chan struct{} // closed to stop the workload
	workers sync.WaitGroup

	tally      errorTally
	unexpected errSink
	ops        atomic.Int64
}

const (
	monkeyClients          = 3
	monkeyWorkersPerClient = 3
)

func newScenario(t *testing.T, strict bool) *scenario {
	seed := seedFor(t)
	return &scenario{
		t:      t,
		e:      newEnv(t, seed),
		seed:   seed,
		wd:     newWatchdog(t),
		strict: strict,
		stop:   make(chan struct{}),
	}
}

func (s *scenario) stopped() bool {
	select {
	case <-s.stop:
		return true
	default:
		return false
	}
}

// sleep waits for d or until the workload is stopped.
func (s *scenario) sleep(d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-s.stop:
	case <-t.C:
	}
}

// persistentOptions are the options of the long-lived clients: a short
// request timeout so that calls swallowed by a blackhole return quickly, a
// short secure channel lifetime forces token renewals under load, and a short
// session timeout lets the server reclaim sessions the storm orphaned.
func persistentOptions() []opcua.Option {
	return []opcua.Option{
		opcua.RequestTimeout(3 * time.Second),
		opcua.Lifetime(2 * time.Second),
		opcua.SessionTimeout(10 * time.Second),
	}
}

// start connects the long-lived clients, opens their streams and starts the
// workload.
func (s *scenario) start() {
	s.t.Helper()
	ctx, cancel := opCtx()
	defer cancel()

	for i := 0; i < monkeyClients; i++ {
		mc := &monkeyClient{name: fmt.Sprintf("p%d", i)}
		mc.rec = newStateRecorder(mc.name, true)
		mc.c = s.e.connect(mc.rec, persistentOptions()...)
		// one synchronous and one buffered notification channel per client
		for j, counters := range [][]int{{0, 1}, {2, 3}} {
			st, err := openStreamWith(ctx, s.e, mc.c, fmt.Sprintf("%s.s%d", mc.name, j), j*8, streamParams(), counters...)
			if err != nil {
				s.t.Fatalf("client %s: %v", mc.name, err)
			}
			if !s.strict {
				st.setLenient()
			}
			mc.streams = append(mc.streams, st)
		}
		s.clients = append(s.clients, mc)
	}

	// server-side value source
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		for !s.stopped() {
			for i := 0; i < numCounters; i++ {
				s.e.bump(i)
			}
			s.sleep(3 * time.Millisecond)
		}
	}()

	for ci, mc := range s.clients {
		for w := 0; w < monkeyWorkersPerClient; w++ {
			s.workers.Add(1)
			go func(mc *monkeyClient, id int) {
				defer s.workers.Done()
				s.worker(mc.c, rand.New(rand.NewSource(s.seed+int64(1000+id))), s.stop)
			}(mc, ci*monkeyWorkersPerClient+w)
		}
	}

	// short-lived clients that are closed while their calls are in flight
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		s.ephemeralClients(rand.New(rand.NewSource(s.seed + 5000)))
	}()
}

// opContext returns the context for one workload operation. Most operations
// get a generous deadline; some get a deadline that expires mid-request and
// some are cancelled from another goroutine while in flight.
func opContext(rng *rand.Rand) (context.Context, context.CancelFunc) {
	switch rng.Intn(10) {
	case 0:
		return context.WithTimeout(context.Background(), time.Duration(1+rng.Intn(30))*time.Millisecond)
	case 1:
		ctx, cancel := context.WithCancel(context.Background())
		t := time.AfterFunc(time.Duration(rng.Intn(20000))*time.Microsecond, cancel)
		return ctx, func() { t.Stop(); cancel() }
	default:
		return context.WithTimeout(context.Background(), 20*time.Second)
	}
}

// churn is a short-lived subscription a worker creates, modifies and cancels.
type churn struct {
	sub   *opcua.Subscription
	items []uint32
	stop  chan struct{}
	done  chan struct{}
}

func (ch *churn) close() {
	close(ch.stop)
	<-ch.done
}

// worker issues random service calls on c until stop is closed.
func (s *scenario) worker(c *opcua.Client, rng *rand.Rand, stop <-chan struct{}) {
	var cur *churn
	defer func() {
		if cur != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = cur.sub.Cancel(ctx)
			cancel()
			cur.close()
		}
	}()

	for {
		select {
		case <-stop:
			return
		default:
		}

		op := rng.Intn(9)
		name := [...]string{"read", "readBlob", "write", "browse", "call", "namespaces", "readMulti", "churn", "churn"}[op]
		err := s.wd.do(name, func() error {
			ctx, cancel := opContext(rng)
			defer cancel()
			switch op {
			case 0:
				dv, err := c.ReadValue(ctx, s.e.scratchID(rng.Intn(numScratch)))
				if err != nil {
					return err
				}
				if s.strict {
					if dv.Status != ua.StatusOK {
						return fmt.Errorf("INVARIANT: read: status %v", dv.Status)
					}
					if _, ok := dv.Value.Value().(int32); !ok {
						return fmt.Errorf("INVARIANT: read: value %T, want int32 (response of another request?)", dv.Value.Value())
					}
				}
			case 1:
				dv, err := c.ReadValue(ctx, s.e.blobID())
				if err != nil {
					return err
				}
				if s.strict {
					if b, _ := dv.Value.Value().([]byte); len(b) != blobSize {
						return fmt.Errorf("INVARIANT: blob: %d bytes, want %d", len(b), blobSize)
					}
				}
			case 2:
				sc, err := c.WriteNodeValue(ctx, s.e.scratchID(rng.Intn(numScratch)), rng.Int31())
				if err != nil {
					return err
				}
				if s.strict && sc != ua.StatusOK {
					return fmt.Errorf("INVARIANT: write: status %v", sc)
				}
			case 3:
				refs, err := c.BrowseAll(ctx, s.e.folderID())
				if err != nil {
					return err
				}
				if n := countLeaves(refs); s.strict && n != numBrowse {
					return fmt.Errorf("INVARIANT: browse: %d leaves, want %d", n, numBrowse)
				}
			case 4:
				n := int32(rng.Intn(1000))
				res, err := c.CallMethod(ctx, s.e.objectsID(), s.e.methodID(), n)
				if err != nil {
					return err
				}
				if s.strict && (res.StatusCode != ua.StatusOK || len(res.OutputArguments) != 1 || res.OutputArguments[0].Value() != n*n) {
					return fmt.Errorf("INVARIANT: call(%d) returned %v %v (response of another request?)", n, res.StatusCode, res.OutputArguments)
				}
			case 5:
				nss, err := c.NamespaceArray(ctx)
				if err != nil {
					return err
				}
				if s.strict && len(nss) <= int(s.e.ns) {
					return fmt.Errorf("INVARIANT: namespace array too short: %v", nss)
				}
			case 6:
				dvs, err := c.ReadValues(ctx, s.e.scratchID(0), s.e.counterID(0), s.e.scratchID(1))
				if err != nil {
					return err
				}
				if s.strict && len(dvs) != 3 {
					return fmt.Errorf("INVARIANT: ReadValues returned %d results, want 3", len(dvs))
				}
			default:
				return s.churnStep(ctx, c, rng, &cur)
			}
			return nil
		})
		s.ops.Add(1)
		s.tally.add(err)
		if err != nil && s.strict && !isConnectionError(err) {
			s.unexpected.addf("worker op %s: unexpected error class: %v", name, err)
		}
		if n := rng.Intn(4); n > 0 {
			time.Sleep(time.Duration(n) * time.Millisecond)
		}
	}
}

// churnStep advances the worker's short-lived subscription by one step:
// create, add an item, remove an item, modify, or cancel.
func (s *scenario) churnStep(ctx context.Context, c *opcua.Client, rng *rand.Rand, cur **churn) error {
	ch := *cur
	if ch == nil {
		ch = &churn{stop: make(chan struct{}), done: make(chan struct{})}
		notifs := make(chan *opcua.PublishNotificationData, rng.Intn(3))
		go func() {
			defer close(ch.done)
			for {
				select {
				case <-notifs:
				case <-ch.stop:
					return
				}
			}
		}()
		sub, err := c.Subscribe(ctx, shortLivedParams(), notifs)
		if err != nil {
			ch.close()
			return err
		}
		ch.sub = sub
		*cur = ch
		return nil
	}

	switch rng.Intn(5) {
	case 0, 1:
		req := opcua.NewMonitoredItemCreateRequestWithDefaults(s.e.scratchID(rng.Intn(numScratch)), ua.AttributeIDValue, rng.Uint32())
		res, err := ch.sub.Monitor(ctx, ua.TimestampsToReturnBoth, req)
		if err != nil {
			return err
		}
		if len(res.Results) == 1 && res.Results[0].StatusCode == ua.StatusOK {
			ch.items = append(ch.items, res.Results[0].MonitoredItemID)
		}
		return nil
	case 2:
		if len(ch.items) == 0 {
			return nil
		}
		id := ch.items[len(ch.items)-1]
		ch.items = ch.items[:len(ch.items)-1]
		_, err := ch.sub.Unmonitor(ctx, id)
		return err
	case 3:
		_, err := ch.sub.ModifySubscription(ctx, opcua.SubscriptionParameters{
			Interval:          time.Duration(10+rng.Intn(50)) * time.Millisecond,
			MaxKeepAliveCount: 5,
			LifetimeCount:     100,
		})
		return err
	default:
		err := ch.sub.Cancel(ctx)
		ch.close()
		*cur = nil
		return err
	}
}

// ephemeralClients repeatedly connects a client, puts it under load and then
// closes it while its calls are still in flight.
func (s *scenario) ephemeralClients(rng *rand.Rand) {
	for n := 0; !s.stopped(); n++ {
		name := fmt.Sprintf("e%d", n)
		rec := newStateRecorder(name, true)
		var c *opcua.Client
		err := s.wd.do("ephemeral connect", func() error {
			var err error
			c, err = opcua.NewClient(s.e.url(), s.e.clientOptions(rec, opcua.RequestTimeout(3*time.Second), opcua.SessionTimeout(5*time.Second))...)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := c.Connect(ctx); err != nil {
				closeClient(c, rec)
				c = nil
				return err
			}
			return nil
		})
		s.tally.add(err)
		if err != nil {
			if s.strict && !isConnectionError(err) {
				s.unexpected.addf("ephemeral connect: unexpected error class: %v", err)
			}
			s.sleep(time.Duration(20+rng.Intn(100)) * time.Millisecond)
			continue
		}

		stop := make(chan struct{})
		var wg sync.WaitGroup
		for w := 0; w < 2; w++ {
			wg.Add(1)
			wrng := rand.New(rand.NewSource(rng.Int63()))
			go func() {
				defer wg.Done()
				s.worker(c, wrng, stop)
			}()
		}
		var st *stream
		_ = s.wd.do("ephemeral stream", func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			st, _ = openStreamWith(ctx, s.e, c, name, rng.Intn(2), shortLivedParams(), rng.Intn(numCounters))
			if st != nil && !s.strict {
				st.setLenient()
			}
			return nil
		})

		s.sleep(time.Duration(100+rng.Intn(500)) * time.Millisecond)

		// Close races with the workers' in-flight calls.
		_ = s.wd.do("Close with calls in flight", func() error {
			closeClient(c, rec)
			return nil
		})
		close(stop)
		s.wd.wait("workers of closed client "+name, &wg)
		if st != nil {
			st.close()
			st.report(s.t)
		}
		if !eventually(settleLimit, func() bool { return c.State() == opcua.Closed }) {
			s.t.Errorf("client %s: State() is %v after Close", name, c.State())
		}
		rec.check(s.t, true)
	}
}

// fault is one action of the monkey.
type fault struct {
	name   string
	weight int
	// corrupting faults can alter message contents and are only used by
	// non-strict scenarios.
	corrupting bool
	apply      func(s *scenario, rng *rand.Rand, hold time.Duration)
}

func dir(rng *rand.Rand) testutil.Direction { return testutil.Direction(rng.Intn(2)) }

var faults = []fault{
	{name: "drop all connections", weight: 4, apply: func(s *scenario, _ *rand.Rand, _ time.Duration) {
		s.e.proxy.DropAll()
	}},
	{name: "half-close", weight: 3, apply: func(s *scenario, rng *rand.Rand, _ time.Duration) {
		s.e.proxy.HalfClose(dir(rng))
	}},
	{name: "blackhole one direction", weight: 3, apply: func(s *scenario, rng *rand.Rand, hold time.Duration) {
		d := dir(rng)
		s.e.proxy.SetBlackhole(d, true)
		s.sleep(hold)
		s.e.proxy.SetBlackhole(d, false)
		// Bytes were swallowed, so the byte streams may be cut inside a
		// message. A real network would have lost the connection too.
		s.e.proxy.DropAll()
	}},
	{name: "blackhole both directions", weight: 2, apply: func(s *scenario, _ *rand.Rand, hold time.Duration) {
		s.e.proxy.SetBlackhole(testutil.ClientToServer, true)
		s.e.proxy.SetBlackhole(testutil.ServerToClient, true)
		s.sleep(hold)
		s.e.proxy.SetBlackhole(testutil.ClientToServer, false)
		s.e.proxy.SetBlackhole(testutil.ServerToClient, false)
		s.e.proxy.DropAll()
	}},
	{name: "latency and jitter", weight: 3, apply: func(s *scenario, rng *rand.Rand, hold time.Duration) {
		s.e.proxy.SetLatency(time.Duration(1+rng.Intn(30))*time.Millisecond, time.Duration(rng.Intn(20))*time.Millisecond)
		s.sleep(hold)
		s.e.proxy.SetLatency(0, 0)
	}},
	{name: "byte-level fragmentation", weight: 3, apply: func(s *scenario, rng *rand.Rand, hold time.Duration) {
		s.e.proxy.SetFragment(1 + rng.Intn(7))
		s.sleep(hold)
		s.e.proxy.SetFragment(0)
	}},
	{name: "bandwidth throttle", weight: 2, apply: func(s *scenario, rng *rand.Rand, hold time.Duration) {
		s.e.proxy.SetThrottle((8 + rng.Intn(120)) * 1024)
		s.sleep(hold)
		s.e.proxy.SetThrottle(0)
	}},
	{name: "truncate mid-message", weight: 3, apply: func(s *scenario, rng *rand.Rand, _ time.Duration) {
		s.e.proxy.TruncateNext(dir(rng), 1+rng.Intn(200))
	}},
	{name: "server unreachable", weight: 3, apply: func(s *scenario, _ *rand.Rand, hold time.Duration) {
		s.e.proxy.SetRefuse(true)
		s.e.proxy.DropAll()
		s.sleep(hold)
		s.e.proxy.SetRefuse(false)
	}},
	{name: "server restart", weight: 2, apply: func(s *scenario, rng *rand.Rand, hold time.Duration) {
		s.e.restartServer(hold / 4)
	}},
	{name: "close session behind the client's back", weight: 2, apply: func(s *scenario, rng *rand.Rand, _ time.Duration) {
		mc := s.clients[rng.Intn(len(s.clients))]
		_ = s.wd.do("CloseSession", func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return mc.c.CloseSession(ctx)
		})
	}},
	{name: "detach session", weight: 2, apply: func(s *scenario, rng *rand.Rand, hold time.Duration) {
		mc := s.clients[rng.Intn(len(s.clients))]
		reactivate := rng.Intn(2) == 0
		_ = s.wd.do("DetachSession", func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			sess, err := mc.c.DetachSession(ctx)
			if err != nil || sess == nil || !reactivate {
				return err // an abandoned session is reclaimed by its timeout
			}
			s.sleep(hold / 4)
			return mc.c.ActivateSession(ctx, sess)
		})
	}},
	{name: "raw malformed frames", weight: 3, apply: func(s *scenario, rng *rand.Rand, _ time.Duration) {
		s.rawAttack(rng)
	}},
	{name: "bit flips", weight: 5, corrupting: true, apply: func(s *scenario, rng *rand.Rand, hold time.Duration) {
		d := dir(rng)
		s.e.proxy.SetCorruption(d, 0.02+rng.Float64()*0.2)
		s.sleep(hold)
		s.e.proxy.SetCorruption(d, 0)
	}},
	{name: "single bit flip", weight: 4, corrupting: true, apply: func(s *scenario, rng *rand.Rand, _ time.Duration) {
		s.e.proxy.CorruptNext(dir(rng), 1+rng.Intn(3))
	}},
}

// rawAttack sends one hostile byte stream straight to the server.
func (s *scenario) rawAttack(rng *rand.Rand) {
	srv := s.e.server()
	if srv == nil {
		return
	}
	a := rawAttacks[rng.Intn(len(rawAttacks))]
	addr := s.e.directAddr()
	_ = s.wd.do("raw attack: "+a.name, func() error {
		_, err := sendRawAttack(addr, "opc.tcp://"+addr, a, rng, 200*time.Millisecond)
		return err
	})
}

// monkey injects random faults for the given duration.
func (s *scenario) monkey(d time.Duration) {
	rng := rand.New(rand.NewSource(s.seed))
	var pool []fault
	for _, f := range faults {
		if f.corrupting && s.strict {
			continue
		}
		for i := 0; i < f.weight; i++ {
			pool = append(pool, f)
		}
	}
	start := time.Now()
	for n := 0; time.Since(start) < d; n++ {
		f := pool[rng.Intn(len(pool))]
		hold := time.Duration(50+rng.Intn(550)) * time.Millisecond
		s.t.Logf("[%6.2fs] fault %d: %s", time.Since(start).Seconds(), n, f.name)
		f.apply(s, rng, hold)
		// leave some room between faults: sometimes enough to recover fully,
		// sometimes so little that the next fault hits a reconnect in progress
		time.Sleep(time.Duration(rng.Intn(400)) * time.Millisecond)
	}
	s.e.proxy.Heal()
	if s.e.server() == nil {
		s.e.startServer()
	}
}

// verifyRecovery checks that, once the faults are gone, every long-lived
// client returns to Connected and every one of its subscriptions delivers
// fresh values again.
func (s *scenario) verifyRecovery() {
	s.t.Helper()
	for _, mc := range s.clients {
		if !eventually(settleLimit, func() bool { return mc.c.State() == opcua.Connected }) {
			s.t.Errorf("STUCK: client %s did not return to Connected within %v after the faults stopped; state=%v transitions=%v\n%s",
				mc.name, settleLimit, mc.c.State(), mc.rec.snapshot(), allStacks())
			return
		}
	}
	// All streams are checked against one common deadline.
	type pending struct {
		mc     *monkeyClient
		st     *stream
		h      uint32
		marker int64
	}
	var waiting []pending
	for _, mc := range s.clients {
		for _, st := range mc.streams {
			for _, h := range st.handles() {
				waiting = append(waiting, pending{mc, st, h, s.e.counters[h].Load()})
			}
		}
	}
	eventually(settleLimit, func() bool {
		still := waiting[:0]
		for _, p := range waiting {
			if p.st.lastValue(int(p.h)) <= p.marker {
				still = append(still, p)
			}
		}
		waiting = still
		return len(waiting) == 0
	})
	for _, p := range waiting {
		s.t.Errorf("STUCK: stream %s counter %d did not resume after the faults stopped: last delivered %d, node is at %d (client state %v, transitions %v, subscription ids %v, server %+v)",
			p.st.name, p.h, p.st.lastValue(int(p.h)), s.e.counters[p.h].Load(), p.mc.c.State(), p.mc.rec.snapshot(), p.mc.c.SubscriptionIDs(), s.e.resources())
	}
	if len(waiting) > 0 {
		s.t.Logf("goroutines:\n%s", allStacks())
	}
}

// finish stops the workload, closes all clients and checks the invariants
// that hold after shutdown.
func (s *scenario) finish(verifyLeaks func()) {
	s.t.Helper()
	close(s.stop)
	s.wd.wait("workload", &s.workers)

	for _, mc := range s.clients {
		for _, st := range mc.streams {
			_ = s.wd.do("cancel stream", func() error {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				return st.sub.Cancel(ctx)
			})
		}
		_ = s.wd.do("Close", func() error { closeClient(mc.c, mc.rec); return nil })
		for _, st := range mc.streams {
			st.close()
			st.report(s.t)
		}
		if !eventually(settleLimit, func() bool { return mc.c.State() == opcua.Closed }) {
			s.t.Errorf("client %s: State() is %v after Close", mc.name, mc.c.State())
		}
		if !eventually(settleLimit, func() bool { last, ok := mc.rec.last(); return ok && last == opcua.Closed }) {
			s.t.Errorf("client %s: last reported state after Close is not Closed: %v", mc.name, mc.rec.snapshot())
		}
		mc.rec.check(s.t, true)
	}
	s.unexpected.report(s.t)
	s.t.Logf("workload: %d operations: %s", s.ops.Load(), s.tally.String())

	// the server is still healthy and holds nothing for the departed clients
	s.e.requireCleanClient()
	if s.strict {
		s.e.requireServerDrained(settleLimit)
	} else if !eventually(settleLimit, func() bool { return s.e.resources().Channels == 0 }) {
		// A corrupted request may have created a session or subscription with
		// an arbitrary lifetime, so only the channels are required to go.
		s.t.Errorf("server still holds secure channels after all clients are gone: %+v", s.e.resources())
	}

	s.e.stopServer()
	s.e.proxy.Close()
	s.wd.close()
	verifyLeaks()
}

// TestChaosMonkeyNetworkFaults runs the mixed workload while the monkey
// injects every fault that does not alter message contents: connection
// resets, half-closes, blackholes, latency, fragmentation, throttling,
// truncation, an unreachable or restarting server, sessions closed or
// detached behind the client's back, clients closed mid-call, cancelled
// contexts and hostile raw connections.
//
// Because no message is altered, results are verified, only connection-class
// errors are accepted, and subscription values must never go backwards.
func TestChaosMonkeyNetworkFaults(t *testing.T) {
	verifyLeaks := leakCheck(t)
	s := newScenario(t, true)
	s.start()
	s.monkey(chaosDuration(t))
	s.verifyRecovery()
	s.finish(verifyLeaks)
}

// TestChaosMonkeyCorruption adds random bit flips to the mix. Without
// message security nothing protects the integrity of the payload, so
// corrupted requests and responses may legitimately produce any error or
// value. What must still hold: no panic, no deadlock, no goroutine leak, the
// clients reconnect, and the server keeps serving a clean client afterwards.
func TestChaosMonkeyCorruption(t *testing.T) {
	verifyLeaks := leakCheck(t)
	s := newScenario(t, false)
	s.start()
	s.monkey(chaosDuration(t))
	s.verifyRecoveryNonStrict()
	s.finish(verifyLeaks)
}

// verifyRecoveryNonStrict only requires the clients to become Connected
// again: a corrupted request may have deleted or re-parameterised anything.
func (s *scenario) verifyRecoveryNonStrict() {
	s.t.Helper()
	for _, mc := range s.clients {
		if !eventually(settleLimit, func() bool { return mc.c.State() == opcua.Connected }) {
			s.t.Errorf("STUCK: client %s did not return to Connected within %v after the faults stopped; state=%v transitions=%v\n%s",
				mc.name, settleLimit, mc.c.State(), mc.rec.snapshot(), allStacks())
			return
		}
	}
}
