// SPDX-License-Identifier: MIT

package secure

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
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/ua"
)

// monkeyClient is a long-lived secured client that must survive the whole
// storm.
type monkeyClient struct {
	name    string
	pol     policy
	c       *opcua.Client
	rec     *chaoskit.StateRecorder
	streams []*stream
}

// scenario is one randomized chaos run: a mixed workload on one long-lived
// client per security policy plus a monkey that injects faults.
type scenario struct {
	t    *testing.T
	e    *env
	seed int64
	wd   *chaoskit.Watchdog
	pols []policy

	clients []*monkeyClient

	stop    chan struct{} // closed to stop the workload
	workers sync.WaitGroup

	tally      chaoskit.ErrorTally
	unexpected chaoskit.ErrSink
	ops        atomic.Int64
	tampered   atomic.Int64 // messages the monkey altered, repeated, dropped or moved
	healed     time.Time    // when the faults stopped
}

const monkeyWorkersPerClient = 2

func newScenario(t *testing.T) *scenario {
	seed := chaoskit.Seed(t)
	return &scenario{
		t:    t,
		e:    newEnv(t, seed),
		seed: seed,
		wd:   chaoskit.NewWatchdog(t),
		pols: selectedPolicies(t),
		stop: make(chan struct{}),
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
// short secure channel lifetime that forces a token renewal (with fresh
// ephemeral keys on the ECC policies) every 900 ms, and a short session
// timeout that lets the server reclaim sessions the storm orphaned.
func persistentOptions(pol policy) []opcua.Option {
	return []opcua.Option{
		opcua.RequestTimeout(3 * time.Second),
		opcua.Lifetime(pol.lifetime(1200 * time.Millisecond)),
		opcua.SessionTimeout(6 * time.Second),
	}
}

// monkeyStreamParams are the parameters of the long-lived subscriptions. The
// storm orphans subscriptions on the server (the client recreates what it
// cannot recover), and the server keeps an orphan for its lifetime: 6 s
// here, so that the server is drained soon after the clients are gone. A
// subscription that expires because the faults kept the client away for
// longer is recreated by the client like any other lost one.
func monkeyStreamParams() *opcua.SubscriptionParameters {
	return &opcua.SubscriptionParameters{
		Interval:          20 * time.Millisecond,
		MaxKeepAliveCount: 5,
		LifetimeCount:     300,
	}
}

// start connects the long-lived clients, opens their streams and starts the
// workload.
func (s *scenario) start() {
	s.t.Helper()
	ctx, cancel := chaoskit.OpCtx()
	defer cancel()

	for i, pol := range s.pols {
		mc := &monkeyClient{name: pol.name, pol: pol}
		mc.rec = chaoskit.NewStateRecorder(mc.name, true)
		mc.c = s.e.connect(mc.rec, pol, persistentOptions(pol)...)
		// a synchronous or a buffered notification channel
		counters := [][]int{{0, 1}, {2, 3}}[i%2]
		st, err := openStreamWith(ctx, s.e, mc.c, mc.name+".s", (i%2)*8, monkeyStreamParams(), counters...)
		if err != nil {
			s.t.Fatalf("client %s: %v", mc.name, err)
		}
		mc.streams = append(mc.streams, st)
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

var workerOps = [...]string{"read", "readBlob", "readBlob", "write", "writeBig", "browse", "call", "once", "readMulti", "churn", "churn"}

// worker issues random service calls on c until stop is closed. Every result
// is verified: on a secured channel a response is either authentic or the
// call fails.
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

		name := workerOps[rng.Intn(len(workerOps))]
		err := s.wd.Do(name, func() error {
			ctx, cancel := opContext(rng)
			defer cancel()
			switch name {
			case "read":
				i := rng.Intn(numScratch)
				dv, err := c.ReadValue(ctx, s.e.scratchID(i))
				if err != nil {
					return err
				}
				if dv.Status != ua.StatusOK {
					return fmt.Errorf("INVARIANT: read: status %v", dv.Status)
				}
				if !validScratch(i, dv.Value.Value()) {
					return fmt.Errorf("INVARIANT: read of Scratch%d returned %v (%T), which no writer produced", i, dv.Value.Value(), dv.Value.Value())
				}
			case "readBlob":
				dv, err := c.ReadValue(ctx, s.e.blobID())
				if err != nil {
					return err
				}
				if !validBlob(dv.Value.Value()) {
					b, _ := dv.Value.Value().([]byte)
					return fmt.Errorf("INVARIANT: multi-chunk read returned %d bytes that differ from the node's value", len(b))
				}
			case "write":
				i := rng.Intn(numScratch)
				sc, err := c.WriteNodeValue(ctx, s.e.scratchID(i), randScratch(rng, i))
				if err != nil {
					return err
				}
				if sc != ua.StatusOK {
					return fmt.Errorf("INVARIANT: write: status %v", sc)
				}
			case "writeBig":
				// A multi-chunk request. The stored value is checked by
				// readMulti: a request that lost, repeated or swapped a chunk
				// must not be executed.
				sc, err := c.WriteNodeValue(ctx, s.e.bigID(), bigValue(byte(rng.Intn(256))))
				if err != nil {
					return err
				}
				if sc != ua.StatusOK {
					return fmt.Errorf("INVARIANT: multi-chunk write: status %v", sc)
				}
			case "browse":
				refs, err := c.BrowseAll(ctx, s.e.folderID())
				if err != nil {
					return err
				}
				if n := countLeaves(refs); n != numBrowse {
					return fmt.Errorf("INVARIANT: browse: %d leaves, want %d", n, numBrowse)
				}
			case "call":
				n := int32(rng.Intn(1000))
				res, err := c.CallMethod(ctx, s.e.objectsID(), s.e.methodID(), n)
				if err != nil {
					return err
				}
				if res.StatusCode != ua.StatusOK || len(res.OutputArguments) != 1 || res.OutputArguments[0].Value() != n*n {
					return fmt.Errorf("INVARIANT: call(%d) returned %v %v (response of another request?)", n, res.StatusCode, res.OutputArguments)
				}
			case "once":
				// The server executes a request at most once: a request the
				// monkey repeats on the wire must be rejected.
				n := s.e.nonce.Add(1)
				res, err := c.CallMethod(ctx, s.e.objectsID(), s.e.onceID(), n)
				if err != nil {
					return err
				}
				if res.StatusCode != ua.StatusOK || len(res.OutputArguments) != 1 || res.OutputArguments[0].Value() != n {
					return fmt.Errorf("INVARIANT: once(%d) returned %v %v", n, res.StatusCode, res.OutputArguments)
				}
			case "readMulti":
				dvs, err := c.ReadValues(ctx, s.e.scratchID(0), s.e.counterID(0), s.e.scratchID(1), s.e.bigID())
				if err != nil {
					return err
				}
				if len(dvs) != 4 {
					return fmt.Errorf("INVARIANT: ReadValues returned %d results, want 4", len(dvs))
				}
				if !validScratch(0, dvs[0].Value.Value()) || !s.e.validCounter(0, dvs[1].Value.Value()) || !validScratch(1, dvs[2].Value.Value()) {
					return fmt.Errorf("INVARIANT: ReadValues returned %v, %v, %v, which no writer produced",
						dvs[0].Value.Value(), dvs[1].Value.Value(), dvs[2].Value.Value())
				}
				if !validBig(dvs[3].Value.Value()) {
					return fmt.Errorf("INVARIANT: the node written with multi-chunk requests holds a value no writer produced")
				}
			default:
				return s.churnStep(ctx, c, rng, &cur)
			}
			return nil
		})
		s.ops.Add(1)
		s.tally.Add(err)
		if err != nil && !isFaultError(err) {
			s.unexpected.Addf("worker op %s: unexpected error class: %v", name, err)
		}
		if err != nil {
			// do not spin while the client is not connected
			time.Sleep(2 * time.Millisecond)
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

// ephemeralClients repeatedly connects a client with the next security
// policy, puts it under load and then closes it while its calls are still in
// flight.
func (s *scenario) ephemeralClients(rng *rand.Rand) {
	for n := 0; !s.stopped(); n++ {
		pol := s.pols[n%len(s.pols)]
		name := fmt.Sprintf("e%d.%s", n, pol.name)
		rec := chaoskit.NewStateRecorder(name, true)
		var c *opcua.Client
		err := s.wd.Do("ephemeral connect", func() error {
			var err error
			c, err = opcua.NewClient(s.e.url(), append([]opcua.Option{opcua.InsecureNoSecurity()}, s.e.clientOptions(rec, pol, opcua.RequestTimeout(3*time.Second), opcua.SessionTimeout(5*time.Second))...)...)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := c.Connect(ctx); err != nil {
				chaoskit.CloseClient(c, rec)
				c = nil
				return err
			}
			return nil
		})
		s.tally.Add(err)
		if err != nil {
			if !isFaultError(err) {
				s.unexpected.Addf("ephemeral connect with %s: unexpected error class: %v", pol.name, err)
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
		_ = s.wd.Do("ephemeral stream", func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			st, _ = openStreamWith(ctx, s.e, c, name, rng.Intn(2), shortLivedParams(), rng.Intn(numCounters))
			return nil
		})

		s.sleep(time.Duration(100+rng.Intn(500)) * time.Millisecond)

		// Close races with the workers' in-flight calls.
		_ = s.wd.Do("Close with calls in flight", func() error {
			chaoskit.CloseClient(c, rec)
			return nil
		})
		close(stop)
		s.wd.Wait("workers of closed client "+name, &wg)
		if st != nil {
			st.close()
			st.report(s.t)
		}
		if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool { return c.State() == opcua.Closed }) {
			s.t.Errorf("client %s: State() is %v after Close", name, c.State())
		}
		rec.Check(s.t, true)
	}
}

// fault is one action of the monkey.
type fault struct {
	name   string
	weight int
	apply  func(s *scenario, rng *rand.Rand, hold time.Duration)
}

func dir(rng *rand.Rand) testutil.Direction { return testutil.Direction(rng.Intn(2)) }

// protected reports whether m is a message of a secure channel: an
// OpenSecureChannel message (signed with the sender's certificate), a service
// message or a CloseSecureChannel message (both protected with the channel's
// keys). HEL, ACK and ERR are not protected by anything and are left alone:
// altering them is no test of the security of the channel.
func protected(m []byte) bool {
	switch string(m[:3]) {
	case "OPN", "MSG", "CLO":
		return true
	}
	return false
}

// tamper installs fn for the protected messages of one direction for hold.
// Every message fn touches is counted. fn is never called concurrently.
func (s *scenario) tamper(rng *rand.Rand, hold time.Duration, fn func(rng *rand.Rand, m []byte) (out [][]byte, touched bool)) {
	d := dir(rng)
	// The proxy may still be in fn when the monkey moves on, so fn gets a
	// generator of its own.
	own := rand.New(rand.NewSource(rng.Int63()))
	var mu sync.Mutex
	s.e.proxy.SetFrameMangle(d, func(m []byte) [][]byte {
		if !protected(m) {
			return [][]byte{m}
		}
		mu.Lock()
		defer mu.Unlock()
		out, touched := fn(own, m)
		if touched {
			s.tampered.Add(1)
		}
		return out
	})
	s.sleep(hold)
	s.e.proxy.SetFrameMangle(d, nil)
}

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
	{name: "truncate mid-chunk", weight: 4, apply: func(s *scenario, rng *rand.Rand, _ time.Duration) {
		s.e.proxy.TruncateNext(dir(rng), 1+rng.Intn(200))
	}},
	{name: "server unreachable", weight: 3, apply: func(s *scenario, _ *rand.Rand, hold time.Duration) {
		s.e.proxy.SetRefuse(true)
		s.e.proxy.DropAll()
		s.sleep(hold)
		s.e.proxy.SetRefuse(false)
	}},
	{name: "server restart", weight: 2, apply: func(s *scenario, _ *rand.Rand, hold time.Duration) {
		s.e.restartServer(hold / 4)
	}},
	{name: "close session behind the client's back", weight: 2, apply: func(s *scenario, rng *rand.Rand, _ time.Duration) {
		mc := s.clients[rng.Intn(len(s.clients))]
		_ = s.wd.Do("CloseSession", func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return mc.c.CloseSession(ctx)
		})
	}},
	{name: "detach session", weight: 2, apply: func(s *scenario, rng *rand.Rand, hold time.Duration) {
		mc := s.clients[rng.Intn(len(s.clients))]
		reactivate := rng.Intn(2) == 0
		_ = s.wd.Do("DetachSession", func() error {
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
	{name: "raw malformed frames", weight: 2, apply: func(s *scenario, rng *rand.Rand, _ time.Duration) {
		s.rawAttack(rng)
	}},

	// Faults that alter what the peer receives. The channel's signature or
	// authentication tag and its sequence numbers must catch every one.
	{name: "bit flips in protected messages", weight: 5, apply: func(s *scenario, rng *rand.Rand, hold time.Duration) {
		p := 0.05 + rng.Float64()*0.3
		s.tamper(rng, hold, func(rng *rand.Rand, m []byte) ([][]byte, bool) {
			if rng.Float64() >= p {
				return [][]byte{m}, false
			}
			m[rng.Intn(len(m))] ^= 1 << uint(rng.Intn(8))
			return [][]byte{m}, true
		})
	}},
	{name: "single bit flip in a chunk body", weight: 4, apply: func(s *scenario, rng *rand.Rand, hold time.Duration) {
		// Past all headers, so the message is well-formed: only the
		// signature or tag tells.
		left := 1 + rng.Intn(3)
		s.tamper(rng, hold, func(rng *rand.Rand, m []byte) ([][]byte, bool) {
			if left == 0 || string(m[:3]) != "MSG" || len(m) < 64 {
				return [][]byte{m}, false
			}
			left--
			m[32+rng.Intn(len(m)-32)] ^= 1 << uint(rng.Intn(8))
			return [][]byte{m}, true
		})
	}},
	{name: "replayed messages", weight: 5, apply: func(s *scenario, rng *rand.Rand, hold time.Duration) {
		p := 0.05 + rng.Float64()*0.3
		s.tamper(rng, hold, func(rng *rand.Rand, m []byte) ([][]byte, bool) {
			if rng.Float64() >= p {
				return [][]byte{m}, false
			}
			return [][]byte{m, m}, true
		})
	}},
	{name: "lost messages", weight: 4, apply: func(s *scenario, rng *rand.Rand, hold time.Duration) {
		// The connection stays up: the next message arrives with a gap in
		// the sequence numbers.
		p := 0.05 + rng.Float64()*0.2
		s.tamper(rng, hold, func(rng *rand.Rand, m []byte) ([][]byte, bool) {
			if rng.Float64() >= p {
				return [][]byte{m}, false
			}
			return nil, true
		})
	}},
	{name: "reordered and misdirected messages", weight: 4, apply: func(s *scenario, rng *rand.Rand, hold time.Duration) {
		// A message is held back and delivered after a later one: of the
		// same connection, or of another connection with other keys.
		p := 0.05 + rng.Float64()*0.2
		var held []byte
		s.tamper(rng, hold, func(rng *rand.Rand, m []byte) ([][]byte, bool) {
			if held != nil {
				out := [][]byte{m, held}
				held = nil
				return out, true
			}
			if rng.Float64() >= p {
				return [][]byte{m}, false
			}
			held = m
			return nil, true
		})
	}},
	{name: "old message replayed later", weight: 3, apply: func(s *scenario, rng *rand.Rand, hold time.Duration) {
		// A recorded message is injected again and again, also after the
		// channel renewed its keys and on other channels.
		var recorded []byte
		s.tamper(rng, hold, func(rng *rand.Rand, m []byte) ([][]byte, bool) {
			if recorded == nil {
				if string(m[:3]) != "CLO" && rng.Intn(3) == 0 {
					recorded = append([]byte(nil), m...)
				}
				return [][]byte{m}, false
			}
			if rng.Intn(4) != 0 {
				return [][]byte{m}, false
			}
			return [][]byte{m, append([]byte(nil), recorded...)}, true
		})
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
	_ = s.wd.Do("raw attack: "+a.name, func() error {
		_, err := sendRawAttack(addr, "opc.tcp://"+addr, a, rng, 200*time.Millisecond)
		return err
	})
}

// monkey injects random faults for the given duration.
func (s *scenario) monkey(d time.Duration) {
	rng := rand.New(rand.NewSource(s.seed))
	var pool []fault
	for _, f := range faults {
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
	s.t.Logf("[%6.2fs] faults stopped", time.Since(start).Seconds())
	s.healed = time.Now()
}

// verifyRecovery checks that, once the faults are gone, every long-lived
// client returns to Connected and every one of its subscriptions delivers
// fresh values again.
func (s *scenario) verifyRecovery() {
	s.t.Helper()
	for _, mc := range s.clients {
		if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool { return mc.c.State() == opcua.Connected }) {
			s.t.Errorf("STUCK: client %s did not return to Connected within %v after the faults stopped; state=%v transitions=%v\n%s",
				mc.name, chaoskit.SettleLimit, mc.c.State(), mc.rec.Snapshot(), chaoskit.AllStacks())
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
	chaoskit.Eventually(chaoskit.SettleLimit, func() bool {
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
			p.st.name, p.h, p.st.lastValue(int(p.h)), s.e.counters[p.h].Load(), p.mc.c.State(), p.mc.rec.Snapshot(), p.mc.c.SubscriptionIDs(), s.e.resources())
	}
	if len(waiting) > 0 {
		s.t.Logf("goroutines:\n%s", chaoskit.AllStacks())
	}
	s.t.Logf("recovered %.2fs after the faults stopped", time.Since(s.healed).Seconds())
	// The channel every client ended up with is the secured one it asked for.
	for _, mc := range s.clients {
		if got := mc.c.SecurityPolicy(); got != mc.pol.uri {
			s.t.Errorf("client %s: security policy after the storm is %q", mc.name, got)
		}
		if got := mc.c.SecurityMode(); got != ua.MessageSecurityModeSignAndEncrypt {
			s.t.Errorf("client %s: security mode after the storm is %v", mc.name, got)
		}
	}
}

// finish stops the workload, closes all clients and checks the invariants
// that hold after shutdown.
func (s *scenario) finish(verifyLeaks func()) {
	s.t.Helper()
	close(s.stop)
	s.wd.Wait("workload", &s.workers)

	for _, mc := range s.clients {
		for _, st := range mc.streams {
			_ = s.wd.Do("cancel stream", func() error {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				return st.sub.Cancel(ctx)
			})
		}
		_ = s.wd.Do("Close", func() error { chaoskit.CloseClient(mc.c, mc.rec); return nil })
		for _, st := range mc.streams {
			st.close()
			st.report(s.t)
		}
		if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool { return mc.c.State() == opcua.Closed }) {
			s.t.Errorf("client %s: State() is %v after Close", mc.name, mc.c.State())
		}
		if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool { last, ok := mc.rec.Last(); return ok && last == opcua.Closed }) {
			s.t.Errorf("client %s: last reported state after Close is not Closed: %v", mc.name, mc.rec.Snapshot())
		}
		mc.rec.Check(s.t, true)
	}
	s.t.Logf("clients closed %.2fs after the faults stopped", time.Since(s.healed).Seconds())
	s.unexpected.Report(s.t)
	s.e.reportReplays()
	s.t.Logf("workload: %d operations, %d messages tampered with: %s", s.ops.Load(), s.tampered.Load(), s.tally.String())

	// the server is still healthy and holds nothing for the departed clients
	for _, pol := range s.pols {
		s.e.requireCleanClient(pol)
	}
	s.t.Logf("clean clients served %.2fs after the faults stopped", time.Since(s.healed).Seconds())
	s.e.requireServerDrained(chaoskit.SettleLimit)
	s.t.Logf("server drained %.2fs after the faults stopped", time.Since(s.healed).Seconds())

	s.e.stopServer()
	s.e.proxy.Close()
	s.wd.Close()
	verifyLeaks()
}

// TestSecureChaosMonkey runs the mixed workload on one long-lived client per
// security policy (one RSA policy, ECC_nistP256, ECC_nistP384 and the three
// ECC policies with authenticated encryption), all in SignAndEncrypt mode
// with a username identity, against one server that offers them all, while
// the monkey injects faults:
//
//   - everything the unsecured monkey does: connection resets, half-closes,
//     blackholes, latency, fragmentation, throttling, truncation in the
//     middle of a chunk, an unreachable or restarting server, sessions closed
//     or detached behind the client's back, clients closed mid-call,
//     cancelled contexts and hostile raw connections;
//   - a channel lifetime of 1.2 s, so that every channel that survives renews
//     its token again and again, with fresh ephemeral keys and, on the
//     policies with SecureChannelEnhancements, keys chained to the previous
//     ones;
//   - attacks on the protected messages: bit flips anywhere and in the chunk
//     body only, messages repeated at once or later (also across a renewal
//     and on another channel), lost without a connection loss, reordered and
//     delivered on the wrong connection.
//
// A secured channel either delivers an authentic message or fails. So,
// unlike in the unsecured corruption scenario, every result is verified: all
// values read or delivered by a subscription are values a writer produced,
// multi-chunk messages are complete and in order in both directions, a
// request is executed at most once, values of a subscription never go
// backwards, and errors are connection-class or security-check errors.
// Afterwards every client is Connected again on its policy with its
// subscriptions delivering, the server serves a new client of every policy
// and holds nothing for the departed ones, and no goroutine is left.
func TestSecureChaosMonkey(t *testing.T) {
	verifyLeaks := chaoskit.LeakCheck(t)
	s := newScenario(t)
	s.start()
	s.monkey(chaoskit.Duration(t, defaultDuration))
	s.verifyRecovery()
	s.finish(verifyLeaks)
}
